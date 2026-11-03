"""컨테이너 진입점: 설정을 읽고 DB, AWS 클라이언트, 스캔 작업자, HTTP 서버를 이어 붙인다.

실행: python -m gapcheck.app   (설정은 환경 변수, compose.yaml 참고)
boto3는 여기서만 import한다(다른 모듈은 클라이언트를 인자로 받는다).
"""
from __future__ import annotations

import logging
import os
import pathlib
import time
from datetime import timedelta

from . import billing, db, explain, ids, llm, notify, server, worker
from .common import iso, utcnow

logger = logging.getLogger("gapcheck")

DEMO_ACCOUNT_ID = "000000000000"


class DemoSts:
    """데모 모드 전용: AWS 없이 화면 흐름을 보여 주려고 어떤 계정이든 검증을 통과시킨다.

    운영에서 켜면 계정 검증이 의미가 없어지므로 DEMO_FIXTURE가 있을 때만 쓰고 화면에 데모 표시를 한다.
    """

    def assume_role(self, RoleArn, RoleSessionName, ExternalId, DurationSeconds):
        account = RoleArn.split(":")[4]
        return {"AssumedRoleUser": {"Arn": f"arn:aws:sts::{account}:assumed-role/{ids.ROLE_NAME}/{RoleSessionName}"}}


class DemoCost:
    """데모 모드 전용: Cost Explorer 대신 날짜에서 계산한 가짜 비용을 보여 준다."""

    SERVICES = (("Amazon Elastic Compute Cloud - Compute", 1.9), ("Amazon Relational Database Service", 1.2),
                ("Amazon Simple Storage Service", 0.35), ("Amazon Virtual Private Cloud", 0.6),
                ("AmazonCloudWatch", 0.15), ("AWS Key Management Service", 0.05))

    def __init__(self, now=utcnow):
        self.now = now

    def get(self, sub, conn, force=False):
        today = self.now().date()
        rows = [(today - timedelta(days=back), name, base * (0.8 + 0.1 * ((today.toordinal() - back) % 5)))
                for back in range(70) for name, base in self.SERVICES]
        next_month = (today.replace(day=1) + timedelta(days=32)).replace(day=1)
        rest = sum(base for _, base in self.SERVICES) * ((next_month - today).days - 1)
        return {**billing.summarize(rows, today, rest), "fetchedAt": iso(self.now())}


class DemoMailer:
    """데모 모드 전용: 메일을 보내지 않고 서버 로그에 남긴다."""

    def send(self, to, subject, body):
        logger.warning("DEMO MAIL to %s: %s\n%s", to, subject, body)


def ce_client(credentials):
    """Cost Explorer는 us-east-1 하나뿐이다. 고객 계정의 임시 자격 증명으로 만든다."""
    import boto3

    return boto3.client("ce", region_name="us-east-1", aws_access_key_id=credentials["AccessKeyId"],
                        aws_secret_access_key=credentials["SecretAccessKey"],
                        aws_session_token=credentials["SessionToken"])


def store_from_env(env=os.environ) -> db.Store:
    return db.Store(db.connector(host=env.get("DB_HOST", "mysql"), port=int(env.get("DB_PORT", "3306")),
                                 user=env.get("DB_USER", "gapcheck"), password=env["DB_PASSWORD"],
                                 database=env.get("DB_NAME", "gapcheck")))


def wait_for_db(store, attempts: int = 30) -> None:
    for attempt in range(attempts):
        try:
            store._execute("SELECT 1", ())
            return
        except Exception as err:
            if attempt == attempts - 1:
                raise
            logger.info("waiting for database (%s)", type(err).__name__)
            time.sleep(2)


def explainer_factory(env, store, ssm_client):
    """Gemini 키는 처음 쓸 때 한 번 읽어 메모리에만 둔다. 로그에 남기지 않는다."""
    model = env.get("GEMINI_MODEL", "")
    fallback_model = env.get("GEMINI_FALLBACK_MODEL", "")
    max_rpm = int(env.get("GEMINI_MAX_RPM", "10"))
    cached = {}

    def api_key() -> str:
        # 빈 값은 캐시하지 않는다: 키를 나중에 SSM에 넣어도 재시작 없이 반영된다
        if not cached.get("key"):
            cached["key"] = env.get("GEMINI_API_KEY", "")
            if not cached["key"] and ssm_client is not None:
                try:
                    cached["key"] = ssm_client().get_parameter(
                        Name=env.get("GEMINI_PARAM", "/gapcheck/gemini-api-key"),
                        WithDecryption=True)["Parameter"]["Value"]
                except Exception as err:
                    logger.error("Gemini key unavailable: %s", type(err).__name__)
        return cached["key"]

    def make_explainer():
        key = api_key() if model else ""
        generate = fallback_generate = None
        if key:
            def generate(system, user, schema):
                return llm.generate_json(system, user, schema, model=model, api_key=key)
            if fallback_model and fallback_model != model:
                def fallback_generate(system, user, schema):
                    return llm.generate_json(system, user, schema, model=fallback_model, api_key=key)
        return explain.Explainer(generate, store, fallback_generate=fallback_generate,
                                 model=model, max_rpm=max_rpm)

    return make_explainer


def main(env=os.environ) -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    store = store_from_env(env)
    wait_for_db(store)

    fixture = env.get("DEMO_FIXTURE", "")
    if fixture:
        logger.warning("DEMO MODE: account verification is bypassed and scans use %s", fixture)
        sts, scanner, ssm = DemoSts(), worker.copy_fixture(pathlib.Path(fixture)), None
        cost, mailer = DemoCost(), DemoMailer()
        service_account_id = env.get("SERVICE_ACCOUNT_ID", DEMO_ACCOUNT_ID)
    else:
        import boto3

        sts, scanner = boto3.client("sts"), worker.run_prowler
        ssm = lambda: boto3.client("ssm")  # noqa: E731 - 키가 필요할 때만 클라이언트를 만든다
        service_account_id = env.get("SERVICE_ACCOUNT_ID") or sts.get_caller_identity()["Account"]
        cost = billing.CostProvider(sts, ce_client)
        # 보내는 주소(SES에서 확인된 주소)가 없으면 알림 메일은 꺼진다
        mailer = notify.SesMailer(boto3.client("sesv2"), env["MAIL_FROM"]) if env.get("MAIL_FROM") else None

    make_explainer = explainer_factory(env, store, ssm)
    data_dir = pathlib.Path(env.get("DATA_DIR", "/data"))
    daily_limit = int(env.get("DAILY_SCAN_LIMIT", "10"))
    notifier = notify.Notifier(store, mailer, env.get("SITE_URL", "")) if mailer else None
    scan_worker = worker.Worker(store, scanner, make_explainer, data_dir / "raw", notifier=notifier,
                                daily_limit=daily_limit)
    scan_worker.start()

    app_dir = pathlib.Path(__file__).resolve().parent.parent
    deps = server.Deps(store=store, sts=sts, worker=scan_worker, service_account_id=service_account_id,
                       daily_limit=daily_limit,
                       frontend_dir=pathlib.Path(env.get("FRONTEND_DIR", app_dir / "frontend")),
                       template_file=pathlib.Path(env.get("TEMPLATE_FILE", app_dir / "customer-role.yaml")),
                       demo=bool(fixture), cost=cost, notifier=notifier)
    port = int(env.get("PORT", "8080"))
    logger.info("listening on :%d", port)
    server.make_server(deps, "0.0.0.0", port).serve_forever()


if __name__ == "__main__":
    main()
