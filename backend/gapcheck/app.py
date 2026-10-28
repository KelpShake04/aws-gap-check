"""컨테이너 진입점: 설정을 읽고 DB, AWS 클라이언트, 스캔 작업자, HTTP 서버를 이어 붙인다.

실행: python -m gapcheck.app   (설정은 환경 변수, compose.yaml 참고)
boto3는 여기서만 import한다(다른 모듈은 클라이언트를 인자로 받는다).
"""
from __future__ import annotations

import logging
import os
import pathlib
import time

from . import db, explain, ids, llm, server, worker

logger = logging.getLogger("gapcheck")

DEMO_ACCOUNT_ID = "000000000000"


class DemoSts:
    """데모 모드 전용: AWS 없이 화면 흐름을 보여 주려고 어떤 계정이든 검증을 통과시킨다.

    운영에서 켜면 계정 검증이 의미가 없어지므로 DEMO_FIXTURE가 있을 때만 쓰고 화면에 데모 표시를 한다.
    """

    def assume_role(self, RoleArn, RoleSessionName, ExternalId, DurationSeconds):
        account = RoleArn.split(":")[4]
        return {"AssumedRoleUser": {"Arn": f"arn:aws:sts::{account}:assumed-role/{ids.ROLE_NAME}/{RoleSessionName}"}}


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
    max_rpm = int(env.get("GEMINI_MAX_RPM", "10"))
    cached = {}

    def api_key() -> str:
        if "key" not in cached:
            cached["key"] = env.get("GEMINI_API_KEY", "")
            if not cached["key"] and ssm_client is not None:
                try:
                    cached["key"] = ssm_client().get_parameter(
                        Name=env.get("GEMINI_PARAM", "/aws-gap-check/gemini-api-key"),
                        WithDecryption=True)["Parameter"]["Value"]
                except Exception as err:
                    logger.error("Gemini key unavailable: %s", type(err).__name__)
        return cached["key"]

    def make_explainer():
        key = api_key() if model else ""
        generate = None
        if key:
            def generate(system, user, schema):
                return llm.generate_json(system, user, schema, model=model, api_key=key)
        return explain.Explainer(generate, store, model=model, max_rpm=max_rpm)

    return make_explainer


def main(env=os.environ) -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    store = store_from_env(env)
    wait_for_db(store)

    fixture = env.get("DEMO_FIXTURE", "")
    if fixture:
        logger.warning("DEMO MODE: account verification is bypassed and scans use %s", fixture)
        sts, scanner, ssm = DemoSts(), worker.copy_fixture(pathlib.Path(fixture)), None
        service_account_id = env.get("SERVICE_ACCOUNT_ID", DEMO_ACCOUNT_ID)
    else:
        import boto3

        sts, scanner = boto3.client("sts"), worker.run_prowler
        ssm = lambda: boto3.client("ssm")  # noqa: E731 - 키가 필요할 때만 클라이언트를 만든다
        service_account_id = env.get("SERVICE_ACCOUNT_ID") or sts.get_caller_identity()["Account"]

    make_explainer = explainer_factory(env, store, ssm)
    data_dir = pathlib.Path(env.get("DATA_DIR", "/data"))
    scan_worker = worker.Worker(store, scanner, make_explainer, data_dir / "raw")
    scan_worker.start()

    app_dir = pathlib.Path(__file__).resolve().parent.parent
    deps = server.Deps(store=store, sts=sts, worker=scan_worker, service_account_id=service_account_id,
                       daily_limit=int(env.get("DAILY_SCAN_LIMIT", "10")),
                       frontend_dir=pathlib.Path(env.get("FRONTEND_DIR", app_dir / "frontend")),
                       template_file=pathlib.Path(env.get("TEMPLATE_FILE", app_dir / "customer-role.yaml")),
                       demo=bool(fixture))
    port = int(env.get("PORT", "8080"))
    logger.info("listening on :%d", port)
    server.make_server(deps, "0.0.0.0", port).serve_forever()


if __name__ == "__main__":
    main()
