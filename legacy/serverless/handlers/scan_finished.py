"""CodeBuild 상태 변경 이벤트 처리 (ScanFinishedFunction).

IN_PROGRESS면 RUNNING으로, 실패면 FAILED로 바꾼다. 성공이면 결과를 파싱해 check 단위로 저장하고
(PROCESSING), 해설을 하나씩 붙이고(EXPLAINING), 우선순위 요약을 만든 뒤 DONE으로 끝낸다.
같은 이벤트가 두 번 와도 이미 끝난 스캔은 건드리지 않는다.
"""
import json
import logging
import os
from dataclasses import dataclass
from typing import Any, Callable

from gapcheck import explain, ids, llm, results
from gapcheck.common import iso, utcnow

logger = logging.getLogger()
logger.setLevel(logging.INFO)

MAX_RESULT_BYTES = 50 * 1024 * 1024
FINAL_STATUSES = ("DONE", "FAILED", "DELETED")
PHASE_MESSAGES = {
    "PROVISIONING": "스캔 환경을 준비하지 못했습니다(이미지 내려받기 실패 등).",
    "DOWNLOAD_SOURCE": "스캔 스크립트를 내려받지 못했습니다.",
    "BUILD": "스캔에 실패했습니다. 연결을 다시 검증하세요(Role 삭제, ExternalId 불일치 등).",
}


@dataclass
class Deps:
    store: Any
    codebuild: Any
    s3: Any
    bucket: str
    make_explainer: Callable  # remaining_ms -> explain.Explainer
    now: Callable = utcnow


def handle(event: dict, deps: Deps, remaining_ms: Callable) -> str:
    detail = event.get("detail") or {}
    status = detail.get("build-status", "")
    build_id = str(detail.get("build-id", "")).split("build/", 1)[-1]
    builds = deps.codebuild.batch_get_builds(ids=[build_id]).get("builds") or []
    if not builds:
        return "unknown build"
    build = builds[0]
    env = {v.get("name"): v.get("value") for v in
           (build.get("environment") or {}).get("environmentVariables") or []}
    sub, scan_id = env.get("USER_SUB", ""), env.get("SCAN_ID", "")
    if not (ids.valid("sub", sub) and ids.valid("scan", scan_id)):
        return "not a service scan"
    scan = deps.store.get_scan(sub, scan_id)
    if scan is None or scan["status"] in FINAL_STATUSES:
        return "ignored"

    if status == "IN_PROGRESS":
        if scan["status"] == "QUEUED":
            _update(deps, sub, scan_id, status="RUNNING")
        return "running"
    if status != "SUCCEEDED":
        failed = next((p for p in build.get("phases") or []
                       if p.get("phaseStatus") in ("FAILED", "FAULT", "TIMED_OUT")), {})
        phase = failed.get("phaseType", "")
        message = PHASE_MESSAGES.get(phase, "스캔이 끝나지 못했습니다.")
        _update(deps, sub, scan_id, status="FAILED", error=f"{message} ({status} {phase})".strip())
        return "failed"
    # EventBridge는 같은 이벤트를 두 번 줄 수 있다. 상태를 먼저 조건부로 잡은 호출만 처리한다.
    if not deps.store.claim_scan(sub, scan_id, ("QUEUED", "RUNNING"),
                                 {"status": "PROCESSING", "updatedAt": iso(deps.now())}):
        return "ignored"
    try:
        _process(deps, sub, scan, remaining_ms)
    except Exception:
        logger.exception("processing failed for scan %s", scan_id)
        _update(deps, sub, scan_id, status="FAILED", error="결과를 처리하지 못했습니다.")
        return "processing failed"
    return "done"


def _process(deps: Deps, sub: str, scan: dict, remaining_ms: Callable) -> None:
    scan_id = scan["id"]
    obj = deps.s3.get_object(Bucket=deps.bucket, Key=f"raw/{sub}/{scan_id}/prowler.ocsf.json")
    if obj.get("ContentLength", 0) > MAX_RESULT_BYTES:
        raise ValueError("result too large")
    explainer = deps.make_explainer(remaining_ms)
    checks = results.store_and_explain(deps.store, explainer, sub, scan,
                                       json.loads(obj["Body"].read()), deps.now)
    logger.info("scan %s done: %d checks, %d model calls", scan_id, checks, explainer.calls)


def _update(deps: Deps, sub: str, scan_id: str, **fields) -> None:
    fields["updatedAt"] = iso(deps.now())
    deps.store.update_scan(sub, scan_id, fields)


_deps = None
_api_key = None


def _gemini_key(ssm) -> str:
    """키는 컨테이너가 살아 있는 동안 메모리에만 둔다. 로그에 남기지 않는다."""
    global _api_key
    if _api_key is None:
        try:
            _api_key = ssm.get_parameter(Name=os.environ["GEMINI_PARAM"],
                                         WithDecryption=True)["Parameter"]["Value"]
        except Exception as err:
            logger.error("Gemini key unavailable: %s", type(err).__name__)
            _api_key = ""
    return _api_key


def _make_deps() -> Deps:
    import boto3

    from gapcheck.store import Store

    store = Store(boto3.resource("dynamodb").Table(os.environ["TABLE_NAME"]))
    ssm = boto3.client("ssm")
    model = os.environ.get("GEMINI_MODEL", "")
    max_rpm = int(os.environ.get("GEMINI_MAX_RPM", "10"))

    def make_explainer(remaining_ms):
        key = _gemini_key(ssm) if model else ""
        generate = None
        if key:
            def generate(system, user, schema):
                return llm.generate_json(system, user, schema, model=model, api_key=key)
        return explain.Explainer(generate, store, model=model, max_rpm=max_rpm,
                                 remaining_ms=remaining_ms)

    return Deps(store=store, codebuild=boto3.client("codebuild"), s3=boto3.client("s3"),
                bucket=os.environ["RESULTS_BUCKET"], make_explainer=make_explainer)


def handler(event, context):
    global _deps
    if _deps is None:
        _deps = _make_deps()
    result = handle(event, _deps, context.get_remaining_time_in_millis)
    logger.info("build event handled: %s", result)
    return result
