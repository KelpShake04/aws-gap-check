"""HTTP API(payload v2) 라우터 (ApiFunction).

사용자 식별은 API Gateway JWT authorizer가 검증한 토큰의 sub로만 한다. 요청 본문이나 경로의
값으로는 다른 사용자의 데이터 키를 만들 수 없다.
"""
import base64
import json
import logging
import os
from dataclasses import dataclass
from typing import Any, Callable

from gapcheck import connections, ids, scans
from gapcheck.common import ApiError, BadRequest, utcnow

logger = logging.getLogger()
logger.setLevel(logging.INFO)

MAX_BODY_BYTES = 16 * 1024
TEMPLATE_PATH = "/customer-role.yaml"
STACK_NAME = "aws-gap-check-readonly-role"


@dataclass
class Deps:
    store: Any
    sts: Any
    codebuild: Any
    s3: Any
    project: str
    bucket: str
    service_account_id: str
    daily_limit: int
    now: Callable = utcnow


def conn_view(conn: dict) -> dict:
    return {key: conn.get(key) for key in
            ("id", "accountId", "status", "message", "externalId", "createdAt", "verifiedAt")}


def scan_view(scan: dict) -> dict:
    return {key: scan.get(key) for key in
            ("id", "connectionId", "accountId", "status", "counts", "summary", "error",
             "createdAt", "updatedAt")}


FINDING_FIELDS = ("checkId", "title", "severity", "service", "resourceType", "description", "risk",
                  "recommendation", "references", "resources", "regions", "totalCount",
                  "explanation", "explainSource")


def setup_info(deps) -> dict:
    """고객 계정에서 템플릿을 배포할 때 필요한 값. ExternalId는 연결마다 따로 있다."""
    return {"serviceAccountId": deps.service_account_id, "roleName": ids.ROLE_NAME,
            "stackName": STACK_NAME, "templatePath": TEMPLATE_PATH}


def create_connection(deps, sub, params, body):
    conn = connections.create(deps.store, sub, deps.now())
    return 201, {"connection": conn_view(conn), "setup": setup_info(deps)}


def list_connections(deps, sub, params, body):
    return 200, {"connections": [conn_view(c) for c in deps.store.list_connections(sub)],
                 "setup": setup_info(deps)}


def verify_connection(deps, sub, params, body):
    conn = connections.verify(deps.store, deps.sts, sub, params.get("id", ""),
                              body().get("accountId"), deps.now())
    return 200, {"connection": conn_view(conn)}


def delete_connection(deps, sub, params, body):
    connections.delete(deps.store, sub, params.get("id", ""))
    return 204, None


def start_scan(deps, sub, params, body):
    scan = scans.start(deps.store, deps.codebuild, sub, str(body().get("connectionId", "")),
                       project=deps.project, now=deps.now(), daily_limit=deps.daily_limit)
    return 202, {"scan": scan_view(scan)}


def list_scans(deps, sub, params, body):
    return 200, {"scans": [scan_view(s) for s in deps.store.list_scans(sub)]}


def get_scan(deps, sub, params, body):
    scan = scans.get(deps.store, sub, params.get("id", ""))
    groups = deps.store.list_findings(sub, scan["id"])
    return 200, {"scan": scan_view(scan),
                 "findings": [{k: g.get(k) for k in FINDING_FIELDS} for g in groups]}


def delete_scan(deps, sub, params, body):
    scans.delete(deps.store, deps.s3, sub, params.get("id", ""), bucket=deps.bucket, now=deps.now())
    return 204, None


ROUTES = {
    "POST /connections": create_connection,
    "GET /connections": list_connections,
    "POST /connections/{id}/verify": verify_connection,
    "DELETE /connections/{id}": delete_connection,
    "POST /scans": start_scan,
    "GET /scans": list_scans,
    "GET /scans/{id}": get_scan,
    "DELETE /scans/{id}": delete_scan,
}


def route(event: dict, deps: Deps) -> dict:
    claims = ((((event.get("requestContext") or {}).get("authorizer") or {})
               .get("jwt") or {}).get("claims") or {})
    sub = claims.get("sub", "")
    if not ids.valid("sub", sub):
        return _response(401, {"error": "unauthorized", "message": "로그인이 필요합니다."})
    handler = ROUTES.get(event.get("routeKey", ""))
    if handler is None:
        return _response(404, {"error": "not_found", "message": "없는 경로입니다."})
    try:
        status, payload = handler(deps, sub, event.get("pathParameters") or {}, lambda: _body(event))
    except ApiError as err:
        return _response(err.status, {"error": err.code, "message": err.message})
    return _response(status, payload)


def _body(event: dict) -> dict:
    raw = event.get("body") or ""
    if event.get("isBase64Encoded"):
        raw = base64.b64decode(raw).decode("utf-8", "replace")
    if len(raw.encode("utf-8")) > MAX_BODY_BYTES:
        raise BadRequest("요청 본문이 너무 큽니다.")
    try:
        data = json.loads(raw or "{}")
    except ValueError:
        raise BadRequest("요청 본문이 JSON이 아닙니다.") from None
    if not isinstance(data, dict):
        raise BadRequest("요청 본문은 JSON 객체여야 합니다.")
    return data


def _response(status: int, payload) -> dict:
    response = {"statusCode": status, "headers": {"Cache-Control": "no-store"}}
    if payload is not None:
        response["headers"]["Content-Type"] = "application/json; charset=utf-8"
        response["body"] = json.dumps(payload, ensure_ascii=False)
    return response


_deps = None


def _make_deps() -> Deps:
    import boto3

    from gapcheck.store import Store

    return Deps(
        store=Store(boto3.resource("dynamodb").Table(os.environ["TABLE_NAME"])),
        sts=boto3.client("sts"),
        codebuild=boto3.client("codebuild"),
        s3=boto3.client("s3"),
        project=os.environ["PROJECT_NAME"],
        bucket=os.environ["RESULTS_BUCKET"],
        service_account_id=os.environ["SERVICE_ACCOUNT_ID"],
        daily_limit=int(os.environ.get("DAILY_SCAN_LIMIT", "10")),
    )


def handler(event, context):
    global _deps
    try:
        if _deps is None:
            _deps = _make_deps()
        return route(event, _deps)
    except Exception:
        # 상세 내용은 로그에만 남기고 사용자에게는 일반 메시지만 준다
        logger.exception("unhandled error on %s", event.get("routeKey"))
        return _response(500, {"error": "internal", "message": "서버 오류가 발생했습니다."})
