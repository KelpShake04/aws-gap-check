"""스캔 시작·조회·삭제와 사용 한도(사용자당 동시 1개, 하루 N회)."""
from __future__ import annotations

from datetime import datetime

from . import ids
from .common import Conflict, NotFound, TooMany, Unavailable, error_code, expires_at, iso, parse_iso

ACTIVE_STATUSES = ("QUEUED", "RUNNING", "PROCESSING", "EXPLAINING")
DELETED = "DELETED"
# 이벤트를 놓쳐 진행 중으로 남은 스캔이 사용자를 영원히 막지 않게 한다(CodeBuild 대기+실행 최대 60분)
STALE_SECONDS = 70 * 60


def is_running(scan: dict, now: datetime) -> bool:
    if scan.get("status") not in ACTIVE_STATUSES:
        return False
    return (now - parse_iso(scan["createdAt"])).total_seconds() < STALE_SECONDS


def start(store, codebuild, sub: str, conn_id: str, *, project: str, now: datetime,
          daily_limit: int) -> dict:
    scan, conn = create(store, sub, conn_id, now=now, daily_limit=daily_limit)
    env = {"SCAN_ID": scan["id"], "USER_SUB": sub,
           "ROLE_ARN": ids.role_arn(conn["accountId"]), "EXTERNAL_ID": conn["externalId"]}
    try:
        build = codebuild.start_build(
            projectName=project,
            environmentVariablesOverride=[{"name": k, "value": v, "type": "PLAINTEXT"}
                                          for k, v in env.items()],
        )["build"]
    except Exception as err:
        store.update_scan(sub, scan["id"], {"status": "FAILED", "error": "스캔을 시작하지 못했습니다."})
        if "LimitExceeded" in error_code(err):
            raise TooMany("다른 스캔이 실행 중입니다. 잠시 후 다시 시도하세요.") from None
        raise Unavailable("스캔을 시작하지 못했습니다.") from None
    store.update_scan(sub, scan["id"], {"buildId": build["id"]})
    scan["buildId"] = build["id"]
    return scan


def create(store, sub: str, conn_id: str, *, now: datetime, daily_limit: int):
    """한도를 확인하고 QUEUED 스캔을 저장한다. (scan, connection)을 돌려준다."""
    conn = store.get_connection(sub, conn_id) if ids.valid("connection", conn_id) else None
    if not conn:
        raise NotFound("연결을 찾을 수 없습니다.")
    if conn.get("status") != "ACTIVE":
        raise Conflict("먼저 연결을 검증하세요.")
    existing = store.list_scans(sub)
    if any(is_running(scan, now) for scan in existing):
        raise Conflict("이미 진행 중인 스캔이 있습니다.")
    today = now.strftime("%Y%m%d")
    if sum(1 for scan in existing if scan["id"].startswith(today)) >= daily_limit:
        raise TooMany(f"오늘 스캔 한도({daily_limit}회)를 넘었습니다.")

    scan = {
        "id": ids.new_scan_id(now),
        "connectionId": conn_id,
        "accountId": conn["accountId"],
        "status": "QUEUED",
        "counts": {},
        "summary": None,
        "error": "",
        "createdAt": iso(now),
        "updatedAt": iso(now),
        "expiresAt": expires_at(now),
    }
    # 이벤트 처리기(작업자)가 찾을 수 있게 실행보다 먼저 저장한다
    store.put_scan(sub, scan)
    return scan, conn


def get(store, sub: str, scan_id: str) -> dict:
    scan = store.get_scan(sub, scan_id) if ids.valid("scan", scan_id) else None
    if not scan or scan.get("status") == DELETED:
        raise NotFound("스캔을 찾을 수 없습니다.")
    return scan


def delete(store, s3, sub: str, scan_id: str, *, bucket: str, now: datetime) -> None:
    def remove_raw():
        listed = s3.list_objects_v2(Bucket=bucket, Prefix=f"raw/{sub}/{scan_id}/")
        keys = [{"Key": obj["Key"]} for obj in listed.get("Contents", [])]
        if keys:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": keys})

    discard(store, sub, scan_id, remove_raw=remove_raw, now=now)


def discard(store, sub: str, scan_id: str, *, remove_raw, now: datetime) -> None:
    """원본 파일(remove_raw)과 결과를 지우고 스캔은 DELETED로 표시만 남긴다."""
    scan = get(store, sub, scan_id)
    if is_running(scan, now):
        raise Conflict("진행 중인 스캔은 끝난 뒤에 삭제할 수 있습니다.")
    remove_raw()
    store.delete_findings(sub, scan_id)
    # 기록은 표시만 남긴다. 지워 버리면 일일 한도 계산에서 빠져 한도를 우회할 수 있다(TTL로 30일 뒤 삭제).
    store.update_scan(sub, scan_id, {"status": DELETED, "counts": {}, "summary": None, "error": "",
                                     "updatedAt": iso(now)})
