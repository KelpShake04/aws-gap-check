"""계정 연결: ExternalId 발급과 Role 검증.

ExternalId는 항상 서버가 만들고 사용자는 바꿀 수 없다. 다른 사용자가 남의 계정 ID를 등록해도
그 계정의 Role은 원래 주인의 ExternalId만 받으므로 AssumeRole이 실패한다(confused deputy 방지).
"""
from __future__ import annotations

from datetime import datetime

from . import ids
from .common import BadRequest, NotFound, error_code, iso

DENIED_MESSAGE = ("Role을 맡을 수 없습니다. 템플릿을 이 연결의 ExternalId로 배포했는지, "
                  "계정 ID가 맞는지 확인하세요.")


def create(store, sub: str, now: datetime) -> dict:
    conn = {
        "id": ids.new_connection_id(),
        "externalId": ids.new_external_id(),
        "accountId": None,
        "status": "PENDING",
        "message": "",
        "createdAt": iso(now),
        "verifiedAt": None,
    }
    store.put_connection(sub, conn)
    return conn


def get(store, sub: str, conn_id: str) -> dict:
    conn = store.get_connection(sub, conn_id) if ids.valid("connection", conn_id) else None
    if not conn:
        raise NotFound("연결을 찾을 수 없습니다.")
    return conn


def verify(store, sts, sub: str, conn_id: str, account_id, now: datetime) -> dict:
    conn = get(store, sub, conn_id)
    if not ids.valid("account", account_id):
        raise BadRequest("계정 ID는 12자리 숫자입니다.")
    try:
        response = sts.assume_role(
            RoleArn=ids.role_arn(account_id),
            RoleSessionName=f"aws-gap-check-verify-{conn_id}",
            ExternalId=conn["externalId"],
            DurationSeconds=900,
        )
        # 임시 자격 증명은 쓰지 않고 버린다. STS가 돌려준 ARN으로 계정만 확인한다.
        assumed_account = response["AssumedRoleUser"]["Arn"].split(":")[4]
        ok = assumed_account == account_id
        message = "" if ok else "Role이 입력한 계정에 있지 않습니다."
    except Exception as err:
        if error_code(err) not in ("AccessDenied", "AccessDeniedException"):
            raise
        ok, message = False, DENIED_MESSAGE
    fields = {"accountId": account_id, "status": "ACTIVE" if ok else "FAILED",
              "message": message, "verifiedAt": iso(now) if ok else None}
    store.update_connection(sub, conn_id, fields)
    conn.update(fields)
    return conn


def delete(store, sub: str, conn_id: str) -> None:
    get(store, sub, conn_id)
    store.delete_connection(sub, conn_id)
