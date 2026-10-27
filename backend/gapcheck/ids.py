"""ID 생성과 입력 형식 검증.

scanner/run_scan.py에도 같은 패턴이 있다(CodeBuild에 따로 배포됨). tests/test_ids.py가 둘을 비교한다.
"""
from __future__ import annotations

import re
import secrets
from datetime import datetime

# 고객 템플릿(infra/customer-role.yaml)의 RoleName과 같아야 한다
ROLE_NAME = "AwsGapCheckReadOnlyRole"

# \d는 유니코드 숫자도 받으므로 [0-9]를 쓴다
PATTERNS = {
    "account": r"[0-9]{12}",
    "external_id": r"agc-[0-9a-f]{32}",
    "connection": r"[0-9a-f]{16}",
    "scan": r"[0-9]{14}-[0-9a-f]{8}",
    "sub": r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
}


def valid(kind: str, value) -> bool:
    return isinstance(value, str) and re.fullmatch(PATTERNS[kind], value) is not None


def new_external_id() -> str:
    return "agc-" + secrets.token_hex(16)


def new_connection_id() -> str:
    return secrets.token_hex(8)


def new_scan_id(now: datetime) -> str:
    """UTC 시각 + 랜덤. 문자열 정렬이 곧 시간순이고, 앞 8자리로 날짜별 개수를 센다."""
    return now.strftime("%Y%m%d%H%M%S") + "-" + secrets.token_hex(4)


def role_arn(account_id: str) -> str:
    if not valid("account", account_id):
        raise ValueError("account id must be 12 digits")
    return f"arn:aws:iam::{account_id}:role/{ROLE_NAME}"
