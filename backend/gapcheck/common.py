"""여러 모듈이 같이 쓰는 오류 타입과 시간 함수."""
from __future__ import annotations

from datetime import datetime, timezone

RETENTION_SECONDS = 30 * 24 * 3600


class ApiError(Exception):
    """사용자에게 그대로 보여 줄 수 있는 오류. 내부 정보(ARN, 스택 트레이스)를 넣지 않는다."""

    status = 500
    code = "internal"

    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


class BadRequest(ApiError):
    status, code = 400, "bad_request"


class Unauthorized(ApiError):
    status, code = 401, "unauthorized"


class Forbidden(ApiError):
    status, code = 403, "forbidden"


class NotFound(ApiError):
    status, code = 404, "not_found"


class Conflict(ApiError):
    status, code = 409, "conflict"


class TooMany(ApiError):
    status, code = 429, "too_many"


class Unavailable(ApiError):
    status, code = 503, "unavailable"


def error_code(err: Exception) -> str:
    """botocore ClientError의 오류 코드. botocore를 import하지 않고 읽는다."""
    response = getattr(err, "response", None) or {}
    return (response.get("Error") or {}).get("Code", "")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(text: str) -> datetime:
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def expires_at(moment: datetime) -> int:
    return int(moment.timestamp()) + RETENTION_SECONDS
