"""Gemini API 호출부. 모델을 바꿀 때는 이 파일만 바꾼다.

표준 라이브러리 urllib로 REST API를 부른다(새 의존성 없음). API 키는 URL이 아니라
`x-goog-api-key` 헤더로만 보내고, 예외 메시지에는 넣지 않는다.

CloudShell의 python3(3.9일 수 있음)에서도 돌아야 하므로 3.10 이후 문법은 쓰지 않는다.
"""
from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request

API_BASE = "https://generativelanguage.googleapis.com/v1beta"
DEFAULT_TIMEOUT = 30
# 표준 JSON Schema를 받는 필드. 동작은 T0.2 스파이크에서 확인한다.
SCHEMA_FIELD = "responseJsonSchema"

_MAX_ERROR_TEXT = 300
_BLOCK_REASONS = {
    "SAFETY", "BLOCKLIST", "PROHIBITED_CONTENT", "SPII", "RECITATION", "IMAGE_SAFETY",
}
_RETRY_DELAY = re.compile(r"([0-9]+(?:\.[0-9]+)?)s")


class LLMError(Exception):
    """모델 호출 실패. 메시지에 API 키가 들어가지 않는다."""


class RateLimited(LLMError):
    """429 응답. retry_after는 서버가 알려 준 대기 시간(초)이고, 없으면 None."""

    def __init__(self, retry_after: float | None = None):
        super().__init__("rate limited")
        self.retry_after = retry_after


class BlockedResponse(LLMError):
    """안전 필터 등으로 응답이 차단됨."""


class InvalidResponse(LLMError):
    """응답이 잘렸거나 JSON 객체가 아님."""


def generate_json(system: str, user: str, schema: dict, *, model: str, api_key: str,
                  timeout: float = DEFAULT_TIMEOUT, max_output_tokens: int = 8192,
                  opener=urllib.request.urlopen) -> dict:
    """프롬프트를 보내고 schema에 맞춘 JSON 객체를 돌려준다.

    모델이 스키마를 지켰는지는 검증하지 않는다. 호출하는 쪽에서 다시 검증한다.
    """
    model = model[len("models/"):] if model.startswith("models/") else model
    body = {
        "systemInstruction": {"parts": [{"text": system}]},
        "contents": [{"role": "user", "parts": [{"text": user}]}],
        "generationConfig": {
            "responseMimeType": "application/json",
            SCHEMA_FIELD: schema,
            "temperature": 0.2,
            "maxOutputTokens": max_output_tokens,
        },
    }
    request = urllib.request.Request(
        f"{API_BASE}/models/{urllib.parse.quote(model)}:generateContent",
        data=json.dumps(body, ensure_ascii=False).encode("utf-8"),
        headers={**_headers(api_key), "Content-Type": "application/json"},
        method="POST",
    )
    return _parse_candidate(_send(request, api_key, timeout, opener))


def list_models(api_key: str, *, timeout: float = DEFAULT_TIMEOUT,
                opener=urllib.request.urlopen) -> list:
    """키로 쓸 수 있는 모델 목록. 각 항목은 API가 준 dict 그대로다."""
    models = []
    page_token = ""
    while True:
        query = {"pageSize": "1000"}
        if page_token:
            query["pageToken"] = page_token
        request = urllib.request.Request(
            f"{API_BASE}/models?{urllib.parse.urlencode(query)}",
            headers=_headers(api_key),
            method="GET",
        )
        payload = _send(request, api_key, timeout, opener)
        models.extend(payload.get("models", []))
        page_token = payload.get("nextPageToken", "")
        if not page_token:
            return models


def _headers(api_key: str) -> dict:
    return {"x-goog-api-key": api_key}


def _send(request, api_key: str, timeout: float, opener) -> dict:
    # 원래 예외를 연결하지 않는다(from None). 트레이스백에 요청 정보가 남지 않게 한다.
    try:
        with opener(request, timeout=timeout) as response:
            raw = response.read()
    except urllib.error.HTTPError as err:
        error_body = _read_error_body(err)
        if err.code == 429:
            raise RateLimited(_retry_after(error_body)) from None
        message = (error_body.get("error") or {}).get("message", "")
        raise LLMError(_redact(f"HTTP {err.code}: {message}", api_key)) from None
    except (urllib.error.URLError, OSError) as err:
        raise LLMError(f"network error: {type(err).__name__}") from None
    try:
        return json.loads(raw)
    except ValueError:
        raise InvalidResponse("API 응답이 JSON이 아님") from None


def _parse_candidate(payload: dict) -> dict:
    block_reason = (payload.get("promptFeedback") or {}).get("blockReason")
    if block_reason:
        raise BlockedResponse(f"prompt blocked: {block_reason}")
    candidates = payload.get("candidates") or []
    if not candidates:
        raise InvalidResponse("후보 응답이 없음")
    candidate = candidates[0]
    finish_reason = candidate.get("finishReason", "STOP")
    if finish_reason in _BLOCK_REASONS:
        raise BlockedResponse(f"finishReason={finish_reason}")
    if finish_reason != "STOP":
        raise InvalidResponse(f"finishReason={finish_reason}")
    parts = (candidate.get("content") or {}).get("parts") or []
    text = "".join(part.get("text", "") for part in parts if not part.get("thought"))
    try:
        result = json.loads(text)
    except ValueError:
        raise InvalidResponse("응답이 JSON이 아님") from None
    if not isinstance(result, dict):
        raise InvalidResponse("응답이 JSON 객체가 아님")
    return result


def _read_error_body(err: urllib.error.HTTPError) -> dict:
    try:
        body = json.loads(err.read())
    except (ValueError, OSError):
        return {}
    return body if isinstance(body, dict) else {}


def _retry_after(error_body: dict):
    for detail in (error_body.get("error") or {}).get("details") or []:
        if str(detail.get("@type", "")).endswith("RetryInfo"):
            match = _RETRY_DELAY.fullmatch(str(detail.get("retryDelay", "")))
            if match:
                return float(match.group(1))
    return None


def _redact(text: str, api_key: str) -> str:
    if api_key:
        text = text.replace(api_key, "***")
    return text[:_MAX_ERROR_TEXT]
