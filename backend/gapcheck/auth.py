"""앱 자체 로그인: 비밀번호 해시(scrypt), 세션 토큰, 로그인 시도 제한.

- 비밀번호는 hashlib.scrypt(n=2^14, r=8, p=1)와 사용자별 salt로 해시한다.
- 세션 토큰은 32바이트 난수이고, DB에는 SHA-256만 저장한다.
- 같은 계정에 5번 틀리면 15분 동안 잠근다. 응답 문구와 처리 시간은 없는 이메일, 틀린 비밀번호,
  잠긴 계정이 모두 같아서 계정이 있는지 알아낼 수 없다.
"""
from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import threading
import uuid
from datetime import datetime, timedelta

from .common import BadRequest, Unauthorized, iso, parse_iso

SCRYPT_N, SCRYPT_R, SCRYPT_P = 2 ** 14, 8, 1
SESSION_LIFETIME = timedelta(hours=12)
MAX_FAILURES = 5
LOCK_TIME = timedelta(minutes=15)
MIN_PASSWORD, MAX_PASSWORD = 10, 128
# scrypt 한 번에 메모리 16MB를 쓴다. 로그인 요청이 몰려도 인스턴스 메모리가 바닥나지 않게 동시 계산 수를 묶는다.
_SCRYPT_SLOTS = threading.BoundedSemaphore(4)
LOGIN_FAILED = "이메일 또는 비밀번호가 맞지 않습니다. 5번 틀리면 15분 동안 로그인할 수 없습니다."

_EMAIL = re.compile(r"[^@\s]{1,64}@[^@\s]+\.[^@\s]+")
_TOKEN = re.compile(r"[A-Za-z0-9_-]{43}")


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = _scrypt(password, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P)
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        kind, n, r, p, salt, digest = stored.split("$")
        if kind != "scrypt":
            return False
        candidate = _scrypt(password, bytes.fromhex(salt), int(n), int(r), int(p))
    except ValueError:
        return False
    return hmac.compare_digest(candidate, bytes.fromhex(digest))


def _scrypt(password: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    with _SCRYPT_SLOTS:
        return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=32)


# 없는 이메일에도 같은 시간만큼 해시를 계산하려고 쓰는 값
_DUMMY_HASH = hash_password(secrets.token_hex(16))


def normalize_email(value) -> str:
    """형식이 맞으면 소문자 이메일, 아니면 빈 문자열."""
    if not isinstance(value, str):
        return ""
    email = value.strip().lower()
    return email if len(email) <= 254 and _EMAIL.fullmatch(email) else ""


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def create_user(store, email: str, now: datetime):
    """(user, 임시 비밀번호)를 돌려준다. 첫 로그인 때 비밀번호를 바꿔야 한다."""
    email = normalize_email(email)
    if not email:
        raise BadRequest("이메일 형식이 올바르지 않습니다.")
    password = secrets.token_urlsafe(12)
    user = {"id": str(uuid.uuid4()), "email": email, "passwordHash": hash_password(password),
            "mustChangePassword": True, "failedLogins": 0, "lockedUntil": None, "createdAt": iso(now)}
    store.create_user(user)
    return user, password


def login(store, email, password, now: datetime):
    """(세션 토큰, user)를 돌려준다. 실패는 모두 같은 Unauthorized다."""
    email = normalize_email(email)
    user = store.get_user_by_email(email) if email else None
    if not isinstance(password, str) or len(password) > MAX_PASSWORD:
        password = ""
    locked = bool(user and user["lockedUntil"] and parse_iso(user["lockedUntil"]) > now)
    usable = user is not None and not locked
    ok = verify_password(password, user["passwordHash"] if usable else _DUMMY_HASH) and usable
    if not ok:
        if usable:
            failures = user["failedLogins"] + 1
            fields = {"failedLogins": failures}
            if failures >= MAX_FAILURES:
                fields = {"failedLogins": 0, "lockedUntil": iso(now + LOCK_TIME)}
            store.update_user(user["id"], fields)
        raise Unauthorized(LOGIN_FAILED)
    if user["failedLogins"] or user["lockedUntil"]:
        store.update_user(user["id"], {"failedLogins": 0, "lockedUntil": None})
    return new_session(store, user["id"], now), user


def new_session(store, user_id: str, now: datetime) -> str:
    token = secrets.token_urlsafe(32)
    store.put_session(token_hash(token), user_id, iso(now), iso(now + SESSION_LIFETIME))
    return token


def session_user(store, token, now: datetime):
    if not isinstance(token, str) or not _TOKEN.fullmatch(token):
        return None
    return store.get_session_user(token_hash(token), iso(now))


def logout(store, token) -> None:
    if isinstance(token, str) and _TOKEN.fullmatch(token):
        store.delete_session(token_hash(token))


def change_password(store, user: dict, current, new, now: datetime) -> str:
    """비밀번호를 바꾸고 다른 세션을 모두 끊은 뒤 새 세션 토큰을 돌려준다."""
    stored = store.get_user(user["id"])
    if not isinstance(current, str) or not verify_password(current[:MAX_PASSWORD], stored["passwordHash"]):
        raise BadRequest("현재 비밀번호가 맞지 않습니다.")
    if not isinstance(new, str) or not MIN_PASSWORD <= len(new) <= MAX_PASSWORD:
        raise BadRequest(f"새 비밀번호는 {MIN_PASSWORD}~{MAX_PASSWORD}자여야 합니다.")
    if new == current:
        raise BadRequest("새 비밀번호가 현재 비밀번호와 같습니다.")
    store.update_user(user["id"], {"passwordHash": hash_password(new), "mustChangePassword": False})
    store.delete_user_sessions(user["id"])
    return new_session(store, user["id"], now)
