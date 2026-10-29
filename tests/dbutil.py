"""실제 MySQL에 붙는 테스트용 도우미. scripts/test_with_db.sh가 TEST_DB_* 환경 변수를 넣어 준다."""
import os
import unittest

from gapcheck.db import Store, connector

TABLES = ("findings", "scans", "connections", "sessions", "users", "explanations")


def fresh_store() -> Store:
    port = os.environ.get("TEST_DB_PORT")
    if not port:
        raise unittest.SkipTest("MySQL 없음: scripts/test_with_db.sh로 실행하세요")
    store = Store(connector(host=os.environ.get("TEST_DB_HOST", "127.0.0.1"), port=int(port),
                            user="gapcheck", password=os.environ["TEST_DB_PASSWORD"],
                            database="gapcheck"))
    for table in TABLES:
        store._execute(f"DELETE FROM {table}", ())
    return store


def add_user(store, user_id: str, email: str = None) -> None:
    store.create_user({"id": user_id, "email": email or f"{user_id[:8]}@example.com",
                       "passwordHash": "x", "mustChangePassword": False, "failedLogins": 0,
                       "lockedUntil": None, "createdAt": "2026-10-28T00:00:00Z"})
