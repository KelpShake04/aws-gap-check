"""MySQL 저장소. 메서드 이름은 DynamoDB 저장소(store.py)와 같아서 connections·scans 모듈을 그대로 쓴다.

사용자 데이터 쿼리에는 항상 user_id 조건이 들어간다(IDOR 방지). 사용자 구분 없이 읽는 쿼리는
작업자 큐(next_queued_scan)와 보존 기간 정리(purge)뿐이다.
열 이름은 아래 고정 표에서만 가져오고 값은 모두 파라미터로 넘긴다(SQL 인젝션 방지).
스키마는 db/init/01-schema.sql.
"""
from __future__ import annotations

import json
import ssl
from datetime import timezone

from .common import iso, parse_iso

TIME, JSON, BOOL = "time", "json", "bool"

CONNECTION = {"id": "id", "externalId": "external_id", "accountId": "account_id",
              "status": "status", "message": "message",
              "createdAt": ("created_at", TIME), "verifiedAt": ("verified_at", TIME)}
SCAN = {"id": "id", "connectionId": "connection_id", "accountId": "account_id", "status": "status",
        "counts": ("counts", JSON), "summary": ("summary", JSON), "error": "error",
        "createdAt": ("created_at", TIME), "updatedAt": ("updated_at", TIME),
        "expiresAt": "expires_at"}
FINDING = {"checkId": "check_id", "rank": "severity_rank", "severity": "severity", "title": "title",
           "service": "service", "resourceType": "resource_type", "description": "description",
           "risk": "risk", "recommendation": "recommendation",
           "references": ("reference_urls", JSON), "resources": ("resources", JSON),
           "regions": ("regions", JSON), "totalCount": "total_count",
           "explanation": ("explanation", JSON), "explainSource": "explain_source",
           "expiresAt": "expires_at"}
USER = {"id": "id", "email": "email", "passwordHash": "password_hash",
        "mustChangePassword": ("must_change_password", BOOL), "failedLogins": "failed_logins",
        "lockedUntil": ("locked_until", TIME), "createdAt": ("created_at", TIME)}


def connector(*, host: str, port: int, user: str, password: str, database: str):
    """요청마다 새 연결을 여는 함수를 돌려준다(PyMySQL 연결은 스레드끼리 나눠 쓰면 안 된다)."""
    import pymysql
    from pymysql.constants import CLIENT

    # shortcut: 같은 호스트의 Docker 네트워크 안이라 인증서는 검증하지 않는다. TLS는 MySQL 8.4 기본 인증
    # (caching_sha2_password)이 추가 패키지 없이 동작하게 하려고 켠다. DB를 다른 호스트로 옮기면 CA를 검증한다.
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    def connect():
        return pymysql.connect(
            host=host, port=port, user=user, password=password, database=database,
            charset="utf8mb4", autocommit=True, ssl=context, connect_timeout=5,
            read_timeout=30, write_timeout=30, cursorclass=pymysql.cursors.DictCursor,
            # UPDATE 결과를 "바뀐 행"이 아니라 "조건에 맞은 행"으로 센다(같은 값으로 고쳐도 True)
            client_flag=CLIENT.FOUND_ROWS,
        )
    return connect


class Store:
    def __init__(self, connect):
        self._connect = connect

    # 사용자와 세션
    def create_user(self, user: dict) -> None:
        self._insert("users", USER, user)

    def get_user(self, user_id: str):
        return self._one("users", USER, "id = %s", (user_id,))

    def get_user_by_email(self, email: str):
        return self._one("users", USER, "email = %s", (email,))

    def update_user(self, user_id: str, fields: dict) -> bool:
        return self._update("users", USER, fields, "id = %s", (user_id,))

    def put_session(self, token_hash: str, user_id: str, created_at: str, expires_at: str) -> None:
        self._execute("INSERT INTO sessions (token_hash, user_id, created_at, expires_at) "
                      "VALUES (%s, %s, %s, %s)",
                      (token_hash, user_id, _to_db(created_at, TIME), _to_db(expires_at, TIME)))

    def get_session_user(self, token_hash: str, now: str):
        rows = self._execute(
            f"SELECT {_columns(USER, 'u.')} FROM sessions s JOIN users u ON u.id = s.user_id "
            "WHERE s.token_hash = %s AND s.expires_at > %s", (token_hash, _to_db(now, TIME)))
        return _from_row(USER, rows[0]) if rows else None

    def delete_session(self, token_hash: str) -> None:
        self._execute("DELETE FROM sessions WHERE token_hash = %s", (token_hash,))

    def delete_user_sessions(self, user_id: str) -> None:
        self._execute("DELETE FROM sessions WHERE user_id = %s", (user_id,))

    # 연결
    def put_connection(self, sub: str, conn: dict) -> None:
        self._insert("connections", CONNECTION, conn, sub)

    def get_connection(self, sub: str, conn_id: str):
        return self._one("connections", CONNECTION, "user_id = %s AND id = %s", (sub, conn_id))

    def list_connections(self, sub: str) -> list:
        return self._many("connections", CONNECTION, "user_id = %s", (sub,), "created_at, id")

    def update_connection(self, sub: str, conn_id: str, fields: dict) -> bool:
        return self._update("connections", CONNECTION, fields, "user_id = %s AND id = %s", (sub, conn_id))

    def delete_connection(self, sub: str, conn_id: str) -> None:
        self._execute("DELETE FROM connections WHERE user_id = %s AND id = %s", (sub, conn_id))

    # 스캔
    def put_scan(self, sub: str, scan: dict) -> None:
        self._insert("scans", SCAN, scan, sub)

    def get_scan(self, sub: str, scan_id: str):
        return self._one("scans", SCAN, "user_id = %s AND id = %s", (sub, scan_id))

    def list_scans(self, sub: str) -> list:
        # 스캔 ID는 시각으로 시작해서 ID 역순이 곧 최신순이다
        return self._many("scans", SCAN, "user_id = %s", (sub,), "id DESC")

    def update_scan(self, sub: str, scan_id: str, fields: dict) -> bool:
        return self._update("scans", SCAN, fields, "user_id = %s AND id = %s", (sub, scan_id))

    def claim_scan(self, sub: str, scan_id: str, from_statuses: tuple, fields: dict) -> bool:
        """상태가 from_statuses 중 하나일 때만 바꾼다. 같은 스캔을 두 번 처리하지 않게 한다."""
        marks = ", ".join(["%s"] * len(from_statuses))
        return self._update("scans", SCAN, fields, f"user_id = %s AND id = %s AND status IN ({marks})",
                            (sub, scan_id, *from_statuses))

    # 결과(check 단위)
    def put_findings(self, sub: str, scan_id: str, groups: list, expires: int) -> None:
        if not groups:
            return
        rows = [_finding_row(sub, scan_id, group, expires) for group in groups]
        sql = _upsert_sql("findings", list(rows[0]))
        with self._connect() as conn:
            conn.begin()
            with conn.cursor() as cursor:
                cursor.executemany(sql, [tuple(row.values()) for row in rows])
            conn.commit()

    def put_finding(self, sub: str, scan_id: str, group: dict, expires: int) -> None:
        row = _finding_row(sub, scan_id, group, expires)
        self._execute(_upsert_sql("findings", list(row)), tuple(row.values()))

    def list_findings(self, sub: str, scan_id: str) -> list:
        # findings.parse와 같은 순서: 심각도, 영향받는 리소스가 많은 순, check ID
        return self._many("findings", FINDING, "user_id = %s AND scan_id = %s", (sub, scan_id),
                          "severity_rank, total_count DESC, check_id")

    def delete_findings(self, sub: str, scan_id: str) -> None:
        self._execute("DELETE FROM findings WHERE user_id = %s AND scan_id = %s", (sub, scan_id))

    # 해설 캐시 (고객 데이터가 없는 일반 해설이라 사용자 사이에 공유)
    def get_explanation(self, check_id: str, version: str, model: str):
        rows = self._execute("SELECT explanation FROM explanations "
                             "WHERE check_id = %s AND prompt_version = %s AND model = %s",
                             (check_id, version, model))
        return json.loads(rows[0]["explanation"]) if rows else None

    def put_explanation(self, check_id: str, version: str, model: str, explanation: dict) -> None:
        row = {"check_id": check_id, "prompt_version": version, "model": model,
               "explanation": _to_db(explanation, JSON)}
        self._execute(_upsert_sql("explanations", list(row)), tuple(row.values()))

    # 작업자 전용 (사용자 구분 없이 읽는다)
    def next_queued_scan(self):
        """가장 오래된 QUEUED 스캔의 (user_id, scan). 없으면 None."""
        rows = self._execute(f"SELECT user_id, {_columns(SCAN)} FROM scans WHERE status = 'QUEUED' "
                             "ORDER BY id LIMIT 1", ())
        return (rows[0]["user_id"], _from_row(SCAN, rows[0])) if rows else None

    def fail_scans(self, statuses: tuple, fields: dict) -> int:
        """서버가 재시작돼 중단된 스캔을 한꺼번에 실패로 바꾼다."""
        marks = ", ".join(["%s"] * len(statuses))
        assignments, values = _assignments(SCAN, fields)
        with self._connect() as conn, conn.cursor() as cursor:
            return cursor.execute(f"UPDATE scans SET {assignments} WHERE status IN ({marks})",
                                  (*values, *statuses))

    def expired_scans(self, now_epoch: int) -> list:
        rows = self._execute("SELECT user_id, id FROM scans WHERE expires_at < %s", (now_epoch,))
        return [(row["user_id"], row["id"]) for row in rows]

    def purge(self, now_epoch: int, now: str) -> None:
        """보존 기간이 지난 스캔(결과는 외래키로 같이 삭제)과 만료된 세션을 지운다."""
        self._execute("DELETE FROM scans WHERE expires_at < %s", (now_epoch,))
        self._execute("DELETE FROM sessions WHERE expires_at < %s", (_to_db(now, TIME),))

    # 내부
    def _execute(self, sql: str, params: tuple) -> list:
        with self._connect() as conn, conn.cursor() as cursor:
            cursor.execute(sql, params)
            return list(cursor.fetchall())

    def _insert(self, table: str, fields: dict, item: dict, sub: str = None) -> None:
        row = _to_row(fields, item)
        if sub is not None:
            row = {"user_id": sub, **row}
        names = ", ".join(f"`{name}`" for name in row)
        marks = ", ".join(["%s"] * len(row))
        self._execute(f"INSERT INTO {table} ({names}) VALUES ({marks})", tuple(row.values()))

    def _one(self, table: str, fields: dict, where: str, params: tuple):
        rows = self._execute(f"SELECT {_columns(fields)} FROM {table} WHERE {where}", params)
        return _from_row(fields, rows[0]) if rows else None

    def _many(self, table: str, fields: dict, where: str, params: tuple, order: str) -> list:
        rows = self._execute(f"SELECT {_columns(fields)} FROM {table} WHERE {where} ORDER BY {order}",
                             params)
        return [_from_row(fields, row) for row in rows]

    def _update(self, table: str, fields: dict, item: dict, where: str, params: tuple) -> bool:
        """있는 행만 고친다. 없으면 False."""
        assignments, values = _assignments(fields, item)
        with self._connect() as conn, conn.cursor() as cursor:
            return cursor.execute(f"UPDATE {table} SET {assignments} WHERE {where}",
                                  (*values, *params)) > 0


def _spec(fields: dict, key: str):
    spec = fields[key]  # 표에 없는 키면 KeyError: 오타가 조용히 무시되지 않게 한다
    return spec if isinstance(spec, tuple) else (spec, None)


def _columns(fields: dict, prefix: str = "") -> str:
    return ", ".join(f"{prefix}`{_spec(fields, key)[0]}`" for key in fields)


def _to_row(fields: dict, item: dict) -> dict:
    row = {}
    for key, value in item.items():
        column, kind = _spec(fields, key)
        row[column] = _to_db(value, kind)
    return row


def _from_row(fields: dict, row: dict) -> dict:
    item = {}
    for key in fields:
        column, kind = _spec(fields, key)
        item[key] = _from_db(row[column], kind)
    return item


def _assignments(fields: dict, item: dict):
    row = _to_row(fields, item)
    return ", ".join(f"`{column}` = %s" for column in row), tuple(row.values())


def _finding_row(sub: str, scan_id: str, group: dict, expires: int) -> dict:
    return {"user_id": sub, "scan_id": scan_id, **_to_row(FINDING, {**group, "expiresAt": expires})}


def _upsert_sql(table: str, columns: list) -> str:
    names = ", ".join(f"`{name}`" for name in columns)
    marks = ", ".join(["%s"] * len(columns))
    updates = ", ".join(f"`{name}` = new.`{name}`" for name in columns)
    return f"INSERT INTO {table} ({names}) VALUES ({marks}) AS new ON DUPLICATE KEY UPDATE {updates}"


def _to_db(value, kind):
    if value is None:
        return None
    if kind == TIME:
        return parse_iso(value).replace(tzinfo=None)
    if kind == JSON:
        return json.dumps(value, ensure_ascii=False)
    if kind == BOOL:
        return 1 if value else 0
    return value


def _from_db(value, kind):
    if value is None:
        return None
    if kind == TIME:
        return iso(value.replace(tzinfo=timezone.utc))
    if kind == JSON:
        return json.loads(value)
    if kind == BOOL:
        return bool(value)
    return value
