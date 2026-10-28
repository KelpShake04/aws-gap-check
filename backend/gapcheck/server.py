"""HTTP 서버(표준 라이브러리 ThreadingHTTPServer): 화면 정적 파일과 /api/*.

- 사용자 식별은 세션 쿠키로만 한다. 경로나 본문의 값으로 다른 사용자의 데이터를 고를 수 없다.
- 쿠키는 HttpOnly·Secure·SameSite=Strict. 상태를 바꾸는 요청(POST, DELETE)은 X-Requested-With
  헤더를 요구한다(다른 사이트의 폼이나 단순 요청으로는 이 헤더를 붙일 수 없다: CSRF 방지).
- 정적 파일은 정해진 목록만 제공한다(경로 조작 방지).
- 오류 응답에는 내부 정보를 넣지 않는다. 자세한 내용은 서버 로그에만 남긴다.
"""
from __future__ import annotations

import json
import logging
import pathlib
import re
from dataclasses import dataclass, field
from http.cookies import CookieError, SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable
from urllib.parse import urlsplit

from . import auth, connections, scans
from .common import ApiError, BadRequest, Forbidden, Unauthorized, utcnow
from .views import TEMPLATE_PATH, conn_view, finding_view, scan_view, setup_info

logger = logging.getLogger(__name__)

MAX_BODY_BYTES = 16 * 1024
COOKIE = "agc_session"
CSRF_HEADER, CSRF_VALUE = "X-Requested-With", "gapcheck"
REGION = "ap-northeast-2"
SECURITY_HEADERS = {
    "Content-Security-Policy": ("default-src 'none'; script-src 'self'; style-src 'self'; "
                                "img-src 'self'; connect-src 'self'; base-uri 'none'; "
                                "form-action 'self'; frame-ancestors 'none'"),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
}
STATIC_FILES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/api.js": ("api.js", "text/javascript; charset=utf-8"),
    "/auth.js": ("auth.js", "text/javascript; charset=utf-8"),
    "/style.css": ("style.css", "text/css; charset=utf-8"),
}


@dataclass
class Deps:
    store: Any
    sts: Any
    worker: Any  # wake(Event), remove_raw(sub, scan_id)
    service_account_id: str
    daily_limit: int
    frontend_dir: pathlib.Path
    template_file: pathlib.Path
    demo: bool = False
    now: Callable = utcnow


@dataclass
class Call:
    deps: Deps
    user: Any
    token: Any
    args: tuple
    body: Callable
    cookie: Any = field(default=None)  # 응답에 붙일 Set-Cookie 값


# ---------- 로그인 ----------
def login(call):
    data = call.body()
    token, user = auth.login(call.deps.store, data.get("email"), data.get("password"), call.deps.now())
    call.cookie = _session_cookie(token)
    return 200, me_view(call.deps, user)


def logout(call):
    auth.logout(call.deps.store, call.token)
    call.cookie = _session_cookie("", max_age=0)
    return 204, None


def me(call):
    return 200, me_view(call.deps, call.user)


def change_password(call):
    data = call.body()
    token = auth.change_password(call.deps.store, call.user, data.get("currentPassword"),
                                 data.get("newPassword"), call.deps.now())
    call.cookie = _session_cookie(token)
    return 200, me_view(call.deps, {**call.user, "mustChangePassword": False})


def me_view(deps, user: dict) -> dict:
    return {"email": user["email"], "mustChangePassword": user["mustChangePassword"],
            "demo": deps.demo, "region": REGION}


# ---------- 계정 연결 ----------
def create_connection(call):
    conn = connections.create(call.deps.store, call.user["id"], call.deps.now())
    return 201, {"connection": conn_view(conn), "setup": setup_info(call.deps)}


def list_connections(call):
    items = call.deps.store.list_connections(call.user["id"])
    return 200, {"connections": [conn_view(c) for c in items], "setup": setup_info(call.deps)}


def verify_connection(call):
    conn = connections.verify(call.deps.store, call.deps.sts, call.user["id"], call.args[0],
                              call.body().get("accountId"), call.deps.now())
    return 200, {"connection": conn_view(conn)}


def delete_connection(call):
    connections.delete(call.deps.store, call.user["id"], call.args[0])
    return 204, None


# ---------- 스캔 ----------
def start_scan(call):
    scan, _ = scans.create(call.deps.store, call.user["id"], str(call.body().get("connectionId", "")),
                           now=call.deps.now(), daily_limit=call.deps.daily_limit)
    call.deps.worker.wake.set()
    return 202, {"scan": scan_view(scan)}


def list_scans(call):
    return 200, {"scans": [scan_view(s) for s in call.deps.store.list_scans(call.user["id"])
                           if s.get("status") != scans.DELETED]}


def get_scan(call):
    sub = call.user["id"]
    scan = scans.get(call.deps.store, sub, call.args[0])
    groups = call.deps.store.list_findings(sub, scan["id"])
    return 200, {"scan": scan_view(scan), "findings": [finding_view(g) for g in groups]}


def delete_scan(call):
    sub, scan_id = call.user["id"], call.args[0]
    scans.discard(call.deps.store, sub, scan_id, now=call.deps.now(),
                  remove_raw=lambda: call.deps.worker.remove_raw(sub, scan_id))
    return 204, None


# 접근 수준: public(로그인 불필요), session(비밀번호 변경 전에도 허용), user(일반)
ROUTES = [
    ("POST", r"/api/login", login, "public"),
    ("POST", r"/api/logout", logout, "public"),
    ("GET", r"/api/me", me, "session"),
    ("POST", r"/api/password", change_password, "session"),
    ("GET", r"/api/connections", list_connections, "user"),
    ("POST", r"/api/connections", create_connection, "user"),
    ("POST", r"/api/connections/([^/]+)/verify", verify_connection, "user"),
    ("DELETE", r"/api/connections/([^/]+)", delete_connection, "user"),
    ("GET", r"/api/scans", list_scans, "user"),
    ("POST", r"/api/scans", start_scan, "user"),
    ("GET", r"/api/scans/([^/]+)", get_scan, "user"),
    ("DELETE", r"/api/scans/([^/]+)", delete_scan, "user"),
]


def _session_cookie(token: str, max_age: int = int(auth.SESSION_LIFETIME.total_seconds())) -> str:
    return f"{COOKIE}={token}; Path=/; Max-Age={max_age}; HttpOnly; Secure; SameSite=Strict"


class Handler(BaseHTTPRequestHandler):
    deps: Deps = None
    server_version = "aws-gap-check"
    sys_version = ""
    timeout = 30  # 느리게 보내는 연결이 스레드를 오래 붙잡지 못하게 한다

    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    def do_DELETE(self):
        self._dispatch("DELETE")

    def _dispatch(self, method: str) -> None:
        path = urlsplit(self.path).path
        try:
            if path.startswith("/api/"):
                self._api(method, path)
            elif method == "GET" and path in STATIC_FILES:
                name, content_type = STATIC_FILES[path]
                self._send(200, (self.deps.frontend_dir / name).read_bytes(), content_type, "no-cache")
            elif method == "GET" and path == TEMPLATE_PATH:
                self._send(200, self.deps.template_file.read_bytes(), "text/yaml; charset=utf-8", "no-cache")
            else:
                self._error(404, "not_found", "없는 경로입니다.")
        except Exception:
            logger.exception("unhandled error on %s %s", method, path)
            self._error(500, "internal", "서버 오류가 발생했습니다.")

    def _api(self, method: str, path: str) -> None:
        for route_method, pattern, handler, level in ROUTES:
            match = re.fullmatch(pattern, path)
            if match and route_method == method:
                break
        else:
            self._error(404, "not_found", "없는 경로입니다.")
            return
        call = Call(self.deps, None, self._token(), match.groups(), self._body)
        try:
            if method != "GET" and self.headers.get(CSRF_HEADER) != CSRF_VALUE:
                raise Forbidden("요청을 확인할 수 없습니다. 페이지를 새로 고친 뒤 다시 시도하세요.")
            if level != "public":
                call.user = auth.session_user(self.deps.store, call.token, self.deps.now())
                if call.user is None:
                    raise Unauthorized("로그인이 필요합니다.")
                if level == "user" and call.user["mustChangePassword"]:
                    raise Forbidden("먼저 비밀번호를 바꾸세요.")
            status, payload = handler(call)
        except ApiError as err:
            self._error(err.status, err.code, err.message,
                        cookie=_session_cookie("", max_age=0) if err.status == 401 else None)
            return
        body = b"" if payload is None else json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self._send(status, body, "application/json; charset=utf-8", "no-store", call.cookie)

    def _token(self):
        try:
            morsel = SimpleCookie(self.headers.get("Cookie", "")).get(COOKIE)
        except CookieError:
            return None
        return morsel.value if morsel else None

    def _body(self) -> dict:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            raise BadRequest("요청 길이가 올바르지 않습니다.") from None
        if length < 0 or length > MAX_BODY_BYTES:
            raise BadRequest("요청 본문이 너무 큽니다.")
        try:
            data = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
        except ValueError:
            raise BadRequest("요청 본문이 JSON이 아닙니다.") from None
        if not isinstance(data, dict):
            raise BadRequest("요청 본문은 JSON 객체여야 합니다.")
        return data

    def _error(self, status: int, code: str, message: str, cookie: str = None) -> None:
        body = json.dumps({"error": code, "message": message}, ensure_ascii=False).encode("utf-8")
        self._send(status, body, "application/json; charset=utf-8", "no-store", cookie)

    def _send(self, status: int, body: bytes, content_type: str, cache: str, cookie: str = None) -> None:
        self.send_response(status)
        for name, value in SECURITY_HEADERS.items():
            self.send_header(name, value)
        self.send_header("Cache-Control", cache)
        if cookie:
            self.send_header("Set-Cookie", cookie)
        if status != 204:
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if status != 204:
            self.wfile.write(body)

    def log_message(self, format, *args):
        logger.info("%s %s", self.address_string(), format % args)


def make_server(deps: Deps, host: str, port: int) -> ThreadingHTTPServer:
    handler = type("BoundHandler", (Handler,), {"deps": deps})
    return ThreadingHTTPServer((host, port), handler)
