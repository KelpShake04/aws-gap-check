"""HTTP 서버·로그인·스캔 작업자 테스트. 실제 MySQL과 hashlib.scrypt가 필요하다(scripts/test_with_db.sh)."""
import hashlib
import http.client
import json
import pathlib
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone

if not hasattr(hashlib, "scrypt"):
    raise unittest.SkipTest("hashlib.scrypt 없음(LibreSSL 빌드): 앱 이미지 안에서 실행하세요")

from gapcheck import auth, explain, findings, server, worker  # noqa: E402
from tests import FIXTURES, ROOT  # noqa: E402
from tests.dbutil import fresh_store  # noqa: E402
from tests.fakes import FakeSts  # noqa: E402

ACCOUNT = "111122223333"
NEW_PASSWORD = "correct horse battery"


class Clock:
    def __init__(self):
        self.value = datetime(2026, 10, 28, 2, 30, tzinfo=timezone.utc)

    def __call__(self):
        return self.value


class Client:
    def __init__(self, port):
        self.port = port
        self.cookie = None

    def request(self, method, path, body=None, csrf=True, raw=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        headers = dict(headers or {})
        if csrf:
            headers[server.CSRF_HEADER] = server.CSRF_VALUE
        if self.cookie:
            headers["Cookie"] = f"{server.COOKIE}={self.cookie}"
        data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
        if data is not None:
            headers["Content-Type"] = "application/json"
        conn.request(method, path, body=data, headers=headers)
        response = conn.getresponse()
        payload = response.read()
        set_cookie = response.getheader("Set-Cookie")
        if set_cookie:
            self.cookie = set_cookie.split(";", 1)[0].split("=", 1)[1] or None
        self.last = response
        conn.close()
        ctype = response.getheader("Content-Type") or ""
        return response.status, (json.loads(payload) if payload and "json" in ctype else payload)


class ServerTest(unittest.TestCase):
    def setUp(self):
        self.store = fresh_store()
        self.clock = Clock()
        self.sts = FakeSts()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        fixture = FIXTURES / "ocsf-sample.json"
        self.worker = worker.Worker(self.store, worker.copy_fixture(fixture),
                                    explain.Explainer, pathlib.Path(self.tmp.name), now=self.clock)
        deps = server.Deps(store=self.store, sts=self.sts, worker=self.worker,
                           service_account_id="999988887777", daily_limit=10,
                           frontend_dir=ROOT / "frontend", template_file=ROOT / "infra" / "customer-role.yaml",
                           now=self.clock)
        self.httpd = server.make_server(deps, "127.0.0.1", 0)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.addCleanup(self.httpd.server_close)
        self.addCleanup(self.httpd.shutdown)
        self.port = self.httpd.server_address[1]

    def user(self, email="alice@example.com", change=True):
        """로그인까지 끝낸 클라이언트."""
        user, temp = auth.create_user(self.store, email, self.clock())
        client = Client(self.port)
        status, body = client.request("POST", "/api/login", {"email": email.upper(), "password": temp})
        self.assertEqual((status, body["mustChangePassword"]), (200, True))
        if change:
            status, _ = client.request("POST", "/api/password",
                                       {"currentPassword": temp, "newPassword": NEW_PASSWORD})
            self.assertEqual(status, 200)
        return client, user

    # ---------- 로그인 ----------
    def test_login_sets_strict_cookie_and_requires_password_change(self):
        user, temp = auth.create_user(self.store, "alice@example.com", self.clock())
        client = Client(self.port)
        client.request("POST", "/api/login", {"email": "alice@example.com", "password": temp})
        cookie = client.last.getheader("Set-Cookie")
        for part in ("HttpOnly", "Secure", "SameSite=Strict", "Path=/"):
            self.assertIn(part, cookie)
        self.assertEqual(client.request("GET", "/api/me")[1]["email"], "alice@example.com")
        self.assertEqual(client.request("GET", "/api/connections")[0], 403)

        old_cookie = client.cookie
        status, body = client.request("POST", "/api/password", {"currentPassword": temp, "newPassword": "short"})
        self.assertEqual(status, 400)
        status, body = client.request("POST", "/api/password",
                                      {"currentPassword": temp, "newPassword": NEW_PASSWORD})
        self.assertEqual((status, body["mustChangePassword"]), (200, False))
        self.assertNotEqual(client.cookie, old_cookie)
        self.assertEqual(client.request("GET", "/api/connections")[0], 200)
        stale = Client(self.port)
        stale.cookie = old_cookie  # 비밀번호를 바꾸면 이전 세션은 끊긴다
        self.assertEqual(stale.request("GET", "/api/me")[0], 401)

    def test_failed_logins_look_the_same_and_lock(self):
        client, _ = self.user()
        anon = Client(self.port)
        unknown = anon.request("POST", "/api/login", {"email": "nobody@example.com", "password": "x" * 12})
        wrong = anon.request("POST", "/api/login", {"email": "alice@example.com", "password": "x" * 12})
        self.assertEqual(unknown, wrong)
        self.assertEqual(unknown[0], 401)
        for _ in range(auth.MAX_FAILURES - 1):
            anon.request("POST", "/api/login", {"email": "alice@example.com", "password": "x" * 12})
        locked = anon.request("POST", "/api/login", {"email": "alice@example.com", "password": NEW_PASSWORD})
        self.assertEqual(locked, unknown)
        self.clock.value += auth.LOCK_TIME + timedelta(seconds=1)
        self.assertEqual(anon.request("POST", "/api/login",
                                      {"email": "alice@example.com", "password": NEW_PASSWORD})[0], 200)

    def test_reset_password_unlocks_and_ends_sessions(self):
        client, user = self.user()
        temp = auth.reset_password(self.store, user["id"])
        self.assertEqual(client.request("GET", "/api/me")[0], 401)
        status, body = Client(self.port).request("POST", "/api/login",
                                                 {"email": "alice@example.com", "password": temp})
        self.assertEqual((status, body["mustChangePassword"]), (200, True))

    def test_bad_login_inputs(self):
        anon = Client(self.port)
        for body in ({}, {"email": 1, "password": None}, {"email": "a@b.c", "password": "x" * 1000}):
            with self.subTest(body=body):
                self.assertEqual(anon.request("POST", "/api/login", body)[0], 401)
        self.assertEqual(anon.request("POST", "/api/login", raw=b"[1]")[0], 400)
        self.assertEqual(anon.request("POST", "/api/login", raw=b"{" + b" " * 20000 + b"}")[0], 400)

    def test_session_expires_and_logout(self):
        client, _ = self.user()
        cookie = client.cookie
        self.assertEqual(client.request("POST", "/api/logout")[0], 204)
        self.assertIsNone(client.cookie)
        client.cookie = cookie
        self.assertEqual(client.request("GET", "/api/me")[0], 401)
        client, _ = self.user("bob@example.com")
        self.clock.value += auth.SESSION_LIFETIME + timedelta(seconds=1)
        self.assertEqual(client.request("GET", "/api/me")[0], 401)

    def test_csrf_header_required_for_writes(self):
        client, _ = self.user()
        self.assertEqual(client.request("POST", "/api/connections", csrf=False)[0], 403)
        self.assertEqual(client.request("POST", "/api/logout", csrf=False)[0], 403)
        self.assertEqual(client.request("GET", "/api/connections", csrf=False)[0], 200)
        user_id = self.store.get_user_by_email("alice@example.com")["id"]
        self.assertEqual(self.store.list_connections(user_id), [])

    def test_requires_login(self):
        anon = Client(self.port)
        for method, path in (("GET", "/api/me"), ("GET", "/api/scans"), ("POST", "/api/connections")):
            with self.subTest(path=path):
                self.assertEqual(anon.request(method, path)[0], 401)
        anon.cookie = "A" * 43
        self.assertEqual(anon.request("GET", "/api/scans")[0], 401)

    # ---------- 연결·스캔 ----------
    def test_full_flow_and_user_isolation(self):
        alice, alice_user = self.user()
        status, body = alice.request("POST", "/api/connections")
        self.assertEqual((status, body["setup"]["serviceAccountId"]), (201, "999988887777"))
        conn_id = body["connection"]["id"]
        self.sts.allowed[body["connection"]["externalId"]] = ACCOUNT
        status, body = alice.request("POST", f"/api/connections/{conn_id}/verify", {"accountId": ACCOUNT})
        self.assertEqual(body["connection"]["status"], "ACTIVE")

        status, body = alice.request("POST", "/api/scans", {"connectionId": conn_id})
        self.assertEqual(status, 202)
        scan_id = body["scan"]["id"]
        self.assertTrue(self.worker.wake.is_set())
        self.assertTrue(self.worker.run_once())

        status, body = alice.request("GET", f"/api/scans/{scan_id}")
        groups, counts = findings.parse(json.loads((FIXTURES / "ocsf-sample.json").read_text()))
        self.assertEqual(body["scan"]["status"], "DONE")
        self.assertEqual(body["scan"]["counts"], counts)
        self.assertEqual([f["checkId"] for f in body["findings"]], [g["checkId"] for g in groups])
        self.assertEqual({f["explainSource"] for f in body["findings"]}, {"prowler"})
        self.assertTrue((self.worker.raw_path(alice_user["id"], scan_id) / worker.RESULT_NAME).is_file())

        bob, _ = self.user("bob@example.com")
        self.assertEqual(bob.request("GET", f"/api/scans/{scan_id}")[0], 404)
        self.assertEqual(bob.request("DELETE", f"/api/scans/{scan_id}")[0], 404)
        self.assertEqual(bob.request("DELETE", f"/api/connections/{conn_id}")[0], 404)
        self.assertEqual(bob.request("POST", "/api/scans", {"connectionId": conn_id})[0], 404)
        self.assertEqual(bob.request("GET", "/api/scans")[1]["scans"], [])

        self.assertEqual(alice.request("DELETE", f"/api/scans/{scan_id}")[0], 204)
        self.assertEqual(alice.request("GET", f"/api/scans/{scan_id}")[0], 404)
        self.assertFalse(self.worker.raw_path(alice_user["id"], scan_id).exists())

    def test_path_values_are_validated(self):
        client, _ = self.user()
        for path in ("/api/scans/..%2F..%2Fetc", "/api/scans/' OR 1=1 --", "/api/connections/x/verify/extra"):
            with self.subTest(path=path):
                self.assertEqual(client.request("GET", path.replace(" ", "%20"))[0], 404)

    # ---------- 정적 파일 ----------
    def test_static_files_and_headers(self):
        anon = Client(self.port)
        status, body = anon.request("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn(b"app.js", body)
        self.assertIn("frame-ancestors 'none'", anon.last.getheader("Content-Security-Policy"))
        self.assertEqual(anon.last.getheader("X-Content-Type-Options"), "nosniff")
        self.assertEqual(anon.request("GET", "/customer-role.yaml")[0], 200)
        for path in ("/../db/init/01-schema.sql", "/frontend/app.js", "/%2e%2e/README.md", "/config.json"):
            with self.subTest(path=path):
                self.assertEqual(anon.request("GET", path)[0], 404)


class WorkerTest(unittest.TestCase):
    def setUp(self):
        self.store = fresh_store()
        self.clock = Clock()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        user, _ = auth.create_user(self.store, "alice@example.com", self.clock())
        self.sub = user["id"]

    def make_worker(self, scanner):
        return worker.Worker(self.store, scanner, explain.Explainer, pathlib.Path(self.tmp.name),
                             now=self.clock)

    def queued(self):
        from gapcheck import connections, scans
        conn = connections.create(self.store, self.sub, self.clock())
        connections.verify(self.store, FakeSts({conn["externalId"]: ACCOUNT}), self.sub, conn["id"],
                           ACCOUNT, self.clock())
        scan, _ = scans.create(self.store, self.sub, conn["id"], now=self.clock(), daily_limit=10)
        return scan, conn

    def test_scanner_gets_validated_inputs(self):
        seen = {}

        def scanner(inputs, out_dir):
            seen.update(inputs, out_dir=out_dir)
            (out_dir / worker.RESULT_NAME).write_text("[]")

        scan, conn = self.queued()
        self.make_worker(scanner).run_once()
        self.assertEqual(seen["ROLE_ARN"], f"arn:aws:iam::{ACCOUNT}:role/AwsGapCheckReadOnlyRole")
        self.assertEqual(seen["EXTERNAL_ID"], conn["externalId"])
        self.assertEqual(seen["out_dir"], pathlib.Path(self.tmp.name) / self.sub / scan["id"])
        self.assertEqual(self.store.get_scan(self.sub, scan["id"])["status"], "DONE")

    def test_failures_are_recorded(self):
        def failing(inputs, out_dir):
            raise worker.ScanError(worker.SCAN_FAILED)

        scan, _ = self.queued()
        self.make_worker(failing).run_once()
        stored = self.store.get_scan(self.sub, scan["id"])
        self.assertEqual((stored["status"], stored["error"]), ("FAILED", worker.SCAN_FAILED))

        scan, conn = self.queued()
        self.store.delete_connection(self.sub, conn["id"])
        self.make_worker(lambda inputs, out_dir: None).run_once()
        self.assertEqual(self.store.get_scan(self.sub, scan["id"])["status"], "FAILED")

        scan, _ = self.queued()
        self.make_worker(lambda i, out: (out / worker.RESULT_NAME).write_text("{not json")).run_once()
        stored = self.store.get_scan(self.sub, scan["id"])
        self.assertEqual((stored["status"], stored["error"]), ("FAILED", "결과를 처리하지 못했습니다."))
        self.assertFalse(self.make_worker(None).run_once())

    def test_recover_and_cleanup(self):
        scan, _ = self.queued()
        self.store.update_scan(self.sub, scan["id"], {"status": "EXPLAINING"})
        w = self.make_worker(None)
        w.recover()
        self.assertEqual(self.store.get_scan(self.sub, scan["id"])["status"], "FAILED")

        raw = w.raw_path(self.sub, scan["id"])
        raw.mkdir(parents=True)
        self.clock.value += timedelta(days=31)
        w.cleanup()
        self.assertFalse(raw.exists())
        self.assertIsNone(self.store.get_scan(self.sub, scan["id"]))

    def test_raw_path_rejects_bad_ids(self):
        w = self.make_worker(None)
        for sub, scan_id in ((self.sub, "../x"), ("../../etc", "20261028023000-deadbeef")):
            with self.subTest(sub=sub, scan_id=scan_id), self.assertRaises(ValueError):
                w.raw_path(sub, scan_id)


if __name__ == "__main__":
    unittest.main()
