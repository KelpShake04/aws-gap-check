"""MySQL 저장소(gapcheck.db) 테스트. 실제 MySQL 8.4가 필요하다(scripts/test_with_db.sh)."""
import unittest
from datetime import datetime, timedelta, timezone

from gapcheck import connections, scans
from gapcheck.common import Conflict, NotFound, TooMany, expires_at, iso
from tests.dbutil import add_user, fresh_store
from tests.fakes import FakeSts

NOW = datetime(2026, 10, 28, 2, 30, tzinfo=timezone.utc)
ALICE = "6f1c2a3b-4d5e-4f60-8a7b-9c0d1e2f3a4b"
BOB = "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d"
ACCOUNT = "111122223333"


def group(check_id, rank=1, **extra):
    return {"checkId": check_id, "rank": rank, "severity": "high", "title": "제목 " + check_id,
            "service": "s3", "resourceType": "AwsS3Bucket", "description": "d", "risk": "r",
            "recommendation": "fix", "references": ["https://example.com"],
            "resources": [{"uid": "arn:x", "name": "버킷", "region": "ap-northeast-2"}],
            "regions": ["ap-northeast-2"], "totalCount": 1, "explanation": None,
            "explainSource": "pending", **extra}


class Base(unittest.TestCase):
    def setUp(self):
        self.store = fresh_store()
        add_user(self.store, ALICE)
        add_user(self.store, BOB)

    def active_connection(self, sub=ALICE):
        conn = connections.create(self.store, sub, NOW)
        sts = FakeSts({conn["externalId"]: ACCOUNT})
        return connections.verify(self.store, sts, sub, conn["id"], ACCOUNT, NOW)

    def queued_scan(self, sub=ALICE, now=NOW):
        scan, _ = scans.create(self.store, sub, self.active_connection(sub)["id"], now=now, daily_limit=10)
        return scan


class ConnectionStoreTest(Base):
    def test_round_trip_and_user_isolation(self):
        conn = connections.create(self.store, ALICE, NOW)
        self.assertEqual(self.store.get_connection(ALICE, conn["id"]), conn)
        self.assertEqual(self.store.list_connections(ALICE), [conn])
        self.assertIsNone(self.store.get_connection(BOB, conn["id"]))
        self.assertEqual(self.store.list_connections(BOB), [])
        with self.assertRaises(NotFound):
            connections.verify(self.store, FakeSts(), BOB, conn["id"], ACCOUNT, NOW)

    def test_verify_and_update_semantics(self):
        conn = self.active_connection()
        stored = self.store.get_connection(ALICE, conn["id"])
        self.assertEqual((stored["status"], stored["accountId"], stored["verifiedAt"]),
                         ("ACTIVE", ACCOUNT, iso(NOW)))
        # 같은 값으로 고쳐도 "있는 행"이면 True, 없는 행이나 남의 행이면 False
        self.assertTrue(self.store.update_connection(ALICE, conn["id"], {"status": "ACTIVE"}))
        self.assertFalse(self.store.update_connection(BOB, conn["id"], {"status": "FAILED"}))
        self.assertFalse(self.store.update_connection(ALICE, "0" * 16, {"status": "FAILED"}))

    def test_unknown_field_is_rejected(self):
        conn = connections.create(self.store, ALICE, NOW)
        with self.assertRaises(KeyError):
            self.store.update_connection(ALICE, conn["id"], {"status = 'x', id": "y"})

    def test_delete_only_own(self):
        conn = connections.create(self.store, ALICE, NOW)
        self.store.delete_connection(BOB, conn["id"])
        self.assertIsNotNone(self.store.get_connection(ALICE, conn["id"]))
        connections.delete(self.store, ALICE, conn["id"])
        self.assertIsNone(self.store.get_connection(ALICE, conn["id"]))


class ScanStoreTest(Base):
    def test_create_round_trip_newest_first(self):
        first = self.queued_scan()
        self.store.update_scan(ALICE, first["id"], {"status": "DONE"})
        second = self.queued_scan(now=NOW + timedelta(minutes=1))
        self.assertEqual([s["id"] for s in self.store.list_scans(ALICE)], [second["id"], first["id"]])
        self.assertEqual(self.store.get_scan(ALICE, second["id"]), second)
        self.assertIsNone(self.store.get_scan(BOB, second["id"]))

    def test_limits_work_on_mysql(self):
        conn = self.active_connection()
        scans.create(self.store, ALICE, conn["id"], now=NOW, daily_limit=1)
        with self.assertRaises(Conflict):
            scans.create(self.store, ALICE, conn["id"], now=NOW, daily_limit=1)
        first = self.store.list_scans(ALICE)[0]
        self.store.update_scan(ALICE, first["id"], {"status": "DONE"})
        scans.discard(self.store, ALICE, first["id"], remove_raw=lambda: None, now=NOW)
        with self.assertRaises(TooMany):
            scans.create(self.store, ALICE, conn["id"], now=NOW, daily_limit=1)

    def test_claim_is_conditional(self):
        scan = self.queued_scan()
        fields = {"status": "RUNNING", "updatedAt": iso(NOW)}
        self.assertTrue(self.store.claim_scan(ALICE, scan["id"], ("QUEUED",), fields))
        self.assertFalse(self.store.claim_scan(ALICE, scan["id"], ("QUEUED",), fields))
        self.assertFalse(self.store.claim_scan(BOB, scan["id"], ("RUNNING",), fields))

    def test_json_fields(self):
        scan = self.queued_scan()
        summary = {"overall": "요약", "top": [{"check_id": "c", "reason": "이유"}]}
        self.store.update_scan(ALICE, scan["id"], {"counts": {"high": 2}, "summary": summary})
        stored = self.store.get_scan(ALICE, scan["id"])
        self.assertEqual((stored["counts"], stored["summary"]), ({"high": 2}, summary))


class FindingStoreTest(Base):
    def test_put_list_upsert_delete(self):
        scan = self.queued_scan()
        self.store.put_findings(ALICE, scan["id"], [group("b", 1), group("a", 1), group("z", 0)], 123)
        self.assertEqual([f["checkId"] for f in self.store.list_findings(ALICE, scan["id"])], ["z", "a", "b"])
        explained = group("a", 1, explanation={"summary": "한 줄"}, explainSource="gemini")
        self.store.put_finding(ALICE, scan["id"], explained, 123)
        stored = self.store.list_findings(ALICE, scan["id"])[1]
        self.assertEqual(stored, {**explained, "expiresAt": 123})
        self.assertEqual(self.store.list_findings(BOB, scan["id"]), [])
        self.store.delete_findings(BOB, scan["id"])
        self.assertEqual(len(self.store.list_findings(ALICE, scan["id"])), 3)
        self.store.delete_findings(ALICE, scan["id"])
        self.assertEqual(self.store.list_findings(ALICE, scan["id"]), [])

    def test_findings_need_own_scan(self):
        scan = self.queued_scan()
        with self.assertRaises(Exception):  # 외래키: 남의 스캔 ID로는 결과를 넣을 수 없다
            self.store.put_findings(BOB, scan["id"], [group("a")], 123)

    def test_explanation_cache(self):
        self.assertIsNone(self.store.get_explanation("c", "v1", "m"))
        self.store.put_explanation("c", "v1", "m", {"summary": "첫"})
        self.store.put_explanation("c", "v1", "m", {"summary": "둘"})
        self.assertEqual(self.store.get_explanation("c", "v1", "m"), {"summary": "둘"})


class UserSessionStoreTest(Base):
    def test_session_lookup_respects_expiry(self):
        self.store.put_session("a" * 64, ALICE, iso(NOW), iso(NOW + timedelta(hours=1)))
        user = self.store.get_session_user("a" * 64, iso(NOW))
        self.assertEqual(user["id"], ALICE)
        self.assertIsNone(self.store.get_session_user("a" * 64, iso(NOW + timedelta(hours=2))))
        self.assertIsNone(self.store.get_session_user("b" * 64, iso(NOW)))
        self.store.delete_user_sessions(ALICE)
        self.assertIsNone(self.store.get_session_user("a" * 64, iso(NOW)))

    def test_user_fields(self):
        self.assertTrue(self.store.update_user(ALICE, {"failedLogins": 3, "lockedUntil": iso(NOW),
                                                       "mustChangePassword": True}))
        user = self.store.get_user_by_email(f"{ALICE[:8]}@example.com")
        self.assertEqual((user["failedLogins"], user["lockedUntil"], user["mustChangePassword"]),
                         (3, iso(NOW), True))
        with self.assertRaises(Exception):  # 이메일 중복
            add_user(self.store, "1" * 8 + ALICE[8:], f"{ALICE[:8]}@example.com")


class WorkerStoreTest(Base):
    def test_queue_fail_and_purge(self):
        old = self.queued_scan(BOB, now=NOW - timedelta(days=31))
        self.store.update_scan(BOB, old["id"], {"status": "DONE", "expiresAt": expires_at(NOW) - 40 * 86400})
        self.store.put_findings(BOB, old["id"], [group("a")], 0)
        first = self.queued_scan(ALICE)
        self.queued_scan(BOB, now=NOW + timedelta(seconds=1))
        sub, scan = self.store.next_queued_scan()
        self.assertEqual((sub, scan["id"]), (ALICE, first["id"]))

        self.store.update_scan(ALICE, first["id"], {"status": "RUNNING"})
        failed = self.store.fail_scans(("RUNNING", "PROCESSING"), {"status": "FAILED", "error": "재시작"})
        self.assertEqual((failed, self.store.get_scan(ALICE, first["id"])["status"]), (1, "FAILED"))

        now_epoch = int(NOW.timestamp())
        self.assertEqual(self.store.expired_scans(now_epoch), [(BOB, old["id"])])
        self.store.put_session("c" * 64, ALICE, iso(NOW), iso(NOW - timedelta(seconds=1)))
        self.store.purge(now_epoch, iso(NOW))
        self.assertIsNone(self.store.get_scan(BOB, old["id"]))
        self.assertEqual(self.store.list_findings(BOB, old["id"]), [])
        self.assertEqual(self.store._execute("SELECT COUNT(*) n FROM sessions", ())[0]["n"], 0)


class PrivilegeTest(Base):
    def test_app_account_cannot_change_schema(self):
        for sql in ("DROP TABLE explanations", "CREATE TABLE t (id INT)", "ALTER TABLE users ADD x INT",
                    "GRANT SELECT ON gapcheck.* TO 'gapcheck'@'%'"):
            with self.subTest(sql=sql), self.assertRaises(Exception):
                self.store._execute(sql, ())


if __name__ == "__main__":
    unittest.main()
