"""ids, store, connections, scans 테스트."""
import unittest
from datetime import datetime, timedelta, timezone

import run_scan
from gapcheck import connections, ids, scans
from gapcheck.common import BadRequest, Conflict, NotFound, TooMany, Unavailable, iso
from gapcheck.store import Store
from tests.fakes import FakeCodeBuild, FakeS3, FakeSts, FakeTable

NOW = datetime(2026, 10, 28, 2, 30, tzinfo=timezone.utc)
ALICE = "6f1c2a3b-4d5e-4f60-8a7b-9c0d1e2f3a4b"
BOB = "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d"
ACCOUNT = "111122223333"


class IdsTest(unittest.TestCase):
    def test_generated_ids_match_patterns(self):
        self.assertTrue(ids.valid("external_id", ids.new_external_id()))
        self.assertTrue(ids.valid("connection", ids.new_connection_id()))
        self.assertTrue(ids.valid("scan", ids.new_scan_id(NOW)))
        self.assertTrue(ids.new_scan_id(NOW).startswith("20261028023000-"))

    def test_rejects_bad_account_ids(self):
        for value in ["11112222333", "1111222233334", "١١١١٢٢٢٢٣٣٣٣", "111122223333\n", None, 111122223333]:
            with self.subTest(value=value):
                self.assertFalse(ids.valid("account", value))
        with self.assertRaises(ValueError):
            ids.role_arn("bad")

    def test_patterns_match_scanner(self):
        self.assertEqual(run_scan.PATTERNS["SCAN_ID"], ids.PATTERNS["scan"])
        self.assertEqual(run_scan.PATTERNS["USER_SUB"], ids.PATTERNS["sub"])
        self.assertEqual(run_scan.PATTERNS["EXTERNAL_ID"], ids.PATTERNS["external_id"])
        self.assertTrue(run_scan.PATTERNS["ROLE_ARN"].endswith(ids.ROLE_NAME))


class Base(unittest.TestCase):
    def setUp(self):
        self.store = Store(FakeTable())

    def active_connection(self, sub=ALICE):
        conn = connections.create(self.store, sub, NOW)
        sts = FakeSts({conn["externalId"]: ACCOUNT})
        return connections.verify(self.store, sts, sub, conn["id"], ACCOUNT, NOW)


class ConnectionTest(Base):
    def test_create_is_pending_with_server_external_id(self):
        conn = connections.create(self.store, ALICE, NOW)
        self.assertEqual(conn["status"], "PENDING")
        self.assertTrue(ids.valid("external_id", conn["externalId"]))
        self.assertEqual(self.store.list_connections(ALICE), [conn])

    def test_verify_success(self):
        conn = connections.create(self.store, ALICE, NOW)
        sts = FakeSts({conn["externalId"]: ACCOUNT})
        result = connections.verify(self.store, sts, ALICE, conn["id"], ACCOUNT, NOW)
        self.assertEqual(result["status"], "ACTIVE")
        self.assertEqual(sts.calls[0]["RoleArn"], f"arn:aws:iam::{ACCOUNT}:role/AwsGapCheckReadOnlyRole")
        self.assertEqual(sts.calls[0]["ExternalId"], conn["externalId"])
        self.assertEqual(self.store.get_connection(ALICE, conn["id"])["status"], "ACTIVE")

    def test_confused_deputy_other_user_cannot_use_account(self):
        alice = connections.create(self.store, ALICE, NOW)
        bob = connections.create(self.store, BOB, NOW)
        sts = FakeSts({alice["externalId"]: ACCOUNT})  # 계정의 Role은 Alice의 ExternalId만 받는다
        result = connections.verify(self.store, sts, BOB, bob["id"], ACCOUNT, NOW)
        self.assertEqual(result["status"], "FAILED")
        self.assertEqual(sts.calls[0]["ExternalId"], bob["externalId"])

    def test_user_cannot_see_or_verify_other_users_connection(self):
        conn = connections.create(self.store, ALICE, NOW)
        self.assertEqual(self.store.list_connections(BOB), [])
        with self.assertRaises(NotFound):
            connections.verify(self.store, FakeSts(), BOB, conn["id"], ACCOUNT, NOW)

    def test_verify_rejects_bad_account_id(self):
        conn = connections.create(self.store, ALICE, NOW)
        with self.assertRaises(BadRequest):
            connections.verify(self.store, FakeSts(), ALICE, conn["id"], "12345", NOW)


class ScanTest(Base):
    def start(self, conn, codebuild=None, now=NOW, limit=10, sub=ALICE):
        return scans.start(self.store, codebuild or FakeCodeBuild(), sub, conn["id"],
                           project="aws-gap-check-scanner", now=now, daily_limit=limit)

    def test_start_passes_validated_inputs_to_codebuild(self):
        conn = self.active_connection()
        codebuild = FakeCodeBuild()
        scan = self.start(conn, codebuild)
        env = codebuild.started[0]["env"]
        self.assertEqual(env["SCAN_ID"], scan["id"])
        self.assertEqual(env["USER_SUB"], ALICE)
        self.assertEqual(env["EXTERNAL_ID"], conn["externalId"])
        for name, value in env.items():
            self.assertRegex(value, "^" + run_scan.PATTERNS[name] + "$")
        self.assertEqual(self.store.get_scan(ALICE, scan["id"])["buildId"], scan["buildId"])

    def test_requires_active_connection_of_same_user(self):
        pending = connections.create(self.store, ALICE, NOW)
        with self.assertRaises(Conflict):
            self.start(pending)
        conn = self.active_connection()
        with self.assertRaises(NotFound):
            self.start(conn, sub=BOB)

    def test_one_running_scan_per_user_until_stale(self):
        conn = self.active_connection()
        self.start(conn)
        with self.assertRaises(Conflict):
            self.start(conn, now=NOW + timedelta(minutes=5))
        self.start(conn, now=NOW + timedelta(minutes=71))

    def test_daily_limit(self):
        conn = self.active_connection()
        first = self.start(conn, limit=1)
        self.store.update_scan(ALICE, first["id"], {"status": "DONE"})
        with self.assertRaises(TooMany):
            self.start(conn, now=NOW + timedelta(minutes=1), limit=1)

    def test_deleting_scans_does_not_reset_daily_limit(self):
        conn = self.active_connection()
        first = self.start(conn, limit=1)
        self.store.update_scan(ALICE, first["id"], {"status": "DONE"})
        scans.delete(self.store, FakeS3(), ALICE, first["id"], bucket="b", now=NOW)
        with self.assertRaises(NotFound):
            scans.get(self.store, ALICE, first["id"])
        with self.assertRaises(TooMany):
            self.start(conn, now=NOW + timedelta(minutes=1), limit=1)

    def test_codebuild_failure_marks_scan_failed(self):
        conn = self.active_connection()
        with self.assertRaises(Unavailable):
            self.start(conn, FakeCodeBuild(fail_code="InvalidInputException"))
        self.assertEqual(self.store.list_scans(ALICE)[0]["status"], "FAILED")

    def test_delete_removes_results_and_raw_file(self):
        conn = self.active_connection()
        scan = self.start(conn)
        self.store.update_scan(ALICE, scan["id"], {"status": "DONE"})
        group = {"rank": 0, "checkId": "c", "title": "t"}
        self.store.put_findings(ALICE, scan["id"], [group], 0)
        s3 = FakeS3()
        s3.put_json("bucket", f"raw/{ALICE}/{scan['id']}/prowler.ocsf.json", [])
        s3.put_json("bucket", f"raw/{BOB}/{scan['id']}/prowler.ocsf.json", [])
        scans.delete(self.store, s3, ALICE, scan["id"], bucket="bucket", now=NOW)
        with self.assertRaises(NotFound):
            scans.get(self.store, ALICE, scan["id"])
        self.assertEqual(self.store.get_scan(ALICE, scan["id"])["status"], scans.DELETED)
        self.assertEqual(self.store.list_findings(ALICE, scan["id"]), [])
        self.assertEqual(list(s3.objects), [("bucket", f"raw/{BOB}/{scan['id']}/prowler.ocsf.json")])

    def test_cannot_delete_running_scan(self):
        scan = self.start(self.active_connection())
        with self.assertRaises(Conflict):
            scans.delete(self.store, FakeS3(), ALICE, scan["id"], bucket="b", now=NOW)

    def test_update_does_not_create_missing_item(self):
        self.assertFalse(self.store.update_scan(ALICE, "20261028023000-deadbeef", {"status": "DONE"}))
        self.assertEqual(self.store.list_scans(ALICE), [])

    def test_created_at_is_iso(self):
        scan = self.start(self.active_connection())
        self.assertEqual(scan["createdAt"], iso(NOW))


if __name__ == "__main__":
    unittest.main()
