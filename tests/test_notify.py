"""알림 메일·자동 점검 테스트. 실제 MySQL이 필요하다(scripts/test_with_db.sh)."""
import pathlib
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from gapcheck import explain, notify, scheduler, worker
from gapcheck.common import iso
from tests import FIXTURES
from tests.dbutil import add_user, fresh_store

SUB = "11111111-1111-1111-1111-111111111111"
CONN = "0123456789abcdef"
ACCOUNT = "111122223333"
T0 = datetime(2026, 11, 3, 1, 0, tzinfo=timezone.utc)


class FakeMailer:
    def __init__(self, fail=False):
        self.sent, self.fail = [], fail

    def send(self, to, subject, body):
        if self.fail:
            raise RuntimeError("ses down")
        self.sent.append((to, subject, body))


def group(check_id, severity, title=None, total=2):
    rank = {"critical": 0, "high": 1, "medium": 2}[severity]
    return {"checkId": check_id, "rank": rank, "severity": severity, "title": title or check_id,
            "service": "s3", "resourceType": "bucket", "description": "d", "risk": "r",
            "recommendation": "rec", "references": [], "resources": [], "regions": [],
            "totalCount": total, "explanation": None, "explainSource": "pending"}


class Base(unittest.TestCase):
    def setUp(self):
        self.store = fresh_store()
        add_user(self.store, SUB, "alice@example.com")
        self.store.put_connection(SUB, {
            "id": CONN, "externalId": "agc-" + "a" * 32, "accountId": ACCOUNT, "status": "ACTIVE",
            "message": "", "schedule": "daily", "createdAt": iso(T0), "verifiedAt": iso(T0)})
        self.mailer = FakeMailer()
        self.notifier = notify.Notifier(self.store, self.mailer, "https://agc.example.org/")

    def add_scan(self, at, status="DONE", groups=()):
        scan = {"id": at.strftime("%Y%m%d%H%M%S") + "-abcd1234", "connectionId": CONN, "accountId": ACCOUNT,
                "status": status, "counts": {}, "summary": None, "error": "", "createdAt": iso(at),
                "updatedAt": iso(at), "expiresAt": int(at.timestamp()) + 86400}
        self.store.put_scan(SUB, scan)
        self.store.put_findings(SUB, scan["id"], list(groups), scan["expiresAt"])
        return scan


class NotifyTest(Base):
    def test_first_scan_mails_all_urgent_with_link(self):
        scan = self.add_scan(T0, groups=[group("a", "critical", "공개 버킷"), group("b", "high"),
                                         group("c", "medium")])
        self.assertTrue(self.notifier.scan_done(SUB, scan))
        to, subject, body = self.mailer.sent[0]
        self.assertEqual(to, "alice@example.com")
        self.assertIn(ACCOUNT, subject)
        self.assertIn("새 위험 항목 2개", subject)
        self.assertIn("[치명] 공개 버킷 (리소스 2개)", body)
        self.assertNotIn("medium", body)
        self.assertIn(f"https://agc.example.org/#/scans/{scan['id']}", body)

    def test_only_new_urgent_items_are_mailed(self):
        first = self.add_scan(T0, groups=[group("a", "critical")])
        self.notifier.scan_done(SUB, first)
        same = self.add_scan(T0 + timedelta(days=1), groups=[group("a", "critical"), group("m", "medium")])
        self.assertFalse(self.notifier.scan_done(SUB, same))
        more = self.add_scan(T0 + timedelta(days=2), groups=[group("a", "critical"), group("n", "high")])
        self.assertTrue(self.notifier.scan_done(SUB, more))
        self.assertEqual(len(self.mailer.sent), 2)
        self.assertIn("새 위험 항목 1개", self.mailer.sent[1][1])

    def test_severity_upgrade_counts_as_new(self):
        self.add_scan(T0, groups=[group("a", "medium")])
        worse = self.add_scan(T0 + timedelta(days=1), groups=[group("a", "high")])
        self.assertTrue(self.notifier.scan_done(SUB, worse))

    def test_schedule_off_sends_nothing(self):
        self.store.update_connection(SUB, CONN, {"schedule": "off"})
        scan = self.add_scan(T0, groups=[group("a", "critical")])
        self.assertFalse(self.notifier.scan_done(SUB, scan))
        self.assertEqual(self.mailer.sent, [])

    def test_compose_cleans_titles_and_caps_list(self):
        items = [group(f"c{i}", "high", "줄\n바꿈\r\n제목") for i in range(12)]
        subject, body = notify.compose(ACCOUNT, "scan", items, "")
        self.assertNotIn("\n바꿈", body)
        self.assertIn("줄 바꿈 제목", body)
        self.assertIn("외 2개", body)
        self.assertNotIn("자세히 보기", body)
        self.assertIn("12개", subject)


class WorkerNotifyTest(Base):
    def make_worker(self, notifier):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        return worker.Worker(self.store, worker.copy_fixture(FIXTURES / "ocsf-sample.json"), explain.Explainer,
                             pathlib.Path(tmp.name), now=lambda: T0, notifier=notifier)

    def queue(self, at):
        scan = self.add_scan(at, status="QUEUED")
        return scan

    def test_scan_done_triggers_mail_once(self):
        scan_worker = self.make_worker(self.notifier)
        self.queue(T0)
        self.assertTrue(scan_worker.run_once())
        self.assertEqual(len(self.mailer.sent), 1)
        self.queue(T0 + timedelta(days=1))
        self.assertTrue(scan_worker.run_once())
        self.assertEqual(len(self.mailer.sent), 1)  # 같은 결과면 두 번째는 보내지 않는다

    def test_mail_failure_does_not_fail_scan(self):
        scan_worker = self.make_worker(notify.Notifier(self.store, FakeMailer(fail=True)))
        scan = self.queue(T0)
        scan_worker.run_once()
        self.assertEqual(self.store.get_scan(SUB, scan["id"])["status"], "DONE")


class SchedulerTest(Base):
    def test_due_connections_get_a_scan(self):
        self.assertEqual(scheduler.run_due(self.store, T0, 10), 1)
        self.assertEqual(len(self.store.list_scans(SUB)), 1)
        self.assertEqual(scheduler.run_due(self.store, T0, 10), 0)  # 이미 진행 중

    def test_interval_must_pass(self):
        self.add_scan(T0)
        self.assertEqual(scheduler.run_due(self.store, T0 + timedelta(hours=23), 10), 0)
        self.assertEqual(scheduler.run_due(self.store, T0 + timedelta(hours=25), 10), 1)

    def test_weekly(self):
        self.store.update_connection(SUB, CONN, {"schedule": "weekly"})
        self.add_scan(T0)
        self.assertEqual(scheduler.run_due(self.store, T0 + timedelta(days=6), 10), 0)
        self.assertEqual(scheduler.run_due(self.store, T0 + timedelta(days=7, minutes=1), 10), 1)

    def test_off_and_unverified_are_ignored(self):
        self.store.update_connection(SUB, CONN, {"schedule": "off"})
        self.assertEqual(scheduler.run_due(self.store, T0, 10), 0)
        self.store.update_connection(SUB, CONN, {"schedule": "daily", "status": "FAILED"})
        self.assertEqual(scheduler.run_due(self.store, T0, 10), 0)

    def test_daily_limit_skips_quietly(self):
        self.assertEqual(scheduler.run_due(self.store, T0, 0), 0)
        self.assertEqual(self.store.list_scans(SUB), [])


if __name__ == "__main__":
    unittest.main()
