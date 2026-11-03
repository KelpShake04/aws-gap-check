import threading
import unittest
from datetime import date, datetime, timedelta, timezone

from gapcheck import billing, connections
from tests.fakes import FakeCe, FakeSts

ACCOUNT = "111122223333"
CONN = {"id": "0123456789abcdef", "accountId": ACCOUNT, "externalId": "agc-" + "a" * 32}
NOW = datetime(2026, 11, 10, 3, 0, tzinfo=timezone.utc)


class Clock:
    def __init__(self, value=NOW):
        self.value = value

    def __call__(self):
        return self.value


def rows():
    # 10월 29~31일 EC2 2.0/일, 11월 1~10일 EC2 3.0 + S3 0.5/일
    out = [(f"2026-10-{d:02d}", "EC2", 2.0) for d in range(29, 32)]
    for d in range(1, 11):
        out += [(f"2026-11-{d:02d}", "EC2", 3.0), (f"2026-11-{d:02d}", "S3", 0.5)]
    return out


class SummarizeTest(unittest.TestCase):
    def test_totals_services_and_daily_window(self):
        data = [(date.fromisoformat(d), s, a) for d, s, a in rows()]
        data += [(date(2026, 11, 3), f"svc{i}", 0.1 * i) for i in range(1, 7)]  # 서비스가 6개를 넘으면 기타
        result = billing.summarize(data, date(2026, 11, 10), forecast_rest=5.5)
        self.assertEqual((result["month"], result["status"], result["currency"]), ("2026-11", "OK", "USD"))
        self.assertEqual(result["previous"], 6.0)
        self.assertEqual(result["spent"], round(35.0 + 2.1, 2))
        self.assertEqual(result["forecast"], round(37.1 + 5.5, 2))
        self.assertEqual([s["name"] for s in result["services"]],
                         ["EC2", "S3", "svc6", "svc5", "svc4", "기타"])
        self.assertEqual(len(result["daily"]), billing.DAYS)
        self.assertEqual(result["daily"][-1], {"date": "2026-11-10", "amount": 3.5})
        self.assertEqual(result["daily"][0]["date"], "2026-10-12")

    def test_no_forecast_and_empty(self):
        result = billing.summarize([], date(2026, 1, 1))
        self.assertEqual((result["spent"], result["previous"], result["forecast"], result["services"]),
                         (0.0, 0.0, None, []))
        self.assertEqual(result["daily"][0]["date"], "2025-12-03")


class ProviderTest(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.sts = FakeSts({CONN["externalId"]: ACCOUNT})
        self.ce = FakeCe(rows())
        self.made = []
        self.provider = billing.CostProvider(self.sts, self.make_ce, now=self.clock)

    def make_ce(self, credentials):
        self.made.append(credentials)
        return self.ce

    def test_fetch_params_and_result(self):
        data = self.provider.get("u1", CONN)
        self.assertEqual((data["status"], data["spent"], data["previous"]), ("OK", 35.0, 6.0))
        self.assertEqual(data["fetchedAt"], "2026-11-10T03:00:00Z")
        call = self.ce.usage_calls[0]
        self.assertEqual(call["TimePeriod"], {"Start": "2026-10-01", "End": "2026-11-11"})
        self.assertEqual(call["Filter"], billing.EXCLUDE_CREDITS)
        self.assertEqual(self.ce.forecast_calls[0]["TimePeriod"], {"Start": "2026-11-11", "End": "2026-12-01"})
        self.assertEqual(data["forecast"], 45.0)
        self.assertEqual(self.sts.calls[0]["ExternalId"], CONN["externalId"])
        self.assertEqual(len(self.made), 1)

    def test_pages_are_followed(self):
        self.ce.pages = 3
        data = self.provider.get("u1", CONN)
        self.assertEqual(len(self.ce.usage_calls), 3)
        self.assertEqual(data["spent"], 35.0)

    def test_cache_and_refresh_limits(self):
        first = self.provider.get("u1", CONN)
        self.clock.value += timedelta(minutes=4)
        self.assertEqual(self.provider.get("u1", CONN, force=True), first)  # 5분 안의 새로고침은 무시
        self.clock.value += timedelta(minutes=2)
        self.assertEqual(self.provider.get("u1", CONN), first)  # 평소엔 6시간 재사용
        self.assertEqual(len(self.ce.usage_calls), 1)
        self.provider.get("u1", CONN, force=True)
        self.assertEqual(len(self.ce.usage_calls), 2)
        self.clock.value += timedelta(hours=6, seconds=1)
        self.provider.get("u1", CONN)
        self.assertEqual(len(self.ce.usage_calls), 3)

    def test_cache_is_per_user_and_connection(self):
        self.provider.get("u1", CONN)
        self.provider.get("u2", CONN)
        self.provider.get("u1", {**CONN, "id": "fedcba9876543210"})
        self.assertEqual(len(self.ce.usage_calls), 3)

    def test_slow_connection_does_not_block_others(self):
        started, release = threading.Event(), threading.Event()
        slow, fast = FakeCe(rows()), FakeCe(rows())
        original = slow.get_cost_and_usage

        def blocking(**kwargs):
            started.set()
            release.wait(5)
            return original(**kwargs)
        slow.get_cost_and_usage = blocking
        ces = iter([slow, fast])
        provider = billing.CostProvider(self.sts, lambda credentials: next(ces), now=self.clock)
        thread = threading.Thread(target=provider.get, args=("u1", CONN))
        thread.start()
        self.assertTrue(started.wait(5))
        other = []
        worker = threading.Thread(target=lambda: other.append(provider.get("u1", {**CONN, "id": "fedcba9876543210"})))
        worker.start()
        worker.join(2)  # 느린 연결을 기다리지 않고 끝나야 한다
        release.set()
        self.assertEqual([d["status"] for d in other], ["OK"])
        thread.join(5)
        self.assertEqual(len(slow.usage_calls), 1)

    def test_no_permission_is_reported_and_cached_briefly(self):
        self.ce.fail_code = "AccessDeniedException"
        data = self.provider.get("u1", CONN)
        self.assertEqual((data["status"], data["message"]), ("NO_PERMISSION", billing.NO_PERMISSION))
        self.provider.get("u1", CONN)
        self.assertEqual(len(self.ce.usage_calls), 1)
        self.clock.value += timedelta(minutes=6)
        self.ce.fail_code = None
        self.assertEqual(self.provider.get("u1", CONN)["status"], "OK")

    def test_assume_role_denied(self):
        self.sts.allowed = {}
        data = self.provider.get("u1", CONN)
        self.assertEqual((data["status"], data["message"]), ("ERROR", connections.DENIED_MESSAGE))
        self.assertEqual(self.ce.usage_calls, [])

    def test_unexpected_error_hides_details(self):
        self.ce.fail_code = "ThrottlingException"
        data = self.provider.get("u1", CONN)
        self.assertEqual((data["status"], data["message"]), ("ERROR", billing.ERROR))

        class Boom(FakeSts):
            def assume_role(self, **kwargs):
                raise RuntimeError("arn:aws:iam::111122223333:secret")

        provider = billing.CostProvider(Boom(), self.make_ce, now=self.clock)
        self.assertEqual(provider.get("u1", CONN)["message"], billing.ERROR)

    def test_forecast_skipped_on_last_day_and_when_unavailable(self):
        self.clock.value = datetime(2026, 11, 30, 12, 0, tzinfo=timezone.utc)
        self.assertIsNone(self.provider.get("u1", CONN)["forecast"])
        self.assertEqual(self.ce.forecast_calls, [])
        self.clock.value = NOW
        self.ce.forecast_fail = True
        data = self.provider.get("u2", CONN)
        self.assertEqual((data["status"], data["forecast"]), ("OK", None))


if __name__ == "__main__":
    unittest.main()
