"""계정 비용 조회(Cost Explorer): 이번 달 사용액, 월말 예상, 서비스별 비중, 최근 30일 추이.

Cost Explorer API는 호출 한 번에 $0.01이 조회 대상 계정에 청구된다. 화면을 열 때마다 부르지 않도록
결과를 메모리에 두고 재사용하고(6시간), 새로 고침도 5분에 한 번만 받는다. 크레딧·환불을 뺀 사용액이다.
"""
from __future__ import annotations

import logging
import threading
from collections import defaultdict
from datetime import date, datetime, timedelta

from . import connections, ids
from .common import error_code, iso, utcnow

logger = logging.getLogger(__name__)

CACHE_SECONDS = 6 * 3600
MIN_REFRESH_SECONDS = 5 * 60  # 오류 결과도 이만큼만 재사용한다
TOP_SERVICES = 5
DAYS = 30
DENIED = ("AccessDenied", "AccessDeniedException")
NO_PERMISSION = ("비용 조회 권한이 없습니다. 계정 연결 화면의 템플릿으로 스택을 업데이트하세요"
                 "(Cost Explorer를 한 번도 켜지 않은 계정이면 콘솔 Billing에서 먼저 켜야 합니다).")
ERROR = "비용 정보를 가져오지 못했습니다. 잠시 후 다시 시도하세요."
# 크레딧을 빼기 전의 실제 사용액을 보여 준다(크레딧이 있으면 순비용이 0에 가깝게 나온다)
EXCLUDE_CREDITS = {"Not": {"Dimensions": {"Key": "RECORD_TYPE", "Values": ["Credit", "Refund"]}}}


def summarize(rows: list, today: date, forecast_rest: float = None, currency: str = "USD") -> dict:
    """rows: (날짜, 서비스, 금액) 목록. 이번 달·지난달 합계와 서비스 상위, 최근 30일 일별 합계를 만든다."""
    month_start = today.replace(day=1)
    spent = previous = 0.0
    services, daily = defaultdict(float), defaultdict(float)
    for day, service, amount in rows:
        daily[day] += amount
        if day >= month_start:
            spent += amount
            services[service] += amount
        elif day >= prev_month_start(today):
            previous += amount
    ranked = sorted(((name, amount) for name, amount in services.items() if amount > 0),
                    key=lambda item: -item[1])
    top = [{"name": name, "amount": round(amount, 2)} for name, amount in ranked[:TOP_SERVICES]]
    rest = sum(amount for _, amount in ranked[TOP_SERVICES:])
    if rest > 0:
        top.append({"name": "기타", "amount": round(rest, 2)})
    start = today - timedelta(days=DAYS - 1)
    return {
        "status": "OK", "currency": currency, "month": today.strftime("%Y-%m"),
        "spent": round(spent, 2), "previous": round(previous, 2),
        "forecast": None if forecast_rest is None else round(spent + forecast_rest, 2),
        "services": top,
        "daily": [{"date": (start + timedelta(days=i)).isoformat(),
                   "amount": round(daily.get(start + timedelta(days=i), 0.0), 2)} for i in range(DAYS)],
    }


def prev_month_start(today: date) -> date:
    return (today.replace(day=1) - timedelta(days=1)).replace(day=1)


class CostProvider:
    """make_ce(credentials)는 Cost Explorer 클라이언트를 돌려준다(boto3는 app.py에서만 import)."""

    def __init__(self, sts, make_ce, now=utcnow):
        self.sts = sts
        self.make_ce = make_ce
        self.now = now
        self._cache = {}
        # 같은 연결의 동시 요청만 한 줄로 세운다(같은 호출을 두 번 청구하지 않게). 다른 연결은 서로 기다리지 않는다
        self._locks = {}
        self._locks_lock = threading.Lock()

    def get(self, sub: str, conn: dict, force: bool = False) -> dict:
        key = (sub, conn["id"])
        with self._locks_lock:
            lock = self._locks.setdefault(key, threading.Lock())
        with lock:
            now = self.now()
            entry = self._cache.get(key)
            if entry:
                age = (now - entry["at"]).total_seconds()
                ttl = CACHE_SECONDS if entry["data"]["status"] == "OK" else MIN_REFRESH_SECONDS
                if age < ttl and (not force or age < MIN_REFRESH_SECONDS):
                    return entry["data"]
            data = {**self._fetch(conn, now), "fetchedAt": iso(now)}
            self._cache[key] = {"at": now, "data": data}
            return data

    def _fetch(self, conn: dict, now: datetime) -> dict:
        try:
            credentials = self.sts.assume_role(
                RoleArn=ids.role_arn(conn["accountId"]), RoleSessionName=f"aws-gap-check-cost-{conn['id']}",
                ExternalId=conn["externalId"], DurationSeconds=900)["Credentials"]
        except Exception as err:
            if error_code(err) not in DENIED:
                logger.error("assume role for cost failed: %s", type(err).__name__)
            return {"status": "ERROR", "message": connections.DENIED_MESSAGE if error_code(err) in DENIED else ERROR}
        try:
            return self._query(self.make_ce(credentials), now.date())
        except Exception as err:
            if error_code(err) in DENIED:
                return {"status": "NO_PERMISSION", "message": NO_PERMISSION}
            logger.error("cost query failed: %s", type(err).__name__)
            return {"status": "ERROR", "message": ERROR}

    def _query(self, ce, today: date) -> dict:
        start = min(prev_month_start(today), today - timedelta(days=DAYS - 1))
        token, rows, currency = None, [], "USD"
        while True:
            page = ce.get_cost_and_usage(
                TimePeriod={"Start": start.isoformat(), "End": (today + timedelta(days=1)).isoformat()},
                Granularity="DAILY", Metrics=["UnblendedCost"], Filter=EXCLUDE_CREDITS,
                GroupBy=[{"Type": "DIMENSION", "Key": "SERVICE"}],
                **({"NextPageToken": token} if token else {}))
            for result in page.get("ResultsByTime", []):
                day = date.fromisoformat(result["TimePeriod"]["Start"])
                for group in result.get("Groups", []):
                    metric = group["Metrics"]["UnblendedCost"]
                    currency = metric.get("Unit", currency)
                    rows.append((day, group["Keys"][0], float(metric["Amount"])))
            token = page.get("NextPageToken")
            if not token:
                break
        return summarize(rows, today, self._forecast_rest(ce, today), currency)

    @staticmethod
    def _forecast_rest(ce, today: date):
        """오늘 이후 월말까지 예상 비용. 새 계정처럼 예측할 데이터가 없으면 None."""
        tomorrow = today + timedelta(days=1)
        next_month = (today.replace(day=1) + timedelta(days=32)).replace(day=1)
        if tomorrow >= next_month:
            return None
        try:
            result = ce.get_cost_forecast(
                TimePeriod={"Start": tomorrow.isoformat(), "End": next_month.isoformat()},
                Metric="UNBLENDED_COST", Granularity="MONTHLY", Filter=EXCLUDE_CREDITS)
            return float(result["Total"]["Amount"])
        except Exception as err:
            logger.info("cost forecast unavailable: %s", type(err).__name__)
            return None
