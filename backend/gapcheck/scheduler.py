"""자동 점검: 주기가 지난 연결마다 QUEUED 스캔을 만든다. 실제 실행은 작업자가 한다.

마지막 스캔(상태와 관계없이)에서 주기가 지나지 않았으면 건너뛴다. 사용자에게 이미 진행 중인 스캔이
있거나 하루 한도에 걸리면 이번엔 건너뛰고 다음 확인 때 다시 시도한다.
"""
from __future__ import annotations

import logging
from datetime import timedelta

from . import scans
from .common import ApiError, parse_iso

logger = logging.getLogger(__name__)

INTERVALS = {"daily": timedelta(hours=24), "weekly": timedelta(days=7)}


def run_due(store, now, daily_limit: int) -> int:
    """새로 만든 스캔 수."""
    created = 0
    for sub, conn in store.scheduled_connections():
        interval = INTERVALS.get(conn["schedule"])
        if interval is None:
            continue
        last = next((s for s in store.list_scans(sub) if s["connectionId"] == conn["id"]), None)
        if last and now - parse_iso(last["createdAt"]) < interval:
            continue
        try:
            scans.create(store, sub, conn["id"], now=now, daily_limit=daily_limit)
            created += 1
        except ApiError as err:
            logger.info("scheduled scan skipped for connection %s: %s", conn["id"], err.code)
    return created
