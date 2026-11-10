"""스캔 작업자: QUEUED 스캔을 오래된 순서로 하나씩 꺼내 Prowler를 실행하고 결과를 저장·해설한다.

작업자 스레드 수는 SCAN_WORKERS(기본 1)로 정한다. 같은 스캔은 claim_scan이 한 스레드에만 준다.
복구·정리·자동 점검은 첫 스레드만 한다(자동 점검 스캔이 중복으로 생기지 않게). 원본 결과는 {raw_dir}/{user}/{scan}/에
두고 보존 기간(30일)이 지나면 DB 기록과 함께 지운다.
"""
from __future__ import annotations

import json
import logging
import os
import pathlib
import shutil
import subprocess
import threading
import time

from . import ids, results, scheduler
from .common import iso, utcnow

logger = logging.getLogger(__name__)

INTERRUPTED = ("RUNNING", "PROCESSING", "EXPLAINING")
RESULT_NAME = "prowler.ocsf.json"
MAX_RESULT_BYTES = 50 * 1024 * 1024
PROWLER_TIMEOUT = 60 * 60
CLEANUP_INTERVAL = 24 * 3600
SCHEDULE_INTERVAL = 60
IDLE_WAIT = 30
SCAN_FAILED = "스캔에 실패했습니다. 연결을 다시 검증하세요(Role 삭제, ExternalId 불일치 등)."


class ScanError(Exception):
    """사용자에게 보여 줄 수 있는 스캔 실패 이유."""


def run_prowler(inputs: dict, out_dir: pathlib.Path) -> None:
    """Prowler를 셸 없이 인자 목록으로 실행한다. 자격 증명은 인스턴스 Role(IMDSv2)에서 얻는다."""
    import run_scan  # scanner/run_scan.py: 입력 형식이 같은 Prowler 인자 구성을 그대로 쓴다

    # DB 비밀번호나 Gemini 키가 Prowler 프로세스로 넘어가지 않게 필요한 환경 변수만 준다
    env = {key: value for key, value in os.environ.items()
           if key in ("PATH", "HOME", "LANG") or key.startswith("AWS_")}
    try:
        process = subprocess.run(run_scan.prowler_command(inputs, str(out_dir)), check=False, env=env,
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                 timeout=PROWLER_TIMEOUT)
    except subprocess.TimeoutExpired:
        raise ScanError("스캔 시간이 초과되었습니다.") from None
    if process.returncode != 0:
        logger.error("prowler exited %d: %s", process.returncode,
                     process.stdout.decode("utf-8", "replace")[-500:])
        raise ScanError(SCAN_FAILED)


def copy_fixture(fixture: pathlib.Path):
    """데모 모드용: Prowler 대신 미리 준비한 결과 파일을 복사한다."""
    def run(inputs: dict, out_dir: pathlib.Path) -> None:
        shutil.copyfile(fixture, out_dir / RESULT_NAME)
    return run


class Worker:
    def __init__(self, store, scanner, make_explainer, raw_dir: pathlib.Path, now=utcnow,
                 notifier=None, daily_limit: int = 10):
        self.notifier = notifier  # scan_done(sub, scan)를 가진 객체. 없으면 알림 메일을 보내지 않는다
        self.daily_limit = daily_limit
        self.store = store
        self.scanner = scanner
        self.make_explainer = make_explainer
        self.raw_dir = raw_dir
        self.now = now
        self.wake = threading.Event()

    def raw_path(self, sub: str, scan_id: str) -> pathlib.Path:
        # 경로에 들어가는 값은 형식을 다시 확인한다(경로 조작 방지)
        if not (ids.valid("sub", sub) and ids.valid("scan", scan_id)):
            raise ValueError("invalid scan path")
        return self.raw_dir / sub / scan_id

    def remove_raw(self, sub: str, scan_id: str) -> None:
        shutil.rmtree(self.raw_path(sub, scan_id), ignore_errors=True)

    def recover(self) -> None:
        """서버가 꺼질 때 진행 중이던 스캔은 이어서 할 수 없으므로 실패로 표시한다."""
        count = self.store.fail_scans(INTERRUPTED, {
            "status": "FAILED", "error": "서버가 다시 시작되어 스캔이 중단되었습니다. 다시 시작하세요.",
            "updatedAt": iso(self.now())})
        if count:
            logger.warning("marked %d interrupted scans as failed", count)

    def cleanup(self) -> None:
        now = self.now()
        epoch = int(now.timestamp())
        for sub, scan_id in self.store.expired_scans(epoch):
            self.remove_raw(sub, scan_id)
        self.store.purge(epoch, iso(now))

    def run_once(self) -> bool:
        """QUEUED 스캔 하나를 처리했으면 True."""
        job = self.store.next_queued_scan()
        if job is None:
            return False
        self.process(*job)
        return True

    def process(self, sub: str, scan: dict) -> None:
        scan_id = scan["id"]
        if not self.store.claim_scan(sub, scan_id, ("QUEUED",),
                                     {"status": "RUNNING", "updatedAt": iso(self.now())}):
            return
        try:
            data = self._scan(sub, scan)
            self._update(sub, scan_id, status="PROCESSING")
            results.store_and_explain(self.store, self.make_explainer(), sub, scan, data, self.now)
            logger.info("scan %s done", scan_id)
            self._notify(sub, scan)
        except ScanError as err:
            self._update(sub, scan_id, status="FAILED", error=str(err))
        except Exception:
            logger.exception("scan %s failed", scan_id)
            self._update(sub, scan_id, status="FAILED", error="결과를 처리하지 못했습니다.")

    def _notify(self, sub: str, scan: dict) -> None:
        """메일 실패가 끝난 스캔을 실패로 만들지 않게 따로 잡는다."""
        if self.notifier is None:
            return
        try:
            self.notifier.scan_done(sub, scan)
        except Exception as err:
            logger.error("alert mail failed for scan %s: %s", scan["id"], type(err).__name__)

    def run_schedule(self) -> None:
        if scheduler.run_due(self.store, self.now(), self.daily_limit):
            self.wake.set()

    def _scan(self, sub: str, scan: dict) -> list:
        conn = self.store.get_connection(sub, scan["connectionId"])
        if not conn or conn.get("status") != "ACTIVE" or conn.get("accountId") != scan["accountId"]:
            raise ScanError("연결이 삭제되었거나 검증되지 않았습니다. 연결을 다시 검증하세요.")
        out_dir = self.raw_path(sub, scan["id"])
        out_dir.mkdir(parents=True, exist_ok=True)
        inputs = {"SCAN_ID": scan["id"], "ROLE_ARN": ids.role_arn(conn["accountId"]),
                  "EXTERNAL_ID": conn["externalId"]}
        self.scanner(inputs, out_dir)
        path = out_dir / RESULT_NAME
        if not path.is_file() or path.stat().st_size == 0:
            raise ScanError("스캔 결과 파일이 없습니다.")
        if path.stat().st_size > MAX_RESULT_BYTES:
            raise ScanError("스캔 결과가 너무 큽니다.")
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, list):
            raise ScanError("스캔 결과 형식이 올바르지 않습니다.")
        return data

    def _update(self, sub: str, scan_id: str, **fields) -> None:
        fields["updatedAt"] = iso(self.now())
        self.store.update_scan(sub, scan_id, fields)

    def loop(self, housekeeping: bool = True) -> None:
        recovered, last_cleanup, last_schedule = False, None, None
        while True:
            try:
                if housekeeping:
                    if not recovered:
                        self.recover()
                        recovered = True
                    if last_cleanup is None or time.monotonic() - last_cleanup > CLEANUP_INTERVAL:
                        self.cleanup()
                        last_cleanup = time.monotonic()
                    if last_schedule is None or time.monotonic() - last_schedule > SCHEDULE_INTERVAL:
                        self.run_schedule()
                        last_schedule = time.monotonic()
                if not self.run_once():
                    self.wake.wait(IDLE_WAIT)
                    self.wake.clear()
            except Exception:
                # DB가 잠깐 끊겨도 작업자 스레드는 살아 있어야 한다
                logger.exception("worker loop error")
                time.sleep(5)

    def start(self, threads: int = 1) -> None:
        for n in range(max(1, threads)):
            threading.Thread(target=self.loop, kwargs={"housekeeping": n == 0},
                             name=f"scan-worker-{n + 1}", daemon=True).start()
