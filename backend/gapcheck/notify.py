"""이메일 알림: 점검이 끝나면 이전보다 새로 생긴 치명·높음 항목을 사용자 이메일로 알린다.

자동 점검이 켜진 연결(schedule != off)만 대상이다. 항목이 그대로면 보내지 않는다(같은 메일이 매일 오지 않게).
메일에는 계정 ID, 점검 항목 제목, 개수, 결과 링크만 넣는다. 리소스 이름·ARN은 넣지 않는다.
"""
from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

URGENT = ("critical", "high")
SEVERITY = {"critical": "치명", "high": "높음"}
MAX_LISTED = 10
FOOTER = "이 메일은 자동 점검 알림입니다. 받지 않으려면 대시보드에서 해당 계정의 자동 점검을 끄세요."


class SesMailer:
    """sesv2 클라이언트로 텍스트 메일을 보낸다. 보내는 주소는 SES에서 확인된 주소여야 한다."""

    def __init__(self, client, sender: str):
        self.client = client
        self.sender = sender

    def send(self, to: str, subject: str, body: str) -> None:
        self.client.send_email(
            FromEmailAddress=self.sender, Destination={"ToAddresses": [to]},
            Content={"Simple": {"Subject": {"Data": subject, "Charset": "UTF-8"},
                                "Body": {"Text": {"Data": body, "Charset": "UTF-8"}}}})


def new_urgent(store, sub: str, scan: dict) -> list:
    """이 스캔의 치명·높음 항목 중 같은 연결의 직전 완료 스캔에는 없던 것. 직전 스캔이 없으면 전부."""
    previous = next((s for s in store.list_scans(sub) if s["connectionId"] == scan["connectionId"]
                     and s["status"] == "DONE" and s["id"] < scan["id"]), None)
    old = {f["checkId"] for f in store.list_findings(sub, previous["id"]) if f["severity"] in URGENT} \
        if previous else set()
    return [f for f in store.list_findings(sub, scan["id"])
            if f["severity"] in URGENT and f["checkId"] not in old]


def compose(account_id: str, scan_id: str, items: list, site_url: str) -> tuple:
    """(제목, 본문). 제목·본문에는 검증된 계정 ID와 점검 항목 제목만 쓴다."""
    subject = f"[aws-gap-check] 계정 {account_id}에서 새 위험 항목 {len(items)}개"
    lines = [f"계정 {account_id}를 점검했더니 지난 점검에 없던 치명·높음 항목이 있습니다.", ""]
    for item in items[:MAX_LISTED]:
        title = " ".join(str(item.get("title") or item["checkId"]).split())[:120]
        lines.append(f"- [{SEVERITY.get(item['severity'], item['severity'])}] {title} (리소스 {item['totalCount']}개)")
    if len(items) > MAX_LISTED:
        lines.append(f"- 외 {len(items) - MAX_LISTED}개")
    if site_url:
        lines += ["", f"자세히 보기: {site_url.rstrip('/')}/#/scans/{scan_id}"]
    return subject, "\n".join(lines + ["", FOOTER])


class Notifier:
    def __init__(self, store, mailer, site_url: str = ""):
        self.store = store
        self.mailer = mailer
        self.site_url = site_url

    def scan_done(self, sub: str, scan: dict) -> bool:
        """보냈으면 True. 보낼 항목이 없거나 알림이 꺼져 있으면 False."""
        conn = self.store.get_connection(sub, scan["connectionId"])
        if not conn or conn.get("schedule", "off") == "off":
            return False
        items = new_urgent(self.store, sub, scan)
        if not items:
            return False
        user = self.store.get_user(sub)
        if not user:
            return False
        self.mailer.send(user["email"], *compose(scan["accountId"], scan["id"], items, self.site_url))
        logger.info("alert mail sent for scan %s (%d items)", scan["id"], len(items))
        return True

    def send_test(self, email: str) -> None:
        self.mailer.send(email, "[aws-gap-check] 테스트 메일",
                         "알림 메일이 정상으로 도착했습니다.\n\n" + FOOTER)
