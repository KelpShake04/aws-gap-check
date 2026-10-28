"""Prowler 결과(OCSF 목록)를 check 단위로 저장하고 해설·우선순위 요약을 붙인다.

상태는 EXPLAINING을 거쳐 DONE으로 끝난다. 호출하는 쪽이 먼저 PROCESSING으로 잡아 둔다.
"""
from __future__ import annotations

from .common import iso
from . import findings


def store_and_explain(store, explainer, sub: str, scan: dict, ocsf: list, now) -> int:
    """처리한 check 수를 돌려준다. now는 시각을 돌려주는 함수다."""
    scan_id = scan["id"]
    groups, counts = findings.parse(ocsf)
    for group in groups:
        group["explanation"], group["explainSource"] = None, "pending"
    store.put_findings(sub, scan_id, groups, scan["expiresAt"])
    store.update_scan(sub, scan_id, {"status": "EXPLAINING", "counts": counts, "updatedAt": iso(now())})

    for group in groups:
        group["explanation"], group["explainSource"] = explainer.explain(group)
        store.put_finding(sub, scan_id, group, scan["expiresAt"])
    summary = explainer.summarize(groups)
    store.update_scan(sub, scan_id, {"status": "DONE", "summary": summary, "updatedAt": iso(now())})
    return len(groups)
