"""Prowler OCSF 결과 파싱: FAIL만 check 단위로 묶고 심각도순으로 정렬한다.

필요한 필드만 꺼낸다. 태그(resources[].labels)와 리소스 상세(resources[].data)는 저장하지 않는다.
"""
from __future__ import annotations

SEVERITIES = ("critical", "high", "medium", "low", "informational")
MAX_RESOURCES = 100


def parse(findings: list):
    """(groups, counts)를 돌려준다. counts는 심각도별 실패 리소스 수, 실패 check 수, 통과 수."""
    groups = {}
    counts = {severity: 0 for severity in SEVERITIES}
    counts["passed"] = 0
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        status = finding.get("status_code")
        if status == "PASS":
            counts["passed"] += 1
        if status != "FAIL":
            continue
        metadata = finding.get("metadata") or {}
        check_id = _text(metadata.get("event_code"), 120)
        if not check_id:
            continue
        severity = _text(finding.get("severity"), 20).lower()
        if severity not in SEVERITIES:
            severity = "informational"
        counts[severity] += 1
        resources = [r for r in finding.get("resources") or [] if isinstance(r, dict)]
        group = groups.get(check_id)
        if group is None:
            info = finding.get("finding_info") or {}
            remediation = finding.get("remediation") or {}
            first = resources[0] if resources else {}
            group = groups[check_id] = {
                "checkId": check_id,
                "title": _text(info.get("title"), 300),
                "severity": severity,
                "rank": SEVERITIES.index(severity),
                "service": _text((first.get("group") or {}).get("name"), 60),
                "resourceType": _text(first.get("type"), 100),
                "description": _text(info.get("desc"), 2000),
                "risk": _text(finding.get("risk_details"), 2000),
                "recommendation": _text(remediation.get("desc"), 2000),
                "references": [_text(url, 500) for url in remediation.get("references") or []
                               if isinstance(url, str) and url.startswith("https://")][:3],
                "resources": [],
                "regions": [],
                "totalCount": 0,
            }
        group["totalCount"] += 1
        for resource in resources:
            region = _text(resource.get("region"), 30)
            if region and region not in group["regions"]:
                group["regions"].append(region)
            if len(group["resources"]) < MAX_RESOURCES:
                group["resources"].append({"uid": _text(resource.get("uid"), 512),
                                           "name": _text(resource.get("name"), 256),
                                           "region": region})
    ordered = sorted(groups.values(), key=lambda g: (g["rank"], -g["totalCount"], g["checkId"]))
    for group in ordered:
        group["regions"].sort()
    counts["failedChecks"] = len(ordered)
    return ordered, counts


def _text(value, limit: int) -> str:
    return value[:limit] if isinstance(value, str) else ""
