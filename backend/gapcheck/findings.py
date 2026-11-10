"""Prowler OCSF 결과 파싱: FAIL만 check 단위로 묶고 심각도순으로 정렬한다.

필요한 필드만 꺼낸다. 태그(resources[].labels)와 리소스 상세(resources[].data)는 저장하지 않는다.
"""
from __future__ import annotations

import glob
import importlib.util
import json
import os
import re
from functools import lru_cache

SEVERITIES = ("critical", "high", "medium", "low", "informational")
SEVERITY_WEIGHTS = {"critical": 10, "high": 5, "medium": 2, "low": 1, "informational": 0}
MAX_RESOURCES = 100
# Prowler 메타데이터 Remediation.Code의 종류. 화면에 이 순서로 보인다(Other는 콘솔 절차)
CODE_KINDS = ("Other", "CLI", "NativeIaC", "Terraform")
# Prowler에 포함된 KISA ISMS-P 2023 매핑(한국어판). check ID → 통제 항목
ISMS_P_FILE = "kisa_isms_p_2023_korean_aws.json"


def scores(counts) -> dict | None:
    """스캔 counts에서 문제점 가중 점수(risk, 낮을수록 안전)와 보안 점수(security, 100점 만점)를 계산한다.

    리소스가 많은 계정에서 risk가 100을 넘더라도 보안 점수가 0에 고정되지 않도록 완만한 감쇠식(100 / (1 + risk/100))을 쓴다.
    """
    if not isinstance(counts, dict) or not isinstance(counts.get("failedChecks"), int):
        return None
    risk = 0
    for sev, weight in SEVERITY_WEIGHTS.items():
        val = counts.get(sev, 0)
        if isinstance(val, int) and not isinstance(val, bool) and val > 0:
            risk += val * weight
    return {"risk": risk, "security": round(100 * 100 / (100 + risk))}


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


@lru_cache(maxsize=512)
def remediation_code(check_id, root: str | None = None) -> dict:
    """check의 공식 수정 예시(Prowler 원문)를 {종류: 코드}로 돌려준다. 없으면 {}.

    OCSF 출력에는 코드가 없어서, 같은 이미지에 설치된 Prowler의 <check>.metadata.json을 읽는다.
    """
    if not isinstance(check_id, str) or not re.fullmatch(r"[a-z0-9_]{1,120}", check_id):
        return {}
    root = root or _prowler_root()
    if not root:
        return {}
    paths = glob.glob(os.path.join(glob.escape(root), "providers", "aws", "services", "*",
                                   check_id, f"{check_id}.metadata.json"))
    try:
        with open(paths[0], encoding="utf-8") as f:
            code = json.load(f)["Remediation"]["Code"]
    except (IndexError, OSError, ValueError, KeyError, TypeError):
        return {}
    if not isinstance(code, dict):
        return {}
    return {kind: _unfence(code[kind])[:4000] for kind in CODE_KINDS
            if isinstance(code.get(kind), str) and code[kind].strip()}


def _prowler_root() -> str:
    spec = importlib.util.find_spec("prowler")
    return os.path.dirname(spec.origin) if spec is not None and spec.origin else ""


@lru_cache(maxsize=4)
def isms_p_index(root: str | None = None) -> dict:
    """check ID → ISMS-P 통제 항목 [{id, name}] 목록. 없으면 {}.

    Prowler에 들어 있는 KISA ISMS-P 2023(한국어) 매핑 파일을 읽는다. 결과는 공유 캐시라 바꾸지 않는다.
    """
    root = root or _prowler_root()
    if not root:
        return {}
    try:
        with open(os.path.join(root, "compliance", "aws", ISMS_P_FILE), encoding="utf-8") as f:
            requirements = json.load(f)["Requirements"]
    except (OSError, ValueError, KeyError, TypeError):
        return {}
    index = {}
    for req in requirements if isinstance(requirements, list) else []:
        if not isinstance(req, dict):
            continue
        item_id, name = req.get("Id"), req.get("Name")
        if not (isinstance(item_id, str) and re.fullmatch(r"[0-9]{1,2}(\.[0-9]{1,2}){1,3}", item_id)
                and isinstance(name, str)):
            continue
        item = {"id": item_id, "name": name[:100]}
        for check in req.get("Checks") or []:
            if isinstance(check, str) and item not in index.setdefault(check, []):
                index[check].append(item)
    for items in index.values():
        items.sort(key=lambda item: tuple(int(part) for part in item["id"].split(".")))
    return index


def isms_p(check_id, root: str | None = None) -> list:
    """check가 대응하는 ISMS-P 통제 항목 목록(복사본)."""
    if not isinstance(check_id, str):
        return []
    return [dict(item) for item in isms_p_index(root).get(check_id, [])]


def isms_p_covered(check_ids, root: str | None = None) -> int:
    """check 목록이 대응하는 ISMS-P 통제 항목 수(중복 제외)."""
    index = isms_p_index(root)
    return len({item["id"] for check in check_ids for item in index.get(check, [])})


def _unfence(text: str) -> str:
    """```hcl ... ``` 처럼 감싼 값이면 펜스 줄을 뺀다."""
    lines = text.strip().split("\n")
    if len(lines) >= 2 and lines[0].startswith("```") and lines[-1].strip() == "```":
        lines = lines[1:-1]
    return "\n".join(lines)


def _text(value, limit: int) -> str:
    return value[:limit] if isinstance(value, str) else ""
