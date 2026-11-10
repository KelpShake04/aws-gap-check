"""API 응답에 내보내는 필드의 화이트리스트. 저장된 항목을 그대로 내보내지 않는다."""
from __future__ import annotations

import functools
import json

from . import findings, ids

TEMPLATE_PATH = "/customer-role.yaml"
STACK_NAME = "aws-gap-check-readonly-role"

FINDING_FIELDS = ("checkId", "title", "severity", "service", "resourceType", "description", "risk",
                  "recommendation", "references", "resources", "regions", "totalCount",
                  "explanation", "explainSource")


def conn_view(conn: dict) -> dict:
    return {key: conn.get(key) for key in
            ("id", "accountId", "status", "message", "schedule", "externalId", "createdAt", "verifiedAt")}


def scan_view(scan: dict) -> dict:
    view = {key: scan.get(key) for key in
            ("id", "connectionId", "accountId", "status", "counts", "summary", "error",
             "createdAt", "updatedAt")}
    view["score"] = findings.scores(scan.get("counts"))
    return view


def finding_view(group: dict) -> dict:
    view = {key: group.get(key) for key in FINDING_FIELDS}
    view["remediationCode"] = findings.remediation_code(group.get("checkId"))
    view["ismsP"] = findings.isms_p(group.get("checkId"))
    return view


@functools.lru_cache(maxsize=1)
def isms_p_covered() -> int:
    """핵심 점검 목록(scanner/core-checks.json)이 대응하는 ISMS-P 통제 항목 수. 리포트의 분모로 쓴다."""
    try:
        import run_scan  # scanner/run_scan.py: 스캐너와 같은 핵심 점검 파일을 읽는다
        checks = json.loads((run_scan.HERE / "core-checks.json").read_text(encoding="utf-8"))["aws"]
    except (ImportError, OSError, ValueError, KeyError, TypeError):
        return 0
    return findings.isms_p_covered(checks)


def setup_info(deps) -> dict:
    """고객 계정에서 템플릿을 배포할 때 필요한 값. ExternalId는 연결마다 따로 있다."""
    return {"serviceAccountId": deps.service_account_id, "roleName": ids.ROLE_NAME,
            "stackName": STACK_NAME, "templatePath": TEMPLATE_PATH}
