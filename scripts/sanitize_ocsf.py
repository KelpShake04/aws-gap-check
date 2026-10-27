#!/usr/bin/env python3
"""실제 Prowler OCSF 결과를 테스트 fixture로 쓸 수 있게 익명화한다.

    python3 scripts/sanitize_ocsf.py <입력.ocsf.json> <출력.json>

바꾸는 것: 계정 ID, 리소스 이름(resources[].name, data.metadata.name), 리소스 ID(sg-, vpc- 등),
이메일, IPv4 주소(0.0.0.0 제외), 액세스 키 ID. 지우는 것: 태그, 리소스 상세(data), 계정·조직 이름.
점검 항목(check ID, 심각도, 상태, Prowler 설명)은 그대로 둔다.

이름 치환은 고객 값이 들어가는 필드에만 하고, 패턴(계정 ID 등) 치환은 모든 문자열에 한다.
자동 치환이 놓칠 수 있으므로 출력의 status_detail 목록을 사람이 확인한 뒤 커밋한다.
"""
from __future__ import annotations

import argparse
import copy
import json
import pathlib
import re
import sys

ACCOUNT_RE = re.compile(r"(?<![0-9])[0-9]{12}(?![0-9])")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
ACCESS_KEY_RE = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
IPV4_RE = re.compile(r"(?<![0-9.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9.])")
RESOURCE_ID_RE = re.compile(
    r"\b(sg|vpc|subnet|i|vol|snap|eni|ami|igw|rtb|acl|nat|eipalloc)-[0-9a-f]{8,17}\b"
)
# UUID 마지막 12자리가 숫자뿐이면 계정 ID로 오인하므로 UUID 구간은 건너뛴다(scan_id 등).
UUID_SPLIT_RE = re.compile(
    r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"
)


class Sanitizer:
    def __init__(self):
        self.maps = {"account": {}, "name": {}, "resource_id": {}}
        self.produced = set()
        self.counts = {"email": 0, "ip": 0, "access_key": 0}

    def _fake(self, kind: str, original: str, make) -> str:
        if original in self.produced:
            return original
        mapping = self.maps[kind]
        if original not in mapping:
            fake = make(len(mapping) + 1)
            mapping[original] = fake
            self.produced.add(fake)
        return mapping[original]

    def register_name(self, name) -> None:
        if not isinstance(name, str) or not name or name.startswith("<"):
            return
        if ACCOUNT_RE.fullmatch(name) or RESOURCE_ID_RE.fullmatch(name):
            return
        self._fake("name", name, lambda n: f"resource-{n}")

    def generic(self, text: str) -> str:
        text = ACCESS_KEY_RE.sub(self._access_key, text)
        text = EMAIL_RE.sub(self._email, text)
        text = IPV4_RE.sub(self._ip, text)
        text = RESOURCE_ID_RE.sub(
            lambda m: self._fake("resource_id", m.group(0),
                                 lambda n: f"{m.group(1)}-{n:017d}"), text)
        parts = UUID_SPLIT_RE.split(text)
        for index in range(0, len(parts), 2):  # 홀수 번째는 UUID
            parts[index] = ACCOUNT_RE.sub(
                lambda m: self._fake("account", m.group(0),
                                     lambda n: str(n) * 12 if n < 10 else f"{n:012d}"),
                parts[index])
        return "".join(parts)

    def customer(self, text: str) -> str:
        """고객 값이 들어가는 필드: 등록된 이름을 긴 것부터 바꾼 뒤 패턴 치환."""
        for name in sorted(self.maps["name"], key=len, reverse=True):
            text = text.replace(name, self.maps["name"][name])
        return self.generic(text)

    def walk(self, value):
        if isinstance(value, str):
            return self.generic(value)
        if isinstance(value, list):
            return [self.walk(item) for item in value]
        if isinstance(value, dict):
            return {key: self.walk(item) for key, item in value.items()}
        return value

    def _access_key(self, _match) -> str:
        self.counts["access_key"] += 1
        return "AKIAIOSFODNN7EXAMPLE"

    def _email(self, _match) -> str:
        self.counts["email"] += 1
        return "user@example.com"

    def _ip(self, match) -> str:
        if match.group(0) == "0.0.0.0":
            return match.group(0)
        self.counts["ip"] += 1
        return "192.0.2.1"


def sanitize(findings: list):
    """익명화한 사본과 치환 통계를 돌려준다. 입력은 바꾸지 않는다."""
    findings = copy.deepcopy(findings)
    sanitizer = Sanitizer()
    for finding in findings:
        for resource in finding.get("resources", []):
            sanitizer.register_name(resource.get("name"))
            metadata = (resource.get("data") or {}).get("metadata")
            if isinstance(metadata, dict):
                sanitizer.register_name(metadata.get("name"))

    for finding in findings:
        for key in ("message", "status_detail"):
            if isinstance(finding.get(key), str):
                finding[key] = sanitizer.customer(finding[key])
        info = finding.get("finding_info") or {}
        for key in ("uid", "name"):
            if isinstance(info.get(key), str):
                info[key] = sanitizer.customer(info[key])
        for resource in finding.get("resources", []):
            resource["labels"] = []
            resource["data"] = {}
            for key in ("name", "uid"):
                if isinstance(resource.get(key), str):
                    resource[key] = sanitizer.customer(resource[key])
        cloud = finding.get("cloud") or {}
        if "account" in cloud:
            cloud["account"]["name"] = ""
            cloud["account"]["labels"] = []
        if "org" in cloud:
            cloud["org"] = {"name": "", "uid": ""}

    findings = sanitizer.walk(findings)
    stats = {kind: len(mapping) for kind, mapping in sanitizer.maps.items()}
    stats.update(sanitizer.counts)
    stats["findings"] = len(findings)
    return findings, stats


def main() -> int:
    parser = argparse.ArgumentParser(description="Prowler OCSF 결과 익명화")
    parser.add_argument("source", type=pathlib.Path)
    parser.add_argument("target", type=pathlib.Path)
    args = parser.parse_args()

    findings = json.loads(args.source.read_text(encoding="utf-8"))
    sanitized, stats = sanitize(findings)
    args.target.write_text(json.dumps(sanitized, indent=2, ensure_ascii=False) + "\n",
                           encoding="utf-8")
    print(f"치환 통계: {stats}")
    print("\n커밋 전에 아래 status_detail에 남은 실제 이름이 없는지 확인하세요:")
    for detail in sorted({f.get("status_detail", "") for f in sanitized}):
        print(f"  - {detail}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
