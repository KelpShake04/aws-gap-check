import copy
import json
import unittest

import sanitize_ocsf
from tests import FIXTURES

SECRETS = [
    "123456789012",                 # 계정 ID
    "demo-account",                 # 계정 이름
    "demo-public-bucket", "agc-private-logs", "intern-kim", "org-trail",  # 리소스 이름
    "launch-wizard-1", "web-sg",    # data.metadata.name에만 있는 이름
    "sg-0a1b2c3d4e5f60718", "vpc-0123456789abcdef0",  # 리소스 ID
    "intern.kim@example.com",       # 태그의 이메일
    "Ignore previous instructions", "<img",  # 태그의 인젝션 문구, HTML
]


def load_fixture():
    return json.loads((FIXTURES / "ocsf-sample.json").read_text())


class SanitizeFixtureTest(unittest.TestCase):
    def setUp(self):
        self.original = load_fixture()
        self.sanitized, self.stats = sanitize_ocsf.sanitize(copy.deepcopy(self.original))
        self.text = json.dumps(self.sanitized, ensure_ascii=False)

    def test_removes_identifying_values(self):
        for secret in SECRETS:
            with self.subTest(secret=secret):
                self.assertNotIn(secret, self.text)

    def test_keeps_check_results(self):
        def summary(findings):
            return [(f["metadata"]["event_code"], f["severity"], f["status_code"],
                     f["finding_info"]["title"], f["risk_details"], f["remediation"])
                    for f in findings]
        self.assertEqual(summary(self.sanitized), summary(self.original))

    def test_drops_tags_and_resource_data(self):
        for finding in self.sanitized:
            for resource in finding["resources"]:
                self.assertEqual(resource["labels"], [])
                self.assertEqual(resource["data"], {})

    def test_same_value_maps_to_same_fake(self):
        accounts = {f["cloud"]["account"]["uid"] for f in self.sanitized}
        self.assertEqual(len(accounts), 1)
        self.assertNotEqual(accounts, {"123456789012"})
        account = accounts.pop()
        for finding in self.sanitized:
            self.assertIn(account, finding["finding_info"]["uid"])

    def test_resource_name_and_uid_stay_consistent(self):
        bucket = self.sanitized[0]["resources"][0]
        self.assertEqual(bucket["uid"], f"arn:aws:s3:::{bucket['name']}")

    def test_input_is_not_modified(self):
        original = load_fixture()
        sanitize_ocsf.sanitize(original)
        self.assertEqual(original, load_fixture())

    def test_reports_counts(self):
        self.assertEqual(self.stats["findings"], len(self.original))
        self.assertEqual(self.stats["account"], 1)
        self.assertGreaterEqual(self.stats["name"], 6)


class GenericPatternTest(unittest.TestCase):
    def detail_after(self, text):
        finding = load_fixture()[0]
        finding["status_detail"] = text
        sanitized, _ = sanitize_ocsf.sanitize([finding])
        return sanitized[0]["status_detail"]

    def test_keeps_any_ipv4_cidr_but_replaces_addresses(self):
        result = self.detail_after("open to 0.0.0.0/0 and 203.0.113.5/32")
        self.assertIn("0.0.0.0/0", result)
        self.assertNotIn("203.0.113.5", result)

    def test_replaces_access_key_id(self):
        result = self.detail_after("access key AKIAABCDEFGHIJKLMNOP is old")
        self.assertNotIn("AKIAABCDEFGHIJKLMNOP", result)


if __name__ == "__main__":
    unittest.main()
