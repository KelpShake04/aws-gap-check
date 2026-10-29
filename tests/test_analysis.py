"""findings, validate, explain 테스트."""
import copy
import json
import unittest

from gapcheck import explain, findings, llm
from gapcheck.validate import ValidationError, validate
from tests import FIXTURES

# fixture에 들어 있는 고객 정보와 공격 문자열. 프롬프트에 하나도 들어가면 안 된다.
CUSTOMER_STRINGS = ["123456789012", "demo-public-bucket", "launch-wizard-1", "web-sg", "intern-kim",
                    "sg-0a1b2c3d4e5f60718", "Ignore previous instructions", "<img", "demo-account"]

GOOD = {"summary": "공개 버킷", "risk": "누구나 읽음", "impact": "유출", "steps": ["차단 켜기"]}


def fixture_groups():
    return findings.parse(json.loads((FIXTURES / "ocsf-sample.json").read_text()))


class FindingsTest(unittest.TestCase):
    def setUp(self):
        self.groups, self.counts = fixture_groups()

    def test_groups_fail_only_sorted_by_severity_then_count(self):
        self.assertEqual([g["checkId"] for g in self.groups], [
            "iam_root_mfa_enabled",
            "s3_bucket_public_access",
            "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22",
            "ec2_ebs_default_encryption",
            "iam_user_mfa_enabled_console_access",
        ])
        sg = self.groups[2]
        self.assertEqual(sg["totalCount"], 2)
        self.assertEqual(len(sg["resources"]), 2)

    def test_counts(self):
        self.assertEqual(self.counts["critical"], 2)
        self.assertEqual(self.counts["high"], 4)
        self.assertEqual(self.counts["passed"], 2)
        self.assertEqual(self.counts["failedChecks"], 5)

    def test_tags_and_resource_data_are_not_kept(self):
        text = json.dumps(self.groups, ensure_ascii=False)
        self.assertNotIn("Ignore previous instructions", text)
        self.assertNotIn("<img", text)
        self.assertNotIn("owner_account", text)

    def test_caps_resources_and_skips_garbage(self):
        base = json.loads((FIXTURES / "ocsf-sample.json").read_text())[0]
        many = [copy.deepcopy(base) for _ in range(150)] + ["junk", {"status_code": "FAIL"}]
        groups, counts = findings.parse(many)
        self.assertEqual(len(groups[0]["resources"]), findings.MAX_RESOURCES)
        self.assertEqual(groups[0]["totalCount"], 150)

    def test_only_https_references(self):
        base = json.loads((FIXTURES / "ocsf-sample.json").read_text())[0]
        base["remediation"]["references"] = ["javascript:alert(1)", "http://x", "https://ok"]
        groups, _ = findings.parse([base])
        self.assertEqual(groups[0]["references"], ["https://ok"])


class ValidateTest(unittest.TestCase):
    def test_accepts_and_drops_unknown_fields(self):
        result = validate({**GOOD, "extra": "x"}, explain.EXPLANATION_SCHEMA)
        self.assertEqual(result, GOOD)

    def test_rejects_missing_or_wrong_types(self):
        for bad in [{}, {**GOOD, "steps": "하나"}, {**GOOD, "risk": 3}, {**GOOD, "steps": []}, []]:
            with self.subTest(bad=bad):
                with self.assertRaises(ValidationError):
                    validate(bad, explain.EXPLANATION_SCHEMA)

    def test_truncates_long_values_and_strips_control_chars(self):
        result = validate({**GOOD, "summary": "가" * 200 + "\x00", "steps": ["a"] * 9},
                          explain.EXPLANATION_SCHEMA)
        self.assertEqual(len(result["summary"]), 80)
        self.assertEqual(len(result["steps"]), 5)


class FallbackTest(unittest.TestCase):
    def test_markdown_marks_are_removed(self):
        group = {"title": "Bucket **public**", "risk": "Breaks **confidentiality** via `s3:GetObject`.",
                 "recommendation": "Enable **Block Public Access** ([docs](https://example.com)) and __log__."}
        result = explain.fallback_explanation(group)
        self.assertEqual(result["summary"], "Bucket public")
        self.assertEqual(result["risk"], "Breaks confidentiality via s3:GetObject.")
        self.assertEqual(result["steps"], ["Enable Block Public Access (docs) and log."])


class FakeCache:
    def __init__(self):
        self.data = {}

    def get_explanation(self, check_id, version, model):
        return self.data.get((check_id, version, model))

    def put_explanation(self, check_id, version, model, explanation):
        self.data[(check_id, version, model)] = explanation


class Recorder:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.prompts = []

    def __call__(self, system, user, schema):
        self.prompts.append(system + user)
        response = self.responses.pop(0) if self.responses else GOOD
        if isinstance(response, Exception):
            raise response
        return response


class ExplainTest(unittest.TestCase):
    def setUp(self):
        self.groups, _ = fixture_groups()
        self.sleeps = []

    def explainer(self, generate, cache=None, remaining=10 ** 9):
        return explain.Explainer(generate, cache, model="m", max_rpm=60,
                                 remaining_ms=lambda: remaining, clock=lambda: 0.0,
                                 sleep=self.sleeps.append)

    def test_prompts_never_contain_customer_data(self):
        generate = Recorder()
        explainer = self.explainer(generate)
        for group in self.groups:
            explainer.explain(group)
        explainer.summarize(self.groups)
        for prompt in generate.prompts:
            for secret in CUSTOMER_STRINGS:
                self.assertNotIn(secret, prompt)

    def test_uses_cache_before_calling_model(self):
        cache, generate = FakeCache(), Recorder()
        explainer = self.explainer(generate, cache)
        self.assertEqual(explainer.explain(self.groups[0]), (GOOD, "gemini"))
        self.assertEqual(explainer.explain(self.groups[0]), (GOOD, "cache"))
        self.assertEqual(len(generate.prompts), 1)

    def test_transient_error_is_retried_once(self):
        generate = Recorder(llm.TransientError("HTTP 503"), GOOD)
        self.assertEqual(self.explainer(generate).explain(self.groups[0]), (GOOD, "gemini"))
        self.assertEqual(len(generate.prompts), 2)
        self.assertIn(explain.TRANSIENT_WAIT, self.sleeps)

    def test_transient_error_twice_falls_back(self):
        generate = Recorder(llm.TransientError("HTTP 503"), llm.TransientError("HTTP 503"))
        self.assertEqual(self.explainer(generate).explain(self.groups[0])[1], "prowler")

    def test_stops_calling_after_consecutive_failures(self):
        calls = []

        def generate(system, user, schema):
            calls.append(1)
            raise llm.LLMError("HTTP 403")

        explainer = self.explainer(generate)
        sources = [explainer.explain(g)[1] for g in self.groups[:6]]
        self.assertEqual(set(sources), {"prowler"})
        self.assertEqual(len(calls), explain.MAX_CONSECUTIVE_FAILURES)

    def test_invalid_output_retries_once_then_falls_back(self):
        generate = Recorder({"summary": 1}, {"summary": 2})
        explanation, source = self.explainer(generate).explain(self.groups[0])
        self.assertEqual(source, "prowler")
        self.assertEqual(explanation["summary"], self.groups[0]["title"][:80])
        self.assertEqual(len(generate.prompts), 2)

    def test_rate_limit_waits_then_retries(self):
        generate = Recorder(llm.RateLimited(7.0), GOOD)
        self.assertEqual(self.explainer(generate).explain(self.groups[0])[1], "gemini")
        self.assertIn(7.0, self.sleeps)

    def test_long_rate_limit_falls_back(self):
        generate = Recorder(llm.RateLimited(3600.0))
        self.assertEqual(self.explainer(generate).explain(self.groups[0])[1], "prowler")

    def test_no_time_left_or_no_model_falls_back(self):
        self.assertEqual(self.explainer(Recorder(), remaining=1000).explain(self.groups[0])[1], "prowler")
        self.assertEqual(self.explainer(None).explain(self.groups[0])[1], "prowler")

    def test_summary_drops_unknown_check_ids(self):
        summary = {"overall": "요약", "top": [
            {"check_id": "s3_bucket_public_access", "reason": "공개"},
            {"check_id": "made_up_check", "reason": "환각"},
        ]}
        result = self.explainer(Recorder(summary)).summarize(self.groups)
        self.assertEqual([t["check_id"] for t in result["top"]], ["s3_bucket_public_access"])

    def test_pacing_spaces_calls(self):
        times = iter([0.0, 0.2])
        explainer = explain.Explainer(Recorder(), None, model="m", max_rpm=60,
                                      clock=lambda: next(times), sleep=self.sleeps.append)
        explainer.explain(self.groups[0])
        explainer.explain(self.groups[1])
        self.assertAlmostEqual(self.sleeps[0], 0.8)


if __name__ == "__main__":
    unittest.main()
