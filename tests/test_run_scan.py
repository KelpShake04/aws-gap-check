import json
import pathlib
import subprocess
import tempfile
import unittest

import run_scan
from tests import ROOT

VALID = {
    "SCAN_ID": "20261028023000-ab12cd34",
    "USER_SUB": "6f1c2a3b-4d5e-4f60-8a7b-9c0d1e2f3a4b",
    "ROLE_ARN": "arn:aws:iam::111122223333:role/AwsGapCheckReadOnlyRole",
    "EXTERNAL_ID": "agc-0123456789abcdef0123456789abcdef",
    "RESULTS_BUCKET": "aws-gap-check-resultsbucket-abc123",
}


def env_with(**changes):
    env = dict(VALID)
    env.update(changes)
    return env


class ReadInputsTest(unittest.TestCase):
    def test_accepts_valid_inputs(self):
        self.assertEqual(run_scan.read_inputs(VALID), VALID)

    def test_rejects_missing_value(self):
        env = dict(VALID)
        del env["EXTERNAL_ID"]
        with self.assertRaises(run_scan.InputError):
            run_scan.read_inputs(env)

    def test_rejects_bad_values(self):
        cases = {
            "SCAN_ID": [
                "20261028023000-ab12cd34\n; rm -rf /",   # 줄바꿈 뒤 명령
                "20261028023000-AB12CD34",               # 대문자 hex
                "٢٠٢٦١٠٢٨٠٢٣٠٠٠-ab12cd34",               # 유니코드 숫자
                "",
            ],
            "USER_SUB": ["../other-user", "6f1c2a3b-4d5e-4f60-8a7b-9c0d1e2f3a4b/x"],
            "ROLE_ARN": [
                "arn:aws:iam::111122223333:role/OtherRole",
                "arn:aws:iam::11112222333:role/AwsGapCheckReadOnlyRole",
                "arn:aws:iam::111122223333:role/AwsGapCheckReadOnlyRole$(id)",
            ],
            "EXTERNAL_ID": ["agc-short", "agc-0123456789abcdef0123456789abcdef;id", "x" * 40],
            "RESULTS_BUCKET": ["Bad_Bucket", "a"],
        }
        for name, values in cases.items():
            for value in values:
                with self.subTest(name=name, value=value):
                    with self.assertRaises(run_scan.InputError):
                        run_scan.read_inputs(env_with(**{name: value}))

    def test_error_message_does_not_echo_value(self):
        with self.assertRaises(run_scan.InputError) as ctx:
            run_scan.read_inputs(env_with(EXTERNAL_ID="agc-$(curl evil)"))
        self.assertNotIn("curl", str(ctx.exception))


class ProwlerCommandTest(unittest.TestCase):
    def setUp(self):
        self.cmd = run_scan.prowler_command(VALID, "/tmp/out")

    def option(self, flag):
        return self.cmd[self.cmd.index(flag) + 1]

    def test_is_argument_list_for_aws_provider(self):
        self.assertIsInstance(self.cmd, list)
        self.assertEqual(self.cmd[:2], [run_scan.PROWLER_BIN, "aws"])

    def test_assumes_customer_role_with_external_id(self):
        self.assertEqual(self.option("--role"), VALID["ROLE_ARN"])
        self.assertEqual(self.option("--external-id"), VALID["EXTERNAL_ID"])
        self.assertEqual(self.option("--role-session-name"),
                         "aws-gap-check-20261028023000-ab12cd34")

    def test_scan_scope_and_output(self):
        self.assertEqual(self.option("--checks-file"),
                         str(ROOT / "scanner" / "core-checks.json"))
        self.assertEqual(self.option("--region"), "ap-northeast-2")
        self.assertEqual(self.option("--output-formats"), "json-ocsf")
        self.assertEqual(self.option("--output-directory"), "/tmp/out")
        self.assertEqual(self.option("--output-filename"), "prowler")

    def test_failed_findings_do_not_fail_the_build(self):
        self.assertIn("--ignore-exit-code-3", self.cmd)

    def test_session_name_fits_sts_limit(self):
        self.assertLessEqual(len(self.option("--role-session-name")), 64)


class ResultTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = pathlib.Path(self.tmp.name) / "prowler.ocsf.json"

    def tearDown(self):
        self.tmp.cleanup()

    def test_key_is_per_user_and_scan(self):
        self.assertEqual(
            run_scan.result_key(VALID),
            "raw/6f1c2a3b-4d5e-4f60-8a7b-9c0d1e2f3a4b/20261028023000-ab12cd34/prowler.ocsf.json",
        )

    def test_counts_findings(self):
        self.path.write_text(json.dumps([{"a": 1}, {"b": 2}]))
        self.assertEqual(run_scan.check_result(self.path), 2)

    def test_rejects_missing_empty_broken_or_non_list(self):
        with self.assertRaises(run_scan.ResultError):
            run_scan.check_result(self.path)
        for content in ["", "[{broken", '{"not": "a list"}']:
            with self.subTest(content=content):
                self.path.write_text(content)
                with self.assertRaises(run_scan.ResultError):
                    run_scan.check_result(self.path)


class MainTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.out = pathlib.Path(self.tmp.name)
        self.calls = []
        self.uploads = []

    def tearDown(self):
        self.tmp.cleanup()

    def fake_run(self, returncode=0, findings=1):
        def run(cmd, check):
            self.calls.append(cmd)
            if returncode == 0:
                (self.out / "prowler.ocsf.json").write_text(json.dumps([{}] * findings))
            return subprocess.CompletedProcess(cmd, returncode)
        return run

    def upload(self, path, bucket, key):
        self.uploads.append((path.name, bucket, key))

    def main(self, env, run):
        return run_scan.main(env, run=run, upload=self.upload, output_dir=str(self.out))

    def test_success_uploads_result(self):
        self.assertEqual(self.main(VALID, self.fake_run()), 0)
        self.assertEqual(self.uploads, [
            ("prowler.ocsf.json", VALID["RESULTS_BUCKET"], run_scan.result_key(VALID)),
        ])

    def test_invalid_input_never_runs_prowler(self):
        code = self.main(env_with(ROLE_ARN="x"), self.fake_run())
        self.assertNotEqual(code, 0)
        self.assertEqual(self.calls, [])
        self.assertEqual(self.uploads, [])

    def test_prowler_failure_fails_build_without_upload(self):
        code = self.main(VALID, self.fake_run(returncode=1))
        self.assertEqual(code, 1)
        self.assertEqual(self.uploads, [])


class CoreChecksTest(unittest.TestCase):
    def test_checks_file_format(self):
        data = json.loads((ROOT / "scanner" / "core-checks.json").read_text())
        checks = data["aws"]
        self.assertGreater(len(checks), 0)
        self.assertEqual(len(checks), len(set(checks)))
        for check in checks:
            self.assertRegex(check, r"^[a-z0-9_]+$")


if __name__ == "__main__":
    unittest.main()
