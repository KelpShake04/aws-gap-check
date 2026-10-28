"""Prowler 실행부(gapcheck.worker.run_prowler) 테스트. DB 없이 돈다."""
import pathlib
import subprocess
import unittest
from unittest import mock

from gapcheck import worker

INPUTS = {"SCAN_ID": "20261029000000-deadbeef", "EXTERNAL_ID": "agc-" + "0" * 32,
          "ROLE_ARN": "arn:aws:iam::111122223333:role/AwsGapCheckReadOnlyRole"}
ENV = {"PATH": "/usr/bin", "HOME": "/home/prowler", "AWS_REGION": "ap-northeast-2",
       "DB_PASSWORD": "db-secret", "GEMINI_API_KEY": "gemini-secret"}


class RunProwlerTest(unittest.TestCase):
    def run_with(self, result):
        with mock.patch.dict("os.environ", ENV, clear=True), \
                mock.patch("gapcheck.worker.subprocess.run", side_effect=[result]) as run:
            try:
                worker.run_prowler(INPUTS, pathlib.Path("/data/raw/x"))
            finally:
                self.call = run.call_args
        return self.call

    def test_passes_argument_list_and_only_needed_env(self):
        call = self.run_with(subprocess.CompletedProcess([], 0, b"", b""))
        command, env = call.args[0], call.kwargs["env"]
        self.assertIsInstance(command, list)
        self.assertIn(INPUTS["EXTERNAL_ID"], command)
        self.assertEqual(env, {"PATH": "/usr/bin", "HOME": "/home/prowler", "AWS_REGION": "ap-northeast-2"})
        self.assertNotIn("shell", call.kwargs)

    def test_failures_become_user_messages(self):
        with self.assertRaises(worker.ScanError) as caught:
            self.run_with(subprocess.CompletedProcess([], 1, b"", b"NoCredentialsError"))
        self.assertEqual(str(caught.exception), worker.SCAN_FAILED)
        with self.assertRaises(worker.ScanError):
            self.run_with(subprocess.TimeoutExpired("prowler", 1))


if __name__ == "__main__":
    unittest.main()
