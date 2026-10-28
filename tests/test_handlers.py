import json
import unittest
from datetime import datetime, timezone

from gapcheck import connections, explain
from gapcheck.store import Store
from handlers import api, scan_finished
from tests import FIXTURES
from tests.fakes import FakeCodeBuild, FakeS3, FakeSts, FakeTable

NOW = datetime(2026, 10, 28, 2, 30, tzinfo=timezone.utc)
ALICE = "6f1c2a3b-4d5e-4f60-8a7b-9c0d1e2f3a4b"
BOB = "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d"
ACCOUNT = "111122223333"


def event(route_key, sub=ALICE, body=None, **params):
    return {"routeKey": route_key, "pathParameters": params or None,
            "body": json.dumps(body) if body is not None else None,
            "requestContext": {"authorizer": {"jwt": {"claims": {"sub": sub}}}}}


class ApiTest(unittest.TestCase):
    def setUp(self):
        self.store = Store(FakeTable())
        self.sts = FakeSts()
        self.codebuild = FakeCodeBuild()
        self.deps = api.Deps(self.store, self.sts, self.codebuild, FakeS3(), "aws-gap-check-scanner",
                             "bucket", "999988887777", 10, now=lambda: NOW)

    def call(self, *args, **kwargs):
        response = api.route(event(*args, **kwargs), self.deps)
        body = json.loads(response["body"]) if "body" in response else None
        return response["statusCode"], body

    def test_full_connection_and_scan_flow(self):
        status, body = self.call("POST /connections")
        self.assertEqual(status, 201)
        conn_id, external_id = body["connection"]["id"], body["connection"]["externalId"]
        self.assertEqual(body["setup"]["serviceAccountId"], "999988887777")
        self.sts.allowed[external_id] = ACCOUNT

        status, body = self.call("POST /connections/{id}/verify", body={"accountId": ACCOUNT}, id=conn_id)
        self.assertEqual((status, body["connection"]["status"]), (200, "ACTIVE"))

        status, body = self.call("POST /scans", body={"connectionId": conn_id})
        self.assertEqual(status, 202)
        scan_id = body["scan"]["id"]
        self.assertEqual(self.call("GET /scans")[1]["scans"][0]["id"], scan_id)
        status, body = self.call("GET /scans/{id}", id=scan_id)
        self.assertEqual((status, body["findings"]), (200, []))

        self.deps.store.update_scan(ALICE, scan_id, {"status": "DONE"})
        self.assertEqual(self.call("DELETE /scans/{id}", id=scan_id)[0], 204)
        self.assertEqual(self.call("GET /scans")[1]["scans"], [])
        self.assertEqual(self.call("GET /scans/{id}", id=scan_id)[0], 404)

    def test_requires_valid_sub(self):
        for sub in ["", "not-a-uuid", None]:
            self.assertEqual(self.call("GET /scans", sub=sub)[0], 401)

    def test_other_user_gets_404(self):
        conn_id = self.call("POST /connections")[1]["connection"]["id"]
        status, _ = self.call("POST /connections/{id}/verify", sub=BOB,
                              body={"accountId": ACCOUNT}, id=conn_id)
        self.assertEqual(status, 404)
        self.assertEqual(self.call("DELETE /connections/{id}", sub=BOB, id=conn_id)[0], 404)

    def test_bad_bodies(self):
        conn_id = self.call("POST /connections")[1]["connection"]["id"]
        bad = event("POST /connections/{id}/verify", id=conn_id)
        for raw in ["{", "[1]", "x" * (api.MAX_BODY_BYTES + 1)]:
            bad["body"] = raw
            self.assertEqual(api.route(bad, self.deps)["statusCode"], 400)

    def test_unknown_route(self):
        self.assertEqual(self.call("PUT /admin")[0], 404)


class ScanFinishedTest(unittest.TestCase):
    def setUp(self):
        self.store = Store(FakeTable())
        self.codebuild = FakeCodeBuild()
        self.s3 = FakeS3()
        conn = connections.create(self.store, ALICE, NOW)
        connections.verify(self.store, FakeSts({conn["externalId"]: ACCOUNT}), ALICE, conn["id"], ACCOUNT, NOW)
        deps = api.Deps(self.store, None, self.codebuild, self.s3, "p", "bucket", "1", 10, now=lambda: NOW)
        self.scan_id = api.route(event("POST /scans", body={"connectionId": conn["id"]}), deps)
        self.scan_id = json.loads(self.scan_id["body"])["scan"]["id"]
        self.build_id = self.codebuild.started[0]["projectName"] + ":build-1"
        self.codebuild.builds[self.build_id] = {"environment": {"environmentVariables": [
            {"name": "SCAN_ID", "value": self.scan_id}, {"name": "USER_SUB", "value": ALICE}]},
            "phases": [{"phaseType": "BUILD", "phaseStatus": "FAILED"}]}
        self.generate_calls = []

    def generate(self, system, user, schema):
        self.generate_calls.append(user)
        if schema is explain.SUMMARY_SCHEMA:
            return {"overall": "요약", "top": [{"check_id": "iam_root_mfa_enabled", "reason": "루트"}]}
        return {"summary": "요약", "risk": "위험", "impact": "영향", "steps": ["조치"]}

    def run_event(self, status):
        deps = scan_finished.Deps(self.store, self.codebuild, self.s3, "bucket",
                                  lambda remaining: explain.Explainer(self.generate, self.store, model="m",
                                                                      max_rpm=6000, sleep=lambda s: None),
                                  now=lambda: NOW)
        detail = {"build-status": status,
                  "build-id": f"arn:aws:codebuild:ap-northeast-2:1:build/{self.build_id}"}
        return scan_finished.handle({"detail": detail}, deps, lambda: 600_000)

    def scan(self):
        return self.store.get_scan(ALICE, self.scan_id)

    def test_success_stores_explained_findings_and_summary(self):
        self.s3.put_json("bucket", f"raw/{ALICE}/{self.scan_id}/prowler.ocsf.json",
                         json.loads((FIXTURES / "ocsf-sample.json").read_text()))
        self.assertEqual(self.run_event("IN_PROGRESS"), "running")
        self.assertEqual(self.scan()["status"], "RUNNING")
        self.assertEqual(self.run_event("SUCCEEDED"), "done")
        scan = self.scan()
        self.assertEqual(scan["status"], "DONE")
        self.assertEqual(scan["counts"]["failedChecks"], 5)
        self.assertEqual(scan["summary"]["top"][0]["check_id"], "iam_root_mfa_enabled")
        groups = self.store.list_findings(ALICE, self.scan_id)
        self.assertEqual(len(groups), 5)
        self.assertTrue(all(g["explainSource"] == "gemini" for g in groups))
        # 같은 이벤트가 다시 와도 처리하지 않는다
        self.assertEqual(self.run_event("SUCCEEDED"), "ignored")
        self.assertEqual(len(self.generate_calls), 6)

    def test_duplicate_success_event_while_processing_is_ignored(self):
        self.s3.put_json("bucket", f"raw/{ALICE}/{self.scan_id}/prowler.ocsf.json",
                         json.loads((FIXTURES / "ocsf-sample.json").read_text()))
        # 첫 이벤트를 처리하는 중(EXPLAINING)에 같은 SUCCEEDED가 한 번 더 온 상황
        self.store.update_scan(ALICE, self.scan_id, {"status": "EXPLAINING"})
        self.assertEqual(self.run_event("SUCCEEDED"), "ignored")
        self.assertEqual(self.generate_calls, [])

    def test_build_failure_marks_failed_with_phase(self):
        self.assertEqual(self.run_event("FAILED"), "failed")
        self.assertEqual(self.scan()["status"], "FAILED")
        self.assertIn("BUILD", self.scan()["error"])

    def test_missing_result_marks_failed(self):
        self.assertEqual(self.run_event("SUCCEEDED"), "processing failed")
        self.assertEqual(self.scan()["status"], "FAILED")

    def test_unknown_or_spike_builds_are_ignored(self):
        self.codebuild.builds[self.build_id]["environment"]["environmentVariables"][1]["value"] = \
            "00000000-0000-4000-8000-000000000000"
        self.assertEqual(self.run_event("SUCCEEDED"), "ignored")


if __name__ == "__main__":
    unittest.main()
