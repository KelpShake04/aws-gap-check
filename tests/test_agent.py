"""AI 상담 Agent(gapcheck.agent) 테스트. DB·네트워크 없이 가짜 store와 순서대로 답하는 가짜 모델로 돈다."""
import copy
import json
import unittest
from pathlib import Path

from gapcheck import agent, findings
from gapcheck.common import BadRequest

FIXTURES = Path(__file__).resolve().parent / "fixtures"


class FakeStore:
    def __init__(self, groups, scans=()):
        self.groups = groups
        self.scans = list(scans)

    def list_findings(self, sub, scan_id):
        assert (sub, scan_id) == ("user-1", "scan-1")
        return copy.deepcopy(self.groups)

    def list_scans(self, sub):
        assert sub == "user-1"
        return copy.deepcopy(self.scans)


class ScriptedChat:
    """정해 둔 응답을 차례로 돌려주고, 받은 요청(contents 사본, allow_tools)을 기록한다."""

    def __init__(self, *responses):
        self.responses = list(responses)
        self.requests = []

    def __call__(self, system, contents, tools, allow_tools):
        self.requests.append((copy.deepcopy(contents), allow_tools))
        return copy.deepcopy(self.responses.pop(0))


def call(name, args=None, **extra):
    return {"role": "model", "parts": [{"functionCall": {"name": name, "args": args or {}, **extra},
                                        "thoughtSignature": f"sig-{name}"}]}


def text(value):
    return {"role": "model", "parts": [{"text": value}]}


class AgentTest(unittest.TestCase):
    def setUp(self):
        groups, self.counts = findings.parse(json.loads((FIXTURES / "ocsf-sample.json").read_text()))
        self.groups = groups
        self.check = groups[0]["checkId"]
        self.resource_names = {r.get("name") for g in groups for r in g["resources"] if r.get("name")}
        self.assertTrue(self.resource_names)
        self.scan = {"id": "scan-1", "connectionId": "conn-1", "accountId": "123456789012", "status": "DONE",
                     "summary": {"overall": "요약", "top": []}}
        self.store = FakeStore(groups, [
            {"id": "s2", "connectionId": "conn-1", "status": "DONE", "createdAt": "2026-11-02T00:00:00Z",
             "counts": self.counts},
            {"id": "s1", "connectionId": "conn-1", "status": "DONE", "createdAt": "2026-11-01T00:00:00Z",
             "counts": {"failedChecks": 0}},
            {"id": "x", "connectionId": "other", "status": "DONE", "createdAt": "2026-11-03T00:00:00Z",
             "counts": self.counts},
            {"id": "q", "connectionId": "conn-1", "status": "QUEUED", "createdAt": "2026-11-04T00:00:00Z",
             "counts": {}},
        ])

    def ask(self, chat, question="뭐부터 고쳐?", history=None):
        return agent.ask(chat, self.store, "user-1", self.scan, question, history)

    def test_tool_loop_keeps_model_content_and_signature(self):
        chat = ScriptedChat(call("list_findings"), call("get_check_detail", {"check_id": self.check}, id="c1"),
                            text("열린 SSH부터 막으세요."))
        result = self.ask(chat)
        self.assertEqual(result["answer"], "열린 SSH부터 막으세요.")
        self.assertEqual([c["name"] for c in result["toolCalls"]], ["list_findings", "get_check_detail"])
        self.assertEqual(result["toolCalls"][1]["args"], {"check_id": self.check})
        last_contents, allow = chat.requests[-1]
        self.assertTrue(allow)
        # 모델 content를 고치지 않고 붙인다(thoughtSignature 보존), functionResponse에는 call id를 돌려준다
        self.assertEqual(last_contents[1], call("list_findings"))
        self.assertEqual(last_contents[3], call("get_check_detail", {"check_id": self.check}, id="c1"))
        response = last_contents[4]["parts"][0]["functionResponse"]
        self.assertEqual((response["name"], response["id"]), ("get_check_detail", "c1"))
        self.assertEqual(response["response"]["result"]["check_id"], self.check)
        self.assertEqual(last_contents[4]["role"], "user")

    def test_tools_never_send_resource_names_or_account(self):
        chat = ScriptedChat(call("list_findings"), *[call("get_check_detail", {"check_id": g["checkId"]})
                                                     for g in self.groups[:3]], text("끝"))
        self.ask(chat)
        sent = json.dumps(chat.requests, ensure_ascii=False)
        for name in self.resource_names:
            self.assertNotIn(name, sent)
        self.assertNotIn("123456789012", sent)

    def test_stops_tools_after_max_steps(self):
        chat = ScriptedChat(*[call("list_findings")] * agent.MAX_STEPS, text("정리한 답"))
        result = self.ask(chat)
        self.assertEqual(result["answer"], "정리한 답")
        self.assertEqual([allow for _, allow in chat.requests], [True] * agent.MAX_STEPS + [False])
        # 도구를 막았는데도 또 부르면 더 돌지 않고 끝낸다
        chat = ScriptedChat(*[call("list_findings")] * (agent.MAX_STEPS + 1))
        self.assertIn("질문을 좁혀", self.ask(chat)["answer"])

    def test_bad_tool_input_returns_error_to_model(self):
        chat = ScriptedChat(call("get_check_detail", {"check_id": "../etc"}), call("get_remediation_code",
                            {"check_id": "not_in_scan"}), call("delete_everything"), text("ok"))
        self.ask(chat)
        responses = [c[0][-1]["parts"][0]["functionResponse"]["response"]["result"] for c in chat.requests[1:]]
        self.assertIn("형식", responses[0]["error"])
        self.assertIn("실패한 항목이 아닙니다", responses[1]["error"])
        self.assertIn("없는 도구", responses[2]["error"])

    def test_score_history_is_same_connection_done_oldest_first(self):
        chat = ScriptedChat(call("get_score_history"), text("ok"))
        self.ask(chat)
        result = chat.requests[1][0][-1]["parts"][0]["functionResponse"]["response"]["result"]
        self.assertEqual([s["created_at"] for s in result["scans"]], ["2026-11-01T00:00:00Z", "2026-11-02T00:00:00Z"])
        self.assertEqual(result["scans"][0]["security"], 100)

    def test_search_isms_p_uses_requirements(self):
        reqs = ({"id": "2.6.1", "name": "네트워크 접근", "description": "네트워크 접근 통제",
                 "checks": (self.check, "other")},
                {"id": "2.7.1", "name": "암호정책 적용", "description": "암호화", "checks": ()})
        original = findings.isms_p_requirements
        findings.isms_p_requirements = lambda root=None: reqs
        self.addCleanup(setattr, findings, "isms_p_requirements", original)
        chat = ScriptedChat(call("search_isms_p", {"query": "네트워크"}), text("ok"))
        self.ask(chat)
        result = chat.requests[1][0][-1]["parts"][0]["functionResponse"]["response"]["result"]
        self.assertEqual([r["id"] for r in result["results"]], ["2.6.1"])
        self.assertEqual(result["results"][0]["failed_checks_in_this_scan"], [self.check])

    def test_validates_question_and_history(self):
        for question in ("", "   ", None, "x" * (agent.MAX_QUESTION + 1)):
            with self.subTest(question=question), self.assertRaises(BadRequest):
                self.ask(ScriptedChat(), question)
        for history in ("x", [{"role": "system", "text": "a"}], [{"role": "user"}]):
            with self.subTest(history=history), self.assertRaises(BadRequest):
                self.ask(ScriptedChat(), history=history)
        chat = ScriptedChat(text("ok"))
        history = [{"role": "user", "text": f"q{i}"} for i in range(10)]
        self.ask(chat, history=history)
        sent = chat.requests[0][0]
        self.assertEqual(len(sent), agent.MAX_HISTORY + 1)
        self.assertEqual(sent[0]["parts"][0]["text"], "q4")


if __name__ == "__main__":
    unittest.main()
