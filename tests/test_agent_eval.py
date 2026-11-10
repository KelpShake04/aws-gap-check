import io
import unittest
from contextlib import redirect_stdout
from unittest import mock

import agent_eval  # scripts/agent_eval.py


def isms_lookup(check_id):
    return {"sg_ssh": [{"id": "2.6.1", "name": "네트워크 접근"}, {"id": "2.10.2", "name": "클라우드 보안"}],
            "root_mfa": [{"id": "2.5.3", "name": "사용자 인증"}]}.get(check_id, [])


FINDINGS = [{"checkId": "sg_ssh", "title": "SSH open"}, {"checkId": "no_map", "title": "Other"},
            {"checkId": "root_mfa", "title": "Root MFA"}]


class AgentEvalTest(unittest.TestCase):
    def test_isms_ids_ignores_versions_and_ips(self):
        self.assertEqual(agent_eval.isms_ids("2.6.1 네트워크 접근, 2.10.2 그리고 v12.6.1, 10.2.6.1"),
                         {"2.6.1", "2.10.2"})

    def test_questions_come_from_scan(self):
        questions = agent_eval.make_questions(FINDINGS, isms_lookup)
        isms = [q for q in questions if q[0] == "isms"]
        self.assertEqual([q[2] for q in isms], [{"2.6.1", "2.10.2"}, {"2.5.3"}])  # 매핑 없는 항목은 뺀다
        self.assertEqual(len([q for q in questions if q[0] == "tool"]), 4)
        self.assertEqual(len([q for q in questions if q[0] == "manual"]), 2)

    def test_judge(self):
        expected = {"2.6.1", "2.10.2"}
        self.assertEqual(agent_eval.judge("isms", expected, "2.6.1 네트워크 접근", ["list_findings"]), "통과")
        self.assertEqual(agent_eval.judge("isms", expected, "2.6.1 입니다", []), "실패(도구 없이 답함)")
        self.assertEqual(agent_eval.judge("isms", expected, "2.5.1 입니다", ["list_findings"]),
                         "실패(정답 2.10.2, 2.6.1 없음)")
        self.assertEqual(agent_eval.judge("isms", expected, "2.6.1, 2.5.1", ["list_findings"]),
                         "부분(근거 없는 번호 2.5.1)")
        self.assertEqual(agent_eval.judge("tool", {"list_findings"}, "...", ["list_findings"]), "통과")
        self.assertTrue(agent_eval.judge("tool", agent_eval.REMEDIATION_TOOLS, "...", ["list_findings"])
                        .startswith("실패"))
        self.assertEqual(agent_eval.judge("manual", None, "거절합니다", []), "확인 필요")

    def test_main_runs_end_to_end_with_demo_chat(self):
        from gapcheck import app, findings
        store = mock.Mock()
        store.get_user_by_email.return_value = {"id": "u1"}
        store.get_scan.return_value = {"id": "s1", "status": "DONE", "connectionId": "c1", "accountId": "111122223333"}
        store.list_findings.return_value = [dict(f, severity="high", totalCount=1, service="ec2") for f in FINDINGS]
        store.list_scans.return_value = []
        out = io.StringIO()
        with mock.patch.object(app, "store_from_env", return_value=store), \
                mock.patch.object(app, "chat_factory", return_value=app.DemoChat()), \
                mock.patch.object(findings, "isms_p", side_effect=isms_lookup), redirect_stdout(out):
            self.assertEqual(agent_eval.main(["--email", "A@example.com", "--scan-id", "s1"]), 0)
        store.get_user_by_email.assert_called_once_with("a@example.com")
        text = out.getvalue()
        self.assertEqual(text.count("\n| "), 8)  # 질문 행: ISMS-P 매핑 있는 항목 2 + 조치 3 + 우선순위 1 + 범위 밖 2
        self.assertIn("자동 채점", text)


if __name__ == "__main__":
    unittest.main()
