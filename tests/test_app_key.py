"""Gemini 키 조회(app.explainer_factory) 테스트. DB 없이 돈다."""
import unittest
from unittest import mock

from gapcheck import app


class GeminiKeyCacheTest(unittest.TestCase):
    def test_empty_key_is_not_cached(self):
        ssm = mock.Mock()
        ssm.get_parameter.side_effect = [RuntimeError("ParameterNotFound"),
                                         {"Parameter": {"Value": "k"}}]
        make = app.explainer_factory({"GEMINI_MODEL": "m"}, mock.Mock(), lambda: ssm)
        make()
        make()
        self.assertEqual(ssm.get_parameter.call_count, 2)

    def test_found_key_is_cached(self):
        ssm = mock.Mock()
        ssm.get_parameter.return_value = {"Parameter": {"Value": "k"}}
        make = app.explainer_factory({"GEMINI_MODEL": "m"}, mock.Mock(), lambda: ssm)
        make()
        make()
        self.assertEqual(ssm.get_parameter.call_count, 1)


if __name__ == "__main__":
    unittest.main()
