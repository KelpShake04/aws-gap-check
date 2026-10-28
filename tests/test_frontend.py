import re
import unittest

from tests import ROOT

# 문자열을 HTML이나 코드로 해석하는 API. 스캔 결과(공격자가 정할 수 있는 리소스 이름 등)가
# 이런 API로 들어가면 저장형 XSS가 되므로 프런트엔드에서 아예 쓰지 않는다.
FORBIDDEN = [r"\.innerHTML", r"\.outerHTML", r"insertAdjacentHTML", r"document\.write",
             r"\beval\s*\(", r"new\s+Function\s*\(", r"setTimeout\s*\(\s*['\"`]",
             r"setInterval\s*\(\s*['\"`]"]


class FrontendSafetyTest(unittest.TestCase):
    def test_no_html_string_apis(self):
        files = sorted((ROOT / "frontend").glob("*.js"))
        self.assertTrue(files)
        for path in files:
            text = path.read_text(encoding="utf-8")
            for pattern in FORBIDDEN:
                with self.subTest(file=path.name, pattern=pattern):
                    self.assertIsNone(re.search(pattern, text))

    def test_no_inline_scripts_or_handlers(self):
        html = (ROOT / "frontend" / "index.html").read_text(encoding="utf-8")
        self.assertNotRegex(html, r"<script(?![^>]*\bsrc=)")
        self.assertNotRegex(html, r"\son[a-z]+\s*=")


if __name__ == "__main__":
    unittest.main()
