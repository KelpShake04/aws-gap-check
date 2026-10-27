import ast
import unittest

from tests import ROOT

# CloudShell의 python3는 3.9일 수 있다. CloudShell에서 실행하는 코드는 3.9 문법만 쓴다.
CLOUDSHELL_CODE = [
    *sorted((ROOT / "scripts").glob("*.py")),
    *sorted((ROOT / "backend" / "gapcheck").glob("*.py")),
]


class Python39SyntaxTest(unittest.TestCase):
    def test_parses_as_python_39(self):
        self.assertTrue(CLOUDSHELL_CODE)
        for path in CLOUDSHELL_CODE:
            with self.subTest(path=path.relative_to(ROOT)):
                ast.parse(path.read_text(encoding="utf-8"), filename=str(path),
                          feature_version=(3, 9))


if __name__ == "__main__":
    unittest.main()
