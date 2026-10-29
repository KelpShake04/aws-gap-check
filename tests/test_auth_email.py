"""auth.normalize_email 테스트."""
import unittest

from gapcheck import auth


class NormalizeEmailTest(unittest.TestCase):
    def test_lowercases_and_strips(self):
        self.assertEqual(auth.normalize_email("  Alice@Example.com "), "alice@example.com")

    def test_rejects_non_ascii(self):
        self.assertEqual(auth.normalize_email("alice@example.com��"), "")
        self.assertEqual(auth.normalize_email("앨리스@example.com"), "")

    def test_rejects_bad_format(self):
        for bad in ("", "alice", "a@b", "a b@example.com", None, 5):
            self.assertEqual(auth.normalize_email(bad), "")


if __name__ == "__main__":
    unittest.main()
