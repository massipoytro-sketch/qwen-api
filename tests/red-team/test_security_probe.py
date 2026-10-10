from __future__ import annotations

import unittest

from security_probe import validate_target


class TargetValidationTests(unittest.TestCase):
    def test_accepts_exact_https_origin(self):
        validate_target("https://shield.example.test", "https://shield.example.test/")

    def test_rejects_wrong_origin(self):
        with self.assertRaisesRegex(ValueError, "does not exactly match"):
            validate_target("https://evil.example.test", "https://shield.example.test")

    def test_rejects_userinfo(self):
        with self.assertRaisesRegex(ValueError, "Credentials"):
            validate_target("https://attacker@shield.example.test", "https://shield.example.test")

    def test_rejects_paths_queries_and_fragments(self):
        for target in (
            "https://shield.example.test/api",
            "https://shield.example.test/?forward=https://evil.example",
            "https://shield.example.test/#fragment",
        ):
            with self.subTest(target=target), self.assertRaises(ValueError):
                validate_target(target, "https://shield.example.test")

    def test_allows_http_only_for_exact_local_origin(self):
        validate_target("http://localhost:3000", "http://localhost:3000")

    def test_rejects_non_https_remote_target(self):
        with self.assertRaisesRegex(ValueError, "must use HTTPS"):
            validate_target("http://shield.example.test", "http://shield.example.test")


if __name__ == "__main__":
    unittest.main()
