from __future__ import annotations

import hashlib
import hmac
import unittest

import security_probe
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

    def test_v1_signature_matches_the_server_canonical_format(self):
        old_key, old_key_id = security_probe.API_KEY, security_probe.KEY_ID
        try:
            security_probe.API_KEY = "cross-language-test-key"
            security_probe.KEY_ID = ""
            body = '{"tenantId":"d2719c91-3a78-4b20-9f60-402b855422ca"}'
            headers = security_probe.auth_headers(body)
            fields = [
                "GAINIREN-REQUEST-V1",
                "POST",
                "/api/security-check",
                headers["x-gainiren-timestamp"],
                headers["x-gainiren-nonce"],
                hashlib.sha256(body.encode("utf-8")).hexdigest(),
            ]
            canonical = "\n".join(fields)
            expected = hmac.new(
                security_probe.API_KEY.encode("utf-8"),
                canonical.encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()
            self.assertEqual(headers["x-gainiren-signature"], f"v1={expected}")
            self.assertNotIn("x-gainiren-key-id", headers)
        finally:
            security_probe.API_KEY, security_probe.KEY_ID = old_key, old_key_id

    def test_v2_signature_binds_the_managed_key_id(self):
        old_key, old_key_id = security_probe.API_KEY, security_probe.KEY_ID
        try:
            security_probe.API_KEY = "cross-language-test-key"
            security_probe.KEY_ID = "11111111-1111-4111-8111-111111111111"
            body = '{"tenantId":"d2719c91-3a78-4b20-9f60-402b855422ca"}'
            headers = security_probe.auth_headers(body)
            fields = [
                "GAINIREN-REQUEST-V2",
                "POST",
                "/api/security-check",
                headers["x-gainiren-timestamp"],
                headers["x-gainiren-nonce"],
                security_probe.KEY_ID,
                hashlib.sha256(body.encode("utf-8")).hexdigest(),
            ]
            canonical = "\\n".join(fields)
            expected = hmac.new(
                security_probe.API_KEY.encode("utf-8"),
                canonical.encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()
            self.assertEqual(headers["x-gainiren-signature"], f"v2={expected}")
            self.assertEqual(headers["x-gainiren-key-id"], security_probe.KEY_ID)
        finally:
            security_probe.API_KEY, security_probe.KEY_ID = old_key, old_key_id

    def test_signature_nonces_are_fresh_between_requests(self):
        old_key, old_key_id = security_probe.API_KEY, security_probe.KEY_ID
        try:
            security_probe.API_KEY = "cross-language-test-key"
            security_probe.KEY_ID = ""
            nonces = {
                security_probe.auth_headers('{"tenantId":"test"}')["x-gainiren-nonce"]
                for _ in range(20)
            }
            self.assertEqual(len(nonces), 20)
        finally:
            security_probe.API_KEY, security_probe.KEY_ID = old_key, old_key_id

    def test_allows_http_only_for_exact_local_origin(self):
        validate_target("http://localhost:3000", "http://localhost:3000")

    def test_rejects_non_https_remote_target(self):
        with self.assertRaisesRegex(ValueError, "must use HTTPS"):
            validate_target("http://shield.example.test", "http://shield.example.test")


if __name__ == "__main__":
    unittest.main()
