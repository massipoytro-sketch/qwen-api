from __future__ import annotations

import os
import unittest

os.environ["HONEY_HASH_KEY"] = "unit-test-honey-hash-key-0123456789-abcdef"
os.environ.pop("SECURITY_ALERT_URL", None)
os.environ.pop("HONEY_SENSOR_TOKEN", None)

from app import app, hash_field  # noqa: E402


class HoneyDbTests(unittest.TestCase):
    def setUp(self):
        app.config["TESTING"] = True
        self.client = app.test_client()

    def test_health_declares_isolated_decoy(self):
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        body = response.get_json()
        self.assertEqual(body["service"], "gainiren-honeydb")
        self.assertFalse(body["productionDatabaseConnected"])

    def test_fake_environment_has_only_synthetic_values(self):
        response = self.client.get("/.env")
        body = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("db.internal.invalid", body)
        self.assertIn("HONEY-CANARY-NOT-A-CREDENTIAL", body)
        self.assertNotIn("SUPABASE_SERVER_KEY", body)
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")

    def test_users_are_synthetic_and_use_reserved_invalid_domains(self):
        response = self.client.get("/api/admin/users")
        body = response.get_json()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(body["dataset"], "SYNTHETIC_ONLY")
        self.assertEqual(body["total"], 3)
        self.assertTrue(all(row["email"].endswith(".invalid") for row in body["items"]))

    def test_fake_backup_contains_only_synthetic_rows(self):
        response = self.client.get("/backup/database.sql")
        body = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("synthetic backup", body)
        self.assertIn("admin@example.invalid", body)
        self.assertNotIn("CREATE ROLE", body.upper())

    def test_oversized_request_is_rejected(self):
        response = self.client.post("/admin/login", data=b"x" * (9 * 1024))
        self.assertEqual(response.status_code, 413)
        self.assertEqual(response.get_json()["error"], "PAYLOAD_TOO_LARGE")

    def test_unknown_paths_return_only_a_generic_not_found(self):
        response = self.client.get("/totally-unknown")
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.get_json()["error"], "NOT_FOUND")

    def test_hash_is_stable_and_does_not_equal_raw_input(self):
        raw = "203.0.113.20"
        self.assertEqual(hash_field(raw), hash_field(raw))
        self.assertNotEqual(hash_field(raw), raw)
        self.assertEqual(len(hash_field(raw)), 64)


if __name__ == "__main__":
    unittest.main()
