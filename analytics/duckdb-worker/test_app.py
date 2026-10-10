import os
import unittest
from datetime import datetime, timezone

os.environ["DUCKDB_ANALYTICS_TOKEN"] = "test-worker-secret-12345678901234567890"

from app import app  # noqa: E402

TENANT = "a" * 64
SUBJECT = "b" * 64
SESSION = "c" * 64


class DuckDbWorkerTests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def post_events(self, events, token="test-worker-secret-12345678901234567890"):
        return self.client.post(
            "/analyze",
            json={"tenantHash": TENANT, "events": events},
            headers={"Authorization": f"Bearer {token}"},
        )

    def event(self, event_type="click", **extra):
        return {
            "subjectHash": SUBJECT,
            "sessionHash": SESSION,
            "eventType": event_type,
            "occurredAt": datetime.now(timezone.utc).isoformat(),
            **extra,
        }

    def test_health_is_read_only_and_available(self):
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["status"], "ok")

    def test_analyzer_rejects_missing_or_invalid_auth(self):
        response = self.client.post("/analyze", json={"tenantHash": TENANT, "events": []})
        self.assertEqual(response.status_code, 401)
        self.assertEqual(self.post_events([], token="wrong-token").status_code, 401)

    def test_rejects_invalid_hash_and_oversized_batch(self):
        invalid = self.client.post(
            "/analyze",
            json={"tenantHash": "not-a-hash", "events": []},
            headers={"Authorization": "Bearer test-worker-secret-12345678901234567890"},
        )
        self.assertEqual(invalid.status_code, 400)
        oversized = self.post_events([self.event() for _ in range(501)])
        self.assertEqual(oversized.status_code, 400)

    def test_detects_recent_session_burst(self):
        response = self.post_events([self.event(event_type=f"click_{i}") for i in range(12)])
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        result = response.get_json()
        self.assertGreaterEqual(result["anomalyCount"], 1)
        self.assertTrue(any(
            anomaly["type"] == "activity_velocity" and anomaly["score"] >= 65
            for anomaly in result["anomalies"]
        ))

    def test_detects_extreme_value_delta(self):
        response = self.post_events([self.event(event_type="reward_change", valueDelta=10000)])
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        result = response.get_json()
        self.assertTrue(any(
            anomaly["type"] == "value_jump" and anomaly["score"] == 100
            for anomaly in result["anomalies"]
        ))

    def test_rejects_non_finite_numeric_values(self):
        response = self.post_events([self.event(event_type="reward", valueDelta="NaN")])
        self.assertEqual(response.status_code, 400)

    def test_rejects_unbounded_payload_shapes(self):
        response = self.client.post(
            "/analyze",
            json={"tenantHash": TENANT, "events": [{"eventType": "x"}]},
            headers={"Authorization": "Bearer test-worker-secret-12345678901234567890"},
        )
        self.assertEqual(response.status_code, 400)


if __name__ == "__main__":
    unittest.main()
