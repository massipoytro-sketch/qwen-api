import hashlib
import hmac
import os
import re
from collections import defaultdict
from datetime import datetime, timezone
from flask import Flask, jsonify, request
import duckdb

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 1_048_576
HASH_RE = re.compile(r"^[0-9a-f]{64}$")
MAX_EVENTS = 500

def parse_time(value):
    if not isinstance(value, str) or len(value) > 40:
        raise ValueError("INVALID_TIMESTAMP")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)

def safe_number(value, low=None, high=None):
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("INVALID_NUMERIC")
    number = float(value)
    if number != number or abs(number) == float("inf"):
        raise ValueError("INVALID_NUMERIC")
    if low is not None and number < low or high is not None and number > high:
        raise ValueError("NUMERIC_OUT_OF_RANGE")
    return number

def authorized():
    expected = os.environ.get("DUCKDB_ANALYTICS_TOKEN", "")
    supplied = request.headers.get("Authorization", "")
    if len(expected) < 32 or not supplied.startswith("Bearer "):
        return False
    return hmac.compare_digest(supplied[7:], expected)

@app.get("/health")
def health():
    return jsonify({"service": "gainiren-duckdb-analytics", "status": "ok", "engine": "duckdb-1.5.6"})

@app.post("/analyze")
def analyze():
    if not authorized():
        return jsonify({"error": "UNAUTHORIZED"}), 401
    body = request.get_json(silent=True)
    if not isinstance(body, dict) or not HASH_RE.fullmatch(str(body.get("tenantHash", ""))):
        return jsonify({"error": "INVALID_REQUEST"}), 400
    events = body.get("events")
    if not isinstance(events, list) or len(events) > MAX_EVENTS:
        return jsonify({"error": "INVALID_EVENT_BATCH"}), 400

    rows = []
    try:
        for item in events:
            if not isinstance(item, dict):
                raise ValueError("INVALID_EVENT")
            subject_hash = item.get("subjectHash")
            session_hash = item.get("sessionHash")
            if subject_hash is not None and not HASH_RE.fullmatch(str(subject_hash)):
                raise ValueError("INVALID_SUBJECT_HASH")
            if session_hash is not None and not HASH_RE.fullmatch(str(session_hash)):
                raise ValueError("INVALID_SESSION_HASH")
            event_type = item.get("eventType")
            if not isinstance(event_type, str) or not event_type or len(event_type) > 100:
                raise ValueError("INVALID_EVENT_TYPE")
            occurred_at = parse_time(item.get("occurredAt"))
            value_delta = safe_number(item.get("valueDelta"))
            bot_score = safe_number(item.get("botScore"), 0, 100)
            behavior_score = safe_number(item.get("behaviorScore"), 0, 100)
            rows.append((body["tenantHash"], subject_hash, session_hash, event_type, occurred_at, value_delta, bot_score, behavior_score))
    except (ValueError, TypeError, OverflowError):
        return jsonify({"error": "INVALID_EVENT_DATA"}), 400

    db = duckdb.connect(database=":memory:")
    try:
        db.execute("SET threads = 2")
        db.execute("SET memory_limit = '256MB'")
        db.execute("""
          CREATE TABLE events (
            tenant_hash VARCHAR, subject_hash VARCHAR, session_hash VARCHAR,
            event_type VARCHAR, occurred_at TIMESTAMPTZ, value_delta DOUBLE,
            bot_score DOUBLE, behavior_score DOUBLE
          )
        """)
        if rows:
            db.executemany("INSERT INTO events VALUES (?, ?, ?, ?, ?, ?, ?, ?)", rows)

        anomalies = []
        bursts = db.execute("""
          SELECT tenant_hash, any_value(subject_hash), session_hash, count(*) AS n, max(occurred_at) AS last_seen
          FROM events
          WHERE session_hash IS NOT NULL AND occurred_at >= now() - INTERVAL '1 minute'
          GROUP BY tenant_hash, session_hash
          HAVING count(*) >= 10
          LIMIT 100
        """).fetchall()
        for tenant_hash, subject_hash, session_hash, count, last_seen in bursts:
            score = 95 if count >= 30 else 80 if count >= 20 else 65
            anomalies.append({
                "type": "activity_velocity", "tenantHash": tenant_hash, "subjectHash": subject_hash,
                "sessionHash": session_hash, "score": score, "confidence": 0.75,
                "reasonCodes": ["DUCKDB_EVENT_BURST"],
                "evidence": {"events1m": int(count), "lastSeen": last_seen.isoformat(), "engine": "duckdb"}
            })

        value_jumps = db.execute("""
          SELECT tenant_hash, subject_hash, session_hash, value_delta, event_type, occurred_at
          FROM events WHERE value_delta IS NOT NULL AND abs(value_delta) >= 500
          ORDER BY abs(value_delta) DESC LIMIT 100
        """).fetchall()
        for tenant_hash, subject_hash, session_hash, delta, event_type, occurred_at in value_jumps:
            score = 100 if abs(delta) >= 10000 else 80 if abs(delta) >= 1000 else 50
            anomalies.append({
                "type": "value_jump", "tenantHash": tenant_hash, "subjectHash": subject_hash,
                "sessionHash": session_hash, "score": score, "confidence": 0.85,
                "reasonCodes": ["DUCKDB_VALUE_JUMP"],
                "evidence": {"delta": delta, "eventType": event_type, "occurredAt": occurred_at.isoformat(), "engine": "duckdb"}
            })

        risk_rows = db.execute("""
          SELECT tenant_hash, any_value(subject_hash), any_value(session_hash),
                 max(coalesce(bot_score, 0)), max(coalesce(behavior_score, 0))
          FROM events GROUP BY tenant_hash, coalesce(session_hash, subject_hash) LIMIT 100
        """).fetchall()
        for tenant_hash, subject_hash, session_hash, bot_score, behavior_score in risk_rows:
            if bot_score >= 70:
                anomalies.append({
                    "type": "advanced_bot", "tenantHash": tenant_hash, "subjectHash": subject_hash,
                    "sessionHash": session_hash, "score": int(bot_score), "confidence": 0.7,
                    "reasonCodes": ["DUCKDB_BOT_EVIDENCE"],
                    "evidence": {"botScore": bot_score, "engine": "duckdb"}
                })
            if behavior_score >= 70:
                anomalies.append({
                    "type": "behavioral_deviation", "tenantHash": tenant_hash, "subjectHash": subject_hash,
                    "sessionHash": session_hash, "score": int(behavior_score), "confidence": 0.7,
                    "reasonCodes": ["DUCKDB_BEHAVIOR_EVIDENCE"],
                    "evidence": {"behaviorScore": behavior_score, "engine": "duckdb"}
                })

        # Bound output and de-duplicate by type + pseudonymous subject/session.
        deduped = {}
        for anomaly in anomalies:
            key = (anomaly["type"], anomaly.get("subjectHash"), anomaly.get("sessionHash"))
            if key not in deduped or anomaly["score"] > deduped[key]["score"]:
                deduped[key] = anomaly
        output = list(deduped.values())[:100]
        return jsonify({
            "engine": "duckdb-1.5.6",
            "version": "duckdb-analytics-v1",
            "batchSize": len(rows),
            "anomalyCount": len(output),
            "anomalies": output,
            "processedAt": datetime.now(timezone.utc).isoformat(),
        })
    finally:
        db.close()

@app.errorhandler(413)
def too_large(_error):
    return jsonify({"error": "PAYLOAD_TOO_LARGE"}), 413

@app.errorhandler(500)
def internal_error(_error):
    # Never expose exception details, database internals, or credentials in HTTP responses.
    return jsonify({"error": "INTERNAL_ERROR"}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8080")))
