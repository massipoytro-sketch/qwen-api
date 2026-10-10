from __future__ import annotations

import hashlib
import hmac
import json
import os
import queue
import threading
import uuid
from datetime import datetime, timezone
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from flask import Flask, Response, jsonify, request

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 8 * 1024
MAX_REQUEST_BYTES = 8 * 1024
HONEY_HASH_KEY = os.environ.get("HONEY_HASH_KEY", "")
SECURITY_ALERT_URL = os.environ.get("SECURITY_ALERT_URL", "").rstrip("/")
HONEY_SENSOR_TOKEN = os.environ.get("HONEY_SENSOR_TOKEN", "")

if len(HONEY_HASH_KEY) < 32:
    raise RuntimeError("HONEY_HASH_KEY must be at least 32 characters.")

if bool(SECURITY_ALERT_URL) != bool(HONEY_SENSOR_TOKEN):
    raise RuntimeError("SECURITY_ALERT_URL and HONEY_SENSOR_TOKEN must be configured together.")
if HONEY_SENSOR_TOKEN and len(HONEY_SENSOR_TOKEN) < 32:
    raise RuntimeError("HONEY_SENSOR_TOKEN must be at least 32 characters.")
if SECURITY_ALERT_URL:
    parsed_alert_url = urlsplit(SECURITY_ALERT_URL)
    if (
        parsed_alert_url.scheme != "https"
        or not parsed_alert_url.hostname
        or parsed_alert_url.username
        or parsed_alert_url.password
        or parsed_alert_url.query
        or parsed_alert_url.fragment
        or not parsed_alert_url.path.endswith("/api/internal/honey-alert")
    ):
        raise RuntimeError("SECURITY_ALERT_URL must be an HTTPS honey-alert endpoint without query or credentials.")


class NoRedirect(HTTPRedirectHandler):
    """Do not forward the shared sensor token to a redirect target."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


ALERT_OPENER = build_opener(NoRedirect)
ALERT_QUEUE: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=512)
ALERT_THREAD_STARTED = False


def hash_field(value: str) -> str:
    return hmac.new(HONEY_HASH_KEY.encode("utf-8"), value.encode("utf-8", "replace"), hashlib.sha256).hexdigest()


def classify_path(path: str) -> tuple[str, str]:
    routes = (
        ("/.env", "environment", "env_file"),
        ("/.git/config", "environment", "git_config"),
        ("/admin/login", "admin", "admin_login"),
        ("/admin", "admin", "admin_panel"),
        ("/api/admin/users", "api_probe", "admin_users_api"),
        ("/api/v1/users", "api_probe", "versioned_users_api"),
        ("/api/internal/config", "debug", "internal_config"),
        ("/debug/env", "debug", "debug_environment"),
        ("/backup/database.sql", "backup", "database_backup"),
        ("/database", "backup", "database_probe"),
    )
    for prefix, surface, category in routes:
        if path == prefix or (prefix != "/" and path.startswith(prefix + "/")):
            return surface, category
    return "unknown", "unknown"


def safe_log(event: dict[str, Any]) -> None:
    # Never write raw addresses, user-agent strings, query strings, or request bodies to logs.
    print(json.dumps(event, separators=(",", ":"), sort_keys=True), flush=True)


def queue_alert(event: dict[str, Any]) -> None:
    if not SECURITY_ALERT_URL or not HONEY_SENSOR_TOKEN:
        return
    try:
        ALERT_QUEUE.put_nowait(event)
    except queue.Full:
        safe_log({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "service": "gainiren-honeydb",
            "event": "alert_queue_full",
            "dropped": 1,
        })


def alert_sender() -> None:
    while True:
        event = ALERT_QUEUE.get()
        try:
            payload = {
                "requestId": event["requestId"],
                "surface": event["surface"],
                "method": event["method"],
                "pathCategory": event["pathCategory"],
                "peerHash": event["peerHash"],
                "userAgentHash": event["userAgentHash"],
                "observedAt": event["observedAt"],
            }
            outbound = Request(
                SECURITY_ALERT_URL,
                data=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
                method="POST",
                headers={
                    "Authorization": f"Bearer {HONEY_SENSOR_TOKEN}",
                    "Content-Type": "application/json",
                },
            )
            with ALERT_OPENER.open(outbound, timeout=2.0) as response:
                status = response.status
                response.read(1024)
            if status not in (200, 202):
                safe_log({
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "service": "gainiren-honeydb",
                    "event": "alert_forward_rejected",
                    "status": status,
                })
        except (HTTPError, URLError, TimeoutError, OSError, ValueError) as exc:
            code = type(exc).__name__
            safe_log({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "service": "gainiren-honeydb",
                "event": "alert_forward_failed",
                "errorCode": code,
            })
        finally:
            ALERT_QUEUE.task_done()


if SECURITY_ALERT_URL and HONEY_SENSOR_TOKEN:
    threading.Thread(target=alert_sender, name="honeydb-alert-sender", daemon=True).start()
    ALERT_THREAD_STARTED = True


@app.before_request
def record_probe() -> Response | None:
    if request.path == "/health":
        return None

    request_id = str(uuid.uuid4())
    surface, category = classify_path(request.path)
    remote = request.remote_addr or "unknown"
    user_agent = request.headers.get("User-Agent", "")[:512]
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "service": "gainiren-honeydb",
        "event": "honeytrap_probe" if surface != "unknown" else "unknown_path_probe",
        "requestId": request_id,
        "surface": surface,
        "pathCategory": category,
        "method": request.method[:12],
        "peerHash": hash_field(remote),
        "userAgentHash": hash_field(user_agent),
    }
    request.environ["gainiren.honey_event"] = event

    content_length = request.content_length
    if content_length is not None and content_length > MAX_REQUEST_BYTES:
        safe_log({**event, "event": "oversized_honeytrap_request", "status": 413})
        return jsonify({"error": "PAYLOAD_TOO_LARGE"}), 413
    return None


@app.after_request
def harden_response(response: Response) -> Response:
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

    event = request.environ.get("gainiren.honey_event")
    if isinstance(event, dict):
        safe_log({key: value for key, value in event.items() if key != "userAgentHash"} | {
            "userAgentHash": event["userAgentHash"],
            "status": response.status_code,
        })
        if event["surface"] != "unknown":
            queue_alert({
                "requestId": event["requestId"],
                "surface": event["surface"],
                "method": event["method"],
                "pathCategory": event["pathCategory"],
                "peerHash": event["peerHash"],
                "userAgentHash": event["userAgentHash"],
                "observedAt": event["timestamp"],
            })
    return response


FAKE_USERS = [
    {"id": "honey-user-001", "email": "admin@example.invalid", "role": "administrator", "status": "synthetic"},
    {"id": "honey-user-002", "email": "audit@example.invalid", "role": "auditor", "status": "synthetic"},
    {"id": "honey-user-003", "email": "service@example.invalid", "role": "service", "status": "synthetic"},
]


@app.get("/health")
def health():
    return jsonify({
        "service": "gainiren-honeydb",
        "status": "ok",
        "mode": "isolated-decoy",
        "productionDatabaseConnected": False,
    })


@app.route("/", methods=["GET", "HEAD"])
def root():
    return jsonify({
        "service": "internal-admin-console",
        "status": "maintenance",
        "notice": "Synthetic decoy environment",
    })


@app.route("/admin", methods=["GET", "HEAD", "POST"])
def admin_panel():
    return jsonify({
        "panel": "admin-console",
        "status": "restricted",
        "recordCount": 3,
        "dataset": "SYNTHETIC_ONLY",
    })


@app.route("/admin/login", methods=["GET", "HEAD", "POST"])
def admin_login():
    # Deliberately never reads or stores submitted usernames/passwords.
    if request.method in ("GET", "HEAD"):
        html = (
            "<!doctype html><html><head><meta charset=utf-8>"
            "<meta name=viewport content='width=device-width, initial-scale=1'>"
            "<title>Internal Console</title></head><body>"
            "<h1>Internal Console</h1><form method=post>"
            "<label>Username <input name=username autocomplete=off></label>"
            "<label>Password <input name=password type=password autocomplete=off></label>"
            "<button type=submit>Sign in</button></form></body></html>"
        )
        return Response(html, mimetype="text/html")
    return jsonify({"error": "AUTHENTICATION_FAILED"}), 401


@app.route("/api/admin/users", methods=["GET", "HEAD", "POST"])
@app.route("/api/v1/users", methods=["GET", "HEAD", "POST"])
def fake_users():
    return jsonify({"items": FAKE_USERS, "total": len(FAKE_USERS), "dataset": "SYNTHETIC_ONLY"})


@app.route("/.env", methods=["GET", "HEAD"])
def fake_env():
    return Response(
        "APP_ENV=staging\n"
        "DB_HOST=db.internal.invalid\n"
        "DB_NAME=honeydb_mock\n"
        "API_KEY=HONEY-CANARY-NOT-A-CREDENTIAL\n"
        "DATASET=SYNTHETIC_ONLY\n",
        mimetype="text/plain",
    )


@app.route("/.git/config", methods=["GET", "HEAD"])
def fake_git_config():
    return Response(
        '[core]\n'
        '\trepositoryformatversion = 0\n'
        '[remote "origin"]\n'
        '\turl = https://example.invalid/synthetic/honeydb.git\n',
        mimetype="text/plain",
    )


@app.route("/api/internal/config", methods=["GET", "HEAD"])
@app.route("/debug/env", methods=["GET", "HEAD"])
def fake_debug_config():
    return jsonify({
        "environment": "staging",
        "database": {"host": "db.internal.invalid", "name": "honeydb_mock"},
        "secrets": {"apiKey": "HONEY-CANARY-NOT-A-CREDENTIAL"},
        "dataset": "SYNTHETIC_ONLY",
    })


@app.route("/backup/database.sql", methods=["GET", "HEAD"])
def fake_backup():
    return Response(
        "-- GainiRen HoneyDB synthetic backup; no production information.\n"
        "CREATE TABLE users (id TEXT, email TEXT, role TEXT);\n"
        "INSERT INTO users VALUES ('honey-user-001','admin@example.invalid','administrator');\n"
        "INSERT INTO users VALUES ('honey-user-002','audit@example.invalid','auditor');\n",
        mimetype="text/plain",
    )


@app.route("/database", methods=["GET", "HEAD", "POST"])
def fake_database():
    return jsonify({"database": "honeydb_mock", "tables": ["users", "sessions", "audit"], "dataset": "SYNTHETIC_ONLY"})


@app.errorhandler(404)
def unknown_route(_error):
    return jsonify({"error": "NOT_FOUND"}), 404


@app.errorhandler(405)
def method_not_allowed(_error):
    return jsonify({"error": "METHOD_NOT_ALLOWED"}), 405


@app.errorhandler(413)
def payload_too_large(_error):
    return jsonify({"error": "PAYLOAD_TOO_LARGE"}), 413
