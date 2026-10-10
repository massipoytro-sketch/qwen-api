#!/usr/bin/env python3
"""Bounded, authorized security probe for the GainiRen security API.

This tool is intentionally non-destructive. It checks authentication, input
validation, tenant isolation, rate limiting and stability under a small burst.
It must only be pointed at a service owned/authorized by the operator.
"""
from __future__ import annotations

import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

ACK = "I_OWN_THIS_SERVICE"
BASE_URL = os.environ.get("BASE_URL", "").rstrip("/")
TENANT_ID = os.environ.get("TENANT_ID", "")
API_KEY = os.environ.get("API_KEY", "")
WRONG_TENANT_ID = os.environ.get("WRONG_TENANT_ID", "00000000-0000-0000-0000-000000000000")
ALLOWED_TARGET_ORIGIN = os.environ.get("ALLOWED_TARGET_ORIGIN", "").rstrip("/")


class NoRedirect(HTTPRedirectHandler):
    """Never forward the tenant API key through an HTTP redirect."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


SAFE_OPENER = build_opener(NoRedirect)


def validate_target(base_url: str, allowed_origin: str) -> None:
    if not base_url or not allowed_origin:
        raise ValueError("BASE_URL and ALLOWED_TARGET_ORIGIN are required")
    try:
        target = urlsplit(base_url)
        allowed = urlsplit(allowed_origin)
        target_port = target.port
        allowed_port = allowed.port
    except ValueError as exc:
        raise ValueError("Target URL is invalid") from exc
    if target.username or target.password or allowed.username or allowed.password:
        raise ValueError("Credentials are not allowed in target URLs")
    if target.query or target.fragment or target.path not in ("", "/"):
        raise ValueError("BASE_URL must be an origin only; query, fragment, and paths are forbidden")
    if allowed.path not in ("", "/") or allowed.query or allowed.fragment:
        raise ValueError("ALLOWED_TARGET_ORIGIN must be an origin only")
    local = target.hostname in ("localhost", "127.0.0.1", "::1")
    if target.scheme != "https" and not (local and target.scheme == "http"):
        raise ValueError("Target must use HTTPS (HTTP is allowed only for local development)")
    if allowed.scheme != "https" and not (
        allowed.hostname in ("localhost", "127.0.0.1", "::1") and allowed.scheme == "http"
    ):
        raise ValueError("Allowed target origin must use HTTPS except for local development")
    target_origin = (target.scheme.lower(), (target.hostname or "").lower(), target_port)
    allowed_origin_tuple = (allowed.scheme.lower(), (allowed.hostname or "").lower(), allowed_port)
    if target_origin != allowed_origin_tuple:
        raise ValueError("BASE_URL origin does not exactly match ALLOWED_TARGET_ORIGIN")


def require_config() -> None:
    if os.environ.get("SECURITY_TEST_ACK") != ACK:
        raise SystemExit("Refusing to run: SECURITY_TEST_ACK must be I_OWN_THIS_SERVICE")
    try:
        validate_target(BASE_URL, ALLOWED_TARGET_ORIGIN)
    except ValueError as exc:
        raise SystemExit(f"Refusing target: {exc}") from exc
    if not TENANT_ID or not API_KEY:
        raise SystemExit("TENANT_ID and API_KEY are required")


def request(path: str, body: str | None, headers: dict[str, str] | None = None) -> tuple[int, dict]:
    data = body.encode() if body is not None else None
    req = Request(BASE_URL + path, data=data, method="POST")
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    try:
        with SAFE_OPENER.open(req, timeout=10) as response:
            raw = response.read(200_000).decode("utf-8", "replace")
            try:
                parsed = json.loads(raw) if raw else {}
            except json.JSONDecodeError:
                parsed = {"raw": raw[:500]}
            return response.status, parsed
    except HTTPError as exc:
        raw = exc.read(20_000).decode("utf-8", "replace")
        try:
            parsed = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            parsed = {"raw": raw[:500]}
        return exc.code, parsed
    except URLError as exc:
        return 599, {"error": str(exc.reason)}


def auth_headers() -> dict[str, str]:
    return {
        "authorization": f"Bearer {API_KEY}",
        "content-type": "application/json",
        "x-request-id": f"redteam-{time.time_ns()}",
    }


def check(name: str, status: int, expected: set[int]) -> dict:
    ok = status in expected
    print(f"{'PASS' if ok else 'FAIL'} {name}: HTTP {status} expected {sorted(expected)}")
    return {"name": name, "status": status, "expected": sorted(expected), "ok": ok}


def main() -> int:
    require_config()
    results = []

    status, _ = request(
        "/api/security-check",
        json.dumps({"tenantId": TENANT_ID, "requestId": "redteam-baseline"}),
        auth_headers(),
    )
    results.append(check("baseline authenticated request", status, {200, 429}))

    status, _ = request(
        "/api/security-check",
        '{"tenantId":',
        auth_headers(),
    )
    results.append(check("malformed JSON", status, {400}))

    status, _ = request(
        "/api/security-check",
        json.dumps({"tenantId": WRONG_TENANT_ID, "requestId": "redteam-isolation"}),
        auth_headers(),
    )
    results.append(check("tenant isolation", status, {401}))

    status, _ = request(
        "/api/security-check",
        json.dumps({"tenantId": TENANT_ID}),
        {"authorization": f"Bearer {API_KEY}", "content-type": "text/plain"},
    )
    results.append(check("content-type enforcement", status, {415}))

    oversized = "{" + "\"tenantId\":\"" + TENANT_ID + "\"," + "\"x\":" + "\"A\"" * 70_000 + "}"
    status, _ = request("/api/security-check", oversized, auth_headers())
    results.append(check("oversized body", status, {413}))

    def burst(_: int) -> int:
        status, _ = request(
            "/api/security-check",
            json.dumps({"tenantId": TENANT_ID}),
            auth_headers(),
        )
        return status

    with ThreadPoolExecutor(max_workers=10) as pool:
        statuses = list(pool.map(burst, range(20)))
    unexpected = [s for s in statuses if s >= 500]
    burst_ok = not unexpected and all(s in {200, 429} for s in statuses)
    print(f"{'PASS' if burst_ok else 'FAIL'} bounded burst: {len(statuses)} requests, statuses={sorted(set(statuses))}")
    results.append({"name": "bounded burst", "statuses": statuses, "ok": burst_ok})

    output = {"target": BASE_URL, "results": results, "passed": all(item["ok"] for item in results)}
    print(json.dumps(output, indent=2))
    return 0 if output["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
