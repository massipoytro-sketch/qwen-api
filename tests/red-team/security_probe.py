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
from urllib.request import Request, urlopen

ACK = "I_OWN_THIS_SERVICE"
BASE_URL = os.environ.get("BASE_URL", "").rstrip("/")
TENANT_ID = os.environ.get("TENANT_ID", "")
API_KEY = os.environ.get("API_KEY", "")
WRONG_TENANT_ID = os.environ.get("WRONG_TENANT_ID", "00000000-0000-0000-0000-000000000000")


def require_config() -> None:
    if os.environ.get("SECURITY_TEST_ACK") != ACK:
        raise SystemExit("Refusing to run: SECURITY_TEST_ACK must be I_OWN_THIS_SERVICE")
    if not BASE_URL.startswith("https://") and "localhost" not in BASE_URL and "127.0.0.1" not in BASE_URL:
        raise SystemExit("BASE_URL must use HTTPS (localhost is allowed for local testing)")
    if not TENANT_ID or not API_KEY:
        raise SystemExit("TENANT_ID and API_KEY are required")


def request(path: str, body: str | None, headers: dict[str, str] | None = None) -> tuple[int, dict]:
    data = body.encode() if body is not None else None
    req = Request(BASE_URL + path, data=data, method="POST")
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    try:
        with urlopen(req, timeout=10) as response:
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
