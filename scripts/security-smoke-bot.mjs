#!/usr/bin/env node
/**
 * Safe, low-volume smoke tests for an authorized GainiRen Security deployment.
 * This intentionally tests only public health and unauthenticated rejection paths.
 * It does not brute-force credentials, create database records, or send load.
 */
const base = (process.env.SECURITY_API_BASE_URL ?? "https://gainiren-security-api.onrender.com").replace(/\/$/, "");
const timeoutMs = 12_000;
const checks = [];

async function check(name, path, init, validate) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(base + path, { ...init, signal: controller.signal, redirect: "error" });
    const text = await response.text();
    let body = null;
    try { body = text ? JSON.parse(text) : null; } catch {}
    const ok = validate(response, body);
    checks.push({ name, ok, status: response.status, detail: ok ? "expected response" : "unexpected response shape/status" });
    console.log(`${ok ? "PASS" : "FAIL"} ${name}: HTTP ${response.status}`);
  } catch (error) {
    checks.push({ name, ok: false, detail: error instanceof Error ? error.name : "unknown error" });
    console.log(`FAIL ${name}: ${error instanceof Error ? error.name : "unknown error"}`);
  } finally {
    clearTimeout(timer);
  }
}

await check("health endpoint", "/api/health", { method: "GET" },
  (r, b) => r.status === 200 && b?.service === "gainiren-security" && b?.status === "ok");

await check("database readiness endpoint", "/api/ready", { method: "GET" },
  (r, b) => r.status === 200 && b?.service === "gainiren-security" && b?.status === "ready");

await check("security-check rejects missing auth", "/api/security-check", {
  method: "POST", headers: { "content-type": "application/json" }, body: "{}",
}, (r, b) => r.status === 401 && b?.error === "UNAUTHORIZED");

await check("security-event rejects missing auth", "/api/security-event", {
  method: "POST", headers: { "content-type": "application/json" }, body: "{}",
}, (r, b) => r.status === 401 && b?.error === "UNAUTHORIZED");

await check("outbox worker rejects missing auth", "/api/outbox-worker", {
  method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ batchSize: 1 }),
}, (r, b) => r.status === 401 && typeof b?.error === "string");

await check("unknown route returns 404", "/api/__smoke_test_not_a_route__", { method: "GET" },
  (r, b) => r.status === 404 && b?.error === "NOT_FOUND");

const failed = checks.filter((x) => !x.ok);
console.log(JSON.stringify({ service: "gainiren-security-smoke-bot", base, total: checks.length, passed: checks.length - failed.length, failed: failed.length, results: checks }, null, 2));
if (failed.length) process.exitCode = 1;
