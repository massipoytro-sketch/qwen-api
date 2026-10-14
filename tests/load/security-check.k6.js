import http from "k6/http";
import { check, sleep } from "k6";
import crypto from "k6/crypto";

const baseUrl = (__ENV.BASE_URL || "").replace(/\/+$/, "");
const tenantId = __ENV.TENANT_ID || "";
const apiKey = __ENV.API_KEY || "";
const keyId = __ENV.KEY_ID || "";
const ack = __ENV.LOAD_TEST_ACK || "";
const profile = __ENV.LOAD_PROFILE || "smoke";
const allowedOrigin = (__ENV.ALLOWED_TARGET_ORIGIN || "").replace(/\/+$/, "");

if (!baseUrl || !tenantId || !apiKey || !allowedOrigin) {
  throw new Error("Set BASE_URL, ALLOWED_TARGET_ORIGIN, TENANT_ID, and API_KEY before starting the test.");
}
if (ack !== "I_OWN_THIS_SERVICE") {
  throw new Error("Set LOAD_TEST_ACK=I_OWN_THIS_SERVICE to confirm authorization to test this service.");
}
let target;
try {
  target = new URL(baseUrl);
} catch {
  throw new Error("BASE_URL must be a valid URL.");
}
if (target.username || target.password || target.search || target.hash || !["", "/"].includes(target.pathname)) {
  throw new Error("BASE_URL must be an origin only, without credentials, path, query, or fragment.");
}
const origin = target.origin.replace(/\/+$/, "");
if (origin !== allowedOrigin) {
  throw new Error("BASE_URL origin must exactly match ALLOWED_TARGET_ORIGIN.");
}
if (target.protocol !== "https:" && !["localhost", "127.0.0.1"].includes(target.hostname)) {
  throw new Error("HTTPS is required except for local development.");
}
if (!["smoke", "stress"].includes(profile)) {
  throw new Error("LOAD_PROFILE must be smoke or stress.");
}

export const options = profile === "stress"
  ? {
      stages: [
        { duration: "10s", target: 3 },
        { duration: "20s", target: 10 },
        { duration: "10s", target: 0 },
      ],
      thresholds: { http_req_duration: ["p(95)<2500"] },
    }
  : {
      vus: 1,
      duration: "20s",
      thresholds: { http_req_duration: ["p(95)<2000"] },
    };

function randomNonce() {
  const bytes = new Uint8Array(crypto.randomBytes(24));
  return Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join("");
}

function signedHeaders(body, nonce, timestamp) {
  const path = "/api/security-check";
  const version = keyId ? "v2" : "v1";
  const canonical = [
    `GAINIREN-REQUEST-${version.toUpperCase()}`,
    "POST",
    path,
    timestamp,
    nonce,
    ...(keyId ? [keyId] : []),
    crypto.sha256(body, "hex"),
  ].join("\n");
  const signature = crypto.hmac("sha256", apiKey, canonical, "hex");
  return {
    authorization: `Bearer ${apiKey}`,
    "Content-Type": "application/json",
    "X-GainiRen-Timestamp": timestamp,
    "X-GainiRen-Nonce": nonce,
    "X-GainiRen-Signature": `${version}=${signature}`,
    ...(keyId ? { "X-GainiRen-Key-Id": keyId } : {}),
  };
}

export default function () {
  const body = JSON.stringify({ tenantId, requestId: `k6-${__VU}-${__ITER}-${Date.now()}` });
  const timestamp = String(Math.floor(Date.now() / 1000));
  const nonce = randomNonce();
  const response = http.post(
    `${baseUrl}/api/security-check`,
    body,
    {
      headers: signedHeaders(body, nonce, timestamp),
      timeout: "10s",
      redirects: 0,
      tags: { endpoint: "security-check", profile },
    },
  );
  const accepted = check(response, {
    "response is 200 or rate-limited": (r) => r.status === 200 || r.status === 429,
    "no internal server errors": (r) => r.status < 500,
    "latency bounded": (r) => r.timings.duration < 10000,
  });
  if (!accepted) {
    console.error(`Unexpected response status=${response.status} profile=${profile}`);
  }
  sleep(1);
}
