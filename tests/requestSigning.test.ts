import { describe, expect, it } from "vitest";
import { createRequestSignature, createStrongRequestSignature, verifyRequestSignature, verifyStrongRequestSignature } from "../src/security/requestSigning";

const apiKey = "test-api-key-that-must-never-be-shipped-to-a-browser";
const keyId = "550e8400-e29b-41d4-a716-446655440000";
const requestUrl = "https://security.example.test/api/security-check?version=1";
const rawBody = JSON.stringify({ tenantId: "d2719c91-3a78-4b20-9f60-402b855422ca" });
const nowMs = Date.parse("2026-10-14T12:00:00.000Z");
const timestamp = String(Math.floor(nowMs / 1000));
const nonce = "3W5u1VVh6GZwK0Ed8rP6J8xZ";

function signedRequest(overrides: { method?: string; url?: string; body?: string; timestamp?: string; nonce?: string; signature?: string } = {}) {
  const method = overrides.method ?? "POST"; const url = overrides.url ?? requestUrl; const body = overrides.body ?? rawBody; const signedTimestamp = overrides.timestamp ?? timestamp; const signedNonce = overrides.nonce ?? nonce;
  const signature = overrides.signature ?? createRequestSignature({ apiKey, method, requestUrl: url, timestamp: signedTimestamp, nonce: signedNonce, rawBody: body });
  return new Request(url, { method, headers: { "content-type": "application/json", "x-gainiren-signature": signature, "x-gainiren-timestamp": signedTimestamp, "x-gainiren-nonce": signedNonce }, body });
}
function strongRequest(overrides: { keyId?: string; contentType?: string; timestamp?: string; nonce?: string; signature?: string } = {}) {
  const signedTimestamp = overrides.timestamp ?? timestamp; const signedNonce = overrides.nonce ?? nonce; const signedKeyId = overrides.keyId ?? keyId; const contentType = overrides.contentType ?? "application/json";
  const signature = overrides.signature ?? createStrongRequestSignature({ apiKey, method: "POST", requestUrl, timestamp: signedTimestamp, nonce: signedNonce, keyId: signedKeyId, contentType, rawBody });
  return new Request(requestUrl, { method: "POST", headers: { "content-type": contentType, "x-gainiren-signature": signature, "x-gainiren-timestamp": signedTimestamp, "x-gainiren-nonce": signedNonce, "x-gainiren-key-id": signedKeyId }, body: rawBody });
}

describe("legacy v1 compatibility verifier", () => {
  it("accepts a valid v1 signature", () => expect(verifyRequestSignature(signedRequest(), rawBody, apiKey, nowMs)).toEqual({ valid: true, nonce, timestamp: Number(timestamp), version: "v1", keyId: null }));
  it("rejects body, method, path and key mutations", () => { const request = signedRequest(); expect(verifyRequestSignature(request, rawBody + " ", apiKey, nowMs)).toEqual({ valid: false, reasonCode: "INVALID_REQUEST_SIGNATURE" }); const altered = new Request(requestUrl, { method: "PUT", headers: request.headers, body: rawBody }); expect(verifyRequestSignature(altered, rawBody, apiKey, nowMs)).toEqual({ valid: false, reasonCode: "INVALID_REQUEST_SIGNATURE" }); const changedPath = new Request("https://security.example.test/api/security-check?version=2", { method: "POST", headers: request.headers, body: rawBody }); expect(verifyRequestSignature(changedPath, rawBody, apiKey, nowMs)).toEqual({ valid: false, reasonCode: "INVALID_REQUEST_SIGNATURE" }); });
  it("rejects stale/future timestamps, malformed nonce and malformed signature", () => { expect(verifyRequestSignature(signedRequest({ timestamp: String(Number(timestamp) - 301) }), rawBody, apiKey, nowMs)).toEqual({ valid: false, reasonCode: "SIGNATURE_TIMESTAMP_OUTSIDE_WINDOW" }); expect(verifyRequestSignature(signedRequest({ timestamp: String(Number(timestamp) + 301) }), rawBody, apiKey, nowMs)).toEqual({ valid: false, reasonCode: "SIGNATURE_TIMESTAMP_OUTSIDE_WINDOW" }); expect(verifyRequestSignature(signedRequest({ nonce: "short" }), rawBody, apiKey, nowMs)).toEqual({ valid: false, reasonCode: "INVALID_REQUEST_NONCE" }); expect(verifyRequestSignature(signedRequest({ signature: "v1=not-a-digest" }), rawBody, apiKey, nowMs)).toEqual({ valid: false, reasonCode: "INVALID_REQUEST_SIGNATURE" }); });
});

describe("Part 5A strong v2 boundary", () => {
  it("accepts a valid key-bound v2 request", () => expect(verifyStrongRequestSignature(strongRequest(), rawBody, apiKey, keyId, nowMs)).toEqual({ valid: true, nonce, timestamp: Number(timestamp), version: "v2", keyId }));
  it("rejects key-id substitution", () => expect(verifyStrongRequestSignature(strongRequest(), rawBody, apiKey, "550e8400-e29b-41d4-a716-446655440001", nowMs)).toEqual({ valid: false, reasonCode: "INVALID_REQUEST_SIGNATURE" }));
  it("rejects content-type substitution", () => { const request = strongRequest(); const headers = new Headers(request.headers); headers.set("content-type", "application/octet-stream"); expect(verifyStrongRequestSignature(new Request(requestUrl, { method: "POST", headers, body: rawBody }), rawBody, apiKey, keyId, nowMs)).toEqual({ valid: false, reasonCode: "INVALID_REQUEST_SIGNATURE" }); });
  it("rejects v1 at the strong boundary and requires key id", () => { const legacy = signedRequest(); const headers = new Headers(legacy.headers); headers.set("x-gainiren-key-id", keyId); expect(verifyStrongRequestSignature(new Request(requestUrl, { method: "POST", headers, body: rawBody }), rawBody, apiKey, keyId, nowMs)).toEqual({ valid: false, reasonCode: "SIGNATURE_VERSION_NOT_ALLOWED" }); expect(verifyStrongRequestSignature(strongRequest({ keyId: "" }), rawBody, apiKey, null, nowMs)).toEqual({ valid: false, reasonCode: "SIGNATURE_KEY_ID_MISSING" }); });
  it("changes when a fresh nonce is used", () => { const a = createStrongRequestSignature({ apiKey, method: "POST", requestUrl, timestamp, nonce, keyId, contentType: "application/json", rawBody }); const b = createStrongRequestSignature({ apiKey, method: "POST", requestUrl, timestamp, nonce: "0Bq2x8xJb7cA9Q6mH1pT4dVn", keyId, contentType: "application/json", rawBody }); expect(a).not.toBe(b); });
});
