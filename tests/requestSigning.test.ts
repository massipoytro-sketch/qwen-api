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

describe("versioned HMAC request signatures", () => {
  it("accepts a valid legacy v1 signature in the compatibility verifier", () => expect(verifyRequestSignature(signedRequest(), rawBody, apiKey, nowMs)).toEqual({ valid: true, nonce, timestamp: Number(timestamp), version: "v1", keyId: null }));
  it("binds v1 to the exact body", () => expect(verifyRequestSignature(signedRequest(), rawBody + " ", apiKey, nowMs)).toEqual({ valid: false, reasonCode: "INVALID_REQUEST_SIGNATURE" }));
  it("binds v1 to method and target", () => { const request = signedRequest({ method: "PUT" }); expect(verifyRequestSignature(request, rawBody, apiKey, nowMs).valid).toBe(true); const altered = new Request(requestUrl, { method: "POST", headers: request.headers, body: rawBody }); expect(verifyRequestSignature(altered, rawBody, apiKey, nowMs)).toEqual({ valid: false, reasonCode: "INVALID_REQUEST_SIGNATURE" }); });
  it("changes when a fresh timestamp or nonce is used", () => { const first = createRequestSignature({ apiKey, method: "POST", requestUrl, timestamp, nonce, rawBody }); const second = createRequestSignature({ apiKey, method: "POST", requestUrl, timestamp: String(Number(timestamp) + 1), nonce: "0Bq2x8xJb7cA9Q6mH1pT4dVn", rawBody }); expect(second).not.toBe(first); });
  it("does not accept a different API key", () => expect(verifyRequestSignature(signedRequest(), rawBody, "another-api-key", nowMs)).toEqual({ valid: false, reasonCode: "INVALID_REQUEST_SIGNATURE" }));
  it("rejects missing headers", () => expect(verifyRequestSignature(new Request(requestUrl, { method: "POST", body: rawBody }), rawBody, apiKey, nowMs)).toEqual({ valid: false, reasonCode: "SIGNATURE_HEADERS_MISSING" }));
  it("rejects stale and future timestamps", () => { expect(verifyRequestSignature(signedRequest({ timestamp: String(Number(timestamp) - 301) }), rawBody, apiKey, nowMs)).toEqual({ valid: false, reasonCode: "SIGNATURE_TIMESTAMP_OUTSIDE_WINDOW" }); expect(verifyRequestSignature(signedRequest({ timestamp: String(Number(timestamp) + 301) }), rawBody, apiKey, nowMs)).toEqual({ valid: false, reasonCode: "SIGNATURE_TIMESTAMP_OUTSIDE_WINDOW" }); });
  it("rejects malformed nonce and signature", () => { expect(verifyRequestSignature(signedRequest({ nonce: "short" }), rawBody, apiKey, nowMs)).toEqual({ valid: false, reasonCode: "INVALID_REQUEST_NONCE" }); expect(verifyRequestSignature(signedRequest({ signature: "v1=not-a-digest" }), rawBody, apiKey, nowMs)).toEqual({ valid: false, reasonCode: "INVALID_REQUEST_SIGNATURE" }); });
});

describe("Part 5A strong v2 request signatures", () => {
  it("accepts a valid key-bound v2 request", () => expect(verifyStrongRequestSignature(strongRequest(), rawBody, apiKey, keyId, nowMs)).toEqual({ valid: true, nonce, timestamp: Number(timestamp), version: "v2", keyId }));
  it("binds the signature to the registered key id", () => { const request = strongRequest(); expect(verifyStrongRequestSignature(request, rawBody, apiKey, "550e8400-e29b-41d4-a716-446655440001", nowMs)).toEqual({ valid: false, reasonCode: "INVALID_REQUEST_SIGNATURE" }); });
  it("binds the signature to content type", () => { const request = strongRequest(); const altered = new Request(requestUrl, { method: "POST", headers: { ...Object.fromEntries(request.headers), "content-type": "application/octet-stream" }, body: rawBody }); expect(verifyStrongRequestSignature(altered, rawBody, apiKey, keyId, nowMs)).toEqual({ valid: false, reasonCode: "INVALID_REQUEST_SIGNATURE" }); });
  it("rejects v1 at the strong boundary", () => { const legacy = signedRequest(); const strongHeaders = new Headers(legacy.headers); strongHeaders.set("x-gainiren-key-id", keyId); expect(verifyStrongRequestSignature(new Request(requestUrl, { method: "POST", headers: strongHeaders, body: rawBody }), rawBody, apiKey, keyId, nowMs)).toEqual({ valid: false, reasonCode: "SIGNATURE_VERSION_NOT_ALLOWED" }); });
  it("requires a valid key id", () => { expect(verifyStrongRequestSignature(strongRequest({ keyId: "" }), rawBody, apiKey, null, nowMs)).toEqual({ valid: false, reasonCode: "SIGNATURE_KEY_ID_MISSING" }); });
  it("produces a different signature for every fresh nonce", () => { const a = createStrongRequestSignature({ apiKey, method: "POST", requestUrl, timestamp, nonce, keyId, contentType: "application/json", rawBody }); const b = createStrongRequestSignature({ apiKey, method: "POST", requestUrl, timestamp, nonce: "0Bq2x8xJb7cA9Q6mH1pT4dVn", keyId, contentType: "application/json", rawBody }); expect(a).not.toBe(b); });
});
