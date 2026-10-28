import { describe, expect, it } from "vitest";
import { createRequestSignature, createResponseSignature, verifyRequestSignature, verifyResponseSignature } from "../src/security/requestSigning";

const apiKey = "test-api-key-that-must-never-be-shipped-to-a-browser";
const requestUrl = "https://security.example.test/api/security-check?version=1";
const rawBody = JSON.stringify({ tenantId: "d2719c91-3a78-4b20-9f60-402b855422ca" });
const nowMs = Date.parse("2026-10-14T12:00:00.000Z");
const timestamp = String(Math.floor(nowMs / 1000));
const nonce = "3W5u1VVh6GZwK0Ed8rP6J8xZ";

function signedRequest(overrides: { method?: string; url?: string; body?: string; timestamp?: string; nonce?: string; signature?: string } = {}) {
  const method = overrides.method ?? "POST";
  const url = overrides.url ?? requestUrl;
  const body = overrides.body ?? rawBody;
  const signedTimestamp = overrides.timestamp ?? timestamp;
  const signedNonce = overrides.nonce ?? nonce;
  const signature = overrides.signature ?? createRequestSignature({ apiKey, method, requestUrl: url, timestamp: signedTimestamp, nonce: signedNonce, rawBody: body });
  return new Request(url, { method, headers: { "content-type": "application/json", "x-gainiren-signature": signature, "x-gainiren-timestamp": signedTimestamp, "x-gainiren-nonce": signedNonce }, body });
}

describe("versioned HMAC request signatures", () => {
  it("accepts a valid request within the timestamp window", () => expect(verifyRequestSignature(signedRequest(), rawBody, apiKey, nowMs)).toEqual({ valid: true, nonce, timestamp: Number(timestamp) }));
  it("binds the signature to the exact body", () => expect(verifyRequestSignature(signedRequest(), rawBody + " ", apiKey, nowMs)).toEqual({ valid: false, reasonCode: "INVALID_REQUEST_SIGNATURE" }));
  it("binds the signature to the method", () => {
    const request = signedRequest({ method: "PUT" });
    expect(verifyRequestSignature(request, rawBody, apiKey, nowMs).valid).toBe(true);
    const altered = new Request(requestUrl, { method: "POST", headers: request.headers, body: rawBody });
    expect(verifyRequestSignature(altered, rawBody, apiKey, nowMs)).toEqual({ valid: false, reasonCode: "INVALID_REQUEST_SIGNATURE" });
  });
  it("changes when a fresh timestamp or nonce is used", () => {
    const first = createRequestSignature({ apiKey, method: "POST", requestUrl, timestamp, nonce, rawBody });
    const second = createRequestSignature({ apiKey, method: "POST", requestUrl, timestamp: String(Number(timestamp) + 1), nonce: "0Bq2x8xJb7cA9Q6mH1pT4dVn", rawBody });
    expect(second).not.toBe(first);
  });
  it("does not accept a signature made with a different API key", () => expect(verifyRequestSignature(signedRequest(), rawBody, "another-api-key", nowMs)).toEqual({ valid: false, reasonCode: "INVALID_REQUEST_SIGNATURE" }));
  it("binds the signature to path and query", () => {
    const request = signedRequest();
    const altered = new Request("https://security.example.test/api/security-check?version=2", { method: "POST", headers: request.headers, body: rawBody });
    expect(verifyRequestSignature(altered, rawBody, apiKey, nowMs)).toEqual({ valid: false, reasonCode: "INVALID_REQUEST_SIGNATURE" });
  });
  it("rejects missing signature headers", () => expect(verifyRequestSignature(new Request(requestUrl, { method: "POST", body: rawBody }), rawBody, apiKey, nowMs)).toEqual({ valid: false, reasonCode: "SIGNATURE_HEADERS_MISSING" }));
  it("rejects stale and future timestamps", () => {
    expect(verifyRequestSignature(signedRequest({ timestamp: String(Number(timestamp) - 301) }), rawBody, apiKey, nowMs)).toEqual({ valid: false, reasonCode: "SIGNATURE_TIMESTAMP_OUTSIDE_WINDOW" });
    expect(verifyRequestSignature(signedRequest({ timestamp: String(Number(timestamp) + 301) }), rawBody, apiKey, nowMs)).toEqual({ valid: false, reasonCode: "SIGNATURE_TIMESTAMP_OUTSIDE_WINDOW" });
  });
  it("rejects malformed nonces and malformed signature values", () => {
    expect(verifyRequestSignature(signedRequest({ nonce: "short" }), rawBody, apiKey, nowMs)).toEqual({ valid: false, reasonCode: "INVALID_REQUEST_NONCE" });
    expect(verifyRequestSignature(signedRequest({ signature: "v1=not-a-digest" }), rawBody, apiKey, nowMs)).toEqual({ valid: false, reasonCode: "INVALID_REQUEST_SIGNATURE" });
  });
});

describe("authenticated response signatures", () => {
  const requestId = "req-2026-10-15-001";
  const body = JSON.stringify({ decision: "CHALLENGE", score: 72, requestId });
  it("verifies the exact signed response", () => {
    const signature = createResponseSignature({ apiKey, requestId, status: 200, body });
    expect(signature).toMatch(/^v1=[a-f0-9]{64}$/);
    expect(verifyResponseSignature({ apiKey, requestId, status: 200, body, signature })).toBe(true);
  });
  it("changes when status, request id or body changes", () => {
    const signature = createResponseSignature({ apiKey, requestId, status: 200, body });
    expect(verifyResponseSignature({ apiKey, requestId, status: 201, body, signature })).toBe(false);
    expect(verifyResponseSignature({ apiKey, requestId: "different-request", status: 200, body, signature })).toBe(false);
    expect(verifyResponseSignature({ apiKey, requestId, status: 200, body: body + " ", signature })).toBe(false);
  });
  it("does not verify with another key", () => {
    const signature = createResponseSignature({ apiKey, requestId, status: 200, body });
    expect(verifyResponseSignature({ apiKey: "different-key", requestId, status: 200, body, signature })).toBe(false);
  });
});
