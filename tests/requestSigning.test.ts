import { describe, expect, it } from "vitest";
import {
  createRequestSignature,
  verifyRequestSignature,
} from "../src/security/requestSigning";

const apiKey = "test-api-key-that-must-never-be-shipped-to-a-browser";
const requestUrl = "https://security.example.test/api/security-check?version=1";
const rawBody = JSON.stringify({ tenantId: "d2719c91-3a78-4b20-9f60-402b855422ca" });
const nowMs = Date.parse("2026-10-14T12:00:00.000Z");
const timestamp = String(Math.floor(nowMs / 1000));
const nonce = "3W5u1VVh6GZwK0Ed8rP6J8xZ";
const keyId = "11111111-1111-4111-8111-111111111111";

function signedRequest(overrides: {
  method?: string;
  url?: string;
  body?: string;
  timestamp?: string;
  nonce?: string;
  signature?: string;
  keyId?: string;
} = {}) {
  const method = overrides.method ?? "POST";
  const url = overrides.url ?? requestUrl;
  const body = overrides.body ?? rawBody;
  const signedTimestamp = overrides.timestamp ?? timestamp;
  const signedNonce = overrides.nonce ?? nonce;
  const signedKeyId = overrides.keyId;
  const signature = overrides.signature ?? createRequestSignature({
    apiKey,
    method,
    requestUrl: url,
    timestamp: signedTimestamp,
    nonce: signedNonce,
    rawBody: body,
    ...(signedKeyId ? { keyId: signedKeyId } : {}),
  });
  return new Request(url, {
    method,
    headers: {
      "content-type": "application/json",
      "x-gainiren-signature": signature,
      "x-gainiren-timestamp": signedTimestamp,
      "x-gainiren-nonce": signedNonce,
      ...(signedKeyId ? { "x-gainiren-key-id": signedKeyId } : {}),
    },
    body,
  });
}

describe("versioned HMAC request signatures", () => {
  it("accepts a valid legacy v1 request in the freshness window", () => {
    const request = signedRequest();
    expect(verifyRequestSignature(request, rawBody, apiKey, nowMs)).toEqual({
      valid: true, nonce, timestamp: Number(timestamp), version: "v1",
    });
  });

  it("accepts v2 only when a managed key id is supplied and bound into the signature", () => {
    const request = signedRequest({ keyId });
    expect(verifyRequestSignature(request, rawBody, apiKey, nowMs, keyId)).toEqual({
      valid: true, nonce, timestamp: Number(timestamp), version: "v2",
    });
  });

  it("rejects missing and mismatched managed key ids", () => {
    const noId = signedRequest();
    expect(verifyRequestSignature(noId, rawBody, apiKey, nowMs, keyId)).toEqual({
      valid: false, reasonCode: "INVALID_REQUEST_KEY_ID",
    });
    const wrongId = signedRequest({ keyId });
    expect(verifyRequestSignature(wrongId, rawBody, apiKey, nowMs, "22222222-2222-4222-8222-222222222222")).toEqual({
      valid: false, reasonCode: "INVALID_REQUEST_KEY_ID",
    });
  });

  it("rejects protocol downgrade and upgrade mismatches", () => {
    const v1 = signedRequest();
    expect(verifyRequestSignature(v1, rawBody, apiKey, nowMs, keyId).valid).toBe(false);
    const v2 = signedRequest({ keyId });
    expect(verifyRequestSignature(v2, rawBody, apiKey, nowMs).valid).toBe(false);
  });

  it("binds the signature to the exact body", () => {
    const request = signedRequest();
    expect(verifyRequestSignature(request, rawBody + " ", apiKey, nowMs)).toEqual({
      valid: false, reasonCode: "INVALID_REQUEST_SIGNATURE",
    });
  });

  it("binds the signature to method, path and query", () => {
    const request = signedRequest();
    const changedMethod = new Request(requestUrl, { method: "PUT", headers: request.headers, body: rawBody });
    const changedPath = new Request("https://security.example.test/api/security-check?version=2", {
      method: "POST", headers: request.headers, body: rawBody,
    });
    expect(verifyRequestSignature(changedMethod, rawBody, apiKey, nowMs).valid).toBe(false);
    expect(verifyRequestSignature(changedPath, rawBody, apiKey, nowMs).valid).toBe(false);
  });

  it("rejects a signature made with another API key", () => {
    expect(verifyRequestSignature(signedRequest(), rawBody, "another-api-key", nowMs).valid).toBe(false);
  });

  it("requires fresh signatures to change when timestamp, nonce or key id changes", () => {
    const first = createRequestSignature({ apiKey, method: "POST", requestUrl, timestamp, nonce, rawBody, keyId });
    const timestampChanged = createRequestSignature({
      apiKey, method: "POST", requestUrl, timestamp: String(Number(timestamp) + 1), nonce, rawBody, keyId,
    });
    const nonceChanged = createRequestSignature({
      apiKey, method: "POST", requestUrl, timestamp, nonce: "0Bq2x8xJb7cA9Q6mH1pT4dVn", rawBody, keyId,
    });
    const keyChanged = createRequestSignature({
      apiKey, method: "POST", requestUrl, timestamp, nonce, rawBody,
      keyId: "22222222-2222-4222-8222-222222222222",
    });
    expect(new Set([first, timestampChanged, nonceChanged, keyChanged]).size).toBe(4);
  });

  it("rejects malformed, missing and stale security headers", () => {
    const missing = new Request(requestUrl, { method: "POST", body: rawBody });
    expect(verifyRequestSignature(missing, rawBody, apiKey, nowMs)).toEqual({
      valid: false, reasonCode: "SIGNATURE_HEADERS_MISSING",
    });
    const staleTimestamp = String(Number(timestamp) - 301);
    expect(verifyRequestSignature(signedRequest({ timestamp: staleTimestamp }), rawBody, apiKey, nowMs)).toEqual({
      valid: false, reasonCode: "SIGNATURE_TIMESTAMP_OUTSIDE_WINDOW",
    });
    expect(verifyRequestSignature(signedRequest({ timestamp: "yesterday" }), rawBody, apiKey, nowMs)).toEqual({
      valid: false, reasonCode: "INVALID_SIGNATURE_TIMESTAMP",
    });
    expect(verifyRequestSignature(signedRequest({ nonce: "short" }), rawBody, apiKey, nowMs)).toEqual({
      valid: false, reasonCode: "INVALID_REQUEST_NONCE",
    });
  });
});
