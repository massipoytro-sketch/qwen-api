import { describe, expect, it } from "vitest";
import { createRequestSignature, createStrongRequestSignature, verifyRequestSignature, verifyStrongRequestSignature } from "../src/security/requestSigning";

const apiKey = "test-api-key-that-must-never-be-shipped-to-a-browser";
const keyId = "550e8400-e29b-41d4-a716-446655440000";
const requestUrl = "https://security.example.test/api/security-check?version=1";
const rawBody = JSON.stringify({ tenantId: "d2719c91-3a78-4b20-9f60-402b855422ca" });
const nowMs = Date.parse("2026-10-14T12:00:00.000Z");
const timestamp = String(Math.floor(nowMs / 1000));
const nonce = "3W5u1VVh6GZwK0Ed8rP6J8xZ";

function signedRequest(overrides: {
  method?: string;
  url?: string;
  body?: string;
  timestamp?: string;
  nonce?: string;
  signature?: string;
} = {}) {
  const method = overrides.method ?? "POST";
  const url = overrides.url ?? requestUrl;
  const body = overrides.body ?? rawBody;
  const signedTimestamp = overrides.timestamp ?? timestamp;
  const signedNonce = overrides.nonce ?? nonce;
  const signature = overrides.signature ?? createRequestSignature({
    apiKey,
    method,
    requestUrl: url,
    timestamp: signedTimestamp,
    nonce: signedNonce,
    rawBody: body,
  });
  return new Request(url, {
    method,
    headers: {
      "content-type": "application/json",
      "x-gainiren-signature": signature,
      "x-gainiren-timestamp": signedTimestamp,
      "x-gainiren-nonce": signedNonce,
    },
    body,
  });
}

function strongRequest(overrides: {
  keyId?: string;
  contentType?: string;
  timestamp?: string;
  nonce?: string;
  signature?: string;
} = {}) {
  const signedTimestamp = overrides.timestamp ?? timestamp;
  const signedNonce = overrides.nonce ?? nonce;
  const signedKeyId = overrides.keyId ?? keyId;
  const contentType = overrides.contentType ?? "application/json";
  const signature = overrides.signature ?? createStrongRequestSignature({
    apiKey,
    method: "POST",
    requestUrl,
    timestamp: signedTimestamp,
    nonce: signedNonce,
    keyId: signedKeyId,
    contentType,
    rawBody,
  });
  return new Request(requestUrl, {
    method: "POST",
    headers: {
      "content-type": contentType,
      "x-gainiren-signature": signature,
      "x-gainiren-timestamp": signedTimestamp,
      "x-gainiren-nonce": signedNonce,
      "x-gainiren-key-id": signedKeyId,
    },
    body: rawBody,
  });
}

describe("versioned HMAC request signatures", () => {
  it("accepts a valid request within the timestamp window", () => {
    const request = signedRequest();
    expect(verifyRequestSignature(request, rawBody, apiKey, nowMs)).toEqual({
      valid: true,
      nonce,
      timestamp: Number(timestamp),
      version: "v1",
      keyId: null,
    });
  });

  it("binds the signature to the exact body", () => {
    const request = signedRequest();
    expect(verifyRequestSignature(request, rawBody + " ", apiKey, nowMs)).toEqual({
      valid: false,
      reasonCode: "INVALID_REQUEST_SIGNATURE",
    });
  });

  it("binds the signature to the method", () => {
    const request = signedRequest({ method: "PUT" });
    expect(verifyRequestSignature(request, rawBody, apiKey, nowMs)).toEqual({
      valid: true,
      nonce,
      timestamp: Number(timestamp),
      version: "v1",
      keyId: null,
    });
    const altered = new Request(requestUrl, {
      method: "POST",
      headers: request.headers,
      body: rawBody,
    });
    expect(verifyRequestSignature(altered, rawBody, apiKey, nowMs)).toEqual({
      valid: false,
      reasonCode: "INVALID_REQUEST_SIGNATURE",
    });
  });

  it("changes when a fresh timestamp or nonce is used", () => {
    const first = createRequestSignature({
      apiKey,
      method: "POST",
      requestUrl,
      timestamp,
      nonce,
      rawBody,
    });
    const second = createRequestSignature({
      apiKey,
      method: "POST",
      requestUrl,
      timestamp: String(Number(timestamp) + 1),
      nonce: "0Bq2x8xJb7cA9Q6mH1pT4dVn",
      rawBody,
    });
    expect(second).not.toBe(first);
  });

  it("does not accept a signature made with a different API key", () => {
    const request = signedRequest();
    expect(verifyRequestSignature(request, rawBody, "another-api-key", nowMs)).toEqual({
      valid: false,
      reasonCode: "INVALID_REQUEST_SIGNATURE",
    });
  });

  it("binds the signature to path and query", () => {
    const request = signedRequest();
    const altered = new Request("https://security.example.test/api/security-check?version=2", {
      method: "POST",
      headers: request.headers,
      body: rawBody,
    });
    expect(verifyRequestSignature(altered, rawBody, apiKey, nowMs)).toEqual({
      valid: false,
      reasonCode: "INVALID_REQUEST_SIGNATURE",
    });
  });

  it("rejects missing signature headers", () => {
    const request = new Request(requestUrl, { method: "POST", body: rawBody });
    expect(verifyRequestSignature(request, rawBody, apiKey, nowMs)).toEqual({
      valid: false,
      reasonCode: "SIGNATURE_HEADERS_MISSING",
    });
  });

  it("rejects a stale timestamp", () => {
    const staleTimestamp = String(Number(timestamp) - 301);
    const request = signedRequest({ timestamp: staleTimestamp });
    expect(verifyRequestSignature(request, rawBody, apiKey, nowMs)).toEqual({
      valid: false,
      reasonCode: "SIGNATURE_TIMESTAMP_OUTSIDE_WINDOW",
    });
  });

  it("rejects timestamps that are too far in the future", () => {
    const futureTimestamp = String(Number(timestamp) + 301);
    const request = signedRequest({ timestamp: futureTimestamp });
    expect(verifyRequestSignature(request, rawBody, apiKey, nowMs)).toEqual({
      valid: false,
      reasonCode: "SIGNATURE_TIMESTAMP_OUTSIDE_WINDOW",
    });
  });

  it("rejects malformed nonces and malformed signature values", () => {
    const badNonce = signedRequest({ nonce: "short" });
    expect(verifyRequestSignature(badNonce, rawBody, apiKey, nowMs)).toEqual({
      valid: false,
      reasonCode: "INVALID_REQUEST_NONCE",
    });
    const badSignature = signedRequest({ signature: "v1=not-a-digest" });
    expect(verifyRequestSignature(badSignature, rawBody, apiKey, nowMs)).toEqual({
      valid: false,
      reasonCode: "INVALID_REQUEST_SIGNATURE",
    });
  });
});

describe("Part 5A strong v2 request signatures", () => {
  it("accepts a valid key-bound v2 request", () => {
    const request = strongRequest();
    expect(verifyStrongRequestSignature(request, rawBody, apiKey, keyId, nowMs)).toEqual({
      valid: true,
      nonce,
      timestamp: Number(timestamp),
      version: "v2",
      keyId,
    });
  });

  it("binds the signature to the registered key id", () => {
    const request = strongRequest();
    expect(verifyStrongRequestSignature(request, rawBody, apiKey, "550e8400-e29b-41d4-a716-446655440001", nowMs)).toEqual({
      valid: false,
      reasonCode: "INVALID_REQUEST_SIGNATURE",
    });
  });

  it("binds the signature to content type", () => {
    const request = strongRequest();
    const headers = new Headers(request.headers);
    headers.set("content-type", "application/octet-stream");
    const altered = new Request(requestUrl, { method: "POST", headers, body: rawBody });
    expect(verifyStrongRequestSignature(altered, rawBody, apiKey, keyId, nowMs)).toEqual({
      valid: false,
      reasonCode: "INVALID_REQUEST_SIGNATURE",
    });
  });

  it("rejects v1 at the strong boundary and requires a key id", () => {
    const legacy = signedRequest();
    const headers = new Headers(legacy.headers);
    headers.set("x-gainiren-key-id", keyId);
    expect(verifyStrongRequestSignature(new Request(requestUrl, { method: "POST", headers, body: rawBody }), rawBody, apiKey, keyId, nowMs)).toEqual({
      valid: false,
      reasonCode: "SIGNATURE_VERSION_NOT_ALLOWED",
    });
    expect(verifyStrongRequestSignature(strongRequest({ keyId: "" }), rawBody, apiKey, null, nowMs)).toEqual({
      valid: false,
      reasonCode: "SIGNATURE_KEY_ID_MISSING",
    });
  });

  it("changes when a fresh nonce is used", () => {
    const first = createStrongRequestSignature({ apiKey, method: "POST", requestUrl, timestamp, nonce, keyId, contentType: "application/json", rawBody });
    const second = createStrongRequestSignature({ apiKey, method: "POST", requestUrl, timestamp, nonce: "0Bq2x8xJb7cA9Q6mH1pT4dVn", keyId, contentType: "application/json", rawBody });
    expect(second).not.toBe(first);
  });
});
