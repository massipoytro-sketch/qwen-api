import { describe, expect, it } from "vitest";
import { createRequestSignature, verifyRequestSignature } from "../src/security/requestSigning";

const apiKey = "test-api-key-that-must-never-be-shipped-to-a-browser";
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

describe("versioned HMAC request signatures", () => {
  it("accepts a valid request within the timestamp window", () => {
    const request = signedRequest();
    expect(verifyRequestSignature(request, rawBody, apiKey, nowMs)).toEqual({
      valid: true,
      nonce,
      timestamp: Number(timestamp),
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
