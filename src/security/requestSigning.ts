import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import { supabase } from "../db/supabase";
import { hashValue } from "./utils";

const SIGNATURE_VERSION = "v1";
const MAX_CLOCK_SKEW_SECONDS = 300;
const NONCE_PATTERN = /^[A-Za-z0-9_-]{16,128}$/;
const SIGNATURE_PATTERN = /^v1=[a-f0-9]{64}$/;

export type SignatureRejectionCode =
  | "SIGNATURE_HEADERS_MISSING"
  | "INVALID_SIGNATURE_TIMESTAMP"
  | "SIGNATURE_TIMESTAMP_OUTSIDE_WINDOW"
  | "INVALID_REQUEST_NONCE"
  | "INVALID_REQUEST_SIGNATURE"
  | "REPLAYED_REQUEST_NONCE";

export type SignatureVerification =
  | { valid: true; nonce: string; timestamp: number }
  | { valid: false; reasonCode: SignatureRejectionCode };

function bodyDigest(rawBody: string): string {
  return createHash("sha256").update(rawBody, "utf8").digest("hex");
}

function requestTarget(requestUrl: string): string {
  const url = new URL(requestUrl);
  return url.pathname + url.search;
}

/**
 * Canonical request format is versioned and binds the method, path/query,
 * timestamp, per-request nonce and SHA-256 digest of the exact JSON text.
 * The API key is used as the HMAC key and must remain server-side.
 */
export function canonicalRequestPayload(input: {
  method: string;
  requestUrl: string;
  timestamp: string;
  nonce: string;
  rawBody: string;
}): string {
  return [
    "GAINIREN-REQUEST-V1",
    input.method.toUpperCase(),
    requestTarget(input.requestUrl),
    input.timestamp,
    input.nonce,
    bodyDigest(input.rawBody),
  ].join("\n");
}

/** Shared by the server-to-server SDK examples and deterministic unit tests. */
export function createRequestSignature(input: {
  apiKey: string;
  method: string;
  requestUrl: string;
  timestamp: string;
  nonce: string;
  rawBody: string;
}): string {
  const payload = canonicalRequestPayload(input);
  const digest = createHmac("sha256", input.apiKey).update(payload, "utf8").digest("hex");
  return `${SIGNATURE_VERSION}=${digest}`;
}

/** Validates integrity and freshness without touching storage. */
export function verifyRequestSignature(
  request: Request,
  rawBody: string,
  apiKey: string,
  nowMs = Date.now(),
): SignatureVerification {
  const signature = request.headers.get("x-gainiren-signature") ?? "";
  const timestampText = request.headers.get("x-gainiren-timestamp") ?? "";
  const nonce = request.headers.get("x-gainiren-nonce") ?? "";

  if (!signature || !timestampText || !nonce) {
    return { valid: false, reasonCode: "SIGNATURE_HEADERS_MISSING" };
  }

  if (!/^\d{10}$/.test(timestampText)) {
    return { valid: false, reasonCode: "INVALID_SIGNATURE_TIMESTAMP" };
  }
  const timestamp = Number(timestampText);
  if (!Number.isSafeInteger(timestamp) || Math.abs(Math.floor(nowMs / 1000) - timestamp) > MAX_CLOCK_SKEW_SECONDS) {
    return { valid: false, reasonCode: "SIGNATURE_TIMESTAMP_OUTSIDE_WINDOW" };
  }
  if (!NONCE_PATTERN.test(nonce)) {
    return { valid: false, reasonCode: "INVALID_REQUEST_NONCE" };
  }
  if (!SIGNATURE_PATTERN.test(signature) || !apiKey) {
    return { valid: false, reasonCode: "INVALID_REQUEST_SIGNATURE" };
  }

  const expected = createRequestSignature({
    apiKey,
    method: request.method,
    requestUrl: request.url,
    timestamp: timestampText,
    nonce,
    rawBody,
  });
  const suppliedBytes = Buffer.from(signature, "utf8");
  const expectedBytes = Buffer.from(expected, "utf8");
  if (suppliedBytes.byteLength !== expectedBytes.byteLength || !timingSafeEqual(suppliedBytes, expectedBytes)) {
    return { valid: false, reasonCode: "INVALID_REQUEST_SIGNATURE" };
  }

  return { valid: true, nonce, timestamp };
}

/**
 * Consumes a verified nonce atomically in Postgres. A duplicate nonce returns
 * false even when two identical signed requests arrive concurrently.
 */
export async function verifyAndConsumeRequestSignature(input: {
  request: Request;
  rawBody: string;
  apiKey: string;
  tenantId: string;
  nowMs?: number;
}): Promise<SignatureVerification> {
  const result = verifyRequestSignature(input.request, input.rawBody, input.apiKey, input.nowMs);
  if (!result.valid) return result;

  const nonceHash = hashValue(result.nonce);
  const consumed = await supabase.schema("security").rpc("consume_request_nonce", {
    p_tenant_id: input.tenantId,
    p_nonce_hash: nonceHash,
  });
  if (consumed.error) throw consumed.error;
  if (consumed.data !== true) return { valid: false, reasonCode: "REPLAYED_REQUEST_NONCE" };
  return result;
}
