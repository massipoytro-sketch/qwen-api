import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import { supabase } from "../db/supabase";
import { hashValue } from "./utils";

const MAX_CLOCK_SKEW_SECONDS = 300;
const NONCE_PATTERN = /^[A-Za-z0-9_-]{16,128}$/;
const KEY_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const V1_SIGNATURE_PATTERN = /^v1=[a-f0-9]{64}$/;
const V2_SIGNATURE_PATTERN = /^v2=[a-f0-9]{64}$/;

export type SignatureRejectionCode =
  | "SIGNATURE_HEADERS_MISSING"
  | "INVALID_SIGNATURE_TIMESTAMP"
  | "SIGNATURE_TIMESTAMP_OUTSIDE_WINDOW"
  | "INVALID_REQUEST_NONCE"
  | "INVALID_REQUEST_KEY_ID"
  | "INVALID_REQUEST_SIGNATURE"
  | "REPLAYED_REQUEST_NONCE";

export type SignatureVerification =
  | { valid: true; nonce: string; timestamp: number; version: "v1" | "v2" }
  | { valid: false; reasonCode: SignatureRejectionCode };

function bodyDigest(rawBody: string): string {
  return createHash("sha256").update(rawBody, "utf8").digest("hex");
}

function requestTarget(requestUrl: string): string {
  const url = new URL(requestUrl);
  return url.pathname + url.search;
}

/**
 * v1 exists only for migration of legacy tenant keys.
 * v2 cryptographically binds the managed key ID to the same request fields.
 */
export function canonicalRequestPayload(input: {
  method: string;
  requestUrl: string;
  timestamp: string;
  nonce: string;
  rawBody: string;
  keyId?: string;
}): string {
  if (input.keyId && !KEY_ID_PATTERN.test(input.keyId)) {
    throw new Error("INVALID_REQUEST_KEY_ID");
  }
  return [
    input.keyId ? "GAINIREN-REQUEST-V2" : "GAINIREN-REQUEST-V1",
    input.method.toUpperCase(),
    requestTarget(input.requestUrl),
    input.timestamp,
    input.nonce,
    ...(input.keyId ? [input.keyId] : []),
    bodyDigest(input.rawBody),
  ].join("\n");
}

/** Used by server-to-server SDKs and deterministic tests; never call in a browser. */
export function createRequestSignature(input: {
  apiKey: string;
  method: string;
  requestUrl: string;
  timestamp: string;
  nonce: string;
  rawBody: string;
  keyId?: string;
}): string {
  const payload = canonicalRequestPayload(input);
  const digest = createHmac("sha256", input.apiKey).update(payload, "utf8").digest("hex");
  return `${input.keyId ? "v2" : "v1"}=${digest}`;
}

/** Validates signature, protocol version and freshness without touching storage. */
export function verifyRequestSignature(
  request: Request,
  rawBody: string,
  apiKey: string,
  nowMs = Date.now(),
  expectedKeyId?: string | null,
): SignatureVerification {
  const signature = request.headers.get("x-gainiren-signature") ?? "";
  const timestampText = request.headers.get("x-gainiren-timestamp") ?? "";
  const nonce = request.headers.get("x-gainiren-nonce") ?? "";
  const requestKeyId = request.headers.get("x-gainiren-key-id")?.trim() ?? "";

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

  const v2 = Boolean(expectedKeyId);
  if (v2) {
    if (!requestKeyId || requestKeyId !== expectedKeyId || !KEY_ID_PATTERN.test(requestKeyId)) {
      return { valid: false, reasonCode: "INVALID_REQUEST_KEY_ID" };
    }
    if (!V2_SIGNATURE_PATTERN.test(signature)) {
      return { valid: false, reasonCode: "INVALID_REQUEST_SIGNATURE" };
    }
  } else {
    if (requestKeyId) return { valid: false, reasonCode: "INVALID_REQUEST_KEY_ID" };
    if (!V1_SIGNATURE_PATTERN.test(signature)) {
      return { valid: false, reasonCode: "INVALID_REQUEST_SIGNATURE" };
    }
  }
  if (!apiKey) return { valid: false, reasonCode: "INVALID_REQUEST_SIGNATURE" };

  const expected = createRequestSignature({
    apiKey,
    method: request.method,
    requestUrl: request.url,
    timestamp: timestampText,
    nonce,
    rawBody,
    ...(v2 && expectedKeyId ? { keyId: expectedKeyId } : {}),
  });
  const suppliedBytes = Buffer.from(signature, "utf8");
  const expectedBytes = Buffer.from(expected, "utf8");
  if (suppliedBytes.byteLength !== expectedBytes.byteLength || !timingSafeEqual(suppliedBytes, expectedBytes)) {
    return { valid: false, reasonCode: "INVALID_REQUEST_SIGNATURE" };
  }

  return { valid: true, nonce, timestamp, version: v2 ? "v2" : "v1" };
}

/**
 * Consumes a verified nonce atomically in PostgreSQL. Duplicate nonces are
 * rejected even if identical signed requests race concurrently.
 */
export async function verifyAndConsumeRequestSignature(input: {
  request: Request;
  rawBody: string;
  apiKey: string;
  tenantId: string;
  keyId?: string | null;
  nowMs?: number;
}): Promise<SignatureVerification> {
  const result = verifyRequestSignature(input.request, input.rawBody, input.apiKey, input.nowMs, input.keyId);
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
