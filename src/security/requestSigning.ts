import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import { supabase } from "../db/supabase";
import { hashValue } from "./utils";

const SIGNATURE_VERSION = "v1";
const STRONG_SIGNATURE_VERSION = "v2";
const MAX_CLOCK_SKEW_SECONDS = 300;
const NONCE_PATTERN = /^[A-Za-z0-9_-]{16,128}$/;
const SIGNATURE_PATTERN = /^v1=[a-f0-9]{64}$/;
const STRONG_SIGNATURE_PATTERN = /^v2=[a-f0-9]{64}$/;
const KEY_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export type SignatureRejectionCode =
  | "SIGNATURE_HEADERS_MISSING"
  | "INVALID_SIGNATURE_TIMESTAMP"
  | "SIGNATURE_TIMESTAMP_OUTSIDE_WINDOW"
  | "INVALID_REQUEST_NONCE"
  | "INVALID_REQUEST_SIGNATURE"
  | "SIGNATURE_KEY_ID_MISSING"
  | "SIGNATURE_KEY_ID_INVALID"
  | "SIGNATURE_VERSION_NOT_ALLOWED"
  | "REPLAYED_REQUEST_NONCE";

export type SignatureVerification =
  | { valid: true; nonce: string; timestamp: number; version: "v1" | "v2"; keyId: string | null }
  | { valid: false; reasonCode: SignatureRejectionCode };

function bodyDigest(rawBody: string): string {
  return createHash("sha256").update(rawBody, "utf8").digest("hex");
}

function requestTarget(requestUrl: string): string {
  const url = new URL(requestUrl);
  return url.pathname + url.search;
}

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

/** Legacy v1 signature retained for controlled migration compatibility. */
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

/**
 * Part 5A strong signature. The registered key UUID is cryptographically bound
 * to the request, preventing a key-id/header substitution during rotation.
 */
export function canonicalStrongRequestPayload(input: {
  method: string;
  requestUrl: string;
  timestamp: string;
  nonce: string;
  keyId: string;
  contentType: string;
  rawBody: string;
}): string {
  return [
    "GAINIREN-REQUEST-V2",
    input.method.toUpperCase(),
    requestTarget(input.requestUrl),
    input.timestamp,
    input.nonce,
    input.keyId.toLowerCase(),
    input.contentType.toLowerCase(),
    bodyDigest(input.rawBody),
  ].join("\n");
}

export function createStrongRequestSignature(input: {
  apiKey: string;
  method: string;
  requestUrl: string;
  timestamp: string;
  nonce: string;
  keyId: string;
  contentType: string;
  rawBody: string;
}): string {
  const payload = canonicalStrongRequestPayload(input);
  const digest = createHmac("sha256", input.apiKey).update(payload, "utf8").digest("hex");
  return `${STRONG_SIGNATURE_VERSION}=${digest}`;
}

function verifyTimestampAndNonce(request: Request, nowMs: number) {
  const timestampText = request.headers.get("x-gainiren-timestamp") ?? "";
  const nonce = request.headers.get("x-gainiren-nonce") ?? "";
  if (!timestampText || !nonce) return { ok: false as const, reasonCode: "SIGNATURE_HEADERS_MISSING" as const };
  if (!/^\d{10}$/.test(timestampText)) return { ok: false as const, reasonCode: "INVALID_SIGNATURE_TIMESTAMP" as const };
  const timestamp = Number(timestampText);
  if (!Number.isSafeInteger(timestamp) || Math.abs(Math.floor(nowMs / 1000) - timestamp) > MAX_CLOCK_SKEW_SECONDS) {
    return { ok: false as const, reasonCode: "SIGNATURE_TIMESTAMP_OUTSIDE_WINDOW" as const };
  }
  if (!NONCE_PATTERN.test(nonce)) return { ok: false as const, reasonCode: "INVALID_REQUEST_NONCE" as const };
  return { ok: true as const, timestamp, timestampText, nonce };
}

export function verifyRequestSignature(request: Request, rawBody: string, apiKey: string, nowMs = Date.now()): SignatureVerification {
  const signature = request.headers.get("x-gainiren-signature") ?? "";
  const common = verifyTimestampAndNonce(request, nowMs);
  if (!common.ok) return { valid: false, reasonCode: common.reasonCode };
  if (!signature || !apiKey) return { valid: false, reasonCode: "INVALID_REQUEST_SIGNATURE" };
  if (!SIGNATURE_PATTERN.test(signature)) return { valid: false, reasonCode: "INVALID_REQUEST_SIGNATURE" };

  const expected = createRequestSignature({ apiKey, method: request.method, requestUrl: request.url, timestamp: common.timestampText, nonce: common.nonce, rawBody });
  const suppliedBytes = Buffer.from(signature, "utf8");
  const expectedBytes = Buffer.from(expected, "utf8");
  if (suppliedBytes.byteLength !== expectedBytes.byteLength || !timingSafeEqual(suppliedBytes, expectedBytes)) {
    return { valid: false, reasonCode: "INVALID_REQUEST_SIGNATURE" };
  }
  return { valid: true, nonce: common.nonce, timestamp: common.timestamp, version: "v1", keyId: null };
}

export function verifyStrongRequestSignature(request: Request, rawBody: string, apiKey: string, keyId: string | null | undefined, nowMs = Date.now()): SignatureVerification {
  const signature = request.headers.get("x-gainiren-signature") ?? "";
  const common = verifyTimestampAndNonce(request, nowMs);
  if (!common.ok) return { valid: false, reasonCode: common.reasonCode };
  if (!keyId) return { valid: false, reasonCode: "SIGNATURE_KEY_ID_MISSING" };
  if (!KEY_ID_PATTERN.test(keyId)) return { valid: false, reasonCode: "SIGNATURE_KEY_ID_INVALID" };
  if (!signature || !apiKey) return { valid: false, reasonCode: "INVALID_REQUEST_SIGNATURE" };
  if (!STRONG_SIGNATURE_PATTERN.test(signature)) return { valid: false, reasonCode: "SIGNATURE_VERSION_NOT_ALLOWED" };
  const contentType = (request.headers.get("content-type") ?? "").split(";")[0].trim().toLowerCase();
  const expected = createStrongRequestSignature({ apiKey, method: request.method, requestUrl: request.url, timestamp: common.timestampText, nonce: common.nonce, keyId, contentType, rawBody });
  const suppliedBytes = Buffer.from(signature, "utf8");
  const expectedBytes = Buffer.from(expected, "utf8");
  if (suppliedBytes.byteLength !== expectedBytes.byteLength || !timingSafeEqual(suppliedBytes, expectedBytes)) {
    return { valid: false, reasonCode: "INVALID_REQUEST_SIGNATURE" };
  }
  return { valid: true, nonce: common.nonce, timestamp: common.timestamp, version: "v2", keyId };
}

export async function verifyAndConsumeRequestSignature(input: {
  request: Request;
  rawBody: string;
  apiKey: string;
  tenantId: string;
  nowMs?: number;
}): Promise<SignatureVerification> {
  const result = verifyRequestSignature(input.request, input.rawBody, input.apiKey, input.nowMs);
  if (!result.valid) return result;
  return consumeNonce(input.tenantId, result);
}

/** Part 5A path: v2 is mandatory and the key-id is part of the signed payload. */
export async function verifyAndConsumeStrongRequestSignature(input: {
  request: Request;
  rawBody: string;
  apiKey: string;
  tenantId: string;
  keyId: string | null | undefined;
  nowMs?: number;
}): Promise<SignatureVerification> {
  const result = verifyStrongRequestSignature(input.request, input.rawBody, input.apiKey, input.keyId, input.nowMs);
  if (!result.valid) return result;
  return consumeNonce(input.tenantId, result);
}

async function consumeNonce(tenantId: string, result: Extract<SignatureVerification, { valid: true }>): Promise<SignatureVerification> {
  const nonceHash = hashValue(result.nonce);
  const consumed = await supabase.schema("security").rpc("consume_request_nonce", { p_tenant_id: tenantId, p_nonce_hash: nonceHash });
  if (consumed.error) throw consumed.error;
  if (consumed.data !== true) return { valid: false, reasonCode: "REPLAYED_REQUEST_NONCE" };
  return result;
}
