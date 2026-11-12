import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import { supabase } from "../db/supabase";
import { hashValue } from "./utils";

const SIGNATURE_VERSION = "v1";
const RESPONSE_SIGNATURE_VERSION = "v1";
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

export function canonicalRequestPayload(input: { method: string; requestUrl: string; timestamp: string; nonce: string; rawBody: string }): string {
  return ["GAINIREN-REQUEST-V1", input.method.toUpperCase(), requestTarget(input.requestUrl), input.timestamp, input.nonce, bodyDigest(input.rawBody)].join("\n");
}

export function createRequestSignature(input: { apiKey: string; method: string; requestUrl: string; timestamp: string; nonce: string; rawBody: string }): string {
  const digest = createHmac("sha256", input.apiKey).update(canonicalRequestPayload(input), "utf8").digest("hex");
  return `${SIGNATURE_VERSION}=${digest}`;
}

/** Binds a response to the authenticated request without exposing the API key. */
export function canonicalResponsePayload(input: { requestId: string; status: number; body: string }): string {
  return ["GAINIREN-RESPONSE-V1", String(input.status), input.requestId, bodyDigest(input.body)].join("\n");
}

export function createResponseSignature(input: { apiKey: string; requestId: string; status: number; body: string }): string {
  const digest = createHmac("sha256", input.apiKey).update(canonicalResponsePayload(input), "utf8").digest("hex");
  return `${RESPONSE_SIGNATURE_VERSION}=${digest}`;
}

export function verifyResponseSignature(input: { apiKey: string; requestId: string; status: number; body: string; signature: string }): boolean {
  if (!SIGNATURE_PATTERN.test(input.signature) || !input.apiKey) return false;
  const expected = createResponseSignature(input);
  const supplied = Buffer.from(input.signature, "utf8");
  const expectedBytes = Buffer.from(expected, "utf8");
  return supplied.byteLength === expectedBytes.byteLength && timingSafeEqual(supplied, expectedBytes);
}

export function verifyRequestSignature(request: Request, rawBody: string, apiKey: string, nowMs = Date.now()): SignatureVerification {
  const signature = request.headers.get("x-gainiren-signature") ?? "";
  const timestampText = request.headers.get("x-gainiren-timestamp") ?? "";
  const nonce = request.headers.get("x-gainiren-nonce") ?? "";
  if (!signature || !timestampText || !nonce) return { valid: false, reasonCode: "SIGNATURE_HEADERS_MISSING" };
  if (!/^\d{10}$/.test(timestampText)) return { valid: false, reasonCode: "INVALID_SIGNATURE_TIMESTAMP" };
  const timestamp = Number(timestampText);
  if (!Number.isSafeInteger(timestamp) || Math.abs(Math.floor(nowMs / 1000) - timestamp) > MAX_CLOCK_SKEW_SECONDS) return { valid: false, reasonCode: "SIGNATURE_TIMESTAMP_OUTSIDE_WINDOW" };
  if (!NONCE_PATTERN.test(nonce)) return { valid: false, reasonCode: "INVALID_REQUEST_NONCE" };
  if (!SIGNATURE_PATTERN.test(signature) || !apiKey) return { valid: false, reasonCode: "INVALID_REQUEST_SIGNATURE" };
  const expected = createRequestSignature({ apiKey, method: request.method, requestUrl: request.url, timestamp: timestampText, nonce, rawBody });
  const suppliedBytes = Buffer.from(signature, "utf8");
  const expectedBytes = Buffer.from(expected, "utf8");
  if (suppliedBytes.byteLength !== expectedBytes.byteLength || !timingSafeEqual(suppliedBytes, expectedBytes)) return { valid: false, reasonCode: "INVALID_REQUEST_SIGNATURE" };
  return { valid: true, nonce, timestamp };
}

export async function verifyAndConsumeRequestSignature(input: { request: Request; rawBody: string; apiKey: string; tenantId: string; nowMs?: number }): Promise<SignatureVerification> {
  const result = verifyRequestSignature(input.request, input.rawBody, input.apiKey, input.nowMs);
  if (!result.valid) return result;
  const nonceHash = hashValue(result.nonce);
  const consumed = await supabase.schema("security").rpc("consume_request_nonce", { p_tenant_id: input.tenantId, p_nonce_hash: nonceHash });
  if (consumed.error) throw consumed.error;
  if (consumed.data !== true) return { valid: false, reasonCode: "REPLAYED_REQUEST_NONCE" };
  return result;
}
