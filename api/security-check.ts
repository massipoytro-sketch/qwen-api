import { createHash } from "node:crypto";
import { z } from "zod";
import { supabase } from "../src/db/supabase";
import { hashValue } from "../src/security/utils";
import { checkRateLimit } from "../src/security/rateLimit";
import { securityCheck } from "../src/security/check";
import { securityLog } from "../src/security/observability";
import { verifyAndConsumeRequestSignature } from "../src/security/requestSigning";
import { env } from "../src/config/env";
const bodySchema = z.object({ tenantId: z.uuid(), subjectId: z.uuid().optional(), sessionId: z.uuid().optional(), requestId: z.string().min(1).max(200).optional() });
const IDEMPOTENCY_PATTERN = /^[A-Za-z0-9._:-]{16,128}$/;
const json = (body: unknown, status = 200, requestId?: string) => new Response(status === 204 ? null : JSON.stringify(body), { status, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", "x-content-type-options": "nosniff", "referrer-policy": "no-referrer", "x-frame-options": "DENY", ...(requestId ? { "x-request-id": requestId } : {}), ...(env.SECURITY_API_CORS_ORIGIN ? { "access-control-allow-origin": env.SECURITY_API_CORS_ORIGIN, "access-control-allow-headers": "authorization,content-type,x-request-id,x-gainiren-signature,x-gainiren-timestamp,x-gainiren-nonce,idempotency-key", "access-control-allow-methods": "POST,OPTIONS", vary: "Origin" } : {}) } });
function requestHash(request: Request, rawBody: string): string { const url = new URL(request.url); return createHash("sha256").update(request.method.toUpperCase()).update("\n").update(url.pathname + url.search).update("\n").update(rawBody).digest("hex"); }
async function finalizeIdempotency(tenantId: string, keyHash: string, status: "completed" | "failed", responseCode: number): Promise<void> { const result = await supabase.schema("security").rpc("finalize_request_idempotency", { p_tenant_id: tenantId, p_idempotency_key_hash: keyHash, p_status: status, p_response_code: responseCode }); if (result.error) securityLog("idempotency_finalize_failed", { tenantId, errorCode: result.error.code ?? "SUPABASE_RESPONSE_ERROR" }); }
export default async function handler(request: Request) {
 const requestIdHeader = request.headers.get("x-request-id") ?? "";
 const requestId = /^[a-zA-Z0-9._:-]{1,100}$/.test(requestIdHeader) ? requestIdHeader : crypto.randomUUID();
 if (request.method === "OPTIONS") return json({}, 204, requestId);
 if (request.method !== "POST") return json({ error: "METHOD_NOT_ALLOWED", requestId }, 405, requestId);
 const auth = request.headers.get("authorization") ?? "";
 const bearer = /^Bearer\s+(.+)$/i.exec(auth);
 if (!bearer) return json({ error: "UNAUTHORIZED", requestId }, 401, requestId);
 const apiKey = bearer[1].trim();
 if (!apiKey || apiKey.length > 512) return json({ error: "UNAUTHORIZED", requestId }, 401, requestId);
 const contentType = (request.headers.get("content-type") ?? "").split(";")[0].trim().toLowerCase();
 if (contentType !== "application/json") return json({ error: "UNSUPPORTED_MEDIA_TYPE", requestId }, 415, requestId);
 try {
  const rawBody = await request.text();
  if (new TextEncoder().encode(rawBody).byteLength > 64 * 1024) return json({ error: "PAYLOAD_TOO_LARGE", requestId }, 413, requestId);
  let body: unknown; try { body = JSON.parse(rawBody); } catch { return json({ error: "INVALID_JSON", requestId }, 400, requestId); }
  const parsed = bodySchema.parse(body);
  const keyHash = hashValue(apiKey);
  const credential = await supabase.schema("security").rpc("consume_rotated_api_key", { p_key_hash: keyHash, p_tenant_id: parsed.tenantId });
  if (credential.error) throw credential.error;
  if (!Array.isArray(credential.data) || credential.data.length !== 1 || credential.data[0]?.tenant_id !== parsed.tenantId) { securityLog("auth_denied", { requestId }); return json({ error: "UNAUTHORIZED", requestId }, 401, requestId); }
  const tenant = await supabase.schema("security").from("tenants").select("id,status").eq("id", parsed.tenantId).eq("status", "active").maybeSingle();
  if (tenant.error) throw tenant.error;
  if (!tenant.data) return json({ error: "UNAUTHORIZED", requestId }, 401, requestId);
  const signature = await verifyAndConsumeRequestSignature({ request, rawBody, apiKey, tenantId: tenant.data.id });
  if (!signature.valid) { securityLog("request_signature_rejected", { requestId, tenantId: tenant.data.id, reasonCode: signature.reasonCode }); return json({ error: "INVALID_REQUEST_SIGNATURE", requestId }, 401, requestId); }
  const rateLimitChecks = await Promise.all([checkRateLimit({ tenantId: tenant.data.id, key: `api:${hashValue(apiKey)}`, bucket: "security-check", limit: 60, windowSeconds: 60 }), ...(parsed.subjectId ? [checkRateLimit({ tenantId: tenant.data.id, key: `subject:${parsed.subjectId}`, bucket: "security-check-subject", limit: 30, windowSeconds: 60, subjectId: parsed.subjectId })] : [])]);
  const blockedLimit = rateLimitChecks.find((limit) => !limit.allowed);
  if (blockedLimit) return json({ error: "RATE_LIMITED", retryAfter: Math.max(1, Math.ceil((Date.parse(blockedLimit.resetAt) - Date.now()) / 1000)), requestId }, 429, requestId);
  const idempotencyKey = request.headers.get("idempotency-key") ?? "";
  if (!IDEMPOTENCY_PATTERN.test(idempotencyKey)) return json({ error: "INVALID_IDEMPOTENCY_KEY", requestId }, 400, requestId);
  const idempotencyHash = hashValue(idempotencyKey);
  const idem = await supabase.schema("security").rpc("consume_request_idempotency", { p_tenant_id: tenant.data.id, p_idempotency_key_hash: idempotencyHash, p_request_hash: requestHash(request, rawBody), p_ttl_seconds: 86400 });
  if (idem.error) throw idem.error;
  if (!idem.data?.accepted) { const reason = idem.data?.reason; securityLog("idempotency_rejected", { requestId, tenantId: tenant.data.id, reason }); return json({ error: reason === "DUPLICATE_REQUEST" ? "DUPLICATE_REQUEST" : "IDEMPOTENCY_KEY_REUSE", requestId }, 409, requestId); }
  try {
   const result = await securityCheck({ tenantId: tenant.data.id, subjectId: parsed.subjectId, sessionId: parsed.sessionId, requestId });
   await finalizeIdempotency(tenant.data.id, idempotencyHash, "completed", 200);
   return json({ ...result, requestId }, 200, requestId);
  } catch (error) {
   await finalizeIdempotency(tenant.data.id, idempotencyHash, "failed", 500);
   throw error;
  }
 } catch (error) {
  if (error instanceof Error && ["SUBJECT_NOT_FOUND", "SESSION_NOT_FOUND", "SESSION_SUBJECT_MISMATCH", "SESSION_NOT_ACTIVE"].includes(error.message)) return json({ error: "INVALID_CONTEXT", requestId }, 400, requestId);
  if (error instanceof z.ZodError) return json({ error: "INVALID_REQUEST", requestId }, 400, requestId);
  securityLog("api_error", { requestId, errorCode: error instanceof Error ? error.name : "UNKNOWN_ERROR" }); return json({ error: "INTERNAL_ERROR", requestId }, 500, requestId);
 }
}
