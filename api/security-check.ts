import { z } from "zod";
import { supabase } from "../src/db/supabase";
import { hashValue } from "../src/security/utils";
import { checkRateLimit } from "../src/security/rateLimit";
import { securityCheck } from "../src/security/check";
import { securityLog } from "../src/security/observability";
import { verifyAndConsumeRequestSignature } from "../src/security/requestSigning";
import { env } from "../src/config/env";

const bodySchema = z.object({ tenantId: z.uuid(), subjectId: z.uuid().optional(), sessionId: z.uuid().optional(), requestId: z.string().min(1).max(200).optional() });
const json = (body: unknown, status = 200, requestId?: string) => new Response(status === 204 ? null : JSON.stringify(body), { status, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", "x-content-type-options": "nosniff", "referrer-policy": "no-referrer", "x-frame-options": "DENY", ...(requestId ? { "x-request-id": requestId } : {}), ...(env.SECURITY_API_CORS_ORIGIN ? { "access-control-allow-origin": env.SECURITY_API_CORS_ORIGIN, "access-control-allow-headers": "authorization,content-type,x-request-id,x-gainiren-signature,x-gainiren-timestamp,x-gainiren-nonce,x-gainiren-key-id", "access-control-allow-methods": "POST,OPTIONS", "vary": "Origin" } : {}) } });

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
    let body: unknown;
    try { body = JSON.parse(rawBody); } catch { return json({ error: "INVALID_JSON", requestId }, 400, requestId); }
    const parsed = bodySchema.parse(body);
    const keyHash = hashValue(apiKey);
    const keyId = request.headers.get("x-gainiren-key-id") ?? "";
    let tenantId: string | null = null;
    let tenantStatus: string | null = null;

    if (keyId) {
      const rotated = await supabase.schema("security").rpc("consume_rotated_api_key", { p_key_hash: keyHash, p_key_id: keyId, p_tenant_id: parsed.tenantId });
      if (rotated.error) throw rotated.error;
      const match = (rotated.data ?? [])[0] as { tenant_id: string; key_id: string } | undefined;
      if (match?.tenant_id === parsed.tenantId && match.key_id === keyId) { tenantId = match.tenant_id; tenantStatus = "active"; }
    }
    if (!tenantId) {
      const tenant = await supabase.schema("security").from("tenants").select("id,status").eq("id", parsed.tenantId).eq("api_key_hash", keyHash).maybeSingle();
      if (tenant.error) throw tenant.error;
      if (tenant.data) { tenantId = tenant.data.id; tenantStatus = tenant.data.status; }
    }
    if (!tenantId || tenantStatus !== "active") return json({ error: "UNAUTHORIZED", requestId }, 401, requestId);

    const signature = await verifyAndConsumeRequestSignature({ request, rawBody, apiKey, tenantId });
    if (!signature.valid) {
      securityLog("request_signature_rejected", { requestId, tenantId, reasonCode: signature.reasonCode });
      return json({ error: "INVALID_REQUEST_SIGNATURE", requestId }, 401, requestId);
    }

    const control = await supabase.schema("security").rpc("get_security_control", { p_tenant_id: tenantId });
    if (control.error) throw control.error;
    const currentControl = (control.data ?? [])[0] as { mode?: string; reason_code?: string | null; version?: number; expires_at?: string | null } | undefined;
    const mode = currentControl?.expires_at && Date.parse(currentControl.expires_at) <= Date.now() ? "normal" : (currentControl?.mode ?? "normal");
    if (mode === "deny_all" || mode === "maintenance") {
      securityLog("security_control_block", { requestId, tenantId, mode, version: currentControl?.version ?? null });
      return json({ error: "SECURITY_CONTROL_BLOCK", mode, reasonCode: currentControl?.reason_code ?? "EMERGENCY_CONTROL", requestId }, 423, requestId);
    }

    const rateLimitChecks = await Promise.all([
      checkRateLimit({ tenantId, key: `api:${apiKey}`, bucket: "security-check", limit: 60, windowSeconds: 60 }),
      ...(parsed.subjectId ? [checkRateLimit({ tenantId, key: `subject:${parsed.subjectId}`, bucket: "security-check-subject", limit: 30, windowSeconds: 60, subjectId: parsed.subjectId })] : []),
    ]);
    const blockedLimit = rateLimitChecks.find((limit) => !limit.allowed);
    if (blockedLimit) return json({ error: "RATE_LIMITED", retryAfter: Math.max(1, Math.ceil((Date.parse(blockedLimit.resetAt) - Date.now()) / 1000)), requestId }, 429, requestId);

    const result = await securityCheck({ tenantId, subjectId: parsed.subjectId, sessionId: parsed.sessionId, requestId });
    if (mode === "challenge_all" && (result.decision === "ALLOW" || result.decision === "MONITOR")) {
      return json({ ...result, decision: "CHALLENGE", score: Math.max(result.score, 40), riskLevel: "medium", challengeRecommendation: { type: "risk_based_verification", reasonCodes: ["TENANT_CHALLENGE_ALL", ...(currentControl?.reason_code ? [currentControl.reason_code] : [])], expiresInSeconds: 300 }, requestId }, 200, requestId);
    }
    return json({ ...result, requestId }, 200, requestId);
  } catch (error) {
    if (error instanceof Error && ["SUBJECT_NOT_FOUND", "SESSION_NOT_FOUND", "SESSION_SUBJECT_MISMATCH", "SESSION_NOT_ACTIVE"].includes(error.message)) return json({ error: "INVALID_CONTEXT", requestId }, 400, requestId);
    if (error instanceof z.ZodError) return json({ error: "INVALID_REQUEST", requestId }, 400, requestId);
    securityLog("api_error", { requestId, errorCode: error instanceof Error ? error.name : "UNKNOWN_ERROR" });
    return json({ error: "INTERNAL_ERROR", requestId }, 500, requestId);
  }
}
