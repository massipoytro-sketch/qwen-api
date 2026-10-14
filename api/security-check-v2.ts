import { createHash } from "node:crypto";
import { z } from "zod";
import { supabase } from "../src/db/supabase";
import { hashValue } from "../src/security/utils";
import { checkRateLimit } from "../src/security/rateLimit";
import { guardedSecurityCheck } from "../src/security/guardedCheck";
import { securityLog } from "../src/security/observability";
import { verifyAndConsumeRequestSignature } from "../src/security/requestSigning";
import { authenticateRotatedTenantKey } from "../src/security/tenantAuth";
import { env } from "../src/config/env";

const bodySchema = z.object({ tenantId: z.uuid(), subjectId: z.uuid().optional(), sessionId: z.uuid().optional(), requestId: z.string().min(1).max(200).optional() }).strict();
const IDEMPOTENCY_PATTERN = /^[A-Za-z0-9._:-]{16,128}$/;
const rank = { ALLOW: 0, MONITOR: 1, CHALLENGE: 2, REVIEW: 3, BLOCK: 4 } as const;

const json = (body: unknown, status = 200, requestId?: string, extraHeaders: Record<string,string> = {}) => new Response(status === 204 ? null : JSON.stringify(body), {
  status,
  headers: {
    "content-type": "application/json; charset=utf-8", "cache-control": "no-store", "x-content-type-options": "nosniff", "x-frame-options": "DENY", "referrer-policy": "no-referrer",
    ...extraHeaders,
    ...(requestId ? { "x-request-id": requestId } : {}),
    ...(env.SECURITY_API_CORS_ORIGIN ? { "access-control-allow-origin": env.SECURITY_API_CORS_ORIGIN, "access-control-allow-headers": "authorization,content-type,x-request-id,x-gainiren-signature,x-gainiren-timestamp,x-gainiren-nonce,x-gainiren-key-id,idempotency-key", "access-control-allow-methods": "POST,OPTIONS", vary: "Origin" } : {}),
  },
});

function requestHash(request: Request, rawBody: string): string {
  const url = new URL(request.url);
  return createHash("sha256").update(request.method.toUpperCase()).update("\n").update(url.pathname + url.search).update("\n").update(rawBody).digest("hex");
}

async function finalizeIdempotency(tenantId: string, keyHash: string, status: "completed" | "failed", responseCode: number) {
  const result = await supabase.schema("security").rpc("finalize_request_idempotency", { p_tenant_id: tenantId, p_idempotency_key_hash: keyHash, p_status: status, p_response_code: responseCode });
  if (result.error) securityLog("idempotency_finalize_failed", { tenantId, errorCode: result.error.code ?? "SUPABASE_RESPONSE_ERROR" });
}

export default async function handler(request: Request) {
  const candidate = request.headers.get("x-request-id") ?? "";
  const requestId = /^[A-Za-z0-9._:-]{1,100}$/.test(candidate) ? candidate : crypto.randomUUID();
  if (request.method === "OPTIONS") return json({}, 204, requestId);
  if (request.method !== "POST") return json({ error: "METHOD_NOT_ALLOWED", requestId }, 405, requestId);
  const bearer = /^Bearer\s+(.+)$/i.exec(request.headers.get("authorization") ?? "");
  if (!bearer || bearer[1].trim().length > 512) return json({ error: "UNAUTHORIZED", requestId }, 401, requestId);
  const apiKey = bearer[1].trim();
  const contentType = (request.headers.get("content-type") ?? "").split(";")[0].trim().toLowerCase();
  if (contentType !== "application/json") return json({ error: "UNSUPPORTED_MEDIA_TYPE", requestId }, 415, requestId);
  try {
    const rawBody = await request.text();
    if (new TextEncoder().encode(rawBody).byteLength > 64 * 1024) return json({ error: "PAYLOAD_TOO_LARGE", requestId }, 413, requestId);
    let body: unknown; try { body = JSON.parse(rawBody); } catch { return json({ error: "INVALID_JSON", requestId }, 400, requestId); }
    const parsed = bodySchema.parse(body);
    const keyIdHeader = request.headers.get("x-gainiren-key-id")?.trim() || null;
    const authentication = await authenticateRotatedTenantKey({
      tenantId: parsed.tenantId,
      apiKey,
      keyId: keyIdHeader,
    });
    if (!authentication.authorized) return json({ error: "UNAUTHORIZED", requestId }, 401, requestId);

    const signature = await verifyAndConsumeRequestSignature({ request, rawBody, apiKey, tenantId: parsed.tenantId });
    if (!signature.valid) { securityLog("request_signature_rejected", { requestId, tenantId: parsed.tenantId, reasonCode: signature.reasonCode }); return json({ error: "INVALID_REQUEST_SIGNATURE", requestId }, 401, requestId); }

    const control = await supabase.schema("security").rpc("get_security_control", { p_tenant_id: parsed.tenantId });
    if (control.error) throw control.error;
    const current = (control.data ?? [])[0] as { mode?: string; reason_code?: string | null; version?: number; expires_at?: string | null } | undefined;
    const controlMode = current?.expires_at && Date.parse(current.expires_at) <= Date.now() ? "normal" : (current?.mode ?? "normal");
    if (controlMode === "deny_all" || controlMode === "maintenance") return json({ error: "SECURITY_CONTROL_BLOCK", mode: controlMode, reasonCode: current?.reason_code ?? "EMERGENCY_CONTROL", requestId }, 423, requestId);

    const runtime = await supabase.schema("security").rpc("get_runtime_control", { p_tenant_id: parsed.tenantId });
    if (runtime.error) throw runtime.error;
    const runtimeValue = runtime.data as { mode?: string; reasonCode?: string; version?: number } | null;
    const runtimeMode = runtimeValue?.mode ?? "normal";
    if (runtimeMode === "lockdown") return json({ decision: "BLOCK", score: 100, riskLevel: "critical", challengeRecommendation: null, runtimeControl: runtimeValue, requestId }, 200, requestId, { "x-gainiren-runtime-control": "lockdown" });

    const limits = await Promise.all([
      checkRateLimit({ tenantId: parsed.tenantId, key: `api:${hashValue(apiKey)}`, bucket: "security-check", limit: 60, windowSeconds: 60 }),
      ...(parsed.subjectId ? [checkRateLimit({ tenantId: parsed.tenantId, key: `subject:${parsed.subjectId}`, bucket: "security-check-subject", limit: 30, windowSeconds: 60, subjectId: parsed.subjectId })] : []),
    ]);
    const blocked = limits.find((limit) => !limit.allowed);
    if (blocked) return json({ error: "RATE_LIMITED", retryAfter: Math.max(1, Math.ceil((Date.parse(blocked.resetAt) - Date.now()) / 1000)), requestId }, 429, requestId);

    const idempotencyKey = request.headers.get("idempotency-key") ?? "";
    if (!IDEMPOTENCY_PATTERN.test(idempotencyKey)) return json({ error: "INVALID_IDEMPOTENCY_KEY", requestId }, 400, requestId);
    const idempotencyHash = hashValue(idempotencyKey);
    const claim = await supabase.schema("security").rpc("consume_request_idempotency", { p_tenant_id: parsed.tenantId, p_idempotency_key_hash: idempotencyHash, p_request_hash: requestHash(request, rawBody), p_ttl_seconds: 86400 });
    if (claim.error) throw claim.error;
    if (!claim.data?.accepted) return json({ error: claim.data?.reason === "DUPLICATE_REQUEST" ? "DUPLICATE_REQUEST" : "IDEMPOTENCY_KEY_REUSE", requestId }, 409, requestId);

    try {
      let result = await guardedSecurityCheck({ tenantId: parsed.tenantId, subjectId: parsed.subjectId, sessionId: parsed.sessionId, requestId });
      if (controlMode === "challenge_all" && rank[result.decision] < rank.CHALLENGE) result = { ...result, decision: "CHALLENGE", score: Math.max(40, result.score), riskLevel: "medium", challengeRecommendation: { type: "risk_based_verification", reasonCodes: ["TENANT_CHALLENGE_ALL", ...(current?.reason_code ? [current.reason_code] : [])], expiresInSeconds: 300 } };
      if (runtimeMode === "review_only" && rank[result.decision] < rank.REVIEW) result = { ...result, decision: "REVIEW", score: Math.max(70, result.score), riskLevel: "high" };
      await finalizeIdempotency(parsed.tenantId, idempotencyHash, "completed", 200);
      return json({ ...result, runtimeControl: runtimeValue, securityControl: { mode: controlMode, reasonCode: current?.reason_code ?? null, version: current?.version ?? null }, requestId }, 200, requestId);
    } catch (error) {
      await finalizeIdempotency(parsed.tenantId, idempotencyHash, "failed", 500);
      throw error;
    }
  } catch (error) {
    if (error instanceof Error && ["SUBJECT_NOT_FOUND","SESSION_NOT_FOUND","SESSION_SUBJECT_MISMATCH","SESSION_NOT_ACTIVE"].includes(error.message)) return json({ error: "INVALID_CONTEXT", requestId }, 400, requestId);
    if (error instanceof z.ZodError) return json({ error: "INVALID_REQUEST", requestId }, 400, requestId);
    securityLog("api_error", { requestId, errorCode: error instanceof Error ? error.name : "UNKNOWN_ERROR" });
    return json({ error: "INTERNAL_ERROR", requestId }, 500, requestId);
  }
}
