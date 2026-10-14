import { createHash } from "node:crypto";
import { z } from "zod";
import { supabase } from "../src/db/supabase";
import { hashValue } from "../src/security/utils";
import { checkRateLimit } from "../src/security/rateLimit";
import { guardedSecurityCheck } from "../src/security/guardedCheck";
import { securityLog, safeErrorCode, safeErrorStatus } from "../src/security/observability";
import { verifyAndConsumeRequestSignature } from "../src/security/requestSigning";
import { authenticateRotatedTenantKey } from "../src/security/tenantAuth";
import { reconcilePersistedDecision, recordEmergencySecurityControl } from "../src/security/reconcile";
import { env } from "../src/config/env";
import type { SecurityCheckResult, SecurityDecision } from "../src/security/types";

const bodySchema = z.object({
  tenantId: z.uuid(),
  subjectId: z.uuid().optional(),
  sessionId: z.uuid().optional(),
  requestId: z.string().min(1).max(200).optional(),
}).strict();
const IDEMPOTENCY_PATTERN = /^[A-Za-z0-9._:-]{16,128}$/;
const rank: Record<SecurityDecision, number> = { ALLOW: 0, MONITOR: 1, CHALLENGE: 2, REVIEW: 3, BLOCK: 4 };

const securityControlSchema = z.object({
  mode: z.enum(["normal", "challenge_all", "deny_all", "maintenance"]).optional(),
  reason_code: z.string().max(80).nullable().optional(),
  version: z.number().finite().optional(),
  expires_at: z.string().datetime().nullable().optional(),
}).strict();

const runtimeControlSchema = z.object({
  mode: z.enum(["normal", "review_only", "lockdown"]),
  reasonCode: z.string().max(100),
  version: z.number().finite(),
  expiresAt: z.string().datetime().nullable().optional(),
}).passthrough();

const json = (
  body: unknown,
  status = 200,
  requestId?: string,
  extraHeaders: Record<string, string> = {},
) => new Response(status === 204 ? null : JSON.stringify(body), {
  status,
  headers: {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
    ...extraHeaders,
    ...(requestId ? { "x-request-id": requestId } : {}),
    ...(env.SECURITY_API_CORS_ORIGIN ? {
      "access-control-allow-origin": env.SECURITY_API_CORS_ORIGIN,
      "access-control-allow-headers": "authorization,content-type,x-request-id,x-gainiren-signature,x-gainiren-timestamp,x-gainiren-nonce,x-gainiren-key-id,idempotency-key",
      "access-control-allow-methods": "POST,OPTIONS",
      vary: "Origin",
    } : {}),
  },
});

function requestHash(request: Request, rawBody: string): string {
  const url = new URL(request.url);
  return createHash("sha256")
    .update(request.method.toUpperCase())
    .update("\n")
    .update(url.pathname + url.search)
    .update("\n")
    .update(rawBody)
    .digest("hex");
}

async function finalizeIdempotency(
  tenantId: string,
  keyHash: string,
  status: "completed" | "failed",
  responseCode: number,
) {
  const result = await supabase.schema("security").rpc("finalize_request_idempotency", {
    p_tenant_id: tenantId,
    p_idempotency_key_hash: keyHash,
    p_status: status,
    p_response_code: responseCode,
  });
  if (result.error) {
    securityLog("idempotency_finalize_failed", {
      tenantId,
      errorCode: safeErrorCode(result.error),
      ...(safeErrorStatus(result.error) ? { errorStatus: safeErrorStatus(result.error) } : {}),
    });
  }
}

function safeControlReason(value: string | null | undefined, fallback: string): string {
  return value && /^[A-Za-z0-9_.:-]{1,80}$/.test(value) ? value : fallback;
}

export default async function handler(request: Request) {
  const candidate = request.headers.get("x-request-id") ?? "";
  const requestId = /^[A-Za-z0-9._:-]{1,100}$/.test(candidate) ? candidate : crypto.randomUUID();
  if (request.method === "OPTIONS") return json({}, 204, requestId);
  if (request.method !== "POST") return json({ error: "METHOD_NOT_ALLOWED", requestId }, 405, requestId);

  const bearer = /^Bearer\s+(.+)$/i.exec(request.headers.get("authorization") ?? "");
  if (!bearer || bearer[1].trim().length < 1 || bearer[1].trim().length > 512) {
    return json({ error: "UNAUTHORIZED", requestId }, 401, requestId);
  }
  const apiKey = bearer[1].trim();
  const contentType = (request.headers.get("content-type") ?? "").split(";")[0].trim().toLowerCase();
  if (contentType !== "application/json") return json({ error: "UNSUPPORTED_MEDIA_TYPE", requestId }, 415, requestId);

  let claimedTenantId: string | null = null;
  let claimedIdempotencyHash: string | null = null;
  let idempotencyClaimed = false;

  try {
    const rawBody = await request.text();
    if (new TextEncoder().encode(rawBody).byteLength > 64 * 1024) {
      return json({ error: "PAYLOAD_TOO_LARGE", requestId }, 413, requestId);
    }

    let body: unknown;
    try {
      body = JSON.parse(rawBody);
    } catch {
      return json({ error: "INVALID_JSON", requestId }, 400, requestId);
    }
    const parsed = bodySchema.parse(body);
    claimedTenantId = parsed.tenantId;

    const authentication = await authenticateRotatedTenantKey({
      tenantId: parsed.tenantId,
      apiKey,
      keyId: request.headers.get("x-gainiren-key-id")?.trim() || null,
    });
    if (!authentication.authorized) return json({ error: "UNAUTHORIZED", requestId }, 401, requestId);

    const signature = await verifyAndConsumeRequestSignature({
      request,
      rawBody,
      apiKey,
      tenantId: parsed.tenantId,
    });
    if (!signature.valid) {
      securityLog("request_signature_rejected", {
        requestId,
        tenantId: parsed.tenantId,
        reasonCode: signature.reasonCode,
      });
      return json({ error: "INVALID_REQUEST_SIGNATURE", requestId }, 401, requestId);
    }

    // Rate limits precede all operator-controlled early returns so emergency
    // blocks cannot be abused to bypass request throttling or flood the ledger.
    const limits = await Promise.all([
      checkRateLimit({
        tenantId: parsed.tenantId,
        key: `api:${hashValue(apiKey)}`,
        bucket: "security-check",
        limit: 60,
        windowSeconds: 60,
      }),
      ...(parsed.subjectId ? [checkRateLimit({
        tenantId: parsed.tenantId,
        key: `subject:${parsed.subjectId}`,
        bucket: "security-check-subject",
        limit: 30,
        windowSeconds: 60,
        subjectId: parsed.subjectId,
      })] : []),
    ]);
    const blocked = limits.find((limit) => !limit.allowed);
    if (blocked) {
      return json({
        error: "RATE_LIMITED",
        retryAfter: Math.max(1, Math.ceil((Date.parse(blocked.resetAt) - Date.now()) / 1000)),
        requestId,
      }, 429, requestId);
    }

    const idempotencyKey = request.headers.get("idempotency-key") ?? "";
    if (!IDEMPOTENCY_PATTERN.test(idempotencyKey)) {
      return json({ error: "INVALID_IDEMPOTENCY_KEY", requestId }, 400, requestId);
    }
    claimedIdempotencyHash = hashValue(idempotencyKey);
    const claim = await supabase.schema("security").rpc("consume_request_idempotency", {
      p_tenant_id: parsed.tenantId,
      p_idempotency_key_hash: claimedIdempotencyHash,
      p_request_hash: requestHash(request, rawBody),
      p_ttl_seconds: 86400,
    });
    if (claim.error) throw claim.error;
    if (!claim.data?.accepted) {
      return json({
        error: claim.data?.reason === "DUPLICATE_REQUEST" ? "DUPLICATE_REQUEST" : "IDEMPOTENCY_KEY_REUSE",
        requestId,
      }, 409, requestId);
    }
    idempotencyClaimed = true;

    const controlResponse = await supabase.schema("security").rpc("get_security_control", {
      p_tenant_id: parsed.tenantId,
    });
    if (controlResponse.error) throw controlResponse.error;
    const currentRow = Array.isArray(controlResponse.data) ? controlResponse.data[0] : undefined;
    const current = currentRow ? securityControlSchema.parse(currentRow) : undefined;
    const controlExpired = Boolean(current?.expires_at && Date.parse(current.expires_at) <= Date.now());
    const controlMode = controlExpired ? "normal" : (current?.mode ?? "normal");
    const controlReason = safeControlReason(current?.reason_code, "EMERGENCY_CONTROL");

    if (controlMode === "deny_all" || controlMode === "maintenance") {
      try {
        await recordEmergencySecurityControl({
          tenantId: parsed.tenantId,
          mode: controlMode,
          reasonCode: controlReason,
          requestId,
        });
      } catch {
        // The denial must remain in effect even if the audit store is unhealthy.
      }
      await finalizeIdempotency(parsed.tenantId, claimedIdempotencyHash, "completed", 423);
      idempotencyClaimed = false;
      return json({
        error: "SECURITY_CONTROL_BLOCK",
        mode: controlMode,
        reasonCode: controlReason,
        requestId,
      }, 423, requestId);
    }

    const runtimeResponse = await supabase.schema("security").rpc("get_runtime_control", {
      p_tenant_id: parsed.tenantId,
    });
    if (runtimeResponse.error) throw runtimeResponse.error;
    const runtimeRaw = runtimeResponse.data ?? {
      mode: "normal",
      reasonCode: "NORMAL",
      version: 0,
      expiresAt: null,
    };
    const runtimeValue = runtimeControlSchema.parse(runtimeRaw);
    const runtimeExpired = Boolean(runtimeValue.expiresAt && Date.parse(runtimeValue.expiresAt) <= Date.now());
    const runtimeMode = runtimeExpired ? "normal" : runtimeValue.mode;

    if (runtimeMode === "lockdown") {
      try {
        await recordEmergencySecurityControl({
          tenantId: parsed.tenantId,
          mode: "lockdown",
          reasonCode: safeControlReason(runtimeValue.reasonCode, "RUNTIME_LOCKDOWN"),
          requestId,
        });
      } catch {
        // The lockdown decision still wins over audit availability.
      }
      await finalizeIdempotency(parsed.tenantId, claimedIdempotencyHash, "completed", 200);
      idempotencyClaimed = false;
      return json({
        decision: "BLOCK",
        score: 100,
        riskLevel: "critical",
        challengeRecommendation: null,
        runtimeControl: { ...runtimeValue, mode: runtimeMode },
        securityControl: { mode: controlMode, reasonCode: controlReason, version: current?.version ?? 0 },
        requestId,
      }, 200, requestId, { "x-gainiren-runtime-control": "lockdown" });
    }

    let result: SecurityCheckResult & { networkControl?: { mode: string; reasonCode: string } } =
      await guardedSecurityCheck({
        tenantId: parsed.tenantId,
        subjectId: parsed.subjectId,
        sessionId: parsed.sessionId,
        requestId,
      });

    let enforcementSource = result.networkControl && result.networkControl.mode !== "monitor"
      ? "network_control"
      : "guarded_security_check";
    const enforcedReasons: string[] = [
      ...(result.challengeRecommendation?.reasonCodes ?? []),
      ...(result.networkControl && result.networkControl.mode !== "monitor" ? [result.networkControl.reasonCode] : []),
    ];

    if (controlMode === "challenge_all" && rank[result.decision] < rank.CHALLENGE) {
      result = {
        ...result,
        decision: "CHALLENGE",
        score: Math.max(40, result.score),
        riskLevel: result.score >= 90 ? "critical" : "medium",
        challengeRecommendation: {
          type: "risk_based_verification",
          reasonCodes: ["TENANT_CHALLENGE_ALL", ...(current?.reason_code ? [current.reason_code] : [])],
          expiresInSeconds: 300,
        },
      };
      enforcementSource = "tenant_challenge_all";
      enforcedReasons.push("TENANT_CHALLENGE_ALL");
      if (current?.reason_code) enforcedReasons.push(current.reason_code);
    } else if (controlMode === "challenge_all") {
      enforcementSource = "tenant_challenge_all";
      enforcedReasons.push("TENANT_CHALLENGE_ALL");
      if (current?.reason_code) enforcedReasons.push(current.reason_code);
    }

    if (runtimeMode === "review_only" && rank[result.decision] < rank.REVIEW) {
      result = {
        ...result,
        decision: "REVIEW",
        score: Math.max(70, result.score),
        riskLevel: result.score >= 90 ? "critical" : "high",
      };
      enforcementSource = "runtime_review_only";
      enforcedReasons.push("RUNTIME_REVIEW_ONLY", runtimeValue.reasonCode);
    }

    if (!result.assessmentId) throw new Error("SECURITY_ASSESSMENT_ID_MISSING");
    const reconciled = await reconcilePersistedDecision({
      tenantId: parsed.tenantId,
      result,
      enforcementSource,
      reasonCodes: enforcedReasons.filter((code) => /^[A-Za-z0-9_.:-]{1,100}$/.test(code)).slice(0, 128),
      requestId,
    });

    result = {
      ...result,
      decision: reconciled.decision,
      score: reconciled.score,
      riskLevel: reconciled.riskLevel,
    };
    if (result.decision !== "CHALLENGE") result.challengeRecommendation = null;
    else result.challengeRecommendation ??= {
      type: "risk_based_verification",
      reasonCodes: reconciled.reasonCodes.slice(0, 32),
      expiresInSeconds: 300,
    };

    await finalizeIdempotency(parsed.tenantId, claimedIdempotencyHash, "completed", 200);
    idempotencyClaimed = false;
    return json({
      ...result,
      runtimeControl: { ...runtimeValue, mode: runtimeMode },
      securityControl: {
        mode: controlMode,
        reasonCode: current?.reason_code ?? null,
        version: current?.version ?? null,
      },
      requestId,
    }, 200, requestId);
  } catch (error) {
    if (idempotencyClaimed && claimedTenantId && claimedIdempotencyHash) {
      await finalizeIdempotency(claimedTenantId, claimedIdempotencyHash, "failed", 500);
    }
    if (error instanceof Error && [
      "SUBJECT_NOT_FOUND",
      "SESSION_NOT_FOUND",
      "SESSION_SUBJECT_MISMATCH",
      "SESSION_NOT_ACTIVE",
    ].includes(error.message)) {
      return json({ error: "INVALID_CONTEXT", requestId }, 400, requestId);
    }
    if (error instanceof z.ZodError) return json({ error: "INVALID_REQUEST", requestId }, 400, requestId);
    securityLog("api_error", {
      requestId,
      errorCode: safeErrorCode(error),
      ...(safeErrorStatus(error) ? { errorStatus: safeErrorStatus(error) } : {}),
    });
    return json({ error: "INTERNAL_ERROR", requestId }, 500, requestId);
  }
}
