import { createHash, randomUUID } from "node:crypto";
import { z } from "zod";
import { supabase } from "../src/db/supabase";
import { hashValue } from "../src/security/utils";
import { checkRateLimit } from "../src/security/rateLimit";
import { guardedSecurityCheck } from "../src/security/guardedCheck";
import { safeErrorCode, safeErrorStatus, securityLog } from "../src/security/observability";
import { verifyAndConsumeRequestSignature } from "../src/security/requestSigning";
import { authenticateRotatedTenantKey } from "../src/security/tenantAuth";
import { reconcilePersistedDecision, recordEmergencySecurityControl } from "../src/security/reconcile";
import { evaluateTransactionFirewall } from "../src/security/transactionFirewall";
import { applySubjectTransactionControl, deriveSubjectTransactionControl, type SubjectTransactionControl } from "../src/security/adaptiveLockdown";
import { isSecureTransport, securityHeaders } from "../src/security/transport";
import { env } from "../src/config/env";
import type { SecurityDecision, SecurityCheckResult } from "../src/security/types";

const operationSchema = z.enum([
  "earn", "reward_credit", "redeem", "purchase", "deposit", "transfer",
  "withdrawal", "payout", "refund", "wallet_adjustment",
]);

const bodySchema = z.object({
  tenantId: z.uuid(),
  subjectId: z.uuid(),
  sessionId: z.uuid().optional(),
  transactionRef: z.string().min(8).max(128).regex(/^[A-Za-z0-9._:-]+$/),
  operation: operationSchema,
  previousValue: z.number().finite().min(0).max(1e15).optional(),
  currentValue: z.number().finite().min(0).max(1e15).optional(),
  amount: z.number().finite().min(0).max(1e15).optional(),
  currency: z.string().regex(/^[A-Z][A-Z0-9_]{1,11}$/).optional(),
}).strict().superRefine((value, context) => {
  if ((value.previousValue === undefined) !== (value.currentValue === undefined)) {
    context.addIssue({
      code: "custom",
      path: ["currentValue"],
      message: "previousValue and currentValue must be supplied together",
    });
  }
});

const controlSchema = z.object({
  mode: z.enum(["normal", "challenge_all", "deny_all", "maintenance"]).optional(),
  reason_code: z.string().max(80).nullable().optional(),
  version: z.number().finite().optional(),
  expires_at: z.string().datetime({ offset: true }).nullable().optional(),
}).strict();

const subjectControlRowSchema = z.object({
  mode: z.enum(["hold", "block"]),
  reason_code: z.string().min(1).max(80).regex(/^[A-Z0-9_.:-]+$/),
  expires_at: z.string().datetime({ offset: true }),
}).strict();

const runtimeSchema = z.object({
  mode: z.enum(["normal", "review_only", "lockdown"]),
  reasonCode: z.string().min(1).max(80).regex(/^[A-Za-z0-9_.:-]+$/),
  version: z.number().finite(),
  expiresAt: z.string().datetime({ offset: true }).nullable().optional(),
}).passthrough();

const rank: Record<SecurityDecision, number> = {
  ALLOW: 0, MONITOR: 1, CHALLENGE: 2, REVIEW: 3, BLOCK: 4,
};
const scoreFloor: Record<SecurityDecision, number> = {
  ALLOW: 0, MONITOR: 1, CHALLENGE: 40, REVIEW: 70, BLOCK: 90,
};
const riskLevelFor = (score: number): SecurityCheckResult["riskLevel"] =>
  score >= 90 ? "critical" : score >= 70 ? "high" : score >= 40 ? "medium" : score > 0 ? "low" : "unknown";

function requestDigest(request: Request, rawBody: string): string {
  const url = new URL(request.url);
  return createHash("sha256")
    .update(request.method.toUpperCase())
    .update("\n")
    .update(url.pathname + url.search)
    .update("\n")
    .update(rawBody)
    .digest("hex");
}

function json(body: unknown, status = 200, requestId?: string) {
  return new Response(status === 204 ? null : JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
      "x-frame-options": "DENY",
      "referrer-policy": "no-referrer",
      ...securityHeaders(),
      ...(requestId ? { "x-request-id": requestId } : {}),
      ...(env.SECURITY_API_CORS_ORIGIN ? {
        "access-control-allow-origin": env.SECURITY_API_CORS_ORIGIN,
        "access-control-allow-headers": "authorization,content-type,x-request-id,x-gainiren-signature,x-gainiren-timestamp,x-gainiren-nonce,x-gainiren-key-id,idempotency-key",
        "access-control-allow-methods": "POST,OPTIONS",
        vary: "Origin",
      } : {}),
    },
  });
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
    securityLog("transaction_idempotency_finalize_failed", {
      tenantId,
      errorCode: safeErrorCode(result.error),
      ...(safeErrorStatus(result.error) ? { errorStatus: safeErrorStatus(result.error) } : {}),
    });
    throw result.error;
  }
}

function safeReason(value: string | null | undefined, fallback: string): string {
  return value && /^[A-Za-z0-9_.:-]{1,80}$/.test(value) ? value : fallback;
}

async function recordTransactionRisk(input: {
  tenantId: string;
  subjectId: string;
  sessionId?: string;
  assessmentId?: string;
  transactionRefHash: string;
  operation: z.infer<typeof operationSchema>;
  previousValue?: number;
  currentValue?: number;
  amount?: number;
  currency?: string;
  score: number;
  decision: SecurityDecision;
  context: Record<string, unknown>;
}) {
  const inserted = await supabase.schema("security").from("transaction_risk_events").insert({
    tenant_id: input.tenantId,
    subject_id: input.subjectId,
    session_id: input.sessionId ?? null,
    assessment_id: input.assessmentId ?? null,
    operation: input.operation,
    before_value: input.previousValue ?? null,
    after_value: input.currentValue ?? null,
    risk_score: input.score,
    decision: input.decision,
    sensitive: true,
    currency: input.currency ?? null,
    context: {
      schemaVersion: "transaction-firewall-v1",
      transactionRefHash: input.transactionRefHash,
      amount: input.amount ?? null,
      ...input.context,
    },
  });
  if (inserted.error) throw inserted.error;
}

async function appendTransactionLedger(input: {
  tenantId: string;
  requestId: string;
  transactionRefHash: string;
  operation: z.infer<typeof operationSchema>;
  assessmentId?: string;
  decision: SecurityDecision;
  score: number;
  commitAllowed: boolean;
  adaptiveControl: string;
  reasonCodes: string[];
}) {
  const result = await supabase.schema("security").rpc("append_security_ledger_entry", {
    p_tenant_id: input.tenantId,
    p_action: "transaction_preflight_decided",
    p_resource_type: "transaction_preflight",
    p_resource_id: input.transactionRefHash,
    p_request_id: input.requestId,
    p_actor_type: "system",
    p_details: {
      operation: input.operation,
      assessmentId: input.assessmentId ?? null,
      decision: input.decision,
      score: input.score,
      commitAllowed: input.commitAllowed,
      adaptiveControl: input.adaptiveControl,
      reasonCodes: input.reasonCodes.slice(0, 64),
      version: "transaction-firewall-v1",
    },
  });
  if (result.error) throw result.error;
}

function enforcedDecision(base: SecurityDecision, minimum: SecurityDecision): SecurityDecision {
  return rank[minimum] > rank[base] ? minimum : base;
}

/**
 * Server-to-server preflight only. The calling wallet backend must not mutate
 * balances unless this endpoint returns commitAllowed=true and its HTTP
 * response is successful. Browser-supplied balances must never be trusted.
 */
export default async function handler(request: Request) {
  const incomingId = request.headers.get("x-request-id") ?? "";
  const requestId = /^[A-Za-z0-9._:-]{1,100}$/.test(incomingId) ? incomingId : randomUUID();
  if (!isSecureTransport(request)) return json({ error: "TLS_REQUIRED", requestId, commitAllowed: false }, 426, requestId);
  if (request.method === "OPTIONS") return json({}, 204, requestId);
  if (request.method !== "POST") return json({ error: "METHOD_NOT_ALLOWED", requestId, commitAllowed: false }, 405, requestId);

  const bearer = /^Bearer\s+(.+)$/i.exec(request.headers.get("authorization") ?? "");
  if (!bearer || bearer[1].trim().length < 1 || bearer[1].trim().length > 512) {
    return json({ error: "UNAUTHORIZED", requestId, commitAllowed: false }, 401, requestId);
  }
  const apiKey = bearer[1].trim();
  const contentType = (request.headers.get("content-type") ?? "").split(";")[0].trim().toLowerCase();
  if (contentType !== "application/json") {
    return json({ error: "UNSUPPORTED_MEDIA_TYPE", requestId, commitAllowed: false }, 415, requestId);
  }

  let claimedTenantId: string | null = null;
  let claimedIdempotencyHash: string | null = null;
  let idempotencyClaimed = false;

  try {
    const rawBody = await request.text();
    if (new TextEncoder().encode(rawBody).byteLength > 32 * 1024) {
      return json({ error: "PAYLOAD_TOO_LARGE", requestId, commitAllowed: false }, 413, requestId);
    }

    let raw: unknown;
    try {
      raw = JSON.parse(rawBody);
    } catch {
      return json({ error: "INVALID_JSON", requestId, commitAllowed: false }, 400, requestId);
    }
    const body = bodySchema.parse(raw);
    claimedTenantId = body.tenantId;

    const auth = await authenticateRotatedTenantKey({
      tenantId: body.tenantId,
      apiKey,
      keyId: request.headers.get("x-gainiren-key-id")?.trim() || null,
    });
    if (!auth.authorized) return json({ error: "UNAUTHORIZED", requestId, commitAllowed: false }, 401, requestId);

    const signature = await verifyAndConsumeRequestSignature({
      request, rawBody, apiKey, tenantId: body.tenantId,
    });
    if (!signature.valid) {
      securityLog("transaction_signature_rejected", {
        requestId, tenantId: body.tenantId, reasonCode: signature.reasonCode,
      });
      return json({ error: "INVALID_REQUEST_SIGNATURE", requestId, commitAllowed: false }, 401, requestId);
    }

    const limits = await Promise.all([
      checkRateLimit({
        tenantId: body.tenantId, key: `transaction-api:${hashValue(apiKey)}`,
        bucket: "transaction-preflight-api", limit: 30, windowSeconds: 60,
      }),
      checkRateLimit({
        tenantId: body.tenantId, key: `transaction-subject:${body.subjectId}`,
        bucket: "transaction-preflight-subject", limit: 10, windowSeconds: 60,
        subjectId: body.subjectId,
      }),
    ]);
    const blockedLimit = limits.find((item) => !item.allowed);
    if (blockedLimit) {
      return json({
        error: "RATE_LIMITED",
        retryAfter: Math.max(1, Math.ceil((Date.parse(blockedLimit.resetAt) - Date.now()) / 1000)),
        requestId,
        commitAllowed: false,
      }, 429, requestId);
    }

    const idempotencyKey = request.headers.get("idempotency-key") ?? "";
    if (!/^[A-Za-z0-9._:-]{16,128}$/.test(idempotencyKey)) {
      return json({ error: "INVALID_IDEMPOTENCY_KEY", requestId, commitAllowed: false }, 400, requestId);
    }
    claimedIdempotencyHash = hashValue(idempotencyKey);
    const claim = await supabase.schema("security").rpc("consume_request_idempotency", {
      p_tenant_id: body.tenantId,
      p_idempotency_key_hash: claimedIdempotencyHash,
      p_request_hash: requestDigest(request, rawBody),
      p_ttl_seconds: 86400,
    });
    if (claim.error) throw claim.error;
    if (!claim.data?.accepted) {
      return json({
        error: claim.data?.reason === "DUPLICATE_REQUEST" ? "DUPLICATE_REQUEST" : "IDEMPOTENCY_KEY_REUSE",
        requestId, commitAllowed: false,
      }, 409, requestId);
    }
    idempotencyClaimed = true;

    const controlResponse = await supabase.schema("security").rpc("get_security_control", {
      p_tenant_id: body.tenantId,
    });
    if (controlResponse.error) throw controlResponse.error;
    const currentRow = Array.isArray(controlResponse.data) ? controlResponse.data[0] : undefined;
    const current = currentRow ? controlSchema.parse(currentRow) : undefined;
    const controlExpired = Boolean(current?.expires_at && Date.parse(current.expires_at) <= Date.now());
    const controlMode = controlExpired ? "normal" : (current?.mode ?? "normal");
    const controlReason = safeReason(current?.reason_code, "EMERGENCY_CONTROL");

    if (controlMode === "deny_all" || controlMode === "maintenance") {
      try {
        await recordEmergencySecurityControl({
          tenantId: body.tenantId, mode: controlMode, reasonCode: controlReason, requestId,
        });
      } catch {
        // The emergency deny is still enforced when the audit store is unavailable.
      }
      await finalizeIdempotency(body.tenantId, claimedIdempotencyHash, "completed", 423);
      idempotencyClaimed = false;
      return json({
        decision: "BLOCK", score: 100, riskLevel: "critical", outcome: "BLOCK",
        commitAllowed: false, adaptiveControl: "tenant_lockdown",
        reasonCodes: ["SECURITY_CONTROL_BLOCK", controlMode, controlReason], requestId,
      }, 423, requestId);
    }

    const runtimeResponse = await supabase.schema("security").rpc("get_runtime_control", {
      p_tenant_id: body.tenantId,
    });
    if (runtimeResponse.error) throw runtimeResponse.error;
    const runtimeValue = runtimeSchema.parse(runtimeResponse.data ?? {
      mode: "normal", reasonCode: "NORMAL", version: 0, expiresAt: null,
    });
    const runtimeExpired = Boolean(runtimeValue.expiresAt && Date.parse(runtimeValue.expiresAt) <= Date.now());
    const runtimeMode = runtimeExpired ? "normal" : runtimeValue.mode;
    if (runtimeMode === "lockdown") {
      try {
        await recordEmergencySecurityControl({
          tenantId: body.tenantId,
          mode: "lockdown",
          reasonCode: safeReason(runtimeValue.reasonCode, "RUNTIME_LOCKDOWN"),
          requestId,
        });
      } catch {
        // Lockdown still wins if the audit store is unavailable.
      }
      await finalizeIdempotency(body.tenantId, claimedIdempotencyHash, "completed", 423);
      idempotencyClaimed = false;
      return json({
        decision: "BLOCK", score: 100, riskLevel: "critical", outcome: "BLOCK",
        commitAllowed: false, adaptiveControl: "tenant_lockdown",
        reasonCodes: ["RUNTIME_LOCKDOWN", runtimeValue.reasonCode], requestId,
      }, 423, requestId);
    }

    const subjectControlResponse = await supabase.schema("security").from("transaction_subject_controls")
      .select("mode,reason_code,expires_at")
      .eq("tenant_id", body.tenantId)
      .eq("subject_id", body.subjectId)
      .eq("scope", "wallet_transactions")
      .maybeSingle();
    if (subjectControlResponse.error) throw subjectControlResponse.error;
    const controlRow = subjectControlResponse.data
      ? subjectControlRowSchema.parse(subjectControlResponse.data)
      : null;
    const activeSubjectControl: SubjectTransactionControl | null = controlRow && Date.parse(controlRow.expires_at) > Date.now()
      ? { mode: controlRow.mode, reasonCode: controlRow.reason_code, expiresAt: controlRow.expires_at }
      : null;

    const historySince = new Date(Date.now() - 5 * 60_000).toISOString();
    const history = await supabase.schema("security").from("transaction_risk_events")
      .select("created_at,operation,risk_score,decision,sensitive")
      .eq("tenant_id", body.tenantId)
      .eq("subject_id", body.subjectId)
      .gte("created_at", historySince)
      .order("created_at", { ascending: false })
      .limit(100);
    if (history.error) throw history.error;
    const nowMs = Date.now();
    const recentOperations1m = (history.data ?? []).filter((event) => {
      const ts = Date.parse(event.created_at);
      return Number.isFinite(ts) && ts <= nowMs && ts >= nowMs - 60_000;
    }).length;
    const recentOperations5m = (history.data ?? []).filter((event) => {
      const ts = Date.parse(event.created_at);
      return Number.isFinite(ts) && ts <= nowMs && ts >= nowMs - 5 * 60_000;
    }).length;

    const checked = await guardedSecurityCheck({
      tenantId: body.tenantId,
      subjectId: body.subjectId,
      sessionId: body.sessionId,
      requestId,
    });
    let baseDecision = checked.decision;
    let baseScore = checked.score;
    let controlReasons: string[] = [];

    if (controlMode === "challenge_all" && rank[baseDecision] < rank.CHALLENGE) {
      baseDecision = "CHALLENGE";
      baseScore = Math.max(baseScore, scoreFloor.CHALLENGE);
      controlReasons = ["TENANT_CHALLENGE_ALL", controlReason];
    } else if (controlMode === "challenge_all") {
      controlReasons = ["TENANT_CHALLENGE_ALL", controlReason];
    }
    if (runtimeMode === "review_only" && rank[baseDecision] < rank.REVIEW) {
      baseDecision = "REVIEW";
      baseScore = Math.max(baseScore, scoreFloor.REVIEW);
      controlReasons = [...controlReasons, "RUNTIME_REVIEW_ONLY", runtimeValue.reasonCode];
    }

    const subjectLock = applySubjectTransactionControl({
      decision: baseDecision,
      score: baseScore,
      control: activeSubjectControl,
    });
    baseDecision = subjectLock.decision;
    baseScore = subjectLock.score;
    controlReasons = [...controlReasons, ...subjectLock.reasonCodes];

    const tx = evaluateTransactionFirewall({
      operation: body.operation,
      baseDecision,
      baseScore,
      attackPathScore: checked.attackPath?.score ?? 0,
      attackPathConfidence: checked.attackPath?.confidence ?? 0,
      ...(body.previousValue !== undefined ? { previousValue: body.previousValue } : {}),
      ...(body.currentValue !== undefined ? { currentValue: body.currentValue } : {}),
      ...(body.amount !== undefined ? { amount: body.amount } : {}),
      ...(body.currency ? { currency: body.currency } : {}),
      recentOperations1m,
      recentOperations5m,
    });

    const decision = enforcedDecision(baseDecision, tx.decision);
    const finalScore = Math.max(baseScore, tx.score, scoreFloor[decision]);
    const proposed: SecurityCheckResult = {
      ...checked,
      decision,
      score: finalScore,
      riskLevel: riskLevelFor(finalScore),
      ...(decision === "CHALLENGE" ? {
        challengeRecommendation: checked.challengeRecommendation ?? {
          type: "risk_based_verification" as const,
          reasonCodes: [...tx.reasonCodes, ...controlReasons].slice(0, 32),
          expiresInSeconds: 300,
        },
      } : { challengeRecommendation: null }),
    };
    if (!proposed.assessmentId) throw new Error("SECURITY_ASSESSMENT_ID_MISSING");

    const reasonCodes = [...new Set([...tx.reasonCodes, ...controlReasons])]
      .map((code) => code.toUpperCase().replace(/[^A-Z0-9_.:-]/g, "_").slice(0, 100))
      .filter((code) => /^[A-Z0-9_.:-]{1,100}$/.test(code))
      .slice(0, 128);

    const reconciled = await reconcilePersistedDecision({
      tenantId: body.tenantId,
      result: proposed,
      enforcementSource: "transaction_firewall",
      reasonCodes,
      requestId,
    });
    if (rank[reconciled.decision] < rank[proposed.decision] || reconciled.score < proposed.score) {
      securityLog("transaction_decision_downgrade_rejected", {
        requestId, tenantId: body.tenantId,
        proposedDecision: proposed.decision, finalDecision: reconciled.decision,
      });
      throw new Error("TRANSACTION_DECISION_DOWNGRADE");
    }

    const transactionRefHash = hashValue(body.transactionRef);
    const commitAllowed = reconciled.decision === "ALLOW" || reconciled.decision === "MONITOR";
    const outcome = reconciled.decision === "BLOCK" ? "BLOCK" :
      reconciled.decision === "REVIEW" ? "HOLD" :
        reconciled.decision === "CHALLENGE" ? "CHALLENGE" :
          reconciled.decision === "MONITOR" ? "ALLOW_MONITORED" : "ALLOW";
    const adaptiveControl = reconciled.decision === "BLOCK" ? "restrict_subject_transactions" :
      reconciled.decision === "REVIEW" ? "hold_transaction" :
        reconciled.decision === "CHALLENGE" ? "step_up_verification" : "none";

    const nextSubjectControl = deriveSubjectTransactionControl({
      decision: reconciled.decision,
      activeControl: activeSubjectControl,
    });
    if (nextSubjectControl) {
      const persistedControl = await supabase.schema("security").from("transaction_subject_controls").upsert({
        tenant_id: body.tenantId,
        subject_id: body.subjectId,
        scope: "wallet_transactions",
        mode: nextSubjectControl.mode,
        reason_code: nextSubjectControl.reasonCode,
        source_assessment_id: reconciled.assessmentId,
        expires_at: nextSubjectControl.expiresAt,
        updated_at: new Date().toISOString(),
      }, { onConflict: "tenant_id,subject_id,scope" });
      if (persistedControl.error) throw persistedControl.error;
    }

    await recordTransactionRisk({
      tenantId: body.tenantId,
      subjectId: body.subjectId,
      sessionId: body.sessionId,
      assessmentId: reconciled.assessmentId,
      transactionRefHash,
      operation: body.operation,
      previousValue: body.previousValue,
      currentValue: body.currentValue,
      amount: body.amount,
      currency: body.currency,
      score: reconciled.score,
      decision: reconciled.decision,
      context: {
        transactionScore: tx.score,
        transactionConfidence: tx.confidence,
        attackPathScore: checked.attackPath?.score ?? 0,
        attackPathConfidence: checked.attackPath?.confidence ?? 0,
        valueJumpScore: tx.valueJumpScore,
        velocityScore: tx.velocityScore,
        recentOperations1m,
        recentOperations5m,
        independentStrongCueCount: tx.independentStrongCueCount,
        reasonCodes,
        adaptiveControl,
        controlMode,
        runtimeMode,
        subjectControlMode: nextSubjectControl?.mode ?? activeSubjectControl?.mode ?? null,
        subjectControlExpiresAt: nextSubjectControl?.expiresAt ?? activeSubjectControl?.expiresAt ?? null,
        engineVersion: tx.version,
      },
    });
    await appendTransactionLedger({
      tenantId: body.tenantId,
      requestId,
      transactionRefHash,
      operation: body.operation,
      assessmentId: reconciled.assessmentId,
      decision: reconciled.decision,
      score: reconciled.score,
      commitAllowed,
      adaptiveControl,
      reasonCodes,
    });

    await finalizeIdempotency(body.tenantId, claimedIdempotencyHash, "completed", 200);
    idempotencyClaimed = false;
    securityLog("transaction_preflight_decided", {
      requestId, tenantId: body.tenantId, subjectId: body.subjectId,
      decision: reconciled.decision, score: reconciled.score,
      operation: body.operation, commitAllowed,
    });
    return json({
      assessmentId: reconciled.assessmentId,
      decision: reconciled.decision,
      score: reconciled.score,
      riskLevel: reconciled.riskLevel,
      outcome,
      commitAllowed,
      challengeRequired: reconciled.decision === "CHALLENGE",
      reviewRequired: reconciled.decision === "REVIEW",
      adaptiveControl,
      reasonCodes,
      transactionRisk: {
        score: tx.score,
        confidence: tx.confidence,
        attackPathScore: checked.attackPath?.score ?? 0,
        valueJumpScore: tx.valueJumpScore,
        velocityScore: tx.velocityScore,
        version: tx.version,
      },
      requestId,
    }, 200, requestId);
  } catch (error) {
    if (idempotencyClaimed && claimedTenantId && claimedIdempotencyHash) {
      try {
        await finalizeIdempotency(claimedTenantId, claimedIdempotencyHash, "failed", 503);
      } catch {
        // Always preserve the fail-closed response if idempotency storage is unhealthy.
      }
    }
    if (error instanceof z.ZodError) {
      return json({ error: "INVALID_REQUEST", requestId, commitAllowed: false }, 400, requestId);
    }
    if (error instanceof Error && [
      "TENANT_NOT_FOUND", "TENANT_NOT_ACTIVE", "SUBJECT_NOT_FOUND",
      "SESSION_NOT_FOUND", "SESSION_SUBJECT_MISMATCH", "SESSION_NOT_ACTIVE",
    ].includes(error.message)) {
      return json({ error: "INVALID_SECURITY_CONTEXT", requestId, commitAllowed: false }, 400, requestId);
    }
    securityLog("transaction_preflight_failed_closed", {
      requestId,
      tenantId: claimedTenantId,
      errorCode: safeErrorCode(error),
      ...(safeErrorStatus(error) ? { errorStatus: safeErrorStatus(error) } : {}),
    });
    return json({ error: "SECURITY_CHECK_UNAVAILABLE", requestId, commitAllowed: false }, 503, requestId);
  }
}
