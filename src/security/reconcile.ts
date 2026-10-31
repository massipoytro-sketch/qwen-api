import { z } from "zod";
import { supabase } from "../db/supabase";
import type { SecurityCheckResult, SecurityDecision } from "./types";
import { safeErrorCode, safeErrorStatus, securityLog } from "./observability";
import { buildPart7DecisionInput } from "./part7-adapter";

const decisionSchema = z.enum(["ALLOW", "MONITOR", "CHALLENGE", "REVIEW", "BLOCK"]);
const riskLevelSchema = z.enum(["unknown", "low", "medium", "high", "critical"]);

const finalizationResultSchema = z.object({
  assessmentId: z.uuid(),
  decision: decisionSchema,
  score: z.number().finite().min(0).max(100),
  riskLevel: riskLevelSchema,
  reasonCodes: z.array(z.string().max(100)).max(256),
  finalizedAt: z.string().datetime(),
}).strict();

function rank(decision: SecurityDecision): number {
  return { ALLOW: 0, MONITOR: 1, CHALLENGE: 2, REVIEW: 3, BLOCK: 4 }[decision];
}

function actionToSecurityDecision(action: string): SecurityDecision {
  switch (action) {
    case "LOCKDOWN":
    case "BLOCK":
    case "DENY_TRANSACTION":
    case "PERMANENT_BAN":
      return "BLOCK";
    case "HOLD_REWARDS":
    case "HUMAN_REVIEW":
      return "REVIEW";
    case "TEMP_RESTRICTION":
    case "CHALLENGE":
      return "CHALLENGE";
    case "MONITOR":
      return "MONITOR";
    case "ALLOW":
      return "ALLOW";
    default:
      throw new Error("PART7_UNKNOWN_ACTION");
  }
}

/**
 * Atomically reconciles post-check controls with the central Part 7 policy
 * decision, stored decision and append-only ledger. Part 7 can only escalate
 * the authoritative Parts 1-6 result; it can never weaken a hard decision.
 */
export async function reconcilePersistedDecision(input: {
  tenantId: string;
  result: SecurityCheckResult & { networkControl?: { mode: string; reasonCode: string } };
  enforcementSource: string;
  reasonCodes?: string[];
  requestId?: string;
}) {
  const parsed = z.object({
    tenantId: z.uuid(),
    result: z.object({
      decision: decisionSchema,
      score: z.number().finite().min(0).max(100),
      riskLevel: riskLevelSchema,
      assessmentId: z.uuid(),
      challengeRecommendation: z.object({
        type: z.enum(["step_up_mfa", "proof_of_work", "risk_based_verification"]),
        reasonCodes: z.array(z.string().min(1).max(100)).max(64),
        expiresInSeconds: z.number().int().nonnegative().max(86400),
      }).nullable().optional(),
      networkControl: z.object({
        mode: z.string().min(1).max(40),
        reasonCode: z.string().min(1).max(100),
      }).optional(),
    }).strict(),
    enforcementSource: z.string().min(1).max(80).regex(/^[A-Za-z0-9_.:-]+$/),
    reasonCodes: z.array(z.string().min(1).max(100).regex(/^[A-Za-z0-9_.:-]+$/)).max(128).default([]),
    requestId: z.string().max(200).optional(),
  }).strict().parse(input);

  const { input: part7Input } = buildPart7DecisionInput({
    subjectRef: parsed.tenantId + ":" + (parsed.requestId ?? parsed.result.assessmentId),
    result: parsed.result,
  });
  const part7Action = (await import("./decision-engine")).recommendSecurityAction(part7Input);
  const part7Decision = actionToSecurityDecision(part7Action.action);
  const finalDecision = rank(part7Decision) >= rank(parsed.result.decision)
    ? part7Decision
    : parsed.result.decision;
  const finalScore = Math.max(parsed.result.score, part7Action.riskScore);
  const finalRiskLevel = finalScore >= 90 ? "critical" : finalScore >= 70 ? "high" : finalScore >= 40 ? "medium" : finalScore > 0 ? "low" : "unknown";
  const finalReasonCodes = [...new Set([
    ...parsed.reasonCodes,
    ...part7Action.reasonCodes,
    `PART7_ACTION_${part7Action.action}`,
    `PART7_RISK_${Math.round(part7Action.riskScore)}`,
  ])].slice(0, 128);

  if (rank(finalDecision) < rank(parsed.result.decision) || finalScore < parsed.result.score) {
    throw new Error("PART7_DECISION_DOWNGRADE_BLOCKED");
  }

  const response = await supabase.schema("security").rpc("finalize_security_decision", {
    p_tenant_id: parsed.tenantId,
    p_assessment_id: parsed.result.assessmentId,
    p_decision: finalDecision,
    p_score: finalScore,
    p_risk_level: finalRiskLevel,
    p_reason_codes: finalReasonCodes,
    p_enforcement_source: `part7:${parsed.enforcementSource}`,
    p_request_id: parsed.requestId ?? null,
  });
  if (response.error) throw response.error;
  const finalized = finalizationResultSchema.parse(response.data);
  if (rank(finalized.decision) < rank(finalDecision) || finalized.score < finalScore) {
    securityLog("part7_finalization_downgrade_rejected", {
      requestId: parsed.requestId ?? null,
      tenantId: parsed.tenantId,
      expectedDecision: finalDecision,
      actualDecision: finalized.decision,
      expectedScore: finalScore,
      actualScore: finalized.score,
    });
    throw new Error("PART7_FINALIZATION_DOWNGRADE");
  }
  return finalized;
}

/** Emergency controls may deny before creating a risk assessment; still ledger them. */
export async function recordEmergencySecurityControl(input: {
  tenantId: string;
  mode: "deny_all" | "maintenance" | "lockdown";
  reasonCode: string;
  requestId?: string;
}) {
  const parsed = z.object({
    tenantId: z.uuid(),
    mode: z.enum(["deny_all", "maintenance", "lockdown"]),
    reasonCode: z.string().min(1).max(80).regex(/^[A-Za-z0-9_.:-]+$/),
    requestId: z.string().max(200).optional(),
  }).strict().parse(input);

  const result = await supabase.schema("security").rpc("append_security_ledger_entry", {
    p_tenant_id: parsed.tenantId,
    p_action: "emergency_security_control_enforced",
    p_resource_type: "security_control",
    p_resource_id: parsed.tenantId,
    p_request_id: parsed.requestId ?? null,
    p_actor_type: "system",
    p_details: {
      mode: parsed.mode,
      reasonCode: parsed.reasonCode,
      enforcement: "deny",
    },
  });
  if (result.error) {
    securityLog("emergency_control_audit_failed", {
      tenantId: parsed.tenantId,
      requestId: parsed.requestId ?? null,
      mode: parsed.mode,
      errorCode: safeErrorCode(result.error),
      ...(safeErrorStatus(result.error) ? { errorStatus: safeErrorStatus(result.error) } : {}),
    });
    throw result.error;
  }
}
