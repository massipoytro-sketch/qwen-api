import { z } from "zod";
import { supabase } from "../db/supabase";
import type { SecurityCheckResult, SecurityDecision } from "./types";
import { safeErrorCode, safeErrorStatus, securityLog } from "./observability";

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

/**
 * Atomically reconciles post-check controls (tenant control plane, network
 * control, and runtime lockdown/review policies) with the assessment, stored
 * decision and append-only ledger. The database RPC only permits escalation.
 */
export async function reconcilePersistedDecision(input: {
  tenantId: string;
  result: SecurityCheckResult;
  enforcementSource: string;
  reasonCodes?: string[];
  requestId?: string;
}) {
  // Whitelist only the fields the atomic database reconciliation consumes.
  // SecurityCheckResult may also carry challenge/graph/network annotations; those
  // must not make a strict control-plane contract reject a valid assessment.
  const parsed = z.object({
    tenantId: z.uuid(),
    result: z.object({
      decision: decisionSchema,
      score: z.number().finite().min(0).max(100),
      riskLevel: riskLevelSchema,
      assessmentId: z.uuid(),
    }).strict(),
    enforcementSource: z.string().min(1).max(80).regex(/^[A-Za-z0-9_.:-]+$/),
    reasonCodes: z.array(z.string().min(1).max(100).regex(/^[A-Za-z0-9_.:-]+$/)).max(128).default([]),
    requestId: z.string().max(200).optional(),
  }).strict().parse({
    ...input,
    result: {
      decision: input.result.decision,
      score: input.result.score,
      riskLevel: input.result.riskLevel,
      assessmentId: input.result.assessmentId,
    },
  });

  const response = await supabase.schema("security").rpc("finalize_security_decision", {
    p_tenant_id: parsed.tenantId,
    p_assessment_id: parsed.result.assessmentId,
    p_decision: parsed.result.decision,
    p_score: parsed.result.score,
    p_risk_level: parsed.result.riskLevel,
    p_reason_codes: [...new Set(parsed.reasonCodes)].slice(0, 128),
    p_enforcement_source: parsed.enforcementSource,
    p_request_id: parsed.requestId ?? null,
  });
  if (response.error) throw response.error;
  return finalizationResultSchema.parse(response.data);
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
