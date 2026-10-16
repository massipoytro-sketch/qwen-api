import { supabase } from "../db/supabase";
import type { SecurityCheckResult, SecurityDecision } from "./types";
import { evaluateControlPlane, type ControlPolicy, type SecurityState } from "./controlPlane";

const rank: Record<SecurityDecision, number> = { ALLOW: 0, MONITOR: 1, CHALLENGE: 2, REVIEW: 3, BLOCK: 4 };
const strongest = (a: SecurityDecision, b: SecurityDecision) => rank[b] > rank[a] ? b : a;

export async function applyControlPlane(input: { tenantId: string; subjectId?: string; sessionId?: string; operation?: string; endpoint?: string; result: SecurityCheckResult }) {
  if (!input.subjectId || !input.result.assessmentId) return { result: input.result, controlPlane: null };
  const [signalsResult, contextResult] = await Promise.all([
    supabase.schema("security").from("risk_signals").select("signal_name,source,score,confidence,evidence").eq("assessment_id", input.result.assessmentId).limit(256),
    supabase.schema("security").rpc("get_control_plane_context", { p_tenant_id: input.tenantId, p_subject_id: input.subjectId }),
  ]);
  if (signalsResult.error) throw signalsResult.error;
  if (contextResult.error) throw contextResult.error;
  const context = contextResult.data ?? {};
  const storedState = String((context as any).state?.state ?? "TRUSTED") as SecurityState;
  const modeValue = String((context as any).mode?.mode ?? "NORMAL");
  const emergencyMode = ["NORMAL", "MAINTENANCE", "LOCKDOWN", "DENY_ALL"].includes(modeValue) ? modeValue as "NORMAL" | "MAINTENANCE" | "LOCKDOWN" | "DENY_ALL" : "NORMAL";
  const policies: ControlPolicy[] = Array.isArray((context as any).policies) ? (context as any).policies.map((policy: any) => ({ id: String(policy.id), priority: Number(policy.priority ?? 100), enabled: policy.enabled !== false, action: policy.action, condition: policy.condition ?? {}, reasonCode: String(policy.reasonCode ?? "POLICY_MATCH"), expiresAt: policy.expiresAt ?? null })) : [];
  const signals = (signalsResult.data ?? []).map((signal) => ({ signalName: signal.signal_name, source: signal.source ?? undefined, score: Number(signal.score ?? 0), confidence: signal.confidence === null || signal.confidence === undefined ? null : Number(signal.confidence), evidence: signal.evidence && typeof signal.evidence === "object" && !Array.isArray(signal.evidence) ? signal.evidence as Record<string, unknown> : {} }));
  const valueSignal = signals.find((signal) => signal.signalName === "value_jump_anomaly");
  const evidence = valueSignal?.evidence ?? {};
  const valueJump = (evidence as any).valueJumpIntelligence ?? evidence;
  const before = Number((valueJump as any)?.previousValue ?? (valueJump as any)?.before ?? NaN);
  const after = Number((valueJump as any)?.currentValue ?? (valueJump as any)?.after ?? NaN);
  const controlPlane = evaluateControlPlane({ tenantId: input.tenantId, subjectId: input.subjectId, sessionId: input.sessionId, operation: input.operation ?? "security-check", endpoint: input.endpoint ?? "/api/security-check", decision: input.result.decision, score: input.result.score, signals, previousState: storedState, emergencyMode, transaction: Number.isFinite(before) && Number.isFinite(after) ? { before, after, sensitive: true } : undefined }, policies);
  const finalDecision = strongest(input.result.decision, controlPlane.decision);
  const finalScore = Math.max(input.result.score, finalDecision === "BLOCK" ? 90 : finalDecision === "REVIEW" ? 70 : finalDecision === "CHALLENGE" ? 40 : finalDecision === "MONITOR" ? 1 : 0);
  const finalRiskLevel = finalScore >= 90 ? "critical" : finalScore >= 70 ? "high" : finalScore >= 40 ? "medium" : finalScore > 0 ? "low" : "unknown";
  const persisted = await supabase.schema("security").rpc("record_control_plane_result", { p_tenant_id: input.tenantId, p_subject_id: input.subjectId, p_assessment_id: input.result.assessmentId, p_state: controlPlane.state, p_decision: finalDecision, p_score: finalScore, p_reason_codes: controlPlane.reasonCodes, p_device_hash: null, p_transaction: controlPlane.transactionRisk > 0 ? { operation: input.operation ?? "security-check", riskScore: controlPlane.transactionRisk, sensitive: true, before: Number.isFinite(before) ? before : null, after: Number.isFinite(after) ? after : null, context: { version: controlPlane.version } } : null, p_incident: controlPlane.incident });
  if (persisted.error) throw new Error("SECURITY_CONTROL_PLANE_PERSIST_FAILED");
  const ledger = await supabase.schema("security").rpc("append_security_ledger_entry", { p_tenant_id: input.tenantId, p_action: "control_plane_enforced", p_resource_type: "risk_assessment", p_resource_id: input.result.assessmentId, p_request_id: null, p_actor_type: "system", p_details: { baseDecision: input.result.decision, finalDecision, baseScore: input.result.score, finalScore, state: controlPlane.state, quarantined: controlPlane.quarantined, reasonCodes: controlPlane.reasonCodes, policyMatches: controlPlane.policyMatches, version: controlPlane.version } });
  if (ledger.error) throw new Error("SECURITY_CONTROL_PLANE_LEDGER_FAILED");
  return { result: { ...input.result, decision: finalDecision, score: finalScore, riskLevel: finalRiskLevel, challengeRecommendation: finalDecision === "CHALLENGE" ? input.result.challengeRecommendation ?? { type: "risk_based_verification" as const, reasonCodes: controlPlane.reasonCodes.slice(0, 32), expiresInSeconds: 300 } : null }, controlPlane };
}
