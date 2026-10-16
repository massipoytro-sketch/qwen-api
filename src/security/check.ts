import { z } from "zod";
import { supabase } from "../db/supabase";
import { env } from "../config/env";
import { scoreSubjectConnections } from "./graph";
import { analyzeWithAI, buildAIAdvisoryEvidence } from "./ai";
import { safeErrorCode, safeErrorStatus, securityLog } from "./observability";
import { analyzeVelocity } from "./velocity";
import { analyzeBotDefense } from "./botDefense";
import { analyzeFraudGraph, analyzeValueJump, enforceFraudFloor } from "./fraud-intelligence";
import { analyzeAccountTakeoverSignals, analyzeConcurrentSessionAnomalies } from "./detectors";
import { analyzeAdvancedBotSignals, evaluateTenantPolicies, getBehaviorBaselineScore, ensureInvestigationCase, enqueueSecurityEvent, upsertFraudCluster } from "./platform";
import { evaluateDefenseInDepth, scoreFloorForDecision } from "./firewall";
import { evaluateControlPlane, type ControlPolicy, type SecurityState } from "./controlPlane";
import type { SecurityCheckInput, SecurityCheckResult, SecurityDecision } from "./types";
import { aggregateSecurityRisk as aggregateRisk } from "./risk";

const inputSchema = z.object({
  tenantId: z.uuid(), subjectId: z.uuid().optional(), sessionId: z.uuid().optional(), requestId: z.string().min(1).max(200).optional(),
});
type RiskLevel = SecurityCheckResult["riskLevel"];
const riskLevelFor = (score: number): RiskLevel => score >= 90 ? "critical" : score >= 70 ? "high" : score >= 40 ? "medium" : score > 0 ? "low" : "unknown";
const decisionFor = (score: number): SecurityDecision => score >= 90 ? "BLOCK" : score >= 70 ? "REVIEW" : score >= 40 ? "CHALLENGE" : score > 0 ? "MONITOR" : "ALLOW";
const clamp = (value: number) => Math.max(0, Math.min(100, value));
type Signal = { signalName: string; source: string; score: number; confidence: number | null; evidence: Record<string, unknown> };


export async function securityCheck(rawInput: SecurityCheckInput): Promise<SecurityCheckResult> {
  const input = inputSchema.parse(rawInput);
  const [tenantResult, subjectResult, sessionResult] = await Promise.all([
    supabase.schema("security").from("tenants").select("id,status").eq("id", input.tenantId).maybeSingle(),
    input.subjectId ? supabase.schema("security").from("subjects").select("id,status,risk_level").eq("tenant_id", input.tenantId).eq("id", input.subjectId).maybeSingle() : Promise.resolve({ data: null, error: null }),
    input.sessionId ? supabase.schema("security").from("sessions").select("id,subject_id,device_id,ip_id,ended_at").eq("tenant_id", input.tenantId).eq("id", input.sessionId).maybeSingle() : Promise.resolve({ data: null, error: null }),
  ]);
  if (tenantResult.error) throw tenantResult.error;
  if (!tenantResult.data) throw new Error("TENANT_NOT_FOUND");
  if (tenantResult.data.status !== "active") throw new Error("TENANT_NOT_ACTIVE");
  if (input.subjectId && subjectResult.error) throw subjectResult.error;
  if (input.subjectId && !subjectResult.data) throw new Error("SUBJECT_NOT_FOUND");
  if (input.sessionId && sessionResult.error) throw sessionResult.error;
  if (input.sessionId && !sessionResult.data) throw new Error("SESSION_NOT_FOUND");
  if (input.sessionId && input.subjectId && sessionResult.data.subject_id !== input.subjectId) throw new Error("SESSION_SUBJECT_MISMATCH");
  if (input.sessionId && sessionResult.data.ended_at) throw new Error("SESSION_NOT_ACTIVE");

  const now = new Date();
  const windowStart = new Date(now.getTime() - 24 * 60 * 60 * 1000).toISOString();
  const [eventResult, subjectEventsResult, sessionAnomalyResult] = await Promise.all([
    supabase.schema("security").from("security_events").select("id,event_type,severity,source,occurred_at,subject_id,session_id,ip_id,device_id,payload").eq("tenant_id", input.tenantId).eq("subject_id", input.subjectId ?? "00000000-0000-0000-0000-000000000000").gte("occurred_at", windowStart).order("occurred_at", { ascending: false }).limit(200),
    supabase.schema("security").from("security_events").select("id,event_type,severity,source,occurred_at,subject_id,session_id,ip_id,device_id,payload").eq("tenant_id", input.tenantId).eq("subject_id", input.subjectId ?? "00000000-0000-0000-0000-000000000000").gte("occurred_at", windowStart).order("occurred_at", { ascending: false }).limit(200),
    input.subjectId ? supabase.schema("security").from("sessions").select("id,subject_id,device_id,ip_id,created_at,last_seen_at,ended_at").eq("tenant_id", input.tenantId).eq("subject_id", input.subjectId).gte("last_seen_at", windowStart).limit(100) : Promise.resolve({ data: [], error: null }),
  ]);
  if (eventResult.error) throw eventResult.error;
  if (subjectEventsResult.error) throw subjectEventsResult.error;
  if (sessionAnomalyResult.error) throw sessionAnomalyResult.error;

  const sourceEvents = subjectEventsResult.data ?? [];
  const detectorEvents = sourceEvents.map((event) => ({
    eventType: event.event_type,
    occurredAt: event.occurred_at,
    severity: event.severity,
    source: event.source,
    payload: event.payload && typeof event.payload === "object" ? event.payload as Record<string, unknown> : {},
  }));
  const takeover = input.subjectId ? analyzeAccountTakeoverSignals(detectorEvents, now) : null;
  const sessions = (sessionAnomalyResult.data ?? []).map((session) => ({
    id: session.id,
    subjectId: session.subject_id,
    deviceId: session.device_id,
    ipId: session.ip_id,
    createdAt: session.created_at,
    lastSeenAt: session.last_seen_at,
    endedAt: session.ended_at,
  }));
  const concurrent = input.subjectId ? analyzeConcurrentSessionAnomalies(sessions, now) : null;

  const signals: Signal[] = [];
  if (takeover) signals.push({ signalName: "account_takeover_detection", source: "account_security", score: takeover.score, confidence: takeover.confidence, evidence: { reasonCodes: takeover.reasonCodes, version: takeover.version } });
  if (concurrent) signals.push({ signalName: "concurrent_session_anomaly", source: "session_integrity", score: concurrent.score, confidence: concurrent.confidence, evidence: { reasonCodes: concurrent.reasonCodes, version: concurrent.version } });

  const networkSignals = sourceEvents.filter((event) => ["network_risk", "impossible_travel_detection", "ip_reputation_risk", "asn_reputation_risk"].includes(event.event_type));
  for (const event of networkSignals.slice(0, 16)) signals.push({ signalName: event.event_type, source: "network_intelligence", score: clamp(Number((event.payload as Record<string, unknown>)?.score ?? 0)), confidence: Number.isFinite(Number((event.payload as Record<string, unknown>)?.confidence)) ? clamp(Number((event.payload as Record<string, unknown>)?.confidence)) / 100 : 0.5, evidence: { trustedReputation: (event.payload as Record<string, unknown>)?.trustedReputation, locationSource: (event.payload as Record<string, unknown>)?.locationSource } });

  const baseScoreResult = await aggregateRisk(input.tenantId, input.subjectId, input.sessionId);
  if (baseScoreResult.error) throw baseScoreResult.error;
  const prePolicyScore = clamp(Number(baseScoreResult.score ?? 0));
  const riskDecision = decisionFor(prePolicyScore);

  const policyResult = await evaluateTenantPolicies({ tenantId: input.tenantId, score: prePolicyScore, signals });
  const firewallResult = evaluateDefenseInDepth({ score: prePolicyScore, subjectStatus: (subjectResult.data?.status ?? "unknown") as "active" | "suspended" | "blocked" | "deleted" | "unknown", signals });
  const firewallSignals: Signal[] = firewallResult.layers.filter((item) => item.action !== "ALLOW").map((item) => ({ signalName: `firewall_${item.layer}`, source: "firewall", score: item.score, confidence: item.confidence, evidence: { action: item.action, reasonCodes: item.reasonCodes, version: firewallResult.version } }));
  const finalSignals = [...signals, ...firewallSignals];

  let controlContext: any = { state: { state: "TRUSTED", stateVersion: 0, reasonCodes: [], lastDecision: "ALLOW", lastScore: 0 }, policies: [], mode: { mode: "NORMAL", scope: "tenant" } };
  if (input.subjectId) {
    const contextResult = await supabase.schema("security").rpc("get_control_plane_context", { p_tenant_id: input.tenantId, p_subject_id: input.subjectId });
    if (contextResult.error) throw contextResult.error;
    controlContext = contextResult.data ?? controlContext;
  }

  const cpPolicies: ControlPolicy[] = Array.isArray(controlContext.policies) ? controlContext.policies.map((p: any) => ({
    id: String(p.id), priority: Number(p.priority ?? 100), enabled: p.enabled !== false, action: p.action, condition: p.condition ?? {}, reasonCode: String(p.reasonCode ?? "POLICY_MATCH"), expiresAt: p.expiresAt ?? null,
  })) : [];
  const previousState = String(controlContext.state?.state ?? "TRUSTED") as SecurityState;
  const mode = ["NORMAL", "MAINTENANCE", "LOCKDOWN", "DENY_ALL"].includes(String(controlContext.mode?.mode)) ? String(controlContext.mode.mode) as "NORMAL" | "MAINTENANCE" | "LOCKDOWN" | "DENY_ALL" : "NORMAL";
  const valueSignal = signals.find((signal) => signal.signalName === "value_jump_anomaly");
  const valueEvidence = valueSignal?.evidence ?? {};
  const transactionBefore = Number(valueEvidence.before ?? NaN);
  const transactionAfter = Number(valueEvidence.after ?? NaN);
  const controlPlane = evaluateControlPlane({
    tenantId: input.tenantId,
    subjectId: input.subjectId,
    sessionId: input.sessionId,
    operation: "security-check",
    endpoint: "/api/security-check",
    decision: riskDecision,
    score: prePolicyScore,
    signals: finalSignals,
    previousState,
    emergencyMode: mode,
    transaction: Number.isFinite(transactionBefore) && Number.isFinite(transactionAfter) ? { before: transactionBefore, after: transactionAfter, sensitive: true } : undefined,
  }, cpPolicies);

  const policyDecisionFloor = policyResult.decisionOverride ? scoreFloorForDecision(policyResult.decisionOverride) : 0;
  const rank: Record<SecurityDecision, number> = { ALLOW: 0, MONITOR: 1, CHALLENGE: 2, REVIEW: 3, BLOCK: 4 };
  const requiredFloor = rank[fraudDecisionFloor] > rank[firewallResult.minimumDecision] ? fraudDecisionFloor : firewallResult.minimumDecision;
  const score = clamp(Math.max(prePolicyScore + policyResult.scoreDelta, scoreFloorForDecision(requiredFloor), policyDecisionFloor, scoreFloorForDecision(controlPlane.decision)));
  const scoreDecision = decisionFor(score);
  const decisionCandidates: SecurityDecision[] = [scoreDecision, firewallResult.minimumDecision, fraudDecisionFloor, controlPlane.decision];
  if (policyResult.decisionOverride) decisionCandidates.push(policyResult.decisionOverride);
  const decision = decisionCandidates.reduce((best, candidate) => rank[candidate] > rank[best] ? candidate : best, "ALLOW" as SecurityDecision);
  const riskLevel = riskLevelFor(score);
  const policyReasonCodes = policyResult.matched.map((policy) => policy.reasonCode);
  const challengeRecommendation = decision === "CHALLENGE" ? firewallResult.recommendedChallenge ?? { type: "risk_based_verification" as const, reasonCodes: [...controlPlane.reasonCodes, ...policyReasonCodes].slice(0, 32), expiresInSeconds: 300 } : null;
  const firewallAudit = { version: firewallResult.version, minimumDecision: firewallResult.minimumDecision, fraudDecisionFloor, reasonCodes: firewallResult.reasonCodes, layers: firewallResult.layers.map((item) => ({ layer: item.layer, action: item.action, score: item.score, confidence: item.confidence, reasonCodes: item.reasonCodes })) };
  securityLog("security_check", { requestId: input.requestId ?? null, tenantId: input.tenantId, subjectId: input.subjectId ?? null, score, decision, signalCount: finalSignals.length, policyMatches: policyResult.matched.length, firewallMinimumDecision: firewallResult.minimumDecision, firewallEscalations: firewallSignals.length, controlPlaneState: controlPlane.state, quarantined: controlPlane.quarantined });

  const assessmentInsert = await supabase.schema("security").from("risk_assessments").insert({ tenant_id: input.tenantId, subject_id: input.subjectId ?? null, session_id: input.sessionId ?? null, score, risk_level: riskLevel, assessment_version: "active-defense-v1", explanation: { requestId: input.requestId ?? null, signalCount: finalSignals.length, sources: finalSignals.map((signal) => signal.source), aggregation: "weighted_evidence_v2", policies: policyResult.matched.map((policy) => ({ id: policy.id, name: policy.name, reasonCode: policy.reasonCode })), policyCount: policyResult.policyCount, firewall: firewallAudit, controlPlane, challengeRecommendation } }).select("id").single();
  if (assessmentInsert.error) throw assessmentInsert.error;
  if (finalSignals.length > 0) {
    const signalInsert = await supabase.schema("security").from("risk_signals").insert(finalSignals.map((signal) => ({ assessment_id: assessmentInsert.data.id, signal_name: signal.signalName, source: signal.source, score: signal.score, confidence: signal.confidence, evidence: signal.evidence })));
    if (signalInsert.error) throw signalInsert.error;
  }
  const decisionInsert = await supabase.schema("security").from("risk_decisions").insert({ assessment_id: assessmentInsert.data.id, decision, reason_codes: [...finalSignals.map((signal) => signal.signalName), ...policyReasonCodes, ...firewallResult.reasonCodes, ...controlPlane.reasonCodes, ...(fraudDecisionFloor !== "ALLOW" ? ["FRAUD_INTELLIGENCE_ESCALATION"] : [])], decision_version: "active-defense-v1" }).select("id").single();
  if (decisionInsert.error) throw decisionInsert.error;
  if (input.requestId) {
    const auditInsert = await supabase.schema("security").from("audit_events").insert({ tenant_id: input.tenantId, actor_type: "system", action: "security_check", resource_type: "risk_assessment", resource_id: assessmentInsert.data.id, request_id: input.requestId, details: { decision, score, riskLevel, version: "active-defense-v1", policyMatches: policyResult.matched.map((policy) => policy.id), firewallMinimumDecision: firewallResult.minimumDecision, fraudDecisionFloor, firewallReasonCodes: firewallResult.reasonCodes, controlPlaneState: controlPlane.state, controlPlaneReasons: controlPlane.reasonCodes, quarantined: controlPlane.quarantined } });
    if (auditInsert.error) throw auditInsert.error;
  }
  const ledgerAppend = await supabase.schema("security").rpc("append_security_ledger_entry", { p_tenant_id: input.tenantId, p_action: "risk_assessment_decided", p_resource_type: "risk_assessment", p_resource_id: assessmentInsert.data.id, p_request_id: input.requestId ?? null, p_actor_type: "system", p_details: { subjectId: input.subjectId ?? null, sessionId: input.sessionId ?? null, decision, score, riskLevel, assessmentVersion: "active-defense-v1", firewallMinimumDecision: firewallResult.minimumDecision, firewallReasonCodes: firewallResult.reasonCodes, controlPlaneState: controlPlane.state, controlPlaneDecision: controlPlane.decision, controlPlaneReasonCodes: controlPlane.reasonCodes, quarantined: controlPlane.quarantined, signalNames: finalSignals.map((signal) => signal.signalName).slice(0, 128) } });
  if (ledgerAppend.error) { securityLog("security_ledger_append_failed", { requestId: input.requestId ?? null, tenantId: input.tenantId, errorCode: safeErrorCode(ledgerAppend.error), ...(safeErrorStatus(ledgerAppend.error) ? { errorStatus: safeErrorStatus(ledgerAppend.error) } : {}) }); throw new Error("SECURITY_LEDGER_APPEND_FAILED"); }
  const controlPersist = input.subjectId ? await supabase.schema("security").rpc("record_control_plane_result", { p_tenant_id: input.tenantId, p_subject_id: input.subjectId, p_assessment_id: assessmentInsert.data.id, p_state: controlPlane.state, p_decision: decision, p_score: score, p_reason_codes: controlPlane.reasonCodes, p_device_hash: null, p_transaction: controlPlane.transactionRisk > 0 ? { operation: "security-check", riskScore: controlPlane.transactionRisk, sensitive: true, before: Number.isFinite(transactionBefore) ? transactionBefore : null, after: Number.isFinite(transactionAfter) ? transactionAfter : null, context: { version: controlPlane.version } } : null, p_incident: controlPlane.incident }).catch((error) => ({ error } as any)) : null;
  if (controlPersist && "error" in controlPersist && controlPersist.error) throw new Error("SECURITY_CONTROL_PLANE_PERSIST_FAILED");
  const backgroundTasks: Promise<unknown>[] = [
    enqueueSecurityEvent({ tenantId: input.tenantId, eventType: "security.risk_assessment.created", aggregateId: assessmentInsert.data.id, dedupeKey: input.requestId ? `risk:${input.requestId}` : assessmentInsert.data.id, payload: { assessmentId: assessmentInsert.data.id, subjectId: input.subjectId ?? null, sessionId: input.sessionId ?? null, score, riskLevel, decision, signalNames: finalSignals.map((signal) => signal.signalName), firewallMinimumDecision: firewallResult.minimumDecision, fraudDecisionFloor, firewallReasonCodes: firewallResult.reasonCodes, controlPlaneState: controlPlane.state, controlPlaneDecision: controlPlane.decision, controlPlaneReasons: controlPlane.reasonCodes, quarantined: controlPlane.quarantined } }),
  ];
  if (input.subjectId && (score >= 70 || decision === "BLOCK" || decision === "REVIEW")) backgroundTasks.push(ensureInvestigationCase({ tenantId: input.tenantId, subjectId: input.subjectId, assessmentId: assessmentInsert.data.id, score, decision, evidence: { signalNames: finalSignals.map((signal) => signal.signalName), policyMatches: policyReasonCodes, firewall: firewallAudit, controlPlane } }));
  if (input.subjectId && graphScoreInfo && graphScoreInfo.relatedSubjects.length >= 2) backgroundTasks.push(upsertFraudCluster({ tenantId: input.tenantId, clusterType: "mixed", subjectIds: [input.subjectId, ...graphScoreInfo.relatedSubjects.map((subject) => subject.subjectId)], riskScore: graphScoreInfo.connectionScore, evidence: { relatedSubjectCount: graphScoreInfo.relatedSubjectCount, riskyConnectionCount: graphScoreInfo.riskyConnectionCount, version: "fraud-clusters-v1" } }));
  const analyticsEventRows: Array<{ subjectId?: string; sessionId?: string; eventType: string; occurredAt: string; valueDelta?: number; botScore?: number; behaviorScore?: number; valueEventId?: string }> = (velocityResult.data ?? []).map((event) => ({ subjectId: input.subjectId, sessionId: input.sessionId, eventType: event.event_type, occurredAt: event.occurred_at, ...(event.anomaly_score === null || event.anomaly_score === undefined ? {} : { behaviorScore: clamp(Number(event.anomaly_score)) }) }));
  for (const botEvent of botResult.data ?? []) analyticsEventRows.push({ subjectId: input.subjectId, sessionId: input.sessionId, eventType: "bot_detection", occurredAt: botEvent.observed_at, botScore: botEvent.is_bot ? clamp(Math.round(Number(botEvent.confidence ?? 0) * 100)) : 0 });
  if (valueAnomaly && input.subjectId) { const valueEvidence = valueAnomaly.evidence as Record<string, unknown>; const valueDelta = Number(valueEvidence.delta); if (Number.isFinite(valueDelta)) analyticsEventRows.push({ subjectId: input.subjectId, sessionId: input.sessionId, eventType: "value_change", occurredAt: valueAnomaly.occurred_at, valueDelta, valueEventId: valueAnomaly.source_event_id ?? undefined, behaviorScore: 0 }); }
  if (env.DUCKDB_ANALYTICS_URL && env.DUCKDB_ANALYTICS_TOKEN && analyticsEventRows.length > 0) { const minuteBucket = Math.floor(Date.now() / 60_000); const bucketKey = input.sessionId ?? input.subjectId ?? assessmentInsert.data.id; backgroundTasks.push(enqueueSecurityEvent({ tenantId: input.tenantId, eventType: "analytics.duckdb_batch", aggregateId: bucketKey, dedupeKey: `duckdb:${bucketKey}:${minuteBucket}`, payload: { tenantId: input.tenantId, events: analyticsEventRows.slice(-500) } })); }
  const settled = await Promise.allSettled(backgroundTasks);
  for (const item of settled) if (item.status === "rejected") securityLog("security_background_task_failed", { requestId: input.requestId ?? null, tenantId: input.tenantId, errorCode: item.reason instanceof Error ? item.reason.name : "UNKNOWN_ERROR" });
  return { decision, score, riskLevel, assessmentId: assessmentInsert.data.id, challengeRecommendation };
}