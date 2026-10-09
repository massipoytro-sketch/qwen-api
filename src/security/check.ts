import { z } from "zod";
import { supabase } from "../db/supabase";
import { env } from "../config/env";
import { scoreSubjectConnections } from "./graph";
import { analyzeWithAI } from "./ai";
import { securityLog } from "./observability";
import { analyzeVelocity } from "./velocity";
import { analyzeAdvancedBotSignals, evaluateTenantPolicies, getBehaviorBaselineScore, ensureInvestigationCase, enqueueSecurityEvent, upsertFraudCluster } from "./platform";
import type { SecurityCheckInput, SecurityCheckResult, SecurityDecision } from "./types";

const inputSchema = z.object({
  tenantId: z.uuid(), subjectId: z.uuid().optional(), sessionId: z.uuid().optional(), requestId: z.string().min(1).max(200).optional(),
});
type RiskLevel = SecurityCheckResult["riskLevel"];
const riskLevelFor = (score: number): RiskLevel => score >= 90 ? "critical" : score >= 70 ? "high" : score >= 40 ? "medium" : score > 0 ? "low" : "unknown";
const decisionFor = (score: number): SecurityDecision => score >= 90 ? "BLOCK" : score >= 70 ? "REVIEW" : score >= 40 ? "CHALLENGE" : score > 0 ? "MONITOR" : "ALLOW";
const clamp = (value: number) => Math.max(0, Math.min(100, value));
type Signal = { signalName: string; source: string; score: number; confidence: number | null; evidence: Record<string, unknown> };
const aggregateRisk = (signals: Signal[]) => {
  if (!signals.length) return 0;
  const weighted = signals.reduce((total, signal) => total + signal.score * (signal.confidence ?? 0.5), 0);
  const sourceBonus = Math.min(15, Math.max(0, new Set(signals.map((s) => s.source)).size - 1) * 5);
  const highSignalBonus = signals.filter((s) => s.score >= 70).length >= 2 ? 10 : 0;
  return clamp(Math.round(Math.min(100, weighted * 0.55 + sourceBonus + highSignalBonus)));
};

export async function securityCheck(rawInput: SecurityCheckInput): Promise<SecurityCheckResult> {
  const input = inputSchema.parse(rawInput);
  const [tenantResult, subjectResult, sessionResult] = await Promise.all([
    supabase.schema("security").from("tenants").select("id,status").eq("id", input.tenantId).maybeSingle(),
    input.subjectId ? supabase.schema("security").from("subjects").select("id,status,risk_level").eq("tenant_id", input.tenantId).eq("id", input.subjectId).maybeSingle() : Promise.resolve({ data: null, error: null }),
    input.sessionId ? supabase.schema("security").from("sessions").select("id,subject_id,device_id,ip_id").eq("tenant_id", input.tenantId).eq("id", input.sessionId).maybeSingle() : Promise.resolve({ data: null, error: null }),
  ]);
  if (tenantResult.error) throw tenantResult.error;
  if (!tenantResult.data) throw new Error("TENANT_NOT_FOUND");
  if (tenantResult.data.status !== "active") throw new Error("TENANT_NOT_ACTIVE");
  if (subjectResult.error) throw subjectResult.error;
  if (sessionResult.error) throw sessionResult.error;
  if (input.subjectId && !subjectResult.data) throw new Error("SUBJECT_NOT_FOUND");
  if (input.sessionId && !sessionResult.data) throw new Error("SESSION_NOT_FOUND");

  const subjectRisk = subjectResult.data?.risk_level === "critical" ? 90 : subjectResult.data?.risk_level === "high" ? 70 : subjectResult.data?.risk_level === "medium" ? 40 : subjectResult.data?.risk_level === "low" ? 10 : 0;
  const deviceId = sessionResult.data?.device_id;
  const ipId = sessionResult.data?.ip_id;

  const [deviceResult, ipResult, botResult, behaviorResult, anomalyResult, velocityResult] = await Promise.all([
    deviceId ? supabase.schema("security").from("devices").select("id,risk_score,confidence").eq("tenant_id", input.tenantId).eq("id", deviceId).maybeSingle() : Promise.resolve({ data: null, error: null }),
    ipId ? supabase.schema("security").from("ip_addresses").select("id,reputation_score,is_proxy,is_vpn,is_tor,is_datacenter").eq("id", ipId).maybeSingle() : Promise.resolve({ data: null, error: null }),
    input.sessionId ? supabase.schema("security").from("bot_events").select("observed_at,is_bot,confidence,signals").eq("tenant_id", input.tenantId).eq("session_id", input.sessionId).gte("observed_at", new Date(Date.now() - 10 * 60_000).toISOString()).order("observed_at", { ascending: false }).limit(100) : Promise.resolve({ data: [], error: null }),
    input.sessionId ? supabase.schema("security").from("behavior_events").select("anomaly_score").eq("tenant_id", input.tenantId).eq("session_id", input.sessionId).gte("occurred_at", new Date(Date.now() - 15 * 60_000).toISOString()).order("occurred_at", { ascending: false }).limit(1).maybeSingle() : Promise.resolve({ data: null, error: null }),
    input.subjectId ? supabase.schema("security").from("activity_anomalies").select("id,anomaly_type,score,confidence,reason_codes,evidence,analyzer_version,occurred_at").eq("tenant_id", input.tenantId).eq("subject_id", input.subjectId).gte("occurred_at", new Date(Date.now() - 15 * 60_000).toISOString()).order("occurred_at", { ascending: false }).limit(1).maybeSingle() : Promise.resolve({ data: null, error: null }),
    input.sessionId ? supabase.schema("security").from("behavior_events").select("occurred_at,event_type,anomaly_score").eq("tenant_id", input.tenantId).eq("session_id", input.sessionId).gte("occurred_at", new Date(Date.now() - 15 * 60_000).toISOString()).order("occurred_at", { ascending: true }).limit(200) : Promise.resolve({ data: [], error: null }),
  ]);
  for (const result of [deviceResult, ipResult, botResult, behaviorResult, anomalyResult, velocityResult]) if (result.error) throw result.error;

  const signals: Signal[] = [];
  if (subjectRisk > 0) signals.push({ signalName: "subject_risk", source: "subject", score: subjectRisk, confidence: 1, evidence: { riskLevel: subjectResult.data?.risk_level } });
  const deviceRisk = clamp(Number(deviceResult.data?.risk_score ?? 0));
  if (deviceRisk > 0) signals.push({ signalName: "device_risk", source: "device", score: deviceRisk, confidence: Number(deviceResult.data?.confidence ?? 0) || null, evidence: { deviceId } });
  const ip = ipResult.data;
  if (ip) {
    const reputationPenalty = ip.reputation_score == null ? 0 : Math.max(0, 50 - Number(ip.reputation_score)) * 0.2;
    const networkPenalty = clamp((ip.is_tor ? 35 : 0) + (ip.is_proxy ? 20 : 0) + (ip.is_vpn ? 15 : 0) + (ip.is_datacenter ? 20 : 0) + reputationPenalty);
    if (networkPenalty > 0) signals.push({ signalName: "network_risk", source: "network", score: networkPenalty, confidence: 0.9, evidence: { isTor: ip.is_tor, isProxy: ip.is_proxy, isVpn: ip.is_vpn, isDatacenter: ip.is_datacenter, reputationScore: ip.reputation_score } });
  }
  const activityEvents = (velocityResult.data ?? []).map((event) => ({ occurredAt: event.occurred_at, eventType: event.event_type }));
  const velocity = analyzeVelocity(activityEvents);
  const advancedBot = analyzeAdvancedBotSignals({
    botEvents: (botResult.data ?? []).map((event) => ({
      occurredAt: event.observed_at, isBot: event.is_bot, confidence: Number(event.confidence ?? 0),
      signals: (event.signals ?? {}) as Record<string, unknown>,
    })),
    activityEvents,
  });
  if (advancedBot.score > 0) signals.push({ signalName: "advanced_bot_detection", source: "advanced_bot", score: advancedBot.score, confidence: advancedBot.confidence, evidence: { reasonCodes: advancedBot.reasonCodes, signalFlags: advancedBot.signalFlags, velocity: advancedBot.velocity, version: advancedBot.version } });
  if (velocity.score > 0) signals.push({ signalName: "activity_velocity", source: "velocity", score: velocity.score, confidence: velocity.confidence, evidence: velocity });
  const anomalyScore = clamp(Number(behaviorResult.data?.anomaly_score ?? 0));
  if (anomalyScore > 0) {
    signals.push({ signalName: "behavior_anomaly", source: "behavior", score: anomalyScore, confidence: 0.8, evidence: { anomalyScore } });
    if (input.subjectId) {
      try {
        const baseline = await getBehaviorBaselineScore({ tenantId: input.tenantId, subjectId: input.subjectId, currentValue: anomalyScore });
        if (baseline.score > 0) signals.push({ signalName: "behavior_baseline_deviation", source: "behavior_baseline", score: baseline.score, confidence: baseline.confidence, evidence: baseline });
      } catch (error) {
        securityLog("behavior_baseline_failed", { requestId: input.requestId ?? null, tenantId: input.tenantId, errorCode: error instanceof Error ? error.name : "UNKNOWN_ERROR" });
      }
    }
  }

  const valueAnomaly = anomalyResult.data;
  if (valueAnomaly && Number(valueAnomaly.score) > 0) signals.push({ signalName: "value_jump_anomaly", source: "activity_anomaly", score: clamp(Number(valueAnomaly.score)), confidence: Number(valueAnomaly.confidence ?? 0.75), evidence: { anomalyType: valueAnomaly.anomaly_type, reasonCodes: valueAnomaly.reason_codes, evidence: valueAnomaly.evidence, analyzerVersion: valueAnomaly.analyzer_version } });

  let graphScoreInfo: Awaited<ReturnType<typeof scoreSubjectConnections>> | null = null;
  if (input.subjectId) {
    graphScoreInfo = await scoreSubjectConnections({ tenantId: input.tenantId, subjectId: input.subjectId });
    if (graphScoreInfo.connectionScore > 0) signals.push({ signalName: "graph_connection_risk", source: "graph", score: graphScoreInfo.connectionScore, confidence: 0.8, evidence: { riskyConnectionCount: graphScoreInfo.riskyConnectionCount, relatedSubjectCount: graphScoreInfo.relatedSubjectCount } });
  }

  const deterministicScore = aggregateRisk(signals);
  if (env.AI_ANALYZER_ENDPOINT && env.AI_ANALYZER_API_KEY && env.AI_ANALYZER_MODEL) {
    try {
      const ai = await analyzeWithAI({ tenantId: input.tenantId, subjectId: input.subjectId, sessionId: input.sessionId, endpoint: env.AI_ANALYZER_ENDPOINT, apiKey: env.AI_ANALYZER_API_KEY, model: env.AI_ANALYZER_MODEL, evidence: { deterministicScore, signals } });
      signals.push({ signalName: "ai_advisory", source: "ai", score: ai.riskScore, confidence: Math.min(0.5, ai.confidence * 0.5), evidence: { riskLevel: ai.riskLevel, reasonCodes: ai.reasonCodes, recommendedAction: ai.recommendedAction, predictionId: ai.predictionId } });
    } catch (error) { securityLog("ai_advisory_failed", { requestId: input.requestId ?? null, tenantId: input.tenantId, error: error instanceof Error ? error.message : "UNKNOWN_ERROR" }); }
  }

  const prePolicyScore = aggregateRisk(signals);
  const prePolicyDecision = decisionFor(prePolicyScore);
  const latestValueSignal = signals.find((signal) => signal.signalName === "value_jump_anomaly");
  const policyResult = await evaluateTenantPolicies(input.tenantId, {
    score: prePolicyScore,
    riskLevel: riskLevelFor(prePolicyScore),
    decision: prePolicyDecision,
    signalNames: signals.map((signal) => signal.signalName),
    velocity,
    valueJumpScore: latestValueSignal?.score ?? 0,
    relatedSubjectCount: graphScoreInfo?.relatedSubjectCount ?? 0,
  });
  const score = clamp(prePolicyScore + policyResult.scoreDelta);
  const rank: Record<SecurityDecision, number> = { ALLOW: 0, MONITOR: 1, CHALLENGE: 2, REVIEW: 3, BLOCK: 4 };
  const scoreDecision = decisionFor(score);
  const decision = policyResult.decisionOverride && rank[policyResult.decisionOverride] > rank[scoreDecision] ? policyResult.decisionOverride : scoreDecision;
  const riskLevel = riskLevelFor(score);
  const policyReasonCodes = policyResult.matched.map((policy) => policy.reasonCode);
  securityLog("security_check", { requestId: input.requestId ?? null, tenantId: input.tenantId, subjectId: input.subjectId ?? null, score, decision, signalCount: signals.length, policyMatches: policyResult.matched.length });
  const assessmentInsert = await supabase.schema("security").from("risk_assessments").insert({ tenant_id: input.tenantId, subject_id: input.subjectId ?? null, session_id: input.sessionId ?? null, score, risk_level: riskLevel, assessment_version: "baseline-v3", explanation: { requestId: input.requestId ?? null, signalCount: signals.length, sources: signals.map((signal) => signal.source), aggregation: "weighted_evidence_v2", policies: policyResult.matched.map((policy) => ({ id: policy.id, name: policy.name, reasonCode: policy.reasonCode })), policyCount: policyResult.policyCount } }).select("id").single();
  if (assessmentInsert.error) throw assessmentInsert.error;
  if (signals.length > 0) {
    const signalInsert = await supabase.schema("security").from("risk_signals").insert(signals.map((signal) => ({ assessment_id: assessmentInsert.data.id, signal_name: signal.signalName, source: signal.source, score: signal.score, confidence: signal.confidence, evidence: signal.evidence })));
    if (signalInsert.error) throw signalInsert.error;
  }
  const decisionInsert = await supabase.schema("security").from("risk_decisions").insert({ assessment_id: assessmentInsert.data.id, decision, reason_codes: [...signals.map((signal) => signal.signalName), ...policyReasonCodes], decision_version: "policy-engine-v1" });
  if (decisionInsert.error) throw decisionInsert.error;
  if (input.requestId) {
    const auditInsert = await supabase.schema("security").from("audit_events").insert({ tenant_id: input.tenantId, actor_type: "system", action: "security_check", resource_type: "risk_assessment", resource_id: assessmentInsert.data.id, request_id: input.requestId, details: { decision, score, riskLevel, version: "baseline-v3", policyMatches: policyResult.matched.map((policy) => policy.id) } });
    if (auditInsert.error) throw auditInsert.error;
  }
  const backgroundTasks: Promise<unknown>[] = [
    enqueueSecurityEvent({ tenantId: input.tenantId, eventType: "security.risk_assessment.created", aggregateId: assessmentInsert.data.id, dedupeKey: input.requestId ? `risk:${input.requestId}` : assessmentInsert.data.id, payload: { assessmentId: assessmentInsert.data.id, subjectId: input.subjectId ?? null, sessionId: input.sessionId ?? null, score, riskLevel, decision, signalNames: signals.map((signal) => signal.signalName) } }),
  ];
  if (input.subjectId && (score >= 70 || decision === "BLOCK" || decision === "REVIEW")) {
    backgroundTasks.push(ensureInvestigationCase({ tenantId: input.tenantId, subjectId: input.subjectId, assessmentId: assessmentInsert.data.id, score, decision, evidence: { signalNames: signals.map((signal) => signal.signalName), policyMatches: policyReasonCodes } }));
  }
  if (input.subjectId && graphScoreInfo && graphScoreInfo.relatedSubjects.length >= 2) {
    backgroundTasks.push(upsertFraudCluster({ tenantId: input.tenantId, clusterType: "mixed", subjectIds: [input.subjectId, ...graphScoreInfo.relatedSubjects.map((subject) => subject.subjectId)], riskScore: graphScoreInfo.connectionScore, evidence: { relatedSubjectCount: graphScoreInfo.relatedSubjectCount, riskyConnectionCount: graphScoreInfo.riskyConnectionCount, version: "fraud-clusters-v1" } }));
  }
  const analyticsEventRows = (velocityResult.data ?? []).map((event) => ({
    subjectId: input.subjectId,
    sessionId: input.sessionId,
    eventType: event.event_type,
    occurredAt: event.occurred_at,
    ...(event.anomaly_score === null || event.anomaly_score === undefined ? {} : { behaviorScore: clamp(Number(event.anomaly_score)) }),
  }));
  if (valueAnomaly && input.subjectId) {
    const valueEvidence = valueAnomaly.evidence as Record<string, unknown>;
    const valueDelta = Number(valueEvidence.delta);
    if (Number.isFinite(valueDelta)) analyticsEventRows.push({
      subjectId: input.subjectId,
      sessionId: input.sessionId,
      eventType: "value_change",
      occurredAt: valueAnomaly.occurred_at,
      valueDelta,
      behaviorScore: 0,
    });
  }
  if (env.DUCKDB_ANALYTICS_URL && env.DUCKDB_ANALYTICS_TOKEN && analyticsEventRows.length > 0) {
    const minuteBucket = Math.floor(Date.now() / 60_000);
    const bucketKey = input.sessionId ?? input.subjectId ?? assessmentInsert.data.id;
    backgroundTasks.push(enqueueSecurityEvent({
      tenantId: input.tenantId,
      eventType: "analytics.duckdb_batch",
      aggregateId: bucketKey,
      dedupeKey: `duckdb:${bucketKey}:${minuteBucket}`,
      payload: { tenantId: input.tenantId, events: analyticsEventRows.slice(-500) },
    }));
  }
  const settled = await Promise.allSettled(backgroundTasks);
  for (const item of settled) if (item.status === "rejected") securityLog("security_background_task_failed", { requestId: input.requestId ?? null, tenantId: input.tenantId, errorCode: item.reason instanceof Error ? item.reason.name : "UNKNOWN_ERROR" });
  return { decision, score, riskLevel, assessmentId: assessmentInsert.data.id };
}
