import { z } from "zod";
import { supabase } from "../db/supabase";
import { env } from "../config/env";
import { scoreSubjectConnections } from "./graph";
import { analyzeWithAI, buildAIAdvisoryEvidence } from "./ai";
import { safeErrorCode, safeErrorStatus, securityLog } from "./observability";
import { analyzeVelocity } from "./velocity";
import { analyzeAccountTakeoverSignals, analyzeConcurrentSessionAnomalies } from "./detectors";
import { analyzeAdvancedBotSignals, evaluateTenantPolicies, getBehaviorBaselineScore, ensureInvestigationCase, enqueueSecurityEvent, upsertFraudCluster } from "./platform";
import { analyzeBotDefense } from "./botDefense";
import { evaluateDefenseInDepth, scoreFloorForDecision } from "./firewall";
import type { SecurityCheckInput, SecurityCheckResult, SecurityDecision } from "./types";

const inputSchema = z.object({ tenantId: z.uuid(), subjectId: z.uuid().optional(), sessionId: z.uuid().optional(), requestId: z.string().min(1).max(200).optional() }).strict();
type Signal = { signalName: string; source: string; score: number; confidence: number | null; evidence: Record<string, unknown> };
const clamp = (n: number) => Math.max(0, Math.min(100, Math.round(n)));
const riskLevelFor = (score: number): SecurityCheckResult["riskLevel"] => score >= 90 ? "critical" : score >= 70 ? "high" : score >= 40 ? "medium" : score > 0 ? "low" : "unknown";
const decisionFor = (score: number): SecurityDecision => score >= 90 ? "BLOCK" : score >= 70 ? "REVIEW" : score >= 40 ? "CHALLENGE" : score > 0 ? "MONITOR" : "ALLOW";
const rank: Record<SecurityDecision, number> = { ALLOW: 0, MONITOR: 1, CHALLENGE: 2, REVIEW: 3, BLOCK: 4 };
const aggregateRisk = (signals: Signal[]) => {
  if (!signals.length) return 0;
  const weighted = signals.reduce((sum, s) => sum + s.score * (s.confidence ?? 0.5), 0);
  const sourceBonus = Math.min(15, Math.max(0, new Set(signals.map((s) => s.source)).size - 1) * 5);
  const highBonus = signals.filter((s) => s.score >= 70).length >= 2 ? 10 : 0;
  return clamp(Math.min(100, weighted * 0.55 + sourceBonus + highBonus));
};

export async function securityCheck(rawInput: SecurityCheckInput): Promise<SecurityCheckResult> {
  const input = inputSchema.parse(rawInput);
  const [tenantResult, subjectResult, sessionResult] = await Promise.all([
    supabase.schema("security").from("tenants").select("id,status").eq("id", input.tenantId).maybeSingle(),
    input.subjectId ? supabase.schema("security").from("subjects").select("id,status,risk_level").eq("tenant_id", input.tenantId).eq("id", input.subjectId).maybeSingle() : Promise.resolve({ data: null, error: null }),
    input.sessionId ? supabase.schema("security").from("sessions").select("id,subject_id,device_id,ip_id,ended_at").eq("tenant_id", input.tenantId).eq("id", input.sessionId).maybeSingle() : Promise.resolve({ data: null, error: null }),
  ]);
  for (const result of [tenantResult, subjectResult, sessionResult]) if (result.error) throw result.error;
  if (!tenantResult.data) throw new Error("TENANT_NOT_FOUND");
  if (tenantResult.data.status !== "active") throw new Error("TENANT_NOT_ACTIVE");
  if (input.subjectId && !subjectResult.data) throw new Error("SUBJECT_NOT_FOUND");
  if (input.sessionId && !sessionResult.data) throw new Error("SESSION_NOT_FOUND");
  if (input.sessionId && input.subjectId && sessionResult.data?.subject_id && sessionResult.data.subject_id !== input.subjectId) throw new Error("SESSION_SUBJECT_MISMATCH");
  if (input.sessionId && sessionResult.data?.ended_at) throw new Error("SESSION_NOT_ACTIVE");

  const deviceId = sessionResult.data?.device_id;
  const ipId = sessionResult.data?.ip_id;
  const [deviceResult, ipResult, botResult, behaviorResult, anomalyResult, velocityResult, accountEventsResult, subjectSessionsResult] = await Promise.all([
    deviceId ? supabase.schema("security").from("devices").select("id,risk_score,confidence").eq("tenant_id", input.tenantId).eq("id", deviceId).maybeSingle() : Promise.resolve({ data: null, error: null }),
    ipId ? supabase.schema("security").from("ip_addresses").select("id,reputation_score,is_proxy,is_vpn,is_tor,is_datacenter").eq("id", ipId).maybeSingle() : Promise.resolve({ data: null, error: null }),
    input.sessionId ? supabase.schema("security").from("bot_events").select("observed_at,is_bot,confidence,signals").eq("tenant_id", input.tenantId).eq("session_id", input.sessionId).gte("observed_at", new Date(Date.now() - 10 * 60_000).toISOString()).order("observed_at", { ascending: false }).limit(100) : Promise.resolve({ data: [], error: null }),
    input.sessionId ? supabase.schema("security").from("behavior_events").select("anomaly_score").eq("tenant_id", input.tenantId).eq("session_id", input.sessionId).gte("occurred_at", new Date(Date.now() - 15 * 60_000).toISOString()).order("occurred_at", { ascending: false }).limit(1).maybeSingle() : Promise.resolve({ data: null, error: null }),
    input.subjectId ? supabase.schema("security").from("activity_anomalies").select("id,anomaly_type,score,confidence,reason_codes,evidence,analyzer_version,occurred_at,source_event_id").eq("tenant_id", input.tenantId).eq("subject_id", input.subjectId).gte("occurred_at", new Date(Date.now() - 15 * 60_000).toISOString()).order("occurred_at", { ascending: false }).limit(20) : Promise.resolve({ data: [], error: null }),
    input.sessionId ? supabase.schema("security").from("behavior_events").select("occurred_at,event_type,anomaly_score").eq("tenant_id", input.tenantId).eq("session_id", input.sessionId).gte("occurred_at", new Date(Date.now() - 15 * 60_000).toISOString()).order("occurred_at", { ascending: true }).limit(200) : Promise.resolve({ data: [], error: null }),
    input.subjectId ? supabase.schema("security").from("security_events").select("event_type,severity,occurred_at").eq("tenant_id", input.tenantId).eq("subject_id", input.subjectId).gte("occurred_at", new Date(Date.now() - 24 * 60 * 60_000).toISOString()).order("occurred_at", { ascending: false }).limit(200) : Promise.resolve({ data: [], error: null }),
    input.subjectId ? supabase.schema("security").from("sessions").select("device_id,ip_id,started_at,ended_at").eq("tenant_id", input.tenantId).eq("subject_id", input.subjectId).gte("started_at", new Date(Date.now() - 24 * 60 * 60_000).toISOString()).order("started_at", { ascending: false }).limit(100) : Promise.resolve({ data: [], error: null }),
  ]);
  for (const result of [deviceResult, ipResult, botResult, behaviorResult, anomalyResult, velocityResult, accountEventsResult, subjectSessionsResult]) if (result.error) throw result.error;

  const signals: Signal[] = [];
  const subjectRisk = subjectResult.data?.risk_level === "critical" ? 90 : subjectResult.data?.risk_level === "high" ? 70 : subjectResult.data?.risk_level === "medium" ? 40 : subjectResult.data?.risk_level === "low" ? 10 : 0;
  if (subjectRisk) signals.push({ signalName: "subject_risk", source: "subject", score: subjectRisk, confidence: 1, evidence: { riskLevel: subjectResult.data?.risk_level } });
  if (subjectResult.data?.status === "blocked" || subjectResult.data?.status === "deleted") signals.push({ signalName: "subject_status_block", source: "account_status", score: 100, confidence: 1, evidence: { status: subjectResult.data.status } });
  else if (subjectResult.data?.status === "suspended") signals.push({ signalName: "subject_status_suspended", source: "account_status", score: 80, confidence: 1, evidence: { status: subjectResult.data.status } });

  const takeover = analyzeAccountTakeoverSignals((accountEventsResult.data ?? []).map((e) => ({ eventType: e.event_type, occurredAt: e.occurred_at, severity: e.severity })));
  if (takeover.score) signals.push({ signalName: "account_takeover_detection", source: "account_security", score: takeover.score, confidence: takeover.confidence, evidence: { reasonCodes: takeover.reasonCodes, failedLoginCount5m: takeover.failedLoginCount5m, sensitiveEventCount1h: takeover.sensitiveEventCount1h, version: takeover.version } });
  const sessions = analyzeConcurrentSessionAnomalies((subjectSessionsResult.data ?? []).map((s) => ({ deviceId: s.device_id, ipId: s.ip_id, startedAt: s.started_at, endedAt: s.ended_at })));
  if (sessions.score) signals.push({ signalName: "concurrent_session_anomaly", source: "session_integrity", score: sessions.score, confidence: sessions.confidence, evidence: { reasonCodes: sessions.reasonCodes, activeSessionCount: sessions.activeSessionCount, distinctDeviceCount: sessions.distinctDeviceCount, distinctIpCount: sessions.distinctIpCount, version: sessions.version } });

  const deviceRisk = clamp(Number(deviceResult.data?.risk_score ?? 0));
  if (deviceRisk) signals.push({ signalName: "device_risk", source: "device", score: deviceRisk, confidence: Number(deviceResult.data?.confidence ?? 0) || null, evidence: { deviceId } });
  const ip = ipResult.data;
  if (ip) {
    const reputationPenalty = ip.reputation_score == null ? 0 : Math.max(0, 50 - Number(ip.reputation_score)) * 0.2;
    const networkRisk = clamp((ip.is_tor ? 35 : 0) + (ip.is_proxy ? 20 : 0) + (ip.is_vpn ? 15 : 0) + (ip.is_datacenter ? 20 : 0) + reputationPenalty);
    if (networkRisk) signals.push({ signalName: "network_risk", source: "network", score: networkRisk, confidence: 0.9, evidence: { isTor: ip.is_tor, isProxy: ip.is_proxy, isVpn: ip.is_vpn, isDatacenter: ip.is_datacenter, reputationScore: ip.reputation_score } });
  }

  const botEvents = (botResult.data ?? []).map((e) => ({ occurredAt: e.observed_at, isBot: e.is_bot, confidence: Number(e.confidence ?? 0), signals: (e.signals ?? {}) as Record<string, unknown> }));
  const activityEvents = (velocityResult.data ?? []).map((e) => ({ occurredAt: e.occurred_at, eventType: e.event_type }));
  const velocity = analyzeVelocity(activityEvents);
  const advancedBot = analyzeAdvancedBotSignals({ botEvents, activityEvents });
  const botDefense = analyzeBotDefense({ events: botEvents });
  const botScore = Math.max(advancedBot.score, botDefense.score);
  if (botScore) signals.push({ signalName: "advanced_bot_detection", source: "advanced_bot", score: botScore, confidence: Math.max(advancedBot.confidence, botDefense.confidence), evidence: { reasonCodes: [...new Set([...advancedBot.reasonCodes, ...botDefense.reasonCodes])].slice(0, 16), signalFlags: [...new Set([...advancedBot.signalFlags, ...botDefense.signalFlags])].slice(0, 16), velocity: advancedBot.velocity, botDefense, version: "bot-defense-v1" } });
  if (velocity.score) signals.push({ signalName: "activity_velocity", source: "velocity", score: velocity.score, confidence: velocity.confidence, evidence: velocity });

  const behaviorScore = clamp(Number(behaviorResult.data?.anomaly_score ?? 0));
  if (behaviorScore) {
    signals.push({ signalName: "behavior_anomaly", source: "behavior", score: behaviorScore, confidence: 0.8, evidence: { anomalyScore: behaviorScore } });
    if (input.subjectId) {
      try {
        const baseline = await getBehaviorBaselineScore({ tenantId: input.tenantId, subjectId: input.subjectId, currentValue: behaviorScore });
        if (baseline.score) signals.push({ signalName: "behavior_baseline_deviation", source: "behavior_baseline", score: baseline.score, confidence: baseline.confidence, evidence: baseline });
      } catch (error) { securityLog("behavior_baseline_failed", { requestId: input.requestId ?? null, tenantId: input.tenantId, errorCode: safeErrorCode(error) }); }
    }
  }

  const anomalies = anomalyResult.data ?? [];
  for (const anomaly of anomalies) {
    const score = clamp(Number(anomaly.score ?? 0));
    if (!score) continue;
    const evidence = { anomalyType: anomaly.anomaly_type, reasonCodes: anomaly.reason_codes, evidence: anomaly.evidence, analyzerVersion: anomaly.analyzer_version };
    const map: Record<string, [string,string]> = { value_jump: ["value_jump_anomaly","activity_anomaly"], activity_velocity: ["analytics_velocity_anomaly","duckdb_analytics"], advanced_bot: ["analytics_bot_anomaly","duckdb_analytics"], behavioral_deviation: ["analytics_behavior_anomaly","duckdb_analytics"], impossible_travel: ["impossible_travel_detection","network_intelligence"] };
    const [signalName, source] = map[anomaly.anomaly_type] ?? ["analytics_anomaly","duckdb_analytics"];
    signals.push({ signalName, source, score, confidence: Number(anomaly.confidence ?? 0.7), evidence });
  }
  const valueAnomaly = anomalies.find((a) => a.anomaly_type === "value_jump") ?? null;

  let graph: Awaited<ReturnType<typeof scoreSubjectConnections>> | null = null;
  if (input.subjectId) {
    graph = await scoreSubjectConnections({ tenantId: input.tenantId, subjectId: input.subjectId });
    if (graph.connectionScore) signals.push({ signalName: "graph_connection_risk", source: "graph", score: graph.connectionScore, confidence: 0.8, evidence: { riskyConnectionCount: graph.riskyConnectionCount, relatedSubjectCount: graph.relatedSubjectCount } });
  }

  const deterministicScore = aggregateRisk(signals);
  if (env.AI_ANALYZER_ENABLED === "true" && env.AI_ANALYZER_ENDPOINT && env.AI_ANALYZER_API_KEY && env.AI_ANALYZER_MODEL) {
    try {
      const ai = await analyzeWithAI({ tenantId: input.tenantId, subjectId: input.subjectId, sessionId: input.sessionId, endpoint: env.AI_ANALYZER_ENDPOINT, apiKey: env.AI_ANALYZER_API_KEY, model: env.AI_ANALYZER_MODEL, evidence: buildAIAdvisoryEvidence({ deterministicScore, signals }) });
      signals.push({ signalName: "ai_advisory", source: "ai", score: ai.riskScore, confidence: Math.min(0.5, ai.confidence * 0.5), evidence: { riskLevel: ai.riskLevel, reasonCodes: ai.reasonCodes, recommendedAction: ai.recommendedAction, predictionId: ai.predictionId } });
    } catch (error) { securityLog("ai_advisory_failed", { requestId: input.requestId ?? null, tenantId: input.tenantId, errorCode: safeErrorCode(error), ...(safeErrorStatus(error) ? { errorStatus: safeErrorStatus(error) } : {}) }); }
  }

  const prePolicyScore = aggregateRisk(signals);
  const policy = await evaluateTenantPolicies(input.tenantId, { score: prePolicyScore, riskLevel: riskLevelFor(prePolicyScore), decision: decisionFor(prePolicyScore), signalNames: signals.map((s) => s.signalName), velocity, valueJumpScore: valueAnomaly?.score ?? 0, relatedSubjectCount: graph?.relatedSubjectCount ?? 0 });
  const subjectStatus = ["active","suspended","blocked","deleted"].includes(subjectResult.data?.status ?? "") ? subjectResult.data!.status as "active"|"suspended"|"blocked"|"deleted" : "unknown";
  const firewall = evaluateDefenseInDepth({ score: prePolicyScore, subjectStatus, signals });
  const firewallSignals: Signal[] = firewall.layers.filter((x) => x.action !== "ALLOW").map((x) => ({ signalName: `firewall_${x.layer}`, source: "firewall", score: x.score, confidence: x.confidence, evidence: { action: x.action, reasonCodes: x.reasonCodes, version: firewall.version } }));
  const finalSignals = [...signals, ...firewallSignals];
  const policyFloor = policy.decisionOverride ? scoreFloorForDecision(policy.decisionOverride) : 0;
  const score = clamp(Math.max(prePolicyScore + policy.scoreDelta, scoreFloorForDecision(firewall.minimumDecision), policyFloor));
  const candidates: SecurityDecision[] = [decisionFor(score), firewall.minimumDecision];
  if (policy.decisionOverride) candidates.push(policy.decisionOverride);
  const decision = candidates.reduce((best, item) => rank[item] > rank[best] ? item : best, "ALLOW" as SecurityDecision);
  const riskLevel = riskLevelFor(score);
  const policyReasonCodes = policy.matched.map((p) => p.reasonCode);
  const challengeRecommendation = decision === "CHALLENGE" ? firewall.recommendedChallenge ?? { type: "risk_based_verification" as const, reasonCodes: policyReasonCodes.length ? policyReasonCodes : ["RISK_THRESHOLD_CHALLENGE"], expiresInSeconds: 300 } : null;
  const firewallAudit = { version: firewall.version, minimumDecision: firewall.minimumDecision, reasonCodes: firewall.reasonCodes, layers: firewall.layers.map((x) => ({ layer: x.layer, action: x.action, score: x.score, confidence: x.confidence, reasonCodes: x.reasonCodes })) };

  const assessment = await supabase.schema("security").from("risk_assessments").insert({ tenant_id: input.tenantId, subject_id: input.subjectId ?? null, session_id: input.sessionId ?? null, score, risk_level: riskLevel, assessment_version: "defense-in-depth-v1", explanation: { requestId: input.requestId ?? null, signalCount: finalSignals.length, sources: finalSignals.map((s) => s.source), aggregation: "weighted_evidence_v2", policies: policy.matched.map((p) => ({ id: p.id, name: p.name, reasonCode: p.reasonCode })), policyCount: policy.policyCount, firewall: firewallAudit, challengeRecommendation } }).select("id").single();
  if (assessment.error) throw assessment.error;
  if (finalSignals.length) {
    const inserted = await supabase.schema("security").from("risk_signals").insert(finalSignals.map((s) => ({ assessment_id: assessment.data.id, signal_name: s.signalName, source: s.source, score: s.score, confidence: s.confidence, evidence: s.evidence })));
    if (inserted.error) throw inserted.error;
  }
  const decisionInsert = await supabase.schema("security").from("risk_decisions").insert({ assessment_id: assessment.data.id, decision, reason_codes: [...finalSignals.map((s) => s.signalName), ...policyReasonCodes, ...firewall.reasonCodes], decision_version: "defense-in-depth-v1" }).select("id").single();
  if (decisionInsert.error) throw decisionInsert.error;
  if (input.requestId) {
    const audit = await supabase.schema("security").from("audit_events").insert({ tenant_id: input.tenantId, actor_type: "system", action: "security_check", resource_type: "risk_assessment", resource_id: assessment.data.id, request_id: input.requestId, details: { decision, score, riskLevel, version: "defense-in-depth-v1", policyMatches: policy.matched.map((p) => p.id), firewallMinimumDecision: firewall.minimumDecision, firewallReasonCodes: firewall.reasonCodes } });
    if (audit.error) throw audit.error;
  }
  const ledger = await supabase.schema("security").rpc("append_security_ledger_entry", { p_tenant_id: input.tenantId, p_action: "risk_assessment_decided", p_resource_type: "risk_assessment", p_resource_id: assessment.data.id, p_request_id: input.requestId ?? null, p_actor_type: "system", p_details: { subjectId: input.subjectId ?? null, sessionId: input.sessionId ?? null, decision, score, riskLevel, assessmentVersion: "defense-in-depth-v1", firewallMinimumDecision: firewall.minimumDecision, firewallReasonCodes: firewall.reasonCodes, signalNames: finalSignals.map((s) => s.signalName).slice(0, 128) } });
  if (ledger.error) throw new Error("SECURITY_LEDGER_APPEND_FAILED");

  const tasks: Promise<unknown>[] = [enqueueSecurityEvent({ tenantId: input.tenantId, eventType: "security.risk_assessment.created", aggregateId: assessment.data.id, dedupeKey: input.requestId ? `risk:${input.requestId}` : assessment.data.id, payload: { assessmentId: assessment.data.id, subjectId: input.subjectId ?? null, sessionId: input.sessionId ?? null, score, riskLevel, decision, signalNames: finalSignals.map((s) => s.signalName), firewallMinimumDecision: firewall.minimumDecision, firewallReasonCodes: firewall.reasonCodes } })];
  if (input.subjectId && (score >= 70 || decision === "BLOCK" || decision === "REVIEW")) tasks.push(ensureInvestigationCase({ tenantId: input.tenantId, subjectId: input.subjectId, assessmentId: assessment.data.id, score, decision, evidence: { signalNames: finalSignals.map((s) => s.signalName), policyMatches: policyReasonCodes, firewall: firewallAudit } }));
  if (input.subjectId && graph && graph.relatedSubjects.length >= 2) tasks.push(upsertFraudCluster({ tenantId: input.tenantId, clusterType: "mixed", subjectIds: [input.subjectId, ...graph.relatedSubjects.map((s) => s.subjectId)], riskScore: graph.connectionScore, evidence: { relatedSubjectCount: graph.relatedSubjectCount, riskyConnectionCount: graph.riskyConnectionCount, version: "fraud-clusters-v1" } }));
  const analyticsRows = (velocityResult.data ?? []).map((e) => ({ subjectId: input.subjectId, sessionId: input.sessionId, eventType: e.event_type, occurredAt: e.occurred_at, ...(e.anomaly_score == null ? {} : { behaviorScore: clamp(Number(e.anomaly_score)) }) }));
  for (const e of botResult.data ?? []) analyticsRows.push({ subjectId: input.subjectId, sessionId: input.sessionId, eventType: "bot_detection", occurredAt: e.observed_at, botScore: e.is_bot ? clamp(Number(e.confidence ?? 0) * 100) : 0 });
  if (valueAnomaly && input.subjectId) {
    const value = valueAnomaly.evidence as Record<string, unknown>;
    const delta = Number(value.delta);
    if (Number.isFinite(delta)) analyticsRows.push({ subjectId: input.subjectId, sessionId: input.sessionId, eventType: "value_change", occurredAt: valueAnomaly.occurred_at, valueDelta: delta, valueEventId: valueAnomaly.source_event_id as string | undefined, behaviorScore: 0 });
  }
  if (env.DUCKDB_ANALYTICS_URL && env.DUCKDB_ANALYTICS_TOKEN && analyticsRows.length) {
    const bucket = input.sessionId ?? input.subjectId ?? assessment.data.id;
    tasks.push(enqueueSecurityEvent({ tenantId: input.tenantId, eventType: "analytics.duckdb_batch", aggregateId: bucket, dedupeKey: `duckdb:${bucket}:${Math.floor(Date.now()/60_000)}`, payload: { tenantId: input.tenantId, events: analyticsRows.slice(-500) } }));
  }
  const settled = await Promise.allSettled(tasks);
  for (const item of settled) if (item.status === "rejected") securityLog("security_background_task_failed", { requestId: input.requestId ?? null, tenantId: input.tenantId, errorCode: item.reason instanceof Error ? item.reason.name : "UNKNOWN_ERROR" });
  securityLog("security_check", { requestId: input.requestId ?? null, tenantId: input.tenantId, subjectId: input.subjectId ?? null, score, decision, signalCount: finalSignals.length, firewallMinimumDecision: firewall.minimumDecision });
  return { decision, score, riskLevel, assessmentId: assessment.data.id, challengeRecommendation };
}
