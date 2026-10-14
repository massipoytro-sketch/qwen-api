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

const inputSchema = z.object({ tenantId: z.uuid(), subjectId: z.uuid().optional(), sessionId: z.uuid().optional(), requestId: z.string().min(1).max(200).optional() });
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
    input.sessionId ? supabase.schema("security").from("sessions").select("id,subject_id,device_id,ip_id,ended_at").eq("tenant_id", input.tenantId).eq("id", input.sessionId).maybeSingle() : Promise.resolve({ data: null, error: null }),
  ]);
  if (tenantResult.error) throw tenantResult.error;
  if (!tenantResult.data) throw new Error("TENANT_NOT_FOUND");
  if (tenantResult.data.status !== "active") throw new Error("TENANT_NOT_ACTIVE");
  if (subjectResult.error) throw subjectResult.error;
  if (sessionResult.error) throw sessionResult.error;
  if (input.subjectId && !subjectResult.data) throw new Error("SUBJECT_NOT_FOUND");
  if (input.sessionId && !sessionResult.data) throw new Error("SESSION_NOT_FOUND");
  if (input.sessionId && input.subjectId && sessionResult.data?.subject_id && sessionResult.data.subject_id !== input.subjectId) throw new Error("SESSION_SUBJECT_MISMATCH");
  if (input.sessionId && sessionResult.data?.ended_at) throw new Error("SESSION_NOT_ACTIVE");

  const subjectRisk = subjectResult.data?.risk_level === "critical" ? 90 : subjectResult.data?.risk_level === "high" ? 70 : subjectResult.data?.risk_level === "medium" ? 40 : subjectResult.data?.risk_level === "low" ? 10 : 0;
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
  const accountTakeover = analyzeAccountTakeoverSignals((accountEventsResult.data ?? []).map((event) => ({ eventType: event.event_type, occurredAt: event.occurred_at, severity: event.severity })));
  if (accountTakeover.score > 0) signals.push({ signalName: "account_takeover_detection", source: "account_security", score: accountTakeover.score, confidence: accountTakeover.confidence, evidence: { reasonCodes: accountTakeover.reasonCodes, failedLoginCount5m: accountTakeover.failedLoginCount5m, sensitiveEventCount1h: accountTakeover.sensitiveEventCount1h, version: accountTakeover.version } });
  const concurrentSessions = analyzeConcurrentSessionAnomalies((subjectSessionsResult.data ?? []).map((session) => ({ deviceId: session.device_id, ipId: session.ip_id, startedAt: session.started_at, endedAt: session.ended_at })));
  if (concurrentSessions.score > 0) signals.push({ signalName: "concurrent_session_anomaly", source: "session_integrity", score: concurrentSessions.score, confidence: concurrentSessions.confidence, evidence: { reasonCodes: concurrentSessions.reasonCodes, activeSessionCount: concurrentSessions.activeSessionCount, distinctDeviceCount: concurrentSessions.distinctDeviceCount, distinctIpCount: concurrentSessions.distinctIpCount, version: concurrentSessions.version } });
  if (subjectRisk > 0) signals.push({ signalName: "subject_risk", source: "subject", score: subjectRisk, confidence: 1, evidence: { riskLevel: subjectResult.data?.risk_level } });
  if (subjectResult.data?.status === "blocked" || subjectResult.data?.status === "deleted") signals.push({ signalName: "subject_status_block", source: "account_status", score: 100, confidence: 1, evidence: { status: subjectResult.data.status } });
  else if (subjectResult.data?.status === "suspended") signals.push({ signalName: "subject_status_suspended", source: "account_status", score: 80, confidence: 1, evidence: { status: subjectResult.data.status } });
  const deviceRisk = clamp(Number(deviceResult.data?.risk_score ?? 0));
  if (deviceRisk > 0) signals.push({ signalName: "device_risk", source: "device", score: deviceRisk, confidence: Number(deviceResult.data?.confidence ?? 0) || null, evidence: { deviceId } });
  const ip = ipResult.data;
  if (ip) {
    const reputationPenalty = ip.reputation_score == null ? 0 : Math.max(0, 50 - Number(ip.reputation_score)) * 0.2;
    const networkPenalty = clamp((ip.is_tor ? 35 : 0) + (ip.is_proxy ? 20 : 0) + (ip.is_vpn ? 15 : 0) + (ip.is_datacenter ? 20 : 0) + reputationPenalty);
    if (networkPenalty > 0) signals.push({ signalName: "network_risk", source: "network", score: networkPenalty, confidence: 0.9, evidence: { isTor: ip.is_tor, isProxy: ip.is_proxy, isVpn: ip.is_vpn, isDatacenter: ip.is_datacenter, reputationScore: ip.reputation_score } });
  }
  const botEvents = (botResult.data ?? []).map((event) => ({ occurredAt: event.observed_at, isBot: event.is_bot, confidence: Number(event.confidence ?? 0), signals: (event.signals ?? {}) as Record<string, unknown> }));
  const activityEvents = (velocityResult.data ?? []).map((event) => ({ occurredAt: event.occurred_at, eventType: event.event_type }));
  const velocity = analyzeVelocity(activityEvents);
  const advancedBot = analyzeAdvancedBotSignals({ botEvents, activityEvents });
  const botDefense = analyzeBotDefense({ events: botEvents });
  const combinedBotScore = Math.max(advancedBot.score, botDefense.score);
  const combinedBotConfidence = Math.max(advancedBot.confidence, botDefense.confidence);
  if (combinedBotScore > 0) signals.push({ signalName: "advanced_bot_detection", source: "advanced_bot", score: combinedBotScore, confidence: combinedBotConfidence, evidence: { reasonCodes: [...new Set([...advancedBot.reasonCodes, ...botDefense.reasonCodes])].slice(0, 16), signalFlags: [...new Set([...advancedBot.signalFlags, ...botDefense.signalFlags])].slice(0, 16), velocity: advancedBot.velocity, botDefense, version: "bot-defense-v1" } });
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

  const recentActivityAnomalies = anomalyResult.data ?? [];
  for (const anomaly of recentActivityAnomalies) {
    const anomalyScore = clamp(Number(anomaly.score ?? 0));
    if (anomalyScore <= 0) continue;
    const evidence = { anomalyType: anomaly.anomaly_type, reasonCodes: anomaly.reason_codes, evidence: anomaly.evidence, analyzerVersion: anomaly.analyzer_version };
    if (anomaly.anomaly_type === "value_jump") signals.push({ signalName: "value_jump_anomaly", source: "activity_anomaly", score: anomalyScore, confidence: Number(anomaly.confidence ?? 0.75), evidence });
    else if (anomaly.anomaly_type === "activity_velocity") signals.push({ signalName: "analytics_velocity_anomaly", source: "duckdb_analytics", score: anomalyScore, confidence: Number(anomaly.confidence ?? 0.7), evidence });
    else if (anomaly.anomaly_type === "advanced_bot") signals.push({ signalName: "analytics_bot_anomaly", source: "duckdb_analytics", score: anomalyScore, confidence: Number(anomaly.confidence ?? 0.7), evidence });
    else if (anomaly.anomaly_type === "behavioral_deviation") signals.push({ signalName: "analytics_behavior_anomaly", source: "duckdb_analytics", score: anomalyScore, confidence: Number(anomaly.confidence ?? 0.7), evidence });
    else if (anomaly.anomaly_type === "impossible_travel") signals.push({ signalName: "impossible_travel_detection", source: "network_intelligence", score: anomalyScore, confidence: Number(anomaly.confidence ?? 0.82), evidence });
    else signals.push({ signalName: "analytics_anomaly", source: "duckdb_analytics", score: anomalyScore, confidence: Number(anomaly.confidence ?? 0.5), evidence });
  }
  const valueAnomaly = recentActivityAnomalies.find((anomaly) => anomaly.anomaly_type === "value_jump") ?? null;
  let graphScoreInfo: Awaited<ReturnType<typeof scoreSubjectConnections>> | null = null;
  if (input.subjectId) {
    graphScoreInfo = await scoreSubjectConnections({ tenantId: input.tenantId, subjectId: input.subjectId });
    if (graphScoreInfo.connectionScore > 0) signals.push({ signalName: "graph_connection_risk", source: "graph", score: graphScoreInfo.connectionScore, confidence: 0.8, evidence: { riskyConnectionCount: graphScoreInfo.riskyConnectionCount, relatedSubjectCount: graphScoreInfo.relatedSubjectCount } });
  }

  const deterministicScore = aggregateRisk(signals);
  // The remainder of this function is unchanged from Part 2: deterministic score/policy/firewall remain authoritative.
  if (env.AI_ANALYZER_ENABLED === "true" && env.AI_ANALYZER_ENDPOINT && env.AI_ANALYZER_API_KEY && env.AI_ANALYZER_MODEL) {
    try {
      const ai = await analyzeWithAI({ tenantId: input.tenantId, subjectId: input.subjectId, sessionId: input.sessionId, endpoint: env.AI_ANALYZER_ENDPOINT, apiKey: env.AI_ANALYZER_API_KEY, model: env.AI_ANALYZER_MODEL, evidence: buildAIAdvisoryEvidence({ deterministicScore, signals }) });
      signals.push({ signalName: "ai_advisory", source: "ai", score: ai.riskScore, confidence: Math.min(0.5, ai.confidence), evidence: { reasonCodes: ai.reasonCodes.slice(0, 16), model: env.AI_ANALYZER_MODEL } });
    } catch (error) {
      securityLog("ai_advisory_failed", { requestId: input.requestId ?? null, tenantId: input.tenantId, errorCode: safeErrorCode(error), ...(safeErrorStatus(error) ? { errorStatus: safeErrorStatus(error) } : {}) });
    }
  }

  const baseScore = aggregateRisk(signals);
  const baseDecision = decisionFor(baseScore);
  const baseRiskLevel = riskLevelFor(baseScore);
  const policy = await evaluateTenantPolicies(input.tenantId, { score: baseScore, riskLevel: baseRiskLevel, decision: baseDecision, signalNames: signals.map((signal) => signal.signalName), velocity: velocity, valueJumpScore: valueAnomaly ? Number(valueAnomaly.score) : 0, relatedSubjectCount: graphScoreInfo?.relatedSubjectCount ?? 0 });
  const policyScore = clamp(baseScore + Math.max(0, policy.scoreDelta));
  const policyDecision = policy.decisionOverride && scoreFloorForDecision(policy.decisionOverride) > policyScore ? policy.decisionOverride : decisionFor(policyScore);
  const firewall = evaluateDefenseInDepth({ score: policyScore, subjectStatus: subjectResult.data?.status ?? "unknown", signals });
  const score = Math.max(policyScore, scoreFloorForDecision(firewall.minimumDecision));
  const decision = firewall.minimumDecision === "BLOCK" ? "BLOCK" : firewall.minimumDecision === "REVIEW" && decisionFor(score) !== "BLOCK" ? "REVIEW" : decisionFor(score);
  const riskLevel = riskLevelFor(score);
  const result: SecurityCheckResult = { decision, score, riskLevel, signals, policy: { matched: policy.matched, scoreDelta: policy.scoreDelta }, defenseInDepth: firewall, requestId: input.requestId ?? crypto.randomUUID() } as SecurityCheckResult;
  return result;
}
