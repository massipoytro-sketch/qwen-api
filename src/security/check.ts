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
  let fraudDecisionFloor: SecurityDecision = "ALLOW";
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
  const activityEvents = (velocityResult.data ?? []).map((event) => ({ occurredAt: event.occurred_at, eventType: event.event_type }));
  const velocity = analyzeVelocity(activityEvents);
  const botEvents = (botResult.data ?? []).map((event) => ({ occurredAt: event.observed_at, isBot: event.is_bot, confidence: Number(event.confidence ?? 0), signals: (event.signals ?? {}) as Record<string, unknown> }));
  const advancedBot = analyzeAdvancedBotSignals({ botEvents, activityEvents });
  const corroboratedBot = analyzeBotDefense({ events: botEvents });
  const combinedBotScore = Math.max(advancedBot.score, corroboratedBot.score);
  const combinedBotConfidence = Math.max(advancedBot.confidence, corroboratedBot.confidence);
  const combinedBotReasons = [...new Set([...advancedBot.reasonCodes, ...corroboratedBot.reasonCodes])];
  const combinedBotFlags = [...new Set([...advancedBot.signalFlags, ...corroboratedBot.signalFlags])].slice(0, 16);
  if (combinedBotScore > 0) signals.push({ signalName: "advanced_bot_detection", source: "advanced_bot", score: combinedBotScore, confidence: combinedBotConfidence, evidence: { reasonCodes: combinedBotReasons, signalFlags: combinedBotFlags, velocity: advancedBot.velocity, corroborationDecision: corroboratedBot.decision, replayCount: corroboratedBot.replayCount, eventCount: corroboratedBot.count10m, legacyDetectorVersion: advancedBot.version, detectorVersion: corroboratedBot.version } });
  if (velocity.score > 0) signals.push({ signalName: "activity_velocity", source: "velocity", score: velocity.score, confidence: velocity.confidence, evidence: velocity });
  const anomalyScore = clamp(Number(behaviorResult.data?.anomaly_score ?? 0));
  if (anomalyScore > 0) {
    signals.push({ signalName: "behavior_anomaly", source: "behavior", score: anomalyScore, confidence: 0.8, evidence: { anomalyScore } });
    if (input.subjectId) {
      try {
        const baseline = await getBehaviorBaselineScore({ tenantId: input.tenantId, subjectId: input.subjectId, currentValue: anomalyScore });
        if (baseline.score > 0) signals.push({ signalName: "behavior_baseline_deviation", source: "behavior_baseline", score: baseline.score, confidence: baseline.confidence, evidence: baseline });
      } catch (error) { securityLog("behavior_baseline_failed", { requestId: input.requestId ?? null, tenantId: input.tenantId, errorCode: error instanceof Error ? error.name : "UNKNOWN_ERROR" }); }
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
  if (valueAnomaly && valueAnomaly.evidence && typeof valueAnomaly.evidence === "object" && !Array.isArray(valueAnomaly.evidence)) {
    const valueEvidence = valueAnomaly.evidence as Record<string, unknown>;
    const previousValue = Number(valueEvidence.previousValue);
    const currentValue = Number(valueEvidence.currentValue);
    if (Number.isFinite(previousValue) && previousValue >= 0 && Number.isFinite(currentValue) && currentValue >= 0) {
      const analyzedValueJump = analyzeValueJump({ previousValue, currentValue, occurredAt: valueAnomaly.occurred_at });
      const valueSignalIndex = signals.findIndex((signal) => signal.signalName === "value_jump_anomaly");
      const existingValueScore = valueSignalIndex >= 0 ? signals[valueSignalIndex].score : 0;
      const existingValueConfidence = valueSignalIndex >= 0 ? signals[valueSignalIndex].confidence ?? 0 : 0;
      const strengthenedValueScore = Math.max(existingValueScore, analyzedValueJump.score);
      const strengthenedValueConfidence = Math.max(existingValueConfidence, analyzedValueJump.confidence);
      if (valueSignalIndex >= 0) signals[valueSignalIndex] = { ...signals[valueSignalIndex], score: strengthenedValueScore, confidence: strengthenedValueConfidence, evidence: { ...signals[valueSignalIndex].evidence, valueJumpIntelligence: analyzedValueJump } };
      else if (analyzedValueJump.score > 0) signals.push({ signalName: "value_jump_anomaly", source: "activity_anomaly", score: analyzedValueJump.score, confidence: analyzedValueJump.confidence, evidence: { valueJumpIntelligence: analyzedValueJump } });
      fraudDecisionFloor = enforceFraudFloor(fraudDecisionFloor, strengthenedValueScore, strengthenedValueConfidence);
    }
  }
  let graphScoreInfo: Awaited<ReturnType<typeof scoreSubjectConnections>> | null = null;
  let fraudGraphInfo: ReturnType<typeof analyzeFraudGraph> | null = null;
  if (input.subjectId) {
    graphScoreInfo = await scoreSubjectConnections({ tenantId: input.tenantId, subjectId: input.subjectId });
    fraudGraphInfo = analyzeFraudGraph({ edgeCount: graphScoreInfo.graph.edgeCount, nodeCount: graphScoreInfo.graph.nodeCount, edges: graphScoreInfo.graph.edges.map((edge) => ({ relationship: edge.relationship, confidence: Number(edge.confidence ?? 0), leftType: edge.left_type, rightType: edge.right_type })), relatedSubjects: graphScoreInfo.relatedSubjects.map((subject) => ({ subjectId: subject.subjectId, sharedResources: subject.sharedResources, confidence: subject.confidence })) });
    if (fraudGraphInfo.score > 0) {
      signals.push({ signalName: "graph_connection_risk", source: "graph_correlation", score: fraudGraphInfo.score, confidence: fraudGraphInfo.confidence, evidence: { reasonCodes: fraudGraphInfo.reasonCodes, highConfidenceEdgeCount: fraudGraphInfo.highConfidenceEdgeCount, independentRelationshipCount: fraudGraphInfo.independentRelationshipCount, correlatedSubjectCount: fraudGraphInfo.correlatedSubjectCount, multiResourceSubjectCount: fraudGraphInfo.multiResourceSubjectCount, legacyConnectionScore: graphScoreInfo.connectionScore, version: fraudGraphInfo.version } });
      fraudDecisionFloor = enforceFraudFloor(fraudDecisionFloor, fraudGraphInfo.score, fraudGraphInfo.confidence);
    }
  }
  const deterministicScore = aggregateRisk(signals);
  let aiAdvisorySignal: Signal | null = null;
  if (env.OPENROUTER_ENABLED === "true" && env.OPENROUTER_API_KEY) {
    try {
      const ai = await analyzeWithAI({ tenantId: input.tenantId, subjectId: input.subjectId, sessionId: input.sessionId, apiKey: env.OPENROUTER_API_KEY, model: env.OPENROUTER_MODEL, evidence: buildAIAdvisoryEvidence({ deterministicScore, signals }) });
      aiAdvisorySignal = { signalName: "ai_advisory", source: "ai_advisory", score: ai.riskScore, confidence: Math.min(0.5, ai.confidence * 0.5), evidence: { riskLevel: ai.riskLevel, reasonCodes: ai.reasonCodes, recommendedAction: ai.recommendedAction, predictionId: ai.predictionId } };
    } catch (error) { securityLog("ai_advisory_failed", { requestId: input.requestId ?? null, tenantId: input.tenantId, errorCode: safeErrorCode(error), ...(safeErrorStatus(error) ? { errorStatus: safeErrorStatus(error) } : {}) }); }
  }
  const prePolicyScore = deterministicScore;
  const prePolicyDecision = decisionFor(prePolicyScore);
  const latestValueSignal = signals.find((signal) => signal.signalName === "value_jump_anomaly");
  const policyResult = await evaluateTenantPolicies(input.tenantId, { score: prePolicyScore, riskLevel: riskLevelFor(prePolicyScore), decision: prePolicyDecision, signalNames: signals.map((signal) => signal.signalName), velocity, valueJumpScore: latestValueSignal?.score ?? 0, relatedSubjectCount: graphScoreInfo?.relatedSubjectCount ?? 0 });
  const knownSubjectStatus = subjectResult.data?.status;
  const firewallSubjectStatus = knownSubjectStatus === "active" || knownSubjectStatus === "suspended" || knownSubjectStatus === "blocked" || knownSubjectStatus === "deleted" ? knownSubjectStatus : "unknown";
  const firewallResult = evaluateDefenseInDepth({ score: prePolicyScore, subjectStatus: firewallSubjectStatus, signals: signals.map((signal) => ({ signalName: signal.signalName, source: signal.source, score: signal.score, confidence: signal.confidence, evidence: signal.evidence })) });
  const firewallSignals: Signal[] = firewallResult.layers.filter((item) => item.action !== "ALLOW").map((item) => ({ signalName: `firewall_${item.layer}`, source: "firewall", score: item.score, confidence: item.confidence, evidence: { action: item.action, reasonCodes: item.reasonCodes, version: firewallResult.version } }));
  const finalSignals = [...signals, ...firewallSignals, ...(aiAdvisorySignal ? [aiAdvisorySignal] : [])];
  const policyDecisionFloor = policyResult.decisionOverride ? scoreFloorForDecision(policyResult.decisionOverride) : 0;
  const rank: Record<SecurityDecision, number> = { ALLOW: 0, MONITOR: 1, CHALLENGE: 2, REVIEW: 3, BLOCK: 4 };
  const requiredFloor = rank[fraudDecisionFloor] > rank[firewallResult.minimumDecision] ? fraudDecisionFloor : firewallResult.minimumDecision;
  const score = clamp(Math.max(prePolicyScore + policyResult.scoreDelta, scoreFloorForDecision(requiredFloor), policyDecisionFloor));
  const scoreDecision = decisionFor(score);
  const decisionCandidates: SecurityDecision[] = [scoreDecision, firewallResult.minimumDecision, fraudDecisionFloor];
  if (policyResult.decisionOverride) decisionCandidates.push(policyResult.decisionOverride);
  const decision = decisionCandidates.reduce((best, candidate) => rank[candidate] > rank[best] ? candidate : best, "ALLOW" as SecurityDecision);
  const riskLevel = riskLevelFor(score);
  const policyReasonCodes = policyResult.matched.map((policy) => policy.reasonCode);
  const challengeRecommendation = decision === "CHALLENGE" ? firewallResult.recommendedChallenge ?? { type: "risk_based_verification" as const, reasonCodes: policyReasonCodes.length ? policyReasonCodes : ["RISK_THRESHOLD_CHALLENGE"], expiresInSeconds: 300 } : null;
  const firewallAudit = { version: firewallResult.version, minimumDecision: firewallResult.minimumDecision, fraudDecisionFloor, reasonCodes: firewallResult.reasonCodes, layers: firewallResult.layers.map((item) => ({ layer: item.layer, action: item.action, score: item.score, confidence: item.confidence, reasonCodes: item.reasonCodes })) };
  securityLog("security_check", { requestId: input.requestId ?? null, tenantId: input.tenantId, subjectId: input.subjectId ?? null, score, decision, signalCount: finalSignals.length, policyMatches: policyResult.matched.length, firewallMinimumDecision: firewallResult.minimumDecision, firewallEscalations: firewallSignals.length });
  const assessmentInsert = await supabase.schema("security").from("risk_assessments").insert({ tenant_id: input.tenantId, subject_id: input.subjectId ?? null, session_id: input.sessionId ?? null, score, risk_level: riskLevel, assessment_version: "defense-in-depth-v1", explanation: { requestId: input.requestId ?? null, signalCount: finalSignals.length, sources: finalSignals.map((signal) => signal.source), aggregation: "weighted_evidence_v2", policies: policyResult.matched.map((policy) => ({ id: policy.id, name: policy.name, reasonCode: policy.reasonCode })), policyCount: policyResult.policyCount, firewall: firewallAudit, challengeRecommendation } }).select("id").single();
  if (assessmentInsert.error) throw assessmentInsert.error;
  if (finalSignals.length > 0) {
    const signalInsert = await supabase.schema("security").from("risk_signals").insert(finalSignals.map((signal) => ({ assessment_id: assessmentInsert.data.id, signal_name: signal.signalName, source: signal.source, score: signal.score, confidence: signal.confidence, evidence: signal.evidence })));
    if (signalInsert.error) throw signalInsert.error;
  }
  const decisionInsert = await supabase.schema("security").from("risk_decisions").insert({ assessment_id: assessmentInsert.data.id, decision, reason_codes: [...finalSignals.map((signal) => signal.signalName), ...policyReasonCodes, ...firewallResult.reasonCodes, ...(fraudDecisionFloor !== "ALLOW" ? ["FRAUD_INTELLIGENCE_ESCALATION"] : [])], decision_version: "defense-in-depth-v1" }).select("id").single();
  if (decisionInsert.error) throw decisionInsert.error;
  if (input.requestId) {
    const auditInsert = await supabase.schema("security").from("audit_events").insert({ tenant_id: input.tenantId, actor_type: "system", action: "security_check", resource_type: "risk_assessment", resource_id: assessmentInsert.data.id, request_id: input.requestId, details: { decision, score, riskLevel, version: "defense-in-depth-v1", policyMatches: policyResult.matched.map((policy) => policy.id), firewallMinimumDecision: firewallResult.minimumDecision, fraudDecisionFloor, firewallReasonCodes: firewallResult.reasonCodes } });
    if (auditInsert.error) throw auditInsert.error;
  }
  const ledgerAppend = await supabase.schema("security").rpc("append_security_ledger_entry", { p_tenant_id: input.tenantId, p_action: "risk_assessment_decided", p_resource_type: "risk_assessment", p_resource_id: assessmentInsert.data.id, p_request_id: input.requestId ?? null, p_actor_type: "system", p_details: { subjectId: input.subjectId ?? null, sessionId: input.sessionId ?? null, decision, score, riskLevel, assessmentVersion: "defense-in-depth-v1", firewallMinimumDecision: firewallResult.minimumDecision, firewallReasonCodes: firewallResult.reasonCodes, signalNames: finalSignals.map((signal) => signal.signalName).slice(0, 128) } });
  if (ledgerAppend.error) { securityLog("security_ledger_append_failed", { requestId: input.requestId ?? null, tenantId: input.tenantId, errorCode: safeErrorCode(ledgerAppend.error), ...(safeErrorStatus(ledgerAppend.error) ? { errorStatus: safeErrorStatus(ledgerAppend.error) } : {}) }); throw new Error("SECURITY_LEDGER_APPEND_FAILED"); }
  const backgroundTasks: Promise<unknown>[] = [enqueueSecurityEvent({ tenantId: input.tenantId, eventType: "security.risk_assessment.created", aggregateId: assessmentInsert.data.id, dedupeKey: input.requestId ? `risk:${input.requestId}` : assessmentInsert.data.id, payload: { assessmentId: assessmentInsert.data.id, subjectId: input.subjectId ?? null, sessionId: input.sessionId ?? null, score, riskLevel, decision, signalNames: finalSignals.map((signal) => signal.signalName), firewallMinimumDecision: firewallResult.minimumDecision, fraudDecisionFloor, firewallReasonCodes: firewallResult.reasonCodes } })];
  if (input.subjectId && (score >= 70 || decision === "BLOCK" || decision === "REVIEW")) backgroundTasks.push(ensureInvestigationCase({ tenantId: input.tenantId, subjectId: input.subjectId, assessmentId: assessmentInsert.data.id, score, decision, evidence: { signalNames: finalSignals.map((signal) => signal.signalName), policyMatches: policyReasonCodes, firewall: firewallAudit } }));
  if (input.subjectId && graphScoreInfo && graphScoreInfo.relatedSubjects.length >= 2) backgroundTasks.push(upsertFraudCluster({ tenantId: input.tenantId, clusterType: "mixed", subjectIds: [input.subjectId, ...graphScoreInfo.relatedSubjects.map((subject) => subject.subjectId)], riskScore: graphScoreInfo.connectionScore, evidence: { relatedSubjectCount: graphScoreInfo.relatedSubjectCount, riskyConnectionCount: graphScoreInfo.riskyConnectionCount, version: "fraud-clusters-v1" } }));
  const analyticsEventRows: Array<{ subjectId?: string; sessionId?: string; eventType: string; occurredAt: string; valueDelta?: number; botScore?: number; behaviorScore?: number; valueEventId?: string }> = (velocityResult.data ?? []).map((event) => ({ subjectId: input.subjectId, sessionId: input.sessionId, eventType: event.event_type, occurredAt: event.occurred_at, ...(event.anomaly_score === null || event.anomaly_score === undefined ? {} : { behaviorScore: clamp(Number(event.anomaly_score)) }) }));
  for (const botEvent of botResult.data ?? []) analyticsEventRows.push({ subjectId: input.subjectId, sessionId: input.sessionId, eventType: "bot_detection", occurredAt: botEvent.observed_at, botScore: botEvent.is_bot ? clamp(Math.round(Number(botEvent.confidence ?? 0) * 100)) : 0 });
  if (valueAnomaly && input.subjectId) {
    const valueEvidence = valueAnomaly.evidence as Record<string, unknown>;
    const valueDelta = Number(valueEvidence.delta);
    if (Number.isFinite(valueDelta)) analyticsEventRows.push({ subjectId: input.subjectId, sessionId: input.sessionId, eventType: "value_change", occurredAt: valueAnomaly.occurred_at, valueDelta, valueEventId: valueAnomaly.source_event_id ?? undefined, behaviorScore: 0 });
  }
  if (env.DUCKDB_ANALYTICS_URL && env.DUCKDB_ANALYTICS_TOKEN && analyticsEventRows.length > 0) {
    const minuteBucket = Math.floor(Date.now() / 60_000);
    const bucketKey = input.sessionId ?? input.subjectId ?? assessmentInsert.data.id;
    backgroundTasks.push(enqueueSecurityEvent({ tenantId: input.tenantId, eventType: "analytics.duckdb_batch", aggregateId: bucketKey, dedupeKey: `duckdb:${bucketKey}:${minuteBucket}`, payload: { tenantId: input.tenantId, events: analyticsEventRows.slice(-500) } }));
  }
  const settled = await Promise.allSettled(backgroundTasks);
  for (const item of settled) if (item.status === "rejected") securityLog("security_background_task_failed", { requestId: input.requestId ?? null, tenantId: input.tenantId, errorCode: item.reason instanceof Error ? item.reason.name : "UNKNOWN_ERROR" });
  return { decision, score, riskLevel, assessmentId: assessmentInsert.data.id, challengeRecommendation };
}
