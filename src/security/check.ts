import { z } from "zod";
import { supabase } from "../db/supabase";
import type { SecurityCheckInput, SecurityCheckResult, SecurityDecision } from "./types";

const inputSchema = z.object({
  tenantId: z.uuid(),
  subjectId: z.uuid().optional(),
  sessionId: z.uuid().optional(),
  requestId: z.string().min(1).max(200).optional(),
});

type RiskLevel = SecurityCheckResult["riskLevel"];

const riskLevelFor = (score: number): RiskLevel => {
  if (score >= 90) return "critical";
  if (score >= 70) return "high";
  if (score >= 40) return "medium";
  if (score > 0) return "low";
  return "unknown";
};

const decisionFor = (score: number): SecurityDecision => {
  if (score >= 90) return "BLOCK";
  if (score >= 70) return "REVIEW";
  if (score >= 40) return "CHALLENGE";
  if (score > 0) return "MONITOR";
  return "ALLOW";
};

const clamp = (value: number) => Math.max(0, Math.min(100, value));

type Signal = {
  signalName: string;
  source: string;
  score: number;
  confidence: number | null;
  evidence: Record<string, unknown>;
};

const aggregateRisk = (signals: Signal[]) => {
  if (!signals.length) return 0;

  // Weighted evidence: strong independent signals reinforce each other,
  // while repeated evidence from one source is naturally bounded.
  const weighted = signals.reduce(
    (total, signal) => total + signal.score * (signal.confidence ?? 0.5),
    0,
  );

  const sourceBonus = Math.min(15, Math.max(0, new Set(signals.map((s) => s.source)).size - 1) * 5);
  const highSignalBonus = signals.filter((s) => s.score >= 70).length >= 2 ? 10 : 0;

  return clamp(Math.round(Math.min(100, weighted * 0.55 + sourceBonus + highSignalBonus)));
};

export async function securityCheck(rawInput: SecurityCheckInput): Promise<SecurityCheckResult> {
  const input = inputSchema.parse(rawInput);

  const [tenantResult, subjectResult, sessionResult] = await Promise.all([
    supabase.schema("security").from("tenants").select("id,status")
      .eq("id", input.tenantId).maybeSingle(),
    input.subjectId
      ? supabase.schema("security").from("subjects").select("id,status,risk_level")
          .eq("tenant_id", input.tenantId).eq("id", input.subjectId).maybeSingle()
      : Promise.resolve({ data: null, error: null }),
    input.sessionId
      ? supabase.schema("security").from("sessions").select("id,subject_id,device_id,ip_id")
          .eq("tenant_id", input.tenantId).eq("id", input.sessionId).maybeSingle()
      : Promise.resolve({ data: null, error: null }),
  ]);

  if (tenantResult.error) throw tenantResult.error;
  if (!tenantResult.data) throw new Error("TENANT_NOT_FOUND");
  if (tenantResult.data.status !== "active") throw new Error("TENANT_NOT_ACTIVE");
  if (subjectResult.error) throw subjectResult.error;
  if (sessionResult.error) throw sessionResult.error;
  if (input.subjectId && !subjectResult.data) throw new Error("SUBJECT_NOT_FOUND");
  if (input.sessionId && !sessionResult.data) throw new Error("SESSION_NOT_FOUND");

  const subjectRisk =
    subjectResult.data?.risk_level === "critical" ? 90 :
    subjectResult.data?.risk_level === "high" ? 70 :
    subjectResult.data?.risk_level === "medium" ? 40 :
    subjectResult.data?.risk_level === "low" ? 10 : 0;

  const deviceId = sessionResult.data?.device_id;
  const ipId = sessionResult.data?.ip_id;

  const [deviceResult, ipResult, botResult, behaviorResult] = await Promise.all([
    deviceId
      ? supabase.schema("security").from("devices").select("id,risk_score,confidence")
          .eq("tenant_id", input.tenantId).eq("id", deviceId).maybeSingle()
      : Promise.resolve({ data: null, error: null }),
    ipId
      ? supabase.schema("security").from("ip_addresses")
          .select("id,reputation_score,is_proxy,is_vpn,is_tor,is_datacenter")
          .eq("id", ipId).maybeSingle()
      : Promise.resolve({ data: null, error: null }),
    input.sessionId
      ? supabase.schema("security").from("bot_events").select("is_bot,confidence")
          .eq("tenant_id", input.tenantId).eq("session_id", input.sessionId)
          .order("observed_at", { ascending: false }).limit(1).maybeSingle()
      : Promise.resolve({ data: null, error: null }),
    input.sessionId
      ? supabase.schema("security").from("behavior_events").select("anomaly_score")
          .eq("tenant_id", input.tenantId).eq("session_id", input.sessionId)
          .order("occurred_at", { ascending: false }).limit(1).maybeSingle()
      : Promise.resolve({ data: null, error: null }),
  ]);

  for (const result of [deviceResult, ipResult, botResult, behaviorResult]) {
    if (result.error) throw result.error;
  }

  const signals: Signal[] = [];

  if (subjectRisk > 0) {
    signals.push({
      signalName: "subject_risk", source: "subject", score: subjectRisk, confidence: 1,
      evidence: { riskLevel: subjectResult.data?.risk_level },
    });
  }

  const deviceRisk = clamp(Number(deviceResult.data?.risk_score ?? 0));
  if (deviceRisk > 0) {
    signals.push({
      signalName: "device_risk", source: "device", score: deviceRisk,
      confidence: Number(deviceResult.data?.confidence ?? 0) || null, evidence: { deviceId },
    });
  }

  const ip = ipResult.data;
  if (ip) {
    const reputationPenalty = ip.reputation_score == null ? 0 : Math.max(0, 50 - Number(ip.reputation_score)) * 0.2;
    const networkPenalty = clamp(
      (ip.is_tor ? 35 : 0) + (ip.is_proxy ? 20 : 0) +
      (ip.is_vpn ? 15 : 0) + (ip.is_datacenter ? 20 : 0) + reputationPenalty,
    );

    if (networkPenalty > 0) {
      signals.push({
        signalName: "network_risk", source: "network", score: networkPenalty, confidence: 0.9,
        evidence: {
          isTor: ip.is_tor, isProxy: ip.is_proxy, isVpn: ip.is_vpn,
          isDatacenter: ip.is_datacenter, reputationScore: ip.reputation_score,
        },
      });
    }
  }

  const bot = botResult.data;
  if (bot?.is_bot) {
    const botScore = clamp(Number(bot.confidence ?? 1) * 100);
    signals.push({
      signalName: "bot_detection", source: "bot_detection", score: botScore,
      confidence: Number(bot.confidence ?? 1), evidence: { isBot: true },
    });
  }

  const anomalyScore = clamp(Number(behaviorResult.data?.anomaly_score ?? 0));
  if (anomalyScore > 0) {
    signals.push({
      signalName: "behavior_anomaly", source: "behavior", score: anomalyScore,
      confidence: 0.8, evidence: { anomalyScore },
    });
  }

  const score = aggregateRisk(signals);
  const riskLevel = riskLevelFor(score);
  const decision = decisionFor(score);

  const assessmentInsert = await supabase.schema("security").from("risk_assessments").insert({
    tenant_id: input.tenantId,
    subject_id: input.subjectId ?? null,
    session_id: input.sessionId ?? null,
    score,
    risk_level: riskLevel,
    assessment_version: "baseline-v2",
    explanation: {
      requestId: input.requestId ?? null,
      signalCount: signals.length,
      sources: signals.map((signal) => signal.source),
      aggregation: "weighted_evidence_v2",
    },
  }).select("id").single();

  if (assessmentInsert.error) throw assessmentInsert.error;

  if (signals.length > 0) {
    const signalInsert = await supabase.schema("security").from("risk_signals").insert(
      signals.map((signal) => ({
        assessment_id: assessmentInsert.data.id,
        signal_name: signal.signalName,
        source: signal.source,
        score: signal.score,
        confidence: signal.confidence,
        evidence: signal.evidence,
      })),
    );
    if (signalInsert.error) throw signalInsert.error;
  }

  const decisionInsert = await supabase.schema("security").from("risk_decisions").insert({
    assessment_id: assessmentInsert.data.id,
    decision,
    reason_codes: signals.map((signal) => signal.signalName),
    decision_version: "baseline-v2",
  });
  if (decisionInsert.error) throw decisionInsert.error;

  if (input.requestId) {
    const auditInsert = await supabase.schema("security").from("audit_events").insert({
      tenant_id: input.tenantId,
      actor_type: "system",
      action: "security_check",
      resource_type: "risk_assessment",
      resource_id: assessmentInsert.data.id,
      request_id: input.requestId,
      details: { decision, score, riskLevel, version: "baseline-v2" },
    });
    if (auditInsert.error) throw auditInsert.error;
  }

  return { decision, score, riskLevel, assessmentId: assessmentInsert.data.id };
}
