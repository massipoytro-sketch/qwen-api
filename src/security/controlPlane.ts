import { createHash } from "node:crypto";
import type { SecurityDecision } from "./types";

export const SECURITY_STATES = [
  "TRUSTED",
  "MONITORED",
  "SUSPICIOUS",
  "CHALLENGE_REQUIRED",
  "QUARANTINED",
  "UNDER_REVIEW",
  "BLOCKED",
] as const;
export type SecurityState = (typeof SECURITY_STATES)[number];

export type ControlSignal = {
  signalName: string;
  source?: string;
  score: number;
  confidence?: number | null;
  reasonCodes?: string[];
  evidence?: Record<string, unknown>;
};

export type ControlPlaneInput = {
  tenantId: string;
  subjectId?: string;
  sessionId?: string;
  deviceId?: string;
  operation?: string;
  endpoint?: string;
  decision: SecurityDecision;
  score: number;
  signals: ControlSignal[];
  previousState?: SecurityState;
  emergencyMode?: "NORMAL" | "MAINTENANCE" | "LOCKDOWN" | "DENY_ALL";
  transaction?: {
    before?: number;
    after?: number;
    currency?: string;
    sensitive?: boolean;
  };
};

export type PolicyCondition = {
  minScore?: number;
  decisionIn?: SecurityDecision[];
  stateIn?: SecurityState[];
  operationIn?: string[];
  endpointIn?: string[];
  signalIn?: string[];
};

export type ControlPolicy = {
  id: string;
  priority: number;
  enabled: boolean;
  expiresAt?: string | null;
  condition: PolicyCondition;
  action: SecurityDecision | "QUARANTINE";
  reasonCode: string;
};

export type ControlPlaneResult = {
  version: "active-defense-v1";
  decision: SecurityDecision;
  state: SecurityState;
  quarantined: boolean;
  transactionRisk: number;
  deviceTrust: number;
  incident: {
    fingerprint: string;
    severity: "low" | "medium" | "high" | "critical";
    reasonCodes: string[];
  } | null;
  policyMatches: string[];
  enforcement: {
    operationAllowed: boolean;
    sensitiveOperationAllowed: boolean;
    requiredChallenge: boolean;
  };
  reasonCodes: string[];
};

const rank: Record<SecurityDecision, number> = { ALLOW: 0, MONITOR: 1, CHALLENGE: 2, REVIEW: 3, BLOCK: 4 };
const stateRank: Record<SecurityState, number> = {
  TRUSTED: 0,
  MONITORED: 1,
  SUSPICIOUS: 2,
  CHALLENGE_REQUIRED: 3,
  QUARANTINED: 4,
  UNDER_REVIEW: 5,
  BLOCKED: 6,
};
const clamp = (n: number) => Math.max(0, Math.min(100, Math.round(Number.isFinite(n) ? n : 0)));
const confidence = (s: ControlSignal) => Math.max(0, Math.min(1, Number.isFinite(s.confidence ?? NaN) ? Number(s.confidence) : 0.5));

function strongest(current: SecurityDecision, candidate: SecurityDecision): SecurityDecision {
  return rank[candidate] > rank[current] ? candidate : current;
}

function signalMax(signals: ControlSignal[], names: string[]): ControlSignal | null {
  const found = signals.filter((s) => names.includes(s.signalName));
  return found.length ? [...found].sort((a, b) => b.score - a.score)[0] ?? null : null;
}

function matches(policy: ControlPolicy, input: ControlPlaneInput, state: SecurityState): boolean {
  if (!policy.enabled) return false;
  if (policy.expiresAt && Date.parse(policy.expiresAt) <= Date.now()) return false;
  const c = policy.condition;
  if (c.minScore !== undefined && input.score < c.minScore) return false;
  if (c.decisionIn && !c.decisionIn.includes(input.decision)) return false;
  if (c.stateIn && !c.stateIn.includes(state)) return false;
  if (c.operationIn && (!input.operation || !c.operationIn.includes(input.operation))) return false;
  if (c.endpointIn && (!input.endpoint || !c.endpointIn.includes(input.endpoint))) return false;
  if (c.signalIn && !input.signals.some((s) => c.signalIn!.includes(s.signalName))) return false;
  return true;
}

export function simulatePolicies(input: ControlPlaneInput, policies: ControlPolicy[]): {
  decision: SecurityDecision;
  quarantine: boolean;
  matches: string[];
  reasonCodes: string[];
} {
  let decision = input.decision;
  let quarantine = false;
  const matchesFound: string[] = [];
  const reasonCodes: string[] = [];
  const initialState = input.previousState ?? "TRUSTED";
  for (const policy of [...policies].sort((a, b) => b.priority - a.priority)) {
    if (!matches(policy, input, initialState)) continue;
    matchesFound.push(policy.id);
    reasonCodes.push(policy.reasonCode);
    if (policy.action === "QUARANTINE") quarantine = true;
    else decision = strongest(decision, policy.action);
  }
  return { decision, quarantine, matches: matchesFound.slice(0, 64), reasonCodes: [...new Set(reasonCodes)].slice(0, 64) };
}

export function evaluateControlPlane(input: ControlPlaneInput, policies: ControlPolicy[] = []): ControlPlaneResult {
  const baseScore = clamp(input.score);
  const takeover = signalMax(input.signals, ["account_takeover_detection"]);
  const device = signalMax(input.signals, ["device_trust_risk", "new_device_risk", "device_change_anomaly"]);
  const bot = signalMax(input.signals, ["advanced_bot_detection", "analytics_bot_anomaly", "bot_detection"]);
  const network = signalMax(input.signals, ["network_risk", "impossible_travel_detection", "ip_reputation_risk"]);
  const fraud = signalMax(input.signals, ["graph_connection_risk", "value_jump_anomaly", "analytics_velocity_anomaly"]);
  const deception = signalMax(input.signals, ["honeytrap_hit", "canary_asset_access", "deception_tripwire"]);
  const integrity = signalMax(input.signals, ["request_integrity_failure", "tenant_isolation_violation", "database_integrity_violation"]);

  let transactionRisk = 0;
  if (input.transaction) {
    const before = Number(input.transaction.before ?? 0);
    const after = Number(input.transaction.after ?? before);
    if (Number.isFinite(before) && Number.isFinite(after) && after >= 0) {
      const jump = after > before ? ((after - before) / Math.max(1, Math.abs(before))) * 100 : 0;
      transactionRisk = clamp(Math.min(100, jump * 0.8 + (input.transaction.sensitive ? 20 : 0)));
    }
  }

  const deviceTrust = clamp(100 - ((device?.score ?? 0) * 0.75 + (device ? (1 - confidence(device)) * 25 : 0)));
  let decision = input.decision;
  const reasons: string[] = [];

  if (input.emergencyMode === "DENY_ALL") {
    decision = "BLOCK";
    reasons.push("EMERGENCY_DENY_ALL");
  } else if (input.emergencyMode === "LOCKDOWN") {
    decision = strongest(decision, "REVIEW");
    reasons.push("EMERGENCY_LOCKDOWN");
  }

  if (integrity && integrity.score >= 70) { decision = "BLOCK"; reasons.push("TRUST_BOUNDARY_VIOLATION"); }
  if (takeover && takeover.score >= 80 && confidence(takeover) >= 0.75) { decision = strongest(decision, "REVIEW"); reasons.push("ACCOUNT_TAKEOVER_ESCALATION"); }
  if (fraud && fraud.score >= 80 && confidence(fraud) >= 0.7) { decision = strongest(decision, "REVIEW"); reasons.push("FRAUD_CORRELATION_ESCALATION"); }
  if (transactionRisk >= 80) { decision = strongest(decision, "REVIEW"); reasons.push("TRANSACTION_RISK_ESCALATION"); }
  if (bot && bot.score >= 90 && confidence(bot) >= 0.85) { decision = strongest(decision, "CHALLENGE"); reasons.push("AUTOMATION_ESCALATION"); }
  if (network && network.score >= 80 && confidence(network) >= 0.8) { decision = strongest(decision, "CHALLENGE"); reasons.push("NETWORK_TRUST_ESCALATION"); }
  if (deception && deception.score >= 70) { decision = strongest(decision, "REVIEW"); reasons.push("DECEPTION_OBSERVATION"); }
  if (device && device.score >= 80) { decision = strongest(decision, "CHALLENGE"); reasons.push("DEVICE_TRUST_ESCALATION"); }

  const preliminaryState: SecurityState = decision === "BLOCK" ? "BLOCKED" :
    decision === "REVIEW" ? "UNDER_REVIEW" :
    decision === "CHALLENGE" ? "CHALLENGE_REQUIRED" :
    decision === "MONITOR" ? "MONITORED" : "TRUSTED";
  const policyResult = simulatePolicies({ ...input, decision, score: baseScore, previousState: input.previousState ?? preliminaryState }, policies);
  decision = strongest(decision, policyResult.decision);
  const quarantined = policyResult.quarantine || decision === "REVIEW" || decision === "BLOCK" ||
    (takeover !== null && takeover.score >= 90 && transactionRisk >= 60);

  let state: SecurityState = quarantined ? "QUARANTINED" :
    decision === "BLOCK" ? "BLOCKED" :
    decision === "REVIEW" ? "UNDER_REVIEW" :
    decision === "CHALLENGE" ? "CHALLENGE_REQUIRED" :
    decision === "MONITOR" ? "MONITORED" : "TRUSTED";
  const previous = input.previousState ?? "TRUSTED";
  if (stateRank[previous] > stateRank[state] && decision !== "ALLOW") state = previous;
  if (decision === "BLOCK") state = "BLOCKED";

  const reasonCodes = [...new Set([...reasons, ...policyResult.reasonCodes])].slice(0, 64);
  const sensitiveAllowed = !quarantined && !["REVIEW", "BLOCK"].includes(decision) &&
    !(input.transaction?.sensitive && transactionRisk >= 60);
  const operationAllowed = decision !== "BLOCK" && input.emergencyMode !== "DENY_ALL";
  const incidentNeeded = decision !== "ALLOW" || reasonCodes.length > 0;
  const severity = decision === "BLOCK" ? "critical" : decision === "REVIEW" ? "high" : decision === "CHALLENGE" ? "medium" : "low";
  const incident = incidentNeeded ? {
    fingerprint: createHash("sha256").update([
      input.tenantId,
      input.subjectId ?? "anonymous",
      input.operation ?? "unknown",
      ...[...new Set(reasonCodes)].sort(),
    ].join("\n")).digest("hex"),
    severity,
    reasonCodes,
  } : null;

  return {
    version: "active-defense-v1",
    decision,
    state,
    quarantined,
    transactionRisk,
    deviceTrust,
    incident,
    policyMatches: policyResult.matches,
    enforcement: {
      operationAllowed,
      sensitiveOperationAllowed: sensitiveAllowed,
      requiredChallenge: decision === "CHALLENGE",
    },
    reasonCodes,
  };
}
