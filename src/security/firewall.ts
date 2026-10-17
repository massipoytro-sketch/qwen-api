import { z } from "zod";
import type { SecurityDecision } from "./types";

export const FIREWALL_LAYERS = [
  "network",
  "bot",
  "identity",
  "fraud",
  "behavior",
  "application",
  "database",
  "deception",
] as const;

export type FirewallLayer = (typeof FIREWALL_LAYERS)[number];
export type FirewallAction = SecurityDecision;
export type ChallengeType = "step_up_mfa" | "proof_of_work" | "risk_based_verification";

export type FirewallSignal = {
  signalName: string;
  source?: string;
  score: number;
  confidence?: number | null;
  evidence?: Record<string, unknown>;
};

export type FirewallLayerResult = {
  layer: FirewallLayer;
  action: FirewallAction;
  score: number;
  confidence: number;
  reasonCodes: string[];
};

export type DefenseInDepthResult = {
  version: "defense-in-depth-v1";
  minimumDecision: SecurityDecision;
  recommendedChallenge: {
    type: ChallengeType;
    reasonCodes: string[];
    expiresInSeconds: number;
  } | null;
  layers: FirewallLayerResult[];
  reasonCodes: string[];
};

const decisionRank: Record<SecurityDecision, number> = {
  ALLOW: 0,
  MONITOR: 1,
  CHALLENGE: 2,
  REVIEW: 3,
  BLOCK: 4,
};

const scoreDecision = (score: number): SecurityDecision =>
  score >= 90 ? "BLOCK" :
  score >= 70 ? "REVIEW" :
  score >= 40 ? "CHALLENGE" :
  score > 0 ? "MONITOR" : "ALLOW";

const clamp = (value: number) => Math.max(0, Math.min(100, Math.round(value)));
const finite = (value: unknown): value is number => typeof value === "number" && Number.isFinite(value);

const inputSchema = z.object({
  score: z.number().finite().min(0).max(100),
  subjectStatus: z.enum(["active", "suspended", "blocked", "deleted", "unknown"]).default("unknown"),
  signals: z.array(z.object({
    signalName: z.string().min(1).max(100),
    source: z.string().max(100).optional(),
    score: z.number().finite().min(0).max(100),
    confidence: z.number().finite().min(0).max(1).nullable().optional(),
    evidence: z.record(z.string(), z.unknown()).optional(),
  }).strict()).max(256),
}).strict();

function relevant(signals: FirewallSignal[], names: string[], sources: string[] = []) {
  return signals.filter((signal) =>
    names.includes(signal.signalName) || (signal.source !== undefined && sources.includes(signal.source))
  );
}

function topSignal(signals: FirewallSignal[]): FirewallSignal | null {
  if (!signals.length) return null;
  return [...signals].sort((a, b) => b.score - a.score)[0] ?? null;
}

function safeConfidence(signal: FirewallSignal | null): number {
  if (!signal || !finite(signal.confidence)) return signal ? 0.5 : 0;
  return Math.max(0, Math.min(1, signal.confidence));
}

function layer(
  name: FirewallLayer,
  action: FirewallAction,
  score = 0,
  confidence = 0,
  reasonCodes: string[] = [],
): FirewallLayerResult {
  return { layer: name, action, score: clamp(score), confidence: Math.max(0, Math.min(1, confidence)), reasonCodes };
}

/**
 * Evaluates independent defensive layers over normalized, server-derived signals.
 * A layer can only make the final decision more restrictive; no layer may relax
 * a decision made from risk score or another layer. VPN/proxy/Tor indicators
 * alone are never treated as proof of fraud.
 */
export function evaluateDefenseInDepth(rawInput: {
  score: number;
  subjectStatus?: "active" | "suspended" | "blocked" | "deleted" | "unknown";
  signals: FirewallSignal[];
}): DefenseInDepthResult {
  const input = inputSchema.parse({
    score: rawInput.score,
    subjectStatus: rawInput.subjectStatus ?? "unknown",
    signals: rawInput.signals,
  });
  const signals = input.signals as FirewallSignal[];
  const layers: FirewallLayerResult[] = [];

  const networkSignal = topSignal(relevant(
    signals,
    ["network_risk", "impossible_travel_detection", "ip_reputation_risk", "asn_reputation_risk"],
    ["network", "network_intelligence"],
  ));
  if (networkSignal) {
    const isTravel = networkSignal.signalName === "impossible_travel_detection";
    const confidence = safeConfidence(networkSignal);
    const action: FirewallAction =
      isTravel && networkSignal.score >= 70 && confidence >= 0.75 ? "CHALLENGE" :
      networkSignal.score >= 85 && confidence >= 0.9 && networkSignal.evidence?.trustedReputation === "malicious" ? "REVIEW" :
      networkSignal.score > 0 ? "MONITOR" : "ALLOW";
    layers.push(layer("network", action, networkSignal.score, confidence, [
      ...(isTravel && action === "CHALLENGE" ? ["IMPOSSIBLE_TRAVEL_STEP_UP"] : []),
      ...(!isTravel && networkSignal.score > 0 ? ["NETWORK_REPUTATION_SIGNAL"] : []),
    ]));
  } else {
    layers.push(layer("network", "ALLOW"));
  }

  const botSignal = topSignal(relevant(
    signals,
    ["advanced_bot_detection", "analytics_bot_anomaly", "bot_detection"],
    ["advanced_bot", "bot", "duckdb_analytics"],
  ));
  if (botSignal) {
    const confidence = safeConfidence(botSignal);
    const strongClientFlags = Array.isArray(botSignal.evidence?.signalFlags)
      ? botSignal.evidence.signalFlags.filter((value): value is string =>
          value === "webdriver" || value === "headless" || value === "automationFramework" ||
          value === "knownBotUserAgent" || value === "impossibleTiming" || value === "tamperedClient").length
      : 0;
    const action: FirewallAction =
      botSignal.score >= 98 && confidence >= 0.95 && strongClientFlags >= 2 ? "REVIEW" :
      botSignal.score >= 75 && confidence >= 0.7 ? "CHALLENGE" :
      botSignal.score >= 45 ? "MONITOR" : "ALLOW";
    layers.push(layer("bot", action, botSignal.score, confidence, [
      ...(action === "CHALLENGE" || action === "REVIEW" ? ["AUTOMATION_RISK_STEP_UP"] : []),
      ...(action === "MONITOR" ? ["BOT_SIGNAL_MONITORED"] : []),
    ]));
  } else {
    layers.push(layer("bot", "ALLOW"));
  }

  const accountSignal = topSignal(relevant(signals, [
    "account_takeover_detection",
    "concurrent_session_anomaly",
    "subject_status_suspended",
    "subject_status_block",
  ], ["account_security", "session_integrity"]));
  if (input.subjectStatus === "blocked" || input.subjectStatus === "deleted" ||
      signals.some((signal) => signal.signalName === "subject_status_block")) {
    layers.push(layer("identity", "BLOCK", 100, 1, ["SUBJECT_STATUS_BLOCKED"]));
  } else if (input.subjectStatus === "suspended" ||
      signals.some((signal) => signal.signalName === "subject_status_suspended")) {
    layers.push(layer("identity", "REVIEW", 80, 1, ["SUBJECT_STATUS_SUSPENDED"]));
  } else if (accountSignal) {
    const confidence = safeConfidence(accountSignal);
    const action: FirewallAction =
      accountSignal.signalName === "account_takeover_detection" && accountSignal.score >= 90 && confidence >= 0.8 ? "REVIEW" :
      accountSignal.score >= 70 && confidence >= 0.65 ? "CHALLENGE" :
      accountSignal.score > 0 ? "MONITOR" : "ALLOW";
    layers.push(layer("identity", action, accountSignal.score, confidence, [
      ...(accountSignal.signalName === "account_takeover_detection" ? ["ACCOUNT_INTEGRITY_SIGNAL"] : []),
      ...(accountSignal.signalName === "concurrent_session_anomaly" ? ["SESSION_CONCURRENCY_SIGNAL"] : []),
    ]));
  } else {
    layers.push(layer("identity", "ALLOW"));
  }

  const fraudSignal = topSignal(relevant(signals, [
    "graph_connection_risk",
    "value_jump_anomaly",
    "analytics_velocity_anomaly",
    "analytics_anomaly",
  ], ["graph", "fraud"]));
  if (fraudSignal) {
    const confidence = safeConfidence(fraudSignal);
    const relatedCount = finite(fraudSignal.evidence?.relatedSubjectCount)
      ? fraudSignal.evidence.relatedSubjectCount : 0;
    const action: FirewallAction =
      fraudSignal.signalName === "attack_path_risk" && fraudSignal.score >= 85 && confidence >= 0.85 ? "REVIEW" :
      fraudSignal.signalName === "value_jump_anomaly" && fraudSignal.score >= 90 && confidence >= 0.8 ? "REVIEW" :
      fraudSignal.signalName === "graph_connection_risk" && fraudSignal.score >= 80 && relatedCount >= 3 ? "REVIEW" :
      fraudSignal.score >= 60 ? "MONITOR" : "ALLOW";
    layers.push(layer("fraud", action, fraudSignal.score, confidence, [
      ...(action === "REVIEW" ? ["CORRELATED_FRAUD_EVIDENCE"] : []),
      ...(action === "MONITOR" ? ["FRAUD_SIGNAL_MONITORED"] : []),
    ]));
  } else {
    layers.push(layer("fraud", "ALLOW"));
  }

  const behaviorSignal = topSignal(relevant(signals, [
    "behavior_anomaly",
    "behavior_baseline_deviation",
    "analytics_behavior_anomaly",
    "activity_velocity",
  ], ["behavior", "behavior_baseline", "velocity"]));
  if (behaviorSignal) {
    const confidence = safeConfidence(behaviorSignal);
    const action: FirewallAction =
      behaviorSignal.score >= 85 && confidence >= 0.85 ? "CHALLENGE" :
      behaviorSignal.score >= 60 ? "MONITOR" : "ALLOW";
    layers.push(layer("behavior", action, behaviorSignal.score, confidence, [
      ...(action === "CHALLENGE" ? ["BEHAVIOR_DEVIATION_STEP_UP"] : []),
      ...(action === "MONITOR" ? ["BEHAVIOR_SIGNAL_MONITORED"] : []),
    ]));
  } else {
    layers.push(layer("behavior", "ALLOW"));
  }

  const integritySignal = topSignal(relevant(signals, [
    "request_integrity_failure",
    "payload_integrity_violation",
  ], ["application_integrity"]));
  layers.push(integritySignal
    ? layer("application", "BLOCK", 100, safeConfidence(integritySignal), ["APPLICATION_INTEGRITY_FAILURE"])
    : layer("application", "ALLOW"));

  const databaseSignal = topSignal(relevant(signals, [
    "tenant_isolation_violation",
    "database_integrity_violation",
  ], ["database_integrity"]));
  layers.push(databaseSignal
    ? layer("database", "BLOCK", 100, safeConfidence(databaseSignal), ["DATABASE_TRUST_BOUNDARY_FAILURE"])
    : layer("database", "ALLOW"));

  const deceptionSignal = topSignal(relevant(signals, [
    "honeytrap_hit",
    "canary_asset_access",
    "deception_tripwire",
  ], ["deception", "honeydb"]));
  layers.push(deceptionSignal && deceptionSignal.score >= 70
    ? layer("deception", "REVIEW", deceptionSignal.score, safeConfidence(deceptionSignal), ["DECEPTION_TRIPWIRE_TRIGGERED"])
    : layer("deception", deceptionSignal ? "MONITOR" : "ALLOW", deceptionSignal?.score ?? 0, safeConfidence(deceptionSignal),
        deceptionSignal ? ["DECEPTION_SIGNAL_RECORDED"] : []));

  const minimumLayer = layers.reduce((best, current) =>
    decisionRank[current.action] > decisionRank[best.action] ? current : best,
  layers[0] ?? layer("network", "ALLOW"));
  const baseDecision = scoreDecision(input.score);
  const minimumDecision =
    decisionRank[minimumLayer.action] > decisionRank[baseDecision] ? minimumLayer.action : baseDecision;

  let recommendedChallenge: DefenseInDepthResult["recommendedChallenge"] = null;
  if (minimumDecision === "CHALLENGE") {
    const identity = layers.find((item) => item.layer === "identity" && item.action === "CHALLENGE");
    const bot = layers.find((item) => item.layer === "bot" && item.action === "CHALLENGE");
    const network = layers.find((item) => item.layer === "network" && item.action === "CHALLENGE");
    const type: ChallengeType = identity || network ? "step_up_mfa" :
      bot ? "proof_of_work" : "risk_based_verification";
    const source = identity ?? bot ?? network;
    recommendedChallenge = {
      type,
      reasonCodes: source?.reasonCodes.length ? source.reasonCodes : ["RISK_BASED_CHALLENGE"],
      expiresInSeconds: 300,
    };
  }

  const reasonCodes = [...new Set(layers.flatMap((item) => item.reasonCodes))].slice(0, 32);
  return {
    version: "defense-in-depth-v1",
    minimumDecision,
    recommendedChallenge,
    layers,
    reasonCodes,
  };
}

/** Converts a required decision into a score floor without ever reducing score. */
export function scoreFloorForDecision(decision: SecurityDecision): number {
  switch (decision) {
    case "MONITOR": return 1;
    case "CHALLENGE": return 40;
    case "REVIEW": return 70;
    case "BLOCK": return 90;
    case "ALLOW": return 0;
  }
}
