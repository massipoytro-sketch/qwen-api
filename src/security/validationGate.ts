import { evaluateDefenseInDepth, type FirewallSignal } from "./firewall";
import type { SecurityDecision } from "./types";

export type ValidationScenario = {
  name: string;
  score: number;
  subjectStatus?: "active" | "suspended" | "blocked" | "deleted" | "unknown";
  signals: FirewallSignal[];
  expectedMinimumDecision: SecurityDecision;
};

export type ValidationFailure = {
  scenario: string;
  invariant: string;
  observed: string;
};

export type ValidationReport = {
  version: "security-validation-v1";
  passed: boolean;
  scenarios: number;
  failures: ValidationFailure[];
};

const rank: Record<SecurityDecision, number> = {
  ALLOW: 0,
  MONITOR: 1,
  CHALLENGE: 2,
  REVIEW: 3,
  BLOCK: 4,
};

function decisionFromScore(score: number): SecurityDecision {
  if (score >= 90) return "BLOCK";
  if (score >= 70) return "REVIEW";
  if (score >= 40) return "CHALLENGE";
  if (score > 0) return "MONITOR";
  return "ALLOW";
}

function validateScenario(scenario: ValidationScenario): ValidationFailure[] {
  const failures: ValidationFailure[] = [];
  let result;
  try {
    result = evaluateDefenseInDepth(scenario);
  } catch (error) {
    failures.push({ scenario: scenario.name, invariant: "scenario_must_parse", observed: error instanceof Error ? error.name : "UNKNOWN_ERROR" });
    return failures;
  }

  if (rank[result.minimumDecision] < rank[scenario.expectedMinimumDecision]) {
    failures.push({ scenario: scenario.name, invariant: "minimum_decision_must_not_be_weaker_than_expected", observed: result.minimumDecision });
  }

  const scoreDecision = decisionFromScore(scenario.score);
  if (rank[result.minimumDecision] < rank[scoreDecision]) {
    failures.push({ scenario: scenario.name, invariant: "firewall_must_not_relax_base_score", observed: result.minimumDecision });
  }

  if (result.layers.length !== 8) {
    failures.push({ scenario: scenario.name, invariant: "all_eight_firewall_layers_must_execute", observed: String(result.layers.length) });
  }

  if (result.minimumDecision === "CHALLENGE" && result.recommendedChallenge === null) {
    failures.push({ scenario: scenario.name, invariant: "challenge_requires_recommendation", observed: "null" });
  }

  if (result.minimumDecision !== "CHALLENGE" && result.recommendedChallenge !== null) {
    failures.push({ scenario: scenario.name, invariant: "non_challenge_must_not_issue_challenge", observed: result.recommendedChallenge.type });
  }

  for (const layer of result.layers) {
    if (!Number.isFinite(layer.score) || layer.score < 0 || layer.score > 100) {
      failures.push({ scenario: scenario.name, invariant: "layer_score_bounded", observed: String(layer.score) });
    }
    if (!Number.isFinite(layer.confidence) || layer.confidence < 0 || layer.confidence > 1) {
      failures.push({ scenario: scenario.name, invariant: "layer_confidence_bounded", observed: String(layer.confidence) });
    }
  }

  return failures;
}

export function runSecurityValidationGate(scenarios: ValidationScenario[]): ValidationReport {
  const failures = scenarios.flatMap(validateScenario);
  return {
    version: "security-validation-v1",
    passed: failures.length === 0,
    scenarios: scenarios.length,
    failures,
  };
}

export const DEFAULT_SECURITY_VALIDATION_SCENARIOS: ValidationScenario[] = [
  { name: "clean_request", score: 0, signals: [], expectedMinimumDecision: "ALLOW" },
  { name: "tor_only_is_monitor", score: 0, signals: [{ signalName: "network_risk", source: "network", score: 35, confidence: 0.9, evidence: { isTor: true } }], expectedMinimumDecision: "MONITOR" },
  { name: "impossible_travel_step_up", score: 0, signals: [{ signalName: "impossible_travel_detection", source: "network_intelligence", score: 80, confidence: 0.9, evidence: { trustedReputation: "unknown" } }], expectedMinimumDecision: "CHALLENGE" },
  { name: "strong_bot_challenge", score: 0, signals: [{ signalName: "advanced_bot_detection", source: "advanced_bot", score: 82, confidence: 0.9, evidence: { signalFlags: ["webdriver", "headless"] } }], expectedMinimumDecision: "CHALLENGE" },
  { name: "confirmed_automation_review", score: 0, signals: [{ signalName: "advanced_bot_detection", source: "advanced_bot", score: 99, confidence: 0.99, evidence: { signalFlags: ["webdriver", "headless", "automationFramework"] } }], expectedMinimumDecision: "REVIEW" },
  { name: "account_takeover_review", score: 0, signals: [{ signalName: "account_takeover_detection", source: "account_security", score: 95, confidence: 0.9 }], expectedMinimumDecision: "REVIEW" },
  { name: "blocked_subject", score: 0, subjectStatus: "blocked", signals: [], expectedMinimumDecision: "BLOCK" },
  { name: "database_boundary_block", score: 0, signals: [{ signalName: "tenant_isolation_violation", source: "database_integrity", score: 100, confidence: 1 }], expectedMinimumDecision: "BLOCK" },
  { name: "application_integrity_block", score: 0, signals: [{ signalName: "request_integrity_failure", source: "application_integrity", score: 100, confidence: 1 }], expectedMinimumDecision: "BLOCK" },
  { name: "fraud_graph_review", score: 0, signals: [{ signalName: "graph_connection_risk", source: "graph", score: 85, confidence: 0.9, evidence: { relatedSubjectCount: 5 } }], expectedMinimumDecision: "REVIEW" },
  { name: "score_floor_is_monotonic", score: 75, signals: [{ signalName: "network_risk", source: "network", score: 5, confidence: 0.9 }], expectedMinimumDecision: "REVIEW" },
  { name: "malformed_confidence_is_safe", score: 0, signals: [{ signalName: "network_risk", source: "network", score: 20, confidence: null }], expectedMinimumDecision: "MONITOR" },
];
