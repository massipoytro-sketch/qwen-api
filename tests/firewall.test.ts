import { describe, expect, it } from "vitest";
import { evaluateDefenseInDepth, scoreFloorForDecision } from "../src/security/firewall";

const signal = (
  signalName: string,
  score: number,
  confidence: number,
  source = "test",
  evidence: Record<string, unknown> = {},
) => ({ signalName, score, confidence, source, evidence });

describe("defense-in-depth firewall", () => {
  it("keeps all layers explicit when no risk signals are present", () => {
    const result = evaluateDefenseInDepth({ score: 0, signals: [] });
    expect(result.minimumDecision).toBe("ALLOW");
    expect(result.layers.map((item) => item.layer)).toEqual([
      "network", "bot", "identity", "fraud", "behavior", "application", "database", "deception",
    ]);
    expect(result.recommendedChallenge).toBeNull();
  });

  it("does not block solely because of proxy, VPN, or Tor indicators", () => {
    const result = evaluateDefenseInDepth({
      score: 10,
      signals: [signal("network_risk", 70, 0.9, "network", { isProxy: true, isVpn: true, isTor: true })],
    });
    expect(result.minimumDecision).toBe("MONITOR");
    expect(result.layers.find((item) => item.layer === "network")?.action).toBe("MONITOR");
  });

  it("recommends step-up verification for strong account takeover evidence", () => {
    const result = evaluateDefenseInDepth({
      score: 15,
      signals: [signal("account_takeover_detection", 95, 0.9, "account_security")],
    });
    expect(result.minimumDecision).toBe("REVIEW");
    expect(result.recommendedChallenge).toBeNull();
    expect(result.reasonCodes).toContain("ACCOUNT_INTEGRITY_SIGNAL");
  });

  it("recommends proof of work for a high-confidence bot signal", () => {
    const result = evaluateDefenseInDepth({
      score: 10,
      signals: [signal("advanced_bot_detection", 88, 0.9, "advanced_bot")],
    });
    expect(result.minimumDecision).toBe("CHALLENGE");
    expect(result.recommendedChallenge?.type).toBe("proof_of_work");
    expect(result.recommendedChallenge?.expiresInSeconds).toBe(300);
  });

  it("escalates highly correlated fraud connections to review, not blind automatic guilt", () => {
    const result = evaluateDefenseInDepth({
      score: 20,
      signals: [signal("graph_connection_risk", 86, 0.85, "graph", { relatedSubjectCount: 4 })],
    });
    expect(result.minimumDecision).toBe("REVIEW");
    expect(result.reasonCodes).toContain("CORRELATED_FRAUD_EVIDENCE");
  });

  it("blocks a subject whose server-side account status is blocked", () => {
    const result = evaluateDefenseInDepth({
      score: 0,
      subjectStatus: "blocked",
      signals: [],
    });
    expect(result.minimumDecision).toBe("BLOCK");
    expect(scoreFloorForDecision(result.minimumDecision)).toBe(90);
  });

  it("blocks explicit application-integrity or database-isolation violations", () => {
    const app = evaluateDefenseInDepth({
      score: 0,
      signals: [signal("payload_integrity_violation", 100, 1, "application_integrity")],
    });
    const db = evaluateDefenseInDepth({
      score: 0,
      signals: [signal("tenant_isolation_violation", 100, 1, "database_integrity")],
    });
    expect(app.minimumDecision).toBe("BLOCK");
    expect(db.minimumDecision).toBe("BLOCK");
  });

  it("does not allow invalid confidence or scores to poison the evaluator", () => {
    expect(() => evaluateDefenseInDepth({
      score: 0,
      signals: [signal("advanced_bot_detection", Number.NaN, 1)],
    })).toThrow();
  });

  it("uses risk-based challenge only when no specialized layer owns the challenge", () => {
    const result = evaluateDefenseInDepth({
      score: 55,
      signals: [signal("behavior_anomaly", 70, 0.8, "behavior")],
    });
    expect(result.minimumDecision).toBe("CHALLENGE");
    expect(result.recommendedChallenge?.type).toBe("risk_based_verification");
  });
});
