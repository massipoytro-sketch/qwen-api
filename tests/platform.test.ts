import { describe, expect, it } from "vitest";
import { analyzeAdvancedBotSignals, evaluatePolicySet, scoreBehaviorAgainstBaseline } from "../src/security/platform";
import type { SecurityPolicyContext } from "../src/security/platform";

const context = (overrides: Partial<SecurityPolicyContext> = {}): SecurityPolicyContext => ({
  score: 75,
  riskLevel: "high",
  decision: "REVIEW",
  signalNames: ["network_risk"],
  velocity: { count1m: 12, count5m: 22, count15m: 30 },
  valueJumpScore: 0,
  relatedSubjectCount: 0,
  ...overrides,
});

const blockPolicy = {
  id: "policy-1",
  name: "high-risk-review",
  priority: 10,
  conditions: { all: [{ field: "risk.score", operator: "gte", value: 70 }] },
  decision: "BLOCK" as const,
  score_delta: 5,
  reason_code: "HIGH_RISK_POLICY",
};

describe("tenant policy engine", () => {
  it("matches supported fields and adds an auditable reason", () => {
    const result = evaluatePolicySet(context(), [blockPolicy]);
    expect(result.matched).toEqual([{ id: "policy-1", name: "high-risk-review", reasonCode: "HIGH_RISK_POLICY" }]);
    expect(result.scoreDelta).toBe(5);
    expect(result.decisionOverride).toBe("BLOCK");
  });

  it("uses priority order deterministically and only applies the first match", () => {
    const result = evaluatePolicySet(context(), [
      { ...blockPolicy, id: "later", priority: 30, score_delta: 20 },
      { ...blockPolicy, id: "first", priority: 1, score_delta: 3 },
    ]);
    expect(result.matched.map((item) => item.id)).toEqual(["first"]);
    expect(result.scoreDelta).toBe(3);
  });

  it("cannot loosen an existing decision through an ALLOW policy", () => {
    const result = evaluatePolicySet(context({ score: 98, riskLevel: "critical", decision: "BLOCK" }), [
      { ...blockPolicy, decision: "ALLOW" as const, score_delta: -50 },
    ]);
    expect(result.decisionOverride).toBeNull();
  });

  it("ignores unsupported or malformed condition structures", () => {
    const result = evaluatePolicySet(context(), [
      { ...blockPolicy, conditions: { all: [{ field: "tenant.secret", operator: "eq", value: "x" }] } },
    ]);
    expect(result.matched).toHaveLength(0);
  });
});

describe("behavioral baseline scoring", () => {
  const baseline = {
    sample_count: 100,
    mean_value: 10,
    stddev_value: 10,
    p50_value: 10,
    p95_value: 25,
  };

  it("does not score when baseline has insufficient samples", () => {
    expect(scoreBehaviorAgainstBaseline(90, { ...baseline, sample_count: 10 }).baselineReady).toBe(false);
  });

  it("scores a strong deviation and reports detector confidence", () => {
    const result = scoreBehaviorAgainstBaseline(50, baseline);
    expect(result.baselineReady).toBe(true);
    expect(result.zScore).toBe(4);
    expect(result.score).toBeGreaterThanOrEqual(85);
    expect(result.confidence).toBeGreaterThan(0.5);
  });

  it("does not generate risk for a value close to baseline", () => {
    expect(scoreBehaviorAgainstBaseline(11, baseline).score).toBe(0);
  });
});

describe("advanced bot evidence fusion", () => {
  it("does not flag a quiet, non-bot session", () => {
    const now = Date.now();
    const result = analyzeAdvancedBotSignals({
      now,
      botEvents: [{ occurredAt: new Date(now - 5_000).toISOString(), isBot: false, confidence: 0.1, signals: {} }],
      activityEvents: [
        { occurredAt: new Date(now - 600_000).toISOString(), eventType: "view" },
        { occurredAt: new Date(now - 300_000).toISOString(), eventType: "scroll" },
      ],
    });
    expect(result.score).toBe(0);
    expect(result.reasonCodes).toHaveLength(0);
  });

  it("raises a strong signal for a recent high-confidence bot observation", () => {
    const now = Date.now();
    const result = analyzeAdvancedBotSignals({
      now,
      botEvents: [{
        occurredAt: new Date(now - 1_000).toISOString(),
        isBot: true,
        confidence: 0.95,
        signals: { webdriver: true, headless: true },
      }],
      activityEvents: [],
    });
    expect(result.score).toBeGreaterThanOrEqual(90);
    expect(result.reasonCodes).toContain("BOT_CLASSIFIER_SIGNAL");
    expect(result.signalFlags).toContain("webdriver");
  });
});
