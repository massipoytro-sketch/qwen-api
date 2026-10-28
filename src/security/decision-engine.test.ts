import { describe, expect, it } from "vitest";
import { recommendSecurityAction, type DecisionInput } from "./decision-engine";
import { aggregateAIShadowPredictions } from "./ai-lab";

const baseInput = (overrides: Partial<DecisionInput> = {}): DecisionInput => ({
  subjectRef: "test-subject",
  deterministic: { identityRisk: 10, behaviorRisk: 10, graphRisk: 10, transactionRisk: 10, accountHistoryRisk: 10 },
  controls: { hardBlock: false, globalLockdown: false, transactionFirewallDenied: false, verifiedChallengePassed: false },
  policyVersion: "test-policy-v1",
  ...overrides,
});

describe("Part 7 recommendation engine", () => {
  it("returns a recommendation without side effects", () => {
    const result = recommendSecurityAction(baseInput());
    expect(result.action).toBe("ALLOW");
    expect(result.recommendationOnly).toBe(true);
    expect(result.sideEffectsPerformed).toBe(false);
  });

  it("gives global lockdown precedence", () => {
    const result = recommendSecurityAction(baseInput({
      controls: { hardBlock: false, globalLockdown: true, transactionFirewallDenied: false, verifiedChallengePassed: false },
    }));
    expect(result.action).toBe("LOCKDOWN");
    expect(result.reasonCodes).toContain("GLOBAL_LOCKDOWN_ACTIVE");
  });

  it("never lets AI weaken a deterministic hard block", () => {
    const ai = aggregateAIShadowPredictions([{
      modelId: "pyod-optimized-ensemble", score: 0, confidence: 1,
      available: true, latencyMs: 1, reasonCodes: [],
    }]);
    const result = recommendSecurityAction(baseInput({
      ai,
      controls: { hardBlock: true, globalLockdown: false, transactionFirewallDenied: false, verifiedChallengePassed: false },
    }));
    expect(result.action).toBe("BLOCK");
  });

  it("never overrides a transaction firewall denial", () => {
    const result = recommendSecurityAction(baseInput({
      controls: { hardBlock: false, globalLockdown: false, transactionFirewallDenied: true, verifiedChallengePassed: false },
    }));
    expect(result.action).toBe("DENY_TRANSACTION");
  });

  it("caps AI contribution so AI alone cannot trigger a restrictive action", () => {
    const ai = aggregateAIShadowPredictions([{
      modelId: "pyod-optimized-ensemble", score: 100, confidence: 1,
      available: true, latencyMs: 1, reasonCodes: ["test"],
    }]);
    const result = recommendSecurityAction(baseInput({ ai }));
    expect(result.aiContribution).toBe(15);
    expect(result.riskScore).toBeLessThan(25);
    expect(result.action).toBe("ALLOW");
  });

  it("ignores AI when every model is unavailable", () => {
    const ai = aggregateAIShadowPredictions([{
      modelId: "pyod-optimized-ensemble", score: 100, confidence: 1,
      available: false, latencyMs: 1, reasonCodes: [],
    }]);
    const result = recommendSecurityAction(baseInput({ ai }));
    expect(result.aiContribution).toBe(0);
    expect(result.reasonCodes).toContain("AI_NOT_USED");
  });

  it("requires human review for critical deterministic risk", () => {
    const result = recommendSecurityAction(baseInput({
      deterministic: { identityRisk: 100, behaviorRisk: 100, graphRisk: 100, transactionRisk: 100, accountHistoryRisk: 100 },
    }));
    expect(result.action).toBe("HUMAN_REVIEW");
    expect(result.requiresHumanApproval).toBe(true);
  });

  it("rejects invalid risk values", () => {
    expect(() => recommendSecurityAction(baseInput({
      deterministic: { identityRisk: 101, behaviorRisk: 0, graphRisk: 0, transactionRisk: 0, accountHistoryRisk: 0 },
    }))).toThrow();
  });
});
