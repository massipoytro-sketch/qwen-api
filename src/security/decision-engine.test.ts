import { describe, expect, it } from "vitest";
import { recommendSecurityAction, type DecisionInput } from "./decision-engine";
import { aggregateAIShadowPredictions } from "./ai-lab";

const baseInput = (overrides: Partial<DecisionInput> = {}): DecisionInput => ({
  subjectRef: "test-subject",
  deterministic: { identityRisk: 10, behaviorRisk: 10, graphRisk: 10, transactionRisk: 10, accountHistoryRisk: 10 },
  signals: {},
  controls: { hardBlock: false, globalLockdown: false, transactionFirewallDenied: false, verifiedChallengePassed: false },
  policyVersion: "test-policy-v1",
  ...overrides,
});

describe("Part 7A recommendation engine", () => {
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

  it("treats VPN as an access challenge, never as fraud proof", () => {
    const result = recommendSecurityAction(baseInput({ signals: { vpnDetected: true } }));
    expect(result.action).toBe("CHALLENGE");
    expect(result.reasonCodes).toContain("VPN_DETECTED_ACCESS_RESTRICTION");
    expect(result.reasonCodes).toContain("DISABLE_VPN_PROXY_TOR_TO_CONTINUE");
  });

  it("treats proxy/Tor as access conditions, not automatic bans", () => {
    const result = recommendSecurityAction(baseInput({ signals: { proxyDetected: true, torDetected: true } }));
    expect(result.action).toBe("CHALLENGE");
    expect(result.action).not.toBe("PERMANENT_BAN");
  });

  it("does not punish a fingerprint change by itself", () => {
    const result = recommendSecurityAction(baseInput({ signals: { fingerprintChanged: true } }));
    expect(result.action).toBe("ALLOW");
    expect(result.reasonCodes).toContain("FINGERPRINT_CHANGED_NOT_FRAUD_PROOF");
  });

  it("holds a confirmed duplicate account for review rather than deleting the primary automatically", () => {
    const result = recommendSecurityAction(baseInput({ signals: { duplicateAccountConfirmed: true } }));
    expect(result.action).toBe("HOLD_REWARDS");
    expect(result.requiresHumanApproval).toBe(true);
    expect(result.reasonCodes).toContain("SECONDARY_ACCOUNT_RESTRICTED_PENDING_REVIEW");
  });

  it("does not permanently ban a merely suspected duplicate account", () => {
    const result = recommendSecurityAction(baseInput({ signals: { duplicateAccountSuspected: true } }));
    expect(result.action).not.toBe("PERMANENT_BAN");
    expect(result.reasonCodes).toContain("DUPLICATE_ACCOUNT_REQUIRES_REVIEW");
  });

  it("holds rewards for confirmed reward fraud or malicious automation", () => {
    const result = recommendSecurityAction(baseInput({ signals: { rewardFraudConfirmed: true } }));
    expect(result.action).toBe("HOLD_REWARDS");
    expect(result.requiresHumanApproval).toBe(true);
  });

  it("holds activity for a confirmed unsuccessful security-abuse attempt", () => {
    const result = recommendSecurityAction(baseInput({ signals: { securityAbuseAttemptConfirmed: true } }));
    expect(result.action).toBe("HOLD_REWARDS");
    expect(result.requiresHumanApproval).toBe(true);
    expect(result.action).not.toBe("PERMANENT_BAN");
  });

  it("requires human approval for confirmed credential/cookie theft or successful compromise", () => {
    const result = recommendSecurityAction(baseInput({ signals: { credentialOrCookieTheftConfirmed: true } }));
    expect(result.action).toBe("PERMANENT_BAN");
    expect(result.requiresHumanApproval).toBe(true);
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
