import { describe, expect, it } from "vitest";
import { evaluatePart7, isHardSecurityAction } from "./part7-integration-v2";

const base = {
  subjectRef: "subject-1",
  deterministic: { identityRisk: 0, behaviorRisk: 0, graphRisk: 0, transactionRisk: 0, accountHistoryRisk: 0 },
  signals: {},
  controls: { hardBlock: false, globalLockdown: false, transactionFirewallDenied: false, verifiedChallengePassed: false },
  policyVersion: "test-v1",
  nowMs: 1_000,
};

describe("Part 7C integration", () => {
  it("allows a clean subject without side effects", () => {
    const result = evaluatePart7(base);
    expect(result.decision.action).toBe("ALLOW");
    expect(result.enforcement.status).toBe("ACTIVE");
    expect(result.sideEffectsPerformed).toBe(false);
  });

  it("preserves lockdown precedence", () => {
    const result = evaluatePart7({ ...base, controls: { ...base.controls, globalLockdown: true } });
    expect(result.decision.action).toBe("LOCKDOWN");
    expect(result.enforcement.status).toBe("RESTRICTED");
    expect(result.failClosed).toBe(true);
  });

  it("preserves transaction firewall denial", () => {
    const result = evaluatePart7({ ...base, controls: { ...base.controls, transactionFirewallDenied: true } });
    expect(result.decision.action).toBe("DENY_TRANSACTION");
    expect(result.failClosed).toBe(true);
  });

  it("turns VPN into a challenge, not a permanent action", () => {
    const result = evaluatePart7({ ...base, signals: { vpnDetected: true } });
    expect(result.decision.action).toBe("CHALLENGE");
    expect(result.enforcement.status).toBe("CHALLENGE");
    expect(result.decision.reasonCodes).toContain("DISABLE_VPN_PROXY_TOR_TO_CONTINUE");
  });

  it("does not treat fingerprint change alone as fraud", () => {
    const result = evaluatePart7({ ...base, signals: { fingerprintChanged: true } });
    expect(result.decision.action).toBe("ALLOW");
    expect(result.decision.reasonCodes).toContain("FINGERPRINT_CHANGED_NOT_FRAUD_PROOF");
  });

  it("holds confirmed reward fraud for review", () => {
    const result = evaluatePart7({ ...base, signals: { rewardFraudConfirmed: true } });
    expect(result.decision.action).toBe("HOLD_REWARDS");
    expect(result.enforcement.status).toBe("REWARDS_HELD");
    expect(result.enforcement.requiresReview).toBe(true);
  });

  it("requires human approval for confirmed compromise", () => {
    const result = evaluatePart7({ ...base, signals: { credentialOrCookieTheftConfirmed: true } });
    expect(result.decision.action).toBe("PERMANENT_BAN");
    expect(result.decision.requiresHumanApproval).toBe(true);
    expect(result.enforcement.requiresReview).toBe(true);
  });

  it("never lets AI override a hard security control", () => {
    const result = evaluatePart7({
      ...base,
      ai: {
        schemaVersion: "ai_shadow_signal_v1",
        mode: "shadow",
        advisoryOnly: true,
        score: 0,
        confidence: 1,
        modelCount: 1,
        availableModelCount: 1,
        predictions: [],
        reasonCodes: [],
      },
      controls: { ...base.controls, hardBlock: true },
    });
    expect(result.decision.action).toBe("BLOCK");
    expect(result.failClosed).toBe(true);
  });

  it("recognizes only hard security actions as fail-closed", () => {
    expect(isHardSecurityAction("BLOCK")).toBe(true);
    expect(isHardSecurityAction("LOCKDOWN")).toBe(true);
    expect(isHardSecurityAction("DENY_TRANSACTION")).toBe(true);
    expect(isHardSecurityAction("CHALLENGE")).toBe(false);
  });
});
