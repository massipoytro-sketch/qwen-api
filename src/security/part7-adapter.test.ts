import { describe, expect, it } from "vitest";
import { buildPart7DecisionInput } from "./part7-adapter";
import { recommendSecurityAction } from "./decision-engine";

const base = {
  assessmentId: "00000000-0000-4000-8000-000000000001",
  decision: "ALLOW" as const,
  score: 10,
  riskLevel: "low" as const,
  challengeRecommendation: null,
};

describe("Part 7 production evidence adapter", () => {
  it("keeps AI shadow-only and unavailable when production artifacts are not deployed", () => {
    const { input, aiShadow } = buildPart7DecisionInput({
      subjectRef: "tenant:assessment",
      result: base,
    });
    expect(aiShadow.mode).toBe("shadow");
    expect(aiShadow.advisoryOnly).toBe(true);
    expect(aiShadow.availableModelCount).toBe(0);
    expect(input.ai?.availableModelCount).toBe(0);
  });

  it("turns VPN/proxy/Tor evidence into a challenge, never a ban", () => {
    const { input } = buildPart7DecisionInput({
      subjectRef: "tenant:network",
      result: {
        ...base,
        score: 15,
        challengeRecommendation: {
          type: "risk_based_verification",
          reasonCodes: ["VPN_DETECTED_ACCESS_RESTRICTION"],
          expiresInSeconds: 300,
        },
      },
    });
    const decision = recommendSecurityAction(input);
    expect(decision.action).toBe("CHALLENGE");
    expect(decision.action).not.toBe("PERMANENT_BAN");
  });

  it("preserves a hard BLOCK as a Part 7 hard decision", () => {
    const { input } = buildPart7DecisionInput({
      subjectRef: "tenant:block",
      result: { ...base, decision: "BLOCK", score: 100, riskLevel: "critical" },
    });
    const decision = recommendSecurityAction(input);
    expect(decision.action).toBe("BLOCK");
    expect(decision.requiresHumanApproval).toBe(true);
  });

  it("does not turn fingerprint change into fraud by itself", () => {
    const { input } = buildPart7DecisionInput({
      subjectRef: "tenant:fingerprint",
      result: {
        ...base,
        challengeRecommendation: {
          type: "risk_based_verification",
          reasonCodes: ["FINGERPRINT_CHANGED_NOT_FRAUD_PROOF"],
          expiresInSeconds: 300,
        },
      },
    });
    const decision = recommendSecurityAction(input);
    expect(decision.action).not.toBe("PERMANENT_BAN");
  });

  it("holds confirmed duplicate accounts for review instead of deleting them", () => {
    const { input } = buildPart7DecisionInput({
      subjectRef: "tenant:duplicate",
      result: {
        ...base,
        score: 20,
        challengeRecommendation: {
          type: "risk_based_verification",
          reasonCodes: ["CONFIRMED_DUPLICATE_ACCOUNT"],
          expiresInSeconds: 300,
        },
      },
    });
    const decision = recommendSecurityAction(input);
    expect(decision.action).toBe("HOLD_REWARDS");
    expect(decision.action).not.toBe("PERMANENT_BAN");
  });
});
