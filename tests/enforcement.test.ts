import { describe, expect, it } from "vitest";
import {
  buildEnforcementContract,
  scoreFloorForEnforcement,
  strictestDecision,
} from "../src/security/enforcement";

const challenge = {
  type: "proof_of_work" as const,
  reasonCodes: ["AUTOMATION_RISK_STEP_UP"],
  expiresInSeconds: 300,
};

describe("Part 4 enforcement contract", () => {
  it("selects the strictest decision across all contributing layers", () => {
    expect(strictestDecision("ALLOW", "MONITOR", "CHALLENGE")).toBe("CHALLENGE");
    expect(strictestDecision("REVIEW", "ALLOW", "BLOCK")).toBe("BLOCK");
  });

  it("never relaxes BLOCK even if another layer recommends ALLOW", () => {
    const result = buildEnforcementContract({
      decisions: ["BLOCK", "ALLOW", "MONITOR"],
      requestId: "req-001",
      reasonCodes: ["DATABASE_TRUST_BOUNDARY_FAILURE"],
      challenge,
    });
    expect(result.decision).toBe("BLOCK");
    expect(result.action).toBe("deny");
    expect(result.challenge).toBeNull();
    expect(result.retryable).toBe(false);
    expect(scoreFloorForEnforcement(result.decision)).toBe(90);
  });

  it("returns a challenge contract with the persistent challenge endpoint", () => {
    const result = buildEnforcementContract({
      decisions: ["MONITOR", "CHALLENGE"],
      requestId: "req-002",
      reasonCodes: ["BOT_SIGNAL", "BOT_SIGNAL"],
      challenge,
    });
    expect(result.action).toBe("challenge");
    expect(result.challenge).toEqual(challenge);
    expect(result.challengeEndpoint).toBe("/api/challenge");
    expect(result.challengeCompletionAuthority).toBe("tenant_server");
    expect(result.reasonCodes).toEqual(["BOT_SIGNAL"]);
  });

  it("does not expose a challenge for REVIEW or lower decisions", () => {
    const result = buildEnforcementContract({
      decisions: ["REVIEW"],
      requestId: "req-003",
      challenge,
    });
    expect(result.action).toBe("hold_for_review");
    expect(result.challenge).toBeNull();
    expect(result.challengeEndpoint).toBeNull();
  });

  it("rejects unsafe request IDs and unbounded challenge contracts", () => {
    expect(() => buildEnforcementContract({ decisions: ["ALLOW"], requestId: "bad id" })).toThrow();
    expect(() => buildEnforcementContract({
      decisions: ["CHALLENGE"],
      requestId: "req-004",
      challenge: { ...challenge, expiresInSeconds: 99999 },
    })).toThrow();
  });

  it("maps each decision to a non-decreasing score floor", () => {
    const floors = ["ALLOW", "MONITOR", "CHALLENGE", "REVIEW", "BLOCK"].map((decision) =>
      scoreFloorForEnforcement(decision as "ALLOW" | "MONITOR" | "CHALLENGE" | "REVIEW" | "BLOCK"));
    expect(floors).toEqual([0, 1, 40, 70, 90]);
    expect(floors.every((value, index) => index === 0 || value >= floors[index - 1])).toBe(true);
  });
});
