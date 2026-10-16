import { describe, expect, it } from "vitest";
import { buildEnforcementContract, createChallengeToken, strictestDecision, verifyChallengeToken } from "../src/security/enforcement";

const tenantId = "77777777-7777-4777-8777-777777777777";
const subjectId = "22222222-2222-4222-8222-222222222222";
const signingKey = "part4-test-signing-key-0123456789abcdef";
const nowMs = Date.parse("2026-10-16T10:00:00.000Z");

describe("Part 4 enforcement", () => {
  it("always chooses the strictest decision", () => {
    expect(strictestDecision("ALLOW", "MONITOR", "CHALLENGE")).toBe("CHALLENGE");
    expect(strictestDecision("REVIEW", "BLOCK", "ALLOW")).toBe("BLOCK");
  });

  it("cannot relax a BLOCK or REVIEW decision", () => {
    expect(buildEnforcementContract({ decision: "BLOCK", firewallDecision: "ALLOW", requestId: "req-1" }).action).toBe("deny");
    expect(buildEnforcementContract({ decision: "REVIEW", firewallDecision: "MONITOR", requestId: "req-2" }).action).toBe("hold_for_review");
  });

  it("creates a short-lived token bound to tenant, subject, request and challenge type", () => {
    const token = createChallengeToken({
      signingKey,
      tenantId,
      subjectId,
      requestId: "req-3",
      type: "step_up_mfa",
      nowMs,
      ttlSeconds: 300,
    });
    expect(verifyChallengeToken({ token, signingKey, tenantId, subjectId, requestId: "req-3", type: "step_up_mfa", nowMs: nowMs + 60_000 })).toBe(true);
    expect(verifyChallengeToken({ token, signingKey, tenantId, subjectId, requestId: "req-4", type: "step_up_mfa", nowMs })).toBe(false);
    expect(verifyChallengeToken({ token, signingKey, tenantId, subjectId, requestId: "req-3", type: "proof_of_work", nowMs })).toBe(false);
    expect(verifyChallengeToken({ token, signingKey, tenantId, subjectId, requestId: "req-3", type: "step_up_mfa", nowMs: nowMs + 301_000 })).toBe(false);
  });

  it("exposes a challenge only when the effective decision is CHALLENGE", () => {
    const contract = buildEnforcementContract({
      decision: "MONITOR",
      firewallDecision: "CHALLENGE",
      requestId: "req-5",
      challenge: { type: "risk_based_verification", reasonCodes: ["TEST_REASON"], expiresInSeconds: 300 },
    });
    expect(contract.action).toBe("challenge");
    expect(contract.challenge?.type).toBe("risk_based_verification");
  });
});
