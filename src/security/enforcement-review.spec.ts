import { describe, expect, it } from "vitest";
import { recommendEnforcement, recommendReviewTransition } from "./enforcement-review";
import type { DecisionRecommendation } from "./decision-engine";

const decision = (action: DecisionRecommendation["action"]): DecisionRecommendation => ({
  schemaVersion: "part7-decision-v2",
  subjectRef: "subject-1",
  action,
  riskScore: 80,
  deterministicScore: 80,
  aiContribution: 0,
  policyVersion: "test-v1",
  reasonCodes: [],
  requiresHumanApproval: action === "PERMANENT_BAN" || action === "HOLD_REWARDS" || action === "HUMAN_REVIEW",
  recommendationOnly: true,
  sideEffectsPerformed: false,
});

describe("Part 7B enforcement and review", () => {
  it("keeps the recommendation layer side-effect free", () => {
    const result = recommendEnforcement({ decision: decision("ALLOW"), currentStatus: "ACTIVE", nowMs: 1 });
    expect(result.sideEffectsPerformed).toBe(false);
    expect(result.status).toBe("ACTIVE");
  });
  it("maps challenge to challenge", () => {
    const result = recommendEnforcement({ decision: decision("CHALLENGE"), currentStatus: "ACTIVE", nowMs: 1 });
    expect(result.status).toBe("CHALLENGE");
  });
  it("holds rewards for review", () => {
    const result = recommendEnforcement({ decision: decision("HOLD_REWARDS"), currentStatus: "ACTIVE", nowMs: 1 });
    expect(result.status).toBe("REWARDS_HELD");
    expect(result.requiresReview).toBe(true);
  });
  it("requires review for the strongest action", () => {
    const result = recommendEnforcement({ decision: decision("PERMANENT_BAN"), currentStatus: "ACTIVE", nowMs: 1 });
    expect(result.status).toBe("BANNED");
    expect(result.requiresReview).toBe(true);
  });
  it("restores a reviewed subject", () => {
    expect(recommendReviewTransition({ currentStatus: "SUSPENDED", action: "RESTORE", nowMs: 1 })).toMatchObject({ status: "ACTIVE", requiresAudit: true });
  });
  it("supports ten-day suspension with expiry", () => {
    const result = recommendReviewTransition({ currentStatus: "RESTRICTED", action: "SUSPEND_10D", nowMs: 1_000 });
    expect(result.status).toBe("SUSPENDED");
    expect(result.expiresAtMs).toBe(1_000 + 10 * 24 * 60 * 60 * 1000);
    expect(result.requiresAudit).toBe(true);
  });
  it("requires audit for permanent review action", () => {
    expect(recommendReviewTransition({ currentStatus: "SUSPENDED", action: "PERMANENT_BAN", nowMs: 1 })).toEqual({ status: "BANNED", requiresAudit: true });
  });
});
