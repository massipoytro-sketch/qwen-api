import { describe, expect, it } from "vitest";
import {
  CHAOS_EXPECTATIONS,
  SECURITY_FUZZ_CASES,
  boundedStressPlan,
  decisionCannotDowngrade,
  evaluateRaceResults,
  recoverySequence,
  validateSecurityInvariants,
} from "../src/security/validation/part5f";

describe("Part 5F chaos validation", () => {
  it("fails closed for every defined infrastructure fault", () => {
    expect(CHAOS_EXPECTATIONS).toHaveLength(8);
    expect(CHAOS_EXPECTATIONS.every((item) => item.expectedDecision === "BLOCK" || item.expectedDecision === "NO_COMMIT")).toBe(true);
  });

  it("detects every forbidden security invariant violation", () => {
    const failures = validateSecurityInvariants({
      globalMode: "lockdown",
      sessionActive: false,
      securityCheckSucceeded: false,
      downstreamDecision: "ALLOW",
      committed: true,
      replayDetected: true,
      duplicateIdempotency: true,
      auditRecorded: false,
    });
    expect(failures).toEqual([
      "lockdown_not_blocked",
      "inactive_session_allowed",
      "failed_check_allowed",
      "replay_committed",
      "duplicate_idempotency_committed",
      "commit_without_audit",
    ]);
  });

  it("rejects decision downgrades", () => {
    expect(decisionCannotDowngrade("BLOCK", "ALLOW")).toBe(false);
    expect(decisionCannotDowngrade("REVIEW", "BLOCK")).toBe(true);
    expect(decisionCannotDowngrade("CHALLENGE", "REVIEW")).toBe(true);
  });
});

describe("Part 5F race validation", () => {
  it("detects duplicate commits for one idempotency identity", () => {
    const result = evaluateRaceResults(["txn-1", "txn-1", "txn-2"], "txn-1");
    expect(result.committed).toBe(2);
    expect(result.duplicateCommit).toBe(true);
  });

  it("accepts exactly one winner", () => {
    const result = evaluateRaceResults(["txn-1", "txn-2", "txn-3"], "txn-1");
    expect(result.committed).toBe(1);
    expect(result.duplicateCommit).toBe(false);
  });
});

describe("Part 5F fuzz and stress boundaries", () => {
  it("keeps fuzz corpus hostile and bounded", () => {
    expect(SECURITY_FUZZ_CASES.length).toBeGreaterThanOrEqual(10);
    expect(SECURITY_FUZZ_CASES.every((item) => item.expectedReject)).toBe(true);
  });

  it("bounds stress workloads so validation cannot become an accidental DoS", () => {
    expect(boundedStressPlan({ concurrency: 99999, requests: 99999999, durationMs: 99999999 })).toEqual({
      concurrency: 256,
      requests: 10_000,
      durationMs: 120_000,
    });
    expect(boundedStressPlan({ concurrency: 0, requests: 0, durationMs: 0 })).toEqual({
      concurrency: 1,
      requests: 1,
      durationMs: 100,
    });
  });

  it("requires the full lockdown recovery sequence", () => {
    expect(recoverySequence(["normal", "review_only", "lockdown", "normal"])).toBe(true);
    expect(recoverySequence(["normal", "lockdown", "normal"])).toBe(false);
  });
});
