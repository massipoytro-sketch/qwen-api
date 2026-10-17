import { describe, expect, it } from "vitest";
import { applySubjectTransactionControl, deriveSubjectTransactionControl } from "../src/security/adaptiveLockdown";

const now = Date.parse("2026-10-17T10:00:00.000Z");

describe("adaptive transaction lockdown", () => {
  it("escalates every sensitive transaction during an active block", () => {
    const result = applySubjectTransactionControl({
      decision: "ALLOW",
      score: 12,
      control: { mode: "block", reasonCode: "TX_ADAPTIVE_BLOCK", expiresAt: new Date(now + 60_000).toISOString() },
      now,
    });
    expect(result.decision).toBe("BLOCK");
    expect(result.score).toBe(90);
    expect(result.reasonCodes).toContain("SUBJECT_TRANSACTION_BLOCK_ACTIVE");
  });

  it("enforces a hold as REVIEW, then ignores an expired hold", () => {
    const active = applySubjectTransactionControl({
      decision: "ALLOW", score: 5,
      control: { mode: "hold", reasonCode: "TX_ADAPTIVE_HOLD", expiresAt: new Date(now + 60_000).toISOString() },
      now,
    });
    const expired = applySubjectTransactionControl({
      decision: "ALLOW", score: 5,
      control: { mode: "hold", reasonCode: "TX_ADAPTIVE_HOLD", expiresAt: new Date(now - 1).toISOString() },
      now,
    });
    expect(active.decision).toBe("REVIEW");
    expect(expired.decision).toBe("ALLOW");
    expect(expired.activeControl).toBeNull();
  });

  it("does not extend an existing active block on repeated blocked attempts", () => {
    const current = { mode: "block" as const, reasonCode: "TX_ADAPTIVE_BLOCK", expiresAt: new Date(now + 600_000).toISOString() };
    expect(deriveSubjectTransactionControl({ decision: "BLOCK", activeControl: current, now })).toBeNull();
  });

  it("escalates a hold into a block without downgrading", () => {
    const current = { mode: "hold" as const, reasonCode: "TX_ADAPTIVE_HOLD", expiresAt: new Date(now + 600_000).toISOString() };
    const next = deriveSubjectTransactionControl({ decision: "BLOCK", activeControl: current, now });
    expect(next?.mode).toBe("block");
  });
});
