import { describe, expect, it } from "vitest";
import { evaluateTransactionFirewall } from "../src/security/transactionFirewall";

describe("Part 5D transaction / wallet firewall", () => {
  it("allows a low-risk earning to proceed while retaining a monitoring score", () => {
    const result = evaluateTransactionFirewall({
      operation: "earn",
      baseDecision: "ALLOW",
      baseScore: 0,
    });
    expect(["ALLOW", "MONITOR"]).toContain(result.decision);
    expect(result.commitAllowed).toBe(true);
    expect(result.outcome).toMatch(/^ALLOW/);
  });

  it("blocks a critical withdrawal only after independent strong cues corroborate", () => {
    const result = evaluateTransactionFirewall({
      operation: "withdrawal",
      baseDecision: "ALLOW",
      baseScore: 10,
      previousValue: 0,
      currentValue: 10_000,
      attackPathScore: 92,
      attackPathConfidence: 0.92,
      recentOperations1m: 20,
      recentOperations5m: 50,
    });
    expect(result.decision).toBe("BLOCK");
    expect(result.commitAllowed).toBe(false);
    expect(result.adaptiveControl).toBe("restrict_subject_transactions");
    expect(result.independentStrongCueCount).toBe(3);
    expect(result.reasonCodes).toContain("TRANSACTION_MULTI_SIGNAL_CONFIRMATION");
  });

  it("holds a large value jump for review instead of blocking on the jump alone", () => {
    const result = evaluateTransactionFirewall({
      operation: "withdrawal",
      baseDecision: "ALLOW",
      baseScore: 5,
      previousValue: 0,
      currentValue: 10_000,
    });
    expect(result.decision).toBe("REVIEW");
    expect(result.outcome).toBe("HOLD");
    expect(result.commitAllowed).toBe(false);
    expect(result.independentStrongCueCount).toBe(1);
  });

  it("never lowers a stricter decision already made by the security engine", () => {
    const result = evaluateTransactionFirewall({
      operation: "earn",
      baseDecision: "REVIEW",
      baseScore: 75,
    });
    expect(result.decision).toBe("REVIEW");
    expect(result.commitAllowed).toBe(false);
  });

  it("rejects an unpaired before/after value", () => {
    expect(() => evaluateTransactionFirewall({
      operation: "withdrawal",
      baseDecision: "ALLOW",
      baseScore: 0,
      previousValue: 100,
    })).toThrow();
  });
});
