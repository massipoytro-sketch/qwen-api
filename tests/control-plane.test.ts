import { describe, expect, it } from "vitest";
import { evaluateControlPlane, simulatePolicies } from "../src/security/controlPlane";

describe("active defense control plane", () => {
  it("escalates a correlated takeover and value jump into quarantine", () => {
    const result = evaluateControlPlane({
      tenantId: "77777777-7777-4777-8777-777777777777",
      subjectId: "11111111-1111-4111-8111-111111111111",
      operation: "withdrawal",
      decision: "CHALLENGE",
      score: 55,
      signals: [
        { signalName: "account_takeover_detection", score: 95, confidence: 0.95 },
        { signalName: "value_jump_anomaly", score: 92, confidence: 0.9 },
      ],
      transaction: { before: 0, after: 10000, sensitive: true },
    });
    expect(result.decision).toBe("REVIEW");
    expect(result.quarantined).toBe(true);
    expect(result.state).toBe("QUARANTINED");
    expect(result.enforcement.sensitiveOperationAllowed).toBe(false);
    expect(result.incident?.fingerprint).toMatch(/^[a-f0-9]{64}$/);
  });

  it("never lets a weak signal downgrade an already blocked state", () => {
    const result = evaluateControlPlane({
      tenantId: "77777777-7777-4777-8777-777777777777",
      subjectId: "22222222-2222-4222-8222-222222222222",
      previousState: "BLOCKED",
      decision: "ALLOW",
      score: 0,
      signals: [],
    });
    expect(result.state).toBe("BLOCKED");
    expect(result.decision).toBe("BLOCK");
    expect(result.enforcement.operationAllowed).toBe(false);
  });

  it("DENY_ALL is fail-closed", () => {
    const result = evaluateControlPlane({
      tenantId: "77777777-7777-4777-8777-777777777777",
      decision: "ALLOW",
      score: 0,
      signals: [],
      emergencyMode: "DENY_ALL",
    });
    expect(result.decision).toBe("BLOCK");
    expect(result.state).toBe("BLOCKED");
    expect(result.reasonCodes).toContain("EMERGENCY_DENY_ALL");
  });

  it("policy simulator is restrictive-only and respects expiration", () => {
    const result = simulatePolicies({ tenantId: "t", decision: "CHALLENGE", score: 45, signals: [], operation: "withdrawal" }, [
      { id: "deny", priority: 100, enabled: true, action: "BLOCK", condition: { operationIn: ["withdrawal"] }, reasonCode: "WITHDRAWAL_LOCK" },
      { id: "expired", priority: 200, enabled: true, action: "ALLOW", condition: {}, reasonCode: "EXPIRED_ALLOW", expiresAt: new Date(Date.now() - 1000).toISOString() },
    ]);
    expect(result.decision).toBe("BLOCK");
    expect(result.matches).toEqual(["deny"]);
  });
});
