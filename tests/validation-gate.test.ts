import { describe, expect, it } from "vitest";
import { DEFAULT_SECURITY_VALIDATION_SCENARIOS, runSecurityValidationGate } from "../src/security/validationGate";

describe("security validation gate", () => {
  it("passes the complete deterministic scenario matrix", () => {
    const report = runSecurityValidationGate(DEFAULT_SECURITY_VALIDATION_SCENARIOS);
    expect(report.passed).toBe(true);
    expect(report.scenarios).toBeGreaterThanOrEqual(12);
    expect(report.failures).toEqual([]);
  });

  it("keeps a high base score from being relaxed by weak signals", () => {
    const report = runSecurityValidationGate([
      {
        name: "high_score_monotonicity",
        score: 90,
        signals: [{ signalName: "network_risk", source: "network", score: 1, confidence: 1 }],
        expectedMinimumDecision: "BLOCK",
      },
    ]);
    expect(report.passed).toBe(true);
  });
});
