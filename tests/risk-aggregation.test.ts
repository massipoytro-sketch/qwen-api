import { describe, expect, it } from "vitest";
import { aggregateSecurityRisk } from "../src/security/risk";

describe("deterministic security risk aggregation", () => {
  const signals = [
    { signalName: "network_risk", source: "network", score: 60, confidence: 0.9 },
    { signalName: "account_takeover_detection", source: "identity", score: 75, confidence: 0.8 },
  ];

  it("returns a stable score from deterministic signals", () => {
    expect(aggregateSecurityRisk(signals)).toBe(68);
  });

  it("cannot be raised or lowered by AI advisory scores", () => {
    const baseline = aggregateSecurityRisk(signals);
    expect(aggregateSecurityRisk([
      ...signals,
      { signalName: "ai_advisory", source: "ai_advisory", score: 100, confidence: 1 },
    ])).toBe(baseline);
    expect(aggregateSecurityRisk([
      ...signals,
      { signalName: "ai_advisory", source: "ai", score: 0, confidence: 1 },
    ])).toBe(baseline);
  });

  it("returns zero when only advisory signals are present", () => {
    expect(aggregateSecurityRisk([
      { signalName: "ai_advisory", source: "ai_advisory", score: 100, confidence: 1 },
    ])).toBe(0);
  });

  it("keeps the score finite for malformed numeric evidence", () => {
    expect(Number.isFinite(aggregateSecurityRisk([
      { signalName: "malformed", source: "network", score: Number.NaN, confidence: Number.POSITIVE_INFINITY },
    ]))).toBe(true);
  });

  it("bounds the score to the supported range", () => {
    expect(aggregateSecurityRisk([
      { signalName: "extreme", source: "network", score: 100, confidence: 1 },
      { signalName: "extreme2", source: "identity", score: 100, confidence: 1 },
      { signalName: "extreme3", source: "device", score: 100, confidence: 1 },
    ])).toBeLessThanOrEqual(100);
  });
});
