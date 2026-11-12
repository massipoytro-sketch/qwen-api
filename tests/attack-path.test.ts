import { describe, expect, it } from "vitest";
import { analyzeAttackPath } from "../src/security/attackPath";

const a = "11111111-1111-4111-8111-111111111111";
const b = "22222222-2222-4222-8222-222222222222";
const c = "33333333-3333-4333-8333-333333333333";
const device = "44444444-4444-4444-8444-444444444444";
const ip = "55555555-5555-4555-8555-555555555555";
const identity = "66666666-6666-4666-8666-666666666666";

describe("Part 5C attack-path engine", () => {
  it("does not escalate an empty graph without meaningful signals", () => {
    const result = analyzeAttackPath({ subjectId: a, edges: [], signals: [] });
    expect(result.score).toBe(0);
    expect(result.reasonCodes).toEqual([]);
    expect(result.paths).toEqual([]);
    expect(result.truncated).toBe(false);
  });

  it("correlates a multi-account, multi-resource value-abuse path", () => {
    const result = analyzeAttackPath({
      subjectId: a,
      edges: [
        { leftType: "subject", leftId: a, relationship: "uses_device", rightType: "device", rightId: device, confidence: 0.95 },
        { leftType: "subject", leftId: b, relationship: "uses_device", rightType: "device", rightId: device, confidence: 0.95 },
        { leftType: "subject", leftId: a, relationship: "uses_ip", rightType: "ip", rightId: ip, confidence: 0.92 },
        { leftType: "subject", leftId: c, relationship: "uses_ip", rightType: "ip", rightId: ip, confidence: 0.9 },
        { leftType: "subject", leftId: a, relationship: "owns_identity", rightType: "identity", rightId: identity, confidence: 0.9 },
      ],
      signals: [
        { signalName: "account_takeover_signal", score: 80, confidence: 0.9 },
        { signalName: "device_risk", score: 90, confidence: 0.95 },
        { signalName: "network_risk", score: 85, confidence: 0.9 },
        { signalName: "bot_detection", score: 90, confidence: 0.9 },
        { signalName: "value_jump_anomaly", score: 100, confidence: 0.95 },
        { signalName: "withdrawal_attempt", score: 90, confidence: 0.9 },
      ],
    });
    expect(result.score).toBeGreaterThanOrEqual(85);
    expect(result.reasonCodes).toContain("ATTACK_PATH_VALUE_TO_TRANSACTION");
    expect(result.reasonCodes).toContain("ATTACK_PATH_ACCOUNT_TAKEOVER_CHAIN");
    expect(result.relatedSubjectCount).toBeGreaterThanOrEqual(2);
    expect(result.paths.length).toBeGreaterThan(0);
    expect(result.examinedEdgeCount).toBe(5);
  });

  it("does not treat one weak signal as a multi-stage attack", () => {
    const result = analyzeAttackPath({
      subjectId: a,
      edges: [
        { leftType: "subject", leftId: a, relationship: "uses_device", rightType: "device", rightId: device, confidence: 0.5 },
      ],
      signals: [{ signalName: "device_risk", score: 40, confidence: 0.55 }],
    });
    expect(result.score).toBe(0);
    expect(result.pathPatterns).toEqual([]);
  });

  it("bounds traversal when input has cycles and reports truncation from caller", () => {
    const result = analyzeAttackPath({
      subjectId: a,
      edges: [
        { leftType: "subject", leftId: a, relationship: "uses_device", rightType: "device", rightId: device, confidence: 0.9 },
        { leftType: "device", leftId: device, relationship: "connected_ip", rightType: "ip", rightId: ip, confidence: 0.8 },
        { leftType: "ip", leftId: ip, relationship: "back_to_device", rightType: "device", rightId: device, confidence: 0.8 },
      ],
      signals: [],
      truncated: true,
    });
    expect(result.maxPathDepth).toBeLessThanOrEqual(4);
    expect(result.truncated).toBe(true);
    expect(result.examinedNodeCount).toBeLessThanOrEqual(3);
  });
});
