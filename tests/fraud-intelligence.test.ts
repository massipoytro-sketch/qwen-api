import { describe, expect, it } from "vitest";
import { analyzeFraudGraph, analyzeValueJump, enforceFraudFloor } from "../src/security/fraud-intelligence";

const subjectA = "11111111-1111-4111-8111-111111111111";
const subjectB = "22222222-2222-4222-8222-222222222222";
const now = new Date("2026-10-16T10:00:00.000Z").toISOString();

describe("fraud graph intelligence", () => {
  it("does not escalate a single shared resource", () => {
    const result = analyzeFraudGraph({
      edgeCount: 1,
      nodeCount: 2,
      edges: [{ relationship: "shared_device", confidence: 0.85, leftType: "subject", rightType: "device" }],
      relatedSubjects: [{ subjectId: subjectB, sharedResources: 1, confidence: 0.85 }],
    });
    expect(result.score).toBeLessThan(45);
    expect(enforceFraudFloor("ALLOW", result.score, result.confidence)).toBe("ALLOW");
  });

  it("requires independent resource classes and multi-resource corroboration for escalation", () => {
    const result = analyzeFraudGraph({
      edgeCount: 6,
      nodeCount: 8,
      edges: [
        { relationship: "uses_device", confidence: 0.95, leftType: "subject", rightType: "device" },
        { relationship: "uses_ip", confidence: 0.95, leftType: "subject", rightType: "ip" },
        { relationship: "owns_identity", confidence: 0.9, leftType: "subject", rightType: "identity" },
        { relationship: "linked_session", confidence: 0.9, leftType: "subject", rightType: "session" },
      ],
      relatedSubjects: [
        { subjectId: subjectB, sharedResources: 3, confidence: 0.95 },
        { subjectId: subjectA, sharedResources: 2, confidence: 0.9 },
      ],
    });
    expect(result.score).toBeGreaterThanOrEqual(70);
    expect(result.reasonCodes).toContain("INDEPENDENT_RESOURCE_CLASSES");
    expect(result.reasonCodes).toContain("SHARED_RESOURCE_CLUSTER");
    expect(enforceFraudFloor("ALLOW", result.score, result.confidence)).toBe("CHALLENGE");
  });

  it("detects a 0→10,000 jump as critical evidence without producing BLOCK", () => {
    const result = analyzeValueJump({ previousValue: 0, currentValue: 10_000, occurredAt: now });
    expect(result.score).toBe(100);
    expect(result.reasonCodes).toContain("CRITICAL_VALUE_JUMP");
    expect(enforceFraudFloor("ALLOW", result.score, result.confidence)).toBe("REVIEW");
  });

  it("does not treat a trivial 0→1 increment as an extreme multiplier", () => {
    const result = analyzeValueJump({ previousValue: 0, currentValue: 1, occurredAt: now });
    expect(result.score).toBe(0);
    expect(result.confidence).toBe(0.4);
  });

  it("does not loosen an existing BLOCK decision", () => {
    expect(enforceFraudFloor("BLOCK", 0, 0)).toBe("BLOCK");
  });

  it("rejects malformed or non-finite graph evidence", () => {
    expect(() => analyzeFraudGraph({
      edgeCount: 1,
      nodeCount: 2,
      edges: [{ relationship: "shared_device", confidence: Number.NaN, leftType: "subject", rightType: "device" }],
      relatedSubjects: [],
    })).toThrow();
  });
});
