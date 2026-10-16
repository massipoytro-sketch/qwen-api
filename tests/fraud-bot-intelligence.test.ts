import { describe, expect, it } from "vitest";
import { analyzeFraudGraph, analyzeValueJump, enforceFraudFloor } from "../src/security/fraud-intelligence";
import { analyzeBotDefense } from "../src/security/bot-defense";

const subjectB = "22222222-2222-4222-8222-222222222222";
const now = Date.parse("2026-10-16T10:00:00.000Z");

const event = (offsetMs: number, flags: string[] = [], extra: Record<string, unknown> = {}) => ({
  occurredAt: new Date(now + offsetMs).toISOString(),
  isBot: null,
  confidence: 0,
  flags,
  requestIntervalMs: null,
  ...extra,
});

describe("Part 3 fraud intelligence", () => {
  it("does not escalate a single shared-resource relationship into a strong action", () => {
    const result = analyzeFraudGraph({
      edgeCount: 1,
      nodeCount: 3,
      edges: [{ relationship: "shared_device", confidence: 0.85, leftType: "subject", rightType: "device" }],
      relatedSubjects: [{ subjectId: subjectB, sharedResources: 1, confidence: 0.85 }],
    });
    expect(result.score).toBeLessThan(45);
    expect(enforceFraudFloor("ALLOW", result.score, result.confidence)).toBe("ALLOW");
  });

  it("raises correlated multi-edge clusters without ever producing BLOCK", () => {
    const result = analyzeFraudGraph({
      edgeCount: 5,
      nodeCount: 8,
      edges: [
        { relationship: "shared_device", confidence: 0.95, leftType: "subject", rightType: "device" },
        { relationship: "shared_ip", confidence: 0.95, leftType: "subject", rightType: "ip" },
        { relationship: "shared_identity", confidence: 0.9, leftType: "subject", rightType: "identity" },
        { relationship: "linked_session", confidence: 0.9, leftType: "subject", rightType: "session" },
        { relationship: "uses_ip", confidence: 0.85, leftType: "subject", rightType: "ip" },
      ],
      relatedSubjects: [
        { subjectId: subjectB, sharedResources: 3, confidence: 0.95 },
      ],
    });
    expect(result.score).toBeGreaterThanOrEqual(70);
    expect(enforceFraudFloor("ALLOW", result.score, result.confidence)).toBe("CHALLENGE");
    expect(enforceFraudFloor("BLOCK", result.score, result.confidence)).toBe("BLOCK");
  });

  it("detects the 0-to-10k style value jump deterministically", () => {
    const result = analyzeValueJump({ previousValue: 0, currentValue: 10_000, occurredAt: new Date(now).toISOString() });
    expect(result.score).toBe(100);
    expect(result.reasonCodes).toContain("CRITICAL_VALUE_JUMP");
  });
});

describe("Part 3 bot defense", () => {
  it("does not challenge on one weak browser flag", () => {
    const result = analyzeBotDefense({
      now,
      events: [event(-5_000, ["webdriver"])],
    });
    expect(result.decision).toBe("ALLOW");
  });

  it("requires corroboration for a strong automation challenge", () => {
    const result = analyzeBotDefense({
      now,
      events: [
        event(-9_000, ["webdriver", "headless", "automationFramework"], { isBot: true, confidence: 0.92, requestIntervalMs: 40 }),
        event(-8_000, ["webdriver", "headless", "automationFramework", "replayedRequest"], { isBot: true, confidence: 0.96, requestIntervalMs: 35 }),
        event(-7_000, ["impossibleTiming", "replayedRequest"], { requestIntervalMs: 30 }),
      ],
    });
    expect(result.decision).toBe("CHALLENGE");
    expect(result.reasonCodes).toContain("MULTI_SIGNAL_BOT_CORRELATION");
    expect(result.reasonCodes).toContain("REQUEST_REPLAY_PATTERN");
  });

  it("never accepts an invalid confidence as evidence", () => {
    const result = analyzeBotDefense({
      now,
      events: [event(-1_000, ["webdriver"], { isBot: true, confidence: 0 })],
    });
    expect(Number.isFinite(result.score)).toBe(true);
    expect(result.decision).toBe("ALLOW");
  });
});
