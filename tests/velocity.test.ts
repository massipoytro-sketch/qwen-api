import { describe, expect, it } from "vitest";
import { analyzeVelocity } from "../src/security/velocity";

const event = (secondsAgo: number, eventType = "click") => ({
  occurredAt: new Date(Date.now() - secondsAgo * 1000).toISOString(),
  eventType,
});

describe("activity velocity analysis", () => {
  it("does not flag a quiet session", () => {
    const result = analyzeVelocity([event(900), event(700), event(400)]);
    expect(result.score).toBe(0);
  });

  it("detects a short burst", () => {
    const result = analyzeVelocity(Array.from({ length: 25 }, (_, i) => event(i, "task")));
    expect(result.count1m).toBe(25);
    expect(result.score).toBeGreaterThan(40);
  });

  it("recognizes suspicious timing regularity as supporting evidence", () => {
    const result = analyzeVelocity(Array.from({ length: 8 }, (_, i) => event(120 - i * 10, "task")));
    expect(result.regularityScore).toBe(100);
  });
});
