import { describe, expect, it } from "vitest";
import { replaySecurityTimeline } from "../src/security/replay";

describe("Part 5 deterministic attack replay", () => {
  it("is monotonic and cannot downgrade a stronger decision", () => {
    const result = replaySecurityTimeline([
      { sequence: 1, eventType: "login", occurredAt: "2026-10-16T10:00:00Z", decision: "MONITOR", score: 10 },
      { sequence: 2, eventType: "session", occurredAt: "2026-10-16T10:00:01Z", decision: "BLOCK", score: 95 },
      { sequence: 3, eventType: "normal_activity", occurredAt: "2026-10-16T10:00:02Z", decision: "ALLOW", score: 1 },
    ]);
    expect(result.finalDecision).toBe("BLOCK");
    expect(result.finalScoreFloor).toBe(95);
    expect(result.escalations).toBe(2);
  });

  it("bounds scores and sanitizes reason codes", () => {
    const result = replaySecurityTimeline([
      {
        sequence: 1,
        eventType: "risk",
        occurredAt: "2026-10-16T10:00:00Z",
        decision: "CHALLENGE",
        score: Number.NaN,
        reasonCodes: ["BOT_SIGNAL", "bad reason", "FRAUD_GRAPH"],
      },
    ]);
    expect(result.finalScoreFloor).toBe(40);
    expect(result.reasonCodes).toEqual(["BOT_SIGNAL", "FRAUD_GRAPH"]);
  });

  it("rejects gaps and oversized replay timelines", () => {
    expect(() => replaySecurityTimeline([
      { sequence: 2, eventType: "event", occurredAt: "2026-10-16T10:00:00Z", decision: "ALLOW", score: 0 },
    ])).toThrow("REPLAY_SEQUENCE_INVALID");
    expect(() => replaySecurityTimeline(Array.from({ length: 501 }, (_, i) => ({
      sequence: i + 1,
      eventType: "event",
      occurredAt: "2026-10-16T10:00:00Z",
      decision: "ALLOW" as const,
      score: 0,
    })))).toThrow("REPLAY_TOO_MANY_EVENTS");
  });

  it("rejects malformed event types, timestamps and decisions", () => {
    expect(() => replaySecurityTimeline([
      { sequence: 1, eventType: "../secrets", occurredAt: "2026-10-16T10:00:00Z", decision: "ALLOW", score: 0 },
    ])).toThrow("REPLAY_EVENT_TYPE_INVALID");
    expect(() => replaySecurityTimeline([
      { sequence: 1, eventType: "event", occurredAt: "not-a-date", decision: "ALLOW", score: 0 },
    ])).toThrow("REPLAY_TIMESTAMP_INVALID");
    expect(() => replaySecurityTimeline([
      { sequence: 1, eventType: "event", occurredAt: "2026-10-16T10:00:00Z", decision: "UNKNOWN" as never, score: 0 },
    ])).toThrow("REPLAY_DECISION_INVALID");
  });

  it("caps reason codes per event before deduplication", () => {
    const result = replaySecurityTimeline([{
      sequence: 1,
      eventType: "event",
      occurredAt: "2026-10-16T10:00:00Z",
      decision: "MONITOR",
      score: 20,
      reasonCodes: Array.from({ length: 100 }, (_, i) => `REASON_${i}`),
    }]);
    expect(result.reasonCodes).toHaveLength(32);
  });

  it("does not perform any external operation", () => {
    const result = replaySecurityTimeline([]);
    expect(result).toEqual({
      eventCount: 0,
      finalDecision: "ALLOW",
      finalScoreFloor: 0,
      escalations: 0,
      decisions: [],
      reasonCodes: [],
    });
  });
});
