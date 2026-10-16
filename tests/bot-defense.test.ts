import { describe, expect, it } from "vitest";
import { analyzeBotDefense } from "../src/security/botDefense";

const now = Date.parse("2026-10-16T10:00:00.000Z");
const at = (offset: number) => new Date(now + offset).toISOString();

describe("corroborated bot defense", () => {
  it("does not escalate a single weak browser flag", () => {
    const result = analyzeBotDefense({
      now,
      events: [{ occurredAt: at(-1_000), isBot: false, confidence: 0.1, signals: { webdriver: true } }],
    });
    expect(result.decision).toBe("ALLOW");
    expect(result.score).toBeLessThan(45);
  });

  it("detects multi-signal automation combined with a request burst", () => {
    const events = Array.from({ length: 40 }, (_, index) => ({
      occurredAt: at(-50_000 + index * 1_000),
      isBot: false,
      confidence: 0.1,
      signals: {
        webdriver: index % 2 === 0,
        impossibleTiming: index % 3 === 0,
        tamperedClient: index % 4 === 0,
      },
    }));
    const result = analyzeBotDefense({ now, events });
    expect(result.score).toBeGreaterThanOrEqual(75);
    expect(result.decision).toBe("CHALLENGE");
    expect(result.reasonCodes).toContain("MULTI_SIGNAL_AUTOMATION");
  });

  it("recognizes repeated replay indicators without ever returning BLOCK", () => {
    const result = analyzeBotDefense({
      now,
      events: Array.from({ length: 3 }, (_, index) => ({
        occurredAt: at(-3_000 + index * 1_000),
        isBot: false,
        confidence: 0.1,
        signals: { replayedRequest: true },
      })),
    });
    expect(result.score).toBeGreaterThanOrEqual(80);
    expect(["CHALLENGE", "REVIEW"]).toContain(result.decision);
    expect(result.decision).not.toBe("BLOCK");
    expect(result.reasonCodes).toContain("REQUEST_REPLAY_PATTERN");
  });

  it("detects periodic events without treating periodicity alone as proof", () => {
    const result = analyzeBotDefense({
      now,
      events: Array.from({ length: 10 }, (_, index) => ({
        occurredAt: at(-90_000 + index * 10_000),
        isBot: false,
        confidence: 0,
        signals: {},
      })),
    });
    expect(result.periodicityScore).toBeGreaterThanOrEqual(55);
    expect(result.reasonCodes).toContain("BOT_MACHINE_PERIODICITY");
    expect(result.decision).not.toBe("BLOCK");
  });

  it("ignores events outside its bounded ten-minute observation window", () => {
    const result = analyzeBotDefense({
      now,
      events: Array.from({ length: 100 }, (_, index) => ({
        occurredAt: at(-12 * 60_000 + index * 1_000),
        isBot: true,
        confidence: 1,
        signals: { webdriver: true, headless: true },
      })),
    });
    expect(result.count10m).toBe(0);
    expect(result.score).toBe(0);
  });

  it("rejects non-finite classifier confidence before it reaches scoring", () => {
    expect(() => analyzeBotDefense({
      now,
      events: [{ occurredAt: at(-1_000), isBot: true, confidence: Number.NaN, signals: {} }],
    })).toThrow();
  });
});
