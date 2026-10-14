import { describe, expect, it } from "vitest";
import { analyzeBotDefense } from "../src/security/botDefense";

const at = (base: number, offset: number) => new Date(base + offset).toISOString();

describe("bot defense", () => {
  it("detects multi-signal automation without requiring a single flag", () => {
    const now = Date.parse("2026-10-14T19:00:00.000Z");
    const events = Array.from({ length: 12 }, (_, i) => ({
      occurredAt: at(now, -60_000 + i * 5_000),
      isBot: false,
      confidence: 0.1,
      signals: { webdriver: i < 4, impossibleTiming: i >= 4 && i < 8, tamperedClient: i >= 8 },
    }));
    const result = analyzeBotDefense({ now, events });
    expect(result.score).toBeGreaterThanOrEqual(45);
    expect(result.signalFlags).toEqual(expect.arrayContaining(["webdriver", "impossibleTiming", "tamperedClient"]));
    expect(result.reasonCodes).toContain("MULTI_SIGNAL_AUTOMATION");
  });

  it("detects machine-like periodic activity", () => {
    const now = Date.parse("2026-10-14T19:00:00.000Z");
    const events = Array.from({ length: 10 }, (_, i) => ({
      occurredAt: at(now, -90_000 + i * 10_000),
      isBot: false,
      confidence: 0,
      signals: {},
    }));
    const result = analyzeBotDefense({ now, events });
    expect(result.periodicityScore).toBeGreaterThanOrEqual(55);
    expect(result.reasonCodes).toContain("BOT_MACHINE_PERIODICITY");
  });

  it("does not turn a small amount of normal activity into a bot block", () => {
    const now = Date.parse("2026-10-14T19:00:00.000Z");
    const result = analyzeBotDefense({ now, events: [
      { occurredAt: at(now, -50_000), isBot: false, confidence: 0, signals: {} },
      { occurredAt: at(now, -10_000), isBot: false, confidence: 0, signals: {} },
    ] });
    expect(result.score).toBe(0);
    expect(result.reasonCodes).toEqual([]);
  });
});
