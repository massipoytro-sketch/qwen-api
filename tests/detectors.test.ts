import { describe, expect, it } from "vitest";
import {
  analyzeAccountTakeoverSignals,
  analyzeConcurrentSessionAnomalies,
  analyzeImpossibleTravel,
} from "../src/security/detectors";

const now = Date.parse("2026-10-12T08:00:00.000Z");

describe("account-takeover detector", () => {
  it("scores failed-login bursts and recovery activity", () => {
    const events = [
      ...Array.from({ length: 5 }, (_, index) => ({
        eventType: "auth.login_failed",
        occurredAt: new Date(now - index * 20_000).toISOString(),
        severity: "warning",
      })),
      { eventType: "password_reset", occurredAt: new Date(now - 60_000).toISOString(), severity: "high" },
    ];
    const result = analyzeAccountTakeoverSignals(events, now);
    expect(result.score).toBeGreaterThanOrEqual(60);
    expect(result.reasonCodes).toContain("FAILED_LOGIN_WITH_RECOVERY");
  });

  it("gives a high-confidence signal to explicitly confirmed compromise", () => {
    const result = analyzeAccountTakeoverSignals([
      { eventType: "session_hijack_confirmed", occurredAt: new Date(now - 10_000).toISOString(), severity: "critical" },
    ], now);
    expect(result.score).toBe(100);
    expect(result.confidence).toBeGreaterThan(0.9);
  });

  it("ignores events from the future, malformed times, and quiet sessions", () => {
    const result = analyzeAccountTakeoverSignals([
      { eventType: "login_failed", occurredAt: "not-a-time" },
      { eventType: "login_failed", occurredAt: new Date(now + 1_000).toISOString() },
      { eventType: "ordinary_login", occurredAt: new Date(now - 10_000).toISOString() },
    ], now);
    expect(result.score).toBe(0);
    expect(result.reasonCodes).toHaveLength(0);
  });
});

describe("concurrent session anomaly detector", () => {
  it("does not flag ordinary use on one device", () => {
    const result = analyzeConcurrentSessionAnomalies([
      { deviceId: "device-a", ipId: "ip-a", startedAt: new Date(now - 60_000).toISOString() },
      { deviceId: "device-a", ipId: "ip-a", startedAt: new Date(now - 120_000).toISOString() },
    ], now);
    expect(result.score).toBe(0);
  });

  it("detects a wide multi-device and multi-network footprint", () => {
    const result = analyzeConcurrentSessionAnomalies(Array.from({ length: 6 }, (_, index) => ({
      deviceId: `device-${index}`,
      ipId: `ip-${index}`,
      startedAt: new Date(now - index * 30_000).toISOString(),
    })), now);
    expect(result.score).toBeGreaterThanOrEqual(70);
    expect(result.reasonCodes).toContain("DIVERSE_SESSION_FOOTPRINT");
  });
});

describe("impossible-travel detector", () => {
  it("detects fast movement between distant trusted GeoIP points", () => {
    const result = analyzeImpossibleTravel(
      { latitude: 40.7128, longitude: -74.006, occurredAt: new Date(now - 60 * 60_000).toISOString(), source: "trusted_geoip", countryCode: "US" },
      { latitude: 51.5072, longitude: -0.1276, occurredAt: new Date(now - 2_000).toISOString(), source: "trusted_geoip", countryCode: "GB" },
      now,
    );
    expect(result.applicable).toBe(true);
    expect(result.score).toBe(90);
    expect(result.reasonCodes).toContain("IMPOSSIBLE_TRAVEL");
  });

  it("does not flag missing or untrusted location metadata", () => {
    expect(analyzeImpossibleTravel(null, {
      latitude: 51, longitude: 0, occurredAt: new Date(now).toISOString(), source: "unknown",
    }, now).applicable).toBe(false);
  });

  it("does not return NaN for invalid coordinates or timestamps", () => {
    const result = analyzeImpossibleTravel(
      { latitude: Number.NaN, longitude: 0, occurredAt: new Date(now - 3_600_000).toISOString(), source: "trusted_geoip" },
      { latitude: 51, longitude: 0, occurredAt: new Date(now).toISOString(), source: "trusted_geoip" },
      now,
    );
    expect(result.score).toBe(0);
    expect(Number.isFinite(result.score)).toBe(true);
  });
});
