import { describe, expect, it } from "vitest";
import { isManagedKeyUsable } from "../src/security/apiKeyAuth";

const now = Date.parse("2026-10-14T12:00:00.000Z");

describe("managed tenant API key lifecycle", () => {
  it("accepts an active key after activation and before expiration", () => {
    expect(isManagedKeyUsable({
      status: "active",
      validFrom: new Date(now - 1000).toISOString(),
      expiresAt: new Date(now + 60_000).toISOString(),
    }, now)).toBe(true);
  });

  it("accepts a grace key only until its grace deadline", () => {
    const base = {
      status: "grace" as const,
      validFrom: new Date(now - 60_000).toISOString(),
      expiresAt: null,
      graceUntil: new Date(now + 60_000).toISOString(),
    };
    expect(isManagedKeyUsable(base, now)).toBe(true);
    expect(isManagedKeyUsable({ ...base, graceUntil: new Date(now - 1).toISOString() }, now)).toBe(false);
  });

  it("rejects revoked, not-yet-valid, and expired keys", () => {
    expect(isManagedKeyUsable({
      status: "revoked",
      validFrom: new Date(now - 60_000).toISOString(),
      expiresAt: null,
      graceUntil: null,
    }, now)).toBe(false);
    expect(isManagedKeyUsable({
      status: "active",
      validFrom: new Date(now + 60_000).toISOString(),
      expiresAt: null,
    }, now)).toBe(false);
    expect(isManagedKeyUsable({
      status: "active",
      validFrom: new Date(now - 60_000).toISOString(),
      expiresAt: new Date(now - 1).toISOString(),
    }, now)).toBe(false);
  });

  it("fails closed on invalid timestamps", () => {
    expect(isManagedKeyUsable({ status: "active", validFrom: "not-a-date" }, now)).toBe(false);
  });
});
