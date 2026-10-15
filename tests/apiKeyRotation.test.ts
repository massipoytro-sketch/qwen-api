import { describe, expect, it } from "vitest";
import { tenantApiKeyLookupFilter } from "../src/security/apiKeyRotation";

const hash = "a".repeat(64);

describe("bounded API key rotation lookup", () => {
  it("matches current credentials and limits previous credentials to the grace window", () => {
    expect(tenantApiKeyLookupFilter(hash, "2026-10-15T10:00:00.000Z")).toBe(
      `api_key_hash.eq.${hash},and(api_key_previous_hash.eq.${hash},api_key_previous_valid_until.gt.2026-10-15T10:00:00.000Z)`,
    );
  });

  it("rejects non-hash credential values before constructing a database filter", () => {
    expect(() => tenantApiKeyLookupFilter("raw-api-secret")).toThrow("INVALID_API_KEY_HASH");
    expect(() => tenantApiKeyLookupFilter("g".repeat(64))).toThrow("INVALID_API_KEY_HASH");
  });

  it("rejects malformed lookup timestamps", () => {
    expect(() => tenantApiKeyLookupFilter(hash, "not-a-time")).toThrow("INVALID_LOOKUP_TIME");
  });
});
