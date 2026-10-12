import { describe, expect, it } from "vitest";
import { safeErrorCode, safeErrorStatus } from "../src/security/observability";

describe("safe error diagnostics", () => {
  it("classifies invalid Supabase API keys without revealing message contents", () => {
    const code = safeErrorCode({ message: "Invalid API key: secret-value-must-never-appear", status: 401 });
    expect(code).toBe("SUPABASE_API_KEY_REJECTED");
    expect(code).not.toContain("secret-value");
    expect(safeErrorStatus({ status: 401 })).toBe(401);
  });

  it("normalizes PostgREST codes", () => {
    expect(safeErrorCode({ code: "PGRST106", message: "sensitive detail" })).toBe("PGRST106");
  });

  it("does not leak a raw error message for unknown provider errors", () => {
    expect(safeErrorCode({ message: "database password: super-secret" })).toBe("SUPABASE_RESPONSE_ERROR");
  });
});
