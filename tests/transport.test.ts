import { describe, expect, it } from "vitest";
import { isSecureTransport, securityHeaders } from "../src/security/transport";

describe("transport security", () => {
  it("emits strict browser isolation headers", () => {
    const headers = securityHeaders();
    expect(headers["strict-transport-security"]).toContain("max-age=31536000");
    expect(headers["content-security-policy"]).toContain("default-src 'none'");
    expect(headers["permissions-policy"]).toContain("camera=()");
    expect(headers["cross-origin-opener-policy"]).toBe("same-origin");
    expect(headers["cross-origin-resource-policy"]).toBe("same-origin");
  });

  it("requires the forwarded HTTPS scheme in production", () => {
    expect(isSecureTransport(new Request("http://security.example.test/api/security-check", {
      headers: { "x-forwarded-proto": "https" },
    }), true)).toBe(true);
    expect(isSecureTransport(new Request("http://security.example.test/api/security-check", {
      headers: { "x-forwarded-proto": "http" },
    }), true)).toBe(false);
  });

  it("rejects missing and malformed transport indicators in production", () => {
    expect(isSecureTransport(new Request("http://security.example.test/api/security-check"), true)).toBe(false);
    expect(isSecureTransport(new Request("https://security.example.test/api/security-check", {
      headers: { "x-forwarded-proto": "http" },
    }), true)).toBe(false);
  });

  it("allows local HTTP only when explicitly outside production", () => {
    expect(isSecureTransport(new Request("http://127.0.0.1:3000/api/security-check"), false)).toBe(true);
  });
});
