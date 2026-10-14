import { describe, expect, it } from "vitest";
import { securityHeaders } from "../src/security/transport";

describe("transport security",()=>{
 it("emits strict browser isolation headers",()=>{const headers=securityHeaders();expect(headers["strict-transport-security"]).toContain("max-age=31536000");expect(headers["content-security-policy"]).toContain("default-src 'none'");expect(headers["permissions-policy"]).toContain("camera=()");expect(headers["cross-origin-opener-policy"]).toBe("same-origin");expect(headers["cross-origin-resource-policy"]).toBe("same-origin");});
});
