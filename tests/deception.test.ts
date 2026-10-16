import { describe, expect, it } from "vitest";
import { hashDeceptionLocator, isSafeDeceptionLocator } from "../src/security/deception";

describe("Part 5 deception locator registry", () => {
  it("accepts bounded synthetic HoneyDB keys and named canaries", () => {
    expect(isSafeDeceptionLocator("honeydb:admin:admin_login")).toBe(true);
    expect(isSafeDeceptionLocator("honeydb:environment:env_file")).toBe(true);
    expect(isSafeDeceptionLocator("route:/admin/login")).toBe(true);
    expect(isSafeDeceptionLocator("canary:backup:db-01")).toBe(true);
  });

  it("rejects query strings, path traversal and raw credential-like values", () => {
    expect(isSafeDeceptionLocator("honeydb:admin:../../env")).toBe(false);
    expect(isSafeDeceptionLocator("route:/admin/login?token=abc")).toBe(false);
    expect(isSafeDeceptionLocator("AWS_SECRET_ACCESS_KEY=abc")).toBe(false);
    expect(isSafeDeceptionLocator("route:")).toBe(false);
  });

  it("produces stable fixed-size hashes without storing the locator itself", () => {
    const locator = "honeydb:admin:admin_login";
    const digest = hashDeceptionLocator(locator);
    expect(digest).toMatch(/^[a-f0-9]{64}$/);
    expect(digest).toBe(hashDeceptionLocator(locator));
    expect(digest).not.toContain(locator);
    expect(digest).not.toBe(locator);
    expect(hashDeceptionLocator(locator)).not.toBe(hashDeceptionLocator("honeydb:admin:admin_panel"));
  });
});
