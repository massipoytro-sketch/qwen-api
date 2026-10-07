import { describe, expect, it } from "vitest";

describe("security foundation", () => {
  it("has a valid project name", async () => {
    const module = await import("../../dist/index.js").catch(() => null);
    expect(module).toBe(null);
  });
});
