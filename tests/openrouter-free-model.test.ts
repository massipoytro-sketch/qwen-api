import { describe, expect, it } from "vitest";
import { validateOpenRouterModel } from "../src/security/ai";

describe("OpenRouter free Nemotron integration", () => {
  it("accepts the pinned free Nemotron 3 Ultra model id", () => {
    expect(validateOpenRouterModel("nvidia/nemotron-3-ultra-550b-a55b:free"))
      .toBe("nvidia/nemotron-3-ultra-550b-a55b:free");
  });

  it("rejects malformed model ids", () => {
    expect(() => validateOpenRouterModel("https://evil.invalid/model"))
      .toThrow();
    expect(() => validateOpenRouterModel("../model"))
      .toThrow();
  });
});
