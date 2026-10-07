import { describe, expect, it } from "vitest";
import { PROJECT_NAME, SECURITY_DECISIONS } from "../src/index";

describe("security foundation", () => {
  it("exposes the project identity", () => {
    expect(PROJECT_NAME).toBe("GainiRen Security");
  });

  it("defines the five initial security decisions", () => {
    expect(SECURITY_DECISIONS).toEqual([
      "ALLOW",
      "MONITOR",
      "CHALLENGE",
      "REVIEW",
      "BLOCK",
    ]);
  });
});

describe("risk boundaries", () => {
  it("keeps the decision ordering explicit", () => {
    expect(SECURITY_DECISIONS.indexOf("ALLOW")).toBe(0);
    expect(SECURITY_DECISIONS.indexOf("BLOCK")).toBe(4);
  });
});
