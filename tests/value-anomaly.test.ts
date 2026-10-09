import { describe, expect, it } from "vitest";
import { scoreValueJump } from "../src/security/valueAnomaly";

describe("value jump scoring", () => {
  it("does not score the first observed value baseline", () => {
    expect(scoreValueJump(10_000, true)).toBe(0);
  });

  it("ignores small changes", () => {
    expect(scoreValueJump(499)).toBe(0);
    expect(scoreValueJump(-499)).toBe(0);
  });

  it("scores large increases and decreases symmetrically", () => {
    expect(scoreValueJump(500)).toBe(50);
    expect(scoreValueJump(-1_000)).toBe(80);
    expect(scoreValueJump(10_000)).toBe(100);
    expect(scoreValueJump(-25_000)).toBe(100);
  });

  it("does not score non-finite values", () => {
    expect(scoreValueJump(Number.NaN)).toBe(0);
    expect(scoreValueJump(Number.POSITIVE_INFINITY)).toBe(0);
  });
});
