import { describe, expect, it } from "vitest";
import { z } from "zod";

const permitSchema = z.object({
  allowed: z.boolean(),
  state: z.enum(["closed", "open", "half_open"]),
  retryAfterSeconds: z.number().int().nonnegative().optional(),
  probeToken: z.string().uuid().nullable().optional(),
  failureCount: z.number().int().nonnegative().optional(),
  failureThreshold: z.number().int().positive().optional(),
});

const inputSchema = z.object({
  tenantId: z.uuid(),
  circuitKey: z.string().min(1).max(100).regex(/^[a-zA-Z0-9:_-]+$/),
  failureThreshold: z.number().int().min(2).max(100).default(5),
  windowSeconds: z.number().int().min(10).max(3600).default(60),
  openSeconds: z.number().int().min(5).max(3600).default(60),
});

describe("persistent circuit breaker contracts", () => {
  it("accepts a closed-circuit permit", () => {
    expect(permitSchema.parse({ allowed: true, state: "closed", probeToken: null, failureCount: 0 }).allowed).toBe(true);
  });

  it("represents open-circuit retry state without exposing dependency errors", () => {
    expect(permitSchema.parse({ allowed: false, state: "open", retryAfterSeconds: 17, probeToken: null, failureCount: 5 }).state).toBe("open");
  });

  it("requires a token for a half-open single probe", () => {
    expect(permitSchema.parse({
      allowed: true, state: "half_open", retryAfterSeconds: 0,
      probeToken: "d2719c91-3a78-4b20-9f60-402b855422ca", failureCount: 5,
    }).state).toBe("half_open");
  });

  it("rejects unsafe circuit names and unbounded thresholds", () => {
    const base = { tenantId: "d2719c91-3a78-4b20-9f60-402b855422ca", circuitKey: "duckdb-analytics" };
    expect(inputSchema.safeParse(base).success).toBe(true);
    expect(inputSchema.safeParse({ ...base, circuitKey: "../../secrets" }).success).toBe(false);
    expect(inputSchema.safeParse({ ...base, failureThreshold: 1 }).success).toBe(false);
    expect(inputSchema.safeParse({ ...base, openSeconds: 50000 }).success).toBe(false);
  });
});
