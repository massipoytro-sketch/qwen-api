import { z } from "zod";
import type { SecurityDecision } from "./types";

const decisionRank: Record<SecurityDecision, number> = {
  ALLOW: 0,
  MONITOR: 1,
  CHALLENGE: 2,
  REVIEW: 3,
  BLOCK: 4,
};

const challengeSchema = z.object({
  type: z.enum(["step_up_mfa", "proof_of_work", "risk_based_verification"]),
  reasonCodes: z.array(z.string().min(1).max(100).regex(/^[A-Z0-9_.:-]+$/)).max(32),
  expiresInSeconds: z.number().int().min(30).max(900),
}).strict();

const inputSchema = z.object({
  decisions: z.array(z.enum(["ALLOW", "MONITOR", "CHALLENGE", "REVIEW", "BLOCK"])).min(1).max(8),
  requestId: z.string().min(1).max(200).regex(/^[A-Za-z0-9._:-]+$/),
  reasonCodes: z.array(z.string().min(1).max(100).regex(/^[A-Z0-9_.:-]+$/)).max(128).default([]),
  challenge: challengeSchema.nullable().optional(),
}).strict();

export type ChallengeRecommendation = z.infer<typeof challengeSchema>;

export function strictestDecision(...decisions: SecurityDecision[]): SecurityDecision {
  return decisions.reduce<SecurityDecision>((best, current) =>
    decisionRank[current] > decisionRank[best] ? current : best, "ALLOW");
}

/**
 * Produces the stable contract that GainiRen consumes at its enforcement
 * boundary. Every contributing decision is considered in restrictive order;
 * BLOCK cannot be overwritten by a lower action. A challenge recommendation is
 * descriptive only: clients must request a durable, single-use challenge from
 * /api/challenge and complete it using the authenticated server-side flow.
 */
export function buildEnforcementContract(input: z.input<typeof inputSchema>) {
  const parsed = inputSchema.parse(input);
  const decision = strictestDecision(...parsed.decisions);
  const action =
    decision === "BLOCK" ? "deny" :
    decision === "REVIEW" ? "hold_for_review" :
    decision === "CHALLENGE" ? "challenge" :
    decision === "MONITOR" ? "allow_with_monitoring" : "allow";

  const challenge = decision === "CHALLENGE" ? parsed.challenge ?? null : null;
  return {
    version: "enforcement-v1" as const,
    requestId: parsed.requestId,
    decision,
    action,
    reasonCodes: [...new Set(parsed.reasonCodes)].slice(0, 64),
    challenge,
    challengeEndpoint: challenge ? "/api/challenge" as const : null,
    challengeCompletionAuthority: challenge ? "tenant_server" as const : null,
    retryable: decision !== "BLOCK",
  };
}

/** Minimum score implied by a decision; can only raise, never reduce, score. */
export function scoreFloorForEnforcement(decision: SecurityDecision): number {
  switch (decision) {
    case "ALLOW": return 0;
    case "MONITOR": return 1;
    case "CHALLENGE": return 40;
    case "REVIEW": return 70;
    case "BLOCK": return 90;
  }
}
