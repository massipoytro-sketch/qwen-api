import { z } from "zod";
import { scoreValueJump } from "./valueAnomaly";
import type { SecurityDecision } from "./types";

const rank: Record<SecurityDecision, number> = {
  ALLOW: 0,
  MONITOR: 1,
  CHALLENGE: 2,
  REVIEW: 3,
  BLOCK: 4,
};
const clamp = (value: number) => Math.max(0, Math.min(100, Math.round(value)));

const operationSchema = z.enum([
  "earn",
  "reward_credit",
  "redeem",
  "purchase",
  "deposit",
  "transfer",
  "withdrawal",
  "payout",
  "refund",
  "wallet_adjustment",
]);

const inputSchema = z.object({
  operation: operationSchema,
  baseDecision: z.enum(["ALLOW", "MONITOR", "CHALLENGE", "REVIEW", "BLOCK"]),
  baseScore: z.number().finite().min(0).max(100),
  attackPathScore: z.number().finite().min(0).max(100).default(0),
  attackPathConfidence: z.number().finite().min(0).max(1).default(0),
  previousValue: z.number().finite().min(0).max(1e15).optional(),
  currentValue: z.number().finite().min(0).max(1e15).optional(),
  amount: z.number().finite().min(0).max(1e15).optional(),
  currency: z.string().regex(/^[A-Z][A-Z0-9_]{1,11}$/).optional(),
  recentOperations1m: z.number().int().min(0).max(10000).default(0),
  recentOperations5m: z.number().int().min(0).max(10000).default(0),
}).strict().superRefine((value, context) => {
  if ((value.previousValue === undefined) !== (value.currentValue === undefined)) {
    context.addIssue({
      code: "custom",
      path: ["currentValue"],
      message: "previousValue and currentValue must be supplied together",
    });
  }
});

const operationFloor: Record<z.infer<typeof operationSchema>, number> = {
  earn: 8,
  reward_credit: 10,
  redeem: 15,
  purchase: 8,
  deposit: 10,
  transfer: 18,
  withdrawal: 22,
  payout: 25,
  refund: 16,
  wallet_adjustment: 25,
};

function strongest(...decisions: SecurityDecision[]): SecurityDecision {
  return decisions.reduce((best, candidate) => rank[candidate] > rank[best] ? candidate : best, "ALLOW");
}

function scoreDecision(score: number, independentStrongCues: number, operation: z.infer<typeof operationSchema>): SecurityDecision {
  if (score >= 95 && independentStrongCues >= 2) return "BLOCK";
  if (score >= 78 && (["transfer", "withdrawal", "payout", "refund", "wallet_adjustment", "redeem"].includes(operation) || independentStrongCues >= 2)) return "REVIEW";
  if (score >= 50 || independentStrongCues >= 1) return "CHALLENGE";
  if (score > 0) return "MONITOR";
  return "ALLOW";
}

/**
 * Deterministic transaction decisioning. Values must come from the trusted
 * application backend / ledger, never directly from the browser.
 * The caller must prevent the wallet mutation unless commitAllowed is true.
 */
export function evaluateTransactionFirewall(rawInput: {
  operation: z.infer<typeof operationSchema>;
  baseDecision: SecurityDecision;
  baseScore: number;
  attackPathScore?: number;
  attackPathConfidence?: number;
  previousValue?: number;
  currentValue?: number;
  amount?: number;
  currency?: string;
  recentOperations1m?: number;
  recentOperations5m?: number;
}) {
  const input = inputSchema.parse({
    ...rawInput,
    attackPathScore: rawInput.attackPathScore ?? 0,
    attackPathConfidence: rawInput.attackPathConfidence ?? 0,
    recentOperations1m: rawInput.recentOperations1m ?? 0,
    recentOperations5m: rawInput.recentOperations5m ?? 0,
  });

  const valueDelta = input.previousValue !== undefined && input.currentValue !== undefined
    ? input.currentValue - input.previousValue
    : null;
  const valueJumpScore = valueDelta === null ? 0 : scoreValueJump(valueDelta);
  const velocityScore = clamp(
    (input.recentOperations1m >= 20 ? 80 : input.recentOperations1m >= 10 ? 60 : input.recentOperations1m >= 5 ? 35 : 0) * 0.7 +
    (input.recentOperations5m >= 50 ? 80 : input.recentOperations5m >= 25 ? 55 : input.recentOperations5m >= 10 ? 30 : 0) * 0.3,
  );

  const highRiskOperation = ["transfer", "withdrawal", "payout", "refund", "wallet_adjustment", "redeem"].includes(input.operation);
  const strongCues = [
    valueJumpScore >= 65,
    input.attackPathScore >= 65 && input.attackPathConfidence >= 0.7,
    velocityScore >= 60,
  ].filter(Boolean).length;

  const synergy = strongCues >= 2 ? 12 : strongCues === 1 && highRiskOperation ? 4 : 0;
  const score = clamp(Math.max(
    input.baseScore,
    operationFloor[input.operation],
    valueJumpScore,
    velocityScore,
    input.attackPathScore,
  ) + synergy);

  const generatedDecision = scoreDecision(score, strongCues, input.operation);
  const decision = strongest(input.baseDecision, generatedDecision);
  const confidence = Math.min(0.98, Math.max(
    0.4,
    strongCues >= 2 ? 0.9 + Math.min(0.08, (strongCues - 2) * 0.04) :
      input.attackPathScore > 0 ? input.attackPathConfidence :
        valueJumpScore > 0 ? 0.72 : velocityScore > 0 ? 0.7 : 0.55,
  ));

  const reasonCodes = [
    "SENSITIVE_OPERATION",
    ...(valueJumpScore >= 40 ? ["TRANSACTION_VALUE_DELTA"] : []),
    ...(valueJumpScore >= 80 ? ["TRANSACTION_EXTREME_VALUE_DELTA"] : []),
    ...(velocityScore >= 35 ? ["TRANSACTION_VELOCITY"] : []),
    ...(input.attackPathScore >= 50 ? ["TRANSACTION_ATTACK_PATH_CORRELATION"] : []),
    ...(strongCues >= 2 ? ["TRANSACTION_MULTI_SIGNAL_CONFIRMATION"] : []),
    ...(highRiskOperation ? ["HIGH_IMPACT_OPERATION"] : []),
  ];

  const outcome = decision === "BLOCK" ? "BLOCK" :
    decision === "REVIEW" ? "HOLD" :
      decision === "CHALLENGE" ? "CHALLENGE" :
        decision === "MONITOR" ? "ALLOW_MONITORED" : "ALLOW";
  const adaptiveControl = decision === "BLOCK" ? "restrict_subject_transactions" :
    decision === "REVIEW" ? "hold_transaction" :
      decision === "CHALLENGE" ? "step_up_verification" : "none";

  return {
    decision,
    score,
    confidence: Number(confidence.toFixed(4)),
    outcome,
    commitAllowed: decision === "ALLOW" || decision === "MONITOR",
    adaptiveControl,
    reasonCodes: [...new Set(reasonCodes)],
    valueDelta,
    valueJumpScore,
    velocityScore,
    independentStrongCueCount: strongCues,
    highRiskOperation,
    version: "transaction-firewall-v1",
  } as const;
}
