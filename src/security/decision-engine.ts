import { z } from "zod";
import type { AIShadowAggregate } from "./ai-lab";

export const DECISION_ENGINE_VERSION = "part7-decision-v1" as const;

/** Pure recommendation only: no account, wallet, session, transaction, or enforcement side effects. */
export const decisionInputSchema = z.object({
  subjectRef: z.string().min(1).max(128),
  deterministic: z.object({
    identityRisk: z.number().finite().min(0).max(100),
    behaviorRisk: z.number().finite().min(0).max(100),
    graphRisk: z.number().finite().min(0).max(100),
    transactionRisk: z.number().finite().min(0).max(100),
    accountHistoryRisk: z.number().finite().min(0).max(100),
  }),
  controls: z.object({
    hardBlock: z.boolean().default(false),
    globalLockdown: z.boolean().default(false),
    transactionFirewallDenied: z.boolean().default(false),
    verifiedChallengePassed: z.boolean().default(false),
  }),
  ai: z.custom<AIShadowAggregate>().optional(),
  policyVersion: z.string().min(1).max(64).default("gainiren-policy-v1"),
});

export type DecisionInput = z.input<typeof decisionInputSchema>;
export type DecisionAction =
  | "BLOCK" | "LOCKDOWN" | "DENY_TRANSACTION" | "ALLOW" | "MONITOR"
  | "CHALLENGE" | "HOLD_REWARDS" | "TEMP_RESTRICTION" | "HUMAN_REVIEW";

export type DecisionRecommendation = Readonly<{
  schemaVersion: typeof DECISION_ENGINE_VERSION;
  subjectRef: string;
  action: DecisionAction;
  riskScore: number;
  deterministicScore: number;
  aiContribution: number;
  policyVersion: string;
  reasonCodes: readonly string[];
  requiresHumanApproval: boolean;
  recommendationOnly: true;
  sideEffectsPerformed: false;
}>;

const clamp = (value: number, min = 0, max = 100) => Math.max(min, Math.min(max, value));
const round = (value: number) => Math.round(value * 100) / 100;

function deterministicRisk(input: z.infer<typeof decisionInputSchema>["deterministic"]): number {
  return input.identityRisk * 0.20
    + input.behaviorRisk * 0.25
    + input.graphRisk * 0.20
    + input.transactionRisk * 0.25
    + input.accountHistoryRisk * 0.10;
}

export function recommendSecurityAction(raw: DecisionInput): DecisionRecommendation {
  const input = decisionInputSchema.parse(raw);
  if (input.controls.globalLockdown) {
    return result(input.subjectRef, "LOCKDOWN", 100, 100, 0, input.policyVersion, ["GLOBAL_LOCKDOWN_ACTIVE"], true);
  }
  if (input.controls.hardBlock) {
    return result(input.subjectRef, "BLOCK", 100, 100, 0, input.policyVersion, ["DETERMINISTIC_HARD_BLOCK"], true);
  }
  if (input.controls.transactionFirewallDenied) {
    return result(input.subjectRef, "DENY_TRANSACTION", 100, 100, 0, input.policyVersion, ["TRANSACTION_FIREWALL_DENIED"], true);
  }

  const baseScore = clamp(deterministicRisk(input.deterministic));
  const aiUsable = input.ai?.mode === "shadow"
    && input.ai.advisoryOnly === true
    && input.ai.availableModelCount > 0
    && Number.isFinite(input.ai.score)
    && input.ai.score >= 0
    && input.ai.score <= 100;
  // At most 15 points of final risk can originate from AI.
  const aiContribution = aiUsable ? clamp(input.ai!.score) * 0.15 : 0;
  const riskScore = round(clamp(baseScore * 0.85 + aiContribution));
  const reasons: string[] = [];
  if (baseScore >= 70) reasons.push("HIGH_DETERMINISTIC_RISK");
  if (aiUsable && input.ai!.score >= 70) reasons.push("AI_HIGH_RISK_ADVISORY");
  if (!aiUsable) reasons.push("AI_NOT_USED");
  if (input.controls.verifiedChallengePassed) reasons.push("CHALLENGE_ALREADY_PASSED");

  let action: DecisionAction;
  let requiresHumanApproval = false;
  if (riskScore >= 85) {
    action = "HUMAN_REVIEW";
    requiresHumanApproval = true;
    reasons.push("CRITICAL_RISK_REQUIRES_HUMAN_REVIEW");
  } else if (riskScore >= 70) {
    action = "HOLD_REWARDS";
    reasons.push("REWARD_HOLD_RECOMMENDED");
  } else if (riskScore >= 50) {
    action = input.controls.verifiedChallengePassed ? "TEMP_RESTRICTION" : "CHALLENGE";
    reasons.push(input.controls.verifiedChallengePassed ? "RESTRICTION_RECOMMENDED" : "STEP_UP_CHALLENGE_RECOMMENDED");
  } else if (riskScore >= 25) {
    action = "MONITOR";
    reasons.push("ELEVATED_RISK_MONITORING");
  } else {
    action = "ALLOW";
    reasons.push("RISK_BELOW_ACTION_THRESHOLD");
  }
  return result(input.subjectRef, action, riskScore, round(baseScore), round(aiContribution), input.policyVersion, reasons, requiresHumanApproval);
}

function result(
  subjectRef: string, action: DecisionAction, riskScore: number, deterministicScore: number,
  aiContribution: number, policyVersion: string, reasonCodes: string[], requiresHumanApproval: boolean,
): DecisionRecommendation {
  return Object.freeze({
    schemaVersion: DECISION_ENGINE_VERSION, subjectRef, action,
    riskScore: round(riskScore), deterministicScore: round(deterministicScore),
    aiContribution: round(aiContribution), policyVersion,
    reasonCodes: [...new Set(reasonCodes)].slice(0, 32), requiresHumanApproval,
    recommendationOnly: true, sideEffectsPerformed: false,
  });
}
