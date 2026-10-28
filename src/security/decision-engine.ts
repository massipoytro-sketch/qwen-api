import { z } from "zod";

export const DECISION_ENGINE_VERSION = "part7-decision-v2" as const;

const aiEvidenceSchema = z.object({
  schemaVersion: z.literal("ai_shadow_signal_v1"),
  mode: z.literal("shadow"),
  advisoryOnly: z.literal(true),
  score: z.number().finite().min(0).max(100),
  confidence: z.number().finite().min(0).max(1),
  modelCount: z.number().int().nonnegative().max(100),
  availableModelCount: z.number().int().nonnegative().max(100),
  predictions: z.array(z.unknown()).max(100),
  reasonCodes: z.array(z.string().min(1).max(100)).max(64),
});

export const decisionInputSchema = z.object({
  subjectRef: z.string().min(1).max(128),
  deterministic: z.object({
    identityRisk: z.number().finite().min(0).max(100),
    behaviorRisk: z.number().finite().min(0).max(100),
    graphRisk: z.number().finite().min(0).max(100),
    transactionRisk: z.number().finite().min(0).max(100),
    accountHistoryRisk: z.number().finite().min(0).max(100),
  }),
  signals: z.object({
    vpnDetected: z.boolean().default(false),
    proxyDetected: z.boolean().default(false),
    torDetected: z.boolean().default(false),
    fingerprintChanged: z.boolean().default(false),
    duplicateAccountSuspected: z.boolean().default(false),
    duplicateAccountConfirmed: z.boolean().default(false),
    securityAbuseAttemptConfirmed: z.boolean().default(false),
    credentialOrCookieTheftConfirmed: z.boolean().default(false),
    successfulUnauthorizedAccessConfirmed: z.boolean().default(false),
    successfulExploitConfirmed: z.boolean().default(false),
    rewardFraudConfirmed: z.boolean().default(false),
    maliciousAutomationConfirmed: z.boolean().default(false),
  }).default({}),
  controls: z.object({
    hardBlock: z.boolean().default(false),
    globalLockdown: z.boolean().default(false),
    transactionFirewallDenied: z.boolean().default(false),
    verifiedChallengePassed: z.boolean().default(false),
  }),
  ai: aiEvidenceSchema.optional(),
  policyVersion: z.string().min(1).max(64).default("gainiren-policy-v1"),
});

export type DecisionInput = z.input<typeof decisionInputSchema>;
export type DecisionAction =
  | "BLOCK" | "LOCKDOWN" | "DENY_TRANSACTION" | "ALLOW" | "MONITOR"
  | "CHALLENGE" | "HOLD_REWARDS" | "TEMP_RESTRICTION" | "HUMAN_REVIEW"
  | "PERMANENT_BAN";

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

/**
 * Part 7A policy/decision foundation.
 * It only produces a recommendation. Enforcement belongs to the later Part 7B layer.
 * Weak infrastructure indicators never become a ban by themselves.
 */
export function recommendSecurityAction(raw: DecisionInput): DecisionRecommendation {
  const input = decisionInputSchema.parse(raw);
  const signals = input.signals;

  if (input.controls.globalLockdown) {
    return result(input.subjectRef, "LOCKDOWN", 100, 100, 0, input.policyVersion, ["GLOBAL_LOCKDOWN_ACTIVE"], true);
  }
  if (input.controls.hardBlock) {
    return result(input.subjectRef, "BLOCK", 100, 100, 0, input.policyVersion, ["DETERMINISTIC_HARD_BLOCK"], true);
  }
  if (input.controls.transactionFirewallDenied) {
    return result(input.subjectRef, "DENY_TRANSACTION", 100, 100, 0, input.policyVersion, ["TRANSACTION_FIREWALL_DENIED"], true);
  }

  // Confirmed high-impact compromise/security abuse has explicit policy precedence.
  if (signals.credentialOrCookieTheftConfirmed || signals.successfulUnauthorizedAccessConfirmed || signals.successfulExploitConfirmed) {
    const reasons = [
      ...(signals.credentialOrCookieTheftConfirmed ? ["CONFIRMED_CREDENTIAL_OR_COOKIE_THEFT"] : []),
      ...(signals.successfulUnauthorizedAccessConfirmed ? ["CONFIRMED_UNAUTHORIZED_ACCESS"] : []),
      ...(signals.successfulExploitConfirmed ? ["CONFIRMED_SUCCESSFUL_EXPLOIT"] : []),
      "PERMANENT_ENFORCEMENT_REQUIRES_HUMAN_APPROVAL",
    ];
    return result(input.subjectRef, "PERMANENT_BAN", 100, 100, 0, input.policyVersion, reasons, true);
  }

  const baseScore = clamp(deterministicRisk(input.deterministic));
  const aiUsable = input.ai !== undefined && input.ai.availableModelCount > 0;
  const aiContribution = aiUsable ? clamp(input.ai.score) * 0.15 : 0;
  const riskScore = round(clamp(baseScore * 0.85 + aiContribution));
  const reasons: string[] = [];

  const networkRestriction = signals.vpnDetected || signals.proxyDetected || signals.torDetected;
  if (signals.vpnDetected) reasons.push("VPN_DETECTED_ACCESS_RESTRICTION");
  if (signals.proxyDetected) reasons.push("PROXY_DETECTED_ACCESS_RESTRICTION");
  if (signals.torDetected) reasons.push("TOR_DETECTED_ACCESS_RESTRICTION");
  if (signals.fingerprintChanged) reasons.push("FINGERPRINT_CHANGED_NOT_FRAUD_PROOF");

  if (signals.duplicateAccountConfirmed) reasons.push("CONFIRMED_DUPLICATE_ACCOUNT");
  else if (signals.duplicateAccountSuspected) reasons.push("DUPLICATE_ACCOUNT_REQUIRES_REVIEW");

  if (signals.rewardFraudConfirmed) reasons.push("CONFIRMED_REWARD_FRAUD");
  if (signals.maliciousAutomationConfirmed) reasons.push("CONFIRMED_MALICIOUS_AUTOMATION");
  if (signals.securityAbuseAttemptConfirmed) reasons.push("CONFIRMED_SECURITY_ABUSE_ATTEMPT");
  if (baseScore >= 70) reasons.push("HIGH_DETERMINISTIC_RISK");
  if (aiUsable && input.ai.score >= 70) reasons.push("AI_HIGH_RISK_ADVISORY");
  if (!aiUsable) reasons.push("AI_NOT_USED");
  if (input.controls.verifiedChallengePassed) reasons.push("CHALLENGE_ALREADY_PASSED");

  if (signals.credentialOrCookieTheftConfirmed || signals.successfulUnauthorizedAccessConfirmed || signals.successfulExploitConfirmed) {
    return result(input.subjectRef, "PERMANENT_BAN", 100, round(baseScore), round(aiContribution), input.policyVersion,
      [...reasons, "PERMANENT_ENFORCEMENT_REQUIRES_HUMAN_APPROVAL"], true);
  }

  if (signals.rewardFraudConfirmed || signals.maliciousAutomationConfirmed) {
    return result(input.subjectRef, "HOLD_REWARDS", Math.max(riskScore, 75), round(baseScore), round(aiContribution), input.policyVersion,
      [...reasons, "REWARD_ACTIVITY_HELD_PENDING_REVIEW"], true);
  }

  if (signals.securityAbuseAttemptConfirmed) {
    return result(input.subjectRef, "HOLD_REWARDS", Math.max(riskScore, 60), round(baseScore), round(aiContribution), input.policyVersion,
      [...reasons, "SECURITY_ABUSE_ACTIVITY_HELD_PENDING_REVIEW"], true);
  }

  if (signals.duplicateAccountConfirmed) {
    return result(input.subjectRef, "HOLD_REWARDS", Math.max(riskScore, 60), round(baseScore), round(aiContribution), input.policyVersion,
      [...reasons, "SECONDARY_ACCOUNT_RESTRICTED_PENDING_REVIEW"], true);
  }

  if (networkRestriction) {
    return result(input.subjectRef, "CHALLENGE", Math.max(40, riskScore), round(baseScore), round(aiContribution), input.policyVersion,
      [...reasons, "DISABLE_VPN_PROXY_TOR_TO_CONTINUE"], false);
  }

  if (riskScore >= 85) {
    return result(input.subjectRef, "HUMAN_REVIEW", riskScore, round(baseScore), round(aiContribution), input.policyVersion,
      [...reasons, "CRITICAL_RISK_REQUIRES_HUMAN_REVIEW"], true);
  }
  if (riskScore >= 70) {
    return result(input.subjectRef, "HOLD_REWARDS", riskScore, round(baseScore), round(aiContribution), input.policyVersion,
      [...reasons, "REWARD_HOLD_RECOMMENDED"], true);
  }
  if (riskScore >= 50) {
    const action = input.controls.verifiedChallengePassed ? "TEMP_RESTRICTION" : "CHALLENGE";
    return result(input.subjectRef, action, riskScore, round(baseScore), round(aiContribution), input.policyVersion,
      [...reasons, input.controls.verifiedChallengePassed ? "RESTRICTION_RECOMMENDED" : "STEP_UP_CHALLENGE_RECOMMENDED"], false);
  }
  if (riskScore >= 25) {
    return result(input.subjectRef, "MONITOR", riskScore, round(baseScore), round(aiContribution), input.policyVersion,
      [...reasons, "ELEVATED_RISK_MONITORING"], false);
  }
  return result(input.subjectRef, "ALLOW", riskScore, round(baseScore), round(aiContribution), input.policyVersion,
    [...reasons, "RISK_BELOW_ACTION_THRESHOLD"], false);
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
