import { aggregateAIShadowPredictions, assertAIShadowOnly, type AIShadowAggregate } from "./ai-lab";
import type { SecurityCheckResult } from "./types";
import type { DecisionInput } from "./decision-engine";

export const PART7_ADAPTER_VERSION = "part7-adapter-v1" as const;

const clamp = (value: number) => Math.max(0, Math.min(100, value));

function hasReason(reasons: readonly string[], pattern: RegExp): boolean {
  return reasons.some((reason) => pattern.test(reason));
}

/**
 * Converts the authoritative Parts 1-6 aggregate into the normalized Part 7
 * evidence contract. The aggregate score is intentionally reused for each
 * deterministic dimension: Parts 1-6 already combine their detailed signals
 * before this boundary, so this adapter must not invent unsupported precision.
 */
export function buildPart7DecisionInput(args: {
  subjectRef: string;
  result: SecurityCheckResult & { networkControl?: { mode: string; reasonCode: string } };
  globalLockdown?: boolean;
  transactionFirewallDenied?: boolean;
  verifiedChallengePassed?: boolean;
}): { input: DecisionInput; aiShadow: AIShadowAggregate } {
  const result = args.result;
  const score = clamp(result.score);
  const reasons = [
    ...(result.challengeRecommendation?.reasonCodes ?? []),
    ...(result.networkControl?.reasonCode ? [result.networkControl.reasonCode] : []),
  ];

  const aiPredictions = [
    "pyod-optimized-ensemble",
    "pygod-dominant",
    "river-half-space-trees",
    "deepcase-sequence",
    "network-unsw-nb15",
    "openrouter-advisory",
  ].map((modelId) => ({
    modelId,
    score: 0,
    confidence: 0,
    available: false,
    latencyMs: 0,
    reasonCodes: ["MODEL_NOT_DEPLOYED_IN_PRODUCTION_SHADOW"],
    evidence: { adapterVersion: PART7_ADAPTER_VERSION },
  }));
  const aiShadow = aggregateAIShadowPredictions(aiPredictions);
  assertAIShadowOnly(aiShadow);

  const input: DecisionInput = {
    subjectRef: args.subjectRef,
    deterministic: {
      identityRisk: score,
      behaviorRisk: score,
      graphRisk: score,
      transactionRisk: score,
      accountHistoryRisk: score,
    },
    signals: {
      vpnDetected: hasReason(reasons, /VPN/i),
      proxyDetected: hasReason(reasons, /PROXY/i),
      torDetected: hasReason(reasons, /TOR/i),
      fingerprintChanged: hasReason(reasons, /FINGERPRINT/i),
      duplicateAccountSuspected: hasReason(reasons, /DUPLICATE_ACCOUNT/i),
      duplicateAccountConfirmed: hasReason(reasons, /CONFIRMED_DUPLICATE_ACCOUNT/i),
      securityAbuseAttemptConfirmed: hasReason(reasons, /SECURITY_ABUSE/i),
      credentialOrCookieTheftConfirmed: hasReason(reasons, /CREDENTIAL|COOKIE_THEFT/i),
      successfulUnauthorizedAccessConfirmed: hasReason(reasons, /UNAUTHORIZED_ACCESS/i),
      successfulExploitConfirmed: hasReason(reasons, /SUCCESSFUL_EXPLOIT/i),
      rewardFraudConfirmed: hasReason(reasons, /REWARD_FRAUD|FRAUD/i),
      maliciousAutomationConfirmed: hasReason(reasons, /MALICIOUS_AUTOMATION|BOT/i),
    },
    controls: {
      hardBlock: result.decision === "BLOCK",
      globalLockdown: args.globalLockdown ?? false,
      transactionFirewallDenied: args.transactionFirewallDenied ?? hasReason(reasons, /TRANSACTION_FIREWALL|FIREWALL_DENIED/i),
      verifiedChallengePassed: args.verifiedChallengePassed ?? false,
    },
    ai: aiShadow,
    policyVersion: "gainiren-policy-v1",
  };

  return { input, aiShadow };
}
