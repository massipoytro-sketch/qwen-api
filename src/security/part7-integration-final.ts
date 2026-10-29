import type { DecisionInput, DecisionRecommendation, DecisionAction } from "./decision-engine";
import { recommendSecurityAction } from "./decision-engine";
import { recommendEnforcement, type EnforcementResult, type EnforcementStatus } from "./enforcement-review";

export const PART7_INTEGRATION_SCHEMA_VERSION = "part7-integration-v1" as const;

export type Part7IntegrationResult = Readonly<{
  schemaVersion: typeof PART7_INTEGRATION_SCHEMA_VERSION;
  decision: DecisionRecommendation;
  enforcement: EnforcementResult;
  failClosed: boolean;
  sideEffectsPerformed: false;
}>;

export function evaluatePart7(input: DecisionInput & { currentStatus?: EnforcementStatus; nowMs: number }): Part7IntegrationResult {
  const decision = recommendSecurityAction(input);
  const enforcement = recommendEnforcement({ decision, currentStatus: input.currentStatus ?? "ACTIVE", nowMs: input.nowMs });
  return { schemaVersion: PART7_INTEGRATION_SCHEMA_VERSION, decision, enforcement, failClosed: isHardSecurityAction(decision.action), sideEffectsPerformed: false };
}

export function isHardSecurityAction(action: DecisionAction): boolean {
  return action === "BLOCK" || action === "LOCKDOWN" || action === "DENY_TRANSACTION";
}
