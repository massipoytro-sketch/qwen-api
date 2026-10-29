import { z } from "zod";
import type { DecisionAction, DecisionRecommendation } from "./decision-engine";

export const ENFORCEMENT_SCHEMA_VERSION = "part7-enforcement-v1" as const;

export const enforcementRequestSchema = z.object({
  decision: z.custom<DecisionRecommendation>(),
  currentStatus: z.enum(["ACTIVE", "MONITORED", "CHALLENGE", "RESTRICTED", "REWARDS_HELD", "SUSPENDED", "BANNED"]).default("ACTIVE"),
  nowMs: z.number().int().nonnegative(),
});

export type EnforcementStatus = z.infer<typeof enforcementRequestSchema>["currentStatus"];
export type EnforcementResult = Readonly<{
  schemaVersion: typeof ENFORCEMENT_SCHEMA_VERSION;
  subjectRef: string;
  status: EnforcementStatus;
  action: DecisionAction;
  requiresReview: boolean;
  reviewReason?: string;
  expiresAtMs?: number;
  sideEffectsPerformed: false;
}>;

export type ReviewAction = "RESTORE" | "KEEP_RESTRICTION" | "EXTEND" | "HOLD_BALANCE" | "SUSPEND_10D" | "PERMANENT_BAN";

export function recommendEnforcement(raw: z.input<typeof enforcementRequestSchema>): EnforcementResult {
  const input = enforcementRequestSchema.parse(raw);
  const d = input.decision;
  const common = { schemaVersion: ENFORCEMENT_SCHEMA_VERSION, subjectRef: d.subjectRef, action: d.action, sideEffectsPerformed: false as const };

  if (d.action === "LOCKDOWN") return { ...common, status: "RESTRICTED", requiresReview: true, reviewReason: "GLOBAL_LOCKDOWN_POLICY" };
  if (d.action === "BLOCK" || d.action === "DENY_TRANSACTION") return { ...common, status: "RESTRICTED", requiresReview: true, reviewReason: "HARD_SECURITY_CONTROL" };
  if (d.action === "PERMANENT_BAN") return { ...common, status: "BANNED", requiresReview: true, reviewReason: "PERMANENT_ACTION_REQUIRES_HUMAN_APPROVAL" };
  if (d.action === "HOLD_REWARDS") return { ...common, status: "REWARDS_HELD", requiresReview: true, reviewReason: "REWARDS_HOLD_REQUIRES_REVIEW" };
  if (d.action === "TEMP_RESTRICTION") return { ...common, status: "RESTRICTED", requiresReview: true, reviewReason: "TEMPORARY_RESTRICTION" };
  if (d.action === "CHALLENGE") return { ...common, status: "CHALLENGE", requiresReview: false };
  if (d.action === "HUMAN_REVIEW") return { ...common, status: "MONITORED", requiresReview: true, reviewReason: "RISK_REQUIRES_HUMAN_REVIEW" };
  if (d.action === "MONITOR") return { ...common, status: "MONITORED", requiresReview: false };
  return { ...common, status: "ACTIVE", requiresReview: false };
}

const reviewTransitionSchema = z.object({
  currentStatus: enforcementRequestSchema.shape.currentStatus,
  action: z.enum(["RESTORE", "KEEP_RESTRICTION", "EXTEND", "HOLD_BALANCE", "SUSPEND_10D", "PERMANENT_BAN"]),
  nowMs: z.number().int().nonnegative(),
  extensionMs: z.number().int().positive().max(90 * 24 * 60 * 60 * 1000).optional(),
});

function assertAllowedReviewTransition(currentStatus: EnforcementStatus, action: ReviewAction): void {
  const allowed: Record<ReviewAction, readonly EnforcementStatus[]> = {
    RESTORE: ["MONITORED", "CHALLENGE", "RESTRICTED", "REWARDS_HELD", "SUSPENDED"],
    KEEP_RESTRICTION: ["RESTRICTED", "SUSPENDED"],
    EXTEND: ["SUSPENDED"],
    HOLD_BALANCE: ["MONITORED", "CHALLENGE", "RESTRICTED", "REWARDS_HELD", "SUSPENDED"],
    SUSPEND_10D: ["MONITORED", "CHALLENGE", "RESTRICTED", "REWARDS_HELD", "SUSPENDED"],
    PERMANENT_BAN: ["MONITORED", "CHALLENGE", "RESTRICTED", "REWARDS_HELD", "SUSPENDED"],
  };

  if (!allowed[action].includes(currentStatus)) {
    throw new Error(`INVALID_REVIEW_TRANSITION:${currentStatus}->${action}`);
  }
}

export function recommendReviewTransition(input: z.input<typeof reviewTransitionSchema>): Readonly<{ status: EnforcementStatus; expiresAtMs?: number; requiresAudit: true }> {
  const parsed = reviewTransitionSchema.parse(input);
  assertAllowedReviewTransition(parsed.currentStatus, parsed.action);

  if (parsed.action === "RESTORE") return { status: "ACTIVE", requiresAudit: true };
  if (parsed.action === "KEEP_RESTRICTION") return { status: "RESTRICTED", requiresAudit: true };
  if (parsed.action === "HOLD_BALANCE") return { status: "REWARDS_HELD", requiresAudit: true };
  if (parsed.action === "SUSPEND_10D") return { status: "SUSPENDED", expiresAtMs: parsed.nowMs + 10 * 24 * 60 * 60 * 1000, requiresAudit: true };
  if (parsed.action === "PERMANENT_BAN") return { status: "BANNED", requiresAudit: true };
  return { status: "SUSPENDED", expiresAtMs: parsed.nowMs + (parsed.extensionMs ?? 24 * 60 * 60 * 1000), requiresAudit: true };
}
