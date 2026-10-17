import { z } from "zod";
import type { SecurityDecision } from "./types";

const rank: Record<SecurityDecision, number> = {
  ALLOW: 0, MONITOR: 1, CHALLENGE: 2, REVIEW: 3, BLOCK: 4,
};
const floor: Record<SecurityDecision, number> = {
  ALLOW: 0, MONITOR: 1, CHALLENGE: 40, REVIEW: 70, BLOCK: 90,
};

const controlSchema = z.object({
  mode: z.enum(["hold", "block"]),
  reasonCode: z.string().min(1).max(80).regex(/^[A-Z0-9_.:-]+$/),
  expiresAt: z.string().datetime({ offset: true }),
}).strict();

export type SubjectTransactionControl = z.infer<typeof controlSchema>;

export function applySubjectTransactionControl(input: {
  decision: SecurityDecision;
  score: number;
  control?: SubjectTransactionControl | null;
  now?: number;
}) {
  const parsed = z.object({
    decision: z.enum(["ALLOW", "MONITOR", "CHALLENGE", "REVIEW", "BLOCK"]),
    score: z.number().finite().min(0).max(100),
    control: controlSchema.nullable().optional(),
    now: z.number().finite().optional(),
  }).strict().parse(input);
  const now = parsed.now ?? Date.now();
  const control = parsed.control && Date.parse(parsed.control.expiresAt) > now
    ? parsed.control
    : null;
  if (!control) {
    return {
      decision: parsed.decision,
      score: parsed.score,
      activeControl: null,
      reasonCodes: [] as string[],
      version: "adaptive-transaction-lock-v1" as const,
    };
  }

  const minimumDecision: SecurityDecision = control.mode === "block" ? "BLOCK" : "REVIEW";
  const decision = rank[minimumDecision] > rank[parsed.decision] ? minimumDecision : parsed.decision;
  const score = Math.max(parsed.score, floor[decision]);
  return {
    decision,
    score,
    activeControl: control,
    reasonCodes: [control.mode === "block" ? "SUBJECT_TRANSACTION_BLOCK_ACTIVE" : "SUBJECT_TRANSACTION_HOLD_ACTIVE", control.reasonCode],
    version: "adaptive-transaction-lock-v1" as const,
  };
}

/**
 * Creates or escalates a time-bound per-subject transaction lock. It never
 * downgrades an existing active block and never extends an unchanged lock
 * merely because a denied request was repeated.
 */
export function deriveSubjectTransactionControl(input: {
  decision: SecurityDecision;
  activeControl?: SubjectTransactionControl | null;
  now?: number;
  holdTtlMs?: number;
  blockTtlMs?: number;
}) {
  const parsed = z.object({
    decision: z.enum(["ALLOW", "MONITOR", "CHALLENGE", "REVIEW", "BLOCK"]),
    activeControl: controlSchema.nullable().optional(),
    now: z.number().finite().optional(),
    holdTtlMs: z.number().int().min(60_000).max(24 * 60 * 60_000).default(10 * 60_000),
    blockTtlMs: z.number().int().min(60_000).max(24 * 60 * 60_000).default(30 * 60_000),
  }).strict().parse(input);
  const now = parsed.now ?? Date.now();
  const active = parsed.activeControl && Date.parse(parsed.activeControl.expiresAt) > now
    ? parsed.activeControl
    : null;

  if (parsed.decision === "BLOCK" && active?.mode !== "block") {
    return {
      mode: "block" as const,
      reasonCode: "TX_ADAPTIVE_BLOCK",
      expiresAt: new Date(now + parsed.blockTtlMs).toISOString(),
      version: "adaptive-transaction-lock-v1" as const,
    };
  }
  if (parsed.decision === "REVIEW" && !active) {
    return {
      mode: "hold" as const,
      reasonCode: "TX_ADAPTIVE_HOLD",
      expiresAt: new Date(now + parsed.holdTtlMs).toISOString(),
      version: "adaptive-transaction-lock-v1" as const,
    };
  }
  return null;
}
