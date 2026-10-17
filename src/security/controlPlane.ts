import { z } from "zod";

export const controlModeSchema = z.enum(["normal", "review_only", "lockdown"]);
export const sessionStatusSchema = z.enum(["active", "revoked", "expired", "unknown"]);
export type ControlMode = z.infer<typeof controlModeSchema>;
export type SessionStatus = z.infer<typeof sessionStatusSchema>;

const rank = { normal: 0, review_only: 1, lockdown: 2 } as const;
export type ControlSnapshot = {
  globalMode: ControlMode;
  tenantMode: ControlMode;
  subjectMode: "normal" | "hold" | "block";
  sessionStatus: SessionStatus;
  loadedAt: string;
  version: number;
};

export function evaluateControlPlane(input: {
  snapshot: ControlSnapshot | null;
  now?: number;
  maxAgeMs?: number;
}) {
  const parsed = z.object({
    snapshot: z.object({
      globalMode: controlModeSchema,
      tenantMode: controlModeSchema,
      subjectMode: z.enum(["normal", "hold", "block"]),
      sessionStatus: sessionStatusSchema,
      loadedAt: z.string().datetime({ offset: true }),
      version: z.number().int().nonnegative(),
    }).strict().nullable(),
    now: z.number().finite().optional(),
    maxAgeMs: z.number().int().min(100).max(60_000).default(5_000),
  }).strict().parse(input);
  const now = parsed.now ?? Date.now();
  const snapshot = parsed.snapshot;
  // Missing/stale state is not equivalent to a healthy system.
  if (!snapshot || now - Date.parse(snapshot.loadedAt) > parsed.maxAgeMs || Date.parse(snapshot.loadedAt) > now + 1_000) {
    return { allowed: false, mode: "lockdown" as const, decisionFloor: "BLOCK" as const, reasonCodes: ["CONTROL_PLANE_UNAVAILABLE"], version: 1 as const };
  }
  if (snapshot.sessionStatus !== "active") {
    return { allowed: false, mode: "lockdown" as const, decisionFloor: "BLOCK" as const, reasonCodes: [snapshot.sessionStatus === "revoked" ? "SESSION_REVOKED" : "SESSION_NOT_ACTIVE"], version: 1 as const };
  }
  if (snapshot.subjectMode === "block") {
    return { allowed: false, mode: "lockdown" as const, decisionFloor: "BLOCK" as const, reasonCodes: ["SUBJECT_CONTROL_BLOCK"], version: 1 as const };
  }
  const mode = [snapshot.globalMode, snapshot.tenantMode].reduce<ControlMode>((current, next) => rank[next] > rank[current] ? next : current, "normal");
  if (mode === "lockdown") return { allowed: false, mode, decisionFloor: "BLOCK" as const, reasonCodes: ["GLOBAL_OR_TENANT_LOCKDOWN"], version: 1 as const };
  if (mode === "review_only" || snapshot.subjectMode === "hold") {
    return { allowed: false, mode: mode === "normal" ? "review_only" as const : mode, decisionFloor: "REVIEW" as const, reasonCodes: [mode === "review_only" ? "CONTROL_PLANE_REVIEW_ONLY" : "SUBJECT_CONTROL_HOLD"], version: 1 as const };
  }
  return { allowed: true, mode: "normal" as const, decisionFloor: "ALLOW" as const, reasonCodes: [] as string[], version: 1 as const };
}

export function validateControlTransition(input: {
  current: ControlMode;
  requested: ControlMode;
  authorized: boolean;
  incidentReason: string;
  now?: number;
}) {
  const parsed = z.object({
    current: controlModeSchema,
    requested: controlModeSchema,
    authorized: z.boolean(),
    incidentReason: z.string().min(3).max(160).regex(/^[A-Za-z0-9 ._:-]+$/),
    now: z.number().finite().optional(),
  }).strict().parse(input);
  if (!parsed.authorized) throw new Error("CONTROL_PLANE_UNAUTHORIZED");
  if (rank[parsed.requested] < rank[parsed.current]) throw new Error("CONTROL_PLANE_DOWNGRADE_REQUIRES_RECOVERY_APPROVAL");
  return {
    current: parsed.current,
    requested: parsed.requested,
    incidentReason: parsed.incidentReason.trim(),
    changedAt: new Date(parsed.now ?? Date.now()).toISOString(),
    version: 1 as const,
  };
}

export function validateRevocation(input: {
  tenantId: string;
  subjectId?: string;
  sessionId?: string;
  reasonCode: string;
  actorId: string;
  authorized: boolean;
}) {
  const parsed = z.object({
    tenantId: z.uuid(),
    subjectId: z.uuid().optional(),
    sessionId: z.uuid().optional(),
    reasonCode: z.string().min(3).max(80).regex(/^[A-Z0-9_.:-]+$/),
    actorId: z.string().min(1).max(128).regex(/^[A-Za-z0-9._:@-]+$/),
    authorized: z.boolean(),
  }).strict().refine((v) => Boolean(v.subjectId || v.sessionId), { message: "subjectId or sessionId is required" }).parse(input);
  if (!parsed.authorized) throw new Error("SESSION_REVOCATION_UNAUTHORIZED");
  return { ...parsed, authorized: undefined, revokedAt: new Date().toISOString(), version: 1 as const };
}
