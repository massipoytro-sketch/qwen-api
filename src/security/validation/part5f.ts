export type ValidationMode = "normal" | "review_only" | "lockdown";

export type SecurityOutcome =
  | "ALLOW"
  | "MONITOR"
  | "CHALLENGE"
  | "REVIEW"
  | "BLOCK";

const ORDER: Record<SecurityOutcome, number> = {
  ALLOW: 0,
  MONITOR: 1,
  CHALLENGE: 2,
  REVIEW: 3,
  BLOCK: 4,
};

export function decisionCannotDowngrade(previous: SecurityOutcome, next: SecurityOutcome): boolean {
  return ORDER[next] >= ORDER[previous];
}

export function validateSecurityInvariants(input: {
  globalMode: ValidationMode;
  sessionActive: boolean;
  securityCheckSucceeded: boolean;
  downstreamDecision: SecurityOutcome;
  committed: boolean;
  replayDetected: boolean;
  duplicateIdempotency: boolean;
  auditRecorded: boolean;
}): string[] {
  const failures: string[] = [];
  if (input.globalMode === "lockdown" && input.downstreamDecision !== "BLOCK") failures.push("lockdown_not_blocked");
  if (!input.sessionActive && input.downstreamDecision === "ALLOW") failures.push("inactive_session_allowed");
  if (!input.securityCheckSucceeded && input.downstreamDecision === "ALLOW") failures.push("failed_check_allowed");
  if (input.replayDetected && input.committed) failures.push("replay_committed");
  if (input.duplicateIdempotency && input.committed) failures.push("duplicate_idempotency_committed");
  if (input.committed && !input.auditRecorded) failures.push("commit_without_audit");
  return failures;
}

export type ChaosFault =
  | "db_unavailable"
  | "db_timeout"
  | "security_api_timeout"
  | "rpc_failure"
  | "control_plane_unreadable"
  | "session_context_missing"
  | "outbox_failure"
  | "service_restart";

export type ChaosExpectation = {
  fault: ChaosFault;
  expectedDecision: "BLOCK" | "NO_COMMIT";
  reason: string;
};

export const CHAOS_EXPECTATIONS: readonly ChaosExpectation[] = [
  { fault: "db_unavailable", expectedDecision: "BLOCK", reason: "security state cannot be trusted" },
  { fault: "db_timeout", expectedDecision: "BLOCK", reason: "stale security state must not authorize" },
  { fault: "security_api_timeout", expectedDecision: "BLOCK", reason: "preflight failure must not permit mutation" },
  { fault: "rpc_failure", expectedDecision: "BLOCK", reason: "privileged security RPC failure fails closed" },
  { fault: "control_plane_unreadable", expectedDecision: "BLOCK", reason: "unknown control state is restrictive" },
  { fault: "session_context_missing", expectedDecision: "BLOCK", reason: "protected operations require session context" },
  { fault: "outbox_failure", expectedDecision: "NO_COMMIT", reason: "event durability failure cannot authorize a commit" },
  { fault: "service_restart", expectedDecision: "BLOCK", reason: "restart must not erase restrictive persisted state" },
];

export type RaceResult = {
  committed: number;
  blocked: number;
  duplicateCommit: boolean;
};

export function evaluateRaceResults(committedIds: readonly string[], expectedId: string): RaceResult {
  const committed = committedIds.filter((id) => id === expectedId).length;
  return { committed, blocked: Math.max(0, committedIds.length - committed), duplicateCommit: committed > 1 };
}

export type FuzzCase = {
  name: string;
  value: unknown;
  expectedReject: boolean;
};

export const SECURITY_FUZZ_CASES: readonly FuzzCase[] = [
  { name: "null", value: null, expectedReject: true },
  { name: "empty_object", value: {}, expectedReject: true },
  { name: "wrong_type", value: "not-an-object", expectedReject: true },
  { name: "huge_string", value: "x".repeat(16_385), expectedReject: true },
  { name: "negative_amount", value: { amount: -1 }, expectedReject: true },
  { name: "non_finite", value: { amount: Number.POSITIVE_INFINITY }, expectedReject: true },
  { name: "future_timestamp", value: { timestamp: "2999-01-01T00:00:00.000Z" }, expectedReject: true },
  { name: "expired_timestamp", value: { timestamp: "2000-01-01T00:00:00.000Z" }, expectedReject: true },
  { name: "prototype_key", value: { __proto__: { admin: true } }, expectedReject: true },
  { name: "deep_nesting", value: { a: { a: { a: { a: { a: { a: {} } } } } } }, expectedReject: true },
];

export function boundedStressPlan(input: { concurrency: number; requests: number; durationMs: number }) {
  return {
    concurrency: Math.min(Math.max(1, Math.floor(input.concurrency)), 256),
    requests: Math.min(Math.max(1, Math.floor(input.requests)), 10_000),
    durationMs: Math.min(Math.max(100, Math.floor(input.durationMs)), 120_000),
  };
}

export function recoverySequence(modes: readonly ValidationMode[]): boolean {
  const expected = ["normal", "review_only", "lockdown", "normal"] as const;
  return modes.length === expected.length && modes.every((mode, i) => mode === expected[i]);
}
