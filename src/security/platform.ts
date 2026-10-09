import { z } from "zod";
import { supabase } from "../db/supabase";
import { hashValue } from "./utils";
import { analyzeVelocity, type TimedEvent } from "./velocity";
import { securityLog } from "./observability";

const clamp = (value: number) => Math.max(0, Math.min(100, Math.round(value)));

export type SecurityPolicyContext = {
  score: number;
  riskLevel: string;
  decision: string;
  signalNames: string[];
  velocity?: { count1m?: number; count5m?: number; count15m?: number };
  valueJumpScore?: number;
  relatedSubjectCount?: number;
};

const policyConditionSchema = z.object({
  field: z.enum([
    "risk.score", "risk.level", "risk.decision", "signals.names",
    "velocity.count1m", "velocity.count5m", "velocity.count15m",
    "value.jumpScore", "graph.relatedSubjects",
  ]),
  operator: z.enum(["eq", "neq", "gt", "gte", "lt", "lte", "in", "contains"]),
  value: z.unknown(),
}).strict();

const policyConditionsSchema = z.object({
  all: z.array(policyConditionSchema).max(20).optional(),
  any: z.array(policyConditionSchema).max(20).optional(),
}).strict().refine((value) => Boolean(value.all?.length || value.any?.length), "At least one condition is required");

type SecurityPolicy = {
  id: string;
  name: string;
  priority: number;
  conditions: unknown;
  decision: "ALLOW" | "MONITOR" | "CHALLENGE" | "REVIEW" | "BLOCK";
  score_delta: number;
  reason_code: string;
};

const policyValue = (context: SecurityPolicyContext, field: string): unknown => {
  switch (field) {
    case "risk.score": return context.score;
    case "risk.level": return context.riskLevel;
    case "risk.decision": return context.decision;
    case "signals.names": return context.signalNames;
    case "velocity.count1m": return context.velocity?.count1m ?? 0;
    case "velocity.count5m": return context.velocity?.count5m ?? 0;
    case "velocity.count15m": return context.velocity?.count15m ?? 0;
    case "value.jumpScore": return context.valueJumpScore ?? 0;
    case "graph.relatedSubjects": return context.relatedSubjectCount ?? 0;
    default: return undefined;
  }
};

function conditionMatches(context: SecurityPolicyContext, rawCondition: unknown): boolean {
  const parsed = policyConditionSchema.safeParse(rawCondition);
  if (!parsed.success) return false;
  const { field, operator, value } = parsed.data;
  const actual = policyValue(context, field);
  if (actual === undefined) return false;

  switch (operator) {
    case "eq": return actual === value;
    case "neq": return actual !== value;
    case "gt": return typeof actual === "number" && typeof value === "number" && actual > value;
    case "gte": return typeof actual === "number" && typeof value === "number" && actual >= value;
    case "lt": return typeof actual === "number" && typeof value === "number" && actual < value;
    case "lte": return typeof actual === "number" && typeof value === "number" && actual <= value;
    case "in": return Array.isArray(value) && value.includes(actual);
    case "contains":
      return Array.isArray(actual) ? actual.includes(value) :
        typeof actual === "string" && typeof value === "string" && actual.includes(value);
  }
}

export function evaluatePolicySet(context: SecurityPolicyContext, policies: SecurityPolicy[]) {
  const ordered = [...policies].sort((a, b) => a.priority - b.priority);
  const matched: Array<{ id: string; name: string; reasonCode: string }> = [];
  let scoreDelta = 0;
  let decisionOverride: SecurityPolicy["decision"] | null = null;

  for (const policy of ordered) {
    const parsed = policyConditionsSchema.safeParse(policy.conditions);
    if (!parsed.success) continue;
    const allMatches = !parsed.data.all?.length || parsed.data.all.every((condition) => conditionMatches(context, condition));
    const anyMatches = !parsed.data.any?.length || parsed.data.any.some((condition) => conditionMatches(context, condition));
    if (!allMatches || !anyMatches) continue;

    matched.push({ id: policy.id, name: policy.name, reasonCode: policy.reason_code });
    scoreDelta = Number.isFinite(policy.score_delta) ? policy.score_delta : 0;
    decisionOverride = policy.decision;

    // Only one policy is applied: the first match in priority order is deterministic and auditable.
    break;
  }

  const rank: Record<SecurityPolicyContext["decision"], number> = {
    ALLOW: 0, MONITOR: 1, CHALLENGE: 2, REVIEW: 3, BLOCK: 4,
  };
  const proposed = decisionOverride;
  const safeOverride = proposed && rank[proposed] > (rank[context.decision as SecurityPolicyContext["decision"]] ?? 0)
    ? proposed
    : null;

  return { matched, scoreDelta, decisionOverride: safeOverride, policyCount: policies.length };
}

export async function evaluateTenantPolicies(tenantId: string, context: SecurityPolicyContext) {
  const result = await supabase.schema("security").from("security_policies")
    .select("id,name,priority,conditions,decision,score_delta,reason_code")
    .eq("tenant_id", tenantId)
    .eq("enabled", true)
    .order("priority", { ascending: true })
    .limit(100);
  if (result.error) throw result.error;
  return evaluatePolicySet(context, (result.data ?? []) as SecurityPolicy[]);
}

export type AdvancedBotEvent = {
  occurredAt: string;
  isBot?: boolean | null;
  confidence?: number | null;
  signals?: Record<string, unknown> | null;
};

const botSignalKeys = [
  "webdriver", "headless", "automationFramework", "knownBotUserAgent",
  "impossibleTiming", "tamperedClient",
] as const;

export function analyzeAdvancedBotSignals(input: {
  botEvents: AdvancedBotEvent[];
  activityEvents: TimedEvent[];
  now?: number;
}) {
  const now = input.now ?? Date.now();
  const recentBotEvents = input.botEvents.filter((event) => {
    const timestamp = Date.parse(event.occurredAt);
    return Number.isFinite(timestamp) && timestamp <= now && timestamp >= now - 10 * 60_000;
  });
  const recentSignals = new Set<string>();
  let explicitBotScore = 0;
  let detectorConfidence = 0;

  for (const event of recentBotEvents) {
    const confidence = Math.max(0, Math.min(1, Number(event.confidence ?? 0)));
    if (event.isBot) explicitBotScore = Math.max(explicitBotScore, confidence * 100);
    detectorConfidence = Math.max(detectorConfidence, confidence);
    for (const key of botSignalKeys) if (event.signals?.[key] === true) recentSignals.add(key);
  }

  const velocity = analyzeVelocity(input.activityEvents, now);
  const signalBonus = Math.min(45, recentSignals.size * 15);
  const behavioralScore = velocity.score * 0.75 + signalBonus * 0.25;
  const score = clamp(Math.max(explicitBotScore, behavioralScore));
  const reasonCodes = [
    ...(explicitBotScore > 0 ? ["BOT_CLASSIFIER_SIGNAL"] : []),
    ...(velocity.score >= 45 ? ["HIGH_ACTIVITY_VELOCITY"] : []),
    ...[...recentSignals].map((key) => `CLIENT_SIGNAL_${key.toUpperCase()}`),
  ];

  return {
    score,
    confidence: score === 0 ? 0.35 : Math.min(0.98, 0.45 + (recentSignals.size > 0 ? 0.15 : 0) + (velocity.count15m >= 5 ? 0.15 : 0) + (explicitBotScore > 0 ? detectorConfidence * 0.2 : 0)),
    reasonCodes,
    velocity,
    signalFlags: [...recentSignals],
    evidenceCount: recentBotEvents.length + velocity.count15m,
    version: "advanced-bot-v1",
  };
}

export type BehaviorBaseline = {
  sample_count: number;
  mean_value: number;
  stddev_value: number;
  p50_value: number | null;
  p95_value: number | null;
  updated_at?: string;
};

export function scoreBehaviorAgainstBaseline(currentValue: number, baseline: BehaviorBaseline | null) {
  if (!Number.isFinite(currentValue) || !baseline || baseline.sample_count < 20) {
    return { score: 0, confidence: 0.35, zScore: 0, baselineReady: false, version: "baseline-v1" };
  }
  const standardDeviation = Math.max(1, baseline.stddev_value);
  const zScore = (currentValue - baseline.mean_value) / standardDeviation;
  let score = zScore >= 4 ? 85 : zScore >= 3 ? 70 : zScore >= 2 ? 45 : zScore >= 1.5 ? 25 : 0;
  if (baseline.p95_value !== null && currentValue >= baseline.p95_value + 10) score = Math.max(score, 60);
  return {
    score: clamp(score),
    confidence: Math.min(0.95, 0.55 + Math.min(0.4, baseline.sample_count / 250)),
    zScore: Number(zScore.toFixed(3)),
    baselineReady: true,
    version: "baseline-v1",
  };
}

const quantile = (sorted: number[], percentile: number) => {
  if (sorted.length === 0) return null;
  const index = (sorted.length - 1) * percentile;
  const low = Math.floor(index);
  const high = Math.ceil(index);
  if (low === high) return sorted[low];
  return sorted[low] + (sorted[high] - sorted[low]) * (index - low);
};

export async function refreshBehavioralBaseline(rawInput: { tenantId: string; subjectId: string }) {
  const input = z.object({ tenantId: z.uuid(), subjectId: z.uuid() }).parse(rawInput);
  const since = new Date(Date.now() - 30 * 24 * 60 * 60_000).toISOString();
  const events = await supabase.schema("security").from("behavior_events")
    .select("anomaly_score")
    .eq("tenant_id", input.tenantId)
    .eq("subject_id", input.subjectId)
    .gte("occurred_at", since)
    .not("anomaly_score", "is", null)
    .order("occurred_at", { ascending: false })
    .limit(500);
  if (events.error) throw events.error;
  const values = (events.data ?? []).map((row) => Number(row.anomaly_score)).filter(Number.isFinite);
  if (values.length < 20) return { ready: false, sampleCount: values.length };

  const sorted = [...values].sort((a, b) => a - b);
  const mean = values.reduce((sum, value) => sum + value, 0) / values.length;
  const variance = values.reduce((sum, value) => sum + (value - mean) ** 2, 0) / values.length;
  const saved = await supabase.schema("security").from("behavioral_baselines").upsert({
    tenant_id: input.tenantId,
    subject_id: input.subjectId,
    baseline_key: "anomaly_score",
    sample_count: values.length,
    mean_value: mean,
    stddev_value: Math.sqrt(variance),
    p50_value: quantile(sorted, 0.5),
    p95_value: quantile(sorted, 0.95),
    detector_version: "baseline-v1",
    updated_at: new Date().toISOString(),
  }, { onConflict: "tenant_id,subject_id,baseline_key" }).select("sample_count,mean_value,stddev_value,p50_value,p95_value,updated_at").single();
  if (saved.error) throw saved.error;
  return { ready: true, baseline: saved.data };
}

export async function getBehaviorBaselineScore(rawInput: { tenantId: string; subjectId: string; currentValue: number }) {
  const input = z.object({
    tenantId: z.uuid(), subjectId: z.uuid(), currentValue: z.number().min(0).max(100),
  }).parse(rawInput);
  let baselineResult = await supabase.schema("security").from("behavioral_baselines")
    .select("sample_count,mean_value,stddev_value,p50_value,p95_value,updated_at")
    .eq("tenant_id", input.tenantId)
    .eq("subject_id", input.subjectId)
    .eq("baseline_key", "anomaly_score")
    .maybeSingle();
  if (baselineResult.error) throw baselineResult.error;

  const stale = !baselineResult.data || Date.now() - Date.parse(baselineResult.data.updated_at) > 24 * 60 * 60_000;
  if (stale) {
    try {
      await refreshBehavioralBaseline({ tenantId: input.tenantId, subjectId: input.subjectId });
      baselineResult = await supabase.schema("security").from("behavioral_baselines")
        .select("sample_count,mean_value,stddev_value,p50_value,p95_value,updated_at")
        .eq("tenant_id", input.tenantId)
        .eq("subject_id", input.subjectId)
        .eq("baseline_key", "anomaly_score")
        .maybeSingle();
      if (baselineResult.error) throw baselineResult.error;
    } catch (error) {
      securityLog("behavior_baseline_refresh_failed", {
        tenantId: input.tenantId,
        subjectId: input.subjectId,
        errorCode: error instanceof Error ? error.name : "UNKNOWN_ERROR",
      });
    }
  }
  return scoreBehaviorAgainstBaseline(input.currentValue, baselineResult.data as BehaviorBaseline | null);
}

export async function upsertFraudCluster(rawInput: {
  tenantId: string;
  clusterType: "shared_device" | "shared_ip" | "shared_identity" | "value_abuse" | "behavioral" | "mixed";
  subjectIds: string[];
  riskScore: number;
  evidence?: Record<string, unknown>;
}) {
  const input = z.object({
    tenantId: z.uuid(),
    clusterType: z.enum(["shared_device", "shared_ip", "shared_identity", "value_abuse", "behavioral", "mixed"]),
    subjectIds: z.array(z.uuid()).min(2).max(100),
    riskScore: z.number().min(0).max(100),
    evidence: z.record(z.string(), z.unknown()).default({}),
  }).parse(rawInput);
  const subjectIds = [...new Set(input.subjectIds)].sort();
  if (subjectIds.length < 2) throw new Error("FRAUD_CLUSTER_REQUIRES_MULTIPLE_SUBJECTS");
  const clusterKey = hashValue(`${input.clusterType}:${subjectIds.join(":")}`);
  const result = await supabase.schema("security").from("fraud_clusters").upsert({
    tenant_id: input.tenantId,
    cluster_key: clusterKey,
    cluster_type: input.clusterType,
    subject_ids: subjectIds,
    risk_score: input.riskScore,
    evidence: input.evidence,
    last_seen_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  }, { onConflict: "tenant_id,cluster_key" }).select("id,cluster_type,subject_ids,risk_score,status,last_seen_at").single();
  if (result.error) throw result.error;
  return result.data;
}

export async function ensureInvestigationCase(rawInput: {
  tenantId: string;
  subjectId: string;
  assessmentId?: string;
  score: number;
  decision: string;
  evidence?: Record<string, unknown>;
}) {
  const input = z.object({
    tenantId: z.uuid(), subjectId: z.uuid(), assessmentId: z.uuid().optional(),
    score: z.number().min(0).max(100),
    decision: z.enum(["ALLOW", "MONITOR", "CHALLENGE", "REVIEW", "BLOCK"]),
    evidence: z.record(z.string(), z.unknown()).default({}),
  }).parse(rawInput);
  const severity = input.score >= 90 ? "critical" : input.score >= 70 ? "high" : "medium";
  const details = {
    source: "automated-risk-review",
    assessmentId: input.assessmentId ?? null,
    score: input.score,
    decision: input.decision,
    evidence: input.evidence,
    updatedAt: new Date().toISOString(),
  };
  const existing = await supabase.schema("security").from("fraud_cases")
    .select("id,evidence,status")
    .eq("tenant_id", input.tenantId)
    .eq("subject_id", input.subjectId)
    .eq("fraud_type", "automated_risk_review")
    .in("status", ["open", "investigating"])
    .order("opened_at", { ascending: false })
    .limit(1)
    .maybeSingle();
  if (existing.error) throw existing.error;

  if (existing.data) {
    const updated = await supabase.schema("security").from("fraud_cases")
      .update({ severity, evidence: { ...(existing.data.evidence as Record<string, unknown> ?? {}), latestAssessment: details } })
      .eq("tenant_id", input.tenantId)
      .eq("id", existing.data.id)
      .select("id,status,severity,opened_at")
      .single();
    if (updated.error) throw updated.error;
    return { ...updated.data, created: false };
  }

  const created = await supabase.schema("security").from("fraud_cases").insert({
    tenant_id: input.tenantId,
    subject_id: input.subjectId,
    status: "open",
    fraud_type: "automated_risk_review",
    severity,
    opened_at: new Date().toISOString(),
    evidence: details,
  }).select("id,status,severity,opened_at").single();
  if (created.error) throw created.error;

  await enqueueSecurityEvent({
    tenantId: input.tenantId,
    eventType: "security.fraud_case.opened",
    aggregateId: created.data.id,
    dedupeKey: created.data.id,
    payload: { caseId: created.data.id, subjectId: input.subjectId, score: input.score, severity },
  }).catch((error) => securityLog("outbox_enqueue_failed", {
    tenantId: input.tenantId, eventType: "security.fraud_case.opened",
    errorCode: error instanceof Error ? error.name : "UNKNOWN_ERROR",
  }));
  return { ...created.data, created: true };
}

export async function appendInvestigationNote(rawInput: {
  tenantId: string;
  caseId: string;
  authorType?: "system" | "operator" | "automation";
  note: string;
  details?: Record<string, unknown>;
}) {
  const input = z.object({
    tenantId: z.uuid(), caseId: z.uuid(),
    authorType: z.enum(["system", "operator", "automation"]).default("operator"),
    note: z.string().trim().min(1).max(10000),
    details: z.record(z.string(), z.unknown()).default({}),
  }).parse(rawInput);
  const caseResult = await supabase.schema("security").from("fraud_cases")
    .select("id").eq("tenant_id", input.tenantId).eq("id", input.caseId).maybeSingle();
  if (caseResult.error) throw caseResult.error;
  if (!caseResult.data) throw new Error("INVESTIGATION_CASE_NOT_FOUND");

  const result = await supabase.schema("security").from("investigation_notes").insert({
    tenant_id: input.tenantId, case_id: input.caseId, author_type: input.authorType,
    note: input.note, details: input.details,
  }).select("id,case_id,author_type,note,details,created_at").single();
  if (result.error) throw result.error;
  return result.data;
}

export async function getInvestigationTimeline(rawInput: { tenantId: string; caseId: string; limit?: number }) {
  const input = z.object({
    tenantId: z.uuid(), caseId: z.uuid(), limit: z.number().int().min(1).max(200).default(100),
  }).parse(rawInput);
  const caseResult = await supabase.schema("security").from("fraud_cases")
    .select("*").eq("tenant_id", input.tenantId).eq("id", input.caseId).maybeSingle();
  if (caseResult.error) throw caseResult.error;
  if (!caseResult.data) throw new Error("INVESTIGATION_CASE_NOT_FOUND");

  const [notesResult, eventsResult, assessmentsResult] = await Promise.all([
    supabase.schema("security").from("investigation_notes").select("id,author_type,note,details,created_at")
      .eq("tenant_id", input.tenantId).eq("case_id", input.caseId).order("created_at", { ascending: false }).limit(input.limit),
    caseResult.data.subject_id
      ? supabase.schema("security").from("security_events").select("id,event_type,severity,source,occurred_at,payload")
        .eq("tenant_id", input.tenantId).eq("subject_id", caseResult.data.subject_id)
        .gte("occurred_at", caseResult.data.opened_at).order("occurred_at", { ascending: false }).limit(input.limit)
      : Promise.resolve({ data: [], error: null }),
    caseResult.data.subject_id
      ? supabase.schema("security").from("risk_assessments").select("id,score,risk_level,assessment_version,evaluated_at,explanation")
        .eq("tenant_id", input.tenantId).eq("subject_id", caseResult.data.subject_id)
        .gte("evaluated_at", caseResult.data.opened_at).order("evaluated_at", { ascending: false }).limit(input.limit)
      : Promise.resolve({ data: [], error: null }),
  ]);
  for (const result of [notesResult, eventsResult, assessmentsResult]) if (result.error) throw result.error;
  return {
    case: caseResult.data,
    notes: notesResult.data ?? [],
    events: eventsResult.data ?? [],
    assessments: assessmentsResult.data ?? [],
  };
}

export async function recordModelFeedback(rawInput: {
  tenantId: string;
  predictionId: string;
  outcome: "confirmed_fraud" | "legitimate" | "needs_review" | "unknown";
  label?: string;
  feedback?: string;
  reviewerRef?: string;
}) {
  const input = z.object({
    tenantId: z.uuid(), predictionId: z.uuid(),
    outcome: z.enum(["confirmed_fraud", "legitimate", "needs_review", "unknown"]),
    label: z.string().max(120).optional(),
    feedback: z.string().max(10000).optional(),
    reviewerRef: z.string().max(200).optional(),
  }).parse(rawInput);
  const prediction = await supabase.schema("security").from("model_predictions")
    .select("id").eq("tenant_id", input.tenantId).eq("id", input.predictionId).maybeSingle();
  if (prediction.error) throw prediction.error;
  if (!prediction.data) throw new Error("MODEL_PREDICTION_NOT_FOUND");
  const result = await supabase.schema("security").from("model_feedback").upsert({
    tenant_id: input.tenantId,
    prediction_id: input.predictionId,
    outcome: input.outcome,
    label: input.label ?? null,
    feedback: input.feedback ?? null,
    reviewer_ref: input.reviewerRef ?? null,
  }, { onConflict: "tenant_id,prediction_id" }).select("id,prediction_id,outcome,label,created_at").single();
  if (result.error) throw result.error;
  return result.data;
}

export async function getModelLabSummary(tenantId: string) {
  const id = z.uuid().parse(tenantId);
  const [models, predictions, feedback] = await Promise.all([
    supabase.schema("security").from("model_versions")
      .select("id,model_name,version,status,feature_schema,metrics,created_at").order("created_at", { ascending: false }).limit(100),
    supabase.schema("security").from("model_predictions").select("id", { count: "exact", head: true }).eq("tenant_id", id),
    supabase.schema("security").from("model_feedback").select("id", { count: "exact", head: true }).eq("tenant_id", id),
  ]);
  for (const result of [models, predictions, feedback]) if (result.error) throw result.error;
  return { models: models.data ?? [], predictionCount: predictions.count ?? 0, feedbackCount: feedback.count ?? 0 };
}

export async function enqueueSecurityEvent(input: {
  tenantId: string;
  eventType: string;
  aggregateId?: string;
  dedupeKey?: string;
  payload?: Record<string, unknown>;
}) {
  const parsed = z.object({
    tenantId: z.uuid(),
    eventType: z.string().min(1).max(120),
    aggregateId: z.string().max(200).optional(),
    dedupeKey: z.string().min(1).max(200).optional(),
    payload: z.record(z.string(), z.unknown()).default({}),
  }).parse(input);
  const result = await supabase.schema("security").from("event_outbox").insert({
    tenant_id: parsed.tenantId,
    event_type: parsed.eventType,
    aggregate_id: parsed.aggregateId ?? null,
    dedupe_key: parsed.dedupeKey ?? null,
    payload: parsed.payload,
  }).select("id,status,created_at").single();
  if (!result.error) return result.data;
  if (result.error.code === "23505" && parsed.dedupeKey) {
    const duplicate = await supabase.schema("security").from("event_outbox").select("id,status,created_at")
      .eq("tenant_id", parsed.tenantId).eq("dedupe_key", parsed.dedupeKey).maybeSingle();
    if (duplicate.error) throw duplicate.error;
    if (duplicate.data) return duplicate.data;
  }
  throw result.error;
}

export type OutboxEvent = {
  id: string;
  tenant_id: string;
  event_type: string;
  aggregate_id: string | null;
  payload: Record<string, unknown>;
  attempts: number;
  lease_token: string;
};

export async function processSecurityOutboxBatch(
  handlers: Record<string, (event: OutboxEvent) => Promise<void>>,
  batchSize = 25,
) {
  const requested = z.number().int().min(1).max(100).parse(batchSize);
  const claimed = await supabase.schema("security").rpc("claim_security_event_outbox", { p_batch_size: requested });
  if (claimed.error) throw claimed.error;
  const events = (claimed.data ?? []) as OutboxEvent[];
  let completed = 0;
  let retried = 0;
  let permanentlyFailed = 0;

  for (let offset = 0; offset < events.length; offset += 5) {
    const chunk = events.slice(offset, offset + 5);
    const result = await Promise.all(chunk.map(async (event) => {
      try {
        const handler = handlers[event.event_type];
        if (!handler) throw new Error("NO_HANDLER");
        await handler(event);
        const done = await supabase.schema("security").rpc("complete_security_event_outbox", {
          p_event_id: event.id, p_lease_token: event.lease_token,
        });
        if (done.error) throw done.error;
        if (done.data !== true) throw new Error("OUTBOX_LEASE_LOST");
        return "completed" as const;
      } catch (error) {
        const code = error instanceof Error ? error.name.replace(/[^A-Za-z0-9_:-]/g, "").slice(0, 80) || "WORKER_ERROR" : "WORKER_ERROR";
        const failed = await supabase.schema("security").rpc("fail_security_event_outbox", {
          p_event_id: event.id,
          p_lease_token: event.lease_token,
          p_error_code: code,
          p_max_attempts: 8,
        });
        if (failed.error) {
          securityLog("outbox_retry_failed", { eventId: event.id, errorCode: failed.error.code ?? "DB_ERROR" });
          return "retry_error" as const;
        }
        if (failed.data !== true) return "lease_lost" as const;
        return event.attempts >= 8 ? "failed" as const : "retried" as const;
      }
    }));
    for (const item of result) {
      if (item === "completed") completed += 1;
      else if (item === "failed") permanentlyFailed += 1;
      else retried += 1;
    }
  }
  return { claimed: events.length, completed, retried, permanentlyFailed };
}

export async function analyzeWithDuckDB(rawInput: {
  tenantId: string;
  events: Array<{
    subjectId?: string;
    sessionId?: string;
    eventType: string;
    occurredAt: string;
    valueDelta?: number;
    botScore?: number;
    behaviorScore?: number;
    valueEventId?: string;
  }>;
}) {
  const endpoint = process.env.DUCKDB_ANALYTICS_URL;
  const token = process.env.DUCKDB_ANALYTICS_TOKEN;
  if (!endpoint || !token) throw new Error("DUCKDB_ANALYTICS_NOT_CONFIGURED");
  const url = new URL(endpoint);
  if (process.env.NODE_ENV === "production" && url.protocol !== "https:") throw new Error("DUCKDB_ENDPOINT_MUST_USE_HTTPS");
  const input = z.object({
    tenantId: z.uuid(),
    events: z.array(z.object({
      subjectId: z.string().optional(),
      sessionId: z.string().optional(),
      eventType: z.string().min(1).max(100),
      occurredAt: z.string().datetime(),
      valueDelta: z.number().finite().optional(),
      botScore: z.number().min(0).max(100).optional(),
      behaviorScore: z.number().min(0).max(100).optional(),
      valueEventId: z.uuid().optional(),
    })).max(500),
  }).parse(rawInput);
  const safePayload = {
    tenantHash: hashValue(input.tenantId),
    events: input.events.map((event) => ({
      subjectHash: event.subjectId ? hashValue(event.subjectId) : null,
      sessionHash: event.sessionId ? hashValue(event.sessionId) : null,
      eventType: event.eventType,
      occurredAt: event.occurredAt,
      valueDelta: event.valueDelta ?? null,
      botScore: event.botScore ?? null,
      behaviorScore: event.behaviorScore ?? null,
    })),
  };
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 8_000);
  try {
    const response = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
      body: JSON.stringify(safePayload),
      signal: controller.signal,
    });
    if (!response.ok) throw new Error(`DUCKDB_ANALYTICS_HTTP_${response.status}`);
    return await response.json() as Record<string, unknown>;
  } finally {
    clearTimeout(timer);
  }
}

export async function saveAnalyticsRun(rawInput: {
  tenantId?: string;
  taskType: string;
  status: "queued" | "running" | "completed" | "failed";
  inputCount?: number;
  summary?: Record<string, unknown>;
  errorCode?: string;
}) {
  const input = z.object({
    tenantId: z.uuid().optional(),
    taskType: z.string().min(1).max(100),
    status: z.enum(["queued", "running", "completed", "failed"]),
    inputCount: z.number().int().min(0).max(10_000_000).default(0),
    summary: z.record(z.string(), z.unknown()).default({}),
    errorCode: z.string().max(100).optional(),
  }).parse(rawInput);
  const result = await supabase.schema("security").from("analytics_runs").insert({
    tenant_id: input.tenantId ?? null,
    task_type: input.taskType,
    status: input.status,
    input_count: input.inputCount,
    summary: input.summary,
    error_code: input.errorCode ?? null,
    started_at: input.status === "running" ? new Date().toISOString() : null,
    completed_at: ["completed", "failed"].includes(input.status) ? new Date().toISOString() : null,
  }).select("id,status,task_type,created_at").single();
  if (result.error) throw result.error;
  return result.data;
}
