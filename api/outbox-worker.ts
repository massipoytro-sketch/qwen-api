import { createHash, timingSafeEqual } from "node:crypto";
import { z } from "zod";
import { env } from "../src/config/env";
import { supabase } from "../src/db/supabase";
import { analyzeWithDuckDB, processSecurityOutboxBatch, saveAnalyticsRun, type OutboxEvent } from "../src/security/platform";
import { hashValue } from "../src/security/utils";
import { securityLog } from "../src/security/observability";

const requestSchema = z.object({ batchSize: z.number().int().min(1).max(100).default(25) }).strict();
const analyticsPayloadSchema = z.object({
  tenantId: z.uuid(),
  events: z.array(z.object({
    subjectId: z.uuid().optional(),
    sessionId: z.uuid().optional(),
    eventType: z.string().min(1).max(100),
    occurredAt: z.string().datetime(),
    valueDelta: z.number().finite().optional(),
    botScore: z.number().min(0).max(100).optional(),
    behaviorScore: z.number().min(0).max(100).optional(),
    valueEventId: z.uuid().optional(),
  })).max(500),
});
const analyticsResponseSchema = z.object({
  engine: z.string(),
  version: z.string(),
  batchSize: z.number().int().nonnegative(),
  anomalyCount: z.number().int().nonnegative(),
  processedAt: z.string().datetime(),
  anomalies: z.array(z.object({
    type: z.string().min(1).max(100),
    tenantHash: z.string().length(64),
    subjectHash: z.string().length(64).nullable().optional(),
    sessionHash: z.string().length(64).nullable().optional(),
    score: z.number().min(0).max(100),
    confidence: z.number().min(0).max(1),
    reasonCodes: z.array(z.string().max(100)).max(32),
    evidence: z.record(z.string(), z.unknown()),
  })).max(100),
});

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), {
  status,
  headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", "x-content-type-options": "nosniff" },
});

function tokenMatches(supplied: string, expected: string) {
  const suppliedHash = createHash("sha256").update(supplied, "utf8").digest();
  const expectedHash = createHash("sha256").update(expected, "utf8").digest();
  return timingSafeEqual(suppliedHash, expectedHash);
}

async function handleDuckDbBatch(event: OutboxEvent) {
  const payload = analyticsPayloadSchema.parse(event.payload);
  const run = await saveAnalyticsRun({
    tenantId: payload.tenantId,
    taskType: "duckdb_batch",
    status: "running",
    inputCount: payload.events.length,
    summary: { outboxEventId: event.id },
  });
  try {
    const rawResult = await analyzeWithDuckDB(payload);
    const analysis = analyticsResponseSchema.parse(rawResult);
    if (analysis.batchSize !== payload.events.length || analysis.anomalyCount !== analysis.anomalies.length) {
      throw new Error("DUCKDB_RESPONSE_COUNT_MISMATCH");
    }
    const expectedTenantHash = hashValue(payload.tenantId);
    if (analysis.anomalies.some((anomaly) => anomaly.tenantHash !== expectedTenantHash)) {
      throw new Error("DUCKDB_TENANT_HASH_MISMATCH");
    }
    const subjectLookup = new Map<string, string>();
    const sessionLookup = new Map<string, string>();
    for (const row of payload.events) {
      if (row.subjectId) subjectLookup.set(hashValue(row.subjectId), row.subjectId);
      if (row.sessionId) sessionLookup.set(hashValue(row.sessionId), row.sessionId);
    }

    let saved = 0;
    for (const anomaly of analysis.anomalies) {
      const subjectId = anomaly.subjectHash ? subjectLookup.get(anomaly.subjectHash) : undefined;
      const sessionId = anomaly.sessionHash ? sessionLookup.get(anomaly.sessionHash) : undefined;
      if (anomaly.subjectHash && !subjectId) continue;
      if (anomaly.sessionHash && !sessionId) continue;
      if (!subjectId) continue; // Findings without a mapped subject remain in aggregate analytics only.
      if (sessionId && !payload.events.some((row) => row.subjectId === subjectId && row.sessionId === sessionId)) continue;
      if (anomaly.type === "value_jump") {
        const sourceEvent = payload.events.find((row) => row.valueEventId && row.subjectId === subjectId && row.valueDelta !== undefined && Number(row.valueDelta) === Number(anomaly.evidence.delta));
        if (sourceEvent?.valueEventId) {
          const directAnomaly = await supabase.schema("security").from("activity_anomalies").select("id")
            .eq("tenant_id", payload.tenantId).eq("source_event_id", sourceEvent.valueEventId).maybeSingle();
          if (directAnomaly.error) throw directAnomaly.error;
          if (directAnomaly.data) continue; // The transactionally recorded value-jump rule already covers this source event.
        }
      }
      const fiveMinuteBucket = Math.floor(Date.now() / (5 * 60_000));
      const dedupeKey = hashValue(`${payload.tenantId}:${fiveMinuteBucket}:${anomaly.type}:${subjectId}:${sessionId ?? ""}`);
      const write = await supabase.schema("security").from("activity_anomalies").upsert({
        tenant_id: payload.tenantId,
        subject_id: subjectId,
        session_id: sessionId ?? null,
        anomaly_type: anomaly.type,
        score: anomaly.score,
        confidence: anomaly.confidence,
        reason_codes: anomaly.reasonCodes,
        evidence: { ...anomaly.evidence, analyticsEngine: analysis.engine, analyticsVersion: analysis.version, analyticsRunId: run.id, outboxEventId: event.id },
        analyzer_version: analysis.version,
        occurred_at: analysis.processedAt,
        dedupe_key: dedupeKey,
      }, { onConflict: "tenant_id,dedupe_key" });
      if (write.error) throw write.error;
      saved += 1;
    }

    const completed = await supabase.schema("security").from("analytics_runs").update({
      status: "completed",
      input_count: analysis.batchSize,
      summary: { engine: analysis.engine, version: analysis.version, anomalyCount: analysis.anomalyCount, persistedFindings: saved },
      completed_at: new Date().toISOString(),
      error_code: null,
    }).eq("tenant_id", payload.tenantId).eq("id", run.id);
    if (completed.error) throw completed.error;
    securityLog("duckdb_batch_completed", { tenantId: payload.tenantId, outboxEventId: event.id, analyticsRunId: run.id, batchSize: analysis.batchSize, anomalyCount: analysis.anomalyCount, persistedFindings: saved });
  } catch (error) {
    await supabase.schema("security").from("analytics_runs").update({
      status: "failed",
      error_code: error instanceof Error ? error.name.replace(/[^A-Za-z0-9_:-]/g, "").slice(0, 100) : "UNKNOWN_ERROR",
      completed_at: new Date().toISOString(),
    }).eq("tenant_id", payload.tenantId).eq("id", run.id);
    throw error;
  }
}

const handlers: Record<string, (event: OutboxEvent) => Promise<void>> = {
  "analytics.duckdb_batch": handleDuckDbBatch,
  "security.risk_assessment.created": async (event) => {
    securityLog("outbox_risk_assessment_observed", { tenantId: event.tenant_id, eventId: event.id, assessmentId: event.aggregate_id });
  },
  "security.fraud_case.opened": async (event) => {
    securityLog("outbox_fraud_case_observed", { tenantId: event.tenant_id, eventId: event.id, caseId: event.aggregate_id });
  },
  "security.value_event.recorded": async (event) => {
    securityLog("outbox_value_event_observed", { tenantId: event.tenant_id, eventId: event.id, valueEventId: event.aggregate_id });
  },
  "security.behavior_event.created": async (event) => {
    securityLog("outbox_behavior_event_observed", { tenantId: event.tenant_id, eventId: event.id, behaviorEventId: event.aggregate_id });
  },
  "security.ingestion.network": async (event) => {
    securityLog("outbox_network_event_observed", { tenantId: event.tenant_id, eventId: event.id, networkEventId: event.aggregate_id });
  },
  "security.ingestion.bot": async (event) => {
    securityLog("outbox_bot_event_observed", { tenantId: event.tenant_id, eventId: event.id, botEventId: event.aggregate_id });
  },
  "security.ingestion.behavior": async (event) => {
    securityLog("outbox_behavior_event_observed", { tenantId: event.tenant_id, eventId: event.id, behaviorEventId: event.aggregate_id });
  },
  "security.ingestion.value": async (event) => {
    securityLog("outbox_value_event_observed", { tenantId: event.tenant_id, eventId: event.id, valueEventId: event.aggregate_id });
  },
  "security.ingestion.security": async (event) => {
    securityLog("outbox_security_event_observed", { tenantId: event.tenant_id, eventId: event.id, securityEventId: event.aggregate_id });
  },
  "security.honeytrap.hit": async (event) => {
    securityLog("outbox_honeytrap_hit_observed", { tenantId: event.tenant_id, eventId: event.id, securityEventId: event.aggregate_id });
  },
};

export default async function handler(request: Request) {
  if (request.method !== "POST") return json({ error: "METHOD_NOT_ALLOWED" }, 405);
  if (!env.OUTBOX_WORKER_TOKEN) return json({ error: "WORKER_NOT_CONFIGURED" }, 503);

  const match = /^Bearer\s+(.+)$/i.exec(request.headers.get("authorization") ?? "");
  if (!match || !tokenMatches(match[1].trim(), env.OUTBOX_WORKER_TOKEN)) {
    return json({ error: "UNAUTHORIZED" }, 401);
  }

  try {
    const raw = await request.text();
    if (new TextEncoder().encode(raw).byteLength > 4096) return json({ error: "PAYLOAD_TOO_LARGE" }, 413);
    let body: unknown = {};
    if (raw.trim()) {
      try { body = JSON.parse(raw); } catch { return json({ error: "INVALID_JSON" }, 400); }
    }
    const parsed = requestSchema.parse(body);
    const result = await processSecurityOutboxBatch(handlers, parsed.batchSize);
    return json({ service: "gainiren-security-worker", status: "ok", ...result });
  } catch (error) {
    securityLog("outbox_worker_failed", { errorCode: error instanceof Error ? error.name : "UNKNOWN_ERROR" });
    return json({ error: "WORKER_FAILED" }, 500);
  }
}
