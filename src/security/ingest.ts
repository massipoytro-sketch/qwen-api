import { isIP } from "node:net";
import { z } from "zod";
import { supabase } from "../db/supabase";
import { registerNetworkEvent } from "./intelligence";
import { registerBotEvent, registerBehaviorEvent } from "./behavior";
import { enqueueSecurityEvent } from "./platform";
import { securityLog } from "./observability";
import { env } from "../config/env";

const base = z.object({
  tenantId: z.uuid(),
  subjectId: z.uuid().optional(),
  sessionId: z.uuid().optional(),
});
const eventSchema = base.extend({
  type: z.enum(["network", "bot", "behavior", "value", "security"]),
  payload: z.record(z.string(), z.unknown()),
});

async function enqueueIngested(input: {
  tenantId: string;
  type: "network" | "bot" | "behavior" | "value" | "security";
  aggregateId: string;
  payload: Record<string, unknown>;
}) {
  try {
    await enqueueSecurityEvent({
      tenantId: input.tenantId,
      eventType: `security.ingestion.${input.type}`,
      aggregateId: input.aggregateId,
      dedupeKey: `${input.type}:${input.aggregateId}`,
      payload: input.payload,
    });
  } catch (error) {
    securityLog("ingestion_outbox_enqueue_failed", {
      tenantId: input.tenantId,
      eventType: input.type,
      errorCode: error instanceof Error ? error.name : "UNKNOWN_ERROR",
    });
  }
}

const networkPayload = z.object({
  ip: z.string().refine((value) => isIP(value) !== 0, "Invalid IP address"),
  eventType: z.string().min(1).max(100).optional(),
  reputationScore: z.number().min(0).max(100).optional(),
  countryCode: z.string().length(2).optional(),
  region: z.string().max(100).optional(),
  city: z.string().max(100).optional(),
  asn: z.number().int().positive().optional(),
  asOrg: z.string().max(255).optional(),
  isProxy: z.boolean().optional(),
  isVpn: z.boolean().optional(),
  isTor: z.boolean().optional(),
  isDatacenter: z.boolean().optional(),
  metadata: z.record(z.string(), z.unknown()).optional(),
});

const botPayload = z.object({
  botType: z.string().min(1).max(100).optional(),
  confidence: z.number().min(0).max(1),
  isBot: z.boolean(),
  signals: z.record(z.string(), z.unknown()).optional(),
});

const behaviorPayload = z.object({
  eventType: z.string().min(1).max(100),
  durationMs: z.number().int().min(0).optional(),
  featureVector: z.array(z.number().finite()).max(2048).optional(),
  anomalyScore: z.number().min(0).max(100).optional(),
  metadata: z.record(z.string(), z.unknown()).optional(),
});

const valuePayload = z.object({
  valueType: z.string().min(1).max(100),
  currentValue: z.number().finite(),
  idempotencyKey: z.string().min(8).max(200),
  source: z.string().min(1).max(100).default("system"),
  metadata: z.record(z.string(), z.unknown()).optional(),
});

export async function ingestSecurityEvent(rawInput: z.input<typeof eventSchema>) {
  const input = eventSchema.parse(rawInput);

  if (input.type === "network") {
    const payload = networkPayload.parse(input.payload);
    const result = await registerNetworkEvent({
      tenantId: input.tenantId, subjectId: input.subjectId, sessionId: input.sessionId, ...payload,
    });
    await enqueueIngested({ tenantId: input.tenantId, type: "network", aggregateId: result.eventId, payload: { subjectId: input.subjectId ?? null, sessionId: input.sessionId ?? null, ipId: result.ipId, riskScore: result.riskScore } });
    return { type: input.type, result };
  }

  if (input.type === "bot") {
    const payload = botPayload.parse(input.payload);
    const result = await registerBotEvent({
      tenantId: input.tenantId, subjectId: input.subjectId, sessionId: input.sessionId, ...payload,
    });
    await enqueueIngested({ tenantId: input.tenantId, type: "bot", aggregateId: result.botEventId, payload: { subjectId: input.subjectId ?? null, sessionId: input.sessionId ?? null, isBot: result.isBot, confidence: result.confidence, riskScore: result.riskScore } });
    return { type: input.type, result };
  }

  if (input.type === "behavior") {
    const payload = behaviorPayload.parse(input.payload);
    const result = await registerBehaviorEvent({
      tenantId: input.tenantId, subjectId: input.subjectId, sessionId: input.sessionId, ...payload,
    });
    await enqueueIngested({ tenantId: input.tenantId, type: "behavior", aggregateId: result.behaviorEventId, payload: { subjectId: input.subjectId ?? null, sessionId: input.sessionId ?? null, eventType: payload.eventType, anomalyScore: result.anomalyScore } });
    return { type: input.type, result };
  }

  if (input.type === "value") {
    if (!input.subjectId) throw new Error("VALUE_EVENT_SUBJECT_REQUIRED");
    const payload = valuePayload.parse(input.payload);
    const recorded = await supabase.schema("security").rpc("record_value_event", {
      p_tenant_id: input.tenantId,
      p_subject_id: input.subjectId,
      p_session_id: input.sessionId ?? null,
      p_value_type: payload.valueType,
      p_current_value: payload.currentValue,
      p_source: payload.source,
      p_idempotency_key: payload.idempotencyKey,
      p_occurred_at: new Date().toISOString(),
      p_metadata: payload.metadata ?? {},
    });

    if (recorded.error) throw recorded.error;
    const data = recorded.data as {
      valueEventId: string;
      previousValue: number | string;
      currentValue: number | string;
      delta: number | string;
      version: number;
      duplicate: boolean;
      baseline: boolean;
      jumpScore: number;
      anomalyId: string | null;
    };
    const delta = Number(data.delta);
    const jumpScore = Number(data.jumpScore ?? 0);

    await enqueueIngested({ tenantId: input.tenantId, type: "value", aggregateId: data.valueEventId, payload: { subjectId: input.subjectId, sessionId: input.sessionId ?? null, valueType: payload.valueType, previousValue: Number(data.previousValue), currentValue: Number(data.currentValue), delta, jumpScore, duplicate: data.duplicate, stateVersion: data.version } });
    if (!data.duplicate && Math.abs(delta) >= 500 && env.DUCKDB_ANALYTICS_URL && env.DUCKDB_ANALYTICS_TOKEN) {
      try {
        await enqueueSecurityEvent({
          tenantId: input.tenantId,
          eventType: "analytics.duckdb_batch",
          aggregateId: data.valueEventId,
          dedupeKey: `duckdb:value:${data.valueEventId}`,
          payload: { tenantId: input.tenantId, events: [{ subjectId: input.subjectId, sessionId: input.sessionId, eventType: "value_change", occurredAt: new Date().toISOString(), valueDelta: delta, valueEventId: data.valueEventId }] },
        });
      } catch (error) {
        securityLog("analytics_outbox_enqueue_failed", { tenantId: input.tenantId, eventType: "value_change", errorCode: error instanceof Error ? error.name : "UNKNOWN_ERROR" });
      }
    }
    return {
      type: input.type,
      result: {
        valueEventId: data.valueEventId,
        previousValue: Number(data.previousValue),
        currentValue: Number(data.currentValue),
        delta,
        jumpScore,
        stateVersion: data.version,
        duplicate: data.duplicate,
        baseline: data.baseline,
      },
    };
  }

  const result = await supabase.schema("security").from("security_events").insert({
    tenant_id: input.tenantId, subject_id: input.subjectId ?? null, session_id: input.sessionId ?? null,
    event_type: String(input.payload.eventType ?? "security_event"),
    severity: String(input.payload.severity ?? "info"),
    source: String(input.payload.source ?? "ingestion"),
    payload: input.payload,
  }).select("id").single();

  if (result.error) throw result.error;
  await enqueueIngested({ tenantId: input.tenantId, type: "security", aggregateId: result.data.id, payload: { subjectId: input.subjectId ?? null, sessionId: input.sessionId ?? null, eventType: String(input.payload.eventType ?? "security_event"), severity: String(input.payload.severity ?? "info"), source: String(input.payload.source ?? "ingestion") } });
  return { type: input.type, result: { securityEventId: result.data.id } };
}
