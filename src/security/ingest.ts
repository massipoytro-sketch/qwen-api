import { z } from "zod";
import { supabase } from "../db/supabase";
import { registerNetworkEvent } from "./intelligence";
import { registerBotEvent, registerBehaviorEvent } from "./behavior";

const base = z.object({
  tenantId: z.uuid(),
  subjectId: z.uuid().optional(),
  sessionId: z.uuid().optional(),
});
const eventSchema = base.extend({
  type: z.enum(["network", "bot", "behavior", "value", "security"]),
  payload: z.record(z.string(), z.unknown()),
});

const networkPayload = z.object({
  ip: z.ip(),
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
  previousValue: z.number().finite(),
  currentValue: z.number().finite(),
  source: z.string().min(1).max(100).default("system"),
  occurredAt: z.iso.datetime().optional(),
  metadata: z.record(z.string(), z.unknown()).optional(),
});

export async function ingestSecurityEvent(rawInput: z.input<typeof eventSchema>) {
  const input = eventSchema.parse(rawInput);

  if (input.type === "network") {
    const payload = networkPayload.parse(input.payload);
    return { type: input.type, result: await registerNetworkEvent({
      tenantId: input.tenantId, subjectId: input.subjectId, sessionId: input.sessionId, ...payload,
    }) };
  }

  if (input.type === "bot") {
    const payload = botPayload.parse(input.payload);
    return { type: input.type, result: await registerBotEvent({
      tenantId: input.tenantId, subjectId: input.subjectId, sessionId: input.sessionId, ...payload,
    }) };
  }

  if (input.type === "behavior") {
    const payload = behaviorPayload.parse(input.payload);
    return { type: input.type, result: await registerBehaviorEvent({
      tenantId: input.tenantId, subjectId: input.subjectId, sessionId: input.sessionId, ...payload,
    }) };
  }

  if (input.type === "value") {
    if (!input.subjectId) throw new Error("VALUE_EVENT_SUBJECT_REQUIRED");
    const payload = valuePayload.parse(input.payload);
    const result = await supabase.schema("security").from("value_events").insert({
      tenant_id: input.tenantId,
      subject_id: input.subjectId,
      session_id: input.sessionId ?? null,
      value_type: payload.valueType,
      previous_value: payload.previousValue,
      current_value: payload.currentValue,
      source: payload.source,
      occurred_at: payload.occurredAt ?? new Date().toISOString(),
      metadata: payload.metadata ?? {},
    }).select("id,delta_value").single();

    if (result.error) throw result.error;

    const delta = Number(result.data.delta_value);
    const absoluteJump = Math.abs(delta);
    const jumpScore = absoluteJump >= 10000 ? 100 : absoluteJump >= 1000 ? 80 : absoluteJump >= 500 ? 50 : 0;

    if (jumpScore > 0) {
      const anomaly = await supabase.schema("security").from("activity_anomalies").insert({
        tenant_id: input.tenantId,
        subject_id: input.subjectId,
        session_id: input.sessionId ?? null,
        anomaly_type: "value_jump",
        score: jumpScore,
        confidence: jumpScore >= 80 ? 0.9 : 0.75,
        reason_codes: [absoluteJump >= 10000 ? "EXTREME_VALUE_JUMP" : "LARGE_VALUE_JUMP"],
        evidence: {
          valueType: payload.valueType,
          previousValue: payload.previousValue,
          currentValue: payload.currentValue,
          delta,
        },
        analyzer_version: "value-jump-v1",
        occurred_at: payload.occurredAt ?? new Date().toISOString(),
      });
      if (anomaly.error) throw anomaly.error;
    }

    return { type: input.type, result: { valueEventId: result.data.id, delta, jumpScore } };
  }

  const result = await supabase.schema("security").from("security_events").insert({
    tenant_id: input.tenantId, subject_id: input.subjectId ?? null, session_id: input.sessionId ?? null,
    event_type: String(input.payload.eventType ?? "security_event"),
    severity: String(input.payload.severity ?? "info"),
    source: String(input.payload.source ?? "ingestion"),
    payload: input.payload,
  }).select("id").single();

  if (result.error) throw result.error;
  return { type: input.type, result: { securityEventId: result.data.id } };
}
