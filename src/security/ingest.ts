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
  type: z.enum(["network","bot","behavior","security"]),
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
