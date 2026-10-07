import { z } from "zod";
import { supabase } from "../db/supabase";
import { registerNetworkEvent } from "./intelligence";
import { registerBotEvent, registerBehaviorEvent } from "./behavior";

const eventSchema = z.object({
  tenantId: z.uuid(),
  subjectId: z.uuid().optional(),
  sessionId: z.uuid().optional(),
  type: z.enum(["network","bot","behavior","security"]),
  payload: z.record(z.string(), z.unknown()),
});

export async function ingestSecurityEvent(rawInput: z.input<typeof eventSchema>) {
  const input = eventSchema.parse(rawInput);

  if (input.type === "network") {
    return { type: input.type, result: await registerNetworkEvent({
      tenantId: input.tenantId,
      subjectId: input.subjectId,
      sessionId: input.sessionId,
      ...input.payload,
    }) };
  }

  if (input.type === "bot") {
    return { type: input.type, result: await registerBotEvent({
      tenantId: input.tenantId,
      subjectId: input.subjectId,
      sessionId: input.sessionId,
      ...input.payload,
    }) };
  }

  if (input.type === "behavior") {
    return { type: input.type, result: await registerBehaviorEvent({
      tenantId: input.tenantId,
      subjectId: input.subjectId,
      sessionId: input.sessionId,
      ...input.payload,
    }) };
  }

  const result = await supabase.schema("security").from("security_events").insert({
    tenant_id: input.tenantId,
    subject_id: input.subjectId ?? null,
    session_id: input.sessionId ?? null,
    event_type: String(input.payload.eventType ?? "security_event"),
    severity: String(input.payload.severity ?? "info"),
    source: String(input.payload.source ?? "ingestion"),
    payload: input.payload,
  }).select("id").single();

  if (result.error) throw result.error;
  return { type: input.type, result: { securityEventId: result.data.id } };
}
