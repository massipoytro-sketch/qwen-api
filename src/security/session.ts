import { z } from "zod";
import { supabase } from "../db/supabase";
import { hashValue } from "./utils";

const sessionInputSchema = z.object({
  tenantId: z.uuid(),
  subjectId: z.uuid().optional(),
  sessionFingerprint: z.string().min(8).max(512).optional(),
  deviceId: z.uuid().optional(),
  ipId: z.uuid().optional(),
  metadata: z.record(z.string(), z.unknown()).default({}),
});

export async function registerSession(
  rawInput: z.input<typeof sessionInputSchema>,
) {
  const input = sessionInputSchema.parse(rawInput);

  if (!input.deviceId && !input.ipId && !input.subjectId) {
    throw new Error("SESSION_CONTEXT_REQUIRED");
  }

  const result = await supabase.schema("security").from("sessions").insert({
    tenant_id: input.tenantId,
    subject_id: input.subjectId ?? null,
    session_fingerprint: input.sessionFingerprint
      ? hashValue(input.sessionFingerprint)
      : null,
    device_id: input.deviceId ?? null,
    ip_id: input.ipId ?? null,
    metadata: input.metadata,
  }).select("id,started_at").single();

  if (result.error) throw result.error;

  return {
    sessionId: result.data.id,
    startedAt: result.data.started_at,
  };
}

export async function endSession(tenantId: string, sessionId: string) {
  const input = z.object({
    tenantId: z.uuid(),
    sessionId: z.uuid(),
  }).parse({ tenantId, sessionId });

  const result = await supabase.schema("security").from("sessions")
    .update({ ended_at: new Date().toISOString() })
    .eq("tenant_id", input.tenantId)
    .eq("id", input.sessionId)
    .is("ended_at", null)
    .select("id,ended_at")
    .single();

  if (result.error) throw result.error;
  return result.data;
}
