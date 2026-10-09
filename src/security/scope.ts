import { z } from "zod";
import { supabase } from "../db/supabase";

const scopeSchema = z.object({
  tenantId: z.uuid(),
  subjectId: z.uuid().optional(),
  sessionId: z.uuid().optional(),
  deviceId: z.uuid().optional(),
  ipId: z.uuid().optional(),
}).strict();

/**
 * Verifies that every supplied object identifier belongs to the same tenant
 * before telemetry or graph edges are written. IP records are shared reference
 * intelligence, so an IP ID is checked for existence but not tenant ownership.
 */
export async function assertTenantScope(rawInput: z.input<typeof scopeSchema>) {
  const input = scopeSchema.parse(rawInput);
  const [subject, session, device, ip] = await Promise.all([
    input.subjectId
      ? supabase.schema("security").from("subjects").select("id").eq("tenant_id", input.tenantId).eq("id", input.subjectId).maybeSingle()
      : Promise.resolve({ data: null, error: null }),
    input.sessionId
      ? supabase.schema("security").from("sessions").select("id,subject_id").eq("tenant_id", input.tenantId).eq("id", input.sessionId).maybeSingle()
      : Promise.resolve({ data: null, error: null }),
    input.deviceId
      ? supabase.schema("security").from("devices").select("id").eq("tenant_id", input.tenantId).eq("id", input.deviceId).maybeSingle()
      : Promise.resolve({ data: null, error: null }),
    input.ipId
      ? supabase.schema("security").from("ip_addresses").select("id").eq("id", input.ipId).maybeSingle()
      : Promise.resolve({ data: null, error: null }),
  ]);

  for (const result of [subject, session, device, ip]) if (result.error) throw result.error;
  if (input.subjectId && !subject.data) throw new Error("SUBJECT_NOT_FOUND");
  if (input.sessionId && !session.data) throw new Error("SESSION_NOT_FOUND");
  if (input.deviceId && !device.data) throw new Error("DEVICE_NOT_FOUND");
  if (input.ipId && !ip.data) throw new Error("IP_NOT_FOUND");
  if (input.subjectId && session.data?.subject_id && session.data.subject_id !== input.subjectId) {
    throw new Error("SESSION_SUBJECT_MISMATCH");
  }
  return { tenantId: input.tenantId, subjectId: input.subjectId ?? null, sessionId: input.sessionId ?? null };
}
