import { z } from "zod";
import { supabase } from "../db/supabase";
import { hashValue } from "./utils";

const inputSchema = z.object({
  tenantId: z.uuid(),
  key: z.string().min(1).max(512),
  bucket: z.string().min(1).max(100),
  limit: z.number().int().positive().max(100000),
  windowSeconds: z.number().int().positive().max(86400),
  subjectId: z.uuid().optional(),
});

export async function checkRateLimit(rawInput: z.input<typeof inputSchema>) {
  const input = inputSchema.parse(rawInput);
  const keyHash = hashValue(input.key);
  const windowStart = new Date(Date.now() - input.windowSeconds * 1000).toISOString();

  const current = await supabase.schema("security").from("rate_limit_events")
    .select("id,event_count")
    .eq("tenant_id", input.tenantId)
    .eq("key_hash", keyHash)
    .eq("bucket", input.bucket)
    .gte("window_started_at", windowStart)
    .order("window_started_at", { ascending: false })
    .limit(1)
    .maybeSingle();

  if (current.error) throw current.error;

  const count = Number(current.data?.event_count ?? 0);
  if (count >= input.limit) {
    return { allowed: false, count, limit: input.limit, remaining: 0, resetAt: new Date(Date.now() + input.windowSeconds * 1000).toISOString() };
  }

  const inserted = await supabase.schema("security").from("rate_limit_events").insert({
    tenant_id: input.tenantId,
    subject_id: input.subjectId ?? null,
    key_hash: keyHash,
    bucket: input.bucket,
    event_count: 1,
    window_started_at: new Date().toISOString(),
  }).select("id").single();

  if (inserted.error) throw inserted.error;

  return {
    allowed: true,
    count: count + 1,
    limit: input.limit,
    remaining: Math.max(0, input.limit - count - 1),
    eventId: inserted.data.id,
  };
}
