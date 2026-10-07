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
  const now = Date.now();
  const windowStartMs = now - input.windowSeconds * 1000;
  const windowStart = new Date(windowStartMs).toISOString();

  const current = await supabase.schema("security").from("rate_limit_events")
    .select("id,event_count,window_started_at")
    .eq("tenant_id", input.tenantId)
    .eq("key_hash", keyHash)
    .eq("bucket", input.bucket)
    .gte("window_started_at", windowStart);

  if (current.error) throw current.error;

  const count = (current.data ?? []).reduce(
    (total, row) => total + Number(row.event_count ?? 0),
    0,
  );

  if (count >= input.limit) {
    const oldest = [...(current.data ?? [])]
      .sort((a, b) => new Date(a.window_started_at).getTime() - new Date(b.window_started_at).getTime())[0];
    const resetAt = oldest
      ? new Date(new Date(oldest.window_started_at).getTime() + input.windowSeconds * 1000).toISOString()
      : new Date(now + input.windowSeconds * 1000).toISOString();
    return { allowed: false, count, limit: input.limit, remaining: 0, resetAt };
  }

  const inserted = await supabase.schema("security").from("rate_limit_events").insert({
    tenant_id: input.tenantId,
    subject_id: input.subjectId ?? null,
    key_hash: keyHash,
    bucket: input.bucket,
    event_count: 1,
    window_started_at: new Date(now).toISOString(),
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
