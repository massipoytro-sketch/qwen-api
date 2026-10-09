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

const resultSchema = z.object({
  allowed: z.boolean(),
  count: z.number().int().nonnegative(),
  limit: z.number().int().positive(),
  remaining: z.number().int().nonnegative(),
  resetAt: z.string().min(1).refine((value) => Number.isFinite(Date.parse(value)), "Invalid reset timestamp"),
  eventId: z.uuid().nullable(),
});

export async function checkRateLimit(rawInput: z.input<typeof inputSchema>) {
  const input = inputSchema.parse(rawInput);
  const keyHash = hashValue(input.key);

  const result = await supabase.schema("security").rpc("record_rate_limit_event", {
    p_tenant_id: input.tenantId,
    p_subject_id: input.subjectId ?? null,
    p_key_hash: keyHash,
    p_bucket: input.bucket,
    p_limit: input.limit,
    p_window_seconds: input.windowSeconds,
  });

  if (result.error) throw result.error;
  const data = resultSchema.parse(result.data);

  return {
    allowed: data.allowed,
    count: data.count,
    limit: data.limit,
    remaining: data.remaining,
    resetAt: data.resetAt,
    ...(data.eventId ? { eventId: data.eventId } : {}),
  };
}
