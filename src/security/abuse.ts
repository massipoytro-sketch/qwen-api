import { z } from "zod";
import { supabase } from "../db/supabase";
import { hashValue } from "./utils";

const inputSchema = z.object({
  tenantId: z.uuid(),
  key: z.string().min(1).max(512),
  windowSeconds: z.number().int().positive().max(86400).default(300),
  warnAt: z.number().int().positive().max(100000).default(20),
  blockAt: z.number().int().positive().max(100000).default(100),
});

export async function detectAbuse(rawInput: z.input<typeof inputSchema>) {
  const input = inputSchema.parse(rawInput);
  const keyHash = hashValue(input.key);
  const since = new Date(Date.now() - input.windowSeconds * 1000).toISOString();

  const result = await supabase.schema("security").from("rate_limit_events")
    .select("event_count,bucket,window_started_at")
    .eq("tenant_id", input.tenantId)
    .eq("key_hash", keyHash)
    .gte("window_started_at", since);

  if (result.error) throw result.error;

  const count = (result.data ?? []).reduce(
    (total, row) => total + Number(row.event_count ?? 0),
    0,
  );

  const level = count >= input.blockAt
    ? "critical"
    : count >= input.warnAt
      ? "high"
      : count > 0
        ? "low"
        : "none";

  return {
    abusive: count >= input.warnAt,
    level,
    count,
    windowSeconds: input.windowSeconds,
    buckets: [...new Set((result.data ?? []).map((row) => row.bucket))],
  };
}
