import { z } from "zod";
import { createHash } from "node:crypto";
import { supabase } from "../db/supabase";

const deviceInputSchema = z.object({
  tenantId: z.uuid(),
  stableKey: z.string().min(8).max(512),
  platform: z.string().max(100).optional(),
  osFamily: z.string().max(100).optional(),
  browserFamily: z.string().max(100).optional(),
  deviceFamily: z.string().max(100).optional(),
  confidence: z.number().min(0).max(1).optional(),
  signals: z.array(z.object({
    name: z.string().min(1).max(100),
    value: z.string().max(2000).optional(),
    score: z.number().min(0).max(100).optional(),
    metadata: z.record(z.string(), z.unknown()).optional(),
  })).default([]),
});

const identityInputSchema = z.object({
  tenantId: z.uuid(),
  subjectId: z.uuid(),
  identityType: z.enum(["email", "phone", "oauth", "username", "external"]),
  valueHash: z.string().min(16).max(256),
  normalizedDomain: z.string().max(255).optional(),
  isVerified: z.boolean().default(false),
  isDisposable: z.boolean().optional(),
  reputationScore: z.number().min(0).max(100).optional(),
  metadata: z.record(z.string(), z.unknown()).optional(),
});

const hashStableKey = (value: string) =>
  createHash("sha256").update(value, "utf8").digest("hex");

export async function registerDevice(rawInput: z.input<typeof deviceInputSchema>) {
  const input = deviceInputSchema.parse(rawInput);
  const stableKeyHash = hashStableKey(input.stableKey);

  const existing = await supabase
    .schema("security")
    .from("devices")
    .select("id,risk_score,confidence")
    .eq("tenant_id", input.tenantId)
    .eq("stable_key", stableKeyHash)
    .maybeSingle();

  if (existing.error) throw existing.error;

  let deviceId = existing.data?.id;

  if (deviceId) {
    const updated = await supabase
      .schema("security")
      .from("devices")
      .update({
        platform: input.platform ?? null,
        os_family: input.osFamily ?? null,
        browser_family: input.browserFamily ?? null,
        device_family: input.deviceFamily ?? null,
        confidence: input.confidence ?? existing.data.confidence,
        last_seen_at: new Date().toISOString(),
      })
      .eq("tenant_id", input.tenantId)
      .eq("id", deviceId)
      .select("id")
      .single();

    if (updated.error) throw updated.error;
  } else {
    const created = await supabase
      .schema("security")
      .from("devices")
      .insert({
        tenant_id: input.tenantId,
        stable_key: stableKeyHash,
        platform: input.platform ?? null,
        os_family: input.osFamily ?? null,
        browser_family: input.browserFamily ?? null,
        device_family: input.deviceFamily ?? null,
        confidence: input.confidence ?? null,
      })
      .select("id")
      .single();

    if (created.error) throw created.error;
    deviceId = created.data.id;
  }

  if (input.signals.length) {
    const rows = input.signals.map((signal) => ({
      tenant_id: input.tenantId,
      device_id: deviceId,
      signal_name: signal.name,
      signal_value_hash: signal.value ? hashStableKey(signal.value) : null,
      signal_score: signal.score ?? null,
      metadata: signal.metadata ?? {},
    }));

    const inserted = await supabase.schema("security").from("device_signals").insert(rows);
    if (inserted.error) throw inserted.error;
  }

  return { deviceId, stableKeyHash, signalCount: input.signals.length };
}

export async function registerIdentity(rawInput: z.input<typeof identityInputSchema>) {
  const input = identityInputSchema.parse(rawInput);

  const result = await supabase
    .schema("security")
    .from("identities")
    .insert({
      tenant_id: input.tenantId,
      subject_id: input.subjectId,
      identity_type: input.identityType,
      value_hash: input.valueHash,
      normalized_domain: input.normalizedDomain ?? null,
      is_verified: input.isVerified,
      is_disposable: input.isDisposable ?? null,
      reputation_score: input.reputationScore ?? null,
      metadata: input.metadata ?? {},
    })
    .select("id")
    .single();

  if (result.error) throw result.error;

  return { identityId: result.data.id };
}
