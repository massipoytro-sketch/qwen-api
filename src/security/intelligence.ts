import { isIP } from "node:net";
import { z } from "zod";
import { createHash } from "node:crypto";
import { supabase } from "../db/supabase";
import { upsertGraphEdge } from "./graph";
import { assertTenantScope } from "./scope";

const deviceInputSchema = z.object({
  tenantId: z.uuid(),
  stableKey: z.string().min(8).max(512),
  platform: z.string().max(100).optional(),
  osFamily: z.string().max(100).optional(),
  browserFamily: z.string().max(100).optional(),
  deviceFamily: z.string().max(100).optional(),
  confidence: z.number().min(0).max(1).optional(),
  signals: z.array(z.object({
    name: z.string().min(1).max(100), value: z.string().max(2000).optional(),
    score: z.number().min(0).max(100).optional(), metadata: z.record(z.string(), z.unknown()).optional(),
  })).default([]),
  subjectId: z.uuid().optional(),
});

const identityInputSchema = z.object({
  tenantId: z.uuid(), subjectId: z.uuid(),
  identityType: z.enum(["email","phone","oauth","username","external"]),
  valueHash: z.string().min(16).max(256), normalizedDomain: z.string().max(255).optional(),
  isVerified: z.boolean().default(false), isDisposable: z.boolean().optional(),
  reputationScore: z.number().min(0).max(100).optional(), metadata: z.record(z.string(), z.unknown()).optional(),
});

const networkInputSchema = z.object({
  tenantId: z.uuid(), ip: z.string().refine((value) => isIP(value) !== 0, "Invalid IP address"), subjectId: z.uuid().optional(), sessionId: z.uuid().optional(),
  eventType: z.string().min(1).max(100).default("request"), reputationScore: z.number().min(0).max(100).optional(),
  countryCode: z.string().length(2).optional(), region: z.string().max(100).optional(), city: z.string().max(100).optional(),
  asn: z.number().int().positive().optional(), asOrg: z.string().max(255).optional(),
  isProxy: z.boolean().default(false), isVpn: z.boolean().default(false), isTor: z.boolean().default(false),
  isDatacenter: z.boolean().default(false), metadata: z.record(z.string(), z.unknown()).optional(),
});

const hashStableKey = (value: string) => createHash("sha256").update(value, "utf8").digest("hex");

const networkRiskScore = (input: z.infer<typeof networkInputSchema>) => Math.min(100, Math.round(
  (input.isTor ? 35 : 0) + (input.isProxy ? 20 : 0) + (input.isVpn ? 15 : 0) +
  (input.isDatacenter ? 20 : 0) +
  (input.reputationScore !== undefined ? Math.max(0, 50 - input.reputationScore) * 0.2 : 0),
));

export async function registerDevice(rawInput: z.input<typeof deviceInputSchema>) {
  const input = deviceInputSchema.parse(rawInput);
  await assertTenantScope({ tenantId: input.tenantId, subjectId: input.subjectId });
  const stableKeyHash = hashStableKey(input.stableKey);
  const existing = await supabase.schema("security").from("devices").select("id,risk_score,confidence")
    .eq("tenant_id", input.tenantId).eq("stable_key", stableKeyHash).maybeSingle();
  if (existing.error) throw existing.error;

  let deviceId = existing.data?.id;
  if (deviceId) {
    const updated = await supabase.schema("security").from("devices").update({
      platform: input.platform ?? null, os_family: input.osFamily ?? null,
      browser_family: input.browserFamily ?? null, device_family: input.deviceFamily ?? null,
      confidence: input.confidence ?? existing.data?.confidence ?? null, last_seen_at: new Date().toISOString(),
    }).eq("tenant_id", input.tenantId).eq("id", deviceId).select("id").single();
    if (updated.error) throw updated.error;
  } else {
    const created = await supabase.schema("security").from("devices").insert({
      tenant_id: input.tenantId, stable_key: stableKeyHash, platform: input.platform ?? null,
      os_family: input.osFamily ?? null, browser_family: input.browserFamily ?? null,
      device_family: input.deviceFamily ?? null, confidence: input.confidence ?? null,
    }).select("id").single();
    if (created.error) throw created.error;
    deviceId = created.data.id;
  }

  if (input.signals.length) {
    const inserted = await supabase.schema("security").from("device_signals").insert(
      input.signals.map((signal) => ({
        tenant_id: input.tenantId, device_id: deviceId, signal_name: signal.name,
        signal_value_hash: signal.value ? hashStableKey(signal.value) : null,
        signal_score: signal.score ?? null, metadata: signal.metadata ?? {},
      })),
    );
    if (inserted.error) throw inserted.error;
  }

  if (input.subjectId) {
    await upsertGraphEdge({ tenantId: input.tenantId, leftType: "subject", leftId: input.subjectId,
      relationship: "uses_device", rightType: "device", rightId: deviceId, confidence: input.confidence ?? 0.8 });
  }
  return { deviceId, stableKeyHash, signalCount: input.signals.length };
}

export async function registerIdentity(rawInput: z.input<typeof identityInputSchema>) {
  const input = identityInputSchema.parse(rawInput);
  await assertTenantScope({ tenantId: input.tenantId, subjectId: input.subjectId });
  const result = await supabase.schema("security").from("identities").insert({
    tenant_id: input.tenantId, subject_id: input.subjectId, identity_type: input.identityType,
    value_hash: input.valueHash, normalized_domain: input.normalizedDomain ?? null,
    is_verified: input.isVerified, is_disposable: input.isDisposable ?? null,
    reputation_score: input.reputationScore ?? null, metadata: input.metadata ?? {},
  }).select("id").single();
  if (result.error) throw result.error;

  await upsertGraphEdge({ tenantId: input.tenantId, leftType: "subject", leftId: input.subjectId,
    relationship: "owns_identity", rightType: "identity", rightId: result.data.id, confidence: input.isVerified ? 1 : 0.8 });
  return { identityId: result.data.id };
}

export async function registerNetworkEvent(rawInput: z.input<typeof networkInputSchema>) {
  const input = networkInputSchema.parse(rawInput);
  await assertTenantScope({ tenantId: input.tenantId, subjectId: input.subjectId, sessionId: input.sessionId });
  const ipResult = await supabase.schema("security").from("ip_addresses").upsert({
    ip: input.ip, country_code: input.countryCode ?? null, region: input.region ?? null, city: input.city ?? null,
    asn: input.asn ?? null, as_org: input.asOrg ?? null, is_proxy: input.isProxy, is_vpn: input.isVpn,
    is_tor: input.isTor, is_datacenter: input.isDatacenter, reputation_score: input.reputationScore ?? null,
    last_seen_at: new Date().toISOString(), metadata: input.metadata ?? {},
  }, { onConflict: "ip" }).select("id").single();
  if (ipResult.error) throw ipResult.error;

  const eventResult = await supabase.schema("security").from("network_events").insert({
    tenant_id: input.tenantId, subject_id: input.subjectId ?? null, session_id: input.sessionId ?? null,
    ip_id: ipResult.data.id, event_type: input.eventType, risk_score: networkRiskScore(input),
    metadata: input.metadata ?? {},
  }).select("id,risk_score").single();
  if (eventResult.error) throw eventResult.error;

  if (input.subjectId) {
    await upsertGraphEdge({ tenantId: input.tenantId, leftType: "subject", leftId: input.subjectId,
      relationship: "uses_ip", rightType: "ip", rightId: ipResult.data.id, confidence: 0.9 });
  }
  if (input.sessionId) {
    await upsertGraphEdge({ tenantId: input.tenantId, leftType: "session", leftId: input.sessionId,
      relationship: "uses_ip", rightType: "ip", rightId: ipResult.data.id, confidence: 1 });
  }
  return { ipId: ipResult.data.id, eventId: eventResult.data.id, riskScore: eventResult.data.risk_score };
}
