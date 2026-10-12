import { isIP } from "node:net";
import { z } from "zod";
import { createHash } from "node:crypto";
import { supabase } from "../db/supabase";
import { upsertGraphEdge } from "./graph";
import { assertTenantScope } from "./scope";
import { analyzeImpossibleTravel } from "./detectors";
import { safeErrorCode, safeErrorStatus, securityLog } from "./observability";

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
  latitude: z.number().min(-90).max(90).optional(),
  longitude: z.number().min(-180).max(180).optional(),
  geoSource: z.enum(["trusted_geoip", "tenant_server"]).optional(),
  asn: z.number().int().positive().optional(), asOrg: z.string().max(255).optional(),
  isProxy: z.boolean().optional(), isVpn: z.boolean().optional(), isTor: z.boolean().optional(),
  isDatacenter: z.boolean().optional(), metadata: z.record(z.string(), z.unknown()).optional(),
}).superRefine((input, context) => {
  const hasLatitude = input.latitude !== undefined;
  const hasLongitude = input.longitude !== undefined;
  if (hasLatitude !== hasLongitude) {
    context.addIssue({ code: "custom", message: "Latitude and longitude must be supplied together", path: ["latitude"] });
  }
  if ((hasLatitude || hasLongitude) && !input.geoSource) {
    context.addIssue({ code: "custom", message: "Location source is required for coordinates", path: ["geoSource"] });
  }
  if (input.geoSource && !(hasLatitude && hasLongitude)) {
    context.addIssue({ code: "custom", message: "Location source requires coordinates", path: ["geoSource"] });
  }
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
  const observedAt = new Date().toISOString();
  const existingIp = await supabase.schema("security").from("ip_addresses")
    .select("id,country_code,region,city,asn,as_org,is_proxy,is_vpn,is_tor,is_datacenter,reputation_score,metadata,latitude,longitude,location_source")
    .eq("ip", input.ip).maybeSingle();
  if (existingIp.error) throw existingIp.error;
  const existingMetadata = existingIp.data?.metadata && typeof existingIp.data.metadata === "object" && !Array.isArray(existingIp.data.metadata)
    ? existingIp.data.metadata as Record<string, unknown>
    : {};
  const ipResult = await supabase.schema("security").from("ip_addresses").upsert({
    ip: input.ip,
    country_code: input.countryCode ?? existingIp.data?.country_code ?? null,
    region: input.region ?? existingIp.data?.region ?? null,
    city: input.city ?? existingIp.data?.city ?? null,
    asn: input.asn ?? existingIp.data?.asn ?? null,
    as_org: input.asOrg ?? existingIp.data?.as_org ?? null,
    is_proxy: input.isProxy ?? existingIp.data?.is_proxy ?? false,
    is_vpn: input.isVpn ?? existingIp.data?.is_vpn ?? false,
    is_tor: input.isTor ?? existingIp.data?.is_tor ?? false,
    is_datacenter: input.isDatacenter ?? existingIp.data?.is_datacenter ?? false,
    reputation_score: input.reputationScore ?? existingIp.data?.reputation_score ?? null,
    latitude: input.latitude ?? existingIp.data?.latitude ?? null,
    longitude: input.longitude ?? existingIp.data?.longitude ?? null,
    location_source: input.geoSource ?? existingIp.data?.location_source ?? null,
    last_seen_at: observedAt,
    metadata: { ...existingMetadata, ...(input.metadata ?? {}) },
  }, { onConflict: "ip" }).select("id,latitude,longitude,country_code,location_source").single();
  if (ipResult.error) throw ipResult.error;

  let impossibleTravel: ReturnType<typeof analyzeImpossibleTravel> | null = null;
  const currentLatitude = Number(ipResult.data.latitude);
  const currentLongitude = Number(ipResult.data.longitude);
  if (
    input.subjectId &&
    Number.isFinite(currentLatitude) &&
    Number.isFinite(currentLongitude) &&
    (ipResult.data.location_source === "trusted_geoip" || ipResult.data.location_source === "tenant_server")
  ) {
    try {
      const currentTime = Date.parse(observedAt);
      const previousEvents = await supabase.schema("security").from("network_events")
        .select("ip_id,observed_at")
        .eq("tenant_id", input.tenantId)
        .eq("subject_id", input.subjectId)
        .neq("ip_id", ipResult.data.id)
        .gte("observed_at", new Date(currentTime - 24 * 60 * 60_000).toISOString())
        .lt("observed_at", observedAt)
        .order("observed_at", { ascending: false })
        .limit(25);
      if (previousEvents.error) throw previousEvents.error;

      const previousIpIds = [...new Set((previousEvents.data ?? []).map((event) => event.ip_id))];
      if (previousIpIds.length > 0) {
        const previousIps = await supabase.schema("security").from("ip_addresses")
          .select("id,latitude,longitude,country_code,location_source")
          .in("id", previousIpIds);
        if (previousIps.error) throw previousIps.error;
        const locationsById = new Map((previousIps.data ?? []).map((location) => [location.id, location]));
        const previousEvent = (previousEvents.data ?? []).find((event) => {
          const location = locationsById.get(event.ip_id);
          return location &&
            Number.isFinite(Number(location.latitude)) &&
            Number.isFinite(Number(location.longitude)) &&
            (location.location_source === "trusted_geoip" || location.location_source === "tenant_server");
        });
        if (previousEvent) {
          const previousLocation = locationsById.get(previousEvent.ip_id);
          if (previousLocation) {
            impossibleTravel = analyzeImpossibleTravel({
              latitude: Number(previousLocation.latitude),
              longitude: Number(previousLocation.longitude),
              occurredAt: previousEvent.observed_at,
              countryCode: previousLocation.country_code,
              source: previousLocation.location_source,
            }, {
              latitude: currentLatitude,
              longitude: currentLongitude,
              occurredAt: observedAt,
              countryCode: ipResult.data.country_code,
              source: ipResult.data.location_source,
            }, currentTime);
          }
        }
      }
    } catch (error) {
      securityLog("impossible_travel_analysis_failed", {
        tenantId: input.tenantId,
        subjectId: input.subjectId,
        errorCode: safeErrorCode(error),
        ...(safeErrorStatus(error) ? { errorStatus: safeErrorStatus(error) } : {}),
      });
    }
  }

  const eventResult = await supabase.schema("security").from("network_events").insert({
    tenant_id: input.tenantId, subject_id: input.subjectId ?? null, session_id: input.sessionId ?? null,
    ip_id: ipResult.data.id, event_type: input.eventType, risk_score: networkRiskScore(input),
    observed_at: observedAt,
    metadata: input.metadata ?? {},
  }).select("id,risk_score").single();
  if (eventResult.error) throw eventResult.error;

  if (impossibleTravel && impossibleTravel.score >= 60 && input.subjectId) {
    const hourBucket = Math.floor(Date.parse(observedAt) / 3_600_000);
    const dedupeKey = `impossible-travel:${input.subjectId}:${ipResult.data.id}:${hourBucket}`;
    const anomaly = await supabase.schema("security").from("activity_anomalies").upsert({
      tenant_id: input.tenantId,
      subject_id: input.subjectId,
      session_id: input.sessionId ?? null,
      anomaly_type: "impossible_travel",
      score: impossibleTravel.score,
      confidence: impossibleTravel.confidence,
      reason_codes: impossibleTravel.reasonCodes,
      evidence: {
        distanceKm: impossibleTravel.distanceKm,
        speedKmh: impossibleTravel.speedKmh,
        elapsedMinutes: impossibleTravel.elapsedMinutes,
        previousCountryCode: undefined,
        currentCountryCode: ipResult.data.country_code ?? null,
      },
      analyzer_version: impossibleTravel.version,
      occurred_at: observedAt,
      dedupe_key: dedupeKey,
    }, { onConflict: "tenant_id,dedupe_key" }).select("id").single();
    if (anomaly.error) {
      securityLog("impossible_travel_persist_failed", {
        tenantId: input.tenantId,
        subjectId: input.subjectId,
        eventId: eventResult.data.id,
        errorCode: safeErrorCode(anomaly.error),
        ...(safeErrorStatus(anomaly.error) ? { errorStatus: safeErrorStatus(anomaly.error) } : {}),
      });
    } else {
      securityLog("impossible_travel_detected", {
        tenantId: input.tenantId,
        subjectId: input.subjectId,
        eventId: eventResult.data.id,
        score: impossibleTravel.score,
        reasonCodes: impossibleTravel.reasonCodes,
      });
    }
  }

  if (input.subjectId) {
    await upsertGraphEdge({ tenantId: input.tenantId, leftType: "subject", leftId: input.subjectId,
      relationship: "uses_ip", rightType: "ip", rightId: ipResult.data.id, confidence: 0.9 });
  }
  if (input.sessionId) {
    await upsertGraphEdge({ tenantId: input.tenantId, leftType: "session", leftId: input.sessionId,
      relationship: "uses_ip", rightType: "ip", rightId: ipResult.data.id, confidence: 1 });
  }
  return {
    ipId: ipResult.data.id,
    eventId: eventResult.data.id,
    riskScore: eventResult.data.risk_score,
    impossibleTravel: impossibleTravel && impossibleTravel.score >= 60 ? {
      score: impossibleTravel.score,
      reasonCodes: impossibleTravel.reasonCodes,
      distanceKm: impossibleTravel.distanceKm,
      speedKmh: impossibleTravel.speedKmh,
      elapsedMinutes: impossibleTravel.elapsedMinutes,
    } : null,
  };
}
