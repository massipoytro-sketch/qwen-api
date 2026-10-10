import { createHash, timingSafeEqual } from "node:crypto";
import { z } from "zod";
import { env } from "../src/config/env";
import { supabase } from "../src/db/supabase";
import { checkRateLimit } from "../src/security/rateLimit";
import { enqueueSecurityEvent } from "../src/security/platform";
import { securityLog } from "../src/security/observability";

const requestSchema = z.object({
  requestId: z.uuid(),
  surface: z.enum(["admin", "environment", "backup", "debug", "api_probe", "unknown"]),
  method: z.enum(["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]),
  pathCategory: z.string().min(1).max(80),
  peerHash: z.string().regex(/^[a-f0-9]{64}$/),
  userAgentHash: z.string().regex(/^[a-f0-9]{64}$/),
  observedAt: z.string().datetime(),
}).strict();

const json = (body: unknown, status = 200, requestId?: string) => new Response(
  status === 204 ? null : JSON.stringify(body),
  {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
      "x-frame-options": "DENY",
      "referrer-policy": "no-referrer",
      ...(requestId ? { "x-request-id": requestId } : {}),
    },
  },
);

function matchesSecret(supplied: string, expected: string): boolean {
  const left = createHash("sha256").update(supplied, "utf8").digest();
  const right = createHash("sha256").update(expected, "utf8").digest();
  return timingSafeEqual(left, right);
}

export default async function handler(request: Request) {
  const candidate = request.headers.get("x-request-id") ?? "";
  const requestId = /^[a-zA-Z0-9._:-]{1,100}$/.test(candidate) ? candidate : crypto.randomUUID();

  if (request.method !== "POST") return json({ error: "METHOD_NOT_ALLOWED", requestId }, 405, requestId);

  const expectedToken = env.HONEY_SENSOR_TOKEN;
  const tenantId = env.HONEY_TENANT_ID;
  if (!expectedToken || !tenantId) return json({ error: "NOT_FOUND", requestId }, 404, requestId);

  const authorization = request.headers.get("authorization") ?? "";
  const match = /^Bearer\s+(.+)$/i.exec(authorization);
  if (!match || match[1].length > 512 || !matchesSecret(match[1].trim(), expectedToken)) {
    return json({ error: "UNAUTHORIZED", requestId }, 401, requestId);
  }

  const contentType = (request.headers.get("content-type") ?? "").split(";")[0].trim().toLowerCase();
  if (contentType !== "application/json") return json({ error: "UNSUPPORTED_MEDIA_TYPE", requestId }, 415, requestId);

  try {
    const raw = await request.text();
    if (new TextEncoder().encode(raw).byteLength > 8 * 1024) {
      return json({ error: "PAYLOAD_TOO_LARGE", requestId }, 413, requestId);
    }

    let body: unknown;
    try {
      body = JSON.parse(raw);
    } catch {
      return json({ error: "INVALID_JSON", requestId }, 400, requestId);
    }
    const parsed = requestSchema.parse(body);

    const rate = await checkRateLimit({
      tenantId,
      key: `honey-sensor:${createHash("sha256").update(expectedToken, "utf8").digest("hex")}`,
      bucket: "honeytrap-ingest",
      limit: 300,
      windowSeconds: 60,
    });
    if (!rate.allowed) {
      return json({
        error: "RATE_LIMITED",
        retryAfter: Math.max(1, Math.ceil((Date.parse(rate.resetAt) - Date.now()) / 1000)),
        requestId,
      }, 429, requestId);
    }

    const inserted = await supabase.schema("security").from("security_events").insert({
      tenant_id: tenantId,
      subject_id: null,
      session_id: null,
      event_type: "honeytrap.hit",
      severity: "high",
      source: "honeydb",
      occurred_at: parsed.observedAt,
      payload: {
        surface: parsed.surface,
        method: parsed.method,
        pathCategory: parsed.pathCategory,
        peerHash: parsed.peerHash,
        userAgentHash: parsed.userAgentHash,
        sensorRequestId: parsed.requestId,
      },
    }).select("id").single();

    if (inserted.error) throw inserted.error;

    await enqueueSecurityEvent({
      tenantId,
      eventType: "security.honeytrap.hit",
      aggregateId: inserted.data.id,
      dedupeKey: `honeytrap:${parsed.requestId}`,
      payload: { securityEventId: inserted.data.id, surface: parsed.surface, pathCategory: parsed.pathCategory },
    }).catch((error) => securityLog("honeytrap_outbox_enqueue_failed", {
      requestId,
      errorCode: error instanceof Error ? error.name : "UNKNOWN_ERROR",
    }));

    securityLog("honeytrap_event_persisted", {
      requestId,
      eventId: inserted.data.id,
      surface: parsed.surface,
      pathCategory: parsed.pathCategory,
    });
    return json({ accepted: true, eventId: inserted.data.id, requestId }, 202, requestId);
  } catch (error) {
    if (error instanceof z.ZodError) return json({ error: "INVALID_EVENT", requestId }, 400, requestId);
    securityLog("honeytrap_ingest_failed", {
      requestId,
      errorCode: error instanceof Error ? error.name : "UNKNOWN_ERROR",
    });
    return json({ error: "INTERNAL_ERROR", requestId }, 500, requestId);
  }
}
