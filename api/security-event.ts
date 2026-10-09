import { z } from "zod";
import { env } from "../src/config/env";
import { supabase } from "../src/db/supabase";
import { hashValue } from "../src/security/utils";
import { checkRateLimit } from "../src/security/rateLimit";
import { ingestSecurityEvent } from "../src/security/ingest";
import { securityLog } from "../src/security/observability";

const requestSchema = z.object({
  tenantId: z.uuid(),
  subjectId: z.uuid().optional(),
  sessionId: z.uuid().optional(),
  type: z.enum(["network", "bot", "behavior", "value", "security"]),
  payload: z.record(z.string(), z.unknown()),
}).strict();

const json = (body: unknown, status = 200, requestId?: string) => new Response(status === 204 ? null : JSON.stringify(body), {
  status,
  headers: {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "x-frame-options": "DENY",
    ...(requestId ? { "x-request-id": requestId } : {}),
    ...(env.SECURITY_API_CORS_ORIGIN ? {
      "access-control-allow-origin": env.SECURITY_API_CORS_ORIGIN,
      "access-control-allow-headers": "authorization,content-type,x-request-id",
      "access-control-allow-methods": "POST,OPTIONS",
      vary: "Origin",
    } : {}),
  },
});

export default async function handler(request: Request) {
  const candidateRequestId = request.headers.get("x-request-id") ?? "";
  const requestId = /^[a-zA-Z0-9._:-]{1,100}$/.test(candidateRequestId) ? candidateRequestId : crypto.randomUUID();

  if (request.method === "OPTIONS") return json({}, 204, requestId);
  if (request.method !== "POST") return json({ error: "METHOD_NOT_ALLOWED", requestId }, 405, requestId);

  const auth = request.headers.get("authorization") ?? "";
  const bearer = /^Bearer\s+(.+)$/i.exec(auth);
  if (!bearer) return json({ error: "UNAUTHORIZED", requestId }, 401, requestId);
  const apiKey = bearer[1].trim();
  if (!apiKey || apiKey.length > 512) return json({ error: "UNAUTHORIZED", requestId }, 401, requestId);

  const contentType = (request.headers.get("content-type") ?? "").split(";")[0].trim().toLowerCase();
  if (contentType !== "application/json") return json({ error: "UNSUPPORTED_MEDIA_TYPE", requestId }, 415, requestId);

  try {
    const rawBody = await request.text();
    if (new TextEncoder().encode(rawBody).byteLength > 64 * 1024) return json({ error: "PAYLOAD_TOO_LARGE", requestId }, 413, requestId);
    let body: unknown;
    try { body = JSON.parse(rawBody); } catch { return json({ error: "INVALID_JSON", requestId }, 400, requestId); }
    const parsed = requestSchema.parse(body);
    const keyHash = hashValue(apiKey);
    const tenant = await supabase.schema("security").from("tenants")
      .select("id,status").eq("id", parsed.tenantId).eq("api_key_hash", keyHash).maybeSingle();
    if (tenant.error) throw tenant.error;
    if (!tenant.data || tenant.data.status !== "active") return json({ error: "UNAUTHORIZED", requestId }, 401, requestId);

    const limit = await checkRateLimit({
      tenantId: tenant.data.id,
      key: `ingest:${apiKey}`,
      bucket: "security-event-ingest",
      limit: 120,
      windowSeconds: 60,
      subjectId: parsed.subjectId,
    });
    if (!limit.allowed) {
      return json({
        error: "RATE_LIMITED",
        retryAfter: Math.max(1, Math.ceil((Date.parse(limit.resetAt) - Date.now()) / 1000)),
        requestId,
      }, 429, requestId);
    }

    const result = await ingestSecurityEvent({
      tenantId: tenant.data.id,
      subjectId: parsed.subjectId,
      sessionId: parsed.sessionId,
      type: parsed.type,
      payload: parsed.payload,
    });
    return json({ ...result, requestId }, 201, requestId);
  } catch (error) {
    if (error instanceof z.ZodError) return json({ error: "INVALID_REQUEST", requestId }, 400, requestId);
    securityLog("ingestion_api_error", { requestId, errorCode: error instanceof Error ? error.name : "UNKNOWN_ERROR" });
    return json({ error: "INTERNAL_ERROR", requestId }, 500, requestId);
  }
}
