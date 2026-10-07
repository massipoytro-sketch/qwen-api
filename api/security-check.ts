import { z } from "zod";
import { supabase } from "../src/db/supabase";
import { hashValue } from "../src/security/utils";
import { checkRateLimit } from "../src/security/rateLimit";
import { securityCheck } from "../src/security/check";
import { securityLog } from "../src/security/observability";
import { env } from "../src/config/env";

const bodySchema = z.object({
  tenantId: z.uuid(),
  subjectId: z.uuid().optional(),
  sessionId: z.uuid().optional(),
  requestId: z.string().min(1).max(200).optional(),
});

const json = (body: unknown, status = 200, requestId?: string) =>
  new Response(JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json",
      "cache-control": "no-store",
      "access-control-allow-origin": env.SECURITY_API_CORS_ORIGIN,
      "access-control-allow-headers": "authorization,content-type",
      "access-control-allow-methods": "POST,OPTIONS",
      ...(requestId ? { "x-request-id": requestId } : {}),
    },
  });

export default async function handler(request: Request) {
  if (request.method === "OPTIONS") return json({}, 204);
  if (request.method !== "POST") return json({ error: "METHOD_NOT_ALLOWED" }, 405);

  const requestId = request.headers.get("x-request-id") ?? crypto.randomUUID();
  const auth = request.headers.get("authorization") ?? "";
  if (!auth.startsWith("Bearer ")) {
    return json({ error: "UNAUTHORIZED", requestId }, 401, requestId);
  }

  const apiKey = auth.slice(7).trim();
  if (!apiKey || apiKey.length > 512) {
    return json({ error: "UNAUTHORIZED", requestId }, 401, requestId);
  }

  const contentLength = Number(request.headers.get("content-length") ?? 0);
  if (contentLength > 64 * 1024) {
    return json({ error: "PAYLOAD_TOO_LARGE", requestId }, 413, requestId);
  }

  try {
    const parsed = bodySchema.parse(await request.json());
    const keyHash = hashValue(apiKey);

    const tenant = await supabase.schema("security").from("tenants")
      .select("id,status")
      .eq("id", parsed.tenantId)
      .eq("api_key_hash", keyHash)
      .maybeSingle();

    if (tenant.error) throw tenant.error;
    if (!tenant.data || tenant.data.status !== "active") {
      securityLog("auth_denied", { requestId });
      return json({ error: "UNAUTHORIZED", requestId }, 401, requestId);
    }

    const limit = await checkRateLimit({
      tenantId: tenant.data.id,
      key: `api:${apiKey}`,
      bucket: "security-check",
      limit: 60,
      windowSeconds: 60,
      subjectId: parsed.subjectId,
    });

    if (!limit.allowed) {
      return json({
        error: "RATE_LIMITED",
        retryAfter: Math.max(1, Math.ceil((new Date(limit.resetAt).getTime() - Date.now()) / 1000)),
        requestId,
      }, 429, requestId);
    }

    const result = await securityCheck({
      tenantId: tenant.data.id,
      subjectId: parsed.subjectId,
      sessionId: parsed.sessionId,
      requestId,
    });

    return json(result, 200, requestId);
  } catch (error) {
    securityLog("api_error", {
      requestId,
      error: error instanceof Error ? error.message : "UNKNOWN_ERROR",
    });
    if (error instanceof z.ZodError) {
      return json({ error: "INVALID_REQUEST", requestId }, 400, requestId);
    }
    return json({ error: "INTERNAL_ERROR", requestId }, 500, requestId);
  }
}
