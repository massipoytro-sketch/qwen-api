import { z } from "zod";
import { env } from "../src/config/env";
import { supabase } from "../src/db/supabase";
import { hashValue } from "../src/security/utils";
import { checkRateLimit } from "../src/security/rateLimit";
import { ingestSecurityEvent } from "../src/security/ingest";
import { securityLog, safeErrorCode, safeErrorStatus } from "../src/security/observability";
import { isSecureTransport, securityHeaders } from "../src/security/transport";
import { verifyAndConsumeRequestSignature } from "../src/security/requestSigning";
import { authenticateRotatedTenantKey } from "../src/security/tenantAuth";

const requestSchema = z.object({
  tenantId: z.uuid(),
  subjectId: z.uuid().optional(),
  sessionId: z.uuid().optional(),
  type: z.enum(["network", "bot", "behavior", "value", "security"]),
  payload: z.record(z.string(), z.unknown()),
}).strict();
const IDEMPOTENCY_PATTERN = /^[A-Za-z0-9._:-]{16,128}$/;

const json = (body: unknown, status = 200, requestId?: string) => new Response(
  status === 204 ? null : JSON.stringify(body),
  {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
      "referrer-policy": "no-referrer",
      "x-frame-options": "DENY",
      ...securityHeaders(),
      ...(requestId ? { "x-request-id": requestId } : {}),
      ...(env.SECURITY_API_CORS_ORIGIN ? {
        "access-control-allow-origin": env.SECURITY_API_CORS_ORIGIN,
        "access-control-allow-headers": "authorization,content-type,x-request-id,x-gainiren-signature,x-gainiren-timestamp,x-gainiren-nonce,x-gainiren-key-id,idempotency-key",
        "access-control-allow-methods": "POST,OPTIONS",
        vary: "Origin",
      } : {}),
    },
  },
);

function requestHash(request: Request, rawBody: string): string {
  const url = new URL(request.url);
  return hashValue([
    "GAINIREN-SECURITY-EVENT-V1",
    request.method.toUpperCase(),
    url.pathname + url.search,
    rawBody,
  ].join("\n"));
}

async function finalizeIdempotency(
  tenantId: string,
  keyHash: string,
  status: "completed" | "failed",
  responseCode: number,
) {
  const result = await supabase.schema("security").rpc("finalize_request_idempotency", {
    p_tenant_id: tenantId,
    p_idempotency_key_hash: keyHash,
    p_status: status,
    p_response_code: responseCode,
  });
  if (result.error) {
    securityLog("ingestion_idempotency_finalize_failed", {
      tenantId,
      errorCode: safeErrorCode(result.error),
      ...(safeErrorStatus(result.error) ? { errorStatus: safeErrorStatus(result.error) } : {}),
    });
  }
}

export default async function handler(request: Request) {
  const candidateRequestId = request.headers.get("x-request-id") ?? "";
  const requestId = /^[a-zA-Z0-9._:-]{1,100}$/.test(candidateRequestId) ? candidateRequestId : crypto.randomUUID();

  if (!isSecureTransport(request)) return json({ error: "TLS_REQUIRED", requestId }, 426, requestId);

  if (request.method === "OPTIONS") return json({}, 204, requestId);
  if (request.method !== "POST") return json({ error: "METHOD_NOT_ALLOWED", requestId }, 405, requestId);

  const bearer = /^Bearer\s+(.+)$/i.exec(request.headers.get("authorization") ?? "");
  if (!bearer || bearer[1].trim().length < 1 || bearer[1].trim().length > 512) {
    return json({ error: "UNAUTHORIZED", requestId }, 401, requestId);
  }
  const apiKey = bearer[1].trim();
  const contentType = (request.headers.get("content-type") ?? "").split(";")[0].trim().toLowerCase();
  if (contentType !== "application/json") return json({ error: "UNSUPPORTED_MEDIA_TYPE", requestId }, 415, requestId);

  let claimedTenantId: string | null = null;
  let claimedIdempotencyHash: string | null = null;
  let claimCreated = false;
  try {
    const rawBody = await request.text();
    if (new TextEncoder().encode(rawBody).byteLength > 64 * 1024) {
      return json({ error: "PAYLOAD_TOO_LARGE", requestId }, 413, requestId);
    }
    let body: unknown;
    try {
      body = JSON.parse(rawBody);
    } catch {
      return json({ error: "INVALID_JSON", requestId }, 400, requestId);
    }

    const parsed = requestSchema.parse(body);
    claimedTenantId = parsed.tenantId;
    const keyIdHeader = request.headers.get("x-gainiren-key-id")?.trim() || null;
    const authentication = await authenticateRotatedTenantKey({
      tenantId: parsed.tenantId,
      apiKey,
      keyId: keyIdHeader,
    });
    if (!authentication.authorized) return json({ error: "UNAUTHORIZED", requestId }, 401, requestId);

    const signature = await verifyAndConsumeRequestSignature({
      request,
      rawBody,
      apiKey,
      tenantId: parsed.tenantId,
    });
    if (!signature.valid) {
      securityLog("request_signature_rejected", {
        requestId,
        tenantId: parsed.tenantId,
        reasonCode: signature.reasonCode,
      });
      return json({ error: "INVALID_REQUEST_SIGNATURE", requestId }, 401, requestId);
    }

    const idempotencyKey = request.headers.get("idempotency-key") ?? "";
    if (!IDEMPOTENCY_PATTERN.test(idempotencyKey)) {
      return json({ error: "INVALID_IDEMPOTENCY_KEY", requestId }, 400, requestId);
    }

    const limits = await Promise.all([
      checkRateLimit({
        tenantId: parsed.tenantId,
        key: `ingest:${hashValue(apiKey)}`,
        bucket: "security-event-ingest",
        limit: 120,
        windowSeconds: 60,
      }),
      checkRateLimit({
        tenantId: parsed.tenantId,
        key: `event-type:${parsed.type}`,
        bucket: "security-event-type",
        limit: 60,
        windowSeconds: 60,
      }),
      ...(parsed.subjectId ? [checkRateLimit({
        tenantId: parsed.tenantId,
        key: `subject:${parsed.subjectId}`,
        bucket: "security-event-subject",
        limit: 60,
        windowSeconds: 60,
        subjectId: parsed.subjectId,
      })] : []),
    ]);
    const blockedLimit = limits.find((limit) => !limit.allowed);
    if (blockedLimit) {
      return json({
        error: "RATE_LIMITED",
        retryAfter: Math.max(1, Math.ceil((Date.parse(blockedLimit.resetAt) - Date.now()) / 1000)),
        requestId,
      }, 429, requestId);
    }

    claimedIdempotencyHash = hashValue(idempotencyKey);
    const claim = await supabase.schema("security").rpc("consume_request_idempotency", {
      p_tenant_id: parsed.tenantId,
      p_idempotency_key_hash: claimedIdempotencyHash,
      p_request_hash: requestHash(request, rawBody),
      p_ttl_seconds: 86400,
    });
    if (claim.error) throw claim.error;
    if (!claim.data?.accepted) {
      const duplicate = claim.data?.reason === "DUPLICATE_REQUEST";
      return json({
        error: duplicate ? "DUPLICATE_REQUEST" : "IDEMPOTENCY_KEY_REUSE",
        requestId,
      }, 409, requestId);
    }
    claimCreated = true;

    const result = await ingestSecurityEvent({
      tenantId: parsed.tenantId,
      subjectId: parsed.subjectId,
      sessionId: parsed.sessionId,
      type: parsed.type,
      payload: parsed.payload,
    });

    await finalizeIdempotency(parsed.tenantId, claimedIdempotencyHash, "completed", 201);
    claimCreated = false;
    return json({ ...result, requestId }, 201, requestId);
  } catch (error) {
    if (claimCreated && claimedTenantId && claimedIdempotencyHash) {
      await finalizeIdempotency(claimedTenantId, claimedIdempotencyHash, "failed", 500);
    }
    if (error instanceof Error && ["SUBJECT_NOT_FOUND", "SESSION_NOT_FOUND", "SESSION_SUBJECT_MISMATCH", "SESSION_NOT_ACTIVE"].includes(error.message)) {
      return json({ error: "INVALID_CONTEXT", requestId }, 400, requestId);
    }
    if (error instanceof z.ZodError) return json({ error: "INVALID_REQUEST", requestId }, 400, requestId);
    securityLog("ingestion_api_error", {
      requestId,
      errorCode: safeErrorCode(error),
      ...(safeErrorStatus(error) ? { errorStatus: safeErrorStatus(error) } : {}),
    });
    return json({ error: "INTERNAL_ERROR", requestId }, 500, requestId);
  }
}
