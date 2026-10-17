import { z } from "zod";
import { timingSafeEqual } from "node:crypto";
import { supabase } from "../src/db/supabase";
import { env } from "../src/config/env";
import { securityLog, safeErrorCode } from "../src/security/observability";
import { isSecureTransport, securityHeaders } from "../src/security/transport";
import { validateRevocation } from "../src/security/controlPlane";

const bodySchema = z.discriminatedUnion("action", [
  z.object({
    action: z.literal("set_global_mode"),
    mode: z.enum(["normal", "review_only", "lockdown"]),
    reasonCode: z.string().min(3).max(80).regex(/^[A-Z0-9_.:-]+$/),
    actorId: z.string().min(1).max(128).regex(/^[A-Za-z0-9._:@-]+$/),
    incidentRef: z.string().max(160).optional(),
    expiresAt: z.string().datetime({ offset: true }).nullable().optional(),
  }).strict(),
  z.object({
    action: z.literal("revoke_session"),
    tenantId: z.uuid(),
    sessionId: z.uuid(),
    subjectId: z.uuid().optional(),
    reasonCode: z.string().min(3).max(80).regex(/^[A-Z0-9_.:-]+$/),
    actorId: z.string().min(1).max(128).regex(/^[A-Za-z0-9._:@-]+$/),
    expiresAt: z.string().datetime({ offset: true }).nullable().optional(),
  }).strict(),
]);

function json(payload: unknown, status = 200, requestId?: string) {
  return new Response(JSON.stringify(payload), { status, headers: {
    "content-type": "application/json; charset=utf-8", "cache-control": "no-store",
    "x-content-type-options": "nosniff", "x-frame-options": "DENY",
    ...securityHeaders(), ...(requestId ? { "x-request-id": requestId } : {}),
  }});
}
function authorized(request: Request): boolean {
  const configured = env.SECURITY_OPS_TOKEN;
  const bearer = /^Bearer\s+(.+)$/i.exec(request.headers.get("authorization") ?? "")?.[1]?.trim();
  if (!configured || !bearer) return false;
  const a = Buffer.from(configured); const b = Buffer.from(bearer);
  return a.length === b.length && timingSafeEqual(a, b);
}

export default async function handler(request: Request) {
  const requestId = /^[A-Za-z0-9._:-]{1,100}$/.test(request.headers.get("x-request-id") ?? "")
    ? request.headers.get("x-request-id")! : crypto.randomUUID();
  if (!isSecureTransport(request)) return json({ error: "TLS_REQUIRED", requestId }, 426, requestId);
  if (request.method !== "POST") return json({ error: "METHOD_NOT_ALLOWED", requestId }, 405, requestId);
  if (!authorized(request)) return json({ error: "UNAUTHORIZED", requestId }, 401, requestId);
  try {
    const raw = await request.text();
    if (new TextEncoder().encode(raw).byteLength > 16 * 1024) return json({ error: "PAYLOAD_TOO_LARGE", requestId }, 413, requestId);
    const input = bodySchema.parse(JSON.parse(raw));
    if (input.action === "set_global_mode") {
      const result = await supabase.schema("security").rpc("set_global_control_plane", {
        p_mode: input.mode, p_reason_code: input.reasonCode, p_actor_id: input.actorId,
        p_incident_ref: input.incidentRef ?? null, p_expires_at: input.expiresAt ?? null,
        p_allow_recovery: false,
      });
      if (result.error) throw result.error;
      securityLog("global_control_plane_changed", { requestId, mode: input.mode, reasonCode: input.reasonCode, actorId: input.actorId });
      return json({ ok: true, control: result.data, requestId }, 200, requestId);
    }
    const revocation = validateRevocation({
      tenantId: input.tenantId, sessionId: input.sessionId, ...(input.subjectId ? { subjectId: input.subjectId } : {}),
      reasonCode: input.reasonCode, actorId: input.actorId, authorized: true,
    });
    const result = await supabase.schema("security").rpc("revoke_security_session", {
      p_tenant_id: input.tenantId, p_session_id: input.sessionId, p_subject_id: input.subjectId ?? null,
      p_reason_code: input.reasonCode, p_actor_id: input.actorId, p_request_id: requestId,
      p_expires_at: input.expiresAt ?? null,
    });
    if (result.error) throw result.error;
    securityLog("security_session_revoked", { requestId, tenantId: input.tenantId, sessionId: input.sessionId, reasonCode: input.reasonCode, actorId: input.actorId });
    return json({ ok: true, revoked: true, revocationVersion: revocation.version, requestId }, 200, requestId);
  } catch (error) {
    securityLog("control_plane_action_failed", { requestId, errorCode: safeErrorCode(error) });
    if (error instanceof z.ZodError || error instanceof SyntaxError) return json({ error: "INVALID_REQUEST", requestId }, 400, requestId);
    return json({ error: "CONTROL_PLANE_UNAVAILABLE", requestId }, 503, requestId);
  }
}
