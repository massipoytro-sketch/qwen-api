import { supabase } from "../db/supabase";

type SafeDetails = Record<string, unknown>;

/**
 * Extract a bounded machine-readable error identifier without logging raw error
 * messages, which may contain request data or provider details.
 */
export function safeErrorCode(error: unknown): string {
  const object = error && typeof error === "object"
    ? error as { code?: unknown; name?: unknown }
    : undefined;
  const candidate = typeof object?.code === "string"
    ? object.code
    : error instanceof Error
      ? error.name
      : typeof object?.name === "string"
        ? object.name
        : "UNKNOWN_ERROR";
  return candidate.replace(/[^A-Za-z0-9_:-]/g, "").slice(0, 80) || "UNKNOWN_ERROR";
}

export function safeErrorStatus(error: unknown): number | undefined {
  if (!error || typeof error !== "object") return undefined;
  const object = error as { status?: unknown; statusCode?: unknown };
  const status = typeof object.status === "number" ? object.status : object.statusCode;
  return typeof status === "number" && Number.isInteger(status) && status >= 100 && status <= 599
    ? status
    : undefined;
}

export function securityLog(event: string, details: SafeDetails = {}) {
  console.info(JSON.stringify({
    timestamp: new Date().toISOString(),
    service: "gainiren-security",
    event,
    ...details,
  }));
}

export async function auditSecurityEvent(input: {
  tenantId?: string;
  actorSubjectId?: string;
  action: string;
  resourceType?: string;
  resourceId?: string;
  requestId?: string;
  details?: SafeDetails;
}) {
  const result = await supabase.schema("security").from("audit_events").insert({
    tenant_id: input.tenantId ?? null,
    actor_subject_id: input.actorSubjectId ?? null,
    actor_type: "system",
    action: input.action,
    resource_type: input.resourceType ?? null,
    resource_id: input.resourceId ?? null,
    request_id: input.requestId ?? null,
    details: input.details ?? {},
  });
  if (result.error) throw result.error;
}
