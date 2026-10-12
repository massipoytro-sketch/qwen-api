import { supabase } from "../db/supabase";

type SafeDetails = Record<string, unknown>;

/**
 * Extract a bounded machine-readable error identifier without logging raw error
 * messages, which may contain request data or provider details.
 */
export function safeErrorCode(error: unknown): string {
  const object = error && typeof error === "object"
    ? error as { code?: unknown; name?: unknown; message?: unknown }
    : undefined;

  if (typeof object?.code === "string" && object.code.trim()) {
    return object.code.replace(/[^A-Za-z0-9_:-]/g, "").slice(0, 80) || "UNKNOWN_ERROR";
  }

  // Supabase/PostgREST may return a structured error without a code (for
  // example when the Data API rejects the schema/profile before RPC lookup).
  // Classify messages, but never log raw provider or database text.
  const message = typeof object?.message === "string"
    ? object.message.toLowerCase()
    : error instanceof Error
      ? error.message.toLowerCase()
      : typeof error === "string"
        ? error.toLowerCase()
        : "";

  const postgrestCode = /\bPGRST\d{3}\b/i.exec(message)?.[0]?.toUpperCase();
  if (postgrestCode) return postgrestCode;
  if (/invalid api key|api key.*invalid/.test(message)) return "SUPABASE_API_KEY_REJECTED";
  if (/jwt|token.*expired|signature verification/.test(message)) return "SUPABASE_AUTH_REJECTED";
  if (/schema.*(not exposed|not in the list|must be one of)/.test(message)) return "SUPABASE_SCHEMA_NOT_EXPOSED";
  if (/could not find the function|function.*not.*schema cache/.test(message)) return "SUPABASE_RPC_NOT_FOUND";
  if (/permission denied|not authorized|insufficient privilege/.test(message)) return "SUPABASE_PERMISSION_DENIED";
  if (/fetch failed|network|timed out|timeout|econnreset|enotfound/.test(message)) return "SUPABASE_NETWORK_ERROR";
  if (error instanceof Error && error.name && error.name !== "Error") {
    return error.name.replace(/[^A-Za-z0-9_:-]/g, "").slice(0, 80) || "UNKNOWN_ERROR";
  }
  if (message) return "SUPABASE_RESPONSE_ERROR";
  if (typeof object?.name === "string") {
    return object.name.replace(/[^A-Za-z0-9_:-]/g, "").slice(0, 80) || "UNKNOWN_ERROR";
  }
  return "UNKNOWN_ERROR";
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
