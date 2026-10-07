import { supabase } from "../db/supabase";

type SafeDetails = Record<string, unknown>;

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
