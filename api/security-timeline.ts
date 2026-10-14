import { createHash, timingSafeEqual } from "node:crypto";
import { z } from "zod";
import { env } from "../src/config/env";
import { supabase } from "../src/db/supabase";
import { hashValue } from "../src/security/utils";
import { checkRateLimit } from "../src/security/rateLimit";
import { safeErrorCode, safeErrorStatus, securityLog } from "../src/security/observability";

const querySchema = z.object({
  tenantId: z.uuid(),
  subjectId: z.uuid(),
  limit: z.coerce.number().int().min(1).max(100).default(50),
}).strict();

const json = (body: unknown, status = 200, requestId?: string) => new Response(JSON.stringify(body), {
  status,
  headers: {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
    ...(requestId ? { "x-request-id": requestId } : {}),
  },
});

function matchesToken(supplied: string, expected: string): boolean {
  const left = createHash("sha256").update(supplied, "utf8").digest();
  const right = createHash("sha256").update(expected, "utf8").digest();
  return timingSafeEqual(left, right);
}

function redactLikelySecrets(value: string): string {
  return value
    .replace(/\bBearer\s+[A-Za-z0-9._~+\/-]+=*/gi, "Bearer [REDACTED]")
    .replace(/\b(api[_-]?key|access[_-]?token|refresh[_-]?token|secret|password)\s*[:=]\s*[^\s,;]+/gi, "$1=[REDACTED]")
    .slice(0, 1000);
}

type TimelineItem = {
  at: string;
  type: "security_event" | "risk_assessment" | "fraud_case" | "investigation_note" | "audit_ledger";
  id: string;
  title: string;
  severity?: string;
  details: Record<string, unknown>;
};

export default async function handler(request: Request) {
  const requestIdHeader = request.headers.get("x-request-id") ?? "";
  const requestId = /^[a-zA-Z0-9._:-]{1,100}$/.test(requestIdHeader) ? requestIdHeader : crypto.randomUUID();

  if (request.method !== "GET") return json({ error: "METHOD_NOT_ALLOWED", requestId }, 405, requestId);
  const expectedToken = env.SECURITY_OPS_TOKEN;
  if (!expectedToken) return json({ error: "NOT_FOUND", requestId }, 404, requestId);

  const authorization = request.headers.get("authorization") ?? "";
  const bearer = /^Bearer\s+(.+)$/i.exec(authorization);
  if (!bearer || bearer[1].length > 512 || !matchesToken(bearer[1].trim(), expectedToken)) {
    securityLog("security_timeline_auth_denied", { requestId });
    return json({ error: "UNAUTHORIZED", requestId }, 401, requestId);
  }

  try {
    const url = new URL(request.url);
    const parsed = querySchema.parse(Object.fromEntries(url.searchParams.entries()));

    const tenant = await supabase.schema("security").from("tenants")
      .select("id,status").eq("id", parsed.tenantId).maybeSingle();
    if (tenant.error) throw tenant.error;
    if (!tenant.data || tenant.data.status !== "active") {
      return json({ error: "NOT_FOUND", requestId }, 404, requestId);
    }

    const rate = await checkRateLimit({
      tenantId: parsed.tenantId,
      key: `security-ops-timeline:${hashValue(expectedToken)}`,
      bucket: "security-ops-timeline",
      limit: 60,
      windowSeconds: 60,
    });
    if (!rate.allowed) {
      return json({
        error: "RATE_LIMITED",
        retryAfter: Math.max(1, Math.ceil((Date.parse(rate.resetAt) - Date.now()) / 1000)),
        requestId,
      }, 429, requestId);
    }

    const [events, assessments, cases, ledger] = await Promise.all([
      supabase.schema("security").from("security_events")
        .select("id,event_type,severity,source,occurred_at")
        .eq("tenant_id", parsed.tenantId).eq("subject_id", parsed.subjectId)
        .order("occurred_at", { ascending: false }).limit(parsed.limit),
      supabase.schema("security").from("risk_assessments")
        .select("id,score,risk_level,assessment_version,evaluated_at")
        .eq("tenant_id", parsed.tenantId).eq("subject_id", parsed.subjectId)
        .order("evaluated_at", { ascending: false }).limit(parsed.limit),
      supabase.schema("security").from("fraud_cases")
        .select("id,status,severity,fraud_type,opened_at,closed_at")
        .eq("tenant_id", parsed.tenantId).eq("subject_id", parsed.subjectId)
        .order("opened_at", { ascending: false }).limit(parsed.limit),
      supabase.schema("security").from("audit_ledger")
        .select("ledger_id,sequence_no,action,resource_type,resource_id,request_id,details,previous_hash,entry_hash,created_at")
        .eq("tenant_id", parsed.tenantId).contains("details", { subjectId: parsed.subjectId })
        .order("sequence_no", { ascending: false }).limit(parsed.limit),
    ]);

    for (const result of [events, assessments, cases, ledger]) if (result.error) throw result.error;

    const caseIds = (cases.data ?? []).map((item) => item.id);
    let notes: Array<{ id: string; case_id: string; author_type: string; note: string; created_at: string }> = [];
    if (caseIds.length) {
      const noteResult = await supabase.schema("security").from("investigation_notes")
        .select("id,case_id,author_type,note,created_at")
        .eq("tenant_id", parsed.tenantId).in("case_id", caseIds)
        .order("created_at", { ascending: false }).limit(parsed.limit);
      if (noteResult.error) throw noteResult.error;
      notes = noteResult.data ?? [];
    }

    const items: TimelineItem[] = [
      ...(events.data ?? []).map((event) => ({
        at: event.occurred_at,
        type: "security_event" as const,
        id: event.id,
        title: event.event_type,
        severity: event.severity,
        details: { source: event.source },
      })),
      ...(assessments.data ?? []).map((assessment) => ({
        at: assessment.evaluated_at,
        type: "risk_assessment" as const,
        id: assessment.id,
        title: "Risk assessment",
        severity: assessment.risk_level,
        details: {
          score: Number(assessment.score),
          riskLevel: assessment.risk_level,
          version: assessment.assessment_version,
        },
      })),
      ...(cases.data ?? []).map((item) => ({
        at: item.closed_at ?? item.opened_at,
        type: "fraud_case" as const,
        id: item.id,
        title: item.fraud_type,
        severity: item.severity,
        details: { status: item.status, openedAt: item.opened_at, closedAt: item.closed_at },
      })),
      ...notes.map((item) => ({
        at: item.created_at,
        type: "investigation_note" as const,
        id: item.id,
        title: "Investigation note",
        details: { caseId: item.case_id, authorType: item.author_type, note: redactLikelySecrets(item.note) },
      })),
      ...(ledger.data ?? []).map((entry) => {
        const details = entry.details && typeof entry.details === "object" && !Array.isArray(entry.details)
          ? entry.details as Record<string, unknown> : {};
        return {
          at: entry.created_at,
          type: "audit_ledger" as const,
          id: entry.ledger_id,
          title: entry.action,
          details: {
            sequence: entry.sequence_no,
            resourceType: entry.resource_type,
            resourceId: entry.resource_id,
            requestId: entry.request_id,
            decision: typeof details.decision === "string" ? details.decision : undefined,
            score: typeof details.score === "number" ? details.score : undefined,
            riskLevel: typeof details.riskLevel === "string" ? details.riskLevel : undefined,
            firewallMinimumDecision: typeof details.firewallMinimumDecision === "string" ? details.firewallMinimumDecision : undefined,
            firewallReasonCodes: Array.isArray(details.firewallReasonCodes) ? details.firewallReasonCodes.slice(0, 32) : [],
            previousHash: entry.previous_hash,
            entryHash: entry.entry_hash,
          },
        };
      }),
    ];

    items.sort((a, b) => Date.parse(b.at) - Date.parse(a.at));
    return json({
      tenantId: parsed.tenantId,
      subjectId: parsed.subjectId,
      generatedAt: new Date().toISOString(),
      limit: parsed.limit,
      totalReturned: Math.min(items.length, parsed.limit),
      items: items.slice(0, parsed.limit),
      requestId,
    }, 200, requestId);
  } catch (error) {
    if (error instanceof z.ZodError) return json({ error: "INVALID_QUERY", requestId }, 400, requestId);
    securityLog("security_timeline_failed", {
      requestId,
      errorCode: safeErrorCode(error),
      ...(safeErrorStatus(error) ? { errorStatus: safeErrorStatus(error) } : {}),
    });
    return json({ error: "INTERNAL_ERROR", requestId }, 500, requestId);
  }
}
