import { createHash, timingSafeEqual } from "node:crypto";
import { z } from "zod";
import { env } from "../src/config/env";
import { supabase } from "../src/db/supabase";
import { checkRateLimit } from "../src/security/rateLimit";
import { replaySecurityTimeline, type ReplayEvent } from "../src/security/replay";
import { scoreFloorForEnforcement } from "../src/security/enforcement";
import { isSecureTransport, securityHeaders } from "../src/security/transport";
import { safeErrorCode, safeErrorStatus, securityLog } from "../src/security/observability";

const createSchema = z.object({
  tenantId: z.uuid(),
  subjectId: z.uuid().optional(),
  sourceEventId: z.uuid().optional(),
  replayMode: z.enum(["dry_run", "deterministic_simulation"]).default("deterministic_simulation"),
}).strict().refine((value) => Boolean(value.subjectId || value.sourceEventId), {
  message: "A subject or source event is required",
});

const querySchema = z.object({
  tenantId: z.uuid(),
  subjectId: z.uuid().optional(),
  replayId: z.uuid().optional(),
  limit: z.coerce.number().int().min(1).max(100).default(25),
}).strict();

const json = (body: unknown, status = 200, requestId?: string) => new Response(JSON.stringify(body), {
  status,
  headers: {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
    ...securityHeaders(),
    ...(requestId ? { "x-request-id": requestId } : {}),
  },
});

function matchesToken(supplied: string, expected: string): boolean {
  const left = createHash("sha256").update(supplied, "utf8").digest();
  const right = createHash("sha256").update(expected, "utf8").digest();
  return timingSafeEqual(left, right);
}

async function readJson(request: Request): Promise<unknown> {
  const contentType = (request.headers.get("content-type") ?? "").split(";")[0].trim().toLowerCase();
  if (contentType !== "application/json") throw new Error("UNSUPPORTED_MEDIA_TYPE");
  const raw = await request.text();
  if (new TextEncoder().encode(raw).byteLength > 8 * 1024) throw new Error("PAYLOAD_TOO_LARGE");
  try {
    return JSON.parse(raw) as unknown;
  } catch {
    throw new Error("INVALID_JSON");
  }
}

async function checkTenantAndRateLimit(tenantId: string, token: string): Promise<boolean> {
  const tenant = await supabase.schema("security").from("tenants")
    .select("id,status").eq("id", tenantId).maybeSingle();
  if (tenant.error) throw tenant.error;
  if (!tenant.data || tenant.data.status !== "active") return false;

  const limit = await checkRateLimit({
    tenantId,
    key: `security-ops-replay:${createHash("sha256").update(token, "utf8").digest("hex")}`,
    bucket: "security-ops-replay",
    limit: 20,
    windowSeconds: 60,
  });
  if (!limit.allowed) throw new Error("RATE_LIMITED");
  return true;
}

function normalizeReasonCodes(raw: unknown): string[] {
  if (!Array.isArray(raw)) return [];
  return [...new Set(raw.filter((value): value is string =>
    typeof value === "string" && /^[A-Z0-9_.:-]{1,100}$/.test(value)
  ))].slice(0, 32);
}

function decisionFromSeverity(severity: string): { decision: ReplayEvent["decision"]; score: number; reasonCode: string } {
  if (severity === "critical") return { decision: "BLOCK", score: 95, reasonCode: "CRITICAL_SECURITY_EVENT" };
  if (severity === "high") return { decision: "REVIEW", score: 75, reasonCode: "HIGH_SECURITY_EVENT" };
  if (severity === "medium") return { decision: "MONITOR", score: 25, reasonCode: "MEDIUM_SECURITY_EVENT" };
  return { decision: "ALLOW", score: 0, reasonCode: "SECURITY_EVENT_OBSERVED" };
}

function normalizeEventType(value: string): string {
  return /^[A-Za-z0-9_.:-]{1,120}$/.test(value) ? value : "security_event";
}

async function loadReplayEvents(input: {
  tenantId: string;
  subjectId?: string;
  sourceEventId?: string;
}): Promise<{ subjectId?: string; sourceEventId?: string; events: ReplayEvent[] }> {
  let subjectId = input.subjectId;
  let sourceEvent: { id: string; subject_id: string | null; event_type: string; severity: string; occurred_at: string } | null = null;

  if (input.sourceEventId) {
    const result = await supabase.schema("security").from("security_events")
      .select("id,subject_id,event_type,severity,occurred_at")
      .eq("tenant_id", input.tenantId).eq("id", input.sourceEventId).maybeSingle();
    if (result.error) throw result.error;
    if (!result.data) throw new Error("SOURCE_EVENT_NOT_FOUND");
    sourceEvent = result.data;
    if (subjectId && sourceEvent.subject_id && subjectId !== sourceEvent.subject_id) {
      throw new Error("REPLAY_SUBJECT_MISMATCH");
    }
    subjectId = subjectId ?? sourceEvent.subject_id ?? undefined;
  }

  const assessmentRows: Array<{
    id: string;
    score: number | string;
    evaluated_at: string;
    assessment_version: string;
  }> = [];
  if (subjectId) {
    const result = await supabase.schema("security").from("risk_assessments")
      .select("id,score,evaluated_at,assessment_version")
      .eq("tenant_id", input.tenantId).eq("subject_id", subjectId)
      .gte("evaluated_at", new Date(Date.now() - 30 * 24 * 60 * 60_000).toISOString())
      .order("evaluated_at", { ascending: true })
      .limit(499);
    if (result.error) throw result.error;
    assessmentRows.push(...(result.data ?? []));
  }

  const decisionsByAssessment = new Map<string, { decision: ReplayEvent["decision"]; reasonCodes: string[] }>();
  if (assessmentRows.length) {
    const decisionResult = await supabase.schema("security").from("risk_decisions")
      .select("assessment_id,decision,reason_codes,decision_version")
      .in("assessment_id", assessmentRows.map((row) => row.id));
    if (decisionResult.error) throw decisionResult.error;
    for (const row of decisionResult.data ?? []) {
      if (["ALLOW", "MONITOR", "CHALLENGE", "REVIEW", "BLOCK"].includes(row.decision)) {
        decisionsByAssessment.set(row.assessment_id, {
          decision: row.decision as ReplayEvent["decision"],
          reasonCodes: normalizeReasonCodes(row.reason_codes),
        });
      }
    }
  }

  const combined: Array<{ at: string; stableId: string; event: Omit<ReplayEvent, "sequence"> }> = [];
  for (const row of assessmentRows) {
    const decision = decisionsByAssessment.get(row.id);
    const rawScore = Number(row.score);
    const score = Number.isFinite(rawScore) ? Math.max(0, Math.min(100, rawScore)) : 0;
    combined.push({
      at: row.evaluated_at,
      stableId: row.id,
      event: {
        eventType: normalizeEventType(`assessment.${row.assessment_version || "unknown"}`),
        occurredAt: row.evaluated_at,
        decision: decision?.decision ?? (
          score >= 90 ? "BLOCK" : score >= 70 ? "REVIEW" : score >= 40 ? "CHALLENGE" : score > 0 ? "MONITOR" : "ALLOW"
        ),
        score,
        reasonCodes: decision?.reasonCodes ?? ["ASSESSMENT_DECISION_MISSING"],
      },
    });
  }

  if (sourceEvent) {
    const classified = decisionFromSeverity(sourceEvent.severity);
    combined.push({
      at: sourceEvent.occurred_at,
      stableId: sourceEvent.id,
      event: {
        eventType: normalizeEventType(sourceEvent.event_type),
        occurredAt: sourceEvent.occurred_at,
        decision: classified.decision,
        score: classified.score,
        reasonCodes: [
          classified.reasonCode,
          ...(sourceEvent.event_type === "honeytrap.hit" ? ["HONEYTRAP_EVENT"] : []),
        ],
      },
    });
  }

  combined.sort((a, b) => Date.parse(a.at) - Date.parse(b.at) || a.stableId.localeCompare(b.stableId));
  if (combined.length === 0) throw new Error("NO_REPLAY_EVENTS");
  if (combined.length > 500) throw new Error("REPLAY_TOO_MANY_EVENTS");

  const events: ReplayEvent[] = combined.map((item, index) => ({ ...item.event, sequence: index + 1 }));
  return { subjectId, sourceEventId: sourceEvent?.id, events };
}

export default async function handler(request: Request) {
  const candidate = request.headers.get("x-request-id") ?? "";
  const requestId = /^[A-Za-z0-9._:-]{1,100}$/.test(candidate) ? candidate : crypto.randomUUID();

  if (!isSecureTransport(request)) return json({ error: "TLS_REQUIRED", requestId }, 426, requestId);
  if (!["GET", "POST"].includes(request.method)) return json({ error: "METHOD_NOT_ALLOWED", requestId }, 405, requestId);

  const expectedToken = env.SECURITY_OPS_TOKEN;
  if (!expectedToken) return json({ error: "NOT_FOUND", requestId }, 404, requestId);
  const authorization = request.headers.get("authorization") ?? "";
  const bearer = /^Bearer\s+(.+)$/i.exec(authorization);
  if (!bearer || bearer[1].length > 512 || !matchesToken(bearer[1].trim(), expectedToken)) {
    securityLog("attack_replay_auth_denied", { requestId });
    return json({ error: "UNAUTHORIZED", requestId }, 401, requestId);
  }

  let replayId: string | undefined;
  let tenantId: string | undefined;

  try {
    if (request.method === "GET") {
      const url = new URL(request.url);
      const parsed = querySchema.parse(Object.fromEntries(url.searchParams.entries()));
      tenantId = parsed.tenantId;
      if (!await checkTenantAndRateLimit(parsed.tenantId, expectedToken)) {
        return json({ error: "NOT_FOUND", requestId }, 404, requestId);
      }
      try {
        const cleanup = await supabase.schema("security").rpc("expire_attack_replays", { p_batch_size: 20 });
        if (cleanup.error) securityLog("attack_replay_cleanup_failed", {
          requestId, tenantId: parsed.tenantId, errorCode: safeErrorCode(cleanup.error),
        });
      } catch (error) {
        securityLog("attack_replay_cleanup_failed", {
          requestId, tenantId: parsed.tenantId, errorCode: safeErrorCode(error),
        });
      }
      if (parsed.replayId) {
        const result = await supabase.schema("security").rpc("get_attack_replay", {
          p_tenant_id: parsed.tenantId,
          p_replay_id: parsed.replayId,
        });
        if (result.error) throw result.error;
        if (!result.data) return json({ error: "REPLAY_NOT_FOUND", requestId }, 404, requestId);
        return json({ replay: result.data, requestId }, 200, requestId);
      }
      const result = await supabase.schema("security").rpc("list_attack_replays", {
        p_tenant_id: parsed.tenantId,
        p_subject_id: parsed.subjectId ?? null,
        p_limit: parsed.limit,
      });
      if (result.error) throw result.error;
      return json({ tenantId: parsed.tenantId, replays: result.data ?? [], requestId }, 200, requestId);
    }

    const parsed = createSchema.parse(await readJson(request));
    tenantId = parsed.tenantId;
    if (!await checkTenantAndRateLimit(parsed.tenantId, expectedToken)) {
      return json({ error: "NOT_FOUND", requestId }, 404, requestId);
    }

    try {
      const cleanup = await supabase.schema("security").rpc("expire_attack_replays", { p_batch_size: 20 });
      if (cleanup.error) securityLog("attack_replay_cleanup_failed", {
        requestId, tenantId: parsed.tenantId, errorCode: safeErrorCode(cleanup.error),
      });
    } catch (error) {
      securityLog("attack_replay_cleanup_failed", {
        requestId, tenantId: parsed.tenantId, errorCode: safeErrorCode(error),
      });
    }

    const loaded = await loadReplayEvents({
      tenantId: parsed.tenantId,
      subjectId: parsed.subjectId,
      sourceEventId: parsed.sourceEventId,
    });
    const result = replaySecurityTimeline(loaded.events);
    const canonicalEvidence = JSON.stringify(loaded.events.map((event) => ({
      sequence: event.sequence,
      eventType: event.eventType,
      occurredAt: event.occurredAt,
      decision: event.decision,
      score: event.score,
      reasonCodes: event.reasonCodes ?? [],
    })));
    const evidenceDigest = createHash("sha256").update("GAINIREN-REPLAY-V1\n", "utf8").update(canonicalEvidence, "utf8").digest("hex");
    const summary = {
      engineVersion: "deterministic-replay-v1",
      eventCount: result.eventCount,
      finalDecision: result.finalDecision,
      finalScoreFloor: Math.max(scoreFloorForEnforcement(result.finalDecision), result.finalScoreFloor),
      escalations: result.escalations,
      reasonCodes: result.reasonCodes.slice(0, 64),
      completed: true,
    };

    const created = await supabase.schema("security").rpc("create_attack_replay", {
      p_tenant_id: parsed.tenantId,
      p_source_event_id: loaded.sourceEventId ?? null,
      p_subject_id: loaded.subjectId ?? null,
      p_replay_mode: parsed.replayMode,
      p_event_count: result.eventCount,
      p_summary: summary,
      p_evidence_digest: evidenceDigest,
    });
    if (created.error) throw created.error;
    replayId = created.data as string;

    try {
      for (let offset = 0; offset < loaded.events.length; offset += 100) {
        const chunk = loaded.events.slice(offset, offset + 100);
        const steps = chunk.map((event) => ({
          sequenceNo: event.sequence,
          eventType: event.eventType,
          eventAt: event.occurredAt,
          action: event.decision === "ALLOW" ? "observe" : event.decision.toLowerCase(),
          signalCodes: (event.reasonCodes ?? []).slice(0, 8),
          evidence: {
            decision: event.decision,
            score: Math.max(0, Math.min(100, Number(event.score) || 0)),
            replayEngineVersion: "deterministic-replay-v1",
          },
        }));
        const persisted = await supabase.schema("security").rpc("append_attack_replay_steps_batch", {
          p_replay_id: replayId,
          p_steps: steps,
        });
        if (persisted.error) throw persisted.error;
        if (Number(persisted.data) !== chunk.length) throw new Error("REPLAY_BATCH_COUNT_MISMATCH");
      }
      const finalized = await supabase.schema("security").rpc("finalize_attack_replay", {
        p_replay_id: replayId,
        p_status: "completed",
        p_summary: summary,
      });
      if (finalized.error) throw finalized.error;
    } catch (error) {
      try {
        const finalizedFailure = await supabase.schema("security").rpc("finalize_attack_replay", {
          p_replay_id: replayId,
          p_status: "failed",
          p_summary: { engineVersion: "deterministic-replay-v1", errorCode: safeErrorCode(error) },
        });
        if (finalizedFailure.error) securityLog("attack_replay_failure_finalize_failed", {
          requestId, tenantId: parsed.tenantId, replayId, errorCode: safeErrorCode(finalizedFailure.error),
        });
      } catch (finalizeError) {
        securityLog("attack_replay_failure_finalize_failed", {
          requestId, tenantId: parsed.tenantId, replayId, errorCode: safeErrorCode(finalizeError),
        });
      }
      throw new Error("REPLAY_PERSISTENCE_FAILED");
    }

    const ledger = await supabase.schema("security").rpc("append_security_ledger_entry", {
      p_tenant_id: parsed.tenantId,
      p_action: "attack_replay_completed",
      p_resource_type: "attack_replay",
      p_resource_id: replayId,
      p_request_id: requestId,
      p_actor_type: "operator",
      p_details: {
        subjectId: loaded.subjectId ?? null,
        sourceEventId: loaded.sourceEventId ?? null,
        eventCount: result.eventCount,
        evidenceDigest,
        finalDecision: result.finalDecision,
        finalScoreFloor: summary.finalScoreFloor,
        escalations: result.escalations,
      },
    });
    if (ledger.error) {
      securityLog("attack_replay_ledger_append_failed", {
        requestId, tenantId: parsed.tenantId, replayId, errorCode: safeErrorCode(ledger.error),
      });
    }

    securityLog("attack_replay_completed", {
      requestId, tenantId: parsed.tenantId, replayId,
      eventCount: result.eventCount, finalDecision: result.finalDecision,
      finalScoreFloor: summary.finalScoreFloor, escalations: result.escalations,
    });
    return json({
      replayId,
      tenantId: parsed.tenantId,
      subjectId: loaded.subjectId ?? null,
      sourceEventId: loaded.sourceEventId ?? null,
      replayMode: parsed.replayMode,
      evidenceDigest,
      result: summary,
      requestId,
    }, 201, requestId);
  } catch (error) {
    if (error instanceof z.ZodError) return json({ error: "INVALID_REQUEST", requestId }, 400, requestId);
    if (error instanceof Error && error.message === "UNSUPPORTED_MEDIA_TYPE") return json({ error: "UNSUPPORTED_MEDIA_TYPE", requestId }, 415, requestId);
    if (error instanceof Error && error.message === "PAYLOAD_TOO_LARGE") return json({ error: "PAYLOAD_TOO_LARGE", requestId }, 413, requestId);
    if (error instanceof Error && error.message === "INVALID_JSON") return json({ error: "INVALID_JSON", requestId }, 400, requestId);
    if (error instanceof Error && error.message === "RATE_LIMITED") return json({ error: "RATE_LIMITED", retryAfter: 60, requestId }, 429, requestId);
    if (error instanceof Error && error.message === "SOURCE_EVENT_NOT_FOUND") return json({ error: "SOURCE_EVENT_NOT_FOUND", requestId }, 404, requestId);
    if (error instanceof Error && error.message === "REPLAY_SUBJECT_MISMATCH") return json({ error: "REPLAY_SUBJECT_MISMATCH", requestId }, 400, requestId);
    if (error instanceof Error && error.message === "NO_REPLAY_EVENTS") return json({ error: "NO_REPLAY_EVENTS", requestId }, 422, requestId);
    if (error instanceof Error && error.message === "REPLAY_TOO_MANY_EVENTS") return json({ error: "REPLAY_TOO_MANY_EVENTS", requestId }, 413, requestId);
    securityLog("attack_replay_failed", {
      requestId, ...(tenantId ? { tenantId } : {}), ...(replayId ? { replayId } : {}),
      errorCode: safeErrorCode(error), ...(safeErrorStatus(error) ? { errorStatus: safeErrorStatus(error) } : {}),
    });
    return json({ error: "REPLAY_FAILED", requestId }, 500, requestId);
  }
}
