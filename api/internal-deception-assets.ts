import { createHash, timingSafeEqual } from "node:crypto";
import { z } from "zod";
import { env } from "../src/config/env";
import { supabase } from "../src/db/supabase";
import { checkRateLimit } from "../src/security/rateLimit";
import { hashDeceptionLocator, isSafeDeceptionLocator } from "../src/security/deception";
import { isSecureTransport, securityHeaders } from "../src/security/transport";
import { safeErrorCode, safeErrorStatus, securityLog } from "../src/security/observability";

const safeLabel = (value: string) => !/[\\u0000-\\u001F\\u007F]/.test(value);

const metadataSchema = z.object({
  description: z.string().max(500).refine(safeLabel, "Control characters are not allowed").optional(),
  ownerTeam: z.string().max(80).refine(safeLabel, "Control characters are not allowed").optional(),
  environment: z.enum(["production", "staging", "test"]).optional(),
  tags: z.array(z.string().min(1).max(40).regex(/^[A-Za-z0-9_.:-]+$/)).max(20).optional(),
}).strict();

const createSchema = z.object({
  tenantId: z.uuid(),
  assetType: z.enum(["route", "credential_canary", "database_canary", "service_canary", "document_canary"]),
  assetName: z.string().trim().min(1).max(160).refine(safeLabel, "Control characters are not allowed"),
  locator: z.string().min(1).max(256).refine(isSafeDeceptionLocator, "Invalid synthetic locator format"),
  metadata: metadataSchema.default({}),
}).strict();

const statusSchema = z.object({
  tenantId: z.uuid(),
  assetId: z.uuid(),
  status: z.enum(["active", "disabled", "retired"]),
}).strict();

const querySchema = z.object({
  tenantId: z.uuid(),
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

async function validateTenantAndLimit(tenantId: string, expectedToken: string) {
  const tenant = await supabase.schema("security").from("tenants")
    .select("id,status").eq("id", tenantId).maybeSingle();
  if (tenant.error) throw tenant.error;
  if (!tenant.data || tenant.data.status !== "active") return false;

  const rate = await checkRateLimit({
    tenantId,
    key: `security-ops-deception:${createHash("sha256").update(expectedToken, "utf8").digest("hex")}`,
    bucket: "security-ops-deception",
    limit: 60,
    windowSeconds: 60,
  });
  if (!rate.allowed) throw new Error("RATE_LIMITED");
  return true;
}

export default async function handler(request: Request) {
  const candidate = request.headers.get("x-request-id") ?? "";
  const requestId = /^[a-zA-Z0-9._:-]{1,100}$/.test(candidate) ? candidate : crypto.randomUUID();

  if (!isSecureTransport(request)) return json({ error: "TLS_REQUIRED", requestId }, 426, requestId);
  if (!["GET", "POST", "PATCH"].includes(request.method)) {
    return json({ error: "METHOD_NOT_ALLOWED", requestId }, 405, requestId);
  }

  const expectedToken = env.SECURITY_OPS_TOKEN;
  if (!expectedToken) return json({ error: "NOT_FOUND", requestId }, 404, requestId);

  const authorization = request.headers.get("authorization") ?? "";
  const bearer = /^Bearer\s+(.+)$/i.exec(authorization);
  if (!bearer || bearer[1].length > 512 || !matchesToken(bearer[1].trim(), expectedToken)) {
    securityLog("deception_registry_auth_denied", { requestId });
    return json({ error: "UNAUTHORIZED", requestId }, 401, requestId);
  }

  try {
    if (request.method === "GET") {
      const url = new URL(request.url);
      const parsed = querySchema.parse(Object.fromEntries(url.searchParams.entries()));
      if (!await validateTenantAndLimit(parsed.tenantId, expectedToken)) {
        return json({ error: "NOT_FOUND", requestId }, 404, requestId);
      }
      const result = await supabase.schema("security").rpc("list_deception_assets", {
        p_tenant_id: parsed.tenantId,
        p_limit: parsed.limit,
      });
      if (result.error) throw result.error;
      const assets = (result.data ?? []).map((asset: Record<string, unknown>) => ({
        id: asset.id,
        assetType: asset.asset_type,
        assetName: asset.asset_name,
        locatorHash: asset.locator_hash,
        status: asset.status,
        hitCount: asset.hit_count,
        lastSeenAt: asset.last_seen_at,
        metadata: asset.metadata,
        createdAt: asset.created_at,
        updatedAt: asset.updated_at,
      }));
      return json({ tenantId: parsed.tenantId, assets, requestId }, 200, requestId);
    }

    const body = await readJson(request);
    if (request.method === "POST") {
      const parsed = createSchema.parse(body);
      if (!await validateTenantAndLimit(parsed.tenantId, expectedToken)) {
        return json({ error: "NOT_FOUND", requestId }, 404, requestId);
      }
      const locatorHash = hashDeceptionLocator(parsed.locator);
      const result = await supabase.schema("security").rpc("register_deception_asset", {
        p_tenant_id: parsed.tenantId,
        p_asset_type: parsed.assetType,
        p_asset_name: parsed.assetName,
        p_locator_hash: locatorHash,
        p_metadata: parsed.metadata,
      });
      if (result.error) {
        if (result.error.code === "23505") return json({ error: "ASSET_ALREADY_REGISTERED", requestId }, 409, requestId);
        throw result.error;
      }
      const asset = Array.isArray(result.data) ? result.data[0] : result.data;
      const ledgerEntry = await supabase.schema("security").rpc("append_security_ledger_entry", {
        p_tenant_id: parsed.tenantId,
        p_action: "deception_asset_registered",
        p_resource_type: "deception_asset",
        p_resource_id: typeof asset?.id === "string" ? asset.id : null,
        p_request_id: requestId,
        p_actor_type: "operator",
        p_details: {
          assetType: parsed.assetType,
          assetName: parsed.assetName,
          locatorHash,
          environment: parsed.metadata.environment ?? null,
          tags: parsed.metadata.tags ?? [],
        },
      });
      if (ledgerEntry.error) securityLog("deception_asset_ledger_append_failed", {
        requestId, tenantId: parsed.tenantId, errorCode: safeErrorCode(ledgerEntry.error),
      });
      securityLog("deception_asset_registered", {
        requestId, tenantId: parsed.tenantId, assetId: asset?.id,
        assetType: parsed.assetType, locatorHash,
      });
      return json({
        registered: true,
        asset: {
          id: asset?.id,
          assetType: asset?.asset_type,
          assetName: asset?.asset_name,
          locatorHash: asset?.locator_hash,
          status: asset?.status,
        },
        requestId,
      }, 201, requestId);
    }

    const parsed = statusSchema.parse(body);
    if (!await validateTenantAndLimit(parsed.tenantId, expectedToken)) {
      return json({ error: "NOT_FOUND", requestId }, 404, requestId);
    }
    const result = await supabase.schema("security").rpc("set_deception_asset_status", {
      p_tenant_id: parsed.tenantId,
      p_asset_id: parsed.assetId,
      p_status: parsed.status,
    });
    if (result.error) {
      if (result.error.code === "P0002") return json({ error: "ASSET_NOT_FOUND", requestId }, 404, requestId);
      throw result.error;
    }
    const asset = Array.isArray(result.data) ? result.data[0] : result.data;
    const ledgerEntry = await supabase.schema("security").rpc("append_security_ledger_entry", {
      p_tenant_id: parsed.tenantId,
      p_action: "deception_asset_status_changed",
      p_resource_type: "deception_asset",
      p_resource_id: parsed.assetId,
      p_request_id: requestId,
      p_actor_type: "operator",
      p_details: { status: parsed.status },
    });
    if (ledgerEntry.error) securityLog("deception_asset_ledger_append_failed", {
      requestId, tenantId: parsed.tenantId, errorCode: safeErrorCode(ledgerEntry.error),
    });
    securityLog("deception_asset_status_changed", {
      requestId, tenantId: parsed.tenantId, assetId: parsed.assetId, status: parsed.status,
    });
    return json({ updated: true, asset: { id: asset?.id, status: asset?.status }, requestId }, 200, requestId);
  } catch (error) {
    if (error instanceof z.ZodError) return json({ error: "INVALID_REQUEST", requestId }, 400, requestId);
    if (error instanceof Error && error.message === "UNSUPPORTED_MEDIA_TYPE") return json({ error: "UNSUPPORTED_MEDIA_TYPE", requestId }, 415, requestId);
    if (error instanceof Error && error.message === "PAYLOAD_TOO_LARGE") return json({ error: "PAYLOAD_TOO_LARGE", requestId }, 413, requestId);
    if (error instanceof Error && error.message === "INVALID_JSON") return json({ error: "INVALID_JSON", requestId }, 400, requestId);
    if (error instanceof Error && error.message === "RATE_LIMITED") return json({ error: "RATE_LIMITED", retryAfter: 60, requestId }, 429, requestId);
    securityLog("deception_registry_failed", {
      requestId,
      errorCode: safeErrorCode(error),
      ...(safeErrorStatus(error) ? { errorStatus: safeErrorStatus(error) } : {}),
    });
    return json({ error: "INTERNAL_ERROR", requestId }, 500, requestId);
  }
}
