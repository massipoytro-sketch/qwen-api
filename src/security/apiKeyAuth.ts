import { timingSafeEqual } from "node:crypto";
import { z } from "zod";
import { supabase } from "../db/supabase";
import { hashValue } from "./utils";

const uuidSchema = z.uuid();
const keyIdSchema = z.uuid();

export type TenantApiKeyAuthentication = {
  tenantId: string;
  signingVersion: "v1" | "v2";
  keyId: string | null;
};

function hashesMatch(candidate: string, stored: string | null | undefined): boolean {
  if (!stored || !/^[a-f0-9]{64}$/.test(stored)) return false;
  const candidateBytes = Buffer.from(hashValue(candidate), "hex");
  const storedBytes = Buffer.from(stored, "hex");
  return candidateBytes.byteLength === storedBytes.byteLength && timingSafeEqual(candidateBytes, storedBytes);
}

/**
 * Authenticates either an existing legacy tenant key (v1) or a managed,
 * versioned key (v2). Managed keys must be explicitly named by X-GainiRen-Key-Id,
 * tenant-scoped, inside their validity window, and active or still in grace.
 * Supplying an invalid key id never falls back to a legacy key.
 */
export async function authenticateTenantApiKey(input: {
  tenantId: string;
  apiKey: string;
  keyId?: string | null;
  nowMs?: number;
}): Promise<TenantApiKeyAuthentication | null> {
  const tenantId = uuidSchema.parse(input.tenantId);
  if (!input.apiKey || input.apiKey.length > 512) return null;

  const tenantResult = await supabase.schema("security").from("tenants")
    .select("id,status,api_key_hash")
    .eq("id", tenantId)
    .maybeSingle();
  if (tenantResult.error) throw tenantResult.error;
  if (!tenantResult.data || tenantResult.data.status !== "active") return null;

  const now = input.nowMs ?? Date.now();
  const keyIdValue = input.keyId?.trim();
  if (keyIdValue) {
    if (!keyIdSchema.safeParse(keyIdValue).success) return null;
    const keyResult = await supabase.schema("security").from("tenant_api_keys")
      .select("id,key_hash,status,valid_from,expires_at,grace_until")
      .eq("tenant_id", tenantId)
      .eq("id", keyIdValue)
      .maybeSingle();
    if (keyResult.error) throw keyResult.error;
    const key = keyResult.data;
    if (!key || !hashesMatch(input.apiKey, key.key_hash)) return null;

    const validFrom = Date.parse(key.valid_from);
    const expiresAt = key.expires_at ? Date.parse(key.expires_at) : Number.POSITIVE_INFINITY;
    const graceUntil = key.grace_until ? Date.parse(key.grace_until) : Number.NEGATIVE_INFINITY;
    if (!Number.isFinite(validFrom) || now < validFrom || now >= expiresAt) return null;
    const active = key.status === "active";
    const inGrace = key.status === "grace" && Number.isFinite(graceUntil) && now < graceUntil;
    if (!active && !inGrace) return null;

    return { tenantId, signingVersion: "v2", keyId: keyIdValue };
  }

  if (hashesMatch(input.apiKey, tenantResult.data.api_key_hash)) {
    return { tenantId, signingVersion: "v1", keyId: null };
  }
  return null;
}
