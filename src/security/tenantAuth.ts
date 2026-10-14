import { z } from "zod";
import { supabase } from "../db/supabase";
import { hashValue } from "./utils";

/**
 * Verifies a tenant API key against the canonical rotatable key registry.
 * The plaintext key is used only in-memory for hashing/signature validation.
 * A supplied key-id is strict: malformed, unknown or mismatched IDs deny access.
 */
export async function authenticateRotatedTenantKey(input: {
  tenantId: string;
  apiKey: string;
  keyId?: string | null;
}): Promise<{ authorized: boolean; keyId: string | null }> {
  const parsed = z.object({
    tenantId: z.uuid(),
    apiKey: z.string().min(1).max(512),
    keyId: z.string().uuid().nullable().optional(),
  }).safeParse(input);
  if (!parsed.success) return { authorized: false, keyId: null };

  const { tenantId, apiKey, keyId } = parsed.data;
  const result = await supabase.schema("security").rpc("consume_rotated_api_key", {
    p_key_hash: hashValue(apiKey),
    p_key_id: keyId ?? null,
    p_tenant_id: tenantId,
  });
  if (result.error) throw result.error;

  const record = Array.isArray(result.data)
    ? result.data[0] as { tenant_id?: string; key_id?: string } | undefined
    : undefined;
  if (!record || record.tenant_id !== tenantId || (keyId && record.key_id !== keyId)) {
    return { authorized: false, keyId: null };
  }

  const tenant = await supabase.schema("security").from("tenants")
    .select("id,status")
    .eq("id", tenantId)
    .eq("status", "active")
    .maybeSingle();
  if (tenant.error) throw tenant.error;
  return { authorized: Boolean(tenant.data), keyId: record.key_id ?? null };
}
