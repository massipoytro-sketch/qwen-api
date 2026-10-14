#!/usr/bin/env node
import { createHash, randomBytes } from "node:crypto";
import { createClient } from "@supabase/supabase-js";

const [tenantId, labelArg = "rotated-key", graceArg = "3600"] = process.argv.slice(2);
const url = process.env.SUPABASE_URL;
const serverKey = process.env.SUPABASE_SERVER_KEY;
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const graceSeconds = Number(graceArg);

if (!tenantId || !uuid.test(tenantId) || !labelArg || labelArg.length > 120 ||
    !Number.isInteger(graceSeconds) || graceSeconds < 0 || graceSeconds > 604800) {
  console.error("Usage: node scripts/rotate-tenant-api-key.mjs <TENANT_UUID> [label] [grace-seconds 0..604800]");
  process.exit(2);
}
if (!url || !serverKey) {
  console.error("Missing SUPABASE_URL or SUPABASE_SERVER_KEY. Never place secrets in Git or client code.");
  process.exit(2);
}
if (process.env.CONFIRM_KEY_ROTATION !== "YES") {
  console.error("Refusing to rotate keys. Set CONFIRM_KEY_ROTATION=YES after confirming the target tenant.");
  process.exit(2);
}

const apiKey = `gr_live_${randomBytes(32).toString("base64url")}`;
const keyHash = createHash("sha256").update(apiKey, "utf8").digest("hex");
const client = createClient(url, serverKey, {
  auth: { autoRefreshToken: false, persistSession: false, detectSessionInUrl: false },
});
const result = await client.schema("security").rpc("rotate_tenant_api_key", {
  p_tenant_id: tenantId,
  p_key_hash: keyHash,
  p_label: labelArg,
  p_grace_seconds: graceSeconds,
});
if (result.error) {
  console.error("API key rotation failed:", result.error.code ?? "DATABASE_ERROR");
  process.exit(1);
}
const row = Array.isArray(result.data) ? result.data[0] : result.data;
if (!row?.key_id) {
  console.error("API key rotation returned an invalid result.");
  process.exit(1);
}

console.log(JSON.stringify({
  warning: "Save this key now. The raw key is displayed once and is never stored in the database.",
  tenantId,
  keyId: row.key_id,
  label: labelArg,
  graceSeconds,
  oldActiveKeysRetired: row.previous_active_keys_retired,
  apiKey,
  requiredHeaders: {
    authorization: "Bearer <apiKey>",
    "x-gainiren-key-id": row.key_id,
    "x-gainiren-timestamp": "<10-digit Unix timestamp>",
    "x-gainiren-nonce": "<fresh cryptographically random nonce>",
    "x-gainiren-signature": "v2=<HMAC-SHA-256 hex>",
  },
}, null, 2));
