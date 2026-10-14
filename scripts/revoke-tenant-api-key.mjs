#!/usr/bin/env node
import { createClient } from "@supabase/supabase-js";

const [tenantId, keyId] = process.argv.slice(2);
const url = process.env.SUPABASE_URL;
const serverKey = process.env.SUPABASE_SERVER_KEY;
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

if (!tenantId || !keyId || !uuid.test(tenantId) || !uuid.test(keyId)) {
  console.error("Usage: node scripts/revoke-tenant-api-key.mjs <TENANT_UUID> <KEY_UUID>");
  process.exit(2);
}
if (!url || !serverKey) {
  console.error("Missing SUPABASE_URL or SUPABASE_SERVER_KEY. Never place secrets in Git or client code.");
  process.exit(2);
}
if (process.env.CONFIRM_KEY_REVOCATION !== "YES") {
  console.error("Refusing to revoke. Set CONFIRM_KEY_REVOCATION=YES after confirming the tenant and key id.");
  process.exit(2);
}

const client = createClient(url, serverKey, {
  auth: { autoRefreshToken: false, persistSession: false, detectSessionInUrl: false },
});
const result = await client.schema("security").rpc("revoke_tenant_api_key", {
  p_tenant_id: tenantId,
  p_key_id: keyId,
});
if (result.error) {
  console.error("API key revocation failed:", result.error.code ?? "DATABASE_ERROR");
  process.exit(1);
}
console.log(JSON.stringify({
  tenantId,
  keyId,
  revoked: result.data === true,
  note: result.data === true ? "Key is revoked." : "Key was already revoked or does not belong to this tenant.",
}, null, 2));
