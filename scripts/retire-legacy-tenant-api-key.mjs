#!/usr/bin/env node
import { createClient } from "@supabase/supabase-js";

import { assertSecurityProjectUrl } from "./lib/assert-security-project.mjs";
const [tenantId] = process.argv.slice(2);
const url = process.env.SUPABASE_URL;
const serverKey = process.env.SUPABASE_SERVER_KEY;
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

if (!tenantId || !uuid.test(tenantId)) {
  console.error("Usage: node scripts/retire-legacy-tenant-api-key.mjs <TENANT_UUID>");
  process.exit(2);
}
if (!url || !serverKey) {
  console.error("Missing SUPABASE_URL or SUPABASE_SERVER_KEY. Never put secrets in Git or client code.");
  process.exit(2);
}
try {
  assertSecurityProjectUrl(url);
} catch (error) {
  console.error(error instanceof Error ? error.message : "Refusing database target.");
  process.exit(2);
}

if (process.env.CONFIRM_LEGACY_KEY_RETIREMENT !== "YES") {
  console.error("Refusing legacy key retirement. First deploy and verify a managed v2 key, then set CONFIRM_LEGACY_KEY_RETIREMENT=YES.");
  process.exit(2);
}

const client = createClient(url, serverKey, {
  auth: { autoRefreshToken: false, persistSession: false, detectSessionInUrl: false },
});
const result = await client.schema("security").rpc("retire_legacy_tenant_api_key", { p_tenant_id: tenantId });
if (result.error) {
  console.error("Legacy key retirement failed:", result.error.code ?? "DATABASE_ERROR");
  process.exit(1);
}
console.log(JSON.stringify({
  tenantId,
  legacyKeyRetired: result.data === true,
  note: result.data === true
    ? "Legacy v1 authentication is disabled for this tenant; only active managed v2 API keys can authenticate."
    : "No legacy key was present. Managed v2 authentication remains available.",
}, null, 2));
