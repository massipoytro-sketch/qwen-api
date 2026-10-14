#!/usr/bin/env node
import { createClient } from "@supabase/supabase-js";

import { assertSecurityProjectUrl } from "./lib/assert-security-project.mjs";
const [tenantId, maxRowsArg = "10000"] = process.argv.slice(2);
const url = process.env.SUPABASE_URL;
const serverKey = process.env.SUPABASE_SERVER_KEY;
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const maxRows = Number(maxRowsArg);

if (!tenantId || !uuid.test(tenantId) || !Number.isInteger(maxRows) || maxRows < 1 || maxRows > 50000) {
  console.error("Usage: node scripts/verify-security-audit-ledger.mjs <TENANT_UUID> [max-rows 1..50000]");
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


const client = createClient(url, serverKey, {
  auth: { autoRefreshToken: false, persistSession: false, detectSessionInUrl: false },
});
const result = await client.schema("security").rpc("verify_security_audit_ledger", {
  p_tenant_id: tenantId,
  p_max_rows: maxRows,
});
if (result.error) {
  console.error("Audit ledger verification failed:", result.error.code ?? "DATABASE_ERROR");
  process.exit(1);
}
const report = Array.isArray(result.data) ? result.data[0] : result.data;
console.log(JSON.stringify({
  tenantId,
  verified: report?.valid === true,
  checkedEntries: report?.checked_entries ?? 0,
  firstInvalidSequence: report?.first_invalid_sequence ?? null,
  reasonCode: report?.reason_code ?? "INVALID_VERIFIER_RESPONSE",
}, null, 2));
if (report?.valid !== true) process.exit(1);
