import { createHash, randomBytes, randomUUID } from "node:crypto";
import { createClient } from "@supabase/supabase-js";

const [nameArg, ...rest] = process.argv.slice(2);
const name = [nameArg, ...rest].join(" ").trim();
const url = process.env.SUPABASE_URL;
const serverKey = process.env.SUPABASE_SERVER_KEY;

if (!name || name.length > 160) {
  console.error('Usage: SUPABASE_URL=... SUPABASE_SERVER_KEY=... node scripts/provision-tenant.mjs "Tenant name"');
  process.exit(2);
}
if (!url || !serverKey) {
  console.error("Missing SUPABASE_URL or SUPABASE_SERVER_KEY. Never put these secrets in Git.");
  process.exit(2);
}

const apiKey = `gr_live_${randomBytes(32).toString("base64url")}`;
const apiKeyHash = createHash("sha256").update(apiKey, "utf8").digest("hex");
const externalKey = randomUUID();
const client = createClient(url, serverKey, {
  auth: { autoRefreshToken: false, persistSession: false, detectSessionInUrl: false },
});

const result = await client.schema("security").rpc("provision_security_tenant", {
  p_name: name,
  p_external_key: externalKey,
  p_api_key_hash: apiKeyHash,
});

if (result.error) {
  console.error("Tenant provisioning failed:", result.error.code ?? "DATABASE_ERROR");
  process.exit(1);
}

const provisioned = Array.isArray(result.data) ? result.data[0] : result.data;
if (!provisioned || typeof provisioned.tenant_id !== "string" || typeof provisioned.key_id !== "string") {
  console.error("Tenant provisioning failed: invalid database response.");
  process.exit(1);
}

console.log(JSON.stringify({
  warning: "Save this API key now. It is shown once and cannot be recovered from the database.",
  tenant: {
    id: provisioned.tenant_id,
    externalKey: provisioned.external_key,
    name: provisioned.name,
    status: provisioned.status,
    createdAt: provisioned.created_at,
  },
  keyId: provisioned.key_id,
  apiKey,
}, null, 2));
