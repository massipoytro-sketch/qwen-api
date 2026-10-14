# GainiRen Security — Versioned Signed API Requests

The `POST /api/security-check` and `POST /api/security-event` endpoints require a tenant API key and a versioned HMAC signature. Each request binds the HTTP method, path and query, timestamp, a fresh one-time nonce, and the exact raw body digest. Sign requests only in a trusted server environment; never put tenant keys in browser JavaScript, a mobile application bundle, a public repository, or client-visible environment variables.

## Protocol v1 — legacy key compatibility

Use this only for tenants still using `security.tenants.api_key_hash`:

- `Authorization: Bearer <legacy-tenant-api-key>`
- `X-GainiRen-Timestamp: <10-digit Unix timestamp in seconds>`
- `X-GainiRen-Nonce: <16–128 characters from A-Z, a-z, 0-9, underscore or hyphen>`
- `X-GainiRen-Signature: v1=<64 lowercase hexadecimal characters>`

The timestamp must be within 300 seconds of server time. Every request must have a fresh cryptographically random nonce. The server stores only the nonce hash in the private `security.request_nonces` table. A duplicate nonce is rejected, including concurrent reuse.

Canonical string, joined with a single LF newline and no trailing newline:

```text
GAINIREN-REQUEST-V1
<HTTP method in uppercase>
<URL path plus query string>
<timestamp header value>
<nonce header value>
<SHA-256 hex digest of the exact raw JSON body>
```

Compute HMAC-SHA-256 over this exact UTF-8 string using the tenant API key as HMAC key. Prefix the lowercase hex digest with `v1=`.

## Protocol v2 — managed, rotatable key

Use this for all new keys:

- `Authorization: Bearer <managed-tenant-api-key>`
- `X-GainiRen-Key-Id: <managed-key UUID>`
- `X-GainiRen-Timestamp: <10-digit Unix timestamp in seconds>`
- `X-GainiRen-Nonce: <fresh cryptographically random nonce>`
- `X-GainiRen-Signature: v2=<64 lowercase hexadecimal characters>`

The server first checks that the key ID belongs to the requested tenant, that its SHA-256 key hash matches, that its validity window is open, and that its status is `active` or unexpired `grace`. Supplying an invalid key ID never falls back to v1. The key ID is also part of the signed canonical request, so it cannot be substituted.

Canonical v2 string:

```text
GAINIREN-REQUEST-V2
<HTTP method in uppercase>
<URL path plus query string>
<timestamp header value>
<nonce header value>
<managed key UUID>
<SHA-256 hex digest of the exact raw JSON body>
```

Compute HMAC-SHA-256 over the exact string using the new API key; prefix the lowercase hex digest with `v2=`.

## Key rotation and revocation

A managed key is identified by its UUID; only the SHA-256 hash is stored in PostgreSQL. The raw key is generated once by the operator script and printed once to save to a secret manager.

Before running a command, confirm that `SUPABASE_URL` and `SUPABASE_SERVER_KEY` target the dedicated `gainiren-shield-lab` project—not the older `rewards-platform` project.

Create/rotate to a managed v2 key:

```sh
CONFIRM_KEY_ROTATION=YES \
SUPABASE_URL='https://<security-project>.supabase.co' \
SUPABASE_SERVER_KEY='<server-only-key>' \
node scripts/rotate-tenant-api-key.mjs '<TENANT_UUID>' 'production-api' 3600
```

The final argument is the old managed key's grace period in seconds (0–604800). During that interval the old key remains valid with its original key ID; after expiry it is rejected. Setting grace to `0` revokes the previous active managed key immediately. The new key and ID must be stored securely and deployed together.

Revoke a managed key immediately:

```sh
CONFIRM_KEY_REVOCATION=YES \
SUPABASE_URL='https://<security-project>.supabase.co' \
SUPABASE_SERVER_KEY='<server-only-key>' \
node scripts/revoke-tenant-api-key.mjs '<TENANT_UUID>' '<KEY_UUID>'
```

Legacy v1 authentication remains enabled until the tenant is explicitly migrated, because the server cannot safely assume all legacy callers have upgraded. After a v2 key has been deployed and verified end-to-end, retire the legacy key:

```sh
CONFIRM_LEGACY_KEY_RETIREMENT=YES \
SUPABASE_URL='https://<security-project>.supabase.co' \
SUPABASE_SERVER_KEY='<server-only-key>' \
node scripts/retire-legacy-tenant-api-key.mjs '<TENANT_UUID>'
```

The retirement RPC refuses to run unless the tenant has a valid active managed v2 key. Once retired, v1 authentication is disabled for that tenant. Do not commit these shell commands with real secrets or paste secrets into ChatGPT.

## Node.js v2 signing example (server-side only)

```js
import { createHash, createHmac, randomBytes } from "node:crypto";

const apiKey = process.env.GAINIREN_TENANT_API_KEY;
const keyId = process.env.GAINIREN_TENANT_KEY_ID;
const endpoint = "https://gainiren-security-api.onrender.com/api/security-check";
const body = JSON.stringify({ tenantId: process.env.GAINIREN_TENANT_ID });
const timestamp = String(Math.floor(Date.now() / 1000));
const nonce = randomBytes(24).toString("base64url");
const url = new URL(endpoint);
const canonical = [
  "GAINIREN-REQUEST-V2",
  "POST",
  url.pathname + url.search,
  timestamp,
  nonce,
  keyId,
  createHash("sha256").update(body, "utf8").digest("hex"),
].join("\n");
const signature = createHmac("sha256", apiKey).update(canonical, "utf8").digest("hex");

const response = await fetch(endpoint, {
  method: "POST",
  headers: {
    authorization: `Bearer ${apiKey}`,
    "content-type": "application/json",
    "x-gainiren-key-id": keyId,
    "x-gainiren-timestamp": timestamp,
    "x-gainiren-nonce": nonce,
    "x-gainiren-signature": `v2=${signature}`,
  },
  body,
  redirect: "error",
});
```

## Operational requirements

- Generate a new nonce and signature for every attempt, including retries.
- Use a cryptographically secure nonce generator and keep clocks synchronized.
- Keep secrets in the server's secret manager. Never emit raw keys, signatures, or nonces to logs.
- HTTPS/TLS is mandatory for public deployment. HMAC complements TLS and does not replace it.
- A failed dependency must not cause the deterministic authentication and risk decision path to trust unverified requests.
