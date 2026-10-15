# GainiRen Security — Server-to-server signing and key rotation

## Important boundary

The security API is a server-to-server service. Do not call `/api/security-check` or `/api/security-event` directly from browser JavaScript or ship a tenant API key in a Vite/React bundle, mobile APK, URL, or public repository. A browser cannot keep an HMAC key secret. The GainiRen backend should call this service over HTTPS.

## Signed request format

For each request, generate a fresh cryptographically random nonce (at least 16 URL-safe characters) and current Unix timestamp in seconds. Sign the exact raw JSON text—not a re-serialized object—using HMAC-SHA256 with the tenant API key.

Canonical text, newline-delimited:

1. `GAINIREN-REQUEST-V1`
2. Uppercase HTTP method
3. URL pathname plus query string
4. Timestamp as 10 decimal digits
5. Fresh nonce
6. Lowercase hex SHA-256 digest of the exact raw request body

Send headers:

- `Authorization: Bearer <tenant-api-key>`
- `Content-Type: application/json`
- `X-GainiRen-Timestamp: <unix-seconds>`
- `X-GainiRen-Nonce: <fresh-random-value>`
- `X-GainiRen-Signature: v1=<64-lowercase-hex-digest>`

The API checks the HMAC in constant time, rejects timestamps outside a five-minute window, then atomically consumes the nonce in Postgres. Reusing the nonce is rejected, including concurrent replay attempts. A new signature is required for every retry; do not blindly resend the same signed request.

## Node.js example

Use this only in a trusted backend. Keep `GAINIREN_SECURITY_API_KEY` in a server-side secret manager.

```js
import { createHash, createHmac, randomBytes } from "node:crypto";

const baseUrl = process.env.GAINIREN_SECURITY_URL; // e.g. https://gainiren-security-api.onrender.com
const apiKey = process.env.GAINIREN_SECURITY_API_KEY;

function sign(method, pathAndQuery, timestamp, nonce, rawBody) {
  const bodyDigest = createHash("sha256").update(rawBody, "utf8").digest("hex");
  const canonical = [
    "GAINIREN-REQUEST-V1",
    method.toUpperCase(),
    pathAndQuery,
    timestamp,
    nonce,
    bodyDigest,
  ].join("\n");
  return "v1=" + createHmac("sha256", apiKey).update(canonical, "utf8").digest("hex");
}

export async function requestSecurityCheck({ tenantId, subjectId, sessionId }) {
  const path = "/api/security-check";
  const rawBody = JSON.stringify({ tenantId, subjectId, sessionId });
  const timestamp = String(Math.floor(Date.now() / 1000));
  const nonce = randomBytes(24).toString("base64url");
  const signature = sign("POST", path, timestamp, nonce, rawBody);

  const response = await fetch(new URL(path, baseUrl), {
    method: "POST",
    redirect: "error",
    headers: {
      authorization: `Bearer ${apiKey}`,
      "content-type": "application/json",
      "x-gainiren-timestamp": timestamp,
      "x-gainiren-nonce": nonce,
      "x-gainiren-signature": signature,
    },
    body: rawBody,
    signal: AbortSignal.timeout(8000),
  });
  if (!response.ok) throw new Error(`Security API returned HTTP ${response.status}`);
  return response.json();
}
```

## Controlled key rotation

The dedicated security database stores SHA-256 hashes, not plaintext API keys. Rotation is performed through `security.rotate_tenant_api_key(uuid,text,integer)`, executable only by `service_role`.

1. Generate a new random API key in a trusted operator environment; do not send it through chat or commit it.
2. Compute lowercase SHA-256 hex of the new key.
3. Update the GainiRen backend secret manager with the new key and verify the caller is ready to use it.
4. Call the rotation RPC with the tenant UUID, new 64-character hash, and a short grace window (default 900 seconds, maximum 86400; use 0 for immediate revocation).
5. During the grace window, both the new key and old key are accepted; the old key stops working automatically at expiry. A rotation to zero grace immediately clears the previous key.
6. Confirm successful signed requests using the new key. Revoke/replace the key immediately if compromise is suspected.

The database writes a ledger entry for each successful rotation. The RPC does not return or store the plaintext key.

## Transport security

The production service must be reached through the Render HTTPS URL. The Node adapter emits HSTS, a restrictive CSP, `nosniff`, `DENY` framing, `no-referrer`, and `no-store` headers. Internal loopback worker calls use HTTP only on `127.0.0.1` and are not exposed externally. Outbound AI/analytics clients must reject redirects and use HTTPS in production.

## Verification

Automated tests cover exact-body binding, method/path/timestamp/nonce binding, malformed headers, timestamp freshness, invalid HMACs, nonce replay rejection, and the bounded key-overlap filter. A transaction-scoped database test verifies normal rotation, grace-window metadata, immediate revocation, audit behavior, and that anonymous clients cannot execute the rotation RPC.
