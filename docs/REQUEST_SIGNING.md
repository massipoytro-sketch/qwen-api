# GainiRen Security — Signed API Requests

The `POST /api/security-check` and `POST /api/security-event` endpoints require a versioned HMAC request signature in addition to the tenant API key. This protects the integrity and freshness of server-to-server requests and makes captured requests unusable after their nonce has been consumed.

## Required headers

- `Authorization: Bearer <tenant-api-key>`
- `Content-Type: application/json`
- `X-GainiRen-Timestamp: <10-digit Unix timestamp in seconds>`
- `X-GainiRen-Nonce: <16–128 characters from A-Z, a-z, 0-9, underscore or hyphen>`
- `X-GainiRen-Signature: v1=<64 lowercase hexadecimal characters>`

The timestamp must be within 300 seconds of server time. Every request must use a fresh cryptographically random nonce. The server hashes the nonce and atomically consumes it in the private `security.request_nonces` table. Reusing a nonce is rejected, including concurrent duplicate submissions. Expired nonce rows are removed in bounded batches.

## Canonical string

Construct the following UTF-8 string, joining fields with a single newline and without a trailing newline:

```text
GAINIREN-REQUEST-V1
<HTTP method in uppercase>
<URL path plus query string>
<timestamp header value>
<nonce header value>
<SHA-256 hex digest of the exact raw JSON body>
```

Compute HMAC-SHA-256 over that canonical string using the tenant API key as the HMAC key. Send the lowercase hexadecimal digest prefixed with `v1=`.

Sign the **exact serialized body string that will be sent**. Do not parse and reserialize JSON after signing. Do not sign the origin/scheme/host; the path and query are signed so requests work behind a TLS-terminating reverse proxy.

## Node.js example (server-side only)

```js
import { createHash, createHmac, randomBytes } from "node:crypto";

const apiKey = process.env.GAINIREN_TENANT_API_KEY;
const endpoint = "https://gainiren-security-api.onrender.com/api/security-check";
const body = JSON.stringify({ tenantId: process.env.GAINIREN_TENANT_ID });
const timestamp = String(Math.floor(Date.now() / 1000));
const nonce = randomBytes(24).toString("base64url");
const url = new URL(endpoint);
const bodyHash = createHash("sha256").update(body, "utf8").digest("hex");
const canonical = [
  "GAINIREN-REQUEST-V1",
  "POST",
  url.pathname + url.search,
  timestamp,
  nonce,
  bodyHash,
].join("\n");
const digest = createHmac("sha256", apiKey).update(canonical, "utf8").digest("hex");

const response = await fetch(endpoint, {
  method: "POST",
  headers: {
    authorization: `Bearer ${apiKey}`,
    "content-type": "application/json",
    "x-gainiren-timestamp": timestamp,
    "x-gainiren-nonce": nonce,
    "x-gainiren-signature": `v1=${digest}`,
  },
  body,
  redirect: "error",
});
```

## Operational rules

- Keep tenant API keys in a server-side secret store. Never embed them in browser JavaScript, a mobile app bundle, a public repository, or client-visible environment variables.
- Generate a new nonce and signature for every attempt, including retries.
- Keep clocks synchronized with a trusted time source.
- A signature error returns a generic authentication failure; logs store only a bounded rejection code, never the signature, API key or nonce.
- TLS is terminated by the hosting edge. Use the HTTPS endpoint; the signature layer complements TLS and does not replace it.
