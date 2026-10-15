# GainiRen Security — Part 3: Cryptographic Integrity

Part 3 adds the second half of the signed-request trust model: authenticated responses.

## Request side

The existing request signature binds:

- HTTP method
- exact path and query
- timestamp
- per-request nonce
- SHA-256 digest of the exact body
- tenant API key through HMAC-SHA-256

The nonce is consumed atomically in Postgres, so reusing a valid signed request is rejected even when the attacker has captured the complete request.

## Response side

The HTTP adapter now signs authenticated API responses with the same tenant API key, without storing or returning the plaintext key.

Header:

`x-gainiren-response-signature: v1=<64 hex characters>`

Canonical response material:

```text
GAINIREN-RESPONSE-V1
HTTP_STATUS
REQUEST_ID
SHA256(EXACT_RESPONSE_BODY)
```

This means a client can verify that a response belongs to its request and that the response body was not altered after the security API produced it. Changing the body, status, request ID, or API key invalidates the signature.

The API adapter never logs the key or signature material. The key exists only in the in-memory request handling path.

## TLS and transport

Production transport already requires HTTPS/forwarded HTTPS and sends HSTS, CSP, cross-origin isolation, permissions restrictions, and other security headers. Part 3 keeps TLS enforcement separate from application cryptography: TLS protects the channel, while request/response HMAC protects message integrity and authenticity.

## Why the signature changes every request

The request signature is not a static token. A fresh timestamp and fresh nonce are part of the signed canonical data, so two otherwise identical requests produce different signatures. The server rejects stale timestamps and consumed nonces.

## AI status

AI is intentionally not part of Part 3. Deterministic controls remain authoritative. The later AI phase will be advisory and cannot weaken deterministic decisions.

## Validation target

Part 3 is complete only after Security CI, Runtime Smoke, HoneyDB CI, CodeQL, typecheck, lint and unit tests pass on the final commit. In particular, the cryptographic tests verify:

- valid request signatures;
- exact-body binding;
- method/path binding;
- timestamp freshness;
- nonce format and replay protection;
- signatures changing with a fresh timestamp/nonce;
- valid response signatures;
- response tamper detection;
- response status/request-ID binding;
- rejection under a different API key.
