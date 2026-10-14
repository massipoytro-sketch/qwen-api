# Part 3 — Cryptographic Trust & Transaction Integrity

This layer is the trust boundary between GainiRen clients/services and the security engine. It is deliberately deterministic and contains no AI.

## 1. Request cryptography

Every signed request binds:

- HTTP method
- exact path/query target
- Unix timestamp
- per-request nonce
- SHA-256 digest of the exact body

The HMAC-SHA256 signature is compared in constant time. A five-minute clock window and an atomic database nonce-consumption step prevent stale and replayed requests. The API never logs the bearer key, signature, nonce value, or raw request body.

## 2. Managed credential lifecycle

The security database already contains the canonical `security.tenant_api_keys` lifecycle. The API now authenticates through its server-side `consume_rotated_api_key` RPC rather than directly reading credential hashes. Existing rotation supports active/grace/revoked states, expiration, atomic rotation, and explicit retirement of the legacy tenant key.

The API does not fall back to the legacy `tenants.api_key_hash` field after a managed-key lookup. This makes revocation authoritative.

## 3. Idempotency

The security-check boundary accepts an `Idempotency-Key` with a strict format. The server hashes the key and an exact method/target/body request digest. PostgreSQL serializes concurrent claims per tenant/key, rejects reuse with a different request, and records completion/failure state. This prevents retry storms from becoming duplicate operations and provides a foundation for future high-value transaction endpoints.

## 4. Transport hardening

The Node adapter already emits HSTS with a one-year lifetime and `includeSubDomains`, plus no-store, CSP, frame protection, MIME sniffing protection and strict referrer policy. TLS protocol/cipher selection remains controlled by the HTTPS edge/Render rather than the application process; the application never treats plain HTTP as a secure transport.

## 5. Bank-grade design principle

The goal is not one giant firewall. The design uses independent trust boundaries:

`transport → credential → signature → replay protection → idempotency → rate control → deterministic risk → policy/firewall → audit ledger → controlled side effects`

A failure in an optional analytics dependency cannot silently lower the deterministic decision. The AI phase will remain advisory and isolated until all deterministic layers and tests are complete.

## Validation targets

Before merging Part 3:

- managed-key lookup must be tenant-scoped and reject revoked/expired keys;
- request signatures must fail for body/path/method/timestamp/nonce changes;
- duplicate nonce must fail atomically;
- idempotency key reused with a different request must fail;
- idempotency completion/failure must be persisted;
- no client role receives direct credential or idempotency-table access;
- full Security CI, Runtime Smoke, HoneyDB CI and CodeQL must pass.
