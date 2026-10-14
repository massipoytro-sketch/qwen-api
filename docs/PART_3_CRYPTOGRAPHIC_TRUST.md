# Part 3 — Cryptographic Trust & Transaction Integrity

This layer hardens the GainiRen security API as a financial-style trust boundary. It is deliberately deterministic; AI remains disabled.

## Request cryptography

Every signed request binds the HTTP method, exact path/query target, Unix timestamp, per-request nonce and SHA-256 digest of the exact body. HMAC-SHA256 verification uses constant-time comparison, a five-minute clock window and an atomic Postgres nonce-consumption step. Modified bodies/targets/methods, stale timestamps and reused nonces cannot pass the same signature.

## Managed credentials

The API authenticates through the existing canonical `security.tenant_api_keys` lifecycle using `consume_rotated_api_key`. It does not fall back to the legacy `tenants.api_key_hash` field. The database already provides atomic rotation, optional grace windows, expiration and explicit legacy-key retirement through controlled RPCs.

## Idempotency

`Idempotency-Key` is required at the security-check boundary. Only a hash is stored. PostgreSQL serializes claims per tenant/key and compares an exact method/target/body digest. Reuse with a different request is rejected, while successful/failed processing is finalized in the idempotency record.

## Transport

The Node adapter already emits HSTS for one year with `includeSubDomains`, plus no-store, CSP, frame protection, MIME-sniffing protection and strict referrer policy. TLS protocol/cipher selection remains the HTTPS edge/Render responsibility rather than pretending the Node process controls edge TLS.

## Bank-grade chain

`TLS edge → managed credential → signed request → replay protection → idempotency → rate/velocity controls → deterministic risk → multi-layer firewall → tamper-evident ledger → controlled side effects`

No AI component can lower the deterministic decision.

## Cleanup safety

A transitional implementation created `security.api_credentials` and `security.request_idempotency`; both are empty and the running API uses the stronger pre-existing `security.tenant_api_keys` lifecycle plus the new idempotency table only. The staged cleanup migration contains DROP statements and is intentionally **not applied** without explicit operator approval. No production security data is in the transitional credential table.
