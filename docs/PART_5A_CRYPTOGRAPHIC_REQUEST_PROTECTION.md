# Part 5A — Cryptographic Request Protection + Replay Defense

Part 5A upgrades the existing Part 3 request-signing foundation into the production cryptographic boundary used by sensitive API operations.

## Request contract

Every production signed request now uses `v2` HMAC-SHA256 and binds all of these values into one canonical payload:

- HTTP method
- exact path + query
- Unix timestamp
- fresh per-request nonce
- registered tenant key UUID
- normalized content type
- SHA-256 digest of the exact raw request body

The signature format is `v2=<64 lowercase hex characters>`.

The key UUID is not merely an authentication hint anymore: it is inside the signed material. Changing `X-GainiRen-Key-Id` without recomputing the signature therefore invalidates the request.

## Replay defense

The timestamp remains bounded to a five-minute clock-skew window. The nonce is consumed atomically in the dedicated `security.request_nonces` table. A duplicate nonce is rejected even when the same signed request is submitted concurrently. The database function is callable only by `service_role`.

The nonce is intentionally random per request. A retry must create a new nonce, timestamp, and signature. Reusing the old signed envelope is not a valid retry mechanism.

## Key rotation

Part 5A keeps the canonical `security.tenant_api_keys` registry and the existing rotation/grace-window model from Part 3. The active key ID must match the registered tenant key used to authenticate the request, and the same key ID is cryptographically bound into the v2 signature.

The server stores only key hashes. Plaintext keys remain in the trusted backend/operator environment.

## Additional cryptographic primitives

`src/security/cryptoSuite.ts` already provides:

- AES-256-GCM authenticated encryption
- optional authenticated data (AAD)
- P-384 ECDH + HKDF-SHA384 key derivation
- ECDSA P-384 / SHA-384 signatures
- signed envelopes with timestamp, nonce and payload hash
- SHA-384 / SHA-512 digests
- HMAC-SHA384

These primitives are separate from the v2 API HMAC boundary so that later database, transaction and control-plane layers can adopt stronger asymmetric trust envelopes without changing the request contract prematurely.

## Security properties added in Part 5A

1. Key-ID substitution is cryptographically rejected.
2. Content-type substitution is cryptographically rejected.
3. Body mutation is rejected by the body digest.
4. Path/query mutation is rejected.
5. Method mutation is rejected.
6. Timestamp replay outside the freshness window is rejected.
7. Nonce replay is rejected atomically at the database boundary.
8. v1 signatures remain available only through the explicit compatibility verifier and are not accepted by the production verifier.
9. The production verifier never logs API keys, signatures, request bodies, or nonce values.

## What Part 5A does not do

It does not add AI, transaction blocking, database deception, graph analysis, or a global kill switch. Those belong to Parts 5B–5E. Part 5F will exercise this boundary with replay, mutation, concurrency, clock-skew, and key-rotation validation.

## Validation target

Before merging Part 5A, CI must pass typecheck, lint, unit tests, runtime smoke, HoneyDB CI and CodeQL. The dedicated `gainiren-shield-lab` database must also pass the transactional nonce replay test without changing the legacy `rewards-platform` database.
