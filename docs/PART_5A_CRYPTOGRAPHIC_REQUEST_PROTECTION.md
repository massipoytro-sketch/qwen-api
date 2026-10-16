# Part 5A — Cryptographic Request Protection + Replay Defense

Part 5A upgrades the existing Part 3 request-signing foundation into the production cryptographic boundary used by sensitive API operations.

## Request contract

Every production signed request now uses `v2` HMAC-SHA256 and binds HTTP method, exact path + query, Unix timestamp, fresh nonce, registered tenant key UUID, normalized content type, and SHA-256 digest of the exact raw request body.

The signature format is `v2=<64 lowercase hex characters>`. The key UUID is cryptographically bound to the request, so changing `X-GainiRen-Key-Id` without recomputing the signature invalidates the request.

## Replay defense

The timestamp is limited to a five-minute clock-skew window. The nonce is consumed atomically in `security.request_nonces`. A duplicate nonce is rejected, including concurrent replay attempts. The nonce-consumption function is service-role-only.

A retry must create a new nonce, timestamp, and signature. Reusing an old signed envelope is not a valid retry.

## Key rotation

The canonical `security.tenant_api_keys` registry and its existing rotation/grace-window model remain the source of truth. The authenticated key ID and the cryptographically signed key ID must agree. Plaintext API keys remain only in the trusted backend/operator environment.

## Existing cryptographic primitives

`src/security/cryptoSuite.ts` provides AES-256-GCM, AAD, P-384 ECDH + HKDF-SHA384, ECDSA P-384/SHA-384, signed envelopes, SHA-384/SHA-512, and HMAC-SHA384. These are kept separate from the v2 API HMAC boundary so later control-plane layers can adopt asymmetric trust without changing the current request contract.

## Guarantees

- key-ID substitution is rejected;
- content-type substitution is rejected;
- body, method and path/query mutation are rejected;
- stale/future timestamps are rejected;
- nonce replay is rejected atomically;
- v1 remains available only through the explicit compatibility verifier and is not accepted by the production verifier;
- secrets, signatures, raw bodies and nonce values are never logged by the signing layer.

## Scope boundary

No AI is added. No transaction firewall, fake database, graph engine or global kill switch is added here. Those are Parts 5B–5E. Part 5F will perform replay, mutation, concurrency, clock-skew and key-rotation validation.

Before Part 5A is merged, CI and CodeQL must pass and the dedicated `gainiren-shield-lab` database must pass the transactional replay test. The legacy `rewards-platform` database is not touched.
