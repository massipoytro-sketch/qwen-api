# GainiRen Security — Part 5: Cryptographic Trust Layer

Part 5 adds a dedicated cryptographic foundation. It is deliberately independent from the AI layer: the security decision engine does not depend on an AI provider.

## Security branches

### 1. Transport branch — TLS 1.3 first

Production traffic must arrive through HTTPS. The application rejects insecure production requests and Render terminates TLS at the edge. The deployment target should use TLS 1.3 as the preferred protocol and disable legacy TLS versions at the edge. HSTS remains enabled at the HTTP response layer.

This code cannot change Render's edge cipher policy from inside the Node process, so the deployment-level TLS policy must be verified separately. Do not claim a TLS 1.3 guarantee merely from application code.

### 2. Data-at-rest branch — AES-256-GCM

`src/security/cryptoSuite.ts` provides AES-256-GCM authenticated encryption for files, blobs and sensitive application payloads.

Properties:
- 256-bit key required exactly.
- Fresh 96-bit random IV for every encryption operation.
- 128-bit GCM authentication tag.
- Optional AAD binds ciphertext to a tenant/resource context without encrypting that context.
- Versioned envelope with `keyId` to support controlled rotation.
- Authentication failure aborts decryption.

Plaintext keys must never be committed to Git, returned to browsers, or logged. Production keys belong in a server-side secret manager and should be rotated by replacing the active `keyId` while retaining only the minimum decrypt-only historical keys needed for migration.

### 3. Key-exchange branch — ECDH P-384

`generateP384KeyPair()` creates a P-384 ECDH pair. `deriveP384SharedKey()` performs the shared-secret operation and derives a 256-bit symmetric key through HKDF-SHA-384.

The private key remains server-side. Only the public key may cross a trust boundary. Derived keys are for the current cryptographic context and must not be persisted as plaintext.

### 4. Digital-signature branch — ECDSA P-384 / SHA-384

`generateEcdsa384KeyPair()`, `signEcdsa384()` and `verifyEcdsa384()` implement ECDSA using P-384 with SHA-384.

The signed-envelope layer additionally includes:
- protocol version,
- algorithm identifier,
- millisecond timestamp,
- 24-byte random nonce,
- SHA-384 payload fingerprint,
- signature over the canonical envelope.

A receiver must verify the signature, timestamp window, payload digest, and consume the nonce exactly once. The existing HMAC request-signing/replay controls remain in place; this ECDSA layer is an additional asymmetric trust option rather than an unsafe replacement.

### 5. Integrity branch — SHA-384 / SHA-512

The suite exposes SHA-384 and SHA-512 fingerprints for files, payloads, checkpoints and integrity manifests. Hashes are fingerprints, not encryption and not password storage.

Use SHA-384 for the P-384 signature protocol and SHA-512 where a longer standalone integrity fingerprint is useful.

### 6. Key-lifecycle branch

The cryptographic envelope carries a `keyId`. This is the foundation for rotation:

`ACTIVE → DECRYPT_ONLY → RETIRED`

A rotation should generate a new key outside application code, mark it active, write new objects with the new key ID, and migrate old objects in a bounded job. Old keys must not be deleted until every dependent object has been re-encrypted and a recovery window has passed.

Never rotate by overwriting a secret with an unrelated value while existing ciphertext still depends on it.

### 7. Anti-replay / message-freshness branch

The signed envelope generates a new random nonce for every signature and includes a timestamp. The nonce is intentionally not sufficient by itself: production consumers must persist a tenant-scoped nonce digest with a uniqueness constraint and reject duplicates. Existing request HMAC verification already uses timestamp + nonce consumption for the main HTTP API.

The goal is that a captured valid message cannot simply be submitted again.

### 8. Trust-boundary branch

Cryptographic verification must happen before privileged side effects. Recommended order:

1. TLS/transport validation.
2. Tenant identity and API-key verification.
3. Signature verification.
4. Timestamp and replay checks.
5. Payload size/schema validation.
6. Deterministic firewall/risk evaluation.
7. Database writes and security ledger append.
8. Optional AI advisory only after all deterministic controls.

No AI model can override a failed cryptographic verification.

## What is intentionally not implemented

- No RSA private-key generation or storage is required because ECDSA P-384 satisfies the requested asymmetric signature level.
- No plaintext master key is embedded in the source tree.
- No browser-facing private key endpoint exists.
- No AI key is needed for this part.
- No claim is made that Render's edge is configured to TLS 1.3 until that deployment setting is explicitly verified.

## Required production key handling

Use server-side secrets only. Suggested secret classes:

- `SECURITY_DATA_KEY_V1`: 32 random bytes, encoded base64url, for AES-256-GCM data encryption.
- `SECURITY_ECDSA_PRIVATE_KEY_V1`: protected PKCS#8 PEM for the signing identity.
- ECDH private keys: ephemeral or short-lived server-side material where possible.

Do not paste any of these secrets into chat, GitHub issues, source files, client bundles, or logs.

## Validation matrix

The Part 5 test suite covers:

- AES-256-GCM round trip.
- Wrong-key rejection.
- Ciphertext/authentication failure.
- AAD mismatch rejection.
- P-384 ECDH shared-secret agreement.
- ECDSA P-384 signing and verification.
- Signature failure after payload modification.
- Fresh nonce per signed message.
- Signed-envelope timestamp expiry.
- SHA-384 and SHA-512 output lengths and change detection.

Part 5 is complete only when typecheck, lint, unit tests, Runtime Smoke, Security CI, HoneyDB CI and CodeQL all pass on the same commit.

## Separation from GainiRen production data

All work remains in the dedicated `gainiren-shield-lab` security project and `massipoytro-sketch/qwen-api`. The older `rewards-platform` database is not a target for these cryptographic migrations.
