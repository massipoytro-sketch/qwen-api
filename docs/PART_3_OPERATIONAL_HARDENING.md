# GainiRen Security — Part 3: operational hardening and verification

## Scope

Part 3 completes the pre-AI core by adding controlled tenant API-key rotation, bounded previous-key overlap, additional tests, and operator/client integration guidance. It does not enable or configure any AI model.

## Request integrity and replay resistance

Security-check and security-event endpoints require a versioned HMAC-SHA256 signature over the method, path/query, timestamp, unique nonce, and SHA-256 digest of the exact raw body. Timestamp skew is limited to five minutes. Signatures are compared in constant time, and nonce consumption is atomic in Postgres. Every retry must use a new nonce, timestamp, and signature.

The signing key is a server-side tenant API key. Never ship it to browser JavaScript, a public mobile application, or a public repository. See `docs/SERVER_TO_SERVER_SIGNING_AND_ROTATION.md` for the canonical payload and Node.js backend example.

## Controlled API-key rotation

The migration adds:
- `api_key_previous_hash`
- `api_key_previous_valid_until`
- `api_key_rotated_at`

`security.rotate_tenant_api_key` accepts only a 64-character lowercase SHA-256 hash, locks the tenant row, requires an active tenant and a different key, caps overlap at 24 hours, and records the rotation in the append-only audit ledger. Its execute privilege is restricted to `service_role`. A zero-second grace window immediately revokes the previous key. Plaintext keys are never stored or returned by the database.

The two signed API endpoints accept the current hash or the previous hash only until the explicit grace expiry. Expired previous hashes are not accepted even if the row still contains their metadata.

## Transport and runtime boundaries

The deployed service is intended to be accessed through Render's HTTPS endpoint. The Node HTTP adapter runs behind the platform's TLS termination and emits HSTS, restrictive CSP, `nosniff`, frame denial, `no-referrer`, and `no-store` headers. The outbox scheduler calls the worker through loopback only. External clients should use HTTPS and reject redirects.

Body size, header size/count, request and header timeouts, method allowlisting, generic errors, and bounded structured logs are enforced by the adapter. The optional AI analyzer remains explicitly disabled by default.

## Database scope

Migration `20261015110000_tenant_api_key_rotation.sql` was applied only to the dedicated `gainiren-shield-lab` project. The older `rewards-platform` database was not touched.

## Validation performed

- PostgreSQL transaction-scoped test passed for normal key rotation, old-key grace metadata, second rotation with immediate revocation, audit writes, and rejection of anonymous execute privilege. Test tenant and ledger writes were rolled back.
- Existing HMAC test suite covers exact-body integrity, method and path/query binding, changing signatures for fresh timestamp/nonce, wrong key rejection, missing headers, stale/future timestamps, malformed nonce, and malformed signature.
- Added unit tests validate key-hash-only query construction, bounded previous-key expiry, and malformed input rejection.
- Part 3 CI must pass on the final commit: typecheck, lint, unit tests, production dependency audit, runtime smoke, HoneyDB tests, and CodeQL.

## Completion boundary

Part 3 completes the code/database hardening stage, not a claim that the system is globally certified or immune to attacks. Before connecting production GainiRen traffic, run the final CI gates, confirm the deployed Render commit, test signed requests against a dedicated non-production tenant, validate rotation and replay rejection end-to-end, and verify TLS at the public endpoint. AI integration is the next separate phase and must remain advisory-only.
