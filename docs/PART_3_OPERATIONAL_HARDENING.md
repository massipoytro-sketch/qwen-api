# GainiRen Security — Part 3: operational hardening and verification

## Scope

Part 3 finishes the pre-AI core by hardening the existing tenant API-key registry, requiring consistent registry-based authentication on security-check and security-event endpoints, and documenting safe operator integration. It does not enable or configure any AI model.

## Request integrity and replay resistance

Security-check and security-event endpoints require a versioned HMAC-SHA256 signature over the method, path/query, timestamp, unique nonce, and SHA-256 digest of the exact raw body. Timestamp skew is limited to five minutes. Signatures are compared in constant time, and nonce consumption is atomic in Postgres. Every retry must use a new nonce, timestamp, and signature.

The signing key is a server-side tenant API key. Never ship it to browser JavaScript, a public mobile application, or a public repository. See `docs/SERVER_TO_SERVER_SIGNING_AND_ROTATION.md` for the canonical payload and Node.js backend example.

## Canonical API-key rotation

The project already has a dedicated `security.tenant_api_keys` registry and `security.consume_rotated_api_key` authentication RPC. Part 3 preserves that single source of truth; it does not keep a second key registry on `security.tenants`.

The hardened `security.rotate_tenant_api_key(uuid,text,text,integer)` RPC:
- accepts only a lowercase 64-character SHA-256 hash and a bounded label;
- requires an active tenant and rejects an already-active/grace key hash;
- permits a grace period from 0 through 86,400 seconds (24 hours);
- transitions the old active key to `grace` during the overlap, or immediately to `revoked` when grace is zero;
- inserts the new key as `active`;
- records a compact rotation entry in the append-only audit ledger;
- is executable only by `service_role`.

The plaintext API key is generated and retained by the trusted operator/backend only. The database stores hashes, never the plaintext key. The security-check and security-event endpoints both authenticate against the same registry, including optional strict `X-GainiRen-Key-Id` matching.

## Transport and runtime boundaries

The deployed service is intended to be accessed through Render's HTTPS endpoint. The Node HTTP adapter runs behind the platform's TLS termination and emits HSTS, restrictive CSP, `nosniff`, frame denial, `no-referrer`, and `no-store` headers. The outbox scheduler calls the worker through loopback only. External clients should use HTTPS and reject redirects.

Body size, header size/count, request and header timeouts, method allowlisting, generic errors, and bounded structured logs are enforced by the adapter. The optional AI analyzer remains explicitly disabled by default.

## Database scope

The API-key rotation work was applied only to the dedicated `gainiren-shield-lab` project. Migration `20261015113000_harden_registry_key_rotation.sql` removes the duplicate draft columns from `security.tenants` and hardens the canonical `security.tenant_api_keys` rotation RPC. The earlier `20261015110000_tenant_api_key_rotation.sql` is superseded by this corrective migration. The older `rewards-platform` database was not touched.

## Validation performed

- PostgreSQL transaction-scoped test passed against the canonical registry for a normal rotation, previous-key grace metadata, immediate revocation with zero grace, audit writes, and rejection of anonymous execute privilege. Test tenant, keys, and ledger writes were rolled back.
- Existing HMAC tests cover exact-body integrity, method and path/query binding, signature changes for fresh timestamp/nonce, wrong-key rejection, missing headers, stale/future timestamps, malformed nonce, and malformed signature.
- Security CI, runtime smoke, HoneyDB CI, and CodeQL must pass on the final Part 3 commit before merging.
- A live end-to-end signed request against a dedicated non-production tenant and confirmation of the deployed Render commit remain required before routing production traffic.

## Completion boundary

Part 3 completes the code/database hardening stage; it is not a claim of global certification or immunity to attacks. AI integration is a separate next phase and remains disabled until then.
