# GainiRen Security — Part 3: Key Lifecycle, Resilience and Validation Readiness

## Scope

Part 3 adds managed API-key lifecycle, a second signature protocol that binds a stable key ID, explicit legacy-key retirement, an audit-ledger integrity verifier, production endpoint guardrails, a database-backed readiness endpoint, and authenticated load/red-team tools.

AI remains disabled unless `AI_ANALYZER_ENABLED=true` and the three provider settings are all configured. Do not configure AI during this phase.

## Managed tenant API keys

The dedicated `security.tenant_api_keys` table stores a UUID key ID and SHA-256 hash—not the raw API key. Only the server role may read key metadata; creation/rotation, revocation, and legacy retirement use service-role-only PostgreSQL functions.

### v2 signatures

Managed API keys must be sent with `X-GainiRen-Key-Id` and a `v2=` HMAC-SHA-256 signature. The canonical message includes the key ID, method, path/query, timestamp, fresh nonce, and exact request-body digest. The ID is checked against the requested tenant and cryptographically signed. An invalid ID never falls back to legacy authentication.

Legacy v1 remains supported only for tenants whose old `api_key_hash` is still set. This is an intentional migration window, not the recommended long-term mode.

### Rotation sequence

1. Run `scripts/rotate-tenant-api-key.mjs` with explicit confirmation against the dedicated security database. It generates a fresh high-entropy key, stores only its hash, rotates the previous active managed key into a bounded grace interval (or revokes it immediately when grace is zero), and prints the raw key only once.
2. Store the new key and key ID in a server-side secret manager; deploy clients that sign protocol v2.
3. Validate the new v2 integration in staging. Do not paste the key into chat, logs, GitHub, or browser code.
4. Revoke any managed key immediately with `scripts/revoke-tenant-api-key.mjs` if needed.
5. After v2 has been verified, retire v1 compatibility using the confirmed `scripts/retire-legacy-tenant-api-key.mjs` operation. The database refuses retirement unless a currently valid active managed key exists for the tenant.

No raw key can be recovered from the hash. If the one-time output is lost, rotate again.

## Tamper-evident audit ledger verification

The database provides `security.verify_security_audit_ledger`, a service-role-only verifier that walks a bounded ledger from sequence 1, checks continuity, validates every previous-hash link, rebuilds the stored JSONB payload, and recomputes each SHA-256 entry digest. A gap, link mismatch, digest mismatch, or row-limit overflow returns failure.

Run `scripts/verify-security-audit-ledger.mjs <TENANT_UUID> [max-rows]` from a trusted operator environment. The hash chain detects unauthorized or accidental changes but is not a substitute for separately controlled off-site immutable checkpoints against a database owner/superuser.

## Runtime readiness and transport posture

- `GET /api/health` is a liveness endpoint and does not depend on Supabase.
- `GET /api/ready` performs a minimal query against the dedicated `security.tenants` table. It returns only `ready` or `not_ready`, never database errors, keys, tenant metadata, or project identifiers.
- Default HTTP responses add HSTS, no-sniff, clickjacking protection, a restrictive API CSP, Permissions Policy, and Cross-Origin-Resource-Policy.
- Production Supabase and configured external dependency endpoints must use HTTPS. A configured CORS origin must be a bare origin, not a path or URL with credentials/query/fragment.
- TLS is provided at the hosting edge; the HTTP server's HSTS header assumes public requests use HTTPS.
- AI is explicitly disabled by default and only runs after an operator intentionally enables it.

## Safe red-team and load harnesses

`tests/red-team/security_probe.py` creates a fresh nonce and signature for each authenticated request. Set `KEY_ID` for v2-managed-key tests; leave it unset only for a remaining v1 legacy tenant. The target URL must exactly match `ALLOWED_TARGET_ORIGIN`, be HTTPS (HTTP is limited to localhost), and requires `SECURITY_TEST_ACK=I_OWN_THIS_SERVICE`. Its burst is fixed at 20 requests with at most 10 concurrent workers.

`tests/load/security-check.k6.js` signs each request with a cryptographically random nonce. It requires `LOAD_TEST_ACK=I_OWN_THIS_SERVICE` and an exact origin allow-list. The stress profile is bounded at 10 virtual users and should only be used on staging or a system the operator owns.

Both tools avoid redirects so bearer tokens are not forwarded. Use fresh test tenants and synthetic data. Do not run load tests on GainiRen live traffic until staging checks have passed and the load window is approved.

## Database boundary

Migration `20261014140000_tenant_api_key_rotation.sql` must be applied only to the dedicated `gainiren-shield-lab` Supabase project. Never apply it to `rewards-platform`. It adds managed key status and lifecycle functions plus the ledger verifier; it does not expose these tables or functions to `anon` or `authenticated`.

## Completion gate

Part 3 implementation is considered complete when the branch includes key lifecycle support, v2 request signing, bounded test harness updates, production configuration guardrails, integrity verification, and operator documentation. After implementation, run the full validation gate: typecheck, lint, unit tests, Python HoneyDB tests, cross-language signature conformance, migration/privilege checks, runtime smoke, CodeQL, staging API tests, failure/recovery tests, then bounded load tests. The result is not a security certification; production launch requires the live staging checks to pass.
