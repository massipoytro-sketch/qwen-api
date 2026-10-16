# Part 4 — Enforcement Firewall + Signed Challenge Boundary

## Goal

Part 4 turns the deterministic assessment into an explicit, stable enforcement contract and hardens the transport boundary around the security-check and challenge APIs. It does not introduce an AI provider, a client-held signing secret, or a stateless bypass around the existing persistent challenge store.

## Enforcement contract

`src/security/enforcement.ts` centralizes restrictive decision ordering:

`ALLOW < MONITOR < CHALLENGE < REVIEW < BLOCK`

The contract includes:
- an immutable version identifier (`enforcement-v1`);
- the request ID and final strictest decision;
- action mapping: `allow`, `allow_with_monitoring`, `challenge`, `hold_for_review`, or `deny`;
- normalized, bounded reason codes;
- a challenge recommendation only when the final decision remains `CHALLENGE`;
- a reference to `/api/challenge` for obtaining a durable challenge; and
- a retryability indicator that is false for `BLOCK`.

The live `POST /api/security-check` route uses `api/security-check-v2.ts`. Its response retains the established top-level fields and adds an `enforcement` object for clients to consume. Emergency `deny_all` / maintenance controls and runtime lockdown also return a fail-closed enforcement contract. Decision reconciliation is checked for downgrade: if the database returns a weaker decision or lower score than the caller attempted to persist, the request fails closed and logs a safe reason code rather than returning the downgrade.

## Persistent challenge flow

A `CHALLENGE` recommendation is not itself proof of completion and contains no reusable bearer credential. The trusted GainiRen backend calls `POST /api/challenge` using tenant authentication and a signed request to issue a bounded, tenant-scoped challenge token. PostgreSQL stores only its token hash. Consumption is single-use; proof-of-work verification is validated in the database transaction; MFA / OTP challenges use the `complete_verified` mode only after the tenant's trusted server has independently verified the user.

The enforcement contract deliberately marks challenge completion authority as `tenant_server`. A browser or mobile app must not hold a tenant API key or report its own MFA success.

## HTTPS and response headers

The production transport guard rejects non-HTTPS requests at the HTTP adapter and again in the security-check, event-ingestion, challenge, worker, HoneyDB-alert and internal timeline handlers. Behind Render's TLS-terminating edge, the guard uses the edge-forwarded scheme. Local HTTP is permitted only outside production. The Node server routes `/api/security-check` to `api/security-check-v2.ts` and exposes `/api/challenge`.

Security responses use the shared header policy:
- HSTS;
- restrictive Content-Security-Policy;
- `X-Content-Type-Options: nosniff`;
- `X-Frame-Options: DENY`;
- `Referrer-Policy: no-referrer`;
- same-origin opener and resource policies; and
- a restrictive Permissions-Policy.

Render terminates public TLS; the Node adapter enforces that traffic arrived through HTTPS. The application does not claim to configure the host's cipher suite or minimum TLS version itself.

## Validation

- `tests/enforcement.test.ts`: strictest-decision ordering, BLOCK preservation, bounded challenge contract, no challenge on REVIEW, invalid IDs and expiry bounds, monotonic score floors.
- `tests/transport.test.ts`: secure forwarded scheme, insecure/missing forwarded scheme, non-production local HTTP, and standard browser isolation headers.
- CI also runs TypeScript, lint, the full Vitest suite, production dependency audit, runtime smoke, HoneyDB CI and CodeQL. The Part 4 pull request must not merge until all checks on its final commit pass.
- Existing challenge/database migrations from Part 3 remain the source of truth; this phase does not need a new database migration.

No AI provider is enabled by Part 4. The OpenRouter/Nemotron phase remains deferred until the core defense stack and full security test plan are complete.
