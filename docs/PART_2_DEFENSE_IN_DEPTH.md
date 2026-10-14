# GainiRen Security — Part 2: Defense in Depth

## Scope

Part 2 adds an application-level decision firewall around the existing deterministic risk engine, a persistent circuit breaker for the optional DuckDB worker, a tenant-scoped append-only hash-chain audit ledger, an internal investigation timeline endpoint, and additional synthetic HoneyDB decoys.

It does not add or enable an AI provider. AI remains out of scope until the later AI phase.

## Multi-layer firewall

`src/security/firewall.ts` evaluates eight independent layers:

- Network reputation and trusted impossible-travel signals.
- Bot and automation confidence.
- Identity status, account-takeover signals, and session concurrency.
- Fraud graph and value-jump correlation.
- Behavioral deviation and velocity.
- Application-integrity violations.
- Database/tenant-boundary violations.
- Deception/canary tripwires.

Each layer emits a bounded action, confidence, and reason codes. The final decision is the strictest result from the base deterministic score, the tenant policy engine, and the firewall layers; the firewall cannot relax a decision. VPN, proxy, and Tor indicators alone are monitoring evidence, not proof of fraud.

When the final decision is `CHALLENGE`, the response includes `challengeRecommendation` with one of `step_up_mfa`, `proof_of_work`, or `risk_based_verification`, a reason-code list, and a five-minute expiry. This is a recommendation contract, not a challenge that has already been completed. GainiRen's trusted server/client flow must enforce the selected challenge and submit a new signed request.

## Tamper-evident audit ledger

The migration creates `security.audit_ledger` with per-tenant sequence numbers, previous hash and SHA-256 entry hash. The `append_security_ledger_entry` database function takes a tenant-scoped advisory transaction lock so concurrent writes cannot fork the chain. It limits metadata size, writes a canonical JSONB payload hash, and exposes execute permission only to `service_role`.

Direct table writes are revoked for client roles and the normal service role. Update, delete and truncate triggers reject ledger mutation. Each successful security assessment appends a compact decision record including subject/session references, risk score, firewall decision, reason codes, and signal names—not raw request bodies or credentials.

The ledger is tamper-evident, not an external WORM archive: a database owner with superuser-level control could alter schema/triggers. For higher assurance, periodically export chain checkpoints to a separately controlled append-only storage system.

## Persistent circuit breaker

`security.circuit_breakers` and the RPCs `acquire_security_circuit_permit` and `record_security_circuit_outcome` implement a per-tenant, database-backed `closed → open → half_open` circuit state. The DuckDB worker uses a five-failure / 60-second window and opens for 60 seconds. Only one expired-open probe may run at once; a successful probe closes the circuit. Error persistence stores a bounded machine-readable code and never provider messages.

If the circuit is open, the outbox event is allowed to retry later instead of issuing more calls to the unhealthy dependency. The core API does not depend on DuckDB to authenticate requests or make the initial deterministic decision.

## Investigation timeline endpoint

`GET /api/internal/security-timeline?tenantId=<uuid>&subjectId=<uuid>&limit=50` merges safe summaries from security events, risk assessments, fraud cases, investigation notes, and the audit ledger.

- It returns `404` when `SECURITY_OPS_TOKEN` is not configured, keeping the route disabled by default.
- When enabled, it requires a bearer token of at least 32 characters and limits requests per tenant.
- It checks tenant status and scopes every data read by both tenant and subject.
- It never returns raw security-event payloads. Investigation notes have likely credential formats redacted and are length-bounded.

Set `SECURITY_OPS_TOKEN` only in the service's server-side secret store. Never put it in client-side code or commit it to GitHub.

## Deception / HoneyDB

HoneyDB remains a physically separate synthetic decoy without a connection to the production database. Part 2 adds fake AWS credential, actuator environment, user export, and GraphQL tripwire surfaces. Every response is clearly synthetic and uses reserved `.invalid` addresses or inert canary text; submitted login credentials are never read or stored. Requests are categorized and forwarded as HMAC-hashed peer/user-agent identifiers, without raw addresses, request bodies, or query strings.

## Validation performed in this branch

- Deterministic unit tests cover firewall escalation, confidence thresholds, challenge recommendations, and the principle that proxy/VPN/Tor alone do not block.
- PostgreSQL transactional validation on the dedicated `gainiren-shield-lab` project passed for circuit breaker opening/rejection and the audit ledger's monotonic sequence, hash-chain linking, hash recomputation, and access restrictions.
- HoneyDB unit tests cover the additional decoy routes and synthetic-only responses.
- Full CI, typecheck, lint, dependency audit, CodeQL, runtime smoke and deployment checks must pass on the final PR commit before Part 2 is called complete.

## Database / deployment order

The migration `20261014130000_defense_in_depth_ops.sql` was applied to the dedicated `gainiren-shield-lab` project. Never apply it to the older `rewards-platform` database. The Render API deploy should occur after the code is merged to `main`. Leave `SECURITY_OPS_TOKEN` unset until an authenticated internal operator actually needs the timeline endpoint.
