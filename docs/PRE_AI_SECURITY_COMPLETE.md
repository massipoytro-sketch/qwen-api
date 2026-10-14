# GainiRen Security — Pre-AI completion

The security service is intentionally deterministic before AI is enabled.

## Request trust order

1. HTTPS/TLS transport validation at the Node boundary in production.
2. Strict HTTP/browser security headers and bounded request size.
3. Canonical tenant API-key authentication through `security.tenant_api_keys`.
4. Versioned HMAC request signature + timestamp + nonce replay protection.
5. Tenant/subject rate limits.
6. Tenant emergency control (`normal`, `challenge_all`, `deny_all`, `maintenance`).
7. Runtime kill switch (`normal`, `review_only`, `lockdown`).
8. Strict idempotency binding to the exact method/path/body digest.
9. Deterministic account/session/device/network/bot/behavior/fraud/graph/value analysis.
10. Defense-in-depth firewall escalation and operator-controlled network controls.
11. Append-only hash-chain audit ledger and durable outbox.
12. Persistent circuit breaker around optional analytics dependencies.
13. One-time challenge-token lifecycle for step-up MFA, proof-of-work and risk verification.
14. Isolated HoneyDB deception telemetry.

The final decision is never lowered by a later layer. Operator controls can only maintain or escalate the decision.

## Credential lifecycle

`security.tenant_api_keys` is the canonical credential table. Existing active tenant hashes were seeded into this table without creating plaintext credentials. Rotated keys can be provisioned and retired through service-role-only database functions. The older `api_credentials` table is transitional and is not used by the production security-check route.

## Challenge lifecycle

Challenge tokens are random, stored only as SHA-256 hashes, tenant/subject/session bound, short-lived and atomically consumed. Replays and expired tokens are rejected. Challenge type is constrained to `step_up_mfa`, `proof_of_work` or `risk_based_verification`.

## Audit and resilience

The security audit ledger uses per-tenant sequence numbers and SHA-256 previous-hash chaining. Mutation paths are blocked by database permissions/triggers. Optional analytics runs behind a persistent circuit breaker so an unhealthy analytics dependency cannot become an authentication dependency.

## AI boundary

AI is disabled by default. The deterministic engine remains authoritative. The optional OpenRouter SDK integration is now implemented with AI disabled by default. It sends only bounded categorical/numeric evidence and is stored as advisory output; it cannot affect risk aggregation, bypass authentication, or write authoritative security decisions. Enable it only after setting the OpenRouter key in Render Secrets and completing synthetic prompt-injection, malformed-output, timeout, and provider-failure tests.

## Database boundary

All database work belongs to the dedicated `gainiren-shield-lab` project. The older `rewards-platform` database is outside this system and must not be modified.
