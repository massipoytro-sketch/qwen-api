# GainiRen Security — Final Readiness Checklist

## What is already implemented

- 23 private security tables under `security`.
- RLS enabled on all 23 tables.
- `anon` and `authenticated` have no schema usage for the private security schema.
- Device, identity, network, bot, behavior, session, rate-limit and abuse pipelines.\n- Server-authoritative value state with idempotency and atomic anomaly persistence.\n- Concurrency-safe database-backed rate limiting.\n- Freshness windows for bot, behavior and value anomaly evidence.\n- Request parsing hardening, 64 KiB body cap, safe error output, security headers, and opt-in CORS.
- Deterministic weighted risk engine.
- Graph correlation and graph-derived risk evidence.
- AI advisory analysis with model versioning and prediction storage.
- Structured security logging and request IDs.
- Authenticated production API baseline.
- Health endpoint.
- CI workflow definition.

## What you must do before real deployment

### 1. Supabase secrets
Create these production environment variables in the API host:

- `SUPABASE_URL`
- `SUPABASE_SERVER_KEY`
- `SECURITY_API_CORS_ORIGIN` (optional; leave unset unless a specific browser origin needs access)

Never put `SUPABASE_SERVER_KEY` in browser/client code.

### 2. AI configuration
Only if AI analysis is wanted:

- `AI_ANALYZER_ENDPOINT`
- `AI_ANALYZER_API_KEY`
- `AI_ANALYZER_MODEL`

Set all three together or leave all three empty.

### 3. Tenant API key
Generate a long random API key outside the repository.

Store only its SHA-256 hash in:

`security.tenants.api_key_hash`

The raw key must be given to the tenant once and must never be committed to GitHub or stored in the database.

### 4. Deploy the API
Deploy the repository as a Node/Vercel-compatible project with the root directory set to the repository root.

Expected endpoints:

- `GET /api/health`
- `POST /api/security-check`

### 5. Live smoke test
First test:

`GET /api/health`

Expected JSON:

`{"service":"gainiren-security","status":"ok","version":"0.1"}`

Then test `POST /api/security-check` with a valid tenant key and tenant UUID.

### 6. Negative security tests
Verify:

- missing Authorization -> 401
- wrong API key -> 401
- inactive tenant -> 401
- malformed UUID -> 400
- oversized request -> 413
- rate limit exceeded -> 429
- valid request -> 200
- no server key appears in responses or logs

### 7. AI failure test
Temporarily make the AI provider unavailable.

The security API must still return a deterministic decision. AI is advisory only.

### 8. Database verification
Confirm:

- all 23 security tables remain RLS-enabled;
- no `anon`/public access is granted to internal security tables;
- tenant API keys are stored as hashes only;
- audit events are being created for security checks.

## Current known limitation

The repository contains a hardened API baseline, but the production deployment, tenant provisioning, end-to-end database transaction tests with test fixtures, live API smoke tests, centralized telemetry, and external security testing still remain pending.

This is not a security certification. Production readiness requires testing in the actual deployment environment.
