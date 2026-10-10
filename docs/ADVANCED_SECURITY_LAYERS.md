# GainiRen Security — advanced layers and launch notes

This document describes the advanced backend modules now checked into `main`. It is not a claim that the complete stack is already deployed or independently certified.

## Request and event flow

```text
GainiRen backend / partner server
  ├─ POST /api/security-event
  │    └─ tenant API-key check → rate limit → validated ingestion → private security tables
  └─ POST /api/security-check
       └─ tenant API-key check → rate limit → evidence collection
           ├─ device / network / bot / activity / value anomaly evidence
           ├─ graph connections and behavioral baseline (best effort)
           ├─ deterministic risk aggregation
           ├─ tenant-scoped policies; decisions may only become more restrictive
           ├─ risk assessment, risk signals, decision and audit evidence
           └─ durable event outbox
                ├─ fraud case / cluster events
                └─ optional analytics.duckdb_batch
                      └─ isolated DuckDB worker → validated, pseudonymized findings
```

PostgreSQL/Supabase remains the source of truth. The DuckDB worker is an optional, separately deployed analytics layer and is never the authority for authentication or the only critical risk signal. AI results are advisory; they do not override the deterministic engine. VPN/proxy/Tor and graph links are evidence rather than proof of malicious activity.

## Feature modules

- **DuckDB Analytics**: bounded event batches (maximum 500 records), hashed subject/session references, no raw IP address, memory limit, fixed analytical SQL only, bearer-token protected endpoint, batch result validation, deduplication and run summaries.
- **Fraud Clusters**: tenant-scoped cluster records based on stable hashed membership keys; cluster state and evidence are stored for follow-up. A cluster is not automatically proof that every member is fraudulent.
- **Behavioral Baselines**: per-tenant/per-subject baselines for anomaly scores; requires at least 20 observations; calculates mean, standard deviation, median and p95; refresh attempts are best-effort.
- **Advanced Bot Engine**: combines current bot classifier events with bounded activity-velocity evidence and allow-listed client flags. It is a heuristic evidence score, not a guarantee of identifying all bots.
- **Policy Engine**: tenant-specific ordered rules with an allow-list of fields/operators, at most 20 conditions in each group, and at most 100 fetched policies. The first matching rule applies; action overrides may only increase restrictiveness. Policy authors still need review.
- **Investigation Center**: high-risk assessments can open/update a fraud case; notes and a timeline API are available to internal server-side code.
- **ML/AI Lab**: model version and prediction records remain available; analyst feedback is stored separately. AI is advisory. Training, model approval/promotion and drift governance still need a governed operational process.
- **Distributed Event Processing**: Postgres outbox, unique dedupe keys, lease tokens, `FOR UPDATE SKIP LOCKED` claims, bounded batches, exponential retry and maximum-attempt fail state.
- **Load/Stress Testing**: opt-in k6 script for the single security-check endpoint. It checks authorization, latency, server errors and the expected tenant rate limiter. Smoke profile is default; stress profile tops out at 10 virtual users.

## Required server environment

Set server-side environment variables only. Never place the Supabase server/service-role key or the tenant API key in browser code or public `VITE_*` variables.

- `SUPABASE_URL`: URL of the dedicated security project.
- `SUPABASE_SERVER_KEY`: service-role/server key for the dedicated security project only.
- `OUTBOX_WORKER_TOKEN`: random secret of at least 32 characters; used only by the internal worker caller and API service.
- `DUCKDB_ANALYTICS_URL`: HTTPS URL to the deployed DuckDB worker `/analyze` endpoint.
- `DUCKDB_ANALYTICS_TOKEN`: random secret of at least 32 characters, identical in the API service and DuckDB worker.
- `SECURITY_API_CORS_ORIGIN`: exact trusted origin if a browser must call the API. Prefer server-to-server calls; do not set wildcard CORS for the security API.
- `AI_ANALYZER_ENDPOINT`, `AI_ANALYZER_API_KEY`, and `AI_ANALYZER_MODEL`: optional; either set all three or none.

The outbox is processed only when the internal worker is invoked. Schedule `POST /api/outbox-worker` from a trusted scheduler with `Authorization: Bearer <OUTBOX_WORKER_TOKEN>`; never make the token available to a browser. The DuckDB worker has a separate URL and token and does not connect directly to Supabase.

## Create a tenant API key

From a trusted local environment with Node 22+ and this project’s dependencies installed, run:

```sh
SUPABASE_URL='https://<security-project>.supabase.co' \
SUPABASE_SERVER_KEY='<server-only-key>' \
node scripts/provision-tenant.mjs "GainiRen"
```

The script stores only a SHA-256 hash in `security.tenants.api_key_hash`, then prints a new API key once. Save it in a secret manager. The script creates an active tenant, so only run it when you intend to provision that tenant. Never execute it against the older rewards-platform project.

## Deploy order

1. Deploy the TypeScript API from `main` with the dedicated security Supabase environment. On Railway, the repository now includes `server.ts` as a bounded Node HTTP adapter; set the start command to `pnpm start` and the healthcheck path to `/api/health`.
2. Run `/api/health` and confirm it reports `gainiren-security`.
3. Provision a tenant with the script above; save the tenant ID and API key securely.
4. Deploy `analytics/duckdb-worker/Dockerfile` as an isolated private web service with `DUCKDB_ANALYTICS_TOKEN`. Confirm `/health` first, then set `DUCKDB_ANALYTICS_URL` to its HTTPS `/analyze` URL and the same token in the API.
5. Configure a trusted scheduler for `/api/outbox-worker` using `OUTBOX_WORKER_TOKEN` and a small recurring batch. Monitor outbox backlog, retries, 5xx responses and analytics-run failures.
6. Integrate GainiRen server-side using `POST /api/security-event` to send authenticated event evidence and `POST /api/security-check` to request a decision.
7. Run smoke tests against staging first. Start with a single virtual user; increase to the bounded stress profile only on an environment you own and can afford to load.

## k6 load-test run

Install k6, set a staging URL and authorized tenant, then run:

```sh
LOAD_TEST_ACK=I_OWN_THIS_SERVICE \
LOAD_PROFILE=smoke \
BASE_URL='https://your-staging-api.example' \
TENANT_ID='<tenant-uuid>' API_KEY='<tenant-api-key>' \
k6 run tests/load/security-check.k6.js
```

For the short bounded stress profile, set `LOAD_PROFILE=stress` only against staging or another environment you operate. The route has a per-tenant rate limit, so HTTP 429 responses are expected at higher rates and are not treated as server failures. Do not run load tests against a third-party or production system without explicit authorization.

## Launch blockers to verify

- GitHub Actions typecheck/lint/test and the DuckDB worker tests must pass on the final commit.
- The API and DuckDB worker must be deployed and reachable before end-to-end analytics can run.
- A real tenant must be provisioned, and its API key stored securely.
- A scheduler must actually invoke the outbox endpoint; adding the endpoint alone does not schedule it.
- Integration tests must verify unauthenticated requests, wrong tenant, idempotency/replay, value jumps, rate-limit concurrency, stale baselines, worker timeout/retry, and service isolation.
- Independent security review, monitoring, backups/restore test, alerting and load tests are still required before calling the system production-hardened.
