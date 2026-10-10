# GainiRen HoneyDB — Isolated Deception Sensor

## Purpose

HoneyDB is a separate, low-trust web service that exposes synthetic-only decoy endpoints. Its purpose is to detect exploratory access to paths such as an admin console, environment file, repository metadata, configuration endpoint or database backup. It is not a proxy, replica or front door for the real Supabase database.

## Separation guarantees

- The HoneyDB container has no Supabase URL or server/service-role key and makes no database connections.
- Every returned user, host, config value, and SQL row is synthetic. User emails use the reserved `.invalid` domain and canary text is explicitly not a credential.
- Submitted request bodies, usernames and passwords are never read or persisted by the sensor.
- Source peer and user-agent values are HMAC-hashed with a dedicated `HONEY_HASH_KEY`; raw values, query strings and request bodies are excluded from logs and forwarded alerts.
- Only summarized events from known decoy surfaces are forwarded to the security API. Forwarding uses a separate `HONEY_SENSOR_TOKEN`, HTTPS, a fixed endpoint, no automatic redirects, and a bounded queue.
- When forwarding is not configured or the API is temporarily unavailable, local structured logs still record the probe. Queue overflow is logged rather than allocating unbounded memory.

## Required runtime configuration

### HoneyDB service

- `HONEY_HASH_KEY`: random secret, at least 32 characters; use a unique value.
- `SECURITY_ALERT_URL`: exact HTTPS URL ending in `/api/internal/honey-alert`.
- `HONEY_SENSOR_TOKEN`: separate random secret of at least 32 characters, shared only with the security API.

### Security API service

- `HONEY_SENSOR_TOKEN`: the same sensor token.
- `HONEY_TENANT_ID`: `77777777-7777-4777-8777-777777777777`, the dedicated internal HoneyDB tenant seeded by the migration. This tenant has no tenant API key and is not for normal website traffic.

Never put any of these values into client/browser code, a VITE-prefixed variable, the database, or GitHub source.

## Deploying the sensor

Deploy `deception/honeydb/Dockerfile` as a separate web service from this repository. The service needs its own host/domain and must not be linked from the real GainiRen site. Set the three HoneyDB variables above after the security API has a stable HTTPS URL. Health check path: `/health`.

The sensor's public decoy endpoints intentionally return fake data, but it must never be trusted by the real application. The production API and database remain separate and are never redirected to HoneyDB. Treat hit rates as security telemetry, not proof that a specific person committed abuse.

## Validation

The HoneyDB CI workflow verifies health metadata, synthetic-only output, generic responses to unknown paths, request-size limits, response security headers, and deterministic HMAC hashing. Production rollout still requires live end-to-end alert-forwarding tests and review of provider networking and rate limits.
