# DuckDB analytics architecture

DuckDB is useful for GainiRen Security as a secondary analytical engine, not as the authoritative transactional database.

## Why

PostgreSQL/Supabase remains the source of truth for tenants, subjects, sessions, security events, risk decisions and audit records. DuckDB is designed for analytical workloads and bulk operations rather than many small concurrent transactions. It can efficiently analyze normalized event batches and Parquet/JSON datasets.

## Planned flow

```text
Supabase/PostgreSQL
       |
       | bounded export / analytical batch
       v
DuckDB worker
       |
       +--> activity velocity
       +--> event burst detection
       +--> bot-behavior correlation
       +--> value-change anomaly detection
       +--> session/device/IP aggregates
       |
       v
activity_anomalies / risk evidence
       |
       v
Deterministic Risk Engine
```

## Important security rule

Do not put DuckDB on the critical per-request path until its deployment model, concurrency, memory limits, timeouts and failure behavior are tested. DuckDB should not become a new single point of failure for authentication or security decisions.

The first deterministic value-jump detector is already in the security ingestion path. For example, a subject changing a tracked value from 0 to 10,000 produces a high anomaly signal. This is evidence, not automatic proof of hacking: legitimate rewards, refunds, administrative adjustments or migrations can also create large changes.

## DuckDB security posture

- Prefer in-memory or isolated analytical instances for request-independent jobs.
- Bound the number of rows per analysis batch.
- Disable automatic extension installation in security-sensitive deployments.
- Prefer DuckDB core extensions only when required.
- Never execute user-provided SQL.
- Never expose a DuckDB database file to the browser.
- Keep raw secrets and unnecessary raw PII out of analytical datasets.
- Store only normalized evidence needed for detection.
- Version every detector/model that produces a security signal.

## Extensions to evaluate

`json` and `parquet` are core DuckDB extensions suitable for normalized analytical data. `spatial` or `inet` can be considered later if geospatial/IP analysis requires them.

## Current status

DuckDB is approved for the analytics layer, but the production worker is intentionally not deployed yet. This prevents adding a native analytical dependency to the live API before its operational failure modes are tested.
