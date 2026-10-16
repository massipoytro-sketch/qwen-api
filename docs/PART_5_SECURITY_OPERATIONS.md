# Part 5 — Security Operations, Deception Registry and Deterministic Attack Replay

## Why Part 5 exists

Parts 1–4 established the trust and enforcement boundary. Part 5 turns the defensive system into an operational security platform: operators can preserve bounded evidence, track deception assets, and reproduce a suspicious decision offline without sending traffic to production or an external target.

## Deception registry

`security.deception_assets` is a tenant-scoped inventory for synthetic HoneyDB surfaces. It stores only a SHA-256 locator hash, a bounded asset type/name, status and small metadata. It does not store credentials, passwords, raw attacker payloads or production database contents.

HoneyDB remains isolated from the production security database. It sends only categorical route information and HMAC-hashed peer/user-agent values. The internal HoneyDB receiver derives the same versioned locator digest, atomically increments hit counts for active registry assets, includes only the matched asset ID/type in the event, appends a tamper-evident ledger entry and queues a durable security event. A canary hit is an observation that can be correlated with the registry; it is not permission to take an automatic destructive action.

### Internal registry API

All operations below require HTTPS and `Authorization: Bearer <SECURITY_OPS_TOKEN>`. The token must be a server-side secret of at least 32 characters. The endpoint is disabled when the token is unset, and requests are rate limited.

- `GET /api/internal/deception-assets?tenantId=<uuid>&limit=50` — list assets without revealing the original locator.
- `POST /api/internal/deception-assets` — register an asset. Allowed locator keys are categorical forms such as `honeydb:admin:admin_login`, `route:/admin/login`, or `canary:backup:db-01`. Only the SHA-256 digest is stored; arbitrary URLs, query strings and credential-like values are rejected. For HoneyDB hits to update the registry, register the asset under the same tenant configured by `HONEY_TENANT_ID`.
- `PATCH /api/internal/deception-assets` — change an asset to `active`, `disabled` or `retired`. Retired/disabled assets stop matching HoneyDB hits but are not deleted.

The metadata schema is intentionally small: description, owner team, environment and tags. Never put secrets, request bodies, names/emails of suspected users, or raw network addresses in the registry.

## Deterministic replay

`security.attack_replay_sessions` and `security.attack_replay_steps` store short-lived replay jobs and bounded sanitized steps. Replay sessions expire after 30 minutes and accept at most 500 steps. Evidence is represented by a SHA-256 digest and small categorical JSON summaries.

The TypeScript replay engine is pure and offline. It:

- accepts only sanitized decision summaries;
- sorts and validates contiguous sequence numbers;
- never makes network calls;
- never writes to Supabase;
- never executes shell commands or tools;
- cannot downgrade a stronger decision;
- bounds scores to 0–100 and reason-code counts;
- supports only `dry_run` and `deterministic_simulation` storage modes.

Replay steps are written in atomic batches of at most 100. This avoids hundreds of network round trips and ensures a failed batch is rolled back without leaving a partially inserted batch. The database RPCs are `SECURITY DEFINER`, use a fixed empty search path with schema-qualified objects, validate tenant ownership and enforce bounded inputs. They are executable only by `service_role`. The replay tables have no direct client or service-role table privileges; reads and writes occur through the RPC boundary.

### Internal replay API

- `POST /api/internal/attack-replay` with `{ "tenantId": "<uuid>", "subjectId": "<uuid>", "replayMode": "deterministic_simulation" }` replays the subject's stored risk-decision summaries from the last 30 days.
- Or pass `sourceEventId` to include a specific tenant-scoped security event; a source event can be replayed without a subject when it is not attached to an account.
- `GET /api/internal/attack-replay?tenantId=<uuid>&subjectId=<uuid>&limit=25` lists recent replay sessions.
- `GET /api/internal/attack-replay?tenantId=<uuid>&replayId=<uuid>` returns a replay and its ordered sanitized steps while its 30-minute retention window is open.

The API does not accept attacker-supplied event timelines, run live probes, execute shell commands, call external hosts, or mutate the original risk decisions. It reads existing server-side records, produces a digest over normalized summaries and records the dry-run result. The replay fold is deliberately monotonic; it preserves the strictest decision present in the history and is not a claim to reproduce every historical policy version.

## Part 5 boundary

This stage is deliberately not a live attack generator. It is an incident-analysis and regression mechanism. Any future load/chaos work must remain on controlled test infrastructure and be separately gated.

AI is still disabled. The deterministic engine remains authoritative.

## Validation

The dedicated `gainiren-shield-lab` database was tested transactionally: deception asset registration/listing, atomic hit counting, disabled-asset behavior, replay creation, rejected sequence gaps, ordered step insertion, finalization, retrieval, hash/access boundaries and client-role RPC restrictions all passed. The verification transaction was rolled back, so no test asset or replay rows were retained. GitHub CI additionally runs TypeScript/lint/unit tests, HoneyDB tests, HTTP runtime smoke checks and CodeQL; the final Part 5 commit must pass all checks before merge.
