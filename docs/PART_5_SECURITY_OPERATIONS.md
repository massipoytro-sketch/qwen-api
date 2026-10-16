# Part 5 — Security Operations, Deception Registry and Deterministic Attack Replay

## Why Part 5 exists

Parts 1–4 established the trust and enforcement boundary. Part 5 turns the defensive system into an operational security platform: operators can preserve bounded evidence, track deception assets, and reproduce a suspicious decision offline without sending traffic to production or an external target.

## Deception registry

`security.deception_assets` is a tenant-scoped inventory for synthetic HoneyDB surfaces. It stores only a SHA-256 locator hash, a bounded asset type/name, status and small metadata. It does not store credentials, passwords, raw attacker payloads or production database contents.

HoneyDB remains isolated from the production security database. A canary hit is an observation that can be correlated with the registry; it is not permission to take an automatic destructive action.

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

The database RPCs are `SECURITY DEFINER`, use a fixed search path, and are executable only by `service_role`. The replay tables have no direct client or service-role table privileges; writes occur through the RPC boundary. This keeps the storage private while allowing the application service to operate it.

## Part 5 boundary

This stage is deliberately not a live attack generator. It is an incident-analysis and regression mechanism. Any future load/chaos work must remain on controlled test infrastructure and be separately gated.

AI is still disabled. The deterministic engine remains authoritative.

## Validation

The dedicated `gainiren-shield-lab` database was tested transactionally: replay creation, ordered step insertion and finalization succeeded through the service-role RPC boundary while direct service-role table SELECT/INSERT privileges remained false. The transaction was rolled back, so no test replay data was retained.
