# Part 5 proposal — Resilience, adversarial replay and cryptographic operations

Part 5 should be the last deterministic hardening stage before the AI phase. Its purpose is not to add another scoring model; it is to prove that the security system survives failure and repeated hostile-looking activity without corrupting state or weakening tenant isolation.

## 1. Attack Replay Lab

A fully synthetic, offline replay harness that can feed bounded event sequences into the real detectors:

- credential-stuffing-like login bursts;
- account-takeover sequences;
- impossible travel;
- multi-session anomalies;
- bot/replay patterns;
- value jumps;
- fraud graph clusters;
- HoneyDB canary hits;
- database/tenant-boundary violations.

The harness must use synthetic UUIDs and reserved `.invalid` identities only. It should never target a real external service.

## 2. Policy Simulator

Run a proposed tenant policy against recorded synthetic events without changing production state. Show:

- old decision vs new decision;
- score delta;
- affected reason codes;
- false-positive risk indicators;
- whether the policy can accidentally relax a stronger firewall decision.

## 3. Cryptographic key lifecycle

Add versioned key identifiers and rotation support for:

- request HMAC keys;
- challenge signing keys;
- internal service tokens.

New keys become active without immediately invalidating the previous key. Old keys have a bounded grace period and are then retired. Secrets remain in Render/Supabase secret storage only.

## 4. Security-state resilience

Exercise:

- database RPC failure;
- outbox backlog;
- analytics dependency timeout;
- circuit breaker opening and recovery;
- duplicate event delivery;
- concurrent ledger appends;
- stale leases;
- partial downstream failure.

The invariant is: an auxiliary dependency may fail, but authentication, tenant isolation and deterministic enforcement must not silently become permissive.

## 5. Ledger checkpoints

Export periodic hash-chain checkpoints to a separately controlled append-only destination. This raises the assurance level beyond an in-database tamper-evident ledger.

## 6. Final pre-AI gate

Part 5 is complete only when CI, CodeQL, runtime smoke, HoneyDB tests, replay tests, database isolation tests and resilience tests are green. Only then should the AI analyst be enabled.

### AI remains separate

The AI phase comes after Part 5. The model is advisory only at first; it cannot lower a deterministic decision, bypass a firewall, or authenticate a request. The provider/model can be selected later without changing the core enforcement architecture.
