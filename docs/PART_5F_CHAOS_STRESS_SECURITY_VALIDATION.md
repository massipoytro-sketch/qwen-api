# Part 5F — Chaos, Stress & Security Validation

Part 5F is the final validation layer for Part 5. It is deliberately test-oriented: it does not weaken production controls and does not run destructive attacks against external systems.

## Engines

1. **Chaos Engine** — models DB outage/timeout, security API timeout, privileged RPC failure, unreadable control plane, missing session context, outbox failure and service restart. Protected operations must fail closed or refuse commit.
2. **Race Engine** — validates the single-winner property for idempotency identities and concurrent transaction attempts. More than one commit for the same logical transaction is a failure.
3. **Stress Engine** — uses bounded concurrency/request/duration plans so CI cannot accidentally become a denial-of-service tool. Production protection must not be weakened by load.
4. **Attack Validation** — the corpus targets replay, duplicate idempotency, invalid timestamps, malformed input, session revocation and global lockdown bypass attempts.
5. **Invariant Engine** — encodes non-negotiable rules: lockdown never allows, inactive sessions never allow, failed security checks never allow, replay/duplicate identities never commit twice, and commits require audit evidence.
6. **Fuzz Engine** — exercises nulls, wrong types, oversized values, negative/non-finite amounts, invalid timestamps, prototype keys and nested objects.
7. **Recovery Engine** — validates the intended normal → review_only → lockdown → normal sequence without losing restrictive persisted state.
8. **Audit Integrity** — requires request → decision → assessment → enforcement → audit references and dedicated audit evidence for global control changes.
9. **Kill-Switch Validation** — lockdown is treated as an invariant, not as a UI feature; recovery must be explicitly authorized by the existing Part 5E boundary.
10. **Master Validation** — the Vitest suite combines these deterministic checks before live integration validation is attempted.

## Safety boundary

Chaos and stress helpers are pure validation code. They do not mutate Supabase, wallet balances, production control-plane state, or third-party systems. Live negative tests must use an isolated environment, synthetic identities, bounded concurrency, and explicit cleanup.

## Closure criteria

Part 5 is not considered fully validated until:

- the complete test suite is green;
- Part 5C/5D/5E live negative tests pass;
- replay/idempotency race tests prove a single commit;
- lockdown and session revocation cannot be bypassed;
- failure paths remain fail-closed;
- audit-chain integrity is proven;
- bounded load tests show no security decision downgrade;
- recovery preserves restrictive state and audit evidence;
- production smoke tests pass after deployment.
