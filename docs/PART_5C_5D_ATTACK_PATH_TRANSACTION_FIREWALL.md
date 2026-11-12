# Part 5C + 5D — Attack Paths and Transaction / Wallet Firewall

## Scope and safety boundary

This implementation adds a deterministic, bounded attack-path engine; tenant-scoped graph expansion; transaction preflight evaluation; an append-only decision ledger record; transaction-risk history; and time-bound per-subject transaction holds/blocks.

It does not claim to prevent a wallet mutation by itself. The wallet-owning GainiRen backend must call `POST /api/transaction-check` server-to-server before committing any balance, reward, redemption, transfer, refund, withdrawal, or payout change. It must treat a non-2xx response, timeout, invalid response, or `commitAllowed !== true` as a no-commit result. Values and account/session IDs must be loaded by the trusted application backend—not accepted as authoritative from browser state.

## 5C — Attack-Path Engine

- Starts from the requested subject and traverses tenant-filtered `security.graph_edges` with a depth limit (maximum 4), edge cap (maximum 500), frontier cap, and search-state cap.
- Keeps relationship confidence and bounded, human-readable path patterns. It does not return raw graph node IDs in the risk summary.
- Correlates independent signal classes (identity, device, network, automation, behavior, value and transaction intent) with cross-subject/shared-resource evidence.
- Emits versioned evidence, reason codes, traversal counts, and truncation status. It is deterministic; it never independently authorizes a BLOCK.
- The existing risk engine remains authoritative for deterministic aggregation, and the existing firewall can only escalate a decision.

## 5D — Transaction / Wallet Firewall

Endpoint: `POST /api/transaction-check`.

Accepted operations: `earn`, `reward_credit`, `redeem`, `purchase`, `deposit`, `transfer`, `withdrawal`, `payout`, `refund`, `wallet_adjustment`.

The endpoint uses the existing tenant key, signature, timestamp/nonce, rate limit, and idempotency gates; it obtains the base decision from the security engine; incorporates recent transaction frequency and the attack-path score; reconciles the result without allowing a downgrade; writes `security.transaction_risk_events`; and appends a hash-chained audit entry. It returns `decision`, `outcome`, `commitAllowed`, `challengeRequired`, `reviewRequired`, `adaptiveControl`, reason codes, and the engine version.

### Adaptive lockdown

A transaction-level `REVIEW` creates a time-bound `hold` for sensitive transactions (default 10 minutes); a transaction-level `BLOCK` creates a time-bound `block` (default 30 minutes). An active hold forces at least `REVIEW`; an active block forces `BLOCK`. Repeated requests do not keep extending an unchanged active lock. A more restrictive new decision may escalate hold to block. Expired controls are ignored. All control records are server-only and RLS-enabled.

## Required integration before claiming end-to-end wallet protection

1. On the server, load the transaction and current wallet/value state from the authoritative ledger.
2. Build a fresh unique `Idempotency-Key` for this transaction attempt, sign the exact request body, and send it to the Shield endpoint.
3. If the call times out, errors, or returns `commitAllowed: false`, do not change any balance.
4. For `CHALLENGE`, complete the configured verification and re-run preflight under a new attempt key; for `REVIEW`, put the transaction into the app's pending/manual-review state; for `BLOCK`, reject it.
5. If `commitAllowed: true`, mutate the wallet using the existing authoritative transaction/ledger operation with its own database transaction and idempotency protection. Never perform a balance update in the browser.
6. Keep the preflight reference and Shield `assessmentId` attached to the app's transaction audit record.

## Validation and deployment

Tests cover multi-stage paths, empty/weak evidence, bounded cyclic traversal, transaction escalation, the no-single-signal hard-block rule, no decision downgrade, input validation, active subject holds/blocks, expiry, and lock escalation.

The SQL migration is deliberately added to the Git branch only. The live Supabase migration history has drifted from the files present in the repository, so reconcile that history before applying it to the live database. The feature branch should be typechecked and tested in CI before review, and must not be merged/deployed until that passes.
