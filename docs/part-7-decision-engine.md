# Part 7 — Risk Decision Engine

## First slice

Part 7 starts with a deterministic, pure recommendation engine that combines existing risk dimensions with the normalized Part 6 AI shadow aggregate. This slice does not execute enforcement actions or mutate production state.

## Non-overridable precedence

1. Global lockdown.
2. Deterministic hard block.
3. Transaction firewall denial.
4. Risk recommendation from deterministic signals plus bounded AI evidence.
5. Human review for critical-risk recommendations.

AI cannot weaken or bypass any of the first three controls.

## Risk calculation

Deterministic risk uses explicit fixed weights:
- identity: 20%
- behavior: 25%
- graph: 20%
- transaction: 25%
- account history: 10%

AI contributes at most 15 points to the final score. If AI is missing, unavailable, or not in shadow/advisory mode, its contribution is zero. AI alone cannot reach challenge, reward-hold, or restriction thresholds.

## Recommendation thresholds

- 0–24: ALLOW
- 25–49: MONITOR
- 50–69: CHALLENGE, or TEMP_RESTRICTION if a challenge was already passed
- 70–84: HOLD_REWARDS
- 85–100: HUMAN_REVIEW; no automatic suspension or permanent ban

The engine returns a recommendation only. Its contract explicitly sets recommendationOnly=true and sideEffectsPerformed=false. No wallet, session, database, or account writes occur here.

## Validation gates

1. Run CI and inspect all checks for this branch.
2. Verify that callers pass authoritative Part 5 hard-block, lockdown, and transaction-firewall outcomes.
3. Add integration tests against the real Shield control adapters without enabling enforcement.
4. Add audit/idempotency and human-approval workflow before any production enforcement is considered.
5. Keep permanent bans and long suspensions outside autonomous AI control.

## Limitation

Part 6 currently provides model contracts/metadata and an aggregator, not a production runtime for every Python model. This slice consumes normalized AI signals when supplied; it does not claim the Python checkpoints are executing in production.
