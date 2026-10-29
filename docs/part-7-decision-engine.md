# Part 7 — Risk Decision Engine

## Part 7A — unified policy foundation

Part 7A combines existing Parts 1–6 evidence into a deterministic recommendation boundary. It does not execute enforcement or mutate production state. The input is normalized into risk dimensions plus explicit policy signals and authoritative Part 5 controls.

## Non-overridable precedence

1. Global lockdown.
2. Deterministic hard block.
3. Transaction firewall denial.
4. Confirmed high-impact compromise/security abuse policy.
5. Deterministic risk plus bounded Part 6 AI shadow evidence.
6. Human review where required.

AI is advisory only and cannot weaken the first three controls or authorize a denied transaction.

## Risk calculation

Deterministic risk uses fixed weights:
- identity: 20%
- behavior: 25%
- graph: 20%
- transaction: 25%
- account history: 10%

AI contributes at most 15 points to the final score. If AI is missing or unavailable, its contribution is zero. AI alone cannot reach a restrictive threshold.

## False-positive protection rules

- VPN detected: access challenge/restriction only; never fraud proof by itself.
- Proxy detected: access challenge/restriction only; never automatic ban.
- Tor detected: access challenge/restriction only; never automatic ban.
- Fingerprint changed: not fraud proof by itself; allow/monitor according to other evidence.
- Shared IP/network: correlation evidence, not proof of one person or duplicate accounts.
- Suspected duplicate account: review/monitor; no automatic permanent ban.
- Confirmed duplicate account: hold reward activity on the secondary account pending review; do not automatically erase the primary account.
- A single weak signal must not create a permanent ban.

## Severe-abuse rules

Confirmed credential/cookie theft, successful unauthorized access, or successful exploitation can produce a `PERMANENT_BAN` recommendation, but the recommendation requires human approval. AI alone can never produce this decision.

Confirmed reward fraud or malicious automation produces `HOLD_REWARDS` pending review rather than silently deleting balance. A confirmed unsuccessful security-abuse attempt is recorded and escalated for review according to severity; it is not automatically a permanent ban.

## Recommendation thresholds

- 0–24: ALLOW
- 25–49: MONITOR
- 50–69: CHALLENGE, or TEMP_RESTRICTION if a challenge was already passed
- 70–84: HOLD_REWARDS
- 85–100: HUMAN_REVIEW

The engine may also return explicit policy actions such as `LOCKDOWN`, `BLOCK`, `DENY_TRANSACTION`, or `PERMANENT_BAN` when authoritative controls or confirmed high-impact evidence require them.

## Contract boundary

The engine returns a recommendation only. Its contract explicitly sets `recommendationOnly=true` and `sideEffectsPerformed=false`. No wallet, session, database, or account writes occur in Part 7A.

## Next slices

- **7B:** enforcement, reward holds, restrictions, suspensions, permanent-ban workflow, review/restore/extend, and immutable audit events.
- **7C:** full Parts 1–7 integration, race/idempotency tests, fail-closed validation, policy regression suite, and final security closeout.

## Validation gate

CI must pass before merging. Production claims require separate runtime smoke tests; passing unit/CI tests does not prove live enforcement or every AI model checkpoint is running in production.
