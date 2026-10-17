# Part 5E — Global Kill Switch, Session Revocation & Control Plane

## Included in this branch
- Deterministic precedence: global mode and tenant mode combine by the more restrictive mode; subject hold/block and session revocation further restrict.
- Missing, stale, future-dated, or unknown control snapshots fail closed.
- Session status must be explicitly active; revoked/expired/unknown sessions are denied.
- Downgrades from lockdown/review-only require a separate recovery approval path.
- SQL migration adds a singleton global control row, tenant-scoped session revocation records, security-definer RPCs with fixed empty search path, RLS, and server-role-only privileges.
- Revocation and control changes append audit-ledger entries.
- Unit tests cover stale/missing state, global precedence, review-only, revoked sessions, unauthorized changes and downgrade prevention.

## Required integration before production
This first implementation establishes the policy contract and database persistence, but does not yet wire the control-plane read into every protected endpoint or add an authenticated operator-management API. Before production, all protected request/transaction paths must read the global control and revocation state in the same authoritative server flow; database failure must deny sensitive mutations. Operator actions must be authenticated using a dedicated, rotated operations credential plus stronger human MFA/approval for recovery; never expose service-role credentials in a browser. Session issuance and refresh must consult revocations, not only JWT expiry. Reconcile migration history before applying the migration; do not apply it blindly to the live database.

## Modes
- normal: proceed to ordinary risk checks.
- review_only: sensitive mutations cannot commit automatically.
- lockdown: deny sensitive operations.
- A stricter mode always wins. A downgrade is a recovery action and needs explicit approval; ordinary runtime requests cannot lower a mode.
