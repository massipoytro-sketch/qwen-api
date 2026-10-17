# Part 5E — Implementation Status

Part 5E is the emergency control plane for GainiRen Shield.

## Enforcement chain

`request -> deterministic security check -> global control plane -> session revocation -> tenant/runtime controls -> reconciliation -> enforcement contract`

The global control plane is deliberately evaluated inside `guardedSecurityCheck`, so the transaction preflight path inherits the same emergency boundary.

## Global kill switch

- `normal`: ordinary security evaluation.
- `review_only`: sensitive decisions cannot fall below `REVIEW`.
- `lockdown`: protected checks resolve to `BLOCK`.
- Expired global controls return to `normal` only by time expiry; ordinary request processing cannot downgrade an active restrictive state.
- Missing/unreadable global state fails closed.

## Session revocation

- Individual session revocation is persistent and tenant-scoped.
- Subject-wide revocation marks every active session for that subject.
- Active revocations are checked before a protected decision can pass.
- Expiring revocations are removable through a bounded service-role cleanup RPC.
- Revocation and control changes are recorded in the security audit ledger.

## Recovery boundary

Normal operations use `SECURITY_OPS_TOKEN`.
Recovery from a restrictive global state additionally requires a separate `SECURITY_RECOVERY_TOKEN`.
The recovery credential is never accepted as a bearer operations credential and is never sent to the browser.

## Database boundary

The Part 5E migration uses private `security` tables, RLS, service-role-only grants, `security definer` functions with empty `search_path`, and fixed function signatures.

**The migration is intentionally not applied to the live Supabase project yet.** The known migration-history drift must be reconciled first.

## Production gate

Part 5E is not called production-ready until:

1. CI is green on the final commit.
2. The migration is reconciled against the live database and applied safely.
3. Negative integration tests prove lockdown cannot be bypassed.
4. Negative integration tests prove revoked sessions cannot pass.
5. Transaction preflight is proven to return `commitAllowed=false` during global lockdown/revocation.
6. Recovery requires the separate recovery credential.
