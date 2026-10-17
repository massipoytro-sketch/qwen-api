# Part 5E — Implementation Status

Part 5E is the emergency control plane for GainiRen Shield.

## Enforcement chain

`request -> deterministic security check -> global control plane -> session revocation -> tenant/runtime controls -> reconciliation -> enforcement contract`

The global control plane is evaluated inside `guardedSecurityCheck`, and the public `/api/security-check` route now uses that guarded path. The Part 5D transaction preflight already uses the same guarded path, so both protected decision paths inherit the emergency boundary.

## Global kill switch

- `normal`: ordinary security evaluation.
- `review_only`: sensitive decisions cannot fall below `REVIEW`.
- `lockdown`: protected checks resolve to `BLOCK`.
- Expired global controls return to `normal` only by time expiry; ordinary request processing cannot downgrade an active restrictive state.
- Missing/unreadable global state fails closed.
- Global changes are versioned and append-only audited in `security.control_plane_audit`.

## Session revocation

- Individual session revocation is persistent and tenant-scoped.
- Subject-wide revocation marks every active session for that subject.
- Active revocations are checked before a protected decision can pass.
- Expiring revocations are removable through a bounded service-role cleanup RPC.
- Tenant-scoped revocations are recorded in the security audit ledger; global control changes use the dedicated global control audit stream.

## Recovery boundary

Normal operations use `SECURITY_OPS_TOKEN`.
Recovery from a restrictive global state additionally requires a separate `SECURITY_RECOVERY_TOKEN`.
The recovery credential is never accepted as a bearer operations credential and is never sent to the browser.

## Database boundary

The Part 5E migration uses private `security` tables, RLS, service-role-only grants, `security definer` functions with empty `search_path`, and fixed function signatures. The live project now contains the singleton control row, revocation store, bounded cleanup RPC, subject-wide revocation RPC, and global control audit stream.

## Verified live database checks

- Global control row exists and is `normal` after recovery.
- `review_only` transition increments the version.
- Downgrade without recovery approval is rejected.
- Recovery with explicit approval returns the control plane to `normal` and increments the version.
- Global control audit contains the tested transitions.

## Production gate

Part 5E is not called fully closed until:

1. CI is green on the final commit.
2. Negative integration tests prove lockdown cannot be bypassed.
3. Negative integration tests prove revoked sessions cannot pass.
4. Transaction preflight is proven to return `commitAllowed=false` during global lockdown/revocation.
5. Recovery requires the separate recovery credential.
