# Runtime security controls

The dedicated security database now contains a tenant-scoped emergency control plane.

## Modes

- `normal`: normal deterministic firewall operation.
- `review_only`: every authenticated security-check result below `REVIEW` is escalated to `REVIEW`.
- `lockdown`: the API firewall immediately returns `BLOCK` with score 100 for the tenant.

Controls can expire automatically with `expires_at`. An expired non-normal control is treated as `normal` by the read function.

## Safety properties

- Only `service_role` can execute the control RPCs.
- The table is private and has RLS enabled.
- Every insert/update is appended to the tamper-evident audit ledger.
- The API reads the control after API-key authentication, request-signature verification, and rate limiting.
- AI is not involved in activating or bypassing a runtime control.
- This is an emergency containment mechanism, not a replacement for the normal multi-layer risk engine.

The control state is deliberately server-side. Do not expose `SECURITY_OPS_TOKEN`, service-role credentials, or control RPCs to browser code.
