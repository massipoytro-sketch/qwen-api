# GainiRen Security — Part 3: Resilience & Control Plane

Part 3 completes the pre-AI defensive foundation with credential rotation and an emergency security control plane.

## 1. Rotatable API credentials

`security.tenant_api_keys` supports multiple hashed credentials per tenant with independent status and expiration. Plain API keys are never stored. Lookup is bound to the exact tenant and optional key ID, and successful use updates only `last_used_at`.

The table is not writable by client roles or directly by `service_role`; provisioning is exposed through the service-role-only `provision_rotated_api_key` RPC. This gives operators a controlled way to add a new key before revoking the old one, enabling overlap during rotation.

The existing `security.tenants.api_key_hash` remains as a backward-compatible legacy credential path until all clients migrate to rotated keys.

## 2. Emergency control plane

`security.security_controls` provides a tenant-scoped kill switch with four modes:

- `normal`: normal deterministic security operation.
- `challenge_all`: low-risk requests are escalated to a five-minute risk-based verification recommendation.
- `deny_all`: requests are stopped before the risk engine executes.
- `maintenance`: same hard stop semantics as deny-all, for controlled maintenance windows.

Every control update increments a monotonic version. Optional expiry makes emergency modes self-reverting instead of creating a permanent lockout by accident.

The control is evaluated only after credential authentication and request-signature verification. Therefore an attacker cannot activate or bypass the control through an unauthenticated request.

## 3. Defense ordering

The protected request path is now:

`TLS/edge → request limits → API credential → request signature + timestamp + nonce → replay protection → tenant control plane → rate limits → deterministic Verification Engine → multi-layer firewall → audit ledger → asynchronous analytics/outbox`

AI is intentionally not inserted into this chain yet. It will be advisory and isolated in the next phase.

## 4. Rotation procedure

1. Generate a new high-entropy API key in the trusted operator environment.
2. Hash it with the same SHA-256 utility used by the API.
3. Provision only the hash through `provision_rotated_api_key`.
4. Deploy/update the client to send the new key and its `x-gainiren-key-id`.
5. Verify signed requests succeed.
6. Revoke the old key in the controlled operator path.
7. Set an expiry on temporary migration keys.

Never paste an API key into GitHub issues, logs, source files, or chat.

## 5. AI boundary

No AI provider is enabled by Part 3. The deterministic engine remains authoritative. The later AI stage will receive bounded, privacy-minimized evidence and can only advise; it cannot lower a deterministic decision.
