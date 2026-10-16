# Part 5 — Active Defense Control Plane

Part 5 is the orchestration layer above Parts 1–4. It does not replace the deterministic firewall or cryptographic boundary; it consumes their evidence and can only move enforcement in the more restrictive direction.

## Control plane

`src/security/controlPlane.ts` defines the deterministic Active Defense Mesh:

- identity / account-takeover evidence;
- device trust evidence;
- network and impossible-travel evidence;
- bot/automation evidence;
- fraud graph and value-jump evidence;
- behavioral evidence;
- database / request-integrity violations;
- deception tripwires;
- transaction/value risk;
- tenant policies;
- emergency `NORMAL`, `MAINTENANCE`, `LOCKDOWN`, and `DENY_ALL` modes.

The control plane produces a single restrictive decision, a security state, quarantine status, incident fingerprint, policy matches, and sensitive-operation enforcement flags.

### Security state machine

`TRUSTED → MONITORED → SUSPICIOUS → CHALLENGE_REQUIRED → QUARANTINED → UNDER_REVIEW → BLOCKED`

State is monotonic when an existing state is stronger. A normal request cannot silently downgrade a `BLOCKED` subject to `TRUSTED`.

### Quarantine

Quarantine is intentionally different from permanent blocking. It can prevent sensitive operations, require a challenge, and increase monitoring while preserving ordinary account access where policy permits.

### Correlation / incident model

A deterministic incident fingerprint is derived from tenant, subject, operation, and sorted reason codes. The database persists subject state, device trust, transaction risk, incident records, and incident evidence under tenant boundaries.

## Policy simulator

`simulatePolicies()` evaluates bounded policy conditions by priority without changing production state. Policies are restrictive-only: an `ALLOW` policy cannot weaken an existing `CHALLENGE`, `REVIEW`, or `BLOCK` decision. Expired policies are ignored.

This is the base for a future historical simulator over large event windows; no policy simulation mutates live assessments.

## Cryptographic trust layer

`src/security/cryptoTrust.ts` provides reusable primitives for the sensitive-operation boundary:

- AES-256-GCM authenticated encryption for data at rest or application payloads;
- ECDH P-384 shared-secret agreement;
- ECDSA P-384 with SHA-384 signatures;
- SHA-384 and SHA-512 data digests;
- HMAC-SHA-256 request signatures bound to method, path, timestamp, nonce, exact body digest and key ID;
- cryptographically random request nonces;
- constant-time signature comparison.

The existing Part 3 request-signing and key-rotation system remains the production request-authentication path. These primitives provide the common cryptographic boundary for additional sensitive operations and future key-management integration.

### TLS

TLS termination is controlled by the deployment edge (Render/Cloudflare/etc.), not by application code. Part 5 therefore does not invent a second TLS implementation. Production endpoints must remain HTTPS-only, redirect-free for signed security calls, and behind a platform configuration that disables obsolete TLS versions/ciphers. Application signatures and encryption are defense-in-depth and do not replace TLS.

## Database boundary

Migration `20261016150000_part5_active_defense_control_plane.sql` creates private, tenant-scoped persistence for:

- `security_subject_states`
- `security_control_policies`
- `device_trust_records`
- `transaction_risk_events`
- `security_incidents`
- `security_incident_evidence`
- `security_control_modes`

RLS is enabled and direct client/service-role table privileges are revoked. Controlled `SECURITY DEFINER` RPCs with a fixed search path are the only service-role access path for the control-plane context and state recording.

The migration was applied only to the dedicated `gainiren-shield-lab` project.

## AI boundary

Part 5 does not give AI authority. OpenRouter/NVIDIA Nemotron remains disabled unless explicitly enabled later. Even when enabled in the later AI phase, deterministic control-plane decisions remain authoritative.
