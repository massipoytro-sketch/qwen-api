# GainiRen Security — Part 3: Security completion layer

Part 3 closes the operational gaps around the deterministic security core. It does **not** enable AI.

## 1. Transport boundary

- Production API traffic must arrive over HTTPS.
- Behind Render's TLS terminator, `X-Forwarded-Proto: https` is the trusted transport signal used by the server boundary.
- HSTS, CSP, frame isolation, referrer policy, permissions policy, and cross-origin isolation headers are applied centrally.
- The local outbox worker explicitly marks its loopback request as HTTPS after it stays inside the same process boundary.

TLS is terminated by the hosting edge; the application enforces that external production traffic was received through that TLS boundary. The database connection remains HTTPS to Supabase through the server-side client.

## 2. Network control plane

`security.network_controls` provides a tenant-scoped operator control for a specific known IP identity:

- `allow` — do not escalate the deterministic result.
- `monitor` — record the override without changing the decision.
- `challenge` — require an additional verification step unless the current result is already stricter.
- `deny` — force `BLOCK`.

Controls can expire automatically. They are private to the service role and are applied after the main deterministic assessment, so an operator override can only become stricter (except `allow`, which intentionally leaves the existing result unchanged).

## 3. One-time challenge state

`security.challenge_tokens` stores only SHA-256 token hashes. Tokens have:

- tenant/subject/session binding;
- explicit challenge type;
- short expiration (30–900 seconds);
- one-time atomic consumption;
- bounded reason codes.

The database never needs the plaintext challenge token. A future MFA/PoW/risk-verification adapter can issue a random token, send only the plaintext to the trusted caller, and store its hash through the service-role RPC.

A consumed challenge is never reusable.

## 4. Request integrity

The existing request-signing layer remains authoritative:

- exact request method and path/query are signed;
- exact body SHA-256 is signed;
- a fresh cryptographically random nonce is required;
- timestamp freshness is bounded;
- HMAC-SHA-256 uses the tenant API secret;
- nonce hashes are atomically consumed in Postgres;
- duplicate signed requests are rejected.

This gives each request a changing signature instead of a reusable static signature.

## 5. Expired-state maintenance

`purge_expired_security_state(batch)` removes expired request nonces, challenge tokens, and network controls in bounded work. It is service-role-only so it can be scheduled from the trusted worker without exposing maintenance to clients.

## 6. Architecture after Part 3

Request → TLS boundary → strict HTTP adapter → bearer authentication → HMAC request signature + timestamp + nonce → rate limits → runtime kill switch → deterministic verification engine → eight-layer firewall → tenant policy floor → network control plane → append-only audit ledger → durable outbox → optional analytics/deception systems.

The decision path does not depend on an AI provider.

## Completion rule

Part 3 is considered complete only after Security CI, runtime smoke, HoneyDB CI and CodeQL all pass on the final commit, followed by a Render deployment smoke test. AI is deliberately postponed until these controls are stable.
