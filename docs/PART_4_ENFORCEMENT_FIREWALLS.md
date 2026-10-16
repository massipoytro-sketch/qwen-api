# Part 4 — Enforcement Firewall

Part 4 moves the security platform from analysis-only behavior toward an explicit enforcement contract at the API boundary.

## Enforcement layers

The existing Part 2 defense-in-depth evaluator remains authoritative. Part 4 adds a final contract that combines the deterministic result with the firewall result using a strict decision ordering:

`ALLOW < MONITOR < CHALLENGE < REVIEW < BLOCK`

A lower layer can never relax a higher decision.

## Request firewall

The security-check endpoint now:

- rejects production plaintext HTTP;
- requires JSON content type;
- enforces the existing 64 KiB body limit;
- authenticates the tenant API key;
- verifies the exact-body HMAC request signature;
- atomically consumes the request nonce to stop replay;
- applies tenant and subject rate limits;
- returns an explicit `enforcement-v1` contract.

The request signature already changes whenever the nonce/timestamp/body changes, so the signed request is not a reusable static signature.

## Challenge tokens

`src/security/enforcement.ts` provides short-lived HMAC challenge tokens bound to:

- tenant;
- subject;
- request ID;
- challenge type;
- expiration time.

Verification uses constant-time signature comparison and rejects mismatched context or expired tokens. The signing key is supplied by the server and is never embedded in the client.

A later challenge-completion endpoint should additionally consume a server-side one-time-use record before accepting completion; the current token helper is intentionally not treated as proof of completion by itself.

## Transport/browser hardening

Security responses add HSTS, a restrictive CSP suitable for an API, `nosniff`, `DENY` framing, no-referrer, same-origin resource policy, restrictive permissions policy, and no-store caching.

TLS termination itself remains the responsibility of the production edge (Render/managed HTTPS). The application refuses production requests whose visible URL is not HTTPS.

## AI

No AI provider is enabled in Part 4. The deterministic security path remains complete without AI.
