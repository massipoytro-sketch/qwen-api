# GainiRen Security — Part 3: Bot Defense

Part 3 hardens the bot layer without making the security decision depend on an AI model.

## Deterministic bot defense

`src/security/botDefense.ts` combines bounded evidence from:

- explicit bot-classifier confidence;
- short-window event bursts;
- machine-like periodic timing;
- multiple independent client automation indicators.

The engine emits a bounded score, confidence, reason codes, and detector version. It does not store or require raw IP addresses, raw browser fingerprints, or credentials in its evidence.

The existing advanced bot detector and the new engine are combined conservatively by taking the stronger score and higher confidence. The firewall in Part 2 can then escalate to `CHALLENGE`/`REVIEW`; it never relaxes a deterministic decision.

## One-time proof-of-work challenge

`POST /api/bot-challenge` supports `mode=issue` and `mode=verify`.

Each issued challenge has:

- a fresh cryptographically random token and nonce;
- tenant/subject/session binding;
- an action and risk-derived difficulty;
- a two-minute expiry;
- an HMAC signature bound to the tenant API key and exact challenge fields;
- a server-side hashed token/nonce record;
- an atomic consume/finalize flow that prevents successful replay.

The proof is SHA-256 based and requires the digest of the token/nonce/solution to start with the configured number of zero nibbles. Difficulty is deliberately bounded from 1–4 so the mechanism remains usable on ordinary phones.

The HTTP request itself still uses the existing timestamp + nonce + HMAC request-signing layer, so a challenge cannot be issued or verified by an unsigned request.

## Database isolation

`security.bot_challenges` is private to the service role. Anonymous and authenticated roles have no table access and cannot execute the challenge RPCs. The dedicated `gainiren-shield-lab` database is the only database changed by this part.

## AI

AI remains disabled. The deterministic bot defense and proof-of-work challenge are complete before the later AI phase.

## Completion gate

Part 3 is complete only after Security CI, Runtime Smoke, HoneyDB CI and CodeQL all pass on the final commit, and the dedicated Supabase challenge access test passes. Do not merge or deploy if any required workflow is failing.
