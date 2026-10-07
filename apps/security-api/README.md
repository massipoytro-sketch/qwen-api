# GainiRen Security API

The first API contract is the server-side `securityCheck()` operation.

Flow:

`request -> tenant/subject/session context -> device/network/bot/behavior signals -> baseline risk engine -> risk assessment -> decision`

Current decisions:
- `ALLOW`
- `MONITOR`
- `CHALLENGE`
- `REVIEW`
- `BLOCK`

The implementation lives in `src/security/check.ts` and uses the server-only Supabase key. It must never be bundled into a public browser client.

The baseline engine is intentionally deterministic. ML/AI signals will be added as additional evidence later; they will not replace the core policy engine.
