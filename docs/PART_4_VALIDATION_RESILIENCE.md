# Part 4 — Deterministic validation and resilience gate

Part 4 is the final pre-AI verification layer. It does not call external targets, generate attack traffic, or depend on an AI provider.

## Validation matrix

The gate executes representative defensive scenarios for:

- clean traffic;
- Tor/proxy/VPN-only monitoring behavior;
- trusted impossible-travel step-up;
- high-confidence automation challenge/review;
- account-takeover review;
- blocked identity;
- database trust-boundary block;
- application-integrity block;
- fraud-graph correlation;
- base-score monotonicity;
- malformed confidence safety.

Every scenario verifies that all eight firewall layers execute, scores/confidence remain bounded, challenge recommendations are consistent with the final decision, and no downstream layer can relax the deterministic score decision.

## Resilience rule

The validation gate is intentionally offline and deterministic. It is suitable for CI and regression testing. It is not a penetration-test substitute. Live edge/WAF, TLS termination, Render runtime, Supabase permissions, backup/restore and operator MFA still require deployment-level checks.

## Completion order

1. Part 1 — request integrity and replay controls: merged.
2. Part 2 — defense in depth, audit ledger, circuit breakers and HoneyDB expansion: merged.
3. Pre-AI consolidation — cryptographic trust, API-key rotation, emergency controls, bot defense, challenge tokens and firewall/network controls: merged as the consolidated deterministic foundation.
4. Part 4 — deterministic validation/resilience gate: this branch.
5. Only after Part 4 is green: enable the separate AI advisory phase.

AI remains disabled by default. The deterministic engine remains authoritative even after AI is introduced.
