# Part 3 — Fraud Intelligence + Corroborated Bot Defense

This phase strengthens the existing deterministic engine rather than adding a separate, unused detector. The fraud and bot evidence below is wired into `src/security/check.ts`, which persists its risk signals, assessment, decision, audit record and ledger event through the existing pipeline.

## Fraud intelligence

`src/security/fraud-intelligence.ts` provides bounded analysis of server-derived graph edges and value jumps.

- Graph evidence is scored by independent resource classes (device, network, identity and session), high-confidence edges, and subjects sharing multiple resources.
- One shared IP or device cannot independently create a high fraud score.
- Value jumps use both the absolute change and multiplier, including the `0 → 10,000` scenario. A trivial `0 → 1` change does not become critical merely because the ratio is undefined/infinite.
- `enforceFraudFloor` is escalation-only: its possible recommendations stop at `REVIEW`; it cannot create `BLOCK` or relax an existing decision.
- The core check enriches the persisted evidence with reason codes and detector versions.

## Corroborated bot defense

The existing `src/security/botDefense.ts` module was strengthened instead of creating a duplicate bot engine. It combines high-confidence classifier evidence with request bursts, timing regularity, repeated browser/automation indicators and replay indicators, with a bounded ten-minute event window.

A single weak browser flag is not enough to challenge a user. The output is bounded to 0–100 and decisions from this component are restricted to `ALLOW`, `MONITOR`, `CHALLENGE`, or `REVIEW`; it never returns `BLOCK`. The main firewall and deterministic identity/database controls remain authoritative.

## Integration

The existing advanced bot detector and the upgraded corroboration detector contribute to one combined bot signal, preventing duplicate bot evidence from inflating risk solely because two algorithms observed the same events. Fraud graph intelligence and value-jump analysis are included before policy evaluation and the eight-layer firewall. The strictest resulting decision is retained.

`guardedSecurityCheck` no longer repeats bot queries after the core assessment. It applies the operator-managed network control plane only; the normal security check already incorporates the deterministic bot/fraud signals.

## Verification

- `tests/bot-defense.test.ts`: weak single flag, correlated multi-signal automation, replay patterns, periodicity-only evidence, time-window bounds and non-finite confidence.
- `tests/fraud-intelligence.test.ts`: shared-resource false-positive guard, independent-resource corroboration, `0 → 10,000`, trivial `0 → 1`, existing BLOCK preservation and malformed numeric input.
- Full TypeScript, lint, unit tests, dependency audit, Runtime Smoke, HoneyDB CI and CodeQL must pass on the PR's final SHA.

No AI is required or enabled by this phase. No rewards-platform database or repository is modified.
