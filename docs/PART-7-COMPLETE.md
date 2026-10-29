# Part 7 — Final Integration and Validation Contract

Part 7 combines the deterministic policy engine (7A), enforcement/review recommendation layer (7B), and the unified integration gateway (7C).

## Decision precedence

1. Global lockdown
2. Transaction firewall denial
3. Hard security block
4. Confirmed high-impact compromise policy
5. Deterministic risk and policy signals
6. AI shadow/advisory evidence

AI remains advisory. It cannot authorize a transaction denied by the firewall, weaken lockdown, or independently create a permanent enforcement decision.

## Safety rules

- VPN/proxy/Tor is an access challenge/restriction, not a permanent account action by itself.
- Fingerprint change alone is not fraud proof.
- Suspected duplicate accounts go to review; confirmation may hold rewards pending review.
- Reward fraud and malicious automation produce a reviewable hold.
- Unsuccessful security-abuse attempts do not automatically create permanent enforcement.
- Confirmed credential/cookie theft, successful unauthorized access, or successful exploitation can recommend permanent enforcement, but human approval and audit remain required.
- Balance is held for review rather than silently deleted.
- Recommendation layers perform no database, wallet, or session side effects.
- Hard controls remain fail-closed.

## Integration boundary

`evaluatePart7()` is the normalized handoff from risk decision to enforcement recommendation. The actual authoritative mutation must remain in the production transaction/session/audit paths already protected by Parts 1–5.

## Completion gate

Part 7 is complete only when the repository CI, typecheck, lint, unit tests, runtime smoke, CodeQL, and HoneyDB checks are green on the final head. Production credential-gated negative API checks remain launch-time operational validation and are not replaced by unit tests.
