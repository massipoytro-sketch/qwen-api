# Part 3 — Fraud Intelligence + Bot Defense

Part 3 adds two deterministic engines that sit underneath the existing security decision pipeline. AI is still disabled and is not required for any decision.

## Fraud intelligence

`src/security/fraud-intelligence.ts` adds:

- bounded graph-correlation scoring;
- independent relationship counting;
- multi-resource cluster evidence;
- conservative value-jump detection, including the `0 → 10,000` pattern;
- a decision floor that can only make a decision stricter.

A shared IP/device alone is intentionally insufficient for a strong action. Stronger responses require corroboration across independent relationships or repeated shared resources.

## Bot defense

`src/security/bot-defense.ts` adds a server-side corroboration engine using:

- classifier confidence;
- webdriver/headless/automation-framework indicators;
- known bot user-agent evidence;
- impossible timing;
- missing interaction;
- request replay indicators;
- request-burst volume.

One weak client flag cannot challenge a user. A challenge requires corroborating evidence; a review requires very strong corroboration and high-confidence classifier/replay evidence.

## Safety properties

- Scores are finite and bounded to 0–100.
- Confidence is bounded to 0–1.
- No bot or fraud engine can directly produce `BLOCK`.
- Existing deterministic firewall/account protections remain authoritative.
- No raw credentials, request bodies, or secrets are introduced.
- Tenant isolation remains mandatory at the database layer.

## Validation

`tests/fraud-bot-intelligence.test.ts` covers weak shared-resource evidence, dense multi-edge correlation, the 0→10k value jump, weak browser signals, corroborated bot activity, replay patterns, and invalid confidence.

The new modules are deliberately isolated first. The next Part 4 step will wire their outputs into the enforcement gateway and challenge/replay protections after Part 3 CI is green.
