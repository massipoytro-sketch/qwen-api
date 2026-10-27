# Part 6 — AI Lab / Shadow Intelligence

Part 6 integrates the already-trained Shadow Engine algorithms into GainiRen Shield through a strict shadow boundary.

## Validated model set

- **PyOD optimized ensemble** — ECOD, COPOD, HBOS, Isolation Forest, LODA and PCA candidates; primary anomaly signal.
- **PyGOD DOMINANT** — graph anomaly signal for account/device/referral relationships.
- **River HalfSpaceTrees** — streaming anomaly/drift signal.
- **DeepCASE** — sequence anomaly signal; remains dependency-isolated because it is a legacy research stack.
- **Network anomaly detector** — network-flow signal; provenance-gated and not treated as reward-fraud validation.
- **OpenRouter advisory** — bounded language-model evidence analysis already present in the production service.

The Shadow Engine training workflow has already completed its seven-stage validation run. Part 6 therefore does not retrain duplicate models inside the production TypeScript service.

## Production boundary

`src/security/ai-lab.ts` is metadata/contract code. It does **not** import Python packages, execute unreviewed checkpoints, or copy research datasets into production.

Every model output must be normalized to:

- model id/version
- score `0..100`
- confidence `0..1`
- availability
- latency
- reason codes
- bounded evidence

Unavailable models are excluded from the aggregate rather than being treated as zero-risk evidence. If all models are unavailable, the aggregate explicitly reports `AI_MODELS_UNAVAILABLE`.

## Enforcement rule

AI is advisory only in Part 6. The aggregate is never an authorization, wallet mutation, challenge, suspension, or ban decision. Part 7 remains the authoritative policy/enforcement layer and must preserve all deterministic hard blocks and global lockdown rules.

## Model provenance gates

- PyOD/PyGOD/River: validated in the isolated Shadow Engine pipeline; production use still requires artifact/version deployment and runtime evaluation.
- DeepCASE: isolated compatibility boundary remains mandatory.
- Network model: public network-intrusion metrics do not prove reward-fraud performance.
- AnomalyGFM and any model with unresolved code/weight/dataset licensing are intentionally **not** in the production registry.

## Part 7 hand-off

Part 7 may consume the normalized AI shadow aggregate as one evidence source alongside deterministic risk, fraud graph, transaction history, behavior, account history, and policy controls. It must never allow an AI signal to downgrade a hard block or authorize a transaction denied by the firewall.
