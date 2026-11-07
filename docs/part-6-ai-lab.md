# Part 6 — AI Lab / Shadow Intelligence

Part 6 is the integration boundary for Shadow Engine. It is **not yet production-complete**. The repository currently contains the AI evidence contract, model registry metadata, and an optional OpenRouter advisory adapter. The external Shadow Engine model artifacts and live inference adapters have not yet passed the required end-to-end validation.

## Current implementation status

- **AI evidence contract:** implemented in `src/security/ai-lab.ts`.
- **OpenRouter advisory:** bounded provider adapter exists in `src/security/ai.ts`; disabled by default and controlled by server-side environment variables.
- **Shadow Engine registry:** PyOD, PyGOD, River, DeepCASE and network detector entries are metadata/contracts, not proof that production model artifacts are trained, deployed or callable.
- **Production adapter:** `src/security/part7-adapter.ts` currently marks all Shadow Engine models unavailable until validated artifacts and runtime adapters are actually deployed.
- **Training validation:** pending. A GitHub Actions run that fails before executing steps, or a hosted training job rejected for lack of compute credits, is not a completed training or validation run.

## Model candidates

- **PyOD ensemble:** ECOD, COPOD, HBOS, Isolation Forest, LODA and PCA candidates.
- **PyGOD DOMINANT:** graph anomaly candidate for account/device/referral relationships.
- **River HalfSpaceTrees:** streaming anomaly/drift candidate.
- **DeepCASE:** sequence anomaly candidate; remains dependency-isolated until compatibility and licensing checks pass.
- **Network anomaly detector:** network-flow candidate. Public network-intrusion benchmarks do not prove reward-fraud performance.
- **OpenRouter advisory:** language-model explanation of bounded security evidence; it is not a detector and is not a source of truth.

## Required model acceptance gates

A model is not marked available until all of the following are recorded:

1. Dataset provenance, license, permitted use, and PII review.
2. Reproducible training command and pinned environment.
3. Train/calibration/test split with leakage checks.
4. Baseline comparison and class-appropriate metrics.
5. False-positive and false-negative review on a GainiRen-relevant evaluation set.
6. Saved artifact with checksum, manifest, feature schema, and model version.
7. Runtime adapter smoke test, timeout/failure test, and bounded output validation.
8. Production-like shadow evaluation before enabling the model in the registry.

External datasets such as bot detection or network intrusion benchmarks are useful research benchmarks, but their labels are not equivalent to confirmed GainiRen reward abuse.

## Production boundary

Every model output must be normalized to:

- model id/version
- score `0..100`
- confidence `0..1`
- availability
- latency
- reason codes
- bounded evidence

Unavailable models are excluded from the aggregate rather than being treated as zero-risk evidence. If all models are unavailable, the aggregate explicitly reports `AI_MODELS_UNAVAILABLE`.

## Enforcement and scoring rule

AI is advisory-only. Neither a language model nor a detector aggregate may change deterministic risk scores, detector labels, routing, authentication, challenges, account state, wallet balances, or enforcement. AI output may be stored for investigation and displayed as an explanation, but must not downgrade or escalate an authoritative decision. Part 7 remains the deterministic policy/enforcement authority.

## Part 7 hand-off

Part 7 may retain the normalized AI shadow aggregate as separate evidence for human review. Hard blocks, global lockdown, transaction firewall denials, and all deterministic policy outcomes remain unchanged regardless of AI output.
