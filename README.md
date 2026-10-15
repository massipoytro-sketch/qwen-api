# GainiRen Security

Open-source, modular security and fraud-intelligence platform for web applications.

## Goals

- Identity and account integrity
- Device intelligence
- Network and IP intelligence
- Bot and automation detection
- Behavioral risk analysis
- Deterministic risk scoring and security decisions
- Fraud relationships and security graph
- AI-assisted anomaly and fraud analysis
- Cryptographic request integrity
- Audit and security operations
- Analytics
- API and SDK integration for client applications

## Architecture

The project is designed as a defense-in-depth system. No single fingerprint, IP signal, browser signal, rule, or AI model should be trusted as the only source of truth.

## Repository layout

```
apps/        Application services
packages/    Reusable security modules
supabase/    Database migrations, functions, and tests
models/      Model metadata and ML assets
tests/       Unit, integration, security, and abuse tests
docs/        Architecture, threat model, database, and security documentation
```

## Development status

Core security phases 1–3 are being developed and validated in isolated pull requests. The platform includes deterministic risk assessment, account/session verification, multi-layer decision firewall, tenant-scoped audit ledger, circuit breakers, synthetic deception sensors, HMAC request signing with replay protection, and controlled API-key rotation. See `docs/PART_2_DEFENSE_IN_DEPTH.md` and `docs/PART_3_OPERATIONAL_HARDENING.md`.

The project and its `gainiren-shield-lab` database are intentionally independent from the older `rewards-platform` application and database. AI remains disabled until the separate AI phase. Production integration is gated on successful CI, end-to-end signed-request tests, and deployment verification.

## Security

See [SECURITY.md](SECURITY.md).
