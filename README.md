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

## Security hardening roadmap

- [Part 2 — Defense in depth](docs/PART_2_DEFENSE_IN_DEPTH.md)
- [Part 3 — Key lifecycle and validation readiness](docs/PART_3_RESILIENCE_AND_VALIDATION.md)
- [Signed API requests](docs/REQUEST_SIGNING.md)

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

Phase 0 — architecture and threat model.

The project is intentionally independent from the existing GainiRen application and its older database until the security platform is stable enough for integration.

## Security

See [SECURITY.md](SECURITY.md).
