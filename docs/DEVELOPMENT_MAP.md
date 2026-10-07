# GainiRen Security — Development & Tooling Map

## Mission

Build GainiRen Security as a modular, server-side security and fraud-intelligence platform using defense-in-depth. No single signal or AI model is allowed to make a final security decision by itself.

## Current baseline

- Runtime: Node.js >=22.13
- Language: TypeScript
- Package manager: pnpm workspace
- Database: Supabase/PostgreSQL, private `security` schema
- Existing intelligence: identity, device, network, bot and behavior signals
- Risk engine: weighted multi-source evidence aggregation (baseline-v2)
- Audit: security audit events
- CI: GitHub Actions typecheck/lint/test
- Tests: initial sanity test only

## Target architecture

```text
Client / Partner
      |
      v
Security API / Ingestion
      |
      +--> Request validation
      +--> Authentication / tenant authorization
      +--> Rate limiting
      |
      v
Session Context
      |
      +--> Identity
      +--> Device Intelligence
      +--> IP / Network Intelligence
      +--> Bot Detection
      +--> Behavioral Analysis
      +--> Security Events
      |
      v
Evidence Normalization
      |
      v
Risk Engine
      |
      +--> Rules / Policies
      +--> Weighted evidence
      +--> Model predictions (optional evidence)
      +--> Graph relationships
      |
      v
Decision Engine
      |
      +--> ALLOW
      +--> MONITOR
      +--> CHALLENGE
      +--> REVIEW
      +--> BLOCK
      |
      +--> Audit + Observability
      +--> Fraud Cases
```

## Development phases

### Phase 1 — Foundation hardening
- [x] Repository structure
- [x] Private security database schema
- [x] RLS and server-only database access
- [x] Environment validation
- [x] CI baseline
- [x] Type-safe input validation
- [ ] Lockfile and dependency audit
- [ ] Dependency update policy
- [ ] Secret scanning
- [ ] SBOM / dependency inventory
- [ ] Security headers and API baseline

### Phase 2 — Unified ingestion pipeline
- [ ] Session registration/lifecycle
- [ ] Request context object
- [ ] Device + IP linking during session creation
- [ ] Unified event envelope
- [ ] Event validation and normalization
- [ ] Idempotency keys
- [ ] Replay protection
- [ ] Event size/rate limits
- [ ] Persist normalized security events

### Phase 3 — Intelligence modules
- [x] Device intelligence
- [x] Identity intelligence
- [x] Network intelligence
- [x] Bot intelligence
- [x] Behavioral intelligence
- [ ] Account integrity signals
- [ ] Velocity / burst detection
- [ ] Multi-account correlation
- [ ] Disposable identity reputation
- [ ] ASN / hosting reputation
- [ ] Graph relationship builder

### Phase 4 — Risk engine v3
- [x] Weighted evidence
- [x] Confidence
- [x] Source diversity
- [x] High-signal reinforcement
- [ ] Time decay
- [ ] Signal freshness
- [ ] Correlation-aware scoring
- [ ] Policy/rule layer
- [ ] Explainable reason codes
- [ ] Calibration tests
- [ ] False-positive evaluation

### Phase 5 — Policy and decision layer
- [ ] Separate policy from scoring
- [ ] Versioned policies
- [ ] Tenant-specific policy configuration
- [ ] Safe defaults
- [ ] Challenge escalation
- [ ] Manual review workflow
- [ ] Decision replay/debugging

### Phase 6 — Observability
- [ ] Structured logging
- [ ] OpenTelemetry traces
- [ ] Metrics
- [ ] Correlation/request IDs
- [ ] Error monitoring
- [ ] Security telemetry dashboards
- [ ] Alerting

### Phase 7 — Fraud graph
- [ ] Device ↔ subject edges
- [ ] IP ↔ subject edges
- [ ] Identity ↔ subject edges
- [ ] Session ↔ device/IP edges
- [ ] Shared infrastructure detection
- [ ] Suspicious cluster scoring
- [ ] Case evidence snapshots

### Phase 8 — ML/AI evidence layer
- [ ] Feature schemas
- [ ] Model registry
- [ ] Offline evaluation
- [ ] Model versioning
- [ ] Prediction storage
- [ ] Drift monitoring
- [ ] Shadow mode
- [ ] Human/rule override
- [ ] Never allow an uncalibrated model to directly block users

### Phase 9 — Abuse controls
- [ ] Multi-dimensional rate limits
- [ ] IP / subject / session / route buckets
- [ ] Progressive penalties
- [ ] Abuse velocity detection
- [ ] Resource exhaustion protection
- [ ] Request body limits
- [ ] Timeout budgets

### Phase 10 — Security engineering
- [ ] OWASP API Security Top 10 review
- [ ] Threat-model refresh
- [ ] Dependency vulnerability scanning
- [ ] Static analysis
- [ ] Property-based testing
- [ ] Fuzzing of parsers/validators
- [ ] Least-privilege review
- [ ] Incident-response runbook

## Tool/library strategy

### Keep
- Zod — request/data validation
- Supabase JS — database access
- Vitest — unit/integration tests
- FingerprintJS — client-side device signal source where appropriate
- MaxMind GeoIP2 — IP geolocation/enrichment
- isbot — bot signal
- UA Parser — user-agent normalization
- @noble/hashes — hashing primitives

### Add after architecture integration
- OpenTelemetry — traces/metrics and service observability
- Pino — low-overhead structured server logging
- rate-limiter-flexible — distributed rate limiting / abuse controls
- fast-check — property-based testing
- Sentry Node — application error monitoring, if an external monitoring service is desired
- OPA/Rego — only when policy complexity justifies a separate policy engine

### Evaluate, do not blindly install
- AI/ML inference runtimes
- additional fingerprinting SDKs
- third-party IP reputation APIs
- CAPTCHA/challenge providers
- graph databases
- Redis/Valkey
- message queues

Every new dependency must have:
1. clear security value,
2. maintenance activity,
3. acceptable dependency footprint,
4. license compatibility,
5. test coverage,
6. failure-mode analysis,
7. a reason it cannot be implemented more safely with existing components.

## Priority order

1. Session + unified event ingestion
2. Tests around the risk engine
3. Rate limiting and abuse controls
4. Structured logging + tracing
5. Policy separation
6. Graph correlation
7. ML/AI evidence
8. Advanced fraud cases
9. Performance/load testing
10. External security review

## Important security principles

- Never store raw secrets or unnecessary raw PII.
- Never expose the Supabase server key to clients.
- Never treat VPN/proxy/Tor as proof of fraud.
- Never make AI the sole blocking authority.
- Preserve evidence and decision versions for replay/debugging.
- Keep tenant boundaries explicit in every query.
- Prefer deterministic rules for critical safety controls.
- Every security-sensitive change must be tested and verified.
