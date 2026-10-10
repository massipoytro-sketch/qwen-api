# GainiRen Defense-in-Depth Architecture

## Goal

Protect the GainiRen public site, administrator panel, application servers, internal APIs and PostgreSQL/Supabase data with multiple independent controls. No single detector is treated as a complete defense.

## Important design correction

The proposed "many firewalls" model is implemented as independent security layers rather than simply chaining identical firewalls:

1. Edge/WAF layer — blocks obvious malicious traffic, abusive paths and protocol anomalies.
2. API gateway — authentication, tenant authorization, body limits, CORS, request IDs and rate limits.
3. Application security engine — bot, device, network, behavior, velocity, value and graph evidence.
4. Policy/decision layer — deterministic ALLOW/MONITOR/CHALLENGE/REVIEW/BLOCK decisions.
5. Admin security layer — separate administrator authentication, step-up authentication, session restrictions and privileged-action audit.
6. Workload/server layer — least privilege, isolated services, restricted egress and secret rotation.
7. Database gateway/network layer — private database networking, restricted roles, connection controls and no public database exposure.
8. Data layer — RLS, tenant isolation, encryption at rest/in transit, immutable audit evidence and backups.

An attacker should have to defeat independent controls rather than a single wall.

## Deception / decoy database

A decoy database (HoneyDB) can be useful as an intrusion-detection trap, but it must never be a second copy of the real production database.

Rules:

- It contains synthetic, clearly non-production records only.
- It has separate credentials, network boundaries and storage.
- Production secrets, service-role keys, password hashes and real personal data are never copied into it.
- No production application path depends on the decoy database.
- Any access attempt is a high-confidence security signal.
- The decoy can expose harmless fake records designed to identify automated enumeration.
- Alerts record the event, source context, request ID and timestamp without storing unnecessary secrets.

The real database remains behind a private network boundary and a separate credential set. The decoy is a sensor, not a fallback database.

## Adaptive containment

When confidence is high, the defense orchestrator may progressively contain a suspicious principal:

- revoke the affected session;
- require a challenge for the subject;
- temporarily block the subject/device/IP combination;
- invalidate affected API credentials;
- isolate a compromised workload from sensitive network destinations;
- disable privileged operations;
- rotate affected credentials;
- preserve forensic evidence;
- notify administrators;
- require explicit administrator approval before destructive remediation.

Recovery is defensive control restoration. The system must never retaliate against the source or attempt unauthorized access to another system.

## Critical-path principle

Optional analytics and AI may fail without taking down the primary security decision engine. Deterministic controls remain authoritative.

## Database protection

The production database should be treated as the highest-trust zone:

- never expose the PostgreSQL listener directly to the public internet;
- use private networking/firewall rules;
- separate runtime roles from migration/admin roles;
- keep service-role credentials server-side only;
- enable RLS and tenant-scoped queries;
- use encrypted connections;
- maintain tested backups and point-in-time recovery;
- monitor unusual authentication, query and connection behavior;
- audit privileged operations.

## Administrator panel

The admin plane is a separate trust boundary. Required controls include:

- strong authentication and MFA/step-up authentication;
- short privileged sessions;
- role-based access control;
- explicit confirmation for destructive actions;
- immutable audit records;
- anomaly detection for administrator behavior;
- emergency account/session revocation;
- no direct browser access to database service-role credentials.

## Security Query Console

The future database query window should be a read-only security console by default. It should expose approved parameterized queries, pagination and result limits. Arbitrary destructive SQL (`DROP`, `DELETE`, `UPDATE`, `INSERT`, privilege changes, extensions, role changes) must not be exposed through the browser.

For advanced operators, privileged SQL access should remain an out-of-band administrative operation with separate credentials and auditing.

## Red-team test plan

The GitHub Actions red-team workflow should test only owned/authorized GainiRen environments and remain bounded. Coverage should include:

- authentication failures;
- wrong-tenant access;
- session/subject mismatch;
- replay/idempotency;
- rate-limit bursts;
- oversized and malformed requests;
- value jumps;
- bot-like timing;
- behavioral anomalies;
- stale anomaly handling;
- policy bypass attempts;
- outbox retry/idempotency;
- deception-zone access detection;
- administrator authorization boundaries;
- database exposure checks;
- recovery/containment behavior.

A passing test means the expected control fired and produced the expected evidence. It does not prove the platform is invulnerable.
