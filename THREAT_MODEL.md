# Threat Model

## Initial threat classes

- Credential abuse and account takeover
- Automated account creation
- Multi-account and account-farm behavior
- Fake or duplicated device identities
- Proxy, VPN, Tor, and datacenter-origin abuse
- Bot and scripted interaction
- Referral and reward abuse
- Suspicious withdrawals and financial abuse
- Replay and request-tampering attacks
- API abuse and rate-limit bypass
- Privilege escalation
- Data leakage and secret exposure
- Internal administrative misuse

## Trust assumptions

No client-side value is authoritative for security-sensitive decisions.

Server-observed data, signed requests, database constraints, authorization rules, and independently verified signals are preferred.

## Non-goals

This project will not rely on invasive browser privacy bypasses or custom cryptographic primitives. Standard audited cryptographic primitives and privacy-aware collection are required.
