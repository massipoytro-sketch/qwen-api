# Architecture

## Core modules

1. Identity Intelligence
2. Device Intelligence
3. Network Intelligence
4. Bot and Automation Intelligence
5. Behavioral Intelligence
6. Risk Engine
7. Fraud Intelligence and Security Graph
8. Cryptography and Trust
9. AI Security Lab
10. Audit and Security Operations
11. Analytics
12. API and SDK

## Security flow

```
Client / API request
        |
        v
Identity + Device + Network + Behavior signals
        |
        v
Signal normalization
        |
        v
Rules + Risk features + Anomaly models
        |
        v
Risk decision
        |
        +--> ALLOW
        +--> MONITOR
        +--> CHALLENGE
        +--> REVIEW
        +--> BLOCK
        |
        v
Audit + analytics + feedback
```

The architecture favors explainable, composable signals and explicit decision logging.

## External boundaries

The security platform will later expose a controlled API/SDK for products such as GainiRen. The security database remains independent from the application's existing database during development.
