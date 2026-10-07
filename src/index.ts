export const PROJECT_NAME = "GainiRen Security" as const;
export const SECURITY_DECISIONS = [
  "ALLOW",
  "MONITOR",
  "CHALLENGE",
  "REVIEW",
  "BLOCK",
] as const;

export type SecurityDecision = (typeof SECURITY_DECISIONS)[number];
