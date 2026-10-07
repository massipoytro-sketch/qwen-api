export const SECURITY_DECISIONS = [
  "ALLOW",
  "MONITOR",
  "CHALLENGE",
  "REVIEW",
  "BLOCK",
] as const;

export type SecurityDecision = (typeof SECURITY_DECISIONS)[number];

export type SecurityCheckInput = {
  tenantId: string;
  subjectId?: string;
  sessionId?: string;
  requestId?: string;
};

export type SecurityCheckResult = {
  decision: SecurityDecision;
  score: number;
  riskLevel: "unknown" | "low" | "medium" | "high" | "critical";
  assessmentId?: string;
};
