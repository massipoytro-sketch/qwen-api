import { z } from "zod";
import type { SecurityDecision } from "./types";

const decisionRank: Record<SecurityDecision, number> = {
  ALLOW: 0, MONITOR: 1, CHALLENGE: 2, REVIEW: 3, BLOCK: 4,
};
const clamp = (value: number) => Math.max(0, Math.min(100, Math.round(value)));
const finite = (value: unknown): value is number => typeof value === "number" && Number.isFinite(value);

export type FraudGraphEdge = { relationship: string; confidence: number; leftType: string; rightType: string };
export type RelatedSubject = { subjectId: string; sharedResources: number; confidence: number };

const graphInputSchema = z.object({
  edgeCount: z.number().int().min(0).max(500),
  nodeCount: z.number().int().min(0).max(1000),
  edges: z.array(z.object({
    relationship: z.string().min(1).max(100),
    confidence: z.number().finite().min(0).max(1),
    leftType: z.string().min(1).max(40),
    rightType: z.string().min(1).max(40),
  }).strict()).max(500),
  relatedSubjects: z.array(z.object({
    subjectId: z.uuid(),
    sharedResources: z.number().int().min(0).max(100),
    confidence: z.number().finite().min(0).max(1),
  }).strict()).max(100),
}).strict();

/** Shared infrastructure is correlation evidence, not proof of fraud. */
export function analyzeFraudGraph(rawInput: z.input<typeof graphInputSchema>) {
  const input = graphInputSchema.parse(rawInput);
  const highConfidenceEdges = input.edges.filter((edge) => edge.confidence >= 0.8);
  const resourceClass = (relationship: string, leftType: string, rightType: string) => {
    const normalized = relationship.toLowerCase();
    if (normalized.includes("device") || leftType === "device" || rightType === "device") return "device";
    if (normalized.includes("ip") || normalized.includes("network") || leftType === "ip" || rightType === "ip") return "network";
    if (normalized.includes("identity") || normalized.includes("email") || leftType === "identity" || rightType === "identity") return "identity";
    if (normalized.includes("session") || leftType === "session" || rightType === "session") return "session";
    return "other";
  };
  const independentClasses = new Set(
    highConfidenceEdges.map((edge) => resourceClass(edge.relationship, edge.leftType, edge.rightType)).filter((value) => value !== "other"),
  );
  const highConfidenceRelated = input.relatedSubjects.filter((item) => item.confidence >= 0.8);
  const multiResourceSubjects = highConfidenceRelated.filter((item) => item.sharedResources >= 2);
  const broadCluster = highConfidenceRelated.filter((item) => item.sharedResources >= 3).length;

  let score = 0;
  score += Math.min(25, highConfidenceEdges.length * 5);
  score += Math.min(35, multiResourceSubjects.length * 10);
  score += Math.min(20, independentClasses.size * 10);
  score += Math.min(20, broadCluster * 10);
  score = clamp(score);

  const reasonCodes = [
    ...(highConfidenceEdges.length >= 2 ? ["MULTI_EDGE_CORRELATION"] : []),
    ...(independentClasses.size >= 2 ? ["INDEPENDENT_RESOURCE_CLASSES"] : []),
    ...(multiResourceSubjects.length > 0 ? ["SHARED_RESOURCE_CLUSTER"] : []),
    ...(broadCluster > 0 ? ["DENSE_FRAUD_CLUSTER"] : []),
  ];
  return {
    score,
    confidence: score === 0 ? 0.35 : Math.min(0.96, 0.55 + independentClasses.size * 0.08 + multiResourceSubjects.length * 0.04),
    reasonCodes,
    highConfidenceEdgeCount: highConfidenceEdges.length,
    independentRelationshipCount: independentClasses.size,
    correlatedSubjectCount: highConfidenceRelated.length,
    multiResourceSubjectCount: multiResourceSubjects.length,
    version: "fraud-graph-v3",
  };
}

const valueJumpSchema = z.object({
  previousValue: z.number().finite().min(0),
  currentValue: z.number().finite().min(0),
  occurredAt: z.string().datetime(),
}).strict();

export function analyzeValueJump(rawInput: z.input<typeof valueJumpSchema>) {
  const input = valueJumpSchema.parse(rawInput);
  const delta = input.currentValue - input.previousValue;
  const increase = Math.max(0, delta);
  const ratio = input.previousValue > 0 ? input.currentValue / input.previousValue : input.currentValue > 0 ? Number.POSITIVE_INFINITY : 1;
  // Multiplier jumps need a non-trivial absolute delta so 0→1 is not a critical event.
  const score = clamp(
    increase >= 10_000 ? 100 :
    increase >= 1_000 ? 85 :
    increase >= 500 && ratio >= 10 ? 75 :
    increase >= 250 && ratio >= 10 ? 65 :
    increase >= 500 ? 55 :
    increase >= 250 ? 40 :
    increase >= 100 && ratio >= 10 ? 30 : 0,
  );
  return {
    score,
    confidence: score === 0 ? 0.4 : Math.min(0.95, 0.6 + (increase >= 1_000 && ratio >= 10 ? 0.15 : 0) + (increase >= 10_000 ? 0.1 : 0)),
    delta,
    ratio: Number.isFinite(ratio) ? Number(ratio.toFixed(3)) : null,
    reasonCodes: [
      ...(increase >= 500 ? ["LARGE_VALUE_DELTA"] : []),
      ...(increase >= 250 && ratio >= 10 ? ["EXTREME_VALUE_MULTIPLIER"] : []),
      ...(increase >= 10_000 ? ["CRITICAL_VALUE_JUMP"] : []),
    ],
    version: "value-jump-v3",
  };
}

/** Applies a fraud escalation floor. This helper can never produce BLOCK. */
export function enforceFraudFloor(base: SecurityDecision, fraudScore: number, confidence: number): SecurityDecision {
  const score = finite(fraudScore) ? clamp(fraudScore) : 0;
  const safeConfidence = finite(confidence) ? Math.max(0, Math.min(1, confidence)) : 0;
  const candidate: SecurityDecision =
    score >= 90 && safeConfidence >= 0.85 ? "REVIEW" :
    score >= 70 && safeConfidence >= 0.7 ? "CHALLENGE" :
    score >= 45 ? "MONITOR" : "ALLOW";
  return decisionRank[candidate] > decisionRank[base] ? candidate : base;
}
