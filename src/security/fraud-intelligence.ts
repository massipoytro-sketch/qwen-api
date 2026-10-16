import { z } from "zod";
import type { SecurityDecision } from "./types";

const decisionRank: Record<SecurityDecision, number> = {
  ALLOW: 0,
  MONITOR: 1,
  CHALLENGE: 2,
  REVIEW: 3,
  BLOCK: 4,
};

const clamp = (value: number) => Math.max(0, Math.min(100, Math.round(value)));
const finite = (value: unknown): value is number => typeof value === "number" && Number.isFinite(value);

export type FraudGraphEdge = {
  relationship: string;
  confidence: number;
  leftType: string;
  rightType: string;
};

export type RelatedSubject = {
  subjectId: string;
  sharedResources: number;
  confidence: number;
};

const graphInputSchema = z.object({
  edgeCount: z.number().int().nonnegative(),
  nodeCount: z.number().int().nonnegative(),
  edges: z.array(z.object({
    relationship: z.string().min(1).max(100),
    confidence: z.number().finite().min(0).max(1),
    leftType: z.string().min(1).max(40),
    rightType: z.string().min(1).max(40),
  })).max(500),
  relatedSubjects: z.array(z.object({
    subjectId: z.uuid(),
    sharedResources: z.number().int().nonnegative().max(100),
    confidence: z.number().finite().min(0).max(1),
  })).max(100),
}).strict();

/**
 * Converts graph topology into bounded fraud evidence. Shared infrastructure is
 * correlation evidence, never proof by itself; multiple independent relationships
 * are required before a strong action is recommended.
 */
export function analyzeFraudGraph(rawInput: z.input<typeof graphInputSchema>) {
  const input = graphInputSchema.parse(rawInput);
  const highConfidenceEdges = input.edges.filter((edge) => edge.confidence >= 0.8);
  const relationshipCounts = new Map<string, number>();
  for (const edge of highConfidenceEdges) relationshipCounts.set(edge.relationship, (relationshipCounts.get(edge.relationship) ?? 0) + 1);

  const independentRelationshipCount = relationshipCounts.size;
  const highConfidenceRelated = input.relatedSubjects.filter((item) => item.confidence >= 0.8);
  const multiResourceSubjects = highConfidenceRelated.filter((item) => item.sharedResources >= 2);
  const broadCluster = highConfidenceRelated.filter((item) => item.sharedResources >= 3).length;

  let score = 0;
  score += Math.min(30, highConfidenceEdges.length * 8);
  score += Math.min(30, multiResourceSubjects.length * 10);
  score += Math.min(20, independentRelationshipCount * 7);
  score += Math.min(20, broadCluster * 10);
  score = clamp(score);

  const reasonCodes = [
    ...(highConfidenceEdges.length >= 2 ? ["MULTI_EDGE_CORRELATION"] : []),
    ...(independentRelationshipCount >= 2 ? ["INDEPENDENT_RELATIONSHIPS"] : []),
    ...(multiResourceSubjects.length > 0 ? ["SHARED_RESOURCE_CLUSTER"] : []),
    ...(broadCluster > 0 ? ["DENSE_FRAUD_CLUSTER"] : []),
  ];

  return {
    score,
    confidence: score === 0 ? 0.35 : Math.min(0.96, 0.55 + independentRelationshipCount * 0.08 + multiResourceSubjects.length * 0.04),
    reasonCodes,
    highConfidenceEdgeCount: highConfidenceEdges.length,
    independentRelationshipCount,
    correlatedSubjectCount: highConfidenceRelated.length,
    multiResourceSubjectCount: multiResourceSubjects.length,
    version: "fraud-graph-v2",
  };
}

export type ValueJump = {
  previousValue: number;
  currentValue: number;
  occurredAt: string;
};

const valueJumpSchema = z.object({
  previousValue: z.number().finite().nonnegative(),
  currentValue: z.number().finite().nonnegative(),
  occurredAt: z.string().datetime(),
}).strict();

export function analyzeValueJump(rawInput: z.input<typeof valueJumpSchema>) {
  const input = valueJumpSchema.parse(rawInput);
  const delta = input.currentValue - input.previousValue;
  const ratio = input.previousValue > 0 ? input.currentValue / input.previousValue : input.currentValue > 0 ? Infinity : 1;
  const absolute = Math.max(0, delta);
  const score = clamp(
    absolute >= 10000 ? 100 :
    ratio >= 20 ? 90 :
    ratio >= 10 ? 75 :
    ratio >= 5 ? 60 :
    absolute >= 1000 ? 55 :
    absolute >= 250 ? 40 : 0,
  );
  return {
    score,
    confidence: score === 0 ? 0.4 : Math.min(0.95, 0.6 + (ratio >= 10 ? 0.2 : 0) + (absolute >= 10000 ? 0.1 : 0)),
    delta,
    ratio: Number.isFinite(ratio) ? Number(ratio.toFixed(3)) : null,
    reasonCodes: [
      ...(absolute >= 1000 ? ["LARGE_VALUE_DELTA"] : []),
      ...(ratio >= 10 ? ["EXTREME_VALUE_MULTIPLIER"] : []),
      ...(absolute >= 10000 ? ["CRITICAL_VALUE_JUMP"] : []),
    ],
    version: "value-jump-v2",
  };
}

export function enforceFraudFloor(base: SecurityDecision, fraudScore: number, confidence: number): SecurityDecision {
  const score = clamp(fraudScore);
  const safeConfidence = finite(confidence) ? Math.max(0, Math.min(1, confidence)) : 0;
  const fraudDecision: SecurityDecision = score >= 90 && safeConfidence >= 0.85 ? "REVIEW" :
    score >= 70 && safeConfidence >= 0.7 ? "CHALLENGE" :
    score >= 45 ? "MONITOR" : "ALLOW";
  return decisionRank[fraudDecision] > decisionRank[base] ? fraudDecision : base;
}
