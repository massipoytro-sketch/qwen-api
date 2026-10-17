import { z } from "zod";

const nodeTypeSchema = z.enum(["subject", "device", "ip", "identity", "session"]);
const edgeSchema = z.object({
  leftType: nodeTypeSchema,
  leftId: z.uuid(),
  relationship: z.string().min(1).max(100),
  rightType: nodeTypeSchema,
  rightId: z.uuid(),
  confidence: z.number().finite().min(0).max(1),
}).strict();

const signalSchema = z.object({
  signalName: z.string().min(1).max(100),
  score: z.number().finite().min(0).max(100),
  confidence: z.number().finite().min(0).max(1).nullable(),
}).strict();

const inputSchema = z.object({
  subjectId: z.uuid(),
  edges: z.array(edgeSchema).max(500),
  signals: z.array(signalSchema).max(256),
  truncated: z.boolean().default(false),
}).strict();

type NodeType = z.infer<typeof nodeTypeSchema>;
type Edge = z.infer<typeof edgeSchema>;
type Signal = z.infer<typeof signalSchema>;

type GraphNode = { type: NodeType; id: string };
type AdjacentEdge = { node: GraphNode; edge: Edge };
type SearchState = {
  key: string;
  node: GraphNode;
  depth: number;
  confidence: number;
  seen: Set<string>;
  nodeTypes: NodeType[];
  relationships: string[];
};

const clamp = (value: number) => Math.max(0, Math.min(100, Math.round(value)));
const nodeKey = (node: GraphNode) => `${node.type}:${node.id}`;
const edgeConfidence = (edge: Edge) => Math.max(0, Math.min(1, edge.confidence));

function signalCategory(signalName: string): string | null {
  const name = signalName.toLowerCase();
  if (name.includes("honey") || name.includes("canary") || name.includes("deception")) return "deception";
  if (name.includes("value_jump") || name.includes("value_delta") || name.includes("value_state")) return "value";
  if (name.includes("withdraw") || name.includes("payout") || name.includes("wallet") || name.includes("transaction") || name.includes("transfer") || name.includes("redeem")) return "transaction";
  if (name.includes("account_takeover") || name.includes("concurrent_session") || name.includes("credential") || name.includes("identity") || name.includes("subject_status")) return "identity";
  if (name.includes("device") || name.includes("fingerprint")) return "device";
  if (name.includes("network") || name.includes("impossible_travel") || name.includes("ip_reputation")) return "network";
  if (name.includes("bot") || name.includes("velocity")) return "automation";
  if (name.includes("behavior") || name.includes("anomaly")) return "behavior";
  return null;
}

/**
 * Deterministic, bounded attack-path analysis over a tenant-scoped graph snapshot.
 * It reports correlated paths as evidence; it never makes a final BLOCK decision.
 */
export function analyzeAttackPath(rawInput: {
  subjectId: string;
  edges: Edge[];
  signals: Signal[];
  truncated?: boolean;
}) {
  const input = inputSchema.parse({
    subjectId: rawInput.subjectId,
    edges: rawInput.edges,
    signals: rawInput.signals,
    truncated: rawInput.truncated ?? false,
  });

  const adjacency = new Map<string, AdjacentEdge[]>();
  const nodes = new Map<string, GraphNode>();
  const addAdjacency = (from: GraphNode, to: GraphNode, edge: Edge) => {
    const key = nodeKey(from);
    const list = adjacency.get(key) ?? [];
    list.push({ node: to, edge });
    adjacency.set(key, list);
    nodes.set(nodeKey(from), from);
    nodes.set(nodeKey(to), to);
  };

  for (const edge of input.edges) {
    const left = { type: edge.leftType, id: edge.leftId };
    const right = { type: edge.rightType, id: edge.rightId };
    if (nodeKey(left) === nodeKey(right)) continue;
    addAdjacency(left, right, edge);
    addAdjacency(right, left, edge);
  }

  const start: GraphNode = { type: "subject", id: input.subjectId };
  const startKey = nodeKey(start);
  nodes.set(startKey, start);

  const queue: SearchState[] = [{
    key: startKey,
    node: start,
    depth: 0,
    confidence: 1,
    seen: new Set([startKey]),
    nodeTypes: ["subject"],
    relationships: [],
  }];
  const best = new Map<string, { depth: number; confidence: number }>([[startKey, { depth: 0, confidence: 1 }]]);
  const subjectPaths = new Map<string, { depth: number; confidence: number; nodeTypes: NodeType[]; relationships: string[] }>();
  let visitedStates = 0;
  let maxPathDepth = 0;
  const maxDepth = 4;
  const maxStates = 600;

  while (queue.length > 0 && visitedStates < maxStates) {
    const current = queue.shift();
    if (!current) break;
    visitedStates += 1;
    if (current.depth >= maxDepth) continue;

    for (const adjacent of adjacency.get(current.key) ?? []) {
      const nextKey = nodeKey(adjacent.node);
      if (current.seen.has(nextKey)) continue;

      const nextDepth = current.depth + 1;
      const nextConfidence = current.confidence * edgeConfidence(adjacent.edge);
      const prior = best.get(nextKey);
      if (prior && (prior.depth < nextDepth || (prior.depth === nextDepth && prior.confidence >= nextConfidence))) continue;

      best.set(nextKey, { depth: nextDepth, confidence: nextConfidence });
      maxPathDepth = Math.max(maxPathDepth, nextDepth);
      const nodeTypes = [...current.nodeTypes, adjacent.node.type];
      const relationships = [...current.relationships, adjacent.edge.relationship].slice(-maxDepth);
      if (adjacent.node.type === "subject" && adjacent.node.id !== input.subjectId) {
        const priorSubject = subjectPaths.get(adjacent.node.id);
        if (!priorSubject || nextDepth < priorSubject.depth || nextConfidence > priorSubject.confidence) {
          subjectPaths.set(adjacent.node.id, { depth: nextDepth, confidence: nextConfidence, nodeTypes, relationships });
        }
      }
      queue.push({
        key: nextKey,
        node: adjacent.node,
        depth: nextDepth,
        confidence: nextConfidence,
        seen: new Set([...current.seen, nextKey]),
        nodeTypes,
        relationships,
      });
      if (queue.length >= maxStates) break;
    }
  }

  const directEdges = input.edges.filter((edge) =>
    (edge.leftType === "subject" && edge.leftId === input.subjectId) ||
    (edge.rightType === "subject" && edge.rightId === input.subjectId),
  );
  const directResourceTypes = new Set(directEdges
    .filter((edge) => edge.confidence >= 0.75)
    .flatMap((edge) => [edge.leftType, edge.rightType])
    .filter((type) => type !== "subject"));
  const highConfidenceEdgeCount = input.edges.filter((edge) => edge.confidence >= 0.8).length;
  const relatedSubjectCount = subjectPaths.size;
  const graphScore = clamp(Math.min(
    40,
    relatedSubjectCount * 10 + directResourceTypes.size * 5 + Math.min(10, highConfidenceEdgeCount * 2),
  ));

  const categoryScores = new Map<string, number>();
  const categoryConfidences = new Map<string, number>();
  for (const signal of input.signals) {
    if (signal.score < 30) continue;
    const category = signalCategory(signal.signalName);
    if (!category) continue;
    categoryScores.set(category, Math.max(categoryScores.get(category) ?? 0, signal.score));
    if (signal.confidence !== null) {
      categoryConfidences.set(category, Math.max(categoryConfidences.get(category) ?? 0, signal.confidence));
    }
  }

  const activeCategories = new Set(categoryScores.keys());
  const maximumSignalScore = Math.max(0, ...categoryScores.values());
  const signalContribution = activeCategories.size >= 2
    ? Math.min(40, (activeCategories.size - 1) * 7 + Math.round(maximumSignalScore * 0.15))
    : 0;

  const reasonCodes: string[] = [];
  const pathPatterns: string[] = [];
  let synergy = 0;

  if (relatedSubjectCount > 0 && directResourceTypes.size >= 2) {
    reasonCodes.push("ATTACK_PATH_SHARED_RESOURCES");
    pathPatterns.push("CROSS_SUBJECT_RESOURCE_PATH");
    synergy += 8;
  }
  if (relatedSubjectCount >= 2 && directResourceTypes.size >= 2) {
    reasonCodes.push("ATTACK_PATH_CROSS_ACCOUNT_CLUSTER");
    pathPatterns.push("CROSS_ACCOUNT_CLUSTER");
    synergy += 10;
  }
  if (activeCategories.has("identity") && activeCategories.has("device") && activeCategories.has("network")) {
    reasonCodes.push("ATTACK_PATH_ACCOUNT_TAKEOVER_CHAIN");
    pathPatterns.push("ACCOUNT_TAKEOVER_CHAIN");
    synergy += 12;
  }
  if (activeCategories.has("automation") && activeCategories.has("value") &&
      (activeCategories.has("network") || relatedSubjectCount > 0 || activeCategories.has("identity"))) {
    reasonCodes.push("ATTACK_PATH_AUTOMATED_VALUE_ABUSE");
    pathPatterns.push("AUTOMATED_VALUE_ABUSE_CHAIN");
    synergy += 16;
  }
  if (activeCategories.has("value") && activeCategories.has("transaction") &&
      (graphScore >= 10 || activeCategories.has("identity") || activeCategories.has("automation"))) {
    reasonCodes.push("ATTACK_PATH_VALUE_TO_TRANSACTION");
    pathPatterns.push("VALUE_TO_TRANSACTION_CHAIN");
    synergy += 18;
  }
  if (activeCategories.has("deception") && activeCategories.size >= 2) {
    reasonCodes.push("ATTACK_PATH_DECEPTION_CORROBORATION");
    pathPatterns.push("DECEPTION_CORROBORATED_PATH");
    synergy += 12;
  }
  if (activeCategories.size >= 4) {
    reasonCodes.push("ATTACK_PATH_MULTI_STAGE_SEQUENCE");
    pathPatterns.push("MULTI_STAGE_ATTACK_SEQUENCE");
    synergy += 8;
  }
  if (relatedSubjectCount > 0 && activeCategories.size >= 2) {
    reasonCodes.push("ATTACK_PATH_GRAPH_AND_SIGNAL_CORROBORATION");
    synergy += 8;
  }

  const score = clamp(graphScore + signalContribution + synergy);
  const meanSignalConfidence = categoryConfidences.size
    ? [...categoryConfidences.values()].reduce((sum, value) => sum + value, 0) / categoryConfidences.size
    : 0.45;
  const confidence = score === 0
    ? 0.35
    : Math.min(0.97, 0.5 + Math.min(0.25, activeCategories.size * 0.05) +
      Math.min(0.15, relatedSubjectCount * 0.05) + meanSignalConfidence * 0.1);

  const examplePaths = [...subjectPaths.values()]
    .sort((a, b) => b.confidence - a.confidence || a.depth - b.depth)
    .slice(0, 5)
    .map((path) => ({
      depth: path.depth,
      confidence: Number(path.confidence.toFixed(4)),
      nodeTypes: path.nodeTypes,
      relationships: path.relationships,
    }));

  return {
    score,
    confidence: Number(confidence.toFixed(4)),
    reasonCodes: [...new Set(reasonCodes)],
    pathPatterns: [...new Set(pathPatterns)],
    relatedSubjectCount,
    directResourceTypes: [...directResourceTypes].sort(),
    highConfidenceEdgeCount,
    examinedNodeCount: nodes.size,
    examinedEdgeCount: input.edges.length,
    maxPathDepth,
    paths: examplePaths,
    truncated: input.truncated || visitedStates >= maxStates,
    version: "attack-path-v1" as const,
  };
}
