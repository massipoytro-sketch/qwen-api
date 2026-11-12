import { z } from "zod";
import { supabase } from "../db/supabase";

const nodeTypeSchema = z.enum(["subject", "device", "ip", "identity", "session"]);
const edgeSchema = z.object({
  tenantId: z.uuid(),
  leftType: nodeTypeSchema,
  leftId: z.uuid(),
  relationship: z.string().min(1).max(100),
  rightType: nodeTypeSchema,
  rightId: z.uuid(),
  confidence: z.number().min(0).max(1).default(1),
  metadata: z.record(z.string(), z.unknown()).default({}),
});
type NodeType = z.infer<typeof nodeTypeSchema>;
type GraphNode = { type: NodeType; id: string };
type GraphEdge = {
  id: string;
  left_type: NodeType;
  left_id: string;
  relationship: string;
  right_type: NodeType;
  right_id: string;
  confidence: number | string | null;
  metadata?: Record<string, unknown>;
};

const graphNodeKey = (node: GraphNode) => `${node.type}:${node.id}`;

export async function upsertGraphEdge(rawInput: z.input<typeof edgeSchema>) {
  const input = edgeSchema.parse(rawInput);
  if (input.leftType === input.rightType && input.leftId === input.rightId) {
    throw new Error("GRAPH_SELF_EDGE");
  }

  const result = await supabase.schema("security").from("graph_edges").upsert({
    tenant_id: input.tenantId,
    left_type: input.leftType,
    left_id: input.leftId,
    relationship: input.relationship,
    right_type: input.rightType,
    right_id: input.rightId,
    confidence: input.confidence,
    metadata: input.metadata,
    last_seen_at: new Date().toISOString(),
  }, {
    onConflict: "tenant_id,left_type,left_id,relationship,right_type,right_id",
  }).select("id,left_type,left_id,relationship,right_type,right_id,confidence").single();

  if (result.error) throw result.error;
  return result.data;
}

export async function buildSubjectGraph(rawInput: { tenantId: string; subjectId: string; limit?: number }) {
  const input = z.object({
    tenantId: z.uuid(),
    subjectId: z.uuid(),
    limit: z.number().int().min(1).max(200).default(100),
  }).parse(rawInput);

  const edges = await supabase.schema("security").from("graph_edges")
    .select("id,left_type,left_id,relationship,right_type,right_id,confidence,metadata")
    .eq("tenant_id", input.tenantId)
    .or(`and(left_type.eq.subject,left_id.eq.${input.subjectId}),and(right_type.eq.subject,right_id.eq.${input.subjectId})`)
    .order("confidence", { ascending: false })
    .limit(input.limit);

  if (edges.error) throw edges.error;

  const nodes = new Map<string, GraphNode>();
  nodes.set(`subject:${input.subjectId}`, { type: "subject", id: input.subjectId });
  for (const edge of edges.data ?? []) {
    nodes.set(`${edge.left_type}:${edge.left_id}`, { type: edge.left_type as NodeType, id: edge.left_id });
    nodes.set(`${edge.right_type}:${edge.right_id}`, { type: edge.right_type as NodeType, id: edge.right_id });
  }

  return {
    subjectId: input.subjectId,
    nodeCount: nodes.size,
    edgeCount: edges.data?.length ?? 0,
    nodes: [...nodes.values()],
    edges: (edges.data ?? []) as GraphEdge[],
  };
}

/**
 * Loads a bounded, tenant-scoped graph around a subject. Traversal limits keep
 * graph expansion predictable and ensure every database query is tenant-filtered.
 */
export async function buildBoundedSubjectGraph(rawInput: {
  tenantId: string;
  subjectId: string;
  maxDepth?: number;
  maxEdges?: number;
}) {
  const input = z.object({
    tenantId: z.uuid(),
    subjectId: z.uuid(),
    maxDepth: z.number().int().min(1).max(4).default(3),
    maxEdges: z.number().int().min(1).max(500).default(250),
  }).strict().parse(rawInput);

  const edgeMap = new Map<string, GraphEdge>();
  const nodeMap = new Map<string, GraphNode>();
  const processed = new Set<string>();
  let frontier: GraphNode[] = [{ type: "subject", id: input.subjectId }];
  let truncated = false;
  nodeMap.set(graphNodeKey(frontier[0]!), frontier[0]!);

  for (let depth = 0; depth < input.maxDepth && frontier.length > 0; depth += 1) {
    const batch = frontier.slice(0, 24);
    if (batch.length < frontier.length) truncated = true;
    for (const node of batch) processed.add(graphNodeKey(node));
    const disjunction = batch.flatMap((node) => [
      `and(left_type.eq.${node.type},left_id.eq.${node.id})`,
      `and(right_type.eq.${node.type},right_id.eq.${node.id})`,
    ]).join(",");
    const remaining = input.maxEdges - edgeMap.size;
    if (remaining <= 0) {
      truncated = true;
      break;
    }

    const batchLimit = Math.min(150, remaining);
    const response = await supabase.schema("security").from("graph_edges")
      .select("id,left_type,left_id,relationship,right_type,right_id,confidence,metadata,last_seen_at")
      .eq("tenant_id", input.tenantId)
      .or(disjunction)
      .order("last_seen_at", { ascending: false })
      .limit(batchLimit);

    if (response.error) throw response.error;
    if ((response.data?.length ?? 0) >= batchLimit) truncated = true;

    const next = new Map<string, GraphNode>();
    for (const rawEdge of response.data ?? []) {
      const edge = {
        ...rawEdge,
        left_type: rawEdge.left_type as NodeType,
        right_type: rawEdge.right_type as NodeType,
        confidence: rawEdge.confidence === null ? 0 : Number(rawEdge.confidence),
      } as GraphEdge;
      edgeMap.set(edge.id, edge);
      const left = { type: edge.left_type, id: edge.left_id };
      const right = { type: edge.right_type, id: edge.right_id };
      nodeMap.set(graphNodeKey(left), left);
      nodeMap.set(graphNodeKey(right), right);
      if (!processed.has(graphNodeKey(left))) next.set(graphNodeKey(left), left);
      if (!processed.has(graphNodeKey(right))) next.set(graphNodeKey(right), right);
    }
    frontier = [...next.values()];
    if (edgeMap.size >= input.maxEdges) {
      truncated = true;
      break;
    }
  }

  return {
    subjectId: input.subjectId,
    nodeCount: nodeMap.size,
    edgeCount: edgeMap.size,
    nodes: [...nodeMap.values()],
    edges: [...edgeMap.values()],
    maxDepth: input.maxDepth,
    truncated,
  };
}

export async function findRelatedSubjects(rawInput: { tenantId: string; subjectId: string; limit?: number }) {
  const input = z.object({
    tenantId: z.uuid(),
    subjectId: z.uuid(),
    limit: z.number().int().min(1).max(100).default(50),
  }).parse(rawInput);

  const graph = await buildSubjectGraph(input);
  const resources = graph.nodes.filter((node) => node.type !== "subject");
  const related = new Map<string, { subjectId: string; sharedResources: number; confidence: number }>();

  for (const resource of resources) {
    const result = await supabase.schema("security").from("graph_edges")
      .select("left_type,left_id,right_type,right_id,relationship,confidence")
      .eq("tenant_id", input.tenantId)
      .or(`and(left_type.eq.${resource.type},left_id.eq.${resource.id}),and(right_type.eq.${resource.type},right_id.eq.${resource.id})`)
      .limit(200);

    if (result.error) throw result.error;

    for (const edge of result.data ?? []) {
      const subjectId =
        edge.left_type === "subject" ? edge.left_id :
        edge.right_type === "subject" ? edge.right_id : null;
      if (!subjectId || subjectId === input.subjectId) continue;

      const current = related.get(subjectId) ?? {
        subjectId, sharedResources: 0, confidence: 0,
      };
      current.sharedResources += 1;
      current.confidence = Math.max(current.confidence, Number(edge.confidence ?? 0));
      related.set(subjectId, current);
    }
  }

  return [...related.values()]
    .sort((a, b) => b.sharedResources - a.sharedResources || b.confidence - a.confidence)
    .slice(0, input.limit);
}

function relatedSubjectsFromBoundedGraph(
  graph: Awaited<ReturnType<typeof buildBoundedSubjectGraph>>,
  subjectId: string,
) {
  const directResources = new Map<string, number>();
  for (const edge of graph.edges) {
    if (edge.left_type === "subject" && edge.left_id === subjectId && edge.right_type !== "subject") {
      directResources.set(`${edge.right_type}:${edge.right_id}`, Number(edge.confidence ?? 0));
    } else if (edge.right_type === "subject" && edge.right_id === subjectId && edge.left_type !== "subject") {
      directResources.set(`${edge.left_type}:${edge.left_id}`, Number(edge.confidence ?? 0));
    }
  }

  const related = new Map<string, { resources: Set<string>; confidence: number }>();
  for (const edge of graph.edges) {
    let resourceKey: string | null = null;
    let otherSubjectId: string | null = null;
    if (edge.left_type === "subject" && edge.left_id !== subjectId && edge.right_type !== "subject") {
      resourceKey = `${edge.right_type}:${edge.right_id}`;
      otherSubjectId = edge.left_id;
    } else if (edge.right_type === "subject" && edge.right_id !== subjectId && edge.left_type !== "subject") {
      resourceKey = `${edge.left_type}:${edge.left_id}`;
      otherSubjectId = edge.right_id;
    }
    if (!resourceKey || !otherSubjectId || !directResources.has(resourceKey)) continue;
    const current = related.get(otherSubjectId) ?? { resources: new Set<string>(), confidence: 0 };
    current.resources.add(resourceKey);
    current.confidence = Math.max(
      current.confidence,
      Math.min(directResources.get(resourceKey) ?? 0, Number(edge.confidence ?? 0)),
    );
    related.set(otherSubjectId, current);
  }

  return [...related.entries()]
    .map(([relatedSubjectId, value]) => ({
      subjectId: relatedSubjectId,
      sharedResources: value.resources.size,
      confidence: value.confidence,
    }))
    .sort((a, b) => b.sharedResources - a.sharedResources || b.confidence - a.confidence)
    .slice(0, 50);
}

export async function scoreSubjectConnections(rawInput: { tenantId: string; subjectId: string }) {
  const parsed = z.object({ tenantId: z.uuid(), subjectId: z.uuid() }).strict().parse(rawInput);
  const graph = await buildBoundedSubjectGraph(parsed);
  const directEdges = graph.edges.filter((edge) =>
    (edge.left_type === "subject" && edge.left_id === parsed.subjectId) ||
    (edge.right_type === "subject" && edge.right_id === parsed.subjectId),
  );
  const riskyRelationships = new Set([
    "uses_device",
    "uses_ip",
    "owns_identity",
    "linked_session",
    "shared_device",
    "shared_ip",
    "shared_identity",
  ]);
  const highConfidence = directEdges.filter((edge) => Number(edge.confidence ?? 0) >= 0.8);
  const risky = highConfidence.filter((edge) => riskyRelationships.has(edge.relationship));
  const relatedSubjects = relatedSubjectsFromBoundedGraph(graph, parsed.subjectId);
  const directNodeCount = new Set(
    directEdges.flatMap((edge) => [
      `${edge.left_type}:${edge.left_id}`,
      `${edge.right_type}:${edge.right_id}`,
    ]),
  ).size;

  const connectionScore = Math.min(
    100,
    risky.length * 15 +
      Math.max(0, directNodeCount - 2) * 3 +
      relatedSubjects.reduce((sum, item) => sum + Math.min(20, item.sharedResources * 10), 0),
  );

  return {
    connectionScore,
    connected: directEdges.length > 0,
    riskyConnectionCount: risky.length,
    relatedSubjectCount: relatedSubjects.length,
    relatedSubjects,
    graph,
  };
}
