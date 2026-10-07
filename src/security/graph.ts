import { z } from "zod";
import { supabase } from "../db/supabase";

const edgeSchema = z.object({
  tenantId: z.uuid(),
  leftType: z.enum(["subject","device","ip","identity","session"]),
  leftId: z.uuid(),
  relationship: z.string().min(1).max(100),
  rightType: z.enum(["subject","device","ip","identity","session"]),
  rightId: z.uuid(),
  confidence: z.number().min(0).max(1).default(1),
  metadata: z.record(z.string(), z.unknown()).default({}),
});

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

  const nodes = new Map<string, { type: string; id: string }>();
  for (const edge of edges.data ?? []) {
    nodes.set(`${edge.left_type}:${edge.left_id}`, { type: edge.left_type, id: edge.left_id });
    nodes.set(`${edge.right_type}:${edge.right_id}`, { type: edge.right_type, id: edge.right_id });
  }

  return {
    subjectId: input.subjectId,
    nodeCount: nodes.size,
    edgeCount: edges.data?.length ?? 0,
    nodes: [...nodes.values()],
    edges: edges.data ?? [],
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

export async function scoreSubjectConnections(rawInput: { tenantId: string; subjectId: string }) {
  const graph = await buildSubjectGraph(rawInput);
  const riskyRelationships = new Set(["shared_device","shared_ip","shared_identity","linked_session"]);
  const highConfidence = graph.edges.filter((edge) => Number(edge.confidence ?? 0) >= 0.8);
  const risky = highConfidence.filter((edge) => riskyRelationships.has(edge.relationship));

  const relatedSubjects = await findRelatedSubjects(rawInput);
  const connectionScore = Math.min(
    100,
    risky.length * 15 +
      Math.max(0, graph.nodeCount - 2) * 3 +
      relatedSubjects.length * 10,
  );
  return {
    connectionScore,
    connected: graph.edgeCount > 0,
    riskyConnectionCount: risky.length,
    relatedSubjectCount: relatedSubjects.length,
    relatedSubjects,
    graph,
  };
}
