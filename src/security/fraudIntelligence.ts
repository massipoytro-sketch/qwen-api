import { createHash } from "node:crypto";
import { z } from "zod";
import { supabase } from "../db/supabase";

const inputSchema = z.object({
  tenantId: z.uuid(),
  subjectId: z.uuid(),
  maxEdges: z.number().int().min(1).max(2000).default(1000),
  maxSubjects: z.number().int().min(2).max(100).default(50),
});

type Edge = {
  left_type: string;
  left_id: string;
  relationship: string;
  right_type: string;
  right_id: string;
  confidence: number | null;
};

function clusterKey(subjectIds: string[]): string {
  const canonical = [...new Set(subjectIds)].sort().join(",");
  return createHash("sha256").update(canonical, "utf8").digest("hex").slice(0, 48);
}

export async function analyzeFraudNetwork(rawInput: z.input<typeof inputSchema>) {
  const input = inputSchema.parse(rawInput);
  const result = await supabase.schema("security").from("graph_edges")
    .select("left_type,left_id,relationship,right_type,right_id,confidence")
    .eq("tenant_id", input.tenantId)
    .or(`and(left_type.eq.subject,left_id.eq.${input.subjectId}),and(right_type.eq.subject,right_id.eq.${input.subjectId})`)
    .order("confidence", { ascending: false })
    .limit(input.maxEdges);
  if (result.error) throw result.error;

  const subjectEdges = result.data as Edge[];
  const resources = new Map<string, { type: string; id: string }>();
  for (const edge of subjectEdges) {
    if (edge.left_type === "subject" && edge.left_id === input.subjectId && edge.right_type !== "subject") resources.set(`${edge.right_type}:${edge.right_id}`, { type: edge.right_type, id: edge.right_id });
    if (edge.right_type === "subject" && edge.right_id === input.subjectId && edge.left_type !== "subject") resources.set(`${edge.left_type}:${edge.left_id}`, { type: edge.left_type, id: edge.left_id });
  }

  const related = new Map<string, { subjectId: string; sharedResources: number; maxConfidence: number; relationships: Set<string> }>();
  const riskyRelationships = new Set(["shared_device", "shared_ip", "shared_identity", "uses_device", "uses_ip", "owns_identity", "linked_session"]);
  let riskyConnections = 0;

  for (const resource of resources.values()) {
    const edges = await supabase.schema("security").from("graph_edges")
      .select("left_type,left_id,relationship,right_type,right_id,confidence")
      .eq("tenant_id", input.tenantId)
      .or(`and(left_type.eq.${resource.type},left_id.eq.${resource.id}),and(right_type.eq.${resource.type},right_id.eq.${resource.id})`)
      .limit(200);
    if (edges.error) throw edges.error;

    for (const edge of edges.data as Edge[]) {
      const subjectId = edge.left_type === "subject" ? edge.left_id : edge.right_type === "subject" ? edge.right_id : null;
      if (!subjectId || subjectId === input.subjectId) continue;
      const confidence = Math.max(0, Math.min(1, Number(edge.confidence ?? 0)));
      const item = related.get(subjectId) ?? { subjectId, sharedResources: 0, maxConfidence: 0, relationships: new Set<string>() };
      item.sharedResources += 1;
      item.maxConfidence = Math.max(item.maxConfidence, confidence);
      item.relationships.add(edge.relationship);
      related.set(subjectId, item);
      if (confidence >= 0.8 && riskyRelationships.has(edge.relationship)) riskyConnections += 1;
    }
  }

  const relatedSubjects = [...related.values()]
    .sort((a, b) => b.sharedResources - a.sharedResources || b.maxConfidence - a.maxConfidence)
    .slice(0, input.maxSubjects)
    .map((item) => ({ subjectId: item.subjectId, sharedResources: item.sharedResources, confidence: Math.round(item.maxConfidence * 100) / 100, relationships: [...item.relationships].slice(0, 12) }));

  const connectionScore = Math.min(100,
    riskyConnections * 12 +
    relatedSubjects.reduce((sum, item) => sum + Math.min(20, item.sharedResources * 5) * item.confidence, 0) +
    Math.min(20, resources.size * 2),
  );

  return {
    version: "fraud-network-v2",
    clusterKey: clusterKey([input.subjectId, ...relatedSubjects.map((item) => item.subjectId)]),
    connectionScore: Math.round(connectionScore),
    connected: relatedSubjects.length > 0,
    resourceCount: resources.size,
    riskyConnectionCount: riskyConnections,
    relatedSubjectCount: relatedSubjects.length,
    relatedSubjects,
  };
}
