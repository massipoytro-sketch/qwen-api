import baseHandler from "./security-check";
import { z } from "zod";
import { supabase } from "../src/db/supabase";
import { securityLog } from "../src/security/observability";

const bodySchema = z.object({ tenantId: z.uuid(), sessionId: z.uuid().optional() }).passthrough();
const rank = { ALLOW: 0, MONITOR: 1, CHALLENGE: 2, REVIEW: 3, BLOCK: 4 } as const;

export default async function handler(request: Request): Promise<Response> {
  const response = await baseHandler(request);
  if (response.status < 200 || response.status >= 300 || request.method !== "POST") return response;
  const cloned = response.clone();
  let body: unknown;
  try { body = await cloned.json(); } catch { return response; }
  const parsed = bodySchema.safeParse(body);
  if (!parsed.success || !parsed.data.sessionId) return response;

  const session = await supabase.schema("security").from("sessions")
    .select("ip_id").eq("tenant_id", parsed.data.tenantId).eq("id", parsed.data.sessionId).maybeSingle();
  if (session.error || !session.data?.ip_id) return response;
  const control = await supabase.schema("security").rpc("get_network_control", { p_tenant_id: parsed.data.tenantId, p_ip_id: session.data.ip_id });
  if (control.error) throw control.error;
  const value = control.data as { mode?: string; reasonCode?: string } | null;
  const mode = value?.mode ?? "monitor";
  const reasonCode = typeof value?.reasonCode === "string" ? value.reasonCode : "NETWORK_CONTROL";
  if (mode === "monitor") return response;

  const currentDecision = typeof parsed.data.decision === "string" ? parsed.data.decision : "ALLOW";
  securityLog("network_control_applied", { requestId: request.headers.get("x-request-id"), tenantId: parsed.data.tenantId, mode, reasonCode });
  if (mode === "allow") return response;
  const next = mode === "deny" ? "BLOCK" : mode === "challenge" && rank[currentDecision as keyof typeof rank] < rank.CHALLENGE ? "CHALLENGE" : currentDecision;
  if (next === currentDecision) return response;
  const result = { ...parsed.data, decision: next, score: next === "BLOCK" ? 100 : Math.max(40, Number(parsed.data.score) || 0), riskLevel: next === "BLOCK" ? "critical" : "medium", challengeRecommendation: next === "CHALLENGE" ? { type: "risk_based_verification", reasonCodes: [reasonCode], expiresInSeconds: 300 } : null, networkControl: { mode, reasonCode } };
  return new Response(JSON.stringify(result), { status: response.status, headers: response.headers });
}
