import { supabase } from "../db/supabase";
import { securityCheck } from "./check";
import type { SecurityCheckInput, SecurityCheckResult, SecurityDecision } from "./types";
import { securityLog } from "./observability";

const rank: Record<SecurityDecision, number> = { ALLOW: 0, MONITOR: 1, CHALLENGE: 2, REVIEW: 3, BLOCK: 4 };

/** Applies operator-controlled network overrides after deterministic analysis. */
export async function guardedSecurityCheck(input: SecurityCheckInput): Promise<SecurityCheckResult & { networkControl?: { mode: string; reasonCode: string } }> {
  const result = await securityCheck(input);
  if (!input.sessionId) return result;
  const session = await supabase.schema("security").from("sessions")
    .select("ip_id").eq("tenant_id", input.tenantId).eq("id", input.sessionId).maybeSingle();
  if (session.error) throw session.error;
  if (!session.data?.ip_id) return result;
  const control = await supabase.schema("security").rpc("get_network_control", { p_tenant_id: input.tenantId, p_ip_id: session.data.ip_id });
  if (control.error) throw control.error;
  const value = control.data as { mode?: string; reasonCode?: string } | null;
  const mode = value?.mode ?? "monitor";
  const reasonCode = typeof value?.reasonCode === "string" ? value.reasonCode : "NETWORK_CONTROL";
  if (mode === "monitor") return result;
  securityLog("network_control_applied", { requestId: input.requestId ?? null, tenantId: input.tenantId, mode, reasonCode });
  if (mode === "deny") return { ...result, decision: "BLOCK", score: 100, riskLevel: "critical", challengeRecommendation: null, networkControl: { mode, reasonCode } };
  if (mode === "challenge" && rank[result.decision] < rank.CHALLENGE) return { ...result, decision: "CHALLENGE", score: Math.max(40, result.score), riskLevel: "medium", challengeRecommendation: { type: "risk_based_verification", reasonCodes: [reasonCode], expiresInSeconds: 300 }, networkControl: { mode, reasonCode } };
  return { ...result, networkControl: { mode, reasonCode } };
}
