import { supabase } from "../db/supabase";
import { securityCheck } from "./check";
import type { SecurityCheckInput, SecurityCheckResult, SecurityDecision } from "./types";
import { securityLog } from "./observability";

const rank: Record<SecurityDecision, number> = { ALLOW: 0, MONITOR: 1, CHALLENGE: 2, REVIEW: 3, BLOCK: 4 };

async function applyControlPlane(input: SecurityCheckInput, result: SecurityCheckResult): Promise<SecurityCheckResult> {
  const global = await supabase.schema("security").from("global_control_plane")
    .select("mode,reason_code,version,expires_at").eq("singleton", true).maybeSingle();
  if (global.error || !global.data) throw global.error ?? new Error("CONTROL_PLANE_UNAVAILABLE");
  const globalExpired = Boolean(global.data.expires_at && Date.parse(global.data.expires_at) <= Date.now());
  const globalMode = globalExpired ? "normal" : global.data.mode;
  const globalReason = typeof global.data.reason_code === "string" ? global.data.reason_code : "CONTROL_PLANE";

  if (input.sessionId) {
    const revoked = await supabase.schema("security").from("session_revocations")
      .select("reason_code,expires_at").eq("tenant_id", input.tenantId).eq("session_id", input.sessionId).maybeSingle();
    if (revoked.error) throw revoked.error;
    const revocation = revoked.data;
    const activeRevocation = Boolean(revocation && (!revocation.expires_at || Date.parse(revocation.expires_at) > Date.now()));
    if (activeRevocation && revocation) {
      securityLog("session_revocation_enforced", { requestId: input.requestId ?? null, tenantId: input.tenantId, sessionId: input.sessionId, reasonCode: revocation.reason_code });
      return { ...result, decision: "BLOCK", score: 100, riskLevel: "critical", challengeRecommendation: null };
    }
  }

  if (globalMode === "lockdown") {
    securityLog("global_lockdown_enforced", { requestId: input.requestId ?? null, tenantId: input.tenantId, version: global.data.version, reasonCode: globalReason });
    return { ...result, decision: "BLOCK", score: 100, riskLevel: "critical", challengeRecommendation: null };
  }
  if (globalMode === "review_only" && rank[result.decision] < rank.REVIEW) {
    securityLog("global_review_only_enforced", { requestId: input.requestId ?? null, tenantId: input.tenantId, version: global.data.version, reasonCode: globalReason });
    return { ...result, decision: "REVIEW", score: Math.max(70, result.score), riskLevel: result.score >= 90 ? "critical" : "high", challengeRecommendation: null };
  }
  return result;
}

/** Global emergency controls and session revocation are enforced on every guarded security check. Missing control state fails closed. */
export async function guardedSecurityCheck(input: SecurityCheckInput): Promise<SecurityCheckResult & { networkControl?: { mode: string; reasonCode: string } }> {
  let result = await securityCheck(input);
  result = await applyControlPlane(input, result);
  if (!input.sessionId) return result;

  const session = await supabase.schema("security").from("sessions").select("ip_id")
    .eq("tenant_id", input.tenantId).eq("id", input.sessionId).maybeSingle();
  if (session.error) throw session.error;
  if (!session.data?.ip_id) return result;

  const control = await supabase.schema("security").rpc("get_network_control", { p_tenant_id: input.tenantId, p_ip_id: session.data.ip_id });
  if (control.error) throw control.error;
  const value = control.data as { mode?: string; reasonCode?: string } | null;
  const mode = value?.mode ?? "monitor";
  const reasonCode = typeof value?.reasonCode === "string" ? value.reasonCode : "NETWORK_CONTROL";
  if (mode === "monitor") return result;
  securityLog("network_control_applied", { requestId: input.requestId ?? null, tenantId: input.tenantId, mode, reasonCode });

  if (mode === "deny" && rank[result.decision] < rank.BLOCK) return { ...result, decision: "BLOCK", score: 100, riskLevel: "critical", challengeRecommendation: null, networkControl: { mode, reasonCode } };
  if (mode === "challenge" && rank[result.decision] < rank.CHALLENGE) {
    result = { ...result, decision: "CHALLENGE", score: Math.max(40, result.score), riskLevel: result.score >= 90 ? "critical" : "medium", challengeRecommendation: { type: "risk_based_verification", reasonCodes: [reasonCode], expiresInSeconds: 300 } };
  }
  return { ...result, networkControl: { mode, reasonCode } };
}
