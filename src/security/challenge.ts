import { randomBytes } from "node:crypto";
import { z } from "zod";
import { supabase } from "../db/supabase";
import { hashValue } from "./utils";

const issueSchema = z.object({
  tenantId: z.uuid(),
  subjectId: z.uuid().nullable().optional(),
  sessionId: z.uuid().nullable().optional(),
  challengeType: z.enum(["step_up_mfa", "proof_of_work", "risk_based_verification"]),
  reasonCodes: z.array(z.string().max(100)).max(32).default([]),
  ttlSeconds: z.number().int().min(30).max(900).default(300),
}).strict();

export async function issueSecurityChallenge(rawInput: z.input<typeof issueSchema>) {
  const input = issueSchema.parse(rawInput);
  const token = randomBytes(32).toString("base64url");
  const tokenId = await supabase.schema("security").rpc("issue_challenge_token", {
    p_tenant_id: input.tenantId,
    p_subject_id: input.subjectId ?? null,
    p_session_id: input.sessionId ?? null,
    p_challenge_type: input.challengeType,
    p_token_hash: hashValue(token),
    p_reason_codes: input.reasonCodes,
    p_ttl_seconds: input.ttlSeconds,
  });
  if (tokenId.error) throw tokenId.error;
  return { tokenId: tokenId.data, token, challengeType: input.challengeType, reasonCodes: input.reasonCodes, expiresInSeconds: input.ttlSeconds };
}

export async function consumeSecurityChallenge(token: string) {
  const parsed = z.string().min(32).max(128).parse(token);
  const result = await supabase.schema("security").rpc("consume_challenge_token", { p_token_hash: hashValue(parsed) });
  if (result.error) throw result.error;
  return result.data as { valid: boolean; reasonCode?: string; tokenId?: string; tenantId?: string; subjectId?: string | null; sessionId?: string | null; challengeType?: string; reasonCodes?: string[] };
}
