import { randomBytes } from "node:crypto";
import { z } from "zod";
import { supabase } from "../db/supabase";
import { assertTenantScope } from "./scope";
import { hashValue } from "./utils";

const issueSchema = z.object({
  tenantId: z.uuid(),
  subjectId: z.uuid().optional(),
  sessionId: z.uuid().optional(),
  challengeType: z.enum(["step_up_mfa", "proof_of_work", "risk_based_verification"]),
  reasonCodes: z.array(z.string().min(1).max(100).regex(/^[A-Z0-9_.:-]+$/)).max(32).default([]),
  ttlSeconds: z.number().int().min(30).max(900).default(300),
}).strict();

const tokenSchema = z.string().min(32).max(128);
const tenantSchema = z.uuid();

export type ConsumedSecurityChallenge = {
  valid: boolean;
  reasonCode?: string;
  tokenId?: string;
  tenantId?: string;
  subjectId?: string | null;
  sessionId?: string | null;
  challengeType?: "step_up_mfa" | "proof_of_work" | "risk_based_verification";
  reasonCodes?: string[];
};

export async function issueSecurityChallenge(rawInput: z.input<typeof issueSchema>) {
  const input = issueSchema.parse(rawInput);
  if (input.subjectId || input.sessionId) {
    await assertTenantScope({
      tenantId: input.tenantId,
      ...(input.subjectId ? { subjectId: input.subjectId } : {}),
      ...(input.sessionId ? { sessionId: input.sessionId } : {}),
    });
  }

  const token = randomBytes(32).toString("base64url");
  const tokenHash = hashValue(token);
  const created = await supabase.schema("security").rpc("issue_challenge_token", {
    p_tenant_id: input.tenantId,
    p_subject_id: input.subjectId ?? null,
    p_session_id: input.sessionId ?? null,
    p_challenge_type: input.challengeType,
    p_token_hash: tokenHash,
    p_reason_codes: input.reasonCodes,
    p_ttl_seconds: input.ttlSeconds,
  });
  if (created.error) throw created.error;

  return {
    tokenId: created.data,
    token,
    challengeType: input.challengeType,
    reasonCodes: input.reasonCodes,
    expiresInSeconds: input.ttlSeconds,
  };
}

/**
 * A challenge token is consumed only within its owning tenant. The database
 * row lock makes concurrent use single-winner; only the token hash is stored.
 */
export async function consumeSecurityChallenge(token: string, tenantId: string): Promise<ConsumedSecurityChallenge> {
  const parsedToken = tokenSchema.parse(token);
  const parsedTenant = tenantSchema.parse(tenantId);
  const result = await supabase.schema("security").rpc("consume_challenge_token", {
    p_tenant_id: parsedTenant,
    p_token_hash: hashValue(parsedToken),
  });
  if (result.error) throw result.error;
  return result.data as ConsumedSecurityChallenge;
}
