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
  proofDifficulty: z.number().int().min(1).max(4).optional(),
}).strict().superRefine((input, context) => {
  if (input.challengeType !== "proof_of_work" && input.proofDifficulty !== undefined) {
    context.addIssue({ code: "custom", path: ["proofDifficulty"], message: "Proof difficulty applies only to proof-of-work challenges" });
  }
});

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
  verificationReferenceHash?: string;
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
  const proofNonce = input.challengeType === "proof_of_work" ? randomBytes(24).toString("base64url") : null;
  const proofDifficulty = proofNonce ? input.proofDifficulty ?? 2 : null;
  const created = await supabase.schema("security").rpc("issue_challenge_token", {
    p_tenant_id: input.tenantId,
    p_subject_id: input.subjectId ?? null,
    p_session_id: input.sessionId ?? null,
    p_challenge_type: input.challengeType,
    p_token_hash: hashValue(token),
    p_reason_codes: input.reasonCodes,
    p_ttl_seconds: input.ttlSeconds,
    p_proof_nonce_hash: proofNonce ? hashValue(proofNonce) : null,
    p_proof_difficulty: proofDifficulty,
  });
  if (created.error) throw created.error;

  return {
    tokenId: created.data,
    token,
    challengeType: input.challengeType,
    reasonCodes: input.reasonCodes,
    expiresInSeconds: input.ttlSeconds,
    ...(proofNonce ? { challengeNonce: proofNonce, proofDifficulty } : {}),
  };
}

/**
 * A challenge token is consumed only within its owning tenant. Proof-of-work
 * is checked again in PostgreSQL within the same row-lock transaction used for
 * single-use consumption. Other challenge types require trusted external
 * verification and must use completeVerifiedSecurityChallenge.
 */
export async function consumeSecurityChallenge(
  token: string,
  tenantId: string,
  proofNonce?: string,
  proofSolution?: string,
): Promise<ConsumedSecurityChallenge> {
  const parsedToken = tokenSchema.parse(token);
  const parsedTenant = tenantSchema.parse(tenantId);
  const parsedProofNonce = proofNonce === undefined ? null : z.string().min(16).max(128).parse(proofNonce);
  const parsedSolution = proofSolution === undefined ? null : z.string().min(1).max(128).regex(/^[A-Za-z0-9_-]+$/).parse(proofSolution);
  const result = await supabase.schema("security").rpc("consume_challenge_token", {
    p_tenant_id: parsedTenant,
    p_token_hash: hashValue(parsedToken),
    p_proof_nonce: parsedProofNonce,
    p_proof_solution: parsedSolution,
  });
  if (result.error) throw result.error;
  return result.data as ConsumedSecurityChallenge;
}

/**
 * The tenant's trusted server calls this only after its MFA/OTP/risk verification
 * provider has independently confirmed success. The reference is hashed in DB
 * output and is never logged or returned in raw form.
 */
export async function completeVerifiedSecurityChallenge(
  token: string,
  tenantId: string,
  verificationReference: string,
): Promise<ConsumedSecurityChallenge> {
  const parsedToken = tokenSchema.parse(token);
  const parsedTenant = tenantSchema.parse(tenantId);
  const reference = z.string().min(8).max(300).regex(/^[^\r\n]+$/).parse(verificationReference);
  const result = await supabase.schema("security").rpc("complete_verified_challenge", {
    p_tenant_id: parsedTenant,
    p_token_hash: hashValue(parsedToken),
    p_verification_reference: reference,
  });
  if (result.error) throw result.error;
  return result.data as ConsumedSecurityChallenge;
}
