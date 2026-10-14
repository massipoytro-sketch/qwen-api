import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { z } from "zod";
import { supabase } from "../db/supabase";
import { hashValue } from "./utils";

const actionSchema = z.enum(["login", "signup", "withdrawal", "sensitive_action", "generic"]);
const issueSchema = z.object({
  tenantId: z.uuid(), subjectId: z.uuid().optional(), sessionId: z.uuid().optional(),
  action: actionSchema.default("generic"), riskScore: z.number().finite().min(0).max(100).default(0),
}).strict();

const clampDifficulty = (riskScore: number) => riskScore >= 85 ? 4 : riskScore >= 65 ? 3 : riskScore >= 40 ? 2 : 1;
const expiresInSeconds = 120;

function signChallenge(input: { apiKey: string; tenantId: string; token: string; nonce: string; action: string; difficulty: number; expiresAt: string }) {
  const payload = ["GAINIREN-BOT-CHALLENGE-V1", input.tenantId, input.token, input.nonce, input.action, String(input.difficulty), input.expiresAt].join("\n");
  return createHmac("sha256", input.apiKey).update(payload, "utf8").digest("hex");
}

function constantTimeHexEqual(left: string, right: string) {
  const a = Buffer.from(left, "utf8"), b = Buffer.from(right, "utf8");
  return a.length === b.length && timingSafeEqual(a, b);
}

export async function issueBotChallenge(rawInput: z.input<typeof issueSchema> & { apiKey: string }) {
  const input = issueSchema.parse(rawInput);
  const token = randomBytes(32).toString("base64url");
  const nonce = randomBytes(24).toString("base64url");
  const difficulty = clampDifficulty(input.riskScore);
  const expiresAt = new Date(Date.now() + expiresInSeconds * 1000).toISOString();
  const inserted = await supabase.schema("security").from("bot_challenges").insert({
    tenant_id: input.tenantId,
    subject_id: input.subjectId ?? null,
    session_id: input.sessionId ?? null,
    token_hash: hashValue(token),
    nonce_hash: hashValue(nonce),
    action: input.action,
    difficulty,
    expires_at: expiresAt,
  }).select("id").single();
  if (inserted.error) throw inserted.error;
  return {
    challengeId: inserted.data.id,
    token,
    nonce,
    signature: signChallenge({ apiKey: rawInput.apiKey, tenantId: input.tenantId, token, nonce, action: input.action, difficulty, expiresAt }),
    algorithm: "sha256-prefix-v1",
    difficulty,
    expiresAt,
    expiresInSeconds,
  };
}

const verifySchema = z.object({
  tenantId: z.uuid(), token: z.string().min(32).max(128), nonce: z.string().min(20).max(128),
  signature: z.string().regex(/^[a-f0-9]{64}$/), solution: z.string().regex(/^\d{1,12}$/),
}).strict();

function proofDigest(token: string, nonce: string, solution: string) {
  return createHash("sha256").update(["GAINIREN-POW-V1", token, nonce, solution].join("\n"), "utf8").digest("hex");
}

export async function verifyBotChallenge(rawInput: z.input<typeof verifySchema> & { apiKey: string }) {
  const input = verifySchema.parse(rawInput);
  const challenge = await supabase.schema("security").rpc("consume_bot_challenge", {
    p_tenant_id: input.tenantId,
    p_token_hash: hashValue(input.token),
    p_nonce_hash: hashValue(input.nonce),
  });
  if (challenge.error) throw challenge.error;
  const row = Array.isArray(challenge.data) ? challenge.data[0] : null;
  if (!row) return { valid: false, reasonCode: "CHALLENGE_NOT_FOUND" as const };
  if (row.already_consumed) return { valid: false, reasonCode: "CHALLENGE_REPLAYED" as const };
  if (new Date(row.expires_at).getTime() <= Date.now()) return { valid: false, reasonCode: "CHALLENGE_EXPIRED" as const };

  const expected = signChallenge({ apiKey: rawInput.apiKey, tenantId: input.tenantId, token: input.token, nonce: input.nonce, action: row.action, difficulty: row.difficulty, expiresAt: row.expires_at });
  if (!constantTimeHexEqual(input.signature, expected)) return { valid: false, reasonCode: "CHALLENGE_SIGNATURE_INVALID" as const };

  const digest = proofDigest(input.token, input.nonce, input.solution);
  if (!digest.startsWith("0".repeat(row.difficulty))) return { valid: false, reasonCode: "PROOF_OF_WORK_INVALID" as const };

  const finalized = await supabase.schema("security").rpc("finalize_bot_challenge", { p_id: row.id, p_tenant_id: input.tenantId });
  if (finalized.error) throw finalized.error;
  if (finalized.data !== true) return { valid: false, reasonCode: "CHALLENGE_REPLAYED" as const };
  return { valid: true, challengeId: row.id, subjectId: row.subject_id, sessionId: row.session_id, action: row.action, difficulty: row.difficulty };
}
