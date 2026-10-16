import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import { z } from "zod";
import type { SecurityDecision } from "./types";
import type { ChallengeType } from "./firewall";

const decisionRank: Record<SecurityDecision, number> = {
  ALLOW: 0,
  MONITOR: 1,
  CHALLENGE: 2,
  REVIEW: 3,
  BLOCK: 4,
};

const challengeSchema = z.object({
  type: z.enum(["step_up_mfa", "proof_of_work", "risk_based_verification"]),
  reasonCodes: z.array(z.string().min(1).max(100)).max(32),
  expiresInSeconds: z.number().int().min(30).max(900),
}).strict();

export function strictestDecision(...decisions: SecurityDecision[]): SecurityDecision {
  return decisions.reduce<SecurityDecision>((best, current) =>
    decisionRank[current] > decisionRank[best] ? current : best, "ALLOW");
}

/**
 * Converts the internal risk result into an enforcement contract. It never
 * relaxes a decision and does not trust client-supplied risk claims.
 */
export function buildEnforcementContract(input: {
  decision: SecurityDecision;
  firewallDecision: SecurityDecision;
  challenge?: { type: ChallengeType; reasonCodes: string[]; expiresInSeconds: number } | null;
  requestId: string;
}) {
  const decision = strictestDecision(input.decision, input.firewallDecision);
  const challenge = decision === "CHALLENGE" && input.challenge
    ? challengeSchema.parse(input.challenge)
    : null;

  return {
    version: "enforcement-v1" as const,
    requestId: input.requestId,
    decision,
    action: decision === "BLOCK" ? "deny" : decision === "REVIEW" ? "hold_for_review" : decision === "CHALLENGE" ? "challenge" : "allow",
    challenge,
    retryable: decision !== "BLOCK",
  };
}

function challengePayload(input: { tenantId: string; subjectId?: string; requestId: string; type: ChallengeType; expiresAt: number }) {
  return [
    "GAINIREN-CHALLENGE-V1",
    input.tenantId,
    input.subjectId ?? "",
    input.requestId,
    input.type,
    String(input.expiresAt),
  ].join("\n");
}

/** Creates a short-lived server-signed challenge token. The signing key must stay server-side. */
export function createChallengeToken(input: {
  signingKey: string;
  tenantId: string;
  subjectId?: string;
  requestId: string;
  type: ChallengeType;
  nowMs?: number;
  ttlSeconds?: number;
}) {
  const tenantId = z.uuid().parse(input.tenantId);
  const subjectId = input.subjectId ? z.uuid().parse(input.subjectId) : undefined;
  const ttlSeconds = Math.max(30, Math.min(900, Math.floor(input.ttlSeconds ?? 300)));
  if (!input.signingKey || input.signingKey.length < 32) throw new Error("CHALLENGE_SIGNING_KEY_TOO_WEAK");
  const expiresAt = Math.floor((input.nowMs ?? Date.now()) / 1000) + ttlSeconds;
  const payload = challengePayload({ tenantId, subjectId, requestId: input.requestId, type: input.type, expiresAt });
  const signature = createHmac("sha256", input.signingKey).update(payload, "utf8").digest("hex");
  const encodedPayload = Buffer.from(payload, "utf8").toString("base64url");
  return `v1.${encodedPayload}.${signature}`;
}

export function verifyChallengeToken(input: {
  token: string;
  signingKey: string;
  tenantId: string;
  subjectId?: string;
  requestId: string;
  type: ChallengeType;
  nowMs?: number;
}) {
  if (!input.signingKey || input.signingKey.length < 32) return false;
  const parts = input.token.split(".");
  if (parts.length !== 3 || parts[0] !== "v1" || !/^[a-f0-9]{64}$/.test(parts[2])) return false;
  let payload: string;
  try { payload = Buffer.from(parts[1], "base64url").toString("utf8"); } catch { return false; }
  const fields = payload.split("\n");
  if (fields.length !== 6 || fields[0] !== "GAINIREN-CHALLENGE-V1") return false;
  const [prefix, tenantId, subjectId, requestId, type, expiresText] = fields;
  if (tenantId !== input.tenantId || subjectId !== (input.subjectId ?? "") || requestId !== input.requestId || type !== input.type) return false;
  const expiresAt = Number(expiresText);
  if (!Number.isSafeInteger(expiresAt) || Math.floor((input.nowMs ?? Date.now()) / 1000) > expiresAt) return false;
  const expected = createHmac("sha256", input.signingKey).update(payload, "utf8").digest("hex");
  const suppliedBytes = Buffer.from(parts[2], "utf8");
  const expectedBytes = Buffer.from(expected, "utf8");
  return suppliedBytes.length === expectedBytes.length && timingSafeEqual(suppliedBytes, expectedBytes);
}

export function securityResponseHeaders(requestId: string, nonce: string) {
  const nonceHash = createHash("sha256").update(nonce, "utf8").digest("base64url");
  return {
    "cache-control": "no-store, max-age=0",
    "pragma": "no-cache",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
    "cross-origin-resource-policy": "same-origin",
    "permissions-policy": "camera=(), microphone=(), geolocation=()",
    "x-request-id": requestId,
    "x-gainiren-request-nonce-hash": nonceHash,
  } as const;
}
