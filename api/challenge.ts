import { z } from "zod";
import { hashValue } from "../src/security/utils";
import { checkRateLimit } from "../src/security/rateLimit";
import { issueSecurityChallenge, consumeSecurityChallenge, completeVerifiedSecurityChallenge } from "../src/security/challenge";
import { verifyAndConsumeRequestSignature } from "../src/security/requestSigning";
import { authenticateRotatedTenantKey } from "../src/security/tenantAuth";
import { safeErrorCode, safeErrorStatus, securityLog } from "../src/security/observability";

const bodySchema = z.discriminatedUnion("mode", [
  z.object({
    mode: z.literal("issue"),
    tenantId: z.uuid(),
    subjectId: z.uuid().optional(),
    sessionId: z.uuid().optional(),
    challengeType: z.enum(["step_up_mfa", "proof_of_work", "risk_based_verification"]),
    reasonCodes: z.array(z.string().min(1).max(100).regex(/^[A-Z0-9_.:-]+$/)).max(32).default([]),
    ttlSeconds: z.number().int().min(30).max(900).default(300),
    proofDifficulty: z.number().int().min(1).max(4).optional(),
  }).strict(),
  z.object({
    mode: z.literal("consume"),
    tenantId: z.uuid(),
    token: z.string().min(32).max(128),
    proofNonce: z.string().min(16).max(128).optional(),
    proofSolution: z.string().min(1).max(128).regex(/^[A-Za-z0-9_-]+$/).optional(),
  }).strict().superRefine((value, context) => {
    if ((value.proofNonce === undefined) !== (value.proofSolution === undefined)) {
      context.addIssue({ code: "custom", path: ["proofSolution"], message: "Proof nonce and solution must be supplied together" });
    }
  }),
  z.object({
    mode: z.literal("complete_verified"),
    tenantId: z.uuid(),
    token: z.string().min(32).max(128),
    verificationReference: z.string().min(8).max(300).regex(/^[^\r\n]+$/),
  }).strict(),
]);

const json = (body: unknown, status = 200, requestId?: string) => new Response(
  status === 204 ? null : JSON.stringify(body),
  {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
      "x-frame-options": "DENY",
      "referrer-policy": "no-referrer",
      ...(requestId ? { "x-request-id": requestId } : {}),
    },
  },
);

export default async function handler(request: Request) {
  const candidate = request.headers.get("x-request-id") ?? "";
  const requestId = /^[A-Za-z0-9._:-]{1,100}$/.test(candidate) ? candidate : crypto.randomUUID();
  if (request.method !== "POST") return json({ error: "METHOD_NOT_ALLOWED", requestId }, 405, requestId);

  const bearer = /^Bearer\s+(.+)$/i.exec(request.headers.get("authorization") ?? "");
  if (!bearer || bearer[1].trim().length < 1 || bearer[1].trim().length > 512) {
    return json({ error: "UNAUTHORIZED", requestId }, 401, requestId);
  }
  const apiKey = bearer[1].trim();
  const contentType = (request.headers.get("content-type") ?? "").split(";")[0].trim().toLowerCase();
  if (contentType !== "application/json") return json({ error: "UNSUPPORTED_MEDIA_TYPE", requestId }, 415, requestId);

  try {
    const rawBody = await request.text();
    if (new TextEncoder().encode(rawBody).byteLength > 16 * 1024) {
      return json({ error: "PAYLOAD_TOO_LARGE", requestId }, 413, requestId);
    }

    let raw: unknown;
    try {
      raw = JSON.parse(rawBody);
    } catch {
      return json({ error: "INVALID_JSON", requestId }, 400, requestId);
    }
    const body = bodySchema.parse(raw);

    const keyIdHeader = request.headers.get("x-gainiren-key-id")?.trim() || null;
    const authentication = await authenticateRotatedTenantKey({
      tenantId: body.tenantId,
      apiKey,
      keyId: keyIdHeader,
    });
    if (!authentication.authorized) return json({ error: "UNAUTHORIZED", requestId }, 401, requestId);

    const signature = await verifyAndConsumeRequestSignature({
      request,
      rawBody,
      apiKey,
      tenantId: body.tenantId,
    });
    if (!signature.valid) {
      securityLog("request_signature_rejected", { requestId, tenantId: body.tenantId, reasonCode: signature.reasonCode });
      return json({ error: "INVALID_REQUEST_SIGNATURE", requestId }, 401, requestId);
    }

    const rate = await checkRateLimit({
      tenantId: body.tenantId,
      key: `challenge:${hashValue(apiKey)}`,
      bucket: "challenge",
      limit: 30,
      windowSeconds: 60,
    });
    if (!rate.allowed) {
      return json({
        error: "RATE_LIMITED",
        retryAfter: Math.max(1, Math.ceil((Date.parse(rate.resetAt) - Date.now()) / 1000)),
        requestId,
      }, 429, requestId);
    }

    if (body.mode === "issue") {
      const issued = await issueSecurityChallenge(body);
      securityLog("security_challenge_issued", {
        requestId,
        tenantId: body.tenantId,
        challengeType: body.challengeType,
        reasonCodeCount: body.reasonCodes.length,
        expiresInSeconds: body.ttlSeconds,
      });
      return json({ ...issued, requestId }, 201, requestId);
    }

    if (body.mode === "complete_verified") {
      const completed = await completeVerifiedSecurityChallenge(body.token, body.tenantId, body.verificationReference);
      return json({ ...completed, requestId }, completed.valid ? 200 : 409, requestId);
    }

    const consumed = await consumeSecurityChallenge(body.token, body.tenantId, body.proofNonce, body.proofSolution);
    return json({ ...consumed, requestId }, consumed.valid ? 200 : 409, requestId);
  } catch (error) {
    if (error instanceof z.ZodError) return json({ error: "INVALID_REQUEST", requestId }, 400, requestId);
    securityLog("challenge_api_error", {
      requestId,
      errorCode: safeErrorCode(error),
      ...(safeErrorStatus(error) ? { errorStatus: safeErrorStatus(error) } : {}),
    });
    return json({ error: "INTERNAL_ERROR", requestId }, 500, requestId);
  }
}
