import { describe, expect, it } from "vitest";
import { createRequestSignature, verifyRequestSignature } from "../src/security/requestSigning";
import { evaluateDefenseInDepth } from "../src/security/firewall";

describe("Part 3 security completion", () => {
  it("binds signatures to the exact request target, body and fresh nonce", () => {
    const rawBody = JSON.stringify({ tenantId: "77777777-7777-4777-8777-777777777777" });
    const input = {
      apiKey: "test-secret",
      method: "POST",
      requestUrl: "https://security.example.invalid/api/security-check?x=1",
      timestamp: String(Math.floor(Date.now() / 1000)),
      nonce: "FreshNonce_123456789",
      rawBody,
    };
    const signature = createRequestSignature(input);
    const request = new Request(input.requestUrl, {
      method: input.method,
      headers: {
        "x-gainiren-signature": signature,
        "x-gainiren-timestamp": input.timestamp,
        "x-gainiren-nonce": input.nonce,
      },
    });
    expect(verifyRequestSignature(request, rawBody, input.apiKey).valid).toBe(true);
    expect(verifyRequestSignature(request, rawBody + " ", input.apiKey).valid).toBe(false);
  });

  it("keeps deception and integrity controls strict", () => {
    const result = evaluateDefenseInDepth({
      score: 10,
      subjectStatus: "active",
      signals: [
        { signalName: "deception_tripwire", source: "honeydb", score: 90, confidence: 1, evidence: {} },
        { signalName: "request_integrity_failure", source: "application_integrity", score: 100, confidence: 1, evidence: {} },
      ],
    });
    expect(result.minimumDecision).toBe("BLOCK");
    expect(result.layers.find((layer) => layer.layer === "application")?.action).toBe("BLOCK");
  });
});
