import { describe, expect, it } from "vitest";
import { buildAIAdvisoryEvidence, readBoundedResponseText, validateAIEndpoint } from "../src/security/ai";

describe("AI analyzer safety boundaries", () => {
  it("sends only bounded numeric and categorical signal data to the model", () => {
    const evidence = buildAIAdvisoryEvidence({
      deterministicScore: 75,
      signals: [{
        signalName: "network_risk",
        source: "network",
        score: 80,
        confidence: 0.9,
        evidence: { rawIp: "192.0.2.10", email: "private@example.invalid" },
      } as never],
    });
    expect(JSON.stringify(evidence)).not.toContain("192.0.2.10");
    expect(JSON.stringify(evidence)).not.toContain("private@example.invalid");
    expect(evidence.signals[0]).toEqual({
      signalName: "network_risk",
      source: "network",
      score: 80,
      confidence: 0.9,
    });
  });

  it("caps the number of model signals and clamps invalid numeric values", () => {
    const evidence = buildAIAdvisoryEvidence({
      deterministicScore: Number.NaN,
      signals: Array.from({ length: 100 }, (_, index) => ({
        signalName: `s${index}`,
        source: "test",
        score: Number.NaN,
        confidence: Number.NaN,
      })),
    });
    expect(evidence.deterministicScore).toBe(0);
    expect(evidence.signals).toHaveLength(64);
    expect(evidence.signals[0].score).toBe(0);
    expect(evidence.signals[0].confidence).toBeNull();
  });

  it("rejects credential-bearing endpoints and HTTP in production", () => {
    expect(() => validateAIEndpoint("https://user:pass@example.com/v1/chat", true))
      .toThrow("AI_ANALYZER_ENDPOINT_CREDENTIALS_FORBIDDEN");
    expect(() => validateAIEndpoint("http://example.com/v1/chat", true))
      .toThrow("AI_ANALYZER_HTTPS_REQUIRED");
    expect(validateAIEndpoint("https://example.com/v1/chat", true).protocol).toBe("https:");
  });

  it("reads a small response body successfully", async () => {
    const response = new Response("{\"ok\":true}");
    await expect(readBoundedResponseText(response, 100)).resolves.toBe("{\"ok\":true}");
  });

  it("rejects an oversized model response", async () => {
    const response = new Response("x".repeat(100));
    await expect(readBoundedResponseText(response, 20)).rejects.toThrow("AI_ANALYZER_RESPONSE_TOO_LARGE");
  });
});
