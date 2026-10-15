import { describe, expect, it, vi } from "vitest";
import {
  buildAIAdvisoryEvidence,
  createBoundedOpenRouterFetcher,
  readBoundedResponseText,
  validateOpenRouterModel,
} from "../src/security/ai";

describe("OpenRouter advisory safety boundaries", () => {
  it("sends only bounded signal categories and numeric evidence", () => {
    const evidence = buildAIAdvisoryEvidence({
      deterministicScore: 75,
      signals: [{
        signalName: "network_risk",
        source: "network",
        score: 80,
        confidence: 0.9,
        rawIp: "192.0.2.10",
        email: "private@example.invalid",
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

  it("caps signals and safely normalizes invalid numeric values", () => {
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

  it("accepts the configured free Nemotron model id but rejects URL/path injection", () => {
    expect(validateOpenRouterModel("nvidia/nemotron-3-ultra-550b-a55b:free"))
      .toBe("nvidia/nemotron-3-ultra-550b-a55b:free");
    expect(() => validateOpenRouterModel("https://evil.example/model")).toThrow();
    expect(() => validateOpenRouterModel("../../secret")).toThrow();
    expect(() => validateOpenRouterModel("")).toThrow();
  });

  it("reads bounded response text and rejects oversized or invalid UTF-8 responses", async () => {
    await expect(readBoundedResponseText(new Response("{\"ok\":true}"), 100))
      .resolves.toBe("{\"ok\":true}");
    await expect(readBoundedResponseText(new Response("x".repeat(100)), 20))
      .rejects.toThrow("AI_ANALYZER_RESPONSE_TOO_LARGE");
    await expect(readBoundedResponseText(new Response(new Uint8Array([0xff])), 20))
      .rejects.toThrow("AI_ANALYZER_INVALID_UTF8");
  });

  it("restricts outbound requests to the exact HTTPS OpenRouter chat endpoint", async () => {
    const fetchImpl = vi.fn(async () => new Response('{"choices":[]}', {
      status: 200,
      headers: {
        "content-type": "application/json",
        "content-length": "13",
        "content-encoding": "identity",
      },
    }));
    const fetcher = createBoundedOpenRouterFetcher(2_000, fetchImpl as typeof fetch);
    const response = await fetcher(new Request("https://openrouter.ai/api/v1/chat/completions", {
      method: "POST",
      headers: { authorization: "Bearer synthetic-test-key-0123456789", "content-type": "application/json" },
      body: "{}",
    }));
    expect(response.status).toBe(200);
    expect(response.headers.get("content-length")).toBeNull();
    expect(response.headers.get("content-encoding")).toBeNull();
    expect(fetchImpl).toHaveBeenCalledTimes(1);

    const rejected = createBoundedOpenRouterFetcher(2_000, fetchImpl as typeof fetch);
    await expect(rejected(new Request("https://attacker.example/api/v1/chat/completions", {
      method: "POST", body: "{}",
    }))).rejects.toThrow("OPENROUTER_ENDPOINT_REJECTED");
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it("rejects redirects instead of forwarding the provider secret elsewhere", async () => {
    const fetchImpl = vi.fn(async (input: RequestInfo | URL) => {
      const request = input instanceof Request ? input : new Request(input);
      expect(request.redirect).toBe("error");
      return new Response('{"choices":[]}', { status: 200, headers: { "content-type": "application/json" } });
    });
    const fetcher = createBoundedOpenRouterFetcher(2_000, fetchImpl as typeof fetch);
    await fetcher(new Request("https://openrouter.ai/api/v1/chat/completions", {
      method: "POST", headers: { authorization: "Bearer synthetic-test-key-0123456789" }, body: "{}",
    }));
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it("aborts stalled provider calls at the configured timeout", async () => {
    const fetchImpl = vi.fn(async (input: RequestInfo | URL) => {
      const request = input instanceof Request ? input : new Request(input);
      return await new Promise<Response>((_resolve, reject) => {
        request.signal.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")), { once: true });
      });
    });
    const fetcher = createBoundedOpenRouterFetcher(20, fetchImpl as typeof fetch);
    await expect(fetcher(new Request("https://openrouter.ai/api/v1/chat/completions", {
      method: "POST", headers: { authorization: "Bearer synthetic-test-key-0123456789" }, body: "{}",
    }))).rejects.toThrow("AI_ANALYZER_TIMEOUT");
  });
});
