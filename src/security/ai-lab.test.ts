import { describe, expect, it } from "vitest";
import {
  AI_LAB_SCHEMA_VERSION,
  AI_MODEL_REGISTRY,
  aggregateAIShadowPredictions,
  assertAIShadowOnly,
  getAIModel,
  normalizeAIShadowPrediction,
} from "./ai-lab";

describe("AI shadow lab", () => {
  it("registers every validated model as shadow-only", () => {
    expect(AI_MODEL_REGISTRY.length).toBeGreaterThanOrEqual(6);
    expect(AI_MODEL_REGISTRY.every((model) => model.mode === "shadow")).toBe(true);
    expect(AI_MODEL_REGISTRY.every((model) => model.productionEnforcement === false)).toBe(true);
  });

  it("normalizes a valid model prediction", () => {
    const prediction = normalizeAIShadowPrediction({
      modelId: "pyod-optimized-ensemble",
      score: 82,
      confidence: 0.91,
      available: true,
      latencyMs: 12,
      reasonCodes: ["velocity_anomaly"],
      evidence: { source: "shadow-engine" },
    });
    expect(prediction.score).toBe(82);
  });

  it("rejects scores outside the security contract", () => {
    expect(() => normalizeAIShadowPrediction({
      modelId: "pyod-optimized-ensemble",
      score: 101,
      confidence: 1,
      available: true,
      latencyMs: 1,
    })).toThrow();
  });

  it("ignores unavailable models rather than letting them reduce risk", () => {
    const result = aggregateAIShadowPredictions([
      {
        modelId: "pyod-optimized-ensemble",
        score: 90,
        confidence: 0.9,
        available: true,
        latencyMs: 20,
        reasonCodes: ["model_a"],
      },
      {
        modelId: "pygod-dominant",
        score: 0,
        confidence: 0,
        available: false,
        latencyMs: 100,
        reasonCodes: ["MODEL_OFFLINE"],
      },
    ]);
    expect(result.schemaVersion).toBe(AI_LAB_SCHEMA_VERSION);
    expect(result.availableModelCount).toBe(1);
    expect(result.score).toBe(90);
    expect(result.reasonCodes).toContain("model_a");
    expect(result.reasonCodes).not.toContain("MODEL_OFFLINE");
    expect(assertAIShadowOnly(result)).toBe(true);
  });

  it("fails closed to an explicit unavailable state", () => {
    const result = aggregateAIShadowPredictions([
      {
        modelId: "pyod-dominant",
        score: 0,
        confidence: 0,
        available: false,
        latencyMs: 1000,
      },
    ]);
    expect(result.score).toBe(0);
    expect(result.confidence).toBe(0);
    expect(result.reasonCodes).toEqual(["AI_MODELS_UNAVAILABLE"]);
  });

  it("keeps model lookup deterministic", () => {
    expect(getAIModel("river-half-space-trees").family).toBe("streaming-anomaly");
    expect(() => getAIModel("not-a-model" as never)).toThrow("AI_MODEL_NOT_REGISTERED");
  });
});
