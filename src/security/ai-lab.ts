import { z } from "zod";

export const AI_LAB_SCHEMA_VERSION = "ai_shadow_signal_v1" as const;

export type AIModelId =
  | "pyod-optimized-ensemble"
  | "pygod-dominant"
  | "river-half-space-trees"
  | "deepcase-sequence"
  | "network-unsw-nb15"
  | "openrouter-advisory";

export type AIModelStatus = "ready" | "isolated" | "provenance_review" | "advisory";

export type AIModelDescriptor = Readonly<{
  id: AIModelId;
  name: string;
  family: string;
  version: string;
  status: AIModelStatus;
  mode: "shadow";
  productionEnforcement: false;
  source: "shadow-engine" | "gainiren-security";
  provenance: string;
  featureSchema: string;
}>;

export const AI_MODEL_REGISTRY: readonly AIModelDescriptor[] = [
  {
    id: "pyod-optimized-ensemble",
    name: "PyOD Optimized Ensemble",
    family: "ECOD/COPOD/HBOS/IForest/LODA/PCA",
    version: "shadow-ensemble-v1",
    status: "ready",
    mode: "shadow",
    productionEnforcement: false,
    source: "shadow-engine",
    provenance: "massipoytro-sketch/-shadow-engine training pipeline",
    featureSchema: "gainiren_behavior_v1",
  },
  {
    id: "pygod-dominant",
    name: "PyGOD DOMINANT",
    family: "graph-anomaly",
    version: "shadow-dominant-v1",
    status: "ready",
    mode: "shadow",
    productionEnforcement: false,
    source: "shadow-engine",
    provenance: "massipoytro-sketch/-shadow-engine isolated PyGOD job",
    featureSchema: "gainiren_graph_v1",
  },
  {
    id: "river-half-space-trees",
    name: "River HalfSpaceTrees",
    family: "streaming-anomaly",
    version: "shadow-hst-v1",
    status: "ready",
    mode: "shadow",
    productionEnforcement: false,
    source: "shadow-engine",
    provenance: "massipoytro-sketch/-shadow-engine streaming training job",
    featureSchema: "gainiren_stream_v1",
  },
  {
    id: "deepcase-sequence",
    name: "DeepCASE Sequence Detector",
    family: "sequence-anomaly",
    version: "compatibility-shadow-v1",
    status: "isolated",
    mode: "shadow",
    productionEnforcement: false,
    source: "shadow-engine",
    provenance: "isolated compatibility validation; legacy dependency boundary",
    featureSchema: "gainiren_sequence_v1",
  },
  {
    id: "network-unsw-nb15",
    name: "Network Anomaly Detector",
    family: "network-intrusion",
    version: "provenance-gated-v1",
    status: "provenance_review",
    mode: "shadow",
    productionEnforcement: false,
    source: "shadow-engine",
    provenance: "UNSW-NB15 provenance gate; not reward-fraud validation",
    featureSchema: "network_flow_v1",
  },
  {
    id: "openrouter-advisory",
    name: "OpenRouter Security Advisory",
    family: "language-model-advisor",
    version: "advisory-v1",
    status: "advisory",
    mode: "shadow",
    productionEnforcement: false,
    source: "gainiren-security",
    provenance: "bounded OpenRouter adapter in gainiren-security",
    featureSchema: "security_evidence_v1",
  },
];

const AI_MODEL_IDS = [
  "pyod-optimized-ensemble",
  "pygod-dominant",
  "river-half-space-trees",
  "deepcase-sequence",
  "network-unsw-nb15",
  "openrouter-advisory",
] as const satisfies readonly AIModelId[];

const predictionSchema = z.object({
  modelId: z.enum(AI_MODEL_IDS),
  score: z.number().finite().min(0).max(100),
  confidence: z.number().finite().min(0).max(1),
  available: z.boolean(),
  latencyMs: z.number().finite().min(0).max(120_000),
  reasonCodes: z.array(z.string().min(1).max(100)).max(32).default([]),
  evidence: z.record(z.string(), z.unknown()).default({}),
});

export type AIShadowPrediction = z.infer<typeof predictionSchema>;

export type AIShadowAggregate = {
  schemaVersion: typeof AI_LAB_SCHEMA_VERSION;
  mode: "shadow";
  advisoryOnly: true;
  score: number;
  confidence: number;
  modelCount: number;
  availableModelCount: number;
  predictions: AIShadowPrediction[];
  reasonCodes: string[];
};

const clamp = (value: number, min = 0, max = 100) => Math.max(min, Math.min(max, value));

export function getAIModel(id: AIModelId): AIModelDescriptor {
  const model = AI_MODEL_REGISTRY.find((candidate) => candidate.id === id);
  if (!model) throw new Error("AI_MODEL_NOT_REGISTERED");
  return model;
}

export function normalizeAIShadowPrediction(raw: unknown): AIShadowPrediction {
  return predictionSchema.parse(raw);
}

export function aggregateAIShadowPredictions(rawPredictions: readonly unknown[]): AIShadowAggregate {
  const predictions = rawPredictions.map(normalizeAIShadowPrediction);
  const available = predictions.filter((prediction) => prediction.available);
  if (available.length === 0) {
    return {
      schemaVersion: AI_LAB_SCHEMA_VERSION,
      mode: "shadow",
      advisoryOnly: true,
      score: 0,
      confidence: 0,
      modelCount: predictions.length,
      availableModelCount: 0,
      predictions,
      reasonCodes: ["AI_MODELS_UNAVAILABLE"],
    };
  }

  const weighted = available.map((prediction) => {
    const model = getAIModel(prediction.modelId);
    const statusWeight = model.status === "ready" ? 1 : model.status === "advisory" ? 0.75 : 0.5;
    return { prediction, weight: Math.max(0.05, prediction.confidence) * statusWeight };
  });
  const denominator = weighted.reduce((sum, item) => sum + item.weight, 0);
  const score = denominator === 0
    ? 0
    : weighted.reduce((sum, item) => sum + item.prediction.score * item.weight, 0) / denominator;
  const confidence = weighted.reduce((sum, item) => sum + item.prediction.confidence * item.weight, 0) / denominator;
  const reasonCodes = [...new Set(available.flatMap((prediction) => prediction.reasonCodes))].slice(0, 64);

  return {
    schemaVersion: AI_LAB_SCHEMA_VERSION,
    mode: "shadow",
    advisoryOnly: true,
    score: clamp(score),
    confidence: clamp(confidence, 0, 1),
    modelCount: predictions.length,
    availableModelCount: available.length,
    predictions,
    reasonCodes,
  };
}

export function assertAIShadowOnly(result: AIShadowAggregate): true {
  if (result.mode !== "shadow" || result.advisoryOnly !== true) {
    throw new Error("AI_ENFORCEMENT_BOUNDARY_VIOLATION");
  }
  return true;
}
