import { z } from "zod";
import { supabase } from "../db/supabase";

const aiInputSchema = z.object({
  tenantId: z.uuid(),
  subjectId: z.uuid().optional(),
  sessionId: z.uuid().optional(),
  evidence: z.record(z.string(), z.unknown()),
  endpoint: z.url(),
  apiKey: z.string().min(1),
  model: z.string().min(1).max(200),
  timeoutMs: z.number().int().min(500).max(30000).default(8000),
});

export function validateAIEndpoint(rawEndpoint: string, production = process.env.NODE_ENV === "production"): URL {
  const endpoint = new URL(rawEndpoint);
  if (endpoint.username || endpoint.password) throw new Error("AI_ANALYZER_ENDPOINT_CREDENTIALS_FORBIDDEN");
  if (endpoint.protocol !== "https:" && (production || endpoint.protocol !== "http:")) {
    throw new Error("AI_ANALYZER_HTTPS_REQUIRED");
  }
  if (!endpoint.hostname) throw new Error("AI_ANALYZER_ENDPOINT_INVALID");
  return endpoint;
}

export function buildAIAdvisoryEvidence(input: {
  deterministicScore: number;
  signals: Array<{
    signalName: string;
    source: string;
    score: number;
    confidence: number | null;
  }>;
}) {
  const clamp = (value: number, max: number) => Math.max(0, Math.min(max, value));
  return {
    schemaVersion: "security_evidence_v1",
    deterministicScore: Number.isFinite(input.deterministicScore)
      ? clamp(input.deterministicScore, 100)
      : 0,
    signalCount: input.signals.length,
    signals: input.signals.slice(0, 64).map((signal) => ({
      signalName: signal.signalName.replace(/[^A-Za-z0-9_.:-]/g, "_").slice(0, 100),
      source: signal.source.replace(/[^A-Za-z0-9_.:-]/g, "_").slice(0, 80),
      score: Number.isFinite(signal.score) ? clamp(signal.score, 100) : 0,
      confidence: signal.confidence !== null && Number.isFinite(signal.confidence)
        ? clamp(signal.confidence, 1)
        : null,
    })),
  };
}

export async function readBoundedResponseText(response: Response, maxBytes = 1_048_576): Promise<string> {
  if (!Number.isInteger(maxBytes) || maxBytes < 1) throw new Error("AI_ANALYZER_RESPONSE_LIMIT_INVALID");
  const reader = response.body?.getReader();
  if (!reader) throw new Error("AI_ANALYZER_EMPTY_RESPONSE");
  const chunks: Uint8Array[] = [];
  let totalBytes = 0;

  try {
    while (true) {
      const part = await reader.read();
      if (part.done) break;
      totalBytes += part.value.byteLength;
      if (totalBytes > maxBytes) {
        await reader.cancel();
        throw new Error("AI_ANALYZER_RESPONSE_TOO_LARGE");
      }
      chunks.push(part.value);
    }
  } finally {
    reader.releaseLock();
  }

  const merged = new Uint8Array(totalBytes);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(merged);
  } catch {
    throw new Error("AI_ANALYZER_INVALID_UTF8");
  }
}

const aiOutputSchema = z.object({
  riskScore: z.number().min(0).max(100),
  riskLevel: z.enum(["unknown","low","medium","high","critical"]),
  summary: z.string().max(4000),
  reasonCodes: z.array(z.string().max(100)).max(32),
  recommendedAction: z.enum(["ALLOW","MONITOR","CHALLENGE","REVIEW","BLOCK"]),
  confidence: z.number().min(0).max(1),
});

export async function analyzeWithAI(rawInput: z.input<typeof aiInputSchema>) {
  const input = aiInputSchema.parse(rawInput);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), input.timeoutMs);

  try {
    const endpoint = validateAIEndpoint(input.endpoint);
    const response = await fetch(endpoint, {
      method: "POST",
      redirect: "error",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${input.apiKey}`,
      },
      body: JSON.stringify({
        model: input.model,
        temperature: 0,
        messages: [
          {
            role: "system",
            content:
              "You are a security evidence analyst. Analyze only supplied evidence. Do not invent facts. Return JSON only with riskScore, riskLevel, summary, reasonCodes, recommendedAction, confidence. Your recommendation is advisory and must not be treated as the final security decision.",
          },
          { role: "user", content: JSON.stringify(input.evidence) },
        ],
      }),
      signal: controller.signal,
    });

    if (!response.ok) throw new Error(`AI_ANALYZER_HTTP_${response.status}`);

    const responseText = await readBoundedResponseText(response);
    let payload: {
      choices?: Array<{ message?: { content?: string } }>;
    };
    try {
      payload = JSON.parse(responseText) as typeof payload;
    } catch {
      throw new Error("AI_ANALYZER_INVALID_JSON");
    }
    const content = payload.choices?.[0]?.message?.content;
    if (!content) throw new Error("AI_ANALYZER_EMPTY_RESPONSE");

    const parsed = aiOutputSchema.parse(JSON.parse(content));

    const existing = await supabase.schema("security").from("model_versions")
      .select("id")
      .eq("model_name", input.model)
      .eq("version", "advisory-v1")
      .maybeSingle();
    if (existing.error) throw existing.error;

    let modelVersionId = existing.data?.id;
    if (!modelVersionId) {
      const created = await supabase.schema("security").from("model_versions").insert({
        model_name: input.model,
        version: "advisory-v1",
        status: "active",
        feature_schema: { evidence: "security_evidence_v1" },
        metrics: { mode: "advisory" },
      }).select("id").single();
      if (created.error) throw created.error;
      modelVersionId = created.data.id;
    }

    const prediction = await supabase.schema("security").from("model_predictions").insert({
      tenant_id: input.tenantId,
      subject_id: input.subjectId ?? null,
      session_id: input.sessionId ?? null,
      model_version_id: modelVersionId,
      prediction_type: "security_advisory",
      prediction_score: parsed.riskScore,
      prediction: parsed,
    }).select("id").single();
    if (prediction.error) throw prediction.error;

    return { ...parsed, predictionId: prediction.data.id, modelVersionId };
  } finally {
    clearTimeout(timer);
  }
}

export type AIAnalysisResult = z.infer<typeof aiOutputSchema>;
