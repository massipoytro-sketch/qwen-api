import { OpenRouter } from "@openrouter/sdk";
import { z } from "zod";
import { supabase } from "../db/supabase";

const aiInputSchema = z.object({
  tenantId: z.uuid(), subjectId: z.uuid().optional(), sessionId: z.uuid().optional(), evidence: z.record(z.string(), z.unknown()),
  endpoint: z.url().optional(), apiKey: z.string().min(1), model: z.string().min(1).max(200), timeoutMs: z.number().int().min(500).max(30000).default(8000),
});

export function buildAIAdvisoryEvidence(input: { deterministicScore: number; signals: Array<{ signalName: string; source: string; score: number; confidence: number | null }> }) {
  const clamp = (value: number, max: number) => Math.max(0, Math.min(max, value));
  return {
    schemaVersion: "security_evidence_v1",
    deterministicScore: Number.isFinite(input.deterministicScore) ? clamp(input.deterministicScore, 100) : 0,
    signalCount: input.signals.length,
    signals: input.signals.slice(0, 64).map((signal) => ({
      signalName: signal.signalName.replace(/[^A-Za-z0-9_.:-]/g, "_").slice(0, 100),
      source: signal.source.replace(/[^A-Za-z0-9_.:-]/g, "_").slice(0, 80),
      score: Number.isFinite(signal.score) ? clamp(signal.score, 100) : 0,
      confidence: signal.confidence !== null && Number.isFinite(signal.confidence) ? clamp(signal.confidence, 1) : null,
    })),
  };
}

const aiOutputSchema = z.object({
  riskScore: z.number().min(0).max(100), riskLevel: z.enum(["unknown", "low", "medium", "high", "critical"]), summary: z.string().max(4000),
  reasonCodes: z.array(z.string().max(100)).max(32), recommendedAction: z.enum(["ALLOW", "MONITOR", "CHALLENGE", "REVIEW", "BLOCK"]), confidence: z.number().min(0).max(1),
});

function extractText(content: unknown): string {
  if (typeof content === "string") return content;
  if (Array.isArray(content)) return content.filter((part): part is { text?: string } => typeof part === "object" && part !== null).map((part) => part.text ?? "").join("");
  return "";
}
function parseAdvisoryJson(text: string): z.infer<typeof aiOutputSchema> {
  const trimmed = text.trim().replace(/^```(?:json)?\s*/i, "").replace(/\s*```$/i, "");
  try { return aiOutputSchema.parse(JSON.parse(trimmed)); } catch {
    const start = trimmed.indexOf("{"), end = trimmed.lastIndexOf("}");
    if (start < 0 || end <= start) throw new Error("AI_ANALYZER_INVALID_JSON");
    return aiOutputSchema.parse(JSON.parse(trimmed.slice(start, end + 1)));
  }
}

export async function analyzeWithAI(rawInput: z.input<typeof aiInputSchema>) {
  const input = aiInputSchema.parse(rawInput);
  const client = new OpenRouter({ apiKey: input.apiKey, appTitle: "GainiRen Security" });
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), input.timeoutMs);
  try {
    const response = await client.chat.send({
      chatRequest: {
        model: input.model, temperature: 0, maxTokens: 1200,
        messages: [
          { role: "system", content: "You are GainiRen Security's advisory evidence analyst. Analyze only the supplied bounded security evidence. Never invent facts. Return JSON only with riskScore, riskLevel, summary, reasonCodes, recommendedAction, confidence. Your output is advisory only; the deterministic firewall remains authoritative." },
          { role: "user", content: JSON.stringify(input.evidence) },
        ],
      },
    }, { fetchOptions: { signal: controller.signal }, retries: { maxAttempts: 2 } });
    const content = extractText(response.choices?.[0]?.message?.content);
    if (!content) throw new Error("AI_ANALYZER_EMPTY_RESPONSE");
    const parsed = parseAdvisoryJson(content);
    const existing = await supabase.schema("security").from("model_versions").select("id").eq("model_name", input.model).eq("version", "openrouter-advisory-v1").maybeSingle();
    if (existing.error) throw existing.error;
    let modelVersionId = existing.data?.id;
    if (!modelVersionId) {
      const created = await supabase.schema("security").from("model_versions").insert({ model_name: input.model, version: "openrouter-advisory-v1", status: "active", feature_schema: { evidence: "security_evidence_v1" }, metrics: { mode: "advisory", provider: "openrouter" } }).select("id").single();
      if (created.error) throw created.error;
      modelVersionId = created.data.id;
    }
    const prediction = await supabase.schema("security").from("model_predictions").insert({ tenant_id: input.tenantId, subject_id: input.subjectId ?? null, session_id: input.sessionId ?? null, model_version_id: modelVersionId, prediction_type: "security_advisory", prediction_score: parsed.riskScore, prediction: parsed }).select("id").single();
    if (prediction.error) throw prediction.error;
    return { ...parsed, predictionId: prediction.data.id, modelVersionId };
  } finally { clearTimeout(timer); }
}
export type AIAnalysisResult = z.infer<typeof aiOutputSchema>;
