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
    const response = await fetch(input.endpoint, {
      method: "POST",
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
          {
            role: "user",
            content: JSON.stringify(input.evidence),
          },
        ],
      }),
      signal: controller.signal,
    });

    if (!response.ok) throw new Error(`AI_ANALYZER_HTTP_${response.status}`);

    const payload = await response.json() as {
      choices?: Array<{ message?: { content?: string } }>;
    };
    const content = payload.choices?.[0]?.message?.content;
    if (!content) throw new Error("AI_ANALYZER_EMPTY_RESPONSE");

    const parsed = aiOutputSchema.parse(JSON.parse(content));

    const version = await supabase.schema("security").from("model_versions").upsert({
      model_name: input.model,
      version: "advisory-v1",
      status: "active",
      feature_schema: { evidence: "security_evidence_v1" },
      metrics: { mode: "advisory" },
    }, { onConflict: "model_name,version" }).select("id").single();
    if (version.error) throw version.error;

    const prediction = await supabase.schema("security").from("model_predictions").insert({
      tenant_id: input.tenantId,
      subject_id: input.subjectId ?? null,
      session_id: input.sessionId ?? null,
      model_version_id: version.data.id,
      prediction_type: "security_advisory",
      prediction_score: parsed.riskScore,
      prediction: parsed,
    }).select("id").single();
    if (prediction.error) throw prediction.error;

    return { ...parsed, predictionId: prediction.data.id, modelVersionId: version.data.id };
  } finally {
    clearTimeout(timer);
  }
}

export type AIAnalysisResult = z.infer<typeof aiOutputSchema>;
