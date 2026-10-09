import { z } from "zod";
import { supabase } from "../db/supabase";

const botEventSchema = z.object({
  tenantId: z.uuid(),
  sessionId: z.uuid().optional(),
  subjectId: z.uuid().optional(),
  botType: z.string().min(1).max(100).default("unknown"),
  confidence: z.number().min(0).max(1),
  isBot: z.boolean(),
  signals: z.record(z.string(), z.unknown()).default({}),
});

const behaviorEventSchema = z.object({
  tenantId: z.uuid(),
  sessionId: z.uuid().optional(),
  subjectId: z.uuid().optional(),
  eventType: z.string().min(1).max(100),
  durationMs: z.number().int().min(0).optional(),
  featureVector: z.array(z.number().finite()).max(2048).optional(),
  anomalyScore: z.number().min(0).max(100).optional(),
  metadata: z.record(z.string(), z.unknown()).default({}),
});

const botRiskScore = (confidence: number, isBot: boolean) =>
  isBot ? Math.min(100, Math.round(confidence * 100)) : 0;

export async function registerBotEvent(rawInput: z.input<typeof botEventSchema>) {
  const input = botEventSchema.parse(rawInput);

  const result = await supabase.schema("security").from("bot_events").insert({
    tenant_id: input.tenantId,
    session_id: input.sessionId ?? null,
    subject_id: input.subjectId ?? null,
    detection_method: input.botType,
    confidence: input.confidence,
    is_bot: input.isBot,
    signals: input.signals,
  }).select("id,confidence,is_bot").single();

  if (result.error) throw result.error;

  return {
    botEventId: result.data.id,
    isBot: result.data.is_bot,
    confidence: result.data.confidence,
    riskScore: botRiskScore(result.data.confidence, result.data.is_bot),
  };
}

export async function registerBehaviorEvent(
  rawInput: z.input<typeof behaviorEventSchema>,
) {
  const input = behaviorEventSchema.parse(rawInput);

  const result = await supabase.schema("security").from("behavior_events").insert({
    tenant_id: input.tenantId,
    session_id: input.sessionId ?? null,
    subject_id: input.subjectId ?? null,
    event_type: input.eventType,
    duration_ms: input.durationMs ?? null,
    feature_vector: input.featureVector ?? null,
    anomaly_score: input.anomalyScore ?? null,
    metadata: input.metadata,
  }).select("id,anomaly_score").single();

  if (result.error) throw result.error;

  return {
    behaviorEventId: result.data.id,
    anomalyScore: result.data.anomaly_score,
  };
}
