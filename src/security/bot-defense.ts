import { z } from "zod";

const clamp = (value: number) => Math.max(0, Math.min(100, Math.round(value)));

const inputSchema = z.object({
  events: z.array(z.object({
    occurredAt: z.string().datetime(),
    isBot: z.boolean().nullable().optional(),
    confidence: z.number().finite().min(0).max(1).nullable().optional(),
    flags: z.array(z.enum([
      "webdriver", "headless", "automationFramework", "knownBotUserAgent",
      "impossibleTiming", "tamperedClient", "missingInteraction", "replayedRequest",
    ])).max(20).default([]),
    requestIntervalMs: z.number().finite().positive().max(86_400_000).nullable().optional(),
  }).strict()).max(500),
  now: z.number().finite().optional(),
}).strict();

/**
 * Server-side bot scoring. It deliberately requires corroboration: a single
 * browser flag or user-agent anomaly cannot block a legitimate user.
 */
export function analyzeBotDefense(rawInput: z.input<typeof inputSchema>) {
  const input = inputSchema.parse(rawInput);
  const now = input.now ?? Date.now();
  const recent = input.events.filter((event) => {
    const at = Date.parse(event.occurredAt);
    return Number.isFinite(at) && at <= now && at >= now - 10 * 60_000;
  });

  const flagCounts = new Map<string, number>();
  let classifierScore = 0;
  let classifierConfidence = 0;
  let replayCount = 0;
  let impossibleTimingCount = 0;

  for (const event of recent) {
    const confidence = Math.max(0, Math.min(1, event.confidence ?? 0));
    if (event.isBot === true) classifierScore = Math.max(classifierScore, confidence * 100);
    classifierConfidence = Math.max(classifierConfidence, confidence);
    for (const flag of event.flags) {
      flagCounts.set(flag, (flagCounts.get(flag) ?? 0) + 1);
      if (flag === "replayedRequest") replayCount += 1;
      if (flag === "impossibleTiming") impossibleTimingCount += 1;
    }
  }

  const corroboratingFlags = ["webdriver", "headless", "automationFramework", "knownBotUserAgent", "tamperedClient", "missingInteraction"]
    .filter((flag) => (flagCounts.get(flag) ?? 0) > 0);
  const repeatedFlags = corroboratingFlags.filter((flag) => (flagCounts.get(flag) ?? 0) >= 2);
  const intervals = recent.map((event) => event.requestIntervalMs).filter((value): value is number => value != null && Number.isFinite(value));
  const tinyIntervals = intervals.filter((value) => value < 80).length;
  const requestBurstScore = recent.length >= 80 ? 100 : recent.length >= 40 ? 80 : recent.length >= 20 ? 55 : recent.length >= 10 ? 30 : 0;
  const timingScore = tinyIntervals >= 8 ? 85 : tinyIntervals >= 4 ? 65 : impossibleTimingCount >= 3 ? 55 : 0;
  const replayScore = replayCount >= 3 ? 100 : replayCount === 2 ? 80 : replayCount === 1 ? 55 : 0;
  const corroborationScore = corroboratingFlags.length >= 4 ? 90 : corroboratingFlags.length >= 3 ? 75 : corroboratingFlags.length >= 2 ? 55 : corroboratingFlags.length === 1 ? 25 : 0;

  const score = clamp(Math.max(
    classifierScore,
    requestBurstScore * 0.6 + corroborationScore * 0.4,
    timingScore * 0.65 + corroborationScore * 0.35,
    replayScore,
  ));
  const strongCorroboration = repeatedFlags.length >= 1 || corroboratingFlags.length >= 3;
  const decision = score >= 98 && strongCorroboration && (classifierConfidence >= 0.95 || replayScore >= 80)
    ? "REVIEW"
    : score >= 75 && (strongCorroboration || replayScore >= 80)
      ? "CHALLENGE"
      : score >= 45 ? "MONITOR" : "ALLOW";

  return {
    score,
    confidence: score === 0 ? 0.35 : Math.min(0.97, 0.5 + corroboratingFlags.length * 0.08 + (classifierScore > 0 ? classifierConfidence * 0.2 : 0)),
    decision,
    reasonCodes: [
      ...(classifierScore > 0 ? ["BOT_CLASSIFIER_SIGNAL"] : []),
      ...(corroboratingFlags.length >= 2 ? ["MULTI_SIGNAL_BOT_CORRELATION"] : []),
      ...(repeatedFlags.length > 0 ? ["REPEATED_CLIENT_AUTOMATION_FLAGS"] : []),
      ...(requestBurstScore >= 55 ? ["REQUEST_BURST"] : []),
      ...(timingScore >= 55 ? ["AUTOMATION_TIMING_PATTERN"] : []),
      ...(replayScore >= 55 ? ["REQUEST_REPLAY_PATTERN"] : []),
    ],
    signalFlags: corroboratingFlags,
    repeatedFlags,
    eventCount: recent.length,
    replayCount,
    version: "bot-defense-v2",
  } as const;
}
