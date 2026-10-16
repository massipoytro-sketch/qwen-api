import { z } from "zod";

const clamp = (value: number) => Math.max(0, Math.min(100, Math.round(value)));
const BOT_FLAGS = [
  "webdriver", "headless", "automationFramework", "knownBotUserAgent",
  "impossibleTiming", "tamperedClient", "missingInteraction", "replayedRequest",
] as const;
type BotFlag = (typeof BOT_FLAGS)[number];

const inputSchema = z.object({
  now: z.number().finite().optional(),
  events: z.array(z.object({
    occurredAt: z.string().datetime(),
    isBot: z.boolean().nullable().optional(),
    confidence: z.number().finite().min(0).max(1).nullable().optional(),
    signals: z.record(z.string(), z.unknown()).nullable().optional(),
    flags: z.array(z.enum(BOT_FLAGS)).max(20).default([]),
    requestIntervalMs: z.number().finite().positive().max(86_400_000).nullable().optional(),
  }).strict()).max(500),
}).strict();

/** Deterministic bot evidence fusion; it never returns BLOCK. */
export function analyzeBotDefense(rawInput: z.input<typeof inputSchema>) {
  const input = inputSchema.parse(rawInput);
  const now = input.now ?? Date.now();
  const recent = input.events
    .map((event) => ({ ...event, time: Date.parse(event.occurredAt) }))
    .filter((event) => Number.isFinite(event.time) && event.time <= now && event.time >= now - 10 * 60_000)
    .sort((a, b) => a.time - b.time);

  const flagCounts = new Map<BotFlag, number>();
  let classifierScore = 0;
  let classifierConfidence = 0;
  let replayCount = 0;
  let impossibleTimingCount = 0;
  for (const event of recent) {
    const confidence = event.confidence ?? 0;
    if (event.isBot === true) classifierScore = Math.max(classifierScore, confidence * 100);
    classifierConfidence = Math.max(classifierConfidence, confidence);
    const mergedFlags = new Set<BotFlag>(event.flags);
    for (const flag of BOT_FLAGS) if (event.signals?.[flag] === true) mergedFlags.add(flag);
    for (const flag of mergedFlags) {
      flagCounts.set(flag, (flagCounts.get(flag) ?? 0) + 1);
      if (flag === "replayedRequest") replayCount += 1;
      if (flag === "impossibleTiming") impossibleTimingCount += 1;
    }
  }

  const corroboratingFlags = BOT_FLAGS.filter((flag) => flag !== "replayedRequest" && (flagCounts.get(flag) ?? 0) > 0);
  const repeatedFlags = corroboratingFlags.filter((flag) => (flagCounts.get(flag) ?? 0) >= 2);
  const count1m = recent.filter((event) => event.time >= now - 60_000).length;
  const count5m = recent.filter((event) => event.time >= now - 5 * 60_000).length;
  const count10m = recent.length;
  const requestBurstScore =
    count1m >= 80 ? 100 :
    count1m >= 40 ? 85 :
    count1m >= 20 ? 65 :
    count1m >= 10 ? 45 :
    count5m >= 40 ? 55 :
    count5m >= 25 ? 40 : 0;

  const timestamps = recent.map((event) => event.time);
  const derivedIntervals: number[] = [];
  for (let i = 1; i < timestamps.length; i += 1) {
    const interval = timestamps[i] - timestamps[i - 1];
    if (interval > 0 && interval <= 120_000) derivedIntervals.push(interval);
  }
  const explicitIntervals = recent
    .map((event) => event.requestIntervalMs)
    .filter((value): value is number => value !== null && value !== undefined && Number.isFinite(value));
  const intervals = explicitIntervals.length ? explicitIntervals : derivedIntervals;
  const tinyIntervals = intervals.filter((value) => value < 80).length;

  let periodicityScore = 0;
  if (derivedIntervals.length >= 5) {
    const mean = derivedIntervals.reduce((total, value) => total + value, 0) / derivedIntervals.length;
    const variance = derivedIntervals.reduce((total, value) => total + (value - mean) ** 2, 0) / derivedIntervals.length;
    const coefficient = mean > 0 ? Math.sqrt(variance) / mean : 1;
    if (coefficient <= 0.08) periodicityScore = 80;
    else if (coefficient <= 0.15) periodicityScore = 55;
    else if (coefficient <= 0.25) periodicityScore = 30;
  }

  const timingScore = tinyIntervals >= 8 ? 85 : tinyIntervals >= 4 ? 65 : impossibleTimingCount >= 3 ? 55 : 0;
  const replayScore = replayCount >= 3 ? 100 : replayCount === 2 ? 85 : replayCount === 1 ? 55 : 0;
  const corroborationScore =
    corroboratingFlags.length >= 4 ? 90 :
    corroboratingFlags.length >= 3 ? 75 :
    corroboratingFlags.length >= 2 ? 55 :
    corroboratingFlags.length === 1 ? 25 : 0;
  const flags = new Set<string>(corroboratingFlags);
  if (periodicityScore >= 55) flags.add("machine_periodicity");
  if (replayScore > 0) flags.add("replayedRequest");
  const signalDensity = Math.min(100, corroboratingFlags.length * 18);
  const score = clamp(Math.max(
    classifierScore,
    requestBurstScore * 0.6 + corroborationScore * 0.4,
    timingScore * 0.65 + corroborationScore * 0.35,
    replayScore,
    periodicityScore * 0.25 + signalDensity * 0.3,
  ));
  const strongCorroboration = repeatedFlags.length >= 1 || corroboratingFlags.length >= 3;
  const decision =
    score >= 98 && strongCorroboration && (classifierConfidence >= 0.95 || replayScore >= 80) ? "REVIEW" :
    score >= 75 && (strongCorroboration || replayScore >= 80) ? "CHALLENGE" :
    score >= 45 ? "MONITOR" : "ALLOW";
  const reasonCodes = [
    ...(classifierScore >= 70 ? ["EXPLICIT_BOT_CLASSIFIER"] : []),
    ...(requestBurstScore >= 55 ? ["BOT_EVENT_BURST"] : []),
    ...(periodicityScore >= 55 ? ["BOT_MACHINE_PERIODICITY"] : []),
    ...(timingScore >= 55 ? ["AUTOMATION_TIMING_PATTERN"] : []),
    ...(replayScore >= 55 ? ["REQUEST_REPLAY_PATTERN"] : []),
    ...(corroboratingFlags.length >= 2 ? ["MULTI_SIGNAL_AUTOMATION"] : []),
    ...(repeatedFlags.length > 0 ? ["REPEATED_AUTOMATION_FLAGS"] : []),
  ];
  const confidence = score === 0 ? 0.35 : Math.min(0.97,
    0.45 + (corroboratingFlags.length >= 2 ? 0.18 : corroboratingFlags.length ? 0.08 : 0)
    + (requestBurstScore >= 55 ? 0.12 : 0)
    + (periodicityScore >= 55 ? 0.08 : 0)
    + (classifierScore > 0 ? classifierConfidence * 0.2 : 0)
    + (replayScore >= 80 ? 0.1 : 0));
  return {
    score,
    confidence: Number(confidence.toFixed(3)),
    decision,
    reasonCodes: [...new Set(reasonCodes)].slice(0, 16),
    signalFlags: [...flags].slice(0, 16),
    repeatedFlags,
    count1m, count5m, count10m,
    burstScore: requestBurstScore,
    periodicityScore,
    replayCount,
    version: "bot-defense-v2",
  } as const;
}
