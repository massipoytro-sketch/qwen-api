import { z } from "zod";

const inputSchema = z.object({
  now: z.number().finite().optional(),
  events: z.array(z.object({
    occurredAt: z.string(),
    isBot: z.boolean().nullable().optional(),
    confidence: z.number().finite().min(0).max(1).nullable().optional(),
    signals: z.record(z.string(), z.unknown()).nullable().optional(),
  }).strict()).max(200),
}).strict();

const clamp = (n: number) => Math.max(0, Math.min(100, Math.round(n)));

export function analyzeBotDefense(rawInput: z.input<typeof inputSchema>) {
  const input = inputSchema.parse(rawInput);
  const now = input.now ?? Date.now();
  const events = input.events
    .map((event) => ({ ...event, time: Date.parse(event.occurredAt) }))
    .filter((event) => Number.isFinite(event.time) && event.time <= now && event.time >= now - 10 * 60_000)
    .sort((a, b) => a.time - b.time);

  const flags = new Set<string>();
  let explicitScore = 0;
  let confidence = 0;
  for (const event of events) {
    const c = Math.max(0, Math.min(1, Number(event.confidence ?? 0)));
    if (event.isBot === true) explicitScore = Math.max(explicitScore, c * 100);
    confidence = Math.max(confidence, c);
    for (const key of ["webdriver", "headless", "automationFramework", "knownBotUserAgent", "impossibleTiming", "tamperedClient"]) {
      if (event.signals?.[key] === true) flags.add(key);
    }
  }

  const count1m = events.filter((e) => e.time >= now - 60_000).length;
  const count5m = events.filter((e) => e.time >= now - 5 * 60_000).length;
  const count10m = events.length;
  const burstScore = count1m >= 30 ? 95 : count1m >= 20 ? 80 : count1m >= 10 ? 60 : count5m >= 40 ? 55 : count5m >= 25 ? 40 : 0;

  let periodicityScore = 0;
  if (events.length >= 6) {
    const intervals: number[] = [];
    for (let i = 1; i < events.length; i++) intervals.push(events[i].time - events[i - 1].time);
    const positive = intervals.filter((v) => v >= 50 && v <= 120_000);
    if (positive.length >= 5) {
      const mean = positive.reduce((a, b) => a + b, 0) / positive.length;
      const variance = positive.reduce((a, b) => a + (b - mean) ** 2, 0) / positive.length;
      const coefficient = mean > 0 ? Math.sqrt(variance) / mean : 1;
      if (coefficient <= 0.08) periodicityScore = 80;
      else if (coefficient <= 0.15) periodicityScore = 55;
      else if (coefficient <= 0.25) periodicityScore = 30;
    }
  }
  if (periodicityScore >= 55) flags.add("machine_periodicity");

  const signalDensity = Math.min(100, flags.size * 18);
  const score = clamp(Math.max(explicitScore, burstScore * 0.45 + periodicityScore * 0.25 + signalDensity * 0.3));
  const reasonCodes = [
    ...(explicitScore >= 70 ? ["EXPLICIT_BOT_CLASSIFIER"] : []),
    ...(burstScore >= 55 ? ["BOT_EVENT_BURST"] : []),
    ...(periodicityScore >= 55 ? ["BOT_MACHINE_PERIODICITY"] : []),
    ...(flags.size >= 2 ? ["MULTI_SIGNAL_AUTOMATION"] : []),
  ];
  const finalConfidence = score === 0 ? 0.35 : Math.min(0.99, 0.45 + (flags.size >= 2 ? 0.2 : flags.size ? 0.1 : 0) + (burstScore >= 55 ? 0.15 : 0) + (periodicityScore >= 55 ? 0.1 : 0) + explicitScore / 500);
  return {
    score,
    confidence: Number(finalConfidence.toFixed(3)),
    reasonCodes,
    signalFlags: [...flags].slice(0, 16),
    count1m,
    count5m,
    count10m,
    burstScore,
    periodicityScore,
    version: "bot-defense-v1",
  };
}
