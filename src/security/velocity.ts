export type TimedEvent = {
  occurredAt: string;
  eventType?: string | null;
};

export type VelocityResult = {
  score: number;
  confidence: number;
  count1m: number;
  count5m: number;
  count15m: number;
  distinctTypes: number;
  regularityScore: number;
};

const clamp = (value: number) => Math.max(0, Math.min(100, value));

export function analyzeVelocity(events: TimedEvent[], now = Date.now()): VelocityResult {
  const valid = events
    .map((event) => ({ ...event, ts: Date.parse(event.occurredAt) }))
    .filter((event) => Number.isFinite(event.ts) && event.ts <= now && event.ts >= now - 15 * 60_000)
    .sort((a, b) => a.ts - b.ts);

  const count1m = valid.filter((e) => e.ts >= now - 60_000).length;
  const count5m = valid.filter((e) => e.ts >= now - 5 * 60_000).length;
  const count15m = valid.length;
  const distinctTypes = new Set(valid.map((e) => e.eventType).filter(Boolean)).size;

  const intervals: number[] = [];
  for (let i = 1; i < valid.length; i++) intervals.push(valid[i].ts - valid[i - 1].ts);
  const mean = intervals.length ? intervals.reduce((a, b) => a + b, 0) / intervals.length : 0;
  const variance = intervals.length > 1
    ? intervals.reduce((sum, value) => sum + (value - mean) ** 2, 0) / intervals.length
    : 0;
  const coefficient = mean > 0 ? Math.sqrt(variance) / mean : 0;
  const regularityScore = intervals.length >= 4 && coefficient < 0.12 ? 100 :
    intervals.length >= 4 && coefficient < 0.25 ? 60 : 0;

  const burstScore = count1m >= 30 ? 100 : count1m >= 20 ? 80 : count1m >= 10 ? 55 : count1m >= 5 ? 25 : 0;
  const sustainedScore = count5m >= 100 ? 100 : count5m >= 60 ? 75 : count5m >= 30 ? 45 : 0;
  const score = clamp(Math.round(burstScore * 0.55 + sustainedScore * 0.3 + regularityScore * 0.15));

  return {
    score,
    confidence: count15m >= 5 ? 0.8 : 0.5,
    count1m,
    count5m,
    count15m,
    distinctTypes,
    regularityScore,
  };
}
