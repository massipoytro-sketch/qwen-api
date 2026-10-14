export type RiskSignal = {
  signalName: string;
  source: string;
  score: number;
  confidence: number | null;
};

const clamp = (value: number, min: number, max: number) => Math.max(min, Math.min(max, value));

/**
 * Only deterministic signals can contribute to security decisions. AI signals
 * are explicitly excluded here as a second guard against accidental coupling.
 */
export function aggregateSecurityRisk(signals: RiskSignal[]): number {
  const deterministic = signals.filter((signal) =>
    signal.source !== "ai" &&
    signal.source !== "ai_advisory" &&
    signal.signalName !== "ai_advisory"
  );
  if (!deterministic.length) return 0;

  const normalized = deterministic.map((signal) => ({
    source: signal.source,
    score: Number.isFinite(signal.score) ? clamp(signal.score, 0, 100) : 0,
    confidence: signal.confidence !== null && Number.isFinite(signal.confidence)
      ? clamp(signal.confidence, 0, 1)
      : 0.5,
  }));
  const weighted = normalized.reduce((total, signal) => total + signal.score * signal.confidence, 0);
  const sourceBonus = Math.min(15, Math.max(0, new Set(normalized.map((signal) => signal.source)).size - 1) * 5);
  const highSignalBonus = normalized.filter((signal) => signal.score >= 70).length >= 2 ? 10 : 0;
  const score = Math.round(Math.min(100, weighted * 0.55 + sourceBonus + highSignalBonus));
  return Number.isFinite(score) ? clamp(score, 0, 100) : 0;
}
