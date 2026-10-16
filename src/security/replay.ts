import type { SecurityDecision } from "./types";
import { strictestDecision, scoreFloorForEnforcement } from "./enforcement";

export type ReplayEvent = {
  sequence: number;
  eventType: string;
  occurredAt: string;
  decision: SecurityDecision;
  score: number;
  reasonCodes?: string[];
};

export type ReplayResult = {
  eventCount: number;
  finalDecision: SecurityDecision;
  finalScoreFloor: number;
  escalations: number;
  decisions: SecurityDecision[];
  reasonCodes: string[];
};

function finiteScore(value: number): number {
  return Number.isFinite(value) ? Math.max(0, Math.min(100, value)) : 0;
}

/**
 * Pure, offline replay. It never performs network I/O, writes to Supabase,
 * executes tools, or changes a live security decision. Input is expected to be
 * a sanitized event summary captured by the operator layer.
 */
export function replaySecurityTimeline(events: ReplayEvent[]): ReplayResult {
  if (!Array.isArray(events)) throw new Error("REPLAY_EVENTS_INVALID");
  if (events.length > 500) throw new Error("REPLAY_TOO_MANY_EVENTS");

  const ordered = [...events].sort((a, b) => a.sequence - b.sequence);
  let previous: SecurityDecision = "ALLOW";
  let escalations = 0;
  const decisions: SecurityDecision[] = [];
  const reasonCodes: string[] = [];

  for (let index = 0; index < ordered.length; index += 1) {
    const event = ordered[index];
    if (!Number.isInteger(event.sequence) || event.sequence !== index + 1) {
      throw new Error("REPLAY_SEQUENCE_INVALID");
    }
    if (typeof event.eventType !== "string" || !/^[A-Za-z0-9_.:-]{1,120}$/.test(event.eventType)) {
      throw new Error("REPLAY_EVENT_TYPE_INVALID");
    }
    if (typeof event.occurredAt !== "string" || !Number.isFinite(Date.parse(event.occurredAt))) {
      throw new Error("REPLAY_TIMESTAMP_INVALID");
    }
    if (!["ALLOW", "MONITOR", "CHALLENGE", "REVIEW", "BLOCK"].includes(event.decision)) {
      throw new Error("REPLAY_DECISION_INVALID");
    }
    if (typeof event.score !== "number") throw new Error("REPLAY_SCORE_INVALID");
    if (event.reasonCodes !== undefined && !Array.isArray(event.reasonCodes)) {
      throw new Error("REPLAY_REASON_CODES_INVALID");
    }

    const decision = strictestDecision(previous, event.decision);
    if (decision !== previous) escalations += 1;
    previous = decision;
    decisions.push(decision);

    for (const code of (event.reasonCodes ?? []).slice(0, 32)) {
      if (typeof code === "string" && /^[A-Z0-9_.:-]{1,100}$/.test(code)) reasonCodes.push(code);
    }
  }

  const uniqueReasons = [...new Set(reasonCodes)].slice(0, 128);
  const highestObservedScore = ordered.reduce((max, event) => Math.max(max, finiteScore(event.score)), 0);

  return {
    eventCount: ordered.length,
    finalDecision: previous,
    finalScoreFloor: Math.max(scoreFloorForEnforcement(previous), highestObservedScore),
    escalations,
    decisions,
    reasonCodes: uniqueReasons,
  };
}
