export type SecurityEventSample = {
  eventType: string;
  occurredAt: string;
  severity?: string | null;
};

export type SessionSample = {
  deviceId?: string | null;
  ipId?: string | null;
  startedAt: string;
  endedAt?: string | null;
};

export type GeoObservation = {
  latitude: number;
  longitude: number;
  occurredAt: string;
  countryCode?: string | null;
  source?: string | null;
};

const clampScore = (score: number) => Math.max(0, Math.min(100, Math.round(score)));
const normalizeEventType = (value: string) => value.toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, "");
const validTime = (value: string) => {
  const timestamp = Date.parse(value);
  return Number.isFinite(timestamp) ? timestamp : null;
};

export function analyzeAccountTakeoverSignals(events: SecurityEventSample[], now = Date.now()) {
  const dayAgo = now - 24 * 60 * 60_000;
  const recent = events.flatMap((event) => {
    const timestamp = validTime(event.occurredAt);
    if (timestamp === null || timestamp > now || timestamp < dayAgo) return [];
    return [{ eventType: normalizeEventType(event.eventType), timestamp, severity: event.severity?.toLowerCase() ?? "" }];
  });
  const failedLoginEvents = recent.filter((event) =>
    /failed_login|login_failed|sign_in_failed|signin_failed|authentication_failed|invalid_password|credential_stuffing/.test(event.eventType) &&
    event.timestamp >= now - 5 * 60_000
  );
  const lastHour = recent.filter((event) => event.timestamp >= now - 60 * 60_000);
  const mfaChange = lastHour.some((event) => /mfa_disabled|mfa_removed|two_factor_disabled|security_key_removed/.test(event.eventType));
  const emailChange = lastHour.some((event) => /email_changed|primary_email_changed|phone_changed/.test(event.eventType));
  const recovery = lastHour.some((event) => /password_reset|credential_changed|account_recovery|recovery_completed|oauth_provider_added/.test(event.eventType));
  const newDevice = lastHour.some((event) => /new_device|device_changed|unknown_device/.test(event.eventType));
  const newCountry = lastHour.some((event) => /new_country|country_changed|location_change/.test(event.eventType));
  const confirmedCompromise = lastHour.some((event) =>
    /account_compromised|session_hijack|token_theft|account_takeover_confirmed/.test(event.eventType) ||
    (event.severity === "critical" && /compromis|hijack|token_theft/.test(event.eventType))
  );

  let score = failedLoginEvents.length >= 10 ? 65 :
    failedLoginEvents.length >= 5 ? 45 :
      failedLoginEvents.length >= 3 ? 30 : 0;
  const reasonCodes: string[] = [];
  if (failedLoginEvents.length >= 3) reasonCodes.push("FAILED_LOGIN_BURST");
  if (mfaChange) { score = Math.max(score, 45); reasonCodes.push("MFA_SECURITY_CHANGE"); }
  if (emailChange) { score = Math.max(score, 35); reasonCodes.push("IDENTITY_CONTACT_CHANGE"); }
  if (recovery) { score = Math.max(score, 25); reasonCodes.push("ACCOUNT_RECOVERY_ACTIVITY"); }
  if (newDevice) { score = Math.max(score, 20); reasonCodes.push("NEW_DEVICE_AUTH_ACTIVITY"); }
  if (newCountry) { score = Math.max(score, 30); reasonCodes.push("NEW_COUNTRY_AUTH_ACTIVITY"); }
  if (failedLoginEvents.length >= 5 && recovery) {
    score = Math.min(100, score + 15);
    reasonCodes.push("FAILED_LOGIN_WITH_RECOVERY");
  }
  if (confirmedCompromise) {
    score = 100;
    reasonCodes.push("ACCOUNT_COMPROMISE_CONFIRMED");
  }

  return {
    score: clampScore(score),
    confidence: confirmedCompromise ? 0.98 : score > 0 ? 0.72 : 0.35,
    reasonCodes: [...new Set(reasonCodes)],
    failedLoginCount5m: failedLoginEvents.length,
    sensitiveEventCount1h: [mfaChange, emailChange, recovery, newDevice, newCountry].filter(Boolean).length,
    version: "account-takeover-v1",
  };
}

export function analyzeConcurrentSessionAnomalies(sessions: SessionSample[], now = Date.now()) {
  const since = now - 24 * 60 * 60_000;
  const active = sessions.filter((session) => {
    const started = validTime(session.startedAt);
    return started !== null && started <= now && started >= since && !session.endedAt;
  });
  const deviceCount = new Set(active.map((session) => session.deviceId).filter((id): id is string => Boolean(id))).size;
  const ipCount = new Set(active.map((session) => session.ipId).filter((id): id is string => Boolean(id))).size;
  const reasonCodes: string[] = [];
  let score = 0;

  if (active.length >= 8) { score = Math.max(score, 65); reasonCodes.push("CONCURRENT_SESSION_BURST"); }
  if (active.length >= 5 && deviceCount >= 4) { score = Math.max(score, 70); reasonCodes.push("MULTI_DEVICE_SESSION_PATTERN"); }
  else if (active.length >= 5 && deviceCount >= 3) { score = Math.max(score, 45); reasonCodes.push("MULTI_DEVICE_SESSION_PATTERN"); }
  if (active.length >= 5 && ipCount >= 4) { score = Math.max(score, 65); reasonCodes.push("MULTI_NETWORK_SESSION_PATTERN"); }
  if (active.length >= 5 && deviceCount >= 3 && ipCount >= 3) {
    score = Math.max(score, 75);
    reasonCodes.push("DIVERSE_SESSION_FOOTPRINT");
  }

  return {
    score: clampScore(score),
    confidence: score > 0 ? Math.min(0.9, 0.55 + active.length / 50) : 0.3,
    reasonCodes: [...new Set(reasonCodes)],
    activeSessionCount: active.length,
    distinctDeviceCount: deviceCount,
    distinctIpCount: ipCount,
    version: "session-anomaly-v1",
  };
}

function validGeo(observation: GeoObservation) {
  return Number.isFinite(observation.latitude) &&
    Number.isFinite(observation.longitude) &&
    observation.latitude >= -90 && observation.latitude <= 90 &&
    observation.longitude >= -180 && observation.longitude <= 180 &&
    (observation.source === "trusted_geoip" || observation.source === "tenant_server");
}

function distanceKm(a: GeoObservation, b: GeoObservation) {
  const radians = (degrees: number) => degrees * Math.PI / 180;
  const dLat = radians(b.latitude - a.latitude);
  const dLon = radians(b.longitude - a.longitude);
  const lat1 = radians(a.latitude);
  const lat2 = radians(b.latitude);
  const h = Math.sin(dLat / 2) ** 2 + Math.cos(lat1) * Math.cos(lat2) * Math.sin(dLon / 2) ** 2;
  return 6371 * 2 * Math.asin(Math.min(1, Math.sqrt(h)));
}

export function analyzeImpossibleTravel(previous: GeoObservation | null, current: GeoObservation, now = Date.now()) {
  const unavailable = {
    applicable: false,
    score: 0,
    confidence: 0.35,
    distanceKm: null as number | null,
    speedKmh: null as number | null,
    elapsedMinutes: null as number | null,
    reasonCodes: [] as string[],
    version: "impossible-travel-v1",
  };
  if (!previous || !validGeo(previous) || !validGeo(current)) return unavailable;
  const previousTime = validTime(previous.occurredAt);
  const currentTime = validTime(current.occurredAt);
  if (previousTime === null || currentTime === null || currentTime <= previousTime || currentTime > now + 60_000) return unavailable;
  const elapsedHours = (currentTime - previousTime) / 3_600_000;
  if (elapsedHours <= 0) return unavailable;

  const distance = distanceKm(previous, current);
  const speed = distance / elapsedHours;
  let score = 0;
  const reasonCodes: string[] = [];
  if (distance >= 500 && speed >= 900) {
    score = 90;
    reasonCodes.push("IMPOSSIBLE_TRAVEL", "EXTREME_TRAVEL_SPEED");
  } else if (distance >= 300 && speed >= 700) {
    score = 75;
    reasonCodes.push("IMPOSSIBLE_TRAVEL", "HIGH_TRAVEL_SPEED");
  } else if (distance >= 200 && speed >= 500) {
    score = 60;
    reasonCodes.push("IMPOSSIBLE_TRAVEL", "HIGH_TRAVEL_SPEED");
  }
  return {
    applicable: true,
    score,
    confidence: score > 0 ? 0.82 : 0.45,
    distanceKm: Number(distance.toFixed(2)),
    speedKmh: Number(speed.toFixed(2)),
    elapsedMinutes: Number(((currentTime - previousTime) / 60_000).toFixed(2)),
    reasonCodes,
    version: "impossible-travel-v1",
  };
}
