const HASH_PATTERN = /^[a-f0-9]{64}$/;

/**
 * Produces a PostgREST OR expression that accepts the current API-key hash,
 * or the previous hash only while its explicitly bounded grace period remains.
 * The supplied key must already be SHA-256 hashed; raw credentials never enter filters.
 */
export function tenantApiKeyLookupFilter(keyHash: string, nowIso = new Date().toISOString()): string {
  if (!HASH_PATTERN.test(keyHash)) throw new Error("INVALID_API_KEY_HASH");
  const time = new Date(nowIso);
  if (!Number.isFinite(time.getTime())) throw new Error("INVALID_LOOKUP_TIME");
  const timestamp = time.toISOString();
  return `api_key_hash.eq.${keyHash},and(api_key_previous_hash.eq.${keyHash},api_key_previous_valid_until.gt.${timestamp})`;
}
