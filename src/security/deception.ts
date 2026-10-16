import { createHash } from "node:crypto";

const LOCATOR_PREFIX = "GAINIREN-DECEPTION-LOCATOR-V1\n";

/**
 * Hashes a canonical locator before it is stored. A locator is a synthetic
 * route/category key, never a secret or real credential.
 */
export function hashDeceptionLocator(locator: string): string {
  return createHash("sha256")
    .update(LOCATOR_PREFIX, "utf8")
    .update(locator, "utf8")
    .digest("hex");
}

export function isSafeDeceptionLocator(locator: string): boolean {
  return /^(honeydb:[a-z_]{1,40}:[a-z_]{1,80}|route:\/[A-Za-z0-9/_-]{1,180}|canary:[A-Za-z0-9:_-]{1,150})$/.test(locator);
}
