import { env } from "../config/env";

/** Render terminates TLS, so production requests are validated through the forwarded scheme. */
export function isSecureTransport(request: Request, production = env.NODE_ENV === "production"): boolean {
  if (!production) return true;
  const forwarded = request.headers.get("x-forwarded-proto")?.split(",", 1)[0]?.trim().toLowerCase();
  if (forwarded) return forwarded === "https";
  return new URL(request.url).protocol === "https:";
}

export function securityHeaders(): Record<string, string> {
  return {
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "permissions-policy": "camera=(), microphone=(), geolocation=(), payment=()",
    "cross-origin-opener-policy": "same-origin",
    "cross-origin-resource-policy": "same-origin",
    "content-security-policy": "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
  };
}
