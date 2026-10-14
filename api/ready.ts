import { createClient } from "@supabase/supabase-js";
import { env } from "../src/config/env";
import { safeErrorCode, safeErrorStatus, securityLog } from "../src/security/observability";

const readinessClient = createClient(env.SUPABASE_URL, env.SUPABASE_SERVER_KEY, {
  auth: { autoRefreshToken: false, persistSession: false, detectSessionInUrl: false },
  global: {
    fetch: (input, init) => fetch(input, {
      ...init,
      signal: init?.signal ?? AbortSignal.timeout(3000),
    }),
  },
});

const response = (status: number, body: Record<string, unknown>) => new Response(JSON.stringify(body), {
  status,
  headers: {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
  },
});

/**
 * Readiness checks only the dedicated security database and returns no schema,
 * project, tenant, or provider details. Liveness (/api/health) remains cheap and
 * does not depend on database availability.
 */
export default async function handler(request: Request) {
  if (request.method !== "GET") return response(405, { status: "method_not_allowed" });
  try {
    const result = await readinessClient.schema("security").from("tenants").select("id").limit(1);
    if (result.error) throw result.error;
    return response(200, { service: "gainiren-security", status: "ready" });
  } catch (error) {
    securityLog("readiness_check_failed", {
      errorCode: safeErrorCode(error),
      ...(safeErrorStatus(error) ? { errorStatus: safeErrorStatus(error) } : {}),
    });
    return response(503, { service: "gainiren-security", status: "not_ready" });
  }
}
