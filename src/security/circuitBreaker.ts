import { z } from "zod";
import { supabase } from "../db/supabase";
import { safeErrorCode, safeErrorStatus, securityLog } from "./observability";

const permitSchema = z.object({
  allowed: z.boolean(),
  state: z.enum(["closed", "open", "half_open"]),
  retryAfterSeconds: z.number().int().nonnegative().optional(),
  probeToken: z.string().uuid().nullable().optional(),
  failureCount: z.number().int().nonnegative().optional(),
  failureThreshold: z.number().int().positive().optional(),
});

export type CircuitBreakerOptions = {
  tenantId: string;
  circuitKey: string;
  failureThreshold?: number;
  windowSeconds?: number;
  openSeconds?: number;
};

async function recordOutcome(input: CircuitBreakerOptions & {
  success: boolean;
  probeToken: string | null;
  errorCode?: string;
}): Promise<void> {
  const result = await supabase.schema("security").rpc("record_security_circuit_outcome", {
    p_tenant_id: input.tenantId,
    p_circuit_key: input.circuitKey,
    p_success: input.success,
    p_probe_token: input.probeToken,
    p_failure_threshold: input.failureThreshold ?? 5,
    p_window_seconds: input.windowSeconds ?? 60,
    p_open_seconds: input.openSeconds ?? 60,
    p_error_code: input.errorCode ?? null,
  });
  if (result.error) throw result.error;
}

/**
 * Executes one operation through a database-backed circuit breaker. Closed
 * permits are cheap and parallel; only one half-open probe can run at a time.
 * Open circuits fail quickly so a struggling optional dependency cannot consume
 * all outbox worker time. Error details are never copied into persistent state.
 */
export async function withSecurityCircuitBreaker<T>(
  options: CircuitBreakerOptions & { operation: () => Promise<T> },
): Promise<T> {
  const parsedOptions = z.object({
    tenantId: z.uuid(),
    circuitKey: z.string().min(1).max(100).regex(/^[a-zA-Z0-9:_-]+$/),
    failureThreshold: z.number().int().min(2).max(100).default(5),
    windowSeconds: z.number().int().min(10).max(3600).default(60),
    openSeconds: z.number().int().min(5).max(3600).default(60),
  }).parse(options);

  const permitResult = await supabase.schema("security").rpc("acquire_security_circuit_permit", {
    p_tenant_id: parsedOptions.tenantId,
    p_circuit_key: parsedOptions.circuitKey,
    p_failure_threshold: parsedOptions.failureThreshold,
    p_window_seconds: parsedOptions.windowSeconds,
    p_open_seconds: parsedOptions.openSeconds,
  });
  if (permitResult.error) throw permitResult.error;

  const permit = permitSchema.parse(permitResult.data);
  if (!permit.allowed) {
    const error = new Error("CIRCUIT_OPEN");
    error.name = "CIRCUIT_OPEN";
    securityLog("circuit_breaker_rejected", {
      tenantId: parsedOptions.tenantId,
      circuitKey: parsedOptions.circuitKey,
      state: permit.state,
      retryAfterSeconds: permit.retryAfterSeconds ?? 1,
      failureCount: permit.failureCount ?? 0,
    });
    throw error;
  }

  const probeToken = permit.state === "half_open" ? permit.probeToken ?? null : null;
  try {
    const value = await options.operation();
    try {
      await recordOutcome({ ...parsedOptions, success: true, probeToken });
    } catch (error) {
      securityLog("circuit_breaker_success_record_failed", {
        tenantId: parsedOptions.tenantId,
        circuitKey: parsedOptions.circuitKey,
        errorCode: safeErrorCode(error),
        ...(safeErrorStatus(error) ? { errorStatus: safeErrorStatus(error) } : {}),
      });
    }
    return value;
  } catch (error) {
    try {
      await recordOutcome({
        ...parsedOptions,
        success: false,
        probeToken,
        errorCode: safeErrorCode(error),
      });
    } catch (recordError) {
      securityLog("circuit_breaker_failure_record_failed", {
        tenantId: parsedOptions.tenantId,
        circuitKey: parsedOptions.circuitKey,
        errorCode: safeErrorCode(recordError),
        ...(safeErrorStatus(recordError) ? { errorStatus: safeErrorStatus(recordError) } : {}),
      });
    }
    throw error;
  }
}
