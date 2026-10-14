import { z } from "zod";

const envSchema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("production"),
  SUPABASE_URL: z.url(),
  SUPABASE_SERVER_KEY: z.string().min(1),
  SECURITY_API_CORS_ORIGIN: z.url().optional(),
  OPENROUTER_ENABLED: z.enum(["true", "false"]).default("false"),
  OPENROUTER_API_KEY: z.string().min(16).max(512).optional(),
  OPENROUTER_MODEL: z.string().min(1).max(200)
    .regex(/^[A-Za-z0-9][A-Za-z0-9._/-]*(?::[A-Za-z0-9._-]+)?$/)
    .default("nvidia/nemotron-3-ultra-550b-a55b:free"),
  OUTBOX_WORKER_TOKEN: z.string().min(32).optional(),
  DUCKDB_ANALYTICS_URL: z.url().optional(),
  DUCKDB_ANALYTICS_TOKEN: z.string().min(32).optional(),
  HONEY_SENSOR_TOKEN: z.string().min(32).optional(),
  HONEY_TENANT_ID: z.uuid().optional(),
  SECURITY_OPS_TOKEN: z.string().min(32).optional(),
}).superRefine((value, ctx) => {
  if (value.OPENROUTER_ENABLED === "true" && !value.OPENROUTER_API_KEY) {
    ctx.addIssue({
      code: "custom",
      path: ["OPENROUTER_API_KEY"],
      message: "OpenRouter API key is required when OpenRouter is enabled",
    });
  }
  const duckDbConfigured = [value.DUCKDB_ANALYTICS_URL, value.DUCKDB_ANALYTICS_TOKEN].filter(Boolean).length;
  if (duckDbConfigured !== 0 && duckDbConfigured !== 2) ctx.addIssue({ code: "custom", path: ["DUCKDB_ANALYTICS_URL"], message: "DuckDB worker URL and token must be configured together" });
  const honeyConfigured = [value.HONEY_SENSOR_TOKEN, value.HONEY_TENANT_ID].filter(Boolean).length;
  if (honeyConfigured !== 0 && honeyConfigured !== 2) ctx.addIssue({ code: "custom", path: ["HONEY_SENSOR_TOKEN"], message: "Honey sensor token and dedicated tenant ID must be configured together" });
});

export const env = envSchema.parse({
  NODE_ENV: process.env.NODE_ENV ?? "production",
  SUPABASE_URL: process.env.SUPABASE_URL,
  SUPABASE_SERVER_KEY: process.env.SUPABASE_SERVER_KEY,
  SECURITY_API_CORS_ORIGIN: process.env.SECURITY_API_CORS_ORIGIN,
  OPENROUTER_ENABLED: process.env.OPENROUTER_ENABLED ?? "false",
  OPENROUTER_API_KEY: process.env.OPENROUTER_API_KEY,
  OPENROUTER_MODEL: process.env.OPENROUTER_MODEL ?? "nvidia/nemotron-3-ultra-550b-a55b:free",
  OUTBOX_WORKER_TOKEN: process.env.OUTBOX_WORKER_TOKEN,
  DUCKDB_ANALYTICS_URL: process.env.DUCKDB_ANALYTICS_URL,
  DUCKDB_ANALYTICS_TOKEN: process.env.DUCKDB_ANALYTICS_TOKEN,
  HONEY_SENSOR_TOKEN: process.env.HONEY_SENSOR_TOKEN,
  HONEY_TENANT_ID: process.env.HONEY_TENANT_ID,
  SECURITY_OPS_TOKEN: process.env.SECURITY_OPS_TOKEN,
});
