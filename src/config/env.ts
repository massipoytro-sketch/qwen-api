import { z } from "zod";

const envSchema = z.object({
  SUPABASE_URL: z.url(),
  SUPABASE_SERVER_KEY: z.string().min(1),
  SECURITY_API_CORS_ORIGIN: z.url().optional(),
  AI_ANALYZER_ENABLED: z.enum(["true", "false"]).default("false"),
  AI_ANALYZER_ENDPOINT: z.url().optional(),
  AI_ANALYZER_API_KEY: z.string().min(1).optional(),
  AI_ANALYZER_MODEL: z.string().min(1).max(200).optional(),
  OUTBOX_WORKER_TOKEN: z.string().min(32).optional(),
  DUCKDB_ANALYTICS_URL: z.url().optional(),
  DUCKDB_ANALYTICS_TOKEN: z.string().min(32).optional(),
  HONEY_SENSOR_TOKEN: z.string().min(32).optional(),
  HONEY_TENANT_ID: z.uuid().optional(),
  SECURITY_OPS_TOKEN: z.string().min(32).optional(),
}).superRefine((value, ctx) => {
  const production = process.env.NODE_ENV === "production";
  const parsedSupabaseUrl = new URL(value.SUPABASE_URL);
  if (production && parsedSupabaseUrl.protocol !== "https:") {
    ctx.addIssue({ code: "custom", path: ["SUPABASE_URL"], message: "Production Supabase URL must use HTTPS" });
  }

  if (value.SECURITY_API_CORS_ORIGIN) {
    const cors = new URL(value.SECURITY_API_CORS_ORIGIN);
    if (
      cors.username || cors.password || cors.search || cors.hash ||
      cors.pathname !== "/" || value.SECURITY_API_CORS_ORIGIN !== cors.origin || (production && cors.protocol !== "https:")
    ) {
      ctx.addIssue({
        code: "custom",
        path: ["SECURITY_API_CORS_ORIGIN"],
        message: "CORS origin must be a bare origin; production origins must use HTTPS",
      });
    }
  }

  for (const [name, endpoint] of [
    ["AI_ANALYZER_ENDPOINT", value.AI_ANALYZER_ENDPOINT],
    ["DUCKDB_ANALYTICS_URL", value.DUCKDB_ANALYTICS_URL],
  ] as const) {
    if (!endpoint) continue;
    const parsedEndpoint = new URL(endpoint);
    if (parsedEndpoint.username || parsedEndpoint.password || parsedEndpoint.hash || (production && parsedEndpoint.protocol !== "https:")) {
      ctx.addIssue({
        code: "custom",
        path: [name],
        message: "Production dependency endpoints must use HTTPS and URLs must not contain credentials or fragments",
      });
    }
  }

  const configured = [
    value.AI_ANALYZER_ENDPOINT,
    value.AI_ANALYZER_API_KEY,
    value.AI_ANALYZER_MODEL,
  ].filter(Boolean).length;

  if (configured !== 0 && configured !== 3) {
    ctx.addIssue({
      code: "custom",
      path: ["AI_ANALYZER_ENDPOINT"],
      message: "AI analyzer configuration must set endpoint, key, and model together",
    });
  }
  const duckDbConfigured = [value.DUCKDB_ANALYTICS_URL, value.DUCKDB_ANALYTICS_TOKEN].filter(Boolean).length;
  if (duckDbConfigured !== 0 && duckDbConfigured !== 2) {
    ctx.addIssue({ code: "custom", path: ["DUCKDB_ANALYTICS_URL"], message: "DuckDB worker URL and token must be configured together" });
  }
  const honeyConfigured = [value.HONEY_SENSOR_TOKEN, value.HONEY_TENANT_ID].filter(Boolean).length;
  if (honeyConfigured !== 0 && honeyConfigured !== 2) {
    ctx.addIssue({ code: "custom", path: ["HONEY_SENSOR_TOKEN"], message: "Honey sensor token and dedicated tenant ID must be configured together" });
  }
});

export const env = envSchema.parse({
  SUPABASE_URL: process.env.SUPABASE_URL,
  SUPABASE_SERVER_KEY: process.env.SUPABASE_SERVER_KEY,
  SECURITY_API_CORS_ORIGIN: process.env.SECURITY_API_CORS_ORIGIN,
  AI_ANALYZER_ENABLED: process.env.AI_ANALYZER_ENABLED ?? "false",
  AI_ANALYZER_ENDPOINT: process.env.AI_ANALYZER_ENDPOINT,
  AI_ANALYZER_API_KEY: process.env.AI_ANALYZER_API_KEY,
  AI_ANALYZER_MODEL: process.env.AI_ANALYZER_MODEL,
  OUTBOX_WORKER_TOKEN: process.env.OUTBOX_WORKER_TOKEN,
  DUCKDB_ANALYTICS_URL: process.env.DUCKDB_ANALYTICS_URL,
  DUCKDB_ANALYTICS_TOKEN: process.env.DUCKDB_ANALYTICS_TOKEN,
  HONEY_SENSOR_TOKEN: process.env.HONEY_SENSOR_TOKEN,
  HONEY_TENANT_ID: process.env.HONEY_TENANT_ID,
  SECURITY_OPS_TOKEN: process.env.SECURITY_OPS_TOKEN,
});
