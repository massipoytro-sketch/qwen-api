import { z } from "zod";

const envSchema = z.object({
  SUPABASE_URL: z.url(),
  SUPABASE_SERVER_KEY: z.string().min(1),
  SECURITY_API_CORS_ORIGIN: z.url().optional(),
  AI_ANALYZER_ENDPOINT: z.url().optional(),
  AI_ANALYZER_API_KEY: z.string().min(1).optional(),
  AI_ANALYZER_MODEL: z.string().min(1).max(200).optional(),
}).superRefine((value, ctx) => {
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
});

export const env = envSchema.parse({
  SUPABASE_URL: process.env.SUPABASE_URL,
  SUPABASE_SERVER_KEY: process.env.SUPABASE_SERVER_KEY,
  SECURITY_API_CORS_ORIGIN: process.env.SECURITY_API_CORS_ORIGIN,
  AI_ANALYZER_ENDPOINT: process.env.AI_ANALYZER_ENDPOINT,
  AI_ANALYZER_API_KEY: process.env.AI_ANALYZER_API_KEY,
  AI_ANALYZER_MODEL: process.env.AI_ANALYZER_MODEL,
});
