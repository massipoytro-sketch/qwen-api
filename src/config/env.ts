import { z } from "zod";

const envSchema = z.object({
  SUPABASE_URL: z.url(),
  SUPABASE_SERVER_KEY: z.string().min(1),
  SECURITY_API_CORS_ORIGIN: z.string().min(1).default("*"),
});

export const env = envSchema.parse({
  SUPABASE_URL: process.env.SUPABASE_URL,
  SUPABASE_SERVER_KEY: process.env.SUPABASE_SERVER_KEY,
  SECURITY_API_CORS_ORIGIN: process.env.SECURITY_API_CORS_ORIGIN ?? "*",
});
