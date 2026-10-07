import { z } from "zod";

const envSchema = z.object({
  SUPABASE_URL: z.url(),
  SUPABASE_SERVER_KEY: z.string().min(1),
});

export const env = envSchema.parse({
  SUPABASE_URL: process.env.SUPABASE_URL,
  SUPABASE_SERVER_KEY: process.env.SUPABASE_SERVER_KEY,
});
