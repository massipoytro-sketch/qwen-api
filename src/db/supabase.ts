import { createClient } from "@supabase/supabase-js";
import { env } from "../config/env";

export const supabase = createClient(
  env.SUPABASE_URL,
  env.SUPABASE_SERVER_KEY,
  {
    auth: {
      autoRefreshToken: false,
      persistSession: false,
      detectSessionInUrl: false,
    },
  },
);
