const SECURITY_PROJECT_HOST = "cqzozhdnktuamrxawntt.supabase.co";

/** Prevent operator utilities from running against the unrelated rewards-platform database. */
export function assertSecurityProjectUrl(rawUrl) {
  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch {
    throw new Error("SUPABASE_URL must be a valid URL for the dedicated GainiRen security project.");
  }
  if (
    parsed.protocol !== "https:" ||
    parsed.hostname.toLowerCase() !== SECURITY_PROJECT_HOST ||
    parsed.username ||
    parsed.password ||
    parsed.search ||
    parsed.hash ||
    parsed.pathname !== "/"
  ) {
    throw new Error("Refusing database target. Operator utilities are locked to the dedicated GainiRen security Supabase project; rewards-platform is prohibited.");
  }
}
