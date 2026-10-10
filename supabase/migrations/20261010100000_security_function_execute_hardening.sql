-- Keep the generic timestamp trigger function out of the browser-callable grant surface.
-- Trigger execution does not require callers to have EXECUTE privileges on the trigger function.
revoke execute on function security.set_updated_at() from public, anon, authenticated;
grant execute on function security.set_updated_at() to service_role;
