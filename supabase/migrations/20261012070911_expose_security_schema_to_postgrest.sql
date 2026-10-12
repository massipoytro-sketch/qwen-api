-- Expose the dedicated security schema through PostgREST for the server-side API.
-- Existing object grants and RLS remain restrictive; do not grant table access to anon/authenticated.
-- This pins the effective PostgREST schema list because Dashboard schema changes were not reaching this project.
ALTER ROLE authenticator SET pgrst.db_schemas = 'public, graphql_public, security';
NOTIFY pgrst, 'reload config';
NOTIFY pgrst, 'reload schema';
