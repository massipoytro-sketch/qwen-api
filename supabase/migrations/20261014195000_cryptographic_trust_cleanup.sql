-- SAFETY NOTE: these transitional credential objects are empty.
-- Apply only after explicit operator approval. The running API uses security.tenant_api_keys.
begin;
drop function if exists security.authenticate_api_credential(uuid,text);
drop function if exists security.rotate_api_credential(uuid,text,timestamptz,boolean);
drop table if exists security.api_credentials;
commit;
