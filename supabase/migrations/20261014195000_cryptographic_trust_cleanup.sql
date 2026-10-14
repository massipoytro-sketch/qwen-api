-- SAFETY NOTE: these transitional tables were created during Part 3 implementation but are empty.
-- Apply only after explicit operator approval. The running API does not use them.
begin;
drop function if exists security.authenticate_api_credential(uuid,text);
drop function if exists security.rotate_api_credential(uuid,text,timestamptz,boolean);
drop function if exists security.consume_request_idempotency(uuid,text,text,integer);
drop function if exists security.finalize_request_idempotency(uuid,text,text,integer);
drop table if exists security.request_idempotency;
drop table if exists security.api_credentials;
commit;
