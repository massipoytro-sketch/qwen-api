-- Final pre-AI security alignment. Apply only to gainiren-shield-lab.
begin;

-- Promote existing tenant hashes into the canonical rotated-key lifecycle.
-- This copies only SHA-256 hashes; no plaintext credential is created or stored.
insert into security.tenant_api_keys(tenant_id,key_hash,label,status,valid_from,expires_at,created_at,updated_at)
select t.id,t.api_key_hash,'legacy-seeded-canonical','active',clock_timestamp(),null,clock_timestamp(),clock_timestamp()
from security.tenants t
where t.status='active' and t.api_key_hash is not null
  and not exists (select 1 from security.tenant_api_keys k where k.tenant_id=t.id and k.key_hash=t.api_key_hash);

-- Transitional objects are retained for controlled cleanup, but are never exposed to browser roles.
revoke all on security.api_credentials from public,anon,authenticated;
revoke all on security.request_idempotency from public,anon,authenticated;

commit;
