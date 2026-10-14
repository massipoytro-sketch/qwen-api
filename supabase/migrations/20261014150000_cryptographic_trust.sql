begin;

create table if not exists security.api_credentials (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references security.tenants(id) on delete cascade,
  key_hash text not null unique,
  status text not null default 'active' check (status in ('active','revoked','expired')),
  valid_from timestamptz not null default now(),
  valid_until timestamptz,
  created_at timestamptz not null default now(),
  revoked_at timestamptz,
  last_used_at timestamptz,
  constraint api_credentials_valid_window check (valid_until is null or valid_until > valid_from),
  constraint api_credentials_revoked_state check ((status = 'revoked' and revoked_at is not null) or status <> 'revoked')
);

create index if not exists api_credentials_tenant_status_idx
  on security.api_credentials (tenant_id, status);
create index if not exists api_credentials_validity_idx
  on security.api_credentials (tenant_id, valid_from, valid_until);

insert into security.api_credentials (tenant_id, key_hash)
select id, api_key_hash
from security.tenants
where api_key_hash is not null
  and not exists (
    select 1 from security.api_credentials c where c.tenant_id = security.tenants.id and c.key_hash = security.tenants.api_key_hash
  );

create table if not exists security.request_idempotency (
  tenant_id uuid not null references security.tenants(id) on delete cascade,
  idempotency_key_hash text not null,
  request_hash text not null,
  status text not null default 'accepted' check (status in ('accepted','completed','failed')),
  response_code integer,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null,
  primary key (tenant_id, idempotency_key_hash)
);

create index if not exists request_idempotency_expiry_idx
  on security.request_idempotency (expires_at);

alter table security.api_credentials enable row level security;
alter table security.request_idempotency enable row level security;

revoke all on security.api_credentials from anon, authenticated;
revoke all on security.request_idempotency from anon, authenticated;
grant select on security.api_credentials to service_role;
grant insert, update, select on security.request_idempotency to service_role;

create or replace function security.authenticate_api_credential(
  p_tenant_id uuid,
  p_key_hash text
) returns table(credential_id uuid, status text)
language plpgsql
security definer
set search_path = security, pg_catalog
as $$
begin
  return query
  update security.api_credentials
     set last_used_at = now()
   where tenant_id = p_tenant_id
     and key_hash = p_key_hash
     and status = 'active'
     and valid_from <= now()
     and (valid_until is null or valid_until > now())
  returning id, status;
end;
$$;

revoke all on function security.authenticate_api_credential(uuid,text) from public, anon, authenticated;
grant execute on function security.authenticate_api_credential(uuid,text) to service_role;

create or replace function security.consume_request_idempotency(
  p_tenant_id uuid,
  p_idempotency_key_hash text,
  p_request_hash text,
  p_ttl_seconds integer default 86400
) returns jsonb
language plpgsql
security definer
set search_path = security, pg_catalog
as $$
declare
  existing security.request_idempotency;
begin
  if p_ttl_seconds < 60 or p_ttl_seconds > 604800 then
    raise exception 'INVALID_IDEMPOTENCY_TTL';
  end if;

  perform pg_advisory_xact_lock(hashtextextended(p_tenant_id::text || ':' || p_idempotency_key_hash, 0));

  select * into existing
    from security.request_idempotency
   where tenant_id = p_tenant_id
     and idempotency_key_hash = p_idempotency_key_hash;

  if found then
    if existing.expires_at <= now() then
      delete from security.request_idempotency
       where tenant_id = p_tenant_id and idempotency_key_hash = p_idempotency_key_hash;
    elsif existing.request_hash <> p_request_hash then
      return jsonb_build_object('accepted', false, 'reason', 'IDEMPOTENCY_KEY_REUSED_WITH_DIFFERENT_REQUEST');
    else
      return jsonb_build_object('accepted', false, 'reason', 'DUPLICATE_REQUEST', 'status', existing.status, 'responseCode', existing.response_code);
    end if;
  end if;

  insert into security.request_idempotency(tenant_id,idempotency_key_hash,request_hash,expires_at)
  values(p_tenant_id,p_idempotency_key_hash,p_request_hash,now() + make_interval(secs => p_ttl_seconds));

  return jsonb_build_object('accepted', true, 'reason', 'NEW_REQUEST');
end;
$$;

revoke all on function security.consume_request_idempotency(uuid,text,text,integer) from public, anon, authenticated;
grant execute on function security.consume_request_idempotency(uuid,text,text,integer) to service_role;

commit;
