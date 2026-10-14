-- GainiRen Security Part 3: key rotation, emergency controls and recovery state.
-- Apply only to the dedicated gainiren-shield-lab database.
begin;

create table if not exists security.tenant_api_keys (
  key_id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references security.tenants(id) on delete cascade,
  key_hash text not null check (key_hash ~ '^[0-9a-f]{64}$'),
  label text not null default 'rotated-key' check (char_length(label) between 1 and 100),
  status text not null default 'active' check (status in ('active','revoked','expired')),
  created_at timestamptz not null default pg_catalog.now(),
  expires_at timestamptz,
  revoked_at timestamptz,
  last_used_at timestamptz,
  unique (tenant_id, key_hash)
);
create index if not exists tenant_api_keys_lookup_idx on security.tenant_api_keys (key_hash, status, expires_at);
create index if not exists tenant_api_keys_tenant_status_idx on security.tenant_api_keys (tenant_id, status, created_at desc);
alter table security.tenant_api_keys enable row level security;
revoke all on table security.tenant_api_keys from public, anon, authenticated;
grant select, update on table security.tenant_api_keys to service_role;

create table if not exists security.security_controls (
  tenant_id uuid primary key references security.tenants(id) on delete cascade,
  mode text not null default 'normal' check (mode in ('normal','challenge_all','deny_all','maintenance')),
  reason_code text check (reason_code is null or reason_code ~ '^[A-Z0-9:_-]{1,80}$'),
  version bigint not null default 1 check (version > 0),
  updated_at timestamptz not null default pg_catalog.now(),
  expires_at timestamptz
);
alter table security.security_controls enable row level security;
revoke all on table security.security_controls from public, anon, authenticated;
grant select, insert, update, delete on table security.security_controls to service_role;

create or replace function security.get_security_control(p_tenant_id uuid)
returns table(mode text, reason_code text, version bigint, expires_at timestamptz)
language sql
security invoker
set search_path = ''
as $function$
  select c.mode, c.reason_code, c.version, c.expires_at
  from security.security_controls c
  where c.tenant_id = p_tenant_id;
$function$;
revoke all on function security.get_security_control(uuid) from public, anon, authenticated;
grant execute on function security.get_security_control(uuid) to service_role;

create or replace function security.consume_rotated_api_key(p_key_hash text)
returns table(tenant_id uuid, key_id uuid)
language plpgsql
security invoker
set search_path = ''
as $function$
begin
  if p_key_hash is null or p_key_hash !~ '^[0-9a-f]{64}$' then
    return;
  end if;
  return query
  update security.tenant_api_keys k
     set last_used_at = pg_catalog.clock_timestamp()
   where k.key_hash = p_key_hash
     and k.status = 'active'
     and (k.expires_at is null or k.expires_at > pg_catalog.clock_timestamp())
   returning k.tenant_id, k.key_id;
end;
$function$;
revoke all on function security.consume_rotated_api_key(text) from public, anon, authenticated;
grant execute on function security.consume_rotated_api_key(text) to service_role;

create or replace function security.set_security_control(
  p_tenant_id uuid,
  p_mode text,
  p_reason_code text default null,
  p_expires_at timestamptz default null
)
returns table(mode text, reason_code text, version bigint, expires_at timestamptz)
language plpgsql
security invoker
set search_path = ''
as $function$
declare v_version bigint;
begin
  if p_mode not in ('normal','challenge_all','deny_all','maintenance') then
    raise exception 'INVALID_SECURITY_CONTROL_MODE' using errcode = '22023';
  end if;
  if p_reason_code is not null and p_reason_code !~ '^[A-Z0-9:_-]{1,80}$' then
    raise exception 'INVALID_SECURITY_CONTROL_REASON' using errcode = '22023';
  end if;
  if not exists (select 1 from security.tenants t where t.id=p_tenant_id and t.status='active') then
    raise exception 'TENANT_NOT_ACTIVE' using errcode = '42501';
  end if;
  insert into security.security_controls(tenant_id,mode,reason_code,version,expires_at)
  values(p_tenant_id,p_mode,p_reason_code,1,p_expires_at)
  on conflict (tenant_id) do update
    set mode=excluded.mode, reason_code=excluded.reason_code,
        version=security.security_controls.version+1,
        expires_at=excluded.expires_at, updated_at=pg_catalog.clock_timestamp();
  return query select c.mode,c.reason_code,c.version,c.expires_at
    from security.security_controls c where c.tenant_id=p_tenant_id;
end;
$function$;
revoke all on function security.set_security_control(uuid,text,text,timestamptz) from public, anon, authenticated;
grant execute on function security.set_security_control(uuid,text,text,timestamptz) to service_role;

commit;
