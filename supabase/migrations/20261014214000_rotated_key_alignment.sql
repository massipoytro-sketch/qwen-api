-- Final security alignment: use the actual id column for rotatable key records,
-- enforce grace-period semantics, and provision tenants/keys atomically.

begin;

drop function if exists security.consume_rotated_api_key(text);
create or replace function security.consume_rotated_api_key(
  p_key_hash text,
  p_key_id uuid default null,
  p_tenant_id uuid default null
)
returns table(tenant_id uuid, key_id uuid)
language plpgsql
security invoker
set search_path = ''
as $function$
declare
  v_now timestamptz := pg_catalog.clock_timestamp();
begin
  if p_key_hash is null or p_key_hash !~ '^[0-9a-f]{64}$' then
    return;
  end if;

  return query
  update security.tenant_api_keys k
  set last_used_at = v_now,
      updated_at = v_now
  where k.key_hash = p_key_hash
    and (p_key_id is null or k.id = p_key_id)
    and (p_tenant_id is null or k.tenant_id = p_tenant_id)
    and k.valid_from <= v_now
    and (
      (k.status = 'active' and k.revoked_at is null)
      or
      (k.status = 'grace' and k.revoked_at is null and k.grace_until is not null and k.grace_until > v_now)
    )
    and (k.expires_at is null or k.expires_at > v_now)
    and (k.grace_until is null or k.grace_until > v_now)
  returning k.tenant_id, k.id;
end;
$function$;

create or replace function security.provision_rotated_api_key(
  p_tenant_id uuid,
  p_key_hash text,
  p_label text default 'rotated-key',
  p_expires_at timestamptz default null
)
returns table(key_id uuid, tenant_id uuid, label text, expires_at timestamptz)
language plpgsql
security definer
set search_path = ''
as $function$
begin
  if p_tenant_id is null
     or p_key_hash is null or p_key_hash !~ '^[0-9a-f]{64}$'
     or p_label is null or pg_catalog.char_length(p_label) not between 1 and 120
     or (p_expires_at is not null and p_expires_at <= pg_catalog.clock_timestamp()) then
    raise exception 'INVALID_API_KEY_PROVISIONING' using errcode = '22023';
  end if;
  if not exists (
    select 1 from security.tenants t where t.id = p_tenant_id and t.status = 'active'
  ) then
    raise exception 'TENANT_NOT_ACTIVE' using errcode = '42501';
  end if;

  return query
  insert into security.tenant_api_keys(tenant_id, key_hash, label, status, valid_from, expires_at)
  values (p_tenant_id, p_key_hash, p_label, 'active', pg_catalog.clock_timestamp(), p_expires_at)
  returning id, tenant_id, label, expires_at;
end;
$function$;

create or replace function security.provision_security_tenant(
  p_name text,
  p_external_key text,
  p_api_key_hash text
)
returns table(tenant_id uuid, external_key text, name text, status text, created_at timestamptz, key_id uuid)
language plpgsql
security definer
set search_path = ''
as $function$
declare
  v_tenant_id uuid;
  v_key_id uuid;
  v_created_at timestamptz;
begin
  if p_name is null or pg_catalog.char_length(pg_catalog.btrim(p_name)) not between 1 and 160
     or p_external_key is null or pg_catalog.char_length(pg_catalog.btrim(p_external_key)) not between 1 and 200
     or p_api_key_hash is null or p_api_key_hash !~ '^[0-9a-f]{64}$' then
    raise exception 'INVALID_TENANT_PROVISIONING_INPUT' using errcode = '22023';
  end if;

  insert into security.tenants(external_key, name, status, api_key_hash)
  values (p_external_key, pg_catalog.btrim(p_name), 'active', null)
  returning id, security.tenants.created_at into v_tenant_id, v_created_at;

  insert into security.tenant_api_keys(tenant_id, key_hash, label, status, valid_from)
  values (v_tenant_id, p_api_key_hash, 'initial-canonical-key', 'active', pg_catalog.clock_timestamp())
  returning id into v_key_id;

  return query select v_tenant_id, p_external_key, pg_catalog.btrim(p_name), 'active'::text, v_created_at, v_key_id;
end;
$function$;

revoke all on function security.consume_rotated_api_key(text,uuid,uuid) from public, anon, authenticated;
revoke all on function security.provision_rotated_api_key(uuid,text,text,timestamptz) from public, anon, authenticated;
revoke all on function security.provision_security_tenant(text,text,text) from public, anon, authenticated;
grant execute on function security.consume_rotated_api_key(text,uuid,uuid) to service_role;
grant execute on function security.provision_rotated_api_key(uuid,text,text,timestamptz) to service_role;
grant execute on function security.provision_security_tenant(text,text,text) to service_role;

commit;
