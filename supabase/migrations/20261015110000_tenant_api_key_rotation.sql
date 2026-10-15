-- Part 3: controlled tenant API-key rotation with a bounded overlap window.
begin;

alter table security.tenants
  add column if not exists api_key_previous_hash text,
  add column if not exists api_key_previous_valid_until timestamptz,
  add column if not exists api_key_rotated_at timestamptz;

alter table security.tenants
  drop constraint if exists tenants_api_key_previous_hash_format,
  add constraint tenants_api_key_previous_hash_format
    check (api_key_previous_hash is null or api_key_previous_hash ~ '^[a-f0-9]{64}$'),
  drop constraint if exists tenants_api_key_previous_window_pair,
  add constraint tenants_api_key_previous_window_pair
    check ((api_key_previous_hash is null) = (api_key_previous_valid_until is null));

create index if not exists tenants_api_key_previous_valid_until_idx
  on security.tenants (api_key_previous_valid_until)
  where api_key_previous_hash is not null;

create or replace function security.rotate_tenant_api_key(
  p_tenant_id uuid,
  p_new_api_key_hash text,
  p_grace_seconds integer default 900
)
returns jsonb
language plpgsql
security invoker
set search_path = pg_catalog, security
as $function$
declare
  tenant_row security.tenants%rowtype;
  rotation_time timestamptz := clock_timestamp();
  previous_hash text;
  previous_until timestamptz;
begin
  if p_tenant_id is null then
    raise exception using errcode = '22023', message = 'INVALID_TENANT_ID';
  end if;
  if p_new_api_key_hash is null or p_new_api_key_hash !~ '^[a-f0-9]{64}$' then
    raise exception using errcode = '22023', message = 'INVALID_API_KEY_HASH';
  end if;
  if p_grace_seconds is null or p_grace_seconds < 0 or p_grace_seconds > 86400 then
    raise exception using errcode = '22023', message = 'INVALID_ROTATION_GRACE';
  end if;

  select * into tenant_row
    from security.tenants
    where id = p_tenant_id
    for update;

  if not found or tenant_row.status <> 'active' then
    raise exception using errcode = 'P0002', message = 'ACTIVE_TENANT_NOT_FOUND';
  end if;
  if tenant_row.api_key_hash is null then
    raise exception using errcode = '22023', message = 'TENANT_HAS_NO_ROTATABLE_API_KEY';
  end if;
  if tenant_row.api_key_hash = p_new_api_key_hash then
    raise exception using errcode = '22023', message = 'NEW_API_KEY_MUST_DIFFER';
  end if;

  previous_hash := tenant_row.api_key_hash;
  previous_until := case when p_grace_seconds = 0 then null
                         else rotation_time + make_interval(secs => p_grace_seconds) end;

  update security.tenants
    set api_key_previous_hash = case when p_grace_seconds = 0 then null else previous_hash end,
        api_key_previous_valid_until = previous_until,
        api_key_hash = p_new_api_key_hash,
        api_key_rotated_at = rotation_time,
        updated_at = rotation_time
    where id = p_tenant_id;

  perform security.append_security_ledger_entry(
    p_tenant_id,
    'tenant_api_key_rotated',
    'tenant',
    p_tenant_id::text,
    null,
    'system',
    jsonb_build_object(
      'rotatedAt', rotation_time,
      'graceSeconds', p_grace_seconds,
      'previousKeyRetainedUntil', previous_until,
      'newKeyHashPrefix', left(p_new_api_key_hash, 8)
    )
  );

  return jsonb_build_object(
    'tenantId', p_tenant_id,
    'rotatedAt', rotation_time,
    'previousKeyValidUntil', previous_until,
    'graceSeconds', p_grace_seconds
  );
end;
$function$;

revoke all on function security.rotate_tenant_api_key(uuid, text, integer) from public, anon, authenticated;
grant execute on function security.rotate_tenant_api_key(uuid, text, integer) to service_role;

commit;
