-- Part 3 corrective migration: use the established tenant_api_keys registry.
-- The earlier draft added duplicate key state to security.tenants. Remove that
-- redundant state and harden the existing registry-based rotation RPC instead.
begin;

drop function if exists security.rotate_tenant_api_key(uuid, text, integer);

alter table security.tenants
  drop constraint if exists tenants_api_key_previous_hash_format,
  drop constraint if exists tenants_api_key_previous_window_pair,
  drop column if exists api_key_previous_hash,
  drop column if exists api_key_previous_valid_until,
  drop column if exists api_key_rotated_at;

drop index if exists security.tenants_api_key_previous_valid_until_idx;

create or replace function security.rotate_tenant_api_key(
  p_tenant_id uuid,
  p_key_hash text,
  p_label text default 'rotated-key',
  p_grace_seconds integer default 3600
)
returns table(key_id uuid, previous_active_keys_retired integer)
language plpgsql
security definer
set search_path = ''
as $function$
declare
  v_now timestamptz := pg_catalog.clock_timestamp();
  v_grace integer := coalesce(p_grace_seconds, 3600);
  v_moved integer := 0;
  v_key_id uuid;
begin
  if p_tenant_id is null
     or p_key_hash is null or p_key_hash !~ '^[0-9a-f]{64}$'
     or p_label is null or pg_catalog.char_length(p_label) not between 1 and 120
     or v_grace < 0 or v_grace > 86400 then
    raise exception 'INVALID_TENANT_API_KEY_ROTATION' using errcode = '22023';
  end if;

  if not exists (
    select 1 from security.tenants t
    where t.id = p_tenant_id and t.status = 'active'
  ) then
    raise exception 'TENANT_NOT_ACTIVE' using errcode = '42501';
  end if;

  if exists (
    select 1 from security.tenant_api_keys k
    where k.tenant_id = p_tenant_id and k.key_hash = p_key_hash
      and k.status in ('active', 'grace') and k.revoked_at is null
      and (k.expires_at is null or k.expires_at > v_now)
      and (k.grace_until is null or k.grace_until > v_now)
  ) then
    raise exception 'API_KEY_ALREADY_REGISTERED' using errcode = '22023';
  end if;

  update security.tenant_api_keys k
    set status = case when v_grace > 0 then 'grace' else 'revoked' end,
        grace_until = case when v_grace > 0 then v_now + pg_catalog.make_interval(secs => v_grace) else null end,
        revoked_at = case when v_grace > 0 then null else v_now end,
        updated_at = v_now
    where k.tenant_id = p_tenant_id and k.status = 'active' and k.revoked_at is null;
  get diagnostics v_moved = row_count;

  insert into security.tenant_api_keys (tenant_id, key_hash, label, status, valid_from)
  values (p_tenant_id, p_key_hash, p_label, 'active', v_now)
  returning id into v_key_id;

  perform security.append_security_ledger_entry(
    p_tenant_id,
    'tenant_api_key_rotated',
    'tenant_api_key',
    v_key_id::text,
    null,
    'system',
    pg_catalog.jsonb_build_object(
      'rotatedAt', v_now,
      'graceSeconds', v_grace,
      'previousActiveKeysRetired', v_moved,
      'keyLabel', p_label
    )
  );

  return query select v_key_id, v_moved;
end;
$function$;

revoke all on function security.rotate_tenant_api_key(uuid, text, text, integer) from public, anon, authenticated;
grant execute on function security.rotate_tenant_api_key(uuid, text, text, integer) to service_role;

commit;
