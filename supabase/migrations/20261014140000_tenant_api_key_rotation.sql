-- Part 3: versioned tenant API credentials with controlled rotation and revocation.
-- Apply only to the dedicated gainiren-shield-lab database.

begin;

create table if not exists security.tenant_api_keys (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references security.tenants(id) on delete cascade,
  key_hash text not null unique check (key_hash ~ '^[0-9a-f]{64}$'),
  label text not null default 'rotated-key' check (char_length(label) between 1 and 120),
  status text not null default 'active' check (status in ('active','grace','revoked')),
  valid_from timestamptz not null default pg_catalog.now(),
  expires_at timestamptz,
  grace_until timestamptz,
  revoked_at timestamptz,
  last_used_at timestamptz,
  created_at timestamptz not null default pg_catalog.now(),
  updated_at timestamptz not null default pg_catalog.now(),
  constraint tenant_api_key_active_not_revoked check (
    (status <> 'revoked' or revoked_at is not null)
  ),
  constraint tenant_api_key_grace_has_deadline check (
    (status <> 'grace' or grace_until is not null)
  ),
  constraint tenant_api_key_expiration_after_valid_from check (
    expires_at is null or expires_at > valid_from
  ),
  constraint tenant_api_key_grace_after_valid_from check (
    grace_until is null or grace_until > valid_from
  )
);

create index if not exists tenant_api_keys_tenant_status_idx
  on security.tenant_api_keys (tenant_id, status, valid_from);
create unique index if not exists tenant_api_keys_one_active_per_tenant
  on security.tenant_api_keys (tenant_id) where status = 'active';

alter table security.tenant_api_keys enable row level security;
revoke all on table security.tenant_api_keys from public, anon, authenticated;
revoke insert, update, delete, truncate on table security.tenant_api_keys from service_role;
grant select on table security.tenant_api_keys to service_role;

create or replace function security.rotate_tenant_api_key(
  p_tenant_id uuid,
  p_key_hash text,
  p_label text default 'rotated-key',
  p_grace_seconds integer default 3600
)
returns table (key_id uuid, previous_active_keys_retired integer)
language plpgsql
security definer
set search_path = ''
as $function$
declare
  v_now timestamptz := pg_catalog.clock_timestamp();
  v_grace integer := greatest(0, least(coalesce(p_grace_seconds, 3600), 604800));
  v_moved integer := 0;
  v_key_id uuid;
begin
  if p_tenant_id is null
     or p_key_hash is null or p_key_hash !~ '^[0-9a-f]{64}$'
     or p_label is null or char_length(p_label) not between 1 and 120 then
    raise exception 'INVALID_TENANT_API_KEY_ROTATION' using errcode = '22023';
  end if;

  if not exists (
    select 1 from security.tenants t
    where t.id = p_tenant_id and t.status = 'active'
  ) then
    raise exception 'TENANT_NOT_ACTIVE' using errcode = '42501';
  end if;

  update security.tenant_api_keys k
    set status = case when v_grace > 0 then 'grace' else 'revoked' end,
        grace_until = case when v_grace > 0 then v_now + pg_catalog.make_interval(secs => v_grace) else null end,
        revoked_at = case when v_grace > 0 then null else v_now end,
        updated_at = v_now
    where k.tenant_id = p_tenant_id and k.status = 'active';
  get diagnostics v_moved = row_count;

  insert into security.tenant_api_keys (tenant_id, key_hash, label, status, valid_from)
  values (p_tenant_id, p_key_hash, p_label, 'active', v_now)
  returning id into v_key_id;

  return query select v_key_id, v_moved;
end;
$function$;

create or replace function security.revoke_tenant_api_key(
  p_tenant_id uuid,
  p_key_id uuid
)
returns boolean
language plpgsql
security definer
set search_path = ''
as $function$
declare
  v_count integer;
begin
  if p_tenant_id is null or p_key_id is null then
    raise exception 'INVALID_TENANT_API_KEY_REVOCATION' using errcode = '22023';
  end if;

  update security.tenant_api_keys k
    set status = 'revoked',
        revoked_at = pg_catalog.clock_timestamp(),
        grace_until = null,
        updated_at = pg_catalog.clock_timestamp()
    where k.tenant_id = p_tenant_id
      and k.id = p_key_id
      and k.status <> 'revoked';
  get diagnostics v_count = row_count;
  return v_count = 1;
end;
$function$;

revoke all on function security.rotate_tenant_api_key(uuid,text,text,integer) from public, anon, authenticated;
revoke all on function security.revoke_tenant_api_key(uuid,uuid) from public, anon, authenticated;
grant execute on function security.rotate_tenant_api_key(uuid,text,text,integer) to service_role;
grant execute on function security.revoke_tenant_api_key(uuid,uuid) to service_role;

 
create or replace function security.verify_security_audit_ledger(
  p_tenant_id uuid,
  p_max_rows integer default 10000
)
returns table (
  valid boolean,
  checked_entries integer,
  first_invalid_sequence bigint,
  reason_code text
)
language plpgsql
security definer
set search_path = ''
as $function$
declare
  v_row record;
  v_count bigint;
  v_expected_sequence bigint := 1;
  v_previous_hash text := null;
  v_payload jsonb;
  v_expected_hash text;
  v_checked integer := 0;
begin
  if p_tenant_id is null or p_max_rows not between 1 and 50000 then
    raise exception 'INVALID_AUDIT_LEDGER_VERIFY_INPUT' using errcode = '22023';
  end if;

  if not exists (
    select 1 from security.tenants t
    where t.id = p_tenant_id and t.status = 'active'
  ) then
    raise exception 'TENANT_NOT_ACTIVE' using errcode = '42501';
  end if;

  select count(*) into v_count
  from security.audit_ledger l
  where l.tenant_id = p_tenant_id;

  if v_count > p_max_rows then
    return query select false, 0, null::bigint, 'ROW_LIMIT_EXCEEDED'::text;
    return;
  end if;

  for v_row in
    select l.ledger_id, l.sequence_no, l.action, l.actor_type,
           l.resource_type, l.resource_id, l.request_id, l.details,
           l.previous_hash, l.entry_hash, l.created_at
    from security.audit_ledger l
    where l.tenant_id = p_tenant_id
    order by l.sequence_no asc
  loop
    if v_row.sequence_no <> v_expected_sequence then
      return query select false, v_checked, v_row.sequence_no, 'SEQUENCE_GAP'::text;
      return;
    end if;
    if v_row.previous_hash is distinct from v_previous_hash then
      return query select false, v_checked, v_row.sequence_no, 'PREVIOUS_HASH_MISMATCH'::text;
      return;
    end if;

    v_payload := pg_catalog.jsonb_build_object(
      'tenantId', p_tenant_id,
      'sequenceNo', v_row.sequence_no,
      'action', v_row.action,
      'actorType', v_row.actor_type,
      'resourceType', v_row.resource_type,
      'resourceId', v_row.resource_id,
      'requestId', v_row.request_id,
      'details', v_row.details,
      'previousHash', v_row.previous_hash,
      'createdAt', v_row.created_at
    );
    v_expected_hash := pg_catalog.encode(
      extensions.digest(
        pg_catalog.convert_to(coalesce(v_row.previous_hash, 'GENESIS') || E'\n' || v_payload::text, 'UTF8'),
        'sha256'
      ),
      'hex'
    );

    if v_expected_hash is distinct from v_row.entry_hash then
      return query select false, v_checked, v_row.sequence_no, 'ENTRY_HASH_MISMATCH'::text;
      return;
    end if;

    v_previous_hash := v_row.entry_hash;
    v_expected_sequence := v_expected_sequence + 1;
    v_checked := v_checked + 1;
  end loop;

  return query select true, v_checked, null::bigint, 'OK'::text;
end;
$function$;

revoke all on function security.verify_security_audit_ledger(uuid,integer) from public, anon, authenticated;
grant execute on function security.verify_security_audit_ledger(uuid,integer) to service_role;

commit;
