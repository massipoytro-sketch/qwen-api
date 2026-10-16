-- Part 5 operational hardening: fixed-search-path RPCs, tenant-bound replay rows,
-- deception-asset hit accounting, and bounded replay retention.
-- Apply only to the dedicated gainiren-shield-lab database.

begin;

alter table security.deception_assets
  add column if not exists hit_count bigint not null default 0,
  add column if not exists last_seen_at timestamptz;
alter table security.deception_assets
  drop constraint if exists deception_assets_hit_count_nonnegative;
alter table security.deception_assets
  add constraint deception_assets_hit_count_nonnegative check (hit_count >= 0);

create or replace function security.register_deception_asset(
  p_tenant_id uuid,
  p_asset_type text,
  p_asset_name text,
  p_locator_hash text,
  p_metadata jsonb default '{}'::jsonb
)
returns setof security.deception_assets
language plpgsql
security definer
set search_path = ''
as $function$
begin
  if p_tenant_id is null
     or p_asset_type is null or p_asset_type not in ('route','credential_canary','database_canary','service_canary','document_canary')
     or p_asset_name is null or pg_catalog.length(p_asset_name) not between 1 and 160
     or p_locator_hash is null or p_locator_hash !~ '^[0-9a-f]{64}$'
     or pg_catalog.jsonb_typeof(coalesce(p_metadata, '{}'::jsonb)) <> 'object'
     or pg_catalog.pg_column_size(coalesce(p_metadata, '{}'::jsonb)) > 8192 then
    raise exception 'INVALID_DECEPTION_ASSET' using errcode = '22023';
  end if;

  if not exists (
    select 1 from security.tenants t
    where t.id = p_tenant_id and t.status = 'active'
  ) then
    raise exception 'TENANT_NOT_ACTIVE' using errcode = '42501';
  end if;

  return query
    insert into security.deception_assets (
      tenant_id, asset_type, asset_name, locator_hash, status, metadata, updated_at
    )
    values (
      p_tenant_id, p_asset_type, pg_catalog.btrim(p_asset_name), p_locator_hash,
      'active', coalesce(p_metadata, '{}'::jsonb), pg_catalog.now()
    )
    returning *;
end;
$function$;

create or replace function security.list_deception_assets(
  p_tenant_id uuid,
  p_limit integer default 100
)
returns setof security.deception_assets
language plpgsql
security definer
set search_path = ''
as $function$
begin
  if p_tenant_id is null or p_limit is null or p_limit not between 1 and 100 then
    raise exception 'INVALID_DECEPTION_ASSET_QUERY' using errcode = '22023';
  end if;
  if not exists (
    select 1 from security.tenants t
    where t.id = p_tenant_id and t.status = 'active'
  ) then
    raise exception 'TENANT_NOT_ACTIVE' using errcode = '42501';
  end if;
  return query
    select a.* from security.deception_assets a
    where a.tenant_id = p_tenant_id
    order by a.updated_at desc, a.id
    limit p_limit;
end;
$function$;

create or replace function security.set_deception_asset_status(
  p_tenant_id uuid,
  p_asset_id uuid,
  p_status text
)
returns setof security.deception_assets
language plpgsql
security definer
set search_path = ''
as $function$
begin
  if p_tenant_id is null or p_asset_id is null or p_status is null
     or p_status not in ('active','disabled','retired') then
    raise exception 'INVALID_DECEPTION_ASSET_STATUS' using errcode = '22023';
  end if;
  if not exists (
    select 1 from security.tenants t
    where t.id = p_tenant_id and t.status = 'active'
  ) then
    raise exception 'TENANT_NOT_ACTIVE' using errcode = '42501';
  end if;
  return query
    update security.deception_assets a
    set status = p_status, updated_at = pg_catalog.now()
    where a.tenant_id = p_tenant_id and a.id = p_asset_id
    returning a.*;
  if not found then
    raise exception 'DECEPTION_ASSET_NOT_FOUND' using errcode = 'P0002';
  end if;
end;
$function$;

create or replace function security.record_deception_asset_hit(
  p_tenant_id uuid,
  p_locator_hash text
)
returns table (
  asset_id uuid,
  asset_name text,
  asset_type text,
  hit_count bigint,
  last_seen_at timestamptz,
  locator_hash text
)
language plpgsql
security definer
set search_path = ''
as $function$
begin
  if p_tenant_id is null or p_locator_hash is null
     or p_locator_hash !~ '^[0-9a-f]{64}$' then
    raise exception 'INVALID_DECEPTION_ASSET_LOOKUP' using errcode = '22023';
  end if;
  if not exists (
    select 1 from security.tenants t
    where t.id = p_tenant_id and t.status = 'active'
  ) then
    raise exception 'TENANT_NOT_ACTIVE' using errcode = '42501';
  end if;

  return query
    update security.deception_assets a
    set hit_count = a.hit_count + 1,
        last_seen_at = pg_catalog.now(),
        updated_at = pg_catalog.now()
    where a.tenant_id = p_tenant_id
      and a.locator_hash = p_locator_hash
      and a.status = 'active'
    returning a.id, a.asset_name, a.asset_type, a.hit_count, a.last_seen_at, a.locator_hash;
end;
$function$;

create or replace function security.create_attack_replay(
  p_tenant_id uuid,
  p_source_event_id uuid,
  p_subject_id uuid,
  p_replay_mode text,
  p_event_count integer,
  p_summary jsonb,
  p_evidence_digest text
)
returns uuid
language plpgsql
security definer
set search_path = ''
as $function$
declare
  v_id uuid;
begin
  if p_tenant_id is null
     or p_replay_mode is null or p_replay_mode not in ('dry_run','deterministic_simulation')
     or p_event_count is null or p_event_count not between 0 and 500
     or p_evidence_digest is null or p_evidence_digest !~ '^[0-9a-f]{64}$'
     or pg_catalog.jsonb_typeof(coalesce(p_summary, '{}'::jsonb)) <> 'object'
     or pg_catalog.pg_column_size(coalesce(p_summary, '{}'::jsonb)) > 16384 then
    raise exception 'INVALID_ATTACK_REPLAY' using errcode = '22023';
  end if;

  if not exists (
    select 1 from security.tenants t
    where t.id = p_tenant_id and t.status = 'active'
  ) then
    raise exception 'TENANT_NOT_ACTIVE' using errcode = '42501';
  end if;

  if p_subject_id is not null and not exists (
    select 1 from security.subjects s
    where s.id = p_subject_id and s.tenant_id = p_tenant_id
  ) then
    raise exception 'REPLAY_SUBJECT_TENANT_MISMATCH' using errcode = '42501';
  end if;

  if p_source_event_id is not null and not exists (
    select 1 from security.security_events e
    where e.id = p_source_event_id and e.tenant_id = p_tenant_id
      and (p_subject_id is null or e.subject_id is null or e.subject_id = p_subject_id)
  ) then
    raise exception 'REPLAY_SOURCE_EVENT_TENANT_MISMATCH' using errcode = '42501';
  end if;

  insert into security.attack_replay_sessions(
    tenant_id, source_event_id, subject_id, replay_mode,
    event_count, evidence_digest, expires_at, summary
  )
  values(
    p_tenant_id, p_source_event_id, p_subject_id, p_replay_mode,
    p_event_count, p_evidence_digest,
    pg_catalog.now() + interval '30 minutes',
    coalesce(p_summary, '{}'::jsonb)
  )
  returning id into v_id;
  return v_id;
end;
$function$;

create or replace function security.append_attack_replay_step(
  p_replay_id uuid,
  p_sequence_no integer,
  p_event_type text,
  p_event_at timestamptz,
  p_action text,
  p_signal_codes text[],
  p_evidence jsonb
)
returns void
language plpgsql
security definer
set search_path = ''
as $function$
declare
  v_status text;
  v_next_sequence integer;
begin
  select s.status into v_status
  from security.attack_replay_sessions s
  where s.id = p_replay_id and s.expires_at > pg_catalog.now()
  for update;

  if not found then
    raise exception 'REPLAY_NOT_FOUND_OR_EXPIRED' using errcode = 'P0002';
  end if;
  if v_status not in ('captured','queued','running') then
    raise exception 'REPLAY_NOT_ACTIVE' using errcode = '55000';
  end if;
  if p_sequence_no is null or p_sequence_no not between 1 and 500
     or p_event_type is null or pg_catalog.length(p_event_type) not between 1 and 120
     or p_event_at is null
     or p_action is null or p_action not in ('observe','monitor','challenge','review','block')
     or pg_catalog.cardinality(coalesce(p_signal_codes, '{}'::text[])) > 32
     or exists (
       select 1 from pg_catalog.unnest(coalesce(p_signal_codes, '{}'::text[])) as u(code)
       where u.code is null or pg_catalog.length(u.code) > 100 or u.code !~ '^[A-Z0-9_.:-]+$'
     )
     or pg_catalog.jsonb_typeof(coalesce(p_evidence, '{}'::jsonb)) <> 'object'
     or pg_catalog.pg_column_size(coalesce(p_evidence, '{}'::jsonb)) > 4096 then
    raise exception 'INVALID_REPLAY_STEP' using errcode = '22023';
  end if;

  select coalesce(pg_catalog.max(s.sequence_no), 0) + 1 into v_next_sequence
  from security.attack_replay_steps s where s.replay_id = p_replay_id;
  if p_sequence_no <> v_next_sequence then
    raise exception 'REPLAY_SEQUENCE_GAP' using errcode = '22023';
  end if;

  insert into security.attack_replay_steps(
    replay_id, sequence_no, event_type, event_at, action, signal_codes, evidence
  ) values (
    p_replay_id, p_sequence_no, p_event_type, p_event_at, p_action,
    coalesce(p_signal_codes, '{}'::text[]), coalesce(p_evidence, '{}'::jsonb)
  );

  update security.attack_replay_sessions
  set status = 'running', started_at = coalesce(started_at, pg_catalog.now())
  where id = p_replay_id;
end;
$function$;

create or replace function security.finalize_attack_replay(
  p_replay_id uuid,
  p_status text,
  p_summary jsonb
)
returns void
language plpgsql
security definer
set search_path = ''
as $function$
declare
  v_expected integer;
  v_actual integer;
  v_expires timestamptz;
  v_status text;
begin
  if p_status is null or p_status not in ('completed','failed','expired')
     or pg_catalog.jsonb_typeof(coalesce(p_summary, '{}'::jsonb)) <> 'object'
     or pg_catalog.pg_column_size(coalesce(p_summary, '{}'::jsonb)) > 16384 then
    raise exception 'INVALID_REPLAY_FINALIZATION' using errcode = '22023';
  end if;

  select s.event_count, s.expires_at, s.status
    into v_expected, v_expires, v_status
  from security.attack_replay_sessions s
  where s.id = p_replay_id
  for update;
  if not found then raise exception 'REPLAY_NOT_FOUND' using errcode = 'P0002'; end if;
  if v_status not in ('captured','queued','running') then
    raise exception 'REPLAY_NOT_ACTIVE' using errcode = '55000';
  end if;
  if v_expires <= pg_catalog.now() and p_status <> 'expired' then
    raise exception 'REPLAY_EXPIRED' using errcode = '55000';
  end if;

  select pg_catalog.count(*)::integer into v_actual
  from security.attack_replay_steps s where s.replay_id = p_replay_id;
  if p_status = 'completed' and v_actual <> v_expected then
    raise exception 'REPLAY_EVENT_COUNT_MISMATCH' using errcode = '22023';
  end if;

  update security.attack_replay_sessions
  set status = p_status,
      completed_at = pg_catalog.now(),
      summary = coalesce(p_summary, '{}'::jsonb)
  where id = p_replay_id;
end;
$function$;

create or replace function security.get_attack_replay(
  p_tenant_id uuid,
  p_replay_id uuid
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $function$
declare
  v_result jsonb;
begin
  if p_tenant_id is null or p_replay_id is null then
    raise exception 'INVALID_REPLAY_LOOKUP' using errcode = '22023';
  end if;
  select pg_catalog.jsonb_build_object(
    'session', pg_catalog.to_jsonb(s),
    'steps', coalesce((
      select pg_catalog.jsonb_agg(pg_catalog.to_jsonb(step) order by step.sequence_no)
      from security.attack_replay_steps step
      where step.replay_id = s.id
    ), '[]'::jsonb)
  ) into v_result
  from security.attack_replay_sessions s
  where s.id = p_replay_id and s.tenant_id = p_tenant_id
    and s.expires_at > pg_catalog.now();

  return v_result;
end;
$function$;

create or replace function security.list_attack_replays(
  p_tenant_id uuid,
  p_subject_id uuid default null,
  p_limit integer default 25
)
returns setof security.attack_replay_sessions
language plpgsql
security definer
set search_path = ''
as $function$
begin
  if p_tenant_id is null or p_limit is null or p_limit not between 1 and 100 then
    raise exception 'INVALID_REPLAY_QUERY' using errcode = '22023';
  end if;
  if p_subject_id is not null and not exists (
    select 1 from security.subjects s where s.id = p_subject_id and s.tenant_id = p_tenant_id
  ) then
    raise exception 'REPLAY_SUBJECT_TENANT_MISMATCH' using errcode = '42501';
  end if;
  if not exists (
    select 1 from security.tenants t where t.id = p_tenant_id and t.status = 'active'
  ) then
    raise exception 'TENANT_NOT_ACTIVE' using errcode = '42501';
  end if;
  return query
    select s.* from security.attack_replay_sessions s
    where s.tenant_id = p_tenant_id
      and (p_subject_id is null or s.subject_id = p_subject_id)
    order by s.created_at desc
    limit p_limit;
end;
$function$;

create or replace function security.expire_attack_replays(p_batch_size integer default 100)
returns integer
language plpgsql
security definer
set search_path = ''
as $function$
declare
  v_count integer;
begin
  if p_batch_size is null or p_batch_size not between 1 and 100 then
    raise exception 'INVALID_REPLAY_CLEANUP_LIMIT' using errcode = '22023';
  end if;
  with stale as (
    select s.id from security.attack_replay_sessions s
    where s.expires_at <= pg_catalog.now() and s.status in ('captured','queued','running')
    order by s.expires_at
    for update skip locked
    limit p_batch_size
  )
  update security.attack_replay_sessions s
  set status = 'expired', completed_at = pg_catalog.now(),
      summary = pg_catalog.jsonb_build_object('reason', 'TTL_EXPIRED')
  from stale where s.id = stale.id;
  get diagnostics v_count = row_count;
  return v_count;
end;
$function$;

revoke all on function security.register_deception_asset(uuid,text,text,text,jsonb) from public, anon, authenticated;
revoke all on function security.list_deception_assets(uuid,integer) from public, anon, authenticated;
revoke all on function security.set_deception_asset_status(uuid,uuid,text) from public, anon, authenticated;
revoke all on function security.record_deception_asset_hit(uuid,text) from public, anon, authenticated;
revoke all on function security.create_attack_replay(uuid,uuid,uuid,text,integer,jsonb,text) from public, anon, authenticated;
revoke all on function security.append_attack_replay_step(uuid,integer,text,timestamptz,text,text[],jsonb) from public, anon, authenticated;
revoke all on function security.finalize_attack_replay(uuid,text,jsonb) from public, anon, authenticated;
revoke all on function security.get_attack_replay(uuid,uuid) from public, anon, authenticated;
revoke all on function security.list_attack_replays(uuid,uuid,integer) from public, anon, authenticated;
revoke all on function security.expire_attack_replays(integer) from public, anon, authenticated;

grant execute on function security.register_deception_asset(uuid,text,text,text,jsonb) to service_role;
grant execute on function security.list_deception_assets(uuid,integer) to service_role;
grant execute on function security.set_deception_asset_status(uuid,uuid,text) to service_role;
grant execute on function security.record_deception_asset_hit(uuid,text) to service_role;
grant execute on function security.create_attack_replay(uuid,uuid,uuid,text,integer,jsonb,text) to service_role;
grant execute on function security.append_attack_replay_step(uuid,integer,text,timestamptz,text,text[],jsonb) to service_role;
grant execute on function security.finalize_attack_replay(uuid,text,jsonb) to service_role;
grant execute on function security.get_attack_replay(uuid,uuid) to service_role;
grant execute on function security.list_attack_replays(uuid,uuid,integer) to service_role;
grant execute on function security.expire_attack_replays(integer) to service_role;

commit;