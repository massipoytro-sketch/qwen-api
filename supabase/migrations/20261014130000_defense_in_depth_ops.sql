-- GainiRen Security Part 2: tamper-evident audit ledger and tenant-scoped circuits.
-- Apply only to the dedicated gainiren-shield-lab database.

begin;

create table if not exists security.audit_ledger (
  ledger_id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references security.tenants(id) on delete cascade,
  sequence_no bigint not null check (sequence_no > 0),
  action text not null check (char_length(action) between 1 and 120),
  actor_type text not null check (actor_type in ('system','operator','automation','service')),
  resource_type text,
  resource_id text,
  request_id text,
  details jsonb not null default '{}'::jsonb check (jsonb_typeof(details) = 'object'),
  previous_hash text check (previous_hash is null or previous_hash ~ '^[0-9a-f]{64}$'),
  entry_hash text not null check (entry_hash ~ '^[0-9a-f]{64}$'),
  created_at timestamptz not null,
  unique (tenant_id, sequence_no),
  unique (tenant_id, entry_hash),
  constraint audit_ledger_resource_type_length check (resource_type is null or char_length(resource_type) <= 100),
  constraint audit_ledger_resource_id_length check (resource_id is null or char_length(resource_id) <= 200),
  constraint audit_ledger_request_id_length check (request_id is null or char_length(request_id) <= 200)
);

create index if not exists audit_ledger_tenant_time_idx
  on security.audit_ledger (tenant_id, created_at desc);
create index if not exists audit_ledger_tenant_action_idx
  on security.audit_ledger (tenant_id, action, created_at desc);

alter table security.audit_ledger enable row level security;
revoke all on table security.audit_ledger from public, anon, authenticated;
revoke insert, update, delete, truncate on table security.audit_ledger from service_role;
grant select on table security.audit_ledger to service_role;

create or replace function security.reject_audit_ledger_mutation()
returns trigger
language plpgsql
set search_path = ''
as $function$
begin
  raise exception 'AUDIT_LEDGER_APPEND_ONLY' using errcode = '55000';
end;
$function$;

drop trigger if exists audit_ledger_reject_update_delete on security.audit_ledger;
create trigger audit_ledger_reject_update_delete
before update or delete on security.audit_ledger
for each row execute function security.reject_audit_ledger_mutation();

drop trigger if exists audit_ledger_reject_truncate on security.audit_ledger;
create trigger audit_ledger_reject_truncate
before truncate on security.audit_ledger
for each statement execute function security.reject_audit_ledger_mutation();

create or replace function security.append_security_ledger_entry(
  p_tenant_id uuid,
  p_action text,
  p_resource_type text default null,
  p_resource_id text default null,
  p_request_id text default null,
  p_actor_type text default 'system',
  p_details jsonb default '{}'::jsonb
)
returns table (
  ledger_id uuid,
  sequence_no bigint,
  previous_hash text,
  entry_hash text,
  created_at timestamptz
)
language plpgsql
security definer
set search_path = ''
as $function$
declare
  v_previous_hash text;
  v_last_sequence bigint;
  v_next_sequence bigint;
  v_created_at timestamptz := pg_catalog.clock_timestamp();
  v_details jsonb := coalesce(p_details, '{}'::jsonb);
  v_payload jsonb;
  v_entry_hash text;
  v_ledger_id uuid;
begin
  if p_tenant_id is null
     or p_action is null or char_length(p_action) not between 1 and 120
     or p_actor_type is null or p_actor_type not in ('system','operator','automation','service')
     or (p_resource_type is not null and char_length(p_resource_type) > 100)
     or (p_resource_id is not null and char_length(p_resource_id) > 200)
     or (p_request_id is not null and char_length(p_request_id) > 200)
     or pg_catalog.octet_length(v_details::text) > 16384
     or pg_catalog.jsonb_typeof(v_details) <> 'object' then
    raise exception 'INVALID_SECURITY_LEDGER_ENTRY' using errcode = '22023';
  end if;

  if not exists (
    select 1 from security.tenants t
    where t.id = p_tenant_id and t.status = 'active'
  ) then
    raise exception 'TENANT_NOT_ACTIVE' using errcode = '42501';
  end if;

  -- Serialize writes per tenant so concurrent requests cannot fork the hash chain.
  perform pg_catalog.pg_advisory_xact_lock(
    pg_catalog.hashtextextended(p_tenant_id::text || ':security-ledger', 0)
  );

  select l.sequence_no, l.entry_hash
    into v_last_sequence, v_previous_hash
  from security.audit_ledger l
  where l.tenant_id = p_tenant_id
  order by l.sequence_no desc
  limit 1;

  v_next_sequence := coalesce(v_last_sequence, 0) + 1;
  v_payload := pg_catalog.jsonb_build_object(
    'tenantId', p_tenant_id,
    'sequenceNo', v_next_sequence,
    'action', p_action,
    'actorType', p_actor_type,
    'resourceType', p_resource_type,
    'resourceId', p_resource_id,
    'requestId', p_request_id,
    'details', v_details,
    'previousHash', v_previous_hash,
    'createdAt', v_created_at
  );
  v_entry_hash := pg_catalog.encode(
    extensions.digest(
      pg_catalog.convert_to(coalesce(v_previous_hash, 'GENESIS') || E'\n' || v_payload::text, 'UTF8'),
      'sha256'
    ),
    'hex'
  );

  insert into security.audit_ledger (
    tenant_id, sequence_no, action, actor_type, resource_type, resource_id,
    request_id, details, previous_hash, entry_hash, created_at
  ) values (
    p_tenant_id, v_next_sequence, p_action, p_actor_type, p_resource_type,
    p_resource_id, p_request_id, v_details, v_previous_hash, v_entry_hash, v_created_at
  ) returning security.audit_ledger.ledger_id into v_ledger_id;

  return query select v_ledger_id, v_next_sequence, v_previous_hash, v_entry_hash, v_created_at;
end;
$function$;

revoke all on function security.append_security_ledger_entry(uuid,text,text,text,text,text,jsonb) from public, anon, authenticated;
grant execute on function security.append_security_ledger_entry(uuid,text,text,text,text,text,jsonb) to service_role;

create table if not exists security.circuit_breakers (
  tenant_id uuid not null references security.tenants(id) on delete cascade,
  circuit_key text not null check (char_length(circuit_key) between 1 and 100 and circuit_key ~ '^[A-Za-z0-9:_-]+$'),
  state text not null default 'closed' check (state in ('closed','open','half_open')),
  failure_count integer not null default 0 check (failure_count >= 0),
  window_started_at timestamptz not null default pg_catalog.now(),
  opened_until timestamptz,
  probe_token uuid,
  probe_started_at timestamptz,
  last_failure_at timestamptz,
  last_success_at timestamptz,
  last_error_code text check (last_error_code is null or char_length(last_error_code) <= 80),
  updated_at timestamptz not null default pg_catalog.now(),
  primary key (tenant_id, circuit_key)
);

create index if not exists circuit_breakers_state_updated_idx
  on security.circuit_breakers (state, updated_at desc);

alter table security.circuit_breakers enable row level security;
revoke all on table security.circuit_breakers from public, anon, authenticated;
grant select, insert, update, delete on table security.circuit_breakers to service_role;

create or replace function security.acquire_security_circuit_permit(
  p_tenant_id uuid,
  p_circuit_key text,
  p_failure_threshold integer default 5,
  p_window_seconds integer default 60,
  p_open_seconds integer default 60
)
returns jsonb
language plpgsql
security invoker
set search_path = ''
as $function$
declare
  v_now timestamptz := pg_catalog.clock_timestamp();
  v_row security.circuit_breakers%rowtype;
  v_probe uuid;
begin
  if p_tenant_id is null
     or p_circuit_key is null or char_length(p_circuit_key) not between 1 and 100
     or p_circuit_key !~ '^[A-Za-z0-9:_-]+$'
     or p_failure_threshold not between 2 and 100
     or p_window_seconds not between 10 and 3600
     or p_open_seconds not between 5 and 3600 then
    raise exception 'INVALID_CIRCUIT_BREAKER_INPUT' using errcode = '22023';
  end if;
  if not exists (select 1 from security.tenants t where t.id = p_tenant_id and t.status = 'active') then
    raise exception 'TENANT_NOT_ACTIVE' using errcode = '42501';
  end if;

  insert into security.circuit_breakers (tenant_id, circuit_key)
  values (p_tenant_id, p_circuit_key)
  on conflict (tenant_id, circuit_key) do nothing;

  select * into v_row
  from security.circuit_breakers c
  where c.tenant_id = p_tenant_id and c.circuit_key = p_circuit_key
  for update;

  if v_row.state = 'open' then
    if v_row.opened_until is not null and v_row.opened_until > v_now then
      return pg_catalog.jsonb_build_object(
        'allowed', false, 'state', 'open',
        'retryAfterSeconds', greatest(1, pg_catalog.ceil(extract(epoch from (v_row.opened_until - v_now))))::integer,
        'probeToken', null, 'failureCount', v_row.failure_count,
        'failureThreshold', p_failure_threshold
      );
    end if;

    v_probe := gen_random_uuid();
    update security.circuit_breakers
      set state = 'half_open', probe_token = v_probe, probe_started_at = v_now,
          opened_until = null, updated_at = v_now
    where tenant_id = p_tenant_id and circuit_key = p_circuit_key;
    return pg_catalog.jsonb_build_object(
      'allowed', true, 'state', 'half_open', 'retryAfterSeconds', 0,
      'probeToken', v_probe, 'failureCount', v_row.failure_count,
      'failureThreshold', p_failure_threshold
    );
  end if;

  if v_row.state = 'half_open' then
    if v_row.probe_token is null or v_row.probe_started_at is null
       or v_row.probe_started_at < v_now - interval '30 seconds' then
      v_probe := gen_random_uuid();
      update security.circuit_breakers
        set probe_token = v_probe, probe_started_at = v_now, updated_at = v_now
      where tenant_id = p_tenant_id and circuit_key = p_circuit_key;
      return pg_catalog.jsonb_build_object(
        'allowed', true, 'state', 'half_open', 'retryAfterSeconds', 0,
        'probeToken', v_probe, 'failureCount', v_row.failure_count,
        'failureThreshold', p_failure_threshold
      );
    end if;
    return pg_catalog.jsonb_build_object(
      'allowed', false, 'state', 'half_open', 'retryAfterSeconds', 2,
      'probeToken', null, 'failureCount', v_row.failure_count,
      'failureThreshold', p_failure_threshold
    );
  end if;

  return pg_catalog.jsonb_build_object(
    'allowed', true, 'state', 'closed', 'retryAfterSeconds', 0,
    'probeToken', null, 'failureCount', v_row.failure_count,
    'failureThreshold', p_failure_threshold
  );
end;
$function$;

create or replace function security.record_security_circuit_outcome(
  p_tenant_id uuid,
  p_circuit_key text,
  p_success boolean,
  p_probe_token uuid default null,
  p_failure_threshold integer default 5,
  p_window_seconds integer default 60,
  p_open_seconds integer default 60,
  p_error_code text default null
)
returns jsonb
language plpgsql
security invoker
set search_path = ''
as $function$
declare
  v_now timestamptz := pg_catalog.clock_timestamp();
  v_row security.circuit_breakers%rowtype;
  v_failures integer;
  v_window_start timestamptz;
  v_next_state text;
  v_opened_until timestamptz;
  v_safe_error text;
begin
  if p_tenant_id is null
     or p_circuit_key is null or char_length(p_circuit_key) not between 1 and 100
     or p_circuit_key !~ '^[A-Za-z0-9:_-]+$'
     or p_success is null
     or p_failure_threshold not between 2 and 100
     or p_window_seconds not between 10 and 3600
     or p_open_seconds not between 5 and 3600 then
    raise exception 'INVALID_CIRCUIT_BREAKER_INPUT' using errcode = '22023';
  end if;
  if not exists (select 1 from security.tenants t where t.id = p_tenant_id and t.status = 'active') then
    raise exception 'TENANT_NOT_ACTIVE' using errcode = '42501';
  end if;

  select * into v_row
  from security.circuit_breakers c
  where c.tenant_id = p_tenant_id and c.circuit_key = p_circuit_key
  for update;
  if not found then
    raise exception 'CIRCUIT_NOT_INITIALIZED' using errcode = '22023';
  end if;

  if v_row.state = 'open' then
    return pg_catalog.jsonb_build_object('accepted', false, 'state', v_row.state, 'failureCount', v_row.failure_count);
  end if;
  if v_row.state = 'half_open' and (p_probe_token is null or p_probe_token is distinct from v_row.probe_token) then
    return pg_catalog.jsonb_build_object('accepted', false, 'state', v_row.state, 'failureCount', v_row.failure_count);
  end if;

  if v_row.state = 'half_open' then
    if p_success then
      update security.circuit_breakers
        set state = 'closed', failure_count = 0, window_started_at = v_now,
            opened_until = null, probe_token = null, probe_started_at = null,
            last_success_at = v_now, last_error_code = null, updated_at = v_now
      where tenant_id = p_tenant_id and circuit_key = p_circuit_key;
      return pg_catalog.jsonb_build_object('accepted', true, 'state', 'closed', 'failureCount', 0);
    end if;

    v_safe_error := left(regexp_replace(coalesce(p_error_code, 'DEPENDENCY_FAILURE'), '[^A-Za-z0-9_:-]', '', 'g'), 80);
    update security.circuit_breakers
      set state = 'open', failure_count = greatest(v_row.failure_count, p_failure_threshold),
          opened_until = v_now + make_interval(secs => p_open_seconds),
          probe_token = null, probe_started_at = null, last_failure_at = v_now,
          last_error_code = v_safe_error, updated_at = v_now
    where tenant_id = p_tenant_id and circuit_key = p_circuit_key;
    return pg_catalog.jsonb_build_object('accepted', true, 'state', 'open', 'failureCount', greatest(v_row.failure_count, p_failure_threshold));
  end if;

  if p_success then
    update security.circuit_breakers
      set last_success_at = v_now, updated_at = v_now,
          failure_count = case when window_started_at < v_now - make_interval(secs => p_window_seconds) then 0 else failure_count end,
          window_started_at = case when window_started_at < v_now - make_interval(secs => p_window_seconds) then v_now else window_started_at end
    where tenant_id = p_tenant_id and circuit_key = p_circuit_key;
    return pg_catalog.jsonb_build_object('accepted', true, 'state', 'closed', 'failureCount', v_row.failure_count);
  end if;

  v_window_start := case
    when v_row.window_started_at < v_now - make_interval(secs => p_window_seconds) then v_now
    else v_row.window_started_at
  end;
  v_failures := case when v_window_start = v_now and v_row.window_started_at < v_now - make_interval(secs => p_window_seconds)
    then 1 else v_row.failure_count + 1 end;
  v_next_state := case when v_failures >= p_failure_threshold then 'open' else 'closed' end;
  v_opened_until := case when v_next_state = 'open' then v_now + make_interval(secs => p_open_seconds) else null end;
  v_safe_error := left(regexp_replace(coalesce(p_error_code, 'DEPENDENCY_FAILURE'), '[^A-Za-z0-9_:-]', '', 'g'), 80);

  update security.circuit_breakers
    set state = v_next_state, failure_count = v_failures, window_started_at = v_window_start,
        opened_until = v_opened_until, last_failure_at = v_now, last_error_code = v_safe_error,
        updated_at = v_now
  where tenant_id = p_tenant_id and circuit_key = p_circuit_key;

  return pg_catalog.jsonb_build_object(
    'accepted', true, 'state', v_next_state, 'failureCount', v_failures,
    'openedUntil', v_opened_until
  );
end;
$function$;

revoke all on function security.acquire_security_circuit_permit(uuid,text,integer,integer,integer) from public, anon, authenticated;
revoke all on function security.record_security_circuit_outcome(uuid,text,boolean,uuid,integer,integer,integer,text) from public, anon, authenticated;
grant execute on function security.acquire_security_circuit_permit(uuid,text,integer,integer,integer) to service_role;
grant execute on function security.record_security_circuit_outcome(uuid,text,boolean,uuid,integer,integer,integer,text) to service_role;

commit;
