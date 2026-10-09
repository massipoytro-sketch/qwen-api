-- Persist value-jump anomalies in the same transaction as their source event.
alter table security.activity_anomalies
  add column if not exists source_event_id uuid references security.value_events(id) on delete set null;
create unique index if not exists activity_anomalies_source_event_id_uq
  on security.activity_anomalies (source_event_id)
  where source_event_id is not null;

create or replace function security.record_value_event(
  p_tenant_id uuid,
  p_subject_id uuid,
  p_session_id uuid,
  p_value_type text,
  p_current_value numeric,
  p_source text,
  p_idempotency_key text,
  p_occurred_at timestamptz default now(),
  p_metadata jsonb default '{}'::jsonb
)
returns jsonb
language plpgsql
security invoker
set search_path = ''
as $$
declare
  v_state security.value_states%rowtype;
  v_event security.value_events%rowtype;
  v_new_state boolean := false;
  v_jump_score integer := 0;
  v_anomaly_id uuid;
begin
  if p_tenant_id is null or p_subject_id is null then
    raise exception 'VALUE_EVENT_SUBJECT_REQUIRED' using errcode = '22023';
  end if;
  if p_value_type is null or char_length(p_value_type) not between 1 and 100 then
    raise exception 'INVALID_VALUE_TYPE' using errcode = '22023';
  end if;
  if p_current_value is null or p_current_value::text in ('NaN', 'Infinity', '-Infinity') then
    raise exception 'INVALID_CURRENT_VALUE' using errcode = '22023';
  end if;
  if p_idempotency_key is null or char_length(p_idempotency_key) not between 8 and 200 then
    raise exception 'IDEMPOTENCY_KEY_REQUIRED' using errcode = '22023';
  end if;

  if not exists (
    select 1 from security.tenants t
    where t.id = p_tenant_id and t.status = 'active'
  ) then
    raise exception 'TENANT_NOT_ACTIVE' using errcode = '42501';
  end if;
  if not exists (
    select 1 from security.subjects s
    where s.id = p_subject_id and s.tenant_id = p_tenant_id
  ) then
    raise exception 'SUBJECT_NOT_FOUND' using errcode = '42501';
  end if;
  if p_session_id is not null and not exists (
    select 1 from security.sessions s
    where s.id = p_session_id and s.tenant_id = p_tenant_id
      and (s.subject_id is null or s.subject_id = p_subject_id)
  ) then
    raise exception 'SESSION_NOT_FOUND' using errcode = '42501';
  end if;

  insert into security.value_states (tenant_id, subject_id, value_type, current_value)
  values (p_tenant_id, p_subject_id, p_value_type, p_current_value)
  on conflict (tenant_id, subject_id, value_type) do nothing
  returning * into v_state;

  if found then
    v_new_state := true;
  else
    select * into v_state
    from security.value_states vs
    where vs.tenant_id = p_tenant_id
      and vs.subject_id = p_subject_id
      and vs.value_type = p_value_type
    for update;
  end if;

  select * into v_event
  from security.value_events ve
  where ve.tenant_id = p_tenant_id
    and ve.idempotency_key = p_idempotency_key
  limit 1;

  if found then
    select a.id into v_anomaly_id
    from security.activity_anomalies a
    where a.source_event_id = v_event.id
    limit 1;
    v_jump_score := case
      when abs(v_event.delta_value) >= 10000 then 100
      when abs(v_event.delta_value) >= 1000 then 80
      when abs(v_event.delta_value) >= 500 then 50
      else 0
    end;
    return jsonb_build_object(
      'valueEventId', v_event.id,
      'previousValue', v_event.previous_value,
      'currentValue', v_event.current_value,
      'delta', v_event.delta_value,
      'version', v_state.version,
      'duplicate', true,
      'baseline', false,
      'jumpScore', v_jump_score,
      'anomalyId', v_anomaly_id
    );
  end if;

  if v_new_state then
    insert into security.value_events (
      tenant_id, subject_id, session_id, value_type, previous_value,
      current_value, source, idempotency_key, occurred_at, metadata
    ) values (
      p_tenant_id, p_subject_id, p_session_id, p_value_type, p_current_value,
      p_current_value, coalesce(nullif(p_source, ''), 'system'), p_idempotency_key,
      coalesce(p_occurred_at, now()), coalesce(p_metadata, '{}'::jsonb)
    ) returning * into v_event;
  else
    insert into security.value_events (
      tenant_id, subject_id, session_id, value_type, previous_value,
      current_value, source, idempotency_key, occurred_at, metadata
    ) values (
      p_tenant_id, p_subject_id, p_session_id, p_value_type, v_state.current_value,
      p_current_value, coalesce(nullif(p_source, ''), 'system'), p_idempotency_key,
      coalesce(p_occurred_at, now()), coalesce(p_metadata, '{}'::jsonb)
    ) returning * into v_event;

    update security.value_states
      set current_value = p_current_value,
          version = version + 1,
          updated_at = now()
      where id = v_state.id
      returning * into v_state;
  end if;

  v_jump_score := case
    when v_new_state then 0
    when abs(v_event.delta_value) >= 10000 then 100
    when abs(v_event.delta_value) >= 1000 then 80
    when abs(v_event.delta_value) >= 500 then 50
    else 0
  end;

  if v_jump_score > 0 then
    insert into security.activity_anomalies (
      tenant_id, subject_id, session_id, anomaly_type, score, confidence,
      reason_codes, evidence, analyzer_version, occurred_at, source_event_id
    ) values (
      p_tenant_id, p_subject_id, p_session_id, 'value_jump', v_jump_score,
      case when v_jump_score >= 80 then 0.9 else 0.75 end,
      array[case when abs(v_event.delta_value) >= 10000 then 'EXTREME_VALUE_JUMP' else 'LARGE_VALUE_JUMP' end],
      jsonb_build_object(
        'valueType', p_value_type,
        'previousValue', v_event.previous_value,
        'currentValue', v_event.current_value,
        'delta', v_event.delta_value,
        'stateVersion', v_state.version
      ),
      'value-jump-v2', coalesce(p_occurred_at, now()), v_event.id
    ) returning id into v_anomaly_id;
  end if;

  return jsonb_build_object(
    'valueEventId', v_event.id,
    'previousValue', v_event.previous_value,
    'currentValue', v_event.current_value,
    'delta', v_event.delta_value,
    'version', v_state.version,
    'duplicate', false,
    'baseline', v_new_state,
    'jumpScore', v_jump_score,
    'anomalyId', v_anomaly_id
  );
end;
$$;

revoke all on function security.record_value_event(uuid, uuid, uuid, text, numeric, text, text, timestamptz, jsonb) from public, anon, authenticated;
grant execute on function security.record_value_event(uuid, uuid, uuid, text, numeric, text, text, timestamptz, jsonb) to service_role;
