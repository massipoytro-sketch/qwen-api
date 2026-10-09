-- Atomic fixed-window rate limiting with transaction-scoped advisory locks.
create index if not exists rate_limit_events_window_lookup_idx
  on security.rate_limit_events (tenant_id, key_hash, bucket, window_started_at desc);

create or replace function security.record_rate_limit_event(
  p_tenant_id uuid,
  p_subject_id uuid,
  p_key_hash text,
  p_bucket text,
  p_limit integer,
  p_window_seconds integer
)
returns jsonb
language plpgsql
security invoker
set search_path = ''
as $$
declare
  v_now timestamptz := clock_timestamp();
  v_window_start timestamptz;
  v_count bigint := 0;
  v_oldest timestamptz;
  v_event_id uuid;
  v_reset_at timestamptz;
begin
  if p_tenant_id is null or p_key_hash is null or char_length(p_key_hash) <> 64
     or p_bucket is null or char_length(p_bucket) not between 1 and 100
     or p_limit is null or p_limit < 1 or p_limit > 100000
     or p_window_seconds is null or p_window_seconds < 1 or p_window_seconds > 86400 then
    raise exception 'INVALID_RATE_LIMIT_INPUT' using errcode = '22023';
  end if;

  if not exists (select 1 from security.tenants t where t.id = p_tenant_id and t.status = 'active') then
    raise exception 'TENANT_NOT_ACTIVE' using errcode = '42501';
  end if;
  if p_subject_id is not null and not exists (
    select 1 from security.subjects s where s.id = p_subject_id and s.tenant_id = p_tenant_id
  ) then
    raise exception 'SUBJECT_NOT_FOUND' using errcode = '42501';
  end if;

  perform pg_advisory_xact_lock(
    hashtextextended(p_tenant_id::text || ':' || p_key_hash || ':' || p_bucket, 0)
  );

  v_window_start := v_now - make_interval(secs => p_window_seconds);
  select coalesce(sum(r.event_count), 0), min(r.window_started_at)
    into v_count, v_oldest
  from security.rate_limit_events r
  where r.tenant_id = p_tenant_id
    and r.key_hash = p_key_hash
    and r.bucket = p_bucket
    and r.window_started_at >= v_window_start
    and r.window_started_at <= v_now;

  if v_count >= p_limit then
    v_reset_at := coalesce(v_oldest + make_interval(secs => p_window_seconds), v_now + make_interval(secs => p_window_seconds));
    return jsonb_build_object(
      'allowed', false, 'count', v_count, 'limit', p_limit, 'remaining', 0,
      'resetAt', v_reset_at, 'eventId', null
    );
  end if;

  insert into security.rate_limit_events (
    tenant_id, subject_id, key_hash, bucket, event_count, window_started_at
  ) values (
    p_tenant_id, p_subject_id, p_key_hash, p_bucket, 1, v_now
  ) returning id into v_event_id;

  v_count := v_count + 1;
  v_reset_at := coalesce(v_oldest + make_interval(secs => p_window_seconds), v_now + make_interval(secs => p_window_seconds));
  return jsonb_build_object(
    'allowed', true, 'count', v_count, 'limit', p_limit,
    'remaining', greatest(0, p_limit - v_count),
    'resetAt', v_reset_at, 'eventId', v_event_id
  );
end;
$$;

revoke all on function security.record_rate_limit_event(uuid, uuid, text, text, integer, integer) from public, anon, authenticated;
grant execute on function security.record_rate_limit_event(uuid, uuid, text, text, integer, integer) to service_role;
