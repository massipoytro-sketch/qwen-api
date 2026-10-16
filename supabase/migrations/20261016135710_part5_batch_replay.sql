-- Part 5 reliability: bounded batch append for ordered attack replay steps.
-- All steps in a batch are written in a single PostgreSQL transaction.

begin;

create or replace function security.append_attack_replay_steps_batch(
  p_replay_id uuid,
  p_steps jsonb
)
returns integer
language plpgsql
security definer
set search_path = ''
as $function$
declare
  v_step jsonb;
  v_count integer := 0;
  v_step_count integer;
begin
  if p_replay_id is null
     or pg_catalog.jsonb_typeof(p_steps) <> 'array'
     or pg_catalog.jsonb_array_length(p_steps) not between 1 and 100
     or pg_catalog.pg_column_size(p_steps) > 262144 then
    raise exception 'INVALID_REPLAY_BATCH' using errcode = '22023';
  end if;

  perform 1
  from security.attack_replay_sessions s
  where s.id = p_replay_id
    and s.expires_at > pg_catalog.now()
    and s.status in ('captured','queued','running')
  for update;
  if not found then
    raise exception 'REPLAY_NOT_FOUND_OR_EXPIRED' using errcode = 'P0002';
  end if;

  v_step_count := pg_catalog.jsonb_array_length(p_steps);
  for v_step in
    select e.value
    from pg_catalog.jsonb_array_elements(p_steps) with ordinality as e(value, ordinal)
    order by e.ordinal
  loop
    perform security.append_attack_replay_step(
      p_replay_id,
      (v_step->>'sequenceNo')::integer,
      v_step->>'eventType',
      (v_step->>'eventAt')::timestamptz,
      v_step->>'action',
      array(
        select pg_catalog.jsonb_array_elements_text(
          case when pg_catalog.jsonb_typeof(v_step->'signalCodes') = 'array'
               then v_step->'signalCodes'
               else '[]'::jsonb end
        )
        limit 32
      ),
      case when pg_catalog.jsonb_typeof(v_step->'evidence') = 'object'
           then v_step->'evidence' else '{}'::jsonb end
    );
    v_count := v_count + 1;
  end loop;

  if v_count <> v_step_count then
    raise exception 'REPLAY_BATCH_COUNT_MISMATCH' using errcode = '22023';
  end if;
  return v_count;
end;
$function$;

revoke all on function security.append_attack_replay_steps_batch(uuid,jsonb) from public, anon, authenticated;
grant execute on function security.append_attack_replay_steps_batch(uuid,jsonb) to service_role;

commit;
