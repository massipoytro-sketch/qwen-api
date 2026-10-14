-- Reapply the idempotent final-decision function definition after correcting COALESCE qualification.
begin;
create or replace function security.finalize_security_decision(
  p_tenant_id uuid,
  p_assessment_id uuid,
  p_decision text,
  p_score numeric,
  p_risk_level text,
  p_reason_codes text[] default '{}',
  p_enforcement_source text default 'security_api',
  p_request_id text default null
)
returns jsonb
language plpgsql
security invoker
set search_path = ''
as $function$
declare
  v_assessment security.risk_assessments%rowtype;
  v_current_decision text;
  v_current_reasons text[] := '{}';
  v_reasons text[] := '{}';
  v_decision text;
  v_score numeric;
  v_risk_level text;
  v_decision_floor numeric;
  v_source text := coalesce(p_enforcement_source, 'security_api');
  v_now timestamptz := pg_catalog.clock_timestamp();
  v_rank integer;
begin
  if p_tenant_id is null or p_assessment_id is null
     or p_decision not in ('ALLOW','MONITOR','CHALLENGE','REVIEW','BLOCK')
     or p_score is null or p_score < 0 or p_score > 100
     or p_risk_level not in ('unknown','low','medium','high','critical')
     or p_enforcement_source is null
     or pg_catalog.char_length(p_enforcement_source) not between 1 and 80
     or p_enforcement_source !~ '^[A-Za-z0-9_.:-]+$'
     or (p_request_id is not null and pg_catalog.char_length(p_request_id) > 200)
     or coalesce(pg_catalog.cardinality(p_reason_codes), 0) > 128
     or exists (
       select 1
       from pg_catalog.unnest(coalesce(p_reason_codes, '{}'::text[])) as item(reason_code)
       where item.reason_code is null
          or pg_catalog.char_length(item.reason_code) not between 1 and 100
          or item.reason_code !~ '^[A-Za-z0-9_.:-]+$'
     ) then
    raise exception 'INVALID_FINAL_SECURITY_DECISION' using errcode = '22023';
  end if;

  select * into v_assessment
  from security.risk_assessments a
  where a.id = p_assessment_id and a.tenant_id = p_tenant_id
  for update;

  if not found then
    raise exception 'RISK_ASSESSMENT_NOT_FOUND' using errcode = 'P0002';
  end if;

  select d.decision, d.reason_codes
    into v_current_decision, v_current_reasons
  from security.risk_decisions d
  where d.assessment_id = p_assessment_id
  order by d.decided_at desc
  limit 1
  for update;

  if v_current_decision is null then
    raise exception 'RISK_DECISION_NOT_FOUND' using errcode = 'P0002';
  end if;

  -- Only the most restrictive decision wins.
  v_rank := greatest(
    case v_current_decision when 'ALLOW' then 0 when 'MONITOR' then 1 when 'CHALLENGE' then 2 when 'REVIEW' then 3 else 4 end,
    case p_decision when 'ALLOW' then 0 when 'MONITOR' then 1 when 'CHALLENGE' then 2 when 'REVIEW' then 3 else 4 end,
    case when p_score >= 90 then 4 when p_score >= 70 then 3 when p_score >= 40 then 2 when p_score > 0 then 1 else 0 end
  );
  v_decision := case v_rank when 4 then 'BLOCK' when 3 then 'REVIEW' when 2 then 'CHALLENGE' when 1 then 'MONITOR' else 'ALLOW' end;

  v_decision_floor := case v_decision
    when 'BLOCK' then 90
    when 'REVIEW' then 70
    when 'CHALLENGE' then 40
    when 'MONITOR' then 1
    else 0
  end;
  v_score := greatest(v_assessment.score, p_score, v_decision_floor);

  v_risk_level := case
    when v_score >= 90 then 'critical'
    when v_score >= 70 then 'high'
    when v_score >= 40 then 'medium'
    when v_score > 0 then 'low'
    else 'unknown'
  end;
  -- Preserve a pre-existing higher risk level even if historic scores were inconsistent.
  v_risk_level := case greatest(
    case v_assessment.risk_level when 'unknown' then 0 when 'low' then 1 when 'medium' then 2 when 'high' then 3 else 4 end,
    case p_risk_level when 'unknown' then 0 when 'low' then 1 when 'medium' then 2 when 'high' then 3 else 4 end,
    case v_risk_level when 'unknown' then 0 when 'low' then 1 when 'medium' then 2 when 'high' then 3 else 4 end
  )
    when 4 then 'critical' when 3 then 'high' when 2 then 'medium' when 1 then 'low' else 'unknown' end;

  select coalesce(array_agg(x.reason_code order by x.reason_code), '{}'::text[])
  into v_reasons
  from (
    select distinct unnest(coalesce(v_current_reasons, '{}'::text[]) || coalesce(p_reason_codes, '{}'::text[])) as reason_code
  ) x;

  update security.risk_assessments a
  set score = v_score,
      risk_level = v_risk_level,
      explanation = coalesce(a.explanation, '{}'::jsonb) || pg_catalog.jsonb_build_object(
        'finalEnforcement',
        pg_catalog.jsonb_build_object(
          'decision', v_decision,
          'score', v_score,
          'riskLevel', v_risk_level,
          'source', v_source,
          'reasonCodes', to_jsonb(v_reasons),
          'finalizedAt', v_now
        )
      )
  where a.id = p_assessment_id and a.tenant_id = p_tenant_id;

  update security.risk_decisions d
  set decision = v_decision,
      reason_codes = v_reasons,
      decision_version = 'part3-finalization-v1'
  where d.assessment_id = p_assessment_id;

  perform security.append_security_ledger_entry(
    p_tenant_id,
    'risk_assessment_enforced',
    'risk_assessment',
    p_assessment_id::text,
    p_request_id,
    'system',
    pg_catalog.jsonb_build_object(
      'assessmentId', p_assessment_id,
      'decision', v_decision,
      'score', v_score,
      'riskLevel', v_risk_level,
      'source', v_source,
      'reasonCodes', to_jsonb(v_reasons)
    )
  );

  return pg_catalog.jsonb_build_object(
    'assessmentId', p_assessment_id,
    'decision', v_decision,
    'score', v_score,
    'riskLevel', v_risk_level,
    'reasonCodes', to_jsonb(v_reasons),
    'finalizedAt', v_now
  );
end;
$function$;

revoke all on function security.finalize_security_decision(uuid,uuid,text,numeric,text,text[],text,text) from public, anon, authenticated;
grant execute on function security.finalize_security_decision(uuid,uuid,text,numeric,text,text[],text,text) to service_role;


commit;
