-- Part 3 security fix: bind challenge issuance and one-time consumption to a tenant.
-- Apply only to the dedicated gainiren-shield-lab database.

begin;

create or replace function security.issue_challenge_token(
  p_tenant_id uuid,
  p_subject_id uuid,
  p_session_id uuid,
  p_challenge_type text,
  p_token_hash text,
  p_reason_codes jsonb default '[]'::jsonb,
  p_ttl_seconds integer default 300
)
returns uuid
language plpgsql
security invoker
set search_path = ''
as $function$
declare
  v_id uuid;
  v_reason_codes jsonb := coalesce(p_reason_codes, '[]'::jsonb);
begin
  if p_tenant_id is null
     or p_challenge_type not in ('step_up_mfa','proof_of_work','risk_based_verification')
     or p_token_hash is null or p_token_hash !~ '^[0-9a-f]{64}$'
     or p_ttl_seconds not between 30 and 900
     or pg_catalog.jsonb_typeof(v_reason_codes) <> 'array'
     or pg_catalog.octet_length(v_reason_codes::text) > 4096
     or pg_catalog.jsonb_array_length(v_reason_codes) > 32
     or exists (
       select 1 from pg_catalog.jsonb_array_elements(v_reason_codes) as item(value)
       where pg_catalog.jsonb_typeof(item.value) <> 'string'
          or pg_catalog.char_length(item.value #>> '{}') > 100
          or item.value #>> '{}' ~ '[\r\n]'
     ) then
    raise exception 'INVALID_CHALLENGE_TOKEN_INPUT' using errcode = '22023';
  end if;

  if not exists (
    select 1 from security.tenants t
    where t.id = p_tenant_id and t.status = 'active'
  ) then
    raise exception 'TENANT_NOT_ACTIVE' using errcode = '42501';
  end if;

  if p_subject_id is not null and not exists (
    select 1 from security.subjects s
    where s.id = p_subject_id and s.tenant_id = p_tenant_id and s.status = 'active'
  ) then
    raise exception 'CHALLENGE_SUBJECT_SCOPE_INVALID' using errcode = '42501';
  end if;

  if p_session_id is not null and not exists (
    select 1 from security.sessions s
    where s.id = p_session_id and s.tenant_id = p_tenant_id
      and s.ended_at is null
      and (p_subject_id is null or s.subject_id = p_subject_id)
  ) then
    raise exception 'CHALLENGE_SESSION_SCOPE_INVALID' using errcode = '42501';
  end if;

  insert into security.challenge_tokens (
    tenant_id, subject_id, session_id, challenge_type, token_hash, expires_at, reason_codes
  ) values (
    p_tenant_id, p_subject_id, p_session_id, p_challenge_type,
    p_token_hash, pg_catalog.clock_timestamp() + pg_catalog.make_interval(secs => p_ttl_seconds),
    v_reason_codes
  )
  returning token_id into v_id;

  return v_id;
end;
$function$;

-- Remove the unscoped RPC so the service cannot accidentally call it.
drop function if exists security.consume_challenge_token(text);

create or replace function security.consume_challenge_token(
  p_tenant_id uuid,
  p_token_hash text
)
returns jsonb
language plpgsql
security invoker
set search_path = ''
as $function$
declare
  v_row security.challenge_tokens%rowtype;
begin
  if p_tenant_id is null or p_token_hash is null or p_token_hash !~ '^[0-9a-f]{64}$' then
    raise exception 'INVALID_CHALLENGE_TOKEN' using errcode = '22023';
  end if;

  if not exists (
    select 1 from security.tenants t
    where t.id = p_tenant_id and t.status = 'active'
  ) then
    raise exception 'TENANT_NOT_ACTIVE' using errcode = '42501';
  end if;

  select * into v_row
  from security.challenge_tokens c
  where c.tenant_id = p_tenant_id and c.token_hash = p_token_hash
  for update;

  if not found then
    return pg_catalog.jsonb_build_object('valid', false, 'reasonCode', 'CHALLENGE_NOT_FOUND');
  end if;
  if v_row.consumed_at is not null then
    return pg_catalog.jsonb_build_object('valid', false, 'reasonCode', 'CHALLENGE_ALREADY_CONSUMED');
  end if;
  if v_row.expires_at <= pg_catalog.clock_timestamp() then
    return pg_catalog.jsonb_build_object('valid', false, 'reasonCode', 'CHALLENGE_EXPIRED');
  end if;

  update security.challenge_tokens
  set consumed_at = pg_catalog.clock_timestamp()
  where token_id = v_row.token_id and tenant_id = p_tenant_id and consumed_at is null;

  if not found then
    return pg_catalog.jsonb_build_object('valid', false, 'reasonCode', 'CHALLENGE_ALREADY_CONSUMED');
  end if;

  return pg_catalog.jsonb_build_object(
    'valid', true,
    'tokenId', v_row.token_id,
    'tenantId', v_row.tenant_id,
    'subjectId', v_row.subject_id,
    'sessionId', v_row.session_id,
    'challengeType', v_row.challenge_type,
    'reasonCodes', v_row.reason_codes
  );
end;
$function$;

revoke all on function security.issue_challenge_token(uuid,uuid,uuid,text,text,jsonb,integer) from public, anon, authenticated;
revoke all on function security.consume_challenge_token(uuid,text) from public, anon, authenticated;
grant execute on function security.issue_challenge_token(uuid,uuid,uuid,text,text,jsonb,integer) to service_role;
grant execute on function security.consume_challenge_token(uuid,text) to service_role;

commit;
