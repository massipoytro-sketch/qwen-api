-- Final challenge protocol hardening: proof-of-work must be proven, not merely consumed.
-- External MFA/risk challenges require explicit confirmation from the authenticated tenant backend.
-- Apply only to the dedicated gainiren-shield-lab database.

begin;

alter table security.challenge_tokens
  add column if not exists proof_nonce_hash text,
  add column if not exists proof_difficulty smallint;

do $block$
begin
  if not exists (
    select 1 from pg_catalog.pg_constraint
    where conrelid = 'security.challenge_tokens'::regclass
      and conname = 'challenge_tokens_proof_nonce_hash_check'
  ) then
    alter table security.challenge_tokens
      add constraint challenge_tokens_proof_nonce_hash_check
      check (proof_nonce_hash is null or proof_nonce_hash ~ '^[0-9a-f]{64}$');
  end if;
  if not exists (
    select 1 from pg_catalog.pg_constraint
    where conrelid = 'security.challenge_tokens'::regclass
      and conname = 'challenge_tokens_proof_difficulty_check'
  ) then
    alter table security.challenge_tokens
      add constraint challenge_tokens_proof_difficulty_check
      check (proof_difficulty is null or proof_difficulty between 1 and 4);
  end if;
  if not exists (
    select 1 from pg_catalog.pg_constraint
    where conrelid = 'security.challenge_tokens'::regclass
      and conname = 'challenge_tokens_pow_configuration_check'
  ) then
    alter table security.challenge_tokens
      add constraint challenge_tokens_pow_configuration_check
      check (
        (challenge_type = 'proof_of_work' and proof_nonce_hash is not null and proof_difficulty is not null)
        or
        (challenge_type <> 'proof_of_work' and proof_nonce_hash is null and proof_difficulty is null)
      ) not valid;
  end if;
end;
$block$;

-- Existing rows predate PoW material; keep the constraint NOT VALID so legacy
-- rows remain readable. New/updated rows are still checked by PostgreSQL.
drop function if exists security.issue_challenge_token(uuid,uuid,uuid,text,text,jsonb,integer);

create function security.issue_challenge_token(
  p_tenant_id uuid,
  p_subject_id uuid,
  p_session_id uuid,
  p_challenge_type text,
  p_token_hash text,
  p_reason_codes jsonb default '[]'::jsonb,
  p_ttl_seconds integer default 300,
  p_proof_nonce_hash text default null,
  p_proof_difficulty smallint default null
)
returns uuid
language plpgsql
security invoker
set search_path = ''
as $function$
declare
  v_id uuid;
  v_reasons jsonb := coalesce(p_reason_codes, '[]'::jsonb);
begin
  if p_tenant_id is null
     or p_challenge_type not in ('step_up_mfa','proof_of_work','risk_based_verification')
     or p_token_hash is null or p_token_hash !~ '^[0-9a-f]{64}$'
     or p_ttl_seconds not between 30 and 900
     or pg_catalog.jsonb_typeof(v_reasons) <> 'array'
     or pg_catalog.octet_length(v_reasons::text) > 4096
     or pg_catalog.jsonb_array_length(v_reasons) > 32
     or exists (
       select 1
       from pg_catalog.jsonb_array_elements(v_reasons) as item(value)
       where pg_catalog.jsonb_typeof(item.value) <> 'string'
          or pg_catalog.char_length(item.value #>> '{}') not between 1 and 100
          or item.value #>> '{}' ~ '[\r\n]'
       ) then
    raise exception 'INVALID_CHALLENGE_TOKEN_INPUT' using errcode = '22023';
  end if;

  if p_challenge_type = 'proof_of_work' then
    if p_proof_nonce_hash is null or p_proof_nonce_hash !~ '^[0-9a-f]{64}$'
       or p_proof_difficulty not between 1 and 4 then
      raise exception 'INVALID_PROOF_OF_WORK_CONFIGURATION' using errcode = '22023';
    end if;
  elsif p_proof_nonce_hash is not null or p_proof_difficulty is not null then
    raise exception 'UNEXPECTED_PROOF_OF_WORK_CONFIGURATION' using errcode = '22023';
  end if;

  if not exists (
    select 1 from security.tenants t where t.id = p_tenant_id and t.status = 'active'
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
    tenant_id, subject_id, session_id, challenge_type, token_hash,
    expires_at, reason_codes, proof_nonce_hash, proof_difficulty
  ) values (
    p_tenant_id, p_subject_id, p_session_id, p_challenge_type, p_token_hash,
    pg_catalog.clock_timestamp() + pg_catalog.make_interval(secs => p_ttl_seconds),
    v_reasons, p_proof_nonce_hash, p_proof_difficulty
  )
  returning token_id into v_id;

  return v_id;
end;
$function$;

drop function if exists security.consume_challenge_token(uuid,text);

create function security.consume_challenge_token(
  p_tenant_id uuid,
  p_token_hash text,
  p_proof_nonce text default null,
  p_proof_solution text default null
)
returns jsonb
language plpgsql
security invoker
set search_path = ''
as $function$
declare
  v_row security.challenge_tokens%rowtype;
  v_digest text;
begin
  if p_tenant_id is null or p_token_hash is null or p_token_hash !~ '^[0-9a-f]{64}$' then
    raise exception 'INVALID_CHALLENGE_TOKEN' using errcode = '22023';
  end if;
  if not exists (
    select 1 from security.tenants t where t.id = p_tenant_id and t.status = 'active'
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

  if v_row.challenge_type <> 'proof_of_work' then
    return pg_catalog.jsonb_build_object('valid', false, 'reasonCode', 'EXTERNAL_VERIFICATION_REQUIRED');
  end if;
  if p_proof_nonce is null or p_proof_solution is null
     or pg_catalog.char_length(p_proof_nonce) not between 16 and 128
     or pg_catalog.char_length(p_proof_solution) not between 1 and 128
     or p_proof_solution !~ '^[A-Za-z0-9_-]+$'
     or extensions.digest(pg_catalog.convert_to(p_proof_nonce, 'UTF8'), 'sha256') is null
     or pg_catalog.encode(extensions.digest(pg_catalog.convert_to(p_proof_nonce, 'UTF8'), 'sha256'), 'hex') is distinct from v_row.proof_nonce_hash then
    return pg_catalog.jsonb_build_object('valid', false, 'reasonCode', 'PROOF_OF_WORK_INVALID');
  end if;

  v_digest := pg_catalog.encode(
    extensions.digest(pg_catalog.convert_to(p_proof_nonce || ':' || p_proof_solution, 'UTF8'), 'sha256'),
    'hex'
  );
  if pg_catalog.left(v_digest, v_row.proof_difficulty) <> pg_catalog.repeat('0', v_row.proof_difficulty) then
    return pg_catalog.jsonb_build_object('valid', false, 'reasonCode', 'PROOF_OF_WORK_INVALID');
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

create or replace function security.complete_verified_challenge(
  p_tenant_id uuid,
  p_token_hash text,
  p_verification_reference text
)
returns jsonb
language plpgsql
security invoker
set search_path = ''
as $function$
declare
  v_row security.challenge_tokens%rowtype;
begin
  if p_tenant_id is null
     or p_token_hash is null or p_token_hash !~ '^[0-9a-f]{64}$'
     or p_verification_reference is null
     or pg_catalog.char_length(p_verification_reference) not between 8 and 300
     or p_verification_reference ~ '[\r\n]' then
    raise exception 'INVALID_VERIFIED_CHALLENGE_INPUT' using errcode = '22023';
  end if;
  if not exists (
    select 1 from security.tenants t where t.id = p_tenant_id and t.status = 'active'
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
  if v_row.challenge_type = 'proof_of_work' then
    return pg_catalog.jsonb_build_object('valid', false, 'reasonCode', 'PROOF_OF_WORK_REQUIRED');
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
    'reasonCodes', v_row.reason_codes,
    'verificationReferenceHash', pg_catalog.encode(extensions.digest(pg_catalog.convert_to(p_verification_reference, 'UTF8'), 'sha256'), 'hex')
  );
end;
$function$;

revoke all on function security.issue_challenge_token(uuid,uuid,uuid,text,text,jsonb,integer,text,smallint) from public, anon, authenticated;
revoke all on function security.consume_challenge_token(uuid,text,text,text) from public, anon, authenticated;
revoke all on function security.complete_verified_challenge(uuid,text,text) from public, anon, authenticated;
grant execute on function security.issue_challenge_token(uuid,uuid,uuid,text,text,jsonb,integer,text,smallint) to service_role;
grant execute on function security.consume_challenge_token(uuid,text,text,text) to service_role;
grant execute on function security.complete_verified_challenge(uuid,text,text) to service_role;

commit;
