-- GainiRen Security Part 3: authenticated idempotency and replay-resistant event delivery.
-- Apply only to the dedicated gainiren-shield-lab database.

begin;

create table if not exists security.request_idempotency (
  tenant_id uuid not null references security.tenants(id) on delete cascade,
  idempotency_key text not null,
  body_hash text not null check (body_hash ~ '^[0-9a-f]{64}$'),
  state text not null default 'processing' check (state in ('processing','completed')),
  response_status integer check (response_status between 200 and 599),
  response_body jsonb,
  lease_until timestamptz not null,
  created_at timestamptz not null default pg_catalog.now(),
  completed_at timestamptz,
  primary key (tenant_id, idempotency_key),
  constraint request_idempotency_key_length check (char_length(idempotency_key) between 16 and 200),
  constraint request_idempotency_completed_shape check (
    (state = 'processing' and response_status is null and response_body is null and completed_at is null)
    or
    (state = 'completed' and response_status is not null and response_body is not null and completed_at is not null)
  )
);

create index if not exists request_idempotency_lease_idx
  on security.request_idempotency (lease_until)
  where state = 'processing';

alter table security.request_idempotency enable row level security;
revoke all on table security.request_idempotency from public, anon, authenticated;
grant select, insert, update, delete on table security.request_idempotency to service_role;

create or replace function security.reserve_request_idempotency(
  p_tenant_id uuid,
  p_idempotency_key text,
  p_body_hash text,
  p_lease_seconds integer default 30
)
returns jsonb
language plpgsql
security invoker
set search_path = ''
as $function$
declare
  v_now timestamptz := pg_catalog.clock_timestamp();
  v_row security.request_idempotency%rowtype;
  v_lease timestamptz;
begin
  if p_tenant_id is null
     or p_idempotency_key is null or char_length(p_idempotency_key) not between 16 and 200
     or p_idempotency_key !~ '^[A-Za-z0-9._:-]+$'
     or p_body_hash is null or p_body_hash !~ '^[0-9a-f]{64}$'
     or p_lease_seconds not between 5 and 300 then
    raise exception 'INVALID_IDEMPOTENCY_INPUT' using errcode = '22023';
  end if;
  if not exists (select 1 from security.tenants t where t.id = p_tenant_id and t.status = 'active') then
    raise exception 'TENANT_NOT_ACTIVE' using errcode = '42501';
  end if;

  v_lease := v_now + make_interval(secs => p_lease_seconds);

  select * into v_row
  from security.request_idempotency r
  where r.tenant_id = p_tenant_id and r.idempotency_key = p_idempotency_key
  for update;

  if not found then
    insert into security.request_idempotency (
      tenant_id, idempotency_key, body_hash, state, lease_until
    ) values (
      p_tenant_id, p_idempotency_key, p_body_hash, 'processing', v_lease
    );
    return pg_catalog.jsonb_build_object('state','reserved','duplicate',false,'response',null);
  end if;

  if v_row.body_hash is distinct from p_body_hash then
    raise exception 'IDEMPOTENCY_KEY_REUSED_WITH_DIFFERENT_BODY' using errcode = '23505';
  end if;

  if v_row.state = 'completed' then
    return pg_catalog.jsonb_build_object(
      'state','completed','duplicate',true,
      'response',pg_catalog.jsonb_build_object('status',v_row.response_status,'body',v_row.response_body)
    );
  end if;

  if v_row.lease_until > v_now then
    return pg_catalog.jsonb_build_object('state','processing','duplicate',true,'response',null);
  end if;

  update security.request_idempotency
    set lease_until = v_lease
  where tenant_id = p_tenant_id and idempotency_key = p_idempotency_key;

  return pg_catalog.jsonb_build_object('state','reserved','duplicate',false,'response',null);
end;
$function$;

create or replace function security.complete_request_idempotency(
  p_tenant_id uuid,
  p_idempotency_key text,
  p_body_hash text,
  p_response_status integer,
  p_response_body jsonb
)
returns boolean
language plpgsql
security invoker
set search_path = ''
as $function$
declare
  v_row security.request_idempotency%rowtype;
begin
  if p_tenant_id is null
     or p_idempotency_key is null or p_body_hash is null
     or p_body_hash !~ '^[0-9a-f]{64}$'
     or p_response_status not between 200 and 599
     or p_response_body is null
     or pg_catalog.octet_length(p_response_body::text) > 32768 then
    raise exception 'INVALID_IDEMPOTENCY_COMPLETION' using errcode = '22023';
  end if;

  select * into v_row
  from security.request_idempotency r
  where r.tenant_id = p_tenant_id and r.idempotency_key = p_idempotency_key
  for update;

  if not found or v_row.body_hash is distinct from p_body_hash then
    return false;
  end if;
  if v_row.state = 'completed' then
    return true;
  end if;

  update security.request_idempotency
    set state = 'completed', response_status = p_response_status,
        response_body = p_response_body, completed_at = pg_catalog.clock_timestamp(),
        lease_until = pg_catalog.clock_timestamp()
  where tenant_id = p_tenant_id and idempotency_key = p_idempotency_key;
  return true;
end;
$function$;

create or replace function security.release_request_idempotency(
  p_tenant_id uuid,
  p_idempotency_key text,
  p_body_hash text
)
returns boolean
language plpgsql
security invoker
set search_path = ''
as $function$
begin
  delete from security.request_idempotency
  where tenant_id = p_tenant_id
    and idempotency_key = p_idempotency_key
    and body_hash = p_body_hash
    and state = 'processing';
  return found;
end;
$function$;

revoke all on function security.reserve_request_idempotency(uuid,text,text,integer) from public, anon, authenticated;
revoke all on function security.complete_request_idempotency(uuid,text,text,integer,jsonb) from public, anon, authenticated;
revoke all on function security.release_request_idempotency(uuid,text,text) from public, anon, authenticated;
grant execute on function security.reserve_request_idempotency(uuid,text,text,integer) to service_role;
grant execute on function security.complete_request_idempotency(uuid,text,text,integer,jsonb) to service_role;
grant execute on function security.release_request_idempotency(uuid,text,text) to service_role;

commit;
