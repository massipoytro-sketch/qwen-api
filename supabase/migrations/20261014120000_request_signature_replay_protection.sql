-- Tenant-scoped nonce store for HMAC-signed API requests.
-- Only the server-side service_role may consume nonces; client roles get no access.

begin;

create table if not exists security.request_nonces (
  tenant_id uuid not null references security.tenants(id) on delete cascade,
  nonce_hash text not null check (nonce_hash ~ '^[0-9a-f]{64}$'),
  created_at timestamptz not null default pg_catalog.now(),
  expires_at timestamptz not null,
  primary key (tenant_id, nonce_hash),
  constraint request_nonces_expiry_after_creation check (expires_at > created_at)
);

create index if not exists request_nonces_expiry_idx
  on security.request_nonces (expires_at);

alter table security.request_nonces enable row level security;
revoke all on table security.request_nonces from public, anon, authenticated;
grant select, insert, delete on table security.request_nonces to service_role;

create or replace function security.consume_request_nonce(
  p_tenant_id uuid,
  p_nonce_hash text
)
returns boolean
language plpgsql
security invoker
set search_path = ''
as $function$
declare
  v_rows integer;
begin
  if p_tenant_id is null or p_nonce_hash is null
     or p_nonce_hash !~ '^[0-9a-f]{64}$' then
    raise exception 'INVALID_REQUEST_NONCE' using errcode = '22023';
  end if;

  if not exists (
    select 1
    from security.tenants t
    where t.id = p_tenant_id and t.status = 'active'
  ) then
    raise exception 'TENANT_NOT_ACTIVE' using errcode = '42501';
  end if;

  -- Bounded cleanup keeps the indexed nonce table from growing forever without
  -- making each API call perform an unbounded delete.
  delete from security.request_nonces expired
  where expired.ctid in (
    select stale.ctid
    from security.request_nonces stale
    where stale.expires_at <= pg_catalog.now()
    order by stale.expires_at asc
    limit 500
  );

  insert into security.request_nonces (tenant_id, nonce_hash, expires_at)
  values (p_tenant_id, p_nonce_hash, pg_catalog.now() + interval '10 minutes')
  on conflict (tenant_id, nonce_hash) do nothing;

  get diagnostics v_rows = row_count;
  return v_rows = 1;
end;
$function$;

revoke all on function security.consume_request_nonce(uuid, text) from public, anon, authenticated;
grant execute on function security.consume_request_nonce(uuid, text) to service_role;

commit;
