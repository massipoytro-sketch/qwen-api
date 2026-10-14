-- GainiRen Security Part 2: emergency runtime control / kill switch.
-- Apply only to the dedicated gainiren-shield-lab database.

begin;

create table if not exists security.runtime_controls (
  tenant_id uuid primary key references security.tenants(id) on delete cascade,
  mode text not null default 'normal' check (mode in ('normal','lockdown','review_only')),
  reason_code text not null default 'NORMAL' check (char_length(reason_code) between 1 and 100),
  expires_at timestamptz,
  version bigint not null default 1 check (version > 0),
  updated_at timestamptz not null default now(),
  updated_by text
);

alter table security.runtime_controls enable row level security;
revoke all on security.runtime_controls from public, anon, authenticated;
revoke all on security.runtime_controls from service_role;
grant select, insert, update, delete on security.runtime_controls to service_role;

create or replace function security.get_runtime_control(p_tenant_id uuid)
returns jsonb
language plpgsql
security invoker
set search_path = ''
as $function$
declare r security.runtime_controls;
begin
  select * into r from security.runtime_controls where tenant_id = p_tenant_id;
  if not found then
    return jsonb_build_object('mode','normal','reasonCode','NORMAL','version',0,'expiresAt',null);
  end if;
  if r.expires_at is not null and r.expires_at <= pg_catalog.now() and r.mode <> 'normal' then
    return jsonb_build_object('mode','normal','reasonCode','EXPIRED','version',r.version,'expiresAt',r.expires_at);
  end if;
  return jsonb_build_object('mode',r.mode,'reasonCode',r.reason_code,'version',r.version,'expiresAt',r.expires_at);
end;
$function$;

create or replace function security.set_runtime_control(
  p_tenant_id uuid,
  p_mode text,
  p_reason_code text,
  p_expires_at timestamptz default null,
  p_updated_by text default null
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $function$
declare v_version bigint;
begin
  if p_mode not in ('normal','lockdown','review_only') then raise exception 'INVALID_RUNTIME_MODE'; end if;
  if p_reason_code is null or char_length(p_reason_code) not between 1 and 100 then raise exception 'INVALID_REASON_CODE'; end if;
  if p_updated_by is not null and char_length(p_updated_by) > 200 then raise exception 'INVALID_UPDATED_BY'; end if;
  if not exists (select 1 from security.tenants where id = p_tenant_id) then raise exception 'TENANT_NOT_FOUND'; end if;
  insert into security.runtime_controls(tenant_id,mode,reason_code,expires_at,version,updated_at,updated_by)
  values (p_tenant_id,p_mode,p_reason_code,p_expires_at,1,pg_catalog.now(),left(p_updated_by,200))
  on conflict (tenant_id) do update set
    mode=excluded.mode, reason_code=excluded.reason_code, expires_at=excluded.expires_at,
    version=security.runtime_controls.version+1, updated_at=pg_catalog.now(), updated_by=excluded.updated_by
  returning version into v_version;
  return jsonb_build_object('tenantId',p_tenant_id,'mode',p_mode,'reasonCode',p_reason_code,'version',v_version,'expiresAt',p_expires_at);
end;
$function$;

revoke all on function security.get_runtime_control(uuid) from public, anon, authenticated;
grant execute on function security.get_runtime_control(uuid) to service_role;
revoke all on function security.set_runtime_control(uuid,text,text,timestamptz,text) from public, anon, authenticated;
grant execute on function security.set_runtime_control(uuid,text,text,timestamptz,text) to service_role;

insert into security.runtime_controls(tenant_id)
select id from security.tenants
on conflict (tenant_id) do nothing;

commit;
