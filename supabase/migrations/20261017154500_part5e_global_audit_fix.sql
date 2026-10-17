-- Part 5E correctness fix: global events have no tenant_id, so they cannot be
-- inserted into security.audit_ledger (tenant_id is NOT NULL). Keep a dedicated
-- append-only global control audit stream instead.
begin;

create table if not exists security.control_plane_audit (
  event_id uuid primary key default gen_random_uuid(),
  scope text not null check (scope in ('global')),
  action text not null check (action ~ '^[a-z0-9_.:-]{1,120}$'),
  mode text check (mode in ('normal','review_only','lockdown')),
  reason_code text not null check (reason_code ~ '^[A-Z0-9_.:-]{1,80}$'),
  actor_id text not null check (length(actor_id) between 1 and 128),
  incident_ref text,
  version bigint not null check (version > 0),
  request_id text,
  created_at timestamptz not null default now(),
  details jsonb not null default '{}'::jsonb
);
create index if not exists control_plane_audit_time_idx on security.control_plane_audit(created_at desc);
create index if not exists control_plane_audit_version_idx on security.control_plane_audit(version desc);
alter table security.control_plane_audit enable row level security;
revoke all on security.control_plane_audit from public, anon, authenticated;
grant select, insert on security.control_plane_audit to service_role;

create or replace function security.set_global_control_plane(
  p_mode text, p_reason_code text, p_actor_id text, p_incident_ref text default null,
  p_expires_at timestamptz default null, p_allow_recovery boolean default false
) returns security.global_control_plane
language plpgsql security definer set search_path = ''
as $$
declare current_row security.global_control_plane;
declare next_row security.global_control_plane;
begin
  if p_mode not in ('normal','review_only','lockdown')
     or p_reason_code !~ '^[A-Z0-9_.:-]{1,80}$'
     or p_actor_id is null or length(p_actor_id) not between 1 and 128 then
    raise exception 'INVALID_CONTROL_PLANE_INPUT' using errcode='22023';
  end if;
  select * into current_row from security.global_control_plane where singleton = true for update;
  if not found then raise exception 'CONTROL_PLANE_NOT_INITIALIZED' using errcode='55000'; end if;
  if (case p_mode when 'normal' then 0 when 'review_only' then 1 else 2 end)
     < (case current_row.mode when 'normal' then 0 when 'review_only' then 1 else 2 end)
     and not p_allow_recovery then
    raise exception 'CONTROL_PLANE_DOWNGRADE_REQUIRES_RECOVERY_APPROVAL' using errcode='42501';
  end if;
  update security.global_control_plane
    set mode=p_mode, reason_code=p_reason_code, changed_by=p_actor_id,
        incident_ref=p_incident_ref, expires_at=p_expires_at,
        version=current_row.version+1, changed_at=now(), updated_at=now()
    where singleton=true returning * into next_row;

  insert into security.control_plane_audit(scope, action, mode, reason_code, actor_id, incident_ref, version, details)
  values ('global','control_plane_changed',p_mode,p_reason_code,p_actor_id,p_incident_ref,next_row.version,
          jsonb_build_object('previousMode',current_row.mode,'previousVersion',current_row.version,'expiresAt',p_expires_at));
  return next_row;
end;
$$;
revoke all on function security.set_global_control_plane(text,text,text,text,timestamptz,boolean) from public, anon, authenticated;
grant execute on function security.set_global_control_plane(text,text,text,text,timestamptz,boolean) to service_role;

commit;
