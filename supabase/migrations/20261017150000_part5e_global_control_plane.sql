-- Part 5E: persistent emergency control plane and session revocation.
-- Do not apply automatically: reconcile the live migration-history drift first.
create table if not exists security.global_control_plane (
  singleton boolean primary key default true check (singleton),
  mode text not null default 'normal' check (mode in ('normal','review_only','lockdown')),
  reason_code text not null default 'BOOTSTRAP_NORMAL' check (reason_code ~ '^[A-Z0-9_.:-]{1,80}$'),
  incident_ref text,
  version bigint not null default 1 check (version > 0),
  changed_by text not null default 'system',
  changed_at timestamptz not null default now(),
  expires_at timestamptz,
  updated_at timestamptz not null default now()
);
insert into security.global_control_plane(singleton,mode,reason_code)
values (true,'normal','BOOTSTRAP_NORMAL') on conflict (singleton) do nothing;

create table if not exists security.session_revocations (
  tenant_id uuid not null,
  session_id uuid not null,
  subject_id uuid,
  reason_code text not null check (reason_code ~ '^[A-Z0-9_.:-]{1,80}$'),
  actor_id text not null check (length(actor_id) between 1 and 128),
  revoked_at timestamptz not null default now(),
  expires_at timestamptz,
  request_id text,
  metadata jsonb not null default '{}'::jsonb,
  primary key (tenant_id, session_id)
);
create index if not exists session_revocations_subject_idx
  on security.session_revocations(tenant_id, subject_id, revoked_at desc);
create index if not exists session_revocations_active_idx
  on security.session_revocations(tenant_id, expires_at) where expires_at is null;

alter table security.global_control_plane enable row level security;
alter table security.session_revocations enable row level security;
revoke all on security.global_control_plane from public, anon, authenticated;
revoke all on security.session_revocations from public, anon, authenticated;
grant select, insert, update on security.global_control_plane to service_role;
grant select, insert on security.session_revocations to service_role;

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
  insert into security.audit_ledger(tenant_id, action, resource_type, resource_id, actor_type, details)
  values (null, 'global_control_plane_changed', 'global_control_plane', 'global',
          'operator', jsonb_build_object('mode',p_mode,'reasonCode',p_reason_code,
          'actorId',p_actor_id,'incidentRef',p_incident_ref,'version',next_row.version));
  return next_row;
end;
$$;
revoke all on function security.set_global_control_plane(text,text,text,text,timestamptz,boolean) from public, anon, authenticated;
grant execute on function security.set_global_control_plane(text,text,text,text,timestamptz,boolean) to service_role;

create or replace function security.revoke_security_session(
  p_tenant_id uuid, p_session_id uuid, p_subject_id uuid, p_reason_code text,
  p_actor_id text, p_request_id text default null, p_expires_at timestamptz default null
) returns boolean
language plpgsql security definer set search_path = ''
as $$
begin
  if p_reason_code !~ '^[A-Z0-9_.:-]{1,80}$' or p_actor_id is null
     or length(p_actor_id) not between 1 and 128 then
    raise exception 'INVALID_SESSION_REVOCATION_INPUT' using errcode='22023';
  end if;
  insert into security.session_revocations(tenant_id,session_id,subject_id,reason_code,actor_id,request_id,expires_at)
  values (p_tenant_id,p_session_id,p_subject_id,p_reason_code,p_actor_id,p_request_id,p_expires_at)
  on conflict (tenant_id,session_id) do nothing;
  insert into security.audit_ledger(tenant_id, action, resource_type, resource_id, actor_type, details)
  values (p_tenant_id,'security_session_revoked','session',p_session_id::text,'operator',
          jsonb_build_object('subjectId',p_subject_id,'reasonCode',p_reason_code,'actorId',p_actor_id,'requestId',p_request_id));
  return true;
end;
$$;
revoke all on function security.revoke_security_session(uuid,uuid,uuid,text,text,text,timestamptz) from public, anon, authenticated;
grant execute on function security.revoke_security_session(uuid,uuid,uuid,text,text,text,timestamptz) to service_role;
