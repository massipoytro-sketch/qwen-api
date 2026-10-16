create table if not exists security.deception_assets (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references security.tenants(id) on delete cascade,
  asset_type text not null check (asset_type in ('route','credential_canary','database_canary','service_canary','document_canary')),
  asset_name text not null check (length(asset_name) between 1 and 160),
  locator_hash text not null check (locator_hash ~ '^[0-9a-f]{64}$'),
  status text not null default 'active' check (status in ('active','disabled','retired')),
  metadata jsonb not null default '{}'::jsonb check (pg_column_size(metadata) <= 8192),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (tenant_id, locator_hash)
);

create table if not exists security.attack_replay_sessions (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references security.tenants(id) on delete cascade,
  source_event_id uuid references security.security_events(id) on delete set null,
  subject_id uuid references security.subjects(id) on delete set null,
  status text not null default 'captured' check (status in ('captured','queued','running','completed','failed','expired')),
  replay_mode text not null default 'dry_run' check (replay_mode in ('dry_run','deterministic_simulation')),
  event_count integer not null default 0 check (event_count between 0 and 500),
  evidence_digest text not null check (evidence_digest ~ '^[0-9a-f]{64}$'),
  started_at timestamptz,
  completed_at timestamptz,
  expires_at timestamptz not null,
  summary jsonb not null default '{}'::jsonb check (pg_column_size(summary) <= 16384),
  created_at timestamptz not null default now(),
  check (completed_at is null or started_at is null or completed_at >= started_at)
);

create table if not exists security.attack_replay_steps (
  id uuid primary key default gen_random_uuid(),
  replay_id uuid not null references security.attack_replay_sessions(id) on delete cascade,
  sequence_no integer not null check (sequence_no between 1 and 500),
  event_type text not null check (length(event_type) between 1 and 120),
  event_at timestamptz not null,
  action text not null check (action in ('observe','monitor','challenge','review','block')),
  signal_codes text[] not null default '{}',
  evidence jsonb not null default '{}'::jsonb check (pg_column_size(evidence) <= 4096),
  unique (replay_id, sequence_no)
);

create index if not exists idx_deception_assets_tenant_status on security.deception_assets(tenant_id,status);
create index if not exists idx_attack_replay_tenant_created on security.attack_replay_sessions(tenant_id,created_at desc);
create index if not exists idx_attack_replay_subject_created on security.attack_replay_sessions(tenant_id,subject_id,created_at desc);
create index if not exists idx_attack_replay_steps_replay_sequence on security.attack_replay_steps(replay_id,sequence_no);

alter table security.deception_assets enable row level security;
alter table security.attack_replay_sessions enable row level security;
alter table security.attack_replay_steps enable row level security;

revoke all on security.deception_assets from anon, authenticated, service_role;
revoke all on security.attack_replay_sessions from anon, authenticated, service_role;
revoke all on security.attack_replay_steps from anon, authenticated, service_role;

drop function if exists security.create_attack_replay(uuid,uuid,uuid,text,integer,jsonb,text);
create or replace function security.create_attack_replay(
  p_tenant_id uuid, p_source_event_id uuid, p_subject_id uuid, p_replay_mode text,
  p_event_count integer, p_summary jsonb, p_evidence_digest text
) returns uuid language plpgsql security definer set search_path=security,public as $$
declare v_id uuid;
begin
  if p_replay_mode not in ('dry_run','deterministic_simulation') then raise exception 'INVALID_REPLAY_MODE'; end if;
  if p_event_count < 0 or p_event_count > 500 then raise exception 'INVALID_REPLAY_EVENT_COUNT'; end if;
  if p_evidence_digest is null or p_evidence_digest !~ '^[0-9a-f]{64}$' then raise exception 'INVALID_REPLAY_DIGEST'; end if;
  if pg_column_size(coalesce(p_summary,'{}'::jsonb)) > 16384 then raise exception 'REPLAY_SUMMARY_TOO_LARGE'; end if;
  if not exists (select 1 from security.tenants where id=p_tenant_id and status='active') then raise exception 'TENANT_NOT_ACTIVE'; end if;
  insert into security.attack_replay_sessions(tenant_id,source_event_id,subject_id,replay_mode,event_count,evidence_digest,expires_at,summary)
  values(p_tenant_id,p_source_event_id,p_subject_id,p_replay_mode,p_event_count,p_evidence_digest,now()+interval '30 minutes',coalesce(p_summary,'{}'::jsonb)) returning id into v_id;
  return v_id;
end $$;
revoke all on function security.create_attack_replay(uuid,uuid,uuid,text,integer,jsonb,text) from public,anon,authenticated;
grant execute on function security.create_attack_replay(uuid,uuid,uuid,text,integer,jsonb,text) to service_role;

create or replace function security.append_attack_replay_step(
  p_replay_id uuid,p_sequence_no integer,p_event_type text,p_event_at timestamptz,
  p_action text,p_signal_codes text[],p_evidence jsonb
) returns void language plpgsql security definer set search_path=security,public as $$
declare v_tenant uuid;
begin
  select tenant_id into v_tenant from security.attack_replay_sessions where id=p_replay_id and expires_at>now() for update;
  if v_tenant is null then raise exception 'REPLAY_NOT_FOUND_OR_EXPIRED'; end if;
  if p_sequence_no < 1 or p_sequence_no > 500 then raise exception 'INVALID_REPLAY_SEQUENCE'; end if;
  if p_action not in ('observe','monitor','challenge','review','block') then raise exception 'INVALID_REPLAY_ACTION'; end if;
  if pg_column_size(coalesce(p_evidence,'{}'::jsonb)) > 4096 then raise exception 'REPLAY_EVIDENCE_TOO_LARGE'; end if;
  if p_sequence_no > 1 and not exists(select 1 from security.attack_replay_steps where replay_id=p_replay_id and sequence_no=p_sequence_no-1) then raise exception 'REPLAY_SEQUENCE_GAP'; end if;
  insert into security.attack_replay_steps(replay_id,sequence_no,event_type,event_at,action,signal_codes,evidence)
  values(p_replay_id,p_sequence_no,p_event_type,p_event_at,p_action,coalesce(p_signal_codes,'{}'),coalesce(p_evidence,'{}'::jsonb));
end $$;
revoke all on function security.append_attack_replay_step(uuid,integer,text,timestamptz,text,text[],jsonb) from public,anon,authenticated;
grant execute on function security.append_attack_replay_step(uuid,integer,text,timestamptz,text,text[],jsonb) to service_role;

create or replace function security.finalize_attack_replay(p_replay_id uuid,p_status text,p_summary jsonb)
returns void language plpgsql security definer set search_path=security,public as $$
begin
  if p_status not in ('completed','failed','expired') then raise exception 'INVALID_REPLAY_STATUS'; end if;
  if pg_column_size(coalesce(p_summary,'{}'::jsonb)) > 16384 then raise exception 'REPLAY_SUMMARY_TOO_LARGE'; end if;
  update security.attack_replay_sessions set status=p_status,completed_at=now(),summary=coalesce(p_summary,'{}'::jsonb)
  where id=p_replay_id and expires_at>now() and status in ('captured','queued','running');
  if not found then raise exception 'REPLAY_NOT_ACTIVE'; end if;
end $$;
revoke all on function security.finalize_attack_replay(uuid,text,jsonb) from public,anon,authenticated;
grant execute on function security.finalize_attack_replay(uuid,text,jsonb) to service_role;
