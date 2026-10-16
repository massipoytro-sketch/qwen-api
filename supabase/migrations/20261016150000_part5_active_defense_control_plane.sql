begin;

create table if not exists security.security_subject_states (
  tenant_id uuid not null references security.tenants(id) on delete cascade,
  subject_id uuid not null,
  state text not null check (state in ('TRUSTED','MONITORED','SUSPICIOUS','CHALLENGE_REQUIRED','QUARANTINED','UNDER_REVIEW','BLOCKED')),
  state_version bigint not null default 1,
  reason_codes jsonb not null default '[]'::jsonb,
  last_decision text not null check (last_decision in ('ALLOW','MONITOR','CHALLENGE','REVIEW','BLOCK')),
  last_score integer not null check (last_score between 0 and 100),
  last_assessment_id uuid,
  updated_at timestamptz not null default now(),
  primary key (tenant_id, subject_id)
);

create table if not exists security.security_control_policies (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references security.tenants(id) on delete cascade,
  name text not null check (length(name) between 1 and 120),
  priority integer not null default 100 check (priority between 0 and 100000),
  enabled boolean not null default true,
  action text not null check (action in ('ALLOW','MONITOR','CHALLENGE','REVIEW','BLOCK','QUARANTINE')),
  condition jsonb not null default '{}'::jsonb,
  reason_code text not null check (reason_code ~ '^[A-Z0-9_:-]{1,100}$'),
  starts_at timestamptz,
  expires_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists security_control_policies_lookup_idx
  on security.security_control_policies (tenant_id, enabled, priority desc);

create table if not exists security.device_trust_records (
  tenant_id uuid not null references security.tenants(id) on delete cascade,
  device_id_hash text not null check (device_id_hash ~ '^[a-f0-9]{64}$'),
  subject_id uuid,
  trust_score integer not null default 50 check (trust_score between 0 and 100),
  observation_count integer not null default 0 check (observation_count >= 0),
  last_network_hash text check (last_network_hash is null or last_network_hash ~ '^[a-f0-9]{64}$'),
  first_seen_at timestamptz not null default now(),
  last_seen_at timestamptz not null default now(),
  metadata jsonb not null default '{}'::jsonb,
  primary key (tenant_id, device_id_hash)
);

create index if not exists device_trust_subject_idx
  on security.device_trust_records (tenant_id, subject_id, last_seen_at desc);

create table if not exists security.transaction_risk_events (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references security.tenants(id) on delete cascade,
  subject_id uuid,
  session_id uuid,
  assessment_id uuid,
  operation text not null check (length(operation) between 1 and 120),
  before_value numeric,
  after_value numeric,
  risk_score integer not null check (risk_score between 0 and 100),
  decision text not null check (decision in ('ALLOW','MONITOR','CHALLENGE','REVIEW','BLOCK')),
  sensitive boolean not null default false,
  currency text,
  context jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create index if not exists transaction_risk_subject_idx
  on security.transaction_risk_events (tenant_id, subject_id, created_at desc);

create table if not exists security.security_incidents (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references security.tenants(id) on delete cascade,
  subject_id uuid,
  fingerprint text not null check (fingerprint ~ '^[a-f0-9]{64}$'),
  status text not null default 'open' check (status in ('open','investigating','contained','resolved','false_positive')),
  severity text not null check (severity in ('low','medium','high','critical')),
  first_seen_at timestamptz not null default now(),
  last_seen_at timestamptz not null default now(),
  occurrence_count integer not null default 1 check (occurrence_count > 0),
  reason_codes jsonb not null default '[]'::jsonb,
  latest_decision text not null check (latest_decision in ('ALLOW','MONITOR','CHALLENGE','REVIEW','BLOCK')),
  summary jsonb not null default '{}'::jsonb,
  unique (tenant_id, fingerprint)
);

create index if not exists security_incidents_subject_idx
  on security.security_incidents (tenant_id, subject_id, last_seen_at desc);

create table if not exists security.security_incident_evidence (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references security.tenants(id) on delete cascade,
  incident_id uuid not null references security.security_incidents(id) on delete cascade,
  assessment_id uuid,
  source text not null check (length(source) between 1 and 80),
  evidence_hash text not null check (evidence_hash ~ '^[a-f0-9]{64}$'),
  evidence jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create index if not exists incident_evidence_lookup_idx
  on security.security_incident_evidence (tenant_id, incident_id, created_at desc);

create table if not exists security.security_control_modes (
  tenant_id uuid primary key references security.tenants(id) on delete cascade,
  mode text not null default 'NORMAL' check (mode in ('NORMAL','MAINTENANCE','LOCKDOWN','DENY_ALL')),
  scope text not null default 'tenant' check (scope in ('tenant','endpoint','operation')),
  scope_key text,
  reason_code text not null default 'ADMINISTRATIVE_CONTROL',
  expires_at timestamptz,
  updated_at timestamptz not null default now()
);

alter table security.security_subject_states enable row level security;
alter table security.security_control_policies enable row level security;
alter table security.device_trust_records enable row level security;
alter table security.transaction_risk_events enable row level security;
alter table security.security_incidents enable row level security;
alter table security.security_incident_evidence enable row level security;
alter table security.security_control_modes enable row level security;

revoke all on security.security_subject_states from anon, authenticated;
revoke all on security.security_control_policies from anon, authenticated;
revoke all on security.device_trust_records from anon, authenticated;
revoke all on security.transaction_risk_events from anon, authenticated;
revoke all on security.security_incidents from anon, authenticated;
revoke all on security.security_incident_evidence from anon, authenticated;
revoke all on security.security_control_modes from anon, authenticated;

revoke all on security.security_subject_states from service_role;
revoke all on security.security_control_policies from service_role;
revoke all on security.device_trust_records from service_role;
revoke all on security.transaction_risk_events from service_role;
revoke all on security.security_incidents from service_role;
revoke all on security.security_incident_evidence from service_role;
revoke all on security.security_control_modes from service_role;

create or replace function security.get_control_plane_context(
  p_tenant_id uuid,
  p_subject_id uuid
)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, security
as $$
declare
  v_state jsonb;
  v_policies jsonb;
  v_mode jsonb;
begin
  select jsonb_build_object(
    'state', s.state,
    'stateVersion', s.state_version,
    'reasonCodes', s.reason_codes,
    'lastDecision', s.last_decision,
    'lastScore', s.last_score
  ) into v_state
  from security.security_subject_states s
  where s.tenant_id = p_tenant_id and s.subject_id = p_subject_id;

  select coalesce(jsonb_agg(jsonb_build_object(
    'id', p.id,
    'priority', p.priority,
    'enabled', p.enabled,
    'action', p.action,
    'condition', p.condition,
    'reasonCode', p.reason_code,
    'expiresAt', p.expires_at
  ) order by p.priority desc), '[]'::jsonb) into v_policies
  from security.security_control_policies p
  where p.tenant_id = p_tenant_id
    and p.enabled
    and (p.starts_at is null or p.starts_at <= now())
    and (p.expires_at is null or p.expires_at > now());

  select coalesce(jsonb_build_object(
    'mode', m.mode,
    'scope', m.scope,
    'scopeKey', m.scope_key,
    'reasonCode', m.reason_code,
    'expiresAt', m.expires_at
  ), jsonb_build_object('mode','NORMAL','scope','tenant')) into v_mode
  from security.security_control_modes m
  where m.tenant_id = p_tenant_id
    and (m.expires_at is null or m.expires_at > now());

  return jsonb_build_object(
    'state', coalesce(v_state, jsonb_build_object('state','TRUSTED','stateVersion',0,'reasonCodes','[]'::jsonb,'lastDecision','ALLOW','lastScore',0)),
    'policies', v_policies,
    'mode', coalesce(v_mode, jsonb_build_object('mode','NORMAL','scope','tenant'))
  );
end;
$$;

create or replace function security.record_control_plane_result(
  p_tenant_id uuid,
  p_subject_id uuid,
  p_assessment_id uuid,
  p_state text,
  p_decision text,
  p_score integer,
  p_reason_codes jsonb,
  p_device_hash text default null,
  p_transaction jsonb default null,
  p_incident jsonb default null
)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, security
as $$
declare
  v_version bigint;
  v_incident_id uuid;
begin
  if p_state not in ('TRUSTED','MONITORED','SUSPICIOUS','CHALLENGE_REQUIRED','QUARANTINED','UNDER_REVIEW','BLOCKED') then raise exception 'INVALID_SECURITY_STATE'; end if;
  if p_decision not in ('ALLOW','MONITOR','CHALLENGE','REVIEW','BLOCK') then raise exception 'INVALID_SECURITY_DECISION'; end if;
  if p_score < 0 or p_score > 100 then raise exception 'INVALID_SECURITY_SCORE'; end if;

  insert into security.security_subject_states as s
    (tenant_id, subject_id, state, state_version, reason_codes, last_decision, last_score, last_assessment_id, updated_at)
  values
    (p_tenant_id, p_subject_id, p_state, 1, coalesce(p_reason_codes,'[]'::jsonb), p_decision, p_score, p_assessment_id, now())
  on conflict (tenant_id, subject_id) do update set
    state = excluded.state,
    state_version = s.state_version + 1,
    reason_codes = excluded.reason_codes,
    last_decision = excluded.last_decision,
    last_score = excluded.last_score,
    last_assessment_id = excluded.last_assessment_id,
    updated_at = now()
  returning state_version into v_version;

  if p_device_hash is not null then
    insert into security.device_trust_records (tenant_id, device_id_hash, subject_id, trust_score, observation_count, last_seen_at)
    values (p_tenant_id, p_device_hash, p_subject_id, greatest(0, 100 - p_score), 1, now())
    on conflict (tenant_id, device_id_hash) do update set
      subject_id = excluded.subject_id,
      trust_score = round((security.device_trust_records.trust_score * 0.8) + (excluded.trust_score * 0.2)),
      observation_count = security.device_trust_records.observation_count + 1,
      last_seen_at = now();
  end if;

  if p_transaction is not null then
    insert into security.transaction_risk_events (
      tenant_id, subject_id, assessment_id, operation, before_value, after_value, risk_score, decision, sensitive, currency, context
    ) values (
      p_tenant_id, p_subject_id, p_assessment_id,
      coalesce(p_transaction->>'operation','unknown'),
      nullif(p_transaction->>'before','')::numeric,
      nullif(p_transaction->>'after','')::numeric,
      greatest(0, least(100, coalesce((p_transaction->>'riskScore')::integer, 0))),
      p_decision,
      coalesce((p_transaction->>'sensitive')::boolean,false),
      p_transaction->>'currency',
      coalesce(p_transaction->'context','{}'::jsonb)
    );
  end if;

  if p_incident is not null then
    insert into security.security_incidents (
      tenant_id, subject_id, fingerprint, severity, reason_codes, latest_decision, summary
    ) values (
      p_tenant_id, p_subject_id,
      p_incident->>'fingerprint',
      p_incident->>'severity',
      coalesce(p_incident->'reasonCodes','[]'::jsonb),
      p_decision,
      jsonb_build_object('assessmentId',p_assessment_id,'state',p_state)
    )
    on conflict (tenant_id, fingerprint) do update set
      last_seen_at = now(),
      occurrence_count = security.security_incidents.occurrence_count + 1,
      severity = excluded.severity,
      reason_codes = excluded.reason_codes,
      latest_decision = excluded.latest_decision,
      summary = excluded.summary
    returning id into v_incident_id;
  end if;

  return jsonb_build_object('stateVersion', v_version, 'incidentId', v_incident_id);
end;
$$;

revoke all on function security.get_control_plane_context(uuid,uuid) from public, anon, authenticated;
revoke all on function security.record_control_plane_result(uuid,uuid,uuid,text,text,integer,jsonb,text,jsonb,jsonb) from public, anon, authenticated;
grant execute on function security.get_control_plane_context(uuid,uuid) to service_role;
grant execute on function security.record_control_plane_result(uuid,uuid,uuid,text,text,integer,jsonb,text,jsonb,jsonb) to service_role;

commit;
