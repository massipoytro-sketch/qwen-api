-- GainiRen Security advanced platform layers. This migration touches only schema security.
create table if not exists security.behavioral_baselines (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references security.tenants(id) on delete cascade,
  subject_id uuid not null references security.subjects(id) on delete cascade,
  baseline_key text not null check (char_length(baseline_key) between 1 and 100),
  sample_count integer not null default 0 check (sample_count >= 0),
  mean_value double precision not null default 0,
  stddev_value double precision not null default 0 check (stddev_value >= 0),
  p50_value double precision,
  p95_value double precision,
  detector_version text not null default 'baseline-v1',
  updated_at timestamptz not null default now(),
  unique (tenant_id, subject_id, baseline_key)
);
create table if not exists security.fraud_clusters (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references security.tenants(id) on delete cascade,
  cluster_key text not null,
  cluster_type text not null check (cluster_type in ('shared_device','shared_ip','shared_identity','value_abuse','behavioral','mixed')),
  subject_ids uuid[] not null default '{}',
  risk_score numeric not null default 0 check (risk_score between 0 and 100),
  status text not null default 'open' check (status in ('open','monitoring','resolved','false_positive')),
  evidence jsonb not null default '{}',
  first_seen_at timestamptz not null default now(),
  last_seen_at timestamptz not null default now(),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (tenant_id, cluster_key)
);
create table if not exists security.security_policies (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references security.tenants(id) on delete cascade,
  name text not null check (char_length(name) between 1 and 160),
  description text,
  enabled boolean not null default true,
  priority integer not null default 100 check (priority between 0 and 100000),
  conditions jsonb not null check (jsonb_typeof(conditions) = 'object'),
  decision text not null check (decision in ('ALLOW','MONITOR','CHALLENGE','REVIEW','BLOCK')),
  score_delta integer not null default 0 check (score_delta between -50 and 50),
  reason_code text not null check (char_length(reason_code) between 1 and 100),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (tenant_id, name)
);
create table if not exists security.event_outbox (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references security.tenants(id) on delete cascade,
  event_type text not null check (char_length(event_type) between 1 and 120),
  aggregate_id text,
  dedupe_key text,
  payload jsonb not null default '{}',
  status text not null default 'pending' check (status in ('pending','processing','completed','failed')),
  attempts integer not null default 0 check (attempts >= 0),
  available_at timestamptz not null default now(),
  locked_at timestamptz,
  lease_token uuid,
  processed_at timestamptz,
  last_error_code text,
  created_at timestamptz not null default now(),
  constraint event_outbox_dedupe_length check (dedupe_key is null or char_length(dedupe_key) between 1 and 200)
);
create unique index if not exists event_outbox_dedupe_uq on security.event_outbox(tenant_id, dedupe_key) where dedupe_key is not null;
create index if not exists event_outbox_ready_idx on security.event_outbox(status, available_at, created_at) where status in ('pending','processing');
create table if not exists security.investigation_notes (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references security.tenants(id) on delete cascade,
  case_id uuid not null references security.fraud_cases(id) on delete cascade,
  author_type text not null default 'system' check (author_type in ('system','operator','automation')),
  note text not null check (char_length(note) between 1 and 10000),
  details jsonb not null default '{}',
  created_at timestamptz not null default now()
);
create table if not exists security.model_feedback (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references security.tenants(id) on delete cascade,
  prediction_id uuid not null references security.model_predictions(id) on delete cascade,
  outcome text not null check (outcome in ('confirmed_fraud','legitimate','needs_review','unknown')),
  label text,
  feedback text,
  reviewer_ref text,
  created_at timestamptz not null default now(),
  unique (tenant_id, prediction_id)
);
create table if not exists security.analytics_runs (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid references security.tenants(id) on delete cascade,
  task_type text not null check (char_length(task_type) between 1 and 100),
  status text not null default 'queued' check (status in ('queued','running','completed','failed')),
  input_count integer not null default 0 check (input_count >= 0),
  summary jsonb not null default '{}',
  detector_version text not null default 'analytics-v1',
  started_at timestamptz,
  completed_at timestamptz,
  error_code text,
  created_at timestamptz not null default now()
);
create index if not exists behavioral_baselines_subject_idx on security.behavioral_baselines(tenant_id, subject_id, baseline_key);
create index if not exists fraud_clusters_tenant_status_idx on security.fraud_clusters(tenant_id, status, risk_score desc);
create index if not exists security_policies_tenant_enabled_priority_idx on security.security_policies(tenant_id, enabled, priority);
create index if not exists investigation_notes_case_time_idx on security.investigation_notes(tenant_id, case_id, created_at desc);
create index if not exists model_feedback_tenant_time_idx on security.model_feedback(tenant_id, created_at desc);
create index if not exists analytics_runs_status_created_idx on security.analytics_runs(status, created_at);
alter table security.behavioral_baselines enable row level security;
alter table security.fraud_clusters enable row level security;
alter table security.security_policies enable row level security;
alter table security.event_outbox enable row level security;
alter table security.investigation_notes enable row level security;
alter table security.model_feedback enable row level security;
alter table security.analytics_runs enable row level security;
revoke all on security.behavioral_baselines, security.fraud_clusters, security.security_policies, security.event_outbox, security.investigation_notes, security.model_feedback, security.analytics_runs from public, anon, authenticated;
grant all on security.behavioral_baselines, security.fraud_clusters, security.security_policies, security.event_outbox, security.investigation_notes, security.model_feedback, security.analytics_runs to service_role;
create or replace function security.claim_security_event_outbox(p_batch_size integer default 25)
returns setof security.event_outbox language plpgsql set search_path = '' as $function$
declare v_limit integer := greatest(1, least(coalesce(p_batch_size, 25), 100));
begin
  return query
  with picked as (
    select o.id from security.event_outbox o
    where (o.status = 'pending' and o.available_at <= pg_catalog.now())
       or (o.status = 'processing' and o.locked_at < pg_catalog.now() - interval '5 minutes')
    order by o.created_at for update skip locked limit v_limit
  ), claimed as (
    update security.event_outbox o set status = 'processing', locked_at = pg_catalog.now(),
      lease_token = gen_random_uuid(), attempts = o.attempts + 1
    from picked p where o.id = p.id returning o.*
  ) select * from claimed;
end; $function$;
create or replace function security.complete_security_event_outbox(p_event_id uuid, p_lease_token uuid)
returns boolean language plpgsql set search_path = '' as $function$
declare v_count integer;
begin
  update security.event_outbox set status = 'completed', processed_at = pg_catalog.now(),
    locked_at = null, lease_token = null, last_error_code = null
  where id = p_event_id and status = 'processing' and lease_token = p_lease_token;
  get diagnostics v_count = row_count;
  return v_count = 1;
end; $function$;
create or replace function security.fail_security_event_outbox(p_event_id uuid, p_lease_token uuid, p_error_code text default 'WORKER_ERROR', p_max_attempts integer default 8)
returns boolean language plpgsql set search_path = '' as $function$
declare v_count integer;
begin
  update security.event_outbox o set
    status = case when o.attempts >= greatest(1, least(coalesce(p_max_attempts, 8), 20)) then 'failed' else 'pending' end,
    available_at = pg_catalog.now() + make_interval(secs => least(3600, power(2, least(o.attempts, 10))::integer)),
    locked_at = null, lease_token = null,
    last_error_code = left(regexp_replace(coalesce(p_error_code, 'WORKER_ERROR'), '[^A-Za-z0-9_:-]', '', 'g'), 100)
  where o.id = p_event_id and o.status = 'processing' and o.lease_token = p_lease_token;
  get diagnostics v_count = row_count;
  return v_count = 1;
end; $function$;
revoke all on function security.claim_security_event_outbox(integer) from public, anon, authenticated;
revoke all on function security.complete_security_event_outbox(uuid, uuid) from public, anon, authenticated;
revoke all on function security.fail_security_event_outbox(uuid, uuid, text, integer) from public, anon, authenticated;
grant execute on function security.claim_security_event_outbox(integer) to service_role;
grant execute on function security.complete_security_event_outbox(uuid, uuid) to service_role;
grant execute on function security.fail_security_event_outbox(uuid, uuid, text, integer) to service_role;
