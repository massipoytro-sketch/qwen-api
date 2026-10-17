-- Part 5C / 5D: bounded attack-path lookup and time-bound subject transaction locks.
-- This migration is for the dedicated GainiRen Shield database only.
begin;

create index if not exists graph_edges_tenant_left_lookup_idx
  on security.graph_edges (tenant_id, left_type, left_id, last_seen_at desc);

create index if not exists graph_edges_tenant_right_lookup_idx
  on security.graph_edges (tenant_id, right_type, right_id, last_seen_at desc);

create index if not exists transaction_risk_events_tenant_subject_created_idx
  on security.transaction_risk_events (tenant_id, subject_id, created_at desc);

create table if not exists security.transaction_subject_controls (
  tenant_id uuid not null references security.tenants(id) on delete cascade,
  subject_id uuid not null,
  scope text not null default 'wallet_transactions'
    check (scope in ('wallet_transactions')),
  mode text not null check (mode in ('hold', 'block')),
  reason_code text not null
    check (reason_code ~ '^[A-Z0-9_.:-]{1,80}$'),
  source_assessment_id uuid,
  expires_at timestamptz not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  primary key (tenant_id, subject_id, scope),
  check (expires_at > created_at)
);

create index if not exists transaction_subject_controls_active_idx
  on security.transaction_subject_controls (tenant_id, subject_id, expires_at desc);

alter table security.transaction_subject_controls enable row level security;
revoke all on table security.transaction_subject_controls from public, anon, authenticated;
grant select, insert, update, delete on table security.transaction_subject_controls to service_role;

commit;
