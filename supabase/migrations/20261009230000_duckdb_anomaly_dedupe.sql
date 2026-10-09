-- Adds idempotency support for analytical findings reprocessed from the distributed outbox.
alter table security.activity_anomalies add column if not exists dedupe_key text;
create unique index if not exists activity_anomalies_dedupe_key_uq
  on security.activity_anomalies(tenant_id, dedupe_key);
revoke all on security.activity_anomalies from public, anon, authenticated;
grant all on security.activity_anomalies to service_role;
