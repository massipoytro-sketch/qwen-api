create table if not exists security.bot_challenges (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references security.tenants(id) on delete cascade,
  subject_id uuid null references security.subjects(id) on delete cascade,
  session_id uuid null references security.sessions(id) on delete cascade,
  token_hash text not null,
  nonce_hash text not null,
  action text not null check (action in ('login','signup','withdrawal','sensitive_action','generic')),
  difficulty smallint not null check (difficulty between 0 and 8),
  expires_at timestamptz not null,
  consumed_at timestamptz null,
  attempts integer not null default 0 check (attempts >= 0 and attempts <= 20),
  created_at timestamptz not null default now(),
  unique (tenant_id, token_hash)
);
create index if not exists bot_challenges_lookup_idx on security.bot_challenges (tenant_id, token_hash, consumed_at, expires_at);
create index if not exists bot_challenges_subject_idx on security.bot_challenges (tenant_id, subject_id, created_at desc);
alter table security.bot_challenges enable row level security;
revoke all on security.bot_challenges from anon, authenticated;
grant select, insert, update, delete on security.bot_challenges to service_role;
create or replace function security.consume_bot_challenge(p_tenant_id uuid,p_token_hash text,p_nonce_hash text,p_now timestamptz default now()) returns table(id uuid, subject_id uuid, session_id uuid, action text, difficulty smallint, expires_at timestamptz, attempts integer, already_consumed boolean)
language plpgsql security invoker set search_path = security, public as $$
declare r security.bot_challenges%rowtype;
begin
  select * into r from security.bot_challenges where tenant_id=p_tenant_id and token_hash=p_token_hash and nonce_hash=p_nonce_hash for update;
  if not found then return; end if;
  if r.consumed_at is not null then
    return query select r.id,r.subject_id,r.session_id,r.action,r.difficulty,r.expires_at,r.attempts,true;
    return;
  end if;
  if r.expires_at <= p_now then return; end if;
  r.attempts := least(r.attempts + 1, 20);
  update security.bot_challenges set attempts=r.attempts where id=r.id;
  return query select r.id,r.subject_id,r.session_id,r.action,r.difficulty,r.expires_at,r.attempts,false;
end; $$;
revoke all on function security.consume_bot_challenge(uuid,text,text,timestamptz) from public, anon, authenticated;
grant execute on function security.consume_bot_challenge(uuid,text,text,timestamptz) to service_role;
create or replace function security.finalize_bot_challenge(p_id uuid,p_tenant_id uuid,p_consumed_at timestamptz default now()) returns boolean
language plpgsql security invoker set search_path = security, public as $$
begin
  update security.bot_challenges set consumed_at=p_consumed_at where id=p_id and tenant_id=p_tenant_id and consumed_at is null;
  return found;
end; $$;
revoke all on function security.finalize_bot_challenge(uuid,uuid,timestamptz) from public, anon, authenticated;
grant execute on function security.finalize_bot_challenge(uuid,uuid,timestamptz) to service_role;
