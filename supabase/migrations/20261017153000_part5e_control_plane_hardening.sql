-- Part 5E hardening: subject-wide session revocation, authoritative control reads,
-- and bounded cleanup. Do not apply until live migration history is reconciled.
begin;

create or replace function security.revoke_security_subject_sessions(
  p_tenant_id uuid,
  p_subject_id uuid,
  p_reason_code text,
  p_actor_id text,
  p_request_id text default null,
  p_expires_at timestamptz default null
) returns bigint
language plpgsql security definer set search_path = ''
as $$
declare affected bigint;
begin
  if p_reason_code !~ '^[A-Z0-9_.:-]{1,80}$'
     or p_actor_id is null or length(p_actor_id) not between 1 and 128 then
    raise exception 'INVALID_SUBJECT_REVOCATION_INPUT' using errcode='22023';
  end if;

  insert into security.session_revocations(tenant_id, session_id, subject_id, reason_code, actor_id, request_id, expires_at)
  select s.tenant_id, s.id, s.subject_id, p_reason_code, p_actor_id, p_request_id, p_expires_at
  from security.sessions s
  where s.tenant_id = p_tenant_id
    and s.subject_id = p_subject_id
    and s.ended_at is null
  on conflict (tenant_id, session_id) do update
    set reason_code = excluded.reason_code,
        actor_id = excluded.actor_id,
        request_id = excluded.request_id,
        expires_at = excluded.expires_at;

  get diagnostics affected = row_count;

  insert into security.audit_ledger(tenant_id, action, resource_type, resource_id, actor_type, details)
  values (
    p_tenant_id,
    'security_subject_sessions_revoked',
    'subject',
    p_subject_id::text,
    'operator',
    jsonb_build_object('reasonCode',p_reason_code,'actorId',p_actor_id,'requestId',p_request_id,'affectedSessions',affected)
  );
  return affected;
end;
$$;
revoke all on function security.revoke_security_subject_sessions(uuid,uuid,text,text,text,timestamptz) from public, anon, authenticated;
grant execute on function security.revoke_security_subject_sessions(uuid,uuid,text,text,text,timestamptz) to service_role;

create or replace function security.get_global_control_plane()
returns table(mode text, reason_code text, version bigint, changed_at timestamptz, expires_at timestamptz)
language sql security definer stable set search_path = ''
as $$
  select g.mode, g.reason_code, g.version, g.changed_at, g.expires_at
  from security.global_control_plane g
  where g.singleton = true;
$$;
revoke all on function security.get_global_control_plane() from public, anon, authenticated;
grant execute on function security.get_global_control_plane() to service_role;

create or replace function security.cleanup_expired_session_revocations(p_limit integer default 500)
returns integer
language plpgsql security definer set search_path = ''
as $$
declare deleted_count integer;
begin
  if p_limit < 1 or p_limit > 5000 then raise exception 'INVALID_CLEANUP_LIMIT' using errcode='22023'; end if;
  with doomed as (
    select tenant_id, session_id
    from security.session_revocations
    where expires_at is not null and expires_at <= now()
    order by expires_at asc
    limit p_limit
  )
  delete from security.session_revocations r
  using doomed d
  where r.tenant_id=d.tenant_id and r.session_id=d.session_id;
  get diagnostics deleted_count = row_count;
  return deleted_count;
end;
$$;
revoke all on function security.cleanup_expired_session_revocations(integer) from public, anon, authenticated;
grant execute on function security.cleanup_expired_session_revocations(integer) to service_role;

commit;
