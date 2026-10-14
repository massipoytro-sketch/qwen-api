-- GainiRen Security Part 2: verify the per-tenant hash-chain ledger.
-- A limited scan clearly reports whether it checked the complete tenant ledger.

begin;

create or replace function security.verify_security_ledger_chain(
  p_tenant_id uuid,
  p_limit integer default 10000
)
returns jsonb
language plpgsql
security invoker
set search_path = ''
as $function$
declare
  v_row security.audit_ledger%rowtype;
  v_payload jsonb;
  v_computed_hash text;
  v_previous_sequence bigint := null;
  v_previous_hash text := null;
  v_first_sequence bigint := null;
  v_last_sequence bigint := null;
  v_mismatch_sequence bigint := null;
  v_checked integer := 0;
  v_total_count bigint := 0;
  v_valid boolean := true;
  v_complete boolean := false;
begin
  if p_tenant_id is null or p_limit is null or p_limit < 1 or p_limit > 10000 then
    raise exception 'INVALID_SECURITY_LEDGER_VERIFY_INPUT' using errcode = '22023';
  end if;

  if not exists (
    select 1 from security.tenants t
    where t.id = p_tenant_id and t.status = 'active'
  ) then
    raise exception 'TENANT_NOT_ACTIVE' using errcode = '42501';
  end if;

  select count(*) into v_total_count
  from security.audit_ledger l
  where l.tenant_id = p_tenant_id;

  for v_row in
    select recent.*
    from (
      select l.*
      from security.audit_ledger l
      where l.tenant_id = p_tenant_id
      order by l.sequence_no desc
      limit p_limit
    ) recent
    order by recent.sequence_no asc
  loop
    if v_first_sequence is null then
      v_first_sequence := v_row.sequence_no;
      if v_row.sequence_no = 1 and v_row.previous_hash is not null then
        v_valid := false;
        v_mismatch_sequence := v_row.sequence_no;
        exit;
      end if;
    else
      if v_row.sequence_no <> v_previous_sequence + 1
         or v_row.previous_hash is distinct from v_previous_hash then
        v_valid := false;
        v_mismatch_sequence := v_row.sequence_no;
        exit;
      end if;
    end if;

    v_payload := pg_catalog.jsonb_build_object(
      'tenantId', v_row.tenant_id,
      'sequenceNo', v_row.sequence_no,
      'action', v_row.action,
      'actorType', v_row.actor_type,
      'resourceType', v_row.resource_type,
      'resourceId', v_row.resource_id,
      'requestId', v_row.request_id,
      'details', v_row.details,
      'previousHash', v_row.previous_hash,
      'createdAt', v_row.created_at
    );

    v_computed_hash := pg_catalog.encode(
      extensions.digest(
        pg_catalog.convert_to(coalesce(v_row.previous_hash, 'GENESIS') || E'\n' || v_payload::text, 'UTF8'),
        'sha256'
      ),
      'hex'
    );

    if v_computed_hash is distinct from v_row.entry_hash then
      v_valid := false;
      v_mismatch_sequence := v_row.sequence_no;
      exit;
    end if;

    v_checked := v_checked + 1;
    v_previous_sequence := v_row.sequence_no;
    v_previous_hash := v_row.entry_hash;
    v_last_sequence := v_row.sequence_no;
  end loop;

  v_complete := v_total_count <= p_limit and (v_total_count = 0 or v_first_sequence = 1);
  return pg_catalog.jsonb_build_object(
    'valid', v_valid,
    'complete', v_complete,
    'checkedCount', v_checked,
    'totalCount', v_total_count,
    'firstSequence', v_first_sequence,
    'lastSequence', v_last_sequence,
    'mismatchSequence', v_mismatch_sequence
  );
end;
$function$;

revoke all on function security.verify_security_ledger_chain(uuid, integer) from public, anon, authenticated;
grant execute on function security.verify_security_ledger_chain(uuid, integer) to service_role;

commit;
