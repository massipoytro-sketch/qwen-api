-- GainiRen Security Part 2: audit emergency runtime-control changes.
-- Apply only to the dedicated gainiren-shield-lab database.

begin;

create or replace function security.audit_runtime_control_change()
returns trigger
language plpgsql
security definer
set search_path = ''
as $function$
begin
  perform security.append_security_ledger_entry(
    new.tenant_id,
    case when tg_op = 'INSERT' then 'runtime_control_created' else 'runtime_control_changed' end,
    'runtime_control',
    new.tenant_id::text,
    null,
    'operator',
    jsonb_build_object(
      'mode', new.mode,
      'reasonCode', new.reason_code,
      'version', new.version,
      'expiresAt', new.expires_at,
      'updatedBy', new.updated_by
    )
  );
  return new;
end;
$function$;

drop trigger if exists runtime_controls_audit_change on security.runtime_controls;
create trigger runtime_controls_audit_change
after insert or update on security.runtime_controls
for each row execute function security.audit_runtime_control_change();

revoke all on function security.audit_runtime_control_change() from public, anon, authenticated;
revoke all on function security.audit_runtime_control_change() from service_role;

commit;
