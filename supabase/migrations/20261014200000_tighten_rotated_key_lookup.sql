begin;
create or replace function security.consume_rotated_api_key(p_key_hash text, p_key_id uuid default null, p_tenant_id uuid default null)
returns table(tenant_id uuid, key_id uuid)
language plpgsql security invoker set search_path=''
as $function$
begin
  if p_key_hash is null or p_key_hash !~ '^[0-9a-f]{64}$' then return; end if;
  return query
  update security.tenant_api_keys k
     set last_used_at=pg_catalog.clock_timestamp()
   where k.key_hash=p_key_hash
     and (p_key_id is null or k.key_id=p_key_id)
     and (p_tenant_id is null or k.tenant_id=p_tenant_id)
     and k.status='active'
     and (k.expires_at is null or k.expires_at>pg_catalog.clock_timestamp())
   returning k.tenant_id,k.key_id;
end;
$function$;
revoke all on function security.consume_rotated_api_key(text) from public, anon, authenticated;
revoke all on function security.consume_rotated_api_key(text,uuid,uuid) from public, anon, authenticated;
grant execute on function security.consume_rotated_api_key(text,uuid,uuid) to service_role;
commit;
