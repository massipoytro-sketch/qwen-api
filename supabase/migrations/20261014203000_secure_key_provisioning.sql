begin;
create or replace function security.provision_rotated_api_key(p_tenant_id uuid,p_key_hash text,p_label text default 'rotated-key',p_expires_at timestamptz default null)
returns table(key_id uuid,tenant_id uuid,label text,expires_at timestamptz)
language plpgsql security definer set search_path=''
as $function$
begin
  if p_key_hash is null or p_key_hash !~ '^[0-9a-f]{64}$' then raise exception 'INVALID_API_KEY_HASH' using errcode='22023'; end if;
  if p_label is null or char_length(p_label) not between 1 and 100 then raise exception 'INVALID_API_KEY_LABEL' using errcode='22023'; end if;
  if not exists(select 1 from security.tenants t where t.id=p_tenant_id and t.status='active') then raise exception 'TENANT_NOT_ACTIVE' using errcode='42501'; end if;
  return query insert into security.tenant_api_keys(tenant_id,key_hash,label,expires_at) values(p_tenant_id,p_key_hash,p_label,p_expires_at) returning key_id,tenant_id,label,expires_at;
end;
$function$;
revoke all on function security.provision_rotated_api_key(uuid,text,text,timestamptz) from public,anon,authenticated;
grant execute on function security.provision_rotated_api_key(uuid,text,text,timestamptz) to service_role;
commit;
