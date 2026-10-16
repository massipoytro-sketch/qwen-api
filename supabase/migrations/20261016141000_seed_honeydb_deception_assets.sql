-- Seed only synthetic HoneyDB canary locator keys for the dedicated internal sensor tenant.
-- No real credentials, IPs, paths with query strings, or production database content are stored.

begin;

insert into security.deception_assets (
  tenant_id, asset_type, asset_name, locator_hash, status, metadata
)
select
  t.id,
  a.asset_type,
  a.asset_name,
  pg_catalog.encode(
    extensions.digest(
      pg_catalog.convert_to('GAINIREN-DECEPTION-LOCATOR-V1' || E'\n' || a.locator, 'UTF8'),
      'sha256'
    ),
    'hex'
  ),
  'active',
  pg_catalog.jsonb_build_object(
    'tags', pg_catalog.jsonb_build_array('synthetic', 'honeydb', 'seeded'),
    'seedVersion', 'part5-v1'
  )
from security.tenants t
cross join (values
  ('route'::text, 'HoneyDB admin panel', 'honeydb:admin:admin_panel'),
  ('route'::text, 'HoneyDB admin login', 'honeydb:admin:admin_login'),
  ('route'::text, 'HoneyDB admin users API', 'honeydb:api_probe:admin_users_api'),
  ('route'::text, 'HoneyDB versioned users API', 'honeydb:api_probe:versioned_users_api'),
  ('route'::text, 'HoneyDB GraphQL tripwire', 'honeydb:api_probe:graphql_probe'),
  ('credential_canary'::text, 'HoneyDB environment-file canary', 'honeydb:environment:env_file'),
  ('document_canary'::text, 'HoneyDB synthetic Git config', 'honeydb:environment:git_config'),
  ('credential_canary'::text, 'HoneyDB cloud credential canary', 'honeydb:environment:cloud_credentials'),
  ('credential_canary'::text, 'HoneyDB debug environment canary', 'honeydb:debug:debug_environment'),
  ('credential_canary'::text, 'HoneyDB internal config canary', 'honeydb:debug:internal_config'),
  ('credential_canary'::text, 'HoneyDB actuator environment canary', 'honeydb:debug:actuator_environment'),
  ('database_canary'::text, 'HoneyDB synthetic database backup', 'honeydb:backup:database_backup'),
  ('database_canary'::text, 'HoneyDB synthetic database probe', 'honeydb:backup:database_probe'),
  ('database_canary'::text, 'HoneyDB synthetic user export', 'honeydb:backup:user_export')
) as a(asset_type, asset_name, locator)
where t.id = '77777777-7777-4777-8777-777777777777'::uuid
  and t.external_key = 'gainiren-honeydb-internal'
  and t.status = 'active'
on conflict (tenant_id, locator_hash) do nothing;

commit;
