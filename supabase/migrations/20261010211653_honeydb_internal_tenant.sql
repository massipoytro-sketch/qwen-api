-- Dedicated tenant for isolated HoneyDB sensor events.
-- No tenant API key is assigned: the internal sensor route uses its separate shared token.
insert into security.tenants (id, external_key, name, status, api_key_hash)
values (
  '77777777-7777-4777-8777-777777777777'::uuid,
  'gainiren-honeydb-internal',
  'GainiRen HoneyDB Internal Sensor',
  'active',
  null
)
on conflict (id) do nothing;
