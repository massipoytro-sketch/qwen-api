-- Store approximate GeoIP coordinates only when the tenant supplies a trusted source.
-- These fields support coarse impossible-travel detection and must never contain GPS/client coordinates.
ALTER TABLE security.ip_addresses
  ADD COLUMN IF NOT EXISTS latitude double precision,
  ADD COLUMN IF NOT EXISTS longitude double precision,
  ADD COLUMN IF NOT EXISTS location_source text;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'ip_addresses_latitude_range_check' AND conrelid = 'security.ip_addresses'::regclass) THEN
    ALTER TABLE security.ip_addresses ADD CONSTRAINT ip_addresses_latitude_range_check
      CHECK (latitude IS NULL OR latitude BETWEEN -90 AND 90);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'ip_addresses_longitude_range_check' AND conrelid = 'security.ip_addresses'::regclass) THEN
    ALTER TABLE security.ip_addresses ADD CONSTRAINT ip_addresses_longitude_range_check
      CHECK (longitude IS NULL OR longitude BETWEEN -180 AND 180);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'ip_addresses_location_pair_check' AND conrelid = 'security.ip_addresses'::regclass) THEN
    ALTER TABLE security.ip_addresses ADD CONSTRAINT ip_addresses_location_pair_check
      CHECK ((latitude IS NULL) = (longitude IS NULL));
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'ip_addresses_location_source_check' AND conrelid = 'security.ip_addresses'::regclass) THEN
    ALTER TABLE security.ip_addresses ADD CONSTRAINT ip_addresses_location_source_check
      CHECK (location_source IS NULL OR location_source IN ('trusted_geoip', 'tenant_server'));
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'ip_addresses_location_source_requires_coords_check' AND conrelid = 'security.ip_addresses'::regclass) THEN
    ALTER TABLE security.ip_addresses ADD CONSTRAINT ip_addresses_location_source_requires_coords_check
      CHECK (location_source IS NULL OR (latitude IS NOT NULL AND longitude IS NOT NULL));
  END IF;
END
$$;
