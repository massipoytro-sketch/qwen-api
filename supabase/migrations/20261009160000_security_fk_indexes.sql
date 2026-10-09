-- Add indexes for security-schema foreign keys that lack a leading-column index.
-- This is limited to the security schema; legacy schemas are intentionally untouched.
do $$
declare
  fk record;
  col_names text;
  index_name text;
  already_covered boolean;
begin
  for fk in
    select c.oid, c.conrelid, c.conname, c.conkey
    from pg_constraint c
    join pg_namespace n on n.oid = c.connamespace
    where c.contype = 'f' and n.nspname = 'security'
  loop
    select exists (
      select 1
      from pg_index i
      where i.indrelid = fk.conrelid
        and i.indisvalid
        and i.indisready
        and i.indnkeyatts >= array_length(fk.conkey, 1)
        and (
          select array_agg((i.indkey::smallint[])[g.idx] order by g.idx)
          from generate_series(0, array_length(fk.conkey, 1) - 1) as g(idx)
        ) = fk.conkey
    ) into already_covered;

    if not already_covered then
      select string_agg(format('%I', a.attname), ', ' order by k.ord)
        into col_names
      from unnest(fk.conkey) with ordinality k(attnum, ord)
      join pg_attribute a on a.attrelid = fk.conrelid and a.attnum = k.attnum;

      index_name := left(
        'idx_' || replace(fk.conrelid::regclass::text, '.', '_') || '_' ||
        replace(replace(col_names, ', ', '_'), '"', ''),
        63
      );

      execute format(
        'create index if not exists %I on %s (%s)',
        index_name, fk.conrelid::regclass, col_names
      );
    end if;
  end loop;
end $$;
