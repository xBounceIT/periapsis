-- Rotate current readiness to a new projection before preserving the immediately
-- preceding manifest. Current replicas validate the complete real journal through
-- schema_compatibility_v3(), whose ordered fingerprint binds each timestamp and SQL hash.
CREATE FUNCTION "app"."schema_compatibility_v3"()
RETURNS TABLE (
  applied_count bigint,
  latest_created_at bigint,
  latest_hash text,
  migration_fingerprint text
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
BEGIN
  RETURN QUERY EXECUTE $query$
    SELECT
      count(*)::bigint AS applied_count,
      max(created_at)::bigint AS latest_created_at,
      (
        SELECT lower(migration.hash::text)
        FROM drizzle.__drizzle_migrations AS migration
        ORDER BY migration.created_at DESC, migration.id DESC
        LIMIT 1
      ) AS latest_hash,
      string_agg(
        migration.created_at::text || '@' || lower(migration.hash::text),
        ':' ORDER BY migration.created_at, migration.id
      ) AS migration_fingerprint
    FROM drizzle.__drizzle_migrations AS migration
  $query$;
END;
$function$;--> statement-breakpoint

ALTER FUNCTION "app"."schema_compatibility_v3"() OWNER TO "periapsis_migrator";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."schema_compatibility_v3"() FROM PUBLIC;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."schema_compatibility_v3"() TO "periapsis_api", "periapsis_worker";--> statement-breakpoint

-- The v2 projection is now an exact sealed 26 -> 27 compatibility edge. It exposes
-- the verified 0000-0025 prefix only while the full real journal is the trusted
-- 0000-0026 manifest sealed by the canonical runner. An unsealed, truncated, drifted,
-- or additional journal receives an impossible sentinel rather than a real prefix.
CREATE OR REPLACE FUNCTION "app"."schema_compatibility_v2"()
RETURNS TABLE (
  applied_count bigint,
  latest_created_at bigint,
  latest_hash text,
  migration_fingerprint text
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
SET app.schema_compatibility_fingerprint = 'UNSEALED'
AS $function$
DECLARE
  journal_count bigint;
  journal_latest_created_at bigint;
  journal_fingerprint text;
  migration_0026_rows bigint;
BEGIN
  SELECT compatibility.applied_count,
         compatibility.latest_created_at,
         compatibility.migration_fingerprint
  INTO journal_count, journal_latest_created_at, journal_fingerprint
  FROM app.schema_compatibility_v3() AS compatibility;

  EXECUTE $query$
    SELECT count(*)::bigint
    FROM drizzle.__drizzle_migrations AS migration
    WHERE migration.created_at = 1787571776845
  $query$
  INTO migration_0026_rows;

  IF journal_count = 27
     AND journal_latest_created_at = 1787571776845
     AND migration_0026_rows = 1
     AND journal_fingerprint = current_setting(
       'app.schema_compatibility_fingerprint',
       true
     ) THEN
    RETURN QUERY EXECUTE $query$
      WITH ordered_migrations AS (
        SELECT
          migration.id,
          migration.created_at,
          lower(migration.hash::text) AS migration_hash,
          row_number() OVER (
            ORDER BY migration.created_at, migration.id
          ) AS migration_ordinal
        FROM drizzle.__drizzle_migrations AS migration
      )
      SELECT
        count(*)::bigint AS applied_count,
        max(migration.created_at)::bigint AS latest_created_at,
        (
          SELECT latest_prefix_migration.migration_hash
          FROM ordered_migrations AS latest_prefix_migration
          WHERE latest_prefix_migration.migration_ordinal = 26
        ) AS latest_hash,
        string_agg(
          migration.migration_hash,
          ':' ORDER BY migration.created_at, migration.id
        ) AS migration_fingerprint
      FROM ordered_migrations AS migration
      WHERE migration.migration_ordinal <= 26
    $query$;
    RETURN;
  END IF;

  RETURN QUERY
  SELECT 0::bigint,
         0::bigint,
         'UNSUPPORTED'::text,
         'UNSUPPORTED'::text;
END;
$function$;--> statement-breakpoint

ALTER FUNCTION "app"."schema_compatibility_v2"() OWNER TO "periapsis_migrator";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."schema_compatibility_v2"() FROM PUBLIC;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."schema_compatibility_v2"() TO "periapsis_api", "periapsis_worker";--> statement-breakpoint

-- Migration 0025 is immutable, so retire its legacy compatibility projection
-- with a forward replacement. No released manifest can contain zero migrations,
-- a zero timestamp, or these non-hash markers. Returning a normal row keeps old
-- readiness probes quiet while ensuring that they fail every exact comparison.
CREATE OR REPLACE FUNCTION "app"."schema_compatibility"()
RETURNS TABLE (
  applied_count bigint,
  latest_created_at bigint,
  latest_hash text,
  migration_fingerprint text
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
BEGIN
  RETURN QUERY
  SELECT 0::bigint,
         0::bigint,
         'UNSUPPORTED'::text,
         'UNSUPPORTED'::text;
END;
$function$;--> statement-breakpoint

ALTER FUNCTION "app"."schema_compatibility"() OWNER TO "periapsis_migrator";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."schema_compatibility"() FROM PUBLIC;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."schema_compatibility"() TO "periapsis_api", "periapsis_worker";--> statement-breakpoint

-- Seal the v2 predecessor projection only after the canonical runner has verified
-- the complete current journal against its repository-owned timestamp@hash manifest.
CREATE OR REPLACE FUNCTION "app"."seal_schema_compatibility_manifest"(
  p_expected_count bigint,
  p_expected_latest_created_at bigint,
  p_expected_latest_hash text,
  p_expected_migration_fingerprint text
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
  actual_count bigint;
  actual_latest_created_at bigint;
  actual_latest_hash text;
  actual_migration_fingerprint text;
  fingerprint_entries text[];
BEGIN
  fingerprint_entries := string_to_array(
    p_expected_migration_fingerprint,
    ':'
  );
  IF p_expected_count IS NULL
     OR p_expected_count NOT BETWEEN 1 AND 2147483647
     OR p_expected_latest_created_at IS NULL
     OR p_expected_latest_created_at <= 0
     OR p_expected_latest_hash IS NULL
     OR p_expected_latest_hash !~ '^[0-9a-f]{64}$'
     OR p_expected_migration_fingerprint IS NULL
     OR p_expected_migration_fingerprint !~ '^[1-9][0-9]*@[0-9a-f]{64}(:[1-9][0-9]*@[0-9a-f]{64})*$'
     OR cardinality(fingerprint_entries) IS DISTINCT FROM p_expected_count::integer
     OR fingerprint_entries[cardinality(fingerprint_entries)] IS DISTINCT FROM (
          p_expected_latest_created_at::text || '@' || p_expected_latest_hash
        ) THEN
    RAISE EXCEPTION 'invalid schema compatibility manifest'
      USING ERRCODE = '22023';
  END IF;

  SELECT compatibility.applied_count,
         compatibility.latest_created_at,
         compatibility.latest_hash,
         compatibility.migration_fingerprint
  INTO actual_count,
       actual_latest_created_at,
       actual_latest_hash,
       actual_migration_fingerprint
  FROM app.schema_compatibility_v3() AS compatibility;

  IF actual_count IS DISTINCT FROM p_expected_count
     OR actual_latest_created_at IS DISTINCT FROM p_expected_latest_created_at
     OR actual_latest_hash IS DISTINCT FROM p_expected_latest_hash
     OR actual_migration_fingerprint IS DISTINCT FROM p_expected_migration_fingerprint THEN
    RAISE EXCEPTION 'schema compatibility manifest does not match the applied migration journal'
      USING ERRCODE = '55000';
  END IF;

  PERFORM set_config(
    'app.schema_compatibility_fingerprint',
    p_expected_migration_fingerprint,
    true
  );
  EXECUTE $statement$
    ALTER FUNCTION app.schema_compatibility_v2()
      SET app.schema_compatibility_fingerprint FROM CURRENT
  $statement$;
END;
$function$;--> statement-breakpoint

ALTER FUNCTION "app"."seal_schema_compatibility_manifest"(bigint, bigint, text, text) OWNER TO "periapsis_migrator";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."seal_schema_compatibility_manifest"(bigint, bigint, text, text) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";
