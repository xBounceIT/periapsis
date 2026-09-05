-- Rotate the current readiness projection for Phase 2B.2b. New replicas bind
-- the complete timestamp@hash journal through v4. Replicas from the immediately
-- supported 2B.2a application release continue to call v3 and receive their
-- exact 27-row manifest only after the canonical runner has sealed this full
-- 30-row journal. Drift, truncation, an unsealed migration, or any extra row is
-- represented by an impossible sentinel rather than a plausible prefix.
CREATE FUNCTION "app"."schema_compatibility_v4"()
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

ALTER FUNCTION "app"."schema_compatibility_v4"() OWNER TO "periapsis_migrator";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."schema_compatibility_v4"() FROM PUBLIC;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."schema_compatibility_v4"() TO "periapsis_api", "periapsis_worker";--> statement-breakpoint

CREATE OR REPLACE FUNCTION "app"."schema_compatibility_v3"()
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
  migration_0029_rows bigint;
BEGIN
  SELECT compatibility.applied_count,
         compatibility.latest_created_at,
         compatibility.migration_fingerprint
  INTO journal_count, journal_latest_created_at, journal_fingerprint
  FROM app.schema_compatibility_v4() AS compatibility;

  EXECUTE $query$
    SELECT count(*)::bigint
    FROM drizzle.__drizzle_migrations AS migration
    WHERE migration.created_at = 1787582150087
  $query$
  INTO migration_0029_rows;

  IF journal_count = 30
     AND journal_latest_created_at = 1787582150087
     AND migration_0029_rows = 1
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
          WHERE latest_prefix_migration.migration_ordinal = 27
        ) AS latest_hash,
        string_agg(
          migration.created_at::text || '@' || migration.migration_hash,
          ':' ORDER BY migration.created_at, migration.id
        ) AS migration_fingerprint
      FROM ordered_migrations AS migration
      WHERE migration.migration_ordinal <= 27
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

ALTER FUNCTION "app"."schema_compatibility_v3"() OWNER TO "periapsis_migrator";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."schema_compatibility_v3"() FROM PUBLIC;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."schema_compatibility_v3"() TO "periapsis_api", "periapsis_worker";--> statement-breakpoint

-- Retire the two-release-old v2 probe explicitly. Keeping the function callable
-- lets old replicas fail their exact readiness comparison without noisy SQL
-- errors, while preventing a 0025 binary from remaining ready after this
-- release has crossed the only supported rolling edge.
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
AS $function$
BEGIN
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
  FROM app.schema_compatibility_v4() AS compatibility;

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
    ALTER FUNCTION app.schema_compatibility_v3()
      SET app.schema_compatibility_fingerprint FROM CURRENT
  $statement$;
END;
$function$;--> statement-breakpoint

ALTER FUNCTION "app"."seal_schema_compatibility_manifest"(bigint, bigint, text, text) OWNER TO "periapsis_migrator";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."seal_schema_compatibility_manifest"(bigint, bigint, text, text) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";
