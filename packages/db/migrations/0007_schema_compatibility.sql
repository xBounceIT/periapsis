-- Drizzle owns this journal outside the application schema. Runtime roles receive only a
-- narrow compatibility projection, never direct access to migration SQL hashes/history.
DO $grant$
BEGIN
  EXECUTE 'GRANT USAGE ON SCHEMA "drizzle" TO "periapsis_migrator"';
  EXECUTE 'GRANT SELECT ON TABLE "drizzle"."__drizzle_migrations" TO "periapsis_migrator"';
END
$grant$;--> statement-breakpoint

CREATE FUNCTION "app"."schema_compatibility"()
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
        lower(migration.hash::text),
        ':' ORDER BY migration.created_at, migration.id
      ) AS migration_fingerprint
    FROM drizzle.__drizzle_migrations AS migration
  $query$;
END;
$function$;--> statement-breakpoint

ALTER FUNCTION "app"."schema_compatibility"() OWNER TO "periapsis_migrator";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."schema_compatibility"() FROM PUBLIC;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."schema_compatibility"() TO "periapsis_api", "periapsis_worker";
