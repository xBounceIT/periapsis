-- V32 seals tenant lifecycle suspension as an authorization, RLS, notifier,
-- SLA, audit, and ticket-write boundary. V31 remains the exact rolling
-- predecessor at migration 0149; V30 is retired.
CREATE FUNCTION app.schema_compatibility_v32()
RETURNS TABLE(
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
DECLARE
  journal_count bigint;
  journal_latest_created_at bigint;
  latest_rows bigint;
BEGIN
  EXECUTE $query$
    SELECT count(*)::bigint, max(migration.created_at)::bigint,
           count(*) FILTER (
             WHERE migration.created_at = 1787852085088
           )::bigint
    FROM drizzle.__drizzle_migrations AS migration
  $query$ INTO journal_count, journal_latest_created_at, latest_rows;
  IF journal_count = 155
     AND journal_latest_created_at = 1787852085088
     AND latest_rows = 1 THEN
    RETURN QUERY EXECUTE $query$
      SELECT count(*)::bigint, max(migration.created_at)::bigint,
             (SELECT lower(latest.hash::text)
              FROM drizzle.__drizzle_migrations AS latest
              ORDER BY latest.created_at DESC, latest.id DESC LIMIT 1),
             string_agg(
               migration.created_at::text || '@' || lower(migration.hash::text),
               ':' ORDER BY migration.created_at, migration.id
             )
      FROM drizzle.__drizzle_migrations AS migration
    $query$;
    RETURN;
  END IF;
  RETURN QUERY SELECT 0::bigint, 0::bigint,
                      'UNSUPPORTED'::text, 'UNSUPPORTED'::text;
END;
$function$;
ALTER FUNCTION app.schema_compatibility_v32()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.schema_compatibility_v32()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,
  periapsis_sla_api_owner, periapsis_sla_worker_owner,
  periapsis_sla_readiness_owner, periapsis_ticket_saved_view_owner,
  periapsis_ticket_attribution_owner,
  periapsis_ticket_sla_projection_owner;
GRANT EXECUTE ON FUNCTION app.schema_compatibility_v32()
TO periapsis_api, periapsis_worker;
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.schema_compatibility_v31()
RETURNS TABLE(
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
  full_count bigint;
  full_latest_created_at bigint;
  full_fingerprint text;
BEGIN
  SELECT compatibility.applied_count, compatibility.latest_created_at,
         compatibility.migration_fingerprint
  INTO full_count, full_latest_created_at, full_fingerprint
  FROM app.schema_compatibility_v32() AS compatibility;
  IF full_count = 155
     AND full_latest_created_at = 1787852085088
     AND full_fingerprint = current_setting(
       'app.schema_compatibility_fingerprint', true
     ) THEN
    RETURN QUERY EXECUTE $query$
      WITH ordered_migrations AS (
        SELECT migration.id, migration.created_at,
               lower(migration.hash::text) AS migration_hash,
               row_number() OVER (
                 ORDER BY migration.created_at, migration.id
               ) AS migration_ordinal
        FROM drizzle.__drizzle_migrations AS migration
      )
      SELECT count(*)::bigint, max(migration.created_at)::bigint,
             (SELECT prefix.migration_hash
              FROM ordered_migrations AS prefix
              WHERE prefix.migration_ordinal = 150),
             string_agg(
               migration.created_at::text || '@' || migration.migration_hash,
               ':' ORDER BY migration.created_at, migration.id
             )
      FROM ordered_migrations AS migration
      WHERE migration.migration_ordinal <= 150
    $query$;
    RETURN;
  END IF;
  RETURN QUERY SELECT 0::bigint, 0::bigint,
                      'UNSUPPORTED'::text, 'UNSUPPORTED'::text;
END;
$function$;
ALTER FUNCTION app.schema_compatibility_v31()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.schema_compatibility_v31()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,
  periapsis_sla_api_owner, periapsis_sla_worker_owner,
  periapsis_sla_readiness_owner, periapsis_ticket_saved_view_owner,
  periapsis_ticket_attribution_owner,
  periapsis_ticket_sla_projection_owner;
GRANT EXECUTE ON FUNCTION app.schema_compatibility_v31()
TO periapsis_api, periapsis_worker;
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.schema_compatibility_v30()
RETURNS TABLE(
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
  RETURN QUERY SELECT 0::bigint, 0::bigint,
                      'UNSUPPORTED'::text, 'UNSUPPORTED'::text;
END;
$function$;
ALTER FUNCTION app.schema_compatibility_v30()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.schema_compatibility_v30()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,
  periapsis_sla_api_owner, periapsis_sla_worker_owner,
  periapsis_sla_readiness_owner, periapsis_ticket_saved_view_owner,
  periapsis_ticket_attribution_owner,
  periapsis_ticket_sla_projection_owner;
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.seal_schema_compatibility_manifest(
  p_expected_count bigint,
  p_expected_latest_created_at bigint,
  p_expected_latest_hash text,
  p_expected_migration_fingerprint text
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, app
AS $function$
DECLARE
  fingerprint_entries text[];
  appended_created_at bigint[];
  actual_count bigint;
  actual_latest_created_at bigint;
  actual_latest_hash text;
  actual_fingerprint text;
  predecessor_count bigint;
  predecessor_latest_created_at bigint;
  predecessor_latest_hash text;
  predecessor_fingerprint text;
  expected_predecessor_fingerprint text;
  retired_count bigint;
BEGIN
  fingerprint_entries := string_to_array(
    p_expected_migration_fingerprint, ':'
  );
  IF p_expected_count IS DISTINCT FROM 155
     OR p_expected_latest_created_at IS DISTINCT FROM 1787852085088
     OR p_expected_latest_hash IS NULL
     OR p_expected_latest_hash !~ '^[0-9a-f]{64}$'
     OR p_expected_migration_fingerprint IS NULL
     OR p_expected_migration_fingerprint !~
          '^[1-9][0-9]*@[0-9a-f]{64}(:[1-9][0-9]*@[0-9a-f]{64})*$'
     OR cardinality(fingerprint_entries) IS DISTINCT FROM 155
     OR fingerprint_entries[155] IS DISTINCT FROM (
       p_expected_latest_created_at::text || '@' || p_expected_latest_hash
     ) THEN
    RAISE EXCEPTION 'invalid schema compatibility v32 manifest'
      USING ERRCODE = '22023';
  END IF;
  SELECT array_agg(
    split_part(entry.value, '@', 1)::bigint ORDER BY entry.ordinality
  ) INTO appended_created_at
  FROM unnest(fingerprint_entries[151:155]) WITH ORDINALITY
       AS entry(value, ordinality);
  IF appended_created_at IS DISTINCT FROM ARRAY[
       1787758674256, 1787758694313, 1787759373746,
       1787852011539, 1787852085088
     ]::bigint[] THEN
    RAISE EXCEPTION 'invalid schema compatibility v32 appended sequence'
      USING ERRCODE = '22023';
  END IF;

  SELECT compatibility.applied_count, compatibility.latest_created_at,
         compatibility.latest_hash, compatibility.migration_fingerprint
  INTO actual_count, actual_latest_created_at, actual_latest_hash,
       actual_fingerprint
  FROM app.schema_compatibility_v32() AS compatibility;
  IF actual_count IS DISTINCT FROM p_expected_count
     OR actual_latest_created_at IS DISTINCT FROM p_expected_latest_created_at
     OR actual_latest_hash IS DISTINCT FROM p_expected_latest_hash
     OR actual_fingerprint IS DISTINCT FROM p_expected_migration_fingerprint THEN
    RAISE EXCEPTION 'schema compatibility v32 manifest does not match the journal'
      USING ERRCODE = '55000';
  END IF;

  PERFORM set_config(
    'app.schema_compatibility_fingerprint',
    p_expected_migration_fingerprint, true
  );
  EXECUTE $statement$
    ALTER FUNCTION app.schema_compatibility_v31()
      SET app.schema_compatibility_fingerprint FROM CURRENT
  $statement$;
  expected_predecessor_fingerprint := array_to_string(
    fingerprint_entries[1:150], ':'
  );
  SELECT compatibility.applied_count, compatibility.latest_created_at,
         compatibility.latest_hash, compatibility.migration_fingerprint
  INTO predecessor_count, predecessor_latest_created_at,
       predecessor_latest_hash, predecessor_fingerprint
  FROM app.schema_compatibility_v31() AS compatibility;
  IF predecessor_count IS DISTINCT FROM 150
     OR predecessor_latest_created_at IS DISTINCT FROM 1787756689913
     OR predecessor_latest_hash IS DISTINCT FROM
          '0f5a388806ac70eb58aa11782575b57ff66bc650df981b36fd3a065dfa713c6a'
     OR predecessor_fingerprint IS DISTINCT FROM
          expected_predecessor_fingerprint THEN
    RAISE EXCEPTION 'sealed schema compatibility v31 prefix is not exact'
      USING ERRCODE = '55000';
  END IF;

  SELECT compatibility.applied_count INTO retired_count
  FROM app.schema_compatibility_v30() AS compatibility;
  IF retired_count IS DISTINCT FROM 0
     OR NOT app.platform_tenant_lifecycle_schema_readiness_v1()
     OR NOT has_function_privilege(
       'periapsis_api', 'app.schema_compatibility_v32()'::regprocedure,
       'EXECUTE'
     )
     OR NOT has_function_privilege(
       'periapsis_worker', 'app.schema_compatibility_v32()'::regprocedure,
       'EXECUTE'
     )
     OR NOT has_function_privilege(
       'periapsis_api', 'app.schema_compatibility_v31()'::regprocedure,
       'EXECUTE'
     )
     OR NOT has_function_privilege(
       'periapsis_worker', 'app.schema_compatibility_v31()'::regprocedure,
       'EXECUTE'
     )
     OR has_function_privilege(
       'periapsis_api', 'app.schema_compatibility_v30()'::regprocedure,
       'EXECUTE'
     )
     OR has_function_privilege(
       'periapsis_worker', 'app.schema_compatibility_v30()'::regprocedure,
       'EXECUTE'
     ) THEN
    RAISE EXCEPTION 'schema compatibility v30 remains active or lifecycle readiness failed'
      USING ERRCODE = '55000';
  END IF;
END;
$function$;
ALTER FUNCTION app.seal_schema_compatibility_manifest(
  bigint, bigint, text, text
) OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.seal_schema_compatibility_manifest(
  bigint, bigint, text, text
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,
  periapsis_sla_api_owner, periapsis_sla_worker_owner,
  periapsis_sla_readiness_owner, periapsis_ticket_saved_view_owner,
  periapsis_ticket_attribution_owner,
  periapsis_ticket_sla_projection_owner;
--> statement-breakpoint

-- Advance every published readiness surface in lockstep with the rolling
-- compatibility window. Their semantic checks are preserved byte-for-byte.
DO $migration$
DECLARE
  readiness_function regprocedure;
  original_definition text;
  rewritten_definition text;
BEGIN
  FOREACH readiness_function IN ARRAY ARRAY[
    'app.federated_authentication_schema_readiness_v1()'::regprocedure,
    'app.identity_mfa_device_management_readiness_v1()'::regprocedure,
    'app.identity_mfa_schema_readiness_v1()'::regprocedure,
    'app.private_sla_schema_readiness_core_v1()'::regprocedure,
    'app.ticket_saved_views_schema_readiness_v1()'::regprocedure,
    'app.ticket_query_projections_readiness_v1()'::regprocedure
  ] LOOP
    SELECT pg_get_functiondef(readiness_function)
    INTO STRICT original_definition;
    IF original_definition NOT LIKE '%app.schema_compatibility_v31()%'
       OR original_definition NOT LIKE '%app.schema_compatibility_v30()%'
       OR original_definition NOT LIKE '%app.schema_compatibility_v29()%'
       OR original_definition NOT LIKE
            '%current_count = 150 AND predecessor_count = 142%' THEN
      RAISE EXCEPTION 'unexpected v31 readiness definition: %',
        readiness_function::text USING ERRCODE = '55000';
    END IF;
    rewritten_definition := replace(
      original_definition,
      'app.schema_compatibility_v31()',
      'app.schema_compatibility_v32()'
    );
    rewritten_definition := replace(
      rewritten_definition,
      'app.schema_compatibility_v30()',
      'app.schema_compatibility_v31()'
    );
    rewritten_definition := replace(
      rewritten_definition,
      'app.schema_compatibility_v29()',
      'app.schema_compatibility_v30()'
    );
    rewritten_definition := replace(
      rewritten_definition,
      'current_count = 150 AND predecessor_count = 142',
      'current_count = 155 AND predecessor_count = 150'
    );
    IF rewritten_definition IS NOT DISTINCT FROM original_definition
       OR rewritten_definition NOT LIKE '%app.schema_compatibility_v32()%'
       OR rewritten_definition LIKE '%app.schema_compatibility_v29()%'
       OR rewritten_definition NOT LIKE
            '%current_count = 155 AND predecessor_count = 150%' THEN
      RAISE EXCEPTION 'failed to rebind v32 readiness definition: %',
        readiness_function::text USING ERRCODE = '55000';
    END IF;
    EXECUTE rewritten_definition;
  END LOOP;
END;
$migration$;
