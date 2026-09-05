CREATE FUNCTION app.schema_compatibility_v12()
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
DECLARE
  journal_count bigint;
  journal_latest_created_at bigint;
  migration_0079_rows bigint;
BEGIN
  EXECUTE $query$
    SELECT count(*)::bigint, max(migration.created_at)::bigint,
           count(*) FILTER (
             WHERE migration.created_at = 1787658434202
           )::bigint
    FROM drizzle.__drizzle_migrations AS migration
  $query$ INTO journal_count, journal_latest_created_at, migration_0079_rows;
  IF journal_count = 80
     AND journal_latest_created_at = 1787658434202
     AND migration_0079_rows = 1 THEN
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
$function$;--> statement-breakpoint

ALTER FUNCTION app.schema_compatibility_v12() OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.schema_compatibility_v12()
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.schema_compatibility_v12()
  TO periapsis_api, periapsis_worker;--> statement-breakpoint

-- v11 is the sole supported predecessor and only projects its sealed prefix
-- when the complete v12 journal is exact.
CREATE OR REPLACE FUNCTION app.schema_compatibility_v11()
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
  full_count bigint;
  full_latest_created_at bigint;
  full_fingerprint text;
BEGIN
  SELECT compatibility.applied_count, compatibility.latest_created_at,
         compatibility.migration_fingerprint
  INTO full_count, full_latest_created_at, full_fingerprint
  FROM app.schema_compatibility_v12() AS compatibility;
  IF full_count = 80
     AND full_latest_created_at = 1787658434202
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
              WHERE prefix.migration_ordinal = 76),
             string_agg(
               migration.created_at::text || '@' || migration.migration_hash,
               ':' ORDER BY migration.created_at, migration.id
             )
      FROM ordered_migrations AS migration
      WHERE migration.migration_ordinal <= 76
    $query$;
    RETURN;
  END IF;
  RETURN QUERY SELECT 0::bigint, 0::bigint,
                      'UNSUPPORTED'::text, 'UNSUPPORTED'::text;
END;
$function$;--> statement-breakpoint

ALTER FUNCTION app.schema_compatibility_v11() OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.schema_compatibility_v11()
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.schema_compatibility_v11()
  TO periapsis_api, periapsis_worker;--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.schema_compatibility_v10()
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
  RETURN QUERY SELECT 0::bigint, 0::bigint,
                      'UNSUPPORTED'::text, 'UNSUPPORTED'::text;
END;
$function$;--> statement-breakpoint

ALTER FUNCTION app.schema_compatibility_v10() OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.schema_compatibility_v10()
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.schema_compatibility_v10()
  TO periapsis_api, periapsis_worker;--> statement-breakpoint

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
SET search_path = pg_catalog
AS $function$
DECLARE
  fingerprint_entries text[];
  fingerprint_created_at bigint[];
  actual_count bigint;
  actual_latest_created_at bigint;
  actual_latest_hash text;
  actual_fingerprint text;
  predecessor_count bigint;
  predecessor_latest_created_at bigint;
  predecessor_latest_hash text;
  predecessor_fingerprint text;
  expected_predecessor_hash text;
  expected_predecessor_fingerprint text;
  retired_count bigint;
BEGIN
  fingerprint_entries := string_to_array(
    p_expected_migration_fingerprint, ':'
  );
  IF p_expected_count IS DISTINCT FROM 80
     OR p_expected_latest_created_at IS DISTINCT FROM 1787658434202
     OR p_expected_latest_hash IS NULL
     OR p_expected_latest_hash !~ '^[0-9a-f]{64}$'
     OR p_expected_migration_fingerprint IS NULL
     OR p_expected_migration_fingerprint !~
          '^[1-9][0-9]*@[0-9a-f]{64}(:[1-9][0-9]*@[0-9a-f]{64})*$'
     OR cardinality(fingerprint_entries) IS DISTINCT FROM 80
     OR fingerprint_entries[80] IS DISTINCT FROM (
       p_expected_latest_created_at::text || '@' || p_expected_latest_hash
     ) THEN
    RAISE EXCEPTION 'invalid schema compatibility v12 manifest'
      USING ERRCODE = '22023';
  END IF;

  SELECT array_agg(
    split_part(entry.value, '@', 1)::bigint ORDER BY entry.ordinality
  ) INTO fingerprint_created_at
  FROM unnest(fingerprint_entries) WITH ORDINALITY
       AS entry(value, ordinality);
  IF fingerprint_created_at IS DISTINCT FROM ARRAY[
    1787472409685, 1787472415216, 1787473527702, 1787473536723,
    1787474082034, 1787474089267, 1787475027656, 1787475184077,
    1787488565252, 1787488569966, 1787492910536, 1787493031146,
    1787494284382, 1787495115125, 1787495293635, 1787495819997,
    1787495999394, 1787496124539, 1787496880587, 1787496982733,
    1787496987011, 1787501702276, 1787506296280, 1787507888755,
    1787508523197, 1787516694668, 1787571776845, 1787581350373,
    1787581530382, 1787582150087, 1787591930962, 1787591938733,
    1787592230466, 1787612620574, 1787613580320, 1787613592459,
    1787613744526, 1787613746038, 1787613747552, 1787613749000,
    1787635396524, 1787635417084, 1787635433516, 1787635452090,
    1787635459707, 1787635471570, 1787635525474, 1787635788324,
    1787635828723, 1787637794128, 1787637795761, 1787643146844,
    1787643153628, 1787643609827, 1787648180127, 1787648190820,
    1787648201836, 1787648215689, 1787648225321, 1787649465766,
    1787649478666, 1787649523649, 1787649541586, 1787650610199,
    1787650730983, 1787653130160, 1787653143051, 1787653149806,
    1787653151267, 1787653305313, 1787655186569, 1787655192148,
    1787655197869, 1787655813403, 1787655819028, 1787655824109,
    1787657661213, 1787657666680, 1787658281433, 1787658434202
  ]::bigint[] THEN
    RAISE EXCEPTION 'invalid schema compatibility v12 timestamp sequence'
      USING ERRCODE = '22023';
  END IF;

  SELECT compatibility.applied_count, compatibility.latest_created_at,
         compatibility.latest_hash, compatibility.migration_fingerprint
  INTO actual_count, actual_latest_created_at, actual_latest_hash,
       actual_fingerprint
  FROM app.schema_compatibility_v12() AS compatibility;
  IF actual_count IS DISTINCT FROM p_expected_count
     OR actual_latest_created_at IS DISTINCT FROM p_expected_latest_created_at
     OR actual_latest_hash IS DISTINCT FROM p_expected_latest_hash
     OR actual_fingerprint IS DISTINCT FROM p_expected_migration_fingerprint THEN
    RAISE EXCEPTION 'schema compatibility v12 manifest does not match the applied journal'
      USING ERRCODE = '55000';
  END IF;

  PERFORM set_config(
    'app.schema_compatibility_fingerprint',
    p_expected_migration_fingerprint, true
  );
  EXECUTE $statement$
    ALTER FUNCTION app.schema_compatibility_v11()
      SET app.schema_compatibility_fingerprint FROM CURRENT
  $statement$;
  expected_predecessor_hash := split_part(fingerprint_entries[76], '@', 2);
  expected_predecessor_fingerprint := array_to_string(
    fingerprint_entries[1:76], ':'
  );
  SELECT compatibility.applied_count, compatibility.latest_created_at,
         compatibility.latest_hash, compatibility.migration_fingerprint
  INTO predecessor_count, predecessor_latest_created_at,
       predecessor_latest_hash, predecessor_fingerprint
  FROM app.schema_compatibility_v11() AS compatibility;
  IF predecessor_count IS DISTINCT FROM 76
     OR predecessor_latest_created_at IS DISTINCT FROM 1787655824109
     OR predecessor_latest_hash IS DISTINCT FROM expected_predecessor_hash
     OR predecessor_fingerprint IS DISTINCT FROM expected_predecessor_fingerprint THEN
    RAISE EXCEPTION 'sealed schema compatibility v11 prefix is not exact'
      USING ERRCODE = '55000';
  END IF;
  SELECT compatibility.applied_count INTO retired_count
  FROM app.schema_compatibility_v10() AS compatibility;
  IF retired_count IS DISTINCT FROM 0 THEN
    RAISE EXCEPTION 'schema compatibility v10 must be retired'
      USING ERRCODE = '55000';
  END IF;
END;
$function$;--> statement-breakpoint

ALTER FUNCTION app.seal_schema_compatibility_manifest(bigint, bigint, text, text)
  OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.seal_schema_compatibility_manifest(bigint, bigint, text, text)
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint

DO $identity_sync_fenced_readiness_assertions$
DECLARE
  expected_function record;
  function_oid regprocedure;
  function_owner text;
  function_configuration text[];
  function_security_definer boolean;
  public_can_execute boolean;
  api_can_execute boolean;
  worker_can_execute boolean;
  notifier_can_execute boolean;
  auditor_can_execute boolean;
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_class AS relation
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = relation.relnamespace
    WHERE namespace.nspname = 'public'
      AND relation.relname IN (
        'tenant_ldap_sync_runs', 'tenant_ldap_sync_staged_observations'
      )
      AND relation.relrowsecurity AND relation.relforcerowsecurity
    GROUP BY namespace.nspname
    HAVING count(*) = 2
  ) OR NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_constraint AS constraint_row
    WHERE constraint_row.conname = 'tenant_ldap_sync_runs_claim_check'
      AND constraint_row.conrelid = 'public.tenant_ldap_sync_runs'::regclass
  ) OR NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_indexes AS index_row
    WHERE index_row.schemaname = 'public'
      AND index_row.indexname = 'tenant_ldap_sync_runs_claim_id_key'
  ) THEN
    RAISE EXCEPTION 'LDAP sync fenced schema boundary is incomplete'
      USING ERRCODE = '55000';
  END IF;

  FOR expected_function IN
    SELECT * FROM (VALUES
      ('app.private_lock_tenant_ldap_sync_claim_v2(uuid,uuid,bytea,bigint,boolean)', false),
      ('app.claim_next_tenant_ldap_sync_run_v2(uuid,bytea,integer,text)', true),
      ('app.stage_tenant_ldap_sync_observation_v2(uuid,uuid,bytea,bigint,uuid,integer,integer,bytea,bytea)', true),
      ('app.claim_tenant_ldap_sync_observation_planning_v2(uuid,uuid,uuid,bytea,bigint,integer[],bytea[])', true),
      ('app.complete_tenant_ldap_sync_enumeration_v2(uuid,uuid,bytea,bigint,integer,boolean,boolean,bytea,text,uuid,uuid,uuid,text)', true),
      ('app.apply_tenant_ldap_sync_identity_plan_v2(uuid,uuid,uuid,bytea,bigint,uuid,bytea,uuid,integer,integer,integer,integer,uuid,bigint,bigint,public.ldap_identity_apply_decision,text,uuid,uuid,uuid,uuid,uuid,public.identity_subject_format,bytea,bytea,integer,uuid[],integer[],bytea[],text,text,text,text,text,uuid[],timestamptz,uuid,uuid,uuid,inet,text)', true),
      ('app.apply_tenant_ldap_sync_absence_chunk_v2(uuid,uuid,bytea,bigint,integer,uuid,uuid,uuid,text)', true),
      ('app.complete_tenant_ldap_sync_run_v2(uuid,uuid,bytea,bigint,integer,uuid,uuid,uuid,text)', true),
      ('app.fail_tenant_ldap_sync_run_v2(uuid,uuid,bytea,bigint,integer,text,uuid,uuid,uuid,text)', true)
    ) AS expected(signature, worker_execute)
  LOOP
    function_oid := to_regprocedure(expected_function.signature);
    IF function_oid IS NULL THEN
      RAISE EXCEPTION 'required fenced LDAP sync ABI % is absent',
        expected_function.signature USING ERRCODE = '55000';
    END IF;
    SELECT pg_catalog.pg_get_userbyid(procedure.proowner), procedure.proconfig,
           procedure.prosecdef,
           pg_catalog.has_function_privilege('public', procedure.oid, 'EXECUTE'),
           pg_catalog.has_function_privilege('periapsis_api', procedure.oid, 'EXECUTE'),
           pg_catalog.has_function_privilege('periapsis_worker', procedure.oid, 'EXECUTE'),
           pg_catalog.has_function_privilege('periapsis_notifier', procedure.oid, 'EXECUTE'),
           pg_catalog.has_function_privilege('periapsis_auditor', procedure.oid, 'EXECUTE')
    INTO function_owner, function_configuration, function_security_definer,
         public_can_execute, api_can_execute, worker_can_execute,
         notifier_can_execute, auditor_can_execute
    FROM pg_catalog.pg_proc AS procedure WHERE procedure.oid = function_oid;
    IF function_owner IS DISTINCT FROM 'periapsis_migrator'
       OR function_configuration IS DISTINCT FROM
            ARRAY['search_path=pg_catalog, public, app']::text[]
       OR NOT function_security_definer OR public_can_execute OR api_can_execute
       OR worker_can_execute IS DISTINCT FROM expected_function.worker_execute
       OR notifier_can_execute OR auditor_can_execute THEN
      RAISE EXCEPTION 'fenced LDAP sync ABI % boundary is not exact',
        expected_function.signature USING ERRCODE = '55000';
    END IF;
  END LOOP;

  IF pg_catalog.has_function_privilege(
       'periapsis_worker', 'app.claim_next_tenant_ldap_sync_run_v1(text)', 'EXECUTE'
     ) OR pg_catalog.has_function_privilege(
       'periapsis_worker', 'app.stage_tenant_ldap_sync_observation_v1(uuid,uuid,integer,integer,bytea,bytea)', 'EXECUTE'
     ) OR pg_catalog.has_function_privilege(
       'periapsis_worker', 'app.complete_tenant_ldap_sync_enumeration_v1(uuid,integer,boolean,boolean,bytea,text,uuid,uuid,uuid,text)', 'EXECUTE'
     ) OR pg_catalog.has_function_privilege(
       'periapsis_worker', 'app.apply_tenant_ldap_sync_absence_chunk_v1(uuid,integer,uuid,uuid,uuid,text)', 'EXECUTE'
     ) OR pg_catalog.has_function_privilege(
       'periapsis_worker', 'app.complete_tenant_ldap_sync_run_v1(uuid,integer,uuid,uuid,uuid,text)', 'EXECUTE'
     ) OR pg_catalog.has_function_privilege(
       'periapsis_worker', 'app.fail_tenant_ldap_sync_run_v1(uuid,integer,text,uuid,uuid,uuid,text)', 'EXECUTE'
     ) OR pg_catalog.has_function_privilege(
       'periapsis_worker', 'app.apply_tenant_ldap_identity_plan_v1(uuid,bytea,public.ldap_identity_apply_mode,uuid,uuid,uuid,integer,integer,integer,integer,uuid,bigint,bigint,public.ldap_identity_apply_decision,text,uuid,uuid,uuid,uuid,uuid,public.identity_subject_format,bytea,bytea,integer,uuid[],integer[],bytea[],text,text,text,text,text,uuid[],timestamptz,uuid,uuid,uuid,inet,text)', 'EXECUTE'
     ) OR pg_catalog.has_function_privilege(
       'periapsis_api', 'app.apply_tenant_ldap_identity_plan_v1(uuid,bytea,public.ldap_identity_apply_mode,uuid,uuid,uuid,integer,integer,integer,integer,uuid,bigint,bigint,public.ldap_identity_apply_decision,text,uuid,uuid,uuid,uuid,uuid,public.identity_subject_format,bytea,bytea,integer,uuid[],integer[],bytea[],text,text,text,text,text,uuid[],timestamptz,uuid,uuid,uuid,inet,text)', 'EXECUTE'
     ) THEN
    RAISE EXCEPTION 'an unfenced LDAP sync mutation surface remains executable'
      USING ERRCODE = '55000';
  END IF;
END;
$identity_sync_fenced_readiness_assertions$;
