-- Worker-only SLA queue metrics. The database owns both eligibility and time:
-- callers cannot choose a tenant, a cutoff, or a snapshot instant.

CREATE FUNCTION app.read_sla_evaluation_queue_metrics_v1()
RETURNS TABLE(
  observed_at timestamp with time zone,
  pending_jobs bigint,
  oldest_pending_micros bigint
)
LANGUAGE sql
VOLATILE
ROWS 1
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
  WITH observed AS MATERIALIZED (
    SELECT clock_timestamp() AS observed_at
  ),
  eligible AS (
    SELECT job.available_at AS ready_at
    FROM public.sla_evaluation_jobs AS job
    CROSS JOIN observed
    WHERE job.status IN (
      'queued'::public.sla_job_status,
      'retry_scheduled'::public.sla_job_status
    )
      AND job.available_at <= observed.observed_at

    UNION ALL

    SELECT job.lease_expires_at AS ready_at
    FROM public.sla_evaluation_jobs AS job
    CROSS JOIN observed
    WHERE job.status = 'leased'::public.sla_job_status
      AND job.lease_expires_at <= observed.observed_at
  ),
  metrics AS (
    SELECT count(*)::bigint AS pending_jobs,
           min(eligible.ready_at) AS oldest_ready_at
    FROM eligible
  )
  SELECT observed.observed_at,
         metrics.pending_jobs,
         CASE
           WHEN metrics.oldest_ready_at IS NULL THEN 0::bigint
           ELSE greatest(
             0::bigint,
             floor(
               extract(
                 epoch FROM observed.observed_at - metrics.oldest_ready_at
               ) * 1000000
             )::bigint
           )
         END AS oldest_pending_micros
  FROM observed
  CROSS JOIN metrics;
$function$;
ALTER FUNCTION app.read_sla_evaluation_queue_metrics_v1()
  OWNER TO periapsis_sla_worker_owner;
REVOKE ALL ON FUNCTION app.read_sla_evaluation_queue_metrics_v1()
FROM PUBLIC, periapsis_migrator, periapsis_api, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner, periapsis_sla_api_owner,
  periapsis_sla_readiness_owner;
GRANT EXECUTE ON FUNCTION app.read_sla_evaluation_queue_metrics_v1()
TO periapsis_worker;
--> statement-breakpoint

-- V28 is the exact 0135 state. V27 exposes only the sealed 0134 prefix for a
-- rolling predecessor binary, while V26 is retired and cannot be invoked by a
-- runtime role.
CREATE FUNCTION app.schema_compatibility_v28()
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
  migration_0135_rows bigint;
BEGIN
  EXECUTE $query$
    SELECT count(*)::bigint, max(migration.created_at)::bigint,
           count(*) FILTER (
             WHERE migration.created_at = 1787737707040
           )::bigint
    FROM drizzle.__drizzle_migrations AS migration
  $query$ INTO journal_count, journal_latest_created_at, migration_0135_rows;
  IF journal_count = 136
     AND journal_latest_created_at = 1787737707040
     AND migration_0135_rows = 1 THEN
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
ALTER FUNCTION app.schema_compatibility_v28()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.schema_compatibility_v28()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,
  periapsis_sla_api_owner, periapsis_sla_worker_owner,
  periapsis_sla_readiness_owner;
GRANT EXECUTE ON FUNCTION app.schema_compatibility_v28()
TO periapsis_api, periapsis_worker;
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.schema_compatibility_v27()
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
  FROM app.schema_compatibility_v28() AS compatibility;
  IF full_count = 136
     AND full_latest_created_at = 1787737707040
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
              WHERE prefix.migration_ordinal = 135),
             string_agg(
               migration.created_at::text || '@' || migration.migration_hash,
               ':' ORDER BY migration.created_at, migration.id
             )
      FROM ordered_migrations AS migration
      WHERE migration.migration_ordinal <= 135
    $query$;
    RETURN;
  END IF;
  RETURN QUERY SELECT 0::bigint, 0::bigint,
                      'UNSUPPORTED'::text, 'UNSUPPORTED'::text;
END;
$function$;
ALTER FUNCTION app.schema_compatibility_v27()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.schema_compatibility_v27()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,
  periapsis_sla_api_owner, periapsis_sla_worker_owner,
  periapsis_sla_readiness_owner;
GRANT EXECUTE ON FUNCTION app.schema_compatibility_v27()
TO periapsis_api, periapsis_worker;
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.schema_compatibility_v26()
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
ALTER FUNCTION app.schema_compatibility_v26()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.schema_compatibility_v26()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,
  periapsis_sla_api_owner, periapsis_sla_worker_owner,
  periapsis_sla_readiness_owner;
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
SET search_path = pg_catalog
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
  IF p_expected_count IS DISTINCT FROM 136
     OR p_expected_latest_created_at IS DISTINCT FROM 1787737707040
     OR p_expected_latest_hash IS NULL
     OR p_expected_latest_hash !~ '^[0-9a-f]{64}$'
     OR p_expected_migration_fingerprint IS NULL
     OR p_expected_migration_fingerprint !~
          '^[1-9][0-9]*@[0-9a-f]{64}(:[1-9][0-9]*@[0-9a-f]{64})*$'
     OR cardinality(fingerprint_entries) IS DISTINCT FROM 136
     OR fingerprint_entries[136] IS DISTINCT FROM (
       p_expected_latest_created_at::text || '@' || p_expected_latest_hash
     ) THEN
    RAISE EXCEPTION 'invalid schema compatibility v28 manifest'
      USING ERRCODE = '22023';
  END IF;
  SELECT array_agg(
    split_part(entry.value, '@', 1)::bigint ORDER BY entry.ordinality
  ) INTO appended_created_at
  FROM unnest(fingerprint_entries[136:136]) WITH ORDINALITY
       AS entry(value, ordinality);
  IF appended_created_at IS DISTINCT FROM
       ARRAY[1787737707040]::bigint[] THEN
    RAISE EXCEPTION 'invalid schema compatibility v28 appended sequence'
      USING ERRCODE = '22023';
  END IF;

  SELECT compatibility.applied_count, compatibility.latest_created_at,
         compatibility.latest_hash, compatibility.migration_fingerprint
  INTO actual_count, actual_latest_created_at, actual_latest_hash,
       actual_fingerprint
  FROM app.schema_compatibility_v28() AS compatibility;
  IF actual_count IS DISTINCT FROM p_expected_count
     OR actual_latest_created_at IS DISTINCT FROM p_expected_latest_created_at
     OR actual_latest_hash IS DISTINCT FROM p_expected_latest_hash
     OR actual_fingerprint IS DISTINCT FROM p_expected_migration_fingerprint THEN
    RAISE EXCEPTION 'schema compatibility v28 manifest does not match the applied journal'
      USING ERRCODE = '55000';
  END IF;

  PERFORM set_config(
    'app.schema_compatibility_fingerprint',
    p_expected_migration_fingerprint, true
  );
  EXECUTE $statement$
    ALTER FUNCTION app.schema_compatibility_v27()
      SET app.schema_compatibility_fingerprint FROM CURRENT
  $statement$;
  expected_predecessor_fingerprint := array_to_string(
    fingerprint_entries[1:135], ':'
  );
  SELECT compatibility.applied_count, compatibility.latest_created_at,
         compatibility.latest_hash, compatibility.migration_fingerprint
  INTO predecessor_count, predecessor_latest_created_at,
       predecessor_latest_hash, predecessor_fingerprint
  FROM app.schema_compatibility_v27() AS compatibility;
  IF predecessor_count IS DISTINCT FROM 135
     OR predecessor_latest_created_at IS DISTINCT FROM 1787732438000
     OR predecessor_latest_hash IS DISTINCT FROM
          'c324d64aee82f94fe3912370c910174dc08b9c4a0241f346ef69c5a2d596b2ba'
     OR predecessor_fingerprint IS DISTINCT FROM
          expected_predecessor_fingerprint THEN
    RAISE EXCEPTION 'sealed schema compatibility v27 prefix is not exact'
      USING ERRCODE = '55000';
  END IF;

  SELECT compatibility.applied_count INTO retired_count
  FROM app.schema_compatibility_v26() AS compatibility;
  IF retired_count IS DISTINCT FROM 0
     OR NOT has_function_privilege(
       'periapsis_api', 'app.schema_compatibility_v28()'::regprocedure,
       'EXECUTE'
     )
     OR NOT has_function_privilege(
       'periapsis_worker', 'app.schema_compatibility_v28()'::regprocedure,
       'EXECUTE'
     )
     OR NOT has_function_privilege(
       'periapsis_api', 'app.schema_compatibility_v27()'::regprocedure,
       'EXECUTE'
     )
     OR NOT has_function_privilege(
       'periapsis_worker', 'app.schema_compatibility_v27()'::regprocedure,
       'EXECUTE'
     )
     OR has_function_privilege(
       'periapsis_api', 'app.schema_compatibility_v26()'::regprocedure,
       'EXECUTE'
     )
     OR has_function_privilege(
       'periapsis_worker', 'app.schema_compatibility_v26()'::regprocedure,
       'EXECUTE'
     ) THEN
    RAISE EXCEPTION 'schema compatibility v26 remains active'
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
  periapsis_sla_readiness_owner;
--> statement-breakpoint

-- Preserve the full structural checks from the three readiness surfaces
-- published at 0134 while rebinding only their exact compatibility edge.
DO $migration$
DECLARE
  readiness_function regprocedure;
  original_definition text;
  rewritten_definition text;
BEGIN
  FOREACH readiness_function IN ARRAY ARRAY[
    'app.federated_authentication_schema_readiness_v1()'::regprocedure,
    'app.identity_mfa_device_management_readiness_v1()'::regprocedure,
    'app.identity_mfa_schema_readiness_v1()'::regprocedure
  ] LOOP
    SELECT pg_get_functiondef(readiness_function)
    INTO original_definition;
    IF original_definition NOT LIKE '%app.schema_compatibility_v27()%'
       OR original_definition NOT LIKE '%app.schema_compatibility_v26()%'
       OR original_definition NOT LIKE '%app.schema_compatibility_v25()%'
       OR original_definition NOT LIKE
            '%current_count = 135 AND predecessor_count = 126%' THEN
      RAISE EXCEPTION 'unexpected 0134 readiness definition: %',
        readiness_function::text USING ERRCODE = '55000';
    END IF;

    rewritten_definition := replace(
      original_definition,
      'app.schema_compatibility_v27()',
      'app.schema_compatibility_v28()'
    );
    rewritten_definition := replace(
      rewritten_definition,
      'app.schema_compatibility_v26()',
      'app.schema_compatibility_v27()'
    );
    rewritten_definition := replace(
      rewritten_definition,
      'app.schema_compatibility_v25()',
      'app.schema_compatibility_v26()'
    );
    rewritten_definition := replace(
      rewritten_definition,
      'current_count = 135 AND predecessor_count = 126',
      'current_count = 136 AND predecessor_count = 135'
    );
    IF rewritten_definition IS NOT DISTINCT FROM original_definition
       OR rewritten_definition NOT LIKE '%app.schema_compatibility_v28()%'
       OR rewritten_definition LIKE '%app.schema_compatibility_v25()%'
       OR rewritten_definition NOT LIKE
            '%current_count = 136 AND predecessor_count = 135%' THEN
      RAISE EXCEPTION 'failed to rebind readiness definition: %',
        readiness_function::text USING ERRCODE = '55000';
    END IF;
    EXECUTE rewritten_definition;
  END LOOP;
END;
$migration$;
--> statement-breakpoint

-- Retain the established SLA structural checks as a non-public core. The new
-- public readiness surface adds exact queue-metrics and planner prerequisites.
DO $migration$
DECLARE
  original_definition text;
  rewritten_definition text;
BEGIN
  SELECT pg_get_functiondef(
    'app.sla_schema_readiness_v1()'::regprocedure
  ) INTO original_definition;
  IF original_definition NOT LIKE
       '%FUNCTION app.sla_schema_readiness_v1()%'
     OR original_definition NOT LIKE '%app.schema_compatibility_v23()%'
     OR original_definition NOT LIKE '%app.schema_compatibility_v22()%'
     OR original_definition NOT LIKE '%app.schema_compatibility_v21()%'
     OR original_definition NOT LIKE '%app.schema_compatibility_v20()%'
     OR original_definition NOT LIKE
          '%current_count = 116 AND predecessor_count = 113%' THEN
    RAISE EXCEPTION 'unexpected pre-metrics SLA readiness definition'
      USING ERRCODE = '55000';
  END IF;
  rewritten_definition := replace(
    original_definition,
    'FUNCTION app.sla_schema_readiness_v1()',
    'FUNCTION app.private_sla_schema_readiness_core_v1()'
  );
  rewritten_definition := replace(
    rewritten_definition,
    'app.schema_compatibility_v23()',
    'app.schema_compatibility_v28()'
  );
  rewritten_definition := replace(
    rewritten_definition,
    'app.schema_compatibility_v22()',
    'app.schema_compatibility_v27()'
  );
  rewritten_definition := replace(
    rewritten_definition,
    'app.schema_compatibility_v21()',
    'app.schema_compatibility_v26()'
  );
  rewritten_definition := replace(
    rewritten_definition,
    'app.schema_compatibility_v20()',
    'app.schema_compatibility_v26()'
  );
  rewritten_definition := replace(
    rewritten_definition,
    'current_count = 116 AND predecessor_count = 113',
    'current_count = 136 AND predecessor_count = 135'
  );
  rewritten_definition := replace(
    rewritten_definition,
    '''%private_seed_tenant_sla_authorization_v1%''',
    '''%seed_tenant_authorization_workflow_compatibility_impl%'''
  );
  IF rewritten_definition IS NOT DISTINCT FROM original_definition
     OR rewritten_definition NOT LIKE '%app.schema_compatibility_v28()%'
     OR rewritten_definition ~ 'app\.schema_compatibility_v2[0-5]\(\)'
     OR rewritten_definition NOT LIKE
          '%current_count = 136 AND predecessor_count = 135%'
     OR rewritten_definition LIKE
          '%''%private_seed_tenant_sla_authorization_v1%''%'
     OR rewritten_definition NOT LIKE
          '%''%seed_tenant_authorization_workflow_compatibility_impl%''%' THEN
    RAISE EXCEPTION 'failed to rebind SLA readiness core'
      USING ERRCODE = '55000';
  END IF;
  EXECUTE rewritten_definition;
  EXECUTE $ddl$
    ALTER FUNCTION app.private_sla_schema_readiness_core_v1()
      OWNER TO periapsis_migrator
  $ddl$;
  EXECUTE $ddl$
    REVOKE ALL ON FUNCTION app.private_sla_schema_readiness_core_v1()
    FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
      periapsis_auditor, periapsis_audit_reader_owner,
      periapsis_notification_dispatch_owner,
      periapsis_sla_api_owner, periapsis_sla_worker_owner,
      periapsis_sla_readiness_owner
  $ddl$;
  EXECUTE $ddl$
    GRANT EXECUTE ON FUNCTION app.private_sla_schema_readiness_core_v1()
    TO periapsis_sla_readiness_owner
  $ddl$;
END;
$migration$;
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.sla_schema_readiness_v1()
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  metrics_function regprocedure;
  function_owner text;
  function_security_definer boolean;
  function_volatility "char";
  function_rows real;
  function_configuration text[];
  function_result text;
  function_definition text;
  seed_definition text;
  seed_compatibility_definition text;
  expected_index record;
BEGIN
  IF NOT app.private_sla_schema_readiness_core_v1() THEN
    RETURN false;
  END IF;

  SELECT pg_get_functiondef(
           to_regprocedure('app.seed_tenant_authorization(uuid,uuid)')
         ),
         pg_get_functiondef(
           to_regprocedure(
             'app.seed_tenant_authorization_workflow_compatibility_impl(uuid,uuid)'
           )
         )
  INTO seed_definition, seed_compatibility_definition;
  IF seed_definition IS NULL
     OR seed_definition NOT LIKE
          '%seed_tenant_authorization_workflow_compatibility_impl%'
     OR seed_compatibility_definition IS NULL
     OR seed_compatibility_definition NOT LIKE
          '%seed_tenant_authorization_sla_compatibility_impl%'
     OR seed_compatibility_definition NOT LIKE
          '%private_seed_tenant_sla_authorization_v1%' THEN
    RETURN false;
  END IF;

  metrics_function := to_regprocedure(
    'app.read_sla_evaluation_queue_metrics_v1()'
  );
  IF metrics_function IS NULL THEN
    RETURN false;
  END IF;
  SELECT pg_get_userbyid(procedure.proowner), procedure.prosecdef,
         procedure.provolatile, procedure.prorows, procedure.proconfig,
         pg_get_function_result(procedure.oid),
         pg_get_functiondef(procedure.oid)
  INTO function_owner, function_security_definer, function_volatility,
       function_rows, function_configuration, function_result,
       function_definition
  FROM pg_proc AS procedure
  WHERE procedure.oid = metrics_function;
  IF function_owner IS DISTINCT FROM 'periapsis_sla_worker_owner'
     OR function_security_definer IS NOT TRUE
     OR function_volatility IS DISTINCT FROM 'v'::"char"
     OR function_rows IS DISTINCT FROM 1::real
     OR function_configuration IS DISTINCT FROM
          ARRAY['search_path=pg_catalog, public, app']::text[]
     OR function_result IS DISTINCT FROM
          'TABLE(observed_at timestamp with time zone, pending_jobs bigint, oldest_pending_micros bigint)'
     OR regexp_count(function_definition, 'clock_timestamp\(\)') <> 1
     OR function_definition NOT LIKE '%WITH observed AS MATERIALIZED%'
     OR function_definition NOT LIKE '%UNION ALL%'
     OR function_definition NOT LIKE '%job.available_at <= observed.observed_at%'
     OR function_definition NOT LIKE
          '%job.lease_expires_at <= observed.observed_at%'
     OR function_definition NOT LIKE
          '%count(*)::bigint AS pending_jobs%'
     OR function_definition NOT LIKE '%min(eligible.ready_at)%'
     OR function_definition NOT LIKE '%1000000%'
     OR function_definition NOT LIKE '%greatest(%'
     OR function_definition LIKE '%current_setting(%' THEN
    RETURN false;
  END IF;

  IF NOT has_function_privilege(
       'periapsis_worker', metrics_function, 'EXECUTE'
     ) OR EXISTS (
       SELECT 1
       FROM (VALUES
         ('periapsis_migrator'), ('periapsis_api'),
         ('periapsis_notifier'), ('periapsis_auditor'),
         ('periapsis_audit_reader_owner'),
         ('periapsis_notification_dispatch_owner'),
         ('periapsis_sla_api_owner'), ('periapsis_sla_readiness_owner')
       ) AS forbidden(role_name)
       WHERE has_function_privilege(
         forbidden.role_name, metrics_function, 'EXECUTE'
       )
     ) OR EXISTS (
       SELECT 1
       FROM pg_proc AS procedure
       CROSS JOIN LATERAL aclexplode(
         coalesce(procedure.proacl, acldefault('f', procedure.proowner))
       ) AS privilege
       WHERE procedure.oid = metrics_function
         AND privilege.privilege_type = 'EXECUTE'
         AND privilege.grantee <> ALL(ARRAY[
           'periapsis_sla_worker_owner'::regrole,
           'periapsis_worker'::regrole
         ]::oid[])
     ) THEN
    RETURN false;
  END IF;

  FOR expected_index IN
    SELECT * FROM (VALUES
      (
        'sla_evaluation_jobs_claim_idx',
        'available_at', 'tenant_id', 'id',
        'status = ANY (ARRAY[''queued''::sla_job_status, ''retry_scheduled''::sla_job_status])'
      ),
      (
        'sla_evaluation_jobs_reclaim_idx',
        'lease_expires_at', 'tenant_id', 'id',
        'status = ''leased''::sla_job_status'
      )
    ) AS required(
      index_name, first_key, second_key, third_key, predicate
    )
  LOOP
    IF NOT EXISTS (
      SELECT 1
      FROM pg_index AS index_row
      JOIN pg_class AS index_class
        ON index_class.oid = index_row.indexrelid
      JOIN pg_class AS table_class
        ON table_class.oid = index_row.indrelid
      JOIN pg_namespace AS namespace
        ON namespace.oid = table_class.relnamespace
      WHERE namespace.nspname = 'public'
        AND table_class.relname = 'sla_evaluation_jobs'
        AND index_class.relname = expected_index.index_name
        AND index_row.indisvalid AND index_row.indisready
        AND index_row.indislive AND NOT index_row.indisunique
        AND NOT index_row.indisexclusion
        AND index_row.indnkeyatts = 3 AND index_row.indnatts = 3
        AND index_row.indexprs IS NULL AND index_row.indpred IS NOT NULL
        AND pg_get_indexdef(index_class.oid, 1, true) =
             expected_index.first_key
        AND pg_get_indexdef(index_class.oid, 2, true) =
             expected_index.second_key
        AND pg_get_indexdef(index_class.oid, 3, true) =
             expected_index.third_key
        AND pg_get_expr(index_row.indpred, index_row.indrelid, true) =
             expected_index.predicate
    ) THEN
      RETURN false;
    END IF;
  END LOOP;

  RETURN true;
END;
$function$;
ALTER FUNCTION app.sla_schema_readiness_v1()
  OWNER TO periapsis_sla_readiness_owner;
REVOKE ALL ON FUNCTION app.sla_schema_readiness_v1()
FROM PUBLIC, periapsis_notifier, periapsis_auditor,
  periapsis_audit_reader_owner, periapsis_notification_dispatch_owner,
  periapsis_sla_api_owner, periapsis_sla_worker_owner;
GRANT EXECUTE ON FUNCTION app.sla_schema_readiness_v1()
TO periapsis_api, periapsis_worker;
