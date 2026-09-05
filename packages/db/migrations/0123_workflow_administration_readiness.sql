-- Workflow administration closes with an exact current projection. V24 is the
-- sole rolling predecessor (through 0120); V23 and older are retired.

CREATE FUNCTION app.schema_compatibility_v25()
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
  migration_0123_rows bigint;
BEGIN
  EXECUTE $query$
    SELECT count(*)::bigint, max(migration.created_at)::bigint,
           count(*) FILTER (
             WHERE migration.created_at = 1787721876116
           )::bigint
    FROM drizzle.__drizzle_migrations AS migration
  $query$ INTO journal_count, journal_latest_created_at, migration_0123_rows;
  IF journal_count = 124
     AND journal_latest_created_at = 1787721876116
     AND migration_0123_rows = 1 THEN
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
ALTER FUNCTION app.schema_compatibility_v25()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.schema_compatibility_v25()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,
  periapsis_sla_api_owner, periapsis_sla_worker_owner,
  periapsis_sla_readiness_owner;
GRANT EXECUTE ON FUNCTION app.schema_compatibility_v25()
TO periapsis_api, periapsis_worker;
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.schema_compatibility_v24()
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
  FROM app.schema_compatibility_v25() AS compatibility;
  IF full_count = 124
     AND full_latest_created_at = 1787721876116
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
              WHERE prefix.migration_ordinal = 121),
             string_agg(
               migration.created_at::text || '@' || migration.migration_hash,
               ':' ORDER BY migration.created_at, migration.id
             )
      FROM ordered_migrations AS migration
      WHERE migration.migration_ordinal <= 121
    $query$;
    RETURN;
  END IF;
  RETURN QUERY SELECT 0::bigint, 0::bigint,
                      'UNSUPPORTED'::text, 'UNSUPPORTED'::text;
END;
$function$;
ALTER FUNCTION app.schema_compatibility_v24()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.schema_compatibility_v24()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,
  periapsis_sla_api_owner, periapsis_sla_worker_owner,
  periapsis_sla_readiness_owner;
GRANT EXECUTE ON FUNCTION app.schema_compatibility_v24()
TO periapsis_api, periapsis_worker;
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.schema_compatibility_v23()
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
ALTER FUNCTION app.schema_compatibility_v23()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.schema_compatibility_v23()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,
  periapsis_sla_api_owner, periapsis_sla_worker_owner,
  periapsis_sla_readiness_owner;
GRANT EXECUTE ON FUNCTION app.schema_compatibility_v23()
TO periapsis_api, periapsis_worker;
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
  retired_legacy_count bigint;
BEGIN
  fingerprint_entries := string_to_array(
    p_expected_migration_fingerprint, ':'
  );
  IF p_expected_count IS DISTINCT FROM 124
     OR p_expected_latest_created_at IS DISTINCT FROM 1787721876116
     OR p_expected_latest_hash IS NULL
     OR p_expected_latest_hash !~ '^[0-9a-f]{64}$'
     OR p_expected_migration_fingerprint IS NULL
     OR p_expected_migration_fingerprint !~
          '^[1-9][0-9]*@[0-9a-f]{64}(:[1-9][0-9]*@[0-9a-f]{64})*$'
     OR cardinality(fingerprint_entries) IS DISTINCT FROM 124
     OR fingerprint_entries[124] IS DISTINCT FROM (
       p_expected_latest_created_at::text || '@' || p_expected_latest_hash
     ) THEN
    RAISE EXCEPTION 'invalid schema compatibility v25 manifest'
      USING ERRCODE = '22023';
  END IF;
  SELECT array_agg(
    split_part(entry.value, '@', 1)::bigint ORDER BY entry.ordinality
  ) INTO appended_created_at
  FROM unnest(fingerprint_entries[122:124]) WITH ORDINALITY
       AS entry(value, ordinality);
  IF appended_created_at IS DISTINCT FROM ARRAY[
    1787719987372, 1787719999609, 1787721876116
  ]::bigint[] THEN
    RAISE EXCEPTION 'invalid schema compatibility v25 appended sequence'
      USING ERRCODE = '22023';
  END IF;

  SELECT compatibility.applied_count, compatibility.latest_created_at,
         compatibility.latest_hash, compatibility.migration_fingerprint
  INTO actual_count, actual_latest_created_at, actual_latest_hash,
       actual_fingerprint
  FROM app.schema_compatibility_v25() AS compatibility;
  IF actual_count IS DISTINCT FROM p_expected_count
     OR actual_latest_created_at IS DISTINCT FROM p_expected_latest_created_at
     OR actual_latest_hash IS DISTINCT FROM p_expected_latest_hash
     OR actual_fingerprint IS DISTINCT FROM p_expected_migration_fingerprint THEN
    RAISE EXCEPTION 'schema compatibility v25 manifest does not match the applied journal'
      USING ERRCODE = '55000';
  END IF;

  PERFORM set_config(
    'app.schema_compatibility_fingerprint',
    p_expected_migration_fingerprint, true
  );
  EXECUTE $statement$
    ALTER FUNCTION app.schema_compatibility_v24()
      SET app.schema_compatibility_fingerprint FROM CURRENT
  $statement$;
  expected_predecessor_fingerprint := array_to_string(
    fingerprint_entries[1:121], ':'
  );
  SELECT compatibility.applied_count, compatibility.latest_created_at,
         compatibility.latest_hash, compatibility.migration_fingerprint
  INTO predecessor_count, predecessor_latest_created_at,
       predecessor_latest_hash, predecessor_fingerprint
  FROM app.schema_compatibility_v24() AS compatibility;
  IF predecessor_count IS DISTINCT FROM 121
     OR predecessor_latest_created_at IS DISTINCT FROM 1787716104120
     OR predecessor_latest_hash IS DISTINCT FROM
          '81b736c90d9fe7f912515a9346eab4df9333e66ecec7328778a49478dc970118'
     OR predecessor_fingerprint IS DISTINCT FROM
          expected_predecessor_fingerprint THEN
    RAISE EXCEPTION 'sealed schema compatibility v24 prefix is not exact'
      USING ERRCODE = '55000';
  END IF;

  SELECT compatibility.applied_count INTO retired_count
  FROM app.schema_compatibility_v23() AS compatibility;
  SELECT compatibility.applied_count INTO retired_legacy_count
  FROM app.schema_compatibility_v22() AS compatibility;
  IF retired_count IS DISTINCT FROM 0
     OR retired_legacy_count IS DISTINCT FROM 0 THEN
    RAISE EXCEPTION 'legacy schema compatibility projections remain active'
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

CREATE FUNCTION app.workflow_administration_schema_readiness_v1()
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  expected_function record;
  function_oid regprocedure;
  function_owner text;
  function_security_definer boolean;
  function_configuration text[];
  current_count bigint;
  predecessor_count bigint;
  retired_count bigint;
  seed_definition text;
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_class AS class
    JOIN pg_namespace AS namespace ON namespace.oid = class.relnamespace
    WHERE namespace.nspname = 'public'
      AND class.relname = 'ticket_workflow_commands'
      AND class.relkind = 'r'
      AND pg_get_userbyid(class.relowner) = 'periapsis_migrator'
      AND class.relrowsecurity AND class.relforcerowsecurity
  ) OR has_table_privilege(
    'periapsis_api', 'public.ticket_workflow_commands',
    'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
  ) OR has_table_privilege(
    'periapsis_worker', 'public.ticket_workflow_commands',
    'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
  ) OR has_table_privilege(
    'periapsis_notifier', 'public.ticket_workflow_commands',
    'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
  ) OR has_table_privilege(
    'periapsis_auditor', 'public.ticket_workflow_commands',
    'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
  ) THEN
    RETURN false;
  END IF;

  IF NOT has_table_privilege(
       'periapsis_api', 'public.ticket_workflows', 'SELECT'
     ) OR NOT has_table_privilege(
       'periapsis_api', 'public.ticket_workflow_versions', 'SELECT'
     ) OR has_table_privilege(
       'periapsis_api', 'public.ticket_workflows',
       'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
     ) OR has_table_privilege(
       'periapsis_api', 'public.ticket_workflow_versions',
       'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
     ) OR EXISTS (
       SELECT 1
       FROM pg_class AS class
       JOIN pg_namespace AS namespace ON namespace.oid = class.relnamespace
       WHERE namespace.nspname = 'public'
         AND class.relname IN (
           'ticket_workflows', 'ticket_workflow_versions'
         ) AND (
           pg_get_userbyid(class.relowner) <> 'periapsis_migrator'
           OR NOT class.relrowsecurity OR NOT class.relforcerowsecurity
         )
     ) THEN
    RETURN false;
  END IF;

  IF NOT EXISTS (
    SELECT 1
    FROM pg_policy AS policy
    JOIN pg_class AS class ON class.oid = policy.polrelid
    JOIN pg_namespace AS namespace ON namespace.oid = class.relnamespace
    WHERE namespace.nspname = 'public'
      AND class.relname = 'ticket_workflows'
      AND pg_get_expr(policy.polqual, policy.polrelid) LIKE '%workflow.read%'
      AND pg_get_expr(policy.polqual, policy.polrelid) LIKE '%workflow.manage%'
  ) OR NOT EXISTS (
    SELECT 1
    FROM pg_policy AS policy
    JOIN pg_class AS class ON class.oid = policy.polrelid
    JOIN pg_namespace AS namespace ON namespace.oid = class.relnamespace
    WHERE namespace.nspname = 'public'
      AND class.relname = 'ticket_workflow_versions'
      AND pg_get_expr(policy.polqual, policy.polrelid) LIKE '%workflow.read%'
      AND pg_get_expr(policy.polqual, policy.polrelid) LIKE '%workflow.manage%'
  ) THEN
    RETURN false;
  END IF;

  FOR expected_function IN
    SELECT * FROM (VALUES
      ('app.lookup_ticket_workflow_admin_replay_v1(uuid,uuid,text,bytea)', true, true),
      ('app.commit_ticket_workflow_admin_v1(uuid,uuid,text,uuid,public.ticket_aggregate_kind,text,text,text,boolean,text,bigint,bigint,jsonb,jsonb,bigint,boolean,uuid,bigint,bigint,bytea,bytea,uuid,uuid,uuid,uuid,uuid,uuid,inet,text,text)', true, true),
      ('app.private_seed_tenant_workflow_authorization_v1(uuid)', true, false),
      ('app.private_workflow_json_exact_keys_v1(jsonb,text[])', false, false),
      ('app.private_workflow_effect_plan_valid_v1(jsonb)', false, false),
      ('app.private_workflow_string_array_valid_v1(jsonb,text,public.ticket_aggregate_kind)', false, false),
      ('app.private_workflow_condition_node_count_v1(jsonb,integer)', false, false),
      ('app.private_ticket_workflow_definition_valid_v1(public.ticket_aggregate_kind,jsonb,jsonb)', false, false),
      ('app.guard_ticket_workflow_command_update_v1()', true, false)
    ) AS expected(signature, security_definer, api_execute)
  LOOP
    function_oid := to_regprocedure(expected_function.signature);
    IF function_oid IS NULL THEN
      RETURN false;
    END IF;
    SELECT pg_get_userbyid(procedure.proowner), procedure.prosecdef,
           procedure.proconfig
    INTO function_owner, function_security_definer, function_configuration
    FROM pg_proc AS procedure WHERE procedure.oid = function_oid;
    IF function_owner IS DISTINCT FROM 'periapsis_migrator'
       OR function_security_definer
          IS DISTINCT FROM expected_function.security_definer
       OR function_configuration[1] NOT LIKE 'search_path=pg_catalog%'
       OR has_function_privilege('periapsis_api', function_oid, 'EXECUTE')
          IS DISTINCT FROM expected_function.api_execute
       OR has_function_privilege('periapsis_worker', function_oid, 'EXECUTE')
       OR has_function_privilege('periapsis_notifier', function_oid, 'EXECUTE')
       OR has_function_privilege('periapsis_auditor', function_oid, 'EXECUTE')
       OR EXISTS (
         SELECT 1 FROM aclexplode(
           coalesce(
             (SELECT procedure.proacl FROM pg_proc AS procedure
              WHERE procedure.oid = function_oid),
             acldefault('f',
               (SELECT procedure.proowner FROM pg_proc AS procedure
                WHERE procedure.oid = function_oid))
           )
         ) AS privilege
         WHERE privilege.grantee = 0
           AND privilege.privilege_type = 'EXECUTE'
       ) THEN
      RETURN false;
    END IF;
  END LOOP;

  IF NOT EXISTS (
    SELECT 1 FROM pg_trigger AS trigger_record
    WHERE trigger_record.tgname = 'ticket_workflow_versions_immutable_v1'
      AND NOT trigger_record.tgisinternal
      AND trigger_record.tgenabled = 'O'
  ) OR NOT EXISTS (
    SELECT 1 FROM pg_trigger AS trigger_record
    WHERE trigger_record.tgname = 'ticket_workflow_commands_immutable_v1'
      AND NOT trigger_record.tgisinternal
      AND trigger_record.tgenabled = 'O'
  ) THEN
    RETURN false;
  END IF;

  IF EXISTS (
    SELECT 1 FROM public.tenant_permissions AS permission
    WHERE permission.key IN ('workflow.read', 'workflow.manage')
      AND permission.service_account_allowed
  ) OR (
    SELECT count(*) FROM public.tenant_permissions AS permission
    JOIN public.tenant_permission_scopes AS scope
      ON scope.permission_id = permission.id
     AND scope.scope = 'tenant'
    WHERE permission.key IN ('workflow.read', 'workflow.manage')
  ) <> 2 OR EXISTS (
    SELECT 1
    FROM public.tenants AS tenant
    JOIN public.tenant_roles AS role
      ON role.tenant_id = tenant.id
     AND role.key = 'tenant_admin'
     AND role.principal_kind = 'human'
     AND role.system_role AND role.archived_at IS NULL
    CROSS JOIN public.tenant_permissions AS permission
    WHERE permission.key IN ('workflow.read', 'workflow.manage')
      AND (
        NOT EXISTS (
          SELECT 1 FROM public.tenant_role_permissions AS grant_record
          WHERE grant_record.tenant_id = tenant.id
            AND grant_record.role_id = role.id
            AND grant_record.permission_id = permission.id
            AND grant_record.scope = 'tenant'
        ) OR NOT EXISTS (
          SELECT 1
          FROM public.tenant_role_delegation_ceilings AS ceiling
          WHERE ceiling.tenant_id = tenant.id
            AND ceiling.role_id = role.id
            AND ceiling.permission_id = permission.id
            AND ceiling.scope = 'tenant'
        )
      )
  ) THEN
    RETURN false;
  END IF;

  SELECT pg_get_functiondef(
    'app.seed_tenant_authorization(uuid,uuid)'::regprocedure
  ) INTO seed_definition;
  IF seed_definition NOT LIKE
       '%seed_tenant_authorization_workflow_compatibility_impl%'
     OR seed_definition NOT LIKE
       '%private_seed_tenant_workflow_authorization_v1%' THEN
    RETURN false;
  END IF;

  SELECT compatibility.applied_count INTO current_count
  FROM app.schema_compatibility_v25() AS compatibility;
  SELECT compatibility.applied_count INTO predecessor_count
  FROM app.schema_compatibility_v24() AS compatibility;
  SELECT compatibility.applied_count INTO retired_count
  FROM app.schema_compatibility_v23() AS compatibility;
  RETURN current_count = 124 AND predecessor_count = 121
    AND retired_count = 0;
END;
$function$;
ALTER FUNCTION app.workflow_administration_schema_readiness_v1()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.workflow_administration_schema_readiness_v1()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,
  periapsis_sla_api_owner, periapsis_sla_worker_owner,
  periapsis_sla_readiness_owner;
GRANT EXECUTE ON FUNCTION app.workflow_administration_schema_readiness_v1()
TO periapsis_api;
