-- Custom SQL migration file, put your code below! --
-- D4 seal: the bounded directory-operation boundary, its post-network pure
-- planner snapshot, mutation-safe projections and transient key inventory must
-- all be exact before a v10 binary can report ready.
DO $identity_directory_operation_readiness_assertions$
DECLARE
  relation_name text;
  relation_oid oid;
  runtime_role text;
  privilege_name text;
  constraint_name text;
  index_name text;
  index_oid oid;
  expected_function record;
  function_oid oid;
  function_owner text;
  function_configuration text[];
  function_volatility "char";
  function_security_definer boolean;
  public_can_execute boolean;
  api_can_execute boolean;
  worker_can_execute boolean;
  notifier_can_execute boolean;
  auditor_can_execute boolean;
  operation_kind_labels text[];
BEGIN
  SELECT array_agg(enum_value.enumlabel::text ORDER BY enum_value.enumsortorder)
  INTO operation_kind_labels
  FROM pg_catalog.pg_enum AS enum_value
  JOIN pg_catalog.pg_type AS enum_type
    ON enum_type.oid = enum_value.enumtypid
  JOIN pg_catalog.pg_namespace AS namespace
    ON namespace.oid = enum_type.typnamespace
  WHERE namespace.nspname = 'public'
    AND enum_type.typname = 'ldap_directory_operation_kind';
  IF operation_kind_labels IS DISTINCT FROM
       ARRAY['search_user', 'filter_user', 'filter_group']::text[]
     OR NOT EXISTS (
       SELECT 1
       FROM pg_catalog.pg_type AS enum_type
       JOIN pg_catalog.pg_namespace AS namespace
         ON namespace.oid = enum_type.typnamespace
       WHERE namespace.nspname = 'public'
         AND enum_type.typname = 'ldap_directory_operation_kind'
         AND pg_catalog.pg_get_userbyid(enum_type.typowner) =
             'periapsis_migrator'
     ) THEN
    RAISE EXCEPTION 'LDAP directory operation kind boundary is not exact'
      USING ERRCODE = '55000';
  END IF;

  FOREACH relation_name IN ARRAY ARRAY[
    'tenant_ldap_directory_operation_runs',
    'tenant_ldap_directory_run_mappings'
  ]::text[] LOOP
    relation_oid := pg_catalog.to_regclass('public.' || relation_name);
    IF relation_oid IS NULL OR NOT EXISTS (
      SELECT 1
      FROM pg_catalog.pg_class AS relation
      WHERE relation.oid = relation_oid
        AND relation.relrowsecurity
        AND relation.relforcerowsecurity
        AND pg_catalog.pg_get_userbyid(relation.relowner) =
            'periapsis_migrator'
    ) OR EXISTS (
      SELECT 1 FROM pg_catalog.pg_policy AS policy
      WHERE policy.polrelid = relation_oid
    ) THEN
      RAISE EXCEPTION 'LDAP directory relation % boundary is not exact',
        relation_name USING ERRCODE = '55000';
    END IF;

    FOREACH runtime_role IN ARRAY ARRAY[
      'periapsis_api', 'periapsis_worker', 'periapsis_notifier',
      'periapsis_auditor'
    ]::text[] LOOP
      FOREACH privilege_name IN ARRAY ARRAY[
        'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE',
        'REFERENCES', 'TRIGGER'
      ]::text[] LOOP
        IF pg_catalog.has_table_privilege(
          runtime_role, relation_oid, privilege_name
        ) THEN
          RAISE EXCEPTION 'runtime role % has % on LDAP directory relation %',
            runtime_role, privilege_name, relation_name
            USING ERRCODE = '55000';
        END IF;
      END LOOP;
      IF EXISTS (
        SELECT 1
        FROM pg_catalog.pg_attribute AS attribute
        WHERE attribute.attrelid = relation_oid
          AND attribute.attnum > 0
          AND NOT attribute.attisdropped
          AND (
            pg_catalog.has_column_privilege(
              runtime_role, relation_oid, attribute.attname, 'SELECT'
            ) OR pg_catalog.has_column_privilege(
              runtime_role, relation_oid, attribute.attname, 'INSERT'
            ) OR pg_catalog.has_column_privilege(
              runtime_role, relation_oid, attribute.attname, 'UPDATE'
            ) OR pg_catalog.has_column_privilege(
              runtime_role, relation_oid, attribute.attname, 'REFERENCES'
            )
          )
      ) THEN
        RAISE EXCEPTION 'runtime role % has column privilege on LDAP directory relation %',
          runtime_role, relation_name USING ERRCODE = '55000';
      END IF;
    END LOOP;
  END LOOP;

  FOREACH constraint_name IN ARRAY ARRAY[
    'tenant_ldap_directory_runs_provider_fk',
    'tenant_ldap_directory_runs_binding_fk',
    'tenant_ldap_directory_runs_access_epoch_fk',
    'tenant_ldap_directory_runs_starter_fk',
    'tenant_ldap_directory_runs_completer_fk',
    'tenant_ldap_directory_run_mappings_run_fk',
    'tenant_ldap_directory_run_mappings_rule_fk',
    'tenant_ldap_directory_run_mappings_epoch_fk'
  ]::text[] LOOP
    IF NOT EXISTS (
      SELECT 1
      FROM pg_catalog.pg_constraint AS constraint_record
      WHERE constraint_record.conname = constraint_name
        AND constraint_record.contype = 'f'
        AND constraint_record.convalidated
    ) THEN
      RAISE EXCEPTION 'LDAP directory composite constraint % is unavailable',
        constraint_name USING ERRCODE = '55000';
    END IF;
  END LOOP;

  FOREACH index_name IN ARRAY ARRAY[
    'tenant_ldap_directory_runs_provider_started_idx',
    'tenant_ldap_directory_runs_actor_started_idx',
    'tenant_ldap_directory_runs_status_started_idx',
    'tenant_ldap_directory_runs_key_version_idx',
    'tenant_ldap_directory_run_mappings_order_idx'
  ]::text[] LOOP
    index_oid := pg_catalog.to_regclass('public.' || index_name);
    IF index_oid IS NULL
       OR pg_catalog.pg_get_indexdef(index_oid, 1, true)
          IS DISTINCT FROM 'tenant_id' THEN
      RAISE EXCEPTION 'LDAP directory index % is not tenant-leading',
        index_name USING ERRCODE = '55000';
    END IF;
  END LOOP;

  IF NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_trigger AS trigger_record
    WHERE trigger_record.tgrelid =
          'public.tenant_ldap_mapping_rules'::regclass
      AND trigger_record.tgname =
          'tenant_ldap_mapping_rules_bump_rule_set_revision'
      AND trigger_record.tgenabled = 'O'
      AND NOT trigger_record.tgisinternal
  ) OR NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_trigger AS trigger_record
    WHERE trigger_record.tgrelid =
          'public.tenant_ldap_directory_operation_runs'::regclass
      AND trigger_record.tgname =
          'tenant_ldap_directory_operation_runs_guard'
      AND trigger_record.tgenabled = 'O'
      AND NOT trigger_record.tgisinternal
  ) OR NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_trigger AS trigger_record
    WHERE trigger_record.tgrelid =
          'public.tenant_ldap_directory_run_mappings'::regclass
      AND trigger_record.tgname =
          'tenant_ldap_directory_run_mappings_guard'
      AND trigger_record.tgenabled = 'O'
      AND NOT trigger_record.tgisinternal
  ) THEN
    RAISE EXCEPTION 'LDAP directory operation trigger boundary is incomplete'
      USING ERRCODE = '55000';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM public.tenant_ldap_directory_operation_runs AS operation
    LEFT JOIN public.identity_keyring_versions AS keyring
      ON keyring.key_version = operation.bind_secret_key_version
    WHERE operation.status = 'started'
      AND operation.expires_at > transaction_timestamp()
      AND (keyring.key_version IS NULL OR keyring.retired_at IS NOT NULL)
  ) OR EXISTS (
    SELECT 1
    FROM public.tenant_ldap_directory_operation_runs AS operation
    WHERE operation.status = 'completed'
      AND (
        (operation.category IN ('stale_configuration', 'cancelled')
         AND operation.endpoint_priority IS NOT NULL)
        OR (operation.category = 'success'
            AND operation.endpoint_priority IS NULL)
        OR (operation.category NOT IN (
              'success', 'stale_configuration', 'cancelled'
            ) AND operation.endpoint_priority IS NULL)
      )
  ) OR EXISTS (
    SELECT 1
    FROM public.tenant_ldap_directory_run_mappings AS pinned
    JOIN public.tenant_ldap_directory_operation_runs AS operation
      ON operation.tenant_id = pinned.tenant_id
     AND operation.id = pinned.operation_run_id
    WHERE operation.binding_id IS NULL
       OR operation.binding_id <> pinned.binding_id
       OR operation.operation_kind <> 'search_user'
  ) THEN
    RAISE EXCEPTION 'LDAP directory operation persisted state is inconsistent'
      USING ERRCODE = '55000';
  END IF;

  FOR expected_function IN
    SELECT * FROM (VALUES
      ('app.bump_tenant_ldap_mapping_rule_set_revision_v1()', 'v'::"char", false, false),
      ('app.guard_tenant_ldap_directory_operation_run_v1()', 'v'::"char", false, false),
      ('app.guard_tenant_ldap_directory_run_mapping_v1()', 'v'::"char", false, false),
      ('app.private_tenant_ldap_endpoint_snapshot_v1(uuid,uuid)', 's'::"char", false, false),
      ('app.private_tenant_ldap_directory_run_is_current_v1(uuid,uuid)', 's'::"char", false, false),
      ('app.private_begin_tenant_ldap_directory_operation_v1(uuid,uuid,public.ldap_directory_operation_kind,uuid,uuid[],text,uuid,uuid,uuid)', 'v'::"char", false, false),
      ('app.begin_tenant_ldap_administrative_search_v1(uuid,uuid,public.ldap_directory_operation_kind,text,uuid,uuid,uuid,inet,text,text)', 'v'::"char", true, false),
      ('app.begin_tenant_ldap_mapping_dry_run_v1(uuid,uuid,uuid[],text,uuid,uuid,uuid,inet,text,text)', 'v'::"char", true, false),
      ('app.complete_tenant_ldap_directory_operation_v1(uuid,public.ldap_provider_test_outcome,public.ldap_provider_test_category,integer,integer,integer,boolean,uuid,uuid,uuid,inet,text,text)', 'v'::"char", true, false),
      ('app.get_tenant_ldap_dry_run_planning_snapshot_v1(uuid,integer[],bytea[])', 's'::"char", true, false),
      ('app.get_tenant_auth_provider_binding_mutation_result_v1(uuid)', 's'::"char", true, false),
      ('app.get_tenant_ldap_mapping_rule_mutation_result_v1(uuid)', 's'::"char", true, false),
      ('app.create_tenant_ldap_mapping_rule_v2(bytea,uuid,public.ldap_mapping_matcher_type,text,public.ldap_mapping_case_mode,integer,uuid,public.ldap_mapping_reconciliation_mode,uuid[],uuid,uuid,text,text,uuid,uuid,uuid,inet,text,text)', 'v'::"char", true, false),
      ('app.verify_identity_keyring_v3(integer[],bytea[],integer)', 'v'::"char", true, true)
    ) AS manifest(signature, volatility, api_execute, worker_execute)
  LOOP
    function_oid := pg_catalog.to_regprocedure(expected_function.signature);
    IF function_oid IS NULL THEN
      RAISE EXCEPTION 'LDAP directory ABI function % is missing',
        expected_function.signature USING ERRCODE = '55000';
    END IF;
    SELECT pg_catalog.pg_get_userbyid(procedure.proowner),
           procedure.proconfig, procedure.provolatile, procedure.prosecdef,
           EXISTS (
             SELECT 1
             FROM pg_catalog.aclexplode(coalesce(
               procedure.proacl,
               pg_catalog.acldefault('f', procedure.proowner)
             )) AS privilege
             WHERE privilege.grantee = 0
               AND privilege.privilege_type = 'EXECUTE'
           ),
           pg_catalog.has_function_privilege(
             'periapsis_api', procedure.oid, 'EXECUTE'
           ),
           pg_catalog.has_function_privilege(
             'periapsis_worker', procedure.oid, 'EXECUTE'
           ),
           pg_catalog.has_function_privilege(
             'periapsis_notifier', procedure.oid, 'EXECUTE'
           ),
           pg_catalog.has_function_privilege(
             'periapsis_auditor', procedure.oid, 'EXECUTE'
           )
    INTO function_owner, function_configuration, function_volatility,
         function_security_definer, public_can_execute, api_can_execute,
         worker_can_execute, notifier_can_execute, auditor_can_execute
    FROM pg_catalog.pg_proc AS procedure
    WHERE procedure.oid = function_oid;
    IF function_owner IS DISTINCT FROM 'periapsis_migrator'
       OR function_configuration IS DISTINCT FROM
            ARRAY['search_path=pg_catalog, public, app']::text[]
       OR function_volatility IS DISTINCT FROM expected_function.volatility
       OR NOT function_security_definer OR public_can_execute
       OR api_can_execute IS DISTINCT FROM expected_function.api_execute
       OR worker_can_execute IS DISTINCT FROM expected_function.worker_execute
       OR notifier_can_execute OR auditor_can_execute THEN
      RAISE EXCEPTION 'LDAP directory ABI function % boundary is not exact',
        expected_function.signature USING ERRCODE = '55000';
    END IF;
  END LOOP;

  IF pg_catalog.has_function_privilege(
       'periapsis_api',
       'app.create_tenant_auth_provider_binding_v1(uuid,uuid,text,boolean,integer,uuid,uuid,inet,text,text)',
       'EXECUTE'
     ) OR pg_catalog.has_function_privilege(
       'periapsis_api',
       'app.create_tenant_ldap_mapping_rule_v1(bytea,uuid,public.ldap_mapping_matcher_type,text,public.ldap_mapping_case_mode,integer,uuid,public.ldap_mapping_reconciliation_mode,uuid[],uuid,uuid,text,text,uuid,uuid,uuid,inet,text,text)',
       'EXECUTE'
     ) OR pg_catalog.has_function_privilege(
       'periapsis_api',
       'app.verify_identity_keyring_v2(integer[],bytea[],integer)',
       'EXECUTE'
     ) OR pg_catalog.has_function_privilege(
       'periapsis_worker',
       'app.verify_identity_keyring_v2(integer[],bytea[],integer)',
       'EXECUTE'
     ) OR EXISTS (
       SELECT 1 FROM pg_catalog.pg_roles AS role
       WHERE role.rolname = ANY(ARRAY[
         'periapsis_api', 'periapsis_worker', 'periapsis_notifier',
         'periapsis_auditor'
       ]::pg_catalog.name[])
         AND (role.rolbypassrls OR role.rolsuper)
     ) THEN
    RAISE EXCEPTION 'LDAP directory predecessor/runtime boundary is not exact'
      USING ERRCODE = '55000';
  END IF;
END;
$identity_directory_operation_readiness_assertions$;--> statement-breakpoint

CREATE FUNCTION app.schema_compatibility_v10()
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
  migration_0064_rows bigint;
BEGIN
  EXECUTE $query$
    SELECT count(*)::bigint, max(migration.created_at)::bigint,
           count(*) FILTER (
             WHERE migration.created_at = 1787650730983
           )::bigint
    FROM drizzle.__drizzle_migrations AS migration
  $query$ INTO journal_count, journal_latest_created_at, migration_0064_rows;
  IF journal_count = 65
     AND journal_latest_created_at = 1787650730983
     AND migration_0064_rows = 1 THEN
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

ALTER FUNCTION app.schema_compatibility_v10()
  OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.schema_compatibility_v10()
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.schema_compatibility_v10()
  TO periapsis_api, periapsis_worker;--> statement-breakpoint

-- Only the immediately preceding v9 binary receives its sealed 59-row prefix.
CREATE OR REPLACE FUNCTION app.schema_compatibility_v9()
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
  FROM app.schema_compatibility_v10() AS compatibility;
  IF full_count = 65
     AND full_latest_created_at = 1787650730983
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
              WHERE prefix.migration_ordinal = 59),
             string_agg(
               migration.created_at::text || '@' || migration.migration_hash,
               ':' ORDER BY migration.created_at, migration.id
             )
      FROM ordered_migrations AS migration
      WHERE migration.migration_ordinal <= 59
    $query$;
    RETURN;
  END IF;
  RETURN QUERY SELECT 0::bigint, 0::bigint,
                      'UNSUPPORTED'::text, 'UNSUPPORTED'::text;
END;
$function$;--> statement-breakpoint

ALTER FUNCTION app.schema_compatibility_v9()
  OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.schema_compatibility_v9()
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.schema_compatibility_v9()
  TO periapsis_api, periapsis_worker;--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.schema_compatibility_v8()
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

ALTER FUNCTION app.schema_compatibility_v8()
  OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.schema_compatibility_v8()
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.schema_compatibility_v8()
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
  IF p_expected_count IS DISTINCT FROM 65
     OR p_expected_latest_created_at IS DISTINCT FROM 1787650730983
     OR p_expected_latest_hash IS NULL
     OR p_expected_latest_hash !~ '^[0-9a-f]{64}$'
     OR p_expected_migration_fingerprint IS NULL
     OR p_expected_migration_fingerprint !~
          '^[1-9][0-9]*@[0-9a-f]{64}(:[1-9][0-9]*@[0-9a-f]{64})*$'
     OR cardinality(fingerprint_entries) IS DISTINCT FROM 65
     OR fingerprint_entries[65] IS DISTINCT FROM (
       p_expected_latest_created_at::text || '@' || p_expected_latest_hash
     ) THEN
    RAISE EXCEPTION 'invalid schema compatibility v10 manifest'
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
    1787650730983
  ]::bigint[] THEN
    RAISE EXCEPTION 'invalid schema compatibility v10 timestamp sequence'
      USING ERRCODE = '22023';
  END IF;

  SELECT compatibility.applied_count, compatibility.latest_created_at,
         compatibility.latest_hash, compatibility.migration_fingerprint
  INTO actual_count, actual_latest_created_at, actual_latest_hash,
       actual_fingerprint
  FROM app.schema_compatibility_v10() AS compatibility;
  IF actual_count IS DISTINCT FROM p_expected_count
     OR actual_latest_created_at IS DISTINCT FROM
          p_expected_latest_created_at
     OR actual_latest_hash IS DISTINCT FROM p_expected_latest_hash
     OR actual_fingerprint IS DISTINCT FROM
          p_expected_migration_fingerprint THEN
    RAISE EXCEPTION 'schema compatibility v10 manifest does not match the applied journal'
      USING ERRCODE = '55000';
  END IF;

  PERFORM set_config(
    'app.schema_compatibility_fingerprint',
    p_expected_migration_fingerprint,
    true
  );
  EXECUTE $statement$
    ALTER FUNCTION app.schema_compatibility_v9()
      SET app.schema_compatibility_fingerprint FROM CURRENT
  $statement$;
  expected_predecessor_hash := split_part(
    fingerprint_entries[59], '@', 2
  );
  expected_predecessor_fingerprint := array_to_string(
    fingerprint_entries[1:59], ':'
  );
  SELECT compatibility.applied_count, compatibility.latest_created_at,
         compatibility.latest_hash, compatibility.migration_fingerprint
  INTO predecessor_count, predecessor_latest_created_at,
       predecessor_latest_hash, predecessor_fingerprint
  FROM app.schema_compatibility_v9() AS compatibility;
  IF predecessor_count IS DISTINCT FROM 59
     OR predecessor_latest_created_at IS DISTINCT FROM 1787648225321
     OR predecessor_latest_hash IS DISTINCT FROM expected_predecessor_hash
     OR predecessor_fingerprint IS DISTINCT FROM
          expected_predecessor_fingerprint THEN
    RAISE EXCEPTION 'sealed schema compatibility v9 prefix is not exact'
      USING ERRCODE = '55000';
  END IF;

  SELECT compatibility.applied_count INTO retired_count
  FROM app.schema_compatibility_v8() AS compatibility;
  IF retired_count IS DISTINCT FROM 0 THEN
    RAISE EXCEPTION 'schema compatibility v8 must be retired'
      USING ERRCODE = '55000';
  END IF;
END;
$function$;--> statement-breakpoint

ALTER FUNCTION app.seal_schema_compatibility_manifest(bigint, bigint, text, text)
  OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.seal_schema_compatibility_manifest(bigint, bigint, text, text)
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;
