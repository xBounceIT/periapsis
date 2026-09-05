DO $identity_jit_sync_readiness_assertions$
DECLARE
  expected_table record;
  expected_function record;
  expected_trigger record;
  relation_oid regclass;
  relation_owner text;
  relation_rls boolean;
  relation_force_rls boolean;
  policy_count integer;
  tenant_not_null boolean;
  function_oid regprocedure;
  function_owner text;
  function_configuration text[];
  function_volatility "char";
  function_security_definer boolean;
  public_can_execute boolean;
  api_can_execute boolean;
  worker_can_execute boolean;
  notifier_can_execute boolean;
  auditor_can_execute boolean;
BEGIN
  IF (
    SELECT array_agg(enum_value.enumlabel::text ORDER BY enum_value.enumsortorder)
    FROM pg_catalog.pg_enum AS enum_value
    JOIN pg_catalog.pg_type AS enum_type ON enum_type.oid = enum_value.enumtypid
    JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = enum_type.typnamespace
    WHERE namespace.nspname = 'public' AND enum_type.typname = 'ldap_jit_run_status'
  ) IS DISTINCT FROM ARRAY[
    'network_pending', 'planning', 'succeeded', 'denied', 'failed',
    'stale', 'expired'
  ]::text[] OR (
    SELECT array_agg(enum_value.enumlabel::text ORDER BY enum_value.enumsortorder)
    FROM pg_catalog.pg_enum AS enum_value
    JOIN pg_catalog.pg_type AS enum_type ON enum_type.oid = enum_value.enumtypid
    JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = enum_type.typnamespace
    WHERE namespace.nspname = 'public' AND enum_type.typname = 'ldap_sync_run_status'
  ) IS DISTINCT FROM ARRAY[
    'queued', 'enumerating', 'applying', 'succeeded', 'failed',
    'cancelled', 'stale'
  ]::text[] OR (
    SELECT array_agg(enum_value.enumlabel::text ORDER BY enum_value.enumsortorder)
    FROM pg_catalog.pg_enum AS enum_value
    JOIN pg_catalog.pg_type AS enum_type ON enum_type.oid = enum_value.enumtypid
    JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = enum_type.typnamespace
    WHERE namespace.nspname = 'public' AND enum_type.typname = 'auth_rate_limit_scope'
  ) IS DISTINCT FROM ARRAY[
    'bootstrap_totp', 'local_login', 'ldap_network', 'ldap_account',
    'ldap_provider', 'mfa_challenge', 'recovery_code', 'tenant_switch'
  ]::text[] THEN
    RAISE EXCEPTION 'LDAP JIT/sync enum contract is not exact'
      USING ERRCODE = '55000';
  END IF;

  FOR expected_table IN
    SELECT * FROM (VALUES
      ('tenant_ldap_jit_authentication_runs', 'tenant_ldap_jit_runs_migrator_all'),
      ('tenant_ldap_jit_run_mappings', 'tenant_ldap_jit_run_mappings_migrator_all'),
      ('tenant_ldap_sync_runs', 'tenant_ldap_sync_runs_migrator_all'),
      ('tenant_ldap_sync_run_mappings', 'tenant_ldap_sync_run_mappings_migrator_all'),
      ('tenant_ldap_sync_staged_observations', 'tenant_ldap_sync_staged_observations_migrator_all'),
      ('tenant_ldap_identity_plan_applications', 'tenant_ldap_identity_plan_applications_migrator_all'),
      ('tenant_ldap_sync_absences', 'tenant_ldap_sync_absences_migrator_all')
    ) AS expected(table_name, policy_name)
  LOOP
    relation_oid := to_regclass('public.' || expected_table.table_name);
    IF relation_oid IS NULL THEN
      RAISE EXCEPTION 'required LDAP JIT/sync relation % is absent',
        expected_table.table_name USING ERRCODE = '55000';
    END IF;
    SELECT pg_catalog.pg_get_userbyid(class.relowner), class.relrowsecurity,
           class.relforcerowsecurity
    INTO relation_owner, relation_rls, relation_force_rls
    FROM pg_catalog.pg_class AS class WHERE class.oid = relation_oid;
    SELECT attribute.attnotnull INTO tenant_not_null
    FROM pg_catalog.pg_attribute AS attribute
    WHERE attribute.attrelid = relation_oid
      AND attribute.attname = 'tenant_id' AND NOT attribute.attisdropped;
    SELECT count(*)::integer INTO policy_count
    FROM pg_catalog.pg_policy AS policy
    WHERE policy.polrelid = relation_oid
      AND policy.polname = expected_table.policy_name
      AND policy.polcmd = '*'
      AND policy.polroles = ARRAY[
        (SELECT role.oid FROM pg_catalog.pg_roles AS role
         WHERE role.rolname = 'periapsis_migrator')
      ]::oid[];
    IF relation_owner IS DISTINCT FROM 'periapsis_migrator'
       OR NOT relation_rls OR NOT relation_force_rls
       OR tenant_not_null IS DISTINCT FROM true OR policy_count <> 1
       OR (SELECT count(*) FROM pg_catalog.pg_policy AS policy
           WHERE policy.polrelid = relation_oid) <> 1
       OR EXISTS (
         SELECT 1 FROM pg_catalog.pg_constraint AS constraint_row
         WHERE constraint_row.conrelid = relation_oid
           AND NOT constraint_row.convalidated
       ) OR EXISTS (
         SELECT 1
         FROM unnest(ARRAY[
           'public', 'periapsis_api', 'periapsis_worker',
           'periapsis_notifier', 'periapsis_auditor'
         ]) AS runtime(role_name)
         WHERE pg_catalog.has_table_privilege(runtime.role_name, relation_oid, 'SELECT')
            OR pg_catalog.has_table_privilege(runtime.role_name, relation_oid, 'INSERT')
            OR pg_catalog.has_table_privilege(runtime.role_name, relation_oid, 'UPDATE')
            OR pg_catalog.has_table_privilege(runtime.role_name, relation_oid, 'DELETE')
            OR pg_catalog.has_table_privilege(runtime.role_name, relation_oid, 'TRUNCATE')
            OR pg_catalog.has_table_privilege(runtime.role_name, relation_oid, 'REFERENCES')
            OR pg_catalog.has_table_privilege(runtime.role_name, relation_oid, 'TRIGGER')
       ) THEN
      RAISE EXCEPTION 'LDAP JIT/sync relation % boundary is not exact',
        expected_table.table_name USING ERRCODE = '55000';
    END IF;
  END LOOP;

  IF EXISTS (
    SELECT 1
    FROM unnest(ARRAY[
      'bind_secret_id', 'bind_secret_version',
      'bind_secret_key_version', 'bind_secret_algorithm'
    ]) AS expected(column_name)
    LEFT JOIN pg_catalog.pg_attribute AS attribute
      ON attribute.attrelid = 'public.tenant_ldap_sync_runs'::regclass
     AND attribute.attname = expected.column_name
     AND NOT attribute.attisdropped
    WHERE attribute.attnotnull IS DISTINCT FROM true
  ) THEN
    RAISE EXCEPTION 'LDAP sync bind-secret pins are absent or nullable'
      USING ERRCODE = '55000';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM pg_catalog.pg_attribute AS attribute
    WHERE attribute.attrelid = ANY(ARRAY[
      'public.tenant_ldap_jit_authentication_runs'::regclass,
      'public.tenant_ldap_jit_run_mappings'::regclass,
      'public.tenant_ldap_sync_runs'::regclass,
      'public.tenant_ldap_sync_run_mappings'::regclass,
      'public.tenant_ldap_sync_staged_observations'::regclass,
      'public.tenant_ldap_identity_plan_applications'::regclass,
      'public.tenant_ldap_sync_absences'::regclass
    ]) AND NOT attribute.attisdropped
      AND attribute.attname = ANY(ARRAY[
        'password', 'bind_password', 'bind_dn', 'subject_value',
        'directory_value', 'distinguished_name', 'username', 'email',
        'display_name', 'first_name', 'last_name', 'raw_entry', 'raw_groups',
        'cursor'
      ])
  ) THEN
    RAISE EXCEPTION 'LDAP JIT/sync durable state contains a raw directory field'
      USING ERRCODE = '55000';
  END IF;

  FOR expected_trigger IN
    SELECT * FROM (VALUES
      ('tenant_ldap_jit_authentication_runs', 'tenant_ldap_jit_runs_guard'),
      ('tenant_ldap_jit_run_mappings', 'tenant_ldap_jit_run_mappings_guard'),
      ('tenant_ldap_sync_runs', 'tenant_ldap_sync_runs_guard_v1'),
      ('tenant_ldap_sync_run_mappings', 'tenant_ldap_sync_run_mappings_guard_v1'),
      ('tenant_ldap_sync_staged_observations', 'tenant_ldap_sync_staged_observations_guard_v1'),
      ('tenant_ldap_identity_plan_applications', 'tenant_ldap_identity_plan_applications_guard_v1'),
      ('tenant_ldap_sync_absences', 'tenant_ldap_sync_absences_guard_v1'),
      ('tenant_ldap_provider_access_grants', 'tenant_ldap_provider_access_grants_ownership_guard_v1')
    ) AS expected(table_name, trigger_name)
  LOOP
    IF NOT EXISTS (
      SELECT 1 FROM pg_catalog.pg_trigger AS trigger_row
      WHERE trigger_row.tgrelid = ('public.' || expected_trigger.table_name)::regclass
        AND trigger_row.tgname = expected_trigger.trigger_name
        AND trigger_row.tgenabled = 'O' AND NOT trigger_row.tgisinternal
    ) THEN
      RAISE EXCEPTION 'LDAP JIT/sync trigger % is absent or disabled',
        expected_trigger.trigger_name USING ERRCODE = '55000';
    END IF;
  END LOOP;

  FOR expected_function IN
    SELECT * FROM (VALUES
      ('app.private_append_tenant_ldap_runtime_audit_v1(uuid,uuid,text,text,uuid,uuid,uuid,inet,text,text,public.audit_outcome,text,jsonb)', 'v'::"char", false, false),
      ('app.apply_tenant_ldap_identity_plan_v1(uuid,bytea,public.ldap_identity_apply_mode,uuid,uuid,uuid,integer,integer,integer,integer,uuid,bigint,bigint,public.ldap_identity_apply_decision,text,uuid,uuid,uuid,uuid,uuid,public.identity_subject_format,bytea,bytea,integer,uuid[],integer[],bytea[],text,text,text,text,text,uuid[],timestamptz,uuid,uuid,uuid,inet,text)', 'v'::"char", true, true),
      ('app.private_tenant_ldap_sync_run_is_current_v1(uuid,uuid)', 's'::"char", false, false),
      ('app.private_begin_tenant_ldap_sync_run_v1(uuid,uuid,public.ldap_sync_trigger,text,uuid,uuid,uuid)', 'v'::"char", false, false),
      ('app.begin_tenant_ldap_manual_sync_run_v1(uuid,uuid,text,uuid,uuid,uuid,inet,text,text)', 'v'::"char", true, false),
      ('app.begin_tenant_ldap_scheduled_sync_run_v1(uuid,uuid,text,uuid,uuid,uuid,text)', 'v'::"char", false, true),
      ('app.start_tenant_ldap_sync_enumeration_v1(uuid,integer)', 'v'::"char", false, true),
      ('app.stage_tenant_ldap_sync_observation_v1(uuid,uuid,integer,integer,bytea,bytea)', 'v'::"char", false, true),
      ('app.complete_tenant_ldap_sync_enumeration_v1(uuid,integer,boolean,boolean,bytea,text,uuid,uuid,uuid,text)', 'v'::"char", false, true),
      ('app.apply_tenant_ldap_sync_absence_chunk_v1(uuid,integer,uuid,uuid,uuid,text)', 'v'::"char", false, true),
      ('app.complete_tenant_ldap_sync_run_v1(uuid,integer,uuid,uuid,uuid,text)', 'v'::"char", false, true),
      ('app.claim_next_tenant_ldap_sync_run_v1(text)', 'v'::"char", false, true),
      ('app.fail_tenant_ldap_sync_run_v1(uuid,integer,text,uuid,uuid,uuid,text)', 'v'::"char", false, true),
      ('app.private_tenant_ldap_jit_run_is_current_v1(uuid,uuid)', 's'::"char", false, false),
      ('app.private_get_tenant_ldap_jit_network_snapshot_v1(uuid,bytea)', 'v'::"char", false, false),
      ('app.begin_tenant_ldap_jit_authentication_v1(uuid,bytea,text,text,bytea,bytea,bytea,uuid,uuid,uuid,inet,text)', 'v'::"char", true, false),
      ('app.read_tenant_ldap_jit_network_snapshot_v1(uuid,bytea)', 'v'::"char", true, false),
      ('app.claim_tenant_ldap_jit_planning_v1(uuid,bytea,integer[],bytea[],uuid,uuid,uuid,inet,text)', 'v'::"char", true, false),
      ('app.apply_tenant_ldap_jit_identity_plan_v1(uuid,bytea,uuid,bytea,public.ldap_identity_apply_decision,text,uuid,uuid,uuid,uuid,uuid,public.identity_subject_format,bytea,bytea,integer,uuid[],integer[],bytea[],text,text,text,text,text,uuid[],timestamptz,uuid,uuid,uuid,inet,text)', 'v'::"char", true, false),
      ('app.complete_tenant_ldap_jit_authentication_v1(uuid,bytea,text,uuid,uuid,uuid,inet,text)', 'v'::"char", true, false),
      ('app.guard_tenant_ldap_jit_run_v1()', 'v'::"char", false, false),
      ('app.guard_tenant_ldap_jit_run_mapping_v1()', 'v'::"char", false, false),
      ('app.guard_tenant_ldap_sync_run_v1()', 'v'::"char", false, false),
      ('app.guard_tenant_ldap_sync_run_mapping_v1()', 'v'::"char", false, false),
      ('app.guard_tenant_ldap_sync_staged_observation_v1()', 'v'::"char", false, false),
      ('app.guard_tenant_ldap_identity_plan_application_v1()', 'v'::"char", false, false),
      ('app.guard_tenant_ldap_sync_absence_v1()', 'v'::"char", false, false),
      ('app.guard_tenant_ldap_access_grant_membership_ownership_v1()', 'v'::"char", false, false)
    ) AS expected(signature, volatility, api_execute, worker_execute)
  LOOP
    function_oid := to_regprocedure(expected_function.signature);
    IF function_oid IS NULL THEN
      RAISE EXCEPTION 'required LDAP JIT/sync ABI function % is absent',
        expected_function.signature USING ERRCODE = '55000';
    END IF;
    SELECT pg_catalog.pg_get_userbyid(procedure.proowner), procedure.proconfig,
           procedure.provolatile, procedure.prosecdef,
           pg_catalog.has_function_privilege('public', procedure.oid, 'EXECUTE'),
           pg_catalog.has_function_privilege('periapsis_api', procedure.oid, 'EXECUTE'),
           pg_catalog.has_function_privilege('periapsis_worker', procedure.oid, 'EXECUTE'),
           pg_catalog.has_function_privilege('periapsis_notifier', procedure.oid, 'EXECUTE'),
           pg_catalog.has_function_privilege('periapsis_auditor', procedure.oid, 'EXECUTE')
    INTO function_owner, function_configuration, function_volatility,
         function_security_definer, public_can_execute, api_can_execute,
         worker_can_execute, notifier_can_execute, auditor_can_execute
    FROM pg_catalog.pg_proc AS procedure WHERE procedure.oid = function_oid;
    IF function_owner IS DISTINCT FROM 'periapsis_migrator'
       OR function_configuration IS DISTINCT FROM
            ARRAY['search_path=pg_catalog, public, app']::text[]
       OR function_volatility IS DISTINCT FROM expected_function.volatility
       OR NOT function_security_definer OR public_can_execute
       OR api_can_execute IS DISTINCT FROM expected_function.api_execute
       OR worker_can_execute IS DISTINCT FROM expected_function.worker_execute
       OR notifier_can_execute OR auditor_can_execute THEN
      RAISE EXCEPTION 'LDAP JIT/sync ABI function % boundary is not exact',
        expected_function.signature USING ERRCODE = '55000';
    END IF;
  END LOOP;

  IF EXISTS (
    SELECT 1 FROM pg_catalog.pg_roles AS role
    WHERE role.rolname = ANY(ARRAY[
      'periapsis_api', 'periapsis_worker', 'periapsis_notifier',
      'periapsis_auditor'
    ]::pg_catalog.name[]) AND (role.rolbypassrls OR role.rolsuper)
  ) OR EXISTS (
    SELECT 1
    FROM public.tenant_ldap_identity_plan_applications AS application
    WHERE application.decision = 'denied'
      AND (application.external_identity_id IS NOT NULL
        OR application.user_id IS NOT NULL
        OR application.membership_id IS NOT NULL
        OR application.access_grant_id IS NOT NULL
        OR application.ensured_edge_count <> 0
        OR application.revoked_edge_count <> 0)
  ) OR EXISTS (
    SELECT 1
    FROM public.tenant_ldap_mapping_rule_role_targets AS target
    JOIN public.tenant_roles AS role
      ON role.tenant_id = target.tenant_id AND role.id = target.role_id
    LEFT JOIN public.tenant_role_permissions AS policy
      ON policy.tenant_id = role.tenant_id AND policy.role_id = role.id
     AND policy.scope = 'platform'
    WHERE role.principal_kind <> 'human'
       OR role.key = 'platform_super_admin'
       OR policy.role_id IS NOT NULL
  ) THEN
    RAISE EXCEPTION 'LDAP JIT/sync privilege or denial invariant is not exact'
      USING ERRCODE = '55000';
  END IF;
END;
$identity_jit_sync_readiness_assertions$;--> statement-breakpoint

CREATE FUNCTION app.schema_compatibility_v11()
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
  migration_0075_rows bigint;
BEGIN
  EXECUTE $query$
    SELECT count(*)::bigint, max(migration.created_at)::bigint,
           count(*) FILTER (
             WHERE migration.created_at = 1787655824109
           )::bigint
    FROM drizzle.__drizzle_migrations AS migration
  $query$ INTO journal_count, journal_latest_created_at, migration_0075_rows;
  IF journal_count = 76
     AND journal_latest_created_at = 1787655824109
     AND migration_0075_rows = 1 THEN
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

ALTER FUNCTION app.schema_compatibility_v11()
  OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.schema_compatibility_v11()
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.schema_compatibility_v11()
  TO periapsis_api, periapsis_worker;--> statement-breakpoint

-- v10 remains the sole supported predecessor and exposes its sealed 65-row
-- prefix only when the complete v11 journal is exact.
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
  FROM app.schema_compatibility_v11() AS compatibility;
  IF full_count = 76
     AND full_latest_created_at = 1787655824109
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
              WHERE prefix.migration_ordinal = 65),
             string_agg(
               migration.created_at::text || '@' || migration.migration_hash,
               ':' ORDER BY migration.created_at, migration.id
             )
      FROM ordered_migrations AS migration
      WHERE migration.migration_ordinal <= 65
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
AS $function$
BEGIN
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
  IF p_expected_count IS DISTINCT FROM 76
     OR p_expected_latest_created_at IS DISTINCT FROM 1787655824109
     OR p_expected_latest_hash IS NULL
     OR p_expected_latest_hash !~ '^[0-9a-f]{64}$'
     OR p_expected_migration_fingerprint IS NULL
     OR p_expected_migration_fingerprint !~
          '^[1-9][0-9]*@[0-9a-f]{64}(:[1-9][0-9]*@[0-9a-f]{64})*$'
     OR cardinality(fingerprint_entries) IS DISTINCT FROM 76
     OR fingerprint_entries[76] IS DISTINCT FROM (
       p_expected_latest_created_at::text || '@' || p_expected_latest_hash
     ) THEN
    RAISE EXCEPTION 'invalid schema compatibility v11 manifest'
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
    1787655197869, 1787655813403, 1787655819028, 1787655824109
  ]::bigint[] THEN
    RAISE EXCEPTION 'invalid schema compatibility v11 timestamp sequence'
      USING ERRCODE = '22023';
  END IF;

  SELECT compatibility.applied_count, compatibility.latest_created_at,
         compatibility.latest_hash, compatibility.migration_fingerprint
  INTO actual_count, actual_latest_created_at, actual_latest_hash,
       actual_fingerprint
  FROM app.schema_compatibility_v11() AS compatibility;
  IF actual_count IS DISTINCT FROM p_expected_count
     OR actual_latest_created_at IS DISTINCT FROM p_expected_latest_created_at
     OR actual_latest_hash IS DISTINCT FROM p_expected_latest_hash
     OR actual_fingerprint IS DISTINCT FROM p_expected_migration_fingerprint THEN
    RAISE EXCEPTION 'schema compatibility v11 manifest does not match the applied journal'
      USING ERRCODE = '55000';
  END IF;

  PERFORM set_config(
    'app.schema_compatibility_fingerprint',
    p_expected_migration_fingerprint, true
  );
  EXECUTE $statement$
    ALTER FUNCTION app.schema_compatibility_v10()
      SET app.schema_compatibility_fingerprint FROM CURRENT
  $statement$;
  expected_predecessor_hash := split_part(fingerprint_entries[65], '@', 2);
  expected_predecessor_fingerprint := array_to_string(
    fingerprint_entries[1:65], ':'
  );
  SELECT compatibility.applied_count, compatibility.latest_created_at,
         compatibility.latest_hash, compatibility.migration_fingerprint
  INTO predecessor_count, predecessor_latest_created_at,
       predecessor_latest_hash, predecessor_fingerprint
  FROM app.schema_compatibility_v10() AS compatibility;
  IF predecessor_count IS DISTINCT FROM 65
     OR predecessor_latest_created_at IS DISTINCT FROM 1787650730983
     OR predecessor_latest_hash IS DISTINCT FROM expected_predecessor_hash
     OR predecessor_fingerprint IS DISTINCT FROM expected_predecessor_fingerprint THEN
    RAISE EXCEPTION 'sealed schema compatibility v10 prefix is not exact'
      USING ERRCODE = '55000';
  END IF;
  SELECT compatibility.applied_count INTO retired_count
  FROM app.schema_compatibility_v9() AS compatibility;
  IF retired_count IS DISTINCT FROM 0 THEN
    RAISE EXCEPTION 'schema compatibility v9 must be retired'
      USING ERRCODE = '55000';
  END IF;
END;
$function$;--> statement-breakpoint

ALTER FUNCTION app.seal_schema_compatibility_manifest(bigint, bigint, text, text)
  OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.seal_schema_compatibility_manifest(bigint, bigint, text, text)
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;
