-- Freeze the additive tenant LDAP identity/access package before publishing
-- schema compatibility v8. This gate deliberately checks catalog privileges,
-- forced RLS, source/epoch consistency, and keyring dependency coverage.
DO $identity_access_readiness_assertions$
DECLARE
  relation_name text;
  relation_oid oid;
  runtime_role text;
  table_privilege text;
  column_privilege text;
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
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_catalog.pg_enum AS enum_value
    JOIN pg_catalog.pg_type AS enum_type ON enum_type.oid = enum_value.enumtypid
    JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = enum_type.typnamespace
    WHERE namespace.nspname = 'public'
      AND enum_type.typname = 'authorization_source_kind'
      AND enum_value.enumlabel = 'identity_provider_access'
  ) THEN
    RAISE EXCEPTION 'identity-provider access source kind is missing'
      USING ERRCODE = '55000';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM pg_catalog.pg_attribute AS attribute
    WHERE attribute.attrelid = 'public.users'::regclass
      AND attribute.attname = 'email'
      AND attribute.attnotnull
  ) THEN
    RAISE EXCEPTION 'global user email must remain nullable before federated admission'
      USING ERRCODE = '55000';
  END IF;

  FOREACH relation_name IN ARRAY ARRAY[
    'tenant_auth_provider_bindings',
    'tenant_identity_provider_access_epochs',
    'tenant_ldap_external_identities',
    'tenant_ldap_external_identity_subject_aliases',
    'tenant_ldap_provider_access_grants',
    'tenant_ldap_provider_profile_contributions',
    'tenant_user_manual_profile_overrides'
  ]::text[] LOOP
    relation_oid := pg_catalog.to_regclass('public.' || relation_name);
    IF relation_oid IS NULL OR NOT EXISTS (
      SELECT 1
      FROM pg_catalog.pg_class AS relation
      WHERE relation.oid = relation_oid
        AND relation.relrowsecurity
        AND relation.relforcerowsecurity
        AND pg_catalog.pg_get_userbyid(relation.relowner) = 'periapsis_migrator'
    ) OR EXISTS (
      SELECT 1
      FROM pg_catalog.pg_policy AS policy
      WHERE policy.polrelid = relation_oid
    ) THEN
      RAISE EXCEPTION 'identity-access relation % security boundary is not exact', relation_name
        USING ERRCODE = '55000';
    END IF;

    FOREACH runtime_role IN ARRAY ARRAY[
      'periapsis_api', 'periapsis_worker', 'periapsis_notifier',
      'periapsis_auditor'
    ]::text[] LOOP
      FOREACH table_privilege IN ARRAY ARRAY[
        'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE',
        'REFERENCES', 'TRIGGER'
      ]::text[] LOOP
        IF pg_catalog.has_table_privilege(
          runtime_role, relation_oid, table_privilege
        ) THEN
          RAISE EXCEPTION 'runtime role % has % on identity-access relation %',
            runtime_role, table_privilege, relation_name
            USING ERRCODE = '55000';
        END IF;
      END LOOP;
      FOREACH column_privilege IN ARRAY ARRAY[
        'SELECT', 'INSERT', 'UPDATE', 'REFERENCES'
      ]::text[] LOOP
        IF EXISTS (
          SELECT 1
          FROM pg_catalog.pg_attribute AS attribute
          WHERE attribute.attrelid = relation_oid
            AND attribute.attnum > 0
            AND NOT attribute.attisdropped
            AND pg_catalog.has_column_privilege(
              runtime_role, relation_oid, attribute.attname, column_privilege
            )
        ) THEN
          RAISE EXCEPTION 'runtime role % has column % on identity-access relation %',
            runtime_role, column_privilege, relation_name
            USING ERRCODE = '55000';
        END IF;
      END LOOP;
    END LOOP;
  END LOOP;

  IF EXISTS (
    SELECT 1
    FROM public.tenant_auth_provider_bindings AS binding
    LEFT JOIN public.tenant_identity_provider_access_epochs AS epoch
      ON epoch.tenant_id = binding.tenant_id
     AND epoch.id = binding.current_access_epoch_id
     AND epoch.binding_id = binding.id
     AND epoch.provider_id = binding.provider_id
    LEFT JOIN public.tenant_authorization_sources AS source
      ON source.tenant_id = epoch.tenant_id
     AND source.id = epoch.source_id
    WHERE binding.enabled IS DISTINCT FROM (
      binding.archived_at IS NULL
      AND epoch.id IS NOT NULL
      AND epoch.ended_at IS NULL
      AND source.kind = 'identity_provider_access'
      AND source.authoritative
      AND NOT source.protected
      AND source.retired_at IS NULL
    )
  ) OR EXISTS (
    SELECT 1
    FROM public.tenant_identity_provider_access_epochs AS epoch
    JOIN public.tenant_authorization_sources AS source
      ON source.tenant_id = epoch.tenant_id AND source.id = epoch.source_id
    WHERE source.kind <> 'identity_provider_access'
       OR NOT source.authoritative
       OR source.protected
       OR source.key <> format(
         'identity_provider_access:%s:%s', epoch.binding_id, epoch.sequence
       )
       OR ((epoch.ended_at IS NULL) <> (source.retired_at IS NULL))
  ) THEN
    RAISE EXCEPTION 'identity-provider binding/source epoch projection is inconsistent'
      USING ERRCODE = '55000';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM public.tenant_ldap_external_identities AS identity
    LEFT JOIN public.identity_keyring_versions AS keyring
      ON keyring.key_version = identity.key_version
    WHERE keyring.key_version IS NULL OR keyring.retired_at IS NOT NULL
  ) OR EXISTS (
    SELECT 1
    FROM public.tenant_ldap_external_identity_subject_aliases AS alias
    LEFT JOIN public.identity_keyring_versions AS keyring
      ON keyring.key_version = alias.digest_key_version
    WHERE alias.retired_at IS NULL
      AND (keyring.key_version IS NULL OR keyring.retired_at IS NOT NULL)
  ) OR EXISTS (
    SELECT 1
    FROM public.tenant_ldap_external_identities AS identity
    WHERE identity.retired_at IS NULL
      AND NOT EXISTS (
        SELECT 1
        FROM public.tenant_ldap_external_identity_subject_aliases AS alias
        JOIN public.identity_keyring_versions AS keyring
          ON keyring.key_version = alias.digest_key_version
         AND keyring.retired_at IS NULL
        WHERE alias.tenant_id = identity.tenant_id
          AND alias.provider_id = identity.provider_id
          AND alias.external_identity_id = identity.id
          AND alias.retired_at IS NULL
      )
  ) THEN
    RAISE EXCEPTION 'external-subject keyring dependency inventory is incomplete'
      USING ERRCODE = '55000';
  END IF;

  FOR expected_function IN
    SELECT *
    FROM (VALUES
      ('app.guard_tenant_auth_provider_binding_v1()', 'v'::"char", false, false),
      ('app.guard_tenant_identity_provider_access_epoch_v1()', 'v'::"char", false, false),
      ('app.guard_tenant_auth_provider_binding_dependency_v1()', 'v'::"char", false, false),
      ('app.guard_tenant_ldap_external_identity_v1()', 'v'::"char", false, false),
      ('app.guard_tenant_ldap_subject_alias_v1()', 'v'::"char", false, false),
      ('app.guard_tenant_ldap_provider_access_grant_v1()', 'v'::"char", false, false),
      ('app.guard_tenant_ldap_provider_profile_contribution_v1()', 'v'::"char", false, false),
      ('app.private_materialize_tenant_user_profile_v1(uuid,uuid)', 'v'::"char", false, false),
      ('app.private_close_tenant_identity_access_epoch_v1(uuid,uuid,uuid,text)', 'v'::"char", false, false),
      ('app.list_tenant_auth_provider_bindings_v1(uuid,boolean,integer)', 's'::"char", true, false),
      ('app.get_tenant_auth_provider_binding_v1(uuid)', 's'::"char", true, false),
      ('app.create_tenant_auth_provider_binding_v1(uuid,uuid,text,boolean,integer,uuid,uuid,inet,text,text)', 'v'::"char", true, false),
      ('app.update_tenant_auth_provider_binding_v1(uuid,integer,text,boolean,integer,uuid,uuid,inet,text,text)', 'v'::"char", true, false),
      ('app.archive_tenant_auth_provider_binding_v1(uuid,integer,text,uuid,uuid,inet,text,text)', 'v'::"char", true, false),
      ('app.verify_identity_keyring_v2(integer[],bytea[],integer)', 'v'::"char", true, true)
    ) AS manifest(signature, volatility, api_execute, worker_execute)
  LOOP
    function_oid := pg_catalog.to_regprocedure(expected_function.signature);
    IF function_oid IS NULL THEN
      RAISE EXCEPTION 'identity-access ABI function % is missing',
        expected_function.signature
        USING ERRCODE = '55000';
    END IF;

    SELECT pg_catalog.pg_get_userbyid(procedure.proowner),
           procedure.proconfig, procedure.provolatile, procedure.prosecdef,
           EXISTS (
             SELECT 1
             FROM pg_catalog.aclexplode(
               coalesce(
                 procedure.proacl,
                 pg_catalog.acldefault('f', procedure.proowner)
               )
             ) AS privilege
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
       OR NOT function_security_definer
       OR public_can_execute
       OR api_can_execute IS DISTINCT FROM expected_function.api_execute
       OR worker_can_execute IS DISTINCT FROM expected_function.worker_execute
       OR notifier_can_execute
       OR auditor_can_execute THEN
      RAISE EXCEPTION 'identity-access ABI function % security boundary is not exact',
        expected_function.signature
        USING ERRCODE = '55000';
    END IF;
  END LOOP;

  IF NOT pg_catalog.has_function_privilege(
       'periapsis_api',
       'app.list_tenant_auth_provider_bindings_v1(uuid,boolean,integer)',
       'EXECUTE'
     )
     OR NOT pg_catalog.has_function_privilege(
       'periapsis_api',
       'app.get_tenant_auth_provider_binding_v1(uuid)',
       'EXECUTE'
     )
     OR NOT pg_catalog.has_function_privilege(
       'periapsis_api',
       'app.create_tenant_auth_provider_binding_v1(uuid,uuid,text,boolean,integer,uuid,uuid,inet,text,text)',
       'EXECUTE'
     )
     OR NOT pg_catalog.has_function_privilege(
       'periapsis_api',
       'app.update_tenant_auth_provider_binding_v1(uuid,integer,text,boolean,integer,uuid,uuid,inet,text,text)',
       'EXECUTE'
     )
     OR NOT pg_catalog.has_function_privilege(
       'periapsis_api',
       'app.archive_tenant_auth_provider_binding_v1(uuid,integer,text,uuid,uuid,inet,text,text)',
       'EXECUTE'
     )
     OR NOT pg_catalog.has_function_privilege(
       'periapsis_api',
       'app.verify_identity_keyring_v2(integer[],bytea[],integer)',
       'EXECUTE'
     )
     OR NOT pg_catalog.has_function_privilege(
       'periapsis_worker',
       'app.verify_identity_keyring_v2(integer[],bytea[],integer)',
       'EXECUTE'
     ) THEN
    RAISE EXCEPTION 'identity-access ABI execute matrix is incomplete'
      USING ERRCODE = '55000';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM pg_catalog.pg_roles AS role
    WHERE role.rolname = ANY(ARRAY[
      'periapsis_api', 'periapsis_worker',
      'periapsis_notifier', 'periapsis_auditor'
    ]::pg_catalog.name[])
      AND (role.rolbypassrls OR role.rolsuper)
  ) THEN
    RAISE EXCEPTION 'identity-access runtime role boundary is not exact'
      USING ERRCODE = '55000';
  END IF;
END;
$identity_access_readiness_assertions$;--> statement-breakpoint

CREATE FUNCTION app.schema_compatibility_v8()
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
  migration_0053_rows bigint;
BEGIN
  EXECUTE $query$
    SELECT count(*)::bigint,
           max(migration.created_at)::bigint,
           count(*) FILTER (
             WHERE migration.created_at = 1787643609827
           )::bigint
    FROM drizzle.__drizzle_migrations AS migration
  $query$
  INTO journal_count, journal_latest_created_at, migration_0053_rows;

  IF journal_count = 54
     AND journal_latest_created_at = 1787643609827
     AND migration_0053_rows = 1 THEN
    RETURN QUERY EXECUTE $query$
      SELECT count(*)::bigint,
             max(migration.created_at)::bigint,
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
  RETURN QUERY SELECT 0::bigint, 0::bigint, 'UNSUPPORTED'::text, 'UNSUPPORTED'::text;
END;
$function$;--> statement-breakpoint

ALTER FUNCTION app.schema_compatibility_v8() OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.schema_compatibility_v8() FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.schema_compatibility_v8() TO periapsis_api, periapsis_worker;--> statement-breakpoint

-- The immediately preceding v7 binary may consume its sealed 51-row prefix;
-- package A is additive and does not enable LDAP login/JIT by itself.
CREATE OR REPLACE FUNCTION app.schema_compatibility_v7()
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
  SELECT compatibility.applied_count,
         compatibility.latest_created_at,
         compatibility.migration_fingerprint
  INTO full_count, full_latest_created_at, full_fingerprint
  FROM app.schema_compatibility_v8() AS compatibility;
  IF full_count = 54
     AND full_latest_created_at = 1787643609827
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
      SELECT count(*)::bigint,
             max(migration.created_at)::bigint,
             (SELECT prefix.migration_hash
              FROM ordered_migrations AS prefix
              WHERE prefix.migration_ordinal = 51),
             string_agg(
               migration.created_at::text || '@' || migration.migration_hash,
               ':' ORDER BY migration.created_at, migration.id
             )
      FROM ordered_migrations AS migration
      WHERE migration.migration_ordinal <= 51
    $query$;
    RETURN;
  END IF;
  RETURN QUERY SELECT 0::bigint, 0::bigint, 'UNSUPPORTED'::text, 'UNSUPPORTED'::text;
END;
$function$;--> statement-breakpoint

ALTER FUNCTION app.schema_compatibility_v7() OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.schema_compatibility_v7() FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.schema_compatibility_v7() TO periapsis_api, periapsis_worker;--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.schema_compatibility_v6()
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
  RETURN QUERY SELECT 0::bigint, 0::bigint, 'UNSUPPORTED'::text, 'UNSUPPORTED'::text;
END;
$function$;--> statement-breakpoint

ALTER FUNCTION app.schema_compatibility_v6() OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.schema_compatibility_v6() FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.schema_compatibility_v6() TO periapsis_api, periapsis_worker;--> statement-breakpoint

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
  fingerprint_entries := string_to_array(p_expected_migration_fingerprint, ':');
  IF p_expected_count IS DISTINCT FROM 54
     OR p_expected_latest_created_at IS DISTINCT FROM 1787643609827
     OR p_expected_latest_hash IS NULL
     OR p_expected_latest_hash !~ '^[0-9a-f]{64}$'
     OR p_expected_migration_fingerprint IS NULL
     OR p_expected_migration_fingerprint !~ '^[1-9][0-9]*@[0-9a-f]{64}(:[1-9][0-9]*@[0-9a-f]{64})*$'
     OR cardinality(fingerprint_entries) IS DISTINCT FROM 54
     OR fingerprint_entries[54] IS DISTINCT FROM (
       p_expected_latest_created_at::text || '@' || p_expected_latest_hash
     ) THEN
    RAISE EXCEPTION 'invalid schema compatibility v8 manifest'
      USING ERRCODE = '22023';
  END IF;

  SELECT array_agg(
    split_part(entry.value, '@', 1)::bigint ORDER BY entry.ordinality
  ) INTO fingerprint_created_at
  FROM unnest(fingerprint_entries) WITH ORDINALITY AS entry(value, ordinality);
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
    1787643153628, 1787643609827
  ]::bigint[] THEN
    RAISE EXCEPTION 'invalid schema compatibility v8 timestamp sequence'
      USING ERRCODE = '22023';
  END IF;

  SELECT compatibility.applied_count, compatibility.latest_created_at,
         compatibility.latest_hash, compatibility.migration_fingerprint
  INTO actual_count, actual_latest_created_at, actual_latest_hash,
       actual_fingerprint
  FROM app.schema_compatibility_v8() AS compatibility;
  IF actual_count IS DISTINCT FROM p_expected_count
     OR actual_latest_created_at IS DISTINCT FROM p_expected_latest_created_at
     OR actual_latest_hash IS DISTINCT FROM p_expected_latest_hash
     OR actual_fingerprint IS DISTINCT FROM p_expected_migration_fingerprint THEN
    RAISE EXCEPTION 'schema compatibility v8 manifest does not match the applied journal'
      USING ERRCODE = '55000';
  END IF;

  PERFORM set_config(
    'app.schema_compatibility_fingerprint', p_expected_migration_fingerprint, true
  );
  EXECUTE $statement$
    ALTER FUNCTION app.schema_compatibility_v7()
      SET app.schema_compatibility_fingerprint FROM CURRENT
  $statement$;
  expected_predecessor_hash := split_part(fingerprint_entries[51], '@', 2);
  expected_predecessor_fingerprint := array_to_string(
    fingerprint_entries[1:51], ':'
  );
  SELECT compatibility.applied_count, compatibility.latest_created_at,
         compatibility.latest_hash, compatibility.migration_fingerprint
  INTO predecessor_count, predecessor_latest_created_at,
       predecessor_latest_hash, predecessor_fingerprint
  FROM app.schema_compatibility_v7() AS compatibility;
  IF predecessor_count IS DISTINCT FROM 51
     OR predecessor_latest_created_at IS DISTINCT FROM 1787637795761
     OR predecessor_latest_hash IS DISTINCT FROM expected_predecessor_hash
     OR predecessor_fingerprint IS DISTINCT FROM expected_predecessor_fingerprint THEN
    RAISE EXCEPTION 'sealed schema compatibility v7 prefix is not exact'
      USING ERRCODE = '55000';
  END IF;

  SELECT compatibility.applied_count INTO retired_count
  FROM app.schema_compatibility_v6() AS compatibility;
  IF retired_count IS DISTINCT FROM 0 THEN
    RAISE EXCEPTION 'schema compatibility v6 must be retired'
      USING ERRCODE = '55000';
  END IF;
END;
$function$;--> statement-breakpoint

ALTER FUNCTION app.seal_schema_compatibility_manifest(bigint, bigint, text, text) OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.seal_schema_compatibility_manifest(bigint, bigint, text, text) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;
