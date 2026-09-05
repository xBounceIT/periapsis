-- V44 is a coordinated fail-closed cutover. V43 remains immutable predecessor
-- evidence, but it does not attest the v44 ticket mutation, SLA action,
-- local-account, bulk/export, and Alert DFIR runtime surfaces. Old binaries
-- reject the advanced journal before any v44 writer becomes admissible.
CREATE FUNCTION app.schema_compatibility_v44()
RETURNS TABLE(
  applied_count bigint,latest_created_at bigint,latest_hash text,
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
  latest_rows bigint;
  journal_fingerprint text;
  self_catalog_ready boolean;
BEGIN
  EXECUTE $query$
    SELECT count(*)::bigint,max(migration.created_at)::bigint,
           count(*) FILTER (
             WHERE migration.created_at = 1788126621907
           )::bigint,
           string_agg(
             migration.created_at::text || '@' || lower(migration.hash::text),
             ':' ORDER BY migration.created_at,migration.id
           )
    FROM drizzle.__drizzle_migrations AS migration
  $query$ INTO journal_count,journal_latest_created_at,latest_rows,
                journal_fingerprint;
  SELECT count(*)=1 INTO self_catalog_ready
  FROM pg_catalog.pg_proc AS function_row
  JOIN pg_catalog.pg_namespace AS namespace
    ON namespace.oid=function_row.pronamespace
  JOIN pg_catalog.pg_roles AS owner ON owner.oid=function_row.proowner
  JOIN pg_catalog.pg_language AS language ON language.oid=function_row.prolang
  WHERE function_row.oid='app.schema_compatibility_v44()'::regprocedure
    AND namespace.nspname='app' AND owner.rolname='periapsis_migrator'
    AND language.lanname='plpgsql' AND function_row.prokind='f'
    AND function_row.provolatile='s' AND function_row.prosecdef
    AND NOT function_row.proisstrict AND NOT function_row.proleakproof
    AND function_row.proparallel='u' AND function_row.pronargs=0
    AND function_row.proconfig IS NOT DISTINCT FROM ARRAY[
      'search_path=pg_catalog',
      'app.schema_compatibility_fingerprint=' || journal_fingerprint
    ]::text[]
    AND pg_catalog.pg_get_function_result(function_row.oid)=
      'TABLE(applied_count bigint, latest_created_at bigint, latest_hash text, migration_fingerprint text)'
    AND (
      SELECT count(*)=3 AND coalesce(bool_and(
        function_acl.grantor=function_row.proowner
        AND function_acl.grantee IN (
          function_row.proowner,
          (SELECT role.oid FROM pg_catalog.pg_roles AS role
           WHERE role.rolname='periapsis_api'),
          (SELECT role.oid FROM pg_catalog.pg_roles AS role
           WHERE role.rolname='periapsis_worker')
        ) AND function_acl.privilege_type='EXECUTE'
        AND NOT function_acl.is_grantable
      ),false)
      FROM pg_catalog.aclexplode(CASE WHEN pg_catalog.cardinality(coalesce(
        function_row.proacl,pg_catalog.acldefault('f',function_row.proowner)
      ))>0 THEN coalesce(
        function_row.proacl,pg_catalog.acldefault('f',function_row.proowner)
      ) ELSE NULL::pg_catalog.aclitem[] END) AS function_acl
    );
  IF journal_count=197 AND journal_latest_created_at=1788126621907
     AND latest_rows=1 AND self_catalog_ready
     AND journal_fingerprint=current_setting(
       'app.schema_compatibility_fingerprint',true
     ) THEN
    RETURN QUERY EXECUTE $query$
      SELECT count(*)::bigint,max(migration.created_at)::bigint,
             (SELECT lower(latest.hash::text)
              FROM drizzle.__drizzle_migrations AS latest
              ORDER BY latest.created_at DESC,latest.id DESC LIMIT 1),
             string_agg(
               migration.created_at::text || '@' || lower(migration.hash::text),
               ':' ORDER BY migration.created_at,migration.id
             )
      FROM drizzle.__drizzle_migrations AS migration
    $query$;
    RETURN;
  END IF;
  RETURN QUERY SELECT 0::bigint,0::bigint,
    'UNSUPPORTED'::text,'UNSUPPORTED'::text;
END;
$function$;
ALTER FUNCTION app.schema_compatibility_v44() OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.schema_compatibility_v44()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier;
GRANT EXECUTE ON FUNCTION app.schema_compatibility_v44()
  TO periapsis_api,periapsis_worker;
--> statement-breakpoint

CREATE FUNCTION app.ticket_mutation_runtime_schema_readiness_v1()
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path=pg_catalog,public,app
SET quote_all_identifiers=off
SET TimeZone='UTC'
SET DateStyle='ISO, YMD'
SET IntervalStyle='postgres'
SET extra_float_digits=3
SET bytea_output='hex'
SET standard_conforming_strings=on
SET lc_numeric='C'
AS $function$
DECLARE
  catalog_ready boolean;
BEGIN
  SELECT count(*)=5 AND coalesce(bool_and(
    owner.rolname='periapsis_migrator'
    AND language.lanname IN ('sql','plpgsql')
    AND function_row.prokind='f'
    AND function_row.prosecdef
    AND function_row.provolatile=expected.volatility
    AND NOT function_row.proisstrict
    AND NOT function_row.proleakproof
    AND function_row.proparallel='u'
    AND function_row.proconfig @> ARRAY[
      'search_path=pg_catalog, public, app'
    ]::text[]
    AND (
      SELECT count(*)=1
        + expected.api_callable::integer
        + expected.worker_callable::integer
        AND coalesce(bool_and(
          function_acl.grantor=function_row.proowner
          AND function_acl.privilege_type='EXECUTE'
          AND NOT function_acl.is_grantable
          AND function_acl.grantee IN (
            function_row.proowner,
            CASE WHEN expected.api_callable THEN
              (SELECT role.oid FROM pg_catalog.pg_roles AS role
               WHERE role.rolname='periapsis_api')
            ELSE function_row.proowner END,
            CASE WHEN expected.worker_callable THEN
              (SELECT role.oid FROM pg_catalog.pg_roles AS role
               WHERE role.rolname='periapsis_worker')
            ELSE function_row.proowner END
          )
        ),false)
      FROM pg_catalog.aclexplode(CASE WHEN pg_catalog.cardinality(coalesce(
        function_row.proacl,
        pg_catalog.acldefault('f',function_row.proowner)
      ))>0 THEN coalesce(
        function_row.proacl,
        pg_catalog.acldefault('f',function_row.proowner)
      ) ELSE NULL::pg_catalog.aclitem[] END) AS function_acl
    )
  ),false) INTO catalog_ready
  FROM (VALUES
    ('app.lookup_tenant_alert_delete_replay_v1(uuid,bytea,bytea)',
      'v'::"char",true,false),
    ('app.delete_tenant_alert_v1(uuid,bigint,text,bytea,bytea,uuid,uuid,inet,text,text)',
      'v'::"char",true,false),
    ('app.private_current_alert_dfir_scope_allows_v1(text,uuid)',
      's'::"char",false,false),
    ('app.commit_tenant_ticket_escalation_v3(uuid,uuid,boolean,jsonb,jsonb,text,text,bytea,bytea,text[],uuid,uuid,inet,text,text)',
      'v'::"char",true,false),
    ('app.ticket_mutation_runtime_schema_readiness_v1()',
      's'::"char",true,true)
  ) AS expected(signature,volatility,api_callable,worker_callable)
  JOIN pg_catalog.pg_proc AS function_row
    ON function_row.oid=expected.signature::regprocedure
  JOIN pg_catalog.pg_roles AS owner ON owner.oid=function_row.proowner
  JOIN pg_catalog.pg_language AS language ON language.oid=function_row.prolang;
  IF NOT catalog_ready THEN RETURN false; END IF;

  SELECT count(*)=3 AND coalesce(bool_and(
    attribute.attnum>0 AND NOT attribute.attisdropped
    AND pg_catalog.format_type(attribute.atttypid,attribute.atttypmod)
      = expected.data_type
  ),false) INTO catalog_ready
  FROM (VALUES
    ('deleted_at','timestamp with time zone'),
    ('deleted_by_membership_id','uuid'),
    ('deletion_reason','text')
  ) AS expected(column_name,data_type)
  JOIN pg_catalog.pg_attribute AS attribute
    ON attribute.attrelid='public.alerts'::regclass
   AND attribute.attname=expected.column_name;
  IF NOT catalog_ready THEN RETURN false; END IF;

  IF NOT EXISTS (
    SELECT 1
    FROM pg_catalog.pg_constraint AS constraint_row
    WHERE constraint_row.conrelid='public.alerts'::regclass
      AND constraint_row.conname='alerts_tombstone_shape_check'
      AND constraint_row.contype='c'
      AND constraint_row.convalidated
      AND pg_catalog.pg_get_constraintdef(constraint_row.oid) LIKE
        '%deleted_at IS NULL%deleted_at IS NOT NULL%deleted_by_membership_id IS NOT NULL%deletion_reason IS NOT NULL%'
  ) OR NOT EXISTS (
    SELECT 1
    FROM pg_catalog.pg_index AS index_row
    JOIN pg_catalog.pg_class AS index_class
      ON index_class.oid=index_row.indexrelid
    WHERE index_row.indrelid='public.alerts'::regclass
      AND index_class.relname='alerts_tenant_live_id_idx'
      AND index_row.indisvalid AND index_row.indisready
      AND pg_catalog.pg_get_expr(
        index_row.indpred,index_row.indrelid,true
      )='deleted_at IS NULL'
  ) OR NOT EXISTS (
    SELECT 1
    FROM pg_catalog.pg_trigger AS trigger_row
    WHERE trigger_row.tgrelid='public.alerts'::regclass
      AND trigger_row.tgname='alerts_soft_delete_guard_v1'
      AND NOT trigger_row.tgisinternal
      AND trigger_row.tgenabled='O'
      AND trigger_row.tgfoid='app.guard_alert_soft_delete_v1()'::regprocedure
  ) THEN
    RETURN false;
  END IF;

  IF NOT EXISTS (
    SELECT 1
    FROM public.tenant_permissions AS permission
    WHERE permission.key='alert.delete'
      AND NOT permission.service_account_allowed
      AND (
        SELECT array_agg(scope.scope ORDER BY scope.scope)::text[]
        FROM public.tenant_permission_scopes AS scope
        WHERE scope.permission_id=permission.id
      )=ARRAY['assigned','operator_team','tenant']::text[]
  ) THEN
    RETURN false;
  END IF;

  SELECT count(*)=2 AND coalesce(bool_and(
    relation.relrowsecurity AND relation.relforcerowsecurity
    AND owner.rolname='periapsis_migrator'
    AND NOT pg_catalog.has_table_privilege(
      'periapsis_api',relation.oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
    )
    AND NOT pg_catalog.has_table_privilege(
      'periapsis_worker',relation.oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
    )
    AND NOT pg_catalog.has_table_privilege(
      'periapsis_notifier',relation.oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
    )
  ),false) INTO catalog_ready
  FROM pg_catalog.pg_class AS relation
  JOIN pg_catalog.pg_roles AS owner ON owner.oid=relation.relowner
  WHERE relation.oid IN (
    'public.alerts'::regclass,
    'public.dfir_attachment_case_links'::regclass
  );
  RETURN catalog_ready;
EXCEPTION WHEN undefined_table OR undefined_function OR insufficient_privilege
  OR invalid_schema_name OR cardinality_violation OR data_exception THEN
  RETURN false;
END;
$function$;
ALTER FUNCTION app.ticket_mutation_runtime_schema_readiness_v1()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.ticket_mutation_runtime_schema_readiness_v1()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier;
GRANT EXECUTE ON FUNCTION app.ticket_mutation_runtime_schema_readiness_v1()
  TO periapsis_api,periapsis_worker;
--> statement-breakpoint

-- The SLA readiness root is deliberately owned by the isolated readiness
-- role and callable at runtime only by the worker. The NOLOGIN migration role
-- receives the narrow execute edge needed by the compatibility sealer; no
-- application login or role membership is broadened.
GRANT EXECUTE ON FUNCTION app.sla_trigger_action_runtime_schema_readiness_v1()
  TO periapsis_migrator;
--> statement-breakpoint

-- Install the final sealer source before deriving the v44 dependency surface,
-- so every private readiness root binds the post-seal catalog in one pass.
CREATE OR REPLACE FUNCTION app.seal_schema_compatibility_manifest(
  p_expected_count bigint,p_expected_latest_created_at bigint,
  p_expected_latest_hash text,p_expected_migration_fingerprint text
)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public,app AS $function$
DECLARE
  journal_count bigint;
  journal_latest_created_at bigint;
  journal_latest_hash text;
  journal_fingerprint text;
  sealed_count bigint;
BEGIN
  IF p_expected_count IS DISTINCT FROM 197
     OR p_expected_latest_created_at IS DISTINCT FROM 1788126621907
     OR p_expected_latest_hash !~ '^[0-9a-f]{64}$'
     OR p_expected_migration_fingerprint !~
       '^[0-9]+@[0-9a-f]{64}(:[0-9]+@[0-9a-f]{64}){196}$' THEN
    RAISE EXCEPTION 'schema compatibility v44 seal input is invalid'
      USING ERRCODE='55000';
  END IF;
  EXECUTE $query$
    SELECT count(*)::bigint,max(migration.created_at)::bigint,
      (SELECT lower(latest.hash::text)
       FROM drizzle.__drizzle_migrations AS latest
       ORDER BY latest.created_at DESC,latest.id DESC LIMIT 1),
      string_agg(migration.created_at::text || '@' || lower(migration.hash::text),
        ':' ORDER BY migration.created_at,migration.id)
    FROM drizzle.__drizzle_migrations AS migration
  $query$ INTO journal_count,journal_latest_created_at,journal_latest_hash,
                journal_fingerprint;
  IF ROW(journal_count,journal_latest_created_at,journal_latest_hash,
         journal_fingerprint) IS DISTINCT FROM
     ROW(p_expected_count,p_expected_latest_created_at,p_expected_latest_hash,
         p_expected_migration_fingerprint)
     OR NOT app.private_mfa_policy_administration_schema_readiness_v4()
     OR NOT app.private_platform_identity_runtime_schema_readiness_v10()
     OR NOT app.private_platform_oidc_direct_runtime_schema_readiness_v6()
     OR NOT app.private_platform_saml_direct_runtime_schema_readiness_v3()
     OR NOT app.ticket_mutation_runtime_schema_readiness_v1()
     OR NOT app.sla_trigger_action_runtime_schema_readiness_v1()
     OR NOT app.platform_local_account_runtime_schema_readiness_v1()
     OR NOT app.ticket_bulk_runtime_schema_readiness_v1()
     OR NOT app.ticket_export_runtime_schema_readiness_v1()
     OR NOT app.alert_dfir_runtime_schema_readiness_v1() THEN
    RAISE EXCEPTION 'schema compatibility v44 pre-seal verification failed'
      USING ERRCODE='55000';
  END IF;
  EXECUTE pg_catalog.format(
    'ALTER FUNCTION app.schema_compatibility_v44() SET app.schema_compatibility_fingerprint = %L',
    p_expected_migration_fingerprint
  );
  ALTER FUNCTION app.schema_compatibility_v43()
    SET app.schema_compatibility_fingerprint='RETIRED';
  REVOKE ALL ON FUNCTION app.schema_compatibility_v43()
    FROM periapsis_api,periapsis_worker;
  REVOKE ALL ON FUNCTION app.platform_identity_runtime_schema_readiness_v9()
    FROM periapsis_api,periapsis_worker;
  REVOKE ALL ON FUNCTION app.platform_oidc_direct_runtime_schema_readiness_v5()
    FROM periapsis_api,periapsis_worker;
  REVOKE ALL ON FUNCTION app.platform_saml_direct_runtime_schema_readiness_v2()
    FROM periapsis_api,periapsis_worker;
  REVOKE ALL ON FUNCTION app.mfa_policy_administration_schema_readiness_v3()
    FROM periapsis_api,periapsis_worker;
  SELECT compatibility.applied_count INTO sealed_count
  FROM app.schema_compatibility_v44() AS compatibility;
  IF sealed_count<>197
     OR NOT app.mfa_policy_administration_schema_readiness_v4()
     OR NOT app.platform_identity_runtime_schema_readiness_v10()
     OR NOT app.platform_oidc_direct_runtime_schema_readiness_v6()
     OR NOT app.platform_saml_direct_runtime_schema_readiness_v3()
     OR NOT app.ticket_mutation_runtime_schema_readiness_v1()
     OR NOT app.sla_trigger_action_runtime_schema_readiness_v1()
     OR NOT app.platform_local_account_runtime_schema_readiness_v1()
     OR NOT app.ticket_bulk_runtime_schema_readiness_v1()
     OR NOT app.ticket_export_runtime_schema_readiness_v1()
     OR NOT app.alert_dfir_runtime_schema_readiness_v1()
     OR pg_catalog.has_function_privilege(
       'periapsis_api','app.schema_compatibility_v43()'::regprocedure,'EXECUTE')
     OR pg_catalog.has_function_privilege(
       'periapsis_worker','app.schema_compatibility_v43()'::regprocedure,'EXECUTE')
     OR pg_catalog.has_function_privilege(
       'periapsis_api','app.platform_identity_runtime_schema_readiness_v9()'::regprocedure,'EXECUTE')
     OR pg_catalog.has_function_privilege(
       'periapsis_worker','app.platform_identity_runtime_schema_readiness_v9()'::regprocedure,'EXECUTE')
     OR pg_catalog.has_function_privilege(
       'periapsis_api','app.platform_oidc_direct_runtime_schema_readiness_v5()'::regprocedure,'EXECUTE')
     OR pg_catalog.has_function_privilege(
       'periapsis_worker','app.platform_oidc_direct_runtime_schema_readiness_v5()'::regprocedure,'EXECUTE')
     OR pg_catalog.has_function_privilege(
       'periapsis_api','app.platform_saml_direct_runtime_schema_readiness_v2()'::regprocedure,'EXECUTE')
     OR pg_catalog.has_function_privilege(
       'periapsis_worker','app.platform_saml_direct_runtime_schema_readiness_v2()'::regprocedure,'EXECUTE')
     OR pg_catalog.has_function_privilege(
       'periapsis_api','app.mfa_policy_administration_schema_readiness_v3()'::regprocedure,'EXECUTE')
     OR pg_catalog.has_function_privilege(
       'periapsis_worker','app.mfa_policy_administration_schema_readiness_v3()'::regprocedure,'EXECUTE') THEN
    RAISE EXCEPTION 'schema compatibility v44 seal verification failed'
      USING ERRCODE='55000';
  END IF;
END;
$function$;
ALTER FUNCTION app.seal_schema_compatibility_manifest(bigint,bigint,text,text)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.seal_schema_compatibility_manifest(bigint,bigint,text,text)
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier;
GRANT EXECUTE ON FUNCTION app.seal_schema_compatibility_manifest(bigint,bigint,text,text)
  TO periapsis_migrator;
--> statement-breakpoint

DO $derive_platform_identity_dependency_surface_v10$
DECLARE
  predecessor_definition text;
  predecessor_source_hash text;
  derived_definition text;
  marker constant text := '        ''schema_compatibility_v44'',';
  exclusions constant text :=
    '        ''private_platform_identity_dependency_surface_hash_v9'',' || chr(10) ||
    '        ''private_platform_identity_runtime_schema_readiness_v9'',' || chr(10) ||
    '        ''platform_identity_runtime_schema_readiness_v9'',' || chr(10) ||
    '        ''schema_compatibility_v43'',' || chr(10) ||
    '        ''private_platform_oidc_direct_dependency_surface_hash_v6'',' || chr(10) ||
    '        ''private_platform_oidc_direct_runtime_schema_readiness_v6'',' || chr(10) ||
    '        ''platform_oidc_direct_runtime_schema_readiness_v6'',' || chr(10) ||
    '        ''private_platform_saml_direct_dependency_surface_hash_v3'',' || chr(10) ||
    '        ''private_platform_saml_direct_runtime_schema_readiness_v3'',' || chr(10) ||
    '        ''platform_saml_direct_runtime_schema_readiness_v3'',' || chr(10) ||
    '        ''private_mfa_policy_administration_dependency_surface_hash_v4'',' || chr(10) ||
    '        ''private_mfa_policy_administration_schema_readiness_v4'',' || chr(10) ||
    '        ''mfa_policy_administration_schema_readiness_v4'',';
BEGIN
  SELECT pg_catalog.pg_get_functiondef(function_row.oid),
         pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8')),'hex')
    INTO STRICT predecessor_definition,predecessor_source_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid=
    'app.private_platform_identity_dependency_surface_hash_v9()'::regprocedure;
  IF predecessor_source_hash<>
    'f86426fedb8a656730f22f4b6ce4f9e4133e830b9867dac78c82392d382b78ed' THEN
    RAISE EXCEPTION 'platform identity dependency v9 drifted'
      USING ERRCODE='55000';
  END IF;
  derived_definition:=pg_catalog.replace(
    predecessor_definition,
    'private_platform_identity_dependency_surface_hash_v9',
    'private_platform_identity_dependency_surface_hash_v10'
  );
  derived_definition:=pg_catalog.replace(
    derived_definition,'private_platform_identity_runtime_schema_readiness_v9',
    'private_platform_identity_runtime_schema_readiness_v10'
  );
  derived_definition:=pg_catalog.replace(
    derived_definition,'platform_identity_runtime_schema_readiness_v9',
    'platform_identity_runtime_schema_readiness_v10'
  );
  derived_definition:=pg_catalog.replace(
    derived_definition,'schema_compatibility_v43','schema_compatibility_v44'
  );
  IF pg_catalog.strpos(derived_definition,marker)=0 THEN
    RAISE EXCEPTION 'platform identity dependency v10 marker drifted'
      USING ERRCODE='55000';
  END IF;
  derived_definition:=pg_catalog.replace(
    derived_definition,marker,marker || chr(10) || exclusions
  );
  EXECUTE derived_definition;
END;
$derive_platform_identity_dependency_surface_v10$;
ALTER FUNCTION app.private_platform_identity_dependency_surface_hash_v10()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_platform_identity_dependency_surface_hash_v10()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier;
--> statement-breakpoint

CREATE FUNCTION app.private_platform_oidc_direct_dependency_surface_hash_v6()
RETURNS text LANGUAGE sql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app
SET quote_all_identifiers=off SET TimeZone='UTC' SET DateStyle='ISO, YMD'
SET IntervalStyle='postgres' SET extra_float_digits=3 SET bytea_output='hex'
SET standard_conforming_strings=on SET lc_numeric='C'
AS $function$
  SELECT app.private_platform_identity_dependency_surface_hash_v10();
$function$;
CREATE FUNCTION app.private_platform_saml_direct_dependency_surface_hash_v3()
RETURNS text LANGUAGE sql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app
SET quote_all_identifiers=off SET TimeZone='UTC' SET DateStyle='ISO, YMD'
SET IntervalStyle='postgres' SET extra_float_digits=3 SET bytea_output='hex'
SET standard_conforming_strings=on SET lc_numeric='C'
AS $function$
  SELECT app.private_platform_identity_dependency_surface_hash_v10();
$function$;
CREATE FUNCTION app.private_mfa_policy_administration_dependency_surface_hash_v4()
RETURNS text LANGUAGE sql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app
SET quote_all_identifiers=off SET TimeZone='UTC' SET DateStyle='ISO, YMD'
SET IntervalStyle='postgres' SET extra_float_digits=3 SET bytea_output='hex'
SET standard_conforming_strings=on SET lc_numeric='C'
AS $function$
  SELECT app.private_platform_identity_dependency_surface_hash_v10();
$function$;
ALTER FUNCTION app.private_platform_oidc_direct_dependency_surface_hash_v6()
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_platform_saml_direct_dependency_surface_hash_v3()
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_mfa_policy_administration_dependency_surface_hash_v4()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_platform_oidc_direct_dependency_surface_hash_v6()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier;
REVOKE ALL ON FUNCTION app.private_platform_saml_direct_dependency_surface_hash_v3()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier;
REVOKE ALL ON FUNCTION app.private_mfa_policy_administration_dependency_surface_hash_v4()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier;
--> statement-breakpoint

DO $derive_mfa_policy_private_readiness_v4$
DECLARE
  definition text;
  predecessor_hash text;
  dependency_source_hash text;
  dependency_result_hash text;
BEGIN
  SELECT pg_catalog.pg_get_functiondef(function_row.oid),
         pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8')),'hex')
    INTO STRICT definition,predecessor_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid=
    'app.private_mfa_policy_administration_schema_readiness_v3()'::regprocedure;
  IF predecessor_hash<>
    '2e922a8d01fb1007d9c5d0b75a13e4982e931b3280e591b7400ed8f9dfd5f524' THEN
    RAISE EXCEPTION 'MFA policy private readiness v3 drifted'
      USING ERRCODE='55000';
  END IF;
  SELECT pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8')),'hex'),
         app.private_mfa_policy_administration_dependency_surface_hash_v4()
    INTO STRICT dependency_source_hash,dependency_result_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid=
    'app.private_mfa_policy_administration_dependency_surface_hash_v4()'::regprocedure;
  definition:=pg_catalog.replace(definition,
    'private_mfa_policy_administration_dependency_surface_hash_v3',
    'private_mfa_policy_administration_dependency_surface_hash_v4');
  definition:=pg_catalog.replace(definition,
    'private_mfa_policy_administration_schema_readiness_v3',
    'private_mfa_policy_administration_schema_readiness_v4');
  definition:=pg_catalog.replace(definition,
    '''app.mfa_policy_administration_schema_readiness_v3()''::regprocedure',
    '''app.mfa_policy_administration_schema_readiness_v3()''::regprocedure,' ||
    chr(10) ||
    '        ''app.mfa_policy_administration_schema_readiness_v4()''::regprocedure'
  );
  definition:=pg_catalog.replace(definition,
    'dc603e6eff492758d3264e9ff9061bb62a524edb3f68953e09b71ee781fdd9bb',
    dependency_source_hash);
  definition:=pg_catalog.replace(definition,
    '0842a04d490bb30c55ce2e3f9236b792138f9ef7b356d656292df7d25f36e4ba',
    dependency_result_hash);
  EXECUTE definition;
END;
$derive_mfa_policy_private_readiness_v4$;
ALTER FUNCTION app.private_mfa_policy_administration_schema_readiness_v4()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_mfa_policy_administration_schema_readiness_v4()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier;
--> statement-breakpoint

DO $derive_platform_identity_private_readiness_v10$
DECLARE
  definition text;
  predecessor_hash text;
  dependency_source_hash text;
  dependency_result_hash text;
BEGIN
  SELECT pg_catalog.pg_get_functiondef(function_row.oid),
         pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8')),'hex')
    INTO STRICT definition,predecessor_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid=
    'app.private_platform_identity_runtime_schema_readiness_v9()'::regprocedure;
  IF predecessor_hash<>
    'dbe384b2c1a6891d02f54b6c0a2fb66cdf8389c81ef359243d7d18f5e9242070' THEN
    RAISE EXCEPTION 'platform identity private readiness v9 drifted'
      USING ERRCODE='55000';
  END IF;
  SELECT pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8')),'hex'),
         app.private_platform_identity_dependency_surface_hash_v10()
    INTO STRICT dependency_source_hash,dependency_result_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid=
    'app.private_platform_identity_dependency_surface_hash_v10()'::regprocedure;
  definition:=pg_catalog.replace(definition,
    'private_platform_identity_dependency_surface_hash_v9',
    'private_platform_identity_dependency_surface_hash_v10');
  definition:=pg_catalog.replace(definition,
    'private_platform_identity_runtime_schema_readiness_v9',
    'private_platform_identity_runtime_schema_readiness_v10');
  definition:=pg_catalog.replace(definition,
    'platform_identity_runtime_schema_readiness_v9',
    'platform_identity_runtime_schema_readiness_v10');
  definition:=pg_catalog.replace(definition,
    'schema_compatibility_v43','schema_compatibility_v44');
  definition:=pg_catalog.replace(definition,
    'private_platform_oidc_direct_dependency_surface_hash_v5',
    'private_platform_oidc_direct_dependency_surface_hash_v6');
  definition:=pg_catalog.replace(definition,
    'private_platform_oidc_direct_runtime_schema_readiness_v5',
    'private_platform_oidc_direct_runtime_schema_readiness_v6');
  definition:=pg_catalog.replace(definition,
    'platform_oidc_direct_runtime_schema_readiness_v5',
    'platform_oidc_direct_runtime_schema_readiness_v6');
  definition:=pg_catalog.replace(definition,
    'private_platform_saml_direct_dependency_surface_hash_v2',
    'private_platform_saml_direct_dependency_surface_hash_v3');
  definition:=pg_catalog.replace(definition,
    'private_platform_saml_direct_runtime_schema_readiness_v2',
    'private_platform_saml_direct_runtime_schema_readiness_v3');
  definition:=pg_catalog.replace(definition,
    'platform_saml_direct_runtime_schema_readiness_v2',
    'platform_saml_direct_runtime_schema_readiness_v3');
  definition:=pg_catalog.replace(definition,
    'private_mfa_policy_administration_dependency_surface_hash_v3',
    'private_mfa_policy_administration_dependency_surface_hash_v4');
  definition:=pg_catalog.replace(definition,
    'private_mfa_policy_administration_schema_readiness_v3',
    'private_mfa_policy_administration_schema_readiness_v4');
  definition:=pg_catalog.replace(definition,
    'mfa_policy_administration_schema_readiness_v3',
    'mfa_policy_administration_schema_readiness_v4');
  definition:=pg_catalog.replace(definition,
    'f86426fedb8a656730f22f4b6ce4f9e4133e830b9867dac78c82392d382b78ed',
    dependency_source_hash);
  definition:=pg_catalog.replace(definition,
    '0842a04d490bb30c55ce2e3f9236b792138f9ef7b356d656292df7d25f36e4ba',
    dependency_result_hash);
  EXECUTE definition;
END;
$derive_platform_identity_private_readiness_v10$;
ALTER FUNCTION app.private_platform_identity_runtime_schema_readiness_v10()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_platform_identity_runtime_schema_readiness_v10()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier;
--> statement-breakpoint

DO $derive_platform_oidc_private_readiness_v6$
DECLARE
  definition text;
  predecessor_hash text;
  dependency_source_hash text;
  dependency_result_hash text;
BEGIN
  SELECT pg_catalog.pg_get_functiondef(function_row.oid),
         pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8')),'hex')
    INTO STRICT definition,predecessor_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid=
    'app.private_platform_oidc_direct_runtime_schema_readiness_v5()'::regprocedure;
  IF predecessor_hash<>
    'a53bf02f5d8ac07860d544d8a7067fd02c8e4cca8f2a1a90e18d5b8ab6c9c714' THEN
    RAISE EXCEPTION 'direct platform OIDC private readiness v5 drifted'
      USING ERRCODE='55000';
  END IF;
  SELECT pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8')),'hex'),
         app.private_platform_oidc_direct_dependency_surface_hash_v6()
    INTO STRICT dependency_source_hash,dependency_result_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid=
    'app.private_platform_oidc_direct_dependency_surface_hash_v6()'::regprocedure;
  definition:=pg_catalog.replace(definition,
    'private_platform_oidc_direct_dependency_surface_hash_v5',
    'private_platform_oidc_direct_dependency_surface_hash_v6');
  definition:=pg_catalog.replace(definition,
    'private_platform_oidc_direct_runtime_schema_readiness_v5',
    'private_platform_oidc_direct_runtime_schema_readiness_v6');
  definition:=pg_catalog.replace(definition,
    'platform_oidc_direct_runtime_schema_readiness_v5',
    'platform_oidc_direct_runtime_schema_readiness_v6');
  definition:=pg_catalog.replace(definition,
    'private_platform_identity_dependency_surface_hash_v9',
    'private_platform_identity_dependency_surface_hash_v10');
  definition:=pg_catalog.replace(definition,
    'private_platform_identity_runtime_schema_readiness_v9',
    'private_platform_identity_runtime_schema_readiness_v10');
  definition:=pg_catalog.replace(definition,
    'platform_identity_runtime_schema_readiness_v9',
    'platform_identity_runtime_schema_readiness_v10');
  definition:=pg_catalog.replace(definition,
    'private_mfa_policy_administration_schema_readiness_v3',
    'private_mfa_policy_administration_schema_readiness_v4');
  definition:=pg_catalog.replace(definition,
    'schema_compatibility_v43','schema_compatibility_v44');
  definition:=pg_catalog.replace(definition,
    'dc603e6eff492758d3264e9ff9061bb62a524edb3f68953e09b71ee781fdd9bb',
    dependency_source_hash);
  definition:=pg_catalog.replace(definition,
    '0842a04d490bb30c55ce2e3f9236b792138f9ef7b356d656292df7d25f36e4ba',
    dependency_result_hash);
  EXECUTE definition;
END;
$derive_platform_oidc_private_readiness_v6$;
ALTER FUNCTION app.private_platform_oidc_direct_runtime_schema_readiness_v6()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_platform_oidc_direct_runtime_schema_readiness_v6()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier;
--> statement-breakpoint

DO $derive_platform_saml_private_readiness_v3$
DECLARE
  definition text;
  predecessor_hash text;
  dependency_source_hash text;
  dependency_result_hash text;
  metadata_source_hash text;
BEGIN
  SELECT pg_catalog.pg_get_functiondef(function_row.oid),
         pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8')),'hex')
    INTO STRICT definition,predecessor_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid=
    'app.private_platform_saml_direct_runtime_schema_readiness_v2()'::regprocedure;
  IF predecessor_hash<>
    'efb3a211fef4cc2b7220a1663599f04857004ac3b43de9b4ff5e402a098cdcfa' THEN
    RAISE EXCEPTION 'direct platform SAML private readiness v2 drifted'
      USING ERRCODE='55000';
  END IF;
  SELECT pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8')),'hex'),
         app.private_platform_saml_direct_dependency_surface_hash_v3()
    INTO STRICT dependency_source_hash,dependency_result_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid=
    'app.private_platform_saml_direct_dependency_surface_hash_v3()'::regprocedure;
  SELECT pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8')),'hex')
    INTO STRICT metadata_source_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid=
    'app.load_platform_saml_metadata_projection_v1(text)'::regprocedure;
  definition:=pg_catalog.replace(definition,
    'private_platform_saml_direct_dependency_surface_hash_v2',
    'private_platform_saml_direct_dependency_surface_hash_v3');
  definition:=pg_catalog.replace(definition,
    'private_platform_saml_direct_runtime_schema_readiness_v2',
    'private_platform_saml_direct_runtime_schema_readiness_v3');
  definition:=pg_catalog.replace(definition,
    'platform_saml_direct_runtime_schema_readiness_v2',
    'platform_saml_direct_runtime_schema_readiness_v3');
  definition:=pg_catalog.replace(definition,
    'dc603e6eff492758d3264e9ff9061bb62a524edb3f68953e09b71ee781fdd9bb',
    dependency_source_hash);
  definition:=pg_catalog.replace(definition,
    '0842a04d490bb30c55ce2e3f9236b792138f9ef7b356d656292df7d25f36e4ba',
    dependency_result_hash);
  definition:=pg_catalog.replace(definition,
    'f3af6d609094cbd7a563b8465bc2560bc6bec1926e7b43945e122da3152db989',
    metadata_source_hash);
  EXECUTE definition;
END;
$derive_platform_saml_private_readiness_v3$;
ALTER FUNCTION app.private_platform_saml_direct_runtime_schema_readiness_v3()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_platform_saml_direct_runtime_schema_readiness_v3()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier;
--> statement-breakpoint

CREATE FUNCTION app.mfa_policy_administration_schema_readiness_v4()
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app AS $function$
DECLARE current_count bigint;
BEGIN
  SELECT compatibility.applied_count INTO current_count
  FROM app.schema_compatibility_v44() AS compatibility;
  RETURN current_count=197
    AND app.private_mfa_policy_administration_schema_readiness_v4();
EXCEPTION WHEN undefined_table OR undefined_function OR insufficient_privilege
  OR invalid_schema_name OR cardinality_violation OR data_exception THEN
  RETURN false;
END;
$function$;
CREATE FUNCTION app.platform_identity_runtime_schema_readiness_v10()
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app AS $function$
DECLARE current_count bigint;
BEGIN
  SELECT compatibility.applied_count INTO current_count
  FROM app.schema_compatibility_v44() AS compatibility;
  RETURN current_count=197
    AND app.mfa_policy_administration_schema_readiness_v4()
    AND app.private_platform_identity_runtime_schema_readiness_v10();
EXCEPTION WHEN undefined_table OR undefined_function OR insufficient_privilege
  OR invalid_schema_name OR cardinality_violation OR data_exception THEN
  RETURN false;
END;
$function$;
CREATE FUNCTION app.platform_oidc_direct_runtime_schema_readiness_v6()
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app AS $function$
DECLARE current_count bigint;
BEGIN
  SELECT compatibility.applied_count INTO current_count
  FROM app.schema_compatibility_v44() AS compatibility;
  RETURN current_count=197
    AND app.platform_identity_runtime_schema_readiness_v10()
    AND app.private_platform_oidc_direct_runtime_schema_readiness_v6()
    AND NOT pg_catalog.has_function_privilege(
      'periapsis_api','app.platform_oidc_direct_runtime_schema_readiness_v5()'::regprocedure,'EXECUTE');
EXCEPTION WHEN undefined_table OR undefined_function OR insufficient_privilege
  OR invalid_schema_name OR cardinality_violation OR data_exception THEN
  RETURN false;
END;
$function$;
CREATE FUNCTION app.platform_saml_direct_runtime_schema_readiness_v3()
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app AS $function$
DECLARE current_count bigint;
BEGIN
  SELECT compatibility.applied_count INTO current_count
  FROM app.schema_compatibility_v44() AS compatibility;
  RETURN current_count=197
    AND app.platform_identity_runtime_schema_readiness_v10()
    AND app.private_platform_saml_direct_runtime_schema_readiness_v3()
    AND NOT pg_catalog.has_function_privilege(
      'periapsis_api','app.platform_saml_direct_runtime_schema_readiness_v2()'::regprocedure,'EXECUTE');
EXCEPTION WHEN undefined_table OR undefined_function OR insufficient_privilege
  OR invalid_schema_name OR cardinality_violation OR data_exception THEN
  RETURN false;
END;
$function$;
ALTER FUNCTION app.mfa_policy_administration_schema_readiness_v4()
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.platform_identity_runtime_schema_readiness_v10()
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.platform_oidc_direct_runtime_schema_readiness_v6()
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.platform_saml_direct_runtime_schema_readiness_v3()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.mfa_policy_administration_schema_readiness_v4()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier;
REVOKE ALL ON FUNCTION app.platform_identity_runtime_schema_readiness_v10()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier;
REVOKE ALL ON FUNCTION app.platform_oidc_direct_runtime_schema_readiness_v6()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier;
REVOKE ALL ON FUNCTION app.platform_saml_direct_runtime_schema_readiness_v3()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier;
GRANT EXECUTE ON FUNCTION app.mfa_policy_administration_schema_readiness_v4()
  TO periapsis_api,periapsis_worker;
GRANT EXECUTE ON FUNCTION app.platform_identity_runtime_schema_readiness_v10()
  TO periapsis_api,periapsis_worker;
GRANT EXECUTE ON FUNCTION app.platform_oidc_direct_runtime_schema_readiness_v6()
  TO periapsis_api,periapsis_worker;
GRANT EXECUTE ON FUNCTION app.platform_saml_direct_runtime_schema_readiness_v3()
  TO periapsis_api,periapsis_worker;
