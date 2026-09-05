-- V43 is a coordinated fail-closed cutover. V42 remains immutable predecessor
-- evidence, but it cannot serve the repaired SAML metadata projection: after
-- 0188 the dependency surface advances and old binaries reject the journal.
CREATE FUNCTION app.schema_compatibility_v43()
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
             WHERE migration.created_at = 1788113074763
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
  WHERE function_row.oid='app.schema_compatibility_v43()'::regprocedure
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
  IF journal_count=190 AND journal_latest_created_at=1788113074763
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
ALTER FUNCTION app.schema_compatibility_v43() OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.schema_compatibility_v43()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier;
GRANT EXECUTE ON FUNCTION app.schema_compatibility_v43()
  TO periapsis_api,periapsis_worker;
--> statement-breakpoint

-- Install the final sealer source before deriving the v43 dependency surface,
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
  IF p_expected_count IS DISTINCT FROM 190
     OR p_expected_latest_created_at IS DISTINCT FROM 1788113074763
     OR p_expected_latest_hash !~ '^[0-9a-f]{64}$'
     OR p_expected_migration_fingerprint !~
       '^[0-9]+@[0-9a-f]{64}(:[0-9]+@[0-9a-f]{64}){189}$' THEN
    RAISE EXCEPTION 'schema compatibility v43 seal input is invalid'
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
     OR NOT app.private_mfa_policy_administration_schema_readiness_v3()
     OR NOT app.private_platform_identity_runtime_schema_readiness_v9()
     OR NOT app.private_platform_oidc_direct_runtime_schema_readiness_v5()
     OR NOT app.private_platform_saml_direct_runtime_schema_readiness_v2() THEN
    RAISE EXCEPTION 'schema compatibility v43 pre-seal verification failed'
      USING ERRCODE='55000';
  END IF;
  EXECUTE pg_catalog.format(
    'ALTER FUNCTION app.schema_compatibility_v43() SET app.schema_compatibility_fingerprint = %L',
    p_expected_migration_fingerprint
  );
  ALTER FUNCTION app.schema_compatibility_v42()
    SET app.schema_compatibility_fingerprint='RETIRED';
  REVOKE ALL ON FUNCTION app.schema_compatibility_v42()
    FROM periapsis_api,periapsis_worker;
  REVOKE ALL ON FUNCTION app.platform_identity_runtime_schema_readiness_v8()
    FROM periapsis_api,periapsis_worker;
  REVOKE ALL ON FUNCTION app.platform_oidc_direct_runtime_schema_readiness_v4()
    FROM periapsis_api,periapsis_worker;
  REVOKE ALL ON FUNCTION app.platform_saml_direct_runtime_schema_readiness_v1()
    FROM periapsis_api,periapsis_worker;
  REVOKE ALL ON FUNCTION app.mfa_policy_administration_schema_readiness_v2()
    FROM periapsis_api,periapsis_worker;
  SELECT compatibility.applied_count INTO sealed_count
  FROM app.schema_compatibility_v43() AS compatibility;
  IF sealed_count<>190
     OR NOT app.mfa_policy_administration_schema_readiness_v3()
     OR NOT app.platform_identity_runtime_schema_readiness_v9()
     OR NOT app.platform_oidc_direct_runtime_schema_readiness_v5()
     OR NOT app.platform_saml_direct_runtime_schema_readiness_v2()
     OR pg_catalog.has_function_privilege(
       'periapsis_api','app.schema_compatibility_v42()'::regprocedure,'EXECUTE')
     OR pg_catalog.has_function_privilege(
       'periapsis_worker','app.schema_compatibility_v42()'::regprocedure,'EXECUTE')
     OR pg_catalog.has_function_privilege(
       'periapsis_api','app.platform_identity_runtime_schema_readiness_v8()'::regprocedure,'EXECUTE')
     OR pg_catalog.has_function_privilege(
       'periapsis_api','app.platform_oidc_direct_runtime_schema_readiness_v4()'::regprocedure,'EXECUTE')
     OR pg_catalog.has_function_privilege(
       'periapsis_api','app.platform_saml_direct_runtime_schema_readiness_v1()'::regprocedure,'EXECUTE')
     OR pg_catalog.has_function_privilege(
       'periapsis_api','app.mfa_policy_administration_schema_readiness_v2()'::regprocedure,'EXECUTE') THEN
    RAISE EXCEPTION 'schema compatibility v43 seal verification failed'
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

DO $derive_platform_identity_dependency_surface_v9$
DECLARE
  predecessor_definition text;
  predecessor_source_hash text;
  derived_definition text;
  marker constant text := '        ''schema_compatibility_v43'',';
  exclusions constant text :=
    '        ''private_platform_identity_dependency_surface_hash_v8'',' || chr(10) ||
    '        ''private_platform_identity_runtime_schema_readiness_v8'',' || chr(10) ||
    '        ''platform_identity_runtime_schema_readiness_v8'',' || chr(10) ||
    '        ''schema_compatibility_v42'',' || chr(10) ||
    '        ''private_platform_oidc_direct_dependency_surface_hash_v5'',' || chr(10) ||
    '        ''private_platform_oidc_direct_runtime_schema_readiness_v5'',' || chr(10) ||
    '        ''platform_oidc_direct_runtime_schema_readiness_v5'',' || chr(10) ||
    '        ''private_platform_saml_direct_dependency_surface_hash_v2'',' || chr(10) ||
    '        ''private_platform_saml_direct_runtime_schema_readiness_v2'',' || chr(10) ||
    '        ''platform_saml_direct_runtime_schema_readiness_v2'',' || chr(10) ||
    '        ''private_mfa_policy_administration_dependency_surface_hash_v3'',' || chr(10) ||
    '        ''private_mfa_policy_administration_schema_readiness_v3'',' || chr(10) ||
    '        ''mfa_policy_administration_schema_readiness_v3'',';
BEGIN
  SELECT pg_catalog.pg_get_functiondef(function_row.oid),
         pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8')),'hex')
    INTO STRICT predecessor_definition,predecessor_source_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid=
    'app.private_platform_identity_dependency_surface_hash_v8()'::regprocedure;
  IF predecessor_source_hash<>
    'ea0eb6ee4edbadef50c532930f7e34d3f616b32899b2f6337412f684804d1431' THEN
    RAISE EXCEPTION 'platform identity dependency v8 drifted'
      USING ERRCODE='55000';
  END IF;
  derived_definition:=pg_catalog.replace(
    predecessor_definition,
    'private_platform_identity_dependency_surface_hash_v8',
    'private_platform_identity_dependency_surface_hash_v9'
  );
  derived_definition:=pg_catalog.replace(
    derived_definition,'private_platform_identity_runtime_schema_readiness_v8',
    'private_platform_identity_runtime_schema_readiness_v9'
  );
  derived_definition:=pg_catalog.replace(
    derived_definition,'platform_identity_runtime_schema_readiness_v8',
    'platform_identity_runtime_schema_readiness_v9'
  );
  derived_definition:=pg_catalog.replace(
    derived_definition,'schema_compatibility_v42','schema_compatibility_v43'
  );
  IF pg_catalog.strpos(derived_definition,marker)=0 THEN
    RAISE EXCEPTION 'platform identity dependency v9 marker drifted'
      USING ERRCODE='55000';
  END IF;
  derived_definition:=pg_catalog.replace(
    derived_definition,marker,marker || chr(10) || exclusions
  );
  EXECUTE derived_definition;
END;
$derive_platform_identity_dependency_surface_v9$;
ALTER FUNCTION app.private_platform_identity_dependency_surface_hash_v9()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_platform_identity_dependency_surface_hash_v9()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier;
--> statement-breakpoint

CREATE FUNCTION app.private_platform_oidc_direct_dependency_surface_hash_v5()
RETURNS text LANGUAGE sql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app
SET quote_all_identifiers=off SET TimeZone='UTC' SET DateStyle='ISO, YMD'
SET IntervalStyle='postgres' SET extra_float_digits=3 SET bytea_output='hex'
SET standard_conforming_strings=on SET lc_numeric='C'
AS $function$
  SELECT app.private_platform_identity_dependency_surface_hash_v9();
$function$;
CREATE FUNCTION app.private_platform_saml_direct_dependency_surface_hash_v2()
RETURNS text LANGUAGE sql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app
SET quote_all_identifiers=off SET TimeZone='UTC' SET DateStyle='ISO, YMD'
SET IntervalStyle='postgres' SET extra_float_digits=3 SET bytea_output='hex'
SET standard_conforming_strings=on SET lc_numeric='C'
AS $function$
  SELECT app.private_platform_identity_dependency_surface_hash_v9();
$function$;
CREATE FUNCTION app.private_mfa_policy_administration_dependency_surface_hash_v3()
RETURNS text LANGUAGE sql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app
SET quote_all_identifiers=off SET TimeZone='UTC' SET DateStyle='ISO, YMD'
SET IntervalStyle='postgres' SET extra_float_digits=3 SET bytea_output='hex'
SET standard_conforming_strings=on SET lc_numeric='C'
AS $function$
  SELECT app.private_platform_identity_dependency_surface_hash_v9();
$function$;
ALTER FUNCTION app.private_platform_oidc_direct_dependency_surface_hash_v5()
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_platform_saml_direct_dependency_surface_hash_v2()
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_mfa_policy_administration_dependency_surface_hash_v3()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_platform_oidc_direct_dependency_surface_hash_v5()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier;
REVOKE ALL ON FUNCTION app.private_platform_saml_direct_dependency_surface_hash_v2()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier;
REVOKE ALL ON FUNCTION app.private_mfa_policy_administration_dependency_surface_hash_v3()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier;
--> statement-breakpoint

DO $derive_mfa_policy_private_readiness_v3$
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
    'app.private_mfa_policy_administration_schema_readiness_v2()'::regprocedure;
  IF predecessor_hash<>
    '6da3d855a035c927b3cc85a67313133f4522cf6dd2de014a93175795b18348b7' THEN
    RAISE EXCEPTION 'MFA policy private readiness v2 drifted'
      USING ERRCODE='55000';
  END IF;
  SELECT pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8')),'hex'),
         app.private_mfa_policy_administration_dependency_surface_hash_v3()
    INTO STRICT dependency_source_hash,dependency_result_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid=
    'app.private_mfa_policy_administration_dependency_surface_hash_v3()'::regprocedure;
  definition:=pg_catalog.replace(definition,
    'private_mfa_policy_administration_dependency_surface_hash_v2',
    'private_mfa_policy_administration_dependency_surface_hash_v3');
  definition:=pg_catalog.replace(definition,
    'private_mfa_policy_administration_schema_readiness_v2',
    'private_mfa_policy_administration_schema_readiness_v3');
  definition:=pg_catalog.replace(definition,
    '''app.mfa_policy_administration_schema_readiness_v2()''::regprocedure',
    '''app.mfa_policy_administration_schema_readiness_v2()''::regprocedure,' ||
    chr(10) ||
    '        ''app.mfa_policy_administration_schema_readiness_v3()''::regprocedure'
  );
  definition:=pg_catalog.replace(definition,
    '129333083f5b12a418e46f4ae1be4d0b8fc46373d55047c163af05bbf2aa66da',
    dependency_source_hash);
  definition:=pg_catalog.replace(definition,
    'bc8f9a573f1d229b702d7d10c8c5c98c811c51f5a90b760d6ca4090704a0c79d',
    dependency_result_hash);
  EXECUTE definition;
END;
$derive_mfa_policy_private_readiness_v3$;
ALTER FUNCTION app.private_mfa_policy_administration_schema_readiness_v3()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_mfa_policy_administration_schema_readiness_v3()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier;
--> statement-breakpoint

DO $derive_platform_identity_private_readiness_v9$
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
    'app.private_platform_identity_runtime_schema_readiness_v8()'::regprocedure;
  IF predecessor_hash<>
    '15d7c8184f0fb1ab40e1e80e9df9e12ba8ba975098a862c854be71fbaf54140c' THEN
    RAISE EXCEPTION 'platform identity private readiness v8 drifted'
      USING ERRCODE='55000';
  END IF;
  SELECT pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8')),'hex'),
         app.private_platform_identity_dependency_surface_hash_v9()
    INTO STRICT dependency_source_hash,dependency_result_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid=
    'app.private_platform_identity_dependency_surface_hash_v9()'::regprocedure;
  definition:=pg_catalog.replace(definition,
    'private_platform_identity_dependency_surface_hash_v8',
    'private_platform_identity_dependency_surface_hash_v9');
  definition:=pg_catalog.replace(definition,
    'private_platform_identity_runtime_schema_readiness_v8',
    'private_platform_identity_runtime_schema_readiness_v9');
  definition:=pg_catalog.replace(definition,
    'platform_identity_runtime_schema_readiness_v8',
    'platform_identity_runtime_schema_readiness_v9');
  definition:=pg_catalog.replace(definition,
    'schema_compatibility_v42','schema_compatibility_v43');
  definition:=pg_catalog.replace(definition,
    'private_platform_oidc_direct_dependency_surface_hash_v4',
    'private_platform_oidc_direct_dependency_surface_hash_v5');
  definition:=pg_catalog.replace(definition,
    'private_platform_oidc_direct_runtime_schema_readiness_v4',
    'private_platform_oidc_direct_runtime_schema_readiness_v5');
  definition:=pg_catalog.replace(definition,
    'platform_oidc_direct_runtime_schema_readiness_v4',
    'platform_oidc_direct_runtime_schema_readiness_v5');
  definition:=pg_catalog.replace(definition,
    'private_platform_saml_direct_dependency_surface_hash_v1',
    'private_platform_saml_direct_dependency_surface_hash_v2');
  definition:=pg_catalog.replace(definition,
    'private_platform_saml_direct_runtime_schema_readiness_v1',
    'private_platform_saml_direct_runtime_schema_readiness_v2');
  definition:=pg_catalog.replace(definition,
    'platform_saml_direct_runtime_schema_readiness_v1',
    'platform_saml_direct_runtime_schema_readiness_v2');
  definition:=pg_catalog.replace(definition,
    'private_mfa_policy_administration_dependency_surface_hash_v2',
    'private_mfa_policy_administration_dependency_surface_hash_v3');
  definition:=pg_catalog.replace(definition,
    'private_mfa_policy_administration_schema_readiness_v2',
    'private_mfa_policy_administration_schema_readiness_v3');
  definition:=pg_catalog.replace(definition,
    'mfa_policy_administration_schema_readiness_v2',
    'mfa_policy_administration_schema_readiness_v3');
  definition:=pg_catalog.replace(definition,
    'ea0eb6ee4edbadef50c532930f7e34d3f616b32899b2f6337412f684804d1431',
    dependency_source_hash);
  definition:=pg_catalog.replace(definition,
    'bc8f9a573f1d229b702d7d10c8c5c98c811c51f5a90b760d6ca4090704a0c79d',
    dependency_result_hash);
  EXECUTE definition;
END;
$derive_platform_identity_private_readiness_v9$;
ALTER FUNCTION app.private_platform_identity_runtime_schema_readiness_v9()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_platform_identity_runtime_schema_readiness_v9()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier;
--> statement-breakpoint

DO $derive_platform_oidc_private_readiness_v5$
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
    'app.private_platform_oidc_direct_runtime_schema_readiness_v4()'::regprocedure;
  IF predecessor_hash<>
    '55776c4ca1137c4717a540667b326ad672d681be5046992629aa68b4ac134023' THEN
    RAISE EXCEPTION 'direct platform OIDC private readiness v4 drifted'
      USING ERRCODE='55000';
  END IF;
  SELECT pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8')),'hex'),
         app.private_platform_oidc_direct_dependency_surface_hash_v5()
    INTO STRICT dependency_source_hash,dependency_result_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid=
    'app.private_platform_oidc_direct_dependency_surface_hash_v5()'::regprocedure;
  definition:=pg_catalog.replace(definition,
    'private_platform_oidc_direct_dependency_surface_hash_v4',
    'private_platform_oidc_direct_dependency_surface_hash_v5');
  definition:=pg_catalog.replace(definition,
    'private_platform_oidc_direct_runtime_schema_readiness_v4',
    'private_platform_oidc_direct_runtime_schema_readiness_v5');
  definition:=pg_catalog.replace(definition,
    'platform_oidc_direct_runtime_schema_readiness_v4',
    'platform_oidc_direct_runtime_schema_readiness_v5');
  definition:=pg_catalog.replace(definition,
    'private_platform_identity_dependency_surface_hash_v8',
    'private_platform_identity_dependency_surface_hash_v9');
  definition:=pg_catalog.replace(definition,
    'private_platform_identity_runtime_schema_readiness_v8',
    'private_platform_identity_runtime_schema_readiness_v9');
  definition:=pg_catalog.replace(definition,
    'platform_identity_runtime_schema_readiness_v8',
    'platform_identity_runtime_schema_readiness_v9');
  definition:=pg_catalog.replace(definition,
    'private_mfa_policy_administration_schema_readiness_v2',
    'private_mfa_policy_administration_schema_readiness_v3');
  definition:=pg_catalog.replace(definition,
    'schema_compatibility_v42','schema_compatibility_v43');
  definition:=pg_catalog.replace(definition,
    '129333083f5b12a418e46f4ae1be4d0b8fc46373d55047c163af05bbf2aa66da',
    dependency_source_hash);
  definition:=pg_catalog.replace(definition,
    'bc8f9a573f1d229b702d7d10c8c5c98c811c51f5a90b760d6ca4090704a0c79d',
    dependency_result_hash);
  EXECUTE definition;
END;
$derive_platform_oidc_private_readiness_v5$;
ALTER FUNCTION app.private_platform_oidc_direct_runtime_schema_readiness_v5()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_platform_oidc_direct_runtime_schema_readiness_v5()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier;
--> statement-breakpoint

DO $derive_platform_saml_private_readiness_v2$
DECLARE
  definition text;
  predecessor_hash text;
  dependency_source_hash text;
  dependency_result_hash text;
  metadata_source_hash text;
  final_marker constant text := '  RETURN true;';
  metadata_check text;
BEGIN
  SELECT pg_catalog.pg_get_functiondef(function_row.oid),
         pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8')),'hex')
    INTO STRICT definition,predecessor_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid=
    'app.private_platform_saml_direct_runtime_schema_readiness_v1()'::regprocedure;
  IF predecessor_hash<>
    'f8601273b911e629b9034cd848977b9a573f45f4173e0ef92114bfaec0250a84' THEN
    RAISE EXCEPTION 'direct platform SAML private readiness v1 drifted'
      USING ERRCODE='55000';
  END IF;
  SELECT pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8')),'hex'),
         app.private_platform_saml_direct_dependency_surface_hash_v2()
    INTO STRICT dependency_source_hash,dependency_result_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid=
    'app.private_platform_saml_direct_dependency_surface_hash_v2()'::regprocedure;
  SELECT pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8')),'hex')
    INTO STRICT metadata_source_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid=
    'app.load_platform_saml_metadata_projection_v1(text)'::regprocedure;
  definition:=pg_catalog.replace(definition,
    'private_platform_saml_direct_dependency_surface_hash_v1',
    'private_platform_saml_direct_dependency_surface_hash_v2');
  definition:=pg_catalog.replace(definition,
    'private_platform_saml_direct_runtime_schema_readiness_v1',
    'private_platform_saml_direct_runtime_schema_readiness_v2');
  definition:=pg_catalog.replace(definition,
    'platform_saml_direct_runtime_schema_readiness_v1',
    'platform_saml_direct_runtime_schema_readiness_v2');
  definition:=pg_catalog.replace(definition,
    '129333083f5b12a418e46f4ae1be4d0b8fc46373d55047c163af05bbf2aa66da',
    dependency_source_hash);
  definition:=pg_catalog.replace(definition,
    'bc8f9a573f1d229b702d7d10c8c5c98c811c51f5a90b760d6ca4090704a0c79d',
    dependency_result_hash);
  metadata_check:=
    '  IF NOT EXISTS (' || chr(10) ||
    '    SELECT 1 FROM pg_catalog.pg_proc AS function_row' || chr(10) ||
    '    JOIN pg_catalog.pg_roles AS owner ON owner.oid=function_row.proowner' || chr(10) ||
    '    JOIN pg_catalog.pg_language AS language ON language.oid=function_row.prolang' || chr(10) ||
    '    WHERE function_row.oid=' || chr(10) ||
    '      ''app.load_platform_saml_metadata_projection_v1(text)''::regprocedure' || chr(10) ||
    '      AND owner.rolname=''periapsis_migrator'' AND language.lanname=''plpgsql''' || chr(10) ||
    '      AND function_row.provolatile=''s'' AND function_row.prosecdef' || chr(10) ||
    '      AND function_row.proconfig IS NOT DISTINCT FROM' || chr(10) ||
    '        ARRAY[''search_path=pg_catalog, public, app'']::text[]' || chr(10) ||
    '      AND pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(' || chr(10) ||
    '        function_row.prosrc,''UTF8'')),''hex'')=''' || metadata_source_hash || '''' || chr(10) ||
    '  ) THEN RETURN false; END IF;' || chr(10) || chr(10);
  IF pg_catalog.strpos(definition,final_marker)=0 THEN
    RAISE EXCEPTION 'direct platform SAML private readiness v2 marker drifted'
      USING ERRCODE='55000';
  END IF;
  definition:=pg_catalog.replace(
    definition,final_marker,metadata_check || final_marker
  );
  EXECUTE definition;
END;
$derive_platform_saml_private_readiness_v2$;
ALTER FUNCTION app.private_platform_saml_direct_runtime_schema_readiness_v2()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_platform_saml_direct_runtime_schema_readiness_v2()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier;
--> statement-breakpoint

CREATE FUNCTION app.mfa_policy_administration_schema_readiness_v3()
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app AS $function$
DECLARE current_count bigint;
BEGIN
  SELECT compatibility.applied_count INTO current_count
  FROM app.schema_compatibility_v43() AS compatibility;
  RETURN current_count=190
    AND app.private_mfa_policy_administration_schema_readiness_v3();
EXCEPTION WHEN undefined_table OR undefined_function OR insufficient_privilege
  OR invalid_schema_name OR cardinality_violation OR data_exception THEN
  RETURN false;
END;
$function$;
CREATE FUNCTION app.platform_identity_runtime_schema_readiness_v9()
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app AS $function$
DECLARE current_count bigint;
BEGIN
  SELECT compatibility.applied_count INTO current_count
  FROM app.schema_compatibility_v43() AS compatibility;
  RETURN current_count=190
    AND app.mfa_policy_administration_schema_readiness_v3()
    AND app.private_platform_identity_runtime_schema_readiness_v9();
EXCEPTION WHEN undefined_table OR undefined_function OR insufficient_privilege
  OR invalid_schema_name OR cardinality_violation OR data_exception THEN
  RETURN false;
END;
$function$;
CREATE FUNCTION app.platform_oidc_direct_runtime_schema_readiness_v5()
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app AS $function$
DECLARE current_count bigint;
BEGIN
  SELECT compatibility.applied_count INTO current_count
  FROM app.schema_compatibility_v43() AS compatibility;
  RETURN current_count=190
    AND app.platform_identity_runtime_schema_readiness_v9()
    AND app.private_platform_oidc_direct_runtime_schema_readiness_v5()
    AND NOT pg_catalog.has_function_privilege(
      'periapsis_api','app.platform_oidc_direct_runtime_schema_readiness_v4()'::regprocedure,'EXECUTE');
EXCEPTION WHEN undefined_table OR undefined_function OR insufficient_privilege
  OR invalid_schema_name OR cardinality_violation OR data_exception THEN
  RETURN false;
END;
$function$;
CREATE FUNCTION app.platform_saml_direct_runtime_schema_readiness_v2()
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app AS $function$
DECLARE current_count bigint;
BEGIN
  SELECT compatibility.applied_count INTO current_count
  FROM app.schema_compatibility_v43() AS compatibility;
  RETURN current_count=190
    AND app.platform_identity_runtime_schema_readiness_v9()
    AND app.private_platform_saml_direct_runtime_schema_readiness_v2()
    AND NOT pg_catalog.has_function_privilege(
      'periapsis_api','app.platform_saml_direct_runtime_schema_readiness_v1()'::regprocedure,'EXECUTE');
EXCEPTION WHEN undefined_table OR undefined_function OR insufficient_privilege
  OR invalid_schema_name OR cardinality_violation OR data_exception THEN
  RETURN false;
END;
$function$;
ALTER FUNCTION app.mfa_policy_administration_schema_readiness_v3()
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.platform_identity_runtime_schema_readiness_v9()
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.platform_oidc_direct_runtime_schema_readiness_v5()
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.platform_saml_direct_runtime_schema_readiness_v2()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.mfa_policy_administration_schema_readiness_v3()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier;
REVOKE ALL ON FUNCTION app.platform_identity_runtime_schema_readiness_v9()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier;
REVOKE ALL ON FUNCTION app.platform_oidc_direct_runtime_schema_readiness_v5()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier;
REVOKE ALL ON FUNCTION app.platform_saml_direct_runtime_schema_readiness_v2()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier;
GRANT EXECUTE ON FUNCTION app.mfa_policy_administration_schema_readiness_v3()
  TO periapsis_api,periapsis_worker;
GRANT EXECUTE ON FUNCTION app.platform_identity_runtime_schema_readiness_v9()
  TO periapsis_api,periapsis_worker;
GRANT EXECUTE ON FUNCTION app.platform_oidc_direct_runtime_schema_readiness_v5()
  TO periapsis_api,periapsis_worker;
GRANT EXECUTE ON FUNCTION app.platform_saml_direct_runtime_schema_readiness_v2()
  TO periapsis_api,periapsis_worker;
