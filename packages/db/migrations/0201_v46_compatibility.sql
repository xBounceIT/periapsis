-- V46 compatibility root and sealed dependency attestation for ticket watchers.
CREATE FUNCTION app.schema_compatibility_v46()
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
  journal_latest_hash text;
  latest_rows bigint;
  journal_fingerprint text;
  self_catalog_ready boolean;
BEGIN
  SELECT journal.applied_count,journal.latest_created_at,
         journal.latest_rows,journal.latest_hash,journal.migration_fingerprint
    INTO journal_count,journal_latest_created_at,latest_rows,
         journal_latest_hash,journal_fingerprint
  FROM app.private_schema_compatibility_journal_v46() AS journal;
  SELECT count(*)=1 INTO self_catalog_ready
  FROM pg_catalog.pg_proc AS function_row
  JOIN pg_catalog.pg_namespace AS namespace
    ON namespace.oid=function_row.pronamespace
  JOIN pg_catalog.pg_roles AS owner ON owner.oid=function_row.proowner
  JOIN pg_catalog.pg_language AS language ON language.oid=function_row.prolang
  WHERE function_row.oid='app.schema_compatibility_v46()'::regprocedure
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
  IF journal_count=202 AND journal_latest_created_at=1788250074583
     AND latest_rows=1 AND self_catalog_ready
     AND journal_fingerprint=current_setting(
       'app.schema_compatibility_fingerprint',true
     ) THEN
    RETURN QUERY SELECT journal_count,journal_latest_created_at,
      journal_latest_hash,journal_fingerprint;
    RETURN;
  END IF;
  RETURN QUERY SELECT 0::bigint,0::bigint,
    'UNSUPPORTED'::text,'UNSUPPORTED'::text;
END;
$function$;
ALTER FUNCTION app.schema_compatibility_v46() OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.schema_compatibility_v46()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier;
GRANT EXECUTE ON FUNCTION app.schema_compatibility_v46()
  TO periapsis_api,periapsis_worker;
--> statement-breakpoint

-- The SLA readiness root is deliberately owned by the isolated readiness
-- role and callable at runtime only by the worker. The NOLOGIN migration role
-- receives the narrow execute edge needed by the compatibility sealer; no
-- application login or role membership is broadened.
GRANT EXECUTE ON FUNCTION app.sla_trigger_action_runtime_schema_readiness_v1()
  TO periapsis_migrator;
--> statement-breakpoint

-- Install the final sealer source before deriving the v46 dependency surface,
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
  journal_latest_rows bigint;
  journal_fingerprint text;
  sealed_count bigint;
BEGIN
  IF p_expected_count IS DISTINCT FROM 202
     OR p_expected_latest_created_at IS DISTINCT FROM 1788250074583
     OR p_expected_latest_hash !~ '^[0-9a-f]{64}$'
     OR p_expected_migration_fingerprint !~
       '^[0-9]+@[0-9a-f]{64}(:[0-9]+@[0-9a-f]{64}){201}$' THEN
    RAISE EXCEPTION 'schema compatibility v46 seal input is invalid'
      USING ERRCODE='55000';
  END IF;
  SELECT journal.applied_count,journal.latest_created_at,journal.latest_rows,
         journal.latest_hash,journal.migration_fingerprint
    INTO journal_count,journal_latest_created_at,journal_latest_rows,
         journal_latest_hash,journal_fingerprint
  FROM app.private_schema_compatibility_journal_v46() AS journal;
  IF ROW(journal_count,journal_latest_created_at,journal_latest_hash,
         journal_fingerprint) IS DISTINCT FROM
     ROW(p_expected_count,p_expected_latest_created_at,p_expected_latest_hash,
          p_expected_migration_fingerprint)
     OR journal_latest_rows<>1
     OR NOT app.private_v46_migration_convergence_schema_readiness_v1()
     OR NOT app.private_mfa_policy_administration_schema_readiness_v6()
     OR NOT app.private_platform_identity_runtime_schema_readiness_v12()
     OR NOT app.private_platform_oidc_direct_runtime_schema_readiness_v8()
     OR NOT app.private_platform_saml_direct_runtime_schema_readiness_v5()
     OR NOT app.ticket_mutation_runtime_schema_readiness_v1()
     OR NOT app.sla_trigger_action_runtime_schema_readiness_v1()
     OR NOT app.platform_local_account_runtime_schema_readiness_v1()
     OR NOT app.ticket_bulk_runtime_schema_readiness_v1()
     OR NOT app.ticket_export_runtime_schema_readiness_v1()
     OR NOT app.alert_dfir_runtime_schema_readiness_v1()
     OR NOT app.ticket_metadata_runtime_schema_readiness_v1()
     OR NOT app.ticket_watcher_runtime_schema_readiness_v1() THEN
    RAISE EXCEPTION 'schema compatibility v46 pre-seal verification failed'
      USING ERRCODE='55000';
  END IF;
  EXECUTE pg_catalog.format(
    'ALTER FUNCTION app.schema_compatibility_v46() SET app.schema_compatibility_fingerprint = %L',
    p_expected_migration_fingerprint
  );
  ALTER FUNCTION app.schema_compatibility_v45()
    SET app.schema_compatibility_fingerprint='RETIRED';
  REVOKE ALL ON FUNCTION app.schema_compatibility_v45()
    FROM periapsis_api,periapsis_worker;
  REVOKE ALL ON FUNCTION app.platform_identity_runtime_schema_readiness_v11()
    FROM periapsis_api,periapsis_worker;
  REVOKE ALL ON FUNCTION app.platform_oidc_direct_runtime_schema_readiness_v7()
    FROM periapsis_api,periapsis_worker;
  REVOKE ALL ON FUNCTION app.platform_saml_direct_runtime_schema_readiness_v4()
    FROM periapsis_api,periapsis_worker;
  REVOKE ALL ON FUNCTION app.mfa_policy_administration_schema_readiness_v5()
    FROM periapsis_api,periapsis_worker;
  SELECT compatibility.applied_count INTO sealed_count
  FROM app.schema_compatibility_v46() AS compatibility;
  IF sealed_count<>202
     OR NOT app.private_v46_migration_convergence_schema_readiness_v1()
     OR NOT app.mfa_policy_administration_schema_readiness_v6()
     OR NOT app.platform_identity_runtime_schema_readiness_v12()
     OR NOT app.platform_oidc_direct_runtime_schema_readiness_v8()
     OR NOT app.platform_saml_direct_runtime_schema_readiness_v5()
     OR NOT app.ticket_mutation_runtime_schema_readiness_v1()
     OR NOT app.sla_trigger_action_runtime_schema_readiness_v1()
     OR NOT app.platform_local_account_runtime_schema_readiness_v1()
     OR NOT app.ticket_bulk_runtime_schema_readiness_v1()
     OR NOT app.ticket_export_runtime_schema_readiness_v1()
     OR NOT app.alert_dfir_runtime_schema_readiness_v1()
     OR NOT app.ticket_metadata_runtime_schema_readiness_v1()
     OR NOT app.ticket_watcher_runtime_schema_readiness_v1()
     OR pg_catalog.has_function_privilege(
       'periapsis_api','app.schema_compatibility_v45()'::regprocedure,'EXECUTE')
     OR pg_catalog.has_function_privilege(
       'periapsis_worker','app.schema_compatibility_v45()'::regprocedure,'EXECUTE')
     OR pg_catalog.has_function_privilege(
       'periapsis_api','app.platform_identity_runtime_schema_readiness_v11()'::regprocedure,'EXECUTE')
     OR pg_catalog.has_function_privilege(
       'periapsis_worker','app.platform_identity_runtime_schema_readiness_v11()'::regprocedure,'EXECUTE')
     OR pg_catalog.has_function_privilege(
       'periapsis_api','app.platform_oidc_direct_runtime_schema_readiness_v7()'::regprocedure,'EXECUTE')
     OR pg_catalog.has_function_privilege(
       'periapsis_worker','app.platform_oidc_direct_runtime_schema_readiness_v7()'::regprocedure,'EXECUTE')
     OR pg_catalog.has_function_privilege(
       'periapsis_api','app.platform_saml_direct_runtime_schema_readiness_v4()'::regprocedure,'EXECUTE')
     OR pg_catalog.has_function_privilege(
       'periapsis_worker','app.platform_saml_direct_runtime_schema_readiness_v4()'::regprocedure,'EXECUTE')
     OR pg_catalog.has_function_privilege(
       'periapsis_api','app.mfa_policy_administration_schema_readiness_v5()'::regprocedure,'EXECUTE')
     OR pg_catalog.has_function_privilege(
       'periapsis_worker','app.mfa_policy_administration_schema_readiness_v5()'::regprocedure,'EXECUTE') THEN
    RAISE EXCEPTION 'schema compatibility v46 seal verification failed'
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

DO $derive_platform_identity_dependency_surface_v12$
DECLARE
  predecessor_definition text;
  predecessor_source_hash text;
  derived_definition text;
  marker constant text := '        ''schema_compatibility_v46'',';
  exclusions constant text :=
    '        ''private_platform_identity_dependency_surface_hash_v11'',' || chr(10) ||
    '        ''private_platform_identity_runtime_schema_readiness_v11'',' || chr(10) ||
    '        ''platform_identity_runtime_schema_readiness_v11'',' || chr(10) ||
    '        ''schema_compatibility_v45'',' || chr(10) ||
    '        ''private_platform_oidc_direct_dependency_surface_hash_v8'',' || chr(10) ||
    '        ''private_platform_oidc_direct_runtime_schema_readiness_v8'',' || chr(10) ||
    '        ''platform_oidc_direct_runtime_schema_readiness_v8'',' || chr(10) ||
    '        ''private_platform_saml_direct_dependency_surface_hash_v5'',' || chr(10) ||
    '        ''private_platform_saml_direct_runtime_schema_readiness_v5'',' || chr(10) ||
    '        ''platform_saml_direct_runtime_schema_readiness_v5'',' || chr(10) ||
    '        ''private_mfa_policy_administration_dependency_surface_hash_v6'',' || chr(10) ||
    '        ''private_mfa_policy_administration_schema_readiness_v6'',' || chr(10) ||
    '        ''mfa_policy_administration_schema_readiness_v6'',';
BEGIN
  SELECT pg_catalog.pg_get_functiondef(function_row.oid),
         pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8')),'hex')
    INTO STRICT predecessor_definition,predecessor_source_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid=
    'app.private_platform_identity_dependency_surface_hash_v11()'::regprocedure;
  IF predecessor_source_hash<>
    'd7b3f12fb20fef0712d4c5ac7e777b2c8c59d94eb6ac5fc62cbe0a80828ef343' THEN
    RAISE EXCEPTION 'platform identity dependency v11 drifted'
      USING ERRCODE='55000';
  END IF;
  derived_definition:=pg_catalog.replace(
    predecessor_definition,
    'private_platform_identity_dependency_surface_hash_v11',
    'private_platform_identity_dependency_surface_hash_v12'
  );
  derived_definition:=pg_catalog.replace(
    derived_definition,'private_platform_identity_runtime_schema_readiness_v11',
    'private_platform_identity_runtime_schema_readiness_v12'
  );
  derived_definition:=pg_catalog.replace(
    derived_definition,'platform_identity_runtime_schema_readiness_v11',
    'platform_identity_runtime_schema_readiness_v12'
  );
  derived_definition:=pg_catalog.replace(
    derived_definition,'schema_compatibility_v45','schema_compatibility_v46'
  );
  IF pg_catalog.strpos(derived_definition,marker)=0 THEN
    RAISE EXCEPTION 'platform identity dependency v11 marker drifted'
      USING ERRCODE='55000';
  END IF;
  derived_definition:=pg_catalog.replace(
    derived_definition,marker,marker || chr(10) || exclusions
  );
  EXECUTE derived_definition;
END;
$derive_platform_identity_dependency_surface_v12$;
ALTER FUNCTION app.private_platform_identity_dependency_surface_hash_v12()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_platform_identity_dependency_surface_hash_v12()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier;
--> statement-breakpoint

CREATE FUNCTION app.private_platform_oidc_direct_dependency_surface_hash_v8()
RETURNS text LANGUAGE sql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app
SET quote_all_identifiers=off SET TimeZone='UTC' SET DateStyle='ISO, YMD'
SET IntervalStyle='postgres' SET extra_float_digits=3 SET bytea_output='hex'
SET standard_conforming_strings=on SET lc_numeric='C'
AS $function$
  SELECT app.private_platform_identity_dependency_surface_hash_v12();
$function$;
CREATE FUNCTION app.private_platform_saml_direct_dependency_surface_hash_v5()
RETURNS text LANGUAGE sql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app
SET quote_all_identifiers=off SET TimeZone='UTC' SET DateStyle='ISO, YMD'
SET IntervalStyle='postgres' SET extra_float_digits=3 SET bytea_output='hex'
SET standard_conforming_strings=on SET lc_numeric='C'
AS $function$
  SELECT app.private_platform_identity_dependency_surface_hash_v12();
$function$;
CREATE FUNCTION app.private_mfa_policy_administration_dependency_surface_hash_v6()
RETURNS text LANGUAGE sql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app
SET quote_all_identifiers=off SET TimeZone='UTC' SET DateStyle='ISO, YMD'
SET IntervalStyle='postgres' SET extra_float_digits=3 SET bytea_output='hex'
SET standard_conforming_strings=on SET lc_numeric='C'
AS $function$
  SELECT app.private_platform_identity_dependency_surface_hash_v12();
$function$;
ALTER FUNCTION app.private_platform_oidc_direct_dependency_surface_hash_v8()
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_platform_saml_direct_dependency_surface_hash_v5()
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_mfa_policy_administration_dependency_surface_hash_v6()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_platform_oidc_direct_dependency_surface_hash_v8()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier;
REVOKE ALL ON FUNCTION app.private_platform_saml_direct_dependency_surface_hash_v5()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier;
REVOKE ALL ON FUNCTION app.private_mfa_policy_administration_dependency_surface_hash_v6()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier;
--> statement-breakpoint

DO $derive_mfa_policy_private_readiness_v6$
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
    'app.private_mfa_policy_administration_schema_readiness_v5()'::regprocedure;
  IF predecessor_hash NOT IN (
    'ad1c5aa88277c11782e7ad20abf4509e5343ec8f62c47c12062176fa797d1032',
    '5348f7c36837a65fa5a41443177acd6820d41f0a1fa5b8b473c1024b070383de'
  ) THEN
    RAISE EXCEPTION 'MFA policy private readiness v5 drifted'
      USING ERRCODE='55000';
  END IF;
  SELECT pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8')),'hex'),
         app.private_mfa_policy_administration_dependency_surface_hash_v6()
    INTO STRICT dependency_source_hash,dependency_result_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid=
    'app.private_mfa_policy_administration_dependency_surface_hash_v6()'::regprocedure;
  definition:=pg_catalog.replace(definition,
    'private_mfa_policy_administration_dependency_surface_hash_v5',
    'private_mfa_policy_administration_dependency_surface_hash_v6');
  definition:=pg_catalog.replace(definition,
    'private_mfa_policy_administration_schema_readiness_v5',
    'private_mfa_policy_administration_schema_readiness_v6');
  definition:=pg_catalog.replace(definition,
    '''app.mfa_policy_administration_schema_readiness_v5()''::regprocedure',
    '''app.mfa_policy_administration_schema_readiness_v5()''::regprocedure,' ||
    chr(10) ||
    '        ''app.mfa_policy_administration_schema_readiness_v6()''::regprocedure'
  );
  definition:=pg_catalog.replace(definition,
    '873cb221e897a3c21b8b45f94da18e78b538ac40ee5bcebd430f1d9355a643f8',
    dependency_source_hash);
  definition:=pg_catalog.replace(definition,
    '3e0cf8fc6faa5eac5f542c3b3cb739d80303d563cdec289b8bf8309d9ec278b6',
    dependency_result_hash);
  definition:=pg_catalog.replace(definition,
    'ac33cd232816dc2108e3af8aef01f938dfef2f5650b9426829cf14cef9d5c3bb',
    dependency_result_hash);
  EXECUTE definition;
END;
$derive_mfa_policy_private_readiness_v6$;
ALTER FUNCTION app.private_mfa_policy_administration_schema_readiness_v6()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_mfa_policy_administration_schema_readiness_v6()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier;
--> statement-breakpoint

DO $derive_platform_identity_private_readiness_v12$
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
    'app.private_platform_identity_runtime_schema_readiness_v11()'::regprocedure;
  IF predecessor_hash NOT IN (
    '81395c7f999f2ab28be82fcc2854e536f8548285ab741661889fb41be09d5f7b',
    'e6b1ab3503731aa6b664f075fcbb3f74431d9d600ca01254a408b232f17a5171'
  ) THEN
    RAISE EXCEPTION 'platform identity private readiness v11 drifted'
      USING ERRCODE='55000';
  END IF;
  SELECT pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8')),'hex'),
         app.private_platform_identity_dependency_surface_hash_v12()
    INTO STRICT dependency_source_hash,dependency_result_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid=
    'app.private_platform_identity_dependency_surface_hash_v12()'::regprocedure;
  definition:=pg_catalog.replace(definition,
    'private_platform_identity_dependency_surface_hash_v11',
    'private_platform_identity_dependency_surface_hash_v12');
  definition:=pg_catalog.replace(definition,
    'private_platform_identity_runtime_schema_readiness_v11',
    'private_platform_identity_runtime_schema_readiness_v12');
  definition:=pg_catalog.replace(definition,
    'platform_identity_runtime_schema_readiness_v11',
    'platform_identity_runtime_schema_readiness_v12');
  definition:=pg_catalog.replace(definition,
    'schema_compatibility_v45','schema_compatibility_v46');
  definition:=pg_catalog.replace(definition,
    'private_platform_oidc_direct_dependency_surface_hash_v7',
    'private_platform_oidc_direct_dependency_surface_hash_v8');
  definition:=pg_catalog.replace(definition,
    'private_platform_oidc_direct_runtime_schema_readiness_v7',
    'private_platform_oidc_direct_runtime_schema_readiness_v8');
  definition:=pg_catalog.replace(definition,
    'platform_oidc_direct_runtime_schema_readiness_v7',
    'platform_oidc_direct_runtime_schema_readiness_v8');
  definition:=pg_catalog.replace(definition,
    'private_platform_saml_direct_dependency_surface_hash_v4',
    'private_platform_saml_direct_dependency_surface_hash_v5');
  definition:=pg_catalog.replace(definition,
    'private_platform_saml_direct_runtime_schema_readiness_v4',
    'private_platform_saml_direct_runtime_schema_readiness_v5');
  definition:=pg_catalog.replace(definition,
    'platform_saml_direct_runtime_schema_readiness_v4',
    'platform_saml_direct_runtime_schema_readiness_v5');
  definition:=pg_catalog.replace(definition,
    'private_mfa_policy_administration_dependency_surface_hash_v5',
    'private_mfa_policy_administration_dependency_surface_hash_v6');
  definition:=pg_catalog.replace(definition,
    'private_mfa_policy_administration_schema_readiness_v5',
    'private_mfa_policy_administration_schema_readiness_v6');
  definition:=pg_catalog.replace(definition,
    'mfa_policy_administration_schema_readiness_v5',
    'mfa_policy_administration_schema_readiness_v6');
  definition:=pg_catalog.replace(definition,
    'd7b3f12fb20fef0712d4c5ac7e777b2c8c59d94eb6ac5fc62cbe0a80828ef343',
    dependency_source_hash);
  definition:=pg_catalog.replace(definition,
    '3e0cf8fc6faa5eac5f542c3b3cb739d80303d563cdec289b8bf8309d9ec278b6',
    dependency_result_hash);
  definition:=pg_catalog.replace(definition,
    'ac33cd232816dc2108e3af8aef01f938dfef2f5650b9426829cf14cef9d5c3bb',
    dependency_result_hash);
  EXECUTE definition;
END;
$derive_platform_identity_private_readiness_v12$;
ALTER FUNCTION app.private_platform_identity_runtime_schema_readiness_v12()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_platform_identity_runtime_schema_readiness_v12()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier;
--> statement-breakpoint

DO $derive_platform_oidc_private_readiness_v8$
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
    'app.private_platform_oidc_direct_runtime_schema_readiness_v7()'::regprocedure;
  IF predecessor_hash NOT IN (
    '588689bdf29011aba884ba70bcf330f09951895b7680c5181196648c4537f2ce',
    '7c0d03aa7dd74f8c72ad867023e324ef49fccbe28b77a6c8d10eb4c8069ecbf0'
  ) THEN
    RAISE EXCEPTION 'direct platform OIDC private readiness v7 drifted'
      USING ERRCODE='55000';
  END IF;
  SELECT pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8')),'hex'),
         app.private_platform_oidc_direct_dependency_surface_hash_v8()
    INTO STRICT dependency_source_hash,dependency_result_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid=
    'app.private_platform_oidc_direct_dependency_surface_hash_v8()'::regprocedure;
  definition:=pg_catalog.replace(definition,
    'private_platform_oidc_direct_dependency_surface_hash_v7',
    'private_platform_oidc_direct_dependency_surface_hash_v8');
  definition:=pg_catalog.replace(definition,
    'private_platform_oidc_direct_runtime_schema_readiness_v7',
    'private_platform_oidc_direct_runtime_schema_readiness_v8');
  definition:=pg_catalog.replace(definition,
    'platform_oidc_direct_runtime_schema_readiness_v7',
    'platform_oidc_direct_runtime_schema_readiness_v8');
  definition:=pg_catalog.replace(definition,
    'private_platform_identity_dependency_surface_hash_v11',
    'private_platform_identity_dependency_surface_hash_v12');
  definition:=pg_catalog.replace(definition,
    'private_platform_identity_runtime_schema_readiness_v11',
    'private_platform_identity_runtime_schema_readiness_v12');
  definition:=pg_catalog.replace(definition,
    'platform_identity_runtime_schema_readiness_v11',
    'platform_identity_runtime_schema_readiness_v12');
  definition:=pg_catalog.replace(definition,
    'private_mfa_policy_administration_schema_readiness_v5',
    'private_mfa_policy_administration_schema_readiness_v6');
  definition:=pg_catalog.replace(definition,
    'schema_compatibility_v45','schema_compatibility_v46');
  definition:=pg_catalog.replace(definition,
    '873cb221e897a3c21b8b45f94da18e78b538ac40ee5bcebd430f1d9355a643f8',
    dependency_source_hash);
  definition:=pg_catalog.replace(definition,
    '3e0cf8fc6faa5eac5f542c3b3cb739d80303d563cdec289b8bf8309d9ec278b6',
    dependency_result_hash);
  definition:=pg_catalog.replace(definition,
    'ac33cd232816dc2108e3af8aef01f938dfef2f5650b9426829cf14cef9d5c3bb',
    dependency_result_hash);
  EXECUTE definition;
END;
$derive_platform_oidc_private_readiness_v8$;
ALTER FUNCTION app.private_platform_oidc_direct_runtime_schema_readiness_v8()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_platform_oidc_direct_runtime_schema_readiness_v8()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier;
--> statement-breakpoint

DO $derive_platform_saml_private_readiness_v5$
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
    'app.private_platform_saml_direct_runtime_schema_readiness_v4()'::regprocedure;
  IF predecessor_hash NOT IN (
    'bbc299650d5f4bc8e3616d4e19a64af11494a2f9156c79a3b37a3b702f3cf03c',
    '541eb8770ec4b1981f8b114c034077a89a617afb792c9912afaa1ed3d4ada471'
  ) THEN
    RAISE EXCEPTION 'direct platform SAML private readiness v4 drifted'
      USING ERRCODE='55000';
  END IF;
  SELECT pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8')),'hex'),
         app.private_platform_saml_direct_dependency_surface_hash_v5()
    INTO STRICT dependency_source_hash,dependency_result_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid=
    'app.private_platform_saml_direct_dependency_surface_hash_v5()'::regprocedure;
  SELECT pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8')),'hex')
    INTO STRICT metadata_source_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid=
    'app.load_platform_saml_metadata_projection_v1(text)'::regprocedure;
  definition:=pg_catalog.replace(definition,
    'private_platform_saml_direct_dependency_surface_hash_v4',
    'private_platform_saml_direct_dependency_surface_hash_v5');
  definition:=pg_catalog.replace(definition,
    'private_platform_saml_direct_runtime_schema_readiness_v4',
    'private_platform_saml_direct_runtime_schema_readiness_v5');
  definition:=pg_catalog.replace(definition,
    'platform_saml_direct_runtime_schema_readiness_v4',
    'platform_saml_direct_runtime_schema_readiness_v5');
  definition:=pg_catalog.replace(definition,
    '873cb221e897a3c21b8b45f94da18e78b538ac40ee5bcebd430f1d9355a643f8',
    dependency_source_hash);
  definition:=pg_catalog.replace(definition,
    '3e0cf8fc6faa5eac5f542c3b3cb739d80303d563cdec289b8bf8309d9ec278b6',
    dependency_result_hash);
  definition:=pg_catalog.replace(definition,
    'ac33cd232816dc2108e3af8aef01f938dfef2f5650b9426829cf14cef9d5c3bb',
    dependency_result_hash);
  definition:=pg_catalog.replace(definition,
    'f3af6d609094cbd7a563b8465bc2560bc6bec1926e7b43945e122da3152db989',
    metadata_source_hash);
  EXECUTE definition;
END;
$derive_platform_saml_private_readiness_v5$;
ALTER FUNCTION app.private_platform_saml_direct_runtime_schema_readiness_v5()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_platform_saml_direct_runtime_schema_readiness_v5()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier;
--> statement-breakpoint

CREATE FUNCTION app.mfa_policy_administration_schema_readiness_v6()
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app AS $function$
DECLARE current_count bigint;
BEGIN
  SELECT compatibility.applied_count INTO current_count
  FROM app.schema_compatibility_v46() AS compatibility;
  RETURN current_count=202
    AND app.private_mfa_policy_administration_schema_readiness_v6();
EXCEPTION WHEN undefined_table OR undefined_function OR insufficient_privilege
  OR invalid_schema_name OR cardinality_violation OR data_exception THEN
  RETURN false;
END;
$function$;
CREATE FUNCTION app.platform_identity_runtime_schema_readiness_v12()
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app AS $function$
DECLARE current_count bigint;
BEGIN
  SELECT compatibility.applied_count INTO current_count
  FROM app.schema_compatibility_v46() AS compatibility;
  RETURN current_count=202
    AND app.mfa_policy_administration_schema_readiness_v6()
    AND app.private_platform_identity_runtime_schema_readiness_v12();
EXCEPTION WHEN undefined_table OR undefined_function OR insufficient_privilege
  OR invalid_schema_name OR cardinality_violation OR data_exception THEN
  RETURN false;
END;
$function$;
CREATE FUNCTION app.platform_oidc_direct_runtime_schema_readiness_v8()
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app AS $function$
DECLARE current_count bigint;
BEGIN
  SELECT compatibility.applied_count INTO current_count
  FROM app.schema_compatibility_v46() AS compatibility;
  RETURN current_count=202
    AND app.platform_identity_runtime_schema_readiness_v12()
    AND app.private_platform_oidc_direct_runtime_schema_readiness_v8()
    AND NOT pg_catalog.has_function_privilege(
      'periapsis_api','app.platform_oidc_direct_runtime_schema_readiness_v7()'::regprocedure,'EXECUTE');
EXCEPTION WHEN undefined_table OR undefined_function OR insufficient_privilege
  OR invalid_schema_name OR cardinality_violation OR data_exception THEN
  RETURN false;
END;
$function$;
CREATE FUNCTION app.platform_saml_direct_runtime_schema_readiness_v5()
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app AS $function$
DECLARE current_count bigint;
BEGIN
  SELECT compatibility.applied_count INTO current_count
  FROM app.schema_compatibility_v46() AS compatibility;
  RETURN current_count=202
    AND app.platform_identity_runtime_schema_readiness_v12()
    AND app.private_platform_saml_direct_runtime_schema_readiness_v5()
    AND NOT pg_catalog.has_function_privilege(
      'periapsis_api','app.platform_saml_direct_runtime_schema_readiness_v4()'::regprocedure,'EXECUTE');
EXCEPTION WHEN undefined_table OR undefined_function OR insufficient_privilege
  OR invalid_schema_name OR cardinality_violation OR data_exception THEN
  RETURN false;
END;
$function$;
ALTER FUNCTION app.mfa_policy_administration_schema_readiness_v6()
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.platform_identity_runtime_schema_readiness_v12()
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.platform_oidc_direct_runtime_schema_readiness_v8()
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.platform_saml_direct_runtime_schema_readiness_v5()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.mfa_policy_administration_schema_readiness_v6()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier;
REVOKE ALL ON FUNCTION app.platform_identity_runtime_schema_readiness_v12()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier;
REVOKE ALL ON FUNCTION app.platform_oidc_direct_runtime_schema_readiness_v8()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier;
REVOKE ALL ON FUNCTION app.platform_saml_direct_runtime_schema_readiness_v5()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier;
GRANT EXECUTE ON FUNCTION app.mfa_policy_administration_schema_readiness_v6()
  TO periapsis_api,periapsis_worker;
GRANT EXECUTE ON FUNCTION app.platform_identity_runtime_schema_readiness_v12()
  TO periapsis_api,periapsis_worker;
GRANT EXECUTE ON FUNCTION app.platform_oidc_direct_runtime_schema_readiness_v8()
  TO periapsis_api,periapsis_worker;
GRANT EXECUTE ON FUNCTION app.platform_saml_direct_runtime_schema_readiness_v5()
  TO periapsis_api,periapsis_worker;
