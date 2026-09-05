-- V41 seals MFA-policy administration through a coordinated fail-closed
-- cutover. V40 is immutable predecessor evidence only: V40 binaries reject
-- the advanced journal, the migration-to-seal interval is unsupported, and
-- the V40 runtime readiness roots are retired atomically by the V41 seal.

DO $derive_schema_compatibility_v41$
DECLARE
  predecessor_definition text;
  derived_definition text;
  predecessor_source_hash text;
BEGIN
  SELECT pg_catalog.pg_get_functiondef(function_row.oid),
         pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8'
         )),'hex')
    INTO STRICT predecessor_definition,predecessor_source_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid = 'app.schema_compatibility_v40()'::regprocedure;
  IF predecessor_source_hash IS DISTINCT FROM
       'd4f2e0efa33d722bcb97b926c8afb8d6050838548f891d789b7d44d303a6fe4c' THEN
    RAISE EXCEPTION 'schema compatibility v40 predecessor drifted'
      USING ERRCODE = '55000';
  END IF;
  derived_definition := pg_catalog.replace(
    predecessor_definition,'schema_compatibility_v40',
    'schema_compatibility_v41'
  );
  derived_definition := pg_catalog.replace(
    derived_definition,'1788085744122','1788094095501'
  );
  derived_definition := pg_catalog.replace(
    derived_definition,'journal_count = 182','journal_count = 184'
  );
  IF derived_definition = predecessor_definition
     OR derived_definition LIKE '%schema_compatibility_v40%'
     OR derived_definition LIKE '%1788085744122%'
     OR derived_definition LIKE '%journal_count = 182%' THEN
    RAISE EXCEPTION 'schema compatibility v41 derivation was not exact'
      USING ERRCODE = '55000';
  END IF;
  EXECUTE derived_definition;
END;
$derive_schema_compatibility_v41$;
ALTER FUNCTION app.schema_compatibility_v41() OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.schema_compatibility_v41()
FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
  periapsis_auditor,periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,periapsis_sla_api_owner,
  periapsis_sla_worker_owner,periapsis_sla_readiness_owner,
  periapsis_ticket_saved_view_owner,periapsis_ticket_attribution_owner,
  periapsis_ticket_sla_projection_owner;
GRANT EXECUTE ON FUNCTION app.schema_compatibility_v41()
TO periapsis_api,periapsis_worker;
--> statement-breakpoint

DO $derive_platform_identity_dependency_surface_v7$
DECLARE
  predecessor_definition text;
  derived_definition text;
  predecessor_source_hash text;
  schema_marker constant text :=
    '        ''schema_compatibility_v41'',';
  schema_replacement constant text := schema_marker || chr(10) ||
    '        ''private_platform_identity_dependency_surface_hash_v6'',' || chr(10) ||
    '        ''private_platform_identity_runtime_schema_readiness_v6'',' || chr(10) ||
    '        ''platform_identity_runtime_schema_readiness_v6'',' || chr(10) ||
    '        ''schema_compatibility_v40'',';
  direct_marker constant text :=
    '        ''private_platform_oidc_direct_dependency_surface_hash_v2'',' || chr(10) ||
    '        ''private_platform_oidc_direct_runtime_schema_readiness_v2'',' || chr(10) ||
    '        ''platform_oidc_direct_runtime_schema_readiness_v2''';
  direct_replacement constant text := direct_marker || ',' || chr(10) ||
    '        ''private_platform_oidc_direct_dependency_surface_hash_v3'',' || chr(10) ||
    '        ''private_platform_oidc_direct_runtime_schema_readiness_v3'',' || chr(10) ||
    '        ''platform_oidc_direct_runtime_schema_readiness_v3'',' || chr(10) ||
    '        ''private_mfa_policy_administration_dependency_surface_hash_v1'',' || chr(10) ||
    '        ''private_mfa_policy_administration_schema_readiness_v1'',' || chr(10) ||
    '        ''mfa_policy_administration_schema_readiness_v1''';
BEGIN
  SELECT pg_catalog.pg_get_functiondef(function_row.oid),
         pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8'
         )),'hex')
    INTO STRICT predecessor_definition,predecessor_source_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid =
    'app.private_platform_identity_dependency_surface_hash_v6()'::regprocedure;
  IF predecessor_source_hash IS DISTINCT FROM
       'b6ac9c2d70924d1d3194dcc38fea91b6245a2e798df202bbdbfcdacf96e57c7e' THEN
    RAISE EXCEPTION 'platform identity dependency v6 predecessor drifted'
      USING ERRCODE = '55000';
  END IF;
  derived_definition := pg_catalog.replace(
    predecessor_definition,'private_platform_identity_dependency_surface_hash_v6',
    'private_platform_identity_dependency_surface_hash_v7'
  );
  derived_definition := pg_catalog.replace(
    derived_definition,'private_platform_identity_runtime_schema_readiness_v6',
    'private_platform_identity_runtime_schema_readiness_v7'
  );
  derived_definition := pg_catalog.replace(
    derived_definition,'platform_identity_runtime_schema_readiness_v6',
    'platform_identity_runtime_schema_readiness_v7'
  );
  derived_definition := pg_catalog.replace(
    derived_definition,'schema_compatibility_v40','schema_compatibility_v41'
  );
  IF pg_catalog.strpos(derived_definition,schema_marker) = 0
     OR pg_catalog.strpos(derived_definition,direct_marker) = 0 THEN
    RAISE EXCEPTION 'platform identity dependency v7 exclusion marker drifted'
      USING ERRCODE = '55000';
  END IF;
  derived_definition := pg_catalog.replace(
    derived_definition,schema_marker,schema_replacement
  );
  derived_definition := pg_catalog.replace(
    derived_definition,direct_marker,direct_replacement
  );
  IF derived_definition = predecessor_definition
     OR derived_definition NOT LIKE '%schema_compatibility_v40%'
     OR derived_definition NOT LIKE
       '%private_platform_oidc_direct_dependency_surface_hash_v3%'
     OR derived_definition NOT LIKE
       '%private_mfa_policy_administration_schema_readiness_v1%' THEN
    RAISE EXCEPTION 'platform identity dependency v7 derivation failed'
      USING ERRCODE = '55000';
  END IF;
  EXECUTE derived_definition;
END;
$derive_platform_identity_dependency_surface_v7$;
ALTER FUNCTION app.private_platform_identity_dependency_surface_hash_v7()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_platform_identity_dependency_surface_hash_v7()
FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
  periapsis_auditor,periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,periapsis_sla_api_owner,
  periapsis_sla_worker_owner,periapsis_sla_readiness_owner,
  periapsis_ticket_saved_view_owner,periapsis_ticket_attribution_owner,
  periapsis_ticket_sla_projection_owner;
GRANT EXECUTE ON FUNCTION
  app.private_platform_identity_dependency_surface_hash_v7()
TO periapsis_migrator;
--> statement-breakpoint

DO $derive_platform_oidc_direct_dependency_surface_v3$
DECLARE
  predecessor_definition text;
  derived_definition text;
  predecessor_source_hash text;
  current_marker constant text :=
    '      ''private_platform_oidc_direct_dependency_surface_hash_v3'',' || chr(10) ||
    '      ''private_platform_oidc_direct_runtime_schema_readiness_v3'',' || chr(10) ||
    '      ''platform_oidc_direct_runtime_schema_readiness_v3'',';
  current_replacement constant text := current_marker || chr(10) ||
    '      ''private_platform_oidc_direct_dependency_surface_hash_v2'',' || chr(10) ||
    '      ''private_platform_oidc_direct_runtime_schema_readiness_v2'',' || chr(10) ||
    '      ''platform_oidc_direct_runtime_schema_readiness_v2'',';
BEGIN
  SELECT pg_catalog.pg_get_functiondef(function_row.oid),
         pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8'
         )),'hex')
    INTO STRICT predecessor_definition,predecessor_source_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid =
    'app.private_platform_oidc_direct_dependency_surface_hash_v2()'::regprocedure;
  IF predecessor_source_hash IS DISTINCT FROM
       'abad60eab36af53228d2f4ca1981f26b349f82f5fdf24538cc57af81039b561a' THEN
    RAISE EXCEPTION 'direct platform OIDC dependency v2 predecessor drifted'
      USING ERRCODE = '55000';
  END IF;
  derived_definition := pg_catalog.replace(
    predecessor_definition,'private_platform_oidc_direct_dependency_surface_hash_v2',
    'private_platform_oidc_direct_dependency_surface_hash_v3'
  );
  derived_definition := pg_catalog.replace(
    derived_definition,'private_platform_oidc_direct_runtime_schema_readiness_v2',
    'private_platform_oidc_direct_runtime_schema_readiness_v3'
  );
  derived_definition := pg_catalog.replace(
    derived_definition,'platform_oidc_direct_runtime_schema_readiness_v2',
    'platform_oidc_direct_runtime_schema_readiness_v3'
  );
  IF pg_catalog.strpos(derived_definition,current_marker) = 0 THEN
    RAISE EXCEPTION 'direct platform OIDC dependency v3 exclusion marker drifted'
      USING ERRCODE = '55000';
  END IF;
  derived_definition := pg_catalog.replace(
    derived_definition,current_marker,current_replacement
  );
  IF derived_definition = predecessor_definition
     OR derived_definition NOT LIKE
       '%private_platform_oidc_direct_dependency_surface_hash_v2%'
     OR derived_definition NOT LIKE
       '%private_platform_oidc_direct_dependency_surface_hash_v3%' THEN
    RAISE EXCEPTION 'direct platform OIDC dependency v3 derivation failed'
      USING ERRCODE = '55000';
  END IF;
  EXECUTE derived_definition;
END;
$derive_platform_oidc_direct_dependency_surface_v3$;
ALTER FUNCTION app.private_platform_oidc_direct_dependency_surface_hash_v3()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION
  app.private_platform_oidc_direct_dependency_surface_hash_v3()
FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
  periapsis_auditor,periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,periapsis_sla_api_owner,
  periapsis_sla_worker_owner,periapsis_sla_readiness_owner,
  periapsis_ticket_saved_view_owner,periapsis_ticket_attribution_owner,
  periapsis_ticket_sla_projection_owner;
GRANT EXECUTE ON FUNCTION
  app.private_platform_oidc_direct_dependency_surface_hash_v3()
TO periapsis_migrator;
--> statement-breakpoint

-- MFA administration deliberately reuses the comprehensive identity catalog
-- transcript. The V7 transcript excludes readiness roots themselves, so the
-- alias is stable while still sealing every table, helper, ABI and role edge
-- on which an MFA policy command depends.
CREATE FUNCTION app.private_mfa_policy_administration_dependency_surface_hash_v1()
RETURNS text
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog,public,app
SET quote_all_identifiers = off
SET TimeZone = 'UTC'
SET DateStyle = 'ISO, YMD'
SET IntervalStyle = 'postgres'
SET extra_float_digits = 3
SET bytea_output = 'hex'
SET standard_conforming_strings = on
SET lc_numeric = 'C'
AS $function$
  SELECT app.private_platform_identity_dependency_surface_hash_v7();
$function$;
ALTER FUNCTION app.private_mfa_policy_administration_dependency_surface_hash_v1()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION
  app.private_mfa_policy_administration_dependency_surface_hash_v1()
FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
  periapsis_auditor,periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,periapsis_sla_api_owner,
  periapsis_sla_worker_owner,periapsis_sla_readiness_owner,
  periapsis_ticket_saved_view_owner,periapsis_ticket_attribution_owner,
  periapsis_ticket_sla_projection_owner;
GRANT EXECUTE ON FUNCTION
  app.private_mfa_policy_administration_dependency_surface_hash_v1()
TO periapsis_migrator;
--> statement-breakpoint

-- Public roots are created before their private implementations so the
-- comprehensive dependency transcript can exclude all roots by exact name.
CREATE FUNCTION app.private_mfa_policy_administration_schema_readiness_v1()
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog,public,app
AS $function$
BEGIN
  RETURN false;
END;
$function$;
ALTER FUNCTION app.private_mfa_policy_administration_schema_readiness_v1()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION
  app.private_mfa_policy_administration_schema_readiness_v1()
FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
  periapsis_auditor,periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,periapsis_sla_api_owner,
  periapsis_sla_worker_owner,periapsis_sla_readiness_owner,
  periapsis_ticket_saved_view_owner,periapsis_ticket_attribution_owner,
  periapsis_ticket_sla_projection_owner;
GRANT EXECUTE ON FUNCTION
  app.private_mfa_policy_administration_schema_readiness_v1()
TO periapsis_migrator;
--> statement-breakpoint

DO $bind_platform_identity_runtime_private_readiness_v7$
DECLARE
  predecessor_definition text;
  derived_definition text;
  predecessor_source_hash text;
  dependency_source_hash text;
  dependency_surface_hash text;
  final_marker constant text :=
    '  RETURN true;' || chr(10) || 'END;';
  mfa_check constant text :=
    '  IF NOT app.private_mfa_policy_administration_schema_readiness_v1() THEN' || chr(10) ||
    '    RETURN false;' || chr(10) ||
    '  END IF;' || chr(10) || chr(10);
BEGIN
  SELECT pg_catalog.pg_get_functiondef(function_row.oid),
         pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8'
         )),'hex')
    INTO STRICT predecessor_definition,predecessor_source_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid =
    'app.private_platform_identity_runtime_schema_readiness_v6()'::regprocedure;
  IF predecessor_source_hash IS DISTINCT FROM
       '06f1d8979113eee281b3103c2a39a5dbe00e73f2fbf92c3f25f7d18655b02569' THEN
    RAISE EXCEPTION 'platform identity private readiness v6 drifted'
      USING ERRCODE = '55000';
  END IF;
  SELECT pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8'
         )),'hex')
    INTO STRICT dependency_source_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid =
    'app.private_platform_identity_dependency_surface_hash_v7()'::regprocedure;
  dependency_surface_hash :=
    app.private_platform_identity_dependency_surface_hash_v7();
  derived_definition := pg_catalog.replace(
    predecessor_definition,'private_platform_identity_runtime_schema_readiness_v6',
    'private_platform_identity_runtime_schema_readiness_v7'
  );
  derived_definition := pg_catalog.replace(
    derived_definition,'private_platform_identity_dependency_surface_hash_v6',
    'private_platform_identity_dependency_surface_hash_v7'
  );
  derived_definition := pg_catalog.replace(
    derived_definition,'platform_identity_runtime_schema_readiness_v6',
    'platform_identity_runtime_schema_readiness_v7'
  );
  derived_definition := pg_catalog.replace(
    derived_definition,'schema_compatibility_v40','schema_compatibility_v41'
  );
  derived_definition := pg_catalog.replace(
    derived_definition,
    'b6ac9c2d70924d1d3194dcc38fea91b6245a2e798df202bbdbfcdacf96e57c7e',
    dependency_source_hash
  );
  derived_definition := pg_catalog.replace(
    derived_definition,
    '6481d203d3c704a2ec2331ae49e0a9b5a2bced4ed8cbc0c7347a61f8d8f019d6',
    dependency_surface_hash
  );
  IF pg_catalog.strpos(derived_definition,final_marker) = 0 THEN
    RAISE EXCEPTION 'platform identity private readiness v7 marker drifted'
      USING ERRCODE = '55000';
  END IF;
  derived_definition := pg_catalog.replace(
    derived_definition,final_marker,mfa_check || final_marker
  );
  EXECUTE derived_definition;
END;
$bind_platform_identity_runtime_private_readiness_v7$;
ALTER FUNCTION app.private_platform_identity_runtime_schema_readiness_v7()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_platform_identity_runtime_schema_readiness_v7()
FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
  periapsis_auditor,periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,periapsis_sla_api_owner,
  periapsis_sla_worker_owner,periapsis_sla_readiness_owner,
  periapsis_ticket_saved_view_owner,periapsis_ticket_attribution_owner,
  periapsis_ticket_sla_projection_owner;
GRANT EXECUTE ON FUNCTION app.private_platform_identity_runtime_schema_readiness_v7()
TO periapsis_migrator;
--> statement-breakpoint

DO $bind_platform_oidc_direct_private_readiness_v3$
DECLARE
  predecessor_definition text;
  derived_definition text;
  predecessor_source_hash text;
  dependency_source_hash text;
  dependency_surface_hash text;
  final_marker constant text :=
    '  RETURN true;' || chr(10) || 'END;';
  mfa_check constant text :=
    '  IF NOT app.private_mfa_policy_administration_schema_readiness_v1() THEN' || chr(10) ||
    '    RETURN false;' || chr(10) ||
    '  END IF;' || chr(10) || chr(10);
BEGIN
  SELECT pg_catalog.pg_get_functiondef(function_row.oid),
         pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8'
         )),'hex')
    INTO STRICT predecessor_definition,predecessor_source_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid =
    'app.private_platform_oidc_direct_runtime_schema_readiness_v2()'::regprocedure;
  IF predecessor_source_hash IS DISTINCT FROM
       'f73c5f95e5bb9489862582c70e65f8663dbc3a5cda310ad8a8c7692be9a033af' THEN
    RAISE EXCEPTION 'direct platform OIDC private readiness v2 drifted'
      USING ERRCODE = '55000';
  END IF;
  SELECT pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8'
         )),'hex')
    INTO STRICT dependency_source_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid =
    'app.private_platform_oidc_direct_dependency_surface_hash_v3()'::regprocedure;
  dependency_surface_hash :=
    app.private_platform_oidc_direct_dependency_surface_hash_v3();
  derived_definition := pg_catalog.replace(
    predecessor_definition,'private_platform_oidc_direct_runtime_schema_readiness_v2',
    'private_platform_oidc_direct_runtime_schema_readiness_v3'
  );
  derived_definition := pg_catalog.replace(
    derived_definition,'private_platform_oidc_direct_dependency_surface_hash_v2',
    'private_platform_oidc_direct_dependency_surface_hash_v3'
  );
  derived_definition := pg_catalog.replace(
    derived_definition,
    'abad60eab36af53228d2f4ca1981f26b349f82f5fdf24538cc57af81039b561a',
    dependency_source_hash
  );
  derived_definition := pg_catalog.replace(
    derived_definition,
    '4693f7681d42acda62971c06878bb66cd1643efa2a2a48899480c3d9ce714c2a',
    dependency_surface_hash
  );
  IF pg_catalog.strpos(derived_definition,final_marker) = 0 THEN
    RAISE EXCEPTION 'direct platform OIDC private readiness v3 marker drifted'
      USING ERRCODE = '55000';
  END IF;
  derived_definition := pg_catalog.replace(
    derived_definition,final_marker,mfa_check || final_marker
  );
  EXECUTE derived_definition;
END;
$bind_platform_oidc_direct_private_readiness_v3$;
ALTER FUNCTION app.private_platform_oidc_direct_runtime_schema_readiness_v3()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION
  app.private_platform_oidc_direct_runtime_schema_readiness_v3()
FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
  periapsis_auditor,periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,periapsis_sla_api_owner,
  periapsis_sla_worker_owner,periapsis_sla_readiness_owner,
  periapsis_ticket_saved_view_owner,periapsis_ticket_attribution_owner,
  periapsis_ticket_sla_projection_owner;
GRANT EXECUTE ON FUNCTION
  app.private_platform_oidc_direct_runtime_schema_readiness_v3()
TO periapsis_migrator;
--> statement-breakpoint

CREATE FUNCTION app.mfa_policy_administration_schema_readiness_v1()
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog,public,app
AS $function$
DECLARE
  current_count bigint;
BEGIN
  SELECT compatibility.applied_count INTO current_count
  FROM app.schema_compatibility_v41() AS compatibility;
  RETURN current_count = 184
    AND NOT pg_catalog.has_function_privilege(
      'periapsis_api','app.schema_compatibility_v40()'::regprocedure,'EXECUTE'
    )
    AND NOT pg_catalog.has_function_privilege(
      'periapsis_worker','app.schema_compatibility_v40()'::regprocedure,'EXECUTE'
    )
    AND app.private_mfa_policy_administration_schema_readiness_v1();
EXCEPTION WHEN undefined_table OR undefined_function OR insufficient_privilege
  OR invalid_schema_name OR cardinality_violation OR data_exception THEN
  RETURN false;
END;
$function$;
ALTER FUNCTION app.mfa_policy_administration_schema_readiness_v1()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.mfa_policy_administration_schema_readiness_v1()
FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
  periapsis_auditor,periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,periapsis_sla_api_owner,
  periapsis_sla_worker_owner,periapsis_sla_readiness_owner,
  periapsis_ticket_saved_view_owner,periapsis_ticket_attribution_owner,
  periapsis_ticket_sla_projection_owner;
GRANT EXECUTE ON FUNCTION app.mfa_policy_administration_schema_readiness_v1()
TO periapsis_api,periapsis_worker;
--> statement-breakpoint

DO $derive_platform_identity_public_readiness_v7$
DECLARE
  predecessor_definition text;
  derived_definition text;
  predecessor_source_hash text;
  final_marker constant text :=
    '    AND app.private_platform_identity_runtime_schema_readiness_v7();';
  v41_checks constant text :=
    '    AND NOT pg_catalog.has_function_privilege(' || chr(10) ||
    '      ''periapsis_api'',''app.schema_compatibility_v40()''::regprocedure,' || chr(10) ||
    '      ''EXECUTE''' || chr(10) ||
    '    )' || chr(10) ||
    '    AND NOT pg_catalog.has_function_privilege(' || chr(10) ||
    '      ''periapsis_worker'',''app.schema_compatibility_v40()''::regprocedure,' || chr(10) ||
    '      ''EXECUTE''' || chr(10) ||
    '    )' || chr(10) ||
    '    AND NOT pg_catalog.has_function_privilege(' || chr(10) ||
    '      ''periapsis_api'',' || chr(10) ||
    '      ''app.platform_identity_runtime_schema_readiness_v6()''::regprocedure,' || chr(10) ||
    '      ''EXECUTE''' || chr(10) ||
    '    )' || chr(10) ||
    '    AND NOT pg_catalog.has_function_privilege(' || chr(10) ||
    '      ''periapsis_worker'',' || chr(10) ||
    '      ''app.platform_identity_runtime_schema_readiness_v6()''::regprocedure,' || chr(10) ||
    '      ''EXECUTE''' || chr(10) ||
    '    )' || chr(10) ||
    '    AND app.mfa_policy_administration_schema_readiness_v1()' || chr(10);
BEGIN
  SELECT pg_catalog.pg_get_functiondef(function_row.oid),
         pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8'
         )),'hex')
    INTO STRICT predecessor_definition,predecessor_source_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid =
    'app.platform_identity_runtime_schema_readiness_v6()'::regprocedure;
  IF predecessor_source_hash IS DISTINCT FROM
       '8b5e5e3c96c883997ea7b525d18638e03ed3a7b9fc40ff4435386fc1faaaa602' THEN
    RAISE EXCEPTION 'platform identity public readiness v6 drifted'
      USING ERRCODE = '55000';
  END IF;
  derived_definition := pg_catalog.replace(
    predecessor_definition,'private_platform_identity_runtime_schema_readiness_v6',
    'private_platform_identity_runtime_schema_readiness_v7'
  );
  derived_definition := pg_catalog.replace(
    derived_definition,'platform_identity_runtime_schema_readiness_v6',
    'platform_identity_runtime_schema_readiness_v7'
  );
  derived_definition := pg_catalog.replace(
    derived_definition,'schema_compatibility_v40','schema_compatibility_v41'
  );
  derived_definition := pg_catalog.replace(
    derived_definition,'current_count = 182','current_count = 184'
  );
  IF pg_catalog.strpos(derived_definition,final_marker) = 0 THEN
    RAISE EXCEPTION 'platform identity public readiness v7 marker drifted'
      USING ERRCODE = '55000';
  END IF;
  derived_definition := pg_catalog.replace(
    derived_definition,final_marker,v41_checks || final_marker
  );
  EXECUTE derived_definition;
END;
$derive_platform_identity_public_readiness_v7$;
ALTER FUNCTION app.platform_identity_runtime_schema_readiness_v7()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.platform_identity_runtime_schema_readiness_v7()
FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
  periapsis_auditor,periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,periapsis_sla_api_owner,
  periapsis_sla_worker_owner,periapsis_sla_readiness_owner,
  periapsis_ticket_saved_view_owner,periapsis_ticket_attribution_owner,
  periapsis_ticket_sla_projection_owner;
GRANT EXECUTE ON FUNCTION app.platform_identity_runtime_schema_readiness_v7()
TO periapsis_api,periapsis_worker;
--> statement-breakpoint

DO $derive_platform_oidc_direct_public_readiness_v3$
DECLARE
  predecessor_definition text;
  derived_definition text;
  predecessor_source_hash text;
  final_marker constant text :=
    '    AND app.private_platform_oidc_direct_runtime_schema_readiness_v3();';
  v41_checks constant text :=
    '    AND NOT pg_catalog.has_function_privilege(' || chr(10) ||
    '      ''periapsis_api'',''app.schema_compatibility_v40()''::regprocedure,' || chr(10) ||
    '      ''EXECUTE''' || chr(10) ||
    '    )' || chr(10) ||
    '    AND NOT pg_catalog.has_function_privilege(' || chr(10) ||
    '      ''periapsis_worker'',''app.schema_compatibility_v40()''::regprocedure,' || chr(10) ||
    '      ''EXECUTE''' || chr(10) ||
    '    )' || chr(10) ||
    '    AND NOT pg_catalog.has_function_privilege(' || chr(10) ||
    '      ''periapsis_api'',' || chr(10) ||
    '      ''app.platform_identity_runtime_schema_readiness_v6()''::regprocedure,' || chr(10) ||
    '      ''EXECUTE''' || chr(10) ||
    '    )' || chr(10) ||
    '    AND NOT pg_catalog.has_function_privilege(' || chr(10) ||
    '      ''periapsis_worker'',' || chr(10) ||
    '      ''app.platform_identity_runtime_schema_readiness_v6()''::regprocedure,' || chr(10) ||
    '      ''EXECUTE''' || chr(10) ||
    '    )' || chr(10) ||
    '    AND NOT pg_catalog.has_function_privilege(' || chr(10) ||
    '      ''periapsis_api'',' || chr(10) ||
    '      ''app.platform_oidc_direct_runtime_schema_readiness_v2()''::regprocedure,' || chr(10) ||
    '      ''EXECUTE''' || chr(10) ||
    '    )' || chr(10) ||
    '    AND NOT pg_catalog.has_function_privilege(' || chr(10) ||
    '      ''periapsis_worker'',' || chr(10) ||
    '      ''app.platform_oidc_direct_runtime_schema_readiness_v2()''::regprocedure,' || chr(10) ||
    '      ''EXECUTE''' || chr(10) ||
    '    )' || chr(10) ||
    '    AND app.platform_identity_runtime_schema_readiness_v7()' || chr(10);
BEGIN
  SELECT pg_catalog.pg_get_functiondef(function_row.oid),
         pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8'
         )),'hex')
    INTO STRICT predecessor_definition,predecessor_source_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid =
    'app.platform_oidc_direct_runtime_schema_readiness_v2()'::regprocedure;
  IF predecessor_source_hash IS DISTINCT FROM
       '30afcb13eb129e7b61a33ad9750a374a9f79c880761413dbf6826c9dde500898' THEN
    RAISE EXCEPTION 'direct platform OIDC public readiness v2 drifted'
      USING ERRCODE = '55000';
  END IF;
  derived_definition := pg_catalog.replace(
    predecessor_definition,'private_platform_oidc_direct_runtime_schema_readiness_v2',
    'private_platform_oidc_direct_runtime_schema_readiness_v3'
  );
  derived_definition := pg_catalog.replace(
    derived_definition,'platform_oidc_direct_runtime_schema_readiness_v2',
    'platform_oidc_direct_runtime_schema_readiness_v3'
  );
  derived_definition := pg_catalog.replace(
    derived_definition,'schema_compatibility_v40','schema_compatibility_v41'
  );
  derived_definition := pg_catalog.replace(
    derived_definition,'current_count = 182','current_count = 184'
  );
  derived_definition := pg_catalog.replace(
    derived_definition,'platform_identity_runtime_schema_readiness_v6',
    'platform_identity_runtime_schema_readiness_v7'
  );
  IF pg_catalog.strpos(derived_definition,final_marker) = 0 THEN
    RAISE EXCEPTION 'direct platform OIDC public readiness v3 marker drifted'
      USING ERRCODE = '55000';
  END IF;
  derived_definition := pg_catalog.replace(
    derived_definition,final_marker,v41_checks || final_marker
  );
  EXECUTE derived_definition;
END;
$derive_platform_oidc_direct_public_readiness_v3$;
ALTER FUNCTION app.platform_oidc_direct_runtime_schema_readiness_v3()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.platform_oidc_direct_runtime_schema_readiness_v3()
FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
  periapsis_auditor,periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,periapsis_sla_api_owner,
  periapsis_sla_worker_owner,periapsis_sla_readiness_owner,
  periapsis_ticket_saved_view_owner,periapsis_ticket_attribution_owner,
  periapsis_ticket_sla_projection_owner;
GRANT EXECUTE ON FUNCTION app.platform_oidc_direct_runtime_schema_readiness_v3()
TO periapsis_api,periapsis_worker;
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
SET search_path = pg_catalog,public,app
AS $function$
DECLARE
  journal_count bigint;
  journal_latest_created_at bigint;
  journal_latest_hash text;
  journal_fingerprint text;
  sealed_count bigint;
  sealed_latest_created_at bigint;
  sealed_latest_hash text;
  sealed_fingerprint text;
  predecessor_count bigint;
BEGIN
  IF p_expected_count IS DISTINCT FROM 184
     OR p_expected_latest_created_at IS DISTINCT FROM 1788094095501
     OR p_expected_latest_hash !~ '^[0-9a-f]{64}$'
     OR p_expected_migration_fingerprint !~
       '^[0-9]+@[0-9a-f]{64}(:[0-9]+@[0-9a-f]{64}){183}$' THEN
    RAISE EXCEPTION 'schema compatibility v41 seal input is invalid'
      USING ERRCODE = '55000';
  END IF;
  EXECUTE $query$
    SELECT count(*)::bigint,max(migration.created_at)::bigint,
           (SELECT lower(latest.hash::text)
            FROM drizzle.__drizzle_migrations AS latest
            ORDER BY latest.created_at DESC,latest.id DESC LIMIT 1),
           string_agg(
             migration.created_at::text || '@' || lower(migration.hash::text),
             ':' ORDER BY migration.created_at,migration.id
           )
    FROM drizzle.__drizzle_migrations AS migration
  $query$ INTO journal_count,journal_latest_created_at,journal_latest_hash,
                journal_fingerprint;
  IF ROW(journal_count,journal_latest_created_at,journal_latest_hash,
         journal_fingerprint) IS DISTINCT FROM
     ROW(p_expected_count,p_expected_latest_created_at,p_expected_latest_hash,
         p_expected_migration_fingerprint)
     OR NOT app.private_mfa_policy_administration_schema_readiness_v1()
     OR NOT app.private_platform_identity_runtime_schema_readiness_v7()
     OR NOT app.private_platform_oidc_direct_runtime_schema_readiness_v3()
     OR pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
       (SELECT function_row.prosrc FROM pg_catalog.pg_proc AS function_row
        WHERE function_row.oid =
          'app.schema_compatibility_v40()'::regprocedure),'UTF8'
     )),'hex') <>
       'd4f2e0efa33d722bcb97b926c8afb8d6050838548f891d789b7d44d303a6fe4c'
     OR pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
       (SELECT function_row.prosrc FROM pg_catalog.pg_proc AS function_row
        WHERE function_row.oid =
          'app.platform_identity_runtime_schema_readiness_v6()'::regprocedure),
       'UTF8'
     )),'hex') <>
       '8b5e5e3c96c883997ea7b525d18638e03ed3a7b9fc40ff4435386fc1faaaa602'
     OR pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
       (SELECT function_row.prosrc FROM pg_catalog.pg_proc AS function_row
        WHERE function_row.oid =
          'app.platform_oidc_direct_runtime_schema_readiness_v2()'::regprocedure),
       'UTF8'
     )),'hex') <>
       '30afcb13eb129e7b61a33ad9750a374a9f79c880761413dbf6826c9dde500898'
  THEN
    RAISE EXCEPTION 'schema compatibility v41 pre-seal verification failed'
      USING ERRCODE = '55000';
  END IF;

  EXECUTE pg_catalog.format(
    'ALTER FUNCTION app.schema_compatibility_v41() SET app.schema_compatibility_fingerprint = %L',
    p_expected_migration_fingerprint
  );
  EXECUTE $ddl$
    ALTER FUNCTION app.schema_compatibility_v40()
      SET app.schema_compatibility_fingerprint = 'RETIRED'
  $ddl$;
  EXECUTE $ddl$
    REVOKE ALL ON FUNCTION app.schema_compatibility_v40()
      FROM periapsis_api,periapsis_worker
  $ddl$;
  EXECUTE $ddl$
    REVOKE ALL ON FUNCTION app.platform_identity_runtime_schema_readiness_v6()
      FROM periapsis_api,periapsis_worker
  $ddl$;
  EXECUTE $ddl$
    REVOKE ALL ON FUNCTION app.platform_oidc_direct_runtime_schema_readiness_v2()
      FROM periapsis_api,periapsis_worker
  $ddl$;
  -- A fresh install executes only the latest sealer. Retire the immutable V39
  -- roots as well so fresh and stepwise cutovers converge on identical ACLs.
  EXECUTE $ddl$
    REVOKE ALL ON FUNCTION app.schema_compatibility_v39()
      FROM periapsis_api,periapsis_worker
  $ddl$;
  EXECUTE $ddl$
    REVOKE ALL ON FUNCTION app.platform_identity_runtime_schema_readiness_v5()
      FROM periapsis_api,periapsis_worker
  $ddl$;
  EXECUTE $ddl$
    REVOKE ALL ON FUNCTION app.platform_oidc_direct_runtime_schema_readiness_v1()
      FROM periapsis_api,periapsis_worker
  $ddl$;

  SELECT compatibility.applied_count,compatibility.latest_created_at,
         compatibility.latest_hash,compatibility.migration_fingerprint
    INTO sealed_count,sealed_latest_created_at,sealed_latest_hash,
         sealed_fingerprint
  FROM app.schema_compatibility_v41() AS compatibility;
  SELECT compatibility.applied_count INTO predecessor_count
  FROM app.schema_compatibility_v40() AS compatibility;
  IF ROW(sealed_count,sealed_latest_created_at,sealed_latest_hash,
         sealed_fingerprint) IS DISTINCT FROM
     ROW(p_expected_count,p_expected_latest_created_at,p_expected_latest_hash,
         p_expected_migration_fingerprint)
     OR predecessor_count <> 0
     OR NOT app.mfa_policy_administration_schema_readiness_v1()
     OR NOT app.platform_identity_runtime_schema_readiness_v7()
     OR NOT app.platform_oidc_direct_runtime_schema_readiness_v3()
     OR pg_catalog.has_function_privilege(
       'periapsis_api','app.schema_compatibility_v40()'::regprocedure,'EXECUTE'
     )
     OR pg_catalog.has_function_privilege(
       'periapsis_worker','app.schema_compatibility_v40()'::regprocedure,'EXECUTE'
     )
     OR pg_catalog.has_function_privilege(
       'periapsis_api',
       'app.platform_identity_runtime_schema_readiness_v6()'::regprocedure,
       'EXECUTE'
     )
     OR pg_catalog.has_function_privilege(
       'periapsis_worker',
       'app.platform_identity_runtime_schema_readiness_v6()'::regprocedure,
       'EXECUTE'
     )
     OR pg_catalog.has_function_privilege(
       'periapsis_api',
       'app.platform_oidc_direct_runtime_schema_readiness_v2()'::regprocedure,
       'EXECUTE'
     )
     OR pg_catalog.has_function_privilege(
       'periapsis_worker',
       'app.platform_oidc_direct_runtime_schema_readiness_v2()'::regprocedure,
       'EXECUTE'
     ) THEN
    RAISE EXCEPTION 'schema compatibility v41 seal verification failed'
      USING ERRCODE = '55000';
  END IF;
END;
$function$;
ALTER FUNCTION app.seal_schema_compatibility_manifest(
  bigint,bigint,text,text
) OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.seal_schema_compatibility_manifest(
  bigint,bigint,text,text
) FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
  periapsis_auditor,periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,periapsis_sla_api_owner,
  periapsis_sla_worker_owner,periapsis_sla_readiness_owner,
  periapsis_ticket_saved_view_owner,periapsis_ticket_attribution_owner,
  periapsis_ticket_sla_projection_owner;
GRANT EXECUTE ON FUNCTION app.seal_schema_compatibility_manifest(
  bigint,bigint,text,text
) TO periapsis_migrator;
--> statement-breakpoint

DO $bind_mfa_policy_administration_private_readiness_v1$
DECLARE
  template_definition text := $template$
CREATE OR REPLACE FUNCTION app.private_mfa_policy_administration_schema_readiness_v1()
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog,public,app
AS $body$
DECLARE
  surface_ok boolean;
BEGIN
  IF pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
       (SELECT function_row.prosrc
        FROM pg_catalog.pg_proc AS function_row
        WHERE function_row.oid =
          'app.private_mfa_policy_administration_dependency_surface_hash_v1()'::regprocedure),
       'UTF8'
     )),'hex') <> '__DEPENDENCY_SOURCE_HASH__'
     OR app.private_mfa_policy_administration_dependency_surface_hash_v1()
       <> '__DEPENDENCY_SURFACE_HASH__' THEN
    RETURN false;
  END IF;

  SELECT count(*) = 2 AND coalesce(bool_and(
    relation_row.relowner = 'periapsis_migrator'::regrole
    AND relation_row.relrowsecurity
    AND relation_row.relforcerowsecurity
    AND relation_row.relkind = 'r'
    AND NOT pg_catalog.has_table_privilege(
      'periapsis_api',relation_row.oid,
      'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
    )
    AND NOT pg_catalog.has_table_privilege(
      'periapsis_worker',relation_row.oid,
      'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
    )
    AND NOT pg_catalog.has_table_privilege(
      'periapsis_notifier',relation_row.oid,
      'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
    )
  ),false) INTO surface_ok
  FROM pg_catalog.pg_class AS relation_row
  WHERE relation_row.oid IN (
    'public.mfa_policy_revisions'::regclass,
    'public.mfa_policy_commands'::regclass
  );
  IF NOT surface_ok OR EXISTS (
    SELECT 1 FROM pg_catalog.pg_policy AS policy_row
    WHERE policy_row.polrelid IN (
      'public.mfa_policy_revisions'::regclass,
      'public.mfa_policy_commands'::regclass
    )
  ) THEN
    RETURN false;
  END IF;

  SELECT count(*) = 3 AND coalesce(bool_and(
    NOT trigger_row.tgisinternal AND trigger_row.tgenabled = 'O'
    AND trigger_row.tgfoid = CASE trigger_row.tgname
      WHEN 'mfa_policy_commands_guard_v1'
        THEN 'app.guard_mfa_policy_command_v1()'::regprocedure
      WHEN 'mfa_policy_revisions_guard_v1'
        THEN 'app.guard_mfa_policy_revision_v1()'::regprocedure
      ELSE 'app.touch_mfa_policy_authority_v1()'::regprocedure
    END
  ),false) INTO surface_ok
  FROM pg_catalog.pg_trigger AS trigger_row
  WHERE (trigger_row.tgrelid,trigger_row.tgname) IN (
    ('public.mfa_policy_commands'::regclass,
     'mfa_policy_commands_guard_v1'),
    ('public.mfa_policy_revisions'::regclass,
     'mfa_policy_revisions_guard_v1'),
    ('public.mfa_policy_revisions'::regclass,
     'mfa_policy_revisions_authority_v1')
  );
  IF NOT surface_ok THEN
    RETURN false;
  END IF;

  WITH expected(signature) AS (VALUES
    ('app.list_platform_mfa_policies_v1(uuid,text,uuid,bigint,integer,boolean)'::regprocedure),
    ('app.list_tenant_mfa_policies_v1(uuid,uuid,text,uuid,bigint,integer,boolean)'::regprocedure),
    ('app.get_platform_mfa_policy_v1(uuid,text,uuid,bigint)'::regprocedure),
    ('app.get_tenant_mfa_policy_v1(uuid,uuid,text,uuid,bigint)'::regprocedure),
    ('app.simulate_platform_mfa_policy_change_v1(uuid,text,jsonb)'::regprocedure),
    ('app.simulate_tenant_mfa_policy_change_v1(uuid,uuid,text,jsonb)'::regprocedure),
    ('app.publish_platform_mfa_policy_v1(uuid,text,jsonb)'::regprocedure),
    ('app.retire_platform_mfa_policy_v1(uuid,text,jsonb)'::regprocedure),
    ('app.publish_tenant_mfa_policy_v1(uuid,uuid,text,jsonb)'::regprocedure),
    ('app.retire_tenant_mfa_policy_v1(uuid,uuid,text,jsonb)'::regprocedure)
  )
  SELECT count(*) = 10 AND coalesce(bool_and(
    function_row.proowner = 'periapsis_migrator'::regrole
    AND function_row.prosecdef
    AND function_row.proconfig @>
      ARRAY['search_path=pg_catalog, public, app']::text[]
    AND pg_catalog.has_function_privilege(
      'periapsis_api',function_row.oid,'EXECUTE'
    )
    AND NOT pg_catalog.has_function_privilege(
      'periapsis_worker',function_row.oid,'EXECUTE'
    )
    AND NOT pg_catalog.has_function_privilege(
      'periapsis_notifier',function_row.oid,'EXECUTE'
    )
    AND NOT pg_catalog.has_function_privilege(
      'periapsis_auditor',function_row.oid,'EXECUTE'
    )
  ),false) INTO surface_ok
  FROM expected
  JOIN pg_catalog.pg_proc AS function_row
    ON function_row.oid = expected.signature;
  IF NOT surface_ok THEN
    RETURN false;
  END IF;

  IF EXISTS (
    SELECT 1
    FROM pg_catalog.pg_proc AS function_row
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = function_row.pronamespace
    WHERE namespace.nspname = 'app'
      AND function_row.proname LIKE '%mfa_polic%'
      AND function_row.oid NOT IN (
        'app.list_platform_mfa_policies_v1(uuid,text,uuid,bigint,integer,boolean)'::regprocedure,
        'app.list_tenant_mfa_policies_v1(uuid,uuid,text,uuid,bigint,integer,boolean)'::regprocedure,
        'app.get_platform_mfa_policy_v1(uuid,text,uuid,bigint)'::regprocedure,
        'app.get_tenant_mfa_policy_v1(uuid,uuid,text,uuid,bigint)'::regprocedure,
        'app.simulate_platform_mfa_policy_change_v1(uuid,text,jsonb)'::regprocedure,
        'app.simulate_tenant_mfa_policy_change_v1(uuid,uuid,text,jsonb)'::regprocedure,
        'app.publish_platform_mfa_policy_v1(uuid,text,jsonb)'::regprocedure,
        'app.retire_platform_mfa_policy_v1(uuid,text,jsonb)'::regprocedure,
        'app.publish_tenant_mfa_policy_v1(uuid,uuid,text,jsonb)'::regprocedure,
        'app.retire_tenant_mfa_policy_v1(uuid,uuid,text,jsonb)'::regprocedure,
        'app.mfa_policy_administration_schema_readiness_v1()'::regprocedure
      )
      AND (
        function_row.proowner <> 'periapsis_migrator'::regrole
        OR NOT function_row.prosecdef
        OR function_row.proconfig IS NULL
        OR NOT function_row.proconfig @>
          ARRAY['search_path=pg_catalog, public, app']::text[]
        OR pg_catalog.has_function_privilege(
          'periapsis_api',function_row.oid,'EXECUTE'
        )
        OR pg_catalog.has_function_privilege(
          'periapsis_worker',function_row.oid,'EXECUTE'
        )
        OR pg_catalog.has_function_privilege(
          'periapsis_notifier',function_row.oid,'EXECUTE'
        )
      )
  ) THEN
    RETURN false;
  END IF;

  IF (SELECT count(*) FROM ONLY public.tenant_permissions AS permission
      WHERE permission.key IN (
        'identity_policy.read','identity_policy.manage'
      ) AND permission.service_account_allowed IS FALSE) <> 2
     OR EXISTS (
       SELECT 1
       FROM ONLY public.tenant_permissions AS permission
       LEFT JOIN ONLY public.tenant_permission_scopes AS permission_scope
         ON permission_scope.permission_id = permission.id
       WHERE permission.key IN (
         'identity_policy.read','identity_policy.manage'
       ) AND (permission_scope.scope IS DISTINCT FROM 'tenant'
              OR permission_scope.permission_id IS NULL)
     )
     OR (SELECT count(*)
       FROM ONLY public.tenant_permissions AS permission
       JOIN ONLY public.tenant_permission_scopes AS permission_scope
         ON permission_scope.permission_id = permission.id
       WHERE permission.key IN (
         'identity_policy.read','identity_policy.manage'
       ) AND permission_scope.scope = 'tenant') <> 2 THEN
    RETURN false;
  END IF;
  IF EXISTS (
    SELECT 1
    FROM ONLY public.tenants AS tenant
    WHERE NOT EXISTS (
      SELECT 1
      FROM ONLY public.tenant_roles AS role
      JOIN ONLY public.tenant_role_permissions AS role_permission
        ON role_permission.tenant_id = role.tenant_id
       AND role_permission.role_id = role.id
       AND role_permission.scope = 'tenant'
      JOIN ONLY public.tenant_permissions AS permission
        ON permission.id = role_permission.permission_id
      JOIN ONLY public.tenant_role_delegation_ceilings AS ceiling
        ON ceiling.tenant_id = role.tenant_id
       AND ceiling.role_id = role.id
       AND ceiling.permission_id = permission.id
       AND ceiling.scope = 'tenant'
      WHERE role.tenant_id = tenant.id
        AND role.key = 'tenant_admin'
        AND role.principal_kind = 'human'
        AND role.system_role AND role.protected_role
        AND role.archived_at IS NULL
        AND permission.key = 'identity_policy.read'
    ) OR NOT EXISTS (
      SELECT 1
      FROM ONLY public.tenant_roles AS role
      JOIN ONLY public.tenant_role_permissions AS role_permission
        ON role_permission.tenant_id = role.tenant_id
       AND role_permission.role_id = role.id
       AND role_permission.scope = 'tenant'
      JOIN ONLY public.tenant_permissions AS permission
        ON permission.id = role_permission.permission_id
      JOIN ONLY public.tenant_role_delegation_ceilings AS ceiling
        ON ceiling.tenant_id = role.tenant_id
       AND ceiling.role_id = role.id
       AND ceiling.permission_id = permission.id
       AND ceiling.scope = 'tenant'
      WHERE role.tenant_id = tenant.id
        AND role.key = 'tenant_admin'
        AND role.principal_kind = 'human'
        AND role.system_role AND role.protected_role
        AND role.archived_at IS NULL
        AND permission.key = 'identity_policy.manage'
    )
  ) THEN
    RETURN false;
  END IF;

  IF EXISTS (
    SELECT 1 FROM ONLY public.mfa_policy_revisions AS policy
    WHERE policy.revision NOT BETWEEN 1 AND 9007199254740991
       OR policy.freshness_nanoseconds NOT BETWEEN 0 AND 31536000000000000
       OR mod(policy.freshness_nanoseconds,1000000000) <> 0
       OR (policy.enrollment_deadline IS NOT NULL
           AND policy.enrollment_deadline <= policy.created_at)
  ) OR EXISTS (
    SELECT 1
    FROM ONLY public.mfa_policy_revisions AS policy
    WHERE policy.retired_at IS NULL
    GROUP BY policy.scope,policy.tenant_id,policy.role_id,
             policy.security_group_id,policy.action
    HAVING count(*) > 1
  ) THEN
    RETURN false;
  END IF;
  RETURN true;
EXCEPTION WHEN undefined_table OR undefined_function OR insufficient_privilege
  OR invalid_schema_name OR cardinality_violation OR data_exception THEN
  RETURN false;
END;
$body$;
$template$;
  dependency_source_hash text;
  dependency_surface_hash text;
BEGIN
  SELECT pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8'
         )),'hex')
    INTO STRICT dependency_source_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid =
    'app.private_mfa_policy_administration_dependency_surface_hash_v1()'::regprocedure;
  dependency_surface_hash :=
    app.private_mfa_policy_administration_dependency_surface_hash_v1();
  IF dependency_source_hash !~ '^[0-9a-f]{64}$'
     OR dependency_surface_hash !~ '^[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'MFA policy dependency surface is invalid'
      USING ERRCODE = '55000';
  END IF;
  template_definition := pg_catalog.replace(
    template_definition,'__DEPENDENCY_SOURCE_HASH__',dependency_source_hash
  );
  template_definition := pg_catalog.replace(
    template_definition,'__DEPENDENCY_SURFACE_HASH__',dependency_surface_hash
  );
  EXECUTE template_definition;
END;
$bind_mfa_policy_administration_private_readiness_v1$;
ALTER FUNCTION app.private_mfa_policy_administration_schema_readiness_v1()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION
  app.private_mfa_policy_administration_schema_readiness_v1()
FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
  periapsis_auditor,periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,periapsis_sla_api_owner,
  periapsis_sla_worker_owner,periapsis_sla_readiness_owner,
  periapsis_ticket_saved_view_owner,periapsis_ticket_attribution_owner,
  periapsis_ticket_sla_projection_owner;
GRANT EXECUTE ON FUNCTION
  app.private_mfa_policy_administration_schema_readiness_v1()
TO periapsis_migrator;
--> statement-breakpoint

-- The sealer is transcript-visible, so V7 is rebound only after the sealer
-- and the dedicated MFA verifier both have their final definitions.
DO $sealed_bind_platform_identity_runtime_private_readiness_v7$
DECLARE
  predecessor_definition text;
  derived_definition text;
  predecessor_source_hash text;
  dependency_source_hash text;
  dependency_surface_hash text;
  final_marker constant text :=
    '  RETURN true;' || chr(10) || 'END;';
  mfa_check constant text :=
    '  IF NOT app.private_mfa_policy_administration_schema_readiness_v1() THEN' || chr(10) ||
    '    RETURN false;' || chr(10) ||
    '  END IF;' || chr(10) || chr(10);
BEGIN
  SELECT pg_catalog.pg_get_functiondef(function_row.oid),
         pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8'
         )),'hex')
    INTO STRICT predecessor_definition,predecessor_source_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid =
    'app.private_platform_identity_runtime_schema_readiness_v6()'::regprocedure;
  IF predecessor_source_hash IS DISTINCT FROM
       '06f1d8979113eee281b3103c2a39a5dbe00e73f2fbf92c3f25f7d18655b02569' THEN
    RAISE EXCEPTION 'platform identity private readiness v6 drifted'
      USING ERRCODE = '55000';
  END IF;
  SELECT pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8'
         )),'hex')
    INTO STRICT dependency_source_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid =
    'app.private_platform_identity_dependency_surface_hash_v7()'::regprocedure;
  dependency_surface_hash :=
    app.private_platform_identity_dependency_surface_hash_v7();
  derived_definition := pg_catalog.replace(
    predecessor_definition,'private_platform_identity_runtime_schema_readiness_v6',
    'private_platform_identity_runtime_schema_readiness_v7'
  );
  derived_definition := pg_catalog.replace(
    derived_definition,'private_platform_identity_dependency_surface_hash_v6',
    'private_platform_identity_dependency_surface_hash_v7'
  );
  derived_definition := pg_catalog.replace(
    derived_definition,'platform_identity_runtime_schema_readiness_v6',
    'platform_identity_runtime_schema_readiness_v7'
  );
  derived_definition := pg_catalog.replace(
    derived_definition,'schema_compatibility_v40','schema_compatibility_v41'
  );
  derived_definition := pg_catalog.replace(
    derived_definition,
    'b6ac9c2d70924d1d3194dcc38fea91b6245a2e798df202bbdbfcdacf96e57c7e',
    dependency_source_hash
  );
  derived_definition := pg_catalog.replace(
    derived_definition,
    '6481d203d3c704a2ec2331ae49e0a9b5a2bced4ed8cbc0c7347a61f8d8f019d6',
    dependency_surface_hash
  );
  IF pg_catalog.strpos(derived_definition,final_marker) = 0 THEN
    RAISE EXCEPTION 'platform identity sealed readiness v7 marker drifted'
      USING ERRCODE = '55000';
  END IF;
  derived_definition := pg_catalog.replace(
    derived_definition,final_marker,mfa_check || final_marker
  );
  EXECUTE derived_definition;
END;
$sealed_bind_platform_identity_runtime_private_readiness_v7$;
ALTER FUNCTION app.private_platform_identity_runtime_schema_readiness_v7()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_platform_identity_runtime_schema_readiness_v7()
FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
  periapsis_auditor,periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,periapsis_sla_api_owner,
  periapsis_sla_worker_owner,periapsis_sla_readiness_owner,
  periapsis_ticket_saved_view_owner,periapsis_ticket_attribution_owner,
  periapsis_ticket_sla_projection_owner;
GRANT EXECUTE ON FUNCTION app.private_platform_identity_runtime_schema_readiness_v7()
TO periapsis_migrator;
--> statement-breakpoint
