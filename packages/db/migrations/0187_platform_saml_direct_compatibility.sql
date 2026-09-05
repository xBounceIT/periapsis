ALTER TABLE "auth_session_tenant_platform_federated_provenance" DROP CONSTRAINT "auth_session_tenant_platform_federated_provenance_value_check";--> statement-breakpoint
ALTER TABLE "auth_session_tenant_platform_federated_provenance" ADD CONSTRAINT "auth_session_tenant_platform_federated_provenance_value_check" CHECK ("auth_session_tenant_platform_federated_provenance"."primary_kind" = 'tenant_platform_provider'
        and "auth_session_tenant_platform_federated_provenance"."authentication_method" in ('oidc','saml')
        and "auth_session_tenant_platform_federated_provenance"."external_identity_revision" between 1 and 2147483647
        and "auth_session_tenant_platform_federated_provenance"."provider_revision" between 1 and 2147483647
        and "auth_session_tenant_platform_federated_provenance"."binding_revision" between 1 and 2147483647
        and "auth_session_tenant_platform_federated_provenance"."security_revision" between 1 and 9007199254740991
        and "auth_session_tenant_platform_federated_provenance"."mapping_revision" between 1 and 9007199254740991
        and "auth_session_tenant_platform_federated_provenance"."authorization_revision" between 1 and 9007199254740991
        and "auth_session_tenant_platform_federated_provenance"."subject_alias_key_version" between 1 and 32767
        and "auth_session_tenant_platform_federated_provenance"."trust_rule_revision" between 1 and 9007199254740991);
--> statement-breakpoint

CREATE FUNCTION app.schema_compatibility_v42()
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
             WHERE migration.created_at = 1788107911419
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
  WHERE function_row.oid='app.schema_compatibility_v42()'::regprocedure
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
  IF journal_count=188 AND journal_latest_created_at=1788107911419
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
ALTER FUNCTION app.schema_compatibility_v42() OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.schema_compatibility_v42()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier;
GRANT EXECUTE ON FUNCTION app.schema_compatibility_v42()
  TO periapsis_api,periapsis_worker;
--> statement-breakpoint

DO $derive_platform_identity_dependency_surface_v8$
DECLARE
  predecessor_definition text;
  predecessor_source_hash text;
  derived_definition text;
  marker constant text := '        ''schema_compatibility_v42'',';
  exclusions constant text :=
    '        ''private_platform_identity_dependency_surface_hash_v7'',' || chr(10) ||
    '        ''private_platform_identity_runtime_schema_readiness_v7'',' || chr(10) ||
    '        ''platform_identity_runtime_schema_readiness_v7'',' || chr(10) ||
    '        ''schema_compatibility_v41'',' || chr(10) ||
    '        ''private_platform_oidc_direct_dependency_surface_hash_v4'',' || chr(10) ||
    '        ''private_platform_oidc_direct_runtime_schema_readiness_v4'',' || chr(10) ||
    '        ''platform_oidc_direct_runtime_schema_readiness_v4'',' || chr(10) ||
    '        ''private_platform_saml_direct_dependency_surface_hash_v1'',' || chr(10) ||
    '        ''private_platform_saml_direct_runtime_schema_readiness_v1'',' || chr(10) ||
    '        ''platform_saml_direct_runtime_schema_readiness_v1'',' || chr(10) ||
    '        ''private_mfa_policy_administration_dependency_surface_hash_v2'',' || chr(10) ||
    '        ''private_mfa_policy_administration_schema_readiness_v2'',' || chr(10) ||
    '        ''mfa_policy_administration_schema_readiness_v2'',';
BEGIN
  SELECT pg_catalog.pg_get_functiondef(function_row.oid),
         pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8')),'hex')
    INTO STRICT predecessor_definition,predecessor_source_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid=
    'app.private_platform_identity_dependency_surface_hash_v7()'::regprocedure;
  IF predecessor_source_hash<>
    '11aaeb68992daf0e5df7a81eefc66aab1f6d2572b834ff73c3a4d6989253b287' THEN
    RAISE EXCEPTION 'platform identity dependency v7 drifted'
      USING ERRCODE='55000';
  END IF;
  derived_definition:=pg_catalog.replace(
    predecessor_definition,
    'private_platform_identity_dependency_surface_hash_v7',
    'private_platform_identity_dependency_surface_hash_v8'
  );
  derived_definition:=pg_catalog.replace(
    derived_definition,'private_platform_identity_runtime_schema_readiness_v7',
    'private_platform_identity_runtime_schema_readiness_v8'
  );
  derived_definition:=pg_catalog.replace(
    derived_definition,'platform_identity_runtime_schema_readiness_v7',
    'platform_identity_runtime_schema_readiness_v8'
  );
  derived_definition:=pg_catalog.replace(
    derived_definition,'schema_compatibility_v41','schema_compatibility_v42'
  );
  IF pg_catalog.strpos(derived_definition,marker)=0 THEN
    RAISE EXCEPTION 'platform identity dependency v8 marker drifted'
      USING ERRCODE='55000';
  END IF;
  derived_definition:=pg_catalog.replace(
    derived_definition,marker,marker || chr(10) || exclusions
  );
  EXECUTE derived_definition;
END;
$derive_platform_identity_dependency_surface_v8$;
ALTER FUNCTION app.private_platform_identity_dependency_surface_hash_v8()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_platform_identity_dependency_surface_hash_v8()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier;
--> statement-breakpoint

CREATE FUNCTION app.private_platform_oidc_direct_dependency_surface_hash_v4()
RETURNS text LANGUAGE sql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app
SET quote_all_identifiers=off SET TimeZone='UTC' SET DateStyle='ISO, YMD'
SET IntervalStyle='postgres' SET extra_float_digits=3 SET bytea_output='hex'
SET standard_conforming_strings=on SET lc_numeric='C'
AS $function$
  SELECT app.private_platform_identity_dependency_surface_hash_v8();
$function$;
CREATE FUNCTION app.private_platform_saml_direct_dependency_surface_hash_v1()
RETURNS text LANGUAGE sql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app
SET quote_all_identifiers=off SET TimeZone='UTC' SET DateStyle='ISO, YMD'
SET IntervalStyle='postgres' SET extra_float_digits=3 SET bytea_output='hex'
SET standard_conforming_strings=on SET lc_numeric='C'
AS $function$
  SELECT app.private_platform_identity_dependency_surface_hash_v8();
$function$;
CREATE FUNCTION app.private_mfa_policy_administration_dependency_surface_hash_v2()
RETURNS text LANGUAGE sql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app
SET quote_all_identifiers=off SET TimeZone='UTC' SET DateStyle='ISO, YMD'
SET IntervalStyle='postgres' SET extra_float_digits=3 SET bytea_output='hex'
SET standard_conforming_strings=on SET lc_numeric='C'
AS $function$
  SELECT app.private_platform_identity_dependency_surface_hash_v8();
$function$;
ALTER FUNCTION app.private_platform_oidc_direct_dependency_surface_hash_v4()
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_platform_saml_direct_dependency_surface_hash_v1()
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_mfa_policy_administration_dependency_surface_hash_v2()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_platform_oidc_direct_dependency_surface_hash_v4()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier;
REVOKE ALL ON FUNCTION app.private_platform_saml_direct_dependency_surface_hash_v1()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier;
REVOKE ALL ON FUNCTION app.private_mfa_policy_administration_dependency_surface_hash_v2()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier;
--> statement-breakpoint

DO $derive_mfa_policy_private_readiness_v2$
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
    'app.private_mfa_policy_administration_schema_readiness_v1()'::regprocedure;
  IF predecessor_hash<>
    'f6eddba06c00c0b535fa762eb3f3adb0b3c361e96ec48745302592a1e646b216' THEN
    RAISE EXCEPTION 'MFA policy private readiness v1 drifted'
      USING ERRCODE='55000';
  END IF;
  SELECT pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8')),'hex'),
         app.private_mfa_policy_administration_dependency_surface_hash_v2()
    INTO STRICT dependency_source_hash,dependency_result_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid=
    'app.private_mfa_policy_administration_dependency_surface_hash_v2()'::regprocedure;
  definition:=pg_catalog.replace(definition,
    'private_mfa_policy_administration_dependency_surface_hash_v1',
    'private_mfa_policy_administration_dependency_surface_hash_v2');
  definition:=pg_catalog.replace(definition,
    'private_mfa_policy_administration_schema_readiness_v1',
    'private_mfa_policy_administration_schema_readiness_v2');
  definition:=pg_catalog.replace(definition,
    '''app.mfa_policy_administration_schema_readiness_v1()''::regprocedure',
    '''app.mfa_policy_administration_schema_readiness_v1()''::regprocedure,' ||
    chr(10) ||
    '        ''app.mfa_policy_administration_schema_readiness_v2()''::regprocedure'
  );
  definition:=pg_catalog.replace(definition,
    'dcfa970dc5239c535eeb30a7433989a3aab8572ec05572e6b660092f9eb6e73b',
    dependency_source_hash);
  definition:=pg_catalog.replace(definition,
    'd22db49908873d5241222746e3ac4d5cc2ec5d46c3376ca7dfb8583bb7dc6287',
    dependency_result_hash);
  EXECUTE definition;
END;
$derive_mfa_policy_private_readiness_v2$;
ALTER FUNCTION app.private_mfa_policy_administration_schema_readiness_v2()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_mfa_policy_administration_schema_readiness_v2()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier;
--> statement-breakpoint

DO $derive_platform_identity_private_readiness_v8$
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
    'app.private_platform_identity_runtime_schema_readiness_v7()'::regprocedure;
  IF predecessor_hash<>
    '40f13f59998b0af66340f6d4e3fdd622d4059eb27440f4536fdc8ffad807caaa' THEN
    RAISE EXCEPTION 'platform identity private readiness v7 drifted'
      USING ERRCODE='55000';
  END IF;
  SELECT pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8')),'hex'),
         app.private_platform_identity_dependency_surface_hash_v8()
    INTO STRICT dependency_source_hash,dependency_result_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid=
    'app.private_platform_identity_dependency_surface_hash_v8()'::regprocedure;
  definition:=pg_catalog.replace(definition,
    'private_platform_identity_dependency_surface_hash_v7',
    'private_platform_identity_dependency_surface_hash_v8');
  definition:=pg_catalog.replace(definition,
    'private_platform_identity_runtime_schema_readiness_v7',
    'private_platform_identity_runtime_schema_readiness_v8');
  definition:=pg_catalog.replace(definition,
    'platform_identity_runtime_schema_readiness_v7',
    'platform_identity_runtime_schema_readiness_v8');
  definition:=pg_catalog.replace(definition,
    'schema_compatibility_v41','schema_compatibility_v42');
  definition:=pg_catalog.replace(definition,
    'private_platform_oidc_direct_dependency_surface_hash_v3',
    'private_platform_oidc_direct_dependency_surface_hash_v4');
  definition:=pg_catalog.replace(definition,
    'private_platform_oidc_direct_runtime_schema_readiness_v3',
    'private_platform_oidc_direct_runtime_schema_readiness_v4');
  definition:=pg_catalog.replace(definition,
    'platform_oidc_direct_runtime_schema_readiness_v3',
    'platform_oidc_direct_runtime_schema_readiness_v4');
  definition:=pg_catalog.replace(definition,
    'private_mfa_policy_administration_dependency_surface_hash_v1',
    'private_mfa_policy_administration_dependency_surface_hash_v2');
  definition:=pg_catalog.replace(definition,
    'private_mfa_policy_administration_schema_readiness_v1',
    'private_mfa_policy_administration_schema_readiness_v2');
  definition:=pg_catalog.replace(definition,
    'mfa_policy_administration_schema_readiness_v1',
    'mfa_policy_administration_schema_readiness_v2');
  definition:=pg_catalog.replace(definition,
    '11aaeb68992daf0e5df7a81eefc66aab1f6d2572b834ff73c3a4d6989253b287',
    dependency_source_hash);
  definition:=pg_catalog.replace(definition,
    'd22db49908873d5241222746e3ac4d5cc2ec5d46c3376ca7dfb8583bb7dc6287',
    dependency_result_hash);
  EXECUTE definition;
END;
$derive_platform_identity_private_readiness_v8$;
ALTER FUNCTION app.private_platform_identity_runtime_schema_readiness_v8()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_platform_identity_runtime_schema_readiness_v8()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier;
--> statement-breakpoint

DO $derive_platform_oidc_private_readiness_v4$
DECLARE
  definition text;
  predecessor_hash text;
  dependency_source_hash text;
  dependency_result_hash text;
  final_marker constant text := '  RETURN true;';
  v4_checks constant text :=
    '  IF NOT EXISTS (' || chr(10) ||
    '    SELECT 1 FROM pg_catalog.pg_indexes' || chr(10) ||
    '    WHERE schemaname=''public''' || chr(10) ||
    '      AND indexname=''platform_post_primary_totp_challenges_live_continuation_key''' || chr(10) ||
    '      AND indexdef LIKE ''%WHERE (state = ''''pending''''::text)%''' || chr(10) ||
    '  ) OR to_regprocedure(''app.begin_platform_post_primary_totp_v2(jsonb)'') IS NULL THEN' || chr(10) ||
    '    RETURN false;' || chr(10) ||
    '  END IF;' || chr(10) || chr(10);
BEGIN
  SELECT pg_catalog.pg_get_functiondef(function_row.oid),
         pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8')),'hex')
    INTO STRICT definition,predecessor_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid=
    'app.private_platform_oidc_direct_runtime_schema_readiness_v3()'::regprocedure;
  IF predecessor_hash<>
    'ee701c9ff0b2c8f9ef9e0e9783ce1de855ecc5af5ce7b92fe06f76bc07bf158d' THEN
    RAISE EXCEPTION 'direct platform OIDC private readiness v3 drifted'
      USING ERRCODE='55000';
  END IF;
  SELECT pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8')),'hex'),
         app.private_platform_oidc_direct_dependency_surface_hash_v4()
    INTO STRICT dependency_source_hash,dependency_result_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid=
    'app.private_platform_oidc_direct_dependency_surface_hash_v4()'::regprocedure;
  definition:=pg_catalog.replace(definition,
    'private_platform_oidc_direct_dependency_surface_hash_v3',
    'private_platform_oidc_direct_dependency_surface_hash_v4');
  definition:=pg_catalog.replace(definition,
    'private_platform_oidc_direct_runtime_schema_readiness_v3',
    'private_platform_oidc_direct_runtime_schema_readiness_v4');
  definition:=pg_catalog.replace(definition,
    'platform_oidc_direct_runtime_schema_readiness_v3',
    'platform_oidc_direct_runtime_schema_readiness_v4');
  definition:=pg_catalog.replace(definition,
    'private_platform_identity_dependency_surface_hash_v7',
    'private_platform_identity_dependency_surface_hash_v8');
  definition:=pg_catalog.replace(definition,
    'private_platform_identity_runtime_schema_readiness_v7',
    'private_platform_identity_runtime_schema_readiness_v8');
  definition:=pg_catalog.replace(definition,
    'platform_identity_runtime_schema_readiness_v7',
    'platform_identity_runtime_schema_readiness_v8');
  definition:=pg_catalog.replace(definition,
    'private_mfa_policy_administration_schema_readiness_v1',
    'private_mfa_policy_administration_schema_readiness_v2');
  definition:=pg_catalog.replace(definition,
    'schema_compatibility_v41','schema_compatibility_v42');
  definition:=pg_catalog.replace(definition,
    '''%platform_oidc_login_policies AS login_policy%''',
    '''%platform_oidc_login_policies AS oidc_login%''');
  definition:=pg_catalog.replace(definition,
    '''%WHEN ''''oidc'''' THEN coalesce(login_policy.enabled, false)%''',
    '''%WHEN ''''oidc'''' THEN coalesce(oidc_login.enabled,false)%''');
  definition:=pg_catalog.replace(definition,
    'f06b06d63728a9a6b678120cd6551c91598219638f488c1887424919c5fd981d',
    dependency_source_hash);
  definition:=pg_catalog.replace(definition,
    '2f2a42486e1b90ead2c74ab87a27f2cc41c710f82ae7f3cd0be593ce5f1e40cc',
    dependency_result_hash);
  IF pg_catalog.strpos(definition,final_marker)=0 THEN
    RAISE EXCEPTION 'direct platform OIDC private readiness v4 marker drifted'
      USING ERRCODE='55000';
  END IF;
  definition:=pg_catalog.replace(
    definition,final_marker,v4_checks || final_marker
  );
  EXECUTE definition;
END;
$derive_platform_oidc_private_readiness_v4$;
ALTER FUNCTION app.private_platform_oidc_direct_runtime_schema_readiness_v4()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_platform_oidc_direct_runtime_schema_readiness_v4()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier;
--> statement-breakpoint

DO $create_platform_saml_private_readiness_v1$
DECLARE
  dependency_source_hash text;
  dependency_result_hash text;
  definition text := $template$
CREATE OR REPLACE FUNCTION app.private_platform_saml_direct_runtime_schema_readiness_v1()
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path=pg_catalog,public,app
AS $body$
DECLARE catalog_ready boolean;
BEGIN
  SELECT count(*)=1 AND coalesce(bool_and(
    owner.rolname='periapsis_migrator' AND language.lanname='sql'
    AND function_row.provolatile='s' AND function_row.prosecdef
    AND function_row.proconfig IS NOT DISTINCT FROM ARRAY[
      'search_path=pg_catalog, public, app','quote_all_identifiers=off',
      'TimeZone=UTC','DateStyle=ISO, YMD','IntervalStyle=postgres',
      'extra_float_digits=3','bytea_output=hex',
      'standard_conforming_strings=on','lc_numeric=C'
    ]::text[]
  ),false) INTO catalog_ready
  FROM pg_catalog.pg_proc AS function_row
  JOIN pg_catalog.pg_roles AS owner ON owner.oid=function_row.proowner
  JOIN pg_catalog.pg_language AS language ON language.oid=function_row.prolang
  WHERE function_row.oid=
    'app.private_platform_saml_direct_dependency_surface_hash_v1()'::regprocedure
    AND pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
      function_row.prosrc,'UTF8')),'hex')='__DEPENDENCY_SOURCE__'
    AND app.private_platform_saml_direct_dependency_surface_hash_v1()=
      '__DEPENDENCY_RESULT__';
  IF NOT catalog_ready THEN RETURN false; END IF;
  WITH expected(name,api_callable) AS (VALUES
    ('begin_platform_saml_authentication_v1',true),
    ('load_platform_saml_start_configuration_v1',true),
    ('create_platform_saml_authentication_transaction_v1',true),
    ('recover_platform_saml_authentication_transaction_create_v1',true),
    ('lookup_platform_saml_authentication_transaction_v1',true),
    ('resolve_platform_saml_authentication_configuration_v1',true),
    ('abort_platform_saml_authentication_transaction_v1',true),
    ('load_platform_saml_sp_key_envelope_v1',true),
    ('load_platform_saml_metadata_projection_v1',true),
    ('load_platform_saml_planning_state_v1',true),
    ('apply_platform_saml_authentication_v1',true),
    ('recover_platform_saml_authentication_apply_v1',true),
    ('reject_platform_saml_authentication_v1',true),
    ('cleanup_platform_saml_authentication_v1',true),
    ('begin_platform_saml_post_primary_totp_v1',true),
    ('load_platform_saml_post_primary_totp_v1',true),
    ('record_platform_saml_post_primary_totp_failure_v1',true),
    ('apply_platform_saml_post_primary_totp_v1',true),
    ('recover_platform_saml_post_primary_totp_apply_v1',true),
    ('abandon_platform_saml_post_primary_totp_v1',true),
    ('cleanup_platform_saml_post_primary_totp_apply_v1',true),
    ('load_platform_saml_session_revalidation_v1',true),
    ('apply_platform_saml_session_revalidation_v1',true),
    ('recover_platform_saml_session_revalidation_apply_v1',true),
    ('cleanup_platform_saml_session_revalidation_delivery_v1',true),
    ('load_platform_saml_tenant_switch_v1',true),
    ('apply_platform_saml_tenant_switch_v1',true),
    ('lookup_platform_saml_tenant_switch_replay_v1',true),
    ('private_platform_saml_tenant_switch_assurance_v1',false),
    ('load_platform_saml_tenant_switch_revalidation_v1',false),
    ('private_platform_saml_totp_completion_fence_v1',false)
  ), actual AS (
    SELECT expected.name,expected.api_callable,function_row.oid,
           owner.rolname AS owner_name
    FROM expected
    LEFT JOIN pg_catalog.pg_proc AS function_row
      ON function_row.proname=expected.name
     AND function_row.pronamespace='app'::regnamespace
    LEFT JOIN pg_catalog.pg_roles AS owner ON owner.oid=function_row.proowner
  )
  SELECT count(*)=(SELECT count(*) FROM expected)
    AND bool_and(actual.oid IS NOT NULL AND actual.owner_name='periapsis_migrator'
      AND NOT EXISTS (
        SELECT 1
        FROM pg_catalog.aclexplode(coalesce(
          (SELECT function_acl.proacl
           FROM pg_catalog.pg_proc AS function_acl
           WHERE function_acl.oid=actual.oid),
          pg_catalog.acldefault('f',
            (SELECT function_acl.proowner
             FROM pg_catalog.pg_proc AS function_acl
             WHERE function_acl.oid=actual.oid))
        )) AS acl
        WHERE acl.grantee=0 AND acl.privilege_type='EXECUTE'
      )
      AND pg_catalog.has_function_privilege(
        'periapsis_api',actual.oid,'EXECUTE')=actual.api_callable
      AND NOT pg_catalog.has_function_privilege(
        'periapsis_worker',actual.oid,'EXECUTE')
      AND NOT pg_catalog.has_function_privilege(
        'periapsis_notifier',actual.oid,'EXECUTE'))
    INTO catalog_ready FROM actual;
  IF NOT coalesce(catalog_ready,false) THEN RETURN false; END IF;
  IF (SELECT count(*) FROM pg_catalog.pg_class AS relation
      JOIN pg_catalog.pg_namespace AS namespace
        ON namespace.oid=relation.relnamespace
      JOIN pg_catalog.pg_roles AS owner ON owner.oid=relation.relowner
      WHERE namespace.nspname='public'
        AND relation.relname IN (
          'platform_saml_login_policies','platform_saml_authentication_transactions',
          'platform_saml_authentication_applications',
          'platform_saml_post_primary_continuations',
          'platform_saml_post_primary_continuation_evidence',
          'platform_saml_post_primary_continuation_policy_pins',
          'platform_saml_post_primary_totp_challenges',
          'platform_saml_session_materials','platform_saml_session_revalidation_commands',
          'auth_session_platform_saml_states','auth_session_platform_saml_provenance',
          'auth_session_platform_saml_evidence','auth_session_platform_saml_policy_pins',
          'platform_saml_tenant_switch_commands')
        AND owner.rolname='periapsis_migrator' AND relation.relrowsecurity
        AND NOT pg_catalog.has_table_privilege(
          'periapsis_api',relation.oid,'SELECT,INSERT,UPDATE,DELETE'))<>14 THEN
    RETURN false;
  END IF;
  IF to_regprocedure('app.begin_platform_post_primary_totp_v2(jsonb)') IS NULL
     OR to_regprocedure('app.activate_platform_direct_login_v2(uuid,uuid,bigint,uuid,uuid,uuid,inet,text,text,text)') IS NULL
     OR NOT EXISTS (
       SELECT 1 FROM pg_catalog.pg_trigger AS trigger_row
       WHERE trigger_row.tgrelid=
         'public.platform_saml_post_primary_totp_challenges'::regclass
         AND trigger_row.tgname='platform_saml_totp_completion_fence_v1'
         AND trigger_row.tgenabled='O'
     )
     OR NOT EXISTS (
       SELECT 1 FROM pg_catalog.pg_indexes
       WHERE schemaname='public'
         AND indexname='platform_post_primary_totp_challenges_live_continuation_key'
         AND indexdef LIKE '%WHERE (state = ''pending''::text)%'
     )
     OR EXISTS (
       SELECT 1 FROM pg_catalog.pg_indexes
       WHERE schemaname='public'
         AND indexname='platform_post_primary_totp_challenges_continuation_key'
     ) THEN
    RETURN false;
  END IF;
  IF pg_catalog.pg_get_functiondef(
       'app.apply_platform_saml_tenant_switch_v1(jsonb)'::regprocedure
     ) NOT LIKE '%auth_session_platform_saml_states%'
     OR pg_catalog.pg_get_functiondef(
       'app.apply_platform_saml_tenant_switch_v1(jsonb)'::regprocedure
     ) LIKE '%auth_session_platform_oidc_states%'
     OR pg_catalog.pg_get_functiondef(
       'app.begin_platform_saml_post_primary_totp_v1(jsonb)'::regprocedure
     ) NOT LIKE '%state=''abandoned''%'
     OR pg_catalog.pg_get_functiondef(
       'app.cleanup_platform_saml_post_primary_totp_apply_v1(jsonb)'::regprocedure
     ) NOT LIKE '%cleanup_reason=''delivery_failed''%' THEN
    RETURN false;
  END IF;
  RETURN true;
EXCEPTION WHEN undefined_table OR undefined_function OR insufficient_privilege
  OR invalid_schema_name OR cardinality_violation OR data_exception THEN
  RETURN false;
END;
$body$;
$template$;
BEGIN
  SELECT pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8')),'hex'),
         app.private_platform_saml_direct_dependency_surface_hash_v1()
    INTO STRICT dependency_source_hash,dependency_result_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid=
    'app.private_platform_saml_direct_dependency_surface_hash_v1()'::regprocedure;
  definition:=pg_catalog.replace(
    definition,'__DEPENDENCY_SOURCE__',dependency_source_hash
  );
  definition:=pg_catalog.replace(
    definition,'__DEPENDENCY_RESULT__',dependency_result_hash
  );
  EXECUTE definition;
END;
$create_platform_saml_private_readiness_v1$;
ALTER FUNCTION app.private_platform_saml_direct_runtime_schema_readiness_v1()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_platform_saml_direct_runtime_schema_readiness_v1()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier;
--> statement-breakpoint

CREATE FUNCTION app.mfa_policy_administration_schema_readiness_v2()
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app AS $function$
DECLARE current_count bigint;
BEGIN
  SELECT compatibility.applied_count INTO current_count
  FROM app.schema_compatibility_v42() AS compatibility;
  RETURN current_count=188
    AND app.private_mfa_policy_administration_schema_readiness_v2();
EXCEPTION WHEN undefined_table OR undefined_function OR insufficient_privilege
  OR invalid_schema_name OR cardinality_violation OR data_exception THEN
  RETURN false;
END;
$function$;
CREATE FUNCTION app.platform_identity_runtime_schema_readiness_v8()
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app AS $function$
DECLARE current_count bigint;
BEGIN
  SELECT compatibility.applied_count INTO current_count
  FROM app.schema_compatibility_v42() AS compatibility;
  RETURN current_count=188
    AND app.mfa_policy_administration_schema_readiness_v2()
    AND app.private_platform_identity_runtime_schema_readiness_v8();
EXCEPTION WHEN undefined_table OR undefined_function OR insufficient_privilege
  OR invalid_schema_name OR cardinality_violation OR data_exception THEN
  RETURN false;
END;
$function$;
CREATE FUNCTION app.platform_oidc_direct_runtime_schema_readiness_v4()
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app AS $function$
DECLARE current_count bigint;
BEGIN
  SELECT compatibility.applied_count INTO current_count
  FROM app.schema_compatibility_v42() AS compatibility;
  RETURN current_count=188
    AND app.platform_identity_runtime_schema_readiness_v8()
    AND app.private_platform_oidc_direct_runtime_schema_readiness_v4()
    AND NOT pg_catalog.has_function_privilege(
      'periapsis_api','app.platform_oidc_direct_runtime_schema_readiness_v3()'::regprocedure,'EXECUTE');
EXCEPTION WHEN undefined_table OR undefined_function OR insufficient_privilege
  OR invalid_schema_name OR cardinality_violation OR data_exception THEN
  RETURN false;
END;
$function$;
CREATE FUNCTION app.platform_saml_direct_runtime_schema_readiness_v1()
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app AS $function$
DECLARE current_count bigint;
BEGIN
  SELECT compatibility.applied_count INTO current_count
  FROM app.schema_compatibility_v42() AS compatibility;
  RETURN current_count=188
    AND app.platform_identity_runtime_schema_readiness_v8()
    AND app.private_platform_saml_direct_runtime_schema_readiness_v1()
    AND NOT pg_catalog.has_function_privilege(
      'periapsis_api','app.platform_identity_runtime_schema_readiness_v7()'::regprocedure,'EXECUTE');
EXCEPTION WHEN undefined_table OR undefined_function OR insufficient_privilege
  OR invalid_schema_name OR cardinality_violation OR data_exception THEN
  RETURN false;
END;
$function$;
ALTER FUNCTION app.mfa_policy_administration_schema_readiness_v2()
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.platform_identity_runtime_schema_readiness_v8()
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.platform_oidc_direct_runtime_schema_readiness_v4()
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.platform_saml_direct_runtime_schema_readiness_v1()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.mfa_policy_administration_schema_readiness_v2()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier;
REVOKE ALL ON FUNCTION app.platform_identity_runtime_schema_readiness_v8()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier;
REVOKE ALL ON FUNCTION app.platform_oidc_direct_runtime_schema_readiness_v4()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier;
REVOKE ALL ON FUNCTION app.platform_saml_direct_runtime_schema_readiness_v1()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier;
GRANT EXECUTE ON FUNCTION app.mfa_policy_administration_schema_readiness_v2()
  TO periapsis_api,periapsis_worker;
GRANT EXECUTE ON FUNCTION app.platform_identity_runtime_schema_readiness_v8()
  TO periapsis_api,periapsis_worker;
GRANT EXECUTE ON FUNCTION app.platform_oidc_direct_runtime_schema_readiness_v4()
  TO periapsis_api,periapsis_worker;
GRANT EXECUTE ON FUNCTION app.platform_saml_direct_runtime_schema_readiness_v1()
  TO periapsis_api,periapsis_worker;
--> statement-breakpoint

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
  IF p_expected_count IS DISTINCT FROM 188
     OR p_expected_latest_created_at IS DISTINCT FROM 1788107911419
     OR p_expected_latest_hash !~ '^[0-9a-f]{64}$'
     OR p_expected_migration_fingerprint !~
       '^[0-9]+@[0-9a-f]{64}(:[0-9]+@[0-9a-f]{64}){187}$' THEN
    RAISE EXCEPTION 'schema compatibility v42 seal input is invalid'
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
     OR NOT app.private_mfa_policy_administration_schema_readiness_v2()
     OR NOT app.private_platform_identity_runtime_schema_readiness_v8()
     OR NOT app.private_platform_oidc_direct_runtime_schema_readiness_v4()
     OR NOT app.private_platform_saml_direct_runtime_schema_readiness_v1()
     OR pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
       (SELECT function_row.prosrc FROM pg_catalog.pg_proc AS function_row
        WHERE function_row.oid='app.schema_compatibility_v41()'::regprocedure),
       'UTF8')),'hex')<>
       '7a38e8d64191b91e449493af3a55621371a2edcba67e590e95f3b1bf01b16553'
     OR pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
       (SELECT function_row.prosrc FROM pg_catalog.pg_proc AS function_row
        WHERE function_row.oid=
          'app.platform_identity_runtime_schema_readiness_v7()'::regprocedure),
       'UTF8')),'hex')<>
       '32df4c5a1525e683df19a4bbd2c1d98e7ab005ef409f30507ef72fe0b2b78492'
     OR pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
       (SELECT function_row.prosrc FROM pg_catalog.pg_proc AS function_row
        WHERE function_row.oid=
          'app.platform_oidc_direct_runtime_schema_readiness_v3()'::regprocedure),
       'UTF8')),'hex')<>
       '777be53762608170c097b72343d5968a23953835edac12226e7c1bca5980a9d9'
     OR pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
       (SELECT function_row.prosrc FROM pg_catalog.pg_proc AS function_row
        WHERE function_row.oid=
          'app.mfa_policy_administration_schema_readiness_v1()'::regprocedure),
       'UTF8')),'hex')<>
       '37565eee8fcb22af77dfe2f641d516e14728c3c38224d24b618e46fd269caa40' THEN
    RAISE EXCEPTION 'schema compatibility v42 pre-seal verification failed'
      USING ERRCODE='55000';
  END IF;
  EXECUTE pg_catalog.format(
    'ALTER FUNCTION app.schema_compatibility_v42() SET app.schema_compatibility_fingerprint = %L',
    p_expected_migration_fingerprint
  );
  ALTER FUNCTION app.schema_compatibility_v41()
    SET app.schema_compatibility_fingerprint='RETIRED';
  REVOKE ALL ON FUNCTION app.schema_compatibility_v41()
    FROM periapsis_api,periapsis_worker;
  REVOKE ALL ON FUNCTION app.platform_identity_runtime_schema_readiness_v7()
    FROM periapsis_api,periapsis_worker;
  REVOKE ALL ON FUNCTION app.platform_oidc_direct_runtime_schema_readiness_v3()
    FROM periapsis_api,periapsis_worker;
  REVOKE ALL ON FUNCTION app.mfa_policy_administration_schema_readiness_v1()
    FROM periapsis_api,periapsis_worker;
  SELECT compatibility.applied_count INTO sealed_count
  FROM app.schema_compatibility_v42() AS compatibility;
  IF sealed_count<>188
     OR NOT app.mfa_policy_administration_schema_readiness_v2()
     OR NOT app.platform_identity_runtime_schema_readiness_v8()
     OR NOT app.platform_oidc_direct_runtime_schema_readiness_v4()
     OR NOT app.platform_saml_direct_runtime_schema_readiness_v1()
     OR pg_catalog.has_function_privilege(
       'periapsis_api','app.schema_compatibility_v41()'::regprocedure,'EXECUTE')
     OR pg_catalog.has_function_privilege(
       'periapsis_worker','app.schema_compatibility_v41()'::regprocedure,'EXECUTE')
     OR pg_catalog.has_function_privilege(
       'periapsis_api','app.platform_identity_runtime_schema_readiness_v7()'::regprocedure,'EXECUTE')
     OR pg_catalog.has_function_privilege(
       'periapsis_api','app.platform_oidc_direct_runtime_schema_readiness_v3()'::regprocedure,'EXECUTE')
     OR pg_catalog.has_function_privilege(
       'periapsis_api','app.mfa_policy_administration_schema_readiness_v1()'::regprocedure,'EXECUTE') THEN
    RAISE EXCEPTION 'schema compatibility v42 seal verification failed'
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

-- The catalog surface changes once the v42 sealer replaces its predecessor.
-- Rebind the private roots to that final dependency result; the roots themselves
-- are excluded from the dependency surface, so this converges in one pass.
DO $rebind_v42_private_readiness_roots$
DECLARE
  root_signature text;
  definition text;
  dependency_result_hash text;
  predecessor_result_hash constant text :=
    'a2c2fbfc80f9ac83a7b0cced85837f1fc3ae2a1f4e0ed06b71baaa686815be48';
BEGIN
  dependency_result_hash:=
    app.private_platform_identity_dependency_surface_hash_v8();
  IF dependency_result_hash=predecessor_result_hash THEN
    RAISE EXCEPTION 'schema compatibility v42 dependency surface did not advance'
      USING ERRCODE='55000';
  END IF;
  FOREACH root_signature IN ARRAY ARRAY[
    'app.private_mfa_policy_administration_schema_readiness_v2()',
    'app.private_platform_identity_runtime_schema_readiness_v8()',
    'app.private_platform_oidc_direct_runtime_schema_readiness_v4()',
    'app.private_platform_saml_direct_runtime_schema_readiness_v1()'
  ]::text[] LOOP
    SELECT pg_catalog.pg_get_functiondef(function_row.oid)
      INTO STRICT definition
    FROM pg_catalog.pg_proc AS function_row
    WHERE function_row.oid=root_signature::regprocedure;
    IF pg_catalog.strpos(definition,predecessor_result_hash)=0 THEN
      RAISE EXCEPTION 'schema compatibility v42 private root % cannot be rebound',
        root_signature USING ERRCODE='55000';
    END IF;
    definition:=pg_catalog.replace(
      definition,predecessor_result_hash,dependency_result_hash
    );
    EXECUTE definition;
  END LOOP;
END;
$rebind_v42_private_readiness_roots$;
