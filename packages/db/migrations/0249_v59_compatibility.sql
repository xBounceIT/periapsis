-- V59 seals the complete 0000-0249 migration and protected dependency surface.
-- PostgreSQL 18.6 UTF8/C independently derives the catalog digest.
-- Prior function sources, exact ACL/configuration transitions and all runtime
-- credential proofs remain attested; only four exact current roots are excluded.
CREATE FUNCTION app.private_schema_compatibility_journal_v59()
RETURNS TABLE(
  applied_count bigint,latest_created_at bigint,latest_rows bigint,
  latest_hash text,migration_fingerprint text
)
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app AS $function$
BEGIN
  IF NOT app.private_v47_migration_convergence_schema_readiness_v1() THEN
    RETURN QUERY SELECT 0::bigint,0::bigint,0::bigint,
      'UNSUPPORTED'::text,'UNSUPPORTED'::text;
    RETURN;
  END IF;
  RETURN QUERY
  SELECT count(*)::bigint,max(migration.created_at)::bigint,
    count(*) FILTER (
      WHERE migration.created_at=max_created_at.value
    )::bigint,
    (SELECT lower(latest.hash::text)
     FROM drizzle.__drizzle_migrations AS latest
     ORDER BY latest.created_at DESC,latest.id DESC LIMIT 1),
    string_agg(
      migration.created_at::text || '@' || CASE
        WHEN migration.created_at=1788128074116
         AND lower(migration.hash::text)=
           '0edecb4d9945aeccc4d5b7c9db7dbb25c5f07c7df933ee4e208d3e4e34397d9e'
          THEN '6112ec54973db26390fa6020a050db71a6c5d28b1c45132bca10b32372109fa4'
        WHEN migration.created_at=1788128702258
         AND lower(migration.hash::text)=
           '0d47a74b3ecb3064766ae3a920e420f56e3cfc7e0bf95578df7fe353c2b3d72c'
          THEN 'fffd40eb9eb5800fbe63f9e62fa85f960190e2a149e2313ccb66a1d6c78293ea'
        ELSE lower(migration.hash::text)
      END,
      ':' ORDER BY migration.created_at,migration.id
    )
  FROM drizzle.__drizzle_migrations AS migration
  CROSS JOIN LATERAL (
    SELECT max(candidate.created_at)::bigint AS value
    FROM drizzle.__drizzle_migrations AS candidate
  ) AS max_created_at;
END;
$function$;
ALTER FUNCTION app.private_schema_compatibility_journal_v59()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_schema_compatibility_journal_v59()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
       periapsis_auditor;
--> statement-breakpoint

CREATE FUNCTION app.schema_compatibility_v59()
RETURNS TABLE(
  applied_count bigint,latest_created_at bigint,latest_hash text,
  migration_fingerprint text
)
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog
SET app.schema_compatibility_fingerprint='UNSEALED'
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
  FROM app.private_schema_compatibility_journal_v59() AS journal;
  SELECT count(*)=1 INTO self_catalog_ready
  FROM pg_catalog.pg_proc AS function_row
  JOIN pg_catalog.pg_namespace AS namespace
    ON namespace.oid=function_row.pronamespace
  JOIN pg_catalog.pg_roles AS owner ON owner.oid=function_row.proowner
  JOIN pg_catalog.pg_language AS language ON language.oid=function_row.prolang
  WHERE function_row.oid='app.schema_compatibility_v59()'::regprocedure
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
  IF journal_count=250 AND journal_latest_created_at=1788875558350
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
ALTER FUNCTION app.schema_compatibility_v59() OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.schema_compatibility_v59()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
       periapsis_auditor;
GRANT EXECUTE ON FUNCTION app.schema_compatibility_v59()
  TO periapsis_api,periapsis_worker;
--> statement-breakpoint

DO $assert_v49_credential_probe_catalog$
DECLARE
  probe_oid constant regprocedure :=
    'app.private_runtime_login_credential_state_v49()'::regprocedure;
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_catalog.pg_proc AS function_row
    JOIN pg_catalog.pg_roles AS owner ON owner.oid=function_row.proowner
    JOIN pg_catalog.pg_language AS language ON language.oid=function_row.prolang
    WHERE function_row.oid=probe_oid
      AND owner.rolsuper
      AND owner.rolname<>ALL(ARRAY[
        'periapsis_api','periapsis_worker','periapsis_notifier',
        'periapsis_auditor','periapsis_api_login','periapsis_worker_login',
        'periapsis_notifier_login','periapsis_auditor_login'
      ]::text[])
      AND language.lanname='sql' AND function_row.prokind='f'
      AND function_row.provolatile='s' AND function_row.prosecdef
      AND NOT function_row.proisstrict AND NOT function_row.proleakproof
      AND function_row.proparallel='u' AND function_row.pronargs=0
      AND function_row.proconfig IS NOT DISTINCT FROM
        ARRAY['search_path=pg_catalog']::text[]
      AND pg_catalog.pg_get_function_result(function_row.oid)=
        'TABLE(role_name text, credential_state text)'
      AND (
        SELECT count(*)=2 AND coalesce(bool_and(
          function_acl.grantor=function_row.proowner
          AND function_acl.grantee IN (
            function_row.proowner,
            (SELECT role.oid FROM pg_catalog.pg_roles AS role
             WHERE role.rolname='periapsis_migrator')
          )
          AND function_acl.privilege_type='EXECUTE'
          AND NOT function_acl.is_grantable
        ),false)
        FROM pg_catalog.aclexplode(coalesce(
          function_row.proacl,
          pg_catalog.acldefault('f',function_row.proowner)
        )) AS function_acl
      )
      AND (
        SELECT count(*)=4
          AND array_agg(role_name ORDER BY role_name COLLATE "C")=
            ARRAY[
              'periapsis_api_login','periapsis_auditor_login',
              'periapsis_notifier_login','periapsis_worker_login'
            ]::text[]
          AND coalesce(bool_and(
            credential_state IN ('absent','scram','other')
          ),false)
        FROM app.private_runtime_login_credential_state_v49()
      )
  ) THEN
    RAISE EXCEPTION 'V49 runtime-login credential probe is not exact'
      USING ERRCODE='55000';
  END IF;
END;
$assert_v49_credential_probe_catalog$;
--> statement-breakpoint

CREATE FUNCTION app.private_release_runtime_dependency_surface_hash_v59()
RETURNS text LANGUAGE sql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app
SET quote_all_identifiers=off SET TimeZone='UTC' SET DateStyle='ISO, YMD'
SET IntervalStyle='postgres' SET extra_float_digits=3 SET bytea_output='hex'
  SET standard_conforming_strings=on SET lc_numeric='C'
AS $function$
WITH rotated_acl_function(function_oid,acl_hashes) AS (
  VALUES
    ('app.schema_compatibility_v44()'::regprocedure,
     ARRAY['6ca5690202c36698ce889b920ad4ae303f50e356c8621120e2d87d57ffeb8df4','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.schema_compatibility_v45()'::regprocedure,
     ARRAY['6ca5690202c36698ce889b920ad4ae303f50e356c8621120e2d87d57ffeb8df4','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.schema_compatibility_v46()'::regprocedure,
     ARRAY['6ca5690202c36698ce889b920ad4ae303f50e356c8621120e2d87d57ffeb8df4','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.schema_compatibility_v47()'::regprocedure,
     ARRAY['6ca5690202c36698ce889b920ad4ae303f50e356c8621120e2d87d57ffeb8df4','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.mfa_policy_administration_schema_readiness_v4()'::regprocedure,
     ARRAY['6ca5690202c36698ce889b920ad4ae303f50e356c8621120e2d87d57ffeb8df4','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.mfa_policy_administration_schema_readiness_v6()'::regprocedure,
     ARRAY['6ca5690202c36698ce889b920ad4ae303f50e356c8621120e2d87d57ffeb8df4','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.platform_identity_runtime_schema_readiness_v10()'::regprocedure,
     ARRAY['6ca5690202c36698ce889b920ad4ae303f50e356c8621120e2d87d57ffeb8df4','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.platform_identity_runtime_schema_readiness_v12()'::regprocedure,
     ARRAY['6ca5690202c36698ce889b920ad4ae303f50e356c8621120e2d87d57ffeb8df4','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.platform_oidc_direct_runtime_schema_readiness_v6()'::regprocedure,
     ARRAY['6ca5690202c36698ce889b920ad4ae303f50e356c8621120e2d87d57ffeb8df4','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.platform_oidc_direct_runtime_schema_readiness_v8()'::regprocedure,
     ARRAY['6ca5690202c36698ce889b920ad4ae303f50e356c8621120e2d87d57ffeb8df4','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.platform_saml_direct_runtime_schema_readiness_v3()'::regprocedure,
     ARRAY['6ca5690202c36698ce889b920ad4ae303f50e356c8621120e2d87d57ffeb8df4','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.platform_saml_direct_runtime_schema_readiness_v5()'::regprocedure,
     ARRAY['6ca5690202c36698ce889b920ad4ae303f50e356c8621120e2d87d57ffeb8df4','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.platform_tenant_lifecycle_schema_readiness_v1()'::regprocedure,
     ARRAY['6ca5690202c36698ce889b920ad4ae303f50e356c8621120e2d87d57ffeb8df4','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.platform_identity_runtime_schema_readiness_v13()'::regprocedure,
     ARRAY['6ca5690202c36698ce889b920ad4ae303f50e356c8621120e2d87d57ffeb8df4','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.platform_oidc_direct_runtime_schema_readiness_v9()'::regprocedure,
     ARRAY['6ca5690202c36698ce889b920ad4ae303f50e356c8621120e2d87d57ffeb8df4','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.platform_saml_direct_runtime_schema_readiness_v6()'::regprocedure,
     ARRAY['6ca5690202c36698ce889b920ad4ae303f50e356c8621120e2d87d57ffeb8df4','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.mfa_policy_administration_schema_readiness_v7()'::regprocedure,
     ARRAY['6ca5690202c36698ce889b920ad4ae303f50e356c8621120e2d87d57ffeb8df4','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.ticket_mutation_runtime_schema_readiness_v2()'::regprocedure,
     ARRAY['6ca5690202c36698ce889b920ad4ae303f50e356c8621120e2d87d57ffeb8df4','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.sla_trigger_action_runtime_schema_readiness_v1()'::regprocedure,
     ARRAY['08f390592be9130a44723ea7169e7ffbc2d743c5df668709b3c170d1639d512d','38ea9d52c52006222fb42da78f1792cbe10395b5580ef382c5bb2e561971aefe']::text[]),
    ('app.sla_object_event_ingress_schema_readiness_v1()'::regprocedure,
     ARRAY['08f390592be9130a44723ea7169e7ffbc2d743c5df668709b3c170d1639d512d','38ea9d52c52006222fb42da78f1792cbe10395b5580ef382c5bb2e561971aefe']::text[]),
    ('app.platform_local_account_runtime_schema_readiness_v1()'::regprocedure,
     ARRAY['6ca5690202c36698ce889b920ad4ae303f50e356c8621120e2d87d57ffeb8df4','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.ticket_bulk_runtime_schema_readiness_v2()'::regprocedure,
     ARRAY['6ca5690202c36698ce889b920ad4ae303f50e356c8621120e2d87d57ffeb8df4','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.ticket_export_runtime_schema_readiness_v2()'::regprocedure,
     ARRAY['6ca5690202c36698ce889b920ad4ae303f50e356c8621120e2d87d57ffeb8df4','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.alert_dfir_runtime_schema_readiness_v1()'::regprocedure,
     ARRAY['6ca5690202c36698ce889b920ad4ae303f50e356c8621120e2d87d57ffeb8df4','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.ticket_metadata_runtime_schema_readiness_v1()'::regprocedure,
     ARRAY['6ca5690202c36698ce889b920ad4ae303f50e356c8621120e2d87d57ffeb8df4','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.notification_dispatch_readiness_v4()'::regprocedure,
     ARRAY['0aafe9011ffb09c1c5b499cfa05ad38a2aa65c8b14c026d4e91b82569d77650a','38fb25bbff0f5b08dacb5c4fc444c4b9fe77803f46fe7280f72b240685011491']::text[]),
    ('app.ticket_watcher_runtime_schema_readiness_v2()'::regprocedure,
     ARRAY['6ca5690202c36698ce889b920ad4ae303f50e356c8621120e2d87d57ffeb8df4','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.contacts_portal_schema_readiness_v2()'::regprocedure,
     ARRAY['6ca5690202c36698ce889b920ad4ae303f50e356c8621120e2d87d57ffeb8df4','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.notification_schema_readiness_v4()'::regprocedure,
     ARRAY['2e50cd2f28a89d4a9f04282e59f740d47e374e0acf4b6e9ec3bc0282ae30b56c','e3d985bd20f7ff89945a3a0f2eb02c3231c8795088c6ccbdae91cc448d8045fe']::text[]),
    ('app.tenant_ldap_interactive_auth_schema_readiness_v1()'::regprocedure,
     ARRAY['545db485e1993c95e1401c3058a41b74e27e144213d3e738160d790e95bdc51e','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.ticket_comment_runtime_repair_schema_readiness_v1()'::regprocedure,
     ARRAY['6ca5690202c36698ce889b920ad4ae303f50e356c8621120e2d87d57ffeb8df4','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.platform_global_ldap_runtime_schema_readiness_v1()'::regprocedure,
     ARRAY['6ca5690202c36698ce889b920ad4ae303f50e356c8621120e2d87d57ffeb8df4','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.federated_authentication_schema_readiness_v1()'::regprocedure,
     ARRAY['545db485e1993c95e1401c3058a41b74e27e144213d3e738160d790e95bdc51e','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.platform_oidc_direct_runtime_schema_readiness_v1()'::regprocedure,
     ARRAY['6ca5690202c36698ce889b920ad4ae303f50e356c8621120e2d87d57ffeb8df4','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.platform_saml_direct_runtime_schema_readiness_v2()'::regprocedure,
     ARRAY['6ca5690202c36698ce889b920ad4ae303f50e356c8621120e2d87d57ffeb8df4','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.schema_compatibility_v48()'::regprocedure,
     ARRAY['6ca5690202c36698ce889b920ad4ae303f50e356c8621120e2d87d57ffeb8df4','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.release_runtime_schema_readiness_v48()'::regprocedure,
     ARRAY['6ca5690202c36698ce889b920ad4ae303f50e356c8621120e2d87d57ffeb8df4','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.federated_authentication_schema_readiness_v48()'::regprocedure,
     ARRAY['545db485e1993c95e1401c3058a41b74e27e144213d3e738160d790e95bdc51e','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.platform_oidc_direct_runtime_schema_readiness_v48()'::regprocedure,
     ARRAY['545db485e1993c95e1401c3058a41b74e27e144213d3e738160d790e95bdc51e','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.platform_saml_direct_runtime_schema_readiness_v48()'::regprocedure,
     ARRAY['545db485e1993c95e1401c3058a41b74e27e144213d3e738160d790e95bdc51e','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.platform_local_account_runtime_schema_readiness_v48()'::regprocedure,
     ARRAY['545db485e1993c95e1401c3058a41b74e27e144213d3e738160d790e95bdc51e','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.sla_trigger_action_runtime_schema_readiness_v48()'::regprocedure,
     ARRAY['7bce3416b1cc14e50b9b4be862cf85ff7a418399764d517e214979df343ad9e6','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.sla_object_event_ingress_schema_readiness_v48()'::regprocedure,
     ARRAY['7bce3416b1cc14e50b9b4be862cf85ff7a418399764d517e214979df343ad9e6','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.ticket_bulk_runtime_schema_readiness_v48()'::regprocedure,
     ARRAY['6ca5690202c36698ce889b920ad4ae303f50e356c8621120e2d87d57ffeb8df4','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.ticket_export_runtime_schema_readiness_v48()'::regprocedure,
     ARRAY['6ca5690202c36698ce889b920ad4ae303f50e356c8621120e2d87d57ffeb8df4','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.ticket_metadata_runtime_schema_readiness_v48()'::regprocedure,
     ARRAY['545db485e1993c95e1401c3058a41b74e27e144213d3e738160d790e95bdc51e','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.schema_compatibility_v49()'::regprocedure,
     ARRAY['6ca5690202c36698ce889b920ad4ae303f50e356c8621120e2d87d57ffeb8df4','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.release_runtime_schema_readiness_v49()'::regprocedure,
     ARRAY['2e50cd2f28a89d4a9f04282e59f740d47e374e0acf4b6e9ec3bc0282ae30b56c','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.federated_authentication_schema_readiness_v49()'::regprocedure,
     ARRAY['545db485e1993c95e1401c3058a41b74e27e144213d3e738160d790e95bdc51e','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.platform_oidc_direct_runtime_schema_readiness_v49()'::regprocedure,
     ARRAY['545db485e1993c95e1401c3058a41b74e27e144213d3e738160d790e95bdc51e','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.platform_saml_direct_runtime_schema_readiness_v49()'::regprocedure,
     ARRAY['545db485e1993c95e1401c3058a41b74e27e144213d3e738160d790e95bdc51e','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.platform_local_account_runtime_schema_readiness_v49()'::regprocedure,
     ARRAY['545db485e1993c95e1401c3058a41b74e27e144213d3e738160d790e95bdc51e','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.sla_trigger_action_runtime_schema_readiness_v49()'::regprocedure,
     ARRAY['7bce3416b1cc14e50b9b4be862cf85ff7a418399764d517e214979df343ad9e6','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.sla_object_event_ingress_schema_readiness_v49()'::regprocedure,
     ARRAY['7bce3416b1cc14e50b9b4be862cf85ff7a418399764d517e214979df343ad9e6','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.ticket_bulk_runtime_schema_readiness_v49()'::regprocedure,
     ARRAY['6ca5690202c36698ce889b920ad4ae303f50e356c8621120e2d87d57ffeb8df4','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.ticket_export_runtime_schema_readiness_v49()'::regprocedure,
     ARRAY['6ca5690202c36698ce889b920ad4ae303f50e356c8621120e2d87d57ffeb8df4','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.ticket_metadata_runtime_schema_readiness_v49()'::regprocedure,
     ARRAY['545db485e1993c95e1401c3058a41b74e27e144213d3e738160d790e95bdc51e','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.notification_dispatch_readiness_v49()'::regprocedure,
     ARRAY['fcb8956540a10aa971cb9d5cec7e43c67b44a1e7bc06426e827a2bbe699508b4','276a698f759a77a0c9d31a7d6bbbdc5fae752774dacea108ebb4171421156f41']::text[]),
    ('app.schema_compatibility_v50()'::regprocedure,
     ARRAY['6ca5690202c36698ce889b920ad4ae303f50e356c8621120e2d87d57ffeb8df4','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.release_runtime_schema_readiness_v50()'::regprocedure,
     ARRAY['2e50cd2f28a89d4a9f04282e59f740d47e374e0acf4b6e9ec3bc0282ae30b56c','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.federated_authentication_schema_readiness_v50()'::regprocedure,
     ARRAY['545db485e1993c95e1401c3058a41b74e27e144213d3e738160d790e95bdc51e','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.platform_oidc_direct_runtime_schema_readiness_v50()'::regprocedure,
     ARRAY['545db485e1993c95e1401c3058a41b74e27e144213d3e738160d790e95bdc51e','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.platform_saml_direct_runtime_schema_readiness_v50()'::regprocedure,
     ARRAY['545db485e1993c95e1401c3058a41b74e27e144213d3e738160d790e95bdc51e','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.platform_local_account_runtime_schema_readiness_v50()'::regprocedure,
     ARRAY['545db485e1993c95e1401c3058a41b74e27e144213d3e738160d790e95bdc51e','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.sla_trigger_action_runtime_schema_readiness_v50()'::regprocedure,
     ARRAY['7bce3416b1cc14e50b9b4be862cf85ff7a418399764d517e214979df343ad9e6','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.sla_object_event_ingress_schema_readiness_v50()'::regprocedure,
     ARRAY['7bce3416b1cc14e50b9b4be862cf85ff7a418399764d517e214979df343ad9e6','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.ticket_bulk_runtime_schema_readiness_v50()'::regprocedure,
     ARRAY['6ca5690202c36698ce889b920ad4ae303f50e356c8621120e2d87d57ffeb8df4','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.ticket_export_runtime_schema_readiness_v50()'::regprocedure,
     ARRAY['6ca5690202c36698ce889b920ad4ae303f50e356c8621120e2d87d57ffeb8df4','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.ticket_metadata_runtime_schema_readiness_v50()'::regprocedure,
     ARRAY['545db485e1993c95e1401c3058a41b74e27e144213d3e738160d790e95bdc51e','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.notification_dispatch_readiness_v50()'::regprocedure,
     ARRAY['fcb8956540a10aa971cb9d5cec7e43c67b44a1e7bc06426e827a2bbe699508b4','276a698f759a77a0c9d31a7d6bbbdc5fae752774dacea108ebb4171421156f41']::text[]),
    ('app.schema_compatibility_v51()'::regprocedure,
     ARRAY['6ca5690202c36698ce889b920ad4ae303f50e356c8621120e2d87d57ffeb8df4','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.release_runtime_schema_readiness_v51()'::regprocedure,
     ARRAY['2e50cd2f28a89d4a9f04282e59f740d47e374e0acf4b6e9ec3bc0282ae30b56c','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.federated_authentication_schema_readiness_v51()'::regprocedure,
     ARRAY['545db485e1993c95e1401c3058a41b74e27e144213d3e738160d790e95bdc51e','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.platform_oidc_direct_runtime_schema_readiness_v51()'::regprocedure,
     ARRAY['545db485e1993c95e1401c3058a41b74e27e144213d3e738160d790e95bdc51e','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.platform_saml_direct_runtime_schema_readiness_v51()'::regprocedure,
     ARRAY['545db485e1993c95e1401c3058a41b74e27e144213d3e738160d790e95bdc51e','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.platform_local_account_runtime_schema_readiness_v51()'::regprocedure,
     ARRAY['545db485e1993c95e1401c3058a41b74e27e144213d3e738160d790e95bdc51e','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.sla_trigger_action_runtime_schema_readiness_v51()'::regprocedure,
     ARRAY['7bce3416b1cc14e50b9b4be862cf85ff7a418399764d517e214979df343ad9e6','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.sla_object_event_ingress_schema_readiness_v51()'::regprocedure,
     ARRAY['7bce3416b1cc14e50b9b4be862cf85ff7a418399764d517e214979df343ad9e6','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.ticket_bulk_runtime_schema_readiness_v51()'::regprocedure,
     ARRAY['6ca5690202c36698ce889b920ad4ae303f50e356c8621120e2d87d57ffeb8df4','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.ticket_export_runtime_schema_readiness_v51()'::regprocedure,
     ARRAY['6ca5690202c36698ce889b920ad4ae303f50e356c8621120e2d87d57ffeb8df4','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.ticket_metadata_runtime_schema_readiness_v51()'::regprocedure,
     ARRAY['545db485e1993c95e1401c3058a41b74e27e144213d3e738160d790e95bdc51e','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.notification_dispatch_readiness_v51()'::regprocedure,
     ARRAY['fcb8956540a10aa971cb9d5cec7e43c67b44a1e7bc06426e827a2bbe699508b4','276a698f759a77a0c9d31a7d6bbbdc5fae752774dacea108ebb4171421156f41']::text[]),
    ('app.schema_compatibility_v52()'::regprocedure,
     ARRAY['6ca5690202c36698ce889b920ad4ae303f50e356c8621120e2d87d57ffeb8df4','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.release_runtime_schema_readiness_v52()'::regprocedure,
     ARRAY['2e50cd2f28a89d4a9f04282e59f740d47e374e0acf4b6e9ec3bc0282ae30b56c','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.federated_authentication_schema_readiness_v52()'::regprocedure,
     ARRAY['545db485e1993c95e1401c3058a41b74e27e144213d3e738160d790e95bdc51e','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.platform_oidc_direct_runtime_schema_readiness_v52()'::regprocedure,
     ARRAY['545db485e1993c95e1401c3058a41b74e27e144213d3e738160d790e95bdc51e','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.platform_saml_direct_runtime_schema_readiness_v52()'::regprocedure,
     ARRAY['545db485e1993c95e1401c3058a41b74e27e144213d3e738160d790e95bdc51e','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.platform_local_account_runtime_schema_readiness_v52()'::regprocedure,
     ARRAY['545db485e1993c95e1401c3058a41b74e27e144213d3e738160d790e95bdc51e','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.sla_trigger_action_runtime_schema_readiness_v52()'::regprocedure,
     ARRAY['7bce3416b1cc14e50b9b4be862cf85ff7a418399764d517e214979df343ad9e6','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.sla_object_event_ingress_schema_readiness_v52()'::regprocedure,
     ARRAY['7bce3416b1cc14e50b9b4be862cf85ff7a418399764d517e214979df343ad9e6','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.ticket_bulk_runtime_schema_readiness_v52()'::regprocedure,
     ARRAY['6ca5690202c36698ce889b920ad4ae303f50e356c8621120e2d87d57ffeb8df4','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.ticket_export_runtime_schema_readiness_v52()'::regprocedure,
     ARRAY['6ca5690202c36698ce889b920ad4ae303f50e356c8621120e2d87d57ffeb8df4','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.ticket_metadata_runtime_schema_readiness_v52()'::regprocedure,
     ARRAY['545db485e1993c95e1401c3058a41b74e27e144213d3e738160d790e95bdc51e','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.notification_dispatch_readiness_v52()'::regprocedure,
     ARRAY['fcb8956540a10aa971cb9d5cec7e43c67b44a1e7bc06426e827a2bbe699508b4','276a698f759a77a0c9d31a7d6bbbdc5fae752774dacea108ebb4171421156f41']::text[]),
    ('app.api_runtime_schema_readiness_v52()'::regprocedure,
     ARRAY['545db485e1993c95e1401c3058a41b74e27e144213d3e738160d790e95bdc51e','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.worker_runtime_schema_readiness_v52()'::regprocedure,
     ARRAY['7bce3416b1cc14e50b9b4be862cf85ff7a418399764d517e214979df343ad9e6','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.schema_compatibility_v53()'::regprocedure,
     ARRAY['6ca5690202c36698ce889b920ad4ae303f50e356c8621120e2d87d57ffeb8df4','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.release_runtime_schema_readiness_v53()'::regprocedure,
     ARRAY['2e50cd2f28a89d4a9f04282e59f740d47e374e0acf4b6e9ec3bc0282ae30b56c','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.federated_authentication_schema_readiness_v53()'::regprocedure,
     ARRAY['545db485e1993c95e1401c3058a41b74e27e144213d3e738160d790e95bdc51e','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.platform_oidc_direct_runtime_schema_readiness_v53()'::regprocedure,
     ARRAY['545db485e1993c95e1401c3058a41b74e27e144213d3e738160d790e95bdc51e','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.platform_saml_direct_runtime_schema_readiness_v53()'::regprocedure,
     ARRAY['545db485e1993c95e1401c3058a41b74e27e144213d3e738160d790e95bdc51e','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.platform_local_account_runtime_schema_readiness_v53()'::regprocedure,
     ARRAY['545db485e1993c95e1401c3058a41b74e27e144213d3e738160d790e95bdc51e','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.sla_trigger_action_runtime_schema_readiness_v53()'::regprocedure,
     ARRAY['7bce3416b1cc14e50b9b4be862cf85ff7a418399764d517e214979df343ad9e6','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.sla_object_event_ingress_schema_readiness_v53()'::regprocedure,
     ARRAY['7bce3416b1cc14e50b9b4be862cf85ff7a418399764d517e214979df343ad9e6','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.ticket_bulk_runtime_schema_readiness_v53()'::regprocedure,
     ARRAY['6ca5690202c36698ce889b920ad4ae303f50e356c8621120e2d87d57ffeb8df4','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.ticket_export_runtime_schema_readiness_v53()'::regprocedure,
     ARRAY['6ca5690202c36698ce889b920ad4ae303f50e356c8621120e2d87d57ffeb8df4','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.ticket_metadata_runtime_schema_readiness_v53()'::regprocedure,
     ARRAY['545db485e1993c95e1401c3058a41b74e27e144213d3e738160d790e95bdc51e','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.notification_dispatch_readiness_v53()'::regprocedure,
     ARRAY['fcb8956540a10aa971cb9d5cec7e43c67b44a1e7bc06426e827a2bbe699508b4','276a698f759a77a0c9d31a7d6bbbdc5fae752774dacea108ebb4171421156f41']::text[]),
    ('app.api_runtime_schema_readiness_v53()'::regprocedure,
     ARRAY['545db485e1993c95e1401c3058a41b74e27e144213d3e738160d790e95bdc51e','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.worker_runtime_schema_readiness_v53()'::regprocedure,
     ARRAY['7bce3416b1cc14e50b9b4be862cf85ff7a418399764d517e214979df343ad9e6','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.schema_compatibility_v54()'::regprocedure,
     ARRAY['6ca5690202c36698ce889b920ad4ae303f50e356c8621120e2d87d57ffeb8df4','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.release_runtime_schema_readiness_v54()'::regprocedure,
     ARRAY['2e50cd2f28a89d4a9f04282e59f740d47e374e0acf4b6e9ec3bc0282ae30b56c','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.federated_authentication_schema_readiness_v54()'::regprocedure,
     ARRAY['545db485e1993c95e1401c3058a41b74e27e144213d3e738160d790e95bdc51e','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.platform_oidc_direct_runtime_schema_readiness_v54()'::regprocedure,
     ARRAY['545db485e1993c95e1401c3058a41b74e27e144213d3e738160d790e95bdc51e','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.platform_saml_direct_runtime_schema_readiness_v54()'::regprocedure,
     ARRAY['545db485e1993c95e1401c3058a41b74e27e144213d3e738160d790e95bdc51e','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.platform_local_account_runtime_schema_readiness_v54()'::regprocedure,
     ARRAY['545db485e1993c95e1401c3058a41b74e27e144213d3e738160d790e95bdc51e','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.sla_trigger_action_runtime_schema_readiness_v54()'::regprocedure,
     ARRAY['7bce3416b1cc14e50b9b4be862cf85ff7a418399764d517e214979df343ad9e6','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.sla_object_event_ingress_schema_readiness_v54()'::regprocedure,
     ARRAY['7bce3416b1cc14e50b9b4be862cf85ff7a418399764d517e214979df343ad9e6','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.ticket_bulk_runtime_schema_readiness_v54()'::regprocedure,
     ARRAY['6ca5690202c36698ce889b920ad4ae303f50e356c8621120e2d87d57ffeb8df4','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.ticket_export_runtime_schema_readiness_v54()'::regprocedure,
     ARRAY['6ca5690202c36698ce889b920ad4ae303f50e356c8621120e2d87d57ffeb8df4','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.ticket_metadata_runtime_schema_readiness_v54()'::regprocedure,
     ARRAY['545db485e1993c95e1401c3058a41b74e27e144213d3e738160d790e95bdc51e','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.notification_dispatch_readiness_v54()'::regprocedure,
     ARRAY['fcb8956540a10aa971cb9d5cec7e43c67b44a1e7bc06426e827a2bbe699508b4','276a698f759a77a0c9d31a7d6bbbdc5fae752774dacea108ebb4171421156f41']::text[]),
    ('app.api_runtime_schema_readiness_v54()'::regprocedure,
     ARRAY['545db485e1993c95e1401c3058a41b74e27e144213d3e738160d790e95bdc51e','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.worker_runtime_schema_readiness_v54()'::regprocedure,
     ARRAY['7bce3416b1cc14e50b9b4be862cf85ff7a418399764d517e214979df343ad9e6','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.schema_compatibility_v55()'::regprocedure,
     ARRAY['6ca5690202c36698ce889b920ad4ae303f50e356c8621120e2d87d57ffeb8df4','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.release_runtime_schema_readiness_v55()'::regprocedure,
     ARRAY['2e50cd2f28a89d4a9f04282e59f740d47e374e0acf4b6e9ec3bc0282ae30b56c','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.federated_authentication_schema_readiness_v55()'::regprocedure,
     ARRAY['545db485e1993c95e1401c3058a41b74e27e144213d3e738160d790e95bdc51e','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.platform_oidc_direct_runtime_schema_readiness_v55()'::regprocedure,
     ARRAY['545db485e1993c95e1401c3058a41b74e27e144213d3e738160d790e95bdc51e','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.platform_saml_direct_runtime_schema_readiness_v55()'::regprocedure,
     ARRAY['545db485e1993c95e1401c3058a41b74e27e144213d3e738160d790e95bdc51e','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.platform_local_account_runtime_schema_readiness_v55()'::regprocedure,
     ARRAY['545db485e1993c95e1401c3058a41b74e27e144213d3e738160d790e95bdc51e','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.sla_trigger_action_runtime_schema_readiness_v55()'::regprocedure,
     ARRAY['7bce3416b1cc14e50b9b4be862cf85ff7a418399764d517e214979df343ad9e6','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.sla_object_event_ingress_schema_readiness_v55()'::regprocedure,
     ARRAY['7bce3416b1cc14e50b9b4be862cf85ff7a418399764d517e214979df343ad9e6','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.ticket_bulk_runtime_schema_readiness_v55()'::regprocedure,
     ARRAY['6ca5690202c36698ce889b920ad4ae303f50e356c8621120e2d87d57ffeb8df4','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.ticket_export_runtime_schema_readiness_v55()'::regprocedure,
     ARRAY['6ca5690202c36698ce889b920ad4ae303f50e356c8621120e2d87d57ffeb8df4','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.ticket_metadata_runtime_schema_readiness_v55()'::regprocedure,
     ARRAY['545db485e1993c95e1401c3058a41b74e27e144213d3e738160d790e95bdc51e','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.notification_dispatch_readiness_v55()'::regprocedure,
     ARRAY['fcb8956540a10aa971cb9d5cec7e43c67b44a1e7bc06426e827a2bbe699508b4','276a698f759a77a0c9d31a7d6bbbdc5fae752774dacea108ebb4171421156f41']::text[]),
    ('app.api_runtime_schema_readiness_v55()'::regprocedure,
     ARRAY['545db485e1993c95e1401c3058a41b74e27e144213d3e738160d790e95bdc51e','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.worker_runtime_schema_readiness_v55()'::regprocedure,
     ARRAY['7bce3416b1cc14e50b9b4be862cf85ff7a418399764d517e214979df343ad9e6','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.schema_compatibility_v56()'::regprocedure,
     ARRAY['6ca5690202c36698ce889b920ad4ae303f50e356c8621120e2d87d57ffeb8df4','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.release_runtime_schema_readiness_v56()'::regprocedure,
     ARRAY['2e50cd2f28a89d4a9f04282e59f740d47e374e0acf4b6e9ec3bc0282ae30b56c','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.federated_authentication_schema_readiness_v56()'::regprocedure,
     ARRAY['545db485e1993c95e1401c3058a41b74e27e144213d3e738160d790e95bdc51e','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.platform_oidc_direct_runtime_schema_readiness_v56()'::regprocedure,
     ARRAY['545db485e1993c95e1401c3058a41b74e27e144213d3e738160d790e95bdc51e','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.platform_saml_direct_runtime_schema_readiness_v56()'::regprocedure,
     ARRAY['545db485e1993c95e1401c3058a41b74e27e144213d3e738160d790e95bdc51e','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.platform_local_account_runtime_schema_readiness_v56()'::regprocedure,
     ARRAY['545db485e1993c95e1401c3058a41b74e27e144213d3e738160d790e95bdc51e','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.sla_trigger_action_runtime_schema_readiness_v56()'::regprocedure,
     ARRAY['7bce3416b1cc14e50b9b4be862cf85ff7a418399764d517e214979df343ad9e6','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.sla_object_event_ingress_schema_readiness_v56()'::regprocedure,
     ARRAY['7bce3416b1cc14e50b9b4be862cf85ff7a418399764d517e214979df343ad9e6','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.ticket_bulk_runtime_schema_readiness_v56()'::regprocedure,
     ARRAY['6ca5690202c36698ce889b920ad4ae303f50e356c8621120e2d87d57ffeb8df4','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.ticket_export_runtime_schema_readiness_v56()'::regprocedure,
     ARRAY['6ca5690202c36698ce889b920ad4ae303f50e356c8621120e2d87d57ffeb8df4','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.ticket_metadata_runtime_schema_readiness_v56()'::regprocedure,
     ARRAY['545db485e1993c95e1401c3058a41b74e27e144213d3e738160d790e95bdc51e','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.notification_dispatch_readiness_v56()'::regprocedure,
     ARRAY['fcb8956540a10aa971cb9d5cec7e43c67b44a1e7bc06426e827a2bbe699508b4','276a698f759a77a0c9d31a7d6bbbdc5fae752774dacea108ebb4171421156f41']::text[]),
    ('app.api_runtime_schema_readiness_v56()'::regprocedure,
     ARRAY['545db485e1993c95e1401c3058a41b74e27e144213d3e738160d790e95bdc51e','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.worker_runtime_schema_readiness_v56()'::regprocedure,
     ARRAY['7bce3416b1cc14e50b9b4be862cf85ff7a418399764d517e214979df343ad9e6','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.schema_compatibility_v57()'::regprocedure,
     ARRAY['6ca5690202c36698ce889b920ad4ae303f50e356c8621120e2d87d57ffeb8df4','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.release_runtime_schema_readiness_v57()'::regprocedure,
     ARRAY['2e50cd2f28a89d4a9f04282e59f740d47e374e0acf4b6e9ec3bc0282ae30b56c','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.federated_authentication_schema_readiness_v57()'::regprocedure,
     ARRAY['545db485e1993c95e1401c3058a41b74e27e144213d3e738160d790e95bdc51e','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.platform_oidc_direct_runtime_schema_readiness_v57()'::regprocedure,
     ARRAY['545db485e1993c95e1401c3058a41b74e27e144213d3e738160d790e95bdc51e','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.platform_saml_direct_runtime_schema_readiness_v57()'::regprocedure,
     ARRAY['545db485e1993c95e1401c3058a41b74e27e144213d3e738160d790e95bdc51e','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.platform_local_account_runtime_schema_readiness_v57()'::regprocedure,
     ARRAY['545db485e1993c95e1401c3058a41b74e27e144213d3e738160d790e95bdc51e','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.sla_trigger_action_runtime_schema_readiness_v57()'::regprocedure,
     ARRAY['7bce3416b1cc14e50b9b4be862cf85ff7a418399764d517e214979df343ad9e6','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.sla_object_event_ingress_schema_readiness_v57()'::regprocedure,
     ARRAY['7bce3416b1cc14e50b9b4be862cf85ff7a418399764d517e214979df343ad9e6','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.ticket_bulk_runtime_schema_readiness_v57()'::regprocedure,
     ARRAY['6ca5690202c36698ce889b920ad4ae303f50e356c8621120e2d87d57ffeb8df4','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.ticket_export_runtime_schema_readiness_v57()'::regprocedure,
     ARRAY['6ca5690202c36698ce889b920ad4ae303f50e356c8621120e2d87d57ffeb8df4','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.ticket_metadata_runtime_schema_readiness_v57()'::regprocedure,
     ARRAY['545db485e1993c95e1401c3058a41b74e27e144213d3e738160d790e95bdc51e','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.notification_dispatch_readiness_v57()'::regprocedure,
     ARRAY['fcb8956540a10aa971cb9d5cec7e43c67b44a1e7bc06426e827a2bbe699508b4','276a698f759a77a0c9d31a7d6bbbdc5fae752774dacea108ebb4171421156f41']::text[]),
    ('app.api_runtime_schema_readiness_v57()'::regprocedure,
     ARRAY['545db485e1993c95e1401c3058a41b74e27e144213d3e738160d790e95bdc51e','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.worker_runtime_schema_readiness_v57()'::regprocedure,
     ARRAY['7bce3416b1cc14e50b9b4be862cf85ff7a418399764d517e214979df343ad9e6','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.schema_compatibility_v58()'::regprocedure,
     ARRAY['6ca5690202c36698ce889b920ad4ae303f50e356c8621120e2d87d57ffeb8df4','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.release_runtime_schema_readiness_v58()'::regprocedure,
     ARRAY['2e50cd2f28a89d4a9f04282e59f740d47e374e0acf4b6e9ec3bc0282ae30b56c','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.federated_authentication_schema_readiness_v58()'::regprocedure,
     ARRAY['545db485e1993c95e1401c3058a41b74e27e144213d3e738160d790e95bdc51e','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.platform_oidc_direct_runtime_schema_readiness_v58()'::regprocedure,
     ARRAY['545db485e1993c95e1401c3058a41b74e27e144213d3e738160d790e95bdc51e','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.platform_saml_direct_runtime_schema_readiness_v58()'::regprocedure,
     ARRAY['545db485e1993c95e1401c3058a41b74e27e144213d3e738160d790e95bdc51e','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.platform_local_account_runtime_schema_readiness_v58()'::regprocedure,
     ARRAY['545db485e1993c95e1401c3058a41b74e27e144213d3e738160d790e95bdc51e','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.sla_trigger_action_runtime_schema_readiness_v58()'::regprocedure,
     ARRAY['7bce3416b1cc14e50b9b4be862cf85ff7a418399764d517e214979df343ad9e6','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.sla_object_event_ingress_schema_readiness_v58()'::regprocedure,
     ARRAY['7bce3416b1cc14e50b9b4be862cf85ff7a418399764d517e214979df343ad9e6','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.ticket_bulk_runtime_schema_readiness_v58()'::regprocedure,
     ARRAY['6ca5690202c36698ce889b920ad4ae303f50e356c8621120e2d87d57ffeb8df4','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.ticket_export_runtime_schema_readiness_v58()'::regprocedure,
     ARRAY['6ca5690202c36698ce889b920ad4ae303f50e356c8621120e2d87d57ffeb8df4','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.ticket_metadata_runtime_schema_readiness_v58()'::regprocedure,
     ARRAY['545db485e1993c95e1401c3058a41b74e27e144213d3e738160d790e95bdc51e','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.notification_dispatch_readiness_v58()'::regprocedure,
     ARRAY['fcb8956540a10aa971cb9d5cec7e43c67b44a1e7bc06426e827a2bbe699508b4','276a698f759a77a0c9d31a7d6bbbdc5fae752774dacea108ebb4171421156f41']::text[]),
    ('app.api_runtime_schema_readiness_v58()'::regprocedure,
     ARRAY['545db485e1993c95e1401c3058a41b74e27e144213d3e738160d790e95bdc51e','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[]),
    ('app.worker_runtime_schema_readiness_v58()'::regprocedure,
     ARRAY['7bce3416b1cc14e50b9b4be862cf85ff7a418399764d517e214979df343ad9e6','55a2b7403faa8c46fdc837c8b99f74bd11ef3e02669ae571337f173a3d5463ca']::text[])
),
historical_source_function(function_oid,source_hashes) AS (
  VALUES
    ('app.private_mfa_policy_administration_schema_readiness_v5()'::regprocedure,
     ARRAY['ad1c5aa88277c11782e7ad20abf4509e5343ec8f62c47c12062176fa797d1032','5348f7c36837a65fa5a41443177acd6820d41f0a1fa5b8b473c1024b070383de']::text[]),
    ('app.private_platform_identity_runtime_schema_readiness_v11()'::regprocedure,
     ARRAY['81395c7f999f2ab28be82fcc2854e536f8548285ab741661889fb41be09d5f7b','e6b1ab3503731aa6b664f075fcbb3f74431d9d600ca01254a408b232f17a5171']::text[]),
    ('app.private_platform_oidc_direct_runtime_schema_readiness_v7()'::regprocedure,
     ARRAY['588689bdf29011aba884ba70bcf330f09951895b7680c5181196648c4537f2ce','7c0d03aa7dd74f8c72ad867023e324ef49fccbe28b77a6c8d10eb4c8069ecbf0']::text[]),
    ('app.private_platform_saml_direct_runtime_schema_readiness_v4()'::regprocedure,
     ARRAY['bbc299650d5f4bc8e3616d4e19a64af11494a2f9156c79a3b37a3b702f3cf03c','541eb8770ec4b1981f8b114c034077a89a617afb792c9912afaa1ed3d4ada471']::text[])
),
rotated_config_function(function_oid,config_hashes) AS (
  VALUES
    ('app.schema_compatibility_v44()'::regprocedure,
     ARRAY['19226d5c6428b02ea92ef8ae49300183854c7269ce7bac9c23c6cfeca1ce24a6','04daa9a15fca5b44fc33547dacaa5a995bc8211fad0ce34e771d033ae0bc0358']::text[]),
    ('app.schema_compatibility_v45()'::regprocedure,
     ARRAY['19226d5c6428b02ea92ef8ae49300183854c7269ce7bac9c23c6cfeca1ce24a6','04daa9a15fca5b44fc33547dacaa5a995bc8211fad0ce34e771d033ae0bc0358']::text[]),
    ('app.schema_compatibility_v46()'::regprocedure,
     ARRAY['19226d5c6428b02ea92ef8ae49300183854c7269ce7bac9c23c6cfeca1ce24a6','04daa9a15fca5b44fc33547dacaa5a995bc8211fad0ce34e771d033ae0bc0358']::text[]),
    ('app.schema_compatibility_v47()'::regprocedure,
     ARRAY['19226d5c6428b02ea92ef8ae49300183854c7269ce7bac9c23c6cfeca1ce24a6','04daa9a15fca5b44fc33547dacaa5a995bc8211fad0ce34e771d033ae0bc0358']::text[]),
    ('app.schema_compatibility_v48()'::regprocedure,
     ARRAY['19226d5c6428b02ea92ef8ae49300183854c7269ce7bac9c23c6cfeca1ce24a6','08b3d8dee91156101e824c301bd0063dd1a443f60af4db0ef45531bae3e003ec','04daa9a15fca5b44fc33547dacaa5a995bc8211fad0ce34e771d033ae0bc0358']::text[]),
    ('app.schema_compatibility_v49()'::regprocedure,
     ARRAY['19226d5c6428b02ea92ef8ae49300183854c7269ce7bac9c23c6cfeca1ce24a6','0f5d39b9b78c595b97cd6bdb4772fd66376837e71470c8298975466a4b2e0c57','04daa9a15fca5b44fc33547dacaa5a995bc8211fad0ce34e771d033ae0bc0358']::text[]),
    ('app.schema_compatibility_v50()'::regprocedure,
     ARRAY['19226d5c6428b02ea92ef8ae49300183854c7269ce7bac9c23c6cfeca1ce24a6','3b0bc33e8cec06615065ebfd10d34ffbe698367f6c9fec5394a88d8a336ff17b','04daa9a15fca5b44fc33547dacaa5a995bc8211fad0ce34e771d033ae0bc0358']::text[]),
    ('app.schema_compatibility_v51()'::regprocedure,
     ARRAY['19226d5c6428b02ea92ef8ae49300183854c7269ce7bac9c23c6cfeca1ce24a6','d2d12096284e8449752ff1bd25ff2ab6ab5fbbed3f0999252defa56230ce5663','04daa9a15fca5b44fc33547dacaa5a995bc8211fad0ce34e771d033ae0bc0358']::text[]),
    ('app.schema_compatibility_v52()'::regprocedure,
     ARRAY['19226d5c6428b02ea92ef8ae49300183854c7269ce7bac9c23c6cfeca1ce24a6','7e3c5e934b5d38ab43fe9d4ef20ab17cba3bd6c7cf0b2cc7a620bee70f67abcd','04daa9a15fca5b44fc33547dacaa5a995bc8211fad0ce34e771d033ae0bc0358']::text[]),
    ('app.schema_compatibility_v53()'::regprocedure,
     ARRAY['19226d5c6428b02ea92ef8ae49300183854c7269ce7bac9c23c6cfeca1ce24a6','980131df33a62002ac3ba5a5e12d731809399c406edbac7bb7231d5be0e51907','04daa9a15fca5b44fc33547dacaa5a995bc8211fad0ce34e771d033ae0bc0358']::text[]),
    ('app.schema_compatibility_v54()'::regprocedure,
     ARRAY['19226d5c6428b02ea92ef8ae49300183854c7269ce7bac9c23c6cfeca1ce24a6','ecc15501f349a6a10f1bc6a37989c18d4a5735f1101d719dcd711e64acff7eda','04daa9a15fca5b44fc33547dacaa5a995bc8211fad0ce34e771d033ae0bc0358']::text[]),
    ('app.schema_compatibility_v55()'::regprocedure,
     ARRAY['19226d5c6428b02ea92ef8ae49300183854c7269ce7bac9c23c6cfeca1ce24a6','4ebf163da21b2205e7684f934f9705bd98aa077e3b13ddadc859857be1611cb5','04daa9a15fca5b44fc33547dacaa5a995bc8211fad0ce34e771d033ae0bc0358']::text[]),
    ('app.schema_compatibility_v56()'::regprocedure,
     ARRAY['19226d5c6428b02ea92ef8ae49300183854c7269ce7bac9c23c6cfeca1ce24a6','ca25b20e4345170727dd8dc883085dc1af97dbf34335a0dc9b563f2e728105df','04daa9a15fca5b44fc33547dacaa5a995bc8211fad0ce34e771d033ae0bc0358']::text[]),
    ('app.schema_compatibility_v57()'::regprocedure,
     ARRAY['19226d5c6428b02ea92ef8ae49300183854c7269ce7bac9c23c6cfeca1ce24a6','1eae44fca0a496a4c401fc80004b09ef5e6902074a02750d33fb70513528a5b2','04daa9a15fca5b44fc33547dacaa5a995bc8211fad0ce34e771d033ae0bc0358']::text[]),
    ('app.schema_compatibility_v58()'::regprocedure,
     ARRAY['19226d5c6428b02ea92ef8ae49300183854c7269ce7bac9c23c6cfeca1ce24a6','21c0ca443faaf6c1b5e5c782bab1459ffb6479375be654f90706115f9cac465b','04daa9a15fca5b44fc33547dacaa5a995bc8211fad0ce34e771d033ae0bc0358']::text[])
),
self_excluded_function(function_oid) AS (
  VALUES
    (pg_catalog.to_regprocedure('app.schema_compatibility_v59()')),
    (pg_catalog.to_regprocedure('app.private_release_runtime_dependency_surface_hash_v59()')),
    (pg_catalog.to_regprocedure('app.private_release_runtime_schema_readiness_v59()')),
    (pg_catalog.to_regprocedure('app.seal_schema_compatibility_manifest(bigint,bigint,text,text)'))
),
sealer_function(function_oid,sealer_role_oid) AS (
  SELECT function_row.oid,function_row.proowner
  FROM pg_catalog.pg_proc AS function_row
  JOIN pg_catalog.pg_roles AS owner ON owner.oid=function_row.proowner
  WHERE function_row.oid=
    'app.private_runtime_login_credential_state_v49()'::regprocedure
    AND owner.rolsuper
    AND owner.rolname<>ALL(ARRAY[
      'periapsis_api','periapsis_worker','periapsis_notifier',
      'periapsis_auditor','periapsis_api_login','periapsis_worker_login',
      'periapsis_notifier_login','periapsis_auditor_login'
    ]::text[])
),
-- Runtime logins are provisioned after sealing and may be absent or NOLOGIN
-- during a quiesced upgrade. Omit only their exact non-secret state and one
-- exact direct edge so absence, offline, and provisioned states converge. The
-- historical NULL and provisioned infinity password-expiry encodings both
-- mean no expiry; every finite timestamp remains distinct and attested. The
-- masked password field contributes only an absent/present sentinel: LOGIN
-- is accepted only with a credential, while NOLOGIN remains a valid quiesced
-- lifecycle state without exposing or hashing secret material. The
-- canonical edge's grantor is deliberately deployment-neutral; any other
-- attribute, setting, membership, option, or object-ACL grantor drift remains
-- in the transcript and therefore closes every V49 root.
runtime_login(role_name,group_role_name,connection_limit) AS (
  VALUES
    ('periapsis_api_login','periapsis_api',40),
    ('periapsis_worker_login','periapsis_worker',20),
    ('periapsis_notifier_login','periapsis_notifier',20),
    ('periapsis_auditor_login','periapsis_auditor',-1)
),
runtime_login_credential(role_name,credential_state) AS (
  SELECT credential.role_name,credential.credential_state
  FROM app.private_runtime_login_credential_state_v49() AS credential
),
catalog_entry(kind,key,payload) AS (
  SELECT 'database'::text,'current'::text,
    pg_catalog.concat_ws('|',
      CASE WHEN database_owner.rolsuper
             AND database_owner.rolname NOT LIKE 'periapsis\_%' ESCAPE '\'
        THEN '<DATABASE-OWNER-SUPERUSER>'
        ELSE database_owner.rolname || ':' ||
          database_owner.rolsuper::text END,
      pg_catalog.pg_encoding_to_char(database.encoding),
      database.datlocprovider::text,database.datcollate,database.datctype,
      coalesce(database.datlocale,''),coalesce(database.daticurules,''),
      coalesce(database.datcollversion,''),database.datistemplate::text,
      database.datallowconn::text,database.dathasloginevt::text,
      database.datconnlimit::text,tablespace.spcname,
      coalesce((
        SELECT string_agg(
          CASE WHEN acl.grantor=database.datdba
             AND database_owner.rolsuper
             AND database_owner.rolname NOT LIKE 'periapsis\_%' ESCAPE '\'
            THEN '<DATABASE-OWNER-SUPERUSER>'
            ELSE coalesce(grantor.rolname,'PUBLIC') END || '>' ||
          CASE WHEN acl.grantee=database.datdba
             AND database_owner.rolsuper
             AND database_owner.rolname NOT LIKE 'periapsis\_%' ESCAPE '\'
            THEN '<DATABASE-OWNER-SUPERUSER>'
            ELSE coalesce(grantee.rolname,'PUBLIC') END || ':' ||
          acl.privilege_type || ':' || acl.is_grantable::text,
          ',' ORDER BY
          CASE WHEN acl.grantor=database.datdba
             AND database_owner.rolsuper
             AND database_owner.rolname NOT LIKE 'periapsis\_%' ESCAPE '\'
            THEN '<DATABASE-OWNER-SUPERUSER>'
            ELSE coalesce(grantor.rolname,'PUBLIC') END COLLATE "C",
          CASE WHEN acl.grantee=database.datdba
             AND database_owner.rolsuper
             AND database_owner.rolname NOT LIKE 'periapsis\_%' ESCAPE '\'
            THEN '<DATABASE-OWNER-SUPERUSER>'
            ELSE coalesce(grantee.rolname,'PUBLIC') END COLLATE "C",
          acl.privilege_type COLLATE "C",acl.is_grantable
        )
        FROM pg_catalog.aclexplode(coalesce(
          database.datacl,
          pg_catalog.acldefault('d',database.datdba)
        )) AS acl
        LEFT JOIN pg_catalog.pg_roles AS grantor ON grantor.oid=acl.grantor
        LEFT JOIN pg_catalog.pg_roles AS grantee ON grantee.oid=acl.grantee
      ),'<empty>'))
  FROM pg_catalog.pg_database AS database
  JOIN pg_catalog.pg_roles AS database_owner
    ON database_owner.oid=database.datdba
  JOIN pg_catalog.pg_tablespace AS tablespace
    ON tablespace.oid=database.dattablespace
  WHERE database.datname=pg_catalog.current_database()

  UNION ALL
  SELECT 'schema',namespace.nspname::text,
    pg_catalog.concat_ws('|',owner.rolname,
      coalesce((
        SELECT string_agg(
          coalesce(grantor.rolname,'PUBLIC') || '>' ||
          coalesce(grantee.rolname,'PUBLIC') || ':' || acl.privilege_type ||
          ':' || acl.is_grantable::text,
          ',' ORDER BY coalesce(grantor.rolname,'PUBLIC') COLLATE "C",
          coalesce(grantee.rolname,'PUBLIC') COLLATE "C",
          acl.privilege_type COLLATE "C",acl.is_grantable
        )
        FROM pg_catalog.aclexplode(coalesce(
          namespace.nspacl,
          pg_catalog.acldefault('n',namespace.nspowner)
        )) AS acl
        LEFT JOIN pg_catalog.pg_roles AS grantor ON grantor.oid=acl.grantor
        LEFT JOIN pg_catalog.pg_roles AS grantee ON grantee.oid=acl.grantee
      ),'<empty>'))
  FROM pg_catalog.pg_namespace AS namespace
  JOIN pg_catalog.pg_roles AS owner ON owner.oid=namespace.nspowner
  WHERE namespace.nspname IN ('public','app')

  UNION ALL
  SELECT 'relation',namespace.nspname || '.' || relation.relname,
    pg_catalog.concat_ws('|',owner.rolname,relation.relkind::text,
      relation.relpersistence::text,coalesce(access_method.amname,''),
      relation.relrowsecurity::text,relation.relforcerowsecurity::text,
      relation.relreplident::text,relation.relispartition::text,
      relation.relhassubclass::text,relation.relhasrules::text,
      relation.relhastriggers::text,relation.relchecks::text,
      relation.relispopulated::text,
      coalesce(pg_catalog.pg_get_expr(
        relation.relpartbound,relation.oid,true
      ),''),coalesce(relation.reloptions::text,''),
      coalesce((
        SELECT string_agg(
          coalesce(grantor.rolname,'PUBLIC') || '>' ||
          coalesce(grantee.rolname,'PUBLIC') || ':' || acl.privilege_type ||
          ':' || acl.is_grantable::text,
          ',' ORDER BY coalesce(grantor.rolname,'PUBLIC') COLLATE "C",
          coalesce(grantee.rolname,'PUBLIC') COLLATE "C",
          acl.privilege_type COLLATE "C",acl.is_grantable
        )
        FROM pg_catalog.aclexplode(coalesce(
          relation.relacl,
          pg_catalog.acldefault(
            CASE WHEN relation.relkind='S' THEN 'S'::"char" ELSE 'r'::"char" END,
            relation.relowner
          )
        )) AS acl
        LEFT JOIN pg_catalog.pg_roles AS grantor ON grantor.oid=acl.grantor
        LEFT JOIN pg_catalog.pg_roles AS grantee ON grantee.oid=acl.grantee
      ),'<empty>'))
  FROM pg_catalog.pg_class AS relation
  JOIN pg_catalog.pg_namespace AS namespace
    ON namespace.oid=relation.relnamespace
  JOIN pg_catalog.pg_roles AS owner ON owner.oid=relation.relowner
  LEFT JOIN pg_catalog.pg_am AS access_method
    ON access_method.oid=relation.relam
  WHERE namespace.nspname IN ('public','app')
    AND relation.relkind IN ('r','p','S','v','m','f')

  UNION ALL
  SELECT 'inheritance',
    child_namespace.nspname || '.' || child.relname || '->' ||
      parent_namespace.nspname || '.' || parent.relname,
    pg_catalog.concat_ws('|',inheritance.inhseqno::text,
      inheritance.inhdetachpending::text)
  FROM pg_catalog.pg_inherits AS inheritance
  JOIN pg_catalog.pg_class AS child ON child.oid=inheritance.inhrelid
  JOIN pg_catalog.pg_namespace AS child_namespace
    ON child_namespace.oid=child.relnamespace
  JOIN pg_catalog.pg_class AS parent ON parent.oid=inheritance.inhparent
  JOIN pg_catalog.pg_namespace AS parent_namespace
    ON parent_namespace.oid=parent.relnamespace
  WHERE child_namespace.nspname IN ('public','app')
     OR parent_namespace.nspname IN ('public','app')

  UNION ALL
  SELECT 'column',namespace.nspname || '.' || relation.relname || '.' ||
         attribute.attname,
    pg_catalog.concat_ws('|',attribute.attnum::text,
      pg_catalog.format_type(attribute.atttypid,attribute.atttypmod),
      attribute.attnotnull::text,attribute.attidentity::text,
      attribute.attgenerated::text,attribute.attstorage::text,
      attribute.attcompression::text,attribute.attstattarget::text,
      coalesce(collation_namespace.nspname || '.' || collation_row.collname,''),
      coalesce(pg_catalog.pg_get_expr(
        default_value.adbin,default_value.adrelid,true
      ),''),coalesce((
        SELECT string_agg(
          coalesce(grantor.rolname,'PUBLIC') || '>' ||
          coalesce(grantee.rolname,'PUBLIC') || ':' || acl.privilege_type ||
          ':' || acl.is_grantable::text,
          ',' ORDER BY coalesce(grantor.rolname,'PUBLIC') COLLATE "C",
          coalesce(grantee.rolname,'PUBLIC') COLLATE "C",
          acl.privilege_type COLLATE "C",acl.is_grantable
        )
        FROM pg_catalog.aclexplode(attribute.attacl) AS acl
        LEFT JOIN pg_catalog.pg_roles AS grantor ON grantor.oid=acl.grantor
        LEFT JOIN pg_catalog.pg_roles AS grantee ON grantee.oid=acl.grantee
      ),'<empty>'))
  FROM pg_catalog.pg_attribute AS attribute
  JOIN pg_catalog.pg_class AS relation ON relation.oid=attribute.attrelid
  JOIN pg_catalog.pg_namespace AS namespace
    ON namespace.oid=relation.relnamespace
  LEFT JOIN pg_catalog.pg_attrdef AS default_value
    ON default_value.adrelid=attribute.attrelid
   AND default_value.adnum=attribute.attnum
  LEFT JOIN pg_catalog.pg_collation AS collation_row
    ON collation_row.oid=attribute.attcollation
  LEFT JOIN pg_catalog.pg_namespace AS collation_namespace
    ON collation_namespace.oid=collation_row.collnamespace
  WHERE namespace.nspname IN ('public','app') AND attribute.attnum>0
    AND NOT attribute.attisdropped
    AND relation.relkind IN ('r','p','v','m','f')

  UNION ALL
  SELECT 'type',namespace.nspname || '.' || type_row.typname,
    pg_catalog.concat_ws('|',owner.rolname,type_row.typtype::text,
      type_row.typcategory::text,type_row.typispreferred::text,
      type_row.typisdefined::text,type_row.typdelim::text,
      type_row.typnotnull::text,type_row.typbyval::text,
      type_row.typlen::text,type_row.typalign::text,
      type_row.typstorage::text,
      CASE WHEN type_row.typrelid=0 THEN ''
        ELSE relation_namespace.nspname || '.' || relation.relname END,
      CASE WHEN type_row.typbasetype=0 THEN ''
        ELSE pg_catalog.format_type(
          type_row.typbasetype,type_row.typtypmod
        ) END,
      CASE WHEN type_row.typelem=0 THEN ''
        ELSE pg_catalog.format_type(type_row.typelem,NULL) END,
      coalesce(
        collation_namespace.nspname || '.' || type_collation.collname,''
      ),
      coalesce(pg_catalog.pg_get_expr(
        type_row.typdefaultbin,0,true
      ),type_row.typdefault,''),type_acl.payload)
  FROM pg_catalog.pg_type AS type_row
  JOIN pg_catalog.pg_namespace AS namespace
    ON namespace.oid=type_row.typnamespace
  JOIN pg_catalog.pg_roles AS owner ON owner.oid=type_row.typowner
  LEFT JOIN pg_catalog.pg_class AS relation
    ON relation.oid=type_row.typrelid
  LEFT JOIN pg_catalog.pg_namespace AS relation_namespace
    ON relation_namespace.oid=relation.relnamespace
  LEFT JOIN pg_catalog.pg_collation AS type_collation
    ON type_collation.oid=type_row.typcollation
  LEFT JOIN pg_catalog.pg_namespace AS collation_namespace
    ON collation_namespace.oid=type_collation.collnamespace
  LEFT JOIN LATERAL (
    SELECT coalesce(string_agg(
      coalesce(grantor.rolname,'PUBLIC') || '>' ||
      coalesce(grantee.rolname,'PUBLIC') || ':' || acl.privilege_type ||
      ':' || acl.is_grantable::text,
      ',' ORDER BY coalesce(grantor.rolname,'PUBLIC') COLLATE "C",
      coalesce(grantee.rolname,'PUBLIC') COLLATE "C",
      acl.privilege_type COLLATE "C",acl.is_grantable
    ),'<empty>') AS payload
    FROM pg_catalog.aclexplode(coalesce(
      type_row.typacl,
      pg_catalog.acldefault('T',type_row.typowner)
    )) AS acl
    LEFT JOIN pg_catalog.pg_roles AS grantor ON grantor.oid=acl.grantor
    LEFT JOIN pg_catalog.pg_roles AS grantee ON grantee.oid=acl.grantee
  ) AS type_acl ON true
  WHERE namespace.nspname IN ('public','app')
    AND type_row.typtype IN ('e','d','r','m','c')

  UNION ALL
  SELECT 'enum',namespace.nspname || '.' || type_row.typname || '.' ||
         enum_row.enumsortorder::text,
    pg_catalog.concat_ws('|',owner.rolname,enum_row.enumlabel)
  FROM pg_catalog.pg_enum AS enum_row
  JOIN pg_catalog.pg_type AS type_row ON type_row.oid=enum_row.enumtypid
  JOIN pg_catalog.pg_namespace AS namespace
    ON namespace.oid=type_row.typnamespace
  JOIN pg_catalog.pg_roles AS owner ON owner.oid=type_row.typowner
  WHERE namespace.nspname IN ('public','app')

  UNION ALL
  SELECT 'cast',
    pg_catalog.format_type(cast_row.castsource,NULL) || '->' ||
      pg_catalog.format_type(cast_row.casttarget,NULL),
    pg_catalog.concat_ws('|',cast_row.castcontext::text,
      cast_row.castmethod::text,
      CASE WHEN cast_row.castfunc=0 THEN ''
        ELSE function_namespace.nspname || '.' || function_row.proname ||
          '(' || pg_catalog.pg_get_function_identity_arguments(
            function_row.oid
          ) || ')' END)
  FROM pg_catalog.pg_cast AS cast_row
  JOIN pg_catalog.pg_type AS source_type
    ON source_type.oid=cast_row.castsource
  JOIN pg_catalog.pg_namespace AS source_namespace
    ON source_namespace.oid=source_type.typnamespace
  JOIN pg_catalog.pg_type AS target_type
    ON target_type.oid=cast_row.casttarget
  JOIN pg_catalog.pg_namespace AS target_namespace
    ON target_namespace.oid=target_type.typnamespace
  LEFT JOIN pg_catalog.pg_proc AS function_row
    ON function_row.oid=cast_row.castfunc
  LEFT JOIN pg_catalog.pg_namespace AS function_namespace
    ON function_namespace.oid=function_row.pronamespace
  WHERE source_namespace.nspname IN ('public','app')
     OR target_namespace.nspname IN ('public','app')
     OR function_namespace.nspname IN ('public','app')

  UNION ALL
  SELECT 'operator',
    namespace.nspname || '.' || operator.oprname || '(' ||
      pg_catalog.format_type(operator.oprleft,NULL) || ',' ||
      pg_catalog.format_type(operator.oprright,NULL) || ')',
    pg_catalog.concat_ws('|',owner.rolname,operator.oprkind::text,
      operator.oprcanmerge::text,operator.oprcanhash::text,
      pg_catalog.format_type(operator.oprresult,NULL),
      code_namespace.nspname || '.' || code_function.proname || '(' ||
        pg_catalog.pg_get_function_identity_arguments(code_function.oid) || ')',
      coalesce(commutator_namespace.nspname || '.' ||
        commutator.oprname || '(' ||
        pg_catalog.format_type(commutator.oprleft,NULL) || ',' ||
        pg_catalog.format_type(commutator.oprright,NULL) || ')',''),
      coalesce(negator_namespace.nspname || '.' || negator.oprname || '(' ||
        pg_catalog.format_type(negator.oprleft,NULL) || ',' ||
        pg_catalog.format_type(negator.oprright,NULL) || ')',''),
      coalesce(restrict_namespace.nspname || '.' ||
        restrict_function.proname || '(' ||
        pg_catalog.pg_get_function_identity_arguments(
          restrict_function.oid
        ) || ')',''),
      coalesce(join_namespace.nspname || '.' || join_function.proname || '(' ||
        pg_catalog.pg_get_function_identity_arguments(join_function.oid) ||
        ')',''))
  FROM pg_catalog.pg_operator AS operator
  JOIN pg_catalog.pg_namespace AS namespace
    ON namespace.oid=operator.oprnamespace
  JOIN pg_catalog.pg_roles AS owner ON owner.oid=operator.oprowner
  JOIN pg_catalog.pg_proc AS code_function
    ON code_function.oid=operator.oprcode
  JOIN pg_catalog.pg_namespace AS code_namespace
    ON code_namespace.oid=code_function.pronamespace
  LEFT JOIN pg_catalog.pg_operator AS commutator
    ON commutator.oid=operator.oprcom
  LEFT JOIN pg_catalog.pg_namespace AS commutator_namespace
    ON commutator_namespace.oid=commutator.oprnamespace
  LEFT JOIN pg_catalog.pg_operator AS negator
    ON negator.oid=operator.oprnegate
  LEFT JOIN pg_catalog.pg_namespace AS negator_namespace
    ON negator_namespace.oid=negator.oprnamespace
  LEFT JOIN pg_catalog.pg_proc AS restrict_function
    ON restrict_function.oid=operator.oprrest
  LEFT JOIN pg_catalog.pg_namespace AS restrict_namespace
    ON restrict_namespace.oid=restrict_function.pronamespace
  LEFT JOIN pg_catalog.pg_proc AS join_function
    ON join_function.oid=operator.oprjoin
  LEFT JOIN pg_catalog.pg_namespace AS join_namespace
    ON join_namespace.oid=join_function.pronamespace
  WHERE namespace.nspname IN ('public','app')

  UNION ALL
  SELECT 'constraint',namespace.nspname || '.' || relation.relname || '.' ||
         constraint_row.conname,
    pg_catalog.concat_ws('|',constraint_row.contype::text,
      constraint_row.condeferrable::text,constraint_row.condeferred::text,
      constraint_row.convalidated::text,
      pg_catalog.pg_get_constraintdef(constraint_row.oid,true),
      coalesce((
        SELECT string_agg(
          pg_catalog.concat_ws('|',constraint_trigger.tgenabled::text,
            constraint_trigger.tgtype::text,
            constraint_trigger.tgdeferrable::text,
            constraint_trigger.tginitdeferred::text,
            constraint_trigger.tgnargs::text,
            pg_catalog.encode(constraint_trigger.tgargs,'hex'),
            trigger_namespace.nspname || '.' || trigger_function.proname ||
              '(' || pg_catalog.pg_get_function_identity_arguments(
                trigger_function.oid
              ) || ')'),
          ',' ORDER BY constraint_trigger.tgtype,
            trigger_namespace.nspname COLLATE "C",
            trigger_function.proname COLLATE "C",
            pg_catalog.pg_get_function_identity_arguments(
              trigger_function.oid
            ) COLLATE "C",constraint_trigger.tgenabled,
            constraint_trigger.tgdeferrable,
            constraint_trigger.tginitdeferred,
            pg_catalog.encode(constraint_trigger.tgargs,'hex') COLLATE "C"
        )
        FROM pg_catalog.pg_trigger AS constraint_trigger
        JOIN pg_catalog.pg_proc AS trigger_function
          ON trigger_function.oid=constraint_trigger.tgfoid
        JOIN pg_catalog.pg_namespace AS trigger_namespace
          ON trigger_namespace.oid=trigger_function.pronamespace
        WHERE constraint_trigger.tgconstraint=constraint_row.oid
      ),'<none>'))
  FROM pg_catalog.pg_constraint AS constraint_row
  JOIN pg_catalog.pg_class AS relation
    ON relation.oid=constraint_row.conrelid
  JOIN pg_catalog.pg_namespace AS namespace
    ON namespace.oid=relation.relnamespace
  WHERE namespace.nspname IN ('public','app')

  UNION ALL
  SELECT 'domain_constraint',
    namespace.nspname || '.' || type_row.typname || '.' ||
      constraint_row.conname,
    pg_catalog.concat_ws('|',constraint_row.contype::text,
      constraint_row.condeferrable::text,constraint_row.condeferred::text,
      constraint_row.convalidated::text,constraint_row.connoinherit::text,
      constraint_row.conislocal::text,constraint_row.coninhcount::text,
      pg_catalog.pg_get_constraintdef(constraint_row.oid,true))
  FROM pg_catalog.pg_constraint AS constraint_row
  JOIN pg_catalog.pg_type AS type_row
    ON type_row.oid=constraint_row.contypid
  JOIN pg_catalog.pg_namespace AS namespace
    ON namespace.oid=type_row.typnamespace
  WHERE constraint_row.conrelid=0
    AND namespace.nspname IN ('public','app')

  UNION ALL
  SELECT 'index',table_namespace.nspname || '.' || table_row.relname || '.' ||
         index_row.relname,
    pg_catalog.concat_ws('|',owner.rolname,index_state.indisunique::text,
      index_state.indisprimary::text,index_state.indisexclusion::text,
      index_state.indimmediate::text,index_state.indisclustered::text,
      index_state.indisvalid::text,index_state.indcheckxmin::text,
      index_state.indisready::text,index_state.indislive::text,
      index_state.indisreplident::text,index_state.indnkeyatts::text,
      index_state.indnatts::text,index_state.indoption::text,
      pg_catalog.pg_get_indexdef(index_row.oid))
  FROM pg_catalog.pg_index AS index_state
  JOIN pg_catalog.pg_class AS index_row
    ON index_row.oid=index_state.indexrelid
  JOIN pg_catalog.pg_roles AS owner ON owner.oid=index_row.relowner
  JOIN pg_catalog.pg_class AS table_row ON table_row.oid=index_state.indrelid
  JOIN pg_catalog.pg_namespace AS table_namespace
    ON table_namespace.oid=table_row.relnamespace
  WHERE table_namespace.nspname IN ('public','app')

  UNION ALL
  SELECT 'policy',namespace.nspname || '.' || relation.relname || '.' ||
         policy.polname,
    pg_catalog.concat_ws('|',policy.polcmd::text,
      policy.polpermissive::text,
      coalesce((
        SELECT string_agg(
          coalesce(role.rolname,'PUBLIC'),','
          ORDER BY coalesce(role.rolname,'PUBLIC') COLLATE "C"
        )
        FROM unnest(policy.polroles) AS policy_role(role_oid)
        LEFT JOIN pg_catalog.pg_roles AS role
          ON role.oid=policy_role.role_oid
      ),''),coalesce(pg_catalog.pg_get_expr(
        policy.polqual,policy.polrelid,true
      ),''),coalesce(pg_catalog.pg_get_expr(
        policy.polwithcheck,policy.polrelid,true
      ),''))
  FROM pg_catalog.pg_policy AS policy
  JOIN pg_catalog.pg_class AS relation ON relation.oid=policy.polrelid
  JOIN pg_catalog.pg_namespace AS namespace
    ON namespace.oid=relation.relnamespace
  WHERE namespace.nspname IN ('public','app')

  UNION ALL
  SELECT 'trigger',namespace.nspname || '.' || relation.relname || '.' ||
         trigger_row.tgname,
    pg_catalog.concat_ws('|',trigger_row.tgenabled::text,
      trigger_row.tgtype::text,trigger_row.tgdeferrable::text,
      trigger_row.tginitdeferred::text,trigger_row.tgnargs::text,
      pg_catalog.encode(trigger_row.tgargs,'hex'),
      pg_catalog.pg_get_function_identity_arguments(function_row.oid),
      function_namespace.nspname || '.' || function_row.proname,
      pg_catalog.pg_get_triggerdef(trigger_row.oid,true))
  FROM pg_catalog.pg_trigger AS trigger_row
  JOIN pg_catalog.pg_class AS relation ON relation.oid=trigger_row.tgrelid
  JOIN pg_catalog.pg_namespace AS namespace
    ON namespace.oid=relation.relnamespace
  JOIN pg_catalog.pg_proc AS function_row
    ON function_row.oid=trigger_row.tgfoid
  JOIN pg_catalog.pg_namespace AS function_namespace
    ON function_namespace.oid=function_row.pronamespace
  WHERE namespace.nspname IN ('public','app')
    AND NOT trigger_row.tgisinternal

  UNION ALL
  SELECT 'event_trigger',event_trigger.evtname,
    pg_catalog.concat_ws('|',owner.rolname,event_trigger.evtevent,
      event_trigger.evtenabled::text,
      CASE WHEN event_trigger.evttags IS NULL THEN '<all>' ELSE
        pg_catalog.array_to_string(ARRAY(
          SELECT tag
          FROM pg_catalog.unnest(event_trigger.evttags) AS configured(tag)
          ORDER BY tag COLLATE "C"
        ),',') END,
      function_namespace.nspname || '.' || function_row.proname || '(' ||
        pg_catalog.pg_get_function_identity_arguments(function_row.oid) || ')')
  FROM pg_catalog.pg_event_trigger AS event_trigger
  JOIN pg_catalog.pg_roles AS owner ON owner.oid=event_trigger.evtowner
  JOIN pg_catalog.pg_proc AS function_row
    ON function_row.oid=event_trigger.evtfoid
  JOIN pg_catalog.pg_namespace AS function_namespace
    ON function_namespace.oid=function_row.pronamespace

  UNION ALL
  SELECT 'rewrite',namespace.nspname || '.' || relation.relname || '.' ||
         rewrite.rulename,
    pg_catalog.concat_ws('|',rewrite.ev_type::text,
      rewrite.ev_enabled::text,rewrite.is_instead::text,
      pg_catalog.pg_get_ruledef(rewrite.oid,true))
  FROM pg_catalog.pg_rewrite AS rewrite
  JOIN pg_catalog.pg_class AS relation ON relation.oid=rewrite.ev_class
  JOIN pg_catalog.pg_namespace AS namespace
    ON namespace.oid=relation.relnamespace
  WHERE namespace.nspname IN ('public','app')
    AND relation.relkind IN ('r','p','v','m','f')

  UNION ALL
  SELECT 'sequence',namespace.nspname || '.' || relation.relname,
    pg_catalog.concat_ws('|',sequence.seqstart::text,
      sequence.seqincrement::text,sequence.seqmax::text,
      sequence.seqmin::text,sequence.seqcache::text,
      sequence.seqcycle::text)
  FROM pg_catalog.pg_sequence AS sequence
  JOIN pg_catalog.pg_class AS relation ON relation.oid=sequence.seqrelid
  JOIN pg_catalog.pg_namespace AS namespace
    ON namespace.oid=relation.relnamespace
  WHERE namespace.nspname IN ('public','app')

  UNION ALL
  SELECT 'view',namespace.nspname || '.' || relation.relname,
    pg_catalog.pg_get_viewdef(relation.oid,true)
  FROM pg_catalog.pg_class AS relation
  JOIN pg_catalog.pg_namespace AS namespace
    ON namespace.oid=relation.relnamespace
  WHERE namespace.nspname IN ('public','app')
    AND relation.relkind IN ('v','m')

  UNION ALL
  SELECT 'publication',publication.pubname,
    pg_catalog.concat_ws('|',owner.rolname,publication.puballtables::text,
      publication.pubinsert::text,publication.pubupdate::text,
      publication.pubdelete::text,publication.pubtruncate::text,
      publication.pubviaroot::text,publication.pubgencols::text)
  FROM pg_catalog.pg_publication AS publication
  JOIN pg_catalog.pg_roles AS owner ON owner.oid=publication.pubowner
  WHERE publication.puballtables
     OR EXISTS (
       SELECT 1
       FROM pg_catalog.pg_publication_namespace AS publication_namespace
       JOIN pg_catalog.pg_namespace AS namespace
         ON namespace.oid=publication_namespace.pnnspid
       WHERE publication_namespace.pnpubid=publication.oid
         AND namespace.nspname IN ('public','app')
     )
     OR EXISTS (
       SELECT 1
       FROM pg_catalog.pg_publication_rel AS publication_relation
       JOIN pg_catalog.pg_class AS relation
         ON relation.oid=publication_relation.prrelid
       JOIN pg_catalog.pg_namespace AS namespace
         ON namespace.oid=relation.relnamespace
       WHERE publication_relation.prpubid=publication.oid
         AND namespace.nspname IN ('public','app')
     )

  UNION ALL
  SELECT 'publication_namespace',
    publication.pubname || '->' || namespace.nspname,
    pg_catalog.concat_ws('|',publication.puballtables::text,
      publication.pubinsert::text,publication.pubupdate::text,
      publication.pubdelete::text,publication.pubtruncate::text,
      publication.pubviaroot::text,publication.pubgencols::text)
  FROM pg_catalog.pg_publication_namespace AS publication_namespace
  JOIN pg_catalog.pg_publication AS publication
    ON publication.oid=publication_namespace.pnpubid
  JOIN pg_catalog.pg_namespace AS namespace
    ON namespace.oid=publication_namespace.pnnspid
  WHERE namespace.nspname IN ('public','app')

  UNION ALL
  SELECT 'publication_relation',
    publication.pubname || '->' || namespace.nspname || '.' ||
      relation.relname,
    pg_catalog.concat_ws('|',
      CASE WHEN publication_relation.prattrs IS NULL THEN '<all>' ELSE
        coalesce((
          SELECT string_agg(attribute.attname,','
            ORDER BY selected.ordinality)
          FROM pg_catalog.unnest(
            publication_relation.prattrs::smallint[]
          ) WITH ORDINALITY AS selected(attnum,ordinality)
          JOIN pg_catalog.pg_attribute AS attribute
            ON attribute.attrelid=publication_relation.prrelid
           AND attribute.attnum=selected.attnum
        ),'<empty>') END,
      coalesce(pg_catalog.pg_get_expr(
        publication_relation.prqual,publication_relation.prrelid,true
      ),''))
  FROM pg_catalog.pg_publication_rel AS publication_relation
  JOIN pg_catalog.pg_publication AS publication
    ON publication.oid=publication_relation.prpubid
  JOIN pg_catalog.pg_class AS relation
    ON relation.oid=publication_relation.prrelid
  JOIN pg_catalog.pg_namespace AS namespace
    ON namespace.oid=relation.relnamespace
  WHERE namespace.nspname IN ('public','app')

  UNION ALL
  SELECT 'subscription',subscription.subname,
    pg_catalog.concat_ws('|',owner.rolname,
      subscription.subenabled::text,subscription.subbinary::text,
      subscription.substream::text,subscription.subtwophasestate::text,
      subscription.subdisableonerr::text,
      subscription.subpasswordrequired::text,
      subscription.subrunasowner::text,subscription.subfailover::text,
      subscription.subskiplsn::text,coalesce(subscription.subslotname,''),
      subscription.subsynccommit,
      pg_catalog.array_to_string(ARRAY(
        SELECT publication_name
        FROM pg_catalog.unnest(
          subscription.subpublications
        ) AS configured(publication_name)
        ORDER BY publication_name COLLATE "C"
      ),','),subscription.suborigin)
  FROM pg_catalog.pg_subscription AS subscription
  JOIN pg_catalog.pg_roles AS owner ON owner.oid=subscription.subowner
  JOIN pg_catalog.pg_database AS database
    ON database.oid=subscription.subdbid
  WHERE database.datname=pg_catalog.current_database()

  UNION ALL
  SELECT 'function',namespace.nspname || '.' || function_row.proname || '(' ||
         pg_catalog.pg_get_function_identity_arguments(function_row.oid) || ')',
    pg_catalog.concat_ws('|',
      CASE WHEN sealer.function_oid IS NOT NULL
        THEN '<V49-SEALER-SUPERUSER>' ELSE owner.rolname END,
      language.lanname,
      function_row.prokind::text,function_row.provolatile::text,
      function_row.prosecdef::text,function_row.proisstrict::text,
      function_row.proleakproof::text,function_row.proparallel::text,
      function_row.pronargs::text,function_row.pronargdefaults::text,
      CASE WHEN function_row.provariadic=0 THEN ''
        ELSE pg_catalog.format_type(function_row.provariadic,NULL) END,
      function_row.procost::text,
      function_row.prorows::text,function_row.proretset::text,
      pg_catalog.pg_get_function_arguments(function_row.oid),
      pg_catalog.pg_get_function_result(function_row.oid),
      CASE WHEN function_row.prosupport=0 THEN '' ELSE (
        SELECT support_namespace.nspname || '.' || support.proname || '(' ||
               pg_catalog.pg_get_function_identity_arguments(support.oid) || ')'
        FROM pg_catalog.pg_proc AS support
        JOIN pg_catalog.pg_namespace AS support_namespace
          ON support_namespace.oid=support.pronamespace
        WHERE support.oid=function_row.prosupport
      ) END,
      coalesce((
        SELECT string_agg(
          pg_catalog.format_type(transform.type_oid,NULL),','
          ORDER BY transform.ordinality
        )
        FROM pg_catalog.unnest(function_row.protrftypes)
          WITH ORDINALITY AS transform(type_oid,ordinality)
      ),''),
      CASE WHEN historical_source.function_oid IS NOT NULL
        AND pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
          function_row.prosrc,'UTF8'
        )),'hex')=ANY(historical_source.source_hashes)
        THEN '<V49-HISTORICAL-NORMALIZED>' ELSE function_row.prosrc END,
      coalesce(function_row.probin,''),
      CASE WHEN function_row.prosqlbody IS NULL THEN ''
        ELSE pg_catalog.pg_get_functiondef(function_row.oid) END,
      CASE WHEN rotated_config.function_oid IS NOT NULL
        AND pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
          coalesce(function_row.proconfig::text,''),'UTF8'
        )),'hex')=ANY(rotated_config.config_hashes)
        THEN '<V49-ROTATED>' ELSE coalesce(function_row.proconfig::text,'') END,
      CASE WHEN rotated_acl.function_oid IS NOT NULL
        AND pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
          function_acl.payload,'UTF8'
        )),'hex')=ANY(rotated_acl.acl_hashes)
        THEN '<V49-ROTATED>' ELSE function_acl.payload END)
  FROM pg_catalog.pg_proc AS function_row
  JOIN pg_catalog.pg_namespace AS namespace
    ON namespace.oid=function_row.pronamespace
  JOIN pg_catalog.pg_roles AS owner ON owner.oid=function_row.proowner
  JOIN pg_catalog.pg_language AS language ON language.oid=function_row.prolang
  LEFT JOIN sealer_function AS sealer
    ON sealer.function_oid=function_row.oid
  LEFT JOIN LATERAL (
    SELECT coalesce(string_agg(
      normalized.grantor_name || '>' || normalized.grantee_name || ':' ||
      normalized.privilege_type || ':' || normalized.is_grantable::text,
      ',' ORDER BY normalized.grantor_name COLLATE "C",
      normalized.grantee_name COLLATE "C",
      normalized.privilege_type COLLATE "C",normalized.is_grantable
    ),'<empty>') AS payload
    FROM (
      SELECT CASE
          WHEN sealer.function_oid IS NOT NULL
           AND acl.grantor=sealer.sealer_role_oid
            THEN '<V49-SEALER-SUPERUSER>'
          ELSE coalesce(grantor.rolname,'PUBLIC')
        END AS grantor_name,
        CASE
          WHEN sealer.function_oid IS NOT NULL
           AND acl.grantee=sealer.sealer_role_oid
            THEN '<V49-SEALER-SUPERUSER>'
          ELSE coalesce(grantee.rolname,'PUBLIC')
        END AS grantee_name,
        acl.privilege_type,acl.is_grantable
      FROM pg_catalog.aclexplode(coalesce(
        function_row.proacl,
        pg_catalog.acldefault('f',function_row.proowner)
      )) AS acl
      LEFT JOIN pg_catalog.pg_roles AS grantor ON grantor.oid=acl.grantor
      LEFT JOIN pg_catalog.pg_roles AS grantee ON grantee.oid=acl.grantee
    ) AS normalized
  ) AS function_acl ON true
  LEFT JOIN rotated_acl_function AS rotated_acl ON rotated_acl.function_oid=function_row.oid
  LEFT JOIN historical_source_function AS historical_source ON historical_source.function_oid=function_row.oid
  LEFT JOIN rotated_config_function AS rotated_config ON rotated_config.function_oid=function_row.oid
  LEFT JOIN self_excluded_function AS self_excluded ON self_excluded.function_oid=function_row.oid
  WHERE namespace.nspname IN ('public','app')
    AND self_excluded.function_oid IS NULL

  UNION ALL
  SELECT 'role',role.rolname,
    pg_catalog.concat_ws('|',role.rolsuper::text,role.rolinherit::text,
      role.rolcreaterole::text,role.rolcreatedb::text,role.rolcanlogin::text,
      role.rolreplication::text,role.rolbypassrls::text,
      role.rolconnlimit::text,coalesce(role.rolconfig::text,''),
      coalesce(credential.credential_state,'credential-state:missing'),
      CASE
        WHEN role.rolvaliduntil IS NULL THEN '<NULL>'
        WHEN role.rolvaliduntil='infinity'::timestamptz THEN 'infinity'
        WHEN role.rolvaliduntil='-infinity'::timestamptz THEN '-infinity'
        ELSE pg_catalog.to_char(
          role.rolvaliduntil AT TIME ZONE 'UTC',
          'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'
        )
      END)
  FROM pg_catalog.pg_roles AS role
  LEFT JOIN runtime_login_credential AS credential
    ON credential.role_name=role.rolname
  WHERE role.rolname LIKE 'periapsis\_%' ESCAPE '\'
    AND NOT EXISTS (
      SELECT 1 FROM sealer_function AS sealer_role
      WHERE sealer_role.sealer_role_oid=role.oid
    )
    AND NOT EXISTS (
      SELECT 1
      FROM runtime_login AS expected
      WHERE expected.role_name=role.rolname
        AND NOT role.rolsuper AND role.rolinherit
        AND NOT role.rolcreaterole AND NOT role.rolcreatedb
        AND NOT role.rolreplication AND NOT role.rolbypassrls
        AND role.rolconnlimit=expected.connection_limit
        AND role.rolconfig IS NULL
        AND (
          (NOT role.rolcanlogin
            AND credential.credential_state IN ('absent','scram'))
          OR (role.rolcanlogin AND credential.credential_state='scram')
        )
        AND (role.rolvaliduntil IS NULL
          OR role.rolvaliduntil='infinity'::timestamptz)
    )

  UNION ALL
  SELECT 'membership',granted.rolname || '->' || member.rolname,
    pg_catalog.concat_ws('|',grantor.rolname,membership.admin_option::text,
      membership.inherit_option::text,membership.set_option::text)
  FROM pg_catalog.pg_auth_members AS membership
  JOIN pg_catalog.pg_roles AS granted ON granted.oid=membership.roleid
  JOIN pg_catalog.pg_roles AS member ON member.oid=membership.member
  JOIN pg_catalog.pg_roles AS grantor ON grantor.oid=membership.grantor
  WHERE (granted.rolname LIKE 'periapsis\_%' ESCAPE '\'
     OR member.rolname LIKE 'periapsis\_%' ESCAPE '\')
    AND NOT EXISTS (
      SELECT 1
      FROM runtime_login AS expected
      WHERE expected.group_role_name=granted.rolname
        AND expected.role_name=member.rolname
        AND NOT membership.admin_option
        AND membership.inherit_option
        AND membership.set_option
        AND 1=(
          SELECT count(*)
          FROM pg_catalog.pg_auth_members AS candidate
          WHERE candidate.roleid=membership.roleid
            AND candidate.member=membership.member
        )
    )

  UNION ALL
  SELECT 'runtime_login_missing_membership',expected.role_name,
    expected.group_role_name
  FROM runtime_login AS expected
  JOIN pg_catalog.pg_roles AS login_role
    ON login_role.rolname=expected.role_name
  WHERE NOT EXISTS (
    SELECT 1
    FROM pg_catalog.pg_auth_members AS membership
    JOIN pg_catalog.pg_roles AS granted
      ON granted.oid=membership.roleid
    WHERE membership.member=login_role.oid
      AND granted.rolname=expected.group_role_name
      AND NOT membership.admin_option
      AND membership.inherit_option
      AND membership.set_option
      AND 1=(
        SELECT count(*)
        FROM pg_catalog.pg_auth_members AS candidate
        WHERE candidate.roleid=membership.roleid
          AND candidate.member=membership.member
      )
  )

  UNION ALL
  SELECT 'role_setting',role.rolname || ':' ||
         CASE WHEN setting.setdatabase=0 THEN '*'
              ELSE 'current' END,
    pg_catalog.array_to_string(ARRAY(
      SELECT value
      FROM pg_catalog.unnest(setting.setconfig) AS configured(value)
      ORDER BY value COLLATE "C"
    ),E'\x1f')
  FROM pg_catalog.pg_db_role_setting AS setting
  JOIN pg_catalog.pg_roles AS role ON role.oid=setting.setrole
  LEFT JOIN pg_catalog.pg_database AS database
    ON database.oid=setting.setdatabase
  WHERE role.rolname LIKE 'periapsis\_%' ESCAPE '\'
    AND (setting.setdatabase=0
      OR database.datname=pg_catalog.current_database())

  UNION ALL
  SELECT 'database_setting',
    CASE WHEN setting.setdatabase=0 THEN '*' ELSE 'current' END,
    pg_catalog.array_to_string(ARRAY(
      SELECT value
      FROM pg_catalog.unnest(setting.setconfig) AS configured(value)
      ORDER BY value COLLATE "C"
    ),E'\x1f')
  FROM pg_catalog.pg_db_role_setting AS setting
  LEFT JOIN pg_catalog.pg_database AS database
    ON database.oid=setting.setdatabase
  WHERE setting.setrole=0
    AND (setting.setdatabase=0
      OR database.datname=pg_catalog.current_database())

  UNION ALL
  SELECT 'runtime_setting',setting.name,setting.value
  FROM (VALUES
    ('row_security',pg_catalog.current_setting('row_security')),
    ('session_replication_role',
      pg_catalog.current_setting('session_replication_role'))
  ) AS setting(name,value)

  UNION ALL
  SELECT 'parameter_acl',parameter.parname,
    coalesce((
      SELECT string_agg(
        CASE WHEN grantor.rolsuper
           AND grantor.rolname NOT LIKE 'periapsis\_%' ESCAPE '\'
          THEN '<PARAMETER-ADMIN-SUPERUSER>'
          ELSE coalesce(grantor.rolname,'PUBLIC') END || '>' ||
        CASE WHEN grantee.rolsuper
           AND grantee.rolname NOT LIKE 'periapsis\_%' ESCAPE '\'
          THEN '<PARAMETER-ADMIN-SUPERUSER>'
          ELSE coalesce(grantee.rolname,'PUBLIC') END || ':' ||
        acl.privilege_type || ':' || acl.is_grantable::text,
        ',' ORDER BY
        CASE WHEN grantor.rolsuper
           AND grantor.rolname NOT LIKE 'periapsis\_%' ESCAPE '\'
          THEN '<PARAMETER-ADMIN-SUPERUSER>'
          ELSE coalesce(grantor.rolname,'PUBLIC') END COLLATE "C",
        CASE WHEN grantee.rolsuper
           AND grantee.rolname NOT LIKE 'periapsis\_%' ESCAPE '\'
          THEN '<PARAMETER-ADMIN-SUPERUSER>'
          ELSE coalesce(grantee.rolname,'PUBLIC') END COLLATE "C",
        acl.privilege_type COLLATE "C",acl.is_grantable
      )
      FROM pg_catalog.aclexplode(parameter.paracl) AS acl
      LEFT JOIN pg_catalog.pg_roles AS grantor ON grantor.oid=acl.grantor
      LEFT JOIN pg_catalog.pg_roles AS grantee ON grantee.oid=acl.grantee
    ),'<empty>')
  FROM pg_catalog.pg_parameter_acl AS parameter
  CROSS JOIN pg_catalog.pg_database AS database
  WHERE database.datname=pg_catalog.current_database()
    AND EXISTS (
      SELECT 1
      FROM pg_catalog.aclexplode(parameter.paracl) AS relevant_acl
      LEFT JOIN pg_catalog.pg_roles AS relevant_grantee
        ON relevant_grantee.oid=relevant_acl.grantee
      WHERE relevant_acl.grantee=0
         OR relevant_grantee.rolname LIKE 'periapsis\_%' ESCAPE '\'
    )

  UNION ALL
  SELECT 'default_acl',owner.rolname || ':' || coalesce(namespace.nspname,'') ||
         ':' || default_acl.defaclobjtype::text,
    coalesce((
      SELECT string_agg(
        coalesce(grantor.rolname,'PUBLIC') || '>' ||
        coalesce(grantee.rolname,'PUBLIC') || ':' || acl.privilege_type ||
        ':' || acl.is_grantable::text,
        ',' ORDER BY coalesce(grantor.rolname,'PUBLIC') COLLATE "C",
        coalesce(grantee.rolname,'PUBLIC') COLLATE "C",
        acl.privilege_type COLLATE "C",acl.is_grantable
      )
      FROM pg_catalog.aclexplode(default_acl.defaclacl) AS acl
      LEFT JOIN pg_catalog.pg_roles AS grantor ON grantor.oid=acl.grantor
      LEFT JOIN pg_catalog.pg_roles AS grantee ON grantee.oid=acl.grantee
    ),'<empty>')
  FROM pg_catalog.pg_default_acl AS default_acl
  JOIN pg_catalog.pg_roles AS owner ON owner.oid=default_acl.defaclrole
  LEFT JOIN pg_catalog.pg_namespace AS namespace
    ON namespace.oid=default_acl.defaclnamespace
  WHERE owner.rolname LIKE 'periapsis\_%' ESCAPE '\'
     OR EXISTS (
       SELECT 1
       FROM pg_catalog.aclexplode(default_acl.defaclacl) AS relevant_acl
       LEFT JOIN pg_catalog.pg_roles AS relevant_grantor
         ON relevant_grantor.oid=relevant_acl.grantor
       LEFT JOIN pg_catalog.pg_roles AS relevant_grantee
         ON relevant_grantee.oid=relevant_acl.grantee
       WHERE relevant_acl.grantee=0
          OR relevant_grantor.rolname LIKE 'periapsis\_%' ESCAPE '\'
          OR relevant_grantee.rolname LIKE 'periapsis\_%' ESCAPE '\'
     )
)
SELECT pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
  string_agg(
    kind || E'\x1f' || key || E'\x1f' || pg_catalog.encode(
      pg_catalog.sha256(pg_catalog.convert_to(payload,'UTF8')),'hex'
    ),E'\n' ORDER BY kind COLLATE "C",key COLLATE "C",
      pg_catalog.encode(pg_catalog.sha256(
        pg_catalog.convert_to(payload,'UTF8')
      ),'hex') COLLATE "C"
  ),'UTF8'
)),'hex')
FROM catalog_entry;
$function$;
ALTER FUNCTION app.private_release_runtime_dependency_surface_hash_v59()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION
  app.private_release_runtime_dependency_surface_hash_v59()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
       periapsis_auditor;
--> statement-breakpoint

CREATE FUNCTION app.private_release_runtime_schema_readiness_v59()
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app AS $function$
DECLARE
  expected_relation_count integer;
  ready_relation_count integer;
  expected_trigger_count integer;
  ready_trigger_count integer;
BEGIN
  IF current_setting('server_version_num')::integer<180000
     OR current_setting('server_version_num')::integer>=190000
     OR current_setting('session_replication_role')<>'origin'
     OR current_setting('row_security')<>'on'
     OR NOT app.private_v47_migration_convergence_schema_readiness_v1()
     OR NOT app.alert_dfir_runtime_schema_readiness_v2()
     OR app.private_release_runtime_dependency_surface_hash_v59()<>
    '64b59fc9bd5e185ae5eaca66ac66fa16dd82f0db1bdcec025b43f30d98e34d20' THEN
    RETURN false;
  END IF;

  WITH expected(name,owner_name) AS (
    VALUES
      ('tenant_ldap_jit_authority_issuance_receipts','periapsis_migrator'),
      ('tenant_mfa_ldap_recovery_replacement_capabilities','periapsis_migrator'),
      ('platform_ldap_authentication_runs','periapsis_migrator'),
      ('platform_ldap_bind_secrets','periapsis_migrator'),
      ('platform_ldap_external_identities','periapsis_migrator'),
      ('platform_ldap_external_identity_aliases','periapsis_migrator'),
      ('platform_ldap_mapping_rules','periapsis_migrator'),
      ('platform_ldap_provider_configurations','periapsis_migrator'),
      ('platform_ldap_provider_endpoints','periapsis_migrator'),
      ('platform_ldap_role_grants','periapsis_migrator'),
      ('platform_ldap_session_provenance','periapsis_migrator'),
      ('platform_ldap_test_runs','periapsis_migrator'),
      ('tenant_membership_lifecycle_commands','periapsis_migrator'),
      ('platform_user_authorization_epochs','periapsis_audit_operations_owner'),
      ('tenant_audit_export_jobs','periapsis_audit_operations_owner'),
      ('tenant_audit_operation_receipts','periapsis_audit_operations_owner'),
      ('tenant_audit_export_manifests','periapsis_audit_operations_owner'),
      ('platform_audit_export_jobs','periapsis_audit_operations_owner'),
      ('platform_audit_operation_receipts','periapsis_audit_operations_owner'),
      ('platform_audit_export_manifests','periapsis_audit_operations_owner'),
      ('tenant_audit_retention_policies','periapsis_audit_operations_owner'),
      ('platform_audit_retention_policy','periapsis_audit_operations_owner'),
      ('tenant_audit_legal_holds','periapsis_audit_operations_owner'),
      ('platform_audit_legal_holds','periapsis_audit_operations_owner'),
      ('tenant_audit_segments','periapsis_audit_operations_owner'),
      ('platform_audit_segments','periapsis_audit_operations_owner'),
      ('tenant_audit_retention_anchors','periapsis_audit_operations_owner'),
      ('platform_audit_retention_anchor','periapsis_audit_operations_owner'),
      ('tenant_audit_retention_prune_capabilities','periapsis_audit_operations_owner'),
      ('tenant_settings','periapsis_tenant_settings_owner'),
      ('platform_global_settings','periapsis_platform_operations_owner'),
      ('platform_feature_flags','periapsis_platform_operations_owner'),
      ('alert_case_link_retractions','periapsis_migrator')
  )
  SELECT (SELECT count(*) FROM expected),count(*)
    INTO expected_relation_count,ready_relation_count
  FROM expected
  JOIN pg_catalog.pg_class AS relation ON relation.relname=expected.name
  JOIN pg_catalog.pg_namespace AS namespace
    ON namespace.oid=relation.relnamespace AND namespace.nspname='public'
  JOIN pg_catalog.pg_roles AS owner
    ON owner.oid=relation.relowner AND owner.rolname=expected.owner_name
  WHERE relation.relkind='r' AND relation.relrowsecurity
    AND relation.relforcerowsecurity;
  IF ready_relation_count<>expected_relation_count THEN RETURN false; END IF;

  WITH expected(name) AS (
    VALUES
      ('ticket_comments_consistency_v1'),
      ('ticket_comment_revisions_consistency_v1'),
      ('ticket_comment_author_snapshots_consistency_v1'),
      ('ticket_comment_escalation_sources_consistency_v1'),
      ('ticket_comment_revision_attachments_consistency_v1'),
      ('ticket_comment_revision_mentions_consistency_v1'),
      ('tenant_ldap_jit_authority_issuance_receipts_immutable_v1'),
      ('auth_session_ldap_provenance_immutable_v1'),
      ('tenant_post_primary_ldap_provenance_immutable_v1'),
      ('platform_ldap_bind_secrets_guard'),
      ('platform_ldap_external_identity_aliases_guard'),
      ('platform_ldap_role_grants_guard'),
      ('platform_ldap_authentication_runs_guard'),
      ('platform_ldap_session_provenance_guard'),
      ('platform_ldap_test_runs_guard'),
      ('tenant_memberships_lifecycle_revision_v1'),
      ('auth_sessions_tenant_membership_fence_v1'),
      ('tenant_post_primary_membership_fence_v1'),
      ('tenant_membership_lifecycle_commands_guard_v1'),
      ('user_platform_roles_audit_epoch_v1'),
      ('platform_role_permissions_audit_epoch_v1'),
      ('tenants_seed_settings_v1'),
      ('audit_events_platform_access_attribution_before_insert'),
      ('alert_case_link_retractions_immutable_v1'),
      ('alert_case_links_immutable_v2')
  )
  SELECT (SELECT count(*) FROM expected),count(*)
    INTO expected_trigger_count,ready_trigger_count
  FROM expected
  JOIN pg_catalog.pg_trigger AS trigger_row
    ON trigger_row.tgname=expected.name
  JOIN pg_catalog.pg_class AS relation ON relation.oid=trigger_row.tgrelid
  JOIN pg_catalog.pg_namespace AS namespace
    ON namespace.oid=relation.relnamespace AND namespace.nspname='public'
  WHERE NOT trigger_row.tgisinternal AND trigger_row.tgenabled='O';
  IF ready_trigger_count<>expected_trigger_count THEN RETURN false; END IF;

  RETURN true;
EXCEPTION WHEN undefined_table OR undefined_function OR insufficient_privilege
  OR invalid_schema_name OR cardinality_violation OR data_exception THEN
  RETURN false;
END;
$function$;
ALTER FUNCTION app.private_release_runtime_schema_readiness_v59()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_release_runtime_schema_readiness_v59()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
       periapsis_auditor;
--> statement-breakpoint

CREATE FUNCTION app.release_runtime_schema_readiness_v59()
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app AS $function$
DECLARE current_count bigint;
BEGIN
  SELECT compatibility.applied_count INTO current_count
  FROM app.schema_compatibility_v59() AS compatibility;
  RETURN current_count=250
    AND app.private_release_runtime_schema_readiness_v59()
    AND (
      WITH predecessor(function_oid) AS (
        VALUES
          ('app.schema_compatibility_v44()'::regprocedure),
          ('app.schema_compatibility_v45()'::regprocedure),
          ('app.schema_compatibility_v46()'::regprocedure),
          ('app.schema_compatibility_v47()'::regprocedure),
          ('app.schema_compatibility_v48()'::regprocedure),
          ('app.schema_compatibility_v49()'::regprocedure),
          ('app.schema_compatibility_v50()'::regprocedure),
          ('app.schema_compatibility_v51()'::regprocedure),
          ('app.schema_compatibility_v52()'::regprocedure),
          ('app.schema_compatibility_v53()'::regprocedure),
          ('app.schema_compatibility_v54()'::regprocedure),
          ('app.schema_compatibility_v55()'::regprocedure),
          ('app.schema_compatibility_v56()'::regprocedure),
          ('app.schema_compatibility_v57()'::regprocedure),
          ('app.schema_compatibility_v58()'::regprocedure)
      )
      SELECT count(*)=15 AND coalesce(bool_and(
        owner.rolname='periapsis_migrator'
        AND function_row.proconfig IS NOT DISTINCT FROM ARRAY[
          'search_path=pg_catalog',
          'app.schema_compatibility_fingerprint=RETIRED'
        ]::text[]
        AND (
          SELECT count(*)=1 AND coalesce(bool_and(
            acl.grantor=function_row.proowner
            AND acl.grantee=function_row.proowner
            AND acl.privilege_type='EXECUTE' AND NOT acl.is_grantable
          ),false)
          FROM pg_catalog.aclexplode(coalesce(
            function_row.proacl,
            pg_catalog.acldefault('f',function_row.proowner)
          )) AS acl
        )
      ),false)
      FROM predecessor
      JOIN pg_catalog.pg_proc AS function_row
        ON function_row.oid=predecessor.function_oid
      JOIN pg_catalog.pg_roles AS owner ON owner.oid=function_row.proowner
    )
    AND NOT EXISTS (
      WITH retired(function_oid) AS (
        VALUES
          ('app.schema_compatibility_v44()'::regprocedure),
          ('app.schema_compatibility_v45()'::regprocedure),
          ('app.schema_compatibility_v46()'::regprocedure),
          ('app.schema_compatibility_v47()'::regprocedure),
          ('app.mfa_policy_administration_schema_readiness_v4()'::regprocedure),
          ('app.mfa_policy_administration_schema_readiness_v6()'::regprocedure),
          ('app.platform_identity_runtime_schema_readiness_v10()'::regprocedure),
          ('app.platform_identity_runtime_schema_readiness_v12()'::regprocedure),
          ('app.platform_oidc_direct_runtime_schema_readiness_v6()'::regprocedure),
          ('app.platform_oidc_direct_runtime_schema_readiness_v8()'::regprocedure),
          ('app.platform_saml_direct_runtime_schema_readiness_v3()'::regprocedure),
          ('app.platform_saml_direct_runtime_schema_readiness_v5()'::regprocedure),
          ('app.platform_tenant_lifecycle_schema_readiness_v1()'::regprocedure),
          ('app.platform_identity_runtime_schema_readiness_v13()'::regprocedure),
          ('app.platform_oidc_direct_runtime_schema_readiness_v9()'::regprocedure),
          ('app.platform_saml_direct_runtime_schema_readiness_v6()'::regprocedure),
          ('app.mfa_policy_administration_schema_readiness_v7()'::regprocedure),
          ('app.ticket_mutation_runtime_schema_readiness_v2()'::regprocedure),
          ('app.sla_trigger_action_runtime_schema_readiness_v1()'::regprocedure),
          ('app.sla_object_event_ingress_schema_readiness_v1()'::regprocedure),
          ('app.platform_local_account_runtime_schema_readiness_v1()'::regprocedure),
          ('app.ticket_bulk_runtime_schema_readiness_v2()'::regprocedure),
          ('app.ticket_export_runtime_schema_readiness_v2()'::regprocedure),
          ('app.alert_dfir_runtime_schema_readiness_v1()'::regprocedure),
          ('app.ticket_metadata_runtime_schema_readiness_v1()'::regprocedure),
          ('app.notification_dispatch_readiness_v4()'::regprocedure),
          ('app.ticket_watcher_runtime_schema_readiness_v2()'::regprocedure),
          ('app.contacts_portal_schema_readiness_v2()'::regprocedure),
          ('app.notification_schema_readiness_v4()'::regprocedure),
          ('app.tenant_ldap_interactive_auth_schema_readiness_v1()'::regprocedure),
          ('app.ticket_comment_runtime_repair_schema_readiness_v1()'::regprocedure),
          ('app.platform_global_ldap_runtime_schema_readiness_v1()'::regprocedure),
          ('app.federated_authentication_schema_readiness_v1()'::regprocedure),
          ('app.platform_oidc_direct_runtime_schema_readiness_v1()'::regprocedure),
          ('app.platform_saml_direct_runtime_schema_readiness_v2()'::regprocedure),
          ('app.schema_compatibility_v48()'::regprocedure),
          ('app.release_runtime_schema_readiness_v48()'::regprocedure),
          ('app.federated_authentication_schema_readiness_v48()'::regprocedure),
          ('app.platform_oidc_direct_runtime_schema_readiness_v48()'::regprocedure),
          ('app.platform_saml_direct_runtime_schema_readiness_v48()'::regprocedure),
          ('app.platform_local_account_runtime_schema_readiness_v48()'::regprocedure),
          ('app.sla_trigger_action_runtime_schema_readiness_v48()'::regprocedure),
          ('app.sla_object_event_ingress_schema_readiness_v48()'::regprocedure),
          ('app.ticket_bulk_runtime_schema_readiness_v48()'::regprocedure),
          ('app.ticket_export_runtime_schema_readiness_v48()'::regprocedure),
          ('app.ticket_metadata_runtime_schema_readiness_v48()'::regprocedure),
          ('app.schema_compatibility_v49()'::regprocedure),
          ('app.release_runtime_schema_readiness_v49()'::regprocedure),
          ('app.federated_authentication_schema_readiness_v49()'::regprocedure),
          ('app.platform_oidc_direct_runtime_schema_readiness_v49()'::regprocedure),
          ('app.platform_saml_direct_runtime_schema_readiness_v49()'::regprocedure),
          ('app.platform_local_account_runtime_schema_readiness_v49()'::regprocedure),
          ('app.sla_trigger_action_runtime_schema_readiness_v49()'::regprocedure),
          ('app.sla_object_event_ingress_schema_readiness_v49()'::regprocedure),
          ('app.ticket_bulk_runtime_schema_readiness_v49()'::regprocedure),
          ('app.ticket_export_runtime_schema_readiness_v49()'::regprocedure),
          ('app.ticket_metadata_runtime_schema_readiness_v49()'::regprocedure),
          ('app.notification_dispatch_readiness_v49()'::regprocedure),
          ('app.schema_compatibility_v50()'::regprocedure),
          ('app.release_runtime_schema_readiness_v50()'::regprocedure),
          ('app.federated_authentication_schema_readiness_v50()'::regprocedure),
          ('app.platform_oidc_direct_runtime_schema_readiness_v50()'::regprocedure),
          ('app.platform_saml_direct_runtime_schema_readiness_v50()'::regprocedure),
          ('app.platform_local_account_runtime_schema_readiness_v50()'::regprocedure),
          ('app.sla_trigger_action_runtime_schema_readiness_v50()'::regprocedure),
          ('app.sla_object_event_ingress_schema_readiness_v50()'::regprocedure),
          ('app.ticket_bulk_runtime_schema_readiness_v50()'::regprocedure),
          ('app.ticket_export_runtime_schema_readiness_v50()'::regprocedure),
          ('app.ticket_metadata_runtime_schema_readiness_v50()'::regprocedure),
          ('app.notification_dispatch_readiness_v50()'::regprocedure),
          ('app.schema_compatibility_v51()'::regprocedure),
          ('app.release_runtime_schema_readiness_v51()'::regprocedure),
          ('app.federated_authentication_schema_readiness_v51()'::regprocedure),
          ('app.platform_oidc_direct_runtime_schema_readiness_v51()'::regprocedure),
          ('app.platform_saml_direct_runtime_schema_readiness_v51()'::regprocedure),
          ('app.platform_local_account_runtime_schema_readiness_v51()'::regprocedure),
          ('app.sla_trigger_action_runtime_schema_readiness_v51()'::regprocedure),
          ('app.sla_object_event_ingress_schema_readiness_v51()'::regprocedure),
          ('app.ticket_bulk_runtime_schema_readiness_v51()'::regprocedure),
          ('app.ticket_export_runtime_schema_readiness_v51()'::regprocedure),
          ('app.ticket_metadata_runtime_schema_readiness_v51()'::regprocedure),
          ('app.notification_dispatch_readiness_v51()'::regprocedure),
          ('app.schema_compatibility_v52()'::regprocedure),
          ('app.release_runtime_schema_readiness_v52()'::regprocedure),
          ('app.federated_authentication_schema_readiness_v52()'::regprocedure),
          ('app.platform_oidc_direct_runtime_schema_readiness_v52()'::regprocedure),
          ('app.platform_saml_direct_runtime_schema_readiness_v52()'::regprocedure),
          ('app.platform_local_account_runtime_schema_readiness_v52()'::regprocedure),
          ('app.sla_trigger_action_runtime_schema_readiness_v52()'::regprocedure),
          ('app.sla_object_event_ingress_schema_readiness_v52()'::regprocedure),
          ('app.ticket_bulk_runtime_schema_readiness_v52()'::regprocedure),
          ('app.ticket_export_runtime_schema_readiness_v52()'::regprocedure),
          ('app.ticket_metadata_runtime_schema_readiness_v52()'::regprocedure),
          ('app.notification_dispatch_readiness_v52()'::regprocedure),
          ('app.api_runtime_schema_readiness_v52()'::regprocedure),
          ('app.worker_runtime_schema_readiness_v52()'::regprocedure),
          ('app.schema_compatibility_v53()'::regprocedure),
          ('app.release_runtime_schema_readiness_v53()'::regprocedure),
          ('app.federated_authentication_schema_readiness_v53()'::regprocedure),
          ('app.platform_oidc_direct_runtime_schema_readiness_v53()'::regprocedure),
          ('app.platform_saml_direct_runtime_schema_readiness_v53()'::regprocedure),
          ('app.platform_local_account_runtime_schema_readiness_v53()'::regprocedure),
          ('app.sla_trigger_action_runtime_schema_readiness_v53()'::regprocedure),
          ('app.sla_object_event_ingress_schema_readiness_v53()'::regprocedure),
          ('app.ticket_bulk_runtime_schema_readiness_v53()'::regprocedure),
          ('app.ticket_export_runtime_schema_readiness_v53()'::regprocedure),
          ('app.ticket_metadata_runtime_schema_readiness_v53()'::regprocedure),
          ('app.notification_dispatch_readiness_v53()'::regprocedure),
          ('app.api_runtime_schema_readiness_v53()'::regprocedure),
          ('app.worker_runtime_schema_readiness_v53()'::regprocedure),
          ('app.schema_compatibility_v54()'::regprocedure),
          ('app.release_runtime_schema_readiness_v54()'::regprocedure),
          ('app.federated_authentication_schema_readiness_v54()'::regprocedure),
          ('app.platform_oidc_direct_runtime_schema_readiness_v54()'::regprocedure),
          ('app.platform_saml_direct_runtime_schema_readiness_v54()'::regprocedure),
          ('app.platform_local_account_runtime_schema_readiness_v54()'::regprocedure),
          ('app.sla_trigger_action_runtime_schema_readiness_v54()'::regprocedure),
          ('app.sla_object_event_ingress_schema_readiness_v54()'::regprocedure),
          ('app.ticket_bulk_runtime_schema_readiness_v54()'::regprocedure),
          ('app.ticket_export_runtime_schema_readiness_v54()'::regprocedure),
          ('app.ticket_metadata_runtime_schema_readiness_v54()'::regprocedure),
          ('app.notification_dispatch_readiness_v54()'::regprocedure),
          ('app.api_runtime_schema_readiness_v54()'::regprocedure),
          ('app.worker_runtime_schema_readiness_v54()'::regprocedure),
          ('app.schema_compatibility_v55()'::regprocedure),
          ('app.release_runtime_schema_readiness_v55()'::regprocedure),
          ('app.federated_authentication_schema_readiness_v55()'::regprocedure),
          ('app.platform_oidc_direct_runtime_schema_readiness_v55()'::regprocedure),
          ('app.platform_saml_direct_runtime_schema_readiness_v55()'::regprocedure),
          ('app.platform_local_account_runtime_schema_readiness_v55()'::regprocedure),
          ('app.sla_trigger_action_runtime_schema_readiness_v55()'::regprocedure),
          ('app.sla_object_event_ingress_schema_readiness_v55()'::regprocedure),
          ('app.ticket_bulk_runtime_schema_readiness_v55()'::regprocedure),
          ('app.ticket_export_runtime_schema_readiness_v55()'::regprocedure),
          ('app.ticket_metadata_runtime_schema_readiness_v55()'::regprocedure),
          ('app.notification_dispatch_readiness_v55()'::regprocedure),
          ('app.api_runtime_schema_readiness_v55()'::regprocedure),
          ('app.worker_runtime_schema_readiness_v55()'::regprocedure),
          ('app.schema_compatibility_v56()'::regprocedure),
          ('app.release_runtime_schema_readiness_v56()'::regprocedure),
          ('app.federated_authentication_schema_readiness_v56()'::regprocedure),
          ('app.platform_oidc_direct_runtime_schema_readiness_v56()'::regprocedure),
          ('app.platform_saml_direct_runtime_schema_readiness_v56()'::regprocedure),
          ('app.platform_local_account_runtime_schema_readiness_v56()'::regprocedure),
          ('app.sla_trigger_action_runtime_schema_readiness_v56()'::regprocedure),
          ('app.sla_object_event_ingress_schema_readiness_v56()'::regprocedure),
          ('app.ticket_bulk_runtime_schema_readiness_v56()'::regprocedure),
          ('app.ticket_export_runtime_schema_readiness_v56()'::regprocedure),
          ('app.ticket_metadata_runtime_schema_readiness_v56()'::regprocedure),
          ('app.notification_dispatch_readiness_v56()'::regprocedure),
          ('app.api_runtime_schema_readiness_v56()'::regprocedure),
          ('app.worker_runtime_schema_readiness_v56()'::regprocedure),
          ('app.schema_compatibility_v57()'::regprocedure),
          ('app.release_runtime_schema_readiness_v57()'::regprocedure),
          ('app.federated_authentication_schema_readiness_v57()'::regprocedure),
          ('app.platform_oidc_direct_runtime_schema_readiness_v57()'::regprocedure),
          ('app.platform_saml_direct_runtime_schema_readiness_v57()'::regprocedure),
          ('app.platform_local_account_runtime_schema_readiness_v57()'::regprocedure),
          ('app.sla_trigger_action_runtime_schema_readiness_v57()'::regprocedure),
          ('app.sla_object_event_ingress_schema_readiness_v57()'::regprocedure),
          ('app.ticket_bulk_runtime_schema_readiness_v57()'::regprocedure),
          ('app.ticket_export_runtime_schema_readiness_v57()'::regprocedure),
          ('app.ticket_metadata_runtime_schema_readiness_v57()'::regprocedure),
          ('app.notification_dispatch_readiness_v57()'::regprocedure),
          ('app.api_runtime_schema_readiness_v57()'::regprocedure),
          ('app.worker_runtime_schema_readiness_v57()'::regprocedure),
          ('app.schema_compatibility_v58()'::regprocedure),
          ('app.release_runtime_schema_readiness_v58()'::regprocedure),
          ('app.federated_authentication_schema_readiness_v58()'::regprocedure),
          ('app.platform_oidc_direct_runtime_schema_readiness_v58()'::regprocedure),
          ('app.platform_saml_direct_runtime_schema_readiness_v58()'::regprocedure),
          ('app.platform_local_account_runtime_schema_readiness_v58()'::regprocedure),
          ('app.sla_trigger_action_runtime_schema_readiness_v58()'::regprocedure),
          ('app.sla_object_event_ingress_schema_readiness_v58()'::regprocedure),
          ('app.ticket_bulk_runtime_schema_readiness_v58()'::regprocedure),
          ('app.ticket_export_runtime_schema_readiness_v58()'::regprocedure),
          ('app.ticket_metadata_runtime_schema_readiness_v58()'::regprocedure),
          ('app.notification_dispatch_readiness_v58()'::regprocedure),
          ('app.api_runtime_schema_readiness_v58()'::regprocedure),
          ('app.worker_runtime_schema_readiness_v58()'::regprocedure)
      )
      SELECT 1
      FROM retired
      JOIN pg_catalog.pg_proc AS function_row
        ON function_row.oid=retired.function_oid
      WHERE EXISTS (
        SELECT 1
        FROM pg_catalog.aclexplode(coalesce(
          function_row.proacl,
          pg_catalog.acldefault('f',function_row.proowner)
        )) AS acl
        WHERE acl.privilege_type='EXECUTE'
          AND acl.grantee<>function_row.proowner
          AND acl.grantee IS DISTINCT FROM (
            SELECT role.oid FROM pg_catalog.pg_roles AS role
            WHERE role.rolname='periapsis_migrator'
          )
          AND (
            retired.function_oid<>
              'app.notification_schema_readiness_v4()'::regprocedure
            OR acl.grantee IS DISTINCT FROM (
              SELECT role.oid FROM pg_catalog.pg_roles AS role
              WHERE role.rolname='periapsis_notification_readiness_owner'
            )
          )
      )
    );
EXCEPTION WHEN undefined_table OR undefined_function OR insufficient_privilege
  OR invalid_schema_name OR cardinality_violation OR data_exception THEN
  RETURN false;
END;
$function$;
ALTER FUNCTION app.release_runtime_schema_readiness_v59()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.release_runtime_schema_readiness_v59()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
       periapsis_auditor;
GRANT EXECUTE ON FUNCTION app.release_runtime_schema_readiness_v59()
  TO periapsis_api,periapsis_worker,
     periapsis_notification_readiness_owner;
--> statement-breakpoint

-- Feature-specific production probes all require the sealed V59 release root.
-- The three historically stale federation probes are intentionally rebuilt
-- from the global exact surface; the other wrappers retain their existing
-- feature/data checks behind the new release gate.
CREATE FUNCTION app.federated_authentication_schema_readiness_v59()
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app AS $function$
BEGIN RETURN app.release_runtime_schema_readiness_v59();
EXCEPTION WHEN undefined_table OR undefined_function OR insufficient_privilege
  OR invalid_schema_name OR cardinality_violation OR data_exception THEN
  RETURN false;
END;
$function$;
CREATE FUNCTION app.platform_oidc_direct_runtime_schema_readiness_v59()
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app AS $function$
BEGIN RETURN app.release_runtime_schema_readiness_v59();
EXCEPTION WHEN undefined_table OR undefined_function OR insufficient_privilege
  OR invalid_schema_name OR cardinality_violation OR data_exception THEN
  RETURN false;
END;
$function$;
CREATE FUNCTION app.platform_saml_direct_runtime_schema_readiness_v59()
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app AS $function$
BEGIN RETURN app.release_runtime_schema_readiness_v59();
EXCEPTION WHEN undefined_table OR undefined_function OR insufficient_privilege
  OR invalid_schema_name OR cardinality_violation OR data_exception THEN
  RETURN false;
END;
$function$;
CREATE FUNCTION app.platform_local_account_runtime_schema_readiness_v59()
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app AS $function$
BEGIN RETURN app.release_runtime_schema_readiness_v59()
  AND app.platform_local_account_runtime_schema_readiness_v1();
EXCEPTION WHEN undefined_table OR undefined_function OR insufficient_privilege
  OR invalid_schema_name OR cardinality_violation OR data_exception THEN
  RETURN false;
END;
$function$;
CREATE FUNCTION app.sla_trigger_action_runtime_schema_readiness_v59()
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app AS $function$
BEGIN RETURN app.release_runtime_schema_readiness_v59()
  AND app.private_sla_system_principal_catalog_ready_v1();
EXCEPTION WHEN undefined_table OR undefined_function OR insufficient_privilege
  OR invalid_schema_name OR cardinality_violation OR data_exception THEN
  RETURN false;
END;
$function$;
CREATE FUNCTION app.sla_object_event_ingress_schema_readiness_v59()
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app AS $function$
BEGIN RETURN app.release_runtime_schema_readiness_v59()
  AND app.sla_object_event_ingress_schema_readiness_v1();
EXCEPTION WHEN undefined_table OR undefined_function OR insufficient_privilege
  OR invalid_schema_name OR cardinality_violation OR data_exception THEN
  RETURN false;
END;
$function$;
CREATE FUNCTION app.ticket_bulk_runtime_schema_readiness_v59()
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app AS $function$
BEGIN RETURN app.release_runtime_schema_readiness_v59()
  AND app.ticket_bulk_runtime_schema_readiness_v2();
EXCEPTION WHEN undefined_table OR undefined_function OR insufficient_privilege
  OR invalid_schema_name OR cardinality_violation OR data_exception THEN
  RETURN false;
END;
$function$;
CREATE FUNCTION app.ticket_export_runtime_schema_readiness_v59()
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app AS $function$
BEGIN RETURN app.release_runtime_schema_readiness_v59()
  AND app.ticket_export_runtime_schema_readiness_v2();
EXCEPTION WHEN undefined_table OR undefined_function OR insufficient_privilege
  OR invalid_schema_name OR cardinality_violation OR data_exception THEN
  RETURN false;
END;
$function$;
CREATE FUNCTION app.ticket_metadata_runtime_schema_readiness_v59()
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app AS $function$
BEGIN RETURN app.release_runtime_schema_readiness_v59()
  AND app.ticket_metadata_runtime_schema_readiness_v1();
EXCEPTION WHEN undefined_table OR undefined_function OR insufficient_privilege
  OR invalid_schema_name OR cardinality_violation OR data_exception THEN
  RETURN false;
END;
$function$;

CREATE FUNCTION app.notification_dispatch_readiness_v59()
RETURNS TABLE(
  queue_depth bigint,
  role_safe boolean,
  schema_safe boolean,
  oldest_pending_seconds bigint
)
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app AS $function$
BEGIN
  SELECT readiness.queue_depth,readiness.role_safe,
         false,readiness.oldest_pending_seconds
  INTO queue_depth,role_safe,schema_safe,oldest_pending_seconds
  FROM app.notification_dispatch_readiness_v4() AS readiness;
  schema_safe := app.release_runtime_schema_readiness_v59();
  RETURN NEXT;
EXCEPTION WHEN undefined_table OR undefined_function OR insufficient_privilege
  OR invalid_schema_name OR cardinality_violation OR data_exception THEN
  queue_depth := 0;
  role_safe := false;
  schema_safe := false;
  oldest_pending_seconds := 0;
  RETURN NEXT;
END;
$function$;

ALTER FUNCTION app.federated_authentication_schema_readiness_v59()
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.platform_oidc_direct_runtime_schema_readiness_v59()
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.platform_saml_direct_runtime_schema_readiness_v59()
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.platform_local_account_runtime_schema_readiness_v59()
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.sla_trigger_action_runtime_schema_readiness_v59()
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.sla_object_event_ingress_schema_readiness_v59()
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.ticket_bulk_runtime_schema_readiness_v59()
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.ticket_export_runtime_schema_readiness_v59()
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.ticket_metadata_runtime_schema_readiness_v59()
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.notification_dispatch_readiness_v59()
  OWNER TO periapsis_notification_readiness_owner;
REVOKE ALL ON FUNCTION
  app.federated_authentication_schema_readiness_v59(),
  app.platform_oidc_direct_runtime_schema_readiness_v59(),
  app.platform_saml_direct_runtime_schema_readiness_v59(),
  app.platform_local_account_runtime_schema_readiness_v59(),
  app.sla_trigger_action_runtime_schema_readiness_v59(),
  app.sla_object_event_ingress_schema_readiness_v59(),
  app.ticket_bulk_runtime_schema_readiness_v59(),
  app.ticket_export_runtime_schema_readiness_v59(),
  app.ticket_metadata_runtime_schema_readiness_v59(),
  app.notification_dispatch_readiness_v59()
FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
  periapsis_auditor,periapsis_notification_admin_owner,
  periapsis_notification_dispatch_owner;
GRANT EXECUTE ON FUNCTION
  app.federated_authentication_schema_readiness_v59(),
  app.platform_oidc_direct_runtime_schema_readiness_v59(),
  app.platform_saml_direct_runtime_schema_readiness_v59(),
  app.platform_local_account_runtime_schema_readiness_v59(),
  app.ticket_metadata_runtime_schema_readiness_v59()
TO periapsis_api;
GRANT EXECUTE ON FUNCTION
  app.ticket_bulk_runtime_schema_readiness_v59(),
  app.ticket_export_runtime_schema_readiness_v59()
TO periapsis_api,periapsis_worker;
GRANT EXECUTE ON FUNCTION
  app.sla_trigger_action_runtime_schema_readiness_v59(),
  app.sla_object_event_ingress_schema_readiness_v59()
TO periapsis_worker;
GRANT EXECUTE ON FUNCTION app.notification_dispatch_readiness_v59()
TO periapsis_migrator,periapsis_notifier;
--> statement-breakpoint

CREATE FUNCTION app.private_rotate_notification_readiness_v59()
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public,app AS $function$
BEGIN
  REVOKE ALL ON FUNCTION app.notification_dispatch_readiness_v4(),
    app.notification_dispatch_readiness_v49(),
    app.notification_dispatch_readiness_v50(),
    app.notification_dispatch_readiness_v51(),
    app.notification_dispatch_readiness_v52(),
    app.notification_dispatch_readiness_v53(),
    app.notification_dispatch_readiness_v54(),
    app.notification_dispatch_readiness_v55(),
    app.notification_dispatch_readiness_v56(),
    app.notification_dispatch_readiness_v57(),
    app.notification_dispatch_readiness_v58()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
    periapsis_auditor,periapsis_notification_admin_owner,
    periapsis_notification_dispatch_owner;
END;
$function$;
ALTER FUNCTION app.private_rotate_notification_readiness_v59()
  OWNER TO periapsis_notification_readiness_owner;
REVOKE ALL ON FUNCTION app.private_rotate_notification_readiness_v59()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
       periapsis_auditor,periapsis_notification_admin_owner,
       periapsis_notification_dispatch_owner;
GRANT EXECUTE ON FUNCTION app.private_rotate_notification_readiness_v59()
  TO periapsis_migrator;
--> statement-breakpoint

-- The generic entry point is source-attested by the migration runner before
-- invocation. It accepts only this exact candidate and is intentionally
-- two-phase: the first call rotates the catalog, while the second call (a new
-- PostgreSQL command boundary) validates every public root. PostgreSQL caches
-- effective routine privileges for the duration of one command, so attempting
-- both phases in one call would observe the pre-REVOKE privilege state.
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
  was_sealed boolean;
BEGIN
  IF p_expected_count IS DISTINCT FROM 250
     OR p_expected_latest_created_at IS DISTINCT FROM 1788875558350
     OR p_expected_latest_hash !~ '^[0-9a-f]{64}$'
     OR p_expected_migration_fingerprint !~
       '^[0-9]+@[0-9a-f]{64}(:[0-9]+@[0-9a-f]{64}){249}$' THEN
    RAISE EXCEPTION 'schema compatibility v59 seal input is invalid'
      USING ERRCODE='55000';
  END IF;
  SELECT journal.applied_count,journal.latest_created_at,journal.latest_rows,
         journal.latest_hash,journal.migration_fingerprint
    INTO journal_count,journal_latest_created_at,journal_latest_rows,
         journal_latest_hash,journal_fingerprint
  FROM app.private_schema_compatibility_journal_v59() AS journal;
  IF ROW(journal_count,journal_latest_created_at,journal_latest_hash,
         journal_fingerprint) IS DISTINCT FROM
     ROW(p_expected_count,p_expected_latest_created_at,p_expected_latest_hash,
         p_expected_migration_fingerprint)
     OR journal_latest_rows<>1
     OR NOT app.private_release_runtime_schema_readiness_v59() THEN
    RAISE EXCEPTION 'schema compatibility v59 pre-seal verification failed'
      USING ERRCODE='55000';
  END IF;

  SELECT coalesce((
    SELECT compatibility.applied_count=250
    FROM app.schema_compatibility_v59() AS compatibility
  ),false) INTO was_sealed;

  IF NOT was_sealed THEN
    EXECUTE pg_catalog.format(
      'ALTER FUNCTION app.schema_compatibility_v59() SET app.schema_compatibility_fingerprint = %L',
      p_expected_migration_fingerprint
    );
    ALTER FUNCTION app.schema_compatibility_v58()
      SET app.schema_compatibility_fingerprint='RETIRED';
    ALTER FUNCTION app.schema_compatibility_v57()
      SET app.schema_compatibility_fingerprint='RETIRED';
    ALTER FUNCTION app.schema_compatibility_v56()
      SET app.schema_compatibility_fingerprint='RETIRED';
    ALTER FUNCTION app.schema_compatibility_v55()
      SET app.schema_compatibility_fingerprint='RETIRED';
    ALTER FUNCTION app.schema_compatibility_v54()
      SET app.schema_compatibility_fingerprint='RETIRED';
    ALTER FUNCTION app.schema_compatibility_v53()
      SET app.schema_compatibility_fingerprint='RETIRED';
    ALTER FUNCTION app.schema_compatibility_v52()
      SET app.schema_compatibility_fingerprint='RETIRED';
    ALTER FUNCTION app.schema_compatibility_v51()
      SET app.schema_compatibility_fingerprint='RETIRED';
    ALTER FUNCTION app.schema_compatibility_v50()
      SET app.schema_compatibility_fingerprint='RETIRED';
    ALTER FUNCTION app.schema_compatibility_v49()
      SET app.schema_compatibility_fingerprint='RETIRED';
    ALTER FUNCTION app.schema_compatibility_v48()
      SET app.schema_compatibility_fingerprint='RETIRED';
    ALTER FUNCTION app.schema_compatibility_v47()
      SET app.schema_compatibility_fingerprint='RETIRED';
    ALTER FUNCTION app.schema_compatibility_v46()
      SET app.schema_compatibility_fingerprint='RETIRED';
    ALTER FUNCTION app.schema_compatibility_v45()
      SET app.schema_compatibility_fingerprint='RETIRED';
    ALTER FUNCTION app.schema_compatibility_v44()
      SET app.schema_compatibility_fingerprint='RETIRED';
    REVOKE ALL ON FUNCTION
      app.schema_compatibility_v58(),
      app.release_runtime_schema_readiness_v58(),
      app.federated_authentication_schema_readiness_v58(),
      app.platform_oidc_direct_runtime_schema_readiness_v58(),
      app.platform_saml_direct_runtime_schema_readiness_v58(),
      app.platform_local_account_runtime_schema_readiness_v58(),
      app.sla_trigger_action_runtime_schema_readiness_v58(),
      app.sla_object_event_ingress_schema_readiness_v58(),
      app.ticket_bulk_runtime_schema_readiness_v58(),
      app.ticket_export_runtime_schema_readiness_v58(),
      app.ticket_metadata_runtime_schema_readiness_v58(),
      app.api_runtime_schema_readiness_v58(),
      app.worker_runtime_schema_readiness_v58()
    FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
      periapsis_auditor,periapsis_notification_readiness_owner,
      periapsis_notification_admin_owner,periapsis_notification_dispatch_owner;
    REVOKE ALL ON FUNCTION
      app.schema_compatibility_v57(),
      app.release_runtime_schema_readiness_v57(),
      app.federated_authentication_schema_readiness_v57(),
      app.platform_oidc_direct_runtime_schema_readiness_v57(),
      app.platform_saml_direct_runtime_schema_readiness_v57(),
      app.platform_local_account_runtime_schema_readiness_v57(),
      app.sla_trigger_action_runtime_schema_readiness_v57(),
      app.sla_object_event_ingress_schema_readiness_v57(),
      app.ticket_bulk_runtime_schema_readiness_v57(),
      app.ticket_export_runtime_schema_readiness_v57(),
      app.ticket_metadata_runtime_schema_readiness_v57(),
      app.api_runtime_schema_readiness_v57(),
      app.worker_runtime_schema_readiness_v57()
    FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
      periapsis_auditor,periapsis_notification_readiness_owner,
      periapsis_notification_admin_owner,periapsis_notification_dispatch_owner;
    REVOKE ALL ON FUNCTION
      app.schema_compatibility_v56(),
      app.release_runtime_schema_readiness_v56(),
      app.federated_authentication_schema_readiness_v56(),
      app.platform_oidc_direct_runtime_schema_readiness_v56(),
      app.platform_saml_direct_runtime_schema_readiness_v56(),
      app.platform_local_account_runtime_schema_readiness_v56(),
      app.sla_trigger_action_runtime_schema_readiness_v56(),
      app.sla_object_event_ingress_schema_readiness_v56(),
      app.ticket_bulk_runtime_schema_readiness_v56(),
      app.ticket_export_runtime_schema_readiness_v56(),
      app.ticket_metadata_runtime_schema_readiness_v56(),
      app.api_runtime_schema_readiness_v56(),
      app.worker_runtime_schema_readiness_v56()
    FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
      periapsis_auditor,periapsis_notification_readiness_owner,
      periapsis_notification_admin_owner,periapsis_notification_dispatch_owner;
    REVOKE ALL ON FUNCTION
      app.schema_compatibility_v55(),
      app.release_runtime_schema_readiness_v55(),
      app.federated_authentication_schema_readiness_v55(),
      app.platform_oidc_direct_runtime_schema_readiness_v55(),
      app.platform_saml_direct_runtime_schema_readiness_v55(),
      app.platform_local_account_runtime_schema_readiness_v55(),
      app.sla_trigger_action_runtime_schema_readiness_v55(),
      app.sla_object_event_ingress_schema_readiness_v55(),
      app.ticket_bulk_runtime_schema_readiness_v55(),
      app.ticket_export_runtime_schema_readiness_v55(),
      app.ticket_metadata_runtime_schema_readiness_v55(),
      app.api_runtime_schema_readiness_v55(),
      app.worker_runtime_schema_readiness_v55()
    FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
      periapsis_auditor,periapsis_notification_readiness_owner,
      periapsis_notification_admin_owner,periapsis_notification_dispatch_owner;
    REVOKE ALL ON FUNCTION
      app.schema_compatibility_v54(),
      app.release_runtime_schema_readiness_v54(),
      app.federated_authentication_schema_readiness_v54(),
      app.platform_oidc_direct_runtime_schema_readiness_v54(),
      app.platform_saml_direct_runtime_schema_readiness_v54(),
      app.platform_local_account_runtime_schema_readiness_v54(),
      app.sla_trigger_action_runtime_schema_readiness_v54(),
      app.sla_object_event_ingress_schema_readiness_v54(),
      app.ticket_bulk_runtime_schema_readiness_v54(),
      app.ticket_export_runtime_schema_readiness_v54(),
      app.ticket_metadata_runtime_schema_readiness_v54(),
      app.api_runtime_schema_readiness_v54(),
      app.worker_runtime_schema_readiness_v54()
    FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
      periapsis_auditor,periapsis_notification_readiness_owner,
      periapsis_notification_admin_owner,periapsis_notification_dispatch_owner;
    REVOKE ALL ON FUNCTION
      app.schema_compatibility_v53(),
      app.release_runtime_schema_readiness_v53(),
      app.federated_authentication_schema_readiness_v53(),
      app.platform_oidc_direct_runtime_schema_readiness_v53(),
      app.platform_saml_direct_runtime_schema_readiness_v53(),
      app.platform_local_account_runtime_schema_readiness_v53(),
      app.sla_trigger_action_runtime_schema_readiness_v53(),
      app.sla_object_event_ingress_schema_readiness_v53(),
      app.ticket_bulk_runtime_schema_readiness_v53(),
      app.ticket_export_runtime_schema_readiness_v53(),
      app.ticket_metadata_runtime_schema_readiness_v53(),
      app.api_runtime_schema_readiness_v53(),
      app.worker_runtime_schema_readiness_v53()
    FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
      periapsis_auditor,periapsis_notification_readiness_owner,
      periapsis_notification_admin_owner,periapsis_notification_dispatch_owner;
    REVOKE ALL ON FUNCTION
      app.schema_compatibility_v52(),
      app.release_runtime_schema_readiness_v52(),
      app.federated_authentication_schema_readiness_v52(),
      app.platform_oidc_direct_runtime_schema_readiness_v52(),
      app.platform_saml_direct_runtime_schema_readiness_v52(),
      app.platform_local_account_runtime_schema_readiness_v52(),
      app.sla_trigger_action_runtime_schema_readiness_v52(),
      app.sla_object_event_ingress_schema_readiness_v52(),
      app.ticket_bulk_runtime_schema_readiness_v52(),
      app.ticket_export_runtime_schema_readiness_v52(),
      app.ticket_metadata_runtime_schema_readiness_v52(),
      app.api_runtime_schema_readiness_v52(),
      app.worker_runtime_schema_readiness_v52()
    FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
      periapsis_auditor,periapsis_notification_readiness_owner,
      periapsis_notification_admin_owner,periapsis_notification_dispatch_owner;
    REVOKE ALL ON FUNCTION
      app.schema_compatibility_v51(),
      app.release_runtime_schema_readiness_v51(),
      app.federated_authentication_schema_readiness_v51(),
      app.platform_oidc_direct_runtime_schema_readiness_v51(),
      app.platform_saml_direct_runtime_schema_readiness_v51(),
      app.platform_local_account_runtime_schema_readiness_v51(),
      app.sla_trigger_action_runtime_schema_readiness_v51(),
      app.sla_object_event_ingress_schema_readiness_v51(),
      app.ticket_bulk_runtime_schema_readiness_v51(),
      app.ticket_export_runtime_schema_readiness_v51(),
      app.ticket_metadata_runtime_schema_readiness_v51()
    FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
      periapsis_auditor,periapsis_notification_readiness_owner,
      periapsis_notification_admin_owner,periapsis_notification_dispatch_owner;
    REVOKE ALL ON FUNCTION
      app.schema_compatibility_v50(),
      app.release_runtime_schema_readiness_v50(),
      app.federated_authentication_schema_readiness_v50(),
      app.platform_oidc_direct_runtime_schema_readiness_v50(),
      app.platform_saml_direct_runtime_schema_readiness_v50(),
      app.platform_local_account_runtime_schema_readiness_v50(),
      app.sla_trigger_action_runtime_schema_readiness_v50(),
      app.sla_object_event_ingress_schema_readiness_v50(),
      app.ticket_bulk_runtime_schema_readiness_v50(),
      app.ticket_export_runtime_schema_readiness_v50(),
      app.ticket_metadata_runtime_schema_readiness_v50()
    FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
      periapsis_auditor,periapsis_notification_readiness_owner,
      periapsis_notification_admin_owner,periapsis_notification_dispatch_owner;
    REVOKE ALL ON FUNCTION
      app.schema_compatibility_v49(),
      app.release_runtime_schema_readiness_v49(),
      app.federated_authentication_schema_readiness_v49(),
      app.platform_oidc_direct_runtime_schema_readiness_v49(),
      app.platform_saml_direct_runtime_schema_readiness_v49(),
      app.platform_local_account_runtime_schema_readiness_v49(),
      app.sla_trigger_action_runtime_schema_readiness_v49(),
      app.sla_object_event_ingress_schema_readiness_v49(),
      app.ticket_bulk_runtime_schema_readiness_v49(),
      app.ticket_export_runtime_schema_readiness_v49(),
      app.ticket_metadata_runtime_schema_readiness_v49()
    FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
      periapsis_auditor,periapsis_notification_readiness_owner,
      periapsis_notification_admin_owner,periapsis_notification_dispatch_owner;
    REVOKE ALL ON FUNCTION
      app.schema_compatibility_v44(),
      app.schema_compatibility_v45(),
      app.schema_compatibility_v46(),
      app.schema_compatibility_v47(),
      app.schema_compatibility_v48()
      FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
           periapsis_auditor;
    REVOKE ALL ON FUNCTION
      app.mfa_policy_administration_schema_readiness_v4(),
      app.mfa_policy_administration_schema_readiness_v6(),
      app.platform_identity_runtime_schema_readiness_v10(),
      app.platform_identity_runtime_schema_readiness_v12(),
      app.platform_oidc_direct_runtime_schema_readiness_v6(),
      app.platform_oidc_direct_runtime_schema_readiness_v8(),
      app.platform_saml_direct_runtime_schema_readiness_v3(),
      app.platform_saml_direct_runtime_schema_readiness_v5(),
      app.platform_tenant_lifecycle_schema_readiness_v1(),
      app.platform_identity_runtime_schema_readiness_v13(),
      app.platform_oidc_direct_runtime_schema_readiness_v9(),
      app.platform_saml_direct_runtime_schema_readiness_v6(),
      app.mfa_policy_administration_schema_readiness_v7(),
      app.ticket_mutation_runtime_schema_readiness_v2(),
      app.platform_local_account_runtime_schema_readiness_v1(),
      app.ticket_bulk_runtime_schema_readiness_v2(),
      app.ticket_export_runtime_schema_readiness_v2(),
      app.alert_dfir_runtime_schema_readiness_v1(),
      app.ticket_metadata_runtime_schema_readiness_v1(),
      app.ticket_watcher_runtime_schema_readiness_v2(),
      app.contacts_portal_schema_readiness_v2(),
      app.tenant_ldap_interactive_auth_schema_readiness_v1(),
      app.ticket_comment_runtime_repair_schema_readiness_v1(),
      app.platform_global_ldap_runtime_schema_readiness_v1(),
      app.federated_authentication_schema_readiness_v1(),
      app.platform_oidc_direct_runtime_schema_readiness_v1(),
      app.platform_saml_direct_runtime_schema_readiness_v2(),
      app.release_runtime_schema_readiness_v48(),
      app.federated_authentication_schema_readiness_v48(),
      app.platform_oidc_direct_runtime_schema_readiness_v48(),
      app.platform_saml_direct_runtime_schema_readiness_v48(),
      app.platform_local_account_runtime_schema_readiness_v48(),
      app.sla_trigger_action_runtime_schema_readiness_v48(),
      app.sla_object_event_ingress_schema_readiness_v48(),
      app.ticket_bulk_runtime_schema_readiness_v48(),
      app.ticket_export_runtime_schema_readiness_v48(),
      app.ticket_metadata_runtime_schema_readiness_v48()
    FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
      periapsis_auditor;
    PERFORM app.private_rotate_sla_readiness_v48();
    PERFORM app.private_rotate_notification_readiness_v59();
    REVOKE ALL ON FUNCTION app.notification_schema_readiness_v4()
    FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
      periapsis_auditor;
  END IF;

  SELECT compatibility.applied_count INTO sealed_count
  FROM app.schema_compatibility_v59() AS compatibility;
  IF NOT was_sealed THEN
    IF sealed_count<>250
       OR NOT app.private_release_runtime_schema_readiness_v59() THEN
      RAISE EXCEPTION 'schema compatibility v59 rotation verification failed'
        USING ERRCODE='55000';
    END IF;
    RETURN;
  END IF;
  IF sealed_count<>250
     OR NOT app.private_release_runtime_schema_readiness_v59()
     OR NOT app.release_runtime_schema_readiness_v59()
     OR NOT app.federated_authentication_schema_readiness_v59()
     OR NOT app.platform_oidc_direct_runtime_schema_readiness_v59()
     OR NOT app.platform_saml_direct_runtime_schema_readiness_v59()
     OR NOT app.platform_local_account_runtime_schema_readiness_v59()
     OR NOT app.sla_trigger_action_runtime_schema_readiness_v59()
     OR NOT app.sla_object_event_ingress_schema_readiness_v59()
     OR NOT app.ticket_bulk_runtime_schema_readiness_v59()
     OR NOT app.ticket_export_runtime_schema_readiness_v59()
     OR NOT app.ticket_metadata_runtime_schema_readiness_v59()
     OR NOT (SELECT readiness.schema_safe
             FROM app.notification_dispatch_readiness_v59() AS readiness) THEN
    RAISE EXCEPTION 'schema compatibility v59 post-seal verification failed'
      USING ERRCODE='55000';
  END IF;
END;
$function$;
ALTER FUNCTION app.seal_schema_compatibility_manifest(bigint,bigint,text,text)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION
  app.seal_schema_compatibility_manifest(bigint,bigint,text,text)
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
       periapsis_auditor;
GRANT EXECUTE ON FUNCTION
  app.seal_schema_compatibility_manifest(bigint,bigint,text,text)
  TO periapsis_migrator;
--> statement-breakpoint
