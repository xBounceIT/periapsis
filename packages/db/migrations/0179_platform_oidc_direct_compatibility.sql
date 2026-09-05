-- V39 seals the dormant, prelinked-only direct platform OIDC runtime.
-- V38 and platform identity readiness v4 cannot describe the new authority
-- revisions, direct provenance, or one-use authentication state.
ALTER FUNCTION app.schema_compatibility_v38()
  SET app.schema_compatibility_fingerprint = 'RETIRED';
REVOKE ALL ON FUNCTION app.schema_compatibility_v38()
FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
  periapsis_auditor,periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,periapsis_sla_api_owner,
  periapsis_sla_worker_owner,periapsis_sla_readiness_owner,
  periapsis_ticket_saved_view_owner,periapsis_ticket_attribution_owner,
  periapsis_ticket_sla_projection_owner;
REVOKE ALL ON FUNCTION app.platform_identity_runtime_schema_readiness_v4()
FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
  periapsis_auditor,periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,periapsis_sla_api_owner,
  periapsis_sla_worker_owner,periapsis_sla_readiness_owner,
  periapsis_ticket_saved_view_owner,periapsis_ticket_attribution_owner,
  periapsis_ticket_sla_projection_owner;
--> statement-breakpoint

DO $derive_schema_compatibility_v39$
DECLARE
  predecessor_definition text;
  derived_definition text;
  predecessor_source_hash text;
BEGIN
  SELECT pg_catalog.pg_get_functiondef(function_row.oid),
         pg_catalog.encode(pg_catalog.sha256(
           pg_catalog.convert_to(function_row.prosrc,'UTF8')
         ),'hex')
    INTO STRICT predecessor_definition,predecessor_source_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid = 'app.schema_compatibility_v38()'::regprocedure;
  IF predecessor_source_hash IS DISTINCT FROM
       '9bb7fe444efefd20ffad95e8a0d062b08f7d94ff38b791bfb0a45ea47c5723ce' THEN
    RAISE EXCEPTION 'schema compatibility v38 predecessor drifted'
      USING ERRCODE = '55000';
  END IF;
  derived_definition := pg_catalog.replace(
    predecessor_definition,'schema_compatibility_v38','schema_compatibility_v39'
  );
  derived_definition := pg_catalog.replace(
    derived_definition,
    'SET "app.schema_compatibility_fingerprint" TO ''RETIRED''',
    'SET "app.schema_compatibility_fingerprint" TO ''UNSEALED'''
  );
  derived_definition := pg_catalog.replace(
    derived_definition,'1788069336676','1788077000000'
  );
  derived_definition := pg_catalog.replace(
    derived_definition,'journal_count = 177','journal_count = 180'
  );
  IF derived_definition = predecessor_definition
     OR derived_definition LIKE '%schema_compatibility_v38%'
     OR derived_definition LIKE
       '%app.schema_compatibility_fingerprint" TO ''RETIRED''%'
     OR derived_definition LIKE '%1788069336676%'
     OR derived_definition LIKE '%journal_count = 177%' THEN
    RAISE EXCEPTION 'schema compatibility v39 derivation was not exact'
      USING ERRCODE = '55000';
  END IF;
  EXECUTE derived_definition;
END;
$derive_schema_compatibility_v39$;
ALTER FUNCTION app.schema_compatibility_v39() OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.schema_compatibility_v39()
FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
  periapsis_auditor,periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,periapsis_sla_api_owner,
  periapsis_sla_worker_owner,periapsis_sla_readiness_owner,
  periapsis_ticket_saved_view_owner,periapsis_ticket_attribution_owner,
  periapsis_ticket_sla_projection_owner;
GRANT EXECUTE ON FUNCTION app.schema_compatibility_v39()
TO periapsis_api,periapsis_worker;
--> statement-breakpoint

DO $derive_platform_identity_dependency_surface_v5$
DECLARE
  predecessor_definition text;
  derived_definition text;
  predecessor_source_hash text;
  exclusion_marker constant text :=
    '        ''private_platform_identity_dependency_surface_hash_v5'',' || chr(10) ||
    '        ''private_platform_identity_runtime_schema_readiness_v5'',' || chr(10) ||
    '        ''platform_identity_runtime_schema_readiness_v5'',' || chr(10) ||
    '        ''schema_compatibility_v39''';
  exclusion_replacement constant text := exclusion_marker || ',' || chr(10) ||
    '        ''private_platform_oidc_direct_dependency_surface_hash_v1'',' || chr(10) ||
    '        ''private_platform_oidc_direct_runtime_schema_readiness_v1'',' || chr(10) ||
    '        ''platform_oidc_direct_runtime_schema_readiness_v1''';
BEGIN
  SELECT pg_catalog.pg_get_functiondef(function_row.oid),
         pg_catalog.encode(pg_catalog.sha256(
           pg_catalog.convert_to(function_row.prosrc,'UTF8')
         ),'hex')
    INTO STRICT predecessor_definition,predecessor_source_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid =
    'app.private_platform_identity_dependency_surface_hash_v4()'::regprocedure;
  IF predecessor_source_hash IS DISTINCT FROM
       'df4b65f12876ea3db587f5721abf2ce4e00e8d6676ece9c3e8de5409d4cb8205' THEN
    RAISE EXCEPTION 'platform identity dependency v4 predecessor drifted'
      USING ERRCODE = '55000';
  END IF;
  derived_definition := pg_catalog.replace(
    predecessor_definition,'private_platform_identity_dependency_surface_hash_v4',
    'private_platform_identity_dependency_surface_hash_v5'
  );
  derived_definition := pg_catalog.replace(
    derived_definition,'private_platform_identity_runtime_schema_readiness_v4',
    'private_platform_identity_runtime_schema_readiness_v5'
  );
  derived_definition := pg_catalog.replace(
    derived_definition,'platform_identity_runtime_schema_readiness_v4',
    'platform_identity_runtime_schema_readiness_v5'
  );
  derived_definition := pg_catalog.replace(
    derived_definition,'schema_compatibility_v38','schema_compatibility_v39'
  );
  IF pg_catalog.strpos(derived_definition,exclusion_marker) = 0 THEN
    RAISE EXCEPTION 'platform identity dependency v5 exclusion marker drifted'
      USING ERRCODE = '55000';
  END IF;
  derived_definition := pg_catalog.replace(
    derived_definition,exclusion_marker,exclusion_replacement
  );
  IF derived_definition = predecessor_definition
     OR derived_definition LIKE
       '%private_platform_identity_dependency_surface_hash_v4%'
     OR derived_definition LIKE
       '%private_platform_identity_runtime_schema_readiness_v4%'
     OR derived_definition LIKE
       '%platform_identity_runtime_schema_readiness_v4%'
     OR derived_definition LIKE '%schema_compatibility_v38%'
     OR derived_definition NOT LIKE
       '%private_platform_oidc_direct_runtime_schema_readiness_v1%' THEN
    RAISE EXCEPTION 'platform identity dependency v5 derivation was not exact'
      USING ERRCODE = '55000';
  END IF;
  EXECUTE derived_definition;
END;
$derive_platform_identity_dependency_surface_v5$;
ALTER FUNCTION app.private_platform_identity_dependency_surface_hash_v5()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_platform_identity_dependency_surface_hash_v5()
FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
  periapsis_auditor,periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,periapsis_sla_api_owner,
  periapsis_sla_worker_owner,periapsis_sla_readiness_owner,
  periapsis_ticket_saved_view_owner,periapsis_ticket_attribution_owner,
  periapsis_ticket_sla_projection_owner;
GRANT EXECUTE ON FUNCTION app.private_platform_identity_dependency_surface_hash_v5()
TO periapsis_migrator;
--> statement-breakpoint

DO $derive_platform_identity_runtime_readiness_v5$
DECLARE
  predecessor_definition text;
  derived_definition text;
  predecessor_source_hash text;
  dependency_source_hash text;
  active_create_entry constant text :=
    '    (''app.create_platform_oidc_auth_provider_v2(uuid,uuid,uuid,text,text,text,jsonb,text,bytea,bytea,uuid,uuid,uuid,inet,text,text,text)'',' || chr(10) ||
    '      ARRAY[''periapsis_api'',''periapsis_migrator'']::text[]),';
  replacement_create_entries constant text :=
    '    (''app.create_platform_oidc_auth_provider_v2(uuid,uuid,uuid,text,text,text,jsonb,text,bytea,bytea,uuid,uuid,uuid,inet,text,text,text)'',' || chr(10) ||
    '      ARRAY[''periapsis_migrator'']::text[]),' || chr(10) ||
    '    (''app.create_platform_oidc_auth_provider_v3(uuid,uuid,uuid,text,text,text,jsonb,text,bytea,bytea,uuid,uuid,uuid,inet,text,text,text)'',' || chr(10) ||
    '      ARRAY[''periapsis_api'',''periapsis_migrator'']::text[]),';
  active_retire_entry constant text :=
    '    (''app.retire_platform_identity_account_v3(uuid,uuid,uuid,bigint,bigint,uuid,uuid,uuid,inet,text,text,text)'',' || chr(10) ||
    '      ARRAY[''periapsis_api'',''periapsis_migrator'']::text[]),';
  replacement_retire_entries constant text :=
    '    (''app.retire_platform_identity_account_v3(uuid,uuid,uuid,bigint,bigint,uuid,uuid,uuid,inet,text,text,text)'',' || chr(10) ||
    '      ARRAY[''periapsis_migrator'']::text[]),' || chr(10) ||
    '    (''app.retire_platform_identity_account_v4(uuid,uuid,uuid,bigint,bigint,uuid,uuid,uuid,inet,text,text,text)'',' || chr(10) ||
    '      ARRAY[''periapsis_api'',''periapsis_migrator'']::text[]),';
  function_marker constant text :=
    '  IF NOT dependency_surface_ready OR NOT trusted_root_catalog_ready' ||
    chr(10) ||
    '     OR NOT account_relation_ready OR NOT account_contract_ready';
  v39_checks constant text := $checks$
  IF NOT (
    SELECT count(*) = 2 AND coalesce(bool_and(
      column_row.atttypid = 'bigint'::pg_catalog.regtype
      AND column_row.attnotnull
      AND pg_catalog.pg_get_expr(default_row.adbin,default_row.adrelid) = '1'
    ),false)
    FROM pg_catalog.pg_attribute AS column_row
    JOIN pg_catalog.pg_attrdef AS default_row
      ON default_row.adrelid = column_row.attrelid
     AND default_row.adnum = column_row.attnum
    WHERE (column_row.attrelid,column_row.attname) IN (
      ('public.users'::regclass,'authentication_revision'),
      ('public.totp_credentials'::regclass,'security_revision')
    ) AND column_row.attnum > 0 AND NOT column_row.attisdropped
  ) OR NOT (
    SELECT count(*) = 2 AND coalesce(bool_and(
      constraint_row.contype = 'c' AND constraint_row.convalidated
      AND constraint_row.conenforced AND NOT constraint_row.condeferrable
    ),false)
    FROM pg_catalog.pg_constraint AS constraint_row
    WHERE (constraint_row.conrelid,constraint_row.conname) IN (
      ('public.users'::regclass,'users_authentication_revision_check'),
      ('public.totp_credentials'::regclass,
       'totp_credentials_security_revision_check')
    )
  ) OR NOT (
    SELECT count(*) = 2 AND coalesce(bool_and(
      NOT trigger_row.tgisinternal AND trigger_row.tgenabled = 'O'
    ),false)
    FROM pg_catalog.pg_trigger AS trigger_row
    WHERE (trigger_row.tgrelid,trigger_row.tgname) IN (
      ('public.users'::regclass,
       'users_platform_identity_projection_update_guard_v1'),
      ('public.totp_credentials'::regclass,
       'totp_credentials_security_revision_guard_v1')
    )
  ) THEN
    RETURN false;
  END IF;
  SELECT pg_catalog.pg_get_functiondef(
    'app.create_platform_oidc_auth_provider_v3(uuid,uuid,uuid,text,text,text,jsonb,text,bytea,bytea,uuid,uuid,uuid,inet,text,text,text)'::regprocedure
  ) INTO function_definition;
  IF function_definition NOT LIKE
       '%INSERT INTO public.platform_oidc_login_policies%'
     OR function_definition NOT LIKE
       '%''oidc'',''disabled'',false,1%'
     OR function_definition NOT LIKE
       '%FROM app.create_platform_oidc_auth_provider_v2(%' THEN
    RETURN false;
  END IF;
  SELECT pg_catalog.pg_get_functiondef(
    'app.retire_platform_identity_account_v4(uuid,uuid,uuid,bigint,bigint,uuid,uuid,uuid,inet,text,text,text)'::regprocedure
  ) INTO function_definition;
  IF function_definition NOT LIKE
       '%FROM app.retire_platform_identity_account_v3(%'
     OR function_definition NOT LIKE
       '%public.platform_post_primary_continuations%'
     OR function_definition NOT LIKE
       '%public.auth_session_platform_oidc_provenance%'
     OR function_definition NOT LIKE
       '%public.auth_session_tenant_platform_federated_provenance%' THEN
    RETURN false;
  END IF;

$checks$;
BEGIN
  SELECT pg_catalog.pg_get_functiondef(function_row.oid),
         pg_catalog.encode(pg_catalog.sha256(
           pg_catalog.convert_to(function_row.prosrc,'UTF8')
         ),'hex')
    INTO STRICT predecessor_definition,predecessor_source_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid =
    'app.private_platform_identity_runtime_schema_readiness_v4()'::regprocedure;
  IF predecessor_source_hash IS DISTINCT FROM
       '7572cd748ac17d4642de8ed29495438977daa2266db454ce4fe3ec52ba94038c' THEN
    RAISE EXCEPTION 'platform identity readiness v4 predecessor drifted'
      USING ERRCODE = '55000';
  END IF;
  SELECT pg_catalog.encode(pg_catalog.sha256(
           pg_catalog.convert_to(function_row.prosrc,'UTF8')
         ),'hex') INTO STRICT dependency_source_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid =
    'app.private_platform_identity_dependency_surface_hash_v5()'::regprocedure;
  derived_definition := pg_catalog.replace(
    predecessor_definition,'private_platform_identity_runtime_schema_readiness_v4',
    'private_platform_identity_runtime_schema_readiness_v5'
  );
  derived_definition := pg_catalog.replace(
    derived_definition,'private_platform_identity_dependency_surface_hash_v4',
    'private_platform_identity_dependency_surface_hash_v5'
  );
  derived_definition := pg_catalog.replace(
    derived_definition,'platform_identity_runtime_schema_readiness_v4',
    'platform_identity_runtime_schema_readiness_v5'
  );
  derived_definition := pg_catalog.replace(
    derived_definition,'schema_compatibility_v38','schema_compatibility_v39'
  );
  derived_definition := pg_catalog.replace(
    derived_definition,
    'df4b65f12876ea3db587f5721abf2ce4e00e8d6676ece9c3e8de5409d4cb8205',
    dependency_source_hash
  );
  derived_definition := pg_catalog.replace(
    derived_definition,
    'f078b26e61ed4daa2885a310118c2aacbdcdc4a9d93999fc16fbc1e639e7049f',
    'a096dcc3b17fd035a87d2d52fdb4d8817f5a6c7fa666aee8fd2c2cc6d4217273'
  );
  IF pg_catalog.strpos(derived_definition,active_create_entry) = 0
     OR pg_catalog.strpos(derived_definition,active_retire_entry) = 0
     OR pg_catalog.strpos(derived_definition,function_marker) = 0 THEN
    RAISE EXCEPTION 'platform identity readiness v5 markers drifted'
      USING ERRCODE = '55000';
  END IF;
  derived_definition := pg_catalog.replace(
    derived_definition,active_create_entry,replacement_create_entries
  );
  derived_definition := pg_catalog.replace(
    derived_definition,active_retire_entry,replacement_retire_entries
  );
  derived_definition := pg_catalog.replace(
    derived_definition,'SELECT count(*) = 20','SELECT count(*) = 22'
  );
  derived_definition := pg_catalog.replace(
    derived_definition,
    '    AND (SELECT count(*) = 22' || chr(10) ||
    '         AND count(*) FILTER (WHERE constraint_row.contype = ''c'') = 5',
    '    AND (SELECT count(*) = 20' || chr(10) ||
    '         AND count(*) FILTER (WHERE constraint_row.contype = ''c'') = 5'
  );
  derived_definition := pg_catalog.replace(
    derived_definition,function_marker,v39_checks || function_marker
  );
  IF derived_definition = predecessor_definition
     OR derived_definition LIKE
       '%private_platform_identity_runtime_schema_readiness_v4%'
     OR derived_definition LIKE
       '%private_platform_identity_dependency_surface_hash_v4%'
     OR derived_definition LIKE
       '%platform_identity_runtime_schema_readiness_v4%'
     OR derived_definition LIKE '%schema_compatibility_v38%'
     OR derived_definition NOT LIKE
       '%AND (SELECT count(*) = 20%constraint_row.contype = ''c'') = 5%'
     OR derived_definition NOT LIKE
       '%SELECT count(*) = 22 AND coalesce(bool_and(%'
     OR derived_definition NOT LIKE
       '%a096dcc3b17fd035a87d2d52fdb4d8817f5a6c7fa666aee8fd2c2cc6d4217273%' THEN
    RAISE EXCEPTION 'platform identity readiness v5 derivation was not exact'
      USING ERRCODE = '55000';
  END IF;
  EXECUTE derived_definition;
END;
$derive_platform_identity_runtime_readiness_v5$;
ALTER FUNCTION app.private_platform_identity_runtime_schema_readiness_v5()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_platform_identity_runtime_schema_readiness_v5()
FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
  periapsis_auditor,periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,periapsis_sla_api_owner,
  periapsis_sla_worker_owner,periapsis_sla_readiness_owner,
  periapsis_ticket_saved_view_owner,periapsis_ticket_attribution_owner,
  periapsis_ticket_sla_projection_owner;
GRANT EXECUTE ON FUNCTION app.private_platform_identity_runtime_schema_readiness_v5()
TO periapsis_migrator;
--> statement-breakpoint

CREATE FUNCTION app.private_platform_oidc_direct_dependency_surface_hash_v1()
RETURNS text
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
SET quote_all_identifiers = off
SET "TimeZone" = 'UTC'
SET "DateStyle" = 'ISO, YMD'
SET "IntervalStyle" = 'postgres'
SET extra_float_digits = 3
SET bytea_output = 'hex'
SET standard_conforming_strings = on
SET lc_numeric = 'C'
AS $function$
WITH relation_row AS (
  SELECT relation.oid,namespace.nspname,relation.relname,
         pg_catalog.jsonb_build_object(
           'kind',relation.relkind,'owner',owner.rolname,
           'rls',relation.relrowsecurity,'forceRls',relation.relforcerowsecurity,
           'columns',(
             SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
               'number',column_row.attnum,'name',column_row.attname,
               'type',pg_catalog.format_type(
                 column_row.atttypid,column_row.atttypmod
               ),'notNull',column_row.attnotnull,
               'identity',column_row.attidentity,
               'generated',column_row.attgenerated,
               'default',pg_catalog.pg_get_expr(
                 default_row.adbin,default_row.adrelid
               )
             ) ORDER BY column_row.attnum)
             FROM pg_catalog.pg_attribute AS column_row
             LEFT JOIN pg_catalog.pg_attrdef AS default_row
               ON default_row.adrelid = column_row.attrelid
              AND default_row.adnum = column_row.attnum
             WHERE column_row.attrelid = relation.oid
               AND column_row.attnum > 0 AND NOT column_row.attisdropped
           ),
           'constraints',(
             SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
               'name',constraint_row.conname,'type',constraint_row.contype,
               'definition',pg_catalog.pg_get_constraintdef(
                 constraint_row.oid,true
               ),'validated',constraint_row.convalidated,
               'enforced',constraint_row.conenforced,
               'deferrable',constraint_row.condeferrable,
               'deferred',constraint_row.condeferred
             ) ORDER BY constraint_row.conname)
             FROM pg_catalog.pg_constraint AS constraint_row
             WHERE constraint_row.conrelid = relation.oid
           ),
           'indexes',(
             SELECT pg_catalog.jsonb_agg(
               pg_catalog.pg_get_indexdef(index_row.indexrelid)
               ORDER BY index_relation.relname
             )
             FROM pg_catalog.pg_index AS index_row
             JOIN pg_catalog.pg_class AS index_relation
               ON index_relation.oid = index_row.indexrelid
             WHERE index_row.indrelid = relation.oid
           ),
           'triggers',(
             SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
               'name',trigger_row.tgname,'enabled',trigger_row.tgenabled,
               'definition',pg_catalog.pg_get_triggerdef(trigger_row.oid,true)
             ) ORDER BY trigger_row.tgname)
             FROM pg_catalog.pg_trigger AS trigger_row
             WHERE trigger_row.tgrelid = relation.oid
               AND NOT trigger_row.tgisinternal
           ),
           'policies',(
             SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
               'name',policy_row.polname,'permissive',policy_row.polpermissive,
               'command',policy_row.polcmd,'roles',(
                 SELECT pg_catalog.jsonb_agg(
                   coalesce(role.rolname,'PUBLIC') ORDER BY
                     coalesce(role.rolname,'PUBLIC')
                 )
                 FROM pg_catalog.unnest(policy_row.polroles) AS policy_role(oid)
                 LEFT JOIN pg_catalog.pg_roles AS role
                   ON role.oid = policy_role.oid
               ),
               'using',pg_catalog.pg_get_expr(
                 policy_row.polqual,policy_row.polrelid
               ),'check',pg_catalog.pg_get_expr(
                 policy_row.polwithcheck,policy_row.polrelid
               )
             ) ORDER BY policy_row.polname)
             FROM pg_catalog.pg_policy AS policy_row
             WHERE policy_row.polrelid = relation.oid
           ),
           'acl',(
             SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
               'grantor',grantor.rolname,
               'grantee',coalesce(grantee.rolname,'PUBLIC'),
               'privilege',acl_row.privilege_type,
               'grantable',acl_row.is_grantable
             ) ORDER BY coalesce(grantee.rolname,'PUBLIC'),
                        acl_row.privilege_type,grantor.rolname)
             FROM pg_catalog.aclexplode(CASE WHEN pg_catalog.cardinality(
               coalesce(relation.relacl,
                 pg_catalog.acldefault('r',relation.relowner))
             ) > 0 THEN coalesce(relation.relacl,
               pg_catalog.acldefault('r',relation.relowner))
             ELSE NULL::pg_catalog.aclitem[] END) AS acl_row
             JOIN pg_catalog.pg_roles AS grantor
               ON grantor.oid = acl_row.grantor
             LEFT JOIN pg_catalog.pg_roles AS grantee
               ON grantee.oid = acl_row.grantee
           )
         )::text AS payload
  FROM pg_catalog.pg_class AS relation
  JOIN pg_catalog.pg_namespace AS namespace
    ON namespace.oid = relation.relnamespace
  JOIN pg_catalog.pg_roles AS owner ON owner.oid = relation.relowner
  WHERE namespace.nspname = 'public' AND relation.relkind = 'r'
    AND (
      relation.relname IN ('users','totp_credentials','auth_sessions',
        'platform_auth_providers','platform_federated_provider_policies',
        'platform_federated_external_identities',
        'platform_federated_external_identity_aliases','mfa_policy_revisions',
        'tenants','tenant_memberships','tenant_mfa_subjects',
        'tenant_platform_auth_provider_bindings',
        'tenant_platform_identity_provider_access_epochs',
        'tenant_authorization_sources',
        'tenant_platform_federated_provider_access_grants',
        'auth_session_mfa_states','auth_session_mfa_policy_pins',
        'auth_session_federated_provenance',
        'auth_session_tenant_platform_federated_provenance',
        'auth_session_tenant_platform_federated_evidence')
      OR relation.relname LIKE 'platform_oidc_%'
      OR relation.relname LIKE 'platform_post_primary_%'
      OR relation.relname LIKE 'auth_session_platform_oidc_%'
    )
), function_row AS (
  SELECT function_record.oid,namespace.nspname,function_record.proname,
         pg_catalog.pg_get_function_identity_arguments(function_record.oid)
           AS identity_arguments,
         pg_catalog.jsonb_build_object(
           'owner',owner.rolname,'language',language.lanname,
           'kind',function_record.prokind,
           'volatility',function_record.provolatile,
           'securityDefiner',function_record.prosecdef,
           'strict',function_record.proisstrict,
           'leakproof',function_record.proleakproof,
           'parallel',function_record.proparallel,
           'result',pg_catalog.pg_get_function_result(function_record.oid),
           'config',function_record.proconfig,
           'sourceHash',pg_catalog.encode(pg_catalog.sha256(
             pg_catalog.convert_to(function_record.prosrc,'UTF8')
           ),'hex'),
           'acl',(
             SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
               'grantor',grantor.rolname,
               'grantee',coalesce(grantee.rolname,'PUBLIC'),
               'privilege',acl_row.privilege_type,
               'grantable',acl_row.is_grantable
             ) ORDER BY coalesce(grantee.rolname,'PUBLIC'),
                        acl_row.privilege_type,grantor.rolname)
             FROM pg_catalog.aclexplode(CASE WHEN pg_catalog.cardinality(
               coalesce(function_record.proacl,
                 pg_catalog.acldefault('f',function_record.proowner))
             ) > 0 THEN coalesce(function_record.proacl,
               pg_catalog.acldefault('f',function_record.proowner))
             ELSE NULL::pg_catalog.aclitem[] END) AS acl_row
             JOIN pg_catalog.pg_roles AS grantor
               ON grantor.oid = acl_row.grantor
             LEFT JOIN pg_catalog.pg_roles AS grantee
               ON grantee.oid = acl_row.grantee
           )
         )::text AS payload
  FROM pg_catalog.pg_proc AS function_record
  JOIN pg_catalog.pg_namespace AS namespace
    ON namespace.oid = function_record.pronamespace
  JOIN pg_catalog.pg_roles AS owner ON owner.oid = function_record.proowner
  JOIN pg_catalog.pg_language AS language
    ON language.oid = function_record.prolang
  WHERE namespace.nspname = 'app'
    AND (
      function_record.proname LIKE '%platform_oidc%'
      OR function_record.proname LIKE '%platform_post_primary%'
      OR function_record.proname IN (
        'guard_user_platform_identity_projection_v1',
        'guard_totp_credential_security_revision_v1',
        'retire_platform_identity_account_v4'
      )
    )
    AND function_record.proname NOT IN (
      'private_platform_oidc_direct_dependency_surface_hash_v1',
      'private_platform_oidc_direct_runtime_schema_readiness_v1',
      'platform_oidc_direct_runtime_schema_readiness_v1'
    )
), transcript AS (
  SELECT 'relation:' || relation_row.nspname || '.' || relation_row.relname
           AS object_key,
         relation_row.payload
  FROM relation_row
  UNION ALL
  SELECT 'function:' || function_row.nspname || '.' || function_row.proname ||
           '(' || function_row.identity_arguments || ')',
         function_row.payload
  FROM function_row
)
SELECT pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
  pg_catalog.string_agg(
    transcript.object_key || '=' || transcript.payload,
    chr(10) ORDER BY transcript.object_key
  ),'UTF8'
)),'hex')
FROM transcript;
$function$;
ALTER FUNCTION app.private_platform_oidc_direct_dependency_surface_hash_v1()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION
  app.private_platform_oidc_direct_dependency_surface_hash_v1()
FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
  periapsis_auditor,periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,periapsis_sla_api_owner,
  periapsis_sla_worker_owner,periapsis_sla_readiness_owner,
  periapsis_ticket_saved_view_owner,periapsis_ticket_attribution_owner,
  periapsis_ticket_sla_projection_owner;
GRANT EXECUTE ON FUNCTION
  app.private_platform_oidc_direct_dependency_surface_hash_v1()
TO periapsis_migrator;
--> statement-breakpoint

CREATE FUNCTION app.private_platform_oidc_direct_runtime_schema_readiness_v1()
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  relation_names constant text[] := ARRAY[
    'auth_session_platform_oidc_evidence',
    'auth_session_platform_oidc_policy_pins',
    'auth_session_platform_oidc_provenance',
    'auth_session_platform_oidc_states',
    'platform_oidc_authentication_applications',
    'platform_oidc_authentication_transactions',
    'platform_oidc_login_policies',
    'platform_oidc_session_revalidation_commands',
    'platform_oidc_tenant_switch_commands',
    'platform_post_primary_continuation_evidence',
    'platform_post_primary_continuation_policy_pins',
    'platform_post_primary_continuations',
    'platform_post_primary_totp_challenges'
  ];
  runtime_roles constant text[] := ARRAY[
    'periapsis_api','periapsis_worker','periapsis_notifier',
    'periapsis_auditor','periapsis_audit_reader_owner',
    'periapsis_notification_dispatch_owner','periapsis_sla_api_owner',
    'periapsis_sla_worker_owner','periapsis_sla_readiness_owner',
    'periapsis_ticket_saved_view_owner','periapsis_ticket_attribution_owner',
    'periapsis_ticket_sla_projection_owner'
  ];
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_catalog.pg_proc AS function_row
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = function_row.pronamespace
    JOIN pg_catalog.pg_roles AS owner ON owner.oid = function_row.proowner
    JOIN pg_catalog.pg_language AS language
      ON language.oid = function_row.prolang
    WHERE namespace.nspname = 'app'
      AND function_row.proname =
        'private_platform_oidc_direct_dependency_surface_hash_v1'
      AND pg_catalog.pg_get_function_identity_arguments(function_row.oid) = ''
      AND owner.rolname = 'periapsis_migrator'
      AND language.lanname = 'sql' AND function_row.provolatile = 's'
      AND function_row.prosecdef
      AND pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
        function_row.prosrc,'UTF8'
      )),'hex') =
        '4d86365af67a2e98aef60473360474ae6b69d30c6548ff9605514fcb6133febe'
      AND function_row.proconfig @> ARRAY[
        'search_path=pg_catalog, public, app'
      ]::text[]
  ) OR app.private_platform_oidc_direct_dependency_surface_hash_v1() <>
       '314be1f25c22af04d55868c1fcefa537884765d0c9083ef203aad1d8fed225df' THEN
    RETURN false;
  END IF;

  IF NOT (
    SELECT count(*) = 13 AND coalesce(bool_and(
      relation.relkind = 'r' AND owner.rolname = 'periapsis_migrator'
      AND relation.relrowsecurity AND relation.relforcerowsecurity
      AND NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_policy AS policy
        WHERE policy.polrelid = relation.oid
      )
      AND NOT EXISTS (
        SELECT 1
        FROM pg_catalog.aclexplode(CASE WHEN pg_catalog.cardinality(
          coalesce(relation.relacl,
            pg_catalog.acldefault('r',relation.relowner))
        ) > 0 THEN coalesce(relation.relacl,
          pg_catalog.acldefault('r',relation.relowner))
        ELSE NULL::pg_catalog.aclitem[] END) AS acl_row
        WHERE acl_row.grantee = 0
      )
    ),false)
    FROM pg_catalog.pg_class AS relation
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = relation.relnamespace
    JOIN pg_catalog.pg_roles AS owner ON owner.oid = relation.relowner
    WHERE namespace.nspname = 'public'
      AND relation.relname = ANY(relation_names)
  ) OR EXISTS (
    SELECT 1
    FROM pg_catalog.unnest(runtime_roles) AS runtime_role(role_name)
    CROSS JOIN pg_catalog.unnest(relation_names) AS relation_name(name)
    CROSS JOIN pg_catalog.unnest(ARRAY[
      'SELECT','INSERT','UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER'
    ]::text[]) AS privilege(privilege_name)
    WHERE pg_catalog.has_table_privilege(
      runtime_role.role_name,
      pg_catalog.format('public.%I',relation_name.name),
      privilege.privilege_name
    )
  ) THEN
    RETURN false;
  END IF;

  IF NOT (
    SELECT count(*) = 3
    FROM pg_catalog.pg_enum AS enum_value
    WHERE enum_value.enumtypid =
      'public.auth_rate_limit_scope'::pg_catalog.regtype
      AND enum_value.enumlabel IN (
        'platform_oidc_network','platform_oidc_account',
        'platform_oidc_provider'
      )
  ) THEN
    RETURN false;
  END IF;

  IF EXISTS (
    SELECT 1
    FROM ONLY public.platform_federated_provider_policies AS runtime_policy
    WHERE runtime_policy.platform_login_enabled
  ) OR EXISTS (
    SELECT 1
    FROM ONLY public.platform_auth_providers AS provider
    LEFT JOIN ONLY public.platform_oidc_login_policies AS login_policy
      ON login_policy.provider_id = provider.id
    WHERE provider.kind = 'oidc' AND (
      login_policy.provider_id IS NULL
      OR login_policy.account_mode <> 'disabled'
      OR login_policy.enabled
      OR login_policy.revision <> 1
    )
  ) OR EXISTS (
    SELECT 1
    FROM ONLY public.platform_oidc_login_policies AS login_policy
    JOIN ONLY public.platform_auth_providers AS provider
      ON provider.id = login_policy.provider_id
    WHERE provider.kind <> 'oidc'
  ) THEN
    RETURN false;
  END IF;

  IF EXISTS (
    SELECT 1
    FROM ONLY public.platform_oidc_authentication_transactions AS transaction
    WHERE transaction.allow_refresh_token
       OR transaction.code_challenge_method <> 'S256'
       OR pg_catalog.octet_length(transaction.browser_capability_digest) <> 32
       OR transaction.browser_capability_digest = transaction.browser_digest
       OR pg_catalog.encode(
         transaction.browser_capability_digest,'hex'
       ) = pg_catalog.repeat('00',32)
       OR transaction.redirect_uri !~
         '^https://[^/?#@]+/api/v1/auth/platform/oidc/callback$'
  ) OR EXISTS (
    SELECT 1
    FROM ONLY public.platform_post_primary_continuations AS continuation
    WHERE continuation.selected_totp_credential_id IS NULL
       OR continuation.selected_totp_security_revision IS NULL
  ) OR EXISTS (
    SELECT 1
    FROM ONLY public.auth_session_platform_oidc_states AS direct_state
    JOIN ONLY public.auth_sessions AS session
      ON session.id = direct_state.session_id
    LEFT JOIN LATERAL (
      SELECT count(*)::integer AS count,
             min(provenance.user_id::text)::uuid AS user_id
      FROM ONLY public.auth_session_platform_oidc_provenance AS provenance
      WHERE provenance.session_id = direct_state.session_id
    ) AS direct_provenance ON true
    WHERE session.authentication_method <> 'oidc'
       OR session.active_tenant_id IS NOT NULL
       OR session.user_id <> direct_state.user_id
       OR direct_state.audience <> 'api'
       OR direct_state.recovery_restricted
       OR direct_state.primary_kind <> 'platform_provider'
       OR direct_provenance.count <> 1
       OR direct_provenance.user_id <> session.user_id
       OR (SELECT count(*)
           FROM ONLY public.auth_session_platform_oidc_evidence AS evidence
           WHERE evidence.session_id = direct_state.session_id
             AND evidence.kind = 'platform_provider') <> 1
       OR (SELECT count(*)
           FROM ONLY public.auth_session_platform_oidc_evidence AS evidence
           WHERE evidence.session_id = direct_state.session_id
             AND evidence.kind = 'totp') NOT BETWEEN 0 AND 1
       OR EXISTS (
         SELECT 1 FROM ONLY public.auth_session_mfa_states AS tenant_state
         WHERE tenant_state.session_id = direct_state.session_id
       )
       OR EXISTS (
         SELECT 1
         FROM ONLY public.auth_session_federated_provenance
           AS tenant_provenance
         WHERE tenant_provenance.session_id = direct_state.session_id
       )
       OR EXISTS (
         SELECT 1
         FROM ONLY public.auth_session_tenant_platform_federated_provenance
           AS tenant_platform_provenance
         WHERE tenant_platform_provenance.session_id = direct_state.session_id
       )
  ) OR EXISTS (
    SELECT 1
    FROM ONLY public.auth_session_platform_oidc_provenance AS provenance
    LEFT JOIN ONLY public.auth_session_platform_oidc_states AS direct_state
      ON direct_state.session_id = provenance.session_id
    WHERE direct_state.session_id IS NULL
       OR direct_state.user_id <> provenance.user_id
  ) THEN
    RETURN false;
  END IF;

  IF NOT (
    WITH api_function(signature) AS (VALUES
      ('app.begin_platform_oidc_authentication_v1(jsonb)'),
      ('app.resolve_platform_oidc_authentication_configuration_v1(jsonb)'),
      ('app.create_platform_oidc_authentication_transaction_v1(jsonb)'),
      ('app.claim_platform_oidc_authentication_transaction_v1(jsonb)'),
      ('app.resolve_platform_oidc_authentication_v1(jsonb)'),
      ('app.fail_platform_oidc_authentication_transaction_v1(jsonb)'),
      ('app.load_platform_oidc_client_secret_v1(jsonb)'),
      ('app.load_platform_oidc_trust_snapshot_v1(jsonb)'),
      ('app.load_platform_oidc_planning_state_v1(jsonb)'),
      ('app.apply_platform_oidc_authentication_v1(jsonb)'),
      ('app.begin_platform_post_primary_totp_v1(jsonb)'),
      ('app.load_platform_post_primary_totp_v1(jsonb)'),
      ('app.record_platform_post_primary_totp_failure_v1(jsonb)'),
      ('app.apply_platform_post_primary_totp_v1(jsonb)'),
      ('app.abandon_platform_post_primary_totp_v1(jsonb)'),
      ('app.load_platform_oidc_session_revalidation_v1(jsonb)'),
      ('app.apply_platform_oidc_session_revalidation_v1(jsonb)'),
      ('app.load_platform_oidc_tenant_switch_v1(jsonb)'),
      ('app.apply_platform_oidc_tenant_switch_v1(jsonb)'),
      ('app.create_platform_oidc_auth_provider_v3(uuid,uuid,uuid,text,text,text,jsonb,text,bytea,bytea,uuid,uuid,uuid,inet,text,text,text)'),
      ('app.retire_platform_identity_account_v4(uuid,uuid,uuid,bigint,bigint,uuid,uuid,uuid,inet,text,text,text)')
    ), checked AS (
      SELECT api_function.signature,
             pg_catalog.to_regprocedure(api_function.signature) AS oid
      FROM api_function
    )
    SELECT count(*) = 21 AND coalesce(bool_and(
      checked.oid IS NOT NULL
      AND pg_catalog.has_function_privilege(
        'periapsis_api',checked.oid,'EXECUTE'
      )
      AND pg_catalog.has_function_privilege(
        'periapsis_migrator',checked.oid,'EXECUTE'
      )
      AND NOT pg_catalog.has_function_privilege(
        'periapsis_worker',checked.oid,'EXECUTE'
      )
      AND NOT pg_catalog.has_function_privilege(
        'periapsis_notifier',checked.oid,'EXECUTE'
      )
      AND NOT pg_catalog.has_function_privilege(
        'periapsis_auditor',checked.oid,'EXECUTE'
      )
      AND NOT EXISTS (
        SELECT 1
        FROM pg_catalog.aclexplode(CASE WHEN pg_catalog.cardinality(
          coalesce(function_row.proacl,
            pg_catalog.acldefault('f',function_row.proowner))
        ) > 0 THEN coalesce(function_row.proacl,
          pg_catalog.acldefault('f',function_row.proowner))
        ELSE NULL::pg_catalog.aclitem[] END) AS acl_row
        WHERE acl_row.grantee = 0
          AND acl_row.privilege_type = 'EXECUTE'
      )
      AND function_row.prosecdef
      AND owner.rolname = 'periapsis_migrator'
      AND function_row.proconfig = ARRAY[
        'search_path=pg_catalog, public, app'
      ]::text[]
    ),false)
    FROM checked
    LEFT JOIN pg_catalog.pg_proc AS function_row
      ON function_row.oid = checked.oid
    LEFT JOIN pg_catalog.pg_roles AS owner
      ON owner.oid = function_row.proowner
  ) OR NOT pg_catalog.has_function_privilege(
    'periapsis_worker',
    'app.cleanup_platform_oidc_authentication_runtime_v1(jsonb)'::regprocedure,
    'EXECUTE'
  ) OR pg_catalog.has_function_privilege(
    'periapsis_api',
    'app.cleanup_platform_oidc_authentication_runtime_v1(jsonb)'::regprocedure,
    'EXECUTE'
  ) THEN
    RETURN false;
  END IF;

  IF EXISTS (
    SELECT 1
    FROM pg_catalog.pg_proc AS function_row
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = function_row.pronamespace
    JOIN pg_catalog.pg_roles AS owner ON owner.oid = function_row.proowner
    WHERE namespace.nspname = 'app'
      AND function_row.proname IN (
        'guard_platform_oidc_login_policy_v1',
        'guard_totp_credential_security_revision_v1',
        'guard_platform_oidc_runtime_write_v1',
        'guard_platform_oidc_transaction_v1',
        'assert_platform_oidc_direct_session_v1',
        'private_platform_oidc_direct_assurance_v1',
        'private_platform_oidc_direct_continuation_source_live_v1',
        'private_platform_post_primary_totp_projection_v1',
        'private_platform_oidc_direct_authority_live_v1',
        'private_platform_oidc_create_direct_session_v1',
        'private_platform_oidc_direct_audit_v1',
        'private_platform_oidc_direct_json_v1',
        'private_platform_oidc_direct_projection_v1',
        'private_platform_oidc_direct_configuration_v1'
      ) AND (
        owner.rolname <> 'periapsis_migrator'
        OR NOT function_row.prosecdef
        OR function_row.proconfig <> ARRAY[
          'search_path=pg_catalog, public, app'
        ]::text[]
        OR EXISTS (
          SELECT 1
          FROM pg_catalog.aclexplode(CASE WHEN pg_catalog.cardinality(
            coalesce(function_row.proacl,
              pg_catalog.acldefault('f',function_row.proowner))
          ) > 0 THEN coalesce(function_row.proacl,
            pg_catalog.acldefault('f',function_row.proowner))
          ELSE NULL::pg_catalog.aclitem[] END) AS acl_row
          WHERE acl_row.grantee = 0
            AND acl_row.privilege_type = 'EXECUTE'
        )
        OR pg_catalog.has_function_privilege(
          'periapsis_api',function_row.oid,'EXECUTE'
        )
        OR pg_catalog.has_function_privilege(
          'periapsis_worker',function_row.oid,'EXECUTE'
        )
      )
  ) THEN
    RETURN false;
  END IF;
  RETURN true;
END;
$function$;
ALTER FUNCTION app.private_platform_oidc_direct_runtime_schema_readiness_v1()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION
  app.private_platform_oidc_direct_runtime_schema_readiness_v1()
FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
  periapsis_auditor,periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,periapsis_sla_api_owner,
  periapsis_sla_worker_owner,periapsis_sla_readiness_owner,
  periapsis_ticket_saved_view_owner,periapsis_ticket_attribution_owner,
  periapsis_ticket_sla_projection_owner;
GRANT EXECUTE ON FUNCTION
  app.private_platform_oidc_direct_runtime_schema_readiness_v1()
TO periapsis_migrator;
--> statement-breakpoint

DO $derive_platform_identity_runtime_public_readiness_v5$
DECLARE
  predecessor_definition text;
  derived_definition text;
  predecessor_source_hash text;
  private_marker constant text :=
    '    AND app.private_platform_identity_runtime_schema_readiness_v5();';
  predecessor_acl_checks constant text :=
    '    AND NOT pg_catalog.has_function_privilege(' || chr(10) ||
    '      ''periapsis_api'',' || chr(10) ||
    '      ''app.schema_compatibility_v38()''::regprocedure,''EXECUTE''' || chr(10) ||
    '    )' || chr(10) ||
    '    AND NOT pg_catalog.has_function_privilege(' || chr(10) ||
    '      ''periapsis_worker'',' || chr(10) ||
    '      ''app.schema_compatibility_v38()''::regprocedure,''EXECUTE''' || chr(10) ||
    '    )' || chr(10) ||
    '    AND NOT pg_catalog.has_function_privilege(' || chr(10) ||
    '      ''periapsis_api'',' || chr(10) ||
    '      ''app.platform_identity_runtime_schema_readiness_v4()''::regprocedure,' || chr(10) ||
    '      ''EXECUTE''' || chr(10) ||
    '    )' || chr(10) ||
    '    AND NOT pg_catalog.has_function_privilege(' || chr(10) ||
    '      ''periapsis_worker'',' || chr(10) ||
    '      ''app.platform_identity_runtime_schema_readiness_v4()''::regprocedure,' || chr(10) ||
    '      ''EXECUTE''' || chr(10) ||
    '    )' || chr(10);
BEGIN
  SELECT pg_catalog.pg_get_functiondef(function_row.oid),
         pg_catalog.encode(pg_catalog.sha256(
           pg_catalog.convert_to(function_row.prosrc,'UTF8')
         ),'hex')
    INTO STRICT predecessor_definition,predecessor_source_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid =
    'app.platform_identity_runtime_schema_readiness_v4()'::regprocedure;
  IF predecessor_source_hash IS DISTINCT FROM
       '2279d5e2e5374a441f2fa3693521e9655ac8fa39d76cf1d55cca05e976547199' THEN
    RAISE EXCEPTION 'platform identity public readiness v4 predecessor drifted'
      USING ERRCODE = '55000';
  END IF;
  derived_definition := pg_catalog.replace(
    predecessor_definition,'platform_identity_runtime_schema_readiness_v4',
    'platform_identity_runtime_schema_readiness_v5'
  );
  derived_definition := pg_catalog.replace(
    derived_definition,'private_platform_identity_runtime_schema_readiness_v4',
    'private_platform_identity_runtime_schema_readiness_v5'
  );
  derived_definition := pg_catalog.replace(
    derived_definition,'schema_compatibility_v38','schema_compatibility_v39'
  );
  derived_definition := pg_catalog.replace(
    derived_definition,'current_count = 177','current_count = 180'
  );
  IF pg_catalog.strpos(derived_definition,private_marker) = 0 THEN
    RAISE EXCEPTION 'platform identity public readiness v5 marker drifted'
      USING ERRCODE = '55000';
  END IF;
  derived_definition := pg_catalog.replace(
    derived_definition,private_marker,predecessor_acl_checks || private_marker
  );
  IF derived_definition = predecessor_definition
     OR derived_definition LIKE
       '%platform_identity_runtime_schema_readiness_v4();%'
     OR derived_definition LIKE '%current_count = 177%'
     OR derived_definition NOT LIKE '%schema_compatibility_v38()%' THEN
    RAISE EXCEPTION 'platform identity public readiness v5 derivation was not exact'
      USING ERRCODE = '55000';
  END IF;
  EXECUTE derived_definition;
END;
$derive_platform_identity_runtime_public_readiness_v5$;
ALTER FUNCTION app.platform_identity_runtime_schema_readiness_v5()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.platform_identity_runtime_schema_readiness_v5()
FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
  periapsis_auditor,periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,periapsis_sla_api_owner,
  periapsis_sla_worker_owner,periapsis_sla_readiness_owner,
  periapsis_ticket_saved_view_owner,periapsis_ticket_attribution_owner,
  periapsis_ticket_sla_projection_owner;
GRANT EXECUTE ON FUNCTION app.platform_identity_runtime_schema_readiness_v5()
TO periapsis_api,periapsis_worker;
--> statement-breakpoint

CREATE FUNCTION app.platform_oidc_direct_runtime_schema_readiness_v1()
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  current_count bigint;
  current_latest_created_at bigint;
  current_latest_hash text;
  current_fingerprint text;
  expected_count bigint;
  expected_latest_created_at bigint;
  expected_latest_hash text;
  expected_fingerprint text;
BEGIN
  SELECT count(*)::bigint,max(migration.created_at)::bigint,
         (SELECT lower(latest.hash::text)
          FROM drizzle.__drizzle_migrations AS latest
          ORDER BY latest.created_at DESC,latest.id DESC LIMIT 1),
         string_agg(
           migration.created_at::text || '@' || lower(migration.hash::text),
           ':' ORDER BY migration.created_at,migration.id
         )
    INTO current_count,current_latest_created_at,current_latest_hash,
         current_fingerprint
  FROM drizzle.__drizzle_migrations AS migration;
  SELECT compatibility.applied_count,compatibility.latest_created_at,
         compatibility.latest_hash,compatibility.migration_fingerprint
    INTO expected_count,expected_latest_created_at,expected_latest_hash,
         expected_fingerprint
  FROM app.schema_compatibility_v39() AS compatibility;
  RETURN current_count = 180
    AND ROW(current_count,current_latest_created_at,current_latest_hash,
            current_fingerprint) IS NOT DISTINCT FROM
        ROW(expected_count,expected_latest_created_at,expected_latest_hash,
            expected_fingerprint)
    AND NOT pg_catalog.has_function_privilege(
      'periapsis_api','app.schema_compatibility_v38()'::regprocedure,'EXECUTE'
    )
    AND NOT pg_catalog.has_function_privilege(
      'periapsis_worker','app.schema_compatibility_v38()'::regprocedure,'EXECUTE'
    )
    AND NOT pg_catalog.has_function_privilege(
      'periapsis_api',
      'app.platform_identity_runtime_schema_readiness_v4()'::regprocedure,
      'EXECUTE'
    )
    AND NOT pg_catalog.has_function_privilege(
      'periapsis_worker',
      'app.platform_identity_runtime_schema_readiness_v4()'::regprocedure,
      'EXECUTE'
    )
    AND app.private_platform_oidc_direct_runtime_schema_readiness_v1();
EXCEPTION WHEN undefined_table OR undefined_function OR insufficient_privilege
  OR invalid_schema_name OR cardinality_violation OR data_exception THEN
  RETURN false;
END;
$function$;
ALTER FUNCTION app.platform_oidc_direct_runtime_schema_readiness_v1()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.platform_oidc_direct_runtime_schema_readiness_v1()
FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
  periapsis_auditor,periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,periapsis_sla_api_owner,
  periapsis_sla_worker_owner,periapsis_sla_readiness_owner,
  periapsis_ticket_saved_view_owner,periapsis_ticket_attribution_owner,
  periapsis_ticket_sla_projection_owner;
GRANT EXECUTE ON FUNCTION app.platform_oidc_direct_runtime_schema_readiness_v1()
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
SET search_path = pg_catalog, public, app
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
BEGIN
  IF p_expected_count IS DISTINCT FROM 180
     OR p_expected_latest_created_at IS DISTINCT FROM 1788077000000
     OR p_expected_latest_hash !~ '^[0-9a-f]{64}$'
     OR p_expected_migration_fingerprint !~
       '^[0-9]+@[0-9a-f]{64}(:[0-9]+@[0-9a-f]{64}){179}$' THEN
    RAISE EXCEPTION 'schema compatibility v39 seal input is invalid'
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
     OR NOT app.private_platform_identity_runtime_schema_readiness_v5()
     OR NOT app.private_platform_oidc_direct_runtime_schema_readiness_v1()
     OR pg_catalog.has_function_privilege(
       'periapsis_api','app.schema_compatibility_v38()'::regprocedure,'EXECUTE'
     )
     OR pg_catalog.has_function_privilege(
       'periapsis_worker','app.schema_compatibility_v38()'::regprocedure,'EXECUTE'
     )
     OR pg_catalog.has_function_privilege(
       'periapsis_api',
       'app.platform_identity_runtime_schema_readiness_v4()'::regprocedure,
       'EXECUTE'
     )
     OR pg_catalog.has_function_privilege(
       'periapsis_worker',
       'app.platform_identity_runtime_schema_readiness_v4()'::regprocedure,
       'EXECUTE'
     ) THEN
    RAISE EXCEPTION 'schema compatibility v39 pre-seal verification failed'
      USING ERRCODE = '55000';
  END IF;
  EXECUTE pg_catalog.format(
    'ALTER FUNCTION app.schema_compatibility_v39() SET app.schema_compatibility_fingerprint = %L',
    p_expected_migration_fingerprint
  );
  SELECT compatibility.applied_count,compatibility.latest_created_at,
         compatibility.latest_hash,compatibility.migration_fingerprint
    INTO sealed_count,sealed_latest_created_at,sealed_latest_hash,
         sealed_fingerprint
  FROM app.schema_compatibility_v39() AS compatibility;
  IF ROW(sealed_count,sealed_latest_created_at,sealed_latest_hash,
         sealed_fingerprint) IS DISTINCT FROM
     ROW(p_expected_count,p_expected_latest_created_at,p_expected_latest_hash,
         p_expected_migration_fingerprint)
     OR NOT app.platform_identity_runtime_schema_readiness_v5()
     OR NOT app.platform_oidc_direct_runtime_schema_readiness_v1() THEN
    RAISE EXCEPTION 'schema compatibility v39 seal verification failed'
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
