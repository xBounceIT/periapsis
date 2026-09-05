-- V48 is the single runtime/release root for the complete 0000-0218
-- inventory. It preserves the immutable V46/V47 migration-convergence
-- evidence while rotating every runtime compatibility edge to this release.
CREATE FUNCTION app.private_schema_compatibility_journal_v48()
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
ALTER FUNCTION app.private_schema_compatibility_journal_v48()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_schema_compatibility_journal_v48()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
       periapsis_auditor;
--> statement-breakpoint

CREATE FUNCTION app.schema_compatibility_v48()
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
  FROM app.private_schema_compatibility_journal_v48() AS journal;
  SELECT count(*)=1 INTO self_catalog_ready
  FROM pg_catalog.pg_proc AS function_row
  JOIN pg_catalog.pg_namespace AS namespace
    ON namespace.oid=function_row.pronamespace
  JOIN pg_catalog.pg_roles AS owner ON owner.oid=function_row.proowner
  JOIN pg_catalog.pg_language AS language ON language.oid=function_row.prolang
  WHERE function_row.oid='app.schema_compatibility_v48()'::regprocedure
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
  IF journal_count=219 AND journal_latest_created_at=1788276517454
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
ALTER FUNCTION app.schema_compatibility_v48() OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.schema_compatibility_v48()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
       periapsis_auditor;
GRANT EXECUTE ON FUNCTION app.schema_compatibility_v48()
  TO periapsis_api,periapsis_worker;
--> statement-breakpoint

-- This digest deliberately covers the complete release catalog, rather than
-- a hand-selected subset. Volatile OIDs and physical storage identifiers are
-- excluded; ownership, ACLs, RLS, columns, enums, constraints, indexes,
-- policies, triggers, role topology and every non-V48 app function source are
-- canonicalized. Historical sealers deliberately changed eight predecessor
-- ACLs, three compatibility configs and four derived private sources; those
-- exact effects are normalized so fresh and rolling installs converge. Login
-- roles are deployment identities rather than migration-owned roles and are
-- excluded, while direct grants from them onto schema objects remain covered.
-- The sealer and public root assert the resulting runtime rotation exactly.
CREATE FUNCTION app.private_release_runtime_dependency_surface_hash_v48()
RETURNS text LANGUAGE sql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app
SET quote_all_identifiers=off SET TimeZone='UTC' SET DateStyle='ISO, YMD'
SET IntervalStyle='postgres' SET extra_float_digits=3 SET bytea_output='hex'
SET standard_conforming_strings=on SET lc_numeric='C'
AS $function$
WITH rotated_function(name) AS (
  VALUES
    ('schema_compatibility_v44'::text),
    ('schema_compatibility_v45'),
    ('schema_compatibility_v46'),
    ('schema_compatibility_v47'),
    ('mfa_policy_administration_schema_readiness_v4'),
    ('mfa_policy_administration_schema_readiness_v6'),
    ('platform_identity_runtime_schema_readiness_v10'),
    ('platform_identity_runtime_schema_readiness_v12'),
    ('platform_oidc_direct_runtime_schema_readiness_v6'),
    ('platform_oidc_direct_runtime_schema_readiness_v8'),
    ('platform_saml_direct_runtime_schema_readiness_v3'),
    ('platform_saml_direct_runtime_schema_readiness_v5'),
    ('platform_tenant_lifecycle_schema_readiness_v1'),
    ('platform_identity_runtime_schema_readiness_v13'),
    ('platform_oidc_direct_runtime_schema_readiness_v9'),
    ('platform_saml_direct_runtime_schema_readiness_v6'),
    ('mfa_policy_administration_schema_readiness_v7'),
    ('ticket_mutation_runtime_schema_readiness_v2'),
    ('sla_trigger_action_runtime_schema_readiness_v1'),
    ('sla_object_event_ingress_schema_readiness_v1'),
    ('platform_local_account_runtime_schema_readiness_v1'),
    ('ticket_bulk_runtime_schema_readiness_v2'),
    ('ticket_export_runtime_schema_readiness_v2'),
    ('alert_dfir_runtime_schema_readiness_v1'),
    ('ticket_metadata_runtime_schema_readiness_v1'),
    ('ticket_watcher_runtime_schema_readiness_v2'),
    ('contacts_portal_schema_readiness_v2'),
    ('notification_schema_readiness_v4'),
    ('tenant_ldap_interactive_auth_schema_readiness_v1'),
    ('ticket_comment_runtime_repair_schema_readiness_v1'),
    ('platform_global_ldap_runtime_schema_readiness_v1'),
    ('federated_authentication_schema_readiness_v1'),
    ('platform_oidc_direct_runtime_schema_readiness_v1'),
    ('platform_saml_direct_runtime_schema_readiness_v2')
),
catalog_entry(kind,key,payload) AS (
  SELECT 'schema'::text,namespace.nspname::text,
    pg_catalog.concat_ws('|',owner.rolname,
      coalesce((
        SELECT string_agg(
          coalesce(grantee.rolname,'PUBLIC') || ':' || acl.privilege_type ||
          ':' || acl.is_grantable::text,
          ',' ORDER BY coalesce(grantee.rolname,'PUBLIC') COLLATE "C",
          acl.privilege_type COLLATE "C",acl.is_grantable
        )
        FROM pg_catalog.aclexplode(coalesce(
          namespace.nspacl,
          pg_catalog.acldefault('n',namespace.nspowner)
        )) AS acl
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
      relation.relreplident::text,coalesce(relation.reloptions::text,''),
      coalesce((
        SELECT string_agg(
          coalesce(grantee.rolname,'PUBLIC') || ':' || acl.privilege_type ||
          ':' || acl.is_grantable::text,
          ',' ORDER BY coalesce(grantee.rolname,'PUBLIC') COLLATE "C",
          acl.privilege_type COLLATE "C",acl.is_grantable
        )
        FROM pg_catalog.aclexplode(coalesce(
          relation.relacl,
          pg_catalog.acldefault(
            CASE WHEN relation.relkind='S' THEN 'S'::"char" ELSE 'r'::"char" END,
            relation.relowner
          )
        )) AS acl
        LEFT JOIN pg_catalog.pg_roles AS grantee ON grantee.oid=acl.grantee
      ),'<empty>'))
  FROM pg_catalog.pg_class AS relation
  JOIN pg_catalog.pg_namespace AS namespace
    ON namespace.oid=relation.relnamespace
  JOIN pg_catalog.pg_roles AS owner ON owner.oid=relation.relowner
  LEFT JOIN pg_catalog.pg_am AS access_method
    ON access_method.oid=relation.relam
  WHERE namespace.nspname='public'
    AND relation.relkind IN ('r','p','S','v','m','f')

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
      ),''),coalesce(attribute.attacl::text,''))
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
  WHERE namespace.nspname='public' AND attribute.attnum>0
    AND NOT attribute.attisdropped
    AND relation.relkind IN ('r','p','v','m','f')

  UNION ALL
  SELECT 'enum',namespace.nspname || '.' || type_row.typname || '.' ||
         enum_row.enumsortorder::text,
    pg_catalog.concat_ws('|',owner.rolname,enum_row.enumlabel)
  FROM pg_catalog.pg_enum AS enum_row
  JOIN pg_catalog.pg_type AS type_row ON type_row.oid=enum_row.enumtypid
  JOIN pg_catalog.pg_namespace AS namespace
    ON namespace.oid=type_row.typnamespace
  JOIN pg_catalog.pg_roles AS owner ON owner.oid=type_row.typowner
  WHERE namespace.nspname='public'

  UNION ALL
  SELECT 'constraint',namespace.nspname || '.' || relation.relname || '.' ||
         constraint_row.conname,
    pg_catalog.concat_ws('|',constraint_row.contype::text,
      constraint_row.condeferrable::text,constraint_row.condeferred::text,
      constraint_row.convalidated::text,
      pg_catalog.pg_get_constraintdef(constraint_row.oid,true))
  FROM pg_catalog.pg_constraint AS constraint_row
  JOIN pg_catalog.pg_class AS relation
    ON relation.oid=constraint_row.conrelid
  JOIN pg_catalog.pg_namespace AS namespace
    ON namespace.oid=relation.relnamespace
  WHERE namespace.nspname='public'

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
  WHERE table_namespace.nspname='public'

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
  WHERE namespace.nspname='public'

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
  WHERE namespace.nspname='public' AND NOT trigger_row.tgisinternal

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
  WHERE namespace.nspname='public'

  UNION ALL
  SELECT 'view',namespace.nspname || '.' || relation.relname,
    pg_catalog.pg_get_viewdef(relation.oid,true)
  FROM pg_catalog.pg_class AS relation
  JOIN pg_catalog.pg_namespace AS namespace
    ON namespace.oid=relation.relnamespace
  WHERE namespace.nspname='public' AND relation.relkind IN ('v','m')

  UNION ALL
  SELECT 'function',namespace.nspname || '.' || function_row.proname || '(' ||
         pg_catalog.pg_get_function_identity_arguments(function_row.oid) || ')',
    pg_catalog.concat_ws('|',owner.rolname,language.lanname,
      function_row.prokind::text,function_row.provolatile::text,
      function_row.prosecdef::text,function_row.proisstrict::text,
      function_row.proleakproof::text,function_row.proparallel::text,
      function_row.pronargs::text,function_row.pronargdefaults::text,
      function_row.provariadic::text,function_row.procost::text,
      function_row.prorows::text,function_row.proretset::text,
      pg_catalog.pg_get_function_arguments(function_row.oid),
      pg_catalog.pg_get_function_result(function_row.oid),
      CASE WHEN function_row.proname IN (
        'private_mfa_policy_administration_schema_readiness_v5',
        'private_platform_identity_runtime_schema_readiness_v11',
        'private_platform_oidc_direct_runtime_schema_readiness_v7',
        'private_platform_saml_direct_runtime_schema_readiness_v4'
      ) THEN '<V48-HISTORICAL-NORMALIZED>' ELSE function_row.prosrc END,
      coalesce(function_row.probin,''),
      CASE WHEN function_row.proname IN (
        'schema_compatibility_v44','schema_compatibility_v45',
        'schema_compatibility_v46','schema_compatibility_v47'
      )
        THEN '<V48-ROTATED>' ELSE coalesce(function_row.proconfig::text,'') END,
      CASE WHEN rotated.name IS NOT NULL THEN '<V48-ROTATED>' ELSE
        coalesce((
          SELECT string_agg(
            coalesce(grantee.rolname,'PUBLIC') || ':' || acl.privilege_type ||
            ':' || acl.is_grantable::text,
            ',' ORDER BY coalesce(grantee.rolname,'PUBLIC') COLLATE "C",
            acl.privilege_type COLLATE "C",acl.is_grantable
          )
          FROM pg_catalog.aclexplode(coalesce(
            function_row.proacl,
            pg_catalog.acldefault('f',function_row.proowner)
          )) AS acl
          LEFT JOIN pg_catalog.pg_roles AS grantee ON grantee.oid=acl.grantee
        ),'<empty>') END)
  FROM pg_catalog.pg_proc AS function_row
  JOIN pg_catalog.pg_namespace AS namespace
    ON namespace.oid=function_row.pronamespace
  JOIN pg_catalog.pg_roles AS owner ON owner.oid=function_row.proowner
  JOIN pg_catalog.pg_language AS language ON language.oid=function_row.prolang
  LEFT JOIN rotated_function AS rotated ON rotated.name=function_row.proname
  WHERE namespace.nspname='app'
    AND function_row.proname NOT LIKE '%\_v48' ESCAPE '\'
    AND function_row.proname<>'seal_schema_compatibility_manifest'

  UNION ALL
  SELECT 'role',role.rolname,
    pg_catalog.concat_ws('|',role.rolsuper::text,role.rolinherit::text,
      role.rolcreaterole::text,role.rolcreatedb::text,role.rolcanlogin::text,
      role.rolreplication::text,role.rolbypassrls::text,
      role.rolconnlimit::text,coalesce(role.rolconfig::text,''))
  FROM pg_catalog.pg_roles AS role
  WHERE role.rolname LIKE 'periapsis\_%' ESCAPE '\'
    AND role.rolname NOT LIKE '%\_login' ESCAPE '\'

  UNION ALL
  SELECT 'membership',granted.rolname || '->' || member.rolname,
    pg_catalog.concat_ws('|',grantor.rolname,membership.admin_option::text)
  FROM pg_catalog.pg_auth_members AS membership
  JOIN pg_catalog.pg_roles AS granted ON granted.oid=membership.roleid
  JOIN pg_catalog.pg_roles AS member ON member.oid=membership.member
  JOIN pg_catalog.pg_roles AS grantor ON grantor.oid=membership.grantor
  WHERE (granted.rolname LIKE 'periapsis\_%' ESCAPE '\'
     OR member.rolname LIKE 'periapsis\_%' ESCAPE '\')
    AND granted.rolname NOT LIKE '%\_login' ESCAPE '\'
    AND member.rolname NOT LIKE '%\_login' ESCAPE '\'

  UNION ALL
  SELECT 'default_acl',owner.rolname || ':' || coalesce(namespace.nspname,'') ||
         ':' || default_acl.defaclobjtype::text,
    coalesce((
      SELECT string_agg(
        coalesce(grantee.rolname,'PUBLIC') || ':' || acl.privilege_type ||
        ':' || acl.is_grantable::text,
        ',' ORDER BY coalesce(grantee.rolname,'PUBLIC') COLLATE "C",
        acl.privilege_type COLLATE "C",acl.is_grantable
      )
      FROM pg_catalog.aclexplode(default_acl.defaclacl) AS acl
      LEFT JOIN pg_catalog.pg_roles AS grantee ON grantee.oid=acl.grantee
    ),'<empty>')
  FROM pg_catalog.pg_default_acl AS default_acl
  JOIN pg_catalog.pg_roles AS owner ON owner.oid=default_acl.defaclrole
  LEFT JOIN pg_catalog.pg_namespace AS namespace
    ON namespace.oid=default_acl.defaclnamespace
  WHERE owner.rolname LIKE 'periapsis\_%' ESCAPE '\'
    AND owner.rolname NOT LIKE '%\_login' ESCAPE '\'
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
ALTER FUNCTION app.private_release_runtime_dependency_surface_hash_v48()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION
  app.private_release_runtime_dependency_surface_hash_v48()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
       periapsis_auditor;
--> statement-breakpoint

-- Keep the ticket-export feature probe's data and privilege assertions while
-- rebasing the one helper definition changed deliberately by 0209.
DO $rebase_ticket_export_readiness_v48$
DECLARE
  definition text;
  readiness_definition_hash text;
  helper_source_hash text;
  helper_definition_hash text;
BEGIN
  SELECT pg_catalog.pg_get_functiondef(function_row.oid),
         pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           pg_catalog.pg_get_functiondef(function_row.oid),'UTF8'
         )),'hex')
    INTO STRICT definition,readiness_definition_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid=
    'app.ticket_export_runtime_schema_readiness_v2()'::regprocedure;
  SELECT pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8')),'hex'),
         pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           pg_catalog.pg_get_functiondef(function_row.oid),'UTF8'
         )),'hex')
    INTO STRICT helper_source_hash,helper_definition_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid=
    'app.private_ticket_export_require_human_v2(jsonb,uuid,public.ticket_aggregate_kind,text,text)'::regprocedure;
  IF readiness_definition_hash<>
       'd4961126fd47ff1a22c6b3ed5c1d645728016eaf9c5fd55ed675c2fa15061ca0'
     OR helper_source_hash<>
       'fee31ac38c6d410b9dcfa39bf1327acfaea350c2c429aa4ad20f9cc647bd9d29'
     OR helper_definition_hash<>
       'a13c11deff0ed2817e99c176fde78a9ec593566893c22b8e86cf68dcc3157b6e'
     OR pg_catalog.strpos(definition,
       'acb19d1ff0e2b4d9f56f09a3ffc5d000731a9b278708e9b8382c9ba39a453a54'
     )=0 THEN
    RAISE EXCEPTION 'ticket export readiness v2 drifted before V48 rebase'
      USING ERRCODE='55000';
  END IF;
  definition:=pg_catalog.replace(definition,
    'acb19d1ff0e2b4d9f56f09a3ffc5d000731a9b278708e9b8382c9ba39a453a54',
    helper_definition_hash);
  EXECUTE definition;
END;
$rebase_ticket_export_readiness_v48$;
--> statement-breakpoint

CREATE FUNCTION app.private_release_runtime_schema_readiness_v48()
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
     OR NOT app.private_v47_migration_convergence_schema_readiness_v1()
     OR app.private_release_runtime_dependency_surface_hash_v48()<>
       'c22f7bce63c255e7447dd4eb3454da4a14de5afc6fc317f4c8fcb63732a912e3' THEN
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
ALTER FUNCTION app.private_release_runtime_schema_readiness_v48()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_release_runtime_schema_readiness_v48()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
       periapsis_auditor;
--> statement-breakpoint

CREATE FUNCTION app.release_runtime_schema_readiness_v48()
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app AS $function$
DECLARE current_count bigint;
BEGIN
  SELECT compatibility.applied_count INTO current_count
  FROM app.schema_compatibility_v48() AS compatibility;
  RETURN current_count=219
    AND app.private_release_runtime_schema_readiness_v48()
    AND (
      SELECT count(*)=4 AND coalesce(bool_and(
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
      FROM (VALUES
        ('schema_compatibility_v44'),('schema_compatibility_v45'),
        ('schema_compatibility_v46'),('schema_compatibility_v47')
      ) AS predecessor(function_name)
      LEFT JOIN pg_catalog.pg_namespace AS namespace
        ON namespace.nspname='app'
      LEFT JOIN pg_catalog.pg_proc AS function_row
        ON function_row.pronamespace=namespace.oid
       AND function_row.proname=predecessor.function_name
       AND function_row.pronargs=0
      LEFT JOIN pg_catalog.pg_roles AS owner
        ON owner.oid=function_row.proowner
    )
    AND NOT EXISTS (
      SELECT 1
      FROM (VALUES
        ('mfa_policy_administration_schema_readiness_v4'),
        ('mfa_policy_administration_schema_readiness_v6'),
        ('platform_identity_runtime_schema_readiness_v10'),
        ('platform_identity_runtime_schema_readiness_v12'),
        ('platform_oidc_direct_runtime_schema_readiness_v6'),
        ('platform_oidc_direct_runtime_schema_readiness_v8'),
        ('platform_saml_direct_runtime_schema_readiness_v3'),
        ('platform_saml_direct_runtime_schema_readiness_v5'),
        ('platform_tenant_lifecycle_schema_readiness_v1'),
        ('platform_identity_runtime_schema_readiness_v13'),
        ('platform_oidc_direct_runtime_schema_readiness_v9'),
        ('platform_saml_direct_runtime_schema_readiness_v6'),
        ('mfa_policy_administration_schema_readiness_v7'),
        ('ticket_mutation_runtime_schema_readiness_v2'),
        ('sla_trigger_action_runtime_schema_readiness_v1'),
        ('sla_object_event_ingress_schema_readiness_v1'),
        ('platform_local_account_runtime_schema_readiness_v1'),
        ('ticket_bulk_runtime_schema_readiness_v2'),
        ('ticket_export_runtime_schema_readiness_v2'),
        ('alert_dfir_runtime_schema_readiness_v1'),
        ('ticket_metadata_runtime_schema_readiness_v1'),
        ('ticket_watcher_runtime_schema_readiness_v2'),
        ('contacts_portal_schema_readiness_v2'),
        ('notification_schema_readiness_v4'),
        ('tenant_ldap_interactive_auth_schema_readiness_v1'),
        ('ticket_comment_runtime_repair_schema_readiness_v1'),
        ('platform_global_ldap_runtime_schema_readiness_v1'),
        ('federated_authentication_schema_readiness_v1'),
        ('platform_oidc_direct_runtime_schema_readiness_v1'),
        ('platform_saml_direct_runtime_schema_readiness_v2')
      ) AS retired(function_name)
      LEFT JOIN pg_catalog.pg_namespace AS namespace
        ON namespace.nspname='app'
      LEFT JOIN pg_catalog.pg_proc AS function_row
        ON function_row.pronamespace=namespace.oid
       AND function_row.proname=retired.function_name
       AND function_row.pronargs=0
      WHERE function_row.oid IS NULL OR EXISTS (
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
            retired.function_name<>'notification_schema_readiness_v4'
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
ALTER FUNCTION app.release_runtime_schema_readiness_v48()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.release_runtime_schema_readiness_v48()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
       periapsis_auditor;
GRANT EXECUTE ON FUNCTION app.release_runtime_schema_readiness_v48()
  TO periapsis_api,periapsis_worker;
--> statement-breakpoint

-- Feature-specific production probes all require the sealed V48 release root.
-- The three historically stale federation probes are intentionally rebuilt
-- from the global exact surface; the other wrappers retain their existing
-- feature/data checks behind the new release gate.
CREATE FUNCTION app.federated_authentication_schema_readiness_v48()
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app AS $function$
BEGIN RETURN app.release_runtime_schema_readiness_v48();
EXCEPTION WHEN undefined_table OR undefined_function OR insufficient_privilege
  OR invalid_schema_name OR cardinality_violation OR data_exception THEN
  RETURN false;
END;
$function$;
CREATE FUNCTION app.platform_oidc_direct_runtime_schema_readiness_v48()
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app AS $function$
BEGIN RETURN app.release_runtime_schema_readiness_v48();
EXCEPTION WHEN undefined_table OR undefined_function OR insufficient_privilege
  OR invalid_schema_name OR cardinality_violation OR data_exception THEN
  RETURN false;
END;
$function$;
CREATE FUNCTION app.platform_saml_direct_runtime_schema_readiness_v48()
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app AS $function$
BEGIN RETURN app.release_runtime_schema_readiness_v48();
EXCEPTION WHEN undefined_table OR undefined_function OR insufficient_privilege
  OR invalid_schema_name OR cardinality_violation OR data_exception THEN
  RETURN false;
END;
$function$;
CREATE FUNCTION app.platform_local_account_runtime_schema_readiness_v48()
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app AS $function$
BEGIN RETURN app.release_runtime_schema_readiness_v48()
  AND app.platform_local_account_runtime_schema_readiness_v1();
EXCEPTION WHEN undefined_table OR undefined_function OR insufficient_privilege
  OR invalid_schema_name OR cardinality_violation OR data_exception THEN
  RETURN false;
END;
$function$;
CREATE FUNCTION app.sla_trigger_action_runtime_schema_readiness_v48()
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app AS $function$
BEGIN RETURN app.release_runtime_schema_readiness_v48()
  AND app.sla_trigger_action_runtime_schema_readiness_v1();
EXCEPTION WHEN undefined_table OR undefined_function OR insufficient_privilege
  OR invalid_schema_name OR cardinality_violation OR data_exception THEN
  RETURN false;
END;
$function$;
CREATE FUNCTION app.sla_object_event_ingress_schema_readiness_v48()
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app AS $function$
BEGIN RETURN app.release_runtime_schema_readiness_v48()
  AND app.sla_object_event_ingress_schema_readiness_v1();
EXCEPTION WHEN undefined_table OR undefined_function OR insufficient_privilege
  OR invalid_schema_name OR cardinality_violation OR data_exception THEN
  RETURN false;
END;
$function$;
CREATE FUNCTION app.ticket_bulk_runtime_schema_readiness_v48()
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app AS $function$
BEGIN RETURN app.release_runtime_schema_readiness_v48()
  AND app.ticket_bulk_runtime_schema_readiness_v2();
EXCEPTION WHEN undefined_table OR undefined_function OR insufficient_privilege
  OR invalid_schema_name OR cardinality_violation OR data_exception THEN
  RETURN false;
END;
$function$;
CREATE FUNCTION app.ticket_export_runtime_schema_readiness_v48()
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app AS $function$
BEGIN RETURN app.release_runtime_schema_readiness_v48()
  AND app.ticket_export_runtime_schema_readiness_v2();
EXCEPTION WHEN undefined_table OR undefined_function OR insufficient_privilege
  OR invalid_schema_name OR cardinality_violation OR data_exception THEN
  RETURN false;
END;
$function$;
CREATE FUNCTION app.ticket_metadata_runtime_schema_readiness_v48()
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app AS $function$
BEGIN RETURN app.release_runtime_schema_readiness_v48()
  AND app.ticket_metadata_runtime_schema_readiness_v1();
EXCEPTION WHEN undefined_table OR undefined_function OR insufficient_privilege
  OR invalid_schema_name OR cardinality_violation OR data_exception THEN
  RETURN false;
END;
$function$;

ALTER FUNCTION app.federated_authentication_schema_readiness_v48()
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.platform_oidc_direct_runtime_schema_readiness_v48()
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.platform_saml_direct_runtime_schema_readiness_v48()
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.platform_local_account_runtime_schema_readiness_v48()
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.sla_trigger_action_runtime_schema_readiness_v48()
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.sla_object_event_ingress_schema_readiness_v48()
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.ticket_bulk_runtime_schema_readiness_v48()
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.ticket_export_runtime_schema_readiness_v48()
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.ticket_metadata_runtime_schema_readiness_v48()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION
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
GRANT EXECUTE ON FUNCTION
  app.federated_authentication_schema_readiness_v48(),
  app.platform_oidc_direct_runtime_schema_readiness_v48(),
  app.platform_saml_direct_runtime_schema_readiness_v48(),
  app.platform_local_account_runtime_schema_readiness_v48(),
  app.ticket_metadata_runtime_schema_readiness_v48()
TO periapsis_api;
GRANT EXECUTE ON FUNCTION
  app.ticket_bulk_runtime_schema_readiness_v48(),
  app.ticket_export_runtime_schema_readiness_v48()
TO periapsis_api,periapsis_worker;
GRANT EXECUTE ON FUNCTION
  app.sla_trigger_action_runtime_schema_readiness_v48(),
  app.sla_object_event_ingress_schema_readiness_v48()
TO periapsis_worker;
--> statement-breakpoint

-- These two predecessor probes are owned by the intentionally isolated SLA
-- readiness role. A migrator-owned sealer cannot revoke grants issued by that
-- owner, so this narrowly scoped helper performs only the retirement step.
CREATE FUNCTION app.private_rotate_sla_readiness_v48()
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public,app AS $function$
BEGIN
  REVOKE ALL ON FUNCTION
    app.sla_trigger_action_runtime_schema_readiness_v1(),
    app.sla_object_event_ingress_schema_readiness_v1()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
    periapsis_auditor;
END;
$function$;
ALTER FUNCTION app.private_rotate_sla_readiness_v48()
  OWNER TO periapsis_sla_readiness_owner;
REVOKE ALL ON FUNCTION app.private_rotate_sla_readiness_v48()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
    periapsis_auditor;
GRANT EXECUTE ON FUNCTION app.private_rotate_sla_readiness_v48()
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
  IF p_expected_count IS DISTINCT FROM 219
     OR p_expected_latest_created_at IS DISTINCT FROM 1788276517454
     OR p_expected_latest_hash !~ '^[0-9a-f]{64}$'
     OR p_expected_migration_fingerprint !~
       '^[0-9]+@[0-9a-f]{64}(:[0-9]+@[0-9a-f]{64}){218}$' THEN
    RAISE EXCEPTION 'schema compatibility v48 seal input is invalid'
      USING ERRCODE='55000';
  END IF;
  SELECT journal.applied_count,journal.latest_created_at,journal.latest_rows,
         journal.latest_hash,journal.migration_fingerprint
    INTO journal_count,journal_latest_created_at,journal_latest_rows,
         journal_latest_hash,journal_fingerprint
  FROM app.private_schema_compatibility_journal_v48() AS journal;
  IF ROW(journal_count,journal_latest_created_at,journal_latest_hash,
         journal_fingerprint) IS DISTINCT FROM
     ROW(p_expected_count,p_expected_latest_created_at,p_expected_latest_hash,
         p_expected_migration_fingerprint)
     OR journal_latest_rows<>1
     OR NOT app.private_release_runtime_schema_readiness_v48() THEN
    RAISE EXCEPTION 'schema compatibility v48 pre-seal verification failed'
      USING ERRCODE='55000';
  END IF;

  SELECT coalesce((
    SELECT compatibility.applied_count=219
    FROM app.schema_compatibility_v48() AS compatibility
  ),false) INTO was_sealed;

  IF NOT was_sealed THEN
    EXECUTE pg_catalog.format(
      'ALTER FUNCTION app.schema_compatibility_v48() SET app.schema_compatibility_fingerprint = %L',
      p_expected_migration_fingerprint
    );
    ALTER FUNCTION app.schema_compatibility_v47()
      SET app.schema_compatibility_fingerprint='RETIRED';
    ALTER FUNCTION app.schema_compatibility_v46()
      SET app.schema_compatibility_fingerprint='RETIRED';
    ALTER FUNCTION app.schema_compatibility_v45()
      SET app.schema_compatibility_fingerprint='RETIRED';
    ALTER FUNCTION app.schema_compatibility_v44()
      SET app.schema_compatibility_fingerprint='RETIRED';
    REVOKE ALL ON FUNCTION
      app.schema_compatibility_v44(),
      app.schema_compatibility_v45(),
      app.schema_compatibility_v46(),
      app.schema_compatibility_v47()
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
      app.platform_saml_direct_runtime_schema_readiness_v2()
    FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
      periapsis_auditor;
    PERFORM app.private_rotate_sla_readiness_v48();
    REVOKE ALL ON FUNCTION app.notification_schema_readiness_v4()
    FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
      periapsis_auditor;
  END IF;

  SELECT compatibility.applied_count INTO sealed_count
  FROM app.schema_compatibility_v48() AS compatibility;
  IF NOT was_sealed THEN
    IF sealed_count<>219
       OR NOT app.private_release_runtime_schema_readiness_v48() THEN
      RAISE EXCEPTION 'schema compatibility v48 rotation verification failed'
        USING ERRCODE='55000';
    END IF;
    RETURN;
  END IF;
  IF sealed_count<>219
     OR NOT app.private_release_runtime_schema_readiness_v48()
     OR NOT app.release_runtime_schema_readiness_v48()
     OR NOT app.federated_authentication_schema_readiness_v48()
     OR NOT app.platform_oidc_direct_runtime_schema_readiness_v48()
     OR NOT app.platform_saml_direct_runtime_schema_readiness_v48()
     OR NOT app.platform_local_account_runtime_schema_readiness_v48()
     OR NOT app.sla_trigger_action_runtime_schema_readiness_v48()
     OR NOT app.sla_object_event_ingress_schema_readiness_v48()
     OR NOT app.ticket_bulk_runtime_schema_readiness_v48()
     OR NOT app.ticket_export_runtime_schema_readiness_v48()
     OR NOT app.ticket_metadata_runtime_schema_readiness_v48() THEN
    RAISE EXCEPTION 'schema compatibility v48 post-seal verification failed'
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
