-- V34 seals the disabled-only platform-provider tenant-binding boundary.  V33
-- remains the exact rolling predecessor at migration 0158; V32 is retired.
CREATE FUNCTION app.schema_compatibility_v34()
RETURNS TABLE(
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
  journal_count bigint;
  journal_latest_created_at bigint;
  latest_rows bigint;
  journal_fingerprint text;
  self_catalog_ready boolean;
BEGIN
  EXECUTE $query$
    SELECT count(*)::bigint, max(migration.created_at)::bigint,
           count(*) FILTER (
             WHERE migration.created_at = 1787936037593
           )::bigint,
           string_agg(
             migration.created_at::text || '@' || lower(migration.hash::text),
             ':' ORDER BY migration.created_at, migration.id
           )
    FROM drizzle.__drizzle_migrations AS migration
  $query$ INTO journal_count, journal_latest_created_at, latest_rows,
                journal_fingerprint;

  SELECT count(*) = 1 INTO self_catalog_ready
  FROM pg_catalog.pg_proc AS function
  JOIN pg_catalog.pg_namespace AS namespace
    ON namespace.oid = function.pronamespace
  JOIN pg_catalog.pg_roles AS owner ON owner.oid = function.proowner
  JOIN pg_catalog.pg_language AS language ON language.oid = function.prolang
  WHERE function.oid = 'app.schema_compatibility_v34()'::regprocedure
    AND namespace.nspname = 'app'
    AND owner.rolname = 'periapsis_migrator'
    AND language.lanname = 'plpgsql'
    AND function.prokind = 'f'
    AND function.provolatile = 's'
    AND function.prosecdef
    AND NOT function.proisstrict
    AND NOT function.proleakproof
    AND function.proparallel = 'u'
    AND function.pronargs = 0
    AND function.proconfig IS NOT DISTINCT FROM ARRAY[
      'search_path=pg_catalog',
      'app.schema_compatibility_fingerprint=' || journal_fingerprint
    ]::text[]
    AND pg_catalog.pg_get_function_result(function.oid) =
      'TABLE(applied_count bigint, latest_created_at bigint, latest_hash text, migration_fingerprint text)'
    AND (
      SELECT count(*) = 3
         AND coalesce(bool_and(
           function_acl.grantor = function.proowner
           AND function_acl.grantee IN (
             function.proowner,
             (SELECT role.oid FROM pg_catalog.pg_roles AS role
              WHERE role.rolname = 'periapsis_api'),
             (SELECT role.oid FROM pg_catalog.pg_roles AS role
              WHERE role.rolname = 'periapsis_worker')
           )
           AND function_acl.privilege_type = 'EXECUTE'
           AND NOT function_acl.is_grantable
         ), false)
      FROM pg_catalog.aclexplode(coalesce(
        function.proacl, pg_catalog.acldefault('f', function.proowner)
      )) AS function_acl
    );

  IF journal_count = 163
     AND journal_latest_created_at = 1787936037593
     AND latest_rows = 1
     AND self_catalog_ready
     AND journal_fingerprint = current_setting(
       'app.schema_compatibility_fingerprint', true
     ) THEN
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
$function$;
ALTER FUNCTION app.schema_compatibility_v34() OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.schema_compatibility_v34()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,
  periapsis_sla_api_owner, periapsis_sla_worker_owner,
  periapsis_sla_readiness_owner, periapsis_ticket_saved_view_owner,
  periapsis_ticket_attribution_owner,
  periapsis_ticket_sla_projection_owner;
GRANT EXECUTE ON FUNCTION app.schema_compatibility_v34()
TO periapsis_api, periapsis_worker;
--> statement-breakpoint

-- V32 already self-retires when the journal moves beyond the exact 0158
-- checkpoint. Normalize its seal so fresh and rolling installs converge on
-- the same catalog without replacing the frozen predecessor implementation.
ALTER FUNCTION app.schema_compatibility_v32()
  SET app.schema_compatibility_fingerprint = 'RETIRED';
REVOKE ALL ON FUNCTION app.schema_compatibility_v32()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,
  periapsis_sla_api_owner, periapsis_sla_worker_owner,
  periapsis_sla_readiness_owner, periapsis_ticket_saved_view_owner,
  periapsis_ticket_attribution_owner,
  periapsis_ticket_sla_projection_owner;
--> statement-breakpoint

-- Hash the complete owner-only binding boundary as well as the five public
-- ABIs.  The shared runtime-surface hash catches grant drift; this digest also
-- catches a replaced guard, a moved trigger, or a dropped key/constraint that
-- would otherwise remain invisible because the protected objects have no
-- runtime ACL.
CREATE FUNCTION app.private_tenant_platform_identity_binding_surface_hash_v1()
RETURNS text
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
  WITH protected_relation(relation_oid) AS (
    VALUES
      ('public.tenant_auth_provider_login_keys'::regclass),
      ('public.tenant_auth_provider_bindings'::regclass),
      ('public.tenant_platform_auth_provider_bindings'::regclass),
      ('public.tenant_platform_identity_provider_access_epochs'::regclass),
      ('public.tenant_platform_identity_binding_commands'::regclass),
      ('public.platform_auth_providers'::regclass),
      ('public.tenants'::regclass)
  ),
  protected_function(function_signature) AS (
    VALUES
      ('app.guard_tenant_auth_provider_login_key_v1()'),
      ('app.private_create_tenant_auth_provider_login_claim_v1(uuid,text,uuid,text)'),
      ('app.private_rename_tenant_auth_provider_login_claim_v1(uuid,text,uuid,text,text)'),
      ('app.guard_tenant_auth_provider_login_claim_child_v1()'),
      ('app.guard_tenant_auth_provider_binding_v1()'),
      ('app.guard_tenant_platform_auth_provider_binding_v1()'),
      ('app.guard_platform_auth_provider_binding_dependency_v1()'),
      ('app.guard_tenant_platform_identity_provider_access_epoch_v1()'),
      ('app.guard_tenant_platform_identity_binding_command_v1()'),
      ('app.guard_tenant_platform_identity_binding_tenant_projection_v1()'),
      ('app.private_tenant_platform_auth_provider_binding_document_v1(uuid)'),
      ('app.private_append_platform_identity_binding_tenant_audit_v1(uuid,uuid,uuid,uuid,uuid,text,uuid,uuid,uuid,inet,text,text,text,jsonb,jsonb)'),
      ('app.list_tenant_platform_auth_provider_bindings_v1(uuid,uuid,text,uuid,integer,boolean)'),
      ('app.get_tenant_platform_auth_provider_binding_v1(uuid,uuid,uuid,text)'),
      ('app.create_tenant_platform_auth_provider_binding_v1(uuid,uuid,uuid,uuid,uuid,text,integer,bytea,bytea,uuid,uuid,uuid,uuid,inet,text,text,text)'),
      ('app.update_tenant_platform_auth_provider_binding_v1(uuid,uuid,uuid,bigint,integer,text,integer,uuid,uuid,uuid,uuid,inet,text,text,text)'),
      ('app.archive_tenant_platform_auth_provider_binding_v1(uuid,uuid,uuid,bigint,integer,uuid,uuid,uuid,uuid,inet,text,text,text)'),
      ('app.create_tenant_auth_provider_binding_v1(uuid,uuid,text,boolean,integer,uuid,uuid,inet,text,text)'),
      ('app.create_tenant_auth_provider_binding_v2(bytea,uuid,text,boolean,integer,uuid,uuid,uuid,inet,text,text)'),
      ('app.update_tenant_auth_provider_binding_v1(uuid,integer,text,boolean,integer,uuid,uuid,inet,text,text)')
  ),
  surface(kind, identity, definition) AS (
    SELECT 'relation', relation_row.oid::regclass::text,
           concat_ws('|', owner.rolname, relation_row.relkind::text,
             relation_row.relpersistence::text,
             relation_row.relreplident::text,
             relation_row.relispartition::text,
             coalesce(relation_row.reloptions::text, ''),
             coalesce(tablespace.spcname, ''),
             coalesce(access_method.amname, ''),
             relation_row.relrowsecurity::text,
             relation_row.relforcerowsecurity::text,
             coalesce(relation_row.relacl::text, ''))
    FROM protected_relation AS expected
    JOIN pg_catalog.pg_class AS relation_row
      ON relation_row.oid = expected.relation_oid
    JOIN pg_catalog.pg_roles AS owner ON owner.oid = relation_row.relowner
    LEFT JOIN pg_catalog.pg_tablespace AS tablespace
      ON tablespace.oid = relation_row.reltablespace
    LEFT JOIN pg_catalog.pg_am AS access_method
      ON access_method.oid = relation_row.relam
    UNION ALL
    SELECT 'column',
           column_row.attrelid::regclass::text || '.' || column_row.attname,
           concat_ws('|',
             pg_catalog.format_type(column_row.atttypid, column_row.atttypmod),
             column_row.attnotnull::text, column_row.attidentity::text,
             column_row.attgenerated::text,
             coalesce(collation_namespace.nspname || '.' ||
               collation_row.collname, ''),
             column_row.attislocal::text,
             column_row.attinhcount::text,
             column_row.attstorage::text,
             column_row.attcompression::text,
             coalesce(pg_catalog.pg_get_expr(
               default_row.adbin, default_row.adrelid
             ), ''),
             coalesce(column_row.attacl::text, ''))
    FROM protected_relation AS expected
    JOIN pg_catalog.pg_attribute AS column_row
      ON column_row.attrelid = expected.relation_oid
     AND column_row.attnum > 0 AND NOT column_row.attisdropped
    LEFT JOIN pg_catalog.pg_attrdef AS default_row
      ON default_row.adrelid = column_row.attrelid
     AND default_row.adnum = column_row.attnum
    LEFT JOIN pg_catalog.pg_collation AS collation_row
      ON collation_row.oid = column_row.attcollation
    LEFT JOIN pg_catalog.pg_namespace AS collation_namespace
      ON collation_namespace.oid = collation_row.collnamespace
    UNION ALL
    SELECT 'constraint',
           constraint_row.conrelid::regclass::text || '.' ||
             constraint_row.conname,
           concat_ws('|', constraint_row.contype::text,
             constraint_row.condeferrable::text,
             constraint_row.condeferred::text,
             constraint_row.convalidated::text,
             constraint_row.confrelid::regclass::text,
             pg_catalog.pg_get_constraintdef(constraint_row.oid, false))
    FROM protected_relation AS expected
    JOIN pg_catalog.pg_constraint AS constraint_row
      ON constraint_row.conrelid = expected.relation_oid
    UNION ALL
    SELECT 'index', index_row.indexrelid::regclass::text,
           pg_catalog.pg_get_indexdef(index_row.indexrelid)
    FROM protected_relation AS expected
    JOIN pg_catalog.pg_index AS index_row
      ON index_row.indrelid = expected.relation_oid
    UNION ALL
    SELECT 'trigger',
           trigger_row.tgrelid::regclass::text || '.' || trigger_row.tgname,
           concat_ws('|', trigger_row.tgenabled::text,
             trigger_row.tgdeferrable::text,
             trigger_row.tginitdeferred::text,
             pg_catalog.pg_get_triggerdef(trigger_row.oid, false))
    FROM protected_relation AS expected
    JOIN pg_catalog.pg_trigger AS trigger_row
      ON trigger_row.tgrelid = expected.relation_oid
     AND NOT trigger_row.tgisinternal
    UNION ALL
    SELECT 'rule',
           rule_row.ev_class::regclass::text || '.' || rule_row.rulename,
           pg_catalog.pg_get_ruledef(rule_row.oid, false)
    FROM protected_relation AS expected
    JOIN pg_catalog.pg_rewrite AS rule_row
      ON rule_row.ev_class = expected.relation_oid
     AND rule_row.rulename <> '_RETURN'
    UNION ALL
    SELECT 'policy',
           policy_row.polrelid::regclass::text || '.' || policy_row.polname,
           concat_ws('|', policy_row.polcmd::text,
             policy_row.polpermissive::text,
             coalesce((
               SELECT string_agg(
                 coalesce(role.rolname, 'PUBLIC'), ','
                 ORDER BY coalesce(role.rolname, 'PUBLIC')
               )
               FROM unnest(policy_row.polroles) AS policy_role(role_oid)
               LEFT JOIN pg_catalog.pg_roles AS role
                 ON role.oid = policy_role.role_oid
             ), ''),
             coalesce(pg_catalog.pg_get_expr(
               policy_row.polqual, policy_row.polrelid
             ), ''),
             coalesce(pg_catalog.pg_get_expr(
               policy_row.polwithcheck, policy_row.polrelid
             ), ''))
    FROM protected_relation AS expected
    JOIN pg_catalog.pg_policy AS policy_row
      ON policy_row.polrelid = expected.relation_oid
    UNION ALL
    SELECT 'inheritance',
           inheritance.inhrelid::regclass::text || '->' ||
             inheritance.inhparent::regclass::text,
           concat_ws('|', inheritance.inhseqno::text,
             inheritance.inhdetachpending::text)
    FROM protected_relation AS expected
    JOIN pg_catalog.pg_inherits AS inheritance
      ON inheritance.inhrelid = expected.relation_oid
      OR inheritance.inhparent = expected.relation_oid
    UNION ALL
    SELECT 'function', function_row.oid::regprocedure::text,
           concat_ws('|', owner.rolname, language.lanname,
             function_row.provolatile::text, function_row.prosecdef::text,
             coalesce(function_row.proconfig::text, ''),
             coalesce(function_row.proacl::text, ''),
             pg_catalog.pg_get_functiondef(function_row.oid))
    FROM protected_function AS expected
    JOIN pg_catalog.pg_proc AS function_row
      ON function_row.oid = pg_catalog.to_regprocedure(expected.function_signature)
    JOIN pg_catalog.pg_roles AS owner ON owner.oid = function_row.proowner
    JOIN pg_catalog.pg_language AS language
      ON language.oid = function_row.prolang
  )
  SELECT encode(sha256(convert_to(string_agg(
    surface.kind || ':' || surface.identity || ':' || surface.definition,
    E'\n' ORDER BY surface.kind, surface.identity
  ), 'UTF8')), 'hex')
  FROM surface;
$function$;
ALTER FUNCTION app.private_tenant_platform_identity_binding_surface_hash_v1()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION
  app.private_tenant_platform_identity_binding_surface_hash_v1()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,
  periapsis_sla_api_owner, periapsis_sla_worker_owner,
  periapsis_sla_readiness_owner, periapsis_ticket_saved_view_owner,
  periapsis_ticket_attribution_owner,
  periapsis_ticket_sla_projection_owner;
--> statement-breakpoint

CREATE FUNCTION app.tenant_platform_identity_binding_schema_readiness_v1()
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  current_count bigint;
  predecessor_count bigint;
  protected_table_count integer;
  policy_count integer;
  direct_table_privilege_count integer;
  non_owner_table_acl_count integer;
  column_acl_count integer;
  protected_function_count integer;
  protected_function_acl_mismatch_count integer;
  private_function_count integer;
  private_function_acl_mismatch_count integer;
  expected_constraint_count integer;
  deferred_guard_count integer;
  guard_trigger_count integer;
  native_writer_count integer;
BEGIN
  SELECT compatibility.applied_count INTO current_count
  FROM app.schema_compatibility_v34() AS compatibility;
  SELECT compatibility.applied_count INTO predecessor_count
  FROM app.schema_compatibility_v33() AS compatibility;

  SELECT count(*)::integer INTO protected_table_count
  FROM pg_catalog.pg_class AS table_row
  JOIN pg_catalog.pg_namespace AS namespace
    ON namespace.oid = table_row.relnamespace
  JOIN pg_catalog.pg_roles AS owner ON owner.oid = table_row.relowner
  WHERE namespace.nspname = 'public'
    AND table_row.relname = ANY (ARRAY[
      'tenant_auth_provider_login_keys',
      'tenant_platform_auth_provider_bindings',
      'tenant_platform_identity_provider_access_epochs',
      'tenant_platform_identity_binding_commands'
    ]::name[])
    AND table_row.relkind = 'r'
    AND table_row.relrowsecurity
    AND table_row.relforcerowsecurity
    AND owner.rolname = 'periapsis_migrator';

  SELECT count(*)::integer INTO policy_count
  FROM pg_catalog.pg_policy AS policy
  WHERE policy.polrelid = ANY (ARRAY[
    'public.tenant_auth_provider_login_keys'::regclass,
    'public.tenant_platform_auth_provider_bindings'::regclass,
    'public.tenant_platform_identity_provider_access_epochs'::regclass,
    'public.tenant_platform_identity_binding_commands'::regclass
  ]::oid[]);

  SELECT count(*)::integer INTO direct_table_privilege_count
  FROM (VALUES
    ('tenant_auth_provider_login_keys'),
    ('tenant_platform_auth_provider_bindings'),
    ('tenant_platform_identity_provider_access_epochs'),
    ('tenant_platform_identity_binding_commands')
  ) AS protected_table(table_name)
  CROSS JOIN (VALUES
    ('periapsis_api'), ('periapsis_worker'), ('periapsis_notifier'),
    ('periapsis_auditor'), ('periapsis_audit_reader_owner'),
    ('periapsis_notification_dispatch_owner'), ('periapsis_sla_api_owner'),
    ('periapsis_sla_worker_owner'), ('periapsis_sla_readiness_owner'),
    ('periapsis_ticket_saved_view_owner'),
    ('periapsis_ticket_attribution_owner'),
    ('periapsis_ticket_sla_projection_owner')
  ) AS runtime_role(role_name)
  WHERE has_table_privilege(
    runtime_role.role_name,
    format('public.%I', protected_table.table_name),
    'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
  );

  SELECT count(*)::integer INTO non_owner_table_acl_count
  FROM pg_catalog.pg_class AS table_row
  JOIN pg_catalog.pg_namespace AS namespace
    ON namespace.oid = table_row.relnamespace
  CROSS JOIN LATERAL pg_catalog.aclexplode(
    coalesce(table_row.relacl, pg_catalog.acldefault('r', table_row.relowner))
  ) AS table_acl
  WHERE namespace.nspname = 'public'
    AND table_row.relname = ANY (ARRAY[
      'tenant_auth_provider_login_keys',
      'tenant_platform_auth_provider_bindings',
      'tenant_platform_identity_provider_access_epochs',
      'tenant_platform_identity_binding_commands'
    ]::name[])
    AND table_acl.grantee <> table_row.relowner;

  SELECT count(*)::integer INTO column_acl_count
  FROM pg_catalog.pg_attribute AS column_row
  WHERE column_row.attrelid = ANY (ARRAY[
    'public.tenant_auth_provider_login_keys'::regclass,
    'public.tenant_platform_auth_provider_bindings'::regclass,
    'public.tenant_platform_identity_provider_access_epochs'::regclass,
    'public.tenant_platform_identity_binding_commands'::regclass
  ]::oid[])
    AND column_row.attnum > 0
    AND NOT column_row.attisdropped
    AND column_row.attacl IS NOT NULL
    AND cardinality(column_row.attacl) > 0;

  WITH protected_function(signature) AS (
    VALUES
      ('app.list_tenant_platform_auth_provider_bindings_v1(uuid,uuid,text,uuid,integer,boolean)'),
      ('app.get_tenant_platform_auth_provider_binding_v1(uuid,uuid,uuid,text)'),
      ('app.create_tenant_platform_auth_provider_binding_v1(uuid,uuid,uuid,uuid,uuid,text,integer,bytea,bytea,uuid,uuid,uuid,uuid,inet,text,text,text)'),
      ('app.update_tenant_platform_auth_provider_binding_v1(uuid,uuid,uuid,bigint,integer,text,integer,uuid,uuid,uuid,uuid,inet,text,text,text)'),
      ('app.archive_tenant_platform_auth_provider_binding_v1(uuid,uuid,uuid,bigint,integer,uuid,uuid,uuid,uuid,inet,text,text,text)')
  )
  SELECT count(*)::integer INTO protected_function_count
  FROM protected_function AS expected
  JOIN pg_catalog.pg_proc AS function
    ON function.oid = pg_catalog.to_regprocedure(expected.signature)
  JOIN pg_catalog.pg_namespace AS namespace
    ON namespace.oid = function.pronamespace
  JOIN pg_catalog.pg_roles AS owner ON owner.oid = function.proowner
  JOIN pg_catalog.pg_language AS language ON language.oid = function.prolang
  WHERE namespace.nspname = 'app'
    AND owner.rolname = 'periapsis_migrator'
    AND language.lanname = 'plpgsql'
    AND function.prosecdef
    AND function.provolatile = 'v'
    AND function.proconfig IS NOT DISTINCT FROM
      ARRAY['search_path=pg_catalog, public, app']::text[];

  WITH protected_function(signature) AS (
    VALUES
      ('app.list_tenant_platform_auth_provider_bindings_v1(uuid,uuid,text,uuid,integer,boolean)'),
      ('app.get_tenant_platform_auth_provider_binding_v1(uuid,uuid,uuid,text)'),
      ('app.create_tenant_platform_auth_provider_binding_v1(uuid,uuid,uuid,uuid,uuid,text,integer,bytea,bytea,uuid,uuid,uuid,uuid,inet,text,text,text)'),
      ('app.update_tenant_platform_auth_provider_binding_v1(uuid,uuid,uuid,bigint,integer,text,integer,uuid,uuid,uuid,uuid,inet,text,text,text)'),
      ('app.archive_tenant_platform_auth_provider_binding_v1(uuid,uuid,uuid,bigint,integer,uuid,uuid,uuid,uuid,inet,text,text,text)')
  )
  SELECT count(*)::integer INTO protected_function_acl_mismatch_count
  FROM protected_function AS expected
  JOIN pg_catalog.pg_proc AS function
    ON function.oid = pg_catalog.to_regprocedure(expected.signature)
  CROSS JOIN LATERAL pg_catalog.aclexplode(
    coalesce(function.proacl, pg_catalog.acldefault('f', function.proowner))
  ) AS function_acl
  WHERE function_acl.privilege_type <> 'EXECUTE'
     OR function_acl.grantee NOT IN (
       function.proowner,
       (SELECT role.oid FROM pg_catalog.pg_roles AS role
        WHERE role.rolname = 'periapsis_api')
     )
     OR (function_acl.grantee <> function.proowner AND function_acl.is_grantable);

  WITH private_function(signature) AS (
    VALUES
      ('app.guard_tenant_auth_provider_login_key_v1()'),
      ('app.private_create_tenant_auth_provider_login_claim_v1(uuid,text,uuid,text)'),
      ('app.private_rename_tenant_auth_provider_login_claim_v1(uuid,text,uuid,text,text)'),
      ('app.guard_tenant_auth_provider_login_claim_child_v1()'),
      ('app.guard_tenant_auth_provider_binding_v1()'),
      ('app.guard_tenant_platform_auth_provider_binding_v1()'),
      ('app.guard_platform_auth_provider_binding_dependency_v1()'),
      ('app.guard_tenant_platform_identity_provider_access_epoch_v1()'),
      ('app.guard_tenant_platform_identity_binding_command_v1()'),
      ('app.guard_tenant_platform_identity_binding_tenant_projection_v1()'),
      ('app.private_tenant_platform_auth_provider_binding_document_v1(uuid)'),
      ('app.private_tenant_platform_identity_binding_surface_hash_v1()'),
      ('app.private_append_platform_identity_binding_tenant_audit_v1(uuid,uuid,uuid,uuid,uuid,text,uuid,uuid,uuid,inet,text,text,text,jsonb,jsonb)')
  )
  SELECT count(*)::integer INTO private_function_count
  FROM private_function AS expected
  JOIN pg_catalog.pg_proc AS function
    ON function.oid = pg_catalog.to_regprocedure(expected.signature)
  JOIN pg_catalog.pg_roles AS owner ON owner.oid = function.proowner
  WHERE owner.rolname = 'periapsis_migrator' AND function.prosecdef;

  WITH private_function(signature) AS (
    VALUES
      ('app.guard_tenant_auth_provider_login_key_v1()'),
      ('app.private_create_tenant_auth_provider_login_claim_v1(uuid,text,uuid,text)'),
      ('app.private_rename_tenant_auth_provider_login_claim_v1(uuid,text,uuid,text,text)'),
      ('app.guard_tenant_auth_provider_login_claim_child_v1()'),
      ('app.guard_tenant_auth_provider_binding_v1()'),
      ('app.guard_tenant_platform_auth_provider_binding_v1()'),
      ('app.guard_platform_auth_provider_binding_dependency_v1()'),
      ('app.guard_tenant_platform_identity_provider_access_epoch_v1()'),
      ('app.guard_tenant_platform_identity_binding_command_v1()'),
      ('app.guard_tenant_platform_identity_binding_tenant_projection_v1()'),
      ('app.private_tenant_platform_auth_provider_binding_document_v1(uuid)'),
      ('app.private_tenant_platform_identity_binding_surface_hash_v1()'),
      ('app.private_append_platform_identity_binding_tenant_audit_v1(uuid,uuid,uuid,uuid,uuid,text,uuid,uuid,uuid,inet,text,text,text,jsonb,jsonb)')
  )
  SELECT count(*)::integer INTO private_function_acl_mismatch_count
  FROM private_function AS expected
  JOIN pg_catalog.pg_proc AS function
    ON function.oid = pg_catalog.to_regprocedure(expected.signature)
  CROSS JOIN LATERAL pg_catalog.aclexplode(
    coalesce(function.proacl, pg_catalog.acldefault('f', function.proowner))
  ) AS function_acl
  WHERE function_acl.privilege_type <> 'EXECUTE'
     OR function_acl.grantee <> function.proowner;

  SELECT count(*)::integer INTO expected_constraint_count
  FROM pg_catalog.pg_constraint AS constraint_row
  WHERE constraint_row.conname = ANY (ARRAY[
    'tenant_auth_provider_bindings_login_claim_fk',
    'tenant_platform_auth_provider_bindings_login_claim_fk',
    'tenant_platform_auth_provider_bindings_current_epoch_fk',
    'tenant_platform_identity_provider_access_epochs_staging_check',
    'tenant_platform_identity_provider_access_epochs_binding_fk',
    'tenant_platform_identity_provider_access_epochs_source_fk'
  ]::name[])
    AND constraint_row.convalidated;

  SELECT count(*)::integer INTO deferred_guard_count
  FROM pg_catalog.pg_trigger AS trigger_row
  WHERE trigger_row.tgname = ANY (ARRAY[
    'tenant_auth_provider_login_keys_child_guard_v1',
    'tenant_auth_provider_bindings_login_claim_guard_v1',
    'tenant_platform_auth_provider_bindings_login_claim_guard_v1'
  ]::name[])
    AND NOT trigger_row.tgisinternal
    AND trigger_row.tgenabled = 'O'
    AND trigger_row.tgdeferrable
    AND trigger_row.tginitdeferred;

  SELECT count(*)::integer INTO guard_trigger_count
  FROM pg_catalog.pg_trigger AS trigger_row
  WHERE trigger_row.tgname = ANY (ARRAY[
    'tenant_auth_provider_login_keys_guard_v1',
    'tenant_platform_auth_provider_bindings_guard_v1',
      'platform_auth_providers_binding_dependency_v1',
      'tenant_platform_identity_provider_access_epochs_guard_v1',
      'tenant_platform_identity_binding_commands_guard_v1',
      'tenants_identity_projection_version_guard_v1'
  ]::name[])
    AND NOT trigger_row.tgisinternal
    AND trigger_row.tgenabled = 'O';

  SELECT count(*)::integer INTO native_writer_count
  FROM (VALUES
    ('app.create_tenant_auth_provider_binding_v1(uuid,uuid,text,boolean,integer,uuid,uuid,inet,text,text)'),
    ('app.create_tenant_auth_provider_binding_v2(bytea,uuid,text,boolean,integer,uuid,uuid,uuid,inet,text,text)'),
    ('app.update_tenant_auth_provider_binding_v1(uuid,integer,text,boolean,integer,uuid,uuid,inet,text,text)')
  ) AS native_writer(signature)
  JOIN pg_catalog.pg_proc AS function
    ON function.oid = pg_catalog.to_regprocedure(native_writer.signature)
  WHERE pg_get_functiondef(function.oid) LIKE
          '%private_%tenant_auth_provider_login_claim_v1%';

  RETURN current_count = 163
     AND predecessor_count = 159
     AND protected_table_count = 4
     AND policy_count = 0
     AND direct_table_privilege_count = 0
     AND non_owner_table_acl_count = 0
     AND column_acl_count = 0
     AND protected_function_count = 5
     AND protected_function_acl_mismatch_count = 0
     AND private_function_count = 13
     AND private_function_acl_mismatch_count = 0
     AND expected_constraint_count = 6
     AND deferred_guard_count = 3
     AND guard_trigger_count = 6
     AND native_writer_count = 3
     AND app.private_tenant_platform_identity_binding_surface_hash_v1() =
       'e6d030f84e156818247ea24720c7fc56a326b8a612c55cc4766027c4d6f0752a'
     AND pg_get_constraintdef(
       (SELECT constraint_row.oid
        FROM pg_catalog.pg_constraint AS constraint_row
        WHERE constraint_row.conname =
          'tenant_platform_identity_provider_access_epochs_staging_check')
     ) = 'CHECK (false)'
     AND pg_get_constraintdef(
       (SELECT constraint_row.oid
        FROM pg_catalog.pg_constraint AS constraint_row
        WHERE constraint_row.conname =
          'tenant_platform_identity_binding_commands_result_check')
     ) = 'CHECK ((result_version = 1))'
     AND NOT EXISTS (
       SELECT 1 FROM ONLY public.tenant_platform_identity_provider_access_epochs
     )
     AND NOT EXISTS (
       SELECT 1
       FROM ONLY public.tenant_platform_auth_provider_bindings AS binding
       WHERE binding.binding_family <> 'platform_provider'
          OR binding.enabled
          OR binding.current_access_epoch_id IS NOT NULL
          OR binding.auth_revision <> 1
          OR binding.mapping_revision <> 1
     )
     AND NOT EXISTS (
       SELECT 1
       FROM ONLY public.tenant_auth_provider_login_keys AS claim
       WHERE (claim.binding_family = 'tenant_provider' AND NOT EXISTS (
         SELECT 1 FROM ONLY public.tenant_auth_provider_bindings AS binding
         WHERE binding.tenant_id = claim.tenant_id
           AND binding.binding_family = claim.binding_family
           AND binding.id = claim.binding_id AND binding.key = claim.key
       )) OR (claim.binding_family = 'platform_provider' AND NOT EXISTS (
         SELECT 1 FROM ONLY public.tenant_platform_auth_provider_bindings AS binding
         WHERE binding.tenant_id = claim.tenant_id
           AND binding.binding_family = claim.binding_family
           AND binding.id = claim.binding_id AND binding.key = claim.key
       ))
     )
     AND NOT EXISTS (
       SELECT 1 FROM ONLY public.tenant_auth_provider_bindings AS binding
       WHERE NOT EXISTS (
         SELECT 1 FROM ONLY public.tenant_auth_provider_login_keys AS claim
         WHERE claim.tenant_id = binding.tenant_id
           AND claim.binding_family = binding.binding_family
           AND claim.binding_id = binding.id AND claim.key = binding.key
       )
     )
     AND NOT EXISTS (
       SELECT 1 FROM ONLY public.tenant_platform_auth_provider_bindings AS binding
       WHERE NOT EXISTS (
         SELECT 1 FROM ONLY public.tenant_auth_provider_login_keys AS claim
         WHERE claim.tenant_id = binding.tenant_id
           AND claim.binding_family = binding.binding_family
           AND claim.binding_id = binding.id AND claim.key = binding.key
       )
     )
     AND NOT EXISTS (
       SELECT 1
       FROM ONLY public.tenant_platform_auth_provider_bindings AS binding
       JOIN ONLY public.platform_auth_providers AS provider
         ON provider.id = binding.platform_provider_id
       JOIN ONLY public.platform_federated_provider_policies AS policy
         ON policy.provider_id = provider.id
       WHERE provider.enabled OR policy.enabled OR policy.platform_login_enabled
          OR policy.account_mode <> 'disabled'
          OR (binding.archived_at IS NULL AND provider.archived_at IS NOT NULL)
     )
     AND NOT EXISTS (
       SELECT 1
       FROM ONLY public.tenant_platform_auth_provider_bindings AS binding
       LEFT JOIN ONLY public.tenants AS tenant ON tenant.id = binding.tenant_id
       WHERE tenant.id IS NULL OR tenant.status NOT IN ('active', 'suspended')
     )
     AND NOT EXISTS (
       SELECT 1
       FROM ONLY public.audit_events AS tenant_event
       LEFT JOIN ONLY public.platform_audit_events AS platform_event
         ON platform_event.id::text =
              tenant_event.metadata ->> 'platform_audit_event_id'
       WHERE tenant_event.action IN (
         'tenant.platform_identity_binding.created',
         'tenant.platform_identity_binding.updated',
         'tenant.platform_identity_binding.archived'
       )
         AND (
           tenant_event.actor_type <> 'system'
           OR tenant_event.actor_user_id IS NOT NULL
           OR platform_event.id IS NULL
           OR platform_event.actor_type <> 'user'
           OR platform_event.resource_id IS DISTINCT FROM tenant_event.resource_id
           OR platform_event.correlation_id IS DISTINCT FROM tenant_event.correlation_id
           OR platform_event.metadata ->> 'tenant_audit_event_id'
                IS DISTINCT FROM tenant_event.id::text
           OR platform_event.metadata ->> 'tenant_id'
                IS DISTINCT FROM tenant_event.tenant_id::text
           OR platform_event.actor_user_id::text IS DISTINCT FROM
                tenant_event.metadata ->> 'platform_actor_user_id'
         )
     )
     AND NOT EXISTS (
       SELECT 1
       FROM ONLY public.platform_audit_events AS platform_event
       LEFT JOIN ONLY public.audit_events AS tenant_event
         ON tenant_event.id::text =
              platform_event.metadata ->> 'tenant_audit_event_id'
       WHERE platform_event.action IN (
         'platform.identity_binding.created',
         'platform.identity_binding.updated',
         'platform.identity_binding.archived'
       )
         AND (
           tenant_event.id IS NULL
           OR tenant_event.resource_id IS DISTINCT FROM platform_event.resource_id
           OR tenant_event.correlation_id IS DISTINCT FROM platform_event.correlation_id
           OR tenant_event.metadata ->> 'platform_audit_event_id'
                IS DISTINCT FROM platform_event.id::text
         )
     )
     AND position(
       'user_platform_roles' IN pg_get_functiondef(
         'app.create_tenant_platform_auth_provider_binding_v1(uuid,uuid,uuid,uuid,uuid,text,integer,bytea,bytea,uuid,uuid,uuid,uuid,inet,text,text,text)'::regprocedure
       )
     ) = 0
     AND position(
       'user_platform_roles' IN pg_get_functiondef(
          'app.update_tenant_platform_auth_provider_binding_v1(uuid,uuid,uuid,bigint,integer,text,integer,uuid,uuid,uuid,uuid,inet,text,text,text)'::regprocedure
       )
     ) = 0
     AND position(
       'user_platform_roles' IN pg_get_functiondef(
          'app.archive_tenant_platform_auth_provider_binding_v1(uuid,uuid,uuid,bigint,integer,uuid,uuid,uuid,uuid,inet,text,text,text)'::regprocedure
       )
     ) = 0;
EXCEPTION
  WHEN insufficient_privilege THEN
    RETURN false;
END;
$function$;
ALTER FUNCTION app.tenant_platform_identity_binding_schema_readiness_v1()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.tenant_platform_identity_binding_schema_readiness_v1()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,
  periapsis_sla_api_owner, periapsis_sla_worker_owner,
  periapsis_sla_readiness_owner, periapsis_ticket_saved_view_owner,
  periapsis_ticket_attribution_owner,
  periapsis_ticket_sla_projection_owner;
--> statement-breakpoint

-- Public trust root for the owner-only 9B verifier chain.  Its own source is
-- pinned by API/worker health and by the predecessor runtime-surface digest;
-- it in turn pins both the catalog-digest helper and the semantic verifier.
CREATE FUNCTION app.tenant_platform_identity_binding_schema_readiness_v2()
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  trusted_root_count integer;
  self_catalog_ready boolean;
BEGIN
  WITH expected_root(
    signature, language_name, result_type, configuration, source_hash
  ) AS (
    VALUES
      ('app.private_tenant_platform_identity_binding_surface_hash_v1()',
       'sql', 'text', ARRAY['search_path=pg_catalog, public, app']::text[],
       'c137bb32f1444708d1579a2ccb24a5719fb7623074dba1d67b63028fe4f1cc18'),
      ('app.tenant_platform_identity_binding_schema_readiness_v1()',
       'plpgsql', 'boolean',
       ARRAY['search_path=pg_catalog, public, app']::text[],
       'ab6a654233a3744f480898ae249c4d4da87553fdd4a76ecca5e898d71ca0c95e'),
      ('app.schema_compatibility_v32()', 'plpgsql',
       'TABLE(applied_count bigint, latest_created_at bigint, latest_hash text, migration_fingerprint text)',
       ARRAY[
         'search_path=pg_catalog',
         'app.schema_compatibility_fingerprint=RETIRED'
       ]::text[],
       '7be37a8d955e9dbff5433782cd3d0843e3249b9a10f58e2f5f994c4adf2db023')
  )
  SELECT count(*)::integer INTO trusted_root_count
  FROM expected_root AS expected
  JOIN pg_catalog.pg_proc AS function
    ON function.oid = pg_catalog.to_regprocedure(expected.signature)
  JOIN pg_catalog.pg_namespace AS namespace
    ON namespace.oid = function.pronamespace
  JOIN pg_catalog.pg_roles AS owner ON owner.oid = function.proowner
  JOIN pg_catalog.pg_language AS language ON language.oid = function.prolang
  WHERE namespace.nspname = 'app'
    AND owner.rolname = 'periapsis_migrator'
    AND language.lanname = expected.language_name
    AND function.prokind = 'f'
    AND function.provolatile = 's'
    AND function.prosecdef
    AND NOT function.proisstrict
    AND NOT function.proleakproof
    AND function.proparallel = 'u'
    AND function.pronargs = 0
    AND function.proconfig IS NOT DISTINCT FROM expected.configuration
    AND pg_catalog.pg_get_function_result(function.oid) = expected.result_type
    AND encode(
      sha256(convert_to(function.prosrc, 'UTF8')), 'hex'
    ) = expected.source_hash
    AND (
      SELECT count(*) = 1
         AND coalesce(bool_and(
           function_acl.grantor = function.proowner
           AND function_acl.grantee = function.proowner
           AND function_acl.privilege_type = 'EXECUTE'
           AND NOT function_acl.is_grantable
         ), false)
      FROM pg_catalog.aclexplode(coalesce(
        function.proacl, pg_catalog.acldefault('f', function.proowner)
      )) AS function_acl
    );

  SELECT count(*) = 1 INTO self_catalog_ready
  FROM pg_catalog.pg_proc AS function
  JOIN pg_catalog.pg_namespace AS namespace
    ON namespace.oid = function.pronamespace
  JOIN pg_catalog.pg_roles AS owner ON owner.oid = function.proowner
  JOIN pg_catalog.pg_language AS language ON language.oid = function.prolang
  WHERE function.oid =
      'app.tenant_platform_identity_binding_schema_readiness_v2()'::regprocedure
    AND namespace.nspname = 'app'
    AND owner.rolname = 'periapsis_migrator'
    AND language.lanname = 'plpgsql'
    AND function.prokind = 'f'
    AND function.provolatile = 's'
    AND function.prosecdef
    AND NOT function.proisstrict
    AND NOT function.proleakproof
    AND function.proparallel = 'u'
    AND function.pronargs = 0
    AND function.proconfig IS NOT DISTINCT FROM
      ARRAY['search_path=pg_catalog, public, app']::text[]
    AND pg_catalog.pg_get_function_result(function.oid) = 'boolean'
    AND (
      SELECT count(*) = 3
         AND coalesce(bool_and(
           function_acl.grantor = function.proowner
           AND function_acl.grantee IN (
             function.proowner,
             (SELECT role.oid FROM pg_catalog.pg_roles AS role
              WHERE role.rolname = 'periapsis_api'),
             (SELECT role.oid FROM pg_catalog.pg_roles AS role
              WHERE role.rolname = 'periapsis_worker')
           )
           AND function_acl.privilege_type = 'EXECUTE'
           AND NOT function_acl.is_grantable
         ), false)
      FROM pg_catalog.aclexplode(coalesce(
        function.proacl, pg_catalog.acldefault('f', function.proowner)
      )) AS function_acl
    );

  RETURN trusted_root_count = 3
     AND self_catalog_ready
     AND app.tenant_platform_identity_binding_schema_readiness_v1();
END;
$function$;
ALTER FUNCTION app.tenant_platform_identity_binding_schema_readiness_v2()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.tenant_platform_identity_binding_schema_readiness_v2()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,
  periapsis_sla_api_owner, periapsis_sla_worker_owner,
  periapsis_sla_readiness_owner, periapsis_ticket_saved_view_owner,
  periapsis_ticket_attribution_owner,
  periapsis_ticket_sla_projection_owner;
GRANT EXECUTE ON FUNCTION app.tenant_platform_identity_binding_schema_readiness_v2()
TO periapsis_api, periapsis_worker;
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
SET search_path = pg_catalog, app
AS $function$
DECLARE
  fingerprint_entries text[];
  appended_created_at bigint[];
  actual_count bigint;
  actual_latest_created_at bigint;
  actual_latest_hash text;
  actual_fingerprint text;
  predecessor_count bigint;
  predecessor_latest_created_at bigint;
  predecessor_latest_hash text;
  predecessor_fingerprint text;
  expected_predecessor_fingerprint text;
  retired_count bigint;
  trusted_root_count integer;
BEGIN
  fingerprint_entries := string_to_array(
    p_expected_migration_fingerprint, ':'
  );
  IF p_expected_count IS DISTINCT FROM 163
     OR p_expected_latest_created_at IS DISTINCT FROM 1787936037593
     OR p_expected_latest_hash IS NULL
     OR p_expected_latest_hash !~ '^[0-9a-f]{64}$'
     OR p_expected_migration_fingerprint IS NULL
     OR p_expected_migration_fingerprint !~
          '^[1-9][0-9]*@[0-9a-f]{64}(:[1-9][0-9]*@[0-9a-f]{64})*$'
     OR cardinality(fingerprint_entries) IS DISTINCT FROM 163
     OR fingerprint_entries[163] IS DISTINCT FROM (
       p_expected_latest_created_at::text || '@' || p_expected_latest_hash
     ) THEN
    RAISE EXCEPTION 'invalid schema compatibility v34 manifest'
      USING ERRCODE = '22023';
  END IF;
  SELECT array_agg(
    split_part(entry.value, '@', 1)::bigint ORDER BY entry.ordinality
  ) INTO appended_created_at
  FROM unnest(fingerprint_entries[160:163]) WITH ORDINALITY
       AS entry(value, ordinality);
  IF appended_created_at IS DISTINCT FROM ARRAY[
       1787934110266, 1787934129921, 1787936025344, 1787936037593
     ]::bigint[] THEN
    RAISE EXCEPTION 'invalid schema compatibility v34 appended sequence'
      USING ERRCODE = '22023';
  END IF;

  -- Seal the current projection before invoking it. ALTER FUNCTION is
  -- transactional, so any later mismatch rolls this catalog change back and
  -- leaves both current and predecessor replicas unavailable.
  PERFORM set_config(
    'app.schema_compatibility_fingerprint',
    p_expected_migration_fingerprint, true
  );
  EXECUTE $statement$
    ALTER FUNCTION app.schema_compatibility_v34()
      SET app.schema_compatibility_fingerprint FROM CURRENT
  $statement$;

  SELECT compatibility.applied_count, compatibility.latest_created_at,
         compatibility.latest_hash, compatibility.migration_fingerprint
  INTO actual_count, actual_latest_created_at, actual_latest_hash,
       actual_fingerprint
  FROM app.schema_compatibility_v34() AS compatibility;
  IF actual_count IS DISTINCT FROM p_expected_count
     OR actual_latest_created_at IS DISTINCT FROM p_expected_latest_created_at
     OR actual_latest_hash IS DISTINCT FROM p_expected_latest_hash
     OR actual_fingerprint IS DISTINCT FROM p_expected_migration_fingerprint THEN
    RAISE EXCEPTION 'schema compatibility v34 manifest does not match the journal'
      USING ERRCODE = '55000';
  END IF;

  -- A successful seal must never leave either old or current replicas
  -- permanently unready. Attest the exact public roots and both owner-only
  -- 9B verifier dependencies before accepting the new journal state.
  WITH expected_root(
    signature, language_name, configuration, result_type,
    expected_acl_roles, source_hash
  ) AS (
    VALUES
      ('app.schema_compatibility_v34()', 'plpgsql', ARRAY[
         'search_path=pg_catalog',
         'app.schema_compatibility_fingerprint=' ||
           p_expected_migration_fingerprint
       ]::text[],
       'TABLE(applied_count bigint, latest_created_at bigint, latest_hash text, migration_fingerprint text)',
       ARRAY[
         'periapsis_api', 'periapsis_migrator', 'periapsis_worker'
       ]::text[],
       'ef25fa07a870db0c2f74ccca05bea77fcd06eaeafcb085a7974a3e2a91573bd5'),
      ('app.schema_compatibility_v33()', 'plpgsql',
       ARRAY['search_path=pg_catalog']::text[],
       'TABLE(applied_count bigint, latest_created_at bigint, latest_hash text, migration_fingerprint text)',
       ARRAY[
         'periapsis_api', 'periapsis_migrator', 'periapsis_worker'
       ]::text[],
       'b0bce19483526ef805636bc5d5edbfe666f0f5c6dbf45157afdcc18609019253'),
      ('app.platform_tenant_lifecycle_schema_readiness_v1()', 'plpgsql',
       ARRAY['search_path=pg_catalog, app']::text[], 'boolean',
       ARRAY[
         'periapsis_api', 'periapsis_migrator', 'periapsis_worker'
       ]::text[],
       'c5c69c71eaa7bb6b134ae78f758d703bcae3bf00b01c6a776476c98c7ffb5863'),
      ('app.platform_identity_provider_schema_readiness_v1()', 'plpgsql',
       ARRAY['search_path=pg_catalog, app']::text[], 'boolean',
       ARRAY[
         'periapsis_api', 'periapsis_migrator', 'periapsis_worker'
       ]::text[],
       'c0079954cfcd0b6f0a5f6d4f2de2fd93f21094291196f9b7fc9c0d937423ef53'),
      ('app.private_tenant_platform_identity_binding_surface_hash_v1()',
       'sql', ARRAY['search_path=pg_catalog, public, app']::text[], 'text',
       ARRAY['periapsis_migrator']::text[],
       'c137bb32f1444708d1579a2ccb24a5719fb7623074dba1d67b63028fe4f1cc18'),
      ('app.tenant_platform_identity_binding_schema_readiness_v1()',
       'plpgsql', ARRAY['search_path=pg_catalog, public, app']::text[],
       'boolean', ARRAY['periapsis_migrator']::text[],
       'ab6a654233a3744f480898ae249c4d4da87553fdd4a76ecca5e898d71ca0c95e'),
      ('app.tenant_platform_identity_binding_schema_readiness_v2()',
       'plpgsql', ARRAY['search_path=pg_catalog, public, app']::text[],
       'boolean', ARRAY[
         'periapsis_api', 'periapsis_migrator', 'periapsis_worker'
       ]::text[],
       'a75ff3692a286c48c992c19256f0e10c03813e9642de5c3d8bc99af2494c0954')
  )
  SELECT count(*)::integer INTO trusted_root_count
  FROM expected_root AS expected
  JOIN pg_catalog.pg_proc AS function
    ON function.oid = pg_catalog.to_regprocedure(expected.signature)
  JOIN pg_catalog.pg_namespace AS namespace
    ON namespace.oid = function.pronamespace
  JOIN pg_catalog.pg_roles AS owner ON owner.oid = function.proowner
  JOIN pg_catalog.pg_language AS language ON language.oid = function.prolang
  WHERE namespace.nspname = 'app'
    AND owner.rolname = 'periapsis_migrator'
    AND language.lanname = expected.language_name
    AND function.prokind = 'f'
    AND function.provolatile = 's'
    AND function.prosecdef
    AND NOT function.proisstrict
    AND NOT function.proleakproof
    AND function.proparallel = 'u'
    AND function.pronargs = 0
    AND function.proconfig IS NOT DISTINCT FROM expected.configuration
    AND pg_catalog.pg_get_function_result(function.oid) = expected.result_type
    AND encode(sha256(convert_to(function.prosrc, 'UTF8')), 'hex') =
      expected.source_hash
    AND (
      SELECT count(*) = cardinality(expected.expected_acl_roles)
         AND array_agg(
           coalesce(grantee.rolname::text, 'PUBLIC')
           ORDER BY coalesce(grantee.rolname::text, 'PUBLIC')
         ) IS NOT DISTINCT FROM expected.expected_acl_roles
         AND coalesce(bool_and(
           function_acl.grantor = function.proowner
           AND function_acl.privilege_type = 'EXECUTE'
           AND NOT function_acl.is_grantable
         ), false)
      FROM pg_catalog.aclexplode(coalesce(
        function.proacl, pg_catalog.acldefault('f', function.proowner)
      )) AS function_acl
      LEFT JOIN pg_catalog.pg_roles AS grantee
        ON grantee.oid = function_acl.grantee
    );
  IF trusted_root_count IS DISTINCT FROM 7 THEN
    RAISE EXCEPTION 'schema compatibility v34 trusted roots are not exact'
      USING ERRCODE = '55000';
  END IF;

  expected_predecessor_fingerprint := array_to_string(
    fingerprint_entries[1:159], ':'
  );
  SELECT compatibility.applied_count, compatibility.latest_created_at,
         compatibility.latest_hash, compatibility.migration_fingerprint
  INTO predecessor_count, predecessor_latest_created_at,
       predecessor_latest_hash, predecessor_fingerprint
  FROM app.schema_compatibility_v33() AS compatibility;
  IF predecessor_count IS DISTINCT FROM 159
     OR predecessor_latest_created_at IS DISTINCT FROM 1787929625096
     OR predecessor_latest_hash IS DISTINCT FROM
          split_part(fingerprint_entries[159], '@', 2)
     OR predecessor_fingerprint IS DISTINCT FROM
          expected_predecessor_fingerprint THEN
    RAISE EXCEPTION 'sealed schema compatibility v33 prefix is not exact'
      USING ERRCODE = '55000';
  END IF;

  SELECT compatibility.applied_count INTO retired_count
  FROM app.schema_compatibility_v32() AS compatibility;
  IF retired_count IS DISTINCT FROM 0
     OR NOT app.platform_identity_provider_schema_readiness_v1()
     OR NOT app.tenant_platform_identity_binding_schema_readiness_v2()
     OR NOT app.platform_tenant_lifecycle_schema_readiness_v1()
     OR NOT has_function_privilege(
       'periapsis_api', 'app.schema_compatibility_v34()'::regprocedure,
       'EXECUTE'
     )
     OR NOT has_function_privilege(
       'periapsis_worker', 'app.schema_compatibility_v34()'::regprocedure,
       'EXECUTE'
     )
     OR NOT has_function_privilege(
       'periapsis_api', 'app.schema_compatibility_v33()'::regprocedure,
       'EXECUTE'
     )
     OR NOT has_function_privilege(
       'periapsis_worker', 'app.schema_compatibility_v33()'::regprocedure,
       'EXECUTE'
     )
     OR has_function_privilege(
       'periapsis_api', 'app.schema_compatibility_v32()'::regprocedure,
       'EXECUTE'
     )
     OR has_function_privilege(
       'periapsis_worker', 'app.schema_compatibility_v32()'::regprocedure,
       'EXECUTE'
     ) THEN
    RAISE EXCEPTION 'schema compatibility v32 remains active or platform identity readiness failed'
      USING ERRCODE = '55000';
  END IF;
END;
$function$;
ALTER FUNCTION app.seal_schema_compatibility_manifest(
  bigint, bigint, text, text
) OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.seal_schema_compatibility_manifest(
  bigint, bigint, text, text
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,
  periapsis_sla_api_owner, periapsis_sla_worker_owner,
  periapsis_sla_readiness_owner, periapsis_ticket_saved_view_owner,
  periapsis_ticket_attribution_owner,
  periapsis_ticket_sla_projection_owner;
--> statement-breakpoint

-- Advance each inherited readiness surface to v34/current + v33/predecessor.
DO $migration$
DECLARE
  readiness_function regprocedure;
  original_definition text;
  rewritten_definition text;
BEGIN
  FOREACH readiness_function IN ARRAY ARRAY[
    'app.federated_authentication_schema_readiness_v1()'::regprocedure,
    'app.identity_mfa_device_management_readiness_v1()'::regprocedure,
    'app.identity_mfa_schema_readiness_v1()'::regprocedure,
    'app.private_sla_schema_readiness_core_v1()'::regprocedure,
    'app.ticket_saved_views_schema_readiness_v1()'::regprocedure,
    'app.ticket_query_projections_readiness_v1()'::regprocedure
  ] LOOP
    SELECT pg_get_functiondef(readiness_function)
    INTO STRICT original_definition;
    IF original_definition NOT LIKE '%app.schema_compatibility_v33()%'
       OR original_definition NOT LIKE '%app.schema_compatibility_v32()%'
       OR original_definition NOT LIKE '%app.schema_compatibility_v31()%'
       OR original_definition NOT LIKE
            '%current_count = 159 AND predecessor_count = 155%' THEN
      RAISE EXCEPTION 'unexpected v33 readiness definition: %',
        readiness_function::text USING ERRCODE = '55000';
    END IF;
    rewritten_definition := replace(
      original_definition,
      'app.schema_compatibility_v33()',
      'app.schema_compatibility_vNEXT()'
    );
    rewritten_definition := replace(
      rewritten_definition,
      'app.schema_compatibility_v32()',
      'app.schema_compatibility_v33()'
    );
    rewritten_definition := replace(
      rewritten_definition,
      'app.schema_compatibility_v31()',
      'app.schema_compatibility_v32()'
    );
    rewritten_definition := replace(
      rewritten_definition,
      'app.schema_compatibility_vNEXT()',
      'app.schema_compatibility_v34()'
    );
    rewritten_definition := replace(
      rewritten_definition,
      'current_count = 159 AND predecessor_count = 155',
      'current_count = 163 AND predecessor_count = 159'
    );
    IF rewritten_definition IS NOT DISTINCT FROM original_definition
       OR rewritten_definition NOT LIKE '%app.schema_compatibility_v34()%'
       OR rewritten_definition LIKE '%app.schema_compatibility_v31()%'
       OR rewritten_definition NOT LIKE
            '%current_count = 163 AND predecessor_count = 159%' THEN
      RAISE EXCEPTION 'failed to rebind v34 readiness definition: %',
        readiness_function::text USING ERRCODE = '55000';
    END IF;
    EXECUTE rewritten_definition;
  END LOOP;
END;
$migration$;
--> statement-breakpoint

GRANT EXECUTE ON FUNCTION app.seal_schema_compatibility_manifest(
  bigint, bigint, text, text
) TO periapsis_migrator;
