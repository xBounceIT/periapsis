-- V35 is a fail-closed cutover. The v34 binary cannot consume the platform
-- admission/runtime ABI, so it is deliberately not advertised as a rolling
-- predecessor while this migration set is installed or sealed.

ALTER FUNCTION app.schema_compatibility_v34()
  SET app.schema_compatibility_fingerprint = 'RETIRED';
REVOKE ALL ON FUNCTION app.schema_compatibility_v34()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,
  periapsis_sla_api_owner, periapsis_sla_worker_owner,
  periapsis_sla_readiness_owner, periapsis_ticket_saved_view_owner,
  periapsis_ticket_attribution_owner,
  periapsis_ticket_sla_projection_owner;
REVOKE ALL ON FUNCTION app.platform_identity_provider_schema_readiness_v1()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,
  periapsis_sla_api_owner, periapsis_sla_worker_owner,
  periapsis_sla_readiness_owner, periapsis_ticket_saved_view_owner,
  periapsis_ticket_attribution_owner,
  periapsis_ticket_sla_projection_owner;
REVOKE ALL ON FUNCTION app.tenant_platform_identity_binding_schema_readiness_v2()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,
  periapsis_sla_api_owner, periapsis_sla_worker_owner,
  periapsis_sla_readiness_owner, periapsis_ticket_saved_view_owner,
  periapsis_ticket_attribution_owner,
  periapsis_ticket_sla_projection_owner;
--> statement-breakpoint

CREATE FUNCTION app.schema_compatibility_v35()
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
    SELECT count(*)::bigint,max(migration.created_at)::bigint,
           count(*) FILTER (
             WHERE migration.created_at = 1788049988184
           )::bigint,
           string_agg(
             migration.created_at::text || '@' || lower(migration.hash::text),
             ':' ORDER BY migration.created_at,migration.id
           )
    FROM drizzle.__drizzle_migrations AS migration
  $query$ INTO journal_count,journal_latest_created_at,latest_rows,
                journal_fingerprint;

  SELECT count(*) = 1 INTO self_catalog_ready
  FROM pg_catalog.pg_proc AS function
  JOIN pg_catalog.pg_namespace AS namespace
    ON namespace.oid = function.pronamespace
  JOIN pg_catalog.pg_roles AS owner ON owner.oid = function.proowner
  JOIN pg_catalog.pg_language AS language ON language.oid = function.prolang
  WHERE function.oid = 'app.schema_compatibility_v35()'::regprocedure
    AND namespace.nspname = 'app'
    AND owner.rolname = 'periapsis_migrator'
    AND language.lanname = 'plpgsql'
    AND function.prokind = 'f' AND function.provolatile = 's'
    AND function.prosecdef AND NOT function.proisstrict
    AND NOT function.proleakproof AND function.proparallel = 'u'
    AND function.pronargs = 0
    AND function.proconfig IS NOT DISTINCT FROM ARRAY[
      'search_path=pg_catalog',
      'app.schema_compatibility_fingerprint=' || journal_fingerprint
    ]::text[]
    AND pg_catalog.pg_get_function_result(function.oid) =
      'TABLE(applied_count bigint, latest_created_at bigint, latest_hash text, migration_fingerprint text)'
    AND (
      SELECT count(*) = 3 AND coalesce(bool_and(
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
      ),false)
      FROM pg_catalog.aclexplode(CASE WHEN pg_catalog.cardinality(coalesce(
        function.proacl,pg_catalog.acldefault('f',function.proowner)
      )) > 0 THEN coalesce(
        function.proacl,pg_catalog.acldefault('f',function.proowner)
      ) ELSE NULL::pg_catalog.aclitem[] END) AS function_acl
    );

  IF journal_count = 167
     AND journal_latest_created_at = 1788049988184
     AND latest_rows = 1
     AND self_catalog_ready
     AND journal_fingerprint = current_setting(
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
ALTER FUNCTION app.schema_compatibility_v35() OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.schema_compatibility_v35()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,
  periapsis_sla_api_owner, periapsis_sla_worker_owner,
  periapsis_sla_readiness_owner, periapsis_ticket_saved_view_owner,
  periapsis_ticket_attribution_owner,
  periapsis_ticket_sla_projection_owner;
GRANT EXECUTE ON FUNCTION app.schema_compatibility_v35()
TO periapsis_api, periapsis_worker;
--> statement-breakpoint

-- Exact transitive catalog closure. Privilege-derived inventories omit the
-- owner-only provider, binding, MFA, trigger, and CHECK helpers, so this digest
-- deliberately covers every public relation and every app routine. The
-- current roots and this helper are excluded to avoid a self-referential hash;
-- their complete pg_proc shapes and source hashes are attested separately.
CREATE FUNCTION app.private_tenant_platform_oidc_dependency_surface_hash_v1()
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
  WITH RECURSIVE managed_runtime_login(role_name,group_role_name) AS (
    VALUES
      ('periapsis_api_login','periapsis_api'),
      ('periapsis_worker_login','periapsis_worker'),
      ('periapsis_notifier_login','periapsis_notifier'),
      ('periapsis_auditor_login','periapsis_auditor')
  ), managed_runtime_login_role(oid) AS (
    SELECT role.oid
    FROM managed_runtime_login AS expected
    JOIN pg_catalog.pg_roles AS role ON role.rolname = expected.role_name
  ), protected_relation(oid) AS (
    SELECT relation_row.oid
    FROM pg_catalog.pg_class AS relation_row
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = relation_row.relnamespace
    WHERE namespace.nspname = 'public'
      AND relation_row.relkind IN ('r','p','v','m','S','f')
  ), app_function(oid) AS (
    SELECT function_row.oid
    FROM pg_catalog.pg_proc AS function_row
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = function_row.pronamespace
    WHERE namespace.nspname = 'app'
  ), protected_function(oid) AS (
    SELECT function_row.oid
    FROM app_function AS expected
    JOIN pg_catalog.pg_proc AS function_row ON function_row.oid = expected.oid
    WHERE NOT (
      function_row.proname IN (
        'private_tenant_platform_oidc_dependency_surface_hash_v1',
        'private_tenant_platform_oidc_runtime_schema_readiness_v1',
        'tenant_platform_oidc_runtime_schema_readiness_v1',
        'schema_compatibility_v35'
      )
      AND pg_catalog.pg_get_function_identity_arguments(function_row.oid) = ''
    )
  ), public_type(oid) AS (
    SELECT type_row.oid
    FROM pg_catalog.pg_type AS type_row
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = type_row.typnamespace
    WHERE namespace.nspname = 'public' AND type_row.typtype IN ('e','d')
  ), role_seed(oid) AS (
    SELECT role.oid
    FROM pg_catalog.pg_roles AS role
    WHERE role.rolname LIKE 'periapsis\_%' ESCAPE '\'
      AND role.rolname NOT IN (
        SELECT expected.role_name FROM managed_runtime_login AS expected
      )
  ), reachable_role(oid) AS (
    SELECT role_seed.oid FROM role_seed
    UNION
    SELECT neighbour.oid
    FROM reachable_role AS reachable
    JOIN LATERAL (
      SELECT membership.roleid AS oid
      FROM pg_catalog.pg_auth_members AS membership
      WHERE membership.member = reachable.oid
      UNION
      SELECT membership.member AS oid
      FROM pg_catalog.pg_auth_members AS membership
      WHERE membership.roleid = reachable.oid
    ) AS neighbour ON true
    WHERE neighbour.oid NOT IN (
      SELECT login_role.oid FROM managed_runtime_login_role AS login_role
    )
  ), relation_identity(oid,identity) AS (
    SELECT relation_row.oid,
      pg_catalog.format('%I.%I',namespace.nspname,relation_row.relname)
    FROM pg_catalog.pg_class AS relation_row
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = relation_row.relnamespace
  ), toast_relation(oid,base_identity) AS (
    SELECT toast.oid,identity.identity
    FROM protected_relation AS expected
    JOIN pg_catalog.pg_class AS base_relation
      ON base_relation.oid = expected.oid
    JOIN relation_identity AS identity ON identity.oid = base_relation.oid
    JOIN pg_catalog.pg_class AS toast
      ON toast.oid = base_relation.reltoastrelid
  ), function_identity(oid,identity) AS (
    SELECT function_row.oid,pg_catalog.format(
      '%I.%I(%s)',namespace.nspname,function_row.proname,
      pg_catalog.pg_get_function_identity_arguments(function_row.oid)
    )
    FROM pg_catalog.pg_proc AS function_row
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = function_row.pronamespace
  ), operator_identity(oid,identity) AS (
    SELECT operator.oid,pg_catalog.format(
      '%I.%I(%s,%s)',namespace.nspname,operator.oprname,
      CASE WHEN operator.oprleft = 0 THEN '-'
        ELSE pg_catalog.format_type(operator.oprleft,NULL) END,
      CASE WHEN operator.oprright = 0 THEN '-'
        ELSE pg_catalog.format_type(operator.oprright,NULL) END
    )
    FROM pg_catalog.pg_operator AS operator
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = operator.oprnamespace
  ), opclass_identity(oid,identity) AS (
    SELECT operator_class.oid,pg_catalog.format(
      '%I.%I',namespace.nspname,operator_class.opcname
    )
    FROM pg_catalog.pg_opclass AS operator_class
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = operator_class.opcnamespace
  ), referenced_collation(oid) AS (
    SELECT DISTINCT column_row.attcollation
    FROM protected_relation AS expected
    JOIN pg_catalog.pg_attribute AS column_row
      ON column_row.attrelid = expected.oid
     AND column_row.attnum > 0 AND NOT column_row.attisdropped
    WHERE column_row.attcollation <> 0
    UNION
    SELECT DISTINCT collation_oid
    FROM protected_relation AS expected
    JOIN pg_catalog.pg_index AS index_row ON index_row.indrelid = expected.oid
    CROSS JOIN LATERAL pg_catalog.unnest(
      index_row.indcollation::pg_catalog.oid[]
    ) AS item(collation_oid)
    WHERE collation_oid <> 0
    UNION
    SELECT DISTINCT collation_oid
    FROM protected_relation AS expected
    JOIN pg_catalog.pg_partitioned_table AS partitioned
      ON partitioned.partrelid = expected.oid
    CROSS JOIN LATERAL pg_catalog.unnest(
      partitioned.partcollation::pg_catalog.oid[]
    ) AS item(collation_oid)
    WHERE collation_oid <> 0
    UNION
    SELECT type_row.typcollation
    FROM public_type AS expected
    JOIN pg_catalog.pg_type AS type_row ON type_row.oid = expected.oid
    WHERE type_row.typcollation <> 0
  ), object_acl(object_kind,object_identity,owner_oid,acl) AS (
    SELECT 'schema',pg_catalog.jsonb_build_object(
      'schema',namespace.nspname
    ),namespace.nspowner,coalesce(
      namespace.nspacl,pg_catalog.acldefault('n',namespace.nspowner)
    )
    FROM pg_catalog.pg_namespace AS namespace
    WHERE namespace.nspname IN ('app','public')
    UNION ALL
    SELECT 'database',pg_catalog.jsonb_build_object('database','current'),
      database_row.datdba,coalesce(
        database_row.datacl,pg_catalog.acldefault('d',database_row.datdba)
      )
    FROM pg_catalog.pg_database AS database_row
    WHERE database_row.datname = pg_catalog.current_database()
    UNION ALL
    SELECT CASE WHEN relation_row.relkind = 'S' THEN 'sequence' ELSE 'relation' END,
      pg_catalog.jsonb_build_object('relation',identity.identity),
      relation_row.relowner,coalesce(
        relation_row.relacl,pg_catalog.acldefault(
          CASE WHEN relation_row.relkind = 'S'
            THEN 'S'::"char" ELSE 'r'::"char" END,
          relation_row.relowner
        )
      )
    FROM protected_relation AS expected
    JOIN pg_catalog.pg_class AS relation_row ON relation_row.oid = expected.oid
    JOIN relation_identity AS identity ON identity.oid = relation_row.oid
    UNION ALL
    SELECT 'column',pg_catalog.jsonb_build_object(
      'relation',identity.identity,'attnum',column_row.attnum,
      'column',column_row.attname
    ),relation_row.relowner,column_row.attacl
    FROM protected_relation AS expected
    JOIN pg_catalog.pg_class AS relation_row ON relation_row.oid = expected.oid
    JOIN relation_identity AS identity ON identity.oid = relation_row.oid
    JOIN pg_catalog.pg_attribute AS column_row
      ON column_row.attrelid = relation_row.oid
     AND column_row.attnum > 0 AND NOT column_row.attisdropped
    UNION ALL
    SELECT 'function',pg_catalog.jsonb_build_object(
      'function',identity.identity
    ),function_row.proowner,coalesce(
      function_row.proacl,pg_catalog.acldefault('f',function_row.proowner)
    )
    FROM protected_function AS expected
    JOIN pg_catalog.pg_proc AS function_row ON function_row.oid = expected.oid
    JOIN function_identity AS identity ON identity.oid = function_row.oid
    UNION ALL
    SELECT 'type',pg_catalog.jsonb_build_object(
      'type',pg_catalog.format('%I.%I',namespace.nspname,type_row.typname)
    ),type_row.typowner,coalesce(
      type_row.typacl,pg_catalog.acldefault('T',type_row.typowner)
    )
    FROM public_type AS expected
    JOIN pg_catalog.pg_type AS type_row ON type_row.oid = expected.oid
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = type_row.typnamespace
  ), toast_index_catalog(base_identity,index_oid,definition) AS (
    SELECT toast_surface.base_identity,index_relation.oid,
      pg_catalog.jsonb_build_object(
        'owner',owner.rolname,'kind',index_relation.relkind::text,
        'persistence',index_relation.relpersistence::text,
        'access_method',access_method.amname,
        'tablespace',CASE WHEN index_relation.reltablespace = 0
          THEN '<database-default>' ELSE tablespace.spcname END,
        'is_partition',index_relation.relispartition,
        'options',pg_catalog.to_jsonb(ARRAY(
          SELECT option
          FROM pg_catalog.unnest(index_relation.reloptions) AS option
          ORDER BY option COLLATE "C"
        )),
        'attribute_count',index_row.indnatts,
        'key_attribute_count',index_row.indnkeyatts,
        'unique',index_row.indisunique,
        'nulls_not_distinct',index_row.indnullsnotdistinct,
        'primary',index_row.indisprimary,
        'exclusion',index_row.indisexclusion,
        'immediate',index_row.indimmediate,
        'clustered',index_row.indisclustered,
        'valid',index_row.indisvalid,
        'check_xmin',index_row.indcheckxmin,
        'ready',index_row.indisready,
        'live',index_row.indislive,
        'replica_identity',index_row.indisreplident,
        'keys',pg_catalog.to_jsonb(index_row.indkey::pg_catalog.int2[]),
        'collations',coalesce((
          SELECT pg_catalog.jsonb_agg(
            CASE WHEN item.collation_oid = 0 THEN NULL ELSE
              pg_catalog.format('%I.%I',namespace.nspname,
                collation_row.collname) END
            ORDER BY item.ordinality
          )
          FROM pg_catalog.unnest(index_row.indcollation::pg_catalog.oid[])
            WITH ORDINALITY AS item(collation_oid,ordinality)
          LEFT JOIN pg_catalog.pg_collation AS collation_row
            ON collation_row.oid = item.collation_oid
          LEFT JOIN pg_catalog.pg_namespace AS namespace
            ON namespace.oid = collation_row.collnamespace
        ),'[]'::pg_catalog.jsonb),
        'operator_classes',coalesce((
          SELECT pg_catalog.jsonb_agg(
            operator_class.identity ORDER BY item.ordinality
          )
          FROM pg_catalog.unnest(index_row.indclass::pg_catalog.oid[])
            WITH ORDINALITY AS item(operator_class_oid,ordinality)
          JOIN opclass_identity AS operator_class
            ON operator_class.oid = item.operator_class_oid
        ),'[]'::pg_catalog.jsonb),
        'options_bits',pg_catalog.to_jsonb(
          index_row.indoption::pg_catalog.int2[]
        ),
        'expressions',pg_catalog.pg_get_expr(
          index_row.indexprs,index_row.indrelid,false
        ),
        'predicate',pg_catalog.pg_get_expr(
          index_row.indpred,index_row.indrelid,false
        )
      )
    FROM toast_relation AS toast_surface
    JOIN pg_catalog.pg_index AS index_row
      ON index_row.indrelid = toast_surface.oid
    JOIN pg_catalog.pg_class AS index_relation
      ON index_relation.oid = index_row.indexrelid
    JOIN pg_catalog.pg_roles AS owner ON owner.oid = index_relation.relowner
    LEFT JOIN pg_catalog.pg_tablespace AS tablespace
      ON tablespace.oid = index_relation.reltablespace
    LEFT JOIN pg_catalog.pg_am AS access_method
      ON access_method.oid = index_relation.relam
  ), toast_index_surface(base_identity,ordinality,definition) AS (
    SELECT base_identity,
      pg_catalog.row_number() OVER (
        PARTITION BY base_identity
        ORDER BY definition::text COLLATE "C",index_oid
      ),definition
    FROM toast_index_catalog
  ), surface(kind,identity,definition) AS (
    SELECT 'schema',pg_catalog.jsonb_build_object(
      'schema',namespace.nspname
    ),pg_catalog.jsonb_build_object('owner',owner.rolname)
    FROM pg_catalog.pg_namespace AS namespace
    JOIN pg_catalog.pg_roles AS owner ON owner.oid = namespace.nspowner
    WHERE namespace.nspname IN ('app','public')
    UNION ALL
    SELECT 'database',pg_catalog.jsonb_build_object('database','current'),
      pg_catalog.jsonb_build_object(
        'owner_is_reachable_runtime_role',database_row.datdba IN (
          SELECT reachable.oid FROM reachable_role AS reachable
        ),
        'encoding',pg_catalog.pg_encoding_to_char(database_row.encoding),
        'locale_provider',database_row.datlocprovider::text,
        'is_template',database_row.datistemplate,
        'allow_connections',database_row.datallowconn,
        'has_login_event_triggers',database_row.dathasloginevt,
        'connection_limit',database_row.datconnlimit,
        'default_tablespace',tablespace.spcname,
        'collate',database_row.datcollate,
        'ctype',database_row.datctype,
        'locale',database_row.datlocale,
        'icu_rules',database_row.daticurules,
        'collation_version',database_row.datcollversion
      )
    FROM pg_catalog.pg_database AS database_row
    JOIN pg_catalog.pg_tablespace AS tablespace
      ON tablespace.oid = database_row.dattablespace
    WHERE database_row.datname = pg_catalog.current_database()
    UNION ALL
    SELECT 'role',pg_catalog.jsonb_build_object('role',role.rolname),
      pg_catalog.jsonb_build_object(
        'superuser',role.rolsuper,'inherit',role.rolinherit,
        'create_role',role.rolcreaterole,'create_database',role.rolcreatedb,
        'login',role.rolcanlogin,'replication',role.rolreplication,
        'bypass_rls',role.rolbypassrls,'connection_limit',role.rolconnlimit,
        'valid_until',CASE
          WHEN role.rolvaliduntil IS NULL THEN NULL
          WHEN role.rolvaliduntil = 'infinity'::pg_catalog.timestamptz
            THEN 'infinity'
          WHEN role.rolvaliduntil = '-infinity'::pg_catalog.timestamptz
            THEN '-infinity'
          ELSE pg_catalog.to_char(
            role.rolvaliduntil AT TIME ZONE 'UTC',
            'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'
          )
        END
      )
    FROM reachable_role AS expected
    JOIN pg_catalog.pg_roles AS role ON role.oid = expected.oid
    UNION ALL
    SELECT 'role-membership',pg_catalog.jsonb_build_object(
      'granted_role',granted.rolname,'member_role',member.rolname
    ),pg_catalog.jsonb_build_object(
      'grantor',grantor.rolname,'admin_option',membership.admin_option,
      'inherit_option',membership.inherit_option,
      'set_option',membership.set_option
    )
    FROM pg_catalog.pg_auth_members AS membership
    JOIN pg_catalog.pg_roles AS granted ON granted.oid = membership.roleid
    JOIN pg_catalog.pg_roles AS member ON member.oid = membership.member
    JOIN pg_catalog.pg_roles AS grantor ON grantor.oid = membership.grantor
    WHERE membership.roleid IN (SELECT oid FROM reachable_role)
      AND membership.roleid NOT IN (
        SELECT login_role.oid FROM managed_runtime_login_role AS login_role
      )
      AND membership.member NOT IN (
        SELECT login_role.oid FROM managed_runtime_login_role AS login_role
      )
      AND membership.grantor NOT IN (
        SELECT login_role.oid FROM managed_runtime_login_role AS login_role
      )
    UNION ALL
    SELECT 'role-setting',pg_catalog.jsonb_build_object(
      'database',CASE WHEN setting.setdatabase = 0 THEN '*'
        ELSE 'current' END,
      'role',CASE WHEN setting.setrole = 0 THEN '*'
        ELSE role.rolname END
    ),pg_catalog.jsonb_build_object(
      'settings',pg_catalog.to_jsonb(ARRAY(
        SELECT item.setting
        FROM pg_catalog.unnest(setting.setconfig) AS item(setting)
        ORDER BY pg_catalog.split_part(item.setting,'=',1) COLLATE "C",
          item.setting COLLATE "C"
      ))
    )
    FROM pg_catalog.pg_db_role_setting AS setting
    LEFT JOIN pg_catalog.pg_roles AS role ON role.oid = setting.setrole
    WHERE setting.setdatabase IN (
        0,(SELECT database_row.oid FROM pg_catalog.pg_database AS database_row
           WHERE database_row.datname = pg_catalog.current_database())
      )
      AND (setting.setrole = 0 OR setting.setrole IN (
        SELECT oid FROM reachable_role
      ))
    UNION ALL
    SELECT 'parameter-acl',pg_catalog.jsonb_build_object(
      'parameter',parameter_acl.parname
    ),pg_catalog.jsonb_build_object('tracked',true)
    FROM pg_catalog.pg_parameter_acl AS parameter_acl
    WHERE EXISTS (
      SELECT 1
      FROM pg_catalog.aclexplode(CASE
        WHEN pg_catalog.cardinality(parameter_acl.paracl) > 0
          THEN parameter_acl.paracl
        ELSE NULL::pg_catalog.aclitem[]
      END) AS acl
      WHERE acl.grantee = 0 OR acl.grantee IN (SELECT oid FROM reachable_role)
    )
    UNION ALL
    SELECT 'parameter-acl-entry',pg_catalog.jsonb_build_object(
      'parameter',parameter_acl.parname,
      'grantor',grantor.rolname,
      'grantee',coalesce(grantee.rolname,'PUBLIC'),
      'privilege',acl.privilege_type
    ),pg_catalog.jsonb_build_object('grantable',acl.is_grantable)
    FROM pg_catalog.pg_parameter_acl AS parameter_acl
    CROSS JOIN LATERAL pg_catalog.aclexplode(CASE
      WHEN pg_catalog.cardinality(parameter_acl.paracl) > 0
        THEN parameter_acl.paracl
      ELSE NULL::pg_catalog.aclitem[]
    END) AS acl
    JOIN pg_catalog.pg_roles AS grantor ON grantor.oid = acl.grantor
    LEFT JOIN pg_catalog.pg_roles AS grantee ON grantee.oid = acl.grantee
    WHERE acl.grantee = 0 OR acl.grantee IN (SELECT oid FROM reachable_role)
    UNION ALL
    SELECT 'default-acl',pg_catalog.jsonb_build_object(
      'owner',owner.rolname,
      'schema',coalesce(namespace.nspname,'<global>'),
      'object_type',default_acl.defaclobjtype::text
    ),pg_catalog.jsonb_build_object('tracked',true)
    FROM pg_catalog.pg_default_acl AS default_acl
    JOIN pg_catalog.pg_roles AS owner ON owner.oid = default_acl.defaclrole
    LEFT JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = default_acl.defaclnamespace
    WHERE default_acl.defaclrole IN (SELECT oid FROM reachable_role)
    UNION ALL
    SELECT 'default-acl-entry',pg_catalog.jsonb_build_object(
      'owner',owner.rolname,
      'schema',coalesce(namespace.nspname,'<global>'),
      'object_type',default_acl.defaclobjtype::text,
      'grantor',grantor.rolname,
      'grantee',coalesce(grantee.rolname,'PUBLIC'),
      'privilege',acl.privilege_type
    ),pg_catalog.jsonb_build_object('grantable',acl.is_grantable)
    FROM pg_catalog.pg_default_acl AS default_acl
    JOIN pg_catalog.pg_roles AS owner ON owner.oid = default_acl.defaclrole
    LEFT JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = default_acl.defaclnamespace
    CROSS JOIN LATERAL pg_catalog.aclexplode(CASE
      WHEN pg_catalog.cardinality(default_acl.defaclacl) > 0
        THEN default_acl.defaclacl
      ELSE NULL::pg_catalog.aclitem[]
    END) AS acl
    JOIN pg_catalog.pg_roles AS grantor ON grantor.oid = acl.grantor
    LEFT JOIN pg_catalog.pg_roles AS grantee ON grantee.oid = acl.grantee
    WHERE default_acl.defaclrole IN (SELECT oid FROM reachable_role)
    UNION ALL
    SELECT 'acl-entry',object_acl.object_identity ||
      pg_catalog.jsonb_build_object(
        'object_kind',object_acl.object_kind,
        'grantor',CASE
          WHEN object_acl.object_kind = 'database'
            AND acl.grantor = object_acl.owner_oid THEN '<database-owner>'
          ELSE grantor.rolname
        END,
        'grantee',CASE
          WHEN object_acl.object_kind = 'database'
            AND acl.grantee = object_acl.owner_oid THEN '<database-owner>'
          ELSE coalesce(grantee.rolname,'PUBLIC')
        END,
        'privilege',acl.privilege_type
      ),pg_catalog.jsonb_build_object('grantable',acl.is_grantable)
    FROM object_acl
    CROSS JOIN LATERAL pg_catalog.aclexplode(CASE
      WHEN pg_catalog.cardinality(object_acl.acl) > 0 THEN object_acl.acl
      ELSE NULL::pg_catalog.aclitem[]
    END) AS acl
    JOIN pg_catalog.pg_roles AS grantor ON grantor.oid = acl.grantor
    LEFT JOIN pg_catalog.pg_roles AS grantee ON grantee.oid = acl.grantee
    UNION ALL
    SELECT 'relation',pg_catalog.jsonb_build_object(
      'relation',identity.identity
    ),pg_catalog.jsonb_build_object(
      'owner',owner.rolname,'kind',relation_row.relkind::text,
      'persistence',relation_row.relpersistence::text,
      'access_method',access_method.amname,
      'tablespace',CASE WHEN relation_row.reltablespace = 0
        THEN '<database-default>' ELSE tablespace.spcname END,
      'of_type',CASE WHEN relation_row.reloftype = 0 THEN NULL
        ELSE pg_catalog.format_type(relation_row.reloftype,NULL) END,
      'has_toast',relation_row.reltoastrelid <> 0,
      'has_index',relation_row.relhasindex,
      'is_shared',relation_row.relisshared,
      'attribute_count',relation_row.relnatts,
      'check_count',relation_row.relchecks,
      'has_rules',relation_row.relhasrules,
      'has_triggers',relation_row.relhastriggers,
      'has_subclass',relation_row.relhassubclass,
      'row_security',relation_row.relrowsecurity,
      'force_row_security',relation_row.relforcerowsecurity,
      'is_populated',relation_row.relispopulated,
      'replica_identity',relation_row.relreplident::text,
      'is_partition',relation_row.relispartition,
      'rewrite_is_clear',relation_row.relrewrite = 0,
      'options',pg_catalog.to_jsonb(ARRAY(
        SELECT option FROM pg_catalog.unnest(relation_row.reloptions) AS option
        ORDER BY option COLLATE "C"
      )),
      'partition_bound',pg_catalog.pg_get_expr(
        relation_row.relpartbound,relation_row.oid,false
      ),
      'view_definition',CASE WHEN relation_row.relkind IN ('v','m')
        THEN pg_catalog.pg_get_viewdef(relation_row.oid,false) ELSE NULL END
    )
    FROM protected_relation AS expected
    JOIN pg_catalog.pg_class AS relation_row ON relation_row.oid = expected.oid
    JOIN relation_identity AS identity ON identity.oid = relation_row.oid
    JOIN pg_catalog.pg_roles AS owner ON owner.oid = relation_row.relowner
    LEFT JOIN pg_catalog.pg_tablespace AS tablespace
      ON tablespace.oid = relation_row.reltablespace
    LEFT JOIN pg_catalog.pg_am AS access_method
      ON access_method.oid = relation_row.relam
    UNION ALL
    SELECT 'toast',pg_catalog.jsonb_build_object(
      'relation',identity.identity
    ),pg_catalog.jsonb_build_object(
      'owner',toast_owner.rolname,'kind',toast.relkind::text,
      'persistence',toast.relpersistence::text,
      'access_method',access_method.amname,
      'tablespace',CASE WHEN toast.reltablespace = 0
        THEN '<database-default>' ELSE tablespace.spcname END,
      'of_type',CASE WHEN toast.reloftype = 0 THEN NULL
        ELSE pg_catalog.format_type(toast.reloftype,NULL) END,
      'has_toast',toast.reltoastrelid <> 0,
      'has_index',toast.relhasindex,
      'is_shared',toast.relisshared,
      'attribute_count',toast.relnatts,
      'check_count',toast.relchecks,
      'has_rules',toast.relhasrules,
      'has_triggers',toast.relhastriggers,
      'has_subclass',toast.relhassubclass,
      'row_security',toast.relrowsecurity,
      'force_row_security',toast.relforcerowsecurity,
      'is_populated',toast.relispopulated,
      'replica_identity',toast.relreplident::text,
      'is_partition',toast.relispartition,
      'rewrite_is_clear',toast.relrewrite = 0,
      'options',pg_catalog.to_jsonb(ARRAY(
        SELECT option FROM pg_catalog.unnest(toast.reloptions) AS option
        ORDER BY option COLLATE "C"
      )),
      'partition_bound',pg_catalog.pg_get_expr(
        toast.relpartbound,toast.oid,false
      )
    )
    FROM protected_relation AS expected
    JOIN pg_catalog.pg_class AS relation_row ON relation_row.oid = expected.oid
    JOIN relation_identity AS identity ON identity.oid = relation_row.oid
    JOIN pg_catalog.pg_class AS toast ON toast.oid = relation_row.reltoastrelid
    JOIN pg_catalog.pg_roles AS toast_owner ON toast_owner.oid = toast.relowner
    LEFT JOIN pg_catalog.pg_tablespace AS tablespace
      ON tablespace.oid = toast.reltablespace
    LEFT JOIN pg_catalog.pg_am AS access_method ON access_method.oid = toast.relam
    UNION ALL
    SELECT 'toast-index',pg_catalog.jsonb_build_object(
      'relation',toast_index.base_identity,
      'ordinality',toast_index.ordinality
    ),toast_index.definition
    FROM toast_index_surface AS toast_index
    UNION ALL
    SELECT 'toast-column',pg_catalog.jsonb_build_object(
      'relation',toast_surface.base_identity,
      'attnum',column_row.attnum
    ),pg_catalog.jsonb_build_object(
      'name',column_row.attname,
      'type',CASE WHEN column_row.attisdropped THEN NULL
        ELSE pg_catalog.format_type(column_row.atttypid,column_row.atttypmod) END,
      'length',column_row.attlen,'dimensions',column_row.attndims,
      'by_value',column_row.attbyval,'alignment',column_row.attalign::text,
      'storage',column_row.attstorage::text,
      'compression',column_row.attcompression::text,
      'not_null',column_row.attnotnull,'has_default',column_row.atthasdef,
      'has_missing',column_row.atthasmissing,
      'identity_kind',column_row.attidentity::text,
      'generated_kind',column_row.attgenerated::text,
      'is_dropped',column_row.attisdropped,
      'is_local',column_row.attislocal,
      'inheritance_count',column_row.attinhcount,
      'collation',CASE WHEN column_row.attcollation = 0 THEN NULL ELSE
        pg_catalog.format('%I.%I',collation_namespace.nspname,
          collation_row.collname) END,
      'statistics_target',column_row.attstattarget,
      'options',pg_catalog.to_jsonb(ARRAY(
        SELECT option FROM pg_catalog.unnest(column_row.attoptions) AS option
        ORDER BY option COLLATE "C"
      )),
      'fdw_options',pg_catalog.to_jsonb(ARRAY(
        SELECT option FROM pg_catalog.unnest(column_row.attfdwoptions) AS option
        ORDER BY option COLLATE "C"
      )),
      'default_expression',pg_catalog.pg_get_expr(
        default_row.adbin,default_row.adrelid,false
      )
    )
    FROM toast_relation AS toast_surface
    JOIN pg_catalog.pg_attribute AS column_row
      ON column_row.attrelid = toast_surface.oid AND column_row.attnum > 0
    LEFT JOIN pg_catalog.pg_attrdef AS default_row
      ON default_row.adrelid = column_row.attrelid
     AND default_row.adnum = column_row.attnum
    LEFT JOIN pg_catalog.pg_collation AS collation_row
      ON collation_row.oid = column_row.attcollation
    LEFT JOIN pg_catalog.pg_namespace AS collation_namespace
      ON collation_namespace.oid = collation_row.collnamespace
    UNION ALL
    SELECT 'column',pg_catalog.jsonb_build_object(
      'relation',identity.identity,'attnum',column_row.attnum
    ),pg_catalog.jsonb_build_object(
      'name',column_row.attname,
      'type',CASE WHEN column_row.attisdropped THEN NULL
        ELSE pg_catalog.format_type(column_row.atttypid,column_row.atttypmod) END,
      'length',column_row.attlen,'dimensions',column_row.attndims,
      'by_value',column_row.attbyval,'alignment',column_row.attalign::text,
      'storage',column_row.attstorage::text,
      'compression',column_row.attcompression::text,
      'not_null',column_row.attnotnull,'has_default',column_row.atthasdef,
      'has_missing',column_row.atthasmissing,
      'identity_kind',column_row.attidentity::text,
      'generated_kind',column_row.attgenerated::text,
      'is_dropped',column_row.attisdropped,
      'is_local',column_row.attislocal,
      'inheritance_count',column_row.attinhcount,
      'collation',CASE WHEN column_row.attcollation = 0 THEN NULL ELSE
        pg_catalog.format('%I.%I',collation_namespace.nspname,
          collation_row.collname) END,
      'statistics_target',column_row.attstattarget,
      'options',pg_catalog.to_jsonb(ARRAY(
        SELECT option FROM pg_catalog.unnest(column_row.attoptions) AS option
        ORDER BY option COLLATE "C"
      )),
      'fdw_options',pg_catalog.to_jsonb(ARRAY(
        SELECT option FROM pg_catalog.unnest(column_row.attfdwoptions) AS option
        ORDER BY option COLLATE "C"
      )),
      'default_expression',pg_catalog.pg_get_expr(
        default_row.adbin,default_row.adrelid,false
      )
    )
    FROM protected_relation AS expected
    JOIN relation_identity AS identity ON identity.oid = expected.oid
    JOIN pg_catalog.pg_attribute AS column_row
      ON column_row.attrelid = expected.oid AND column_row.attnum > 0
    LEFT JOIN pg_catalog.pg_attrdef AS default_row
      ON default_row.adrelid = column_row.attrelid
     AND default_row.adnum = column_row.attnum
    LEFT JOIN pg_catalog.pg_collation AS collation_row
      ON collation_row.oid = column_row.attcollation
    LEFT JOIN pg_catalog.pg_namespace AS collation_namespace
      ON collation_namespace.oid = collation_row.collnamespace
    UNION ALL
    SELECT 'constraint',pg_catalog.jsonb_build_object(
      'relation',relation.identity,
      'domain',CASE WHEN constraint_row.contypid = 0 THEN NULL ELSE
        pg_catalog.format('%I.%I',domain_namespace.nspname,domain_type.typname) END,
      'constraint',constraint_row.conname
    ),pg_catalog.jsonb_build_object(
      'namespace',constraint_namespace.nspname,
      'type',constraint_row.contype::text,
      'deferrable',constraint_row.condeferrable,
      'initially_deferred',constraint_row.condeferred,
      'enforced',constraint_row.conenforced,
      'validated',constraint_row.convalidated,
      'supporting_index',supporting_index.identity,
      'parent_constraint',CASE WHEN parent_constraint.oid IS NULL THEN NULL
        ELSE pg_catalog.jsonb_build_object(
          'relation',parent_relation.identity,
          'name',parent_constraint.conname
        ) END,
      'referenced_relation',referenced_relation.identity,
      'update_action',constraint_row.confupdtype::text,
      'delete_action',constraint_row.confdeltype::text,
      'match_type',constraint_row.confmatchtype::text,
      'is_local',constraint_row.conislocal,
      'inheritance_count',constraint_row.coninhcount,
      'no_inherit',constraint_row.connoinherit,
      'period',constraint_row.conperiod,
      'key_columns',pg_catalog.to_jsonb(constraint_row.conkey),
      'referenced_key_columns',pg_catalog.to_jsonb(constraint_row.confkey),
      'delete_set_columns',pg_catalog.to_jsonb(constraint_row.confdelsetcols),
      'pk_fk_operators',coalesce((
        SELECT pg_catalog.jsonb_agg(operator.identity ORDER BY item.ordinality)
        FROM pg_catalog.unnest(constraint_row.conpfeqop)
          WITH ORDINALITY AS item(operator_oid,ordinality)
        JOIN operator_identity AS operator ON operator.oid = item.operator_oid
      ),'[]'::pg_catalog.jsonb),
      'pk_pk_operators',coalesce((
        SELECT pg_catalog.jsonb_agg(operator.identity ORDER BY item.ordinality)
        FROM pg_catalog.unnest(constraint_row.conppeqop)
          WITH ORDINALITY AS item(operator_oid,ordinality)
        JOIN operator_identity AS operator ON operator.oid = item.operator_oid
      ),'[]'::pg_catalog.jsonb),
      'fk_fk_operators',coalesce((
        SELECT pg_catalog.jsonb_agg(operator.identity ORDER BY item.ordinality)
        FROM pg_catalog.unnest(constraint_row.conffeqop)
          WITH ORDINALITY AS item(operator_oid,ordinality)
        JOIN operator_identity AS operator ON operator.oid = item.operator_oid
      ),'[]'::pg_catalog.jsonb),
      'exclusion_operators',coalesce((
        SELECT pg_catalog.jsonb_agg(operator.identity ORDER BY item.ordinality)
        FROM pg_catalog.unnest(constraint_row.conexclop)
          WITH ORDINALITY AS item(operator_oid,ordinality)
        JOIN operator_identity AS operator ON operator.oid = item.operator_oid
      ),'[]'::pg_catalog.jsonb),
      'definition',pg_catalog.pg_get_constraintdef(
        constraint_row.oid,false
      )
    )
    FROM pg_catalog.pg_constraint AS constraint_row
    JOIN pg_catalog.pg_namespace AS constraint_namespace
      ON constraint_namespace.oid = constraint_row.connamespace
    LEFT JOIN relation_identity AS relation
      ON relation.oid = constraint_row.conrelid
    LEFT JOIN pg_catalog.pg_type AS domain_type
      ON domain_type.oid = constraint_row.contypid
    LEFT JOIN pg_catalog.pg_namespace AS domain_namespace
      ON domain_namespace.oid = domain_type.typnamespace
    LEFT JOIN relation_identity AS supporting_index
      ON supporting_index.oid = constraint_row.conindid
    LEFT JOIN pg_catalog.pg_constraint AS parent_constraint
      ON parent_constraint.oid = constraint_row.conparentid
    LEFT JOIN relation_identity AS parent_relation
      ON parent_relation.oid = parent_constraint.conrelid
    LEFT JOIN relation_identity AS referenced_relation
      ON referenced_relation.oid = constraint_row.confrelid
    WHERE constraint_row.conrelid IN (SELECT oid FROM protected_relation)
       OR constraint_row.contypid IN (SELECT oid FROM public_type)
    UNION ALL
    SELECT 'index',pg_catalog.jsonb_build_object(
      'relation',base_relation.identity,'index',index_identity.identity
    ),pg_catalog.jsonb_build_object(
      'owner',owner.rolname,'kind',index_relation.relkind::text,
      'persistence',index_relation.relpersistence::text,
      'access_method',access_method.amname,
      'tablespace',CASE WHEN index_relation.reltablespace = 0
        THEN '<database-default>' ELSE tablespace.spcname END,
      'is_partition',index_relation.relispartition,
      'options',pg_catalog.to_jsonb(ARRAY(
        SELECT option FROM pg_catalog.unnest(index_relation.reloptions) AS option
        ORDER BY option COLLATE "C"
      )),
      'attribute_count',index_row.indnatts,
      'key_attribute_count',index_row.indnkeyatts,
      'unique',index_row.indisunique,
      'nulls_not_distinct',index_row.indnullsnotdistinct,
      'primary',index_row.indisprimary,
      'exclusion',index_row.indisexclusion,
      'immediate',index_row.indimmediate,
      'clustered',index_row.indisclustered,
      'valid',index_row.indisvalid,
      'check_xmin',index_row.indcheckxmin,
      'ready',index_row.indisready,
      'live',index_row.indislive,
      'replica_identity',index_row.indisreplident,
      'keys',pg_catalog.to_jsonb(index_row.indkey::pg_catalog.int2[]),
      'collations',coalesce((
        SELECT pg_catalog.jsonb_agg(
          CASE WHEN item.collation_oid = 0 THEN NULL ELSE
            pg_catalog.format('%I.%I',namespace.nspname,collation_row.collname) END
          ORDER BY item.ordinality
        )
        FROM pg_catalog.unnest(index_row.indcollation::pg_catalog.oid[])
          WITH ORDINALITY AS item(collation_oid,ordinality)
        LEFT JOIN pg_catalog.pg_collation AS collation_row
          ON collation_row.oid = item.collation_oid
        LEFT JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = collation_row.collnamespace
      ),'[]'::pg_catalog.jsonb),
      'operator_classes',coalesce((
        SELECT pg_catalog.jsonb_agg(operator_class.identity ORDER BY item.ordinality)
        FROM pg_catalog.unnest(index_row.indclass::pg_catalog.oid[])
          WITH ORDINALITY AS item(operator_class_oid,ordinality)
        JOIN opclass_identity AS operator_class
          ON operator_class.oid = item.operator_class_oid
      ),'[]'::pg_catalog.jsonb),
      'options_bits',pg_catalog.to_jsonb(index_row.indoption::pg_catalog.int2[]),
      'expressions',pg_catalog.pg_get_expr(
        index_row.indexprs,index_row.indrelid,false
      ),
      'predicate',pg_catalog.pg_get_expr(
        index_row.indpred,index_row.indrelid,false
      ),
      'definition',pg_catalog.pg_get_indexdef(index_row.indexrelid,0,false)
    )
    FROM protected_relation AS expected
    JOIN pg_catalog.pg_index AS index_row ON index_row.indrelid = expected.oid
    JOIN pg_catalog.pg_class AS index_relation
      ON index_relation.oid = index_row.indexrelid
    JOIN relation_identity AS base_relation ON base_relation.oid = expected.oid
    JOIN relation_identity AS index_identity
      ON index_identity.oid = index_relation.oid
    JOIN pg_catalog.pg_roles AS owner ON owner.oid = index_relation.relowner
    LEFT JOIN pg_catalog.pg_tablespace AS tablespace
      ON tablespace.oid = index_relation.reltablespace
    LEFT JOIN pg_catalog.pg_am AS access_method
      ON access_method.oid = index_relation.relam
    UNION ALL
    SELECT 'trigger',pg_catalog.jsonb_build_object(
      'relation',trigger_relation.identity,
      'name',CASE WHEN trigger_row.tgisinternal THEN NULL
        ELSE trigger_row.tgname END,
      'internal',trigger_row.tgisinternal,
      'constraint',CASE WHEN trigger_constraint.oid IS NULL THEN NULL
        ELSE pg_catalog.jsonb_build_object(
          'relation',constraint_relation.identity,
          'name',trigger_constraint.conname
        ) END,
      'function',trigger_function.identity,
      'type',trigger_row.tgtype
    ),pg_catalog.jsonb_build_object(
      'enabled',trigger_row.tgenabled::text,
      'constraint_relation',constraint_target.identity,
      'constraint_index',constraint_index.identity,
      'deferrable',trigger_row.tgdeferrable,
      'initially_deferred',trigger_row.tginitdeferred,
      'parent_trigger',CASE WHEN parent_trigger.oid IS NULL THEN NULL ELSE
        pg_catalog.jsonb_build_object(
          'relation',parent_trigger_relation.identity,
          'name',CASE WHEN parent_trigger.tgisinternal THEN NULL
            ELSE parent_trigger.tgname END,
          'function',parent_trigger_function.identity,
          'type',parent_trigger.tgtype
        ) END,
      'argument_count',trigger_row.tgnargs,
      'attributes',pg_catalog.to_jsonb(trigger_row.tgattr::pg_catalog.int2[]),
      'arguments_hex',pg_catalog.encode(trigger_row.tgargs,'hex'),
      'qualifier_present',trigger_row.tgqual IS NOT NULL,
      'old_transition_table',trigger_row.tgoldtable,
      'new_transition_table',trigger_row.tgnewtable,
      'definition',CASE WHEN trigger_row.tgisinternal THEN
        pg_catalog.replace(
          pg_catalog.pg_get_triggerdef(trigger_row.oid,false),
          trigger_row.tgname,'<internal>'
        ) ELSE pg_catalog.pg_get_triggerdef(trigger_row.oid,false) END
    )
    FROM protected_relation AS expected
    JOIN pg_catalog.pg_trigger AS trigger_row
      ON trigger_row.tgrelid = expected.oid
    JOIN relation_identity AS trigger_relation
      ON trigger_relation.oid = trigger_row.tgrelid
    JOIN function_identity AS trigger_function
      ON trigger_function.oid = trigger_row.tgfoid
    LEFT JOIN pg_catalog.pg_constraint AS trigger_constraint
      ON trigger_constraint.oid = trigger_row.tgconstraint
    LEFT JOIN relation_identity AS constraint_relation
      ON constraint_relation.oid = trigger_constraint.conrelid
    LEFT JOIN relation_identity AS constraint_target
      ON constraint_target.oid = trigger_row.tgconstrrelid
    LEFT JOIN relation_identity AS constraint_index
      ON constraint_index.oid = trigger_row.tgconstrindid
    LEFT JOIN pg_catalog.pg_trigger AS parent_trigger
      ON parent_trigger.oid = trigger_row.tgparentid
    LEFT JOIN relation_identity AS parent_trigger_relation
      ON parent_trigger_relation.oid = parent_trigger.tgrelid
    LEFT JOIN function_identity AS parent_trigger_function
      ON parent_trigger_function.oid = parent_trigger.tgfoid
    UNION ALL
    SELECT 'policy',pg_catalog.jsonb_build_object(
      'relation',identity.identity,'policy',policy_row.polname
    ),pg_catalog.jsonb_build_object(
      'command',policy_row.polcmd::text,
      'permissive',policy_row.polpermissive,
      'roles',pg_catalog.to_jsonb(ARRAY(
        SELECT coalesce(role.rolname,'PUBLIC')
        FROM pg_catalog.unnest(policy_row.polroles) AS item(role_oid)
        LEFT JOIN pg_catalog.pg_roles AS role ON role.oid = item.role_oid
        ORDER BY coalesce(role.rolname,'PUBLIC') COLLATE "C"
      )),
      'qualifier',pg_catalog.pg_get_expr(
        policy_row.polqual,policy_row.polrelid,false
      ),
      'with_check',pg_catalog.pg_get_expr(
        policy_row.polwithcheck,policy_row.polrelid,false
      )
    )
    FROM protected_relation AS expected
    JOIN relation_identity AS identity ON identity.oid = expected.oid
    JOIN pg_catalog.pg_policy AS policy_row ON policy_row.polrelid = expected.oid
    UNION ALL
    SELECT 'rule',pg_catalog.jsonb_build_object(
      'relation',identity.identity,'rule',rule_row.rulename
    ),pg_catalog.jsonb_build_object(
      'definition',pg_catalog.pg_get_ruledef(rule_row.oid,false)
    )
    FROM protected_relation AS expected
    JOIN relation_identity AS identity ON identity.oid = expected.oid
    JOIN pg_catalog.pg_rewrite AS rule_row ON rule_row.ev_class = expected.oid
    UNION ALL
    SELECT 'inheritance',pg_catalog.jsonb_build_object(
      'child',child.identity,'parent',parent.identity
    ),pg_catalog.jsonb_build_object(
      'sequence',inheritance.inhseqno,
      'detach_pending',inheritance.inhdetachpending
    )
    FROM pg_catalog.pg_inherits AS inheritance
    JOIN relation_identity AS child ON child.oid = inheritance.inhrelid
    JOIN relation_identity AS parent ON parent.oid = inheritance.inhparent
    WHERE inheritance.inhrelid IN (SELECT oid FROM protected_relation)
       OR inheritance.inhparent IN (SELECT oid FROM protected_relation)
    UNION ALL
    SELECT 'partition-key',pg_catalog.jsonb_build_object(
      'relation',identity.identity
    ),pg_catalog.jsonb_build_object(
      'strategy',partitioned.partstrat::text,
      'attribute_count',partitioned.partnatts,
      'default_partition',default_partition.identity,
      'attributes',pg_catalog.to_jsonb(
        partitioned.partattrs::pg_catalog.int2[]
      ),
      'operator_classes',coalesce((
        SELECT pg_catalog.jsonb_agg(operator_class.identity ORDER BY item.ordinality)
        FROM pg_catalog.unnest(partitioned.partclass::pg_catalog.oid[])
          WITH ORDINALITY AS item(operator_class_oid,ordinality)
        JOIN opclass_identity AS operator_class
          ON operator_class.oid = item.operator_class_oid
      ),'[]'::pg_catalog.jsonb),
      'collations',coalesce((
        SELECT pg_catalog.jsonb_agg(
          CASE WHEN item.collation_oid = 0 THEN NULL ELSE
            pg_catalog.format('%I.%I',namespace.nspname,collation_row.collname) END
          ORDER BY item.ordinality
        )
        FROM pg_catalog.unnest(partitioned.partcollation::pg_catalog.oid[])
          WITH ORDINALITY AS item(collation_oid,ordinality)
        LEFT JOIN pg_catalog.pg_collation AS collation_row
          ON collation_row.oid = item.collation_oid
        LEFT JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = collation_row.collnamespace
      ),'[]'::pg_catalog.jsonb),
      'expressions',pg_catalog.pg_get_expr(
        partitioned.partexprs,partitioned.partrelid,false
      )
    )
    FROM protected_relation AS expected
    JOIN relation_identity AS identity ON identity.oid = expected.oid
    JOIN pg_catalog.pg_partitioned_table AS partitioned
      ON partitioned.partrelid = expected.oid
    LEFT JOIN relation_identity AS default_partition
      ON default_partition.oid = partitioned.partdefid
    UNION ALL
    SELECT 'sequence',pg_catalog.jsonb_build_object(
      'sequence',identity.identity
    ),pg_catalog.jsonb_build_object(
      'type',pg_catalog.format_type(sequence.seqtypid,NULL),
      'start',sequence.seqstart,'increment',sequence.seqincrement,
      'maximum',sequence.seqmax,'minimum',sequence.seqmin,
      'cache',sequence.seqcache,'cycle',sequence.seqcycle
    )
    FROM protected_relation AS expected
    JOIN pg_catalog.pg_class AS relation_row ON relation_row.oid = expected.oid
    JOIN relation_identity AS identity ON identity.oid = expected.oid
    JOIN pg_catalog.pg_sequence AS sequence ON sequence.seqrelid = expected.oid
    WHERE relation_row.relkind = 'S'
    UNION ALL
    SELECT 'sequence-dependency',pg_catalog.jsonb_build_object(
      'sequence',sequence_identity.identity,
      'referenced_relation',referenced_identity.identity,
      'referenced_attnum',dependency.refobjsubid
    ),pg_catalog.jsonb_build_object(
      'referenced_column',referenced_column.attname,
      'dependency_type',dependency.deptype::text,
      'dependent_subobject',dependency.objsubid
    )
    FROM protected_relation AS expected
    JOIN pg_catalog.pg_class AS sequence_relation
      ON sequence_relation.oid = expected.oid AND sequence_relation.relkind = 'S'
    JOIN relation_identity AS sequence_identity
      ON sequence_identity.oid = sequence_relation.oid
    JOIN pg_catalog.pg_depend AS dependency
      ON dependency.classid = 'pg_catalog.pg_class'::pg_catalog.regclass
     AND dependency.objid = sequence_relation.oid
     AND dependency.refclassid = 'pg_catalog.pg_class'::pg_catalog.regclass
     AND dependency.deptype IN ('a','i')
    JOIN relation_identity AS referenced_identity
      ON referenced_identity.oid = dependency.refobjid
    LEFT JOIN pg_catalog.pg_attribute AS referenced_column
      ON referenced_column.attrelid = dependency.refobjid
     AND referenced_column.attnum = dependency.refobjsubid
    UNION ALL
    SELECT 'collation',pg_catalog.jsonb_build_object(
      'collation',pg_catalog.format('%I.%I',namespace.nspname,
        collation_row.collname),
      'encoding',CASE WHEN collation_row.collencoding = -1 THEN '*'
        ELSE pg_catalog.pg_encoding_to_char(collation_row.collencoding) END
    ),pg_catalog.jsonb_build_object(
      'owner',owner.rolname,
      'provider',collation_row.collprovider::text,
      'deterministic',collation_row.collisdeterministic,
      'collate',collation_row.collcollate,
      'ctype',collation_row.collctype,
      'locale',collation_row.colllocale,
      'icu_rules',collation_row.collicurules,
      'version',collation_row.collversion
    )
    FROM referenced_collation AS expected
    JOIN pg_catalog.pg_collation AS collation_row
      ON collation_row.oid = expected.oid
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = collation_row.collnamespace
    JOIN pg_catalog.pg_roles AS owner ON owner.oid = collation_row.collowner
    UNION ALL
    SELECT 'type',pg_catalog.jsonb_build_object(
      'type',pg_catalog.format('%I.%I',namespace.nspname,type_row.typname)
    ),pg_catalog.jsonb_build_object(
      'owner',owner.rolname,'kind',type_row.typtype::text,
      'category',type_row.typcategory::text,
      'delimiter',type_row.typdelim::text,
      'not_null',type_row.typnotnull,
      'base_type',CASE WHEN type_row.typbasetype = 0 THEN NULL ELSE
        pg_catalog.format_type(type_row.typbasetype,type_row.typtypmod) END,
      'collation',CASE WHEN type_row.typcollation = 0 THEN NULL ELSE
        pg_catalog.format('%I.%I',collation_namespace.nspname,
          collation_row.collname) END,
      'default',type_row.typdefault,
      'enum_labels',coalesce((
        SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
          'label',enum.enumlabel,'sort_order',enum.enumsortorder::text
        ) ORDER BY enum.enumsortorder,enum.enumlabel COLLATE "C")
        FROM pg_catalog.pg_enum AS enum WHERE enum.enumtypid = type_row.oid
      ),'[]'::pg_catalog.jsonb)
    )
    FROM public_type AS expected
    JOIN pg_catalog.pg_type AS type_row ON type_row.oid = expected.oid
    JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = type_row.typnamespace
    JOIN pg_catalog.pg_roles AS owner ON owner.oid = type_row.typowner
    LEFT JOIN pg_catalog.pg_collation AS collation_row
      ON collation_row.oid = type_row.typcollation
    LEFT JOIN pg_catalog.pg_namespace AS collation_namespace
      ON collation_namespace.oid = collation_row.collnamespace
    UNION ALL
    SELECT 'function',pg_catalog.jsonb_build_object(
      'function',identity.identity
    ),pg_catalog.jsonb_build_object(
      'owner',owner.rolname,'language',language.lanname,
      'kind',function_row.prokind::text,
      'volatility',function_row.provolatile::text,
      'security_definer',function_row.prosecdef,
      'strict',function_row.proisstrict,
      'leakproof',function_row.proleakproof,
      'returns_set',function_row.proretset,
      'parallel',function_row.proparallel::text,
      'argument_count',function_row.pronargs,
      'default_argument_count',function_row.pronargdefaults,
      'variadic_type',CASE WHEN function_row.provariadic = 0 THEN NULL ELSE
        pg_catalog.format_type(function_row.provariadic,NULL) END,
      'support_function',support_function.identity,
      'cost',function_row.procost::text,'rows',function_row.prorows::text,
      'transform_types',pg_catalog.to_jsonb(ARRAY(
        SELECT pg_catalog.format_type(item.type_oid,NULL)
        FROM pg_catalog.unnest(function_row.protrftypes) AS item(type_oid)
        ORDER BY pg_catalog.format_type(item.type_oid,NULL) COLLATE "C"
      )),
      'config',pg_catalog.to_jsonb(ARRAY(
        SELECT setting FROM pg_catalog.unnest(function_row.proconfig) AS setting
        ORDER BY pg_catalog.split_part(setting,'=',1) COLLATE "C",
          setting COLLATE "C"
      )),
      'result',pg_catalog.pg_get_function_result(function_row.oid),
      'binary',function_row.probin,
      'source',function_row.prosrc,
      'definition',pg_catalog.pg_get_functiondef(function_row.oid)
    )
    FROM protected_function AS expected
    JOIN pg_catalog.pg_proc AS function_row ON function_row.oid = expected.oid
    JOIN function_identity AS identity ON identity.oid = function_row.oid
    JOIN pg_catalog.pg_roles AS owner ON owner.oid = function_row.proowner
    JOIN pg_catalog.pg_language AS language ON language.oid = function_row.prolang
    LEFT JOIN function_identity AS support_function
      ON support_function.oid = function_row.prosupport
    UNION ALL
    SELECT 'custom-operator',pg_catalog.jsonb_build_object(
      'operator',identity.identity
    ),pg_catalog.jsonb_build_object(
      'owner',owner.rolname,'kind',operator.oprkind::text,
      'can_merge',operator.oprcanmerge,'can_hash',operator.oprcanhash,
      'result_type',pg_catalog.format_type(operator.oprresult,NULL),
      'commutator',commutator.identity,'negator',negator.identity,
      'implementation',implementation.identity,
      'restriction',restriction.identity,'join',join_function.identity
    )
    FROM pg_catalog.pg_operator AS operator
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = operator.oprnamespace
    JOIN operator_identity AS identity ON identity.oid = operator.oid
    JOIN pg_catalog.pg_roles AS owner ON owner.oid = operator.oprowner
    LEFT JOIN operator_identity AS commutator ON commutator.oid = operator.oprcom
    LEFT JOIN operator_identity AS negator ON negator.oid = operator.oprnegate
    LEFT JOIN function_identity AS implementation
      ON implementation.oid = operator.oprcode
    LEFT JOIN function_identity AS restriction
      ON restriction.oid = operator.oprrest
    LEFT JOIN function_identity AS join_function
      ON join_function.oid = operator.oprjoin
    WHERE namespace.nspname IN ('app','public')
    UNION ALL
    SELECT 'custom-cast',pg_catalog.jsonb_build_object(
      'source_type',pg_catalog.format_type(cast_row.castsource,NULL),
      'target_type',pg_catalog.format_type(cast_row.casttarget,NULL)
    ),pg_catalog.jsonb_build_object(
      'function',cast_function.identity,
      'context',cast_row.castcontext::text,
      'method',cast_row.castmethod::text
    )
    FROM pg_catalog.pg_cast AS cast_row
    JOIN pg_catalog.pg_type AS source_type ON source_type.oid = cast_row.castsource
    JOIN pg_catalog.pg_namespace AS source_namespace
      ON source_namespace.oid = source_type.typnamespace
    JOIN pg_catalog.pg_type AS target_type ON target_type.oid = cast_row.casttarget
    JOIN pg_catalog.pg_namespace AS target_namespace
      ON target_namespace.oid = target_type.typnamespace
    LEFT JOIN function_identity AS cast_function
      ON cast_function.oid = cast_row.castfunc
    WHERE source_namespace.nspname IN ('app','public')
       OR target_namespace.nspname IN ('app','public')
  ), canonical_entry(entry) AS (
    SELECT pg_catalog.jsonb_build_object(
      'kind',surface.kind,'identity',surface.identity,
      'definition',surface.definition
    )::text
    FROM surface
  )
  SELECT pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
    coalesce(pg_catalog.string_agg(
      pg_catalog.octet_length(pg_catalog.convert_to(entry,'UTF8'))::text ||
      ':' || entry,'' ORDER BY entry COLLATE "C"
    ),''),'UTF8'
  )),'hex')
  FROM canonical_entry;
$function$;
ALTER FUNCTION app.private_tenant_platform_oidc_dependency_surface_hash_v1()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION
  app.private_tenant_platform_oidc_dependency_surface_hash_v1()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,
  periapsis_sla_api_owner, periapsis_sla_worker_owner,
  periapsis_sla_readiness_owner, periapsis_ticket_saved_view_owner,
  periapsis_ticket_attribution_owner,
  periapsis_ticket_sla_projection_owner;
--> statement-breakpoint

CREATE FUNCTION app.private_tenant_platform_oidc_runtime_schema_readiness_v1()
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  protected_relation_count integer;
  relation_acl_mismatch_count integer;
  runtime_login_role_mismatch_count integer;
  runtime_login_membership_mismatch_count integer;
  runtime_login_setting_mismatch_count integer;
  runtime_login_parameter_acl_mismatch_count integer;
  runtime_login_default_acl_mismatch_count integer;
  constraint_count integer;
  index_count integer;
  trigger_count integer;
  protected_function_count integer;
  private_function_count integer;
  private_acl_mismatch_count integer;
  function_definition text;
  dependency_surface_ready boolean;
  trusted_root_catalog_ready boolean;
BEGIN
  SELECT count(*) = 1 AND coalesce(bool_and(
    owner.rolname = 'periapsis_migrator' AND language.lanname = 'sql'
    AND function_row.prokind = 'f' AND function_row.provolatile = 's'
    AND function_row.prosecdef AND NOT function_row.proisstrict
    AND NOT function_row.proleakproof AND function_row.proparallel = 'u'
    AND function_row.pronargs = 0
    AND function_row.pronargdefaults = 0
    AND function_row.proargtypes = ''::pg_catalog.oidvector
    AND function_row.proargdefaults IS NULL
    AND function_row.provariadic = 0
    AND function_row.prosupport = 0
    AND NOT function_row.proretset
    AND function_row.procost = 100::real
    AND function_row.prorows = 0::real
    AND function_row.protrftypes IS NULL
    AND function_row.probin IS NULL
    AND function_row.prosqlbody IS NULL
    AND function_row.proallargtypes IS NULL
    AND function_row.proargmodes IS NULL
    AND function_row.proargnames IS NULL
    AND function_row.proconfig IS NOT DISTINCT FROM ARRAY[
      'search_path=pg_catalog, public, app',
      'quote_all_identifiers=off',
      'TimeZone=UTC',
      'DateStyle=ISO, YMD',
      'IntervalStyle=postgres',
      'extra_float_digits=3',
      'bytea_output=hex',
      'standard_conforming_strings=on',
      'lc_numeric=C'
    ]::text[]
    AND pg_catalog.pg_get_function_result(function_row.oid) = 'text'
    AND encode(sha256(convert_to(function_row.prosrc,'UTF8')),'hex') =
      '7ef3708e7225a7b643f114a26f96812fb2b1e0e187e467b9fed82350c0096d0f'
    AND app.private_tenant_platform_oidc_dependency_surface_hash_v1() =
      '793517cf04f1301d6a4a2a81d2f906315376e1de5f7afe2083fc07ca6d485b40'
    AND (SELECT count(*) = 1 AND coalesce(bool_and(
      acl.grantor = function_row.proowner
      AND acl.grantee = function_row.proowner
      AND acl.privilege_type = 'EXECUTE' AND NOT acl.is_grantable
    ),false) FROM pg_catalog.aclexplode(CASE
      WHEN pg_catalog.cardinality(coalesce(function_row.proacl,
        pg_catalog.acldefault('f',function_row.proowner))) > 0
        THEN coalesce(function_row.proacl,
          pg_catalog.acldefault('f',function_row.proowner))
      ELSE NULL::pg_catalog.aclitem[]
    END) AS acl)
  ),false) INTO dependency_surface_ready
  FROM pg_catalog.pg_proc AS function_row
  JOIN pg_catalog.pg_roles AS owner ON owner.oid = function_row.proowner
  JOIN pg_catalog.pg_language AS language ON language.oid = function_row.prolang
  WHERE function_row.oid =
    'app.private_tenant_platform_oidc_dependency_surface_hash_v1()'::regprocedure;

  WITH expected(signature,language_name,expected_result,expected_acl_roles) AS (
    VALUES
      ('app.schema_compatibility_v35()','plpgsql',
       'TABLE(applied_count bigint, latest_created_at bigint, latest_hash text, migration_fingerprint text)',
       ARRAY['periapsis_api','periapsis_migrator','periapsis_worker']::text[]),
      ('app.schema_compatibility_v34()','plpgsql',
       'TABLE(applied_count bigint, latest_created_at bigint, latest_hash text, migration_fingerprint text)',
       ARRAY['periapsis_migrator']::text[]),
      ('app.private_tenant_platform_oidc_dependency_surface_hash_v1()','sql',
       'text',ARRAY['periapsis_migrator']::text[]),
      ('app.private_tenant_platform_oidc_runtime_schema_readiness_v1()','plpgsql',
       'boolean',ARRAY['periapsis_migrator']::text[]),
      ('app.tenant_platform_oidc_runtime_schema_readiness_v1()','plpgsql',
       'boolean',ARRAY['periapsis_api','periapsis_migrator','periapsis_worker']::text[])
  ), actual AS (
    SELECT expected.*,function_row.oid,function_row.proowner,
      function_row.proconfig,function_row.prolang
    FROM expected
    LEFT JOIN pg_catalog.pg_proc AS function_row
      ON function_row.oid = pg_catalog.to_regprocedure(expected.signature)
  )
  SELECT count(*) = 5 AND coalesce(bool_and(
    actual.oid IS NOT NULL
    AND owner.rolname = 'periapsis_migrator'
    AND language.lanname = actual.language_name
    AND function_row.prokind = 'f' AND function_row.provolatile = 's'
    AND function_row.prosecdef AND NOT function_row.proisstrict
    AND NOT function_row.proleakproof AND function_row.proparallel = 'u'
    AND function_row.pronargs = 0
    AND function_row.pronargdefaults = 0
    AND function_row.proargtypes = ''::pg_catalog.oidvector
    AND function_row.proargdefaults IS NULL
    AND function_row.provariadic = 0
    AND function_row.prosupport = 0
    AND function_row.proretset = (actual.signature IN (
      'app.schema_compatibility_v35()',
      'app.schema_compatibility_v34()'
    ))
    AND function_row.procost = 100::real
    AND function_row.prorows = CASE WHEN function_row.proretset
      THEN 1000::real ELSE 0::real END
    AND function_row.protrftypes IS NULL
    AND function_row.probin IS NULL
    AND function_row.prosqlbody IS NULL
    AND CASE WHEN function_row.proretset THEN
      function_row.proallargtypes IS NOT DISTINCT FROM ARRAY[
        'bigint'::pg_catalog.regtype,
        'bigint'::pg_catalog.regtype,
        'text'::pg_catalog.regtype,
        'text'::pg_catalog.regtype
      ]::pg_catalog.oid[]
      AND function_row.proargmodes IS NOT DISTINCT FROM
        ARRAY['t','t','t','t']::"char"[]
      AND function_row.proargnames IS NOT DISTINCT FROM ARRAY[
        'applied_count','latest_created_at','latest_hash',
        'migration_fingerprint'
      ]::text[]
    ELSE
      function_row.proallargtypes IS NULL
      AND function_row.proargmodes IS NULL
      AND function_row.proargnames IS NULL
    END
    AND pg_catalog.pg_get_function_result(function_row.oid) =
      actual.expected_result
    AND CASE actual.signature
      WHEN 'app.schema_compatibility_v35()' THEN
        function_row.proconfig[1] = 'search_path=pg_catalog'
        AND function_row.proconfig[2] ~
          '^app\.schema_compatibility_fingerprint=(UNSEALED|[0-9]+@[0-9a-f]{64}(:[0-9]+@[0-9a-f]{64})*)$'
        AND pg_catalog.cardinality(function_row.proconfig) = 2
      WHEN 'app.schema_compatibility_v34()' THEN
        function_row.proconfig IS NOT DISTINCT FROM ARRAY[
          'search_path=pg_catalog',
          'app.schema_compatibility_fingerprint=RETIRED'
        ]::text[]
      WHEN 'app.private_tenant_platform_oidc_dependency_surface_hash_v1()' THEN
        function_row.proconfig IS NOT DISTINCT FROM ARRAY[
          'search_path=pg_catalog, public, app',
          'quote_all_identifiers=off','TimeZone=UTC',
          'DateStyle=ISO, YMD','IntervalStyle=postgres',
          'extra_float_digits=3','bytea_output=hex',
          'standard_conforming_strings=on','lc_numeric=C'
        ]::text[]
      ELSE function_row.proconfig IS NOT DISTINCT FROM
        ARRAY['search_path=pg_catalog, public, app']::text[]
    END
    AND (
      SELECT count(*) = pg_catalog.cardinality(actual.expected_acl_roles)
        AND pg_catalog.array_agg(
          coalesce(grantee.rolname,'PUBLIC')::text
          ORDER BY coalesce(grantee.rolname,'PUBLIC')::text COLLATE "C"
        ) IS NOT DISTINCT FROM actual.expected_acl_roles
        AND coalesce(bool_and(
          acl.grantor = function_row.proowner
          AND acl.privilege_type = 'EXECUTE' AND NOT acl.is_grantable
        ),false)
      FROM pg_catalog.aclexplode(CASE
        WHEN pg_catalog.cardinality(coalesce(
          function_row.proacl,pg_catalog.acldefault('f',function_row.proowner)
        )) > 0 THEN coalesce(
          function_row.proacl,pg_catalog.acldefault('f',function_row.proowner)
        ) ELSE NULL::pg_catalog.aclitem[]
      END) AS acl
      LEFT JOIN pg_catalog.pg_roles AS grantee ON grantee.oid = acl.grantee
    )
  ),false) INTO trusted_root_catalog_ready
  FROM actual
  LEFT JOIN pg_catalog.pg_proc AS function_row ON function_row.oid = actual.oid
  LEFT JOIN pg_catalog.pg_roles AS owner ON owner.oid = function_row.proowner
  LEFT JOIN pg_catalog.pg_language AS language ON language.oid = function_row.prolang;

  WITH expected(name) AS (VALUES
    ('platform_federated_external_identities'),
    ('platform_federated_external_identity_aliases'),
    ('tenant_platform_federated_provider_access_grants'),
    ('tenant_platform_federated_provider_profile_contributions'),
    ('tenant_platform_oidc_authentication_transactions'),
    ('tenant_platform_oidc_authentication_applications'),
    ('auth_session_tenant_platform_federated_provenance'),
    ('auth_session_tenant_platform_federated_evidence'),
    ('tenant_post_primary_platform_federated_evidence'),
    ('tenant_platform_federated_session_revalidation_commands'),
    ('tenant_mfa_authority_platform_federated_evidence'),
    ('tenant_post_primary_platform_federated_provenance'),
    ('tenant_post_primary_passkey_provenance'),
    ('tenant_mfa_webauthn_evidence_copy_capabilities')
  )
  SELECT count(*)::integer INTO protected_relation_count
  FROM expected
  JOIN pg_catalog.pg_class AS relation_row
    ON relation_row.relname = expected.name
  JOIN pg_catalog.pg_namespace AS namespace
    ON namespace.oid = relation_row.relnamespace
  JOIN pg_catalog.pg_roles AS owner ON owner.oid = relation_row.relowner
  WHERE namespace.nspname = 'public' AND relation_row.relkind = 'r'
    AND owner.rolname = 'periapsis_migrator'
    AND relation_row.relrowsecurity AND relation_row.relforcerowsecurity
    AND NOT EXISTS (
      SELECT 1 FROM pg_catalog.pg_policy AS policy
      WHERE policy.polrelid = relation_row.oid
    );

  WITH expected(name) AS (VALUES
    ('platform_federated_external_identities'),
    ('platform_federated_external_identity_aliases'),
    ('tenant_platform_federated_provider_access_grants'),
    ('tenant_platform_federated_provider_profile_contributions'),
    ('tenant_platform_oidc_authentication_transactions'),
    ('tenant_platform_oidc_authentication_applications'),
    ('auth_session_tenant_platform_federated_provenance'),
    ('auth_session_tenant_platform_federated_evidence'),
    ('tenant_post_primary_platform_federated_evidence'),
    ('tenant_platform_federated_session_revalidation_commands'),
    ('tenant_mfa_authority_platform_federated_evidence'),
    ('tenant_post_primary_platform_federated_provenance'),
    ('tenant_post_primary_passkey_provenance'),
    ('tenant_mfa_webauthn_evidence_copy_capabilities')
  ), runtime_role(name) AS (VALUES
    ('periapsis_api'),('periapsis_worker'),('periapsis_notifier'),
    ('periapsis_auditor'),('periapsis_audit_reader_owner'),
    ('periapsis_notification_dispatch_owner'),('periapsis_sla_api_owner'),
    ('periapsis_sla_worker_owner'),('periapsis_sla_readiness_owner'),
    ('periapsis_ticket_saved_view_owner'),
    ('periapsis_ticket_attribution_owner'),
    ('periapsis_ticket_sla_projection_owner')
  )
  SELECT count(*)::integer INTO relation_acl_mismatch_count
  FROM expected CROSS JOIN runtime_role
  WHERE has_table_privilege(
    runtime_role.name,format('public.%I',expected.name),
    'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
  );

  -- Runtime login identities are deployment-owned and may be absent while a
  -- clean database is sealed, present as NOLOGIN during the quiesced v35
  -- cutover, or LOGIN after provisioning. Exclude those lifecycle-only bits
  -- from the dependency transcript, but attest every security-bearing role
  -- attribute, direct membership edge, and per-role setting independently.
  WITH runtime_login(role_name,group_role_name) AS (VALUES
    ('periapsis_api_login','periapsis_api'),
    ('periapsis_worker_login','periapsis_worker'),
    ('periapsis_notifier_login','periapsis_notifier'),
    ('periapsis_auditor_login','periapsis_auditor')
  )
  SELECT count(*)::integer INTO runtime_login_role_mismatch_count
  FROM runtime_login AS expected
  JOIN pg_catalog.pg_roles AS role ON role.rolname = expected.role_name
  WHERE role.rolsuper OR NOT role.rolinherit OR role.rolcreaterole
     OR role.rolcreatedb OR role.rolreplication OR role.rolbypassrls
     OR (role.rolvaliduntil IS NOT NULL
         AND role.rolvaliduntil <> 'infinity'::timestamptz)
     OR (role.rolconnlimit <> -1 AND role.rolconnlimit <= 0);

  WITH runtime_login(role_name,group_role_name) AS (VALUES
    ('periapsis_api_login','periapsis_api'),
    ('periapsis_worker_login','periapsis_worker'),
    ('periapsis_notifier_login','periapsis_notifier'),
    ('periapsis_auditor_login','periapsis_auditor')
  ), allowed_edge(granted_role,member_role,admin_option,inherit_option,
       set_option) AS (
    SELECT expected.group_role_name,expected.role_name,
      false,true,true
    FROM runtime_login AS expected
    JOIN pg_catalog.pg_roles AS login_role
      ON login_role.rolname = expected.role_name
  ), required_edge(granted_role,member_role,admin_option,inherit_option,
       set_option) AS (
    SELECT allowed.*
    FROM allowed_edge AS allowed
    JOIN pg_catalog.pg_roles AS login_role
      ON login_role.rolname = allowed.member_role
     AND login_role.rolcanlogin
  ), actual_edge(granted_role,member_role,admin_option,inherit_option,
       set_option) AS (
    SELECT granted.rolname,member.rolname,membership.admin_option,
      membership.inherit_option,membership.set_option
    FROM pg_catalog.pg_auth_members AS membership
    JOIN pg_catalog.pg_roles AS granted ON granted.oid = membership.roleid
    JOIN pg_catalog.pg_roles AS member ON member.oid = membership.member
    JOIN pg_catalog.pg_roles AS grantor ON grantor.oid = membership.grantor
    WHERE granted.rolname IN (
        SELECT expected.role_name FROM runtime_login AS expected
      )
       OR member.rolname IN (
        SELECT expected.role_name FROM runtime_login AS expected
      )
       OR grantor.rolname IN (
        SELECT expected.role_name FROM runtime_login AS expected
      )
  ), mismatch AS (
    (SELECT * FROM required_edge EXCEPT SELECT * FROM actual_edge)
    UNION ALL
    (SELECT * FROM actual_edge EXCEPT SELECT * FROM allowed_edge)
  )
  SELECT count(*)::integer INTO runtime_login_membership_mismatch_count
  FROM mismatch;

  WITH runtime_login(role_name) AS (VALUES
    ('periapsis_api_login'),('periapsis_worker_login'),
    ('periapsis_notifier_login'),('periapsis_auditor_login')
  )
  SELECT count(*)::integer INTO runtime_login_setting_mismatch_count
  FROM pg_catalog.pg_db_role_setting AS setting
  JOIN pg_catalog.pg_roles AS role ON role.oid = setting.setrole
  WHERE role.rolname IN (
    SELECT expected.role_name FROM runtime_login AS expected
  );

  WITH runtime_login_oid(oid) AS (
    SELECT role.oid
    FROM pg_catalog.pg_roles AS role
    WHERE role.rolname IN (
      'periapsis_api_login','periapsis_worker_login',
      'periapsis_notifier_login','periapsis_auditor_login'
    )
  )
  SELECT count(*)::integer INTO runtime_login_parameter_acl_mismatch_count
  FROM pg_catalog.pg_parameter_acl AS parameter_acl
  CROSS JOIN LATERAL pg_catalog.aclexplode(CASE
    WHEN pg_catalog.cardinality(parameter_acl.paracl) > 0
      THEN parameter_acl.paracl
    ELSE NULL::pg_catalog.aclitem[]
  END) AS acl
  WHERE acl.grantor IN (SELECT login_role.oid FROM runtime_login_oid AS login_role)
     OR acl.grantee IN (SELECT login_role.oid FROM runtime_login_oid AS login_role);

  WITH runtime_login_oid(oid) AS (
    SELECT role.oid
    FROM pg_catalog.pg_roles AS role
    WHERE role.rolname IN (
      'periapsis_api_login','periapsis_worker_login',
      'periapsis_notifier_login','periapsis_auditor_login'
    )
  )
  SELECT count(*)::integer INTO runtime_login_default_acl_mismatch_count
  FROM pg_catalog.pg_default_acl AS default_acl
  LEFT JOIN LATERAL pg_catalog.aclexplode(CASE
    WHEN pg_catalog.cardinality(default_acl.defaclacl) > 0
      THEN default_acl.defaclacl
    ELSE NULL::pg_catalog.aclitem[]
  END) AS acl ON true
  WHERE default_acl.defaclrole IN (
      SELECT login_role.oid FROM runtime_login_oid AS login_role
    )
     OR acl.grantor IN (
      SELECT login_role.oid FROM runtime_login_oid AS login_role
    )
     OR acl.grantee IN (
      SELECT login_role.oid FROM runtime_login_oid AS login_role
    );

  WITH expected(name,relation,type,referenced,definition) AS (VALUES
    ('platform_oidc_provider_configurations_text_check'::name,
      'public.platform_oidc_provider_configurations'::regclass,'c',NULL::regclass,
      'CHECK (issuer = btrim(issuer) AND private_platform_identity_uri_is_canonical_v1(issuer, true, false, 4096) AND octet_length(convert_to(client_id, ''UTF8''::name)) >= 1 AND octet_length(convert_to(client_id, ''UTF8''::name)) <= 512 AND client_id = btrim(client_id) AND private_platform_identity_uri_is_canonical_v1(redirect_uri, true, true, 4096) AND private_platform_identity_uri_is_canonical_v1(tenant_redirect_uri, true, false, 4096) AND tenant_redirect_uri ~ ''^https://[^/?#@]+/api/v1/auth/federated/oidc/callback$''::text AND private_platform_identity_uri_is_canonical_v1(post_logout_redirect_uri, true, true, 4096) AND private_platform_identity_text_is_safe_v1(client_id, true))'),
    ('platform_federated_external_identities_provider_fk'::name,
      'public.platform_federated_external_identities'::regclass,'f',
      'public.platform_auth_providers'::regclass,
      'FOREIGN KEY (platform_provider_id, provider_kind) REFERENCES platform_auth_providers(id, kind) ON UPDATE CASCADE ON DELETE RESTRICT'),
    ('platform_federated_external_identities_policy_fk'::name,
      'public.platform_federated_external_identities'::regclass,'f',
      'public.platform_federated_provider_policies'::regclass,
      'FOREIGN KEY (platform_provider_id, provider_kind) REFERENCES platform_federated_provider_policies(provider_id, provider_kind) ON UPDATE CASCADE ON DELETE RESTRICT'),
    ('platform_federated_external_identities_keyring_fk'::name,
      'public.platform_federated_external_identities'::regclass,'f',
      'public.identity_keyring_versions'::regclass,
      'FOREIGN KEY (key_version) REFERENCES identity_keyring_versions(key_version) ON UPDATE CASCADE ON DELETE RESTRICT'),
    ('platform_federated_external_identity_aliases_identity_fk'::name,
      'public.platform_federated_external_identity_aliases'::regclass,'f',
      'public.platform_federated_external_identities'::regclass,
      'FOREIGN KEY (platform_provider_id, external_identity_id) REFERENCES platform_federated_external_identities(platform_provider_id, id) ON UPDATE CASCADE ON DELETE RESTRICT'),
    ('platform_federated_external_identity_aliases_keyring_fk'::name,
      'public.platform_federated_external_identity_aliases'::regclass,'f',
      'public.identity_keyring_versions'::regclass,
      'FOREIGN KEY (key_version) REFERENCES identity_keyring_versions(key_version) ON UPDATE CASCADE ON DELETE RESTRICT'),
    ('tenant_platform_federated_provider_access_grants_epoch_fk'::name,
      'public.tenant_platform_federated_provider_access_grants'::regclass,'f',
      'public.tenant_platform_identity_provider_access_epochs'::regclass,
      'FOREIGN KEY (tenant_id, access_epoch_id, binding_id, platform_provider_id, source_id) REFERENCES tenant_platform_identity_provider_access_epochs(tenant_id, id, binding_id, platform_provider_id, source_id) ON UPDATE CASCADE ON DELETE RESTRICT'),
    ('tenant_platform_federated_provider_access_grants_identity_fk'::name,
      'public.tenant_platform_federated_provider_access_grants'::regclass,'f',
      'public.platform_federated_external_identities'::regclass,
      'FOREIGN KEY (platform_provider_id, external_identity_id, user_id) REFERENCES platform_federated_external_identities(platform_provider_id, id, user_id) ON UPDATE CASCADE ON DELETE RESTRICT'),
    ('tenant_platform_federated_provider_access_grants_membership_fk'::name,
      'public.tenant_platform_federated_provider_access_grants'::regclass,'f',
      'public.tenant_memberships'::regclass,
      'FOREIGN KEY (tenant_id, membership_id, user_id) REFERENCES tenant_memberships(tenant_id, id, user_id) ON UPDATE CASCADE ON DELETE RESTRICT'),
    ('tenant_platform_federated_provider_access_grants_source_fk'::name,
      'public.tenant_platform_federated_provider_access_grants'::regclass,'f',
      'public.tenant_authorization_sources'::regclass,
      'FOREIGN KEY (tenant_id, source_id) REFERENCES tenant_authorization_sources(tenant_id, id) ON UPDATE CASCADE ON DELETE RESTRICT'),
    ('tenant_platform_federated_provider_profile_contributions_grant_fk'::name,
      'public.tenant_platform_federated_provider_profile_contributions'::regclass,'f',
      'public.tenant_platform_federated_provider_access_grants'::regclass,
      'FOREIGN KEY (tenant_id, access_grant_id) REFERENCES tenant_platform_federated_provider_access_grants(tenant_id, id) ON UPDATE CASCADE ON DELETE RESTRICT'),
    ('tenant_platform_oidc_authentication_transactions_binding_fk'::name,
      'public.tenant_platform_oidc_authentication_transactions'::regclass,'f',
      'public.tenant_platform_auth_provider_bindings'::regclass,
      'FOREIGN KEY (tenant_id, binding_id, platform_provider_id) REFERENCES tenant_platform_auth_provider_bindings(tenant_id, id, platform_provider_id) ON UPDATE CASCADE ON DELETE RESTRICT'),
    ('tenant_platform_oidc_authentication_transactions_epoch_fk'::name,
      'public.tenant_platform_oidc_authentication_transactions'::regclass,'f',
      'public.tenant_platform_identity_provider_access_epochs'::regclass,
      'FOREIGN KEY (tenant_id, access_epoch_id, binding_id, platform_provider_id, access_source_id) REFERENCES tenant_platform_identity_provider_access_epochs(tenant_id, id, binding_id, platform_provider_id, source_id) ON UPDATE CASCADE ON DELETE RESTRICT'),
    ('tenant_platform_oidc_authentication_transactions_policy_fk'::name,
      'public.tenant_platform_oidc_authentication_transactions'::regclass,'f',
      'public.platform_federated_provider_policies'::regclass,
      'FOREIGN KEY (platform_provider_id, provider_kind) REFERENCES platform_federated_provider_policies(provider_id, provider_kind) ON UPDATE CASCADE ON DELETE RESTRICT'),
    ('tenant_platform_oidc_authentication_transactions_configuration_fk'::name,
      'public.tenant_platform_oidc_authentication_transactions'::regclass,'f',
      'public.platform_oidc_provider_configurations'::regclass,
      'FOREIGN KEY (platform_provider_id) REFERENCES platform_oidc_provider_configurations(provider_id) ON UPDATE CASCADE ON DELETE RESTRICT'),
    ('tenant_platform_oidc_authentication_transactions_keyring_fk'::name,
      'public.tenant_platform_oidc_authentication_transactions'::regclass,'f',
      'public.identity_keyring_versions'::regclass,
      'FOREIGN KEY (verifier_key_version) REFERENCES identity_keyring_versions(key_version) ON UPDATE CASCADE ON DELETE RESTRICT'),
    ('tenant_platform_oidc_authentication_applications_transaction_fk'::name,
      'public.tenant_platform_oidc_authentication_applications'::regclass,'f',
      'public.tenant_platform_oidc_authentication_transactions'::regclass,
      'FOREIGN KEY (tenant_id, transaction_id, platform_provider_id, binding_id) REFERENCES tenant_platform_oidc_authentication_transactions(tenant_id, transaction_id, platform_provider_id, binding_id) ON UPDATE CASCADE ON DELETE RESTRICT'),
    ('tenant_platform_oidc_authentication_applications_session_fk'::name,
      'public.tenant_platform_oidc_authentication_applications'::regclass,'f',
      'public.auth_session_mfa_states'::regclass,
      'FOREIGN KEY (tenant_id, session_id, primary_kind, user_id) REFERENCES auth_session_mfa_states(tenant_id, session_id, primary_kind, user_id) ON UPDATE CASCADE ON DELETE RESTRICT'),
    ('tenant_platform_oidc_authentication_applications_continuation_fk'::name,
      'public.tenant_platform_oidc_authentication_applications'::regclass,'f',
      'public.tenant_post_primary_continuations'::regclass,
      'FOREIGN KEY (tenant_id, continuation_id, user_id) REFERENCES tenant_post_primary_continuations(tenant_id, id, user_id) ON UPDATE CASCADE ON DELETE RESTRICT'),
    ('tenant_platform_oidc_authentication_applications_identity_fk'::name,
      'public.tenant_platform_oidc_authentication_applications'::regclass,'f',
      'public.platform_federated_external_identities'::regclass,
      'FOREIGN KEY (platform_provider_id, external_identity_id, user_id) REFERENCES platform_federated_external_identities(platform_provider_id, id, user_id) ON UPDATE CASCADE ON DELETE RESTRICT'),
    ('auth_session_tenant_platform_federated_provenance_state_fk'::name,
      'public.auth_session_tenant_platform_federated_provenance'::regclass,'f',
      'public.auth_session_mfa_states'::regclass,
      'FOREIGN KEY (tenant_id, session_id, primary_kind, user_id) REFERENCES auth_session_mfa_states(tenant_id, session_id, primary_kind, user_id) ON UPDATE CASCADE ON DELETE RESTRICT'),
    ('auth_session_tenant_platform_federated_provenance_identity_fk'::name,
      'public.auth_session_tenant_platform_federated_provenance'::regclass,'f',
      'public.platform_federated_external_identities'::regclass,
      'FOREIGN KEY (platform_provider_id, external_identity_id, user_id) REFERENCES platform_federated_external_identities(platform_provider_id, id, user_id) ON UPDATE CASCADE ON DELETE RESTRICT'),
    ('auth_session_tenant_platform_federated_provenance_binding_fk'::name,
      'public.auth_session_tenant_platform_federated_provenance'::regclass,'f',
      'public.tenant_platform_auth_provider_bindings'::regclass,
      'FOREIGN KEY (tenant_id, binding_id, platform_provider_id) REFERENCES tenant_platform_auth_provider_bindings(tenant_id, id, platform_provider_id) ON UPDATE CASCADE ON DELETE RESTRICT'),
    ('auth_session_tenant_platform_federated_provenance_access_grant_fk'::name,
      'public.auth_session_tenant_platform_federated_provenance'::regclass,'f',
      'public.tenant_platform_federated_provider_access_grants'::regclass,
      'FOREIGN KEY (tenant_id, access_grant_id, platform_provider_id, binding_id, access_epoch_id, access_source_id, external_identity_id, membership_id, user_id) REFERENCES tenant_platform_federated_provider_access_grants(tenant_id, id, platform_provider_id, binding_id, access_epoch_id, source_id, external_identity_id, membership_id, user_id) ON UPDATE CASCADE ON DELETE RESTRICT'),
    ('auth_session_tenant_platform_federated_evidence_provenance_fk'::name,
      'public.auth_session_tenant_platform_federated_evidence'::regclass,'f',
      'public.auth_session_tenant_platform_federated_provenance'::regclass,
      'FOREIGN KEY (tenant_id, session_id, user_id, platform_provider_id, binding_id, external_identity_id) REFERENCES auth_session_tenant_platform_federated_provenance(tenant_id, session_id, user_id, platform_provider_id, binding_id, external_identity_id) ON UPDATE CASCADE ON DELETE RESTRICT'),
    ('tenant_post_primary_platform_federated_evidence_continuation_fk'::name,
      'public.tenant_post_primary_platform_federated_evidence'::regclass,'f',
      'public.tenant_post_primary_continuations'::regclass,
      'FOREIGN KEY (tenant_id, continuation_id, user_id) REFERENCES tenant_post_primary_continuations(tenant_id, id, user_id) ON UPDATE CASCADE ON DELETE RESTRICT'),
    ('tenant_post_primary_platform_federated_evidence_identity_fk'::name,
      'public.tenant_post_primary_platform_federated_evidence'::regclass,'f',
      'public.platform_federated_external_identities'::regclass,
      'FOREIGN KEY (platform_provider_id, external_identity_id, user_id) REFERENCES platform_federated_external_identities(platform_provider_id, id, user_id) ON UPDATE CASCADE ON DELETE RESTRICT'),
    ('tenant_platform_federated_session_revalidation_commands_session_fk'::name,
      'public.tenant_platform_federated_session_revalidation_commands'::regclass,'f',
      'public.auth_session_tenant_platform_federated_provenance'::regclass,
      'FOREIGN KEY (tenant_id, session_id) REFERENCES auth_session_tenant_platform_federated_provenance(tenant_id, session_id) ON UPDATE CASCADE ON DELETE RESTRICT'),
    ('tenant_mfa_authority_platform_federated_evidence_anchor_fk'::name,
      'public.tenant_mfa_authority_platform_federated_evidence'::regclass,'f',
      'public.tenant_mfa_authority_anchors'::regclass,
      'FOREIGN KEY (tenant_id, anchor_id) REFERENCES tenant_mfa_authority_anchors(tenant_id, id) ON UPDATE CASCADE ON DELETE RESTRICT'),
    ('tenant_mfa_authority_platform_federated_evidence_identity_fk'::name,
      'public.tenant_mfa_authority_platform_federated_evidence'::regclass,'f',
      'public.platform_federated_external_identities'::regclass,
      'FOREIGN KEY (platform_provider_id, external_identity_id, user_id) REFERENCES platform_federated_external_identities(platform_provider_id, id, user_id) ON UPDATE CASCADE ON DELETE RESTRICT'),
    ('tenant_mfa_authority_platform_federated_evidence_binding_fk'::name,
      'public.tenant_mfa_authority_platform_federated_evidence'::regclass,'f',
      'public.tenant_platform_auth_provider_bindings'::regclass,
      'FOREIGN KEY (tenant_id, binding_id, platform_provider_id) REFERENCES tenant_platform_auth_provider_bindings(tenant_id, id, platform_provider_id) ON UPDATE CASCADE ON DELETE RESTRICT'),
    ('tenant_post_primary_platform_federated_provenance_continuation_fk'::name,
      'public.tenant_post_primary_platform_federated_provenance'::regclass,'f',
      'public.tenant_post_primary_continuations'::regclass,
      'FOREIGN KEY (tenant_id, continuation_id, user_id, platform_provider_id, binding_id, external_identity_id) REFERENCES tenant_post_primary_continuations(tenant_id, id, user_id, platform_provider_id, binding_id, external_identity_id) ON UPDATE CASCADE ON DELETE RESTRICT'),
    ('tenant_post_primary_platform_federated_provenance_identity_fk'::name,
      'public.tenant_post_primary_platform_federated_provenance'::regclass,'f',
      'public.platform_federated_external_identities'::regclass,
      'FOREIGN KEY (platform_provider_id, external_identity_id, user_id) REFERENCES platform_federated_external_identities(platform_provider_id, id, user_id) ON UPDATE CASCADE ON DELETE RESTRICT'),
    ('tenant_post_primary_platform_federated_provenance_binding_fk'::name,
      'public.tenant_post_primary_platform_federated_provenance'::regclass,'f',
      'public.tenant_platform_auth_provider_bindings'::regclass,
      'FOREIGN KEY (tenant_id, binding_id, platform_provider_id) REFERENCES tenant_platform_auth_provider_bindings(tenant_id, id, platform_provider_id) ON UPDATE CASCADE ON DELETE RESTRICT'),
    ('tenant_post_primary_platform_federated_provenance_access_grant_fk'::name,
      'public.tenant_post_primary_platform_federated_provenance'::regclass,'f',
      'public.tenant_platform_federated_provider_access_grants'::regclass,
      'FOREIGN KEY (tenant_id, access_grant_id, platform_provider_id, binding_id, access_epoch_id, access_source_id, external_identity_id, membership_id, user_id) REFERENCES tenant_platform_federated_provider_access_grants(tenant_id, id, platform_provider_id, binding_id, access_epoch_id, source_id, external_identity_id, membership_id, user_id) ON UPDATE CASCADE ON DELETE RESTRICT'),
    ('tenant_post_primary_platform_federated_provenance_source_session_fk'::name,
      'public.tenant_post_primary_platform_federated_provenance'::regclass,'f',
      'public.auth_sessions'::regclass,
      'FOREIGN KEY (source_session_id) REFERENCES auth_sessions(id) ON DELETE RESTRICT'),
    ('tenant_mfa_webauthn_evidence_copy_capabilities_credential_fk'::name,
      'public.tenant_mfa_webauthn_evidence_copy_capabilities'::regclass,'f',
      'public.tenant_webauthn_credentials'::regclass,
      'FOREIGN KEY (tenant_id, user_id, credential_id) REFERENCES tenant_webauthn_credentials(tenant_id, user_id, id) ON UPDATE CASCADE ON DELETE RESTRICT'),
    ('tenant_mfa_webauthn_evidence_copy_capabilities_destination_key'::name,
      'public.tenant_mfa_webauthn_evidence_copy_capabilities'::regclass,'u',
      NULL::regclass,
      'UNIQUE (backend_pid, transaction_id, tenant_id, destination_session_id, credential_id)'),
    ('tenant_mfa_webauthn_evidence_copy_capabilities_pkey'::name,
      'public.tenant_mfa_webauthn_evidence_copy_capabilities'::regclass,'p',
      NULL::regclass,
      'PRIMARY KEY (tenant_id, source_anchor_id, destination_session_id, backend_pid, transaction_id)'),
    ('tenant_mfa_webauthn_evidence_copy_capabilities_source_fk'::name,
      'public.tenant_mfa_webauthn_evidence_copy_capabilities'::regclass,'f',
      'public.tenant_mfa_authority_evidence'::regclass,
      'FOREIGN KEY (tenant_id, source_anchor_id, source_evidence_id) REFERENCES tenant_mfa_authority_evidence(tenant_id, anchor_id, id) ON UPDATE CASCADE ON DELETE RESTRICT'),
    ('tenant_mfa_webauthn_evidence_copy_capabilities_tenant_fk'::name,
      'public.tenant_mfa_webauthn_evidence_copy_capabilities'::regclass,'f',
      'public.tenants'::regclass,
      'FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE RESTRICT'),
    ('tenant_mfa_webauthn_evidence_copy_capabilities_value_check'::name,
      'public.tenant_mfa_webauthn_evidence_copy_capabilities'::regclass,'c',
      NULL::regclass,
      'CHECK (backend_pid > 0 AND transaction_id > 0 AND (uuid_extract_version(destination_session_id) = 7) IS TRUE AND factor_kind = ''webauthn''::text AND source_revision >= 1 AND source_revision <= ''9007199254740991''::bigint AND target_revision >= source_revision AND target_revision <= LEAST(source_revision + 1, ''9007199254740991''::bigint) AND (source_level = ANY (ARRAY[''primary''::text, ''mfa''::text, ''phishing_resistant''::text])) AND (target_level = ANY (ARRAY[''primary''::text, ''mfa''::text, ''phishing_resistant''::text])) AND target_authenticated_at >= source_authenticated_at AND (source_expires_at IS NULL OR source_expires_at > source_authenticated_at) AND (consumed_evidence_id IS NULL AND consumed_at IS NULL OR consumed_evidence_id IS NOT NULL AND (uuid_extract_version(consumed_evidence_id) = 7) IS TRUE AND consumed_at IS NOT NULL AND consumed_at >= created_at))'),
    ('tenant_post_primary_continuations_lifecycle_check'::name,
      'public.tenant_post_primary_continuations'::regclass,'c',NULL::regclass,
      'CHECK (state = ''pending''::text AND version >= 1 AND consumed_at IS NULL AND revoked_at IS NULL AND revoke_reason IS NULL OR state = ''consumed''::text AND version >= 2 AND consumed_at IS NOT NULL AND revoked_at IS NULL AND revoke_reason IS NULL OR (state = ANY (ARRAY[''revoked''::text, ''expired''::text])) AND version >= 2 AND consumed_at IS NULL AND revoked_at IS NOT NULL AND revoke_reason IS NOT NULL AND btrim(revoke_reason) <> ''''::text AND char_length(revoke_reason) <= 500 AND revoke_reason !~ ''[[:cntrl:]]''::text)'),
    ('tenant_post_primary_passkey_provenance_continuation_fk'::name,
      'public.tenant_post_primary_passkey_provenance'::regclass,'f',
      'public.tenant_post_primary_continuations'::regclass,
      'FOREIGN KEY (tenant_id, continuation_id, user_id, credential_id) REFERENCES tenant_post_primary_continuations(tenant_id, id, user_id, passkey_credential_id) ON UPDATE CASCADE ON DELETE RESTRICT'),
    ('tenant_post_primary_passkey_provenance_credential_fk'::name,
      'public.tenant_post_primary_passkey_provenance'::regclass,'f',
      'public.tenant_webauthn_credentials'::regclass,
      'FOREIGN KEY (tenant_id, user_id, credential_id) REFERENCES tenant_webauthn_credentials(tenant_id, user_id, id) ON UPDATE CASCADE ON DELETE RESTRICT'),
    ('tenant_post_primary_passkey_provenance_pkey'::name,
      'public.tenant_post_primary_passkey_provenance'::regclass,'p',
      NULL::regclass,'PRIMARY KEY (tenant_id, continuation_id)'),
    ('tenant_post_primary_passkey_provenance_source_session_id_auth_s'::name,
      'public.tenant_post_primary_passkey_provenance'::regclass,'f',
      'public.auth_sessions'::regclass,
      'FOREIGN KEY (source_session_id) REFERENCES auth_sessions(id) ON DELETE RESTRICT'),
    ('tenant_post_primary_passkey_provenance_tenant_id_tenants_id_fk'::name,
      'public.tenant_post_primary_passkey_provenance'::regclass,'f',
      'public.tenants'::regclass,
      'FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE RESTRICT'),
    ('tenant_post_primary_passkey_provenance_value_check'::name,
      'public.tenant_post_primary_passkey_provenance'::regclass,'c',
      NULL::regclass,
      'CHECK (primary_kind = ''passkey''::text AND authentication_method = ''passkey''::text AND credential_revision >= 1 AND credential_revision <= ''9007199254740991''::bigint AND (origin = ''initial_login''::text AND source_session_id IS NULL AND source_session_family_id IS NULL AND source_session_version IS NULL AND source_absolute_expires_at IS NULL OR origin = ''session_revalidation''::text AND source_session_id IS NOT NULL AND source_session_family_id IS NOT NULL AND (uuid_extract_version(source_session_family_id) = 7) IS TRUE AND source_session_version >= 1 AND source_session_version <= ''9007199254740991''::bigint AND source_absolute_expires_at > authenticated_at AND date_trunc(''milliseconds''::text, source_absolute_expires_at) = source_absolute_expires_at))')
  )
  SELECT count(*)::integer INTO constraint_count
  FROM expected
  JOIN pg_catalog.pg_constraint AS constraint_row
    ON constraint_row.conname = expected.name
   AND constraint_row.conrelid = expected.relation
  WHERE constraint_row.contype::text = expected.type
    AND constraint_row.conenforced
    AND constraint_row.convalidated
    AND NOT constraint_row.condeferrable
    AND NOT constraint_row.condeferred
    AND (expected.type <> 'f' OR
      constraint_row.confrelid = expected.referenced)
    AND (expected.type = 'f' OR constraint_row.confrelid = 0)
    AND (expected.type <> 'f' OR (
      constraint_row.confupdtype = CASE
        WHEN expected.name IN (
          'tenant_post_primary_platform_federated_provenance_source_session_fk'::name,
          'tenant_mfa_webauthn_evidence_copy_capabilities_tenant_fk'::name,
          'tenant_post_primary_passkey_provenance_source_session_id_auth_s'::name,
          'tenant_post_primary_passkey_provenance_tenant_id_tenants_id_fk'::name
        ) THEN 'a'::"char"
        ELSE 'c'::"char"
      END
      AND constraint_row.confdeltype = 'r'
      AND constraint_row.confmatchtype = 's'
    ))
    AND pg_catalog.pg_get_constraintdef(constraint_row.oid,true)
      = expected.definition;

  WITH expected(name,relation,is_unique,definition,predicate) AS (VALUES
    ('platform_federated_external_identities_live_provider_user_key'::name,
      'public.platform_federated_external_identities'::regclass,true,
      'CREATE UNIQUE INDEX platform_federated_external_identities_live_provider_user_key ON public.platform_federated_external_identities USING btree (platform_provider_id, user_id) WHERE (retired_at IS NULL)',
      'retired_at IS NULL'),
    ('platform_federated_external_identity_aliases_digest_key'::name,
      'public.platform_federated_external_identity_aliases'::regclass,true,
      'CREATE UNIQUE INDEX platform_federated_external_identity_aliases_digest_key ON public.platform_federated_external_identity_aliases USING btree (platform_provider_id, key_version, subject_digest)',
      NULL::text),
    ('platform_federated_external_identity_aliases_version_key'::name,
      'public.platform_federated_external_identity_aliases'::regclass,true,
      'CREATE UNIQUE INDEX platform_federated_external_identity_aliases_version_key ON public.platform_federated_external_identity_aliases USING btree (external_identity_id, key_version)',
      NULL::text),
    ('tenant_platform_federated_provider_access_grants_live_binding_member_key'::name,
      'public.tenant_platform_federated_provider_access_grants'::regclass,true,
      'CREATE UNIQUE INDEX tenant_platform_federated_provider_access_grants_live_binding_m ON public.tenant_platform_federated_provider_access_grants USING btree (tenant_id, binding_id, membership_id) WHERE (ended_at IS NULL)',
      'ended_at IS NULL'),
    ('tenant_platform_federated_provider_profile_contributions_live_grant_key'::name,
      'public.tenant_platform_federated_provider_profile_contributions'::regclass,true,
      'CREATE UNIQUE INDEX tenant_platform_federated_provider_profile_contributions_live_g ON public.tenant_platform_federated_provider_profile_contributions USING btree (tenant_id, access_grant_id) WHERE (retired_at IS NULL)',
      'retired_at IS NULL'),
    ('tenant_platform_oidc_authentication_transactions_operation_key'::name,
      'public.tenant_platform_oidc_authentication_transactions'::regclass,true,
      'CREATE UNIQUE INDEX tenant_platform_oidc_authentication_transactions_operation_key ON public.tenant_platform_oidc_authentication_transactions USING btree (operation_run_id)',
      NULL::text),
    ('tenant_platform_oidc_authentication_transactions_receipt_key'::name,
      'public.tenant_platform_oidc_authentication_transactions'::regclass,true,
      'CREATE UNIQUE INDEX tenant_platform_oidc_authentication_transactions_receipt_key ON public.tenant_platform_oidc_authentication_transactions USING btree (receipt_digest)',
      NULL::text),
    ('tenant_platform_oidc_authentication_transactions_state_key'::name,
      'public.tenant_platform_oidc_authentication_transactions'::regclass,true,
      'CREATE UNIQUE INDEX tenant_platform_oidc_authentication_transactions_state_key ON public.tenant_platform_oidc_authentication_transactions USING btree (state_digest)',
      NULL::text),
    ('tenant_platform_oidc_authentication_transactions_live_browser_key'::name,
      'public.tenant_platform_oidc_authentication_transactions'::regclass,true,
      'CREATE UNIQUE INDEX tenant_platform_oidc_authentication_transactions_live_browser_k ON public.tenant_platform_oidc_authentication_transactions USING btree (browser_digest) WHERE (state = ANY (ARRAY[''pending''::text, ''claimed''::text]))',
      'state = ANY (ARRAY[''pending''::text, ''claimed''::text])'),
    ('tenant_mfa_authority_platform_federated_evidence_anchor_idx'::name,
      'public.tenant_mfa_authority_platform_federated_evidence'::regclass,false,
      'CREATE INDEX tenant_mfa_authority_platform_federated_evidence_anchor_idx ON public.tenant_mfa_authority_platform_federated_evidence USING btree (tenant_id, anchor_id, authenticated_at, id)',
      NULL::text),
    ('tenant_post_primary_passkey_provenance_credential_idx'::name,
      'public.tenant_post_primary_passkey_provenance'::regclass,false,
      'CREATE INDEX tenant_post_primary_passkey_provenance_credential_idx ON public.tenant_post_primary_passkey_provenance USING btree (tenant_id, user_id, credential_id, continuation_id)',
      NULL::text),
    ('tenant_post_primary_passkey_provenance_source_session_idx'::name,
      'public.tenant_post_primary_passkey_provenance'::regclass,false,
      'CREATE INDEX tenant_post_primary_passkey_provenance_source_session_idx ON public.tenant_post_primary_passkey_provenance USING btree (tenant_id, source_session_id, continuation_id) WHERE (origin = ''session_revalidation''::text)',
      'origin = ''session_revalidation''::text')
  )
  SELECT count(*)::integer INTO index_count
  FROM expected
  JOIN pg_catalog.pg_class AS index_relation
    ON index_relation.relname = expected.name
  JOIN pg_catalog.pg_namespace AS index_namespace
    ON index_namespace.oid = index_relation.relnamespace
   AND index_namespace.nspname = 'public'
  JOIN pg_catalog.pg_index AS index_row
    ON index_row.indexrelid = index_relation.oid
   AND index_row.indrelid = expected.relation
  JOIN pg_catalog.pg_roles AS index_owner
    ON index_owner.oid = index_relation.relowner
  JOIN pg_catalog.pg_am AS access_method
    ON access_method.oid = index_relation.relam
  WHERE index_relation.relkind = 'i'
    AND index_relation.relpersistence = 'p'
    AND index_owner.rolname = 'periapsis_migrator'
    AND access_method.amname = 'btree'
    AND index_relation.reltablespace = 0
    AND index_relation.reloptions IS NULL
    AND index_row.indisunique IS NOT DISTINCT FROM expected.is_unique
    AND NOT index_row.indnullsnotdistinct
    AND NOT index_row.indisprimary AND NOT index_row.indisexclusion
    AND index_row.indimmediate
    AND NOT index_row.indisclustered AND NOT index_row.indisreplident
    AND index_row.indisvalid AND index_row.indisready AND index_row.indislive
    AND NOT index_row.indcheckxmin
    AND index_row.indnkeyatts = index_row.indnatts
    AND pg_catalog.pg_get_indexdef(index_row.indexrelid) = expected.definition
    AND pg_catalog.pg_get_expr(
      index_row.indpred,index_row.indrelid,true
    ) IS NOT DISTINCT FROM expected.predicate;

  WITH expected(
    name,relation,function,type,has_constraint,is_deferrable,is_deferred,
    attributes,qualifier,arguments
  ) AS (VALUES
    ('platform_oidc_provider_configurations_tenant_redirect_v1'::name,
      'public.platform_oidc_provider_configurations'::regclass,
      'app.private_fill_platform_oidc_tenant_redirect_v1()'::regprocedure,
      23,false,false,false,'16',NULL::text,''),
    ('auth_session_tenant_platform_federated_provenance_parent_v1'::name,
      'public.auth_session_tenant_platform_federated_provenance'::regclass,
      'app.enforce_auth_session_mfa_provenance_v1()'::regprocedure,
      29,true,true,true,'',NULL::text,''),
    ('tenant_post_primary_continuations_platform_provenance_v1'::name,
      'public.tenant_post_primary_continuations'::regclass,
      'app.validate_tenant_platform_continuation_provenance_v1()'::regprocedure,
      23,false,false,false,'',NULL::text,''),
    ('platform_federated_external_identities_guard_v1'::name,
      'public.platform_federated_external_identities'::regclass,
      'app.guard_platform_federated_external_identity_v1()'::regprocedure,
      31,false,false,false,'',NULL::text,''),
    ('platform_federated_external_identity_aliases_guard_v1'::name,
      'public.platform_federated_external_identity_aliases'::regclass,
      'app.guard_platform_federated_alias_v1()'::regprocedure,
      31,false,false,false,'',NULL::text,''),
    ('tenant_platform_oidc_authentication_transactions_guard_v1'::name,
      'public.tenant_platform_oidc_authentication_transactions'::regclass,
      'app.guard_tenant_platform_oidc_transaction_v1()'::regprocedure,
      31,false,false,false,'',NULL::text,''),
    ('tenant_platform_oidc_authentication_applications_immutable_v1'::name,
      'public.tenant_platform_oidc_authentication_applications'::regclass,
      'app.guard_tenant_platform_runtime_immutable_v1()'::regprocedure,
      27,false,false,false,'',NULL::text,''),
    ('tenant_platform_oidc_applications_continuation_guard_v1'::name,
      'public.tenant_platform_oidc_authentication_applications'::regclass,
      'app.guard_tenant_platform_continuation_child_v1()'::regprocedure,
      7,false,false,false,'',NULL::text,''),
    ('auth_session_tenant_platform_federated_provenance_immutable_v1'::name,
      'public.auth_session_tenant_platform_federated_provenance'::regclass,
      'app.guard_tenant_platform_runtime_immutable_v1()'::regprocedure,
      27,false,false,false,'',NULL::text,''),
    ('auth_session_tenant_platform_federated_evidence_immutable_v1'::name,
      'public.auth_session_tenant_platform_federated_evidence'::regclass,
      'app.guard_tenant_platform_runtime_immutable_v1()'::regprocedure,
      27,false,false,false,'',NULL::text,''),
    ('tenant_post_primary_platform_federated_evidence_immutable_v1'::name,
      'public.tenant_post_primary_platform_federated_evidence'::regclass,
      'app.guard_tenant_platform_runtime_immutable_v1()'::regprocedure,
      27,false,false,false,'',NULL::text,''),
    ('tenant_post_primary_platform_evidence_continuation_guard_v1'::name,
      'public.tenant_post_primary_platform_federated_evidence'::regclass,
      'app.guard_tenant_platform_continuation_child_v1()'::regprocedure,
      7,false,false,false,'',NULL::text,''),
    ('tenant_platform_federated_session_revalidation_commands_immutable_v1'::name,
      'public.tenant_platform_federated_session_revalidation_commands'::regclass,
      'app.guard_tenant_platform_runtime_immutable_v1()'::regprocedure,
      27,false,false,false,'',NULL::text,''),
    ('tenant_platform_identity_provider_access_epochs_guard_v1'::name,
      'public.tenant_platform_identity_provider_access_epochs'::regclass,
      'app.guard_tenant_platform_identity_provider_access_epoch_v1()'::regprocedure,
      31,false,false,false,'',NULL::text,''),
    ('tenant_mfa_authority_platform_federated_evidence_immutable_v1'::name,
      'public.tenant_mfa_authority_platform_federated_evidence'::regclass,
      'app.guard_tenant_platform_runtime_immutable_v1()'::regprocedure,
      27,false,false,false,'',NULL::text,''),
    ('tenant_post_primary_platform_federated_provenance_immutable_v1'::name,
      'public.tenant_post_primary_platform_federated_provenance'::regclass,
      'app.guard_tenant_platform_runtime_immutable_v1()'::regprocedure,
      27,false,false,false,'',NULL::text,''),
    ('tenant_post_primary_platform_federated_provenance_guard_v1'::name,
      'public.tenant_post_primary_platform_federated_provenance'::regclass,
      'app.validate_tenant_platform_continuation_authority_v1()'::regprocedure,
      7,false,false,false,'',NULL::text,''),
    ('tenant_mfa_authority_platform_federated_evidence_guard_v1'::name,
      'public.tenant_mfa_authority_platform_federated_evidence'::regclass,
      'app.validate_tenant_platform_mfa_authority_evidence_v1()'::regprocedure,
      7,false,false,false,'',NULL::text,''),
    ('tenant_mfa_authority_platform_federated_evidence_copy_v1'::name,
      'public.tenant_mfa_authority_anchors'::regclass,
      'app.copy_tenant_platform_mfa_authority_evidence_v1()'::regprocedure,
      5,false,false,false,'',NULL::text,''),
    ('mfa_policy_revisions_authority_v1'::name,
      'public.mfa_policy_revisions'::regclass,
      'app.touch_mfa_policy_authority_v1()'::regprocedure,
      29,false,false,false,'',NULL::text,''),
    ('tenant_mfa_webauthn_evidence_copy_cleanup_v1'::name,
      'public.tenant_mfa_webauthn_evidence_copy_capabilities'::regclass,
      'app.assert_mfa_webauthn_evidence_copy_cleanup_v1()'::regprocedure,
      21,true,true,true,'',NULL::text,''),
    ('tenant_post_primary_continuations_federated_child_v1'::name,
      'public.tenant_post_primary_continuations'::regclass,
      'app.enforce_tenant_federated_continuation_provenance_v1()'::regprocedure,
      21,true,true,true,'',NULL::text,''),
    ('tenant_post_primary_continuations_passkey_child_v1'::name,
      'public.tenant_post_primary_continuations'::regclass,
      'app.enforce_tenant_passkey_continuation_provenance_v1()'::regprocedure,
      21,true,true,true,'',NULL::text,''),
    ('tenant_post_primary_federated_provenance_guard_v1'::name,
      'public.tenant_post_primary_federated_provenance'::regclass,
      'app.validate_tenant_federated_continuation_authority_v1()'::regprocedure,
      7,false,false,false,'',NULL::text,''),
    ('tenant_post_primary_federated_provenance_immutable_v1'::name,
      'public.tenant_post_primary_federated_provenance'::regclass,
      'app.guard_tenant_platform_runtime_immutable_v1()'::regprocedure,
      27,false,false,false,'',NULL::text,''),
    ('tenant_post_primary_federated_provenance_parent_v1'::name,
      'public.tenant_post_primary_federated_provenance'::regclass,
      'app.enforce_tenant_federated_continuation_provenance_v1()'::regprocedure,
      29,true,true,true,'',NULL::text,''),
    ('tenant_post_primary_passkey_provenance_guard_v1'::name,
      'public.tenant_post_primary_passkey_provenance'::regclass,
      'app.validate_tenant_passkey_continuation_authority_v1()'::regprocedure,
      7,false,false,false,'',NULL::text,''),
    ('tenant_post_primary_passkey_provenance_immutable_v1'::name,
      'public.tenant_post_primary_passkey_provenance'::regclass,
      'app.guard_tenant_platform_runtime_immutable_v1()'::regprocedure,
      27,false,false,false,'',NULL::text,''),
    ('tenant_post_primary_passkey_provenance_parent_v1'::name,
      'public.tenant_post_primary_passkey_provenance'::regclass,
      'app.enforce_tenant_passkey_continuation_provenance_v1()'::regprocedure,
      29,true,true,true,'',NULL::text,''),
    ('tenant_webauthn_ceremonies_security_snapshot_v1'::name,
      'public.tenant_webauthn_ceremonies'::regclass,
      'app.validate_webauthn_completed_security_snapshot_v1()'::regprocedure,
      21,true,true,true,'',NULL::text,''),
    ('tenant_webauthn_credentials_security_revision_v1'::name,
      'public.tenant_webauthn_credentials'::regclass,
      'app.guard_webauthn_credential_security_revision_v1()'::regprocedure,
      19,false,false,false,'',NULL::text,'')
  )
  SELECT count(*)::integer INTO trigger_count
  FROM expected
  JOIN pg_catalog.pg_trigger AS trigger_row
    ON trigger_row.tgname = expected.name
   AND trigger_row.tgrelid = expected.relation
   AND trigger_row.tgfoid = expected.function
  WHERE trigger_row.tgtype = expected.type
    AND trigger_row.tgenabled = 'O'
    AND NOT trigger_row.tgisinternal
    AND CASE WHEN expected.has_constraint THEN EXISTS (
      SELECT 1
      FROM pg_catalog.pg_constraint AS trigger_constraint
      WHERE trigger_constraint.oid = trigger_row.tgconstraint
        AND trigger_constraint.conname = expected.name
        AND trigger_constraint.conrelid = expected.relation
        AND trigger_constraint.contypid = 0
        AND trigger_constraint.contype = 't'
    ) ELSE trigger_row.tgconstraint = 0 END
    AND trigger_row.tgdeferrable IS NOT DISTINCT FROM expected.is_deferrable
    AND trigger_row.tginitdeferred IS NOT DISTINCT FROM expected.is_deferred
    AND trigger_row.tgconstrrelid = 0
    AND trigger_row.tgconstrindid = 0
    AND trigger_row.tgparentid = 0
    AND trigger_row.tgoldtable IS NULL AND trigger_row.tgnewtable IS NULL
    AND trigger_row.tgattr::text = expected.attributes
    AND pg_catalog.pg_get_expr(
      trigger_row.tgqual,trigger_row.tgrelid,true
    ) IS NOT DISTINCT FROM expected.qualifier
    AND trigger_row.tgnargs = 0
    AND encode(trigger_row.tgargs,'hex') = expected.arguments
    AND pg_catalog.pg_get_triggerdef(trigger_row.oid,false) IS NOT NULL;

  WITH expected(signature,api_execute,worker_execute) AS (VALUES
    ('app.create_platform_oidc_auth_provider_v2(uuid,uuid,uuid,text,text,text,jsonb,text,bytea,bytea,uuid,uuid,uuid,inet,text,text,text)',true,false),
    ('app.activate_platform_auth_provider_tenant_execution_v1(uuid,uuid,bigint,text,uuid,uuid,uuid,inet,text,text,text)',true,false),
    ('app.deactivate_platform_auth_provider_tenant_execution_v1(uuid,uuid,bigint,uuid,uuid,uuid,inet,text,text,text)',true,false),
    ('app.activate_tenant_platform_auth_provider_binding_v1(uuid,uuid,uuid,bigint,integer,text,text,uuid,uuid,uuid,uuid,inet,text,text,text)',true,false),
    ('app.deactivate_tenant_platform_auth_provider_binding_v1(uuid,uuid,uuid,bigint,integer,uuid,uuid,uuid,uuid,inet,text,text,text)',true,false),
    ('app.begin_tenant_oidc_authentication_v1(jsonb)',true,false),
    ('app.resolve_tenant_oidc_authentication_v1(jsonb)',true,false),
    ('app.create_oidc_authentication_transaction_v1(jsonb)',true,false),
    ('app.claim_oidc_authentication_transaction_v1(jsonb)',true,false),
    ('app.fail_oidc_authentication_transaction_v1(jsonb)',true,false),
    ('app.apply_federated_authentication_v1(jsonb)',true,false),
    ('app.load_federated_authentication_planning_state_v1(jsonb)',true,false),
    ('app.load_oidc_trust_snapshot_v1(jsonb)',true,false),
    ('app.load_oidc_client_secret_envelope_v1(jsonb)',true,false),
    ('app.load_federated_session_revalidation_v1(jsonb)',true,false),
    ('app.apply_federated_session_revalidation_v1(jsonb)',true,false),
    ('app.publish_platform_oidc_trust_snapshot_v1(jsonb)',false,true),
    ('app.rotate_auth_session_tenant(bytea,uuid,bytea,bytea,uuid,timestamp with time zone,timestamp with time zone,uuid,uuid,uuid,inet,text)',true,false),
    ('app.start_totp_enrollment_v1(jsonb)',true,false),
    ('app.create_mfa_step_up_challenge_v1(jsonb)',true,false),
    ('app.create_webauthn_ceremony_v1(jsonb)',true,false),
    ('app.claim_totp_enrollment_v2(uuid,bytea,timestamp with time zone,bytea)',true,false),
    ('app.claim_mfa_step_up_challenge_v2(bytea,bytea,text,timestamp with time zone,bytea)',true,false),
    ('app.claim_webauthn_ceremony_v2(bytea,bytea,timestamp with time zone,bytea)',true,false),
    ('app.resolve_mfa_authority_v2(uuid,text,text,text,timestamp with time zone,bytea)',true,false),
    ('app.resolve_mfa_completion_artifact_v1(jsonb)',true,false),
    ('app.complete_mfa_totp_step_up_v1(jsonb)',true,false),
    ('app.complete_mfa_recovery_step_up_v1(jsonb)',true,false),
    ('app.complete_mfa_passkey_registration_v1(jsonb)',true,false),
    ('app.complete_mfa_passkey_authentication_v1(jsonb)',true,false),
    ('app.verify_identity_keyring_v3(integer[],bytea[],integer)',true,true)
  )
  SELECT count(*)::integer INTO protected_function_count
  FROM expected
  JOIN pg_catalog.pg_proc AS function
    ON function.oid = pg_catalog.to_regprocedure(expected.signature)
  JOIN pg_catalog.pg_roles AS owner ON owner.oid = function.proowner
  WHERE owner.rolname = 'periapsis_migrator' AND function.prosecdef
    AND function.proconfig IS NOT DISTINCT FROM
      ARRAY['search_path=pg_catalog, public, app']::text[]
    AND has_function_privilege(
      'periapsis_api',function.oid,'EXECUTE'
    ) IS NOT DISTINCT FROM expected.api_execute
    AND has_function_privilege(
      'periapsis_worker',function.oid,'EXECUTE'
    ) IS NOT DISTINCT FROM expected.worker_execute
    AND NOT has_function_privilege('periapsis_notifier',function.oid,'EXECUTE')
    AND NOT has_function_privilege('periapsis_auditor',function.oid,'EXECUTE');

  WITH expected(signature) AS (VALUES
    ('app.apply_tenant_platform_federated_session_revalidation_v1(jsonb)'),
    ('app.apply_tenant_platform_oidc_authentication_v1(jsonb)'),
    ('app.assert_auth_session_mfa_provenance_v1(uuid,uuid)'),
    ('app.assert_mfa_webauthn_evidence_copy_cleanup_v1()'),
    ('app.begin_tenant_platform_oidc_authentication_v1(jsonb)'),
    ('app.claim_mfa_step_up_challenge_v1(bytea,bytea,text,timestamp with time zone)'),
    ('app.claim_tenant_platform_oidc_authentication_transaction_v1(jsonb)'),
    ('app.claim_totp_enrollment_v1(uuid,bytea,timestamp with time zone)'),
    ('app.claim_webauthn_ceremony_v1(bytea,bytea,timestamp with time zone)'),
    ('app.copy_tenant_platform_mfa_authority_evidence_v1()'),
    ('app.create_tenant_platform_oidc_authentication_transaction_v1(jsonb)'),
    ('app.enforce_tenant_federated_continuation_provenance_v1()'),
    ('app.enforce_tenant_passkey_continuation_provenance_v1()'),
    ('app.fail_tenant_platform_oidc_authentication_transaction_v1(jsonb)'),
    ('app.guard_platform_federated_alias_v1()'),
    ('app.guard_platform_federated_external_identity_v1()'),
    ('app.guard_tenant_platform_continuation_child_v1()'),
    ('app.guard_tenant_platform_oidc_transaction_v1()'),
    ('app.guard_tenant_platform_runtime_immutable_v1()'),
    ('app.guard_webauthn_credential_security_revision_v1()'),
    ('app.load_tenant_platform_federated_planning_state_v1(jsonb)'),
    ('app.load_tenant_platform_federated_session_revalidation_v1(jsonb)'),
    ('app.load_tenant_platform_oidc_client_secret_v1(jsonb)'),
    ('app.load_tenant_platform_oidc_trust_snapshot_v1(jsonb)'),
    ('app.private_apply_passkey_session_revalidation_v1(jsonb)'),
    ('app.private_capture_tenant_federated_login_authority_v1(jsonb,jsonb)'),
    ('app.private_capture_tenant_federated_revalidation_authority_v1(jsonb,jsonb)'),
    ('app.private_complete_mfa_factor_legacy_v1(jsonb,text)'),
    ('app.private_complete_mfa_factor_v1(jsonb,text)'),
    ('app.private_federated_assurance_decision_v1(jsonb,jsonb,boolean,timestamp with time zone)'),
    ('app.private_load_passkey_session_revalidation_v1(jsonb)'),
    ('app.private_materialize_tenant_user_profile_v1(uuid,uuid)'),
    ('app.private_mfa_anchor_from_stepup_binding_v1(jsonb,timestamp with time zone)'),
    ('app.private_mfa_apply_passkey_continuation_v1(jsonb,uuid,text,uuid,bigint,text,uuid,bigint,timestamp with time zone)'),
    ('app.private_mfa_apply_passkey_session_v1(jsonb,uuid,text,uuid,bigint,text,uuid,bigint,timestamp with time zone)'),
    ('app.private_mfa_apply_session_v1(jsonb,uuid,text,uuid,bigint,text,uuid,bigint,timestamp with time zone)'),
    ('app.private_mfa_apply_tenant_platform_federated_session_v1(jsonb,uuid,text,uuid,bigint,timestamp with time zone)'),
    ('app.private_mfa_assert_artifact_receipt_v1(uuid,bytea,timestamp with time zone)'),
    ('app.private_mfa_assert_live_continuation_policy_v1(uuid,timestamp with time zone)'),
    ('app.private_mfa_assert_live_passkey_anchor_evidence_v1(uuid,timestamp with time zone,text,uuid)'),
    ('app.private_mfa_assert_live_passkey_continuation_evidence_v1(uuid,uuid,uuid,timestamp with time zone)'),
    ('app.private_mfa_assert_live_passkey_session_evidence_v1(uuid,uuid,uuid,timestamp with time zone)'),
    ('app.private_mfa_assert_live_policy_anchor_v1(uuid,timestamp with time zone)'),
    ('app.private_mfa_enter_continuation_receipt_v1(jsonb,text)'),
    ('app.private_mfa_evidence_projection_v1(uuid,text,uuid)'),
    ('app.private_mfa_finish_webauthn_evidence_copy_v1(jsonb,uuid,uuid,timestamp with time zone)'),
    ('app.private_mfa_lock_continuation_authority_v1(uuid,timestamp with time zone)'),
    ('app.private_mfa_lock_live_passkey_session_v1(uuid,uuid,uuid,uuid,bigint,bigint,timestamp with time zone,text,timestamp with time zone)'),
    ('app.private_mfa_lock_policy_authority_v1(uuid)'),
    ('app.private_mfa_prepare_webauthn_evidence_copy_v1(jsonb,bytea)'),
    ('app.private_mfa_restore_continuation_receipt_v1(text)'),
    ('app.private_platform_oidc_claim_policy_v1(uuid,text)'),
    ('app.private_tenant_platform_oidc_configuration_record_v1(uuid,uuid,uuid,jsonb)'),
    ('app.private_tenant_platform_session_authority_live_v1(uuid,uuid,timestamp with time zone)'),
    ('app.private_unbound_claim_mfa_step_up_challenge_v1(bytea,bytea,text,timestamp with time zone)'),
    ('app.private_unbound_claim_totp_enrollment_v1(uuid,bytea,timestamp with time zone)'),
    ('app.private_unbound_claim_webauthn_ceremony_v1(bytea,bytea,timestamp with time zone)'),
    ('app.private_unbound_create_mfa_step_up_challenge_v1(jsonb)'),
    ('app.private_unbound_create_webauthn_ceremony_v1(jsonb)'),
    ('app.private_unbound_mfa_anchor_from_stepup_binding_v1(jsonb,timestamp with time zone)'),
    ('app.private_unbound_start_totp_enrollment_v1(jsonb)'),
    ('app.private_unprovenanced_rotate_auth_session_tenant_v1(bytea,uuid,bytea,bytea,uuid,timestamp with time zone,timestamp with time zone,uuid,uuid,uuid,inet,text)'),
    ('app.private_v34_apply_federated_authentication_v1(jsonb)'),
    ('app.private_v34_apply_federated_session_revalidation_v1(jsonb)'),
    ('app.private_v34_begin_tenant_oidc_authentication_v1(jsonb)'),
    ('app.private_v34_claim_oidc_authentication_transaction_v1(jsonb)'),
    ('app.private_v34_complete_mfa_passkey_authentication_v1(jsonb)'),
    ('app.private_v34_complete_mfa_passkey_registration_v1(jsonb)'),
    ('app.private_v34_create_oidc_authentication_transaction_v1(jsonb)'),
    ('app.private_v34_fail_oidc_authentication_transaction_v1(jsonb)'),
    ('app.private_v34_load_federated_authentication_planning_state_v1(jsonb)'),
    ('app.private_v34_load_federated_session_revalidation_v1(jsonb)'),
    ('app.private_v34_load_oidc_client_secret_envelope_v1(jsonb)'),
    ('app.private_v34_load_oidc_trust_snapshot_v1(jsonb)'),
    ('app.private_v34_resolve_tenant_oidc_authentication_v1(jsonb)'),
    ('app.private_webauthn_credential_projection_v1(uuid)'),
    ('app.resolve_mfa_authority_v1(uuid,text,text,text,timestamp with time zone)'),
    ('app.resolve_tenant_platform_oidc_authentication_v1(jsonb)'),
    ('app.touch_mfa_policy_authority_v1()'),
    ('app.validate_mfa_evidence_subject_v1()'),
    ('app.validate_tenant_federated_continuation_authority_v1()'),
    ('app.validate_tenant_passkey_continuation_authority_v1()'),
    ('app.validate_tenant_platform_continuation_authority_v1()'),
    ('app.validate_tenant_platform_continuation_provenance_v1()'),
    ('app.validate_tenant_platform_mfa_authority_evidence_v1()'),
    ('app.validate_webauthn_completed_security_snapshot_v1()')
  )
  SELECT count(*) FILTER (WHERE
    function_row.oid IS NULL
    OR owner.rolname IS DISTINCT FROM 'periapsis_migrator'
    OR language.lanname IS DISTINCT FROM CASE expected.signature
      WHEN 'app.claim_totp_enrollment_v1(uuid,bytea,timestamp with time zone)'
        THEN 'sql'
      WHEN 'app.claim_mfa_step_up_challenge_v1(bytea,bytea,text,timestamp with time zone)'
        THEN 'sql'
      WHEN 'app.claim_webauthn_ceremony_v1(bytea,bytea,timestamp with time zone)'
        THEN 'sql'
      WHEN 'app.private_platform_oidc_claim_policy_v1(uuid,text)'
        THEN 'sql'
      WHEN 'app.private_tenant_platform_oidc_configuration_record_v1(uuid,uuid,uuid,jsonb)'
        THEN 'sql'
      WHEN 'app.private_tenant_platform_session_authority_live_v1(uuid,uuid,timestamp with time zone)'
        THEN 'sql'
      ELSE 'plpgsql'
    END
    OR function_row.prokind IS DISTINCT FROM 'f'
    OR function_row.prosecdef IS NOT TRUE
    OR function_row.proconfig IS DISTINCT FROM
      ARRAY['search_path=pg_catalog, public, app']::text[]
    OR CASE WHEN function_row.oid IS NULL THEN true ELSE NOT (
      SELECT count(*) = 1 AND coalesce(bool_and(
        acl.grantor = function_row.proowner
        AND acl.grantee = function_row.proowner
        AND acl.privilege_type = 'EXECUTE'
        AND NOT acl.is_grantable
      ),false)
      FROM pg_catalog.aclexplode(CASE
        WHEN pg_catalog.cardinality(coalesce(
          function_row.proacl,
          pg_catalog.acldefault('f',function_row.proowner)
        )) > 0 THEN coalesce(
          function_row.proacl,
          pg_catalog.acldefault('f',function_row.proowner)
        ) ELSE NULL::pg_catalog.aclitem[]
      END) AS acl
    ) END
  )::integer INTO private_acl_mismatch_count
  FROM expected
  LEFT JOIN pg_catalog.pg_proc AS function_row
    ON function_row.oid = pg_catalog.to_regprocedure(expected.signature)
  LEFT JOIN pg_catalog.pg_roles AS owner ON owner.oid = function_row.proowner
  LEFT JOIN pg_catalog.pg_language AS language ON language.oid = function_row.prolang;
  private_function_count := 86 - private_acl_mismatch_count;

  IF NOT EXISTS (
       SELECT 1 FROM pg_catalog.pg_attribute AS column_row
       WHERE column_row.attrelid =
         'public.platform_oidc_provider_configurations'::regclass
         AND column_row.attname = 'tenant_redirect_uri'
         AND column_row.attnotnull
         AND pg_catalog.format_type(
           column_row.atttypid,column_row.atttypmod
         ) = 'text'
     )
     OR EXISTS (
       SELECT 1
       FROM ONLY public.platform_federated_provider_policies AS policy
       WHERE policy.platform_login_enabled
     )
     OR EXISTS (
       SELECT 1
       FROM ONLY public.tenant_platform_auth_provider_bindings AS binding
       LEFT JOIN ONLY public.tenant_platform_identity_provider_access_epochs
         AS epoch
         ON epoch.tenant_id = binding.tenant_id
        AND epoch.id = binding.current_access_epoch_id
        AND epoch.binding_id = binding.id
        AND epoch.platform_provider_id = binding.platform_provider_id
        AND epoch.ended_at IS NULL
       LEFT JOIN ONLY public.tenant_authorization_sources AS source
         ON source.tenant_id = epoch.tenant_id AND source.id = epoch.source_id
        AND source.kind = 'identity_provider_access'
        AND source.authoritative AND NOT source.protected
        AND source.key = format(
          'identity_provider_access:%s:%s',epoch.binding_id,epoch.sequence
        ) AND source.retired_at IS NULL
       WHERE binding.enabled
         AND (epoch.id IS NULL OR source.id IS NULL
           OR binding.current_access_epoch_id IS NULL)
     )
     OR EXISTS (
       SELECT 1
       FROM ONLY public.tenant_platform_identity_provider_access_epochs AS epoch
       JOIN ONLY public.tenant_authorization_sources AS source
         ON source.tenant_id = epoch.tenant_id AND source.id = epoch.source_id
       WHERE epoch.ended_at IS NOT NULL
         AND source.retired_at IS DISTINCT FROM epoch.ended_at
     ) THEN
    RETURN false;
  END IF;

  SELECT pg_catalog.pg_get_functiondef(
    'app.private_tenant_platform_oidc_configuration_record_v1(uuid,uuid,uuid,jsonb)'::regprocedure
  ) INTO function_definition;
  IF function_definition NOT LIKE '%tenant_redirect_uri%'
     OR function_definition NOT LIKE '%private_platform_oidc_claim_policy_v1%'
     OR function_definition NOT LIKE
       '%p_expected_pins ->> ''providerRevision''%'
     OR function_definition NOT LIKE
       '%projected.pins = p_expected_pins%'
     OR function_definition LIKE '%''redirectUri'', projected.redirect_uri%' THEN
    RETURN false;
  END IF;
  SELECT pg_catalog.pg_get_functiondef(
    'app.apply_tenant_platform_oidc_authentication_v1(jsonb)'::regprocedure
  ) INTO function_definition;
  IF function_definition NOT LIKE '%private_mfa_policy_snapshot_v1%'
     OR function_definition NOT LIKE
       '%auth_session_tenant_platform_federated_evidence%'
     OR function_definition NOT LIKE
       '%array_agg(DISTINCT matches.user_id%'
     OR function_definition NOT LIKE
       '%uuid_send(gen_random_uuid()) || uuid_send(gen_random_uuid())%'
     OR function_definition LIKE '%gen_random_bytes(32)%'
     OR function_definition LIKE
       '%provider.version = transaction_record.provider_revision%'
     OR function_definition LIKE
       '%SET subject_ciphertext = protected_subject_ciphertext%'
     OR function_definition LIKE '%tenant_membership_role_grants%'
     OR function_definition LIKE '%tenant_security_group_role_grants%' THEN
    RETURN false;
  END IF;
  SELECT pg_catalog.pg_get_functiondef(
    'app.load_tenant_platform_federated_planning_state_v1(jsonb)'::regprocedure
  ) INTO function_definition;
  IF function_definition LIKE '%provider.version = provider_revision%'
     OR function_definition NOT LIKE
       '%policy.configuration_revision = configuration_revision%'
     OR function_definition NOT LIKE
       '%policy.security_revision = security_revision%' THEN
    RETURN false;
  END IF;
  SELECT pg_catalog.pg_get_functiondef(
    'app.load_tenant_platform_oidc_trust_snapshot_v1(jsonb)'::regprocedure
  ) INTO function_definition;
  IF function_definition LIKE
       '%provider.version = (p_lookup ->> ''providerRevision'')::bigint%'
     OR function_definition NOT LIKE
       '%provider_revision := (p_lookup ->> ''providerRevision'')::bigint%'
     OR function_definition NOT LIKE
       '%provider_revision NOT BETWEEN 1 AND 2147483647%'
     OR function_definition NOT LIKE
       '%policy.security_revision = (p_lookup ->> ''securityRevision'')::bigint%' THEN
    RETURN false;
  END IF;
  SELECT pg_catalog.pg_get_functiondef(
    'app.guard_platform_federated_external_identity_v1()'::regprocedure
  ) INTO function_definition;
  IF function_definition NOT LIKE '%NEW.version = OLD.version%'
     OR function_definition NOT LIKE '%OLD.retired_at IS NULL%'
     OR function_definition NOT LIKE '%NEW.retired_at IS NULL%' THEN
    RETURN false;
  END IF;
  SELECT pg_catalog.pg_get_functiondef(
    'app.private_tenant_platform_session_authority_live_v1(uuid,uuid,timestamp with time zone)'::regprocedure
  ) INTO function_definition;
  IF function_definition LIKE
       '%provider.version = provenance.provider_revision%'
     OR function_definition NOT LIKE
       '%binding.version = provenance.binding_revision%'
     OR function_definition NOT LIKE
       '%policy.security_revision = provenance.security_revision%' THEN
    RETURN false;
  END IF;
  SELECT pg_catalog.pg_get_functiondef(
    'app.apply_tenant_platform_federated_session_revalidation_v1(jsonb)'::regprocedure
  ) INTO function_definition;
  IF function_definition NOT LIKE
       '%ELSIF decision IN (''revoke'',''deny'') THEN%'
     OR function_definition NOT LIKE
       '%tenant_platform_federated_session_revalidation_commands%'
     OR function_definition NOT LIKE
       '%tenant platform session replay mismatch%'
     OR function_definition NOT LIKE
       '%tenant platform session command lost CAS%' THEN
    RETURN false;
  END IF;
  SELECT pg_catalog.pg_get_functiondef(
    'app.load_federated_session_revalidation_v1(jsonb)'::regprocedure
  ) INTO function_definition;
  IF function_definition NOT LIKE
       '%load_tenant_platform_federated_session_revalidation_v1%'
     OR function_definition NOT LIKE
       '%private_v34_load_federated_session_revalidation_v1%' THEN
    RETURN false;
  END IF;
  SELECT pg_catalog.pg_get_functiondef(
    'app.apply_federated_session_revalidation_v1(jsonb)'::regprocedure
  ) INTO function_definition;
  IF function_definition NOT LIKE
       '%apply_tenant_platform_federated_session_revalidation_v1%'
     OR function_definition NOT LIKE
       '%private_v34_apply_federated_session_revalidation_v1%' THEN
    RETURN false;
  END IF;
  SELECT pg_catalog.pg_get_functiondef(
    'app.verify_identity_keyring_v3(integer[],bytea[],integer)'::regprocedure
  ) INTO function_definition;
  IF function_definition NOT LIKE
       '%public.platform_federated_external_identities%'
     OR function_definition NOT LIKE
       '%public.platform_federated_external_identity_aliases%'
     OR function_definition NOT LIKE
       '%public.tenant_platform_oidc_authentication_transactions%'
     OR function_definition NOT LIKE
       '%transaction.state IN (''pending'',''claimed'')%'
     OR function_definition NOT LIKE
       '%transaction.expires_at > transaction_timestamp()%'
     OR function_definition NOT LIKE
       '%RETURN app.verify_identity_keyring_v2(%' THEN
    RETURN false;
  END IF;
  SELECT pg_catalog.pg_get_functiondef(
    'app.rotate_auth_session_tenant(bytea,uuid,bytea,bytea,uuid,timestamp with time zone,timestamp with time zone,uuid,uuid,uuid,inet,text)'::regprocedure
  ) INTO function_definition;
  IF function_definition NOT LIKE '%auth_session_mfa_states%'
     OR function_definition NOT LIKE
       '%auth_session_federated_provenance%'
     OR function_definition NOT LIKE
       '%auth_session_tenant_platform_federated_provenance%'
     OR function_definition NOT LIKE '%FOR UPDATE%'
     OR function_definition NOT LIKE
       '%typed-provenance session tenant switch requires provenance-aware rotation%' THEN
    RETURN false;
  END IF;

  RETURN protected_relation_count = 14
     AND relation_acl_mismatch_count = 0
     AND runtime_login_role_mismatch_count = 0
     AND runtime_login_membership_mismatch_count = 0
     AND runtime_login_setting_mismatch_count = 0
     AND runtime_login_parameter_acl_mismatch_count = 0
     AND runtime_login_default_acl_mismatch_count = 0
     AND constraint_count = 49
     AND index_count = 12
     AND trigger_count = 31
     AND protected_function_count = 31
     AND private_function_count = 86
     AND private_acl_mismatch_count = 0
     AND dependency_surface_ready
     AND trusted_root_catalog_ready;
END;
$function$;
ALTER FUNCTION app.private_tenant_platform_oidc_runtime_schema_readiness_v1()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION
  app.private_tenant_platform_oidc_runtime_schema_readiness_v1()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,
  periapsis_sla_api_owner, periapsis_sla_worker_owner,
  periapsis_sla_readiness_owner, periapsis_ticket_saved_view_owner,
  periapsis_ticket_attribution_owner,
  periapsis_ticket_sla_projection_owner;
--> statement-breakpoint

CREATE FUNCTION app.tenant_platform_oidc_runtime_schema_readiness_v1()
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  current_count bigint;
BEGIN
  SELECT compatibility.applied_count INTO current_count
  FROM app.schema_compatibility_v35() AS compatibility;
  RETURN current_count = 167
    AND NOT has_function_privilege(
      'periapsis_api','app.schema_compatibility_v34()'::regprocedure,'EXECUTE'
    )
    AND NOT has_function_privilege(
      'periapsis_worker','app.schema_compatibility_v34()'::regprocedure,'EXECUTE'
    )
    AND app.private_tenant_platform_oidc_runtime_schema_readiness_v1();
END;
$function$;
ALTER FUNCTION app.tenant_platform_oidc_runtime_schema_readiness_v1()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.tenant_platform_oidc_runtime_schema_readiness_v1()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,
  periapsis_sla_api_owner, periapsis_sla_worker_owner,
  periapsis_sla_readiness_owner, periapsis_ticket_saved_view_owner,
  periapsis_ticket_attribution_owner,
  periapsis_ticket_sla_projection_owner;
GRANT EXECUTE ON FUNCTION app.tenant_platform_oidc_runtime_schema_readiness_v1()
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
  IF p_expected_count IS DISTINCT FROM 167
     OR p_expected_latest_created_at IS DISTINCT FROM 1788049988184
     OR p_expected_latest_hash !~ '^[0-9a-f]{64}$'
     OR p_expected_migration_fingerprint !~
       '^[0-9]+@[0-9a-f]{64}(:[0-9]+@[0-9a-f]{64}){166}$' THEN
    RAISE EXCEPTION 'schema compatibility v35 seal input is invalid'
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
     OR NOT app.private_tenant_platform_oidc_runtime_schema_readiness_v1()
     OR has_function_privilege(
       'periapsis_api','app.schema_compatibility_v34()'::regprocedure,'EXECUTE'
     )
     OR has_function_privilege(
       'periapsis_worker','app.schema_compatibility_v34()'::regprocedure,'EXECUTE'
     ) THEN
    RAISE EXCEPTION 'schema compatibility v35 cannot be sealed'
      USING ERRCODE = '55000';
  END IF;

  EXECUTE format(
    'ALTER FUNCTION app.schema_compatibility_v35() SET app.schema_compatibility_fingerprint = %L',
    p_expected_migration_fingerprint
  );
  SELECT compatibility.applied_count,compatibility.latest_created_at,
         compatibility.latest_hash,compatibility.migration_fingerprint
  INTO sealed_count,sealed_latest_created_at,sealed_latest_hash,
       sealed_fingerprint
  FROM app.schema_compatibility_v35() AS compatibility;
  IF ROW(sealed_count,sealed_latest_created_at,sealed_latest_hash,
         sealed_fingerprint) IS DISTINCT FROM
     ROW(p_expected_count,p_expected_latest_created_at,p_expected_latest_hash,
         p_expected_migration_fingerprint)
     OR NOT app.tenant_platform_oidc_runtime_schema_readiness_v1() THEN
    RAISE EXCEPTION 'schema compatibility v35 seal verification failed'
      USING ERRCODE = '55000';
  END IF;
END;
$function$;
ALTER FUNCTION app.seal_schema_compatibility_manifest(
  bigint,bigint,text,text
) OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.seal_schema_compatibility_manifest(
  bigint,bigint,text,text
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,
  periapsis_sla_api_owner, periapsis_sla_worker_owner,
  periapsis_sla_readiness_owner, periapsis_ticket_saved_view_owner,
  periapsis_ticket_attribution_owner,
  periapsis_ticket_sla_projection_owner;
GRANT EXECUTE ON FUNCTION app.seal_schema_compatibility_manifest(
  bigint,bigint,text,text
) TO periapsis_migrator;
--> statement-breakpoint
