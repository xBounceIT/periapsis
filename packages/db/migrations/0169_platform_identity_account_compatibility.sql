-- V36 adds provider-global identity-account administration and provider-kind
-- specific create ABIs. The v35 runtime root does not describe that surface,
-- so fail closed instead of advertising it as a rolling predecessor.

ALTER FUNCTION app.schema_compatibility_v35()
  SET app.schema_compatibility_fingerprint = 'RETIRED';
REVOKE ALL ON FUNCTION app.schema_compatibility_v35()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,
  periapsis_sla_api_owner, periapsis_sla_worker_owner,
  periapsis_sla_readiness_owner, periapsis_ticket_saved_view_owner,
  periapsis_ticket_attribution_owner,
  periapsis_ticket_sla_projection_owner;
REVOKE ALL ON FUNCTION app.tenant_platform_oidc_runtime_schema_readiness_v1()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,
  periapsis_sla_api_owner, periapsis_sla_worker_owner,
  periapsis_sla_readiness_owner, periapsis_ticket_saved_view_owner,
  periapsis_ticket_attribution_owner,
  periapsis_ticket_sla_projection_owner;
--> statement-breakpoint

CREATE FUNCTION app.schema_compatibility_v36()
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
             WHERE migration.created_at = 1788062677386
           )::bigint,
           string_agg(
             migration.created_at::text || '@' || lower(migration.hash::text),
             ':' ORDER BY migration.created_at,migration.id
           )
    FROM drizzle.__drizzle_migrations AS migration
  $query$ INTO journal_count,journal_latest_created_at,latest_rows,
                journal_fingerprint;

  SELECT count(*) = 1 INTO self_catalog_ready
  FROM pg_catalog.pg_proc AS function_row
  JOIN pg_catalog.pg_namespace AS namespace
    ON namespace.oid = function_row.pronamespace
  JOIN pg_catalog.pg_roles AS owner ON owner.oid = function_row.proowner
  JOIN pg_catalog.pg_language AS language ON language.oid = function_row.prolang
  WHERE function_row.oid = 'app.schema_compatibility_v36()'::regprocedure
    AND namespace.nspname = 'app'
    AND owner.rolname = 'periapsis_migrator'
    AND language.lanname = 'plpgsql'
    AND function_row.prokind = 'f' AND function_row.provolatile = 's'
    AND function_row.prosecdef AND NOT function_row.proisstrict
    AND NOT function_row.proleakproof AND function_row.proparallel = 'u'
    AND function_row.pronargs = 0
    AND function_row.proconfig IS NOT DISTINCT FROM ARRAY[
      'search_path=pg_catalog',
      'app.schema_compatibility_fingerprint=' || journal_fingerprint
    ]::text[]
    AND pg_catalog.pg_get_function_result(function_row.oid) =
      'TABLE(applied_count bigint, latest_created_at bigint, latest_hash text, migration_fingerprint text)'
    AND (
      SELECT count(*) = 3 AND coalesce(bool_and(
        function_acl.grantor = function_row.proowner
        AND function_acl.grantee IN (
          function_row.proowner,
          (SELECT role.oid FROM pg_catalog.pg_roles AS role
           WHERE role.rolname = 'periapsis_api'),
          (SELECT role.oid FROM pg_catalog.pg_roles AS role
           WHERE role.rolname = 'periapsis_worker')
        )
        AND function_acl.privilege_type = 'EXECUTE'
        AND NOT function_acl.is_grantable
      ),false)
      FROM pg_catalog.aclexplode(CASE WHEN pg_catalog.cardinality(coalesce(
        function_row.proacl,
        pg_catalog.acldefault('f',function_row.proowner)
      )) > 0 THEN coalesce(
        function_row.proacl,
        pg_catalog.acldefault('f',function_row.proowner)
      ) ELSE NULL::pg_catalog.aclitem[] END) AS function_acl
    );

  IF journal_count = 170
     AND journal_latest_created_at = 1788062677386
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
ALTER FUNCTION app.schema_compatibility_v36() OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.schema_compatibility_v36()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,
  periapsis_sla_api_owner, periapsis_sla_worker_owner,
  periapsis_sla_readiness_owner, periapsis_ticket_saved_view_owner,
  periapsis_ticket_attribution_owner,
  periapsis_ticket_sla_projection_owner;
GRANT EXECUTE ON FUNCTION app.schema_compatibility_v36()
TO periapsis_api, periapsis_worker;
--> statement-breakpoint

-- The v35 dependency transcript is deliberately frozen. Derive the v36
-- implementation only from its exact attested predecessor, changing the four
-- self-excluded roots so v35 becomes part of the new sealed surface.
DO $derive_platform_identity_dependency_surface_v2$
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
  WHERE function_row.oid =
    'app.private_tenant_platform_oidc_dependency_surface_hash_v1()'::regprocedure;
  IF predecessor_source_hash IS DISTINCT FROM
       '7ef3708e7225a7b643f114a26f96812fb2b1e0e187e467b9fed82350c0096d0f' THEN
    RAISE EXCEPTION 'platform identity dependency predecessor drifted'
      USING ERRCODE = '55000';
  END IF;

  derived_definition := pg_catalog.replace(
    predecessor_definition,
    'private_tenant_platform_oidc_dependency_surface_hash_v1',
    'private_platform_identity_dependency_surface_hash_v2'
  );
  derived_definition := pg_catalog.replace(
    derived_definition,
    'private_tenant_platform_oidc_runtime_schema_readiness_v1',
    'private_platform_identity_runtime_schema_readiness_v2'
  );
  derived_definition := pg_catalog.replace(
    derived_definition,
    'tenant_platform_oidc_runtime_schema_readiness_v1',
    'platform_identity_runtime_schema_readiness_v2'
  );
  derived_definition := pg_catalog.replace(
    derived_definition,'schema_compatibility_v35','schema_compatibility_v36'
  );
  IF derived_definition = predecessor_definition
     OR derived_definition LIKE
       '%private_tenant_platform_oidc_dependency_surface_hash_v1%'
     OR derived_definition LIKE
       '%private_tenant_platform_oidc_runtime_schema_readiness_v1%'
     OR derived_definition LIKE
       '%tenant_platform_oidc_runtime_schema_readiness_v1%'
     OR derived_definition LIKE '%schema_compatibility_v35%' THEN
    RAISE EXCEPTION 'platform identity dependency derivation was not exact'
      USING ERRCODE = '55000';
  END IF;
  EXECUTE derived_definition;
END;
$derive_platform_identity_dependency_surface_v2$;
ALTER FUNCTION app.private_platform_identity_dependency_surface_hash_v2()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION
  app.private_platform_identity_dependency_surface_hash_v2()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,
  periapsis_sla_api_owner, periapsis_sla_worker_owner,
  periapsis_sla_readiness_owner, periapsis_ticket_saved_view_owner,
  periapsis_ticket_attribution_owner,
  periapsis_ticket_sla_projection_owner;
--> statement-breakpoint

CREATE FUNCTION app.private_platform_identity_runtime_schema_readiness_v2()
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  dependency_surface_ready boolean;
  trusted_root_catalog_ready boolean;
  account_relation_ready boolean;
  account_contract_ready boolean;
  account_function_ready boolean;
  function_definition text;
BEGIN
  SELECT count(*) = 1 AND coalesce(bool_and(
    owner.rolname = 'periapsis_migrator'
    AND language.lanname = 'sql'
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
      'quote_all_identifiers=off','TimeZone=UTC',
      'DateStyle=ISO, YMD','IntervalStyle=postgres',
      'extra_float_digits=3','bytea_output=hex',
      'standard_conforming_strings=on','lc_numeric=C'
    ]::text[]
    AND pg_catalog.pg_get_function_result(function_row.oid) = 'text'
    AND pg_catalog.encode(pg_catalog.sha256(
      pg_catalog.convert_to(function_row.prosrc,'UTF8')
    ),'hex') =
      '6a8c4ddd4a219c10033e60b1cdd85d4e7c72980abdc83695cfc8b3e9ffc76852'
    AND app.private_platform_identity_dependency_surface_hash_v2() =
      'dbe197debc5813ff66b9d7ad38c1cf273537f587d9d2612dea829e0709c3dfa9'
    AND (
      SELECT count(*) = 1 AND coalesce(bool_and(
        function_acl.grantor = function_row.proowner
        AND function_acl.grantee = function_row.proowner
        AND function_acl.privilege_type = 'EXECUTE'
        AND NOT function_acl.is_grantable
      ),false)
      FROM pg_catalog.aclexplode(CASE WHEN pg_catalog.cardinality(coalesce(
        function_row.proacl,
        pg_catalog.acldefault('f',function_row.proowner)
      )) > 0 THEN coalesce(
        function_row.proacl,
        pg_catalog.acldefault('f',function_row.proowner)
      ) ELSE NULL::pg_catalog.aclitem[] END) AS function_acl
    )
  ),false) INTO dependency_surface_ready
  FROM pg_catalog.pg_proc AS function_row
  JOIN pg_catalog.pg_roles AS owner ON owner.oid = function_row.proowner
  JOIN pg_catalog.pg_language AS language ON language.oid = function_row.prolang
  WHERE function_row.oid =
    'app.private_platform_identity_dependency_surface_hash_v2()'::regprocedure;

  WITH expected(signature,language_name,expected_result,expected_acl_roles) AS (
    VALUES
      ('app.schema_compatibility_v36()','plpgsql',
       'TABLE(applied_count bigint, latest_created_at bigint, latest_hash text, migration_fingerprint text)',
       ARRAY['periapsis_api','periapsis_migrator','periapsis_worker']::text[]),
      ('app.schema_compatibility_v35()','plpgsql',
       'TABLE(applied_count bigint, latest_created_at bigint, latest_hash text, migration_fingerprint text)',
       ARRAY['periapsis_migrator']::text[]),
      ('app.platform_tenant_lifecycle_schema_readiness_v1()','plpgsql',
       'boolean',
       ARRAY['periapsis_api','periapsis_migrator','periapsis_worker']::text[]),
      ('app.private_platform_identity_dependency_surface_hash_v2()','sql',
       'text',ARRAY['periapsis_migrator']::text[]),
      ('app.private_platform_identity_runtime_schema_readiness_v2()','plpgsql',
       'boolean',ARRAY['periapsis_migrator']::text[]),
      ('app.platform_identity_runtime_schema_readiness_v2()','plpgsql',
       'boolean',
       ARRAY['periapsis_api','periapsis_migrator','periapsis_worker']::text[])
  ), actual AS (
    SELECT expected.*,function_row.oid,function_row.proowner,
      function_row.proconfig,function_row.prolang
    FROM expected
    LEFT JOIN pg_catalog.pg_proc AS function_row
      ON function_row.oid = pg_catalog.to_regprocedure(expected.signature)
  )
  SELECT count(*) = 6 AND coalesce(bool_and(
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
      'app.schema_compatibility_v36()','app.schema_compatibility_v35()'
    ))
    AND function_row.procost = 100::real
    AND function_row.prorows = CASE WHEN function_row.proretset
      THEN 1000::real ELSE 0::real END
    AND function_row.protrftypes IS NULL
    AND function_row.probin IS NULL
    AND function_row.prosqlbody IS NULL
    AND CASE WHEN function_row.proretset THEN
      function_row.proallargtypes IS NOT DISTINCT FROM ARRAY[
        'bigint'::pg_catalog.regtype,'bigint'::pg_catalog.regtype,
        'text'::pg_catalog.regtype,'text'::pg_catalog.regtype
      ]::pg_catalog.oid[]
      AND function_row.proargmodes IS NOT DISTINCT FROM
        ARRAY['t','t','t','t']::"char"[]
      AND function_row.proargnames IS NOT DISTINCT FROM ARRAY[
        'applied_count','latest_created_at','latest_hash',
        'migration_fingerprint'
      ]::text[]
    ELSE function_row.proallargtypes IS NULL
      AND function_row.proargmodes IS NULL
      AND function_row.proargnames IS NULL
    END
    AND pg_catalog.pg_get_function_result(function_row.oid) =
      actual.expected_result
    AND CASE actual.signature
      WHEN 'app.schema_compatibility_v36()' THEN
        function_row.proconfig[1] = 'search_path=pg_catalog'
        AND function_row.proconfig[2] ~
          '^app\.schema_compatibility_fingerprint=(UNSEALED|[0-9]+@[0-9a-f]{64}(:[0-9]+@[0-9a-f]{64})*)$'
        AND pg_catalog.cardinality(function_row.proconfig) = 2
      WHEN 'app.schema_compatibility_v35()' THEN
        function_row.proconfig IS NOT DISTINCT FROM ARRAY[
          'search_path=pg_catalog',
          'app.schema_compatibility_fingerprint=RETIRED'
        ]::text[]
      WHEN 'app.platform_tenant_lifecycle_schema_readiness_v1()' THEN
        function_row.proconfig IS NOT DISTINCT FROM
          ARRAY['search_path=pg_catalog, app']::text[]
      WHEN 'app.private_platform_identity_dependency_surface_hash_v2()' THEN
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
          function_acl.grantor = function_row.proowner
          AND function_acl.privilege_type = 'EXECUTE'
          AND NOT function_acl.is_grantable
        ),false)
      FROM pg_catalog.aclexplode(CASE WHEN pg_catalog.cardinality(coalesce(
        function_row.proacl,
        pg_catalog.acldefault('f',function_row.proowner)
      )) > 0 THEN coalesce(
        function_row.proacl,
        pg_catalog.acldefault('f',function_row.proowner)
      ) ELSE NULL::pg_catalog.aclitem[] END) AS function_acl
      LEFT JOIN pg_catalog.pg_roles AS grantee
        ON grantee.oid = function_acl.grantee
    )
  ),false) INTO trusted_root_catalog_ready
  FROM actual
  LEFT JOIN pg_catalog.pg_proc AS function_row ON function_row.oid = actual.oid
  LEFT JOIN pg_catalog.pg_roles AS owner ON owner.oid = function_row.proowner
  LEFT JOIN pg_catalog.pg_language AS language
    ON language.oid = function_row.prolang;

  SELECT count(*) = 1 AND coalesce(bool_and(
    owner.rolname = 'periapsis_migrator'
    AND relation_row.relkind = 'r'
    AND relation_row.relpersistence = 'p'
    AND relation_row.relrowsecurity AND relation_row.relforcerowsecurity
    AND NOT EXISTS (
      SELECT 1 FROM pg_catalog.pg_policy AS policy
      WHERE policy.polrelid = relation_row.oid
    )
    AND (
      SELECT count(*) = 8 AND coalesce(bool_and(
        relation_acl.grantor = relation_row.relowner
        AND relation_acl.grantee = relation_row.relowner
        AND relation_acl.privilege_type IN (
          'SELECT','INSERT','UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER',
          'MAINTAIN'
        )
        AND NOT relation_acl.is_grantable
      ),false)
      FROM pg_catalog.aclexplode(CASE WHEN pg_catalog.cardinality(coalesce(
        relation_row.relacl,
        pg_catalog.acldefault('r',relation_row.relowner)
      )) > 0 THEN coalesce(
        relation_row.relacl,
        pg_catalog.acldefault('r',relation_row.relowner)
      ) ELSE NULL::pg_catalog.aclitem[] END) AS relation_acl
    )
  ),false) INTO account_relation_ready
  FROM pg_catalog.pg_class AS relation_row
  JOIN pg_catalog.pg_namespace AS namespace
    ON namespace.oid = relation_row.relnamespace
  JOIN pg_catalog.pg_roles AS owner ON owner.oid = relation_row.relowner
  WHERE namespace.nspname = 'public'
    AND relation_row.relname = 'platform_identity_account_commands';

  SELECT
    (SELECT count(*) = 10
     FROM pg_catalog.pg_attribute AS column_row
     WHERE column_row.attrelid =
       'public.platform_identity_account_commands'::regclass
       AND column_row.attnum > 0 AND NOT column_row.attisdropped)
    AND (SELECT count(*) = 20
         AND count(*) FILTER (WHERE constraint_row.contype = 'c') = 5
         AND count(*) FILTER (WHERE constraint_row.contype = 'f') = 3
         AND count(*) FILTER (WHERE constraint_row.contype = 'n') = 10
         AND count(*) FILTER (WHERE constraint_row.contype = 'p') = 1
         AND count(*) FILTER (WHERE constraint_row.contype = 'u') = 1
      FROM pg_catalog.pg_constraint AS constraint_row
      WHERE constraint_row.conrelid =
        'public.platform_identity_account_commands'::regclass
        AND constraint_row.conenforced AND constraint_row.convalidated
        AND NOT constraint_row.condeferrable
        AND NOT constraint_row.condeferred)
    AND (SELECT count(*) = 4 AND bool_and(
           index_row.indisvalid AND index_row.indisready
           AND index_row.indislive
         )
      FROM pg_catalog.pg_index AS index_row
      WHERE index_row.indrelid =
        'public.platform_identity_account_commands'::regclass)
    AND (SELECT count(*) = 1 AND bool_and(
           trigger_row.tgenabled = 'O'
           AND NOT trigger_row.tgisinternal
           AND pg_catalog.pg_get_triggerdef(trigger_row.oid,false) =
             'CREATE TRIGGER platform_identity_account_commands_guard_v1 BEFORE INSERT OR DELETE OR UPDATE ON public.platform_identity_account_commands FOR EACH ROW EXECUTE FUNCTION guard_platform_identity_account_command_v1()'
         )
      FROM pg_catalog.pg_trigger AS trigger_row
      WHERE trigger_row.tgrelid =
        'public.platform_identity_account_commands'::regclass
        AND NOT trigger_row.tgisinternal)
    AND EXISTS (
      SELECT 1
      FROM pg_catalog.pg_class AS index_relation
      JOIN pg_catalog.pg_namespace AS namespace
        ON namespace.oid = index_relation.relnamespace
      JOIN pg_catalog.pg_index AS index_row
        ON index_row.indexrelid = index_relation.oid
      WHERE namespace.nspname = 'public'
        AND index_relation.relname =
          'platform_federated_external_identities_live_provider_cursor_idx'
        AND index_row.indisvalid AND index_row.indisready
        AND index_row.indislive
        AND pg_catalog.pg_get_indexdef(index_relation.oid) =
          'CREATE INDEX platform_federated_external_identities_live_provider_cursor_idx ON public.platform_federated_external_identities USING btree (platform_provider_id, id) WHERE (retired_at IS NULL)'
    ) INTO account_contract_ready;

  WITH expected(signature,expected_acl_roles) AS (VALUES
    ('app.create_platform_oidc_auth_provider_v2(uuid,uuid,uuid,text,text,text,jsonb,text,bytea,bytea,uuid,uuid,uuid,inet,text,text,text)',
      ARRAY['periapsis_api','periapsis_migrator']::text[]),
    ('app.create_platform_saml_auth_provider_v2(uuid,uuid,uuid,text,text,text,jsonb,bytea,bytea,uuid,uuid,uuid,inet,text,text,text)',
      ARRAY['periapsis_api','periapsis_migrator']::text[]),
    ('app.list_platform_identity_accounts_v1(uuid,text,uuid,uuid,integer,boolean)',
      ARRAY['periapsis_api','periapsis_migrator']::text[]),
    ('app.get_platform_identity_account_v1(uuid,uuid,uuid,text)',
      ARRAY['periapsis_api','periapsis_migrator']::text[]),
    ('app.prelink_platform_identity_account_v1(uuid,uuid,uuid,uuid,uuid,text,public.identity_subject_format,bytea,bytea,integer,integer[],bytea[],bytea,bytea,uuid,uuid,uuid,inet,text,text,text)',
      ARRAY['periapsis_api','periapsis_migrator']::text[]),
    ('app.retire_platform_identity_account_v1(uuid,uuid,uuid,bigint,uuid,uuid,uuid,inet,text,text,text)',
      ARRAY['periapsis_api','periapsis_migrator']::text[]),
    ('app.guard_platform_identity_account_command_v1()',
      ARRAY['periapsis_migrator']::text[]),
    ('app.private_platform_identity_digest_equal_v1(bytea,bytea)',
      ARRAY['periapsis_migrator']::text[]),
    ('app.private_append_platform_identity_account_tenant_audit_v1(uuid,uuid,uuid,uuid,uuid,uuid,uuid,inet,text,text,text,integer)',
      ARRAY['periapsis_migrator']::text[]),
    ('app.private_platform_identity_account_document_v1(uuid,uuid)',
      ARRAY['periapsis_migrator']::text[]),
    ('app.create_platform_auth_provider_v1(uuid,uuid,uuid,public.auth_provider_kind,text,text,text,jsonb,bytea,bytea,uuid,uuid,uuid,inet,text,text,text)',
      ARRAY['periapsis_migrator']::text[])
  ), actual AS (
    SELECT expected.*,function_row.oid,function_row.proowner,function_row.proacl
    FROM expected
    LEFT JOIN pg_catalog.pg_proc AS function_row
      ON function_row.oid = pg_catalog.to_regprocedure(expected.signature)
  )
  SELECT count(*) = 11 AND coalesce(bool_and(
    actual.oid IS NOT NULL AND owner.rolname = 'periapsis_migrator'
    AND (
      SELECT count(*) = pg_catalog.cardinality(actual.expected_acl_roles)
        AND pg_catalog.array_agg(
          coalesce(grantee.rolname,'PUBLIC')::text
          ORDER BY coalesce(grantee.rolname,'PUBLIC')::text COLLATE "C"
        ) IS NOT DISTINCT FROM actual.expected_acl_roles
        AND coalesce(bool_and(
          function_acl.grantor = actual.proowner
          AND function_acl.privilege_type = 'EXECUTE'
          AND NOT function_acl.is_grantable
        ),false)
      FROM pg_catalog.aclexplode(CASE WHEN pg_catalog.cardinality(coalesce(
        actual.proacl,pg_catalog.acldefault('f',actual.proowner)
      )) > 0 THEN coalesce(
        actual.proacl,pg_catalog.acldefault('f',actual.proowner)
      ) ELSE NULL::pg_catalog.aclitem[] END) AS function_acl
      LEFT JOIN pg_catalog.pg_roles AS grantee
        ON grantee.oid = function_acl.grantee
    )
  ),false) INTO account_function_ready
  FROM actual
  LEFT JOIN pg_catalog.pg_roles AS owner ON owner.oid = actual.proowner;

  IF NOT dependency_surface_ready OR NOT trusted_root_catalog_ready
     OR NOT account_relation_ready OR NOT account_contract_ready
     OR NOT account_function_ready THEN
    RETURN false;
  END IF;

  IF EXISTS (
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
        AND source.key = pg_catalog.format(
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
     )
     OR EXISTS (
       SELECT 1
       FROM ONLY public.platform_federated_external_identities AS identity
       WHERE NOT EXISTS (
         SELECT 1
         FROM ONLY public.platform_federated_external_identity_aliases AS alias
         WHERE alias.platform_provider_id = identity.platform_provider_id
           AND alias.external_identity_id = identity.id
           AND alias.key_version = identity.key_version
       )
     ) THEN
    RETURN false;
  END IF;

  SELECT pg_catalog.pg_get_functiondef(
    'app.prelink_platform_identity_account_v1(uuid,uuid,uuid,uuid,uuid,text,public.identity_subject_format,bytea,bytea,integer,integer[],bytea[],bytea,bytea,uuid,uuid,uuid,inet,text,text,text)'::regprocedure
  ) INTO function_definition;
  IF function_definition NOT LIKE '%provider_record.kind <> ''oidc''%'
     OR function_definition NOT LIKE '%provider_record.archived_at IS NOT NULL%'
     OR function_definition NOT LIKE
       '%configuration_record.issuer IS DISTINCT FROM p_issuer%'
     OR function_definition NOT LIKE '%matched_alias_count <> alias_count%'
     OR function_definition NOT LIKE '%matched_account_count <> 1%'
     OR function_definition NOT LIKE '%divergent_alias_count > 0%'
     OR function_definition NOT LIKE
       '%private_platform_identity_digest_equal_v1(%'
     OR function_definition NOT LIKE
       '%INSERT INTO public.platform_identity_account_commands%'
     OR function_definition NOT LIKE '%account.prelinked%' THEN
    RETURN false;
  END IF;

  SELECT pg_catalog.pg_get_functiondef(
    'app.retire_platform_identity_account_v1(uuid,uuid,uuid,bigint,uuid,uuid,uuid,inet,text,text,text)'::regprocedure
  ) INTO function_definition;
  IF function_definition NOT LIKE '%affected_families%'
     OR function_definition NOT LIKE '%session.rotation_family_id%'
     OR function_definition NOT LIKE
       '%tenant_post_primary_continuations AS continuation%'
     OR function_definition NOT LIKE
       '%tenant_platform_federated_provider_access_grants AS grant_row%'
     OR function_definition NOT LIKE
       '%session_invalidation_epoch = subject.session_invalidation_epoch + 1%'
     OR function_definition NOT LIKE
       '%identity_epoch = subject.identity_epoch + 1%'
     OR function_definition NOT LIKE
       '%private_append_platform_identity_account_tenant_audit_v1(%'
     OR function_definition NOT LIKE
       '%platform.identity_account.retired%' THEN
    RETURN false;
  END IF;

  SELECT pg_catalog.pg_get_functiondef(
    'app.create_platform_oidc_auth_provider_v2(uuid,uuid,uuid,text,text,text,jsonb,text,bytea,bytea,uuid,uuid,uuid,inet,text,text,text)'::regprocedure
  ) INTO function_definition;
  IF function_definition NOT LIKE
       '%create_platform_auth_provider_v1(%''oidc''%'
     OR function_definition LIKE '%p_kind%' THEN
    RETURN false;
  END IF;
  SELECT pg_catalog.pg_get_functiondef(
    'app.create_platform_saml_auth_provider_v2(uuid,uuid,uuid,text,text,text,jsonb,bytea,bytea,uuid,uuid,uuid,inet,text,text,text)'::regprocedure
  ) INTO function_definition;
  IF function_definition NOT LIKE
       '%create_platform_auth_provider_v1(%''saml''%'
     OR function_definition LIKE '%p_kind%' THEN
    RETURN false;
  END IF;

  SELECT pg_catalog.pg_get_functiondef(
    'app.complete_tenant_ldap_directory_operation_v1(uuid,public.ldap_provider_test_outcome,public.ldap_provider_test_category,integer,integer,integer,boolean,uuid,uuid,uuid,inet,text,text)'::regprocedure
  ) INTO function_definition;
  IF function_definition NOT LIKE
       '%jsonb_strip_nulls(jsonb_build_object(%'
     OR function_definition NOT LIKE
       '%''authorization_revision'', locked_run.authorization_revision%'
  THEN
    RETURN false;
  END IF;
  SELECT pg_catalog.pg_get_functiondef(
    'app.complete_mfa_passkey_authentication_v1(jsonb)'::regprocedure
  ) INTO function_definition;
  IF function_definition NOT LIKE
       '%SELECT provenance.credential_id INTO v_primary_credential_id%'
     OR function_definition NOT LIKE
       '%IF FOUND AND v_primary_credential_id = v_credential_id THEN%'
     OR function_definition LIKE
       '%INTO STRICT v_primary_credential_id%' THEN
    RETURN false;
  END IF;

  RETURN true;
END;
$function$;
ALTER FUNCTION app.private_platform_identity_runtime_schema_readiness_v2()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION
  app.private_platform_identity_runtime_schema_readiness_v2()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,
  periapsis_sla_api_owner, periapsis_sla_worker_owner,
  periapsis_sla_readiness_owner, periapsis_ticket_saved_view_owner,
  periapsis_ticket_attribution_owner,
  periapsis_ticket_sla_projection_owner;
--> statement-breakpoint

CREATE FUNCTION app.platform_identity_runtime_schema_readiness_v2()
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
  FROM app.schema_compatibility_v36() AS compatibility;
  RETURN current_count = 170
    AND NOT pg_catalog.has_function_privilege(
      'periapsis_api','app.schema_compatibility_v35()'::regprocedure,'EXECUTE'
    )
    AND NOT pg_catalog.has_function_privilege(
      'periapsis_worker','app.schema_compatibility_v35()'::regprocedure,'EXECUTE'
    )
    AND NOT pg_catalog.has_function_privilege(
      'periapsis_api',
      'app.tenant_platform_oidc_runtime_schema_readiness_v1()'::regprocedure,
      'EXECUTE'
    )
    AND NOT pg_catalog.has_function_privilege(
      'periapsis_worker',
      'app.tenant_platform_oidc_runtime_schema_readiness_v1()'::regprocedure,
      'EXECUTE'
    )
    AND app.private_platform_identity_runtime_schema_readiness_v2();
END;
$function$;
ALTER FUNCTION app.platform_identity_runtime_schema_readiness_v2()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.platform_identity_runtime_schema_readiness_v2()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,
  periapsis_sla_api_owner, periapsis_sla_worker_owner,
  periapsis_sla_readiness_owner, periapsis_ticket_saved_view_owner,
  periapsis_ticket_attribution_owner,
  periapsis_ticket_sla_projection_owner;
GRANT EXECUTE ON FUNCTION app.platform_identity_runtime_schema_readiness_v2()
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
  IF p_expected_count IS DISTINCT FROM 170
     OR p_expected_latest_created_at IS DISTINCT FROM 1788062677386
     OR p_expected_latest_hash !~ '^[0-9a-f]{64}$'
     OR p_expected_migration_fingerprint !~
       '^[0-9]+@[0-9a-f]{64}(:[0-9]+@[0-9a-f]{64}){169}$' THEN
    RAISE EXCEPTION 'schema compatibility v36 seal input is invalid'
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
     OR NOT app.private_platform_identity_runtime_schema_readiness_v2()
     OR pg_catalog.has_function_privilege(
       'periapsis_api','app.schema_compatibility_v35()'::regprocedure,'EXECUTE'
     )
     OR pg_catalog.has_function_privilege(
       'periapsis_worker','app.schema_compatibility_v35()'::regprocedure,'EXECUTE'
     ) THEN
    RAISE EXCEPTION 'schema compatibility v36 cannot be sealed'
      USING ERRCODE = '55000';
  END IF;

  EXECUTE pg_catalog.format(
    'ALTER FUNCTION app.schema_compatibility_v36() SET app.schema_compatibility_fingerprint = %L',
    p_expected_migration_fingerprint
  );
  SELECT compatibility.applied_count,compatibility.latest_created_at,
         compatibility.latest_hash,compatibility.migration_fingerprint
    INTO sealed_count,sealed_latest_created_at,sealed_latest_hash,
         sealed_fingerprint
  FROM app.schema_compatibility_v36() AS compatibility;
  IF ROW(sealed_count,sealed_latest_created_at,sealed_latest_hash,
         sealed_fingerprint) IS DISTINCT FROM
     ROW(p_expected_count,p_expected_latest_created_at,p_expected_latest_hash,
         p_expected_migration_fingerprint)
     OR NOT app.platform_identity_runtime_schema_readiness_v2() THEN
    RAISE EXCEPTION 'schema compatibility v36 seal verification failed'
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
