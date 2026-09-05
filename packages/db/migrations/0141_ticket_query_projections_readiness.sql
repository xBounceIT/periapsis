-- Seal the ticket-query projection boundary and publish its structural
-- readiness contract. V30 is current; V29 is the sole rolling predecessor.

CREATE FUNCTION app.schema_compatibility_v30()
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
AS $function$
DECLARE
  journal_count bigint;
  journal_latest_created_at bigint;
  latest_rows bigint;
BEGIN
  EXECUTE $query$
    SELECT count(*)::bigint, max(migration.created_at)::bigint,
           count(*) FILTER (
             WHERE migration.created_at = 1787747400262
           )::bigint
    FROM drizzle.__drizzle_migrations AS migration
  $query$ INTO journal_count, journal_latest_created_at, latest_rows;
  IF journal_count = 142
     AND journal_latest_created_at = 1787747400262
     AND latest_rows = 1 THEN
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
ALTER FUNCTION app.schema_compatibility_v30()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.schema_compatibility_v30()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,
  periapsis_sla_api_owner, periapsis_sla_worker_owner,
  periapsis_sla_readiness_owner, periapsis_ticket_saved_view_owner,
  periapsis_ticket_attribution_owner,
  periapsis_ticket_sla_projection_owner;
GRANT EXECUTE ON FUNCTION app.schema_compatibility_v30()
TO periapsis_api, periapsis_worker;
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.schema_compatibility_v29()
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
  full_count bigint;
  full_latest_created_at bigint;
  full_fingerprint text;
BEGIN
  SELECT compatibility.applied_count, compatibility.latest_created_at,
         compatibility.migration_fingerprint
  INTO full_count, full_latest_created_at, full_fingerprint
  FROM app.schema_compatibility_v30() AS compatibility;
  IF full_count = 142
     AND full_latest_created_at = 1787747400262
     AND full_fingerprint = current_setting(
       'app.schema_compatibility_fingerprint', true
     ) THEN
    RETURN QUERY EXECUTE $query$
      WITH ordered_migrations AS (
        SELECT migration.id, migration.created_at,
               lower(migration.hash::text) AS migration_hash,
               row_number() OVER (
                 ORDER BY migration.created_at, migration.id
               ) AS migration_ordinal
        FROM drizzle.__drizzle_migrations AS migration
      )
      SELECT count(*)::bigint, max(migration.created_at)::bigint,
             (SELECT prefix.migration_hash
              FROM ordered_migrations AS prefix
              WHERE prefix.migration_ordinal = 139),
             string_agg(
               migration.created_at::text || '@' || migration.migration_hash,
               ':' ORDER BY migration.created_at, migration.id
             )
      FROM ordered_migrations AS migration
      WHERE migration.migration_ordinal <= 139
    $query$;
    RETURN;
  END IF;
  RETURN QUERY SELECT 0::bigint, 0::bigint,
                      'UNSUPPORTED'::text, 'UNSUPPORTED'::text;
END;
$function$;
ALTER FUNCTION app.schema_compatibility_v29()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.schema_compatibility_v29()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,
  periapsis_sla_api_owner, periapsis_sla_worker_owner,
  periapsis_sla_readiness_owner, periapsis_ticket_saved_view_owner,
  periapsis_ticket_attribution_owner,
  periapsis_ticket_sla_projection_owner;
GRANT EXECUTE ON FUNCTION app.schema_compatibility_v29()
TO periapsis_api, periapsis_worker;
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.schema_compatibility_v28()
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
AS $function$
BEGIN
  RETURN QUERY SELECT 0::bigint, 0::bigint,
                      'UNSUPPORTED'::text, 'UNSUPPORTED'::text;
END;
$function$;
ALTER FUNCTION app.schema_compatibility_v28()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.schema_compatibility_v28()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,
  periapsis_sla_api_owner, periapsis_sla_worker_owner,
  periapsis_sla_readiness_owner, periapsis_ticket_saved_view_owner,
  periapsis_ticket_attribution_owner,
  periapsis_ticket_sla_projection_owner;
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
SET search_path = pg_catalog
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
BEGIN
  fingerprint_entries := string_to_array(
    p_expected_migration_fingerprint, ':'
  );
  IF p_expected_count IS DISTINCT FROM 142
     OR p_expected_latest_created_at IS DISTINCT FROM 1787747400262
     OR p_expected_latest_hash IS NULL
     OR p_expected_latest_hash !~ '^[0-9a-f]{64}$'
     OR p_expected_migration_fingerprint IS NULL
     OR p_expected_migration_fingerprint !~
          '^[1-9][0-9]*@[0-9a-f]{64}(:[1-9][0-9]*@[0-9a-f]{64})*$'
     OR cardinality(fingerprint_entries) IS DISTINCT FROM 142
     OR fingerprint_entries[142] IS DISTINCT FROM (
       p_expected_latest_created_at::text || '@' || p_expected_latest_hash
     ) THEN
    RAISE EXCEPTION 'invalid schema compatibility v30 manifest'
      USING ERRCODE = '22023';
  END IF;
  SELECT array_agg(
    split_part(entry.value, '@', 1)::bigint ORDER BY entry.ordinality
  ) INTO appended_created_at
  FROM unnest(fingerprint_entries[140:142]) WITH ORDINALITY
       AS entry(value, ordinality);
  IF appended_created_at IS DISTINCT FROM ARRAY[
       1787747398262, 1787747399262, 1787747400262
     ]::bigint[] THEN
    RAISE EXCEPTION 'invalid schema compatibility v30 appended sequence'
      USING ERRCODE = '22023';
  END IF;

  SELECT compatibility.applied_count, compatibility.latest_created_at,
         compatibility.latest_hash, compatibility.migration_fingerprint
  INTO actual_count, actual_latest_created_at, actual_latest_hash,
       actual_fingerprint
  FROM app.schema_compatibility_v30() AS compatibility;
  IF actual_count IS DISTINCT FROM p_expected_count
     OR actual_latest_created_at IS DISTINCT FROM p_expected_latest_created_at
     OR actual_latest_hash IS DISTINCT FROM p_expected_latest_hash
     OR actual_fingerprint IS DISTINCT FROM p_expected_migration_fingerprint THEN
    RAISE EXCEPTION 'schema compatibility v30 manifest does not match the journal'
      USING ERRCODE = '55000';
  END IF;

  PERFORM set_config(
    'app.schema_compatibility_fingerprint',
    p_expected_migration_fingerprint, true
  );
  EXECUTE $statement$
    ALTER FUNCTION app.schema_compatibility_v29()
      SET app.schema_compatibility_fingerprint FROM CURRENT
  $statement$;
  expected_predecessor_fingerprint := array_to_string(
    fingerprint_entries[1:139], ':'
  );
  SELECT compatibility.applied_count, compatibility.latest_created_at,
         compatibility.latest_hash, compatibility.migration_fingerprint
  INTO predecessor_count, predecessor_latest_created_at,
       predecessor_latest_hash, predecessor_fingerprint
  FROM app.schema_compatibility_v29() AS compatibility;
  IF predecessor_count IS DISTINCT FROM 139
     OR predecessor_latest_created_at IS DISTINCT FROM 1787741355171
     OR predecessor_latest_hash IS DISTINCT FROM
          '89a75840127b58a16350a341265a945c22513607bb809cb4e7b28e7a91e18ac4'
     OR predecessor_fingerprint IS DISTINCT FROM
          expected_predecessor_fingerprint THEN
    RAISE EXCEPTION 'sealed schema compatibility v29 prefix is not exact'
      USING ERRCODE = '55000';
  END IF;
  SELECT compatibility.applied_count INTO retired_count
  FROM app.schema_compatibility_v28() AS compatibility;
  IF retired_count IS DISTINCT FROM 0
     OR NOT has_function_privilege(
       'periapsis_api', 'app.schema_compatibility_v30()'::regprocedure,
       'EXECUTE'
     )
     OR NOT has_function_privilege(
       'periapsis_worker', 'app.schema_compatibility_v30()'::regprocedure,
       'EXECUTE'
     )
     OR NOT has_function_privilege(
       'periapsis_api', 'app.schema_compatibility_v29()'::regprocedure,
       'EXECUTE'
     )
     OR NOT has_function_privilege(
       'periapsis_worker', 'app.schema_compatibility_v29()'::regprocedure,
       'EXECUTE'
     )
     OR has_function_privilege(
       'periapsis_api', 'app.schema_compatibility_v28()'::regprocedure,
       'EXECUTE'
     )
     OR has_function_privilege(
       'periapsis_worker', 'app.schema_compatibility_v28()'::regprocedure,
       'EXECUTE'
     ) THEN
    RAISE EXCEPTION 'schema compatibility v28 remains active'
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

-- Rebind every established structural readiness surface to V30/V29 and retire
-- its former V28 compatibility fallback without weakening domain checks.
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
    'app.ticket_saved_views_schema_readiness_v1()'::regprocedure
  ] LOOP
    SELECT pg_get_functiondef(readiness_function)
    INTO original_definition;
    IF original_definition NOT LIKE '%app.schema_compatibility_v29()%'
       OR original_definition NOT LIKE '%app.schema_compatibility_v28()%'
       OR original_definition NOT LIKE '%app.schema_compatibility_v27()%'
       OR original_definition NOT LIKE
            '%current_count = 139 AND predecessor_count = 136%' THEN
      RAISE EXCEPTION 'unexpected 0138 readiness definition: %',
        readiness_function::text USING ERRCODE = '55000';
    END IF;
    rewritten_definition := replace(
      original_definition,
      'app.schema_compatibility_v29()',
      'app.schema_compatibility_v30()'
    );
    rewritten_definition := replace(
      rewritten_definition,
      'app.schema_compatibility_v28()',
      'app.schema_compatibility_v29()'
    );
    rewritten_definition := replace(
      rewritten_definition,
      'app.schema_compatibility_v27()',
      'app.schema_compatibility_v28()'
    );
    rewritten_definition := replace(
      rewritten_definition,
      'current_count = 139 AND predecessor_count = 136',
      'current_count = 142 AND predecessor_count = 139'
    );
    IF rewritten_definition IS NOT DISTINCT FROM original_definition
       OR rewritten_definition NOT LIKE '%app.schema_compatibility_v30()%'
       OR rewritten_definition LIKE '%app.schema_compatibility_v27()%'
       OR rewritten_definition NOT LIKE
            '%current_count = 142 AND predecessor_count = 139%' THEN
      RAISE EXCEPTION 'failed to rebind readiness definition: %',
        readiness_function::text USING ERRCODE = '55000';
    END IF;
    EXECUTE rewritten_definition;
  END LOOP;
END;
$migration$;
--> statement-breakpoint

CREATE FUNCTION app.ticket_query_projections_readiness_v1()
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  attribution_owner oid := to_regrole('periapsis_ticket_attribution_owner');
  sla_projection_owner oid := to_regrole(
    'periapsis_ticket_sla_projection_owner'
  );
  expected_role text;
  runtime_role text;
  source_relation regclass;
  view_relation regclass;
  role_record record;
  relation_record record;
  typed_view record;
  expected_index record;
  selected_columns text[];
  view_owner text;
  view_definition text;
  current_count bigint;
  predecessor_count bigint;
  retired_count bigint;
BEGIN
  IF attribution_owner IS NULL OR sla_projection_owner IS NULL THEN
    RETURN false;
  END IF;
  FOREACH expected_role IN ARRAY ARRAY[
    'periapsis_ticket_attribution_owner',
    'periapsis_ticket_sla_projection_owner'
  ] LOOP
    SELECT role_source.rolsuper, role_source.rolinherit,
           role_source.rolcreaterole, role_source.rolcreatedb,
           role_source.rolcanlogin, role_source.rolreplication,
           role_source.rolbypassrls, role_source.rolconfig
    INTO role_record
    FROM pg_roles AS role_source
    WHERE role_source.rolname = expected_role;
    IF NOT FOUND OR role_record.rolsuper OR role_record.rolinherit
       OR role_record.rolcreaterole OR role_record.rolcreatedb
       OR role_record.rolcanlogin OR role_record.rolreplication
       OR role_record.rolbypassrls
       OR NOT (
         'search_path=pg_catalog, app, public' = ANY(role_record.rolconfig)
       )
       OR NOT has_function_privilege(
         expected_role, 'app.context_tenant_id()', 'EXECUTE'
       )
       OR NOT has_function_privilege(
         expected_role, 'app.current_tenant_membership_id()', 'EXECUTE'
       ) THEN
      RETURN false;
    END IF;
    FOREACH runtime_role IN ARRAY ARRAY[
      'periapsis_api', 'periapsis_worker', 'periapsis_notifier',
      'periapsis_auditor', 'periapsis_audit_reader_owner',
      'periapsis_notification_dispatch_owner',
      'periapsis_sla_api_owner', 'periapsis_sla_worker_owner',
      'periapsis_sla_readiness_owner', 'periapsis_ticket_saved_view_owner'
    ] LOOP
      IF pg_has_role(runtime_role, expected_role, 'MEMBER') THEN
        RETURN false;
      END IF;
    END LOOP;
  END LOOP;

  -- Source relations stay FORCE-RLS and expose exactly the columns required by
  -- their dedicated view owner, never table-wide SELECT.
  FOREACH source_relation IN ARRAY ARRAY[
    'public.tenant_service_accounts'::regclass,
    'public.sla_column_versions'::regclass,
    'public.sla_materialized_column_values'::regclass
  ] LOOP
    SELECT relation.relrowsecurity, relation.relforcerowsecurity
    INTO relation_record
    FROM pg_class AS relation
    WHERE relation.oid = source_relation;
    IF NOT FOUND OR NOT relation_record.relrowsecurity
       OR NOT relation_record.relforcerowsecurity THEN
      RETURN false;
    END IF;
  END LOOP;
  IF has_table_privilege(
       'periapsis_ticket_attribution_owner',
       'public.tenant_service_accounts', 'SELECT'
     ) OR has_table_privilege(
       'periapsis_ticket_sla_projection_owner',
       'public.sla_column_versions', 'SELECT'
     ) OR has_table_privilege(
       'periapsis_ticket_sla_projection_owner',
       'public.sla_materialized_column_values', 'SELECT'
     ) THEN
    RETURN false;
  END IF;
  SELECT array_agg(attribute.attname::text ORDER BY attribute.attnum)
  INTO selected_columns
  FROM pg_attribute AS attribute
  WHERE attribute.attrelid = 'public.tenant_service_accounts'::regclass
    AND attribute.attnum > 0 AND NOT attribute.attisdropped
    AND has_column_privilege(
      'periapsis_ticket_attribution_owner', attribute.attrelid,
      attribute.attname, 'SELECT'
    );
  IF selected_columns IS DISTINCT FROM
       ARRAY['id', 'tenant_id', 'display_name']::text[] THEN
    RETURN false;
  END IF;
  SELECT array_agg(attribute.attname::text ORDER BY attribute.attnum)
  INTO selected_columns
  FROM pg_attribute AS attribute
  WHERE attribute.attrelid = 'public.sla_column_versions'::regclass
    AND attribute.attnum > 0 AND NOT attribute.attisdropped
    AND has_column_privilege(
      'periapsis_ticket_sla_projection_owner', attribute.attrelid,
      attribute.attname, 'SELECT'
    );
  IF selected_columns IS DISTINCT FROM ARRAY[
       'tenant_id', 'column_id', 'version', 'format', 'sortable'
     ]::text[] THEN
    RETURN false;
  END IF;
  SELECT array_agg(attribute.attname::text ORDER BY attribute.attnum)
  INTO selected_columns
  FROM pg_attribute AS attribute
  WHERE attribute.attrelid =
          'public.sla_materialized_column_values'::regclass
    AND attribute.attnum > 0 AND NOT attribute.attisdropped
    AND has_column_privilege(
      'periapsis_ticket_sla_projection_owner', attribute.attrelid,
      attribute.attname, 'SELECT'
    );
  IF selected_columns IS DISTINCT FROM ARRAY[
       'tenant_id', 'object_type', 'object_id', 'column_id',
       'column_version', 'state_value', 'instant_value',
       'duration_micros_value', 'percentage_value', 'style_key',
       'materialized_at'
     ]::text[] THEN
    RETURN false;
  END IF;
  IF has_any_column_privilege(
       'periapsis_ticket_attribution_owner',
       'public.sla_column_versions', 'SELECT'
     ) OR has_any_column_privilege(
       'periapsis_ticket_attribution_owner',
       'public.sla_materialized_column_values', 'SELECT'
     ) OR has_any_column_privilege(
       'periapsis_ticket_sla_projection_owner',
       'public.tenant_service_accounts', 'SELECT'
     ) THEN
    RETURN false;
  END IF;

  -- The API and unrelated runtime roles must have no table or residual column
  -- privilege on any private source relation.
  FOREACH runtime_role IN ARRAY ARRAY[
    'periapsis_api', 'periapsis_worker', 'periapsis_notifier',
    'periapsis_auditor', 'periapsis_audit_reader_owner',
    'periapsis_notification_dispatch_owner',
    'periapsis_sla_readiness_owner', 'periapsis_ticket_saved_view_owner'
  ] LOOP
    FOREACH source_relation IN ARRAY ARRAY[
      'public.tenant_service_accounts'::regclass,
      'public.sla_column_versions'::regclass,
      'public.sla_materialized_column_values'::regclass
    ] LOOP
      IF has_table_privilege(runtime_role, source_relation, 'SELECT')
         OR has_any_column_privilege(
           runtime_role, source_relation, 'SELECT'
         ) THEN
        RETURN false;
      END IF;
    END LOOP;
  END LOOP;

  -- Dedicated, single-role SELECT policies provide the only source-row path.
  IF (
       SELECT count(*)
       FROM pg_policy AS policy
       WHERE policy.polname = 'tenant_service_accounts_ticket_attribution'
         AND policy.polrelid =
               'public.tenant_service_accounts'::regclass
         AND policy.polcmd = 'r'
         AND policy.polroles = ARRAY[attribution_owner]::oid[]
         AND replace(
           pg_get_expr(policy.polqual, policy.polrelid), 'app.', ''
         ) =
           '((tenant_id = context_tenant_id()) AND (current_tenant_membership_id() IS NOT NULL))'
         AND policy.polwithcheck IS NULL
     ) <> 1 OR (
       SELECT count(*)
       FROM pg_policy AS policy
       WHERE policy.polname IN (
         'sla_column_versions_ticket_projection',
         'sla_materialized_columns_ticket_projection'
       )
         AND policy.polrelid IN (
           'public.sla_column_versions'::regclass,
           'public.sla_materialized_column_values'::regclass
         )
         AND policy.polcmd = 'r'
         AND policy.polroles = ARRAY[sla_projection_owner]::oid[]
         AND replace(
           pg_get_expr(policy.polqual, policy.polrelid), 'app.', ''
         ) =
           '((tenant_id = context_tenant_id()) AND (current_tenant_membership_id() IS NOT NULL))'
         AND policy.polwithcheck IS NULL
     ) <> 2 OR (
       SELECT count(*)
       FROM pg_policy AS policy
       WHERE attribution_owner = ANY(policy.polroles)
          OR sla_projection_owner = ANY(policy.polroles)
     ) <> 3 THEN
    RETURN false;
  END IF;

  -- Every public ABI relation is a definer-rights security barrier with an
  -- exact narrow column shape and SELECT granted only to the API.
  FOREACH view_relation IN ARRAY ARRAY[
    'app.ticket_service_account_attributions_v1'::regclass,
    'app.ticket_sla_column_revisions_v1'::regclass,
    'app.ticket_sla_materialized_values_v1'::regclass,
    'app.ticket_sla_instant_sort_values_v1'::regclass,
    'app.ticket_sla_duration_sort_values_v1'::regclass,
    'app.ticket_sla_percentage_sort_values_v1'::regclass,
    'app.ticket_sla_state_sort_values_v1'::regclass
  ] LOOP
    SELECT relation.relkind, pg_get_userbyid(relation.relowner) AS owner_name,
           relation.reloptions
    INTO relation_record
    FROM pg_class AS relation
    WHERE relation.oid = view_relation;
    IF NOT FOUND OR relation_record.relkind <> 'v'
       OR relation_record.reloptions IS NULL
       OR cardinality(relation_record.reloptions) <> 2
       OR NOT relation_record.reloptions @> ARRAY[
         'security_barrier=true', 'security_invoker=false'
       ]::text[]
       OR NOT has_table_privilege(
         'periapsis_api', view_relation, 'SELECT'
       ) THEN
      RETURN false;
    END IF;
    FOREACH runtime_role IN ARRAY ARRAY[
      'periapsis_worker', 'periapsis_notifier', 'periapsis_auditor',
      'periapsis_audit_reader_owner',
      'periapsis_notification_dispatch_owner',
      'periapsis_sla_api_owner', 'periapsis_sla_worker_owner',
      'periapsis_sla_readiness_owner',
      'periapsis_ticket_saved_view_owner', 'periapsis_migrator'
    ] LOOP
      IF has_table_privilege(runtime_role, view_relation, 'SELECT') THEN
        RETURN false;
      END IF;
    END LOOP;
    IF EXISTS (
      SELECT 1
      FROM aclexplode(
        coalesce(
          (SELECT relation.relacl FROM pg_class AS relation
           WHERE relation.oid = view_relation),
          acldefault('r',
            (SELECT relation.relowner FROM pg_class AS relation
             WHERE relation.oid = view_relation))
        )
      ) AS privilege
      WHERE privilege.grantee = 0
        AND privilege.privilege_type = 'SELECT'
    ) THEN
      RETURN false;
    END IF;
  END LOOP;
  SELECT pg_get_userbyid(relation.relowner) AS owner_name,
         array_agg(attribute.attname::text ORDER BY attribute.attnum)
           FILTER (WHERE attribute.attnum > 0 AND NOT attribute.attisdropped)
           AS columns
  INTO relation_record
  FROM pg_class AS relation
  JOIN pg_attribute AS attribute ON attribute.attrelid = relation.oid
  WHERE relation.oid = 'app.ticket_service_account_attributions_v1'::regclass
  GROUP BY relation.relowner;
  IF relation_record.owner_name IS DISTINCT FROM
       'periapsis_ticket_attribution_owner'
     OR relation_record.columns IS DISTINCT FROM
       ARRAY['tenant_id', 'id', 'display_name']::text[] THEN
    RETURN false;
  END IF;
  SELECT pg_get_userbyid(relation.relowner) AS owner_name,
         array_agg(attribute.attname::text ORDER BY attribute.attnum)
           FILTER (WHERE attribute.attnum > 0 AND NOT attribute.attisdropped)
           AS columns
  INTO relation_record
  FROM pg_class AS relation
  JOIN pg_attribute AS attribute ON attribute.attrelid = relation.oid
  WHERE relation.oid = 'app.ticket_sla_column_revisions_v1'::regclass
  GROUP BY relation.relowner;
  IF relation_record.owner_name IS DISTINCT FROM
       'periapsis_ticket_sla_projection_owner'
     OR relation_record.columns IS DISTINCT FROM ARRAY[
       'tenant_id', 'column_id', 'version', 'format', 'sortable'
     ]::text[] THEN
    RETURN false;
  END IF;
  SELECT pg_get_userbyid(relation.relowner) AS owner_name,
         array_agg(attribute.attname::text ORDER BY attribute.attnum)
           FILTER (WHERE attribute.attnum > 0 AND NOT attribute.attisdropped)
           AS columns,
         pg_get_viewdef(relation.oid, false) AS definition
  INTO relation_record
  FROM pg_class AS relation
  JOIN pg_attribute AS attribute ON attribute.attrelid = relation.oid
  WHERE relation.oid = 'app.ticket_sla_materialized_values_v1'::regclass
  GROUP BY relation.oid, relation.relowner;
  IF relation_record.owner_name IS DISTINCT FROM
       'periapsis_ticket_sla_projection_owner'
     OR relation_record.columns IS DISTINCT FROM ARRAY[
       'tenant_id', 'object_type', 'object_id', 'column_id',
       'column_version', 'format', 'state_value', 'instant_value',
       'duration_micros_value', 'percentage_value', 'style_key',
       'materialized_at'
     ]::text[]
     OR relation_record.definition NOT LIKE
          '%revision.tenant_id = value.tenant_id%'
     OR relation_record.definition NOT LIKE
          '%revision.column_id = value.column_id%'
     OR relation_record.definition NOT LIKE
          '%revision.version = value.column_version%' THEN
    RETURN false;
  END IF;

  FOR typed_view IN
    SELECT * FROM (VALUES
      ('app.ticket_sla_instant_sort_values_v1'::regclass,
       'instant_value'::text, 'datetime'::text),
      ('app.ticket_sla_duration_sort_values_v1'::regclass,
       'duration_micros_value'::text, 'duration'::text),
      ('app.ticket_sla_percentage_sort_values_v1'::regclass,
       'percentage_value'::text, 'percentage'::text),
      ('app.ticket_sla_state_sort_values_v1'::regclass,
       'state_value'::text, 'state_badge'::text)
    ) AS expected(relation_oid, value_column, expected_format)
  LOOP
    SELECT pg_get_userbyid(relation.relowner),
           array_agg(attribute.attname::text ORDER BY attribute.attnum)
             FILTER (
               WHERE attribute.attnum > 0 AND NOT attribute.attisdropped
             ),
           pg_get_viewdef(relation.oid, false)
    INTO view_owner, selected_columns, view_definition
    FROM pg_class AS relation
    JOIN pg_attribute AS attribute ON attribute.attrelid = relation.oid
    WHERE relation.oid = typed_view.relation_oid
    GROUP BY relation.oid, relation.relowner;
    IF view_owner IS DISTINCT FROM
         'periapsis_ticket_sla_projection_owner'
       OR selected_columns IS DISTINCT FROM (
         ARRAY[
           'tenant_id', 'object_type', 'object_id', 'column_id',
           'column_version'
         ]::text[] || ARRAY[typed_view.value_column]::text[]
       )
       OR view_definition NOT LIKE (
         '%value.' || typed_view.value_column || ' IS NOT NULL%'
       )
       OR view_definition NOT LIKE (
         '%revision.format = ''' || typed_view.expected_format ||
         '''::sla_column_format%'
       ) THEN
      RETURN false;
    END IF;
  END LOOP;

  IF NOT EXISTS (
       SELECT 1 FROM pg_index AS index_record
       WHERE index_record.indexrelid =
               'public.alerts_tenant_updated_idx'::regclass
         AND index_record.indrelid = 'public.alerts'::regclass
         AND index_record.indisvalid AND index_record.indisready
         AND pg_get_indexdef(index_record.indexrelid) =
           'CREATE INDEX alerts_tenant_updated_idx ON public.alerts USING btree (tenant_id, updated_at, id)'
     ) OR NOT EXISTS (
       SELECT 1 FROM pg_index AS index_record
       WHERE index_record.indexrelid =
               'public.cases_tenant_updated_idx'::regclass
         AND index_record.indrelid = 'public.cases'::regclass
         AND index_record.indisvalid AND index_record.indisready
         AND pg_get_indexdef(index_record.indexrelid) =
           'CREATE INDEX cases_tenant_updated_idx ON public.cases USING btree (tenant_id, updated_at, id)'
     ) THEN
    RETURN false;
  END IF;
  FOR expected_index IN
    SELECT * FROM (VALUES
      ('sla_materialized_projection_instant_sort_idx'::text,
       'CREATE INDEX sla_materialized_projection_instant_sort_idx ON public.sla_materialized_column_values USING btree (tenant_id, column_id, instant_value, object_id) WHERE (instant_value IS NOT NULL)'::text),
      ('sla_materialized_projection_duration_sort_idx'::text,
       'CREATE INDEX sla_materialized_projection_duration_sort_idx ON public.sla_materialized_column_values USING btree (tenant_id, column_id, duration_micros_value, object_id) WHERE (duration_micros_value IS NOT NULL)'::text),
      ('sla_materialized_projection_percent_sort_idx'::text,
       'CREATE INDEX sla_materialized_projection_percent_sort_idx ON public.sla_materialized_column_values USING btree (tenant_id, column_id, percentage_value, object_id) WHERE (percentage_value IS NOT NULL)'::text),
      ('sla_materialized_projection_state_sort_idx'::text,
       'CREATE INDEX sla_materialized_projection_state_sort_idx ON public.sla_materialized_column_values USING btree (tenant_id, column_id, state_value, object_id) WHERE (state_value IS NOT NULL)'::text)
    ) AS expected(index_name, definition)
  LOOP
    IF to_regclass('public.' || expected_index.index_name) IS NULL
       OR NOT EXISTS (
         SELECT 1 FROM pg_index AS index_record
         WHERE index_record.indexrelid =
                 to_regclass('public.' || expected_index.index_name)
           AND index_record.indrelid =
                 'public.sla_materialized_column_values'::regclass
           AND index_record.indisvalid AND index_record.indisready
           AND pg_get_indexdef(index_record.indexrelid) =
                 expected_index.definition
       ) THEN
      RETURN false;
    END IF;
  END LOOP;

  SELECT compatibility.applied_count INTO current_count
  FROM app.schema_compatibility_v30() AS compatibility;
  SELECT compatibility.applied_count INTO predecessor_count
  FROM app.schema_compatibility_v29() AS compatibility;
  SELECT compatibility.applied_count INTO retired_count
  FROM app.schema_compatibility_v28() AS compatibility;
  RETURN current_count = 142 AND predecessor_count = 139
    AND retired_count = 0;
END;
$function$;
ALTER FUNCTION app.ticket_query_projections_readiness_v1()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.ticket_query_projections_readiness_v1()
FROM PUBLIC, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,
  periapsis_sla_api_owner, periapsis_sla_worker_owner,
  periapsis_sla_readiness_owner, periapsis_ticket_saved_view_owner,
  periapsis_ticket_attribution_owner,
  periapsis_ticket_sla_projection_owner;
GRANT EXECUTE ON FUNCTION app.ticket_query_projections_readiness_v1()
TO periapsis_api;
