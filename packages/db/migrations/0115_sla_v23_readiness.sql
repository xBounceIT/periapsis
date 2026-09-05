-- Phase 5 closes the SLA v2 database boundary and rotates the exact journal
-- contract. V22 is the sole rolling predecessor; older projections fail
-- closed once the full 116-entry journal is installed.

CREATE FUNCTION app.schema_compatibility_v23()
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
  migration_0115_rows bigint;
BEGIN
  EXECUTE $query$
    SELECT count(*)::bigint, max(migration.created_at)::bigint,
           count(*) FILTER (
             WHERE migration.created_at = 1787707726069
           )::bigint
    FROM drizzle.__drizzle_migrations AS migration
  $query$ INTO journal_count, journal_latest_created_at, migration_0115_rows;
  IF journal_count = 116
     AND journal_latest_created_at = 1787707726069
     AND migration_0115_rows = 1 THEN
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
--> statement-breakpoint
ALTER FUNCTION app.schema_compatibility_v23()
  OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.schema_compatibility_v23()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,
  periapsis_sla_api_owner, periapsis_sla_worker_owner,
  periapsis_sla_readiness_owner;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.schema_compatibility_v23()
TO periapsis_api, periapsis_worker, periapsis_sla_readiness_owner;
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.schema_compatibility_v22()
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
  FROM app.schema_compatibility_v23() AS compatibility;
  IF full_count = 116
     AND full_latest_created_at = 1787707726069
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
              WHERE prefix.migration_ordinal = 113),
             string_agg(
               migration.created_at::text || '@' || migration.migration_hash,
               ':' ORDER BY migration.created_at, migration.id
             )
      FROM ordered_migrations AS migration
      WHERE migration.migration_ordinal <= 113
    $query$;
    RETURN;
  END IF;
  RETURN QUERY SELECT 0::bigint, 0::bigint,
                      'UNSUPPORTED'::text, 'UNSUPPORTED'::text;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.schema_compatibility_v22()
  OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.schema_compatibility_v22()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,
  periapsis_sla_api_owner, periapsis_sla_worker_owner,
  periapsis_sla_readiness_owner;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.schema_compatibility_v22()
TO periapsis_api, periapsis_worker, periapsis_sla_readiness_owner;
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.schema_compatibility_v21()
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
--> statement-breakpoint
ALTER FUNCTION app.schema_compatibility_v21()
  OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.schema_compatibility_v21()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,
  periapsis_sla_api_owner, periapsis_sla_worker_owner,
  periapsis_sla_readiness_owner;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.schema_compatibility_v21()
TO periapsis_api, periapsis_worker, periapsis_sla_readiness_owner;
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
  retired_legacy_count bigint;
BEGIN
  fingerprint_entries := string_to_array(
    p_expected_migration_fingerprint, ':'
  );
  IF p_expected_count IS DISTINCT FROM 116
     OR p_expected_latest_created_at IS DISTINCT FROM 1787707726069
     OR p_expected_latest_hash IS NULL
     OR p_expected_latest_hash !~ '^[0-9a-f]{64}$'
     OR p_expected_migration_fingerprint IS NULL
     OR p_expected_migration_fingerprint !~
          '^[1-9][0-9]*@[0-9a-f]{64}(:[1-9][0-9]*@[0-9a-f]{64})*$'
     OR cardinality(fingerprint_entries) IS DISTINCT FROM 116
     OR fingerprint_entries[116] IS DISTINCT FROM (
       p_expected_latest_created_at::text || '@' || p_expected_latest_hash
     ) THEN
    RAISE EXCEPTION 'invalid schema compatibility v23 manifest'
      USING ERRCODE = '22023';
  END IF;
  SELECT array_agg(
    split_part(entry.value, '@', 1)::bigint ORDER BY entry.ordinality
  ) INTO appended_created_at
  FROM unnest(fingerprint_entries[114:116]) WITH ORDINALITY
       AS entry(value, ordinality);
  IF appended_created_at IS DISTINCT FROM ARRAY[
    1787707721918, 1787707724010, 1787707726069
  ]::bigint[] THEN
    RAISE EXCEPTION 'invalid schema compatibility v23 appended sequence'
      USING ERRCODE = '22023';
  END IF;

  SELECT compatibility.applied_count, compatibility.latest_created_at,
         compatibility.latest_hash, compatibility.migration_fingerprint
  INTO actual_count, actual_latest_created_at, actual_latest_hash,
       actual_fingerprint
  FROM app.schema_compatibility_v23() AS compatibility;
  IF actual_count IS DISTINCT FROM p_expected_count
     OR actual_latest_created_at IS DISTINCT FROM p_expected_latest_created_at
     OR actual_latest_hash IS DISTINCT FROM p_expected_latest_hash
     OR actual_fingerprint IS DISTINCT FROM p_expected_migration_fingerprint THEN
    RAISE EXCEPTION 'schema compatibility v23 manifest does not match the applied journal'
      USING ERRCODE = '55000';
  END IF;

  PERFORM set_config(
    'app.schema_compatibility_fingerprint',
    p_expected_migration_fingerprint, true
  );
  EXECUTE $statement$
    ALTER FUNCTION app.schema_compatibility_v22()
      SET app.schema_compatibility_fingerprint FROM CURRENT
  $statement$;
  expected_predecessor_fingerprint := array_to_string(
    fingerprint_entries[1:113], ':'
  );
  SELECT compatibility.applied_count, compatibility.latest_created_at,
         compatibility.latest_hash, compatibility.migration_fingerprint
  INTO predecessor_count, predecessor_latest_created_at,
       predecessor_latest_hash, predecessor_fingerprint
  FROM app.schema_compatibility_v22() AS compatibility;
  IF predecessor_count IS DISTINCT FROM 113
     OR predecessor_latest_created_at IS DISTINCT FROM 1787705491869
     OR predecessor_latest_hash IS DISTINCT FROM
          'abe24f55b98a9a74e9eab4e7c360d029d697d12f807ae5c3bb67906dc3509099'
     OR predecessor_fingerprint IS DISTINCT FROM
          expected_predecessor_fingerprint THEN
    RAISE EXCEPTION 'sealed schema compatibility v22 prefix is not exact'
      USING ERRCODE = '55000';
  END IF;

  SELECT compatibility.applied_count INTO retired_count
  FROM app.schema_compatibility_v21() AS compatibility;
  SELECT compatibility.applied_count INTO retired_legacy_count
  FROM app.schema_compatibility_v20() AS compatibility;
  IF retired_count IS DISTINCT FROM 0
     OR retired_legacy_count IS DISTINCT FROM 0 THEN
    RAISE EXCEPTION 'schema compatibility older than v22 must be retired'
      USING ERRCODE = '55000';
  END IF;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.seal_schema_compatibility_manifest(
  bigint, bigint, text, text
) OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.seal_schema_compatibility_manifest(
  bigint, bigint, text, text
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,
  periapsis_sla_api_owner, periapsis_sla_worker_owner,
  periapsis_sla_readiness_owner;
--> statement-breakpoint

-- Readiness functions follow after the compatibility rotation so every
-- exposed module boundary reports the same exact current/predecessor edge.
CREATE OR REPLACE FUNCTION app.sla_schema_readiness_v1()
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  current_count bigint;
  predecessor_count bigint;
  retired_count bigint;
  retired_legacy_count bigint;
  seed_definition text;
  expected_index record;
BEGIN
  IF EXISTS (
    SELECT 1
    FROM (VALUES
      ('periapsis_sla_api_owner'),
      ('periapsis_sla_worker_owner'),
      ('periapsis_sla_readiness_owner')
    ) AS expected(role_name)
    LEFT JOIN pg_roles AS role ON role.rolname = expected.role_name
    WHERE role.oid IS NULL OR role.rolcanlogin OR role.rolsuper
       OR role.rolcreatedb OR role.rolcreaterole OR role.rolinherit
       OR role.rolreplication OR role.rolbypassrls
  ) THEN
    RETURN false;
  END IF;
  IF EXISTS (
    SELECT 1
    FROM (VALUES
      ('sla_business_calendars'), ('sla_business_calendar_versions'),
      ('sla_policies'), ('sla_policy_versions'),
      ('sla_metric_definitions'), ('sla_trigger_definitions'),
      ('sla_columns'), ('sla_column_versions'),
      ('sla_configuration_commands'), ('sla_instances'),
      ('sla_metric_instances'), ('sla_trigger_cursors'),
      ('sla_trigger_occurrences'), ('sla_materialized_column_values'),
      ('sla_object_event_ledger'), ('sla_evaluation_jobs'),
      ('sla_overrides')
    ) AS expected(table_name)
    LEFT JOIN pg_class AS table_row
      ON table_row.relname = expected.table_name
    LEFT JOIN pg_namespace AS namespace
      ON namespace.oid = table_row.relnamespace
     AND namespace.nspname = 'public'
    LEFT JOIN pg_attribute AS tenant_column
      ON tenant_column.attrelid = table_row.oid
     AND tenant_column.attname = 'tenant_id'
     AND NOT tenant_column.attisdropped
    WHERE table_row.oid IS NULL OR namespace.oid IS NULL
       OR table_row.relkind <> 'r'
       OR NOT table_row.relrowsecurity OR NOT table_row.relforcerowsecurity
       OR pg_get_userbyid(table_row.relowner) <> 'periapsis_migrator'
       OR tenant_column.attnum IS NULL OR NOT tenant_column.attnotnull
  ) THEN
    RETURN false;
  END IF;
  IF EXISTS (
    SELECT 1
    FROM (VALUES
      ('sla_business_calendars'), ('sla_business_calendar_versions'),
      ('sla_policies'), ('sla_policy_versions'),
      ('sla_metric_definitions'), ('sla_trigger_definitions'),
      ('sla_columns'), ('sla_column_versions'),
      ('sla_configuration_commands'), ('sla_instances'),
      ('sla_metric_instances'), ('sla_trigger_cursors'),
      ('sla_trigger_occurrences'), ('sla_materialized_column_values'),
      ('sla_object_event_ledger'), ('sla_evaluation_jobs'),
      ('sla_overrides')
    ) AS expected(table_name)
    CROSS JOIN (VALUES
      ('SELECT'), ('INSERT'), ('UPDATE'), ('DELETE'), ('TRUNCATE'),
      ('REFERENCES'), ('TRIGGER')
    ) AS privilege(privilege_name)
    CROSS JOIN (VALUES ('periapsis_api'), ('periapsis_worker'))
      AS runtime(role_name)
    WHERE has_table_privilege(
      runtime.role_name, 'public.' || expected.table_name,
      privilege.privilege_name
    )
  ) THEN
    RETURN false;
  END IF;
  IF EXISTS (
    SELECT 1
    FROM (VALUES
      ('app.private_lock_sla_authority_epochs_v1(uuid,uuid)', 'periapsis_migrator', 'v'::"char"),
      ('app.private_sla_metric_document_v2(uuid,uuid)', 'periapsis_sla_api_owner', 's'::"char"),
      ('app.private_sla_configuration_document_v2(uuid,text,uuid,integer)', 'periapsis_sla_api_owner', 's'::"char"),
      ('app.read_sla_configuration_revision_v2(uuid,text,uuid,integer,text)', 'periapsis_sla_api_owner', 's'::"char"),
      ('app.read_sla_metric_definition_v2(uuid,uuid,text)', 'periapsis_sla_api_owner', 's'::"char"),
      ('app.private_sla_runtime_metric_document_v2(uuid,uuid)', 'periapsis_sla_api_owner', 's'::"char"),
      ('app.begin_sla_object_event_v2(uuid,uuid,public.sla_object_type,uuid,text,uuid,timestamp with time zone,bytea,bytea,uuid)', 'periapsis_sla_api_owner', 'v'::"char"),
      ('app.begin_sla_override_v2(uuid,uuid,public.sla_object_type,uuid,uuid,uuid,public.sla_override_kind,integer,integer,uuid,integer,uuid,integer,bytea,bytea,bytea,uuid,text)', 'periapsis_sla_api_owner', 'v'::"char"),
      ('app.private_sla_worker_metric_document_v2(uuid,uuid)', 'periapsis_sla_worker_owner', 's'::"char"),
      ('app.private_sla_worker_job_document_v2(uuid,uuid,integer)', 'periapsis_sla_worker_owner', 's'::"char"),
      ('app.publish_sla_calendar_v2(uuid,uuid,integer,jsonb,bytea,bytea,uuid,uuid,inet,text,text)', 'periapsis_sla_api_owner', 'v'::"char"),
      ('app.publish_sla_policy_v2(uuid,uuid,integer,jsonb,bytea,bytea,uuid,uuid,inet,text,text)', 'periapsis_sla_api_owner', 'v'::"char"),
      ('app.publish_sla_column_v2(uuid,uuid,integer,jsonb,bytea,bytea,uuid,uuid,inet,text,text)', 'periapsis_sla_api_owner', 'v'::"char"),
      ('app.archive_sla_configuration_v1(uuid,text,uuid,integer,text,bytea,bytea,uuid,uuid,inet,text,text)', 'periapsis_sla_api_owner', 'v'::"char"),
      ('app.read_sla_configuration_v2(uuid,text,uuid,text,uuid,integer,boolean)', 'periapsis_sla_api_owner', 's'::"char"),
      ('app.read_sla_runtime_state_v2(uuid,public.sla_object_type,uuid,text,timestamp with time zone)', 'periapsis_sla_api_owner', 's'::"char"),
      ('app.commit_sla_object_event_v1(uuid,uuid,public.sla_object_type,uuid,text,uuid,public.sla_event_outcome,uuid,integer,integer,uuid,integer,timestamp with time zone,jsonb,bytea,bytea,uuid,uuid,inet,text,text)', 'periapsis_sla_api_owner', 'v'::"char"),
      ('app.commit_sla_override_v1(uuid,uuid,public.sla_object_type,uuid,uuid,uuid,public.sla_override_kind,text,public.sla_override_outcome,integer,integer,integer,integer,uuid,integer,bigint,bigint,timestamp with time zone,bytea,bytea,jsonb,bytea,bytea,uuid,uuid,inet,text,text)', 'periapsis_sla_api_owner', 'v'::"char"),
      ('app.claim_sla_evaluation_jobs_v2(uuid,timestamp with time zone,integer,bigint)', 'periapsis_sla_worker_owner', 'v'::"char"),
      ('app.finalize_sla_evaluation_job_v1(uuid,uuid,uuid,uuid,integer,bigint,timestamp with time zone,jsonb)', 'periapsis_sla_worker_owner', 'v'::"char"),
      ('app.fail_sla_evaluation_job_v1(uuid,uuid,uuid,bigint,integer,text,boolean,timestamp with time zone,timestamp with time zone)', 'periapsis_sla_worker_owner', 'v'::"char")
    ) AS expected(signature, owner_name, volatility)
    LEFT JOIN pg_proc AS procedure
      ON procedure.oid = to_regprocedure(expected.signature)
    WHERE procedure.oid IS NULL OR NOT procedure.prosecdef
       OR procedure.provolatile <> expected.volatility
       OR pg_get_userbyid(procedure.proowner) <> expected.owner_name
  ) THEN
    RETURN false;
  END IF;
  IF EXISTS (
    SELECT 1
    FROM (VALUES
      ('periapsis_api', 'app.publish_sla_calendar_v2(uuid,uuid,integer,jsonb,bytea,bytea,uuid,uuid,inet,text,text)'),
      ('periapsis_api', 'app.publish_sla_policy_v2(uuid,uuid,integer,jsonb,bytea,bytea,uuid,uuid,inet,text,text)'),
      ('periapsis_api', 'app.publish_sla_column_v2(uuid,uuid,integer,jsonb,bytea,bytea,uuid,uuid,inet,text,text)'),
      ('periapsis_api', 'app.archive_sla_configuration_v1(uuid,text,uuid,integer,text,bytea,bytea,uuid,uuid,inet,text,text)'),
      ('periapsis_api', 'app.read_sla_configuration_v2(uuid,text,uuid,text,uuid,integer,boolean)'),
      ('periapsis_api', 'app.read_sla_runtime_state_v2(uuid,public.sla_object_type,uuid,text,timestamp with time zone)'),
      ('periapsis_api', 'app.read_sla_configuration_revision_v2(uuid,text,uuid,integer,text)'),
      ('periapsis_api', 'app.read_sla_metric_definition_v2(uuid,uuid,text)'),
      ('periapsis_api', 'app.begin_sla_object_event_v2(uuid,uuid,public.sla_object_type,uuid,text,uuid,timestamp with time zone,bytea,bytea,uuid)'),
      ('periapsis_api', 'app.begin_sla_override_v2(uuid,uuid,public.sla_object_type,uuid,uuid,uuid,public.sla_override_kind,integer,integer,uuid,integer,uuid,integer,bytea,bytea,bytea,uuid,text)'),
      ('periapsis_api', 'app.commit_sla_object_event_v1(uuid,uuid,public.sla_object_type,uuid,text,uuid,public.sla_event_outcome,uuid,integer,integer,uuid,integer,timestamp with time zone,jsonb,bytea,bytea,uuid,uuid,inet,text,text)'),
      ('periapsis_api', 'app.commit_sla_override_v1(uuid,uuid,public.sla_object_type,uuid,uuid,uuid,public.sla_override_kind,text,public.sla_override_outcome,integer,integer,integer,integer,uuid,integer,bigint,bigint,timestamp with time zone,bytea,bytea,jsonb,bytea,bytea,uuid,uuid,inet,text,text)'),
      ('periapsis_worker', 'app.claim_sla_evaluation_jobs_v2(uuid,timestamp with time zone,integer,bigint)'),
      ('periapsis_worker', 'app.finalize_sla_evaluation_job_v1(uuid,uuid,uuid,uuid,integer,bigint,timestamp with time zone,jsonb)'),
      ('periapsis_worker', 'app.fail_sla_evaluation_job_v1(uuid,uuid,uuid,bigint,integer,text,boolean,timestamp with time zone,timestamp with time zone)')
    ) AS expected(role_name, signature)
    WHERE NOT has_function_privilege(
      expected.role_name, expected.signature, 'EXECUTE'
    )
  ) THEN
    RETURN false;
  END IF;
  IF enum_range(NULL::public.sla_warning_kind)::text[] IS DISTINCT FROM
       ARRAY['none', 'consumed_percent', 'remaining_duration']::text[]
     OR enum_range(NULL::public.sla_trigger_kind)::text[] IS DISTINCT FROM
       ARRAY[
         'consumed_percent', 'remaining_duration', 'due', 'after_breach',
         'repeated_after_breach', 'state_changed', 'resumed'
       ]::text[]
     OR enum_range(NULL::public.sla_column_calculation)::text[] IS DISTINCT FROM
       ARRAY[
         'due_at', 'remaining_seconds', 'state', 'consumed_percentage',
         'breached_at'
       ]::text[] THEN
    RETURN false;
  END IF;
  IF EXISTS (
    SELECT 1
    FROM (VALUES
      ('sla_business_calendar_versions_immutable_v1'),
      ('sla_policy_versions_immutable_v1'),
      ('sla_metric_definitions_immutable_v1'),
      ('sla_trigger_definitions_immutable_v1'),
      ('sla_column_versions_immutable_v1'),
      ('sla_configuration_commands_immutable_v1'),
      ('sla_object_event_ledger_immutable_v1'),
      ('sla_trigger_occurrences_immutable_v1'),
      ('sla_overrides_immutable_v1'),
      ('sla_metric_instances_identity_v1'),
      ('sla_trigger_cursors_identity_v1'),
      ('sla_trigger_occurrences_identity_v1'),
      ('sla_materialized_columns_identity_v1'),
      ('sla_object_event_ledger_identity_v1'),
      ('sla_evaluation_jobs_identity_v1'),
      ('sla_overrides_identity_v1')
    ) AS expected(trigger_name)
    LEFT JOIN pg_trigger AS trigger_row
      ON trigger_row.tgname = expected.trigger_name
     AND NOT trigger_row.tgisinternal
    WHERE trigger_row.oid IS NULL OR trigger_row.tgenabled <> 'O'
  ) THEN
    RETURN false;
  END IF;
  FOR expected_index IN
    SELECT * FROM (VALUES
      ('sla_evaluation_jobs_claim_idx'),
      ('sla_evaluation_jobs_reclaim_idx'),
      ('sla_evaluation_jobs_live_aggregate_key'),
      ('sla_instances_object_projection_idx'),
      ('sla_metric_instances_schedule_idx'),
      ('sla_trigger_occurrences_dedup_key')
    ) AS required(index_name)
  LOOP
    IF NOT EXISTS (
      SELECT 1 FROM pg_index AS index_row
      JOIN pg_class AS index_class
        ON index_class.oid = index_row.indexrelid
      WHERE index_class.relname = expected_index.index_name
        AND index_row.indisvalid AND index_row.indisready
        AND index_row.indislive
    ) THEN
      RETURN false;
    END IF;
  END LOOP;
  IF EXISTS (
    SELECT 1
    FROM (VALUES
      ('sla.read', 'tenant'::public.authorization_scope),
      ('sla.manage', 'tenant'::public.authorization_scope),
      ('sla.simulate', 'tenant'::public.authorization_scope),
      ('alert.sla.override', 'own'::public.authorization_scope),
      ('alert.sla.override', 'assigned'::public.authorization_scope),
      ('alert.sla.override', 'operator_team'::public.authorization_scope),
      ('alert.sla.override', 'tenant'::public.authorization_scope),
      ('case.sla.override', 'own'::public.authorization_scope),
      ('case.sla.override', 'assigned'::public.authorization_scope),
      ('case.sla.override', 'operator_team'::public.authorization_scope),
      ('case.sla.override', 'tenant'::public.authorization_scope)
    ) AS expected(permission_key, scope)
    LEFT JOIN public.tenant_permissions AS permission
      ON permission.key = expected.permission_key
     AND NOT permission.service_account_allowed
    LEFT JOIN public.tenant_permission_scopes AS permission_scope
      ON permission_scope.permission_id = permission.id
     AND permission_scope.scope = expected.scope
    WHERE permission_scope.permission_id IS NULL
  ) THEN
    RETURN false;
  END IF;
  SELECT pg_get_functiondef(
    to_regprocedure('app.seed_tenant_authorization(uuid,uuid)')
  ) INTO seed_definition;
  IF seed_definition IS NULL OR seed_definition NOT LIKE
       '%private_seed_tenant_sla_authorization_v1%' THEN
    RETURN false;
  END IF;

  IF EXISTS (
    SELECT 1
    FROM pg_proc AS procedure
    CROSS JOIN LATERAL aclexplode(
      coalesce(procedure.proacl, acldefault('f', procedure.proowner))
    ) AS privilege
    WHERE procedure.oid = ANY(ARRAY[
      'app.private_sla_metric_document_v2(uuid,uuid)'::regprocedure,
      'app.private_sla_configuration_document_v2(uuid,text,uuid,integer)'::regprocedure,
      'app.private_sla_runtime_metric_document_v2(uuid,uuid)'::regprocedure,
      'app.private_sla_worker_metric_document_v2(uuid,uuid)'::regprocedure,
      'app.private_sla_worker_job_document_v2(uuid,uuid,integer)'::regprocedure
    ])
      AND privilege.privilege_type = 'EXECUTE'
      AND (
        privilege.grantee = 0
        OR privilege.grantee = ANY(ARRAY[
          'periapsis_api'::regrole,
          'periapsis_worker'::regrole,
          'periapsis_notifier'::regrole,
          'periapsis_auditor'::regrole
        ])
      )
  ) OR has_function_privilege(
    'periapsis_api',
    'app.publish_sla_calendar_v1(uuid,uuid,integer,jsonb,bytea,bytea,uuid,uuid,inet,text,text)',
    'EXECUTE'
  ) OR has_function_privilege(
    'periapsis_api',
    'app.publish_sla_policy_v1(uuid,uuid,integer,jsonb,bytea,bytea,uuid,uuid,inet,text,text)',
    'EXECUTE'
  ) OR has_function_privilege(
    'periapsis_api',
    'app.publish_sla_column_v1(uuid,uuid,integer,jsonb,bytea,bytea,uuid,uuid,inet,text,text)',
    'EXECUTE'
  ) OR has_function_privilege(
    'periapsis_api',
    'app.read_sla_configuration_v1(uuid,text,uuid,text,uuid,integer,boolean)',
    'EXECUTE'
  ) OR has_function_privilege(
    'periapsis_api',
    'app.read_sla_runtime_state_v1(uuid,public.sla_object_type,uuid,text,timestamp with time zone)',
    'EXECUTE'
  ) OR has_function_privilege(
    'periapsis_worker',
    'app.claim_sla_evaluation_jobs_v1(uuid,timestamp with time zone,integer,bigint)',
    'EXECUTE'
  ) OR NOT has_table_privilege(
    'periapsis_sla_worker_owner',
    'public.sla_business_calendars',
    'SELECT'
  ) OR has_table_privilege(
    'periapsis_worker',
    'public.sla_business_calendars',
    'SELECT'
  ) OR NOT EXISTS (
    SELECT 1
    FROM pg_policy AS policy
    WHERE policy.polrelid = 'public.sla_business_calendars'::regclass
      AND policy.polname = 'sla_business_calendars_sla_worker_owner_read_v2'
      AND policy.polcmd = 'r'
      AND policy.polroles = ARRAY['periapsis_sla_worker_owner'::regrole]::oid[]
      AND pg_get_expr(policy.polqual, policy.polrelid) = 'true'
  ) THEN
    RETURN false;
  END IF;

  SELECT compatibility.applied_count INTO current_count
  FROM app.schema_compatibility_v23() AS compatibility;
  SELECT compatibility.applied_count INTO predecessor_count
  FROM app.schema_compatibility_v22() AS compatibility;
  SELECT compatibility.applied_count INTO retired_count
  FROM app.schema_compatibility_v21() AS compatibility;
  SELECT compatibility.applied_count INTO retired_legacy_count
  FROM app.schema_compatibility_v20() AS compatibility;
  RETURN current_count = 116 AND predecessor_count = 113
    AND retired_count = 0 AND retired_legacy_count = 0;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.sla_schema_readiness_v1()
  OWNER TO periapsis_sla_readiness_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.sla_schema_readiness_v1()
FROM PUBLIC, periapsis_notifier, periapsis_auditor,
  periapsis_sla_api_owner, periapsis_sla_worker_owner;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.sla_schema_readiness_v1()
TO periapsis_api, periapsis_worker;
--> statement-breakpoint
CREATE OR REPLACE FUNCTION app.contacts_portal_schema_readiness_v1()
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  relation_name text;
  expected_function record;
  function_oid regprocedure;
  function_owner text;
  function_security_definer boolean;
  function_configuration text[];
  function_definition text;
  result_constraint text;
  snapshot_default text;
  current_count bigint;
  predecessor_count bigint;
  rolling_count bigint;
BEGIN
  FOREACH relation_name IN ARRAY ARRAY[
    'customer_contacts',
    'customer_contact_notification_windows',
    'customer_contact_groups',
    'customer_contact_group_versions',
    'customer_contact_group_version_members',
    'ticket_customer_contacts',
    'ticket_comment_author_snapshots',
    'ticket_activity_author_snapshots',
    'customer_contact_commands'
  ] LOOP
    IF NOT EXISTS (
      SELECT 1 FROM pg_class AS class
      JOIN pg_namespace AS namespace ON namespace.oid = class.relnamespace
      JOIN pg_attribute AS tenant_column
        ON tenant_column.attrelid = class.oid
       AND tenant_column.attname = 'tenant_id'
       AND tenant_column.attnotnull AND NOT tenant_column.attisdropped
      WHERE namespace.nspname = 'public'
        AND class.relname = relation_name AND class.relkind = 'r'
        AND pg_get_userbyid(class.relowner) = 'periapsis_migrator'
        AND class.relrowsecurity AND class.relforcerowsecurity
    ) OR has_table_privilege(
      'periapsis_notifier', format('public.%I', relation_name),
      'SELECT,INSERT,UPDATE,DELETE'
    ) OR has_table_privilege(
      'periapsis_worker', format('public.%I', relation_name),
      'SELECT,INSERT,UPDATE,DELETE'
    ) THEN
      RETURN false;
    END IF;
  END LOOP;

  IF (
    SELECT count(*)
    FROM public.tenant_permissions AS permission
    WHERE permission.key IN (
      'contact.read', 'contact.manage', 'contact.preference.manage',
      'contact_group.read', 'contact_group.manage',
      'portal.alert.read', 'portal.case.read', 'portal.comment.public',
      'portal.attachment.read', 'portal.contact.preference.manage'
    )
  ) <> 10 OR EXISTS (
    SELECT 1 FROM public.tenant_permissions AS permission
    WHERE permission.key IN ('contact.group.read', 'contact.group.manage')
  ) THEN
    RETURN false;
  END IF;

  IF NOT has_function_privilege(
       'periapsis_notification_dispatch_owner',
       'app.context_tenant_id()', 'EXECUTE'
     ) OR has_function_privilege(
       'periapsis_notifier', 'app.context_tenant_id()', 'EXECUTE'
     ) THEN
    RETURN false;
  END IF;

  FOREACH relation_name IN ARRAY ARRAY[
    'tenant_authorization_states',
    'tenant_security_group_memberships',
    'tenant_security_groups',
    'tenant_security_group_role_grants',
    'operator_team_assignment_epochs',
    'alerts', 'cases', 'ticket_workflow_versions'
  ] LOOP
    IF NOT has_table_privilege(
         'periapsis_notification_dispatch_owner',
         format('public.%I', relation_name), 'SELECT'
       ) OR has_table_privilege(
         'periapsis_notifier', format('public.%I', relation_name), 'SELECT'
       ) THEN
      RETURN false;
    END IF;
  END LOOP;

  IF (
    SELECT count(*)
    FROM pg_policy AS policy
    WHERE policy.polname IN (
      'contacts_fanout_dispatch_auth_state_v1',
      'contacts_fanout_dispatch_security_memberships_v1',
      'contacts_fanout_dispatch_security_groups_v1',
      'contacts_fanout_dispatch_security_grants_v1',
      'contacts_fanout_dispatch_team_epochs_v1',
      'contacts_fanout_dispatch_alerts_v1',
      'contacts_fanout_dispatch_cases_v1',
      'contacts_fanout_dispatch_workflow_versions_v1'
    ) AND policy.polcmd = 'r'
      AND (SELECT role.oid FROM pg_roles AS role
           WHERE role.rolname = 'periapsis_notification_dispatch_owner')
          = ANY(policy.polroles)
      AND replace(
        pg_get_expr(policy.polqual, policy.polrelid), 'app.', ''
      ) = '(tenant_id = context_tenant_id())'
      AND EXISTS (
        SELECT 1
        FROM pg_depend AS dependency
        WHERE dependency.classid = 'pg_catalog.pg_policy'::regclass
          AND dependency.objid = policy.oid
          AND dependency.refclassid = 'pg_catalog.pg_proc'::regclass
          AND dependency.refobjid =
              'app.context_tenant_id()'::regprocedure
      )
  ) <> 8 THEN
    RETURN false;
  END IF;

  SELECT pg_get_constraintdef(constraint_record.oid, true)
  INTO result_constraint
  FROM pg_constraint AS constraint_record
  WHERE constraint_record.conrelid = 'public.customer_contact_commands'::regclass
    AND constraint_record.conname = 'customer_contact_commands_result_check';
  SELECT pg_get_expr(attribute_default.adbin, attribute_default.adrelid)
  INTO snapshot_default
  FROM pg_attribute AS attribute
  JOIN pg_attrdef AS attribute_default
    ON attribute_default.adrelid = attribute.attrelid
   AND attribute_default.adnum = attribute.attnum
  WHERE attribute.attrelid = 'public.customer_contact_commands'::regclass
    AND attribute.attname = 'result_snapshot'
    AND attribute.attnotnull AND NOT attribute.attisdropped;
  IF result_constraint IS NULL
     OR result_constraint NOT LIKE '%pg_column_size(result_snapshot) <= 524288%'
     OR result_constraint NOT LIKE '%jsonb_array_length(jsonb_path_query_array(result_snapshot, ''$.keyvalue()."key"''::jsonpath)) = 4%'
     OR result_constraint NOT LIKE '%jsonb_array_length(jsonb_path_query_array(result_snapshot -> ''resource''::text, ''$.keyvalue()."key"''::jsonpath)) = 13%'
     OR result_constraint NOT LIKE '%jsonb_array_length(jsonb_path_query_array(result_snapshot -> ''resource''::text, ''$.keyvalue()."key"''::jsonpath)) = 20%'
     OR result_constraint NOT LIKE '%jsonb_array_length(jsonb_path_query_array(result_snapshot -> ''resource''::text, ''$.keyvalue()."key"''::jsonpath)) = 11%'
     OR result_constraint NOT LIKE '%jsonb_array_length(jsonb_path_query_array(result_snapshot -> ''resource''::text, ''$.keyvalue()."key"''::jsonpath)) = 10%'
     OR snapshot_default NOT LIKE '%legacy.unavailable%'
     OR snapshot_default NOT LIKE '%unavailable%' THEN
    RETURN false;
  END IF;

  IF (
    SELECT count(*)
    FROM pg_trigger AS trigger_record
    JOIN pg_class AS class ON class.oid = trigger_record.tgrelid
    JOIN pg_namespace AS namespace ON namespace.oid = class.relnamespace
    WHERE namespace.nspname = 'public'
      AND trigger_record.tgname IN (
        'customer_contact_commands_capture_result_v1',
        'customer_contact_commands_immutable_v1',
        'ticket_comments_capture_author_snapshot_v1',
        'ticket_activities_capture_author_snapshot_v1'
      )
      AND NOT trigger_record.tgisinternal
      AND trigger_record.tgenabled = 'O'
  ) <> 4 OR EXISTS (
    SELECT 1 FROM public.ticket_comments AS comment
    WHERE NOT EXISTS (
      SELECT 1 FROM public.ticket_comment_author_snapshots AS snapshot
      WHERE snapshot.tenant_id = comment.tenant_id
        AND snapshot.comment_id = comment.id
    )
  ) OR EXISTS (
    SELECT 1 FROM public.ticket_activities AS activity
    WHERE NOT EXISTS (
      SELECT 1 FROM public.ticket_activity_author_snapshots AS snapshot
      WHERE snapshot.tenant_id = activity.tenant_id
        AND snapshot.activity_id = activity.id
    )
  ) THEN
    RETURN false;
  END IF;

  FOR expected_function IN
    SELECT * FROM (VALUES
      ('app.capture_customer_contact_command_result_v1()', 'periapsis_migrator', false, false, false),
      ('app.guard_customer_contact_command_immutability_v1()', 'periapsis_migrator', false, false, false),
      ('app.capture_ticket_comment_author_snapshot_v1()', 'periapsis_migrator', false, false, false),
      ('app.capture_ticket_activity_author_snapshot_v1()', 'periapsis_migrator', false, false, false),
      ('app.replay_customer_contact_command_v1(text,bytea,bytea,uuid,public.ticket_aggregate_kind,uuid)', 'periapsis_migrator', true, false, false),
      ('app.commit_customer_contact_v1(text,uuid,bigint,jsonb,bytea,bytea,text,uuid,uuid,uuid,inet,text,text)', 'periapsis_migrator', true, false, false),
      ('app.commit_customer_contact_group_v1(text,uuid,bigint,jsonb,bytea,bytea,uuid,uuid,uuid,inet,text,text)', 'periapsis_migrator', true, false, false),
      ('app.commit_ticket_customer_contact_v1(text,uuid,bigint,bigint,jsonb,bytea,bytea,text,uuid,uuid,uuid,inet,text,text)', 'periapsis_migrator', true, false, false),
      ('app.create_customer_portal_ticket_comment_v1(public.ticket_aggregate_kind,uuid,uuid,text,text,bytea,bytea,uuid,uuid,inet,text,text)', 'periapsis_migrator', true, false, false),
      ('app.private_notification_human_has_canonical_tenant_admin_v1(uuid,uuid)', 'periapsis_notification_dispatch_owner', false, false, true),
      ('app.private_notification_ticket_is_customer_projectable_v1(uuid,public.ticket_aggregate_kind,uuid)', 'periapsis_notification_dispatch_owner', false, false, true),
      ('app.private_notification_operator_candidates_v1(uuid,uuid)', 'periapsis_notification_dispatch_owner', false, false, true),
      ('app.load_notification_fanout_inputs_v2(uuid,uuid)', 'periapsis_notification_dispatch_owner', false, true, true),
      ('app.tenant_human_has_exact_permission_v3(uuid,uuid,text,public.authorization_scope)', 'periapsis_migrator', false, false, true)
    ) AS expected(signature, expected_owner, api_execute, notifier_execute, dispatch_execute)
  LOOP
    function_oid := to_regprocedure(expected_function.signature);
    IF function_oid IS NULL THEN
      RETURN false;
    END IF;
    SELECT pg_get_userbyid(procedure.proowner), procedure.prosecdef,
           procedure.proconfig, pg_get_functiondef(procedure.oid)
    INTO function_owner, function_security_definer,
         function_configuration, function_definition
    FROM pg_proc AS procedure WHERE procedure.oid = function_oid;
    IF function_owner IS DISTINCT FROM expected_function.expected_owner
       OR function_security_definer IS NOT TRUE
       OR function_configuration[1] NOT LIKE 'search_path=pg_catalog%'
       OR EXISTS (
         SELECT 1 FROM pg_proc AS procedure
         CROSS JOIN LATERAL aclexplode(
           coalesce(procedure.proacl, acldefault('f', procedure.proowner))
         ) AS privilege
         WHERE procedure.oid = function_oid AND privilege.grantee = 0
           AND privilege.privilege_type = 'EXECUTE'
       ) OR has_function_privilege(
         'periapsis_api', function_oid, 'EXECUTE'
       ) IS DISTINCT FROM expected_function.api_execute
       OR has_function_privilege(
         'periapsis_notifier', function_oid, 'EXECUTE'
       ) IS DISTINCT FROM expected_function.notifier_execute
       OR has_function_privilege(
         'periapsis_notification_dispatch_owner', function_oid, 'EXECUTE'
       ) IS DISTINCT FROM expected_function.dispatch_execute THEN
      RETURN false;
    END IF;
  END LOOP;

  IF EXISTS (
    SELECT 1
    FROM pg_proc AS procedure
    JOIN pg_namespace AS namespace ON namespace.oid = procedure.pronamespace
    WHERE namespace.nspname = 'app'
      AND procedure.proname IN (
        'replay_customer_contact_command_v1',
        'commit_customer_contact_v1',
        'commit_customer_contact_group_v1',
        'commit_ticket_customer_contact_v1',
        'create_customer_portal_ticket_comment_v1'
      )
    GROUP BY procedure.proname
    HAVING count(*) <> 1
  ) OR (
    SELECT count(DISTINCT procedure.proname)
    FROM pg_proc AS procedure
    JOIN pg_namespace AS namespace ON namespace.oid = procedure.pronamespace
    WHERE namespace.nspname = 'app'
      AND procedure.proname IN (
        'replay_customer_contact_command_v1',
        'commit_customer_contact_v1',
        'commit_customer_contact_group_v1',
        'commit_ticket_customer_contact_v1',
        'create_customer_portal_ticket_comment_v1'
      )
  ) <> 5 THEN
    RETURN false;
  END IF;

  FOREACH function_oid IN ARRAY ARRAY[
    'app.replay_customer_contact_command_v1(text,bytea,bytea,uuid,public.ticket_aggregate_kind,uuid)'::regprocedure,
    'app.commit_customer_contact_v1(text,uuid,bigint,jsonb,bytea,bytea,text,uuid,uuid,uuid,inet,text,text)'::regprocedure,
    'app.commit_customer_contact_group_v1(text,uuid,bigint,jsonb,bytea,bytea,uuid,uuid,uuid,inet,text,text)'::regprocedure,
    'app.commit_ticket_customer_contact_v1(text,uuid,bigint,bigint,jsonb,bytea,bytea,text,uuid,uuid,uuid,inet,text,text)'::regprocedure,
    'app.create_customer_portal_ticket_comment_v1(public.ticket_aggregate_kind,uuid,uuid,text,text,bytea,bytea,uuid,uuid,inet,text,text)'::regprocedure,
    'app.private_notification_operator_candidates_v1(uuid,uuid)'::regprocedure,
    'app.load_notification_fanout_inputs_v2(uuid,uuid)'::regprocedure
  ] LOOP
    SELECT lower(pg_get_functiondef(procedure.oid))
    INTO function_definition
    FROM pg_proc AS procedure WHERE procedure.oid = function_oid;
    IF function_definition LIKE '%membership.role%'
       OR function_definition LIKE '%contact.group.read%'
       OR function_definition LIKE '%contact.group.manage%' THEN
      RETURN false;
    END IF;
  END LOOP;

  SELECT lower(pg_get_functiondef(
    'app.load_notification_fanout_inputs_v2(uuid,uuid)'::regprocedure
  )) INTO function_definition;
  IF function_definition NOT LIKE '%private_notification_operator_candidates_v1%'
     OR function_definition NOT LIKE '%private_notification_ticket_is_customer_projectable_v1%'
     OR function_definition NOT LIKE '%linked_membership_id%'
     OR function_definition NOT LIKE '%linked_user_id%'
     OR function_definition NOT LIKE '%maximum_audience%'
     OR has_function_privilege(
       'periapsis_notifier',
       'app.load_notification_fanout_inputs_v1(uuid,uuid)', 'EXECUTE'
     ) THEN
    RETURN false;
  END IF;

  SELECT compatibility.applied_count INTO current_count
  FROM app.schema_compatibility_v23() AS compatibility;
  SELECT compatibility.applied_count INTO predecessor_count
  FROM app.schema_compatibility_v22() AS compatibility;
  SELECT compatibility.applied_count INTO rolling_count
  FROM app.schema_compatibility_v21() AS compatibility;
  RETURN current_count = 116 AND predecessor_count = 113
    AND rolling_count = 0;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.contacts_portal_schema_readiness_v1()
  OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.contacts_portal_schema_readiness_v1()
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor, periapsis_notification_dispatch_owner;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.contacts_portal_schema_readiness_v1()
  TO periapsis_api, periapsis_worker;
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.audit_reader_schema_readiness_v1()
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE current_count bigint; predecessor_count bigint; retired_count bigint;
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_roles AS role
    WHERE role.rolname = 'periapsis_audit_reader_owner'
      AND NOT role.rolcanlogin AND NOT role.rolsuper
      AND NOT role.rolcreatedb AND NOT role.rolcreaterole
      AND NOT role.rolinherit AND NOT role.rolreplication
      AND NOT role.rolbypassrls
  ) OR NOT has_function_privilege(
    'periapsis_api',
    'app.list_tenant_audit_events_v1(uuid,text,bigint,integer,timestamp with time zone,timestamp with time zone,public.audit_actor_type,uuid,uuid,text,text,uuid,uuid,uuid,public.audit_outcome,text,uuid,uuid,uuid,inet,text)',
    'EXECUTE'
  ) OR NOT EXISTS (
    SELECT 1 FROM public.tenant_permissions AS permission
    JOIN public.tenant_permission_scopes AS scope
      ON scope.permission_id = permission.id
    WHERE permission.key = 'audit.read'
      AND NOT permission.service_account_allowed AND scope.scope = 'tenant'
  ) THEN
    RETURN false;
  END IF;
  SELECT applied_count INTO current_count FROM app.schema_compatibility_v23();
  SELECT applied_count INTO predecessor_count FROM app.schema_compatibility_v22();
  SELECT applied_count INTO retired_count FROM app.schema_compatibility_v21();
  RETURN current_count = 116 AND predecessor_count = 113
    AND retired_count = 0;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.audit_reader_schema_readiness_v1()
  OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.audit_reader_schema_readiness_v1()
FROM PUBLIC, periapsis_notifier, periapsis_auditor,
  periapsis_audit_reader_owner, periapsis_sla_api_owner,
  periapsis_sla_worker_owner, periapsis_sla_readiness_owner;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.audit_reader_schema_readiness_v1()
TO periapsis_api, periapsis_worker;
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.ticket_search_schema_readiness_v1()
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE current_count bigint; predecessor_count bigint; retired_count bigint;
BEGIN
  IF EXISTS (
    SELECT 1
    FROM (VALUES
      ('alerts', 'alerts_ticket_search_idx'),
      ('cases', 'cases_ticket_search_idx')
    ) AS expected(table_name, index_name)
    LEFT JOIN pg_class AS index_class
      ON index_class.relname = expected.index_name
    LEFT JOIN pg_index AS index_row
      ON index_row.indexrelid = index_class.oid
    WHERE index_row.indexrelid IS NULL OR NOT index_row.indisvalid
       OR NOT index_row.indisready OR NOT index_row.indislive
  ) THEN
    RETURN false;
  END IF;
  SELECT applied_count INTO current_count FROM app.schema_compatibility_v23();
  SELECT applied_count INTO predecessor_count FROM app.schema_compatibility_v22();
  SELECT applied_count INTO retired_count FROM app.schema_compatibility_v21();
  RETURN current_count = 116 AND predecessor_count = 113
    AND retired_count = 0;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.ticket_search_schema_readiness_v1()
  OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.ticket_search_schema_readiness_v1()
FROM PUBLIC, periapsis_notifier, periapsis_auditor,
  periapsis_audit_reader_owner, periapsis_sla_api_owner,
  periapsis_sla_worker_owner, periapsis_sla_readiness_owner;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.ticket_search_schema_readiness_v1()
TO periapsis_api, periapsis_worker;
--> statement-breakpoint
