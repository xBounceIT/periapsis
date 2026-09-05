CREATE FUNCTION app.schema_compatibility_v22()
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
  migration_0112_rows bigint;
BEGIN
  EXECUTE $query$
    SELECT count(*)::bigint, max(migration.created_at)::bigint,
           count(*) FILTER (
             WHERE migration.created_at = 1787705491869
           )::bigint
    FROM drizzle.__drizzle_migrations AS migration
  $query$ INTO journal_count, journal_latest_created_at, migration_0112_rows;
  IF journal_count = 113
     AND journal_latest_created_at = 1787705491869
     AND migration_0112_rows = 1 THEN
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
ALTER FUNCTION app.schema_compatibility_v22()
  OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.schema_compatibility_v22()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
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
  FROM app.schema_compatibility_v22() AS compatibility;
  IF full_count = 113
     AND full_latest_created_at = 1787705491869
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
              WHERE prefix.migration_ordinal = 107),
             string_agg(
               migration.created_at::text || '@' || migration.migration_hash,
               ':' ORDER BY migration.created_at, migration.id
             )
      FROM ordered_migrations AS migration
      WHERE migration.migration_ordinal <= 107
    $query$;
    RETURN;
  END IF;
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
  legacy_count bigint;
  legacy_latest_created_at bigint;
  legacy_hash text;
  legacy_fingerprint text;
  expected_legacy_fingerprint text;
BEGIN
  fingerprint_entries := string_to_array(
    p_expected_migration_fingerprint, ':'
  );
  IF p_expected_count IS DISTINCT FROM 113
     OR p_expected_latest_created_at IS DISTINCT FROM 1787705491869
     OR p_expected_latest_hash IS NULL
     OR p_expected_latest_hash !~ '^[0-9a-f]{64}$'
     OR p_expected_migration_fingerprint IS NULL
     OR p_expected_migration_fingerprint !~
          '^[1-9][0-9]*@[0-9a-f]{64}(:[1-9][0-9]*@[0-9a-f]{64})*$'
     OR cardinality(fingerprint_entries) IS DISTINCT FROM 113
     OR fingerprint_entries[113] IS DISTINCT FROM (
       p_expected_latest_created_at::text || '@' || p_expected_latest_hash
     ) THEN
    RAISE EXCEPTION 'invalid schema compatibility v22 manifest'
      USING ERRCODE = '22023';
  END IF;
  SELECT array_agg(
    split_part(entry.value, '@', 1)::bigint ORDER BY entry.ordinality
  ) INTO appended_created_at
  FROM unnest(fingerprint_entries[108:113]) WITH ORDINALITY
       AS entry(value, ordinality);
  IF appended_created_at IS DISTINCT FROM ARRAY[
    1787705439947, 1787705463307, 1787705470675,
    1787705476966, 1787705484785, 1787705491869
  ]::bigint[] THEN
    RAISE EXCEPTION 'invalid schema compatibility v22 appended sequence'
      USING ERRCODE = '22023';
  END IF;

  SELECT compatibility.applied_count, compatibility.latest_created_at,
         compatibility.latest_hash, compatibility.migration_fingerprint
  INTO actual_count, actual_latest_created_at, actual_latest_hash,
       actual_fingerprint
  FROM app.schema_compatibility_v22() AS compatibility;
  IF actual_count IS DISTINCT FROM p_expected_count
     OR actual_latest_created_at IS DISTINCT FROM p_expected_latest_created_at
     OR actual_latest_hash IS DISTINCT FROM p_expected_latest_hash
     OR actual_fingerprint IS DISTINCT FROM p_expected_migration_fingerprint THEN
    RAISE EXCEPTION 'schema compatibility v22 manifest does not match the applied journal'
      USING ERRCODE = '55000';
  END IF;

  PERFORM set_config(
    'app.schema_compatibility_fingerprint',
    p_expected_migration_fingerprint, true
  );
  EXECUTE $statement$
    ALTER FUNCTION app.schema_compatibility_v21()
      SET app.schema_compatibility_fingerprint FROM CURRENT
  $statement$;
  expected_predecessor_fingerprint := array_to_string(
    fingerprint_entries[1:107], ':'
  );
  SELECT compatibility.applied_count, compatibility.latest_created_at,
         compatibility.latest_hash, compatibility.migration_fingerprint
  INTO predecessor_count, predecessor_latest_created_at,
       predecessor_latest_hash, predecessor_fingerprint
  FROM app.schema_compatibility_v21() AS compatibility;
  IF predecessor_count IS DISTINCT FROM 107
     OR predecessor_latest_created_at IS DISTINCT FROM 1787699142047
     OR predecessor_latest_hash IS DISTINCT FROM
          '08415f4562df5ff64cb71895e9189f7223fd68b4b061125da3fa6ca1f8b9a667'
     OR predecessor_fingerprint IS DISTINCT FROM
          expected_predecessor_fingerprint THEN
    RAISE EXCEPTION 'sealed schema compatibility v21 prefix is not exact'
      USING ERRCODE = '55000';
  END IF;

  PERFORM set_config(
    'app.schema_compatibility_fingerprint',
    expected_predecessor_fingerprint, true
  );
  EXECUTE $statement$
    ALTER FUNCTION app.schema_compatibility_v20()
      SET app.schema_compatibility_fingerprint FROM CURRENT
  $statement$;
  expected_legacy_fingerprint := array_to_string(
    fingerprint_entries[1:104], ':'
  );
  SELECT compatibility.applied_count, compatibility.latest_created_at,
         compatibility.latest_hash, compatibility.migration_fingerprint
  INTO legacy_count, legacy_latest_created_at, legacy_hash,
       legacy_fingerprint
  FROM app.schema_compatibility_v20() AS compatibility;
  IF legacy_count IS DISTINCT FROM 104
     OR legacy_latest_created_at IS DISTINCT FROM 1787693815749
     OR legacy_fingerprint IS DISTINCT FROM expected_legacy_fingerprint
     OR legacy_hash IS DISTINCT FROM split_part(fingerprint_entries[104], '@', 2) THEN
    RAISE EXCEPTION 'rolling schema compatibility v20 prefix is not exact'
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
  periapsis_sla_api_owner, periapsis_sla_worker_owner,
  periapsis_sla_readiness_owner;
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
  FROM app.schema_compatibility_v22() AS compatibility;
  SELECT compatibility.applied_count INTO predecessor_count
  FROM app.schema_compatibility_v21() AS compatibility;
  SELECT compatibility.applied_count INTO rolling_count
  FROM app.schema_compatibility_v20() AS compatibility;
  RETURN current_count = 113 AND predecessor_count = 107
    AND rolling_count = 104;
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
