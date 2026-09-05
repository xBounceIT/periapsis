-- Identity MFA closes its database boundary with a new exact compatibility
-- projection. V23 is the only supported rolling predecessor (through 0116);
-- older projections are retired fail-closed.

CREATE FUNCTION app.schema_compatibility_v24()
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
  migration_0120_rows bigint;
BEGIN
  EXECUTE $query$
    SELECT count(*)::bigint, max(migration.created_at)::bigint,
           count(*) FILTER (
             WHERE migration.created_at = 1787716104120
           )::bigint
    FROM drizzle.__drizzle_migrations AS migration
  $query$ INTO journal_count, journal_latest_created_at, migration_0120_rows;
  IF journal_count = 121
     AND journal_latest_created_at = 1787716104120
     AND migration_0120_rows = 1 THEN
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
ALTER FUNCTION app.schema_compatibility_v24()
  OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.schema_compatibility_v24()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,
  periapsis_sla_api_owner, periapsis_sla_worker_owner,
  periapsis_sla_readiness_owner;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.schema_compatibility_v24()
TO periapsis_api, periapsis_worker;
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.schema_compatibility_v23()
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
  FROM app.schema_compatibility_v24() AS compatibility;
  IF full_count = 121
     AND full_latest_created_at = 1787716104120
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
              WHERE prefix.migration_ordinal = 117),
             string_agg(
               migration.created_at::text || '@' || migration.migration_hash,
               ':' ORDER BY migration.created_at, migration.id
             )
      FROM ordered_migrations AS migration
      WHERE migration.migration_ordinal <= 117
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
TO periapsis_api, periapsis_worker;
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
AS $function$
BEGIN
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
  IF p_expected_count IS DISTINCT FROM 121
     OR p_expected_latest_created_at IS DISTINCT FROM 1787716104120
     OR p_expected_latest_hash IS NULL
     OR p_expected_latest_hash !~ '^[0-9a-f]{64}$'
     OR p_expected_migration_fingerprint IS NULL
     OR p_expected_migration_fingerprint !~
          '^[1-9][0-9]*@[0-9a-f]{64}(:[1-9][0-9]*@[0-9a-f]{64})*$'
     OR cardinality(fingerprint_entries) IS DISTINCT FROM 121
     OR fingerprint_entries[121] IS DISTINCT FROM (
       p_expected_latest_created_at::text || '@' || p_expected_latest_hash
     ) THEN
    RAISE EXCEPTION 'invalid schema compatibility v24 manifest'
      USING ERRCODE = '22023';
  END IF;
  SELECT array_agg(
    split_part(entry.value, '@', 1)::bigint ORDER BY entry.ordinality
  ) INTO appended_created_at
  FROM unnest(fingerprint_entries[118:121]) WITH ORDINALITY
       AS entry(value, ordinality);
  IF appended_created_at IS DISTINCT FROM ARRAY[
    1787714672362, 1787714674442, 1787714676640, 1787716104120
  ]::bigint[] THEN
    RAISE EXCEPTION 'invalid schema compatibility v24 appended sequence'
      USING ERRCODE = '22023';
  END IF;

  SELECT compatibility.applied_count, compatibility.latest_created_at,
         compatibility.latest_hash, compatibility.migration_fingerprint
  INTO actual_count, actual_latest_created_at, actual_latest_hash,
       actual_fingerprint
  FROM app.schema_compatibility_v24() AS compatibility;
  IF actual_count IS DISTINCT FROM p_expected_count
     OR actual_latest_created_at IS DISTINCT FROM p_expected_latest_created_at
     OR actual_latest_hash IS DISTINCT FROM p_expected_latest_hash
     OR actual_fingerprint IS DISTINCT FROM p_expected_migration_fingerprint THEN
    RAISE EXCEPTION 'schema compatibility v24 manifest does not match the applied journal'
      USING ERRCODE = '55000';
  END IF;

  PERFORM set_config(
    'app.schema_compatibility_fingerprint',
    p_expected_migration_fingerprint, true
  );
  EXECUTE $statement$
    ALTER FUNCTION app.schema_compatibility_v23()
      SET app.schema_compatibility_fingerprint FROM CURRENT
  $statement$;
  expected_predecessor_fingerprint := array_to_string(
    fingerprint_entries[1:117], ':'
  );
  SELECT compatibility.applied_count, compatibility.latest_created_at,
         compatibility.latest_hash, compatibility.migration_fingerprint
  INTO predecessor_count, predecessor_latest_created_at,
       predecessor_latest_hash, predecessor_fingerprint
  FROM app.schema_compatibility_v23() AS compatibility;
  IF predecessor_count IS DISTINCT FROM 117
     OR predecessor_latest_created_at IS DISTINCT FROM 1787711774160
     OR predecessor_latest_hash IS DISTINCT FROM
          '428a381a9463bb2c4358d0c5dba2465e5acd72326d5296dbfb895c806e2fb159'
     OR predecessor_fingerprint IS DISTINCT FROM
          expected_predecessor_fingerprint THEN
    RAISE EXCEPTION 'sealed schema compatibility v23 prefix is not exact'
      USING ERRCODE = '55000';
  END IF;

  SELECT compatibility.applied_count INTO retired_count
  FROM app.schema_compatibility_v22() AS compatibility;
  SELECT compatibility.applied_count INTO retired_legacy_count
  FROM app.schema_compatibility_v21() AS compatibility;
  IF retired_count IS DISTINCT FROM 0
     OR retired_legacy_count IS DISTINCT FROM 0 THEN
    RAISE EXCEPTION 'legacy schema compatibility projections remain active'
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

CREATE FUNCTION app.identity_mfa_schema_readiness_v1()
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  relation_name text;
  trigger_name text;
  expected_function record;
  function_oid regprocedure;
  function_owner text;
  function_security_definer boolean;
  function_configuration text[];
  current_count bigint;
  predecessor_count bigint;
  retired_count bigint;
BEGIN
  FOREACH relation_name IN ARRAY ARRAY[
    'auth_session_local_credential_provenance',
    'auth_session_mfa_evidence',
    'auth_session_mfa_policy_pins',
    'auth_session_mfa_states',
    'auth_session_passkey_provenance',
    'mfa_policy_revisions',
    'tenant_mfa_authority_anchors',
    'tenant_mfa_authority_evidence',
    'tenant_mfa_authority_policy_pins',
    'tenant_mfa_step_up_challenges',
    'tenant_mfa_subjects',
    'tenant_post_primary_continuation_evidence',
    'tenant_post_primary_continuation_policy_pins',
    'tenant_post_primary_continuations',
    'tenant_recovery_code_sets',
    'tenant_recovery_codes',
    'tenant_totp_enrollments',
    'tenant_totp_factors',
    'tenant_webauthn_ceremonies',
    'tenant_webauthn_ceremony_credentials',
    'tenant_webauthn_credential_transports',
    'tenant_webauthn_credentials'
  ] LOOP
    IF NOT EXISTS (
      SELECT 1
      FROM pg_class AS class
      JOIN pg_namespace AS namespace ON namespace.oid = class.relnamespace
      JOIN pg_attribute AS tenant_column
        ON tenant_column.attrelid = class.oid
       AND tenant_column.attname = 'tenant_id'
       AND NOT tenant_column.attisdropped
      WHERE namespace.nspname = 'public'
        AND class.relname = relation_name
        AND class.relkind = 'r'
        AND pg_get_userbyid(class.relowner) = 'periapsis_migrator'
        AND class.relrowsecurity
        AND class.relforcerowsecurity
    ) OR has_table_privilege(
      'periapsis_api', format('public.%I', relation_name),
      'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
    ) OR has_table_privilege(
      'periapsis_worker', format('public.%I', relation_name),
      'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
    ) OR has_table_privilege(
      'periapsis_notifier', format('public.%I', relation_name),
      'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
    ) OR has_table_privilege(
      'periapsis_auditor', format('public.%I', relation_name),
      'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
    ) THEN
      RETURN false;
    END IF;
  END LOOP;

  FOREACH trigger_name IN ARRAY ARRAY[
    'auth_session_mfa_states_provenance_v1',
    'auth_session_local_provenance_parent_v1',
    'auth_session_passkey_provenance_parent_v1',
    'auth_session_mfa_evidence_subject_v1',
    'tenant_mfa_authority_evidence_subject_v1',
    'tenant_continuation_evidence_subject_v1'
  ] LOOP
    IF NOT EXISTS (
      SELECT 1 FROM pg_trigger AS trigger_record
      WHERE trigger_record.tgname = trigger_name
        AND NOT trigger_record.tgisinternal
        AND trigger_record.tgenabled = 'O'
    ) THEN
      RETURN false;
    END IF;
  END LOOP;

  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint AS constraint_record
    WHERE constraint_record.conname = 'mfa_policy_revisions_scope_check'
      AND constraint_record.contype = 'c'
  ) OR NOT EXISTS (
    SELECT 1 FROM pg_constraint AS constraint_record
    WHERE constraint_record.conname = 'mfa_policy_revisions_role_fk'
      AND constraint_record.contype = 'f'
  ) OR NOT EXISTS (
    SELECT 1 FROM pg_constraint AS constraint_record
    WHERE constraint_record.conname = 'mfa_policy_revisions_security_group_fk'
      AND constraint_record.contype = 'f'
  ) OR NOT EXISTS (
    SELECT 1 FROM pg_constraint AS constraint_record
    WHERE constraint_record.conname = 'auth_session_mfa_evidence_typed_source_check'
      AND constraint_record.contype = 'c'
  ) OR NOT EXISTS (
    SELECT 1 FROM pg_constraint AS constraint_record
    WHERE constraint_record.conname = 'tenant_mfa_step_up_challenges_replay_check'
      AND constraint_record.contype = 'c'
  ) OR NOT EXISTS (
    SELECT 1 FROM pg_constraint AS constraint_record
    WHERE constraint_record.conname = 'tenant_webauthn_ceremonies_replay_check'
      AND constraint_record.contype = 'c'
  ) OR NOT EXISTS (
    SELECT 1 FROM pg_constraint AS constraint_record
    WHERE constraint_record.conname = 'auth_sessions_method_check'
      AND pg_get_constraintdef(constraint_record.oid) LIKE '%passkey%'
  ) THEN
    RETURN false;
  END IF;

  IF to_regprocedure('app.complete_webauthn_registration_v1(jsonb)') IS NOT NULL
     OR to_regprocedure('app.complete_webauthn_authentication_v1(jsonb)') IS NOT NULL THEN
    RETURN false;
  END IF;

  FOR expected_function IN
    SELECT * FROM (VALUES
      ('app.resolve_mfa_authority_v1(uuid,text,text,text,timestamp with time zone)'),
      ('app.resolve_primary_passkey_v1(uuid,text,text,timestamp with time zone)'),
      ('app.admit_mfa_operation_v1(uuid,bytea,bytea,bytea,timestamp with time zone)'),
      ('app.start_totp_enrollment_v1(jsonb)'),
      ('app.claim_totp_enrollment_v1(uuid,bytea,timestamp with time zone)'),
      ('app.complete_totp_enrollment_v1(jsonb)'),
      ('app.fail_totp_enrollment_v1(uuid,bigint,timestamp with time zone)'),
      ('app.replace_mfa_recovery_codes_v1(jsonb)'),
      ('app.create_mfa_step_up_challenge_v1(jsonb)'),
      ('app.claim_mfa_step_up_challenge_v1(bytea,bytea,text,timestamp with time zone)'),
      ('app.fail_mfa_step_up_challenge_v1(bytea,bigint,text,text,timestamp with time zone)'),
      ('app.load_mfa_totp_factor_v1(uuid,uuid,uuid)'),
      ('app.load_mfa_recovery_set_v1(uuid,uuid)'),
      ('app.complete_mfa_totp_step_up_v1(jsonb)'),
      ('app.complete_mfa_recovery_step_up_v1(jsonb)'),
      ('app.create_webauthn_ceremony_v1(jsonb)'),
      ('app.claim_webauthn_ceremony_v1(bytea,bytea,timestamp with time zone)'),
      ('app.fail_webauthn_ceremony_v1(bytea,bigint,text,text,timestamp with time zone)'),
      ('app.load_webauthn_credential_v1(uuid,bytea,bytea,boolean)'),
      ('app.complete_mfa_passkey_registration_v1(jsonb)'),
      ('app.complete_mfa_passkey_authentication_v1(jsonb)')
    ) AS expected(signature)
  LOOP
    function_oid := to_regprocedure(expected_function.signature);
    IF function_oid IS NULL THEN
      RETURN false;
    END IF;
    SELECT pg_get_userbyid(procedure.proowner), procedure.prosecdef,
           procedure.proconfig
    INTO function_owner, function_security_definer, function_configuration
    FROM pg_proc AS procedure WHERE procedure.oid = function_oid;
    IF function_owner IS DISTINCT FROM 'periapsis_migrator'
       OR function_security_definer IS NOT TRUE
       OR function_configuration[1] NOT LIKE 'search_path=pg_catalog%'
       OR NOT has_function_privilege('periapsis_api', function_oid, 'EXECUTE')
       OR has_function_privilege('periapsis_worker', function_oid, 'EXECUTE')
       OR has_function_privilege('periapsis_notifier', function_oid, 'EXECUTE')
       OR has_function_privilege('periapsis_auditor', function_oid, 'EXECUTE')
       OR EXISTS (
         SELECT 1 FROM pg_proc AS public_procedure
         CROSS JOIN LATERAL aclexplode(
           coalesce(
             public_procedure.proacl,
             acldefault('f', public_procedure.proowner)
           )
         ) AS privilege
         WHERE public_procedure.oid = function_oid
           AND privilege.grantee = 0
           AND privilege.privilege_type = 'EXECUTE'
       ) THEN
      RETURN false;
    END IF;
  END LOOP;

  IF EXISTS (
    SELECT 1
    FROM pg_proc AS procedure
    JOIN pg_namespace AS namespace ON namespace.oid = procedure.pronamespace
    WHERE namespace.nspname = 'app'
      AND procedure.proname LIKE 'private_mfa_%'
      AND (
        pg_get_userbyid(procedure.proowner) <> 'periapsis_migrator'
        OR NOT procedure.prosecdef
        OR has_function_privilege('periapsis_api', procedure.oid, 'EXECUTE')
        OR has_function_privilege('periapsis_worker', procedure.oid, 'EXECUTE')
        OR EXISTS (
          SELECT 1
          FROM aclexplode(
            coalesce(procedure.proacl, acldefault('f', procedure.proowner))
          ) AS privilege
          WHERE privilege.grantee = 0
            AND privilege.privilege_type = 'EXECUTE'
        )
      )
  ) THEN
    RETURN false;
  END IF;

  SELECT compatibility.applied_count INTO current_count
  FROM app.schema_compatibility_v24() AS compatibility;
  SELECT compatibility.applied_count INTO predecessor_count
  FROM app.schema_compatibility_v23() AS compatibility;
  SELECT compatibility.applied_count INTO retired_count
  FROM app.schema_compatibility_v22() AS compatibility;
  RETURN current_count = 121 AND predecessor_count = 117
    AND retired_count = 0;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.identity_mfa_schema_readiness_v1()
  OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.identity_mfa_schema_readiness_v1()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,
  periapsis_sla_api_owner, periapsis_sla_worker_owner,
  periapsis_sla_readiness_owner;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.identity_mfa_schema_readiness_v1()
TO periapsis_api;
--> statement-breakpoint
