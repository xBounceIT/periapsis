-- Federation advances schema compatibility to v27.  The exact sealed 0125
-- state remains the sole rolling predecessor through v26; v25 is retired.

CREATE FUNCTION app.schema_compatibility_v27()
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
  migration_0134_rows bigint;
BEGIN
  EXECUTE $query$
    SELECT count(*)::bigint, max(migration.created_at)::bigint,
           count(*) FILTER (
             WHERE migration.created_at = 1787732438000
           )::bigint
    FROM drizzle.__drizzle_migrations AS migration
  $query$ INTO journal_count, journal_latest_created_at, migration_0134_rows;
  IF journal_count = 135
     AND journal_latest_created_at = 1787732438000
     AND migration_0134_rows = 1 THEN
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
ALTER FUNCTION app.schema_compatibility_v27()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.schema_compatibility_v27()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,
  periapsis_sla_api_owner, periapsis_sla_worker_owner,
  periapsis_sla_readiness_owner;
GRANT EXECUTE ON FUNCTION app.schema_compatibility_v27()
TO periapsis_api, periapsis_worker;
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.schema_compatibility_v26()
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
  FROM app.schema_compatibility_v27() AS compatibility;
  IF full_count = 135
     AND full_latest_created_at = 1787732438000
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
              WHERE prefix.migration_ordinal = 126),
             string_agg(
               migration.created_at::text || '@' || migration.migration_hash,
               ':' ORDER BY migration.created_at, migration.id
             )
      FROM ordered_migrations AS migration
      WHERE migration.migration_ordinal <= 126
    $query$;
    RETURN;
  END IF;
  RETURN QUERY SELECT 0::bigint, 0::bigint,
                      'UNSUPPORTED'::text, 'UNSUPPORTED'::text;
END;
$function$;
ALTER FUNCTION app.schema_compatibility_v26()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.schema_compatibility_v26()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,
  periapsis_sla_api_owner, periapsis_sla_worker_owner,
  periapsis_sla_readiness_owner;
GRANT EXECUTE ON FUNCTION app.schema_compatibility_v26()
TO periapsis_api, periapsis_worker;
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.schema_compatibility_v25()
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
ALTER FUNCTION app.schema_compatibility_v25()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.schema_compatibility_v25()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,
  periapsis_sla_api_owner, periapsis_sla_worker_owner,
  periapsis_sla_readiness_owner;
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
  IF p_expected_count IS DISTINCT FROM 135
     OR p_expected_latest_created_at IS DISTINCT FROM 1787732438000
     OR p_expected_latest_hash IS NULL
     OR p_expected_latest_hash !~ '^[0-9a-f]{64}$'
     OR p_expected_migration_fingerprint IS NULL
     OR p_expected_migration_fingerprint !~
          '^[1-9][0-9]*@[0-9a-f]{64}(:[1-9][0-9]*@[0-9a-f]{64})*$'
     OR cardinality(fingerprint_entries) IS DISTINCT FROM 135
     OR fingerprint_entries[135] IS DISTINCT FROM (
       p_expected_latest_created_at::text || '@' || p_expected_latest_hash
     ) THEN
    RAISE EXCEPTION 'invalid schema compatibility v27 manifest'
      USING ERRCODE = '22023';
  END IF;
  SELECT array_agg(
    split_part(entry.value, '@', 1)::bigint ORDER BY entry.ordinality
  ) INTO appended_created_at
  FROM unnest(fingerprint_entries[127:135]) WITH ORDINALITY
       AS entry(value, ordinality);
  IF appended_created_at IS DISTINCT FROM ARRAY[
    1787732404997, 1787732423963, 1787732426000,
    1787732428000, 1787732430000, 1787732432000,
    1787732434000, 1787732436000, 1787732438000
  ]::bigint[] THEN
    RAISE EXCEPTION 'invalid schema compatibility v27 appended sequence'
      USING ERRCODE = '22023';
  END IF;

  SELECT compatibility.applied_count, compatibility.latest_created_at,
         compatibility.latest_hash, compatibility.migration_fingerprint
  INTO actual_count, actual_latest_created_at, actual_latest_hash,
       actual_fingerprint
  FROM app.schema_compatibility_v27() AS compatibility;
  IF actual_count IS DISTINCT FROM p_expected_count
     OR actual_latest_created_at IS DISTINCT FROM p_expected_latest_created_at
     OR actual_latest_hash IS DISTINCT FROM p_expected_latest_hash
     OR actual_fingerprint IS DISTINCT FROM p_expected_migration_fingerprint THEN
    RAISE EXCEPTION 'schema compatibility v27 manifest does not match the applied journal'
      USING ERRCODE = '55000';
  END IF;

  PERFORM set_config(
    'app.schema_compatibility_fingerprint',
    p_expected_migration_fingerprint, true
  );
  EXECUTE $statement$
    ALTER FUNCTION app.schema_compatibility_v26()
      SET app.schema_compatibility_fingerprint FROM CURRENT
  $statement$;
  expected_predecessor_fingerprint := array_to_string(
    fingerprint_entries[1:126], ':'
  );
  SELECT compatibility.applied_count, compatibility.latest_created_at,
         compatibility.latest_hash, compatibility.migration_fingerprint
  INTO predecessor_count, predecessor_latest_created_at,
       predecessor_latest_hash, predecessor_fingerprint
  FROM app.schema_compatibility_v26() AS compatibility;
  IF predecessor_count IS DISTINCT FROM 126
     OR predecessor_latest_created_at IS DISTINCT FROM 1787723203494
     OR predecessor_latest_hash IS DISTINCT FROM
          '211491eec9cf3e475db463fd815d31a98c2e80263e3c3957cf0eef7a5434a9d8'
     OR predecessor_fingerprint IS DISTINCT FROM
          expected_predecessor_fingerprint THEN
    RAISE EXCEPTION 'sealed schema compatibility v26 prefix is not exact'
      USING ERRCODE = '55000';
  END IF;

  SELECT compatibility.applied_count INTO retired_count
  FROM app.schema_compatibility_v25() AS compatibility;
  IF retired_count IS DISTINCT FROM 0
     OR has_function_privilege(
       'periapsis_api', 'app.schema_compatibility_v25()'::regprocedure,
       'EXECUTE'
     )
     OR has_function_privilege(
       'periapsis_worker', 'app.schema_compatibility_v25()'::regprocedure,
       'EXECUTE'
     ) THEN
    RAISE EXCEPTION 'legacy schema compatibility v25 remains active'
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
  periapsis_sla_readiness_owner;
--> statement-breakpoint

CREATE FUNCTION app.federated_authentication_schema_readiness_v1()
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
  function_definition text;
  current_count bigint;
  predecessor_count bigint;
  retired_count bigint;
BEGIN
  FOREACH relation_name IN ARRAY ARRAY[
    'auth_session_federated_provenance',
    'tenant_federated_authentication_applications',
    'tenant_federated_authentication_transactions',
    'tenant_federated_external_identities',
    'tenant_federated_external_identity_aliases',
    'tenant_federated_mapping_rule_epochs',
    'tenant_federated_mapping_rule_role_targets',
    'tenant_federated_provider_access_grants',
    'tenant_federated_provider_policies',
    'tenant_federated_provider_profile_contributions',
    'tenant_federated_session_revalidation_commands',
    'tenant_federated_trust_rules',
    'tenant_oidc_claim_rules',
    'tenant_oidc_client_secrets',
    'tenant_oidc_discovery_snapshots',
    'tenant_oidc_jwks_snapshots',
    'tenant_oidc_provider_configurations',
    'tenant_saml_attribute_rules',
    'tenant_saml_metadata_snapshots',
    'tenant_saml_provider_configurations',
    'tenant_saml_session_materials',
    'tenant_saml_sp_certificates',
    'tenant_saml_sp_keys'
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
    ) OR EXISTS (
      SELECT 1
      FROM pg_policy AS policy
      JOIN pg_class AS class ON class.oid = policy.polrelid
      JOIN pg_namespace AS namespace ON namespace.oid = class.relnamespace
      WHERE namespace.nspname = 'public' AND class.relname = relation_name
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
    'auth_session_federated_provenance_parent_v1',
    'tenant_post_primary_continuations_federated_provenance_v1',
    'tenant_saml_provider_configurations_canonical_v1',
    'tenant_federated_authentication_transactions_guard_v1',
    'tenant_federated_authentication_applications_immutable_v1',
    'tenant_federated_session_revalidation_commands_immutable_v1'
  ] LOOP
    IF NOT EXISTS (
      SELECT 1 FROM pg_trigger AS trigger
      WHERE trigger.tgname = trigger_name
        AND NOT trigger.tgisinternal AND trigger.tgenabled = 'O'
    ) THEN
      RETURN false;
    END IF;
  END LOOP;

  FOR expected_function IN
    SELECT * FROM (VALUES
      ('app.create_oidc_authentication_transaction_v1(jsonb)', true),
      ('app.claim_oidc_authentication_transaction_v1(jsonb)', true),
      ('app.fail_oidc_authentication_transaction_v1(jsonb)', true),
      ('app.create_saml_authentication_transaction_v1(jsonb)', true),
      ('app.lookup_saml_authentication_transaction_v1(jsonb)', true),
      ('app.begin_tenant_oidc_authentication_v1(jsonb)', true),
      ('app.resolve_tenant_oidc_authentication_v1(jsonb)', true),
      ('app.begin_tenant_saml_authentication_v1(jsonb)', true),
      ('app.resolve_tenant_saml_authentication_v1(jsonb)', true),
      ('app.load_federated_authentication_planning_state_v1(jsonb)', true),
      ('app.load_oidc_trust_snapshot_v1(jsonb)', true),
      ('app.load_oidc_client_secret_envelope_v1(jsonb)', true),
      ('app.load_saml_sp_key_envelope_v1(jsonb)', true),
      ('app.apply_federated_authentication_v1(jsonb)', true),
      ('app.load_federated_session_revalidation_v1(jsonb)', true),
      ('app.apply_federated_session_revalidation_v1(jsonb)', true),
      ('app.private_federated_assert_begin_lookup_v1(jsonb)', false),
      ('app.private_federated_assurance_requirement_v1(uuid,uuid,uuid,bigint,text,timestamp with time zone)', false),
      ('app.private_federated_assurance_decision_v1(jsonb,jsonb,boolean,timestamp with time zone)', false),
      ('app.private_federated_apply_response_v1(bytea,text,uuid,text,text,uuid,uuid,uuid,text,boolean)', false),
      ('app.private_federated_replay_live_v1(uuid,uuid,uuid,auth_provider_kind,uuid,uuid,uuid,uuid,timestamp with time zone)', false),
      ('app.private_federated_issue_authority_v1(jsonb,uuid,uuid,uuid,bigint,bigint,bigint,uuid,uuid,auth_provider_kind,bigint,timestamp with time zone,bytea)', false),
      ('app.private_federated_apply_identity_v1(jsonb,uuid,uuid,uuid,auth_provider_kind,bigint,bigint,timestamp with time zone)', false),
      ('app.private_mfa_apply_federated_session_v1(jsonb,uuid,text,uuid,bigint,timestamp with time zone)', false),
      ('app.guard_federated_authentication_transaction_v1()', false),
      ('app.guard_federated_immutable_ledger_v1()', false),
      ('app.validate_federated_continuation_provenance_v1()', false),
      ('app.validate_saml_configuration_canonical_v1()', false)
    ) AS expected(signature, api_execute)
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
       OR NOT function_security_definer
       OR function_configuration IS DISTINCT FROM
            ARRAY['search_path=pg_catalog, public, app']::text[]
       OR has_function_privilege('periapsis_api', function_oid, 'EXECUTE')
          IS DISTINCT FROM expected_function.api_execute
       OR has_function_privilege('periapsis_worker', function_oid, 'EXECUTE')
       OR has_function_privilege('periapsis_notifier', function_oid, 'EXECUTE')
       OR has_function_privilege('periapsis_auditor', function_oid, 'EXECUTE')
       OR has_function_privilege(
            'periapsis_notification_dispatch_owner', function_oid, 'EXECUTE'
          )
       OR has_function_privilege(
            'periapsis_sla_api_owner', function_oid, 'EXECUTE'
          )
       OR has_function_privilege(
            'periapsis_sla_worker_owner', function_oid, 'EXECUTE'
          )
       OR EXISTS (
         SELECT 1
         FROM aclexplode(
           coalesce(
             (SELECT procedure.proacl FROM pg_proc AS procedure
              WHERE procedure.oid = function_oid),
             acldefault('f',
               (SELECT procedure.proowner FROM pg_proc AS procedure
                WHERE procedure.oid = function_oid))
           )
         ) AS privilege
         WHERE privilege.grantee = 0
           AND privilege.privilege_type = 'EXECUTE'
       ) THEN
      RETURN false;
    END IF;
  END LOOP;

  IF (
    SELECT count(*)
    FROM pg_proc AS procedure
    JOIN pg_namespace AS namespace ON namespace.oid = procedure.pronamespace
    WHERE namespace.nspname = 'app'
      AND procedure.proname = ANY(ARRAY[
        'create_oidc_authentication_transaction_v1',
        'claim_oidc_authentication_transaction_v1',
        'fail_oidc_authentication_transaction_v1',
        'create_saml_authentication_transaction_v1',
        'lookup_saml_authentication_transaction_v1',
        'begin_tenant_oidc_authentication_v1',
        'resolve_tenant_oidc_authentication_v1',
        'begin_tenant_saml_authentication_v1',
        'resolve_tenant_saml_authentication_v1',
        'load_federated_authentication_planning_state_v1',
        'load_oidc_trust_snapshot_v1',
        'load_oidc_client_secret_envelope_v1',
        'load_saml_sp_key_envelope_v1',
        'apply_federated_authentication_v1',
        'load_federated_session_revalidation_v1',
        'apply_federated_session_revalidation_v1'
      ])
  ) IS DISTINCT FROM 16 THEN
    RETURN false;
  END IF;

  SELECT pg_get_functiondef(
    'app.apply_federated_authentication_v1(jsonb)'::regprocedure
  ) INTO function_definition;
  IF function_definition NOT LIKE '%private_federated_apply_identity_v1%'
     OR function_definition NOT LIKE '%tenant_federated_authentication_applications%'
     OR function_definition NOT LIKE '%FOR UPDATE%'
     OR function_definition LIKE '%secret_material_included'', true%' THEN
    RETURN false;
  END IF;
  SELECT pg_get_functiondef(
    'app.private_federated_apply_identity_v1(jsonb,uuid,uuid,uuid,auth_provider_kind,bigint,bigint,timestamp with time zone)'::regprocedure
  ) INTO function_definition;
  IF function_definition NOT LIKE '%tenant_federated_provider_access_grants%'
     OR function_definition NOT LIKE '%tenant_memberships%'
     OR function_definition NOT LIKE '%tenant_authorization_sources%' THEN
    RETURN false;
  END IF;
  SELECT pg_get_functiondef(
    'app.apply_federated_session_revalidation_v1(jsonb)'::regprocedure
  ) INTO function_definition;
  IF function_definition NOT LIKE '%tenant_federated_provider_access_grants%'
     OR function_definition NOT LIKE '%request_digest%'
     OR function_definition NOT LIKE '%FOR UPDATE%'
     OR function_definition LIKE '%''applied'', false%' THEN
    RETURN false;
  END IF;

  IF NOT has_function_privilege(
       'periapsis_api', 'app.schema_compatibility_v27()'::regprocedure,
       'EXECUTE'
     ) OR NOT has_function_privilege(
       'periapsis_worker', 'app.schema_compatibility_v27()'::regprocedure,
       'EXECUTE'
     ) OR NOT has_function_privilege(
       'periapsis_api', 'app.schema_compatibility_v26()'::regprocedure,
       'EXECUTE'
     ) OR NOT has_function_privilege(
       'periapsis_worker', 'app.schema_compatibility_v26()'::regprocedure,
       'EXECUTE'
     ) OR has_function_privilege(
       'periapsis_api', 'app.schema_compatibility_v25()'::regprocedure,
       'EXECUTE'
     ) OR has_function_privilege(
       'periapsis_worker', 'app.schema_compatibility_v25()'::regprocedure,
       'EXECUTE'
     ) THEN
    RETURN false;
  END IF;

  SELECT compatibility.applied_count INTO current_count
  FROM app.schema_compatibility_v27() AS compatibility;
  SELECT compatibility.applied_count INTO predecessor_count
  FROM app.schema_compatibility_v26() AS compatibility;
  SELECT compatibility.applied_count INTO retired_count
  FROM app.schema_compatibility_v25() AS compatibility;
  RETURN current_count = 135 AND predecessor_count = 126
    AND retired_count = 0;
END;
$function$;
ALTER FUNCTION app.federated_authentication_schema_readiness_v1()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.federated_authentication_schema_readiness_v1()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,
  periapsis_sla_api_owner, periapsis_sla_worker_owner,
  periapsis_sla_readiness_owner;
GRANT EXECUTE ON FUNCTION app.federated_authentication_schema_readiness_v1()
  TO periapsis_api;
--> statement-breakpoint

-- Compatibility advancement must not make the already-published identity
-- readiness surfaces report false while their structural contract remains live.
CREATE OR REPLACE FUNCTION app.identity_mfa_device_management_readiness_v1()
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
  projection_definition text;
  revoke_definition text;
  current_count bigint;
  predecessor_count bigint;
  retired_count bigint;
BEGIN
  FOREACH relation_name IN ARRAY ARRAY[
    'tenant_mfa_subjects',
    'tenant_totp_factors',
    'tenant_webauthn_credentials',
    'tenant_webauthn_credential_transports',
    'auth_session_mfa_states',
    'auth_session_mfa_evidence',
    'auth_session_passkey_provenance'
  ] LOOP
    IF NOT EXISTS (
      SELECT 1
      FROM pg_class AS class
      JOIN pg_namespace AS namespace ON namespace.oid = class.relnamespace
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

  FOR expected_function IN
    SELECT * FROM (VALUES
      ('app.private_mfa_device_authority_v1(uuid,uuid,uuid,timestamp with time zone,boolean)', true, false),
      ('app.private_mfa_device_projection_v1(text,uuid)', true, false),
      ('app.private_mfa_append_device_audit_v1(uuid,uuid,text,text,text,uuid,timestamp with time zone,integer)', true, false),
      ('app.list_my_mfa_devices_v1(uuid,text,uuid,integer,boolean)', true, true),
      ('app.rename_my_passkey_v1(jsonb)', true, true),
      ('app.revoke_my_mfa_device_v1(jsonb)', true, true)
    ) AS expected(signature, security_definer, api_execute)
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
       OR function_security_definer
          IS DISTINCT FROM expected_function.security_definer
       OR function_configuration[1] NOT LIKE 'search_path=pg_catalog%'
       OR has_function_privilege('periapsis_api', function_oid, 'EXECUTE')
          IS DISTINCT FROM expected_function.api_execute
       OR has_function_privilege('periapsis_worker', function_oid, 'EXECUTE')
       OR has_function_privilege('periapsis_notifier', function_oid, 'EXECUTE')
       OR has_function_privilege('periapsis_auditor', function_oid, 'EXECUTE')
       OR EXISTS (
         SELECT 1
         FROM aclexplode(
           coalesce(
             (SELECT procedure.proacl FROM pg_proc AS procedure
              WHERE procedure.oid = function_oid),
             acldefault('f',
               (SELECT procedure.proowner FROM pg_proc AS procedure
                WHERE procedure.oid = function_oid))
           )
         ) AS privilege
         WHERE privilege.grantee = 0
           AND privilege.privilege_type = 'EXECUTE'
       ) THEN
      RETURN false;
    END IF;
  END LOOP;

  SELECT pg_get_functiondef(
    'app.private_mfa_device_projection_v1(text,uuid)'::regprocedure
  ) INTO projection_definition;
  IF projection_definition ~* '(secret_envelope|public_key|aaguid|sign_count|user_handle_digest|key_version|last_accepted_counter)'
     OR projection_definition NOT LIKE '%displayName%'
     OR projection_definition NOT LIKE '%transports%' THEN
    RETURN false;
  END IF;
  SELECT pg_get_functiondef(
    'app.revoke_my_mfa_device_v1(jsonb)'::regprocedure
  ) INTO revoke_definition;
  IF revoke_definition NOT LIKE '%mfa_device_revoked%'
     OR revoke_definition NOT LIKE '%auth_session_passkey_provenance%'
     OR revoke_definition NOT LIKE '%auth_session_mfa_evidence%'
     OR revoke_definition NOT LIKE '%private_mfa_append_device_audit_v1%'
     OR revoke_definition LIKE '%secret_envelope%' THEN
    RETURN false;
  END IF;

  IF NOT has_function_privilege(
       'periapsis_api', 'app.schema_compatibility_v27()'::regprocedure,
       'EXECUTE'
     ) OR NOT has_function_privilege(
       'periapsis_worker', 'app.schema_compatibility_v27()'::regprocedure,
       'EXECUTE'
     ) OR NOT has_function_privilege(
       'periapsis_api', 'app.schema_compatibility_v26()'::regprocedure,
       'EXECUTE'
     ) OR NOT has_function_privilege(
       'periapsis_worker', 'app.schema_compatibility_v26()'::regprocedure,
       'EXECUTE'
     ) OR has_function_privilege(
       'periapsis_api', 'app.schema_compatibility_v25()'::regprocedure,
       'EXECUTE'
     ) OR has_function_privilege(
       'periapsis_worker', 'app.schema_compatibility_v25()'::regprocedure,
       'EXECUTE'
     ) THEN
    RETURN false;
  END IF;

  SELECT compatibility.applied_count INTO current_count
  FROM app.schema_compatibility_v27() AS compatibility;
  SELECT compatibility.applied_count INTO predecessor_count
  FROM app.schema_compatibility_v26() AS compatibility;
  SELECT compatibility.applied_count INTO retired_count
  FROM app.schema_compatibility_v25() AS compatibility;
  RETURN current_count = 135 AND predecessor_count = 126
    AND retired_count = 0;
END;
$function$;
ALTER FUNCTION app.identity_mfa_device_management_readiness_v1()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.identity_mfa_device_management_readiness_v1()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,
  periapsis_sla_api_owner, periapsis_sla_worker_owner,
  periapsis_sla_readiness_owner;
GRANT EXECUTE ON FUNCTION app.identity_mfa_device_management_readiness_v1()
TO periapsis_api;
--> statement-breakpoint

-- Keep the original identity MFA readiness contract live as compatibility
-- advances. Its structural checks remain intact and the device-management
-- public surface is included rather than being hidden behind a retired v24
-- projection.
CREATE OR REPLACE FUNCTION app.identity_mfa_schema_readiness_v1()
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
      ('app.complete_mfa_passkey_authentication_v1(jsonb)'),
      ('app.list_my_mfa_devices_v1(uuid,text,uuid,integer,boolean)'),
      ('app.rename_my_passkey_v1(jsonb)'),
      ('app.revoke_my_mfa_device_v1(jsonb)')
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
  FROM app.schema_compatibility_v27() AS compatibility;
  SELECT compatibility.applied_count INTO predecessor_count
  FROM app.schema_compatibility_v26() AS compatibility;
  SELECT compatibility.applied_count INTO retired_count
  FROM app.schema_compatibility_v25() AS compatibility;
  RETURN current_count = 135 AND predecessor_count = 126
    AND retired_count = 0
    AND app.identity_mfa_device_management_readiness_v1();
END;
$function$;
ALTER FUNCTION app.identity_mfa_schema_readiness_v1()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.identity_mfa_schema_readiness_v1()
FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor,
  periapsis_audit_reader_owner, periapsis_notification_dispatch_owner,
  periapsis_sla_api_owner, periapsis_sla_worker_owner,
  periapsis_sla_readiness_owner;
GRANT EXECUTE ON FUNCTION app.identity_mfa_schema_readiness_v1()
TO periapsis_api;
