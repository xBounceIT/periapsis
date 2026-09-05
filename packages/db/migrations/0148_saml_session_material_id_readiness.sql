-- V31 seals immutable SAML material identities. V30 is the exact rolling
-- predecessor; V29 is retired.
CREATE FUNCTION app.schema_compatibility_v31()
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
             WHERE migration.created_at = 1787756689913
           )::bigint
    FROM drizzle.__drizzle_migrations AS migration
  $query$ INTO journal_count, journal_latest_created_at, latest_rows;
  IF journal_count = 150
     AND journal_latest_created_at = 1787756689913
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
ALTER FUNCTION app.schema_compatibility_v31()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.schema_compatibility_v31()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,
  periapsis_sla_api_owner, periapsis_sla_worker_owner,
  periapsis_sla_readiness_owner, periapsis_ticket_saved_view_owner,
  periapsis_ticket_attribution_owner,
  periapsis_ticket_sla_projection_owner;
GRANT EXECUTE ON FUNCTION app.schema_compatibility_v31()
TO periapsis_api, periapsis_worker;
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.schema_compatibility_v30()
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
  FROM app.schema_compatibility_v31() AS compatibility;
  IF full_count = 150
     AND full_latest_created_at = 1787756689913
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
              WHERE prefix.migration_ordinal = 142),
             string_agg(
               migration.created_at::text || '@' || migration.migration_hash,
               ':' ORDER BY migration.created_at, migration.id
             )
      FROM ordered_migrations AS migration
      WHERE migration.migration_ordinal <= 142
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
AS $function$
BEGIN
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
  IF p_expected_count IS DISTINCT FROM 150
     OR p_expected_latest_created_at IS DISTINCT FROM 1787756689913
     OR p_expected_latest_hash IS NULL
     OR p_expected_latest_hash !~ '^[0-9a-f]{64}$'
     OR p_expected_migration_fingerprint IS NULL
     OR p_expected_migration_fingerprint !~
          '^[1-9][0-9]*@[0-9a-f]{64}(:[1-9][0-9]*@[0-9a-f]{64})*$'
     OR cardinality(fingerprint_entries) IS DISTINCT FROM 150
     OR fingerprint_entries[150] IS DISTINCT FROM (
       p_expected_latest_created_at::text || '@' || p_expected_latest_hash
     ) THEN
    RAISE EXCEPTION 'invalid schema compatibility v31 manifest'
      USING ERRCODE = '22023';
  END IF;
  SELECT array_agg(
    split_part(entry.value, '@', 1)::bigint ORDER BY entry.ordinality
  ) INTO appended_created_at
  FROM unnest(fingerprint_entries[143:150]) WITH ORDINALITY
       AS entry(value, ordinality);
  IF appended_created_at IS DISTINCT FROM ARRAY[
       1787751875723, 1787752062111, 1787752076413,
       1787752129946, 1787753338492, 1787753339492,
       1787753340492, 1787756689913
     ]::bigint[] THEN
    RAISE EXCEPTION 'invalid schema compatibility v31 appended sequence'
      USING ERRCODE = '22023';
  END IF;

  SELECT compatibility.applied_count, compatibility.latest_created_at,
         compatibility.latest_hash, compatibility.migration_fingerprint
  INTO actual_count, actual_latest_created_at, actual_latest_hash,
       actual_fingerprint
  FROM app.schema_compatibility_v31() AS compatibility;
  IF actual_count IS DISTINCT FROM p_expected_count
     OR actual_latest_created_at IS DISTINCT FROM p_expected_latest_created_at
     OR actual_latest_hash IS DISTINCT FROM p_expected_latest_hash
     OR actual_fingerprint IS DISTINCT FROM p_expected_migration_fingerprint THEN
    RAISE EXCEPTION 'schema compatibility v31 manifest does not match the journal'
      USING ERRCODE = '55000';
  END IF;

  PERFORM set_config(
    'app.schema_compatibility_fingerprint',
    p_expected_migration_fingerprint, true
  );
  EXECUTE $statement$
    ALTER FUNCTION app.schema_compatibility_v30()
      SET app.schema_compatibility_fingerprint FROM CURRENT
  $statement$;
  expected_predecessor_fingerprint := array_to_string(
    fingerprint_entries[1:142], ':'
  );
  SELECT compatibility.applied_count, compatibility.latest_created_at,
         compatibility.latest_hash, compatibility.migration_fingerprint
  INTO predecessor_count, predecessor_latest_created_at,
       predecessor_latest_hash, predecessor_fingerprint
  FROM app.schema_compatibility_v30() AS compatibility;
  IF predecessor_count IS DISTINCT FROM 142
     OR predecessor_latest_created_at IS DISTINCT FROM 1787747400262
     OR predecessor_latest_hash IS DISTINCT FROM
          'd7db1d274a73068b9152b822082f8752d4fc30e9ddb675904cba1ce1b6cba40c'
     OR predecessor_fingerprint IS DISTINCT FROM
          expected_predecessor_fingerprint THEN
    RAISE EXCEPTION 'sealed schema compatibility v30 prefix is not exact'
      USING ERRCODE = '55000';
  END IF;
  SELECT compatibility.applied_count INTO retired_count
  FROM app.schema_compatibility_v29() AS compatibility;
  IF retired_count IS DISTINCT FROM 0
     OR NOT has_function_privilege(
       'periapsis_api', 'app.schema_compatibility_v31()'::regprocedure,
       'EXECUTE'
     )
     OR NOT has_function_privilege(
       'periapsis_worker', 'app.schema_compatibility_v31()'::regprocedure,
       'EXECUTE'
     )
     OR NOT has_function_privilege(
       'periapsis_api', 'app.schema_compatibility_v30()'::regprocedure,
       'EXECUTE'
     )
     OR NOT has_function_privilege(
       'periapsis_worker', 'app.schema_compatibility_v30()'::regprocedure,
       'EXECUTE'
     )
     OR has_function_privilege(
       'periapsis_api', 'app.schema_compatibility_v29()'::regprocedure,
       'EXECUTE'
     )
     OR has_function_privilege(
       'periapsis_worker', 'app.schema_compatibility_v29()'::regprocedure,
       'EXECUTE'
     ) THEN
    RAISE EXCEPTION 'schema compatibility v29 remains active'
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

CREATE FUNCTION app.private_saml_session_material_id_readiness_v1()
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  expected_function record;
  function_oid regprocedure;
  function_owner text;
  function_security_definer boolean;
  function_configuration text[];
  function_definition text;
  expected_trigger record;
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_class AS relation
    JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
    WHERE namespace.nspname = 'public'
      AND relation.relname = 'tenant_saml_logout_commands'
      AND relation.relkind = 'r'
      AND pg_get_userbyid(relation.relowner) = 'periapsis_migrator'
      AND relation.relrowsecurity AND relation.relforcerowsecurity
  ) OR EXISTS (
    SELECT 1
    FROM pg_policy AS policy
    WHERE policy.polrelid = 'public.tenant_saml_logout_commands'::regclass
  ) OR EXISTS (
    SELECT 1
    FROM pg_class AS relation
    CROSS JOIN LATERAL aclexplode(
      coalesce(relation.relacl, acldefault('r', relation.relowner))
    ) AS privilege
    WHERE relation.oid = 'public.tenant_saml_logout_commands'::regclass
      AND privilege.grantee <> relation.relowner
  ) OR EXISTS (
    SELECT 1
    FROM pg_attribute AS attribute
    JOIN pg_class AS relation ON relation.oid = attribute.attrelid
    CROSS JOIN LATERAL aclexplode(attribute.attacl) AS privilege
    WHERE attribute.attrelid =
            'public.tenant_saml_logout_commands'::regclass
      AND attribute.attnum > 0
      AND NOT attribute.attisdropped
      AND attribute.attacl IS NOT NULL
      AND privilege.grantee <> relation.relowner
  ) OR has_table_privilege(
    'periapsis_api', 'public.tenant_saml_logout_commands',
    'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
  ) OR has_table_privilege(
    'periapsis_worker', 'public.tenant_saml_logout_commands',
    'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
  ) OR has_table_privilege(
    'periapsis_notifier', 'public.tenant_saml_logout_commands',
    'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
  ) OR has_table_privilege(
    'periapsis_auditor', 'public.tenant_saml_logout_commands',
    'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
  ) THEN
    RETURN false;
  END IF;

  IF EXISTS (
    SELECT 1
    FROM pg_attribute AS attribute
    WHERE attribute.attrelid = 'public.tenant_saml_session_materials'::regclass
      AND attribute.attname IN ('id','aad_version')
      AND NOT attribute.attisdropped
      AND attribute.atthasdef
  ) OR NOT EXISTS (
    SELECT 1 FROM pg_attribute AS attribute
    WHERE attribute.attrelid = 'public.tenant_saml_session_materials'::regclass
      AND attribute.attname = 'aad_version'
      AND NOT attribute.attisdropped AND attribute.attnotnull
      AND attribute.atttypid = 'integer'::regtype
  ) OR EXISTS (
    SELECT 1 FROM pg_attribute AS attribute
    WHERE attribute.attrelid = 'public.tenant_saml_session_materials'::regclass
      AND attribute.attname IN ('key_version','ciphertext')
      AND NOT attribute.attisdropped AND attribute.attnotnull
  ) OR NOT EXISTS (
    SELECT 1 FROM pg_constraint AS constraint_record
    WHERE constraint_record.conrelid =
            'public.tenant_saml_session_materials'::regclass
      AND constraint_record.conname =
            'tenant_saml_session_materials_tenant_id_key'
      AND constraint_record.contype = 'u'
  ) OR NOT EXISTS (
    SELECT 1 FROM pg_constraint AS constraint_record
    WHERE constraint_record.conrelid =
            'public.tenant_federated_authentication_transactions'::regclass
      AND constraint_record.conname =
            'tenant_federated_authentication_transactions_tenant_operation_key'
      AND constraint_record.contype = 'u'
  ) OR NOT EXISTS (
    SELECT 1 FROM pg_constraint AS constraint_record
    WHERE constraint_record.conrelid =
            'public.tenant_saml_logout_commands'::regclass
      AND constraint_record.conname =
            'tenant_saml_logout_commands_material_transaction_fk'
      AND constraint_record.contype = 'f'
      AND constraint_record.confrelid =
            'public.tenant_federated_authentication_transactions'::regclass
  ) OR NOT EXISTS (
    SELECT 1 FROM pg_constraint AS constraint_record
    WHERE constraint_record.conrelid =
            'public.tenant_saml_logout_commands'::regclass
      AND constraint_record.conname =
            'tenant_saml_logout_commands_material_fk'
      AND constraint_record.contype = 'f'
      AND constraint_record.confrelid =
            'public.tenant_saml_session_materials'::regclass
      AND pg_get_constraintdef(constraint_record.oid) =
            'FOREIGN KEY (tenant_id, material_id) REFERENCES tenant_saml_session_materials(tenant_id, id) ON UPDATE CASCADE ON DELETE RESTRICT'
  ) OR NOT EXISTS (
    SELECT 1 FROM pg_constraint AS constraint_record
    WHERE constraint_record.conrelid =
            'public.tenant_saml_session_materials'::regclass
      AND constraint_record.conname =
            'tenant_saml_session_materials_value_check'
      AND pg_get_constraintdef(constraint_record.oid)
            LIKE '%aad_version%ANY (ARRAY[1, 2])%'
      AND pg_get_constraintdef(constraint_record.oid)
            LIKE '%(key_version IS NULL) = (ciphertext IS NULL)%'
  ) THEN
    RETURN false;
  END IF;

  FOR expected_trigger IN
    SELECT * FROM (VALUES
      (
        'tenant_saml_logout_commands_immutable_v1',
        'public.tenant_saml_logout_commands',
        'app.guard_federated_immutable_ledger_v1()',
        27
      ),
      (
        'tenant_saml_session_materials_v2_guard',
        'public.tenant_saml_session_materials',
        'app.guard_saml_session_material_v2()',
        23
      ),
      (
        'tenant_post_primary_continuations_federated_provenance_v1',
        'public.tenant_post_primary_continuations',
        'app.validate_federated_continuation_provenance_v1()',
        23
      )
    ) AS expected(name, relation_name, function_name, trigger_type)
  LOOP
    IF NOT EXISTS (
      SELECT 1 FROM pg_trigger AS trigger
      WHERE trigger.tgname = expected_trigger.name
        AND trigger.tgrelid = expected_trigger.relation_name::regclass
        AND trigger.tgfoid = expected_trigger.function_name::regprocedure
        AND trigger.tgtype = expected_trigger.trigger_type::smallint
        AND trigger.tgqual IS NULL
        AND trigger.tgnargs = 0
        AND NOT trigger.tgisinternal
        AND trigger.tgenabled = 'O'
    ) THEN
      RETURN false;
    END IF;
  END LOOP;

  FOR expected_function IN
    SELECT * FROM (VALUES
      ('app.lookup_saml_authentication_transaction_v1(jsonb)', true),
      ('app.apply_federated_authentication_v1(jsonb)', true),
      ('app.revoke_local_saml_session_v1(uuid,jsonb)', true),
      ('app.private_federated_issue_authority_v1(jsonb,uuid,uuid,uuid,bigint,bigint,bigint,uuid,uuid,auth_provider_kind,bigint,timestamp with time zone,bytea)', false),
      ('app.private_saml_logout_configuration_record_v1(uuid,uuid,uuid)', false),
      ('app.guard_saml_session_material_v2()', false),
      ('app.private_lookup_saml_authentication_transaction_v30(jsonb)', false),
      ('app.private_apply_federated_authentication_v30(jsonb)', false),
      ('app.private_federated_issue_authority_v30(jsonb,uuid,uuid,uuid,bigint,bigint,bigint,uuid,uuid,auth_provider_kind,bigint,timestamp with time zone,bytea)', false)
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
         FROM pg_proc AS procedure
         CROSS JOIN LATERAL aclexplode(
           coalesce(procedure.proacl, acldefault('f', procedure.proowner))
         ) AS privilege
         WHERE procedure.oid = function_oid
           AND privilege.privilege_type = 'EXECUTE'
           AND privilege.grantee <> procedure.proowner
           AND NOT (
             expected_function.api_execute
             AND privilege.grantee = 'periapsis_api'::regrole
             AND NOT privilege.is_grantable
           )
       ) THEN
      RETURN false;
    END IF;
  END LOOP;

  IF (
    SELECT count(*) FROM pg_proc AS procedure
    JOIN pg_namespace AS namespace ON namespace.oid = procedure.pronamespace
    WHERE namespace.nspname = 'app'
      AND procedure.proname IN (
        'lookup_saml_authentication_transaction_v1',
        'apply_federated_authentication_v1',
        'revoke_local_saml_session_v1'
      )
  ) IS DISTINCT FROM 3 THEN
    RETURN false;
  END IF;

  SELECT pg_get_functiondef(
    'app.lookup_saml_authentication_transaction_v1(jsonb)'::regprocedure
  ) INTO function_definition;
  IF function_definition NOT LIKE '%operation_run_id%'
     OR function_definition NOT LIKE '%materialId%' THEN
    RETURN false;
  END IF;
  SELECT pg_get_functiondef(
    'app.apply_federated_authentication_v1(jsonb)'::regprocedure
  ) INTO function_definition;
  IF function_definition NOT LIKE '%private_apply_federated_authentication_v30%'
     OR function_definition NOT LIKE '%request_snapshot%'
     OR function_definition NOT LIKE '%materialId%'
     OR function_definition NOT LIKE '%samlSession,keyVersion%'
     OR function_definition NOT LIKE '%samlSession,ciphertext%'
     OR function_definition LIKE
          '%request_snapshot IS DISTINCT FROM v_apply%' THEN
    RETURN false;
  END IF;
  SELECT pg_get_functiondef(
    'app.private_federated_issue_authority_v1(jsonb,uuid,uuid,uuid,bigint,bigint,bigint,uuid,uuid,auth_provider_kind,bigint,timestamp with time zone,bytea)'::regprocedure
  ) INTO function_definition;
  IF function_definition NOT LIKE '%operation_run_id = v_material_id%'
     OR function_definition NOT LIKE '%aad_version%'
     OR (
       function_definition NOT LIKE '%v_material_key_version%'
       AND function_definition NOT LIKE '%v_key_version%'
     )
     OR function_definition NOT LIKE '%v_key_version, v_ciphertext%'
     OR function_definition LIKE '%uuidv7(), p_tenant_id%' THEN
    RETURN false;
  END IF;
  SELECT pg_get_functiondef(
    'app.apply_federated_session_revalidation_v1(jsonb)'::regprocedure
  ) INTO function_definition;
  IF function_definition LIKE
       '%INSERT INTO public.tenant_saml_session_materials%'
     OR function_definition NOT LIKE
       '%SET session_id = NULL, continuation_id = v_continuation_id%'
     OR function_definition NOT LIKE '%aad_version = 2%'
     OR function_definition NOT LIKE
          '%SAML session material ownership is stale%' THEN
    RETURN false;
  END IF;
  SELECT pg_get_functiondef(
    'app.private_mfa_apply_federated_session_v1(jsonb,uuid,text,uuid,bigint,timestamp with time zone)'::regprocedure
  ) INTO function_definition;
  IF function_definition NOT LIKE '%aad_version = 2%'
     OR function_definition NOT LIKE
          '%SAML session material ownership is stale%' THEN
    RETURN false;
  END IF;
  SELECT pg_get_functiondef(
    'app.revoke_local_saml_session_v1(uuid,jsonb)'::regprocedure
  ) INTO function_definition;
  IF function_definition NOT LIKE '%tenant_saml_logout_commands%'
     OR function_definition NOT LIKE '%FOR UPDATE%'
     OR function_definition NOT LIKE '%session_version%'
     OR function_definition NOT LIKE '%saml_local_logout%'
     OR function_definition NOT LIKE '%authenticatedUserId%'
     OR function_definition NOT LIKE '%session.user_id = p_user_id%'
     OR function_definition NOT LIKE '%membership.status = ''active''%'
     OR function_definition NOT LIKE
          '%current_setting(''app.tenant_id'', true)%'
     OR function_definition NOT LIKE
          '%current_setting(''app.user_id'', true)%'
     OR function_definition NOT LIKE
          '%WHEN NOT v_request_upstream OR v_material.key_version IS NULL THEN NULL%'
     OR function_definition LIKE '%set_config(''app.user_id''%'
     OR function_definition LIKE '%name_id%'
     OR function_definition LIKE '%session_index%plaintext%' THEN
    RETURN false;
  END IF;

  IF EXISTS (
    SELECT 1
    FROM public.tenant_saml_session_materials AS material
    LEFT JOIN public.auth_sessions AS session
      ON session.id = material.session_id
     AND session.active_tenant_id = material.tenant_id
    WHERE material.aad_version = 1
      AND material.session_id IS NOT NULL
      AND (session.id IS NULL OR session.revoked_at IS NULL)
  ) OR EXISTS (
    SELECT 1
    FROM public.auth_sessions AS session
    JOIN public.auth_session_federated_provenance AS provenance
      ON provenance.tenant_id = session.active_tenant_id
     AND provenance.session_id = session.id
     AND provenance.user_id = session.user_id
     AND provenance.primary_kind = 'tenant_provider'
     AND provenance.authentication_method = 'saml'
     AND provenance.provider_kind = 'saml'
    WHERE session.authentication_method = 'saml'
      AND session.revoked_at IS NULL
      AND (
        SELECT count(*)
        FROM public.tenant_saml_session_materials AS material
        WHERE material.tenant_id = session.active_tenant_id
          AND material.session_id = session.id
          AND material.continuation_id IS NULL
          AND material.user_id = session.user_id
          AND material.provider_id = provenance.provider_id
          AND material.binding_id = provenance.binding_id
          AND material.external_identity_id = provenance.external_identity_id
          AND material.aad_version = 2
      ) IS DISTINCT FROM 1::bigint
  ) OR EXISTS (
    SELECT 1
    FROM public.tenant_post_primary_continuations AS continuation
    WHERE continuation.primary_kind = 'tenant_provider'
      AND continuation.provider_kind = 'saml'
      AND continuation.state = 'pending'
      AND (
        SELECT count(*)
        FROM public.tenant_saml_session_materials AS material
        WHERE material.tenant_id = continuation.tenant_id
          AND material.session_id IS NULL
          AND material.continuation_id = continuation.id
          AND material.user_id = continuation.user_id
          AND material.provider_id = continuation.provider_id
          AND material.binding_id = continuation.binding_id
          AND material.external_identity_id = continuation.external_identity_id
          AND material.aad_version = 2
      ) IS DISTINCT FROM 1::bigint
  ) OR EXISTS (
    SELECT 1
    FROM public.tenant_saml_session_materials AS material
    LEFT JOIN public.tenant_post_primary_continuations AS continuation
      ON continuation.tenant_id = material.tenant_id
     AND continuation.id = material.continuation_id
    WHERE material.aad_version = 1
      AND material.continuation_id IS NOT NULL
      AND (continuation.id IS NULL OR continuation.state = 'pending')
  ) OR EXISTS (
    SELECT 1
    FROM public.tenant_saml_session_materials AS material
    LEFT JOIN public.tenant_federated_authentication_transactions AS transaction
      ON transaction.tenant_id = material.tenant_id
     AND transaction.operation_run_id = material.id
     AND transaction.protocol = 'saml'
     AND transaction.provider_id = material.provider_id
     AND transaction.binding_id = material.binding_id
     AND transaction.state = 'completed'
    LEFT JOIN public.tenant_federated_authentication_applications AS application
      ON application.tenant_id = material.tenant_id
     AND application.protocol = 'saml'
     AND application.transaction_id = transaction.transaction_id
     AND application.category = 'success'
     AND application.user_id = material.user_id
     AND application.provider_id = material.provider_id
     AND application.binding_id = material.binding_id
     AND application.request_snapshot -> 'samlSession' ->> 'materialId'
           = material.id::text
    WHERE material.aad_version = 2
      AND (transaction.transaction_id IS NULL OR application.id IS NULL)
  ) THEN
    RETURN false;
  END IF;
  RETURN true;
END;
$function$;
ALTER FUNCTION app.private_saml_session_material_id_readiness_v1()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_saml_session_material_id_readiness_v1()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,
  periapsis_sla_api_owner, periapsis_sla_worker_owner,
  periapsis_sla_readiness_owner, periapsis_ticket_saved_view_owner,
  periapsis_ticket_attribution_owner,
  periapsis_ticket_sla_projection_owner;
--> statement-breakpoint

-- Advance every published readiness surface in lockstep. Federation also
-- replaces the predecessor apply-source assertion with the semantic replay
-- wrapper and requires the new material boundary.
DO $migration$
DECLARE
  readiness_function regprocedure;
  original_definition text;
  rewritten_definition text;
  old_apply_check text := $old$  IF function_definition NOT LIKE '%private_federated_apply_identity_v1%'
     OR function_definition NOT LIKE '%tenant_federated_authentication_applications%'
     OR function_definition NOT LIKE '%FOR UPDATE%'
     OR function_definition LIKE '%secret_material_included'', true%' THEN
    RETURN false;
  END IF;$old$;
  new_apply_check text := $new$  IF function_definition NOT LIKE '%private_apply_federated_authentication_v30%'
     OR function_definition NOT LIKE '%request_snapshot%'
     OR function_definition NOT LIKE '%materialId%'
     OR function_definition NOT LIKE '%samlSession,keyVersion%'
     OR function_definition NOT LIKE '%samlSession,ciphertext%' THEN
    RETURN false;
  END IF;$new$;
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
    IF original_definition NOT LIKE '%app.schema_compatibility_v30()%'
       OR original_definition NOT LIKE '%app.schema_compatibility_v29()%'
       OR original_definition NOT LIKE '%app.schema_compatibility_v28()%'
       OR original_definition NOT LIKE
            '%current_count = 142 AND predecessor_count = 139%' THEN
      RAISE EXCEPTION 'unexpected v30 readiness definition: %',
        readiness_function::text USING ERRCODE = '55000';
    END IF;
    rewritten_definition := replace(
      original_definition,
      'app.schema_compatibility_v30()',
      'app.schema_compatibility_v31()'
    );
    rewritten_definition := replace(
      rewritten_definition,
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
      'current_count = 142 AND predecessor_count = 139',
      'current_count = 150 AND predecessor_count = 142'
    );
    IF readiness_function =
         'app.federated_authentication_schema_readiness_v1()'::regprocedure THEN
      IF strpos(rewritten_definition, old_apply_check) = 0 THEN
        RAISE EXCEPTION 'unexpected federation apply readiness definition'
          USING ERRCODE = '55000';
      END IF;
      rewritten_definition := replace(
        rewritten_definition, old_apply_check, new_apply_check
      );
      rewritten_definition := replace(
        rewritten_definition,
        'RETURN current_count = 150 AND predecessor_count = 142
    AND retired_count = 0;',
        'RETURN current_count = 150 AND predecessor_count = 142
    AND retired_count = 0
    AND app.private_saml_session_material_id_readiness_v1();'
      );
    END IF;
    IF rewritten_definition IS NOT DISTINCT FROM original_definition
       OR rewritten_definition NOT LIKE '%app.schema_compatibility_v31()%'
       OR rewritten_definition LIKE '%app.schema_compatibility_v28()%'
       OR rewritten_definition NOT LIKE
            '%current_count = 150 AND predecessor_count = 142%' THEN
      RAISE EXCEPTION 'failed to rebind readiness definition: %',
        readiness_function::text USING ERRCODE = '55000';
    END IF;
    IF readiness_function =
         'app.federated_authentication_schema_readiness_v1()'::regprocedure
       AND rewritten_definition NOT LIKE
         '%private_saml_session_material_id_readiness_v1()%' THEN
      RAISE EXCEPTION 'failed to bind SAML material readiness'
        USING ERRCODE = '55000';
    END IF;
    EXECUTE rewritten_definition;
  END LOOP;
END;
$migration$;
--> statement-breakpoint

REVOKE ALL ON FUNCTION app.federated_authentication_schema_readiness_v1()
FROM PUBLIC, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,
  periapsis_sla_api_owner, periapsis_sla_worker_owner,
  periapsis_sla_readiness_owner, periapsis_ticket_saved_view_owner,
  periapsis_ticket_attribution_owner,
  periapsis_ticket_sla_projection_owner;
GRANT EXECUTE ON FUNCTION app.federated_authentication_schema_readiness_v1()
TO periapsis_api;
--> statement-breakpoint
