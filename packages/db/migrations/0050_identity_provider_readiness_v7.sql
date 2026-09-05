-- Persisted active-key convergence is part of readiness, not process-local
-- configuration. Installed retained versions may decrypt old data, but only
-- the singleton active version can write new identity ciphertext.
CREATE OR REPLACE FUNCTION app.verify_identity_keyring_v1(
  p_versions integer[],
  p_verifiers bytea[],
  p_active_version integer
)
RETURNS boolean
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  item_count integer;
  item_index integer;
  existing_verifier bytea;
  existing_retired_at timestamp with time zone;
  bound_active_version integer;
BEGIN
  item_count := coalesce(array_length(p_versions, 1), 0);
  IF item_count < 1 OR item_count > 16
     OR coalesce(array_ndims(p_versions), 0) <> 1
     OR coalesce(array_ndims(p_verifiers), 0) <> 1
     OR array_lower(p_versions, 1) <> 1
     OR array_lower(p_verifiers, 1) <> 1
     OR coalesce(array_length(p_verifiers, 1), 0) <> item_count
     OR p_active_version IS NULL
     OR NOT p_active_version = ANY(p_versions) THEN
    RETURN false;
  END IF;

  FOR item_index IN 1..item_count LOOP
    IF p_versions[item_index] IS NULL
       OR p_versions[item_index] NOT BETWEEN 1 AND 32767
       OR p_verifiers[item_index] IS NULL
       OR octet_length(p_verifiers[item_index]) <> 32
       OR (item_index > 1
         AND p_versions[item_index - 1] >= p_versions[item_index]) THEN
      RETURN false;
    END IF;
  END LOOP;
  IF (
    SELECT count(DISTINCT verifier)::integer
    FROM unnest(p_verifiers) AS supplied(verifier)
  ) <> item_count THEN
    RETURN false;
  END IF;

  LOCK TABLE public.identity_keyring_versions IN SHARE ROW EXCLUSIVE MODE;

  FOR item_index IN 1..item_count LOOP
    INSERT INTO public.identity_keyring_versions (
      key_version, verifier, is_active, bound_at
    ) VALUES (
      p_versions[item_index], p_verifiers[item_index], false,
      transaction_timestamp()
    )
    ON CONFLICT DO NOTHING;

    SELECT keyring.verifier, keyring.retired_at
    INTO existing_verifier, existing_retired_at
    FROM public.identity_keyring_versions AS keyring
    WHERE keyring.key_version = p_versions[item_index];

    IF existing_verifier IS DISTINCT FROM p_verifiers[item_index]
       OR existing_retired_at IS NOT NULL THEN
      RETURN false;
    END IF;
  END LOOP;

  IF EXISTS (
    SELECT 1
    FROM public.tenant_ldap_provider_secrets AS secret
    LEFT JOIN public.identity_keyring_versions AS installed_key
      ON installed_key.key_version = secret.key_version
    WHERE NOT secret.key_version = ANY(p_versions)
      OR installed_key.key_version IS NULL
      OR installed_key.retired_at IS NOT NULL
  ) THEN
    RETURN false;
  END IF;

  SELECT keyring.key_version
  INTO bound_active_version
  FROM public.identity_keyring_versions AS keyring
  WHERE keyring.is_active;

  IF bound_active_version IS NULL THEN
    UPDATE public.identity_keyring_versions AS keyring
    SET is_active = true
    WHERE keyring.key_version = p_active_version
      AND keyring.retired_at IS NULL;
    IF NOT FOUND THEN
      RETURN false;
    END IF;
    bound_active_version := p_active_version;
  END IF;

  IF bound_active_version IS DISTINCT FROM p_active_version THEN
    RETURN false;
  END IF;

  RETURN EXISTS (
    SELECT 1
    FROM public.identity_keyring_versions AS active_key
    WHERE active_key.key_version = p_active_version
      AND active_key.is_active
      AND active_key.retired_at IS NULL
      AND active_key.verifier = p_verifiers[
        array_position(p_versions, p_active_version)
      ]
  );
END;
$function$;--> statement-breakpoint

ALTER FUNCTION app.verify_identity_keyring_v1(integer[], bytea[], integer) OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.verify_identity_keyring_v1(integer[], bytea[], integer) FROM PUBLIC, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.verify_identity_keyring_v1(integer[], bytea[], integer) TO periapsis_api, periapsis_worker;--> statement-breakpoint

-- Rotation is a migration-only compare-and-swap. After promotion, a replica
-- configured with the predecessor active version fails verification.
CREATE FUNCTION app.promote_identity_keyring_version_v1(
  p_expected_active_version integer,
  p_next_active_version integer
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  bound_active_version integer;
BEGIN
  IF p_expected_active_version IS NULL
     OR p_next_active_version IS NULL
     OR p_expected_active_version NOT BETWEEN 1 AND 32767
     OR p_next_active_version NOT BETWEEN 1 AND 32767
     OR p_next_active_version <= p_expected_active_version THEN
    RAISE EXCEPTION 'identity key promotion versions are invalid'
      USING ERRCODE = '22023';
  END IF;

  LOCK TABLE public.identity_keyring_versions IN SHARE ROW EXCLUSIVE MODE;
  SELECT keyring.key_version
  INTO bound_active_version
  FROM public.identity_keyring_versions AS keyring
  WHERE keyring.is_active;

  IF bound_active_version IS DISTINCT FROM p_expected_active_version THEN
    RAISE EXCEPTION 'identity key active version does not match'
      USING ERRCODE = '40001';
  END IF;
  IF NOT EXISTS (
    SELECT 1
    FROM public.identity_keyring_versions AS next_key
    WHERE next_key.key_version = p_next_active_version
      AND next_key.retired_at IS NULL
  ) THEN
    RAISE EXCEPTION 'next identity key version is not installed'
      USING ERRCODE = '55000';
  END IF;

  UPDATE public.identity_keyring_versions AS active_key
  SET is_active = false
  WHERE active_key.key_version = p_expected_active_version
    AND active_key.is_active;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'identity key active version changed concurrently'
      USING ERRCODE = '40001';
  END IF;

  UPDATE public.identity_keyring_versions AS next_key
  SET is_active = true
  WHERE next_key.key_version = p_next_active_version
    AND NOT next_key.is_active
    AND next_key.retired_at IS NULL;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'next identity key version changed concurrently'
      USING ERRCODE = '40001';
  END IF;
END;
$function$;--> statement-breakpoint

ALTER FUNCTION app.promote_identity_keyring_version_v1(integer, integer) OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.promote_identity_keyring_version_v1(integer, integer) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.rotate_tenant_ldap_bind_secret_v1(
  p_provider_id uuid,
  p_expected_version integer,
  p_secret_id uuid,
  p_secret_ciphertext bytea,
  p_secret_nonce bytea,
  p_key_version integer,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text
)
RETURNS integer
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  actor_membership uuid;
  locked_provider public.tenant_auth_providers%ROWTYPE;
  existing_secret_id uuid;
  existing_secret_version integer;
  bind_secret_was_configured boolean;
  next_version integer;
BEGIN
  PERFORM app.lock_current_tenant_authorization_state();
  actor_membership := app.current_tenant_membership_id();
  IF NOT app.current_tenant_human_has_exact_permission_v3(
    'identity_provider.manage', 'tenant'
  ) THEN
    RAISE EXCEPTION 'identity_provider.manage tenant scope is required'
      USING ERRCODE = '42501';
  END IF;

  SELECT provider.*
  INTO locked_provider
  FROM public.tenant_auth_providers AS provider
  WHERE provider.tenant_id = context_tenant
    AND provider.id = p_provider_id
    AND provider.kind = 'ldap'
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant LDAP provider was not found'
      USING ERRCODE = 'P0002';
  END IF;
  IF locked_provider.archived_at IS NOT NULL THEN
    RAISE EXCEPTION 'archived tenant LDAP provider secret cannot be changed'
      USING ERRCODE = '55000';
  END IF;
  IF p_expected_version IS NULL
     OR p_expected_version <> locked_provider.version THEN
    RAISE EXCEPTION 'tenant LDAP provider version does not match'
      USING ERRCODE = '40001';
  END IF;
  IF locked_provider.version >= 2147483647 THEN
    RAISE EXCEPTION 'tenant LDAP provider version is exhausted'
      USING ERRCODE = '55000';
  END IF;
  IF p_secret_id IS NULL
     OR (uuid_extract_version(p_secret_id) = 7) IS NOT TRUE THEN
    RAISE EXCEPTION 'tenant LDAP bind-secret row ID must be UUIDv7'
      USING ERRCODE = '22023';
  END IF;

  PERFORM keyring.key_version
  FROM public.identity_keyring_versions AS keyring
  WHERE keyring.key_version = p_key_version
    AND keyring.is_active
    AND keyring.retired_at IS NULL
  FOR SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'identity key version is not the verified active version'
      USING ERRCODE = '55000';
  END IF;

  SELECT secret.id, secret.version
  INTO existing_secret_id, existing_secret_version
  FROM public.tenant_ldap_provider_secrets AS secret
  WHERE secret.tenant_id = context_tenant
    AND secret.provider_id = p_provider_id
  FOR UPDATE;
  bind_secret_was_configured := FOUND;
  IF bind_secret_was_configured THEN
    IF existing_secret_id <> p_secret_id THEN
      RAISE EXCEPTION 'tenant LDAP bind-secret row identity cannot change'
        USING ERRCODE = '55000';
    END IF;
    IF existing_secret_version >= 2147483647 THEN
      RAISE EXCEPTION 'tenant LDAP bind-secret version is exhausted'
        USING ERRCODE = '55000';
    END IF;
  END IF;

  INSERT INTO public.tenant_ldap_provider_secrets (
    id, tenant_id, provider_id, provider_kind, secret_ciphertext,
    secret_nonce, key_version, encryption_algorithm,
    rotated_by_membership_id
  ) VALUES (
    p_secret_id, context_tenant, p_provider_id, 'ldap', p_secret_ciphertext,
    p_secret_nonce, p_key_version, 'aes-256-gcm', actor_membership
  )
  ON CONFLICT (tenant_id, provider_id) DO UPDATE
  SET secret_ciphertext = EXCLUDED.secret_ciphertext,
      secret_nonce = EXCLUDED.secret_nonce,
      key_version = EXCLUDED.key_version,
      encryption_algorithm = EXCLUDED.encryption_algorithm,
      rotated_by_membership_id = EXCLUDED.rotated_by_membership_id,
      rotated_at = transaction_timestamp(),
      version = tenant_ldap_provider_secrets.version + 1,
      updated_at = transaction_timestamp();

  next_version := locked_provider.version + 1;
  UPDATE public.tenant_auth_providers AS provider
  SET updated_by_membership_id = actor_membership,
      version = next_version,
      updated_at = transaction_timestamp()
  WHERE provider.tenant_id = context_tenant
    AND provider.id = p_provider_id;

  PERFORM app.append_tenant_authorization_audit(
    uuidv7(), 'tenant.identity_provider.bind_secret_rotated',
    'identity_provider', p_provider_id, p_request_id, p_correlation_id,
    p_ip_address, p_user_agent, p_authentication_method,
    jsonb_build_object(
      'bind_secret_configured', bind_secret_was_configured,
      'version', locked_provider.version
    ),
    jsonb_build_object(
      'bind_secret_configured', true,
      'key_version', p_key_version,
      'version', next_version
    ),
    '{}'::jsonb
  );

  RETURN next_version;
END;
$function$;--> statement-breakpoint

ALTER FUNCTION app.rotate_tenant_ldap_bind_secret_v1(uuid, integer, uuid, bytea, bytea, integer, uuid, uuid, inet, text, text) OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.rotate_tenant_ldap_bind_secret_v1(uuid, integer, uuid, bytea, bytea, integer, uuid, uuid, inet, text, text) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.rotate_tenant_ldap_bind_secret_v1(uuid, integer, uuid, bytea, bytea, integer, uuid, uuid, inet, text, text) TO periapsis_api;
--> statement-breakpoint

-- Freeze the exact identity-provider foundation before publishing v7.
DO $identity_provider_readiness_assertions$
DECLARE
  expected record;
  function_oid oid;
  actual_source_hash text;
  actual_volatility "char";
  actual_security_definer boolean;
  actual_owner text;
  actual_configuration text[];
  public_can_execute boolean;
  api_can_execute boolean;
  worker_can_execute boolean;
  notifier_can_execute boolean;
  auditor_can_execute boolean;
  relation_name text;
  relation_oid oid;
  runtime_role text;
  table_privilege text;
  column_privilege text;
  expected_permission_keys text[] := ARRAY[
    'identity_mapping.manage',
    'identity_mapping.read',
    'identity_provider.manage',
    'identity_provider.read',
    'identity_provider.test',
    'identity_sync.run'
  ]::text[];
BEGIN
  FOR expected IN
    SELECT *
    FROM (VALUES
      ('app.archive_tenant_ldap_provider_v1(uuid,integer,text,uuid,uuid,inet,text,text)', 'd7d1d408861fbda89cd7b38780fd34795e7f061d7d9bd68e4fe12b260c258daa', 'v'::"char", true, true, false),
      ('app.begin_tenant_ldap_provider_test_v1(uuid,uuid,public.ldap_provider_test_kind,uuid,uuid,inet,text,text)', '593d9e30aaf6807cf812a323b68c43784863013f0e41377213886a2fb66893cb', 'v'::"char", true, true, false),
      ('app.bind_local_login_identifier_v1()', 'c0887f6a7154778f3011e749e418bdf1c62ca70d56a07eb81639675f7f1e0411', 'v'::"char", true, false, false),
      ('app.clear_tenant_ldap_bind_secret_v1(uuid,integer,text,uuid,uuid,inet,text,text)', '7b063d1751f01111d4798bd9a07d77ff2ca2b27f076073546ead5ac121c661fd', 'v'::"char", true, true, false),
      ('app.complete_tenant_ldap_provider_test_v1(uuid,public.ldap_provider_test_outcome,public.ldap_provider_test_category,integer,integer,uuid,uuid,inet,text,text)', '491a220eb3a584986a7fb61ad4ad14eaa42e7f173aa04b559e8bc11f10e8db26', 'v'::"char", true, true, false),
      ('app.create_platform_tenant(uuid,uuid,text,text,text,text,uuid,uuid,uuid,inet,text,text)', '923aa838e410673d02e599dc849825344e8a4b159ee4f214ceb1c0a7fcaa0634', 'v'::"char", true, true, false),
      ('app.create_platform_tenant_identity_profile_compatibility_impl(uuid,uuid,text,text,text,text,uuid,uuid,uuid,inet,text,text)', '6a99f26071467f19834fcc4fb764aa9dd98573113950738f1ad7b05ed06630ed', 'v'::"char", true, false, false),
      ('app.create_tenant_ldap_provider_v1(uuid,bytea,text,text,text,jsonb,jsonb,uuid,uuid,inet,text,text)', '8af1cc7a2fa989681243e0f4dc644b84fbf520212363bd0e076b203b46eabd3e', 'v'::"char", true, true, false),
      ('app.get_local_break_glass_credential(text)', 'e8ef84d23ceddf8fc3de563fb405a1c36b8b2d32745ebe09335ca2af6eada3ab', 's'::"char", true, true, false),
      ('app.get_tenant_ldap_bind_secret_id_v1(uuid)', '7a0a4e22d05bcb274f1ee8b4e5df5a0d488a4438a6661f77f2cedb68bff98ad5', 's'::"char", true, true, false),
      ('app.get_tenant_ldap_provider_v1(uuid)', '8573a70937ffc01fbf10aba7fb2b59f87c85607bb09ca9cd2a33ed3220082c8a', 's'::"char", true, true, false),
      ('app.guard_tenant_authorization_command()', '9b7498b311b1eb389cc9d0b9f779fd8a1111963cb3f81092768f49c5504d6616', 'v'::"char", true, false, false),
      ('app.guard_tenant_ldap_provider_test_run_v1()', '3ed2e85136eaad15c1b9f7d7d313f92529db18d06067c80f6011802252e6ad4f', 'v'::"char", true, false, false),
      ('app.list_tenant_ldap_providers_v1(uuid,boolean,integer)', '86520d3e571afccf6abcd3360dfd9635b30ccfeebac74b07e2785967b014cffa', 's'::"char", true, true, false),
      ('app.private_replace_tenant_ldap_configuration_v1(uuid,uuid,uuid,jsonb,jsonb)', '81843691617b9e7fad64e3145a8c31a746413accec5f15fd021119ca3c1b3573', 'v'::"char", true, false, false),
      ('app.private_seed_tenant_identity_authorization_v1(uuid)', '0f09ef7dabefdaaf0a2e2a05d56e373ba3abf31e7b424a6ee193e610f8c14713', 'v'::"char", true, false, false),
      ('app.promote_identity_keyring_version_v1(integer,integer)', '56becc5271f4fbe5a27ab700748853b98d75d62ffb5d8fa2a9bedd1a47ed495a', 'v'::"char", true, false, false),
      ('app.rotate_tenant_ldap_bind_secret_v1(uuid,integer,uuid,bytea,bytea,integer,uuid,uuid,inet,text,text)', '5c791a30a4696282457ff59cfa45e7d44654b7a5a15b71016a4e315a51d080d8', 'v'::"char", true, true, false),
      ('app.seed_tenant_authorization(uuid,uuid)', '5fd1de7ad11cc2fc817d996d11e974e60ad08175d36354d05138d202999b277d', 'v'::"char", true, false, false),
      ('app.seed_tenant_authorization_identity_provider_compatibility_impl(uuid,uuid)', '8354790a843c2245d94ff59c991604487d605881b658881af56e8df264824f26', 'v'::"char", true, false, false),
      ('app.update_tenant_ldap_provider_v1(uuid,integer,text,text,text,boolean,jsonb,jsonb,uuid,uuid,inet,text,text)', '9f0957c5b265e27c679c28c3e5905abf45423283ae7839abbe4ef556710702a0', 'v'::"char", true, true, false),
      ('app.verify_identity_keyring_v1(integer[],bytea[],integer)', '6d9e2061a4362b9c42c73e45848d4735421f5201beabb606b3ebbfc71bce266e', 'v'::"char", true, true, true)
    ) AS manifest(
      signature, source_hash, volatility, security_definer,
      api_execute, worker_execute
    )
  LOOP
    function_oid := pg_catalog.to_regprocedure(expected.signature);
    IF function_oid IS NULL THEN
      RAISE EXCEPTION 'identity-provider readiness ABI function % is missing',
        expected.signature
        USING ERRCODE = '55000';
    END IF;

    SELECT
      pg_catalog.encode(
        pg_catalog.sha256(
          pg_catalog.convert_to(
            pg_catalog.btrim(
              pg_catalog.regexp_replace(
                procedure.prosrc,
                '[[:space:]]+',
                ' ',
                'g'
              )
            ),
            'UTF8'
          )
        ),
        'hex'
      ),
      procedure.provolatile,
      procedure.prosecdef,
      pg_catalog.pg_get_userbyid(procedure.proowner),
      procedure.proconfig,
      EXISTS (
        SELECT 1
        FROM pg_catalog.aclexplode(
          coalesce(
            procedure.proacl,
            pg_catalog.acldefault('f', procedure.proowner)
          )
        ) AS privilege
        WHERE privilege.grantee = 0
          AND privilege.privilege_type = 'EXECUTE'
      ),
      pg_catalog.has_function_privilege(
        'periapsis_api', procedure.oid, 'EXECUTE'
      ),
      pg_catalog.has_function_privilege(
        'periapsis_worker', procedure.oid, 'EXECUTE'
      ),
      pg_catalog.has_function_privilege(
        'periapsis_notifier', procedure.oid, 'EXECUTE'
      ),
      pg_catalog.has_function_privilege(
        'periapsis_auditor', procedure.oid, 'EXECUTE'
      )
    INTO
      actual_source_hash,
      actual_volatility,
      actual_security_definer,
      actual_owner,
      actual_configuration,
      public_can_execute,
      api_can_execute,
      worker_can_execute,
      notifier_can_execute,
      auditor_can_execute
    FROM pg_catalog.pg_proc AS procedure
    WHERE procedure.oid = function_oid;

    IF actual_source_hash IS DISTINCT FROM expected.source_hash
       OR actual_volatility IS DISTINCT FROM expected.volatility
       OR actual_security_definer IS DISTINCT FROM expected.security_definer
       OR actual_owner IS DISTINCT FROM 'periapsis_migrator'
       OR actual_configuration IS DISTINCT FROM
            ARRAY['search_path=pg_catalog, public, app']::text[]
       OR public_can_execute
       OR api_can_execute IS DISTINCT FROM expected.api_execute
       OR worker_can_execute IS DISTINCT FROM expected.worker_execute
       OR notifier_can_execute
       OR auditor_can_execute THEN
      RAISE EXCEPTION 'identity-provider readiness ABI function % does not match its sealed contract',
        expected.signature
        USING ERRCODE = '55000';
    END IF;
  END LOOP;

  IF (
    SELECT count(*)
    FROM pg_catalog.pg_proc AS procedure
    WHERE procedure.pronamespace = 'app'::pg_catalog.regnamespace
      AND procedure.proname = ANY(ARRAY[
        'archive_tenant_ldap_provider_v1',
        'begin_tenant_ldap_provider_test_v1',
        'bind_local_login_identifier_v1',
        'clear_tenant_ldap_bind_secret_v1',
        'complete_tenant_ldap_provider_test_v1',
        'create_platform_tenant',
        'create_platform_tenant_identity_profile_compatibility_impl',
        'create_tenant_ldap_provider_v1',
        'get_local_break_glass_credential',
        'get_tenant_ldap_bind_secret_id_v1',
        'get_tenant_ldap_provider_v1',
        'guard_tenant_authorization_command',
        'guard_tenant_ldap_provider_test_run_v1',
        'list_tenant_ldap_providers_v1',
        'private_replace_tenant_ldap_configuration_v1',
        'private_seed_tenant_identity_authorization_v1',
        'promote_identity_keyring_version_v1',
        'rotate_tenant_ldap_bind_secret_v1',
        'seed_tenant_authorization',
        'seed_tenant_authorization_identity_provider_compatibility_impl',
        'update_tenant_ldap_provider_v1',
        'verify_identity_keyring_v1'
      ]::text[])
  ) IS DISTINCT FROM 22 OR pg_catalog.to_regprocedure(
    'app.get_tenant_ldap_bind_secret_envelope_v1(uuid)'
  ) IS NOT NULL THEN
    RAISE EXCEPTION 'identity-provider readiness ABI overload surface is not exact'
      USING ERRCODE = '55000';
  END IF;

  FOR expected IN
    SELECT *
    FROM (VALUES
      ('app.archive_tenant_ldap_provider_v1(uuid,integer,text,uuid,uuid,inet,text,text)', 'integer'),
      ('app.bind_local_login_identifier_v1()', 'trigger'),
      ('app.clear_tenant_ldap_bind_secret_v1(uuid,integer,text,uuid,uuid,inet,text,text)', 'integer'),
      ('app.create_platform_tenant(uuid,uuid,text,text,text,text,uuid,uuid,uuid,inet,text,text)', 'TABLE(id uuid, slug text, name text, status tenant_status, timezone text, locale text, version integer, created_at timestamp with time zone, updated_at timestamp with time zone)'),
      ('app.create_platform_tenant_identity_profile_compatibility_impl(uuid,uuid,text,text,text,text,uuid,uuid,uuid,inet,text,text)', 'TABLE(id uuid, slug text, name text, status tenant_status, timezone text, locale text, version integer, created_at timestamp with time zone, updated_at timestamp with time zone)'),
      ('app.create_tenant_ldap_provider_v1(uuid,bytea,text,text,text,jsonb,jsonb,uuid,uuid,inet,text,text)', 'TABLE(provider_id uuid, result_version integer, replayed boolean)'),
      ('app.get_local_break_glass_credential(text)', 'TABLE(user_id uuid, password_phc text, password_algorithm text, password_version integer, must_rotate boolean)'),
      ('app.get_tenant_ldap_bind_secret_id_v1(uuid)', 'uuid'),
      ('app.list_tenant_ldap_providers_v1(uuid,boolean,integer)', 'TABLE(provider_id uuid, provider_key text, display_name text, description text, enabled boolean, template ldap_provider_template, bind_secret_configured boolean, enabled_endpoint_count integer, archived_at timestamp with time zone, version integer, created_at timestamp with time zone, updated_at timestamp with time zone)'),
      ('app.get_tenant_ldap_provider_v1(uuid)', 'TABLE(provider_id uuid, provider_key text, display_name text, description text, enabled boolean, configuration jsonb, endpoints jsonb, bind_secret_configured boolean, bind_secret_rotated_at timestamp with time zone, archived_at timestamp with time zone, archive_reason text, version integer, created_at timestamp with time zone, updated_at timestamp with time zone)'),
      ('app.begin_tenant_ldap_provider_test_v1(uuid,uuid,public.ldap_provider_test_kind,uuid,uuid,inet,text,text)', 'TABLE(test_run_id uuid, provider_id uuid, provider_version integer, configuration_version integer, secret_version integer, configuration jsonb, endpoints jsonb, secret_id uuid, secret_ciphertext bytea, secret_nonce bytea, secret_key_version integer, encryption_algorithm text, started_at timestamp with time zone)'),
      ('app.complete_tenant_ldap_provider_test_v1(uuid,public.ldap_provider_test_outcome,public.ldap_provider_test_category,integer,integer,uuid,uuid,inet,text,text)', 'TABLE(test_run_id uuid, outcome ldap_provider_test_outcome, category ldap_provider_test_category, endpoint_priority integer, duration_ms integer, stale boolean, completed_at timestamp with time zone)'),
      ('app.guard_tenant_authorization_command()', 'trigger'),
      ('app.guard_tenant_ldap_provider_test_run_v1()', 'trigger'),
      ('app.private_replace_tenant_ldap_configuration_v1(uuid,uuid,uuid,jsonb,jsonb)', 'void'),
      ('app.private_seed_tenant_identity_authorization_v1(uuid)', 'void'),
      ('app.promote_identity_keyring_version_v1(integer,integer)', 'void'),
      ('app.rotate_tenant_ldap_bind_secret_v1(uuid,integer,uuid,bytea,bytea,integer,uuid,uuid,inet,text,text)', 'integer'),
      ('app.seed_tenant_authorization(uuid,uuid)', 'void'),
      ('app.seed_tenant_authorization_identity_provider_compatibility_impl(uuid,uuid)', 'void'),
      ('app.update_tenant_ldap_provider_v1(uuid,integer,text,text,text,boolean,jsonb,jsonb,uuid,uuid,inet,text,text)', 'integer'),
      ('app.verify_identity_keyring_v1(integer[],bytea[],integer)', 'boolean')
    ) AS result_manifest(signature, result_type)
  LOOP
    function_oid := pg_catalog.to_regprocedure(expected.signature);
    IF pg_catalog.pg_get_function_result(function_oid)
         IS DISTINCT FROM expected.result_type THEN
      RAISE EXCEPTION 'identity-provider readiness result ABI % is not exact',
        expected.signature
        USING ERRCODE = '55000';
    END IF;
  END LOOP;

  FOR expected IN
    SELECT *
    FROM (VALUES
      ('auth_provider_kind', ARRAY['ldap', 'oidc', 'saml']::text[]),
      ('identity_deprovision_mode', ARRAY['retain', 'immediate', 'grace']::text[]),
      ('identity_jit_mode', ARRAY['disabled', 'existing_identity', 'create']::text[]),
      ('identity_no_match_policy', ARRAY['deny', 'provider_access_only']::text[]),
      ('identity_subject_format', ARRAY['ad_object_guid', 'entry_uuid', 'utf8_exact', 'utf8_casefold']::text[]),
      ('ldap_account_status_mode', ARRAY['none', 'active_directory_uac', 'attribute_equals']::text[]),
      ('ldap_nested_group_mode', ARRAY['disabled', 'active_directory', 'reverse_search', 'posix_member_uid']::text[]),
      ('ldap_provider_template', ARRAY['active_directory', 'openldap', 'posix', 'custom']::text[]),
      ('ldap_provider_test_category', ARRAY['success', 'dns_failed', 'destination_blocked', 'connect_timeout', 'connect_failed', 'tls_failed', 'certificate_rejected', 'bind_rejected', 'protocol_failed', 'cancelled', 'stale_configuration']::text[]),
      ('ldap_provider_test_kind', ARRAY['connection', 'bind']::text[]),
      ('ldap_provider_test_outcome', ARRAY['success', 'failure', 'inconclusive']::text[]),
      ('ldap_provider_test_status', ARRAY['started', 'completed']::text[]),
      ('ldap_referral_mode', ARRAY['disabled', 'configured_endpoints']::text[]),
      ('ldap_transport', ARRAY['ldaps', 'starttls']::text[]),
      ('login_identifier_kind', ARRAY['local_email']::text[])
    ) AS enum_manifest(type_name, labels)
  LOOP
    IF NOT EXISTS (
      SELECT 1
      FROM pg_catalog.pg_type AS type_record
      WHERE type_record.oid = pg_catalog.to_regtype(
              'public.' || expected.type_name
            )
        AND type_record.typtype = 'e'
        AND pg_catalog.pg_get_userbyid(type_record.typowner) =
              'periapsis_migrator'
        AND (
          SELECT array_agg(
            enum_record.enumlabel::text ORDER BY enum_record.enumsortorder
          )
          FROM pg_catalog.pg_enum AS enum_record
          WHERE enum_record.enumtypid = type_record.oid
        ) = expected.labels
    ) THEN
      RAISE EXCEPTION 'identity-provider enum % is not exact',
        expected.type_name
        USING ERRCODE = '55000';
    END IF;
  END LOOP;

  FOREACH relation_name IN ARRAY ARRAY[
    'user_login_identifiers',
    'tenant_user_profiles',
    'identity_keyring_versions',
    'tenant_auth_providers',
    'tenant_ldap_provider_configs',
    'tenant_ldap_provider_urls',
    'tenant_ldap_provider_secrets',
    'tenant_ldap_provider_test_runs'
  ]::text[]
  LOOP
    relation_oid := pg_catalog.to_regclass('public.' || relation_name);
    IF relation_oid IS NULL OR NOT EXISTS (
      SELECT 1
      FROM pg_catalog.pg_class AS relation
      WHERE relation.oid = relation_oid
        AND relation.relkind = 'r'
        AND relation.relrowsecurity
        AND relation.relforcerowsecurity
        AND pg_catalog.pg_get_userbyid(relation.relowner) = 'periapsis_migrator'
    ) THEN
      RAISE EXCEPTION 'identity-provider readiness relation % is not forced-RLS migrator storage',
        relation_name
        USING ERRCODE = '55000';
    END IF;

    IF EXISTS (
      SELECT 1
      FROM pg_catalog.pg_policy AS policy
      WHERE policy.polrelid = relation_oid
    ) THEN
      RAISE EXCEPTION 'identity-provider private relation % has a forbidden RLS policy',
        relation_name
        USING ERRCODE = '55000';
    END IF;

    FOREACH runtime_role IN ARRAY ARRAY[
      'periapsis_api',
      'periapsis_worker',
      'periapsis_notifier',
      'periapsis_auditor'
    ]::text[]
    LOOP
      FOREACH table_privilege IN ARRAY ARRAY[
        'SELECT', 'INSERT', 'UPDATE', 'DELETE',
        'TRUNCATE', 'REFERENCES', 'TRIGGER'
      ]::text[]
      LOOP
        IF pg_catalog.has_table_privilege(
          runtime_role, relation_oid, table_privilege
        ) THEN
          RAISE EXCEPTION 'runtime role % has forbidden % privilege on %',
            runtime_role, table_privilege, relation_name
            USING ERRCODE = '55000';
        END IF;
      END LOOP;

      FOREACH column_privilege IN ARRAY ARRAY[
        'SELECT', 'INSERT', 'UPDATE', 'REFERENCES'
      ]::text[]
      LOOP
        IF pg_catalog.has_any_column_privilege(
          runtime_role, relation_oid, column_privilege
        ) THEN
          RAISE EXCEPTION 'runtime role % has forbidden column % privilege on %',
            runtime_role, column_privilege, relation_name
            USING ERRCODE = '55000';
        END IF;
      END LOOP;
    END LOOP;
  END LOOP;

  FOREACH relation_name IN ARRAY ARRAY[
    'tenant_user_profiles',
    'tenant_auth_providers',
    'tenant_ldap_provider_configs',
    'tenant_ldap_provider_urls',
    'tenant_ldap_provider_secrets',
    'tenant_ldap_provider_test_runs'
  ]::text[]
  LOOP
    IF NOT EXISTS (
      SELECT 1
      FROM pg_catalog.pg_attribute AS attribute
      WHERE attribute.attrelid = pg_catalog.to_regclass(
        'public.' || relation_name
      )
        AND attribute.attname = 'tenant_id'
        AND attribute.attnotnull
        AND NOT attribute.attisdropped
    ) THEN
      RAISE EXCEPTION 'customer-owned relation % lacks a non-null tenant_id',
        relation_name
        USING ERRCODE = '55000';
    END IF;
  END LOOP;

  IF EXISTS (
    SELECT 1
    FROM pg_catalog.pg_attribute AS attribute
    WHERE attribute.attrelid = 'public.users'::pg_catalog.regclass
      AND attribute.attname = 'email'
      AND attribute.attnotnull
      AND NOT attribute.attisdropped
  ) OR NOT EXISTS (
    SELECT 1
    FROM pg_catalog.pg_attribute AS attribute
    WHERE attribute.attrelid =
            'public.local_break_glass_credentials'::pg_catalog.regclass
      AND attribute.attname = 'login_identifier_id'
      AND attribute.attnotnull
      AND NOT attribute.attisdropped
  ) THEN
    RAISE EXCEPTION 'identity/email compatibility column nullability is not exact'
      USING ERRCODE = '55000';
  END IF;

  FOR expected IN
    SELECT *
    FROM (VALUES
      ('identity_keyring_versions', 'identity_keyring_versions_retirement_check', 'c', 'CHECK ((retired_at IS NULL OR retired_at >= bound_at) AND (NOT is_active OR retired_at IS NULL))'),
      ('local_break_glass_credentials', 'local_break_glass_credentials_login_identifier_fk', 'f', 'FOREIGN KEY (login_identifier_id, user_id) REFERENCES user_login_identifiers(id, user_id) ON UPDATE CASCADE ON DELETE RESTRICT'),
      ('tenant_auth_providers', 'tenant_auth_providers_archive_check', 'c', 'CHECK (archived_at IS NULL AND archived_by_membership_id IS NULL AND archive_reason IS NULL OR archived_at IS NOT NULL AND archived_by_membership_id IS NOT NULL AND archive_reason IS NOT NULL AND enabled IS FALSE AND archived_at >= created_at AND btrim(archive_reason) <> ''''::text AND char_length(archive_reason) <= 500 AND archive_reason !~ ''[[:cntrl:]]''::text)'),
      ('tenant_auth_providers', 'tenant_auth_providers_archiver_membership_fk', 'f', 'FOREIGN KEY (tenant_id, archived_by_membership_id) REFERENCES tenant_memberships(tenant_id, id) ON UPDATE CASCADE ON DELETE RESTRICT'),
      ('tenant_auth_providers', 'tenant_auth_providers_creator_membership_fk', 'f', 'FOREIGN KEY (tenant_id, created_by_membership_id) REFERENCES tenant_memberships(tenant_id, id) ON UPDATE CASCADE ON DELETE RESTRICT'),
      ('tenant_auth_providers', 'tenant_auth_providers_tenant_key_key', 'u', 'UNIQUE (tenant_id, key)'),
      ('tenant_auth_providers', 'tenant_auth_providers_updater_membership_fk', 'f', 'FOREIGN KEY (tenant_id, updated_by_membership_id) REFERENCES tenant_memberships(tenant_id, id) ON UPDATE CASCADE ON DELETE RESTRICT'),
      ('tenant_ldap_provider_configs', 'tenant_ldap_provider_configs_pkey', 'p', 'PRIMARY KEY (tenant_id, provider_id)'),
      ('tenant_ldap_provider_configs', 'tenant_ldap_provider_configs_provider_fk', 'f', 'FOREIGN KEY (tenant_id, provider_id, provider_kind) REFERENCES tenant_auth_providers(tenant_id, id, kind) ON UPDATE CASCADE ON DELETE RESTRICT'),
      ('tenant_ldap_provider_configs', 'tenant_ldap_provider_configs_updater_fk', 'f', 'FOREIGN KEY (tenant_id, updated_by_membership_id) REFERENCES tenant_memberships(tenant_id, id) ON UPDATE CASCADE ON DELETE RESTRICT'),
      ('tenant_ldap_provider_secrets', 'tenant_ldap_provider_secrets_pkey', 'p', 'PRIMARY KEY (tenant_id, provider_id)'),
      ('tenant_ldap_provider_secrets', 'tenant_ldap_provider_secrets_provider_fk', 'f', 'FOREIGN KEY (tenant_id, provider_id, provider_kind) REFERENCES tenant_auth_providers(tenant_id, id, kind) ON UPDATE CASCADE ON DELETE RESTRICT'),
      ('tenant_ldap_provider_secrets', 'tenant_ldap_provider_secrets_rotator_fk', 'f', 'FOREIGN KEY (tenant_id, rotated_by_membership_id) REFERENCES tenant_memberships(tenant_id, id) ON UPDATE CASCADE ON DELETE RESTRICT'),
      ('tenant_ldap_provider_secrets', 'tenant_ldap_provider_secrets_tenant_id_id_unique', 'u', 'UNIQUE (tenant_id, id)'),
      ('tenant_ldap_provider_test_runs', 'tenant_ldap_provider_test_runs_completer_fk', 'f', 'FOREIGN KEY (tenant_id, completed_by_membership_id) REFERENCES tenant_memberships(tenant_id, id) ON UPDATE CASCADE ON DELETE RESTRICT'),
      ('tenant_ldap_provider_test_runs', 'tenant_ldap_provider_test_runs_lifecycle_check', 'c', 'CHECK ((status = ''started''::ldap_provider_test_status AND outcome IS NULL AND category IS NULL AND endpoint_priority IS NULL AND duration_ms IS NULL AND completed_by_membership_id IS NULL AND completed_at IS NULL AND version = 1 OR status = ''completed''::ldap_provider_test_status AND outcome IS NOT NULL AND category IS NOT NULL AND duration_ms IS NOT NULL AND completed_by_membership_id IS NOT NULL AND completed_by_membership_id = started_by_membership_id AND completed_at >= started_at AND version = 2) IS TRUE)'),
      ('tenant_ldap_provider_test_runs', 'tenant_ldap_provider_test_runs_provider_fk', 'f', 'FOREIGN KEY (tenant_id, provider_id, provider_kind) REFERENCES tenant_auth_providers(tenant_id, id, kind) ON UPDATE CASCADE ON DELETE RESTRICT'),
      ('tenant_ldap_provider_test_runs', 'tenant_ldap_provider_test_runs_result_semantics_check', 'c', 'CHECK ((outcome IS NULL AND category IS NULL OR outcome = ''success''::ldap_provider_test_outcome AND category = ''success''::ldap_provider_test_category AND endpoint_priority IS NOT NULL OR outcome = ''inconclusive''::ldap_provider_test_outcome AND category = ''stale_configuration''::ldap_provider_test_category OR outcome = ''failure''::ldap_provider_test_outcome AND (category <> ALL (ARRAY[''success''::ldap_provider_test_category, ''stale_configuration''::ldap_provider_test_category])) AND (category = ''cancelled''::ldap_provider_test_category OR endpoint_priority IS NOT NULL) AND (test_kind = ''bind''::ldap_provider_test_kind OR category <> ''bind_rejected''::ldap_provider_test_category)) IS TRUE)'),
      ('tenant_ldap_provider_test_runs', 'tenant_ldap_provider_test_runs_secret_check', 'c', 'CHECK ((test_kind = ''connection''::ldap_provider_test_kind AND secret_version IS NULL OR test_kind = ''bind''::ldap_provider_test_kind AND secret_version IS NOT NULL) IS TRUE)'),
      ('tenant_ldap_provider_test_runs', 'tenant_ldap_provider_test_runs_starter_fk', 'f', 'FOREIGN KEY (tenant_id, started_by_membership_id) REFERENCES tenant_memberships(tenant_id, id) ON UPDATE CASCADE ON DELETE RESTRICT'),
      ('tenant_ldap_provider_urls', 'tenant_ldap_provider_urls_provider_endpoint_key', 'u', 'UNIQUE (tenant_id, provider_id, transport, host, port)'),
      ('tenant_ldap_provider_urls', 'tenant_ldap_provider_urls_provider_fk', 'f', 'FOREIGN KEY (tenant_id, provider_id, provider_kind) REFERENCES tenant_auth_providers(tenant_id, id, kind) ON UPDATE CASCADE ON DELETE RESTRICT'),
      ('tenant_ldap_provider_urls', 'tenant_ldap_provider_urls_provider_priority_key', 'u', 'UNIQUE (tenant_id, provider_id, priority)'),
      ('tenant_user_profiles', 'tenant_user_profiles_membership_fk', 'f', 'FOREIGN KEY (tenant_id, membership_id, user_id) REFERENCES tenant_memberships(tenant_id, id, user_id) ON UPDATE CASCADE ON DELETE RESTRICT'),
      ('user_login_identifiers', 'user_login_identifiers_kind_value_key', 'u', 'UNIQUE (kind, canonical_value)')
    ) AS constraint_manifest(
      relation_name, constraint_name, constraint_type, constraint_definition
    )
  LOOP
    IF NOT EXISTS (
      SELECT 1
      FROM pg_catalog.pg_constraint AS constraint_record
      WHERE constraint_record.conrelid = pg_catalog.to_regclass(
              'public.' || expected.relation_name
            )
        AND constraint_record.conname = expected.constraint_name
        AND constraint_record.contype = expected.constraint_type::"char"
        AND NOT constraint_record.condeferrable
        AND NOT constraint_record.condeferred
        AND constraint_record.convalidated
        AND pg_catalog.pg_get_constraintdef(constraint_record.oid, true) =
              expected.constraint_definition
    ) THEN
      RAISE EXCEPTION 'identity-provider readiness constraint %.% is missing or unvalidated',
        expected.relation_name, expected.constraint_name
        USING ERRCODE = '55000';
    END IF;
  END LOOP;

  FOR expected IN
    SELECT *
    FROM (VALUES
      ('user_login_identifiers_user_active_kind_key', 'CREATE UNIQUE INDEX user_login_identifiers_user_active_kind_key ON public.user_login_identifiers USING btree (user_id, kind) WHERE (retired_at IS NULL)', true),
      ('identity_keyring_versions_single_active_key', 'CREATE UNIQUE INDEX identity_keyring_versions_single_active_key ON public.identity_keyring_versions USING btree (is_active) WHERE is_active', true),
      ('tenant_ldap_provider_test_runs_status_started_idx', 'CREATE INDEX tenant_ldap_provider_test_runs_status_started_idx ON public.tenant_ldap_provider_test_runs USING btree (tenant_id, status, started_at, id)', false)
    ) AS index_manifest(index_name, index_definition, is_unique)
  LOOP
    IF NOT EXISTS (
      SELECT 1
      FROM pg_catalog.pg_index AS index_record
      JOIN pg_catalog.pg_class AS index_relation
        ON index_relation.oid = index_record.indexrelid
      WHERE index_relation.relname = expected.index_name
        AND index_record.indisunique = expected.is_unique
        AND index_record.indisvalid
        AND index_record.indisready
        AND pg_catalog.pg_get_indexdef(index_record.indexrelid) =
              expected.index_definition
    ) THEN
      RAISE EXCEPTION 'identity-provider readiness index % is not exact',
        expected.index_name
        USING ERRCODE = '55000';
    END IF;
  END LOOP;

  IF (
    SELECT array_agg(permission.key ORDER BY permission.key)
    FROM public.tenant_permissions AS permission
    WHERE permission.key = ANY(expected_permission_keys)
  ) IS DISTINCT FROM expected_permission_keys OR EXISTS (
    SELECT 1
    FROM public.tenant_permissions AS permission
    WHERE permission.key = ANY(expected_permission_keys)
      AND permission.service_account_allowed
  ) OR EXISTS (
    SELECT permission.id
    FROM public.tenant_permissions AS permission
    LEFT JOIN public.tenant_permission_scopes AS permission_scope
      ON permission_scope.permission_id = permission.id
    WHERE permission.key = ANY(expected_permission_keys)
    GROUP BY permission.id
    HAVING array_agg(permission_scope.scope ORDER BY permission_scope.scope)
      IS DISTINCT FROM ARRAY['tenant'::public.authorization_scope]
  ) THEN
    RAISE EXCEPTION 'identity-provider permission catalog is not exact'
      USING ERRCODE = '55000';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM public.tenants AS tenant
    CROSS JOIN unnest(expected_permission_keys) AS expected_key(key)
    WHERE NOT EXISTS (
      SELECT 1
      FROM public.tenant_roles AS role
      JOIN public.tenant_role_permissions AS role_permission
        ON role_permission.tenant_id = role.tenant_id
       AND role_permission.role_id = role.id
       AND role_permission.scope = 'tenant'
      JOIN public.tenant_permissions AS permission
        ON permission.id = role_permission.permission_id
       AND permission.key = expected_key.key
      JOIN public.tenant_role_delegation_ceilings AS ceiling
        ON ceiling.tenant_id = role_permission.tenant_id
       AND ceiling.role_id = role_permission.role_id
       AND ceiling.permission_id = role_permission.permission_id
       AND ceiling.scope = role_permission.scope
      WHERE role.tenant_id = tenant.id
        AND role.key = 'tenant_admin'
        AND role.principal_kind = 'human'
        AND role.system_role
        AND role.protected_role
        AND role.archived_at IS NULL
    )
  ) THEN
    RAISE EXCEPTION 'tenant_admin identity-provider policy seed is incomplete'
      USING ERRCODE = '55000';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM public.users AS identity
    WHERE identity.email IS NULL
  ) OR EXISTS (
    SELECT 1
    FROM public.local_break_glass_credentials AS credential
    LEFT JOIN public.user_login_identifiers AS identifier
      ON identifier.id = credential.login_identifier_id
     AND identifier.user_id = credential.user_id
    WHERE identifier.id IS NULL
      OR identifier.kind <> 'local_email'
      OR identifier.verified_at IS NULL
      OR identifier.retired_at IS NOT NULL
  ) OR EXISTS (
    SELECT 1
    FROM public.tenant_memberships AS membership
    LEFT JOIN public.tenant_user_profiles AS profile
      ON profile.tenant_id = membership.tenant_id
     AND profile.membership_id = membership.id
     AND profile.user_id = membership.user_id
    WHERE profile.membership_id IS NULL
  ) OR EXISTS (
    SELECT 1
    FROM public.tenant_ldap_provider_configs AS configuration
    WHERE NOT configuration.verify_certificate
      OR configuration.jit_mode <> 'disabled'
      OR configuration.no_match_policy <> 'deny'
      OR configuration.deprovision_mode <> 'retain'
      OR configuration.deprovision_grace_seconds <> 0
      OR configuration.sync_interval_seconds IS NOT NULL
  ) THEN
    RAISE EXCEPTION 'identity-provider rolling compatibility data is not exact'
      USING ERRCODE = '55000';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM public.tenant_auth_providers AS provider
    LEFT JOIN public.tenant_ldap_provider_configs AS configuration
      ON configuration.tenant_id = provider.tenant_id
     AND configuration.provider_id = provider.id
    WHERE provider.kind = 'ldap'
      AND (
        configuration.provider_id IS NULL
        OR NOT EXISTS (
          SELECT 1
          FROM public.tenant_ldap_provider_urls AS endpoint
          WHERE endpoint.tenant_id = provider.tenant_id
            AND endpoint.provider_id = provider.id
        )
        OR (provider.archived_at IS NOT NULL AND provider.enabled)
        OR (
          provider.enabled
          AND (
            NOT EXISTS (
              SELECT 1
              FROM public.tenant_ldap_provider_urls AS endpoint
              WHERE endpoint.tenant_id = provider.tenant_id
                AND endpoint.provider_id = provider.id
                AND endpoint.enabled
            )
            OR NOT EXISTS (
              SELECT 1
              FROM public.tenant_ldap_provider_secrets AS secret
              WHERE secret.tenant_id = provider.tenant_id
                AND secret.provider_id = provider.id
            )
          )
        )
      )
  ) THEN
    RAISE EXCEPTION 'tenant LDAP provider lifecycle projection is incomplete'
      USING ERRCODE = '55000';
  END IF;

  IF EXISTS (
    SELECT 1 FROM public.tenant_ldap_provider_secrets
  ) AND (
    SELECT count(*)
    FROM public.identity_keyring_versions AS keyring
    WHERE keyring.is_active
      AND keyring.retired_at IS NULL
  ) IS DISTINCT FROM 1 THEN
    RAISE EXCEPTION 'live identity ciphertext requires one active key version'
      USING ERRCODE = '55000';
  END IF;
  IF EXISTS (
    SELECT 1
    FROM public.tenant_ldap_provider_secrets AS secret
    LEFT JOIN public.identity_keyring_versions AS keyring
      ON keyring.key_version = secret.key_version
    WHERE keyring.key_version IS NULL
      OR keyring.retired_at IS NOT NULL
  ) THEN
    RAISE EXCEPTION 'live identity ciphertext references an unavailable key version'
      USING ERRCODE = '55000';
  END IF;

  FOR expected IN
    SELECT *
    FROM (VALUES
      ('local_break_glass_credentials', 'local_break_glass_credentials_bind_identifier', 'app.bind_local_login_identifier_v1()', 23, '2 11'),
      ('tenant_authorization_commands', 'tenant_authorization_commands_guard', 'app.guard_tenant_authorization_command()', 31, ''),
      ('tenant_ldap_provider_test_runs', 'tenant_ldap_provider_test_runs_guard_update_delete', 'app.guard_tenant_ldap_provider_test_run_v1()', 27, '')
    ) AS trigger_manifest(
      relation_name, trigger_name, function_signature, trigger_type, trigger_attributes
    )
  LOOP
    IF NOT EXISTS (
      SELECT 1
      FROM pg_catalog.pg_trigger AS trigger_record
      WHERE trigger_record.tgrelid = pg_catalog.to_regclass(
              'public.' || expected.relation_name
            )
        AND trigger_record.tgname = expected.trigger_name
        AND trigger_record.tgfoid = pg_catalog.to_regprocedure(
              expected.function_signature
            )
        AND trigger_record.tgtype = expected.trigger_type
        AND trigger_record.tgattr::text = expected.trigger_attributes
        AND trigger_record.tgenabled = 'O'
        AND NOT trigger_record.tgisinternal
    ) THEN
      RAISE EXCEPTION 'identity-provider trigger %.% is not exact',
        expected.relation_name, expected.trigger_name
        USING ERRCODE = '55000';
    END IF;
  END LOOP;

  IF (
    SELECT count(*)
    FROM pg_catalog.pg_trigger AS trigger_record
    WHERE NOT trigger_record.tgisinternal
      AND trigger_record.tgrelid = ANY(ARRAY[
        'public.local_break_glass_credentials'::pg_catalog.regclass,
        'public.tenant_authorization_commands'::pg_catalog.regclass,
        'public.tenant_ldap_provider_test_runs'::pg_catalog.regclass
      ]::oid[])
  ) IS DISTINCT FROM 3::bigint THEN
    RAISE EXCEPTION 'identity-provider trigger surface is not exact'
      USING ERRCODE = '55000';
  END IF;

  IF NOT EXISTS (
    SELECT 1
    FROM pg_catalog.pg_roles AS role
    WHERE role.rolname = 'periapsis_migrator'
      AND role.rolbypassrls
      AND NOT role.rolsuper
  ) OR (
    SELECT count(*)
    FROM pg_catalog.pg_roles AS role
    WHERE role.rolname = ANY(ARRAY[
      'periapsis_api', 'periapsis_worker',
      'periapsis_notifier', 'periapsis_auditor'
    ]::pg_catalog.name[])
      AND NOT role.rolbypassrls
      AND NOT role.rolsuper
  ) IS DISTINCT FROM 4::bigint THEN
    RAISE EXCEPTION 'identity-provider role BYPASSRLS and superuser boundary is not exact'
      USING ERRCODE = '55000';
  END IF;
END;
$identity_provider_readiness_assertions$;--> statement-breakpoint

-- v7 is ready only for the exact 51-row identity-provider release journal.
CREATE FUNCTION app.schema_compatibility_v7()
RETURNS TABLE (
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
  migration_0050_rows bigint;
  journal_created_at bigint[];
BEGIN
  EXECUTE $query$
    SELECT
      count(*)::bigint,
      max(migration.created_at)::bigint,
      count(*) FILTER (
        WHERE migration.created_at = 1787637795761
      )::bigint,
      array_agg(
        migration.created_at::bigint
        ORDER BY migration.created_at, migration.id
      )
    FROM drizzle.__drizzle_migrations AS migration
  $query$
  INTO
    journal_count,
    journal_latest_created_at,
    migration_0050_rows,
    journal_created_at;

  IF journal_count = 51
     AND journal_latest_created_at = 1787637795761
     AND migration_0050_rows = 1
     AND journal_created_at = ARRAY[
       1787472409685, 1787472415216, 1787473527702, 1787473536723,
       1787474082034, 1787474089267, 1787475027656, 1787475184077,
       1787488565252, 1787488569966, 1787492910536, 1787493031146,
       1787494284382, 1787495115125, 1787495293635, 1787495819997,
       1787495999394, 1787496124539, 1787496880587, 1787496982733,
       1787496987011, 1787501702276, 1787506296280, 1787507888755,
       1787508523197, 1787516694668, 1787571776845, 1787581350373,
       1787581530382, 1787582150087, 1787591930962, 1787591938733,
       1787592230466, 1787612620574, 1787613580320, 1787613592459,
       1787613744526, 1787613746038, 1787613747552, 1787613749000,
       1787635396524, 1787635417084, 1787635433516, 1787635452090,
       1787635459707, 1787635471570, 1787635525474, 1787635788324,
       1787635828723, 1787637794128, 1787637795761
     ]::bigint[] THEN
    RETURN QUERY EXECUTE $query$
      SELECT
        count(*)::bigint AS applied_count,
        max(migration.created_at)::bigint AS latest_created_at,
        (
          SELECT lower(latest_migration.hash::text)
          FROM drizzle.__drizzle_migrations AS latest_migration
          ORDER BY latest_migration.created_at DESC, latest_migration.id DESC
          LIMIT 1
        ) AS latest_hash,
        string_agg(
          migration.created_at::text || '@' || lower(migration.hash::text),
          ':' ORDER BY migration.created_at, migration.id
        ) AS migration_fingerprint
      FROM drizzle.__drizzle_migrations AS migration
    $query$;
    RETURN;
  END IF;

  RETURN QUERY
  SELECT 0::bigint,
         0::bigint,
         'UNSUPPORTED'::text,
         'UNSUPPORTED'::text;
END;
$function$;--> statement-breakpoint

ALTER FUNCTION app.schema_compatibility_v7() OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.schema_compatibility_v7() FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.schema_compatibility_v7() TO periapsis_api, periapsis_worker;--> statement-breakpoint

-- The immediately preceding binary can project its sealed 40-row v6 prefix
-- only while the identity/email bridge remains predecessor-compatible.
CREATE OR REPLACE FUNCTION app.schema_compatibility_v6()
RETURNS TABLE (
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
  journal_fingerprint text;
  migration_0039_rows bigint;
  migration_0050_rows bigint;
BEGIN
  SELECT compatibility.applied_count,
         compatibility.latest_created_at,
         compatibility.migration_fingerprint
  INTO journal_count, journal_latest_created_at, journal_fingerprint
  FROM app.schema_compatibility_v7() AS compatibility;

  EXECUTE $query$
    SELECT
      count(*) FILTER (
        WHERE migration.created_at = 1787613749000
      )::bigint,
      count(*) FILTER (
        WHERE migration.created_at = 1787637795761
      )::bigint
    FROM drizzle.__drizzle_migrations AS migration
  $query$
  INTO migration_0039_rows, migration_0050_rows;

  IF journal_count = 51
     AND journal_latest_created_at = 1787637795761
     AND migration_0039_rows = 1
     AND migration_0050_rows = 1
     AND journal_fingerprint = current_setting(
       'app.schema_compatibility_fingerprint',
       true
     )
     AND NOT EXISTS (
       SELECT 1
       FROM public.users AS identity
       WHERE identity.email IS NULL
     )
     AND NOT EXISTS (
       SELECT 1
       FROM public.local_break_glass_credentials AS credential
       LEFT JOIN public.user_login_identifiers AS identifier
         ON identifier.id = credential.login_identifier_id
        AND identifier.user_id = credential.user_id
       WHERE identifier.id IS NULL
         OR identifier.kind <> 'local_email'
         OR identifier.verified_at IS NULL
         OR identifier.retired_at IS NOT NULL
     )
     AND NOT EXISTS (
       SELECT 1
       FROM public.tenant_memberships AS membership
       LEFT JOIN public.tenant_user_profiles AS profile
         ON profile.tenant_id = membership.tenant_id
        AND profile.membership_id = membership.id
        AND profile.user_id = membership.user_id
       WHERE profile.membership_id IS NULL
     )
     AND NOT EXISTS (
       SELECT 1
       FROM public.tenant_ldap_provider_configs AS configuration
       WHERE configuration.jit_mode <> 'disabled'
         OR configuration.no_match_policy <> 'deny'
         OR configuration.deprovision_mode <> 'retain'
         OR configuration.deprovision_grace_seconds <> 0
         OR configuration.sync_interval_seconds IS NOT NULL
     ) THEN
    RETURN QUERY EXECUTE $query$
      WITH ordered_migrations AS (
        SELECT
          migration.id,
          migration.created_at,
          lower(migration.hash::text) AS migration_hash,
          row_number() OVER (
            ORDER BY migration.created_at, migration.id
          ) AS migration_ordinal
        FROM drizzle.__drizzle_migrations AS migration
      )
      SELECT
        count(*)::bigint AS applied_count,
        max(migration.created_at)::bigint AS latest_created_at,
        (
          SELECT latest_prefix_migration.migration_hash
          FROM ordered_migrations AS latest_prefix_migration
          WHERE latest_prefix_migration.migration_ordinal = 40
        ) AS latest_hash,
        string_agg(
          migration.created_at::text || '@' || migration.migration_hash,
          ':' ORDER BY migration.created_at, migration.id
        ) AS migration_fingerprint
      FROM ordered_migrations AS migration
      WHERE migration.migration_ordinal <= 40
    $query$;
    RETURN;
  END IF;

  RETURN QUERY
  SELECT 0::bigint,
         0::bigint,
         'UNSUPPORTED'::text,
         'UNSUPPORTED'::text;
END;
$function$;--> statement-breakpoint

ALTER FUNCTION app.schema_compatibility_v6() OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.schema_compatibility_v6() FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.schema_compatibility_v6() TO periapsis_api, periapsis_worker;--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.schema_compatibility_v5()
RETURNS TABLE (
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
  RETURN QUERY
  SELECT 0::bigint,
         0::bigint,
         'UNSUPPORTED'::text,
         'UNSUPPORTED'::text;
END;
$function$;--> statement-breakpoint

ALTER FUNCTION app.schema_compatibility_v5() OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.schema_compatibility_v5() FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.schema_compatibility_v5() TO periapsis_api, periapsis_worker;--> statement-breakpoint

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
  actual_count bigint;
  actual_latest_created_at bigint;
  actual_latest_hash text;
  actual_migration_fingerprint text;
  predecessor_count bigint;
  predecessor_latest_created_at bigint;
  predecessor_latest_hash text;
  predecessor_migration_fingerprint text;
  retired_count bigint;
  retired_latest_created_at bigint;
  retired_latest_hash text;
  retired_migration_fingerprint text;
  expected_predecessor_hash text;
  expected_predecessor_fingerprint text;
  fingerprint_entries text[];
  fingerprint_created_at bigint[];
BEGIN
  fingerprint_entries := string_to_array(
    p_expected_migration_fingerprint,
    ':'
  );
  IF p_expected_count IS DISTINCT FROM 51
     OR p_expected_latest_created_at IS DISTINCT FROM 1787637795761
     OR p_expected_latest_hash IS NULL
     OR p_expected_latest_hash !~ '^[0-9a-f]{64}$'
     OR p_expected_migration_fingerprint IS NULL
     OR p_expected_migration_fingerprint !~ '^[1-9][0-9]*@[0-9a-f]{64}(:[1-9][0-9]*@[0-9a-f]{64})*$'
     OR cardinality(fingerprint_entries) IS DISTINCT FROM 51
     OR fingerprint_entries[51] IS DISTINCT FROM (
          p_expected_latest_created_at::text || '@' || p_expected_latest_hash
        ) THEN
    RAISE EXCEPTION 'invalid schema compatibility v7 manifest'
      USING ERRCODE = '22023';
  END IF;

  SELECT array_agg(
           split_part(entry.value, '@', 1)::bigint
           ORDER BY entry.ordinality
         )
  INTO fingerprint_created_at
  FROM unnest(fingerprint_entries) WITH ORDINALITY AS entry(value, ordinality);

  IF fingerprint_created_at IS DISTINCT FROM ARRAY[
       1787472409685, 1787472415216, 1787473527702, 1787473536723,
       1787474082034, 1787474089267, 1787475027656, 1787475184077,
       1787488565252, 1787488569966, 1787492910536, 1787493031146,
       1787494284382, 1787495115125, 1787495293635, 1787495819997,
       1787495999394, 1787496124539, 1787496880587, 1787496982733,
       1787496987011, 1787501702276, 1787506296280, 1787507888755,
       1787508523197, 1787516694668, 1787571776845, 1787581350373,
       1787581530382, 1787582150087, 1787591930962, 1787591938733,
       1787592230466, 1787612620574, 1787613580320, 1787613592459,
       1787613744526, 1787613746038, 1787613747552, 1787613749000,
       1787635396524, 1787635417084, 1787635433516, 1787635452090,
       1787635459707, 1787635471570, 1787635525474, 1787635788324,
       1787635828723, 1787637794128, 1787637795761
     ]::bigint[] THEN
    RAISE EXCEPTION 'invalid schema compatibility v7 timestamp sequence'
      USING ERRCODE = '22023';
  END IF;

  SELECT compatibility.applied_count,
         compatibility.latest_created_at,
         compatibility.latest_hash,
         compatibility.migration_fingerprint
  INTO actual_count,
       actual_latest_created_at,
       actual_latest_hash,
       actual_migration_fingerprint
  FROM app.schema_compatibility_v7() AS compatibility;

  IF actual_count IS DISTINCT FROM p_expected_count
     OR actual_latest_created_at IS DISTINCT FROM p_expected_latest_created_at
     OR actual_latest_hash IS DISTINCT FROM p_expected_latest_hash
     OR actual_migration_fingerprint IS DISTINCT FROM p_expected_migration_fingerprint THEN
    RAISE EXCEPTION 'schema compatibility v7 manifest does not match the applied journal'
      USING ERRCODE = '55000';
  END IF;

  PERFORM set_config(
    'app.schema_compatibility_fingerprint',
    p_expected_migration_fingerprint,
    true
  );
  EXECUTE $statement$
    ALTER FUNCTION app.schema_compatibility_v6()
      SET app.schema_compatibility_fingerprint FROM CURRENT
  $statement$;

  expected_predecessor_hash := split_part(fingerprint_entries[40], '@', 2);
  expected_predecessor_fingerprint := array_to_string(
    fingerprint_entries[1:40],
    ':'
  );
  SELECT compatibility.applied_count,
         compatibility.latest_created_at,
         compatibility.latest_hash,
         compatibility.migration_fingerprint
  INTO predecessor_count,
       predecessor_latest_created_at,
       predecessor_latest_hash,
       predecessor_migration_fingerprint
  FROM app.schema_compatibility_v6() AS compatibility;

  IF predecessor_count IS DISTINCT FROM 40
     OR predecessor_latest_created_at IS DISTINCT FROM 1787613749000
     OR predecessor_latest_hash IS DISTINCT FROM expected_predecessor_hash
     OR predecessor_migration_fingerprint IS DISTINCT FROM
          expected_predecessor_fingerprint THEN
    RAISE EXCEPTION 'sealed schema compatibility v6 prefix is not exact'
      USING ERRCODE = '55000';
  END IF;

  SELECT compatibility.applied_count,
         compatibility.latest_created_at,
         compatibility.latest_hash,
         compatibility.migration_fingerprint
  INTO retired_count,
       retired_latest_created_at,
       retired_latest_hash,
       retired_migration_fingerprint
  FROM app.schema_compatibility_v5() AS compatibility;
  IF retired_count IS DISTINCT FROM 0
     OR retired_latest_created_at IS DISTINCT FROM 0
     OR retired_latest_hash IS DISTINCT FROM 'UNSUPPORTED'
     OR retired_migration_fingerprint IS DISTINCT FROM 'UNSUPPORTED' THEN
    RAISE EXCEPTION 'schema compatibility v5 must be retired'
      USING ERRCODE = '55000';
  END IF;
END;
$function$;--> statement-breakpoint

ALTER FUNCTION app.seal_schema_compatibility_manifest(bigint, bigint, text, text) OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.seal_schema_compatibility_manifest(bigint, bigint, text, text) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;
