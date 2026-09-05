-- Every identity-provider table is owned by the migration boundary. Runtime
-- roles receive no direct table access; bounded SECURITY DEFINER entry points
-- below are the only supported ABI.
ALTER TYPE public.auth_provider_kind OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TYPE public.identity_deprovision_mode OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TYPE public.identity_jit_mode OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TYPE public.identity_no_match_policy OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TYPE public.identity_subject_format OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TYPE public.ldap_account_status_mode OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TYPE public.ldap_nested_group_mode OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TYPE public.ldap_provider_template OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TYPE public.ldap_referral_mode OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TYPE public.ldap_transport OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TYPE public.login_identifier_kind OWNER TO periapsis_migrator;--> statement-breakpoint

ALTER TABLE public.user_login_identifiers OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TABLE public.tenant_user_profiles OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TABLE public.identity_keyring_versions OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TABLE public.tenant_auth_providers OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TABLE public.tenant_ldap_provider_configs OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TABLE public.tenant_ldap_provider_urls OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TABLE public.tenant_ldap_provider_secrets OWNER TO periapsis_migrator;--> statement-breakpoint

ALTER TABLE public.user_login_identifiers FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE public.tenant_user_profiles FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE public.identity_keyring_versions FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE public.tenant_auth_providers FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE public.tenant_ldap_provider_configs FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE public.tenant_ldap_provider_urls FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE public.tenant_ldap_provider_secrets FORCE ROW LEVEL SECURITY;--> statement-breakpoint

REVOKE ALL ON TABLE public.user_login_identifiers FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON TABLE public.tenant_user_profiles FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON TABLE public.identity_keyring_versions FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON TABLE public.tenant_auth_providers FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON TABLE public.tenant_ldap_provider_configs FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON TABLE public.tenant_ldap_provider_urls FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON TABLE public.tenant_ldap_provider_secrets FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint

-- Identity administration is human-only and tenant scoped. Mapping authority
-- remains additional to the exact consequence/delegation checks required by
-- ADR-0007.
INSERT INTO public.tenant_permissions (
  id, key, display_name, description, service_account_allowed
)
VALUES
  (uuidv7(), 'identity_provider.read', 'Read identity providers', 'List tenant identity-provider configuration without secret material.', false),
  (uuidv7(), 'identity_provider.manage', 'Manage identity providers', 'Create, update, enable, disable, archive, and rotate tenant identity-provider configuration.', false),
  (uuidv7(), 'identity_provider.test', 'Test identity providers', 'Run bounded connection, bind, search, and filter diagnostics.', false),
  (uuidv7(), 'identity_mapping.read', 'Read identity mappings', 'Read identity-provider mapping rules and redacted dry-run results.', false),
  (uuidv7(), 'identity_mapping.manage', 'Manage identity mappings', 'Create and publish source-owned identity mapping rules subject to complete consequence checks.', false),
  (uuidv7(), 'identity_sync.run', 'Run identity synchronization', 'Request and inspect bounded tenant identity synchronization runs.', false)
ON CONFLICT (key) DO NOTHING;--> statement-breakpoint

INSERT INTO public.tenant_permission_scopes (permission_id, scope)
SELECT permission.id, 'tenant'::public.authorization_scope
FROM public.tenant_permissions AS permission
WHERE permission.key IN (
  'identity_provider.read',
  'identity_provider.manage',
  'identity_provider.test',
  'identity_mapping.read',
  'identity_mapping.manage',
  'identity_sync.run'
)
ON CONFLICT DO NOTHING;--> statement-breakpoint

CREATE FUNCTION app.private_seed_tenant_identity_authorization_v1(
  p_tenant_id uuid
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  administrator_role public.tenant_roles%ROWTYPE;
  inserted_policies integer;
  inserted_ceilings integer;
  next_version integer;
BEGIN
  PERFORM state.revision
  FROM public.tenant_authorization_states AS state
  WHERE state.tenant_id = p_tenant_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant authorization state is required for identity-provider seeding'
      USING ERRCODE = '55000';
  END IF;

  SELECT role.*
  INTO STRICT administrator_role
  FROM public.tenant_roles AS role
  WHERE role.tenant_id = p_tenant_id
    AND role.key = 'tenant_admin'
    AND role.principal_kind = 'human'
    AND role.system_role
    AND role.protected_role
    AND role.archived_at IS NULL
  FOR UPDATE;

  INSERT INTO public.tenant_role_permissions (
    tenant_id, role_id, permission_id, scope, created_by_membership_id
  )
  SELECT p_tenant_id, administrator_role.id, permission.id, 'tenant', NULL
  FROM public.tenant_permissions AS permission
  WHERE permission.key IN (
    'identity_provider.read',
    'identity_provider.manage',
    'identity_provider.test',
    'identity_mapping.read',
    'identity_mapping.manage',
    'identity_sync.run'
  )
  ON CONFLICT DO NOTHING;
  GET DIAGNOSTICS inserted_policies = ROW_COUNT;

  INSERT INTO public.tenant_role_delegation_ceilings (
    tenant_id, role_id, permission_id, scope, created_by_membership_id
  )
  SELECT p_tenant_id, administrator_role.id, permission.id, 'tenant', NULL
  FROM public.tenant_permissions AS permission
  WHERE permission.key IN (
    'identity_provider.read',
    'identity_provider.manage',
    'identity_provider.test',
    'identity_mapping.read',
    'identity_mapping.manage',
    'identity_sync.run'
  )
  ON CONFLICT DO NOTHING;
  GET DIAGNOSTICS inserted_ceilings = ROW_COUNT;

  IF inserted_policies > 0 OR inserted_ceilings > 0 THEN
    IF administrator_role.version >= 2147483647 THEN
      RAISE EXCEPTION 'tenant_admin role version is exhausted during identity-provider seeding'
        USING ERRCODE = '55000';
    END IF;
    next_version := administrator_role.version + 1;
    UPDATE public.tenant_roles AS role
    SET version = next_version,
        updated_at = transaction_timestamp()
    WHERE role.tenant_id = p_tenant_id
      AND role.id = administrator_role.id;

    INSERT INTO public.audit_events (
      id, tenant_id, sequence, actor_type, action, resource_type,
      resource_id, authentication_method, outcome, after, metadata
    ) VALUES (
      uuidv7(), p_tenant_id, 0, 'system',
      'tenant.authorization.identity_provider_administration_enabled',
      'tenant_role', administrator_role.id, 'database_migration', 'success',
      jsonb_build_object(
        'permissions', jsonb_build_array(
          'identity_provider.read',
          'identity_provider.manage',
          'identity_provider.test',
          'identity_mapping.read',
          'identity_mapping.manage',
          'identity_sync.run'
        ),
        'scope', 'tenant',
        'prior_version', administrator_role.version,
        'result_version', next_version
      ),
      jsonb_build_object(
        'migration', '0044_identity_provider_security',
        'principal_kind', 'human'
      )
    );
  END IF;
END;
$function$;--> statement-breakpoint

ALTER FUNCTION app.private_seed_tenant_identity_authorization_v1(uuid) OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_seed_tenant_identity_authorization_v1(uuid) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint

DO $identity_permission_seed$
DECLARE
  tenant_record record;
BEGIN
  FOR tenant_record IN
    SELECT tenant.id
    FROM public.tenants AS tenant
    ORDER BY tenant.id
  LOOP
    PERFORM app.private_seed_tenant_identity_authorization_v1(tenant_record.id);
  END LOOP;
END;
$identity_permission_seed$;--> statement-breakpoint

-- Future tenant initialization must receive the same permission catalog before
-- its authorization state is exposed.
ALTER FUNCTION app.seed_tenant_authorization(uuid, uuid)
  RENAME TO seed_tenant_authorization_identity_provider_compatibility_impl;--> statement-breakpoint
DROP FUNCTION IF EXISTS app.seed_tenant_authorization(uuid, uuid);--> statement-breakpoint
ALTER FUNCTION app.seed_tenant_authorization_identity_provider_compatibility_impl(uuid, uuid) OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.seed_tenant_authorization_identity_provider_compatibility_impl(uuid, uuid) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint

CREATE FUNCTION app.seed_tenant_authorization(
  p_tenant_id uuid,
  p_initial_admin_membership_id uuid
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  PERFORM app.seed_tenant_authorization_identity_provider_compatibility_impl(
    p_tenant_id, p_initial_admin_membership_id
  );
  PERFORM app.private_seed_tenant_identity_authorization_v1(p_tenant_id);
END;
$function$;--> statement-breakpoint

ALTER FUNCTION app.seed_tenant_authorization(uuid, uuid) OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.seed_tenant_authorization(uuid, uuid) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint

DO $identity_catalog_assertions$
DECLARE
  expected_keys text[] := ARRAY[
    'identity_mapping.manage',
    'identity_mapping.read',
    'identity_provider.manage',
    'identity_provider.read',
    'identity_provider.test',
    'identity_sync.run'
  ]::text[];
BEGIN
  IF (
    SELECT array_agg(permission.key ORDER BY permission.key)
    FROM public.tenant_permissions AS permission
    WHERE permission.key = ANY(expected_keys)
  ) IS DISTINCT FROM expected_keys THEN
    RAISE EXCEPTION 'identity-provider permission catalog is incomplete'
      USING ERRCODE = '55000';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM public.tenant_permissions AS permission
    WHERE permission.key = ANY(expected_keys)
      AND permission.service_account_allowed
  ) OR EXISTS (
    SELECT permission.id
    FROM public.tenant_permissions AS permission
    LEFT JOIN public.tenant_permission_scopes AS permission_scope
      ON permission_scope.permission_id = permission.id
    WHERE permission.key = ANY(expected_keys)
    GROUP BY permission.id
    HAVING array_agg(permission_scope.scope ORDER BY permission_scope.scope)
      IS DISTINCT FROM ARRAY['tenant'::public.authorization_scope]
  ) THEN
    RAISE EXCEPTION 'identity-provider permissions must be human-only and tenant-scoped'
      USING ERRCODE = '55000';
  END IF;
END;
$identity_catalog_assertions$;--> statement-breakpoint

-- Bind every installed key version to its exact key material and verify that
-- the process holds every version needed by live identity ciphertext. The
-- function returns one boolean and never exposes verifier or secret rows.
CREATE FUNCTION app.verify_identity_keyring_v1(
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
BEGIN
  item_count := coalesce(array_length(p_versions, 1), 0);
  IF item_count < 1 OR item_count > 16
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

  LOCK TABLE public.identity_keyring_versions IN SHARE ROW EXCLUSIVE MODE;

  FOR item_index IN 1..item_count LOOP
    INSERT INTO public.identity_keyring_versions (
      key_version, verifier, bound_at
    ) VALUES (
      p_versions[item_index], p_verifiers[item_index], transaction_timestamp()
    )
    ON CONFLICT (key_version) DO NOTHING;

    SELECT keyring.verifier
    INTO existing_verifier
    FROM public.identity_keyring_versions AS keyring
    WHERE keyring.key_version = p_versions[item_index]
      AND keyring.retired_at IS NULL;

    IF existing_verifier IS NULL
       OR existing_verifier <> p_verifiers[item_index] THEN
      RETURN false;
    END IF;
  END LOOP;

  IF EXISTS (
    SELECT 1
    FROM public.tenant_ldap_provider_secrets AS secret
    WHERE NOT secret.key_version = ANY(p_versions)
  ) THEN
    RETURN false;
  END IF;

  RETURN EXISTS (
    SELECT 1
    FROM public.identity_keyring_versions AS active_key
    WHERE active_key.key_version = p_active_version
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

-- Restore the trigger function owner after the generated/backfill stage and
-- keep it inaccessible as a callable runtime API.
ALTER FUNCTION app.bind_local_login_identifier_v1() OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.bind_local_login_identifier_v1() FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;
