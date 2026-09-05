-- Expand-only platform federation administration. Public login, tenant
-- bindings, direct identities, and session provenance remain absent and are
-- therefore impossible to enable through this migration.

INSERT INTO public.platform_permissions (id, key, description)
VALUES
  (uuidv7(), 'platform.identity_provider.read', 'Read safe platform identity-provider summaries.'),
  (uuidv7(), 'platform.identity_provider.manage', 'Create, update, archive, and rotate platform identity-provider configuration.'),
  (uuidv7(), 'platform.identity_provider.test', 'Run bounded platform identity-provider diagnostics.'),
  (uuidv7(), 'platform.identity_binding.read', 'Read explicit tenant bindings to platform identity providers.'),
  (uuidv7(), 'platform.identity_binding.manage', 'Create and retire explicit tenant bindings to platform identity providers.'),
  (uuidv7(), 'platform.identity_policy.read', 'Read platform federation and assurance policies.'),
  (uuidv7(), 'platform.identity_policy.manage', 'Manage platform federation and assurance policies.'),
  (uuidv7(), 'platform.identity_account.read', 'Read safe platform federated-account summaries.'),
  (uuidv7(), 'platform.identity_account.manage', 'Manage protected platform federated-account links and lifecycle.')
ON CONFLICT (key) DO NOTHING;
--> statement-breakpoint
INSERT INTO public.platform_role_permissions (role_id, permission_id)
SELECT role.id, permission.id
FROM public.platform_roles AS role
CROSS JOIN public.platform_permissions AS permission
WHERE role.key = 'platform_super_admin'
  AND permission.key = ANY (ARRAY[
    'platform.identity_provider.read',
    'platform.identity_provider.manage',
    'platform.identity_provider.test',
    'platform.identity_binding.read',
    'platform.identity_binding.manage',
    'platform.identity_policy.read',
    'platform.identity_policy.manage',
    'platform.identity_account.read',
    'platform.identity_account.manage'
  ]::text[])
ON CONFLICT DO NOTHING;
--> statement-breakpoint

ALTER TABLE public.platform_auth_providers OWNER TO periapsis_migrator;
ALTER TABLE public.platform_federated_provider_policies OWNER TO periapsis_migrator;
ALTER TABLE public.platform_federated_trust_rules OWNER TO periapsis_migrator;
ALTER TABLE public.platform_identity_provider_commands OWNER TO periapsis_migrator;
ALTER TABLE public.platform_identity_provider_test_runs OWNER TO periapsis_migrator;
ALTER TABLE public.platform_oidc_claim_rules OWNER TO periapsis_migrator;
ALTER TABLE public.platform_oidc_client_secrets OWNER TO periapsis_migrator;
ALTER TABLE public.platform_oidc_discovery_snapshots OWNER TO periapsis_migrator;
ALTER TABLE public.platform_oidc_jwks_snapshots OWNER TO periapsis_migrator;
ALTER TABLE public.platform_oidc_provider_configurations OWNER TO periapsis_migrator;
ALTER TABLE public.platform_saml_attribute_rules OWNER TO periapsis_migrator;
ALTER TABLE public.platform_saml_metadata_snapshots OWNER TO periapsis_migrator;
ALTER TABLE public.platform_saml_provider_configurations OWNER TO periapsis_migrator;
ALTER TABLE public.platform_saml_sp_certificates OWNER TO periapsis_migrator;
ALTER TABLE public.platform_saml_sp_keys OWNER TO periapsis_migrator;
--> statement-breakpoint

ALTER TABLE public.platform_auth_providers FORCE ROW LEVEL SECURITY;
ALTER TABLE public.platform_federated_provider_policies FORCE ROW LEVEL SECURITY;
ALTER TABLE public.platform_federated_trust_rules FORCE ROW LEVEL SECURITY;
ALTER TABLE public.platform_identity_provider_commands FORCE ROW LEVEL SECURITY;
ALTER TABLE public.platform_identity_provider_test_runs FORCE ROW LEVEL SECURITY;
ALTER TABLE public.platform_oidc_claim_rules FORCE ROW LEVEL SECURITY;
ALTER TABLE public.platform_oidc_client_secrets FORCE ROW LEVEL SECURITY;
ALTER TABLE public.platform_oidc_discovery_snapshots FORCE ROW LEVEL SECURITY;
ALTER TABLE public.platform_oidc_jwks_snapshots FORCE ROW LEVEL SECURITY;
ALTER TABLE public.platform_oidc_provider_configurations FORCE ROW LEVEL SECURITY;
ALTER TABLE public.platform_saml_attribute_rules FORCE ROW LEVEL SECURITY;
ALTER TABLE public.platform_saml_metadata_snapshots FORCE ROW LEVEL SECURITY;
ALTER TABLE public.platform_saml_provider_configurations FORCE ROW LEVEL SECURITY;
ALTER TABLE public.platform_saml_sp_certificates FORCE ROW LEVEL SECURITY;
ALTER TABLE public.platform_saml_sp_keys FORCE ROW LEVEL SECURITY;
--> statement-breakpoint

REVOKE ALL ON TABLE
  public.platform_auth_providers,
  public.platform_federated_provider_policies,
  public.platform_federated_trust_rules,
  public.platform_identity_provider_commands,
  public.platform_identity_provider_test_runs,
  public.platform_oidc_claim_rules,
  public.platform_oidc_client_secrets,
  public.platform_oidc_discovery_snapshots,
  public.platform_oidc_jwks_snapshots,
  public.platform_oidc_provider_configurations,
  public.platform_saml_attribute_rules,
  public.platform_saml_metadata_snapshots,
  public.platform_saml_provider_configurations,
  public.platform_saml_sp_certificates,
  public.platform_saml_sp_keys
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor,
  periapsis_audit_reader_owner;
--> statement-breakpoint

-- Keep the declarative Drizzle invariants exact while this unshipped expand
-- slice is sealed. A create idempotency key is operation-scoped, never
-- protocol-scoped, and SAML encryption cannot be configured before the
-- write-only SP-key lifecycle exists.
ALTER TABLE public.platform_identity_provider_commands
  DROP CONSTRAINT platform_identity_provider_commands_operation_check;
ALTER TABLE public.platform_identity_provider_commands
  ADD CONSTRAINT platform_identity_provider_commands_operation_check
  CHECK (operation = 'provider.create');
ALTER TABLE public.platform_identity_provider_test_runs
  DROP CONSTRAINT platform_identity_provider_test_runs_value_check;
ALTER TABLE public.platform_identity_provider_test_runs
  ADD CONSTRAINT platform_identity_provider_test_runs_value_check
  CHECK ((
    kind IN ('configuration', 'connection', 'trust')
    AND status IN ('running', 'completed')
    AND (
      (
        status = 'running'
        AND outcome IS NULL
        AND category IS NULL
        AND completed_at IS NULL
      )
      OR (
        status = 'completed'
        AND outcome IS NOT NULL
        AND category IS NOT NULL
        AND outcome IN ('success', 'failure', 'inconclusive')
        AND category IN (
          'success', 'cancelled', 'configuration_invalid', 'destination_blocked',
          'dns_failed', 'connect_failed', 'connect_timeout', 'tls_failed',
          'discovery_unreachable', 'issuer_mismatch', 'jwks_invalid',
          'metadata_invalid', 'certificate_expired', 'stale_configuration',
          'protocol_failed'
        )
        AND (
          (outcome = 'success' AND category = 'success')
          OR (outcome = 'inconclusive' AND category = 'stale_configuration')
          OR (outcome = 'failure' AND category NOT IN ('success', 'stale_configuration'))
        )
        AND completed_at >= started_at
      )
    )
  ) IS TRUE);
ALTER TABLE public.platform_oidc_claim_rules
  DROP CONSTRAINT platform_oidc_claim_rules_value_check;
ALTER TABLE public.platform_oidc_claim_rules
  ADD CONSTRAINT platform_oidc_claim_rules_value_check
  CHECK (
    source IN ('id_token', 'userinfo')
    AND sequence BETWEEN 0 AND 1023
    AND kind IN ('scalar', 'profile', 'groups', 'acr', 'amr')
    AND char_length(claim_name) BETWEEN 1 AND 256
    AND claim_name ~ '^[!-~]+$'
    AND claim_name !~ '["\\]'
    AND (
      (
        kind = 'profile'
        AND profile_field IS NOT NULL
        AND profile_field IN ('username', 'email', 'display_name')
      )
      OR (kind <> 'profile' AND profile_field IS NULL)
    )
    AND (
      kind NOT IN ('acr', 'amr')
      OR (claim_name = kind AND NOT required)
    )
  );
ALTER TABLE public.platform_oidc_discovery_snapshots
  DROP CONSTRAINT platform_oidc_discovery_snapshots_value_check;
ALTER TABLE public.platform_oidc_discovery_snapshots
  ADD CONSTRAINT platform_oidc_discovery_snapshots_value_check
  CHECK (
    revision > 0
    AND octet_length(document) BETWEEN 2 AND 1048576
    AND octet_length(document_digest) = 32
    AND fresh_until BETWEEN retrieved_at AND retrieved_at + interval '7 days'
    AND (cacheable OR (must_revalidate AND fresh_until = retrieved_at))
    AND client_authentication IN ('client_secret_basic', 'client_secret_post')
    AND cardinality(signing_algorithms) BETWEEN 1 AND 16
    AND array_position(signing_algorithms, NULL) IS NULL
  );
ALTER TABLE public.platform_oidc_provider_configurations
  DROP CONSTRAINT platform_oidc_provider_configurations_scope_check;
ALTER TABLE public.platform_oidc_provider_configurations
  ADD CONSTRAINT platform_oidc_provider_configurations_scope_check
  CHECK (
    cardinality(extra_scopes) <= 32
    AND array_position(extra_scopes, NULL) IS NULL
    AND array_position(extra_scopes, 'openid') IS NULL
  );
ALTER TABLE public.platform_saml_provider_configurations
  DROP CONSTRAINT platform_saml_provider_configurations_policy_check;
ALTER TABLE public.platform_saml_provider_configurations
  ADD CONSTRAINT platform_saml_provider_configurations_policy_check
  CHECK (
    redirect_signature_algorithm IN (
      'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
      'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384',
      'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512',
      'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256',
      'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384',
      'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512'
    )
    AND signature_policy IN ('signed_assertion', 'signed_response', 'both')
    AND encryption_policy = 'disabled'
    AND cardinality(decryption_key_versions) = 0
    AND array_position(decryption_key_versions, NULL) IS NULL
    AND cardinality(requested_authn_contexts) BETWEEN 1 AND 32
    AND array_position(requested_authn_contexts, NULL) IS NULL
    AND clock_skew_nanoseconds BETWEEN 0 AND 300000000000
    AND max_authentication_age_nanoseconds
      BETWEEN 60000000000 AND 86400000000000
  );
ALTER TABLE public.platform_saml_provider_configurations
  DROP CONSTRAINT platform_saml_provider_configurations_subject_check;
ALTER TABLE public.platform_saml_provider_configurations
  ADD CONSTRAINT platform_saml_provider_configurations_subject_check
  CHECK (
    (
      subject_source = 'persistent_nameid'
      AND subject_attribute_name IS NULL
      AND subject_attribute_name_format IS NULL
    )
    OR (
      subject_source = 'immutable_attribute'
      AND subject_attribute_name IS NOT NULL
      AND subject_attribute_name_format IS NOT NULL
      AND octet_length(convert_to(subject_attribute_name, 'UTF8'))
        BETWEEN 1 AND 512
      AND octet_length(convert_to(subject_attribute_name_format, 'UTF8'))
        BETWEEN 1 AND 512
    )
  );
ALTER TABLE public.platform_saml_attribute_rules
  DROP CONSTRAINT platform_saml_attribute_rules_value_check;
ALTER TABLE public.platform_saml_attribute_rules
  ADD CONSTRAINT platform_saml_attribute_rules_value_check
  CHECK (
    sequence BETWEEN 0 AND 1023
    AND kind IN ('scalar', 'profile', 'groups')
    AND octet_length(convert_to(attribute_name, 'UTF8')) BETWEEN 1 AND 512
    AND octet_length(convert_to(attribute_name_format, 'UTF8')) BETWEEN 1 AND 512
    AND attribute_name !~ '[[:cntrl:]]'
    AND attribute_name_format !~ '[[:cntrl:]]'
    AND (
      (
        kind = 'profile'
        AND profile_field IS NOT NULL
        AND profile_field IN ('username', 'email', 'display_name')
      )
      OR (kind <> 'profile' AND profile_field IS NULL)
    )
  );
ALTER TABLE public.platform_federated_trust_rules
  DROP CONSTRAINT platform_federated_trust_rules_value_check;
ALTER TABLE public.platform_federated_trust_rules
  ADD CONSTRAINT platform_federated_trust_rules_value_check
  CHECK (
    provider_kind IN ('oidc', 'saml')
    AND revision > 0
    AND level IN ('mfa', 'phishing_resistant')
    AND maximum_authentication_age_seconds BETWEEN 60 AND 2592000
    AND cardinality(required_values) <= 128
    AND array_position(required_values, NULL) IS NULL
    AND (
      (
        provider_kind = 'oidc'
        AND (exact_value IS NOT NULL OR cardinality(required_values) > 0)
      )
      OR (
        provider_kind = 'saml'
        AND exact_value IS NOT NULL
        AND cardinality(required_values) = 0
      )
    )
  );
--> statement-breakpoint

CREATE FUNCTION app.private_platform_identity_text_is_safe_v1(
  p_value text,
  p_require_trimmed boolean
)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
STRICT
PARALLEL SAFE
SET search_path = pg_catalog, app
AS $function$
  SELECT (NOT p_require_trimmed OR btrim(p_value) = p_value)
     AND NOT EXISTS (
       SELECT 1
       FROM generate_series(1, char_length(p_value)) AS character(position)
       CROSS JOIN LATERAL (
         SELECT ascii(substr(p_value, character.position, 1)) AS codepoint
       ) AS decoded
       WHERE decoded.codepoint BETWEEN 0 AND 31
          OR decoded.codepoint BETWEEN 127 AND 159
          OR decoded.codepoint = 173
          OR decoded.codepoint BETWEEN 1536 AND 1541
          OR decoded.codepoint IN (
            1564, 1757, 1807, 6158, 65279, 69821, 69837, 917505
          )
          OR decoded.codepoint BETWEEN 2192 AND 2193
          OR decoded.codepoint = 2274
          OR decoded.codepoint BETWEEN 8203 AND 8207
          OR decoded.codepoint BETWEEN 8234 AND 8238
          OR decoded.codepoint BETWEEN 8288 AND 8292
          OR decoded.codepoint BETWEEN 8294 AND 8303
          OR decoded.codepoint BETWEEN 65529 AND 65531
          OR decoded.codepoint BETWEEN 78896 AND 78911
          OR decoded.codepoint BETWEEN 113824 AND 113827
          OR decoded.codepoint BETWEEN 119155 AND 119162
          OR decoded.codepoint BETWEEN 917536 AND 917631
     )
     AND (
       NOT p_require_trimmed
       OR p_value = ''
       OR (
         ascii(substr(p_value, 1, 1)) NOT IN (
           32, 160, 5760, 8232, 8233, 8239, 8287, 12288
         )
         AND ascii(substr(p_value, char_length(p_value), 1)) NOT IN (
           32, 160, 5760, 8232, 8233, 8239, 8287, 12288
         )
         AND NOT ascii(substr(p_value, 1, 1)) BETWEEN 8192 AND 8202
         AND NOT ascii(substr(p_value, char_length(p_value), 1))
           BETWEEN 8192 AND 8202
       )
     );
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_platform_identity_uri_is_canonical_v1(
  p_value text,
  p_https_only boolean,
  p_allow_query boolean,
  p_maximum_bytes integer
)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
STRICT
PARALLEL SAFE
SET search_path = pg_catalog, app
AS $function$
DECLARE
  authority text;
  host_value text;
  port_value text;
  parsed_address inet;
BEGIN
  IF p_maximum_bytes NOT BETWEEN 1 AND 4096
     OR octet_length(p_value) NOT BETWEEN 1 AND p_maximum_bytes
     OR NOT app.private_platform_identity_text_is_safe_v1(p_value, true)
     OR p_value ~ '[[:space:]\\]'
     OR p_value ~ '%$'
     OR p_value ~ '%([^0-9A-Fa-f]|[0-9A-Fa-f]([^0-9A-Fa-f]|$))' THEN
    RETURN false;
  END IF;

  IF NOT p_https_only THEN
    RETURN p_value ~ '^[a-z][a-z0-9+.-]*:[^[:space:]]+$';
  END IF;

  IF p_value !~ '^https://'
     OR p_value ~ '#'
     OR (NOT p_allow_query AND p_value ~ '\?') THEN
    RETURN false;
  END IF;
  authority := substring(p_value FROM '^https://([^/?#]+)');
  IF authority IS NULL OR authority = '' OR authority ~ '@' THEN
    RETURN false;
  END IF;

  IF authority ~ '^\[' THEN
    IF authority !~ '^\[[0-9a-f:.]+\](:[1-9][0-9]{0,4})?$' THEN
      RETURN false;
    END IF;
    host_value := substring(authority FROM '^\[([^]]+)\]');
    port_value := substring(authority FROM '\]:([0-9]+)$');
    BEGIN
      parsed_address := host_value::inet;
    EXCEPTION WHEN invalid_text_representation THEN
      RETURN false;
    END;
    IF family(parsed_address) <> 6 OR host(parsed_address) <> host_value THEN
      RETURN false;
    END IF;
  ELSE
    IF authority ~ ':' THEN
      IF authority !~ '^[^:]+:[1-9][0-9]{0,4}$' THEN
        RETURN false;
      END IF;
      host_value := split_part(authority, ':', 1);
      port_value := split_part(authority, ':', 2);
    ELSE
      host_value := authority;
      port_value := NULL;
    END IF;
    IF host_value <> lower(host_value) OR char_length(host_value) > 253 THEN
      RETURN false;
    END IF;
    IF host_value ~ '^[0-9.]+$' THEN
      BEGIN
        parsed_address := host_value::inet;
      EXCEPTION WHEN invalid_text_representation THEN
        RETURN false;
      END;
      IF family(parsed_address) <> 4 OR host(parsed_address) <> host_value THEN
        RETURN false;
      END IF;
    ELSIF host_value !~
      '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$' THEN
      RETURN false;
    END IF;
  END IF;

  IF port_value IS NOT NULL AND port_value::integer > 65535 THEN
    RETURN false;
  END IF;
  RETURN true;
END;
$function$;
--> statement-breakpoint

ALTER FUNCTION app.private_platform_identity_text_is_safe_v1(text, boolean)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_platform_identity_uri_is_canonical_v1(
  text, boolean, boolean, integer
) OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_platform_identity_text_is_safe_v1(text, boolean)
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
    periapsis_auditor, periapsis_audit_reader_owner;
REVOKE ALL ON FUNCTION app.private_platform_identity_uri_is_canonical_v1(
  text, boolean, boolean, integer
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
    periapsis_auditor, periapsis_audit_reader_owner;
--> statement-breakpoint

-- The deployed keyring readiness ABI must inventory every live platform
-- ciphertext before an operator may remove a configured key version. Run the
-- keyring lock first so no secret rotation can retain a key row while waiting
-- for an envelope table lock; only then freeze both platform envelope tables.
CREATE OR REPLACE FUNCTION app.verify_identity_keyring_v3(
  p_versions integer[],
  p_verifiers bytea[],
  p_active_version integer
)
RETURNS boolean
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, app
AS $function$
BEGIN
  LOCK TABLE public.identity_keyring_versions IN EXCLUSIVE MODE;
  LOCK TABLE public.platform_oidc_client_secrets,
    public.platform_saml_sp_keys IN SHARE MODE;

  IF EXISTS (
    SELECT 1
    FROM public.tenant_ldap_directory_operation_runs AS operation
    LEFT JOIN public.identity_keyring_versions AS keyring
      ON keyring.key_version = operation.bind_secret_key_version
    WHERE operation.status = 'started'
      AND operation.expires_at > transaction_timestamp()
      AND (
        keyring.key_version IS NULL
        OR keyring.retired_at IS NOT NULL
        OR NOT operation.bind_secret_key_version = ANY(p_versions)
      )
  ) THEN
    RETURN false;
  END IF;

  IF EXISTS (
    SELECT 1
    FROM ONLY public.platform_oidc_client_secrets AS secret
    WHERE secret.retired_at IS NULL
      AND NOT secret.key_version = ANY(p_versions)
  ) OR EXISTS (
    SELECT 1
    FROM ONLY public.platform_saml_sp_keys AS sp_key
    WHERE sp_key.retired_at IS NULL
      AND NOT sp_key.key_version = ANY(p_versions)
  ) THEN
    RETURN false;
  END IF;

  RETURN app.verify_identity_keyring_v2(
    p_versions, p_verifiers, p_active_version
  );
END;
$function$;
ALTER FUNCTION app.verify_identity_keyring_v3(integer[], bytea[], integer)
  OWNER TO periapsis_migrator;
-- V1 and V2 remain implementation details used only through newer
-- SECURITY DEFINER wrappers. Remove every historical non-owner grant so a
-- runtime role cannot bypass the complete V3 platform-envelope inventory.
DO $platform_legacy_keyring_acl_reset$
DECLARE
  verifier_signature regprocedure;
  grantee_name name;
BEGIN
  FOR verifier_signature IN
    SELECT legacy_verifier.signature
    FROM (VALUES
      ('app.verify_identity_keyring_v1(integer[],bytea[],integer)'::regprocedure),
      ('app.verify_identity_keyring_v2(integer[],bytea[],integer)'::regprocedure)
    ) AS legacy_verifier(signature)
  LOOP
    FOR grantee_name IN
      SELECT DISTINCT grantee.rolname
      FROM pg_catalog.pg_proc AS function
      CROSS JOIN LATERAL pg_catalog.aclexplode(
        coalesce(
          function.proacl,
          pg_catalog.acldefault('f', function.proowner)
        )
      ) AS function_acl
      JOIN pg_catalog.pg_roles AS grantee
        ON grantee.oid = function_acl.grantee
      WHERE function.oid = verifier_signature
        AND function_acl.grantee <> function.proowner
    LOOP
      EXECUTE pg_catalog.format(
        'REVOKE ALL ON FUNCTION %s FROM %I CASCADE',
        verifier_signature, grantee_name
      );
    END LOOP;
  END LOOP;
END;
$platform_legacy_keyring_acl_reset$;
REVOKE ALL ON FUNCTION app.verify_identity_keyring_v1(integer[], bytea[], integer)
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
    periapsis_auditor, periapsis_audit_reader_owner,
    periapsis_notification_dispatch_owner,
    periapsis_sla_api_owner, periapsis_sla_worker_owner,
    periapsis_sla_readiness_owner, periapsis_ticket_saved_view_owner,
    periapsis_ticket_attribution_owner, periapsis_ticket_sla_projection_owner;
REVOKE ALL ON FUNCTION app.verify_identity_keyring_v2(integer[], bytea[], integer)
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
    periapsis_auditor, periapsis_audit_reader_owner,
    periapsis_notification_dispatch_owner,
    periapsis_sla_api_owner, periapsis_sla_worker_owner,
    periapsis_sla_readiness_owner, periapsis_ticket_saved_view_owner,
    periapsis_ticket_attribution_owner, periapsis_ticket_sla_projection_owner;
--> statement-breakpoint
-- CREATE OR REPLACE preserves the predecessor ACL. Reset every explicit
-- non-owner grantee, including roles introduced outside the migration catalog,
-- before installing the exact runtime boundary below.
DO $platform_keyring_acl_reset$
DECLARE
  grantee_name name;
BEGIN
  FOR grantee_name IN
    SELECT DISTINCT grantee.rolname
    FROM pg_catalog.pg_proc AS function
    CROSS JOIN LATERAL pg_catalog.aclexplode(
      coalesce(
        function.proacl,
        pg_catalog.acldefault('f', function.proowner)
      )
    ) AS function_acl
    JOIN pg_catalog.pg_roles AS grantee
      ON grantee.oid = function_acl.grantee
    WHERE function.oid =
      'app.verify_identity_keyring_v3(integer[],bytea[],integer)'::regprocedure
      AND function_acl.grantee <> function.proowner
  LOOP
    EXECUTE pg_catalog.format(
      'REVOKE ALL ON FUNCTION app.verify_identity_keyring_v3(integer[], bytea[], integer) FROM %I CASCADE',
      grantee_name
    );
  END LOOP;
END;
$platform_keyring_acl_reset$;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.verify_identity_keyring_v3(integer[], bytea[], integer)
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
    periapsis_auditor, periapsis_audit_reader_owner,
    periapsis_notification_dispatch_owner,
    periapsis_sla_api_owner, periapsis_sla_worker_owner,
    periapsis_sla_readiness_owner, periapsis_ticket_saved_view_owner,
    periapsis_ticket_attribution_owner, periapsis_ticket_sla_projection_owner;
GRANT EXECUTE ON FUNCTION app.verify_identity_keyring_v3(integer[], bytea[], integer)
  TO periapsis_migrator, periapsis_api, periapsis_worker;
--> statement-breakpoint

CREATE FUNCTION app.private_require_platform_identity_permission_v1(
  p_session_id uuid,
  p_permission text,
  p_authentication_method text
)
RETURNS uuid
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, app
AS $function$
DECLARE
  actor_id uuid := app.context_user_id();
  session_tenant_id uuid;
BEGIN
  IF p_session_id IS NULL
     OR uuid_extract_version(p_session_id) IS DISTINCT FROM 7
     OR p_permission IS NULL
     OR p_permission <> ALL (ARRAY[
       'platform.identity_provider.read',
       'platform.identity_provider.manage',
       'platform.identity_provider.test',
       'platform.identity_binding.read',
       'platform.identity_binding.manage',
       'platform.identity_policy.read',
       'platform.identity_policy.manage',
       'platform.identity_account.read',
       'platform.identity_account.manage'
     ]::text[])
     OR p_authentication_method IS NULL
     OR p_authentication_method NOT IN (
       'bootstrap_totp', 'oidc', 'passkey', 'recovery_code', 'saml', 'totp'
     ) THEN
    RAISE EXCEPTION 'invalid platform identity authorization request'
      USING ERRCODE = '22023';
  END IF;

  SELECT session.active_tenant_id INTO session_tenant_id
  FROM public.auth_sessions AS session
  JOIN public.users AS actor ON actor.id = session.user_id
  WHERE session.id = p_session_id
    AND session.user_id = actor_id
    AND session.authentication_method = p_authentication_method
    AND session.revoked_at IS NULL
    AND session.idle_expires_at > transaction_timestamp()
    AND session.absolute_expires_at > transaction_timestamp()
    AND actor.active
  FOR SHARE OF session, actor;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'live platform session authority is required'
      USING ERRCODE = '42501';
  END IF;

  IF session_tenant_id IS NOT NULL THEN
    -- The authorization state is the canonical tenant suspension and
    -- membership-change fence.  Take it before the tenant and membership rows,
    -- matching every writer, so authority remains true through the mutation.
    PERFORM 1
    FROM public.tenant_authorization_states AS authorization_state
    WHERE authorization_state.tenant_id = session_tenant_id
    FOR SHARE;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'live platform session authority is required'
        USING ERRCODE = '42501';
    END IF;

    PERFORM 1
    FROM public.tenants AS tenant
    WHERE tenant.id = session_tenant_id
      AND tenant.status = 'active'
    FOR SHARE;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'live platform session authority is required'
        USING ERRCODE = '42501';
    END IF;

    PERFORM 1
    FROM public.tenant_memberships AS membership
    WHERE membership.tenant_id = session_tenant_id
      AND membership.user_id = actor_id
      AND membership.status = 'active'
    FOR SHARE;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'live platform session authority is required'
        USING ERRCODE = '42501';
    END IF;
  END IF;

  PERFORM 1
  FROM public.user_platform_roles AS user_role
  JOIN public.platform_role_permissions AS role_permission
    ON role_permission.role_id = user_role.role_id
  JOIN public.platform_permissions AS permission
    ON permission.id = role_permission.permission_id
  WHERE user_role.user_id = actor_id
    AND user_role.revoked_at IS NULL
    AND permission.key = p_permission
  FOR SHARE OF user_role, role_permission, permission;
  IF NOT FOUND OR NOT app.platform_user_has_permission(actor_id, p_permission) THEN
    RAISE EXCEPTION 'required platform identity permission is missing'
      USING ERRCODE = '42501';
  END IF;

  RETURN actor_id;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.private_require_platform_identity_permission_v1(uuid, text, text)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_require_platform_identity_permission_v1(uuid, text, text)
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;
--> statement-breakpoint

CREATE FUNCTION app.list_platform_auth_providers_v1(
  p_session_id uuid,
  p_authentication_method text,
  p_after uuid DEFAULT NULL,
  p_limit integer DEFAULT 50,
  p_include_archived boolean DEFAULT false
)
RETURNS TABLE (document jsonb)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, app
AS $function$
BEGIN
  IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 200
     OR p_include_archived IS NULL
     OR (p_after IS NOT NULL AND uuid_extract_version(p_after) IS DISTINCT FROM 7) THEN
    RAISE EXCEPTION 'invalid platform identity provider list request'
      USING ERRCODE = '22023';
  END IF;

  PERFORM app.private_require_platform_identity_permission_v1(
    p_session_id, 'platform.identity_provider.read', p_authentication_method
  );

  RETURN QUERY
  SELECT jsonb_build_object(
    'id', provider.id,
    'key', provider.key,
    'displayName', provider.display_name,
    'description', provider.description,
    'kind', provider.kind,
    'enabled', provider.enabled,
    'platformLoginEnabled', policy.platform_login_enabled,
    'configured', CASE provider.kind
      WHEN 'oidc' THEN oidc.provider_id IS NOT NULL
      WHEN 'saml' THEN saml.provider_id IS NOT NULL
      ELSE false
    END,
    'secretPresent', CASE provider.kind
      WHEN 'oidc' THEN EXISTS (
        SELECT 1
        FROM ONLY public.platform_oidc_client_secrets AS secret
        WHERE secret.provider_id = provider.id AND secret.retired_at IS NULL
      )
      WHEN 'saml' THEN false
      ELSE false
    END,
    'archivedAt', provider.archived_at,
    'version', provider.version,
    'createdAt', provider.created_at,
    'updatedAt', provider.updated_at
  )
  FROM ONLY public.platform_auth_providers AS provider
  LEFT JOIN ONLY public.platform_federated_provider_policies AS policy
    ON policy.provider_id = provider.id
  LEFT JOIN ONLY public.platform_oidc_provider_configurations AS oidc
    ON oidc.provider_id = provider.id AND provider.kind = 'oidc'
  LEFT JOIN ONLY public.platform_saml_provider_configurations AS saml
    ON saml.provider_id = provider.id AND provider.kind = 'saml'
  WHERE (p_after IS NULL OR provider.id > p_after)
    AND (p_include_archived OR provider.archived_at IS NULL)
  ORDER BY provider.id
  LIMIT p_limit;
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.get_platform_auth_provider_v1(
  p_session_id uuid,
  p_provider_id uuid,
  p_authentication_method text
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, app
AS $function$
DECLARE
  result jsonb;
BEGIN
  IF p_provider_id IS NULL
     OR uuid_extract_version(p_provider_id) IS DISTINCT FROM 7 THEN
    RAISE EXCEPTION 'invalid platform identity provider identifier'
      USING ERRCODE = '22023';
  END IF;

  PERFORM app.private_require_platform_identity_permission_v1(
    p_session_id, 'platform.identity_provider.read', p_authentication_method
  );

  SELECT jsonb_build_object(
    'id', provider.id,
    'key', provider.key,
    'displayName', provider.display_name,
    'description', provider.description,
    'kind', provider.kind,
    'enabled', provider.enabled,
    'platformLoginEnabled', policy.platform_login_enabled,
    'configurationRevision', policy.configuration_revision,
    'securityRevision', policy.security_revision,
    'planRevision', policy.plan_revision,
    'assurancePolicyRevision', policy.assurance_policy_revision,
    'accountMode', policy.account_mode,
    'configuration', CASE provider.kind
      WHEN 'oidc' THEN jsonb_build_object(
        'issuer', oidc.issuer,
        'clientId', oidc.client_id,
        'redirectUri', oidc.redirect_uri,
        'postLogoutRedirectUri', oidc.post_logout_redirect_uri,
        'extraScopes', oidc.extra_scopes,
        'allowRefreshToken', oidc.allow_refresh_token,
        'useUserInfo', oidc.use_user_info,
        'clientSecretRevision', oidc.client_secret_revision,
        'clientSecretPresent', EXISTS (
          SELECT 1 FROM ONLY public.platform_oidc_client_secrets AS secret
          WHERE secret.provider_id = provider.id AND secret.retired_at IS NULL
        ),
        'discoveryRevision', oidc.discovery_revision,
        'jwksRevision', oidc.jwks_revision
      )
      WHEN 'saml' THEN jsonb_build_object(
        'expectedEntityId', saml.expected_entity_id,
        'spEntityId', saml.sp_entity_id,
        'acsUrl', saml.acs_url,
        'spKeyRevision', saml.sp_key_revision,
        'spKeyPresent', EXISTS (
          SELECT 1 FROM ONLY public.platform_saml_sp_keys AS sp_key
          WHERE sp_key.provider_id = provider.id AND sp_key.retired_at IS NULL
        ),
        'metadataRevision', saml.metadata_revision,
        'redirectSignatureAlgorithm', saml.redirect_signature_algorithm,
        'signaturePolicy', saml.signature_policy,
        'encryptionPolicy', saml.encryption_policy,
        'requestedAuthnContexts', saml.requested_authn_contexts,
        'subjectSource', saml.subject_source,
        'clockSkewNanoseconds', saml.clock_skew_nanoseconds,
        'maxAuthenticationAgeNanoseconds', saml.max_authentication_age_nanoseconds
      ) || CASE
        WHEN saml.subject_source = 'immutable_attribute' THEN jsonb_build_object(
          'subjectAttributeName', saml.subject_attribute_name,
          'subjectAttributeNameFormat', saml.subject_attribute_name_format
        )
        ELSE '{}'::jsonb
      END
      ELSE NULL
    END,
    'archivedAt', provider.archived_at,
    'version', provider.version,
    'createdAt', provider.created_at,
    'updatedAt', provider.updated_at
  ) INTO result
  FROM ONLY public.platform_auth_providers AS provider
  JOIN ONLY public.platform_federated_provider_policies AS policy
    ON policy.provider_id = provider.id
  LEFT JOIN ONLY public.platform_oidc_provider_configurations AS oidc
    ON oidc.provider_id = provider.id AND provider.kind = 'oidc'
  LEFT JOIN ONLY public.platform_saml_provider_configurations AS saml
    ON saml.provider_id = provider.id AND provider.kind = 'saml'
  WHERE provider.id = p_provider_id;

  IF result IS NULL THEN
    RAISE EXCEPTION 'platform identity provider does not exist'
      USING ERRCODE = 'P0002';
  END IF;
  RETURN result;
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_platform_auth_provider_document_v1(
  p_provider_id uuid
)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, app
AS $function$
DECLARE
  result jsonb;
BEGIN
  SELECT jsonb_build_object(
    'id', provider.id,
    'key', provider.key,
    'displayName', provider.display_name,
    'description', provider.description,
    'kind', provider.kind,
    'enabled', provider.enabled,
    'platformLoginEnabled', policy.platform_login_enabled,
    'configurationRevision', policy.configuration_revision,
    'securityRevision', policy.security_revision,
    'planRevision', policy.plan_revision,
    'assurancePolicyRevision', policy.assurance_policy_revision,
    'accountMode', policy.account_mode,
    'configuration', CASE provider.kind
      WHEN 'oidc' THEN jsonb_build_object(
        'issuer', oidc.issuer,
        'clientId', oidc.client_id,
        'redirectUri', oidc.redirect_uri,
        'postLogoutRedirectUri', oidc.post_logout_redirect_uri,
        'extraScopes', oidc.extra_scopes,
        'allowRefreshToken', oidc.allow_refresh_token,
        'useUserInfo', oidc.use_user_info,
        'clientSecretRevision', oidc.client_secret_revision,
        'clientSecretPresent', EXISTS (
          SELECT 1 FROM ONLY public.platform_oidc_client_secrets AS secret
          WHERE secret.provider_id = provider.id AND secret.retired_at IS NULL
        ),
        'discoveryRevision', oidc.discovery_revision,
        'jwksRevision', oidc.jwks_revision
      )
      WHEN 'saml' THEN jsonb_build_object(
        'expectedEntityId', saml.expected_entity_id,
        'spEntityId', saml.sp_entity_id,
        'acsUrl', saml.acs_url,
        'spKeyRevision', saml.sp_key_revision,
        'spKeyPresent', EXISTS (
          SELECT 1 FROM ONLY public.platform_saml_sp_keys AS sp_key
          WHERE sp_key.provider_id = provider.id AND sp_key.retired_at IS NULL
        ),
        'metadataRevision', saml.metadata_revision,
        'redirectSignatureAlgorithm', saml.redirect_signature_algorithm,
        'signaturePolicy', saml.signature_policy,
        'encryptionPolicy', saml.encryption_policy,
        'requestedAuthnContexts', saml.requested_authn_contexts,
        'subjectSource', saml.subject_source,
        'clockSkewNanoseconds', saml.clock_skew_nanoseconds,
        'maxAuthenticationAgeNanoseconds', saml.max_authentication_age_nanoseconds
      ) || CASE
        WHEN saml.subject_source = 'immutable_attribute' THEN jsonb_build_object(
          'subjectAttributeName', saml.subject_attribute_name,
          'subjectAttributeNameFormat', saml.subject_attribute_name_format
        )
        ELSE '{}'::jsonb
      END
      ELSE NULL
    END,
    'archivedAt', provider.archived_at,
    'version', provider.version,
    'createdAt', provider.created_at,
    'updatedAt', provider.updated_at
  ) INTO result
  FROM ONLY public.platform_auth_providers AS provider
  JOIN ONLY public.platform_federated_provider_policies AS policy
    ON policy.provider_id = provider.id
  LEFT JOIN ONLY public.platform_oidc_provider_configurations AS oidc
    ON oidc.provider_id = provider.id AND provider.kind = 'oidc'
  LEFT JOIN ONLY public.platform_saml_provider_configurations AS saml
    ON saml.provider_id = provider.id AND provider.kind = 'saml'
  WHERE provider.id = p_provider_id;

  IF result IS NULL THEN
    RAISE EXCEPTION 'platform identity provider does not exist'
      USING ERRCODE = 'P0002';
  END IF;
  RETURN result;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.private_platform_auth_provider_document_v1(uuid)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_platform_auth_provider_document_v1(uuid)
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
    periapsis_auditor, periapsis_audit_reader_owner;
--> statement-breakpoint

CREATE FUNCTION app.create_platform_auth_provider_v1(
  p_session_id uuid,
  p_command_id uuid,
  p_provider_id uuid,
  p_kind public.auth_provider_kind,
  p_key text,
  p_display_name text,
  p_description text,
  p_configuration jsonb,
  p_key_digest bytea,
  p_request_digest bytea,
  p_audit_event_id uuid,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text,
  p_reason text
)
RETURNS TABLE (
  provider_id uuid,
  version bigint,
  replayed boolean,
  document jsonb
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, app
AS $function$
DECLARE
  actor_id uuid;
  read_actor_id uuid;
  operation_name text;
  replay_record public.platform_identity_provider_commands%ROWTYPE;
  oidc_extra_scopes text[];
  saml_decryption_key_versions integer[];
  saml_requested_contexts text[];
  saml_clock_skew bigint;
  saml_maximum_authentication_age bigint;
  provider_document jsonb;
BEGIN
  IF p_command_id IS NULL OR uuid_extract_version(p_command_id) IS DISTINCT FROM 7
     OR p_provider_id IS NULL OR uuid_extract_version(p_provider_id) IS DISTINCT FROM 7
     OR p_kind IS NULL OR p_kind NOT IN ('oidc', 'saml')
     OR p_key IS NULL OR p_key !~ '^[a-z][a-z0-9_-]{2,63}$'
     OR p_display_name IS NULL
     OR char_length(p_display_name) NOT BETWEEN 1 AND 120
     OR NOT app.private_platform_identity_text_is_safe_v1(p_display_name, true)
     OR p_description IS NULL OR char_length(p_description) > 1000
     OR NOT app.private_platform_identity_text_is_safe_v1(p_description, true)
     OR p_configuration IS NULL OR jsonb_typeof(p_configuration) <> 'object'
     OR pg_column_size(p_configuration) NOT BETWEEN 2 AND 65536
     OR p_key_digest IS NULL OR octet_length(p_key_digest) <> 32
     OR p_request_digest IS NULL OR octet_length(p_request_digest) <> 32
     OR p_audit_event_id IS NULL OR uuid_extract_version(p_audit_event_id) IS DISTINCT FROM 7
     OR p_request_id IS NULL OR uuid_extract_version(p_request_id) IS DISTINCT FROM 7
     OR p_correlation_id IS NULL OR uuid_extract_version(p_correlation_id) IS DISTINCT FROM 7
     OR p_ip_address IS NULL
     OR p_user_agent IS NULL OR octet_length(p_user_agent) NOT BETWEEN 1 AND 512
     OR NOT app.private_platform_identity_text_is_safe_v1(p_user_agent, false)
     OR p_reason IS NULL
     OR NOT app.private_platform_lifecycle_reason_is_valid_v1(p_reason) THEN
    RAISE EXCEPTION 'invalid platform identity provider create command'
      USING ERRCODE = '22023';
  END IF;

  actor_id := app.private_require_platform_identity_permission_v1(
    p_session_id, 'platform.identity_provider.manage', p_authentication_method
  );
  read_actor_id := app.private_require_platform_identity_permission_v1(
    p_session_id, 'platform.identity_provider.read', p_authentication_method
  );
  IF read_actor_id IS DISTINCT FROM actor_id THEN
    RAISE EXCEPTION 'live platform identity provider read authority is required'
      USING ERRCODE = '42501';
  END IF;
  operation_name := 'provider.create';

  PERFORM pg_advisory_xact_lock(hashtextextended(
    actor_id::text || ':' || operation_name || ':' || encode(p_key_digest, 'hex'), 0
  ));
  DELETE FROM ONLY public.platform_identity_provider_commands AS command
  WHERE command.actor_user_id = actor_id
    AND command.operation = operation_name
    AND command.key_digest = p_key_digest
    AND command.expires_at <= transaction_timestamp();

  IF pg_try_advisory_xact_lock(hashtextextended(
       'platform_identity_provider_commands:expiry-cleanup:v1', 0
     )) THEN
    WITH expired_command AS (
      SELECT command.id
      FROM ONLY public.platform_identity_provider_commands AS command
      WHERE command.expires_at <= transaction_timestamp()
      ORDER BY command.expires_at, command.id
      LIMIT 64
      FOR UPDATE SKIP LOCKED
    )
    DELETE FROM ONLY public.platform_identity_provider_commands AS command
    USING expired_command
    WHERE command.id = expired_command.id;
  END IF;

  SELECT command.* INTO replay_record
  FROM ONLY public.platform_identity_provider_commands AS command
  WHERE command.actor_user_id = actor_id
    AND command.operation = operation_name
    AND command.key_digest = p_key_digest
    AND command.expires_at > transaction_timestamp();
  IF FOUND THEN
    IF replay_record.request_digest <> p_request_digest THEN
      RAISE EXCEPTION 'platform identity provider idempotency conflict'
        USING ERRCODE = '23505';
    END IF;
    PERFORM 1
    FROM ONLY public.platform_auth_providers AS provider
    WHERE provider.id = replay_record.result_provider_id
    FOR UPDATE;
    provider_document := app.private_platform_auth_provider_document_v1(
      replay_record.result_provider_id
    );
    RETURN QUERY SELECT replay_record.result_provider_id,
                        replay_record.result_version,
                        true,
                        provider_document;
    RETURN;
  END IF;

  IF p_kind = 'oidc' THEN
    IF NOT p_configuration ?& ARRAY[
         'issuer','clientId','redirectUri','postLogoutRedirectUri',
         'extraScopes','allowRefreshToken','useUserInfo'
       ]::text[]
       OR EXISTS (
         SELECT 1 FROM jsonb_object_keys(p_configuration) AS key(value)
         WHERE key.value <> ALL (ARRAY[
           'issuer','clientId','redirectUri','postLogoutRedirectUri',
           'extraScopes','allowRefreshToken','useUserInfo'
         ]::text[])
       )
       OR jsonb_typeof(p_configuration->'issuer') <> 'string'
       OR jsonb_typeof(p_configuration->'clientId') <> 'string'
       OR jsonb_typeof(p_configuration->'redirectUri') <> 'string'
       OR jsonb_typeof(p_configuration->'postLogoutRedirectUri') <> 'string'
       OR jsonb_typeof(p_configuration->'extraScopes') <> 'array'
       OR EXISTS (
         SELECT 1 FROM jsonb_array_elements(p_configuration->'extraScopes') AS item(value)
         WHERE jsonb_typeof(item.value) <> 'string'
       )
       OR jsonb_typeof(p_configuration->'allowRefreshToken') <> 'boolean'
       OR jsonb_typeof(p_configuration->'useUserInfo') <> 'boolean'
       OR NOT app.private_platform_identity_uri_is_canonical_v1(
         p_configuration->>'issuer', true, false, 4096
       )
       OR NOT app.private_platform_identity_uri_is_canonical_v1(
         p_configuration->>'redirectUri', true, true, 4096
       )
       OR NOT app.private_platform_identity_uri_is_canonical_v1(
         p_configuration->>'postLogoutRedirectUri', true, true, 4096
       )
       OR octet_length(p_configuration->>'clientId') NOT BETWEEN 1 AND 512
       OR NOT app.private_platform_identity_text_is_safe_v1(
         p_configuration->>'clientId', true
       ) THEN
      RAISE EXCEPTION 'invalid platform OIDC configuration'
        USING ERRCODE = '22023';
    END IF;
    oidc_extra_scopes := ARRAY(
      SELECT value
      FROM jsonb_array_elements_text(p_configuration->'extraScopes')
        AS item(value)
    );
    IF cardinality(oidc_extra_scopes) > 32
       OR EXISTS (
         SELECT 1
         FROM unnest(oidc_extra_scopes) AS scope(value)
         WHERE octet_length(scope.value) NOT BETWEEN 1 AND 128
            OR scope.value = 'openid'
            OR scope.value !~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$'
       )
       OR cardinality(oidc_extra_scopes) <> (
         SELECT count(DISTINCT scope.value)
         FROM unnest(oidc_extra_scopes) AS scope(value)
       )
       OR oidc_extra_scopes IS DISTINCT FROM ARRAY(
         SELECT scope.value
         FROM unnest(oidc_extra_scopes) AS scope(value)
         ORDER BY scope.value COLLATE "C"
       ) THEN
      RAISE EXCEPTION 'invalid platform OIDC configuration'
        USING ERRCODE = '22023';
    END IF;
  ELSE
    IF NOT p_configuration ?& ARRAY[
         'expectedEntityId','spEntityId','acsUrl','redirectSignatureAlgorithm',
         'signaturePolicy','encryptionPolicy','decryptionKeyVersions',
         'requestedAuthnContexts','subjectSource','clockSkewNanoseconds',
         'maxAuthenticationAgeNanoseconds'
       ]::text[]
       OR EXISTS (
         SELECT 1 FROM jsonb_object_keys(p_configuration) AS key(value)
         WHERE key.value <> ALL (ARRAY[
           'expectedEntityId','spEntityId','acsUrl','redirectSignatureAlgorithm',
           'signaturePolicy','encryptionPolicy','decryptionKeyVersions',
           'requestedAuthnContexts','subjectSource','subjectAttributeName',
           'subjectAttributeNameFormat','clockSkewNanoseconds',
           'maxAuthenticationAgeNanoseconds'
         ]::text[])
       )
       OR jsonb_typeof(p_configuration->'expectedEntityId') <> 'string'
       OR jsonb_typeof(p_configuration->'spEntityId') <> 'string'
       OR jsonb_typeof(p_configuration->'acsUrl') <> 'string'
       OR jsonb_typeof(p_configuration->'redirectSignatureAlgorithm') <> 'string'
       OR jsonb_typeof(p_configuration->'signaturePolicy') <> 'string'
       OR jsonb_typeof(p_configuration->'encryptionPolicy') <> 'string'
       OR jsonb_typeof(p_configuration->'decryptionKeyVersions') <> 'array'
       OR jsonb_typeof(p_configuration->'requestedAuthnContexts') <> 'array'
       OR EXISTS (
         SELECT 1 FROM jsonb_array_elements(p_configuration->'requestedAuthnContexts') AS item(value)
         WHERE jsonb_typeof(item.value) <> 'string'
       )
       OR jsonb_typeof(p_configuration->'subjectSource') <> 'string'
       OR (p_configuration ? 'subjectAttributeName'
           AND jsonb_typeof(p_configuration->'subjectAttributeName') <> 'string')
       OR (p_configuration ? 'subjectAttributeNameFormat'
           AND jsonb_typeof(p_configuration->'subjectAttributeNameFormat') <> 'string')
       OR jsonb_typeof(p_configuration->'clockSkewNanoseconds') <> 'number'
       OR jsonb_typeof(p_configuration->'maxAuthenticationAgeNanoseconds') <> 'number'
       OR (p_configuration->'clockSkewNanoseconds')::text !~ '^(0|[1-9][0-9]*)$'
       OR (p_configuration->'maxAuthenticationAgeNanoseconds')::text
          !~ '^(0|[1-9][0-9]*)$'
       OR NOT app.private_platform_identity_uri_is_canonical_v1(
         p_configuration->>'expectedEntityId', false, true, 2048
       )
       OR NOT app.private_platform_identity_uri_is_canonical_v1(
         p_configuration->>'spEntityId', false, true, 2048
       )
       OR NOT app.private_platform_identity_uri_is_canonical_v1(
         p_configuration->>'acsUrl', true, true, 4096
       )
       OR p_configuration->>'redirectSignatureAlgorithm' <> ALL (ARRAY[
         'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
         'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384',
         'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512',
         'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256',
         'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384',
         'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512'
       ]::text[])
       OR p_configuration->>'signaturePolicy' NOT IN (
         'signed_assertion', 'signed_response', 'both'
       )
       OR p_configuration->>'encryptionPolicy' <> 'disabled'
       OR jsonb_array_length(p_configuration->'decryptionKeyVersions') <> 0 THEN
      RAISE EXCEPTION 'invalid platform SAML configuration'
        USING ERRCODE = '22023';
    END IF;
    BEGIN
      saml_clock_skew := (p_configuration->>'clockSkewNanoseconds')::bigint;
      saml_maximum_authentication_age :=
        (p_configuration->>'maxAuthenticationAgeNanoseconds')::bigint;
    EXCEPTION WHEN numeric_value_out_of_range THEN
      RAISE EXCEPTION 'invalid platform SAML configuration'
        USING ERRCODE = '22023';
    END;
    IF saml_clock_skew NOT BETWEEN 0 AND 300000000000
       OR saml_maximum_authentication_age
          NOT BETWEEN 60000000000 AND 86400000000000 THEN
      RAISE EXCEPTION 'invalid platform SAML configuration'
        USING ERRCODE = '22023';
    END IF;
    saml_decryption_key_versions := ARRAY[]::integer[];
    saml_requested_contexts := ARRAY(
      SELECT value
      FROM jsonb_array_elements_text(p_configuration->'requestedAuthnContexts') AS item(value)
    );
    IF cardinality(saml_requested_contexts) NOT BETWEEN 1 AND 32
       OR EXISTS (
         SELECT 1
         FROM unnest(saml_requested_contexts) AS context(value)
         WHERE NOT app.private_platform_identity_uri_is_canonical_v1(
           context.value, false, true, 2048
         )
       )
       OR cardinality(saml_requested_contexts) <> (
         SELECT count(DISTINCT context.value)
         FROM unnest(saml_requested_contexts) AS context(value)
       )
       OR saml_requested_contexts IS DISTINCT FROM ARRAY(
         SELECT context.value
         FROM unnest(saml_requested_contexts) AS context(value)
         ORDER BY context.value COLLATE "C"
       )
       OR p_configuration->>'subjectSource' NOT IN (
         'persistent_nameid', 'immutable_attribute'
       )
       OR (
         p_configuration->>'subjectSource' = 'persistent_nameid'
         AND (
           p_configuration ? 'subjectAttributeName'
           OR p_configuration ? 'subjectAttributeNameFormat'
         )
       )
       OR (
         p_configuration->>'subjectSource' = 'immutable_attribute'
         AND (
           NOT p_configuration ?& ARRAY[
             'subjectAttributeName', 'subjectAttributeNameFormat'
           ]::text[]
           OR octet_length(p_configuration->>'subjectAttributeName')
              NOT BETWEEN 1 AND 512
           OR NOT app.private_platform_identity_text_is_safe_v1(
             p_configuration->>'subjectAttributeName', true
           )
           OR NOT app.private_platform_identity_uri_is_canonical_v1(
             p_configuration->>'subjectAttributeNameFormat', false, true, 512
           )
         )
       ) THEN
      RAISE EXCEPTION 'invalid platform SAML configuration'
        USING ERRCODE = '22023';
    END IF;
  END IF;

  INSERT INTO public.platform_auth_providers (
    id, key, display_name, description, kind, enabled,
    created_by_user_id, updated_by_user_id, version
  ) VALUES (
    p_provider_id, p_key, p_display_name, p_description, p_kind, false,
    actor_id, actor_id, 1
  );
  INSERT INTO public.platform_federated_provider_policies (
    provider_id, provider_kind, configuration_revision, security_revision,
    plan_revision, assurance_policy_revision, account_mode,
    platform_login_enabled, enabled
  ) VALUES (
    p_provider_id, p_kind, 1, 1, 1, 1, 'disabled', false, false
  );

  IF p_kind = 'oidc' THEN
    INSERT INTO public.platform_oidc_provider_configurations (
      provider_id, issuer, client_id, redirect_uri, post_logout_redirect_uri,
      extra_scopes, allow_refresh_token, use_user_info,
      client_secret_revision, discovery_revision, jwks_revision
    ) VALUES (
      p_provider_id,
      p_configuration->>'issuer',
      p_configuration->>'clientId',
      p_configuration->>'redirectUri',
      p_configuration->>'postLogoutRedirectUri',
      oidc_extra_scopes,
      COALESCE((p_configuration->>'allowRefreshToken')::boolean, false),
      COALESCE((p_configuration->>'useUserInfo')::boolean, false),
      1, 1, 1
    );
  ELSE
    INSERT INTO public.platform_saml_provider_configurations (
      provider_id, expected_entity_id, sp_entity_id, acs_url, sp_key_revision,
      metadata_revision, redirect_signature_algorithm, signature_policy,
      encryption_policy, decryption_key_versions, requested_authn_contexts,
      subject_source, subject_attribute_name, subject_attribute_name_format,
      clock_skew_nanoseconds, max_authentication_age_nanoseconds
    ) VALUES (
      p_provider_id,
      p_configuration->>'expectedEntityId',
      p_configuration->>'spEntityId',
      p_configuration->>'acsUrl',
      1, 1,
      p_configuration->>'redirectSignatureAlgorithm',
      p_configuration->>'signaturePolicy',
      p_configuration->>'encryptionPolicy',
      saml_decryption_key_versions,
      saml_requested_contexts,
      p_configuration->>'subjectSource',
      p_configuration->>'subjectAttributeName',
      p_configuration->>'subjectAttributeNameFormat',
      saml_clock_skew,
      saml_maximum_authentication_age
    );
  END IF;

  INSERT INTO public.platform_identity_provider_commands (
    id, actor_user_id, operation, key_digest, request_digest,
    result_provider_id, result_version
  ) VALUES (
    p_command_id, actor_id, operation_name, p_key_digest, p_request_digest,
    p_provider_id, 1
  );

  PERFORM app.append_platform_audit_event(
    p_audit_event_id, 'user', actor_id,
    'platform.identity_provider.created', 'platform_identity_provider', p_provider_id,
    p_request_id, p_correlation_id, p_ip_address, p_user_agent,
    p_authentication_method, 'success', p_reason,
    jsonb_build_object(
      'kind', p_kind,
      'key', p_key,
      'version', 1,
      'enabled', false,
      'platform_login_enabled', false,
      'secret_material_included', false
    )
  );

  provider_document := app.private_platform_auth_provider_document_v1(
    p_provider_id
  );
  RETURN QUERY SELECT p_provider_id, 1::bigint, false, provider_document;
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.update_platform_auth_provider_v1(
  p_session_id uuid,
  p_provider_id uuid,
  p_expected_version bigint,
  p_key text,
  p_display_name text,
  p_description text,
  p_audit_event_id uuid,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text,
  p_reason text
)
RETURNS TABLE (version bigint, document jsonb)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, app
AS $function$
DECLARE
  actor_id uuid;
  read_actor_id uuid;
  provider_record public.platform_auth_providers%ROWTYPE;
  provider_document jsonb;
BEGIN
  IF p_provider_id IS NULL OR uuid_extract_version(p_provider_id) IS DISTINCT FROM 7
     OR p_expected_version IS NULL
     OR p_expected_version NOT BETWEEN 1 AND 2147483646
     OR p_key IS NULL OR p_key !~ '^[a-z][a-z0-9_-]{2,63}$'
     OR p_display_name IS NULL
     OR char_length(p_display_name) NOT BETWEEN 1 AND 120
     OR NOT app.private_platform_identity_text_is_safe_v1(p_display_name, true)
     OR p_description IS NULL OR char_length(p_description) > 1000
     OR NOT app.private_platform_identity_text_is_safe_v1(p_description, true)
     OR p_audit_event_id IS NULL OR uuid_extract_version(p_audit_event_id) IS DISTINCT FROM 7
     OR p_request_id IS NULL OR uuid_extract_version(p_request_id) IS DISTINCT FROM 7
     OR p_correlation_id IS NULL OR uuid_extract_version(p_correlation_id) IS DISTINCT FROM 7
     OR p_ip_address IS NULL OR p_user_agent IS NULL
     OR octet_length(p_user_agent) NOT BETWEEN 1 AND 512
     OR NOT app.private_platform_identity_text_is_safe_v1(p_user_agent, false)
     OR p_reason IS NULL
     OR NOT app.private_platform_lifecycle_reason_is_valid_v1(p_reason) THEN
    RAISE EXCEPTION 'invalid platform identity provider update command'
      USING ERRCODE = '22023';
  END IF;
  actor_id := app.private_require_platform_identity_permission_v1(
    p_session_id, 'platform.identity_provider.manage', p_authentication_method
  );
  read_actor_id := app.private_require_platform_identity_permission_v1(
    p_session_id, 'platform.identity_provider.read', p_authentication_method
  );
  IF read_actor_id IS DISTINCT FROM actor_id THEN
    RAISE EXCEPTION 'live platform identity provider read authority is required'
      USING ERRCODE = '42501';
  END IF;

  SELECT provider.* INTO provider_record
  FROM ONLY public.platform_auth_providers AS provider
  WHERE provider.id = p_provider_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'platform identity provider does not exist'
      USING ERRCODE = 'P0002';
  END IF;
  IF provider_record.version <> p_expected_version THEN
    RAISE EXCEPTION 'platform identity provider revision conflict'
      USING ERRCODE = '40001';
  END IF;
  IF provider_record.archived_at IS NOT NULL THEN
    RAISE EXCEPTION 'platform identity provider is archived'
      USING ERRCODE = '55000';
  END IF;

  UPDATE ONLY public.platform_auth_providers AS provider
  SET key = p_key,
      display_name = p_display_name,
      description = p_description,
      updated_by_user_id = actor_id,
      version = provider_record.version + 1,
      updated_at = transaction_timestamp()
  WHERE provider.id = p_provider_id;

  PERFORM app.append_platform_audit_event(
    p_audit_event_id, 'user', actor_id,
    'platform.identity_provider.updated', 'platform_identity_provider', p_provider_id,
    p_request_id, p_correlation_id, p_ip_address, p_user_agent,
    p_authentication_method, 'success', p_reason,
    jsonb_build_object(
      'kind', provider_record.kind,
      'previous_version', provider_record.version,
      'version', provider_record.version + 1
    )
  );
  provider_document := app.private_platform_auth_provider_document_v1(
    p_provider_id
  );
  RETURN QUERY SELECT provider_record.version + 1, provider_document;
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.archive_platform_auth_provider_v1(
  p_session_id uuid,
  p_provider_id uuid,
  p_expected_version bigint,
  p_audit_event_id uuid,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text,
  p_reason text
)
RETURNS bigint
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, app
AS $function$
DECLARE
  actor_id uuid;
  provider_record public.platform_auth_providers%ROWTYPE;
  policy_record public.platform_federated_provider_policies%ROWTYPE;
  changed_at timestamp with time zone := transaction_timestamp();
BEGIN
  IF p_provider_id IS NULL OR uuid_extract_version(p_provider_id) IS DISTINCT FROM 7
     OR p_expected_version IS NULL
     OR p_expected_version NOT BETWEEN 1 AND 2147483646
     OR p_audit_event_id IS NULL OR uuid_extract_version(p_audit_event_id) IS DISTINCT FROM 7
     OR p_request_id IS NULL OR uuid_extract_version(p_request_id) IS DISTINCT FROM 7
     OR p_correlation_id IS NULL OR uuid_extract_version(p_correlation_id) IS DISTINCT FROM 7
     OR p_ip_address IS NULL OR p_user_agent IS NULL
     OR octet_length(p_user_agent) NOT BETWEEN 1 AND 512
     OR NOT app.private_platform_identity_text_is_safe_v1(p_user_agent, false)
     OR p_reason IS NULL
     OR NOT app.private_platform_lifecycle_reason_is_valid_v1(p_reason) THEN
    RAISE EXCEPTION 'invalid platform identity provider archive command'
      USING ERRCODE = '22023';
  END IF;
  actor_id := app.private_require_platform_identity_permission_v1(
    p_session_id, 'platform.identity_provider.manage', p_authentication_method
  );

  SELECT provider.* INTO provider_record
  FROM ONLY public.platform_auth_providers AS provider
  WHERE provider.id = p_provider_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'platform identity provider does not exist'
      USING ERRCODE = 'P0002';
  END IF;
  IF provider_record.version <> p_expected_version THEN
    RAISE EXCEPTION 'platform identity provider revision conflict'
      USING ERRCODE = '40001';
  END IF;
  IF provider_record.archived_at IS NOT NULL THEN
    RAISE EXCEPTION 'platform identity provider is archived'
      USING ERRCODE = '55000';
  END IF;

  SELECT policy.* INTO policy_record
  FROM ONLY public.platform_federated_provider_policies AS policy
  WHERE policy.provider_id = p_provider_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'platform identity provider policy is unavailable'
      USING ERRCODE = '55000';
  END IF;
  IF policy_record.security_revision >= 9007199254740991 THEN
    RAISE EXCEPTION 'platform identity provider revision is exhausted'
      USING ERRCODE = '55000';
  END IF;
  IF provider_record.enabled
     OR policy_record.enabled
     OR policy_record.platform_login_enabled THEN
    RAISE EXCEPTION 'platform identity provider must be disabled before archive'
      USING ERRCODE = '55000';
  END IF;

  UPDATE ONLY public.platform_auth_providers AS provider
  SET enabled = false,
      archived_at = changed_at,
      archived_by_user_id = actor_id,
      archive_reason = p_reason,
      updated_by_user_id = actor_id,
      version = provider_record.version + 1,
      updated_at = changed_at
  WHERE provider.id = p_provider_id;
  UPDATE ONLY public.platform_federated_provider_policies AS policy
  SET enabled = false,
      platform_login_enabled = false,
      security_revision = policy.security_revision + 1,
      updated_at = changed_at
  WHERE policy.provider_id = p_provider_id;
  UPDATE ONLY public.platform_oidc_client_secrets AS secret
  SET retired_at = changed_at
  WHERE secret.provider_id = p_provider_id
    AND secret.retired_at IS NULL;
  UPDATE ONLY public.platform_saml_sp_keys AS sp_key
  SET retired_at = changed_at
  WHERE sp_key.provider_id = p_provider_id
    AND sp_key.retired_at IS NULL;

  PERFORM app.append_platform_audit_event(
    p_audit_event_id, 'user', actor_id,
    'platform.identity_provider.archived', 'platform_identity_provider', p_provider_id,
    p_request_id, p_correlation_id, p_ip_address, p_user_agent,
    p_authentication_method, 'success', p_reason,
    jsonb_build_object(
      'kind', provider_record.kind,
      'previous_version', provider_record.version,
      'version', provider_record.version + 1,
      'enabled', false,
      'platform_login_enabled', false
    )
  );
  RETURN provider_record.version + 1;
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.replace_platform_oidc_client_secret_v1(
  p_session_id uuid,
  p_provider_id uuid,
  p_secret_id uuid,
  p_expected_version bigint,
  p_key_version integer,
  p_nonce bytea,
  p_ciphertext bytea,
  p_audit_event_id uuid,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text,
  p_reason text
)
RETURNS TABLE (version bigint, secret_revision bigint)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, app
AS $function$
DECLARE
  actor_id uuid;
  provider_record public.platform_auth_providers%ROWTYPE;
  policy_record public.platform_federated_provider_policies%ROWTYPE;
  configuration_record public.platform_oidc_provider_configurations%ROWTYPE;
  next_secret_revision bigint;
  changed_at timestamp with time zone := transaction_timestamp();
BEGIN
  IF p_provider_id IS NULL OR uuid_extract_version(p_provider_id) IS DISTINCT FROM 7
     OR p_secret_id IS NULL OR uuid_extract_version(p_secret_id) IS DISTINCT FROM 7
     OR p_expected_version IS NULL
     OR p_expected_version NOT BETWEEN 1 AND 2147483646
     OR p_key_version IS NULL OR p_key_version NOT BETWEEN 1 AND 32767
     OR p_nonce IS NULL OR octet_length(p_nonce) <> 12
     OR p_ciphertext IS NULL OR octet_length(p_ciphertext) NOT BETWEEN 17 AND 8208
     OR p_audit_event_id IS NULL OR uuid_extract_version(p_audit_event_id) IS DISTINCT FROM 7
     OR p_request_id IS NULL OR uuid_extract_version(p_request_id) IS DISTINCT FROM 7
     OR p_correlation_id IS NULL OR uuid_extract_version(p_correlation_id) IS DISTINCT FROM 7
     OR p_ip_address IS NULL OR p_user_agent IS NULL
     OR octet_length(p_user_agent) NOT BETWEEN 1 AND 512
     OR NOT app.private_platform_identity_text_is_safe_v1(p_user_agent, false)
     OR p_reason IS NULL
     OR NOT app.private_platform_lifecycle_reason_is_valid_v1(p_reason) THEN
    RAISE EXCEPTION 'invalid platform OIDC secret command'
      USING ERRCODE = '22023';
  END IF;
  actor_id := app.private_require_platform_identity_permission_v1(
    p_session_id, 'platform.identity_provider.manage', p_authentication_method
  );

  SELECT provider.* INTO provider_record
  FROM ONLY public.platform_auth_providers AS provider
  WHERE provider.id = p_provider_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'platform identity provider does not exist'
      USING ERRCODE = 'P0002';
  END IF;
  IF provider_record.version <> p_expected_version THEN
    RAISE EXCEPTION 'platform identity provider revision conflict'
      USING ERRCODE = '40001';
  END IF;
  IF provider_record.kind <> 'oidc'
     OR provider_record.archived_at IS NOT NULL THEN
    RAISE EXCEPTION 'platform identity provider is not a live OIDC provider'
      USING ERRCODE = '55000';
  END IF;

  SELECT policy.* INTO policy_record
  FROM ONLY public.platform_federated_provider_policies AS policy
  WHERE policy.provider_id = p_provider_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'platform identity provider policy is unavailable'
      USING ERRCODE = '55000';
  END IF;

  SELECT configuration.* INTO configuration_record
  FROM ONLY public.platform_oidc_provider_configurations AS configuration
  WHERE configuration.provider_id = p_provider_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'platform OIDC configuration is unavailable'
      USING ERRCODE = '55000';
  END IF;
  IF configuration_record.client_secret_revision >= 9007199254740991
     OR configuration_record.version >= 9007199254740991
     OR policy_record.configuration_revision >= 9007199254740991
     OR policy_record.security_revision >= 9007199254740991 THEN
    RAISE EXCEPTION 'platform identity provider revision is exhausted'
      USING ERRCODE = '55000';
  END IF;
  PERFORM 1
  FROM public.identity_keyring_versions AS keyring
  WHERE keyring.key_version = p_key_version
    AND keyring.is_active
    AND keyring.retired_at IS NULL
  FOR SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'identity key version is unavailable'
      USING ERRCODE = '55000';
  END IF;

  next_secret_revision := configuration_record.client_secret_revision + 1;
  UPDATE ONLY public.platform_oidc_client_secrets AS secret
  SET retired_at = changed_at
  WHERE secret.provider_id = p_provider_id AND secret.retired_at IS NULL;
  INSERT INTO public.platform_oidc_client_secrets (
    id, provider_id, revision, key_version, nonce, ciphertext
  ) VALUES (
    p_secret_id, p_provider_id, next_secret_revision,
    p_key_version, p_nonce, p_ciphertext
  );
  UPDATE ONLY public.platform_oidc_provider_configurations AS configuration
  SET client_secret_revision = next_secret_revision,
      version = configuration.version + 1,
      updated_at = changed_at
  WHERE configuration.provider_id = p_provider_id;
  UPDATE ONLY public.platform_federated_provider_policies AS policy
  SET configuration_revision = policy.configuration_revision + 1,
      security_revision = policy.security_revision + 1,
      platform_login_enabled = false,
      updated_at = changed_at
  WHERE policy.provider_id = p_provider_id;
  UPDATE ONLY public.platform_auth_providers AS provider
  SET updated_by_user_id = actor_id,
      version = provider_record.version + 1,
      updated_at = changed_at
  WHERE provider.id = p_provider_id;

  PERFORM app.append_platform_audit_event(
    p_audit_event_id, 'user', actor_id,
    'platform.identity_provider.oidc_secret_replaced',
    'platform_identity_provider', p_provider_id,
    p_request_id, p_correlation_id, p_ip_address, p_user_agent,
    p_authentication_method, 'success', p_reason,
    jsonb_build_object(
      'kind', 'oidc',
      'previous_version', provider_record.version,
      'version', provider_record.version + 1,
      'secret_version', next_secret_revision,
      'secret_material_included', true,
      'platform_login_enabled', false
    )
  );

  RETURN QUERY SELECT provider_record.version + 1, next_secret_revision;
END;
$function$;
--> statement-breakpoint

ALTER FUNCTION app.list_platform_auth_providers_v1(uuid, text, uuid, integer, boolean)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.get_platform_auth_provider_v1(uuid, uuid, text)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.create_platform_auth_provider_v1(
  uuid, uuid, uuid, public.auth_provider_kind, text, text, text, jsonb,
  bytea, bytea, uuid, uuid, uuid, inet, text, text, text
) OWNER TO periapsis_migrator;
ALTER FUNCTION app.update_platform_auth_provider_v1(
  uuid, uuid, bigint, text, text, text, uuid, uuid, uuid, inet, text, text, text
) OWNER TO periapsis_migrator;
ALTER FUNCTION app.archive_platform_auth_provider_v1(
  uuid, uuid, bigint, uuid, uuid, uuid, inet, text, text, text
) OWNER TO periapsis_migrator;
ALTER FUNCTION app.replace_platform_oidc_client_secret_v1(
  uuid, uuid, uuid, bigint, integer, bytea, bytea, uuid, uuid, uuid,
  inet, text, text, text
) OWNER TO periapsis_migrator;
--> statement-breakpoint

REVOKE ALL ON FUNCTION app.list_platform_auth_providers_v1(uuid, text, uuid, integer, boolean)
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;
REVOKE ALL ON FUNCTION app.get_platform_auth_provider_v1(uuid, uuid, text)
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;
REVOKE ALL ON FUNCTION app.create_platform_auth_provider_v1(
  uuid, uuid, uuid, public.auth_provider_kind, text, text, text, jsonb,
  bytea, bytea, uuid, uuid, uuid, inet, text, text, text
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;
REVOKE ALL ON FUNCTION app.update_platform_auth_provider_v1(
  uuid, uuid, bigint, text, text, text, uuid, uuid, uuid, inet, text, text, text
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;
REVOKE ALL ON FUNCTION app.archive_platform_auth_provider_v1(
  uuid, uuid, bigint, uuid, uuid, uuid, inet, text, text, text
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;
REVOKE ALL ON FUNCTION app.replace_platform_oidc_client_secret_v1(
  uuid, uuid, uuid, bigint, integer, bytea, bytea, uuid, uuid, uuid,
  inet, text, text, text
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;
--> statement-breakpoint

GRANT EXECUTE ON FUNCTION app.list_platform_auth_providers_v1(uuid, text, uuid, integer, boolean)
  TO periapsis_api;
GRANT EXECUTE ON FUNCTION app.get_platform_auth_provider_v1(uuid, uuid, text)
  TO periapsis_api;
GRANT EXECUTE ON FUNCTION app.create_platform_auth_provider_v1(
  uuid, uuid, uuid, public.auth_provider_kind, text, text, text, jsonb,
  bytea, bytea, uuid, uuid, uuid, inet, text, text, text
) TO periapsis_api;
GRANT EXECUTE ON FUNCTION app.update_platform_auth_provider_v1(
  uuid, uuid, bigint, text, text, text, uuid, uuid, uuid, inet, text, text, text
) TO periapsis_api;
GRANT EXECUTE ON FUNCTION app.archive_platform_auth_provider_v1(
  uuid, uuid, bigint, uuid, uuid, uuid, inet, text, text, text
) TO periapsis_api;
GRANT EXECUTE ON FUNCTION app.replace_platform_oidc_client_secret_v1(
  uuid, uuid, uuid, bigint, integer, bytea, bytea, uuid, uuid, uuid,
  inet, text, text, text
) TO periapsis_api;
