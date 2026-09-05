-- Activate the previously staged platform-provider tenant-binding model.  All
-- new state remains owner-only behind SECURITY DEFINER ABIs; direct platform
-- login stays structurally disabled.

ALTER TABLE public.platform_federated_external_identities OWNER TO periapsis_migrator;
ALTER TABLE public.platform_federated_external_identity_aliases OWNER TO periapsis_migrator;
ALTER TABLE public.tenant_platform_federated_provider_access_grants OWNER TO periapsis_migrator;
ALTER TABLE public.tenant_platform_federated_provider_profile_contributions OWNER TO periapsis_migrator;
ALTER TABLE public.tenant_platform_oidc_authentication_transactions OWNER TO periapsis_migrator;
ALTER TABLE public.tenant_platform_oidc_authentication_applications OWNER TO periapsis_migrator;
ALTER TABLE public.auth_session_tenant_platform_federated_provenance OWNER TO periapsis_migrator;
ALTER TABLE public.auth_session_tenant_platform_federated_evidence OWNER TO periapsis_migrator;
ALTER TABLE public.tenant_mfa_authority_platform_federated_evidence OWNER TO periapsis_migrator;
ALTER TABLE public.tenant_post_primary_platform_federated_evidence OWNER TO periapsis_migrator;
ALTER TABLE public.tenant_post_primary_platform_federated_provenance OWNER TO periapsis_migrator;
ALTER TABLE public.tenant_post_primary_federated_provenance OWNER TO periapsis_migrator;
ALTER TABLE public.tenant_platform_federated_session_revalidation_commands OWNER TO periapsis_migrator;
--> statement-breakpoint

ALTER TABLE public.platform_federated_external_identities FORCE ROW LEVEL SECURITY;
ALTER TABLE public.platform_federated_external_identity_aliases FORCE ROW LEVEL SECURITY;
ALTER TABLE public.tenant_platform_federated_provider_access_grants FORCE ROW LEVEL SECURITY;
ALTER TABLE public.tenant_platform_federated_provider_profile_contributions FORCE ROW LEVEL SECURITY;
ALTER TABLE public.tenant_platform_oidc_authentication_transactions FORCE ROW LEVEL SECURITY;
ALTER TABLE public.tenant_platform_oidc_authentication_applications FORCE ROW LEVEL SECURITY;
ALTER TABLE public.auth_session_tenant_platform_federated_provenance FORCE ROW LEVEL SECURITY;
ALTER TABLE public.auth_session_tenant_platform_federated_evidence FORCE ROW LEVEL SECURITY;
ALTER TABLE public.tenant_mfa_authority_platform_federated_evidence FORCE ROW LEVEL SECURITY;
ALTER TABLE public.tenant_post_primary_platform_federated_evidence FORCE ROW LEVEL SECURITY;
ALTER TABLE public.tenant_post_primary_platform_federated_provenance FORCE ROW LEVEL SECURITY;
ALTER TABLE public.tenant_post_primary_federated_provenance FORCE ROW LEVEL SECURITY;
ALTER TABLE public.tenant_platform_federated_session_revalidation_commands FORCE ROW LEVEL SECURITY;
--> statement-breakpoint

REVOKE ALL ON TABLE
  public.platform_federated_external_identities,
  public.platform_federated_external_identity_aliases,
  public.tenant_platform_federated_provider_access_grants,
  public.tenant_platform_federated_provider_profile_contributions,
  public.tenant_platform_oidc_authentication_transactions,
  public.tenant_platform_oidc_authentication_applications,
  public.auth_session_tenant_platform_federated_provenance,
  public.auth_session_tenant_platform_federated_evidence,
  public.tenant_mfa_authority_platform_federated_evidence,
  public.tenant_post_primary_platform_federated_evidence,
  public.tenant_post_primary_platform_federated_provenance,
  public.tenant_post_primary_federated_provenance,
  public.tenant_platform_federated_session_revalidation_commands
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner, periapsis_sla_api_owner,
  periapsis_sla_worker_owner, periapsis_sla_readiness_owner,
  periapsis_ticket_saved_view_owner, periapsis_ticket_attribution_owner,
  periapsis_ticket_sla_projection_owner;
--> statement-breakpoint

ALTER TABLE public.platform_federated_provider_policies
  DROP CONSTRAINT platform_federated_provider_policies_login_check;
ALTER TABLE public.platform_federated_provider_policies
  ADD CONSTRAINT platform_federated_provider_policies_login_check
  CHECK (NOT platform_login_enabled);
ALTER TABLE public.platform_oidc_provider_configurations
  DROP CONSTRAINT platform_oidc_provider_configurations_text_check;
ALTER TABLE public.platform_oidc_provider_configurations
  ADD CONSTRAINT platform_oidc_provider_configurations_text_check CHECK (
    issuer = btrim(issuer)
    AND app.private_platform_identity_uri_is_canonical_v1(issuer, true, false, 4096)
    AND octet_length(convert_to(client_id, 'UTF8')) BETWEEN 1 AND 512
    AND client_id = btrim(client_id)
    AND app.private_platform_identity_uri_is_canonical_v1(redirect_uri, true, true, 4096)
    AND app.private_platform_identity_uri_is_canonical_v1(tenant_redirect_uri, true, false, 4096)
    AND tenant_redirect_uri ~ '^https://[^/?#@]+/api/v1/auth/federated/oidc/callback$'
    AND app.private_platform_identity_uri_is_canonical_v1(post_logout_redirect_uri, true, true, 4096)
    AND app.private_platform_identity_text_is_safe_v1(client_id, true)
  );
ALTER TABLE public.tenant_platform_oidc_authentication_transactions
  DROP CONSTRAINT tenant_platform_oidc_authentication_transactions_pin_check;
ALTER TABLE public.tenant_platform_oidc_authentication_transactions
  ADD CONSTRAINT tenant_platform_oidc_authentication_transactions_pin_check CHECK (
    provider_kind = 'oidc' AND protocol = 'oidc'
    AND provider_revision BETWEEN 1 AND 2147483647
    AND binding_revision BETWEEN 1 AND 2147483647
    AND configuration_revision BETWEEN 1 AND 9007199254740991
    AND security_revision BETWEEN 1 AND 9007199254740991
    AND plan_revision BETWEEN 1 AND 9007199254740991
    AND mapping_revision BETWEEN 1 AND 9007199254740991
    AND authorization_revision BETWEEN 1 AND 9007199254740991
    AND assurance_policy_revision BETWEEN 1 AND 9007199254740991
    AND client_secret_revision BETWEEN 1 AND 9007199254740991
    AND discovery_revision BETWEEN 1 AND 9007199254740991
    AND jwks_revision BETWEEN 1 AND 9007199254740991
    AND verifier_key_version BETWEEN 1 AND 32767
    AND octet_length(verifier_ciphertext) BETWEEN 16 AND 4096
    AND octet_length(convert_to(client_id, 'UTF8')) BETWEEN 1 AND 512
    AND app.private_platform_identity_uri_is_canonical_v1(tenant_redirect_uri, true, false, 4096)
    AND tenant_redirect_uri ~ '^https://[^/?#@]+/api/v1/auth/federated/oidc/callback$'
    AND app.private_platform_identity_uri_is_canonical_v1(post_logout_redirect_uri, true, true, 4096)
    AND cardinality(scopes) BETWEEN 1 AND 64
    AND array_position(scopes, NULL) IS NULL
    AND char_length(return_path) BETWEEN 1 AND 2048
    AND left(return_path, 1) = '/' AND left(return_path, 2) <> '//'
    AND position(E'\\' IN return_path) = 0
    AND app.private_platform_identity_text_is_safe_v1(client_id, true)
    AND app.private_platform_identity_text_is_safe_v1(return_path, true)
  );
--> statement-breakpoint

-- The generated 0163 column is NOT NULL.  The v2 create ABI supplies its
-- deployment-derived value through a transaction-local setting so the sealed
-- v1 writer cannot accidentally copy the future direct-platform redirect.
CREATE FUNCTION app.private_fill_platform_oidc_tenant_redirect_v1()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  configured_redirect text;
BEGIN
  IF TG_OP = 'INSERT' AND NEW.tenant_redirect_uri IS NULL THEN
    configured_redirect := nullif(
      current_setting('app.platform_tenant_oidc_redirect_uri', true), ''
    );
    IF configured_redirect IS NULL THEN
      RAISE EXCEPTION 'tenant OIDC redirect is required'
        USING ERRCODE = '22023';
    END IF;
    NEW.tenant_redirect_uri := configured_redirect;
  END IF;
  IF NOT app.private_platform_identity_uri_is_canonical_v1(
       NEW.tenant_redirect_uri, true, false, 4096
     ) OR NEW.tenant_redirect_uri !~
       '^https://[^/?#@]+/api/v1/auth/federated/oidc/callback$' THEN
    RAISE EXCEPTION 'tenant OIDC redirect is invalid'
      USING ERRCODE = '22023';
  END IF;
  RETURN NEW;
END;
$function$;
CREATE TRIGGER platform_oidc_provider_configurations_tenant_redirect_v1
BEFORE INSERT OR UPDATE OF tenant_redirect_uri
ON public.platform_oidc_provider_configurations
FOR EACH ROW EXECUTE FUNCTION app.private_fill_platform_oidc_tenant_redirect_v1();
--> statement-breakpoint

CREATE FUNCTION app.create_platform_oidc_auth_provider_v2(
  p_session_id uuid,
  p_command_id uuid,
  p_provider_id uuid,
  p_key text,
  p_display_name text,
  p_description text,
  p_configuration jsonb,
  p_tenant_redirect_uri text,
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
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  previous_redirect text;
BEGIN
  IF p_tenant_redirect_uri IS NULL
     OR NOT app.private_platform_identity_uri_is_canonical_v1(
       p_tenant_redirect_uri, true, false, 4096
     )
     OR p_tenant_redirect_uri !~
       '^https://[^/?#@]+/api/v1/auth/federated/oidc/callback$' THEN
    RAISE EXCEPTION 'tenant OIDC redirect is invalid'
      USING ERRCODE = '22023';
  END IF;
  previous_redirect := current_setting(
    'app.platform_tenant_oidc_redirect_uri', true
  );
  PERFORM set_config(
    'app.platform_tenant_oidc_redirect_uri', p_tenant_redirect_uri, true
  );
  RETURN QUERY
  SELECT created.provider_id, created.version, created.replayed, created.document
  FROM app.create_platform_auth_provider_v1(
    p_session_id, p_command_id, p_provider_id, 'oidc', p_key,
    p_display_name, p_description, p_configuration, p_key_digest,
    p_request_digest, p_audit_event_id, p_request_id, p_correlation_id,
    p_ip_address, p_user_agent, p_authentication_method, p_reason
  ) AS created;
  PERFORM set_config(
    'app.platform_tenant_oidc_redirect_uri', coalesce(previous_redirect, ''), true
  );
EXCEPTION WHEN OTHERS THEN
  PERFORM set_config(
    'app.platform_tenant_oidc_redirect_uri', coalesce(previous_redirect, ''), true
  );
  RAISE;
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_platform_oidc_provider_activation_available_v1(
  p_provider_id uuid
)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
  SELECT EXISTS (
    SELECT 1
    FROM ONLY public.platform_auth_providers AS provider
    JOIN ONLY public.platform_federated_provider_policies AS policy
      ON policy.provider_id = provider.id AND policy.provider_kind = 'oidc'
    JOIN ONLY public.platform_oidc_provider_configurations AS configuration
      ON configuration.provider_id = provider.id
     AND configuration.provider_kind = 'oidc'
    JOIN ONLY public.platform_oidc_client_secrets AS secret
      ON secret.provider_id = configuration.provider_id
     AND secret.revision = configuration.client_secret_revision
     AND secret.retired_at IS NULL
    JOIN ONLY public.identity_keyring_versions AS secret_key
      ON secret_key.key_version = secret.key_version
     AND secret_key.retired_at IS NULL
    JOIN ONLY public.platform_oidc_discovery_snapshots AS discovery
      ON discovery.provider_id = configuration.provider_id
     AND discovery.revision = configuration.discovery_revision
     AND discovery.issuer = configuration.issuer
     AND discovery.cacheable
     AND discovery.fresh_until > statement_timestamp()
    JOIN ONLY public.platform_oidc_jwks_snapshots AS jwks
      ON jwks.provider_id = configuration.provider_id
     AND jwks.revision = configuration.jwks_revision
     AND jwks.cacheable
     AND jwks.fresh_until > statement_timestamp()
    WHERE provider.id = p_provider_id
      AND provider.kind = 'oidc'
      AND NOT provider.enabled
      AND provider.archived_at IS NULL
      AND NOT policy.enabled
      AND NOT policy.platform_login_enabled
      AND octet_length(discovery.document_digest) = 32
      AND octet_length(jwks.document_digest) = 32
  );
$function$;

CREATE FUNCTION app.private_tenant_platform_binding_activation_available_v1(
  p_binding_id uuid
)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
  SELECT EXISTS (
    SELECT 1
    FROM ONLY public.tenant_platform_auth_provider_bindings AS binding
    JOIN ONLY public.tenants AS tenant
      ON tenant.id = binding.tenant_id AND tenant.status = 'active'
    JOIN ONLY public.platform_auth_providers AS provider
      ON provider.id = binding.platform_provider_id
     AND provider.kind = 'oidc' AND provider.enabled
     AND provider.archived_at IS NULL
    JOIN ONLY public.platform_federated_provider_policies AS policy
      ON policy.provider_id = provider.id AND policy.provider_kind = 'oidc'
     AND policy.enabled AND NOT policy.platform_login_enabled
    WHERE binding.id = p_binding_id
      AND NOT binding.enabled
      AND binding.archived_at IS NULL
      AND binding.current_access_epoch_id IS NULL
      AND NOT EXISTS (
        SELECT 1
        FROM ONLY public.tenant_platform_identity_provider_access_epochs AS epoch
        WHERE epoch.tenant_id = binding.tenant_id
          AND epoch.binding_id = binding.id
          AND epoch.platform_provider_id = binding.platform_provider_id
          AND epoch.ended_at IS NULL
      )
  );
$function$;
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.private_platform_auth_provider_document_v1(
  p_provider_id uuid
)
RETURNS jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
  SELECT jsonb_build_object(
    'id', provider.id,
    'key', provider.key,
    'displayName', provider.display_name,
    'description', provider.description,
    'kind', provider.kind,
    'enabled', provider.enabled,
    'activationAvailable',
      app.private_platform_oidc_provider_activation_available_v1(provider.id),
    'platformLoginEnabled', policy.platform_login_enabled,
    'configurationRevision', policy.configuration_revision,
    'securityRevision', policy.security_revision,
    'planRevision', policy.plan_revision,
    'assurancePolicyRevision', policy.assurance_policy_revision,
    'accountMode', policy.account_mode,
    'configuration', CASE provider.kind WHEN 'oidc' THEN jsonb_build_object(
      'issuer', oidc.issuer,
      'clientId', oidc.client_id,
      'redirectUri', oidc.redirect_uri,
      'tenantRedirectUri', oidc.tenant_redirect_uri,
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
    ) WHEN 'saml' THEN jsonb_build_object(
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
    ) || CASE WHEN saml.subject_source = 'immutable_attribute' THEN
      jsonb_build_object(
        'subjectAttributeName', saml.subject_attribute_name,
        'subjectAttributeNameFormat', saml.subject_attribute_name_format
      ) ELSE '{}'::jsonb END
    ELSE NULL END,
    'archivedAt', provider.archived_at,
    'version', provider.version,
    'createdAt', provider.created_at,
    'updatedAt', provider.updated_at
  )
  FROM ONLY public.platform_auth_providers AS provider
  JOIN ONLY public.platform_federated_provider_policies AS policy
    ON policy.provider_id = provider.id
  LEFT JOIN ONLY public.platform_oidc_provider_configurations AS oidc
    ON oidc.provider_id = provider.id AND provider.kind = 'oidc'
  LEFT JOIN ONLY public.platform_saml_provider_configurations AS saml
    ON saml.provider_id = provider.id AND provider.kind = 'saml'
  WHERE provider.id = p_provider_id;
$function$;

CREATE OR REPLACE FUNCTION app.list_platform_auth_providers_v1(
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
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 200
     OR p_include_archived IS NULL
     OR (p_after IS NOT NULL
       AND uuid_extract_version(p_after) IS DISTINCT FROM 7) THEN
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
    'activationAvailable',
      app.private_platform_oidc_provider_activation_available_v1(provider.id),
    'platformLoginEnabled', policy.platform_login_enabled,
    'configured', CASE provider.kind
      WHEN 'oidc' THEN oidc.provider_id IS NOT NULL
      WHEN 'saml' THEN saml.provider_id IS NOT NULL
      ELSE false END,
    'secretPresent', CASE provider.kind WHEN 'oidc' THEN EXISTS (
      SELECT 1 FROM ONLY public.platform_oidc_client_secrets AS secret
      WHERE secret.provider_id = provider.id AND secret.retired_at IS NULL
    ) ELSE false END,
    'archivedAt', provider.archived_at,
    'version', provider.version,
    'createdAt', provider.created_at,
    'updatedAt', provider.updated_at
  )
  FROM ONLY public.platform_auth_providers AS provider
  JOIN ONLY public.platform_federated_provider_policies AS policy
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

CREATE OR REPLACE FUNCTION app.get_platform_auth_provider_v1(
  p_session_id uuid,
  p_provider_id uuid,
  p_authentication_method text
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
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
  result := app.private_platform_auth_provider_document_v1(p_provider_id);
  IF result IS NULL THEN
    RAISE EXCEPTION 'platform identity provider does not exist'
      USING ERRCODE = 'P0002';
  END IF;
  RETURN result;
END;
$function$;

CREATE OR REPLACE FUNCTION app.private_tenant_platform_auth_provider_binding_document_v1(
  p_binding_id uuid
)
RETURNS jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
  SELECT jsonb_build_object(
    'id', binding.id,
    'providerId', binding.platform_provider_id,
    'tenant', jsonb_build_object(
      'id', tenant.id, 'slug', tenant.slug, 'name', tenant.name,
      'status', tenant.status, 'version', tenant.version
    ),
    'origin', 'platform',
    'loginKey', binding.key,
    'jitMode', binding.jit_mode,
    'noMatchPolicy', binding.no_match_policy,
    'profilePriority', binding.profile_priority,
    'enabled', binding.enabled,
    'activationAvailable',
      app.private_tenant_platform_binding_activation_available_v1(binding.id),
    'authRevision', binding.auth_revision,
    'mappingRevision', binding.mapping_revision,
    'currentAccessEpochId', binding.current_access_epoch_id,
    'archivedAt', binding.archived_at,
    'version', binding.version,
    'createdAt', binding.created_at,
    'updatedAt', binding.updated_at
  )
  FROM ONLY public.tenant_platform_auth_provider_bindings AS binding
  JOIN ONLY public.tenants AS tenant ON tenant.id = binding.tenant_id
  WHERE binding.id = p_binding_id;
$function$;
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.guard_platform_auth_provider_binding_dependency_v1()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF EXISTS (
    SELECT 1 FROM ONLY public.tenant_platform_auth_provider_bindings AS binding
    WHERE binding.platform_provider_id = OLD.id
      AND binding.archived_at IS NULL
      AND (binding.enabled OR TG_OP = 'DELETE'
        OR (TG_OP = 'UPDATE' AND NEW.archived_at IS NOT NULL))
  ) AND (
    TG_OP = 'DELETE'
    OR (TG_OP = 'UPDATE' AND (NOT NEW.enabled OR NEW.archived_at IS NOT NULL))
  ) THEN
    RAISE EXCEPTION 'platform identity provider has live tenant bindings'
      USING ERRCODE = '55000';
  END IF;
  RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END;
$function$;

CREATE OR REPLACE FUNCTION app.guard_tenant_platform_identity_provider_access_epoch_v1()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'tenant platform identity-provider access epochs are immutable'
      USING ERRCODE = '55000';
  END IF;
  IF TG_OP = 'INSERT' THEN
    IF NEW.version <> 1 OR NEW.sequence < 1
       OR NEW.started_at IS DISTINCT FROM transaction_timestamp()
       OR NEW.ended_at IS NOT NULL OR NEW.ended_by_user_id IS NOT NULL
       OR NEW.end_reason IS NOT NULL
       OR NOT EXISTS (
         SELECT 1
         FROM ONLY public.tenant_platform_auth_provider_bindings AS binding
         JOIN ONLY public.tenant_authorization_sources AS source
           ON source.tenant_id = binding.tenant_id
          AND source.id = NEW.source_id
          AND source.kind = 'identity_provider_access'
          AND source.authoritative
          AND NOT source.protected
          AND source.key = format(
            'identity_provider_access:%s:%s', NEW.binding_id, NEW.sequence
          )
          AND source.retired_at IS NULL
         WHERE binding.tenant_id = NEW.tenant_id
           AND binding.id = NEW.binding_id
           AND binding.platform_provider_id = NEW.platform_provider_id
           AND NOT binding.enabled AND binding.archived_at IS NULL
       ) OR EXISTS (
         SELECT 1
         FROM ONLY public.tenant_platform_identity_provider_access_epochs AS epoch
         WHERE epoch.tenant_id = NEW.tenant_id
           AND epoch.binding_id = NEW.binding_id
           AND epoch.ended_at IS NULL
       ) THEN
      RAISE EXCEPTION 'tenant platform access epoch create is invalid'
        USING ERRCODE = '23514';
    END IF;
  ELSE
    IF ROW(NEW.id, NEW.tenant_id, NEW.binding_id, NEW.platform_provider_id,
           NEW.source_id, NEW.sequence, NEW.started_by_user_id, NEW.started_at)
       IS DISTINCT FROM
       ROW(OLD.id, OLD.tenant_id, OLD.binding_id, OLD.platform_provider_id,
           OLD.source_id, OLD.sequence, OLD.started_by_user_id, OLD.started_at)
       OR OLD.ended_at IS NOT NULL
       OR NEW.ended_at IS DISTINCT FROM transaction_timestamp()
       OR NEW.ended_by_user_id IS NULL OR NEW.end_reason IS NULL
       OR NEW.version <> OLD.version + 1
       OR EXISTS (
         SELECT 1
         FROM ONLY public.tenant_platform_auth_provider_bindings AS binding
         WHERE binding.tenant_id = OLD.tenant_id
           AND binding.id = OLD.binding_id
           AND binding.current_access_epoch_id = OLD.id
       )
       OR NOT EXISTS (
         SELECT 1
         FROM ONLY public.tenant_authorization_sources AS source
         WHERE source.tenant_id = OLD.tenant_id
           AND source.id = OLD.source_id
           AND source.kind = 'identity_provider_access'
           AND source.authoritative AND NOT source.protected
           AND source.key = format(
             'identity_provider_access:%s:%s', OLD.binding_id, OLD.sequence
           )
           AND source.retired_at IS NULL
       ) THEN
      RAISE EXCEPTION 'tenant platform access epoch close is invalid'
        USING ERRCODE = '23514';
    END IF;
  END IF;
  RETURN NEW;
END;
$function$;

CREATE OR REPLACE FUNCTION app.guard_tenant_platform_auth_provider_binding_v1()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'tenant platform auth-provider bindings are archival records'
      USING ERRCODE = '55000';
  END IF;
  IF NEW.binding_family <> 'platform_provider'
     OR NOT EXISTS (
       SELECT 1 FROM ONLY public.tenant_auth_provider_login_keys AS claim
       WHERE claim.tenant_id = NEW.tenant_id
         AND claim.binding_family = NEW.binding_family
         AND claim.binding_id = NEW.id AND claim.key = NEW.key
     ) THEN
    RAISE EXCEPTION 'tenant platform auth-provider binding invariant is invalid'
      USING ERRCODE = '23514';
  END IF;
  IF NEW.enabled AND NOT EXISTS (
    SELECT 1
    FROM ONLY public.tenant_platform_identity_provider_access_epochs AS epoch
    JOIN ONLY public.tenant_authorization_sources AS source
      ON source.tenant_id = epoch.tenant_id AND source.id = epoch.source_id
    WHERE epoch.tenant_id = NEW.tenant_id
      AND epoch.id = NEW.current_access_epoch_id
      AND epoch.binding_id = NEW.id
      AND epoch.platform_provider_id = NEW.platform_provider_id
      AND epoch.ended_at IS NULL
      AND source.kind = 'identity_provider_access'
      AND source.authoritative AND NOT source.protected
      AND source.key = format(
        'identity_provider_access:%s:%s', epoch.binding_id, epoch.sequence
      )
      AND source.retired_at IS NULL
  ) THEN
    RAISE EXCEPTION 'enabled tenant platform binding has no live access epoch'
      USING ERRCODE = '23514';
  END IF;
  IF TG_OP = 'INSERT' THEN
    IF NEW.enabled OR NEW.current_access_epoch_id IS NOT NULL
       OR NEW.auth_revision <> 1 OR NEW.mapping_revision <> 1
       OR NEW.version <> 1 OR NEW.archived_at IS NOT NULL
       OR NEW.created_at IS DISTINCT FROM transaction_timestamp()
       OR NEW.updated_at IS DISTINCT FROM transaction_timestamp()
       OR NEW.created_by_user_id IS DISTINCT FROM NEW.updated_by_user_id THEN
      RAISE EXCEPTION 'tenant platform binding create envelope is invalid'
        USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
  END IF;
  IF ROW(NEW.id, NEW.tenant_id, NEW.binding_family, NEW.platform_provider_id,
         NEW.created_by_user_id, NEW.created_at)
     IS DISTINCT FROM
     ROW(OLD.id, OLD.tenant_id, OLD.binding_family, OLD.platform_provider_id,
         OLD.created_by_user_id, OLD.created_at) THEN
    RAISE EXCEPTION 'tenant platform binding identity is immutable'
      USING ERRCODE = '55000';
  END IF;
  -- Namespace-parent ON UPDATE CASCADE is the only unversioned key move.
  IF NEW.key IS DISTINCT FROM OLD.key
     AND NEW.version = OLD.version
     AND NEW.updated_at IS NOT DISTINCT FROM OLD.updated_at
     AND ROW(NEW.enabled, NEW.jit_mode, NEW.no_match_policy,
             NEW.profile_priority, NEW.auth_revision, NEW.mapping_revision,
             NEW.current_access_epoch_id, NEW.archived_at)
       IS NOT DISTINCT FROM
       ROW(OLD.enabled, OLD.jit_mode, OLD.no_match_policy,
             OLD.profile_priority, OLD.auth_revision, OLD.mapping_revision,
             OLD.current_access_epoch_id, OLD.archived_at) THEN
    RETURN NEW;
  END IF;
  IF NEW.version <> OLD.version + 1
     OR NEW.updated_at IS DISTINCT FROM transaction_timestamp()
     OR NEW.updated_at < OLD.updated_at THEN
    RAISE EXCEPTION 'tenant platform binding version transition is invalid'
      USING ERRCODE = '23514';
  END IF;
  IF OLD.archived_at IS NOT NULL AND NEW IS DISTINCT FROM OLD THEN
    RAISE EXCEPTION 'tenant platform binding archive is terminal'
      USING ERRCODE = '55000';
  END IF;
  IF NOT OLD.enabled AND NEW.enabled THEN
    IF OLD.archived_at IS NOT NULL OR NEW.archived_at IS NOT NULL
       OR OLD.current_access_epoch_id IS NOT NULL
       OR NEW.current_access_epoch_id IS NULL
       OR NEW.auth_revision <> OLD.auth_revision + 1
       OR NEW.mapping_revision <> OLD.mapping_revision + 1 THEN
      RAISE EXCEPTION 'tenant platform binding activation is invalid'
        USING ERRCODE = '23514';
    END IF;
  ELSIF OLD.enabled AND NOT NEW.enabled THEN
    IF NEW.current_access_epoch_id IS NOT NULL
       OR NEW.auth_revision <> OLD.auth_revision + 1
       OR NEW.mapping_revision <> OLD.mapping_revision
       OR NEW.jit_mode <> 'disabled' OR NEW.no_match_policy <> 'deny'
       OR ROW(NEW.key, NEW.profile_priority, NEW.archived_at)
          IS DISTINCT FROM
          ROW(OLD.key, OLD.profile_priority, OLD.archived_at) THEN
      RAISE EXCEPTION 'tenant platform binding deactivation is invalid'
        USING ERRCODE = '23514';
    END IF;
  ELSE
    IF NEW.enabled
       OR NEW.auth_revision IS DISTINCT FROM OLD.auth_revision
       OR NEW.mapping_revision IS DISTINCT FROM OLD.mapping_revision
       OR NEW.current_access_epoch_id IS DISTINCT FROM OLD.current_access_epoch_id
       OR NEW.jit_mode IS DISTINCT FROM OLD.jit_mode
       OR NEW.no_match_policy IS DISTINCT FROM OLD.no_match_policy THEN
      RAISE EXCEPTION 'tenant platform binding metadata transition is invalid'
        USING ERRCODE = '23514';
    END IF;
  END IF;
  RETURN NEW;
END;
$function$;
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.private_append_platform_identity_binding_tenant_audit_v1(
  p_event_id uuid,
  p_tenant_id uuid,
  p_platform_actor_user_id uuid,
  p_platform_audit_event_id uuid,
  p_platform_provider_id uuid,
  p_action text,
  p_binding_id uuid,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text,
  p_reason text,
  p_before jsonb,
  p_after jsonb
)
RETURNS uuid
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF p_event_id IS NULL OR uuid_extract_version(p_event_id) IS DISTINCT FROM 7
     OR p_platform_actor_user_id IS NULL
     OR uuid_extract_version(p_platform_actor_user_id) IS DISTINCT FROM 7
     OR p_platform_audit_event_id IS NULL
     OR uuid_extract_version(p_platform_audit_event_id) IS DISTINCT FROM 7
     OR p_event_id = p_platform_audit_event_id
     OR p_action NOT IN (
       'tenant.platform_identity_binding.created',
       'tenant.platform_identity_binding.updated',
       'tenant.platform_identity_binding.archived',
       'tenant.platform_identity_binding.activated',
       'tenant.platform_identity_binding.deactivated'
     ) OR p_reason IS NULL
     OR NOT app.private_platform_lifecycle_reason_is_valid_v1(p_reason) THEN
    RAISE EXCEPTION 'tenant platform identity binding audit envelope is invalid'
      USING ERRCODE = '22023';
  END IF;
  INSERT INTO public.audit_events (
    id, tenant_id, sequence, actor_type, actor_user_id, action,
    resource_type, resource_id, request_id, correlation_id, ip_address,
    user_agent, authentication_method, outcome, reason, before, after, metadata
  ) VALUES (
    p_event_id, p_tenant_id, 0, 'system', NULL, p_action,
    'platform_identity_binding', p_binding_id, p_request_id, p_correlation_id,
    p_ip_address, p_user_agent, p_authentication_method, 'success', p_reason,
    p_before, p_after, jsonb_build_object(
      'platform_actor_user_id', p_platform_actor_user_id,
      'platform_audit_event_id', p_platform_audit_event_id,
      'platform_provider_id', p_platform_provider_id
    )
  );
  RETURN p_event_id;
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.set_platform_oidc_auth_provider_activation_v1(
  p_session_id uuid,
  p_provider_id uuid,
  p_expected_version bigint,
  p_enabled boolean,
  p_account_mode text,
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
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  actor_id uuid;
  provider_record public.platform_auth_providers%ROWTYPE;
  policy_record public.platform_federated_provider_policies%ROWTYPE;
  changed_at timestamptz := transaction_timestamp();
BEGIN
  IF p_provider_id IS NULL
     OR uuid_extract_version(p_provider_id) IS DISTINCT FROM 7
     OR p_expected_version NOT BETWEEN 1 AND 2147483646
     OR p_enabled IS NULL
     OR (p_enabled AND p_account_mode NOT IN ('existing_identity', 'create'))
     OR (NOT p_enabled AND p_account_mode <> 'disabled')
     OR p_audit_event_id IS NULL
     OR uuid_extract_version(p_audit_event_id) IS DISTINCT FROM 7
     OR p_reason IS NULL
     OR NOT app.private_platform_lifecycle_reason_is_valid_v1(p_reason) THEN
    RAISE EXCEPTION 'invalid platform OIDC activation command'
      USING ERRCODE = '22023';
  END IF;
  actor_id := app.private_require_platform_identity_permission_v1(
    p_session_id, 'platform.identity_provider.manage', p_authentication_method
  );
  SELECT provider.* INTO STRICT provider_record
  FROM ONLY public.platform_auth_providers AS provider
  WHERE provider.id = p_provider_id FOR UPDATE;
  SELECT policy.* INTO STRICT policy_record
  FROM ONLY public.platform_federated_provider_policies AS policy
  WHERE policy.provider_id = p_provider_id FOR UPDATE;
  IF provider_record.version <> p_expected_version THEN
    RAISE EXCEPTION 'platform identity provider revision conflict'
      USING ERRCODE = '40001';
  END IF;
  IF provider_record.kind <> 'oidc'
     OR provider_record.archived_at IS NOT NULL
     OR provider_record.enabled = p_enabled
     OR policy_record.enabled = p_enabled
     OR policy_record.platform_login_enabled THEN
    RAISE EXCEPTION 'platform OIDC provider cannot change activation state'
      USING ERRCODE = '55000';
  END IF;
  IF p_enabled AND NOT
     app.private_platform_oidc_provider_activation_available_v1(p_provider_id) THEN
    RAISE EXCEPTION 'platform OIDC provider is not activation-ready'
      USING ERRCODE = '55000';
  END IF;
  IF NOT p_enabled AND EXISTS (
    SELECT 1 FROM ONLY public.tenant_platform_auth_provider_bindings AS binding
    WHERE binding.platform_provider_id = p_provider_id AND binding.enabled
      AND binding.archived_at IS NULL
  ) THEN
    RAISE EXCEPTION 'platform OIDC provider has active tenant bindings'
      USING ERRCODE = '55000';
  END IF;
  UPDATE ONLY public.platform_auth_providers AS provider
  SET enabled = p_enabled, updated_by_user_id = actor_id,
      version = provider.version + 1, updated_at = changed_at
  WHERE provider.id = p_provider_id AND provider.version = p_expected_version;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'platform identity provider revision conflict'
      USING ERRCODE = '40001';
  END IF;
  UPDATE ONLY public.platform_federated_provider_policies AS policy
  SET enabled = p_enabled, platform_login_enabled = false,
      account_mode = p_account_mode,
      security_revision = policy.security_revision + 1,
      plan_revision = policy.plan_revision + 1,
      updated_at = changed_at
  WHERE policy.provider_id = p_provider_id;
  PERFORM app.append_platform_audit_event(
    p_audit_event_id, 'user', actor_id,
    CASE WHEN p_enabled THEN 'platform.identity_provider.activated'
         ELSE 'platform.identity_provider.deactivated' END,
    'platform_identity_provider', p_provider_id, p_request_id,
    p_correlation_id, p_ip_address, p_user_agent, p_authentication_method,
    'success', p_reason, jsonb_build_object(
      'enabled', p_enabled, 'platform_login_enabled', false,
      'account_mode', p_account_mode,
      'previous_version', p_expected_version,
      'version', p_expected_version + 1
    )
  );
  RETURN QUERY SELECT p_expected_version + 1,
    app.private_platform_auth_provider_document_v1(p_provider_id);
EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
  RAISE EXCEPTION 'platform identity provider does not exist'
    USING ERRCODE = 'P0002';
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.set_tenant_platform_oidc_binding_activation_v1(
  p_session_id uuid,
  p_provider_id uuid,
  p_binding_id uuid,
  p_expected_binding_version bigint,
  p_expected_tenant_version integer,
  p_enabled boolean,
  p_jit_mode text,
  p_no_match_policy text,
  p_source_id uuid,
  p_epoch_id uuid,
  p_platform_audit_event_id uuid,
  p_tenant_audit_event_id uuid,
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
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  actor_id uuid;
  binding_record public.tenant_platform_auth_provider_bindings%ROWTYPE;
  tenant_record public.tenants%ROWTYPE;
  provider_record public.platform_auth_providers%ROWTYPE;
  policy_record public.platform_federated_provider_policies%ROWTYPE;
  epoch_record public.tenant_platform_identity_provider_access_epochs%ROWTYPE;
  changed_at timestamptz := transaction_timestamp();
  next_sequence integer;
  binding_update_count integer;
  before_document jsonb;
  after_document jsonb;
  source_retired_at timestamptz;
  affected_membership_ids uuid[];
  affected_membership_id uuid;
  owned_membership_ids uuid[];
  owned_membership_id uuid;
BEGIN
  IF p_provider_id IS NULL OR p_binding_id IS NULL
     OR uuid_extract_version(p_provider_id) IS DISTINCT FROM 7
     OR uuid_extract_version(p_binding_id) IS DISTINCT FROM 7
     OR p_expected_binding_version NOT BETWEEN 1 AND 2147483646
     OR p_expected_tenant_version < 1
     OR p_enabled IS NULL
     OR (p_enabled AND p_jit_mode NOT IN ('disabled', 'create'))
     OR (p_enabled AND p_no_match_policy NOT IN ('deny', 'provider_access_only'))
     OR (NOT p_enabled AND (p_jit_mode IS NOT NULL OR p_no_match_policy IS NOT NULL))
     OR p_platform_audit_event_id IS NULL OR p_tenant_audit_event_id IS NULL
     OR uuid_extract_version(p_platform_audit_event_id) IS DISTINCT FROM 7
     OR uuid_extract_version(p_tenant_audit_event_id) IS DISTINCT FROM 7
     OR p_platform_audit_event_id = p_tenant_audit_event_id
     OR p_reason IS NULL
     OR NOT app.private_platform_lifecycle_reason_is_valid_v1(p_reason) THEN
    RAISE EXCEPTION 'invalid tenant platform OIDC activation command'
      USING ERRCODE = '22023';
  END IF;
  IF p_enabled AND (
    p_source_id IS NULL OR p_epoch_id IS NULL
    OR uuid_extract_version(p_source_id) IS DISTINCT FROM 7
    OR uuid_extract_version(p_epoch_id) IS DISTINCT FROM 7
  ) OR NOT p_enabled AND (p_source_id IS NOT NULL OR p_epoch_id IS NOT NULL) THEN
    RAISE EXCEPTION 'tenant platform OIDC activation reservation is invalid'
      USING ERRCODE = '22023';
  END IF;
  actor_id := app.private_require_platform_identity_permission_v1(
    p_session_id, 'platform.identity_binding.manage', p_authentication_method
  );
  SELECT provider.* INTO STRICT provider_record
  FROM ONLY public.platform_auth_providers AS provider
  WHERE provider.id = p_provider_id FOR UPDATE;
  SELECT policy.* INTO STRICT policy_record
  FROM ONLY public.platform_federated_provider_policies AS policy
  WHERE policy.provider_id = p_provider_id FOR UPDATE;
  SELECT binding.* INTO STRICT binding_record
  FROM ONLY public.tenant_platform_auth_provider_bindings AS binding
  WHERE binding.id = p_binding_id
    AND binding.platform_provider_id = p_provider_id FOR UPDATE;
  SELECT tenant.* INTO STRICT tenant_record
  FROM ONLY public.tenants AS tenant
  WHERE tenant.id = binding_record.tenant_id FOR UPDATE;
  before_document := app.private_tenant_platform_auth_provider_binding_document_v1(
    p_binding_id
  );
  IF binding_record.version <> p_expected_binding_version
     OR tenant_record.version <> p_expected_tenant_version THEN
    RAISE EXCEPTION 'tenant platform identity binding revision conflict'
      USING ERRCODE = '40001';
  END IF;
  IF binding_record.enabled = p_enabled
     OR binding_record.archived_at IS NOT NULL
     OR tenant_record.status <> 'active'
     OR provider_record.kind <> 'oidc'
     OR provider_record.archived_at IS NOT NULL
     OR policy_record.platform_login_enabled THEN
    RAISE EXCEPTION 'tenant platform OIDC binding cannot change activation state'
      USING ERRCODE = '55000';
  END IF;
  IF p_enabled THEN
    IF NOT app.private_tenant_platform_binding_activation_available_v1(
       p_binding_id
    ) OR NOT policy_record.enabled
       OR policy_record.account_mode = 'disabled'
       OR (p_jit_mode = 'create' AND policy_record.account_mode <> 'create') THEN
      RAISE EXCEPTION 'tenant platform OIDC binding is not activation-ready'
        USING ERRCODE = '55000';
    END IF;
    SELECT coalesce(max(epoch.sequence), 0) + 1 INTO next_sequence
    FROM ONLY public.tenant_platform_identity_provider_access_epochs AS epoch
    WHERE epoch.tenant_id = binding_record.tenant_id
      AND epoch.binding_id = binding_record.id;
    INSERT INTO public.tenant_authorization_sources (
      id, tenant_id, kind, key, authoritative, protected
    ) VALUES (
      p_source_id, binding_record.tenant_id, 'identity_provider_access',
      format(
        'identity_provider_access:%s:%s', binding_record.id, next_sequence
      ), true, false
    );
    INSERT INTO public.tenant_platform_identity_provider_access_epochs (
      id, tenant_id, binding_id, platform_provider_id, source_id, sequence,
      started_by_user_id, started_at, version
    ) VALUES (
      p_epoch_id, binding_record.tenant_id, binding_record.id,
      binding_record.platform_provider_id, p_source_id, next_sequence,
      actor_id, changed_at, 1
    );
    UPDATE ONLY public.tenant_platform_auth_provider_bindings AS binding
    SET enabled = true, jit_mode = p_jit_mode,
        no_match_policy = p_no_match_policy,
        current_access_epoch_id = p_epoch_id,
        auth_revision = binding.auth_revision + 1,
        mapping_revision = binding.mapping_revision + 1,
        updated_by_user_id = actor_id, version = binding.version + 1,
        updated_at = changed_at
    WHERE binding.id = p_binding_id
      AND binding.version = p_expected_binding_version AND NOT binding.enabled;
    GET DIAGNOSTICS binding_update_count = ROW_COUNT;
  ELSE
    SELECT epoch.* INTO STRICT epoch_record
    FROM ONLY public.tenant_platform_identity_provider_access_epochs AS epoch
    WHERE epoch.tenant_id = binding_record.tenant_id
      AND epoch.id = binding_record.current_access_epoch_id
      AND epoch.binding_id = binding_record.id
      AND epoch.platform_provider_id = binding_record.platform_provider_id
      AND epoch.ended_at IS NULL FOR UPDATE;
    SELECT array_agg(DISTINCT grant_record.membership_id
                     ORDER BY grant_record.membership_id)
      INTO affected_membership_ids
    FROM ONLY public.tenant_platform_federated_provider_access_grants AS grant_record
    WHERE grant_record.tenant_id = binding_record.tenant_id
      AND grant_record.binding_id = binding_record.id
      AND grant_record.access_epoch_id = epoch_record.id
      AND grant_record.ended_at IS NULL;
    SELECT array_agg(DISTINCT grant_record.membership_id
                     ORDER BY grant_record.membership_id)
      INTO owned_membership_ids
    FROM ONLY public.tenant_platform_federated_provider_access_grants AS grant_record
    WHERE grant_record.tenant_id = binding_record.tenant_id
      AND grant_record.binding_id = binding_record.id
      AND grant_record.access_epoch_id = epoch_record.id
      AND grant_record.owns_membership
      AND grant_record.ended_at IS NULL;
    UPDATE ONLY public.tenant_platform_auth_provider_bindings AS binding
    SET enabled = false, jit_mode = 'disabled', no_match_policy = 'deny',
        current_access_epoch_id = NULL,
        auth_revision = binding.auth_revision + 1,
        updated_by_user_id = actor_id, version = binding.version + 1,
        updated_at = changed_at
    WHERE binding.id = p_binding_id
      AND binding.version = p_expected_binding_version AND binding.enabled;
    GET DIAGNOSTICS binding_update_count = ROW_COUNT;
    IF binding_update_count <> 1 THEN
      RAISE EXCEPTION 'tenant platform identity binding revision conflict'
        USING ERRCODE = '40001';
    END IF;
    UPDATE ONLY public.tenant_platform_federated_provider_profile_contributions AS contribution
    SET retired_at = changed_at, version = contribution.version + 1
    FROM public.tenant_platform_federated_provider_access_grants AS grant_record
    WHERE grant_record.tenant_id = binding_record.tenant_id
      AND grant_record.binding_id = binding_record.id
      AND grant_record.id = contribution.access_grant_id
      AND contribution.tenant_id = grant_record.tenant_id
      AND contribution.retired_at IS NULL;
    UPDATE ONLY public.tenant_platform_federated_provider_access_grants AS grant_record
    SET ended_at = changed_at, version = grant_record.version + 1
    WHERE grant_record.tenant_id = binding_record.tenant_id
      AND grant_record.binding_id = binding_record.id
      AND grant_record.ended_at IS NULL;
    FOREACH affected_membership_id IN ARRAY coalesce(
      affected_membership_ids, ARRAY[]::uuid[]
    ) LOOP
      PERFORM app.private_materialize_tenant_user_profile_v1(
        binding_record.tenant_id, affected_membership_id
      );
    END LOOP;
    FOREACH owned_membership_id IN ARRAY coalesce(
      owned_membership_ids, ARRAY[]::uuid[]
    ) LOOP
      UPDATE ONLY public.tenant_memberships AS membership
      SET status = 'suspended', updated_at = changed_at
      WHERE membership.tenant_id = binding_record.tenant_id
        AND membership.id = owned_membership_id
        AND membership.status = 'active'
        AND NOT EXISTS (
          SELECT 1
          FROM ONLY public.tenant_platform_federated_provider_access_grants AS other
          WHERE other.tenant_id = membership.tenant_id
            AND other.membership_id = membership.id
            AND other.ended_at IS NULL
        )
        AND NOT EXISTS (
          SELECT 1
          FROM ONLY public.tenant_ldap_provider_access_grants AS other
          WHERE other.tenant_id = membership.tenant_id
            AND other.membership_id = membership.id
            AND other.ended_at IS NULL
        )
        AND NOT EXISTS (
          SELECT 1
          FROM ONLY public.tenant_federated_provider_access_grants AS other
          WHERE other.tenant_id = membership.tenant_id
            AND other.membership_id = membership.id
            AND other.ended_at IS NULL
        )
        AND NOT EXISTS (
          SELECT 1
          FROM ONLY public.user_login_identifiers AS identifier
          WHERE identifier.user_id = membership.user_id
            AND identifier.retired_at IS NULL
        );
    END LOOP;
    UPDATE ONLY public.tenant_platform_identity_provider_access_epochs AS epoch
    SET ended_at = changed_at, ended_by_user_id = actor_id,
        end_reason = p_reason, version = epoch.version + 1
    WHERE epoch.id = epoch_record.id;
    UPDATE ONLY public.tenant_authorization_sources AS source
    SET retired_at = changed_at
    WHERE source.tenant_id = binding_record.tenant_id
      AND source.id = epoch_record.source_id
      AND source.kind = 'identity_provider_access'
      AND source.authoritative AND NOT source.protected
      AND source.key = format(
        'identity_provider_access:%s:%s', binding_record.id, epoch_record.sequence
      )
      AND source.retired_at IS NULL
    RETURNING source.retired_at INTO source_retired_at;
    IF source_retired_at IS DISTINCT FROM changed_at THEN
      RAISE EXCEPTION 'tenant platform access source could not be retired'
        USING ERRCODE = '55000';
    END IF;
    UPDATE ONLY public.tenant_mfa_subjects AS subject
    SET session_invalidation_epoch = subject.session_invalidation_epoch + 1,
        version = subject.version + 1, updated_at = changed_at
    WHERE subject.tenant_id = binding_record.tenant_id
      AND EXISTS (
        SELECT 1
        FROM ONLY public.platform_federated_external_identities AS identity
        JOIN ONLY public.tenant_platform_federated_provider_access_grants AS grant_record
          ON grant_record.external_identity_id = identity.id
         AND grant_record.user_id = identity.user_id
        WHERE identity.user_id = subject.user_id
          AND grant_record.tenant_id = subject.tenant_id
          AND grant_record.binding_id = binding_record.id
      );
  END IF;
  IF binding_update_count <> 1 THEN
    RAISE EXCEPTION 'tenant platform identity binding revision conflict'
      USING ERRCODE = '40001';
  END IF;
  after_document := app.private_tenant_platform_auth_provider_binding_document_v1(
    p_binding_id
  );
  PERFORM app.private_append_platform_identity_binding_tenant_audit_v1(
    p_tenant_audit_event_id, binding_record.tenant_id, actor_id,
    p_platform_audit_event_id, p_provider_id,
    CASE WHEN p_enabled THEN 'tenant.platform_identity_binding.activated'
         ELSE 'tenant.platform_identity_binding.deactivated' END,
    p_binding_id, p_request_id, p_correlation_id, p_ip_address, p_user_agent,
    p_authentication_method, p_reason, before_document, after_document
  );
  PERFORM app.append_platform_audit_event(
    p_platform_audit_event_id, 'user', actor_id,
    CASE WHEN p_enabled THEN 'platform.identity_binding.activated'
         ELSE 'platform.identity_binding.deactivated' END,
    'platform_identity_binding', p_binding_id, p_request_id,
    p_correlation_id, p_ip_address, p_user_agent, p_authentication_method,
    'success', p_reason, jsonb_build_object(
      'tenant_id', binding_record.tenant_id,
      'provider_id', p_provider_id,
      'enabled', p_enabled,
      'tenant_audit_event_id', p_tenant_audit_event_id
    )
  );
  RETURN QUERY SELECT p_expected_binding_version + 1, after_document;
EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
  RAISE EXCEPTION 'tenant platform identity binding does not exist'
    USING ERRCODE = 'P0002';
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.activate_platform_auth_provider_tenant_execution_v1(
  p_session_id uuid,
  p_provider_id uuid,
  p_expected_version bigint,
  p_account_mode text,
  p_audit_event_id uuid,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text,
  p_reason text
)
RETURNS TABLE (version bigint, document jsonb)
LANGUAGE sql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
  SELECT activated.version, activated.document
  FROM app.set_platform_oidc_auth_provider_activation_v1(
    p_session_id, p_provider_id, p_expected_version, true, p_account_mode,
    p_audit_event_id, p_request_id, p_correlation_id, p_ip_address,
    p_user_agent, p_authentication_method, p_reason
  ) AS activated;
$function$;

CREATE FUNCTION app.deactivate_platform_auth_provider_tenant_execution_v1(
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
RETURNS TABLE (version bigint, document jsonb)
LANGUAGE sql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
  SELECT deactivated.version, deactivated.document
  FROM app.set_platform_oidc_auth_provider_activation_v1(
    p_session_id, p_provider_id, p_expected_version, false,
    'disabled', p_audit_event_id, p_request_id, p_correlation_id,
    p_ip_address, p_user_agent, p_authentication_method, p_reason
  ) AS deactivated;
$function$;

CREATE FUNCTION app.activate_tenant_platform_auth_provider_binding_v1(
  p_session_id uuid,
  p_provider_id uuid,
  p_binding_id uuid,
  p_expected_binding_version bigint,
  p_expected_tenant_version integer,
  p_jit_mode text,
  p_no_match_policy text,
  p_tenant_audit_event_id uuid,
  p_platform_audit_event_id uuid,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text,
  p_reason text
)
RETURNS TABLE (version bigint, document jsonb)
LANGUAGE sql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
  SELECT activated.version, activated.document
  FROM app.set_tenant_platform_oidc_binding_activation_v1(
    p_session_id, p_provider_id, p_binding_id, p_expected_binding_version,
    p_expected_tenant_version, true, p_jit_mode, p_no_match_policy,
    uuidv7(), uuidv7(),
    p_platform_audit_event_id, p_tenant_audit_event_id, p_request_id,
    p_correlation_id, p_ip_address, p_user_agent,
    p_authentication_method, p_reason
  ) AS activated;
$function$;

CREATE FUNCTION app.deactivate_tenant_platform_auth_provider_binding_v1(
  p_session_id uuid,
  p_provider_id uuid,
  p_binding_id uuid,
  p_expected_binding_version bigint,
  p_expected_tenant_version integer,
  p_tenant_audit_event_id uuid,
  p_platform_audit_event_id uuid,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text,
  p_reason text
)
RETURNS TABLE (version bigint, document jsonb)
LANGUAGE sql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
  SELECT deactivated.version, deactivated.document
  FROM app.set_tenant_platform_oidc_binding_activation_v1(
    p_session_id, p_provider_id, p_binding_id, p_expected_binding_version,
    p_expected_tenant_version, false, NULL, NULL, NULL, NULL,
    p_platform_audit_event_id, p_tenant_audit_event_id, p_request_id,
    p_correlation_id, p_ip_address, p_user_agent,
    p_authentication_method, p_reason
  ) AS deactivated;
$function$;
--> statement-breakpoint

ALTER FUNCTION app.private_fill_platform_oidc_tenant_redirect_v1() OWNER TO periapsis_migrator;
ALTER FUNCTION app.create_platform_oidc_auth_provider_v2(uuid,uuid,uuid,text,text,text,jsonb,text,bytea,bytea,uuid,uuid,uuid,inet,text,text,text) OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_platform_oidc_provider_activation_available_v1(uuid) OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_tenant_platform_binding_activation_available_v1(uuid) OWNER TO periapsis_migrator;
ALTER FUNCTION app.set_platform_oidc_auth_provider_activation_v1(uuid,uuid,bigint,boolean,text,uuid,uuid,uuid,inet,text,text,text) OWNER TO periapsis_migrator;
ALTER FUNCTION app.set_tenant_platform_oidc_binding_activation_v1(uuid,uuid,uuid,bigint,integer,boolean,text,text,uuid,uuid,uuid,uuid,uuid,uuid,inet,text,text,text) OWNER TO periapsis_migrator;
ALTER FUNCTION app.activate_platform_auth_provider_tenant_execution_v1(uuid,uuid,bigint,text,uuid,uuid,uuid,inet,text,text,text) OWNER TO periapsis_migrator;
ALTER FUNCTION app.deactivate_platform_auth_provider_tenant_execution_v1(uuid,uuid,bigint,uuid,uuid,uuid,inet,text,text,text) OWNER TO periapsis_migrator;
ALTER FUNCTION app.activate_tenant_platform_auth_provider_binding_v1(uuid,uuid,uuid,bigint,integer,text,text,uuid,uuid,uuid,uuid,inet,text,text,text) OWNER TO periapsis_migrator;
ALTER FUNCTION app.deactivate_tenant_platform_auth_provider_binding_v1(uuid,uuid,uuid,bigint,integer,uuid,uuid,uuid,uuid,inet,text,text,text) OWNER TO periapsis_migrator;
--> statement-breakpoint

REVOKE ALL ON FUNCTION app.create_platform_auth_provider_v1(uuid,uuid,uuid,public.auth_provider_kind,text,text,text,jsonb,bytea,bytea,uuid,uuid,uuid,inet,text,text,text)
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
    periapsis_auditor, periapsis_audit_reader_owner;
REVOKE ALL ON FUNCTION
  app.private_fill_platform_oidc_tenant_redirect_v1(),
  app.create_platform_oidc_auth_provider_v2(uuid,uuid,uuid,text,text,text,jsonb,text,bytea,bytea,uuid,uuid,uuid,inet,text,text,text),
  app.private_platform_oidc_provider_activation_available_v1(uuid),
  app.private_tenant_platform_binding_activation_available_v1(uuid),
  app.set_platform_oidc_auth_provider_activation_v1(uuid,uuid,bigint,boolean,text,uuid,uuid,uuid,inet,text,text,text),
  app.set_tenant_platform_oidc_binding_activation_v1(uuid,uuid,uuid,bigint,integer,boolean,text,text,uuid,uuid,uuid,uuid,uuid,uuid,inet,text,text,text),
  app.activate_platform_auth_provider_tenant_execution_v1(uuid,uuid,bigint,text,uuid,uuid,uuid,inet,text,text,text),
  app.deactivate_platform_auth_provider_tenant_execution_v1(uuid,uuid,bigint,uuid,uuid,uuid,inet,text,text,text),
  app.activate_tenant_platform_auth_provider_binding_v1(uuid,uuid,uuid,bigint,integer,text,text,uuid,uuid,uuid,uuid,inet,text,text,text),
  app.deactivate_tenant_platform_auth_provider_binding_v1(uuid,uuid,uuid,bigint,integer,uuid,uuid,uuid,uuid,inet,text,text,text)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner, periapsis_sla_api_owner,
  periapsis_sla_worker_owner, periapsis_sla_readiness_owner,
  periapsis_ticket_saved_view_owner, periapsis_ticket_attribution_owner,
  periapsis_ticket_sla_projection_owner;
GRANT EXECUTE ON FUNCTION
  app.create_platform_oidc_auth_provider_v2(uuid,uuid,uuid,text,text,text,jsonb,text,bytea,bytea,uuid,uuid,uuid,inet,text,text,text),
  app.activate_platform_auth_provider_tenant_execution_v1(uuid,uuid,bigint,text,uuid,uuid,uuid,inet,text,text,text),
  app.deactivate_platform_auth_provider_tenant_execution_v1(uuid,uuid,bigint,uuid,uuid,uuid,inet,text,text,text),
  app.activate_tenant_platform_auth_provider_binding_v1(uuid,uuid,uuid,bigint,integer,text,text,uuid,uuid,uuid,uuid,inet,text,text,text),
  app.deactivate_tenant_platform_auth_provider_binding_v1(uuid,uuid,uuid,bigint,integer,uuid,uuid,uuid,uuid,inet,text,text,text)
TO periapsis_api;
--> statement-breakpoint
