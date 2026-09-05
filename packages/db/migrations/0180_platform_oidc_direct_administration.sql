-- V40 makes the otherwise complete direct platform OIDC runtime explicitly
-- administrable. Tenant execution and direct platform login remain distinct
-- lifecycle decisions: direct login depends on an already-live OIDC runtime,
-- while neither writer mutates the other's policy.

COMMENT ON TABLE public.platform_oidc_login_policies IS
  'Independent prelinked-only direct platform OIDC login lifecycle. Only the protected V40 activation ABIs may mutate it.';
COMMENT ON COLUMN public.platform_federated_provider_policies.platform_login_enabled IS
  'Retired compatibility sentinel, permanently false. Direct login is governed by platform_oidc_login_policies.';
--> statement-breakpoint

CREATE FUNCTION app.private_platform_oidc_direct_activation_available_v1(
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
    JOIN ONLY public.platform_federated_provider_policies AS runtime_policy
      ON runtime_policy.provider_id = provider.id
     AND runtime_policy.provider_kind = 'oidc'
     AND runtime_policy.enabled
     AND NOT runtime_policy.platform_login_enabled
    JOIN ONLY public.platform_oidc_login_policies AS login_policy
      ON login_policy.provider_id = provider.id
     AND login_policy.provider_kind = 'oidc'
     AND NOT login_policy.enabled
     AND login_policy.account_mode = 'disabled'
    JOIN ONLY public.platform_oidc_provider_configurations AS configuration
      ON configuration.provider_id = provider.id
     AND configuration.version = runtime_policy.configuration_revision
     AND NOT configuration.allow_refresh_token
     AND configuration.redirect_uri ~
       '^https://[^/?#@]+/api/v1/auth/platform/oidc/callback$'
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
      AND provider.enabled
      AND provider.archived_at IS NULL
      AND (
        SELECT count(*)
        FROM ONLY public.mfa_policy_revisions AS platform_floor
        WHERE platform_floor.scope = 'platform_floor'
          AND platform_floor.tenant_id IS NULL
          AND platform_floor.retired_at IS NULL
      ) = 1
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
    'platformLoginEnabled', CASE provider.kind
      WHEN 'oidc' THEN coalesce(login_policy.enabled, false)
      ELSE false END,
    'platformLoginActivationAvailable', CASE provider.kind
      WHEN 'oidc' THEN
        app.private_platform_oidc_direct_activation_available_v1(provider.id)
      ELSE false END,
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
  LEFT JOIN ONLY public.platform_oidc_login_policies AS login_policy
    ON login_policy.provider_id = provider.id
   AND login_policy.provider_kind = 'oidc'
   AND provider.kind = 'oidc'
  LEFT JOIN ONLY public.platform_oidc_provider_configurations AS oidc
    ON oidc.provider_id = provider.id AND provider.kind = 'oidc'
  LEFT JOIN ONLY public.platform_saml_provider_configurations AS saml
    ON saml.provider_id = provider.id AND provider.kind = 'saml'
  WHERE provider.id = p_provider_id;
$function$;
--> statement-breakpoint

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
    'platformLoginEnabled', CASE provider.kind
      WHEN 'oidc' THEN coalesce(login_policy.enabled, false)
      ELSE false END,
    'platformLoginActivationAvailable', CASE provider.kind
      WHEN 'oidc' THEN
        app.private_platform_oidc_direct_activation_available_v1(provider.id)
      ELSE false END,
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
  LEFT JOIN ONLY public.platform_oidc_login_policies AS login_policy
    ON login_policy.provider_id = provider.id
   AND login_policy.provider_kind = 'oidc'
   AND provider.kind = 'oidc'
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

CREATE OR REPLACE FUNCTION app.guard_platform_oidc_login_policy_v1()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  capability text;
  expected_capability text;
  transition text;
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.provider_kind <> 'oidc' OR NEW.account_mode <> 'disabled'
       OR NEW.enabled OR NEW.revision <> 1
       OR NEW.created_at IS DISTINCT FROM transaction_timestamp()
       OR NEW.updated_at IS DISTINCT FROM transaction_timestamp() THEN
      RAISE EXCEPTION 'direct platform OIDC policy creation is invalid'
        USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
  END IF;
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'direct platform OIDC policies are archival records'
      USING ERRCODE = '55000';
  END IF;

  IF ROW(NEW.provider_id, NEW.provider_kind, NEW.created_at)
       IS DISTINCT FROM
     ROW(OLD.provider_id, OLD.provider_kind, OLD.created_at)
     OR OLD.revision >= 9007199254740991
     OR NEW.revision <> OLD.revision + 1
     OR NEW.updated_at IS DISTINCT FROM transaction_timestamp() THEN
    RAISE EXCEPTION 'direct platform OIDC policy transition is invalid'
      USING ERRCODE = '23514';
  END IF;
  IF NOT OLD.enabled AND OLD.account_mode = 'disabled'
     AND NEW.enabled AND NEW.account_mode = 'existing_identity' THEN
    transition := 'activate';
  ELSIF OLD.enabled AND OLD.account_mode = 'existing_identity'
     AND NOT NEW.enabled AND NEW.account_mode = 'disabled' THEN
    transition := 'deactivate';
  ELSE
    RAISE EXCEPTION 'direct platform OIDC policy transition is invalid'
      USING ERRCODE = '23514';
  END IF;

  capability := current_setting(
    'app.platform_oidc_direct_login_write_v1', true
  );
  expected_capability := format(
    '%s:%s:%s', OLD.provider_id, OLD.revision, transition
  );
  IF capability IS DISTINCT FROM expected_capability THEN
    RAISE EXCEPTION 'direct platform OIDC policy requires its protected ABI'
      USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END;
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
  IF EXISTS (
    SELECT 1 FROM ONLY public.platform_oidc_login_policies AS login_policy
    WHERE login_policy.provider_id = OLD.id
      AND login_policy.provider_kind = 'oidc'
      AND login_policy.enabled
  ) AND (
    TG_OP = 'DELETE'
    OR (TG_OP = 'UPDATE' AND (NOT NEW.enabled OR NEW.archived_at IS NOT NULL))
  ) THEN
    RAISE EXCEPTION 'platform identity provider has active direct login'
      USING ERRCODE = '55000';
  END IF;
  RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.guard_platform_oidc_direct_runtime_dependency_v1()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM ONLY public.platform_oidc_login_policies AS login_policy
    WHERE login_policy.provider_id = OLD.provider_id
      AND login_policy.provider_kind = 'oidc'
      AND login_policy.enabled
  ) THEN
    RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
  END IF;
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'active direct login requires its tenant-execution runtime'
      USING ERRCODE = '55000';
  END IF;
  IF NEW.provider_id IS DISTINCT FROM OLD.provider_id
     OR NEW.provider_kind IS DISTINCT FROM OLD.provider_kind
     OR NOT NEW.enabled OR NEW.platform_login_enabled THEN
    RAISE EXCEPTION 'active direct login requires its tenant-execution runtime'
      USING ERRCODE = '55000';
  END IF;
  RETURN NEW;
END;
$function$;
CREATE TRIGGER platform_oidc_direct_runtime_dependency_guard_v1
BEFORE UPDATE OR DELETE ON public.platform_federated_provider_policies
FOR EACH ROW EXECUTE FUNCTION app.guard_platform_oidc_direct_runtime_dependency_v1();
--> statement-breakpoint

CREATE FUNCTION app.set_platform_oidc_direct_login_activation_v1(
  p_session_id uuid,
  p_provider_id uuid,
  p_expected_version bigint,
  p_enabled boolean,
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
  read_actor_id uuid;
  provider_record public.platform_auth_providers%ROWTYPE;
  runtime_policy_record public.platform_federated_provider_policies%ROWTYPE;
  login_policy_record public.platform_oidc_login_policies%ROWTYPE;
  changed_at timestamptz := transaction_timestamp();
  transition text;
  update_count integer;
  provider_document jsonb;
BEGIN
  IF p_provider_id IS NULL
     OR uuid_extract_version(p_provider_id) IS DISTINCT FROM 7
     OR p_expected_version NOT BETWEEN 1 AND 2147483646
     OR p_enabled IS NULL
     OR p_audit_event_id IS NULL
     OR uuid_extract_version(p_audit_event_id) IS DISTINCT FROM 7
     OR p_reason IS NULL
     OR NOT app.private_platform_lifecycle_reason_is_valid_v1(p_reason) THEN
    RAISE EXCEPTION 'invalid direct platform OIDC lifecycle command'
      USING ERRCODE = '22023';
  END IF;
  actor_id := app.private_require_platform_identity_permission_v1(
    p_session_id, 'platform.identity_provider.manage', p_authentication_method
  );
  read_actor_id := app.private_require_platform_identity_permission_v1(
    p_session_id, 'platform.identity_provider.read', p_authentication_method
  );
  IF read_actor_id IS DISTINCT FROM actor_id THEN
    RAISE EXCEPTION 'live platform identity-provider authority is required'
      USING ERRCODE = '42501';
  END IF;

  SELECT provider.* INTO STRICT provider_record
  FROM ONLY public.platform_auth_providers AS provider
  WHERE provider.id = p_provider_id
  FOR UPDATE;
  SELECT runtime_policy.* INTO STRICT runtime_policy_record
  FROM ONLY public.platform_federated_provider_policies AS runtime_policy
  WHERE runtime_policy.provider_id = p_provider_id
    AND runtime_policy.provider_kind = 'oidc'
  FOR UPDATE;
  SELECT login_policy.* INTO STRICT login_policy_record
  FROM ONLY public.platform_oidc_login_policies AS login_policy
  WHERE login_policy.provider_id = p_provider_id
    AND login_policy.provider_kind = 'oidc'
  FOR UPDATE;

  IF provider_record.version <> p_expected_version THEN
    RAISE EXCEPTION 'platform identity provider revision conflict'
      USING ERRCODE = '40001';
  END IF;
  IF login_policy_record.revision >= 9007199254740991 THEN
    RAISE EXCEPTION 'direct platform OIDC policy revision is exhausted'
      USING ERRCODE = '55000';
  END IF;

  IF p_enabled THEN
    transition := 'activate';
    IF provider_record.kind <> 'oidc'
       OR provider_record.archived_at IS NOT NULL
       OR NOT provider_record.enabled
       OR NOT runtime_policy_record.enabled
       OR runtime_policy_record.platform_login_enabled
       OR login_policy_record.enabled
       OR login_policy_record.account_mode <> 'disabled' THEN
      RAISE EXCEPTION 'direct platform OIDC login cannot be activated'
        USING ERRCODE = '55000';
    END IF;
    IF NOT app.private_platform_oidc_direct_activation_available_v1(
      p_provider_id
    ) THEN
      RAISE EXCEPTION 'direct platform OIDC login is not activation-ready'
        USING ERRCODE = '55000';
    END IF;
  ELSE
    transition := 'deactivate';
    IF provider_record.kind <> 'oidc'
       OR runtime_policy_record.platform_login_enabled
       OR NOT login_policy_record.enabled
       OR login_policy_record.account_mode <> 'existing_identity' THEN
      RAISE EXCEPTION 'direct platform OIDC login cannot be deactivated'
        USING ERRCODE = '55000';
    END IF;
  END IF;

  UPDATE ONLY public.platform_auth_providers AS provider
  SET updated_by_user_id = actor_id,
      version = provider.version + 1,
      updated_at = changed_at
  WHERE provider.id = p_provider_id
    AND provider.version = p_expected_version;
  GET DIAGNOSTICS update_count = ROW_COUNT;
  IF update_count <> 1 THEN
    RAISE EXCEPTION 'platform identity provider revision conflict'
      USING ERRCODE = '40001';
  END IF;

  PERFORM pg_catalog.set_config(
    'app.platform_oidc_direct_login_write_v1',
    format(
      '%s:%s:%s', p_provider_id, login_policy_record.revision, transition
    ),
    true
  );
  UPDATE ONLY public.platform_oidc_login_policies AS login_policy
  SET enabled = p_enabled,
      account_mode = CASE WHEN p_enabled
        THEN 'existing_identity' ELSE 'disabled' END,
      revision = login_policy.revision + 1,
      updated_at = changed_at
  WHERE login_policy.provider_id = p_provider_id
    AND login_policy.revision = login_policy_record.revision;
  GET DIAGNOSTICS update_count = ROW_COUNT;
  PERFORM pg_catalog.set_config(
    'app.platform_oidc_direct_login_write_v1', '', true
  );
  IF update_count <> 1 THEN
    RAISE EXCEPTION 'direct platform OIDC policy revision conflict'
      USING ERRCODE = '40001';
  END IF;

  IF p_enabled AND app.private_platform_oidc_direct_configuration_v1(
       p_provider_id, NULL
     ) IS NULL THEN
    RAISE EXCEPTION 'direct platform OIDC activation did not become live'
      USING ERRCODE = '55000';
  ELSIF NOT p_enabled AND app.private_platform_oidc_direct_configuration_v1(
       p_provider_id, NULL
     ) IS NOT NULL THEN
    RAISE EXCEPTION 'direct platform OIDC deactivation remained live'
      USING ERRCODE = '55000';
  END IF;

  PERFORM app.append_platform_audit_event(
    p_audit_event_id, 'user', actor_id,
    CASE WHEN p_enabled
      THEN 'platform.identity_provider.direct_login.activated'
      ELSE 'platform.identity_provider.direct_login.deactivated' END,
    'platform_identity_provider', p_provider_id,
    p_request_id, p_correlation_id, p_ip_address, p_user_agent,
    p_authentication_method, 'success', p_reason,
    jsonb_build_object(
      'kind', 'oidc',
      'enabled', p_enabled,
      'account_mode', CASE WHEN p_enabled
        THEN 'existing_identity' ELSE 'disabled' END,
      'previous_provider_version', provider_record.version,
      'provider_version', provider_record.version + 1,
      'previous_login_policy_revision', login_policy_record.revision,
      'login_policy_revision', login_policy_record.revision + 1
    )
  );
  provider_document := app.private_platform_auth_provider_document_v1(
    p_provider_id
  );
  RETURN QUERY SELECT p_expected_version + 1, provider_document;
EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
  RAISE EXCEPTION 'platform OIDC provider lifecycle is unavailable'
    USING ERRCODE = 'P0002';
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.activate_platform_oidc_direct_login_v1(
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
  SELECT activated.version, activated.document
  FROM app.set_platform_oidc_direct_login_activation_v1(
    p_session_id, p_provider_id, p_expected_version, true,
    p_audit_event_id, p_request_id, p_correlation_id, p_ip_address,
    p_user_agent, p_authentication_method, p_reason
  ) AS activated;
$function$;

CREATE FUNCTION app.deactivate_platform_oidc_direct_login_v1(
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
  FROM app.set_platform_oidc_direct_login_activation_v1(
    p_session_id, p_provider_id, p_expected_version, false,
    p_audit_event_id, p_request_id, p_correlation_id, p_ip_address,
    p_user_agent, p_authentication_method, p_reason
  ) AS deactivated;
$function$;
--> statement-breakpoint

-- A successful tenant switch revokes the source bearer before the adapter can
-- persist its response.  This narrow proof lookup lets the adapter recover
-- that one committed result without reopening the revoked source session or
-- exposing a broader command/session read surface.
CREATE FUNCTION app.lookup_platform_oidc_tenant_switch_replay_v1(
  p_lookup jsonb
)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
#variable_conflict use_variable
DECLARE
  source_session_id uuid;
  target_tenant_id uuid;
  new_session_id uuid;
  rotation_family_id uuid;
  source_token_digest bytea;
  new_token_digest bytea;
  csrf_secret_digest bytea;
  occurred_at timestamptz;
  idle_expires_at timestamptz;
  absolute_expires_at timestamptz;
  audit jsonb;
  audit_event_id uuid;
  audit_request_id uuid;
  audit_correlation_id uuid;
  audit_ip_address inet;
  matched_result jsonb;
BEGIN
  PERFORM app.private_platform_oidc_direct_json_v1(
    p_lookup,
    ARRAY['sourceSessionId','targetTenantId','newSessionId',
      'rotationFamilyId','sourceTokenDigest','newTokenDigest',
      'csrfSecretDigest','occurredAt','idleExpiresAt','absoluteExpiresAt',
      'audit'],
    ARRAY['sourceSessionId','targetTenantId','newSessionId',
      'rotationFamilyId','sourceTokenDigest','newTokenDigest',
      'csrfSecretDigest','occurredAt','idleExpiresAt','absoluteExpiresAt',
      'audit'],32768
  );
  source_session_id := app.private_mfa_require_uuidv7_v1(
    p_lookup ->> 'sourceSessionId'
  );
  target_tenant_id := app.private_mfa_require_uuidv7_v1(
    p_lookup ->> 'targetTenantId'
  );
  new_session_id := app.private_mfa_require_uuidv7_v1(
    p_lookup ->> 'newSessionId'
  );
  rotation_family_id := app.private_mfa_require_uuidv7_v1(
    p_lookup ->> 'rotationFamilyId'
  );
  source_token_digest := app.private_mfa_decode_base64_v1(
    p_lookup ->> 'sourceTokenDigest',32,32
  );
  new_token_digest := app.private_mfa_decode_base64_v1(
    p_lookup ->> 'newTokenDigest',32,32
  );
  csrf_secret_digest := app.private_mfa_decode_base64_v1(
    p_lookup ->> 'csrfSecretDigest',32,32
  );
  occurred_at := (p_lookup ->> 'occurredAt')::timestamptz;
  idle_expires_at := (p_lookup ->> 'idleExpiresAt')::timestamptz;
  absolute_expires_at := (p_lookup ->> 'absoluteExpiresAt')::timestamptz;
  audit := p_lookup -> 'audit';
  PERFORM app.private_platform_oidc_direct_json_v1(
    audit,
    ARRAY['eventId','requestId','correlationId','ipAddress','userAgent',
      'authenticationMethod','reason'],
    ARRAY['eventId','requestId','correlationId','authenticationMethod'],8192
  );
  audit_event_id := app.private_mfa_require_uuidv7_v1(
    audit ->> 'eventId'
  );
  audit_request_id := app.private_mfa_require_uuidv7_v1(
    audit ->> 'requestId'
  );
  audit_correlation_id := app.private_mfa_require_uuidv7_v1(
    audit ->> 'correlationId'
  );
  IF audit ? 'ipAddress' AND audit ->> 'ipAddress' <> '' THEN
    audit_ip_address := (audit ->> 'ipAddress')::inet;
  END IF;
  IF source_session_id = new_session_id
     OR source_token_digest IN (new_token_digest,csrf_secret_digest)
     OR new_token_digest = csrf_secret_digest
     OR pg_catalog.encode(source_token_digest,'hex') = pg_catalog.repeat('00',32)
     OR pg_catalog.encode(new_token_digest,'hex') = pg_catalog.repeat('00',32)
     OR pg_catalog.encode(csrf_secret_digest,'hex') = pg_catalog.repeat('00',32)
     OR audit ->> 'authenticationMethod' <> 'oidc'
     OR idle_expires_at <= occurred_at
     OR absolute_expires_at < idle_expires_at THEN
    RAISE EXCEPTION 'invalid direct platform OIDC tenant switch replay lookup'
      USING ERRCODE = '22023';
  END IF;

  SELECT command.result_snapshot INTO matched_result
  FROM ONLY public.platform_oidc_tenant_switch_commands AS command
  JOIN ONLY public.auth_sessions AS source_session
    ON source_session.id = command.source_session_id
  JOIN ONLY public.auth_session_platform_oidc_states AS source_state
    ON source_state.session_id = source_session.id
   AND source_state.user_id = source_session.user_id
  JOIN ONLY public.auth_session_platform_oidc_provenance AS source_provenance
    ON source_provenance.session_id = source_session.id
   AND source_provenance.user_id = source_session.user_id
   AND source_provenance.primary_kind = source_state.primary_kind
  JOIN ONLY public.auth_sessions AS rotated_session
    ON rotated_session.id = command.rotated_session_id
   AND rotated_session.rotated_from_session_id = source_session.id
   AND rotated_session.user_id = source_session.user_id
  JOIN ONLY public.auth_session_mfa_states AS rotated_state
    ON rotated_state.session_id = rotated_session.id
   AND rotated_state.tenant_id = command.target_tenant_id
   AND rotated_state.user_id = rotated_session.user_id
  JOIN ONLY public.auth_session_tenant_platform_federated_provenance
    AS rotated_provenance
    ON rotated_provenance.session_id = rotated_session.id
   AND rotated_provenance.tenant_id = command.target_tenant_id
   AND rotated_provenance.user_id = rotated_session.user_id
   AND rotated_provenance.primary_kind = 'tenant_platform_provider'
   AND rotated_provenance.authentication_method = 'oidc'
   AND rotated_provenance.platform_provider_id =
     source_provenance.platform_provider_id
   AND rotated_provenance.external_identity_id =
     source_provenance.external_identity_id
   AND rotated_provenance.membership_id = command.membership_id
   AND rotated_provenance.binding_id = command.binding_id
   AND rotated_provenance.access_epoch_id = command.access_epoch_id
   AND rotated_provenance.access_source_id = command.access_source_id
   AND rotated_provenance.access_grant_id = command.access_grant_id
  JOIN ONLY public.platform_audit_events AS audit_event
    ON audit_event.id = audit_event_id
  WHERE command.source_session_id = source_session_id
    AND command.target_tenant_id = target_tenant_id
    AND command.rotated_session_id = new_session_id
    AND command.decision = 'rotated'
    AND command.applied_at = occurred_at
    AND command.expected_version = rotated_state.session_version - 1
    AND command.result_snapshot = jsonb_build_object(
      'applied',true,'decision','rotated',
      'sourceSessionId',source_session_id::text,
      'sessionId',new_session_id::text,
      'targetTenantId',target_tenant_id::text,
      'sessionVersion',rotated_state.session_version
    )
    AND source_session.rotation_family_id = rotation_family_id
    AND source_session.token_digest = source_token_digest
    AND source_session.revoked_at = occurred_at
    AND source_session.revoke_reason =
      'platform_oidc_tenant_switch_rotated'
    AND source_session.absolute_expires_at = absolute_expires_at
    AND source_state.session_version = command.expected_version
    AND rotated_session.rotation_family_id = rotation_family_id
    AND rotated_session.active_tenant_id = target_tenant_id
    AND rotated_session.token_digest = new_token_digest
    AND rotated_session.csrf_secret_digest = csrf_secret_digest
    AND rotated_session.authentication_method = 'oidc'
    AND rotated_session.revoked_at IS NULL
    AND rotated_session.revoke_reason IS NULL
    AND rotated_session.last_seen_at = occurred_at
    AND rotated_session.idle_expires_at = idle_expires_at
    AND rotated_session.absolute_expires_at = absolute_expires_at
    AND rotated_session.created_at = occurred_at
    AND rotated_state.session_version = command.expected_version + 1
    AND rotated_state.issued_at = occurred_at
    AND rotated_state.audience = 'api'
    AND NOT rotated_state.recovery_restricted
    AND rotated_state.primary_kind = 'tenant_platform_provider'
    AND audit_event.actor_type = 'system'
    AND audit_event.actor_user_id IS NULL
    AND audit_event.action = 'platform.oidc.session.tenant_switched'
    AND audit_event.resource_type = 'auth_session'
    AND audit_event.resource_id = source_session_id
    AND audit_event.request_id = audit_request_id
    AND audit_event.correlation_id = audit_correlation_id
    AND audit_event.ip_address IS NOT DISTINCT FROM audit_ip_address
    AND audit_event.user_agent IS NOT DISTINCT FROM
      nullif(audit ->> 'userAgent','')
    AND audit_event.authentication_method = 'oidc'
    AND audit_event.outcome = 'success'
    AND audit_event.reason IS NOT DISTINCT FROM audit ->> 'reason'
    AND audit_event.metadata = jsonb_build_object(
      'provider_id',source_provenance.platform_provider_id,
      'user_id',source_session.user_id,
      'target_tenant_id',target_tenant_id,
      'decision','rotated',
      'expected_version',command.expected_version
    );
  IF NOT FOUND THEN
    RETURN jsonb_build_object('matched',false);
  END IF;
  RETURN jsonb_build_object('matched',true,'result',matched_result);
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range
  OR data_exception THEN
  RAISE EXCEPTION 'invalid direct platform OIDC tenant switch replay lookup'
    USING ERRCODE = '22023';
END;
$function$;
--> statement-breakpoint

ALTER FUNCTION app.private_platform_auth_provider_document_v1(uuid)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.list_platform_auth_providers_v1(
  uuid,text,uuid,integer,boolean
) OWNER TO periapsis_migrator;
ALTER FUNCTION app.guard_platform_oidc_login_policy_v1()
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.guard_platform_auth_provider_binding_dependency_v1()
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.guard_platform_oidc_direct_runtime_dependency_v1()
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_platform_oidc_direct_activation_available_v1(uuid)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.set_platform_oidc_direct_login_activation_v1(
  uuid,uuid,bigint,boolean,uuid,uuid,uuid,inet,text,text,text
) OWNER TO periapsis_migrator;
ALTER FUNCTION app.activate_platform_oidc_direct_login_v1(
  uuid,uuid,bigint,uuid,uuid,uuid,inet,text,text,text
) OWNER TO periapsis_migrator;
ALTER FUNCTION app.deactivate_platform_oidc_direct_login_v1(
  uuid,uuid,bigint,uuid,uuid,uuid,inet,text,text,text
) OWNER TO periapsis_migrator;
ALTER FUNCTION app.lookup_platform_oidc_tenant_switch_replay_v1(jsonb)
  OWNER TO periapsis_migrator;
--> statement-breakpoint

REVOKE ALL ON FUNCTION
  app.guard_platform_oidc_login_policy_v1(),
  app.guard_platform_auth_provider_binding_dependency_v1(),
  app.guard_platform_oidc_direct_runtime_dependency_v1(),
  app.private_platform_oidc_direct_activation_available_v1(uuid),
  app.set_platform_oidc_direct_login_activation_v1(
    uuid,uuid,bigint,boolean,uuid,uuid,uuid,inet,text,text,text
  )
FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
  periapsis_auditor,periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,periapsis_sla_api_owner,
  periapsis_sla_worker_owner,periapsis_sla_readiness_owner,
  periapsis_ticket_saved_view_owner,periapsis_ticket_attribution_owner,
  periapsis_ticket_sla_projection_owner;
REVOKE ALL ON FUNCTION
  app.activate_platform_oidc_direct_login_v1(
    uuid,uuid,bigint,uuid,uuid,uuid,inet,text,text,text
  ),
  app.deactivate_platform_oidc_direct_login_v1(
    uuid,uuid,bigint,uuid,uuid,uuid,inet,text,text,text
  ),
  app.lookup_platform_oidc_tenant_switch_replay_v1(
    jsonb
  )
FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
  periapsis_auditor,periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,periapsis_sla_api_owner,
  periapsis_sla_worker_owner,periapsis_sla_readiness_owner,
  periapsis_ticket_saved_view_owner,periapsis_ticket_attribution_owner,
  periapsis_ticket_sla_projection_owner;
GRANT EXECUTE ON FUNCTION
  app.activate_platform_oidc_direct_login_v1(
    uuid,uuid,bigint,uuid,uuid,uuid,inet,text,text,text
  ),
  app.deactivate_platform_oidc_direct_login_v1(
    uuid,uuid,bigint,uuid,uuid,uuid,inet,text,text,text
  ),
  app.lookup_platform_oidc_tenant_switch_replay_v1(
    jsonb
  )
TO periapsis_api,periapsis_migrator;
