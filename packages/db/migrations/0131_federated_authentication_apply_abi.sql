-- Commit-time federation ABI.  All public entry points accept one bounded
-- operation-shaped JSON document; raw claims, subjects, tokens and assertions
-- never cross this boundary.

-- Planning must not evaluate only the subject's roles before a provider
-- mapping is applied: doing so could issue an under-assured session when a
-- matched rule grants a role with a stronger MFA policy.  Include every live
-- target for the pinned mapping revision.  This can over-challenge a login,
-- but it cannot under-challenge one and is stable across planning/apply.
CREATE FUNCTION app.private_federated_assurance_requirement_v1(
  p_tenant_id uuid,
  p_user_id uuid,
  p_binding_id uuid,
  p_mapping_revision bigint,
  p_action text,
  p_evaluated_at timestamptz
)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_base jsonb;
  v_requirement jsonb;
  v_count integer;
BEGIN
  IF p_tenant_id IS NULL OR p_binding_id IS NULL
     OR p_mapping_revision < 1 OR p_evaluated_at IS NULL
     OR NOT app.private_mfa_safe_text_v1(p_action, 256) THEN
    RAISE EXCEPTION 'federated assurance context is invalid'
      USING ERRCODE = '22023';
  END IF;
  v_base := app.private_mfa_policy_snapshot_v1(
    p_tenant_id, p_user_id, p_action, p_evaluated_at
  );

  WITH target_groups AS (
    SELECT DISTINCT epoch.tenant_security_group_id AS id
    FROM public.tenant_federated_mapping_rule_epochs AS epoch
    WHERE epoch.tenant_id = p_tenant_id
      AND epoch.binding_id = p_binding_id
      AND epoch.mapping_revision = p_mapping_revision
      AND epoch.enabled AND epoch.ended_at IS NULL
  ), target_roles AS (
    SELECT DISTINCT target.role_id AS id
    FROM public.tenant_federated_mapping_rule_epochs AS epoch
    JOIN public.tenant_federated_mapping_rule_role_targets AS target
      ON target.tenant_id = epoch.tenant_id
     AND target.rule_epoch_id = epoch.id
    WHERE epoch.tenant_id = p_tenant_id
      AND epoch.binding_id = p_binding_id
      AND epoch.mapping_revision = p_mapping_revision
      AND epoch.enabled AND epoch.ended_at IS NULL
  ), base_policies AS (
    SELECT entry -> 'policy' AS policy
    FROM jsonb_array_elements(v_base -> 'policies') AS entry
  ), extra_policies AS (
    SELECT jsonb_build_object(
      'id', revision.id::text,
      'revision', revision.revision,
      'level', revision.level,
      'localRequired', revision.local_required,
      'freshnessNanoseconds', revision.freshness_nanoseconds,
      'enrollmentDeadline', revision.enrollment_deadline
    ) AS policy
    FROM public.mfa_policy_revisions AS revision
    WHERE revision.tenant_id = p_tenant_id
      AND revision.retired_at IS NULL
      AND ((revision.scope = 'role'
            AND revision.role_id IN (SELECT id FROM target_roles))
        OR (revision.scope = 'security_group'
            AND revision.security_group_id IN (SELECT id FROM target_groups)))
  ), policies AS (
    SELECT DISTINCT ON (policy ->> 'id') policy
    FROM (
      SELECT policy FROM base_policies
      UNION ALL
      SELECT policy FROM extra_policies
    ) AS combined
    ORDER BY policy ->> 'id', (policy ->> 'revision')::bigint DESC
  )
  SELECT count(*)::integer,
    jsonb_build_object(
      'level', CASE max(CASE policy ->> 'level'
        WHEN 'primary' THEN 1 WHEN 'mfa' THEN 2
        WHEN 'phishing_resistant' THEN 3 END)
        WHEN 1 THEN 'primary' WHEN 2 THEN 'mfa'
        WHEN 3 THEN 'phishing_resistant' END,
      'localRequired', coalesce(bool_or((policy ->> 'localRequired')::boolean), false),
      'freshnessNanoseconds', coalesce(min((policy ->> 'freshnessNanoseconds')::bigint)
        FILTER (WHERE (policy ->> 'freshnessNanoseconds')::bigint > 0), 0),
      'enrollmentDeadline', min(nullif(policy ->> 'enrollmentDeadline', '')::timestamptz),
      'policyRevisions', coalesce(jsonb_agg(jsonb_build_object(
        'policyId', policy ->> 'id',
        'revision', (policy ->> 'revision')::bigint
      ) ORDER BY policy ->> 'id'), '[]'::jsonb)
    )
  INTO v_count, v_requirement
  FROM policies;

  IF v_count NOT BETWEEN 1 AND 1024
     OR jsonb_array_length(v_requirement -> 'policyRevisions') <> v_count THEN
    RAISE EXCEPTION 'federated assurance policy set is unavailable'
      USING ERRCODE = '42501';
  END IF;
  RETURN v_requirement;
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.apply_federated_authentication_v1(p_command jsonb)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_apply jsonb;
  v_auth jsonb;
  v_plan jsonb;
  v_protocol_document jsonb;
  v_pins jsonb;
  v_provider jsonb;
  v_operation_digest bytea;
  v_transaction_id bytea;
  v_session_index_digest bytea;
  v_response_id_digest bytea;
  v_assertion_id_digest bytea;
  v_protocol text;
  v_disposition text;
  v_assurance text;
  v_return_path text;
  v_tenant_id uuid;
  v_provider_id uuid;
  v_binding_id uuid;
  v_provider_kind public.auth_provider_kind;
  v_plan_user_id uuid;
  v_expected_version bigint;
  v_applied_at timestamptz;
  v_authenticated_at timestamptz;
  v_valid_until timestamptz;
  v_protocol_completed_at timestamptz;
  v_plan_revision bigint;
  v_provider_revision bigint;
  v_binding_revision bigint;
  v_configuration_revision bigint;
  v_security_revision bigint;
  v_mapping_revision bigint;
  v_authorization_revision bigint;
  v_policy_revision bigint;
  v_identity_epoch bigint;
  v_configuration_version bigint;
  v_requirement jsonb;
  v_decision text;
  v_live record;
  v_existing record;
  v_identity record;
  v_authority jsonb;
  v_result jsonb;
  v_session_id uuid;
  v_continuation_id uuid;
  v_resource_id uuid;
BEGIN
  PERFORM app.private_mfa_assert_json_object_v1(
    p_command, ARRAY['operationDigest','apply'], ARRAY['operationDigest','apply'],
    2162688
  );
  v_operation_digest := app.private_mfa_decode_base64_v1(
    p_command ->> 'operationDigest', 32, 32
  );
  IF encode(v_operation_digest, 'hex') = repeat('00', 32) THEN
    RAISE EXCEPTION 'federated operation digest is invalid'
      USING ERRCODE = '22023';
  END IF;
  v_apply := p_command -> 'apply';
  PERFORM app.private_mfa_assert_json_object_v1(
    v_apply,
    ARRAY['authentication','plan','disposition','assurance','appliedAt',
      'session','continuation','samlSession'],
    ARRAY['authentication','plan','disposition','assurance','appliedAt'],
    2097152
  );
  v_auth := v_apply -> 'authentication';
  v_plan := v_apply -> 'plan';
  PERFORM app.private_mfa_assert_json_object_v1(
    v_auth,
    ARRAY['protocol','method','tenantId','authenticatedAt','validUntil',
      'evidence','oidc','saml','passkey'],
    ARRAY['protocol','method','tenantId','authenticatedAt','validUntil','evidence'],
    524288
  );
  v_protocol := v_auth ->> 'protocol';
  v_disposition := v_apply ->> 'disposition';
  v_assurance := v_apply ->> 'assurance';
  IF v_protocol NOT IN ('oidc','saml')
     OR v_auth ->> 'method' <> v_protocol
     OR v_disposition NOT IN ('session','continuation')
     OR NOT ((v_disposition = 'session' AND v_assurance = 'satisfied')
       OR (v_disposition = 'continuation'
         AND v_assurance IN ('step_up_required','enrollment_only')))
     OR v_auth ? 'passkey' THEN
    RAISE EXCEPTION 'federated apply route is invalid' USING ERRCODE = '22023';
  END IF;
  BEGIN
    v_tenant_id := app.private_mfa_require_uuidv7_v1(v_auth ->> 'tenantId');
    v_plan_user_id := nullif(v_plan ->> 'userId', '')::uuid;
    v_applied_at := (v_apply ->> 'appliedAt')::timestamptz;
    v_authenticated_at := (v_auth ->> 'authenticatedAt')::timestamptz;
    v_valid_until := (v_auth ->> 'validUntil')::timestamptz;
    v_plan_revision := (v_plan ->> 'planRevision')::bigint;
    v_identity_epoch := (v_plan ->> 'identityEpoch')::bigint;
    v_provider_revision := (v_plan ->> 'providerRevision')::bigint;
    v_binding_revision := (v_plan ->> 'bindingRevision')::bigint;
    v_configuration_revision := (v_plan ->> 'configurationRevision')::bigint;
    v_security_revision := (v_plan ->> 'securityRevision')::bigint;
    v_mapping_revision := (v_plan ->> 'mappingRevision')::bigint;
    v_authorization_revision := (v_plan ->> 'authorizationRevision')::bigint;
    v_policy_revision := (v_plan ->> 'policyRevision')::bigint;
  EXCEPTION WHEN OTHERS THEN
    RAISE EXCEPTION 'federated apply scalar is invalid' USING ERRCODE = '22023';
  END;
  IF v_plan ->> 'tenantId' <> v_tenant_id::text
     OR v_plan_revision < 1 OR v_provider_revision < 1
     OR v_binding_revision < 1 OR v_configuration_revision < 1
     OR v_security_revision < 1 OR v_mapping_revision < 1
     OR v_authorization_revision < 1 OR v_policy_revision < 1
     OR (v_plan_user_id IS NULL) <> (v_identity_epoch = 0)
     OR (v_plan_user_id IS NOT NULL
       AND (v_identity_epoch < 1
         OR NOT ((uuid_extract_version(v_plan_user_id) = 7) IS TRUE)))
     OR v_applied_at IS NULL
     OR date_trunc('microseconds', v_applied_at) <> v_applied_at
     OR abs(extract(epoch FROM (transaction_timestamp() - v_applied_at))) > 300
     OR v_authenticated_at IS NULL OR v_authenticated_at > v_applied_at
     OR v_valid_until IS NULL OR v_valid_until <= v_applied_at
     OR date_trunc('microseconds', v_authenticated_at) <> v_authenticated_at
     OR date_trunc('microseconds', v_valid_until) <> v_valid_until
     OR jsonb_typeof(v_auth -> 'evidence') <> 'array'
     OR jsonb_array_length(v_auth -> 'evidence') NOT BETWEEN 1 AND 64
     OR jsonb_typeof(v_plan -> 'hasEnrollableFactor') <> 'boolean' THEN
    RAISE EXCEPTION 'federated apply snapshot is invalid' USING ERRCODE = '22023';
  END IF;

  IF v_protocol = 'oidc' THEN
    IF v_auth ? 'saml' OR NOT (v_auth ? 'oidc') OR v_apply ? 'samlSession' THEN
      RAISE EXCEPTION 'OIDC apply shape is invalid' USING ERRCODE = '22023';
    END IF;
    v_protocol_document := v_auth -> 'oidc';
    PERFORM app.private_mfa_assert_json_object_v1(
      v_protocol_document,
      ARRAY['transactionId','expectedVersion','pins','completedAt','returnPath'],
      ARRAY['transactionId','expectedVersion','pins','completedAt','returnPath'],
      262144
    );
  ELSE
    IF v_auth ? 'oidc' OR NOT (v_auth ? 'saml') THEN
      RAISE EXCEPTION 'SAML apply shape is invalid' USING ERRCODE = '22023';
    END IF;
    v_protocol_document := v_auth -> 'saml';
    PERFORM app.private_mfa_assert_json_object_v1(
      v_protocol_document,
      ARRAY['transactionId','expectedVersion','pins','responseId','assertionId',
        'sessionIndexDigest','hasSessionIndex','consumedAt','returnPath'],
      ARRAY['transactionId','expectedVersion','pins','responseId','assertionId',
        'hasSessionIndex','consumedAt','returnPath'],
      262144
    );
  END IF;
  v_transaction_id := app.private_mfa_decode_base64_v1(
    v_protocol_document ->> 'transactionId', 32, 32
  );
  BEGIN
    v_expected_version := (v_protocol_document ->> 'expectedVersion')::bigint;
    v_protocol_completed_at := (
      v_protocol_document ->> CASE WHEN v_protocol = 'oidc'
        THEN 'completedAt' ELSE 'consumedAt' END
    )::timestamptz;
  EXCEPTION WHEN OTHERS THEN
    RAISE EXCEPTION 'federated protocol completion is invalid'
      USING ERRCODE = '22023';
  END;
  v_return_path := v_protocol_document ->> 'returnPath';
  IF v_expected_version < 1 OR v_protocol_completed_at IS NULL
     OR v_protocol_completed_at > v_applied_at
     OR v_applied_at - v_protocol_completed_at > interval '5 minutes'
     OR v_return_path IS NULL OR btrim(v_return_path) <> v_return_path
     OR char_length(v_return_path) NOT BETWEEN 1 AND 2048
     OR v_return_path ~ '[[:cntrl:]]'
     OR left(v_return_path, 1) <> '/' THEN
    RAISE EXCEPTION 'federated protocol completion is invalid'
      USING ERRCODE = '22023';
  END IF;

  v_pins := v_protocol_document -> 'pins';
  IF v_protocol = 'oidc' THEN
    PERFORM app.private_mfa_assert_json_object_v1(
      v_pins,
      ARRAY['provider','providerRevision','bindingRevision','configurationRevision',
        'securityRevision','mappingRevision','authorizationRevision',
        'assurancePolicyRevision','clientSecretRevision','discoveryRevision',
        'discoveryDigest','jwksRevision','jwksDigest'],
      ARRAY['provider','providerRevision','bindingRevision','configurationRevision',
        'securityRevision','mappingRevision','authorizationRevision',
        'assurancePolicyRevision','clientSecretRevision','discoveryRevision',
        'discoveryDigest','jwksRevision','jwksDigest'],
      131072
    );
  ELSE
    PERFORM app.private_mfa_assert_json_object_v1(
      v_pins,
      ARRAY['provider','providerRevision','bindingRevision','configurationRevision',
        'securityRevision','mappingRevision','authorizationRevision',
        'assurancePolicyRevision','metadataRevision','metadataDigest',
        'spKeyRevision','configurationDigest'],
      ARRAY['provider','providerRevision','bindingRevision','configurationRevision',
        'securityRevision','mappingRevision','authorizationRevision',
        'assurancePolicyRevision','metadataRevision','metadataDigest',
        'spKeyRevision','configurationDigest'],
      131072
    );
  END IF;
  v_provider := v_pins -> 'provider';
  PERFORM app.private_mfa_assert_json_object_v1(
    v_provider, ARRAY['scope','tenantId','providerId','bindingId'],
    ARRAY['scope','tenantId','providerId','bindingId'], 8192
  );
  BEGIN
    v_provider_id := app.private_mfa_require_uuidv7_v1(v_provider ->> 'providerId');
    v_binding_id := app.private_mfa_require_uuidv7_v1(v_provider ->> 'bindingId');
    v_provider_kind := v_protocol::public.auth_provider_kind;
  EXCEPTION WHEN OTHERS THEN
    RAISE EXCEPTION 'federated provider identity is invalid' USING ERRCODE = '22023';
  END;
  IF v_provider ->> 'scope' <> 'tenant'
     OR v_provider ->> 'tenantId' <> v_tenant_id::text
     OR (v_pins ->> 'providerRevision')::bigint <> v_provider_revision
     OR (v_pins ->> 'bindingRevision')::bigint <> v_binding_revision
     OR (v_pins ->> 'configurationRevision')::bigint <> v_configuration_revision
     OR (v_pins ->> 'securityRevision')::bigint <> v_security_revision
     OR (v_pins ->> 'mappingRevision')::bigint <> v_mapping_revision
     OR (v_pins ->> 'authorizationRevision')::bigint <> v_authorization_revision
     OR (v_pins ->> 'assurancePolicyRevision')::bigint <> v_policy_revision THEN
    RAISE EXCEPTION 'federated plan pins are inconsistent' USING ERRCODE = '22023';
  END IF;

  IF v_protocol = 'saml' THEN
    IF NOT app.private_mfa_safe_text_v1(v_protocol_document ->> 'responseId', 1024)
       OR NOT app.private_mfa_safe_text_v1(v_protocol_document ->> 'assertionId', 1024)
       OR v_protocol_document ->> 'responseId' = v_protocol_document ->> 'assertionId'
       OR jsonb_typeof(v_protocol_document -> 'hasSessionIndex') <> 'boolean' THEN
      RAISE EXCEPTION 'SAML replay evidence is invalid' USING ERRCODE = '22023';
    END IF;
    v_response_id_digest := sha256(convert_to(v_protocol_document ->> 'responseId', 'UTF8'));
    v_assertion_id_digest := sha256(convert_to(v_protocol_document ->> 'assertionId', 'UTF8'));
    IF (v_protocol_document ->> 'hasSessionIndex')::boolean THEN
      IF NOT (v_protocol_document ? 'sessionIndexDigest') THEN
        RAISE EXCEPTION 'SAML session index evidence is invalid' USING ERRCODE = '22023';
      END IF;
      v_session_index_digest := app.private_mfa_decode_base64_v1(
        v_protocol_document ->> 'sessionIndexDigest', 32, 32
      );
    ELSIF v_protocol_document ? 'sessionIndexDigest' THEN
      RAISE EXCEPTION 'SAML session index evidence is non-canonical' USING ERRCODE = '22023';
    END IF;
  END IF;

  SELECT transaction_row.*,
         provider.version AS live_provider_revision,
         binding.version AS live_binding_revision,
         binding.mapping_revision AS live_mapping_revision,
         binding.auth_revision AS live_authorization_revision,
         policy.configuration_revision AS live_policy_configuration_revision,
         policy.security_revision AS live_security_revision,
         policy.plan_revision AS live_plan_revision,
         policy.assurance_policy_revision AS live_policy_revision
    INTO v_live
  FROM public.tenant_federated_authentication_transactions AS transaction_row
  JOIN public.tenants AS tenant
    ON tenant.id = transaction_row.tenant_id AND tenant.status = 'active'
  JOIN public.tenant_auth_providers AS provider
    ON provider.tenant_id = transaction_row.tenant_id
   AND provider.id = transaction_row.provider_id
   AND provider.kind = transaction_row.provider_kind
   AND provider.enabled AND provider.archived_at IS NULL
  JOIN public.tenant_auth_provider_bindings AS binding
    ON binding.tenant_id = transaction_row.tenant_id
   AND binding.id = transaction_row.binding_id
   AND binding.provider_id = transaction_row.provider_id
   AND binding.enabled AND binding.archived_at IS NULL
   AND binding.current_access_epoch_id IS NOT NULL
  JOIN public.tenant_identity_provider_access_epochs AS access_epoch
    ON access_epoch.tenant_id = binding.tenant_id
   AND access_epoch.id = binding.current_access_epoch_id
   AND access_epoch.binding_id = binding.id
   AND access_epoch.provider_id = binding.provider_id
   AND access_epoch.ended_at IS NULL
  JOIN public.tenant_authorization_sources AS access_source
    ON access_source.tenant_id = access_epoch.tenant_id
   AND access_source.id = access_epoch.source_id
   AND access_source.kind = 'identity_provider_access'
   AND access_source.retired_at IS NULL
  JOIN public.tenant_federated_provider_policies AS policy
    ON policy.tenant_id = transaction_row.tenant_id
   AND policy.provider_id = transaction_row.provider_id
   AND policy.binding_id = transaction_row.binding_id
   AND policy.provider_kind = transaction_row.provider_kind
   AND policy.enabled
  WHERE transaction_row.tenant_id = v_tenant_id
    AND transaction_row.protocol = v_protocol
    AND transaction_row.transaction_id = v_transaction_id
    AND transaction_row.provider_id = v_provider_id
    AND transaction_row.binding_id = v_binding_id
    AND transaction_row.provider_kind = v_provider_kind
  FOR UPDATE OF transaction_row, provider, binding, policy;
  IF NOT FOUND THEN
    RETURN app.private_federated_apply_response_v1(
      v_operation_digest, v_protocol, v_tenant_id, v_disposition, 'denied'
    );
  END IF;

  IF v_protocol = 'oidc' THEN
    SELECT configuration.version INTO v_configuration_version
    FROM public.tenant_oidc_provider_configurations AS configuration
    WHERE configuration.tenant_id = v_tenant_id
      AND configuration.provider_id = v_provider_id
      AND configuration.provider_kind = 'oidc'
      AND configuration.client_secret_revision = (v_pins ->> 'clientSecretRevision')::bigint
      AND configuration.discovery_revision = (v_pins ->> 'discoveryRevision')::bigint
      AND configuration.jwks_revision = (v_pins ->> 'jwksRevision')::bigint
      AND EXISTS (
        SELECT 1 FROM public.tenant_oidc_client_secrets AS secret
        WHERE secret.tenant_id = configuration.tenant_id
          AND secret.provider_id = configuration.provider_id
          AND secret.revision = configuration.client_secret_revision
          AND secret.retired_at IS NULL
      )
      AND EXISTS (
        SELECT 1 FROM public.tenant_oidc_discovery_snapshots AS discovery
        WHERE discovery.tenant_id = configuration.tenant_id
          AND discovery.provider_id = configuration.provider_id
          AND discovery.revision = configuration.discovery_revision
          AND discovery.document_digest = app.private_mfa_decode_base64_v1(
            v_pins ->> 'discoveryDigest', 32, 32
          )
      )
      AND EXISTS (
        SELECT 1 FROM public.tenant_oidc_jwks_snapshots AS jwks
        WHERE jwks.tenant_id = configuration.tenant_id
          AND jwks.provider_id = configuration.provider_id
          AND jwks.revision = configuration.jwks_revision
          AND jwks.document_digest = app.private_mfa_decode_base64_v1(
            v_pins ->> 'jwksDigest', 32, 32
          )
      )
    FOR SHARE;
  ELSE
    SELECT configuration.version INTO v_configuration_version
    FROM public.tenant_saml_provider_configurations AS configuration
    WHERE configuration.tenant_id = v_tenant_id
      AND configuration.provider_id = v_provider_id
      AND configuration.provider_kind = 'saml'
      AND configuration.metadata_revision = (v_pins ->> 'metadataRevision')::bigint
      AND configuration.sp_key_revision = (v_pins ->> 'spKeyRevision')::bigint
      AND EXISTS (
        SELECT 1 FROM public.tenant_saml_metadata_snapshots AS metadata
        WHERE metadata.tenant_id = configuration.tenant_id
          AND metadata.provider_id = configuration.provider_id
          AND metadata.revision = configuration.metadata_revision
          AND metadata.document_digest = app.private_mfa_decode_base64_v1(
            v_pins ->> 'metadataDigest', 32, 32
          )
          AND metadata.maximum_valid_until > v_applied_at
      )
      AND EXISTS (
        SELECT 1 FROM public.tenant_saml_sp_keys AS sp_key
        WHERE sp_key.tenant_id = configuration.tenant_id
          AND sp_key.provider_id = configuration.provider_id
          AND sp_key.revision = configuration.sp_key_revision
          AND sp_key.retired_at IS NULL
      )
    FOR SHARE;
  END IF;
  IF NOT FOUND OR v_configuration_version IS DISTINCT FROM v_configuration_revision
     OR v_live.live_provider_revision IS DISTINCT FROM v_provider_revision
     OR v_live.live_binding_revision IS DISTINCT FROM v_binding_revision
     OR v_live.live_mapping_revision IS DISTINCT FROM v_mapping_revision
     OR v_live.live_authorization_revision IS DISTINCT FROM v_authorization_revision
     OR v_live.live_policy_configuration_revision IS DISTINCT FROM v_configuration_revision
     OR v_live.live_security_revision IS DISTINCT FROM v_security_revision
     OR v_live.live_plan_revision IS DISTINCT FROM v_plan_revision
     OR v_live.live_policy_revision IS DISTINCT FROM v_policy_revision
     OR v_live.provider_revision IS DISTINCT FROM v_provider_revision
     OR v_live.binding_revision IS DISTINCT FROM v_binding_revision
     OR v_live.configuration_revision IS DISTINCT FROM v_configuration_revision
     OR v_live.security_revision IS DISTINCT FROM v_security_revision
     OR v_live.mapping_revision IS DISTINCT FROM v_mapping_revision
     OR v_live.authorization_revision IS DISTINCT FROM v_authorization_revision
     OR v_live.assurance_policy_revision IS DISTINCT FROM v_policy_revision
     OR (v_protocol = 'oidc' AND (
       v_live.client_secret_revision IS DISTINCT FROM
         (v_pins ->> 'clientSecretRevision')::bigint
       OR v_live.discovery_revision IS DISTINCT FROM
         (v_pins ->> 'discoveryRevision')::bigint
       OR v_live.discovery_digest IS DISTINCT FROM app.private_mfa_decode_base64_v1(
         v_pins ->> 'discoveryDigest', 32, 32
       )
       OR v_live.jwks_revision IS DISTINCT FROM
         (v_pins ->> 'jwksRevision')::bigint
       OR v_live.jwks_digest IS DISTINCT FROM app.private_mfa_decode_base64_v1(
         v_pins ->> 'jwksDigest', 32, 32
       )))
     OR (v_protocol = 'saml' AND (
       v_live.metadata_revision IS DISTINCT FROM
         (v_pins ->> 'metadataRevision')::bigint
       OR v_live.metadata_digest IS DISTINCT FROM app.private_mfa_decode_base64_v1(
         v_pins ->> 'metadataDigest', 32, 32
       )
       OR v_live.sp_key_revision IS DISTINCT FROM
         (v_pins ->> 'spKeyRevision')::bigint
       OR v_live.configuration_digest IS DISTINCT FROM app.private_mfa_decode_base64_v1(
         v_pins ->> 'configurationDigest', 32, 32
       )))
     OR v_live.return_path IS DISTINCT FROM v_return_path THEN
    RETURN app.private_federated_apply_response_v1(
      v_operation_digest, v_protocol, v_tenant_id, v_disposition, 'stale'
    );
  END IF;

  SELECT application.*,
         coalesce(provenance.external_identity_id,
           continuation.external_identity_id) AS replay_external_identity_id
    INTO v_existing
  FROM public.tenant_federated_authentication_applications AS application
  LEFT JOIN public.auth_session_federated_provenance AS provenance
    ON provenance.tenant_id = application.tenant_id
   AND provenance.session_id = application.session_id
   AND provenance.user_id = application.user_id
  LEFT JOIN public.tenant_post_primary_continuations AS continuation
    ON continuation.tenant_id = application.tenant_id
   AND continuation.id = application.continuation_id
   AND continuation.user_id = application.user_id
  WHERE application.tenant_id = v_tenant_id
    AND application.protocol = v_protocol
    AND application.transaction_id = v_transaction_id
  FOR UPDATE OF application;
  IF FOUND THEN
    IF v_existing.operation_digest IS DISTINCT FROM v_operation_digest
       OR v_existing.request_snapshot IS DISTINCT FROM v_apply THEN
      RETURN app.private_federated_apply_response_v1(
        v_operation_digest, v_protocol, v_tenant_id, v_disposition, 'replay'
      );
    END IF;
    IF v_existing.category = 'success' AND NOT app.private_federated_replay_live_v1(
      v_tenant_id, v_provider_id, v_binding_id, v_provider_kind,
      v_existing.replay_external_identity_id, v_existing.user_id,
      v_existing.session_id, v_existing.continuation_id, v_applied_at
    ) THEN
      RETURN app.private_federated_apply_response_v1(
        v_operation_digest, v_protocol, v_tenant_id, v_disposition, 'denied'
      );
    END IF;
    IF v_existing.category = 'success' THEN
      RETURN jsonb_set(v_existing.result_snapshot, '{replayed}', 'true'::jsonb, true);
    END IF;
    RETURN v_existing.result_snapshot;
  END IF;
  IF EXISTS (
    SELECT 1 FROM public.tenant_federated_authentication_applications AS application
    WHERE application.tenant_id = v_tenant_id
      AND (application.operation_digest = v_operation_digest
        OR (v_protocol = 'saml' AND (
          application.response_id_digest = v_response_id_digest
          OR application.assertion_id_digest = v_assertion_id_digest
          OR (v_session_index_digest IS NOT NULL
            AND application.session_index_digest = v_session_index_digest))))
  ) THEN
    RETURN app.private_federated_apply_response_v1(
      v_operation_digest, v_protocol, v_tenant_id, v_disposition, 'replay'
    );
  END IF;

  IF v_live.version IS DISTINCT FROM v_expected_version
     OR v_live.expires_at <= v_applied_at
     OR v_live.expires_at <= transaction_timestamp()
     OR (v_protocol = 'oidc' AND v_live.state <> 'claimed')
     OR (v_protocol = 'saml' AND v_live.state <> 'pending') THEN
    RETURN app.private_federated_apply_response_v1(
      v_operation_digest, v_protocol, v_tenant_id, v_disposition, 'stale'
    );
  END IF;

  v_requirement := app.private_federated_assurance_requirement_v1(
    v_tenant_id, v_plan_user_id, v_binding_id, v_mapping_revision,
    'session.create', v_applied_at
  );
  IF v_requirement ->> 'level' IS DISTINCT FROM v_plan -> 'requirement' ->> 'level'
     OR (v_requirement ->> 'localRequired')::boolean IS DISTINCT FROM
       (v_plan -> 'requirement' ->> 'localRequired')::boolean
     OR (v_requirement ->> 'freshnessNanoseconds')::bigint IS DISTINCT FROM
       (v_plan -> 'requirement' ->> 'freshnessNanoseconds')::bigint
     OR nullif(v_requirement ->> 'enrollmentDeadline', '')::timestamptz
       IS DISTINCT FROM nullif(
         v_plan -> 'requirement' ->> 'enrollmentDeadline', ''
       )::timestamptz
     OR v_requirement -> 'policyRevisions'
       IS DISTINCT FROM v_plan -> 'requirement' -> 'policyRevisions' THEN
    RETURN app.private_federated_apply_response_v1(
      v_operation_digest, v_protocol, v_tenant_id, v_disposition, 'stale'
    );
  END IF;
  v_decision := app.private_federated_assurance_decision_v1(
    v_requirement, v_auth -> 'evidence',
    (v_plan ->> 'hasEnrollableFactor')::boolean, v_applied_at
  );
  IF v_decision IS DISTINCT FROM v_assurance THEN
    RETURN app.private_federated_apply_response_v1(
      v_operation_digest, v_protocol, v_tenant_id, v_disposition, 'denied'
    );
  END IF;

  SELECT * INTO STRICT v_identity
  FROM app.private_federated_apply_identity_v1(
    v_apply, v_tenant_id, v_provider_id, v_binding_id, v_provider_kind,
    v_mapping_revision, v_configuration_revision, v_applied_at
  );
  IF (v_plan_user_id IS NOT NULL
       AND v_identity.out_identity_epoch IS DISTINCT FROM v_identity_epoch)
     OR (v_plan_user_id IS NULL
       AND v_identity.out_identity_epoch IS DISTINCT FROM 1) THEN
    RAISE EXCEPTION 'federated identity epoch drifted'
      USING ERRCODE = '40001';
  END IF;
  v_authority := app.private_federated_issue_authority_v1(
    v_apply, v_tenant_id, v_identity.out_user_id,
    v_identity.out_external_identity_id,
    v_identity.out_external_identity_revision,
    v_identity.out_identity_epoch,
    v_identity.out_session_invalidation_epoch,
    v_provider_id, v_binding_id, v_provider_kind,
    v_security_revision, v_applied_at, v_session_index_digest
  );
  v_session_id := nullif(v_authority ->> 'sessionId', '')::uuid;
  v_continuation_id := nullif(v_authority ->> 'continuationId', '')::uuid;
  v_result := app.private_federated_apply_response_v1(
    v_operation_digest, v_protocol, v_tenant_id, v_disposition, 'success',
    v_identity.out_user_id, v_session_id, v_continuation_id,
    v_return_path, false
  );

  UPDATE public.tenant_federated_authentication_transactions AS transaction_row
  SET state = 'completed', version = transaction_row.version + 1,
      completed_at = v_applied_at, failure_reason = NULL
  WHERE transaction_row.tenant_id = v_tenant_id
    AND transaction_row.transaction_id = v_transaction_id
    AND transaction_row.protocol = v_protocol
    AND transaction_row.version = v_expected_version
    AND ((v_protocol = 'oidc' AND transaction_row.state = 'claimed')
      OR (v_protocol = 'saml' AND transaction_row.state = 'pending'));
  IF NOT FOUND THEN
    RAISE EXCEPTION 'federated transaction completion lost CAS'
      USING ERRCODE = '40001';
  END IF;

  INSERT INTO public.tenant_federated_authentication_applications (
    tenant_id, protocol, transaction_id, operation_digest,
    provider_id, binding_id, provider_kind,
    response_id_digest, assertion_id_digest, session_index_digest,
    category, primary_kind, user_id, session_id, continuation_id,
    request_snapshot, result_snapshot, applied_at
  ) VALUES (
    v_tenant_id, v_protocol, v_transaction_id, v_operation_digest,
    v_provider_id, v_binding_id, v_provider_kind,
    v_response_id_digest, v_assertion_id_digest, v_session_index_digest,
    'success', 'tenant_provider', v_identity.out_user_id,
    v_session_id, v_continuation_id, v_apply, v_result, v_applied_at
  );

  v_resource_id := coalesce(v_session_id, v_continuation_id);
  INSERT INTO public.audit_events (
    id, tenant_id, sequence, occurred_at, actor_type, actor_user_id,
    action, resource_type, resource_id, authentication_method,
    outcome, metadata
  ) VALUES (
    uuidv7(), v_tenant_id, 0, v_applied_at, 'user',
    v_identity.out_user_id, 'tenant.identity.federated_login_completed',
    CASE WHEN v_session_id IS NOT NULL THEN 'auth_session'
      ELSE 'post_primary_continuation' END,
    v_resource_id, v_protocol, 'success', jsonb_build_object(
      'protocol', v_protocol,
      'provider_id', v_provider_id::text,
      'binding_id', v_binding_id::text,
      'disposition', v_disposition,
      'policy_revision_count', jsonb_array_length(
        v_requirement -> 'policyRevisions'
      ),
      'secret_material_included', false
    )
  );
  RETURN v_result;
EXCEPTION
  WHEN unique_violation THEN
    IF v_operation_digest IS NULL OR v_protocol NOT IN ('oidc','saml')
       OR v_tenant_id IS NULL OR v_disposition NOT IN ('session','continuation') THEN
      RAISE;
    END IF;
    RETURN app.private_federated_apply_response_v1(
      v_operation_digest, v_protocol, v_tenant_id, v_disposition,
      'identity_collision'
    );
  WHEN serialization_failure THEN
    IF v_operation_digest IS NULL OR v_protocol NOT IN ('oidc','saml')
       OR v_tenant_id IS NULL OR v_disposition NOT IN ('session','continuation') THEN
      RAISE;
    END IF;
    RETURN app.private_federated_apply_response_v1(
      v_operation_digest, v_protocol, v_tenant_id, v_disposition, 'stale'
    );
  WHEN insufficient_privilege THEN
    IF v_operation_digest IS NULL OR v_protocol NOT IN ('oidc','saml')
       OR v_tenant_id IS NULL OR v_disposition NOT IN ('session','continuation') THEN
      RAISE;
    END IF;
    RETURN app.private_federated_apply_response_v1(
      v_operation_digest, v_protocol, v_tenant_id, v_disposition, 'denied'
    );
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_federated_assurance_decision_v1(
  p_requirement jsonb,
  p_evidence jsonb,
  p_has_enrollable_factor boolean,
  p_evaluated_at timestamptz
)
RETURNS text
LANGUAGE plpgsql
IMMUTABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_required_rank integer;
  v_freshness_nanoseconds bigint;
  v_enrollment_deadline timestamptz;
  v_proof jsonb;
  v_proof_rank integer;
  v_authenticated_at timestamptz;
  v_expires_at timestamptz;
  v_factor_revision bigint;
  v_trust_revision bigint;
  v_satisfied boolean := false;
BEGIN
  IF p_evaluated_at IS NULL OR p_has_enrollable_factor IS NULL
     OR jsonb_typeof(p_requirement) <> 'object'
     OR jsonb_typeof(p_evidence) <> 'array'
     OR jsonb_array_length(p_evidence) > 1024 THEN
    RETURN 'denied';
  END IF;
  PERFORM app.private_mfa_assert_json_object_v1(
    p_requirement,
    ARRAY['level','localRequired','freshnessNanoseconds',
      'enrollmentDeadline','policyRevisions'],
    ARRAY['level','localRequired','freshnessNanoseconds',
      'enrollmentDeadline','policyRevisions'],
    262144
  );
  v_required_rank := CASE p_requirement ->> 'level'
    WHEN 'primary' THEN 1 WHEN 'mfa' THEN 2
    WHEN 'phishing_resistant' THEN 3 END;
  BEGIN
    v_freshness_nanoseconds := (p_requirement ->> 'freshnessNanoseconds')::bigint;
    v_enrollment_deadline := nullif(
      p_requirement ->> 'enrollmentDeadline', ''
    )::timestamptz;
  EXCEPTION WHEN OTHERS THEN
    RETURN 'denied';
  END;
  IF v_required_rank IS NULL
     OR v_freshness_nanoseconds NOT BETWEEN 0 AND 31536000000000000
     OR jsonb_typeof(p_requirement -> 'localRequired') <> 'boolean'
     OR jsonb_typeof(p_requirement -> 'policyRevisions') <> 'array'
     OR jsonb_array_length(p_requirement -> 'policyRevisions') NOT BETWEEN 1 AND 1024 THEN
    RETURN 'denied';
  END IF;

  FOR v_proof IN SELECT value FROM jsonb_array_elements(p_evidence)
  LOOP
    BEGIN
      PERFORM app.private_mfa_assert_json_object_v1(
        v_proof,
        ARRAY['level','kind','local','providerId','bindingId','authenticatedAt',
          'expiresAt','factorRevision','trustRuleRevision'],
        ARRAY['level','kind','local','authenticatedAt','expiresAt',
          'factorRevision','trustRuleRevision'],
        8192
      );
      v_proof_rank := CASE v_proof ->> 'level'
        WHEN 'primary' THEN 1 WHEN 'mfa' THEN 2
        WHEN 'phishing_resistant' THEN 3 END;
      v_authenticated_at := (v_proof ->> 'authenticatedAt')::timestamptz;
      v_expires_at := nullif(v_proof ->> 'expiresAt', '')::timestamptz;
      v_factor_revision := nullif(v_proof ->> 'factorRevision', '')::bigint;
      v_trust_revision := nullif(v_proof ->> 'trustRuleRevision', '')::bigint;
    EXCEPTION WHEN OTHERS THEN
      RETURN 'denied';
    END;
    IF v_proof_rank IS NULL OR v_proof ->> 'kind' NOT IN ('factor','recovery')
       OR jsonb_typeof(v_proof -> 'local') <> 'boolean'
       OR v_authenticated_at IS NULL
       OR (v_expires_at IS NOT NULL AND v_expires_at <= v_authenticated_at)
       OR ((v_proof ->> 'local')::boolean
         AND (nullif(v_proof ->> 'providerId', '') IS NOT NULL
           OR nullif(v_proof ->> 'bindingId', '') IS NOT NULL
           OR v_factor_revision < 1 OR v_trust_revision IS NOT NULL))
       OR (NOT (v_proof ->> 'local')::boolean
         AND (nullif(v_proof ->> 'providerId', '') IS NULL
           OR nullif(v_proof ->> 'bindingId', '') IS NULL
           OR v_trust_revision < 1 OR v_factor_revision IS NOT NULL)) THEN
      RETURN 'denied';
    END IF;
    IF v_authenticated_at <= p_evaluated_at
       AND (v_expires_at IS NULL OR v_expires_at > p_evaluated_at)
       AND (v_freshness_nanoseconds = 0
         OR p_evaluated_at - v_authenticated_at
           <= v_freshness_nanoseconds * interval '1 microsecond' / 1000)
       AND (NOT (p_requirement ->> 'localRequired')::boolean
         OR (v_proof ->> 'local')::boolean)
       AND v_proof ->> 'kind' <> 'recovery'
       AND v_proof_rank >= v_required_rank THEN
      v_satisfied := true;
    END IF;
  END LOOP;
  IF v_satisfied THEN
    RETURN 'satisfied';
  END IF;
  IF p_has_enrollable_factor THEN
    IF v_enrollment_deadline IS NULL THEN
      RETURN 'step_up_required';
    END IF;
    IF p_evaluated_at < v_enrollment_deadline THEN
      RETURN 'enrollment_only';
    END IF;
    RETURN 'enrollment_expired';
  END IF;
  RETURN 'step_up_required';
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_federated_apply_response_v1(
  p_operation_digest bytea,
  p_protocol text,
  p_tenant_id uuid,
  p_disposition text,
  p_category text,
  p_user_id uuid DEFAULT NULL,
  p_session_id uuid DEFAULT NULL,
  p_continuation_id uuid DEFAULT NULL,
  p_return_path text DEFAULT NULL,
  p_replayed boolean DEFAULT false
)
RETURNS jsonb
LANGUAGE sql
IMMUTABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
  SELECT jsonb_strip_nulls(jsonb_build_object(
    'operationDigest', encode(p_operation_digest, 'base64'),
    'protocol', p_protocol,
    'tenantId', p_tenant_id::text,
    'disposition', p_disposition,
    'category', p_category,
    'userId', p_user_id::text,
    'sessionId', p_session_id::text,
    'continuationId', p_continuation_id::text,
    'returnPath', p_return_path,
    'replayed', p_replayed
  ));
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_federated_replay_live_v1(
  p_tenant_id uuid,
  p_provider_id uuid,
  p_binding_id uuid,
  p_provider_kind public.auth_provider_kind,
  p_external_identity_id uuid,
  p_user_id uuid,
  p_session_id uuid,
  p_continuation_id uuid,
  p_evaluated_at timestamptz
)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
  SELECT p_tenant_id IS NOT NULL AND p_provider_id IS NOT NULL
    AND p_binding_id IS NOT NULL AND p_provider_kind IS NOT NULL
    AND p_external_identity_id IS NOT NULL
    AND p_user_id IS NOT NULL AND p_evaluated_at IS NOT NULL
    AND EXISTS (
      SELECT 1
      FROM public.tenant_federated_external_identities AS identity
      JOIN public.tenants AS tenant
        ON tenant.id = identity.tenant_id
       AND tenant.status = 'active'
      JOIN public.tenant_auth_providers AS provider
        ON provider.tenant_id = identity.tenant_id
       AND provider.id = identity.provider_id
       AND provider.kind = p_provider_kind
       AND provider.enabled
       AND provider.archived_at IS NULL
      JOIN public.tenant_auth_provider_bindings AS binding
        ON binding.tenant_id = identity.tenant_id
       AND binding.id = identity.binding_id
       AND binding.provider_id = identity.provider_id
       AND binding.enabled
       AND binding.archived_at IS NULL
       AND binding.current_access_epoch_id IS NOT NULL
      JOIN public.tenant_federated_provider_policies AS policy
        ON policy.tenant_id = identity.tenant_id
       AND policy.provider_id = identity.provider_id
       AND policy.binding_id = identity.binding_id
       AND policy.provider_kind = p_provider_kind
       AND policy.enabled
      JOIN public.users AS local_user
        ON local_user.id = identity.user_id AND local_user.active
      JOIN public.tenant_memberships AS membership
        ON membership.tenant_id = identity.tenant_id
       AND membership.user_id = identity.user_id
       AND membership.status = 'active'
      JOIN public.tenant_federated_provider_access_grants AS grant_row
        ON grant_row.tenant_id = identity.tenant_id
       AND grant_row.provider_id = identity.provider_id
       AND grant_row.binding_id = identity.binding_id
       AND grant_row.external_identity_id = identity.id
       AND grant_row.membership_id = membership.id
       AND grant_row.user_id = identity.user_id
       AND grant_row.access_epoch_id = binding.current_access_epoch_id
       AND grant_row.started_at <= p_evaluated_at
       AND grant_row.ended_at IS NULL
      JOIN public.tenant_identity_provider_access_epochs AS access_epoch
        ON access_epoch.tenant_id = grant_row.tenant_id
       AND access_epoch.id = grant_row.access_epoch_id
       AND access_epoch.binding_id = grant_row.binding_id
       AND access_epoch.provider_id = grant_row.provider_id
       AND access_epoch.source_id = grant_row.source_id
       AND access_epoch.started_at <= p_evaluated_at
       AND access_epoch.ended_at IS NULL
      JOIN public.tenant_authorization_sources AS access_source
        ON access_source.tenant_id = grant_row.tenant_id
       AND access_source.id = grant_row.source_id
       AND access_source.retired_at IS NULL
      WHERE identity.tenant_id = p_tenant_id
        AND identity.provider_id = p_provider_id
        AND identity.binding_id = p_binding_id
        AND identity.id = p_external_identity_id
        AND identity.user_id = p_user_id
        AND identity.retired_at IS NULL
    )
    AND (
      (p_session_id IS NOT NULL AND p_continuation_id IS NULL AND EXISTS (
        SELECT 1
        FROM public.auth_sessions AS session
        JOIN public.auth_session_mfa_states AS state
          ON state.session_id = session.id
         AND state.tenant_id = p_tenant_id
         AND state.user_id = p_user_id
         AND state.primary_kind = 'tenant_provider'
        JOIN public.auth_session_federated_provenance AS provenance
          ON provenance.tenant_id = state.tenant_id
         AND provenance.session_id = state.session_id
         AND provenance.user_id = state.user_id
         AND provenance.provider_id = p_provider_id
         AND provenance.binding_id = p_binding_id
         AND provenance.provider_kind = p_provider_kind
         AND provenance.external_identity_id = p_external_identity_id
        WHERE session.id = p_session_id
          AND session.user_id = p_user_id
          AND session.active_tenant_id = p_tenant_id
          AND session.revoked_at IS NULL
          AND session.idle_expires_at > p_evaluated_at
          AND session.absolute_expires_at > p_evaluated_at
      ))
      OR (p_session_id IS NULL AND p_continuation_id IS NOT NULL AND EXISTS (
        SELECT 1
        FROM public.tenant_post_primary_continuations AS continuation
        WHERE continuation.id = p_continuation_id
          AND continuation.tenant_id = p_tenant_id
          AND continuation.user_id = p_user_id
          AND continuation.primary_kind = 'tenant_provider'
          AND continuation.provider_id = p_provider_id
          AND continuation.binding_id = p_binding_id
          AND continuation.provider_kind = p_provider_kind
          AND continuation.external_identity_id = p_external_identity_id
          AND continuation.state = 'pending'
          AND continuation.expires_at > p_evaluated_at
      ))
    );
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_federated_issue_authority_v1(
  p_apply jsonb,
  p_tenant_id uuid,
  p_user_id uuid,
  p_external_identity_id uuid,
  p_external_identity_revision bigint,
  p_identity_epoch bigint,
  p_session_invalidation_epoch bigint,
  p_provider_id uuid,
  p_binding_id uuid,
  p_provider_kind public.auth_provider_kind,
  p_security_revision bigint,
  p_applied_at timestamptz,
  p_session_index_digest bytea
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_auth jsonb := p_apply -> 'authentication';
  v_plan jsonb := p_apply -> 'plan';
  v_requirement jsonb := p_apply -> 'plan' -> 'requirement';
  v_disposition text := p_apply ->> 'disposition';
  v_reservation jsonb;
  v_session_id uuid;
  v_family_id uuid;
  v_continuation_id uuid;
  v_token_digest bytea;
  v_csrf_digest bytea;
  v_receipt_digest bytea;
  v_idle_expires_at timestamptz;
  v_absolute_expires_at timestamptz;
  v_continuation_expires_at timestamptz;
  v_policy jsonb;
  v_evidence jsonb;
  v_level text;
  v_trust_revision bigint;
  v_authenticated_at timestamptz;
  v_expires_at timestamptz;
  v_saml_material jsonb := p_apply -> 'samlSession';
  v_material_key_version integer;
  v_material_ciphertext bytea;
BEGIN
  IF p_external_identity_revision < 1 OR p_identity_epoch < 1
     OR p_session_invalidation_epoch < 1 OR p_security_revision < 1
     OR p_provider_kind NOT IN ('oidc','saml')
     OR v_auth ->> 'method' <> p_provider_kind::text
     OR jsonb_typeof(v_auth -> 'evidence') <> 'array'
     OR jsonb_array_length(v_auth -> 'evidence') NOT BETWEEN 1 AND 64
     OR jsonb_typeof(v_requirement) <> 'object'
     OR jsonb_typeof(v_requirement -> 'policyRevisions') <> 'array'
     OR jsonb_array_length(v_requirement -> 'policyRevisions') NOT BETWEEN 1 AND 1024 THEN
    RAISE EXCEPTION 'federated authority snapshot is invalid'
      USING ERRCODE = '22023';
  END IF;

  IF v_disposition = 'session' THEN
    IF p_apply ? 'continuation' OR NOT (p_apply ? 'session')
       OR p_apply -> 'session' = 'null'::jsonb THEN
      RAISE EXCEPTION 'federated session reservation is invalid'
        USING ERRCODE = '22023';
    END IF;
    v_reservation := p_apply -> 'session';
    PERFORM app.private_mfa_assert_json_object_v1(
      v_reservation,
      ARRAY['sessionId','familyId','tokenDigest','csrfDigest',
        'authenticationMethod','idleExpiresAt','absoluteExpiresAt'],
      ARRAY['sessionId','familyId','tokenDigest','csrfDigest',
        'authenticationMethod','idleExpiresAt','absoluteExpiresAt'],
      16384
    );
    v_session_id := app.private_mfa_require_uuidv7_v1(
      v_reservation ->> 'sessionId'
    );
    v_family_id := app.private_mfa_require_uuidv7_v1(
      v_reservation ->> 'familyId'
    );
    v_token_digest := app.private_mfa_decode_base64_v1(
      v_reservation ->> 'tokenDigest', 32, 32
    );
    v_csrf_digest := app.private_mfa_decode_base64_v1(
      v_reservation ->> 'csrfDigest', 32, 32
    );
    BEGIN
      v_idle_expires_at := (v_reservation ->> 'idleExpiresAt')::timestamptz;
      v_absolute_expires_at := (v_reservation ->> 'absoluteExpiresAt')::timestamptz;
    EXCEPTION WHEN OTHERS THEN
      RAISE EXCEPTION 'federated session expiry is invalid'
        USING ERRCODE = '22023';
    END;
    IF v_session_id = v_family_id
       OR v_reservation ->> 'authenticationMethod' <> p_provider_kind::text
       OR encode(v_token_digest, 'hex') = repeat('00', 32)
       OR encode(v_csrf_digest, 'hex') = repeat('00', 32)
       OR v_token_digest = v_csrf_digest
       OR v_idle_expires_at <= p_applied_at
       OR v_absolute_expires_at <= p_applied_at
       OR v_idle_expires_at > v_absolute_expires_at
       OR v_idle_expires_at > p_applied_at + interval '24 hours'
       OR v_absolute_expires_at > p_applied_at + interval '31 days'
       OR date_trunc('milliseconds', v_idle_expires_at) <> v_idle_expires_at
       OR date_trunc('milliseconds', v_absolute_expires_at) <> v_absolute_expires_at THEN
      RAISE EXCEPTION 'federated session reservation is invalid'
        USING ERRCODE = '22023';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended(
      least(encode(v_token_digest, 'hex'), encode(v_csrf_digest, 'hex')),
      73124201
    ));
    PERFORM pg_advisory_xact_lock(hashtextextended(
      greatest(encode(v_token_digest, 'hex'), encode(v_csrf_digest, 'hex')),
      73124201
    ));
    IF EXISTS (
      SELECT 1 FROM public.auth_sessions AS session
      WHERE session.token_digest IN (v_token_digest, v_csrf_digest)
         OR session.csrf_secret_digest IN (v_token_digest, v_csrf_digest)
    ) THEN
      RAISE EXCEPTION 'federated session digest collision'
        USING ERRCODE = '40001';
    END IF;
    INSERT INTO public.auth_sessions (
      id, user_id, rotation_family_id, active_tenant_id,
      token_digest, csrf_secret_digest, authentication_method,
      mfa_satisfied_at, last_seen_at, idle_expires_at,
      absolute_expires_at, created_at
    ) VALUES (
      v_session_id, p_user_id, v_family_id, p_tenant_id,
      v_token_digest, v_csrf_digest, p_provider_kind::text,
      p_applied_at, p_applied_at, v_idle_expires_at,
      v_absolute_expires_at, p_applied_at
    );
    INSERT INTO public.auth_session_mfa_states (
      session_id, tenant_id, user_id, session_version, identity_epoch,
      recovery_restricted, audience, primary_kind,
      session_invalidation_epoch, issued_at
    ) VALUES (
      v_session_id, p_tenant_id, p_user_id, 1, p_identity_epoch,
      false, 'api', 'tenant_provider', p_session_invalidation_epoch,
      p_applied_at
    );
    INSERT INTO public.auth_session_federated_provenance (
      tenant_id, session_id, user_id, primary_kind,
      authentication_method, provider_id, binding_id, provider_kind,
      external_identity_id, external_identity_revision,
      trust_rule_revision, authenticated_at
    ) VALUES (
      p_tenant_id, v_session_id, p_user_id, 'tenant_provider',
      p_provider_kind::text, p_provider_id, p_binding_id, p_provider_kind,
      p_external_identity_id, p_external_identity_revision,
      p_security_revision, (v_auth ->> 'authenticatedAt')::timestamptz
    );
  ELSIF v_disposition = 'continuation' THEN
    IF p_apply ? 'session' OR NOT (p_apply ? 'continuation')
       OR p_apply -> 'continuation' = 'null'::jsonb THEN
      RAISE EXCEPTION 'federated continuation reservation is invalid'
        USING ERRCODE = '22023';
    END IF;
    v_reservation := p_apply -> 'continuation';
    PERFORM app.private_mfa_assert_json_object_v1(
      v_reservation,
      ARRAY['continuationId','receiptDigest','expiresAt'],
      ARRAY['continuationId','receiptDigest','expiresAt'],
      8192
    );
    v_continuation_id := app.private_mfa_require_uuidv7_v1(
      v_reservation ->> 'continuationId'
    );
    v_receipt_digest := app.private_mfa_decode_base64_v1(
      v_reservation ->> 'receiptDigest', 32, 32
    );
    BEGIN
      v_continuation_expires_at := (v_reservation ->> 'expiresAt')::timestamptz;
    EXCEPTION WHEN OTHERS THEN
      RAISE EXCEPTION 'federated continuation expiry is invalid'
        USING ERRCODE = '22023';
    END;
    IF encode(v_receipt_digest, 'hex') = repeat('00', 32)
       OR v_continuation_expires_at <= p_applied_at
       OR v_continuation_expires_at > p_applied_at + interval '15 minutes'
       OR date_trunc('microseconds', v_continuation_expires_at)
          <> v_continuation_expires_at THEN
      RAISE EXCEPTION 'federated continuation reservation is invalid'
        USING ERRCODE = '22023';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended(
      encode(v_receipt_digest, 'hex'), 77191203
    ));
    INSERT INTO public.tenant_post_primary_continuations (
      id, tenant_id, user_id, receipt_digest, identity_epoch,
      action, audience, primary_kind, provider_id, binding_id,
      provider_kind, external_identity_id, primary_revision,
      session_invalidation_epoch, state, version,
      created_at, expires_at
    ) VALUES (
      v_continuation_id, p_tenant_id, p_user_id, v_receipt_digest,
      p_identity_epoch, 'session.create', 'api', 'tenant_provider',
      p_provider_id, p_binding_id, p_provider_kind,
      p_external_identity_id, p_external_identity_revision,
      p_session_invalidation_epoch, 'pending', 1,
      p_applied_at, v_continuation_expires_at
    );
  ELSE
    RAISE EXCEPTION 'federated authority disposition is invalid'
      USING ERRCODE = '22023';
  END IF;

  FOR v_policy IN
    SELECT value FROM jsonb_array_elements(v_requirement -> 'policyRevisions')
  LOOP
    PERFORM app.private_mfa_assert_json_object_v1(
      v_policy, ARRAY['policyId','revision'], ARRAY['policyId','revision'], 1024
    );
    IF v_disposition = 'session' THEN
      INSERT INTO public.auth_session_mfa_policy_pins (
        tenant_id, session_id, policy_id, policy_revision
      ) VALUES (
        p_tenant_id, v_session_id,
        (v_policy ->> 'policyId')::uuid,
        (v_policy ->> 'revision')::bigint
      );
    ELSE
      INSERT INTO public.tenant_post_primary_continuation_policy_pins (
        tenant_id, continuation_id, policy_id, policy_revision
      ) VALUES (
        p_tenant_id, v_continuation_id,
        (v_policy ->> 'policyId')::uuid,
        (v_policy ->> 'revision')::bigint
      );
    END IF;
  END LOOP;

  FOR v_evidence IN SELECT value FROM jsonb_array_elements(v_auth -> 'evidence')
  LOOP
    PERFORM app.private_mfa_assert_json_object_v1(
      v_evidence,
      ARRAY['level','kind','local','providerId','bindingId','authenticatedAt',
        'expiresAt','factorRevision','trustRuleRevision'],
      ARRAY['level','kind','local','authenticatedAt'],
      8192
    );
    BEGIN
      v_level := v_evidence ->> 'level';
      v_authenticated_at := (v_evidence ->> 'authenticatedAt')::timestamptz;
      v_expires_at := nullif(v_evidence ->> 'expiresAt', '')::timestamptz;
      v_trust_revision := nullif(v_evidence ->> 'trustRuleRevision', '')::bigint;
    EXCEPTION WHEN OTHERS THEN
      RAISE EXCEPTION 'federated assurance evidence is invalid'
        USING ERRCODE = '22023';
    END;
    IF v_level NOT IN ('primary','mfa','phishing_resistant')
       OR v_evidence ->> 'kind' <> 'factor'
       OR (v_evidence ->> 'local')::boolean
       OR (v_evidence ->> 'providerId')::uuid IS DISTINCT FROM p_provider_id
       OR (v_evidence ->> 'bindingId')::uuid IS DISTINCT FROM p_binding_id
       OR v_evidence ? 'factorRevision'
          AND v_evidence -> 'factorRevision' <> 'null'::jsonb
       OR v_trust_revision < 1
       OR v_authenticated_at > p_applied_at
       OR (v_expires_at IS NOT NULL AND v_expires_at <= p_applied_at)
       OR NOT EXISTS (
         SELECT 1 FROM public.tenant_federated_trust_rules AS rule
         WHERE rule.tenant_id = p_tenant_id
           AND rule.provider_id = p_provider_id
           AND rule.binding_id = p_binding_id
           AND rule.provider_kind = p_provider_kind
           AND rule.revision = v_trust_revision
           AND rule.level = v_level
           AND rule.enabled AND rule.retired_at IS NULL
       ) THEN
      RAISE EXCEPTION 'federated assurance evidence is stale'
        USING ERRCODE = '40001';
    END IF;
    IF v_disposition = 'session' THEN
      INSERT INTO public.auth_session_mfa_evidence (
        id, tenant_id, session_id, level, kind,
        provider_id, binding_id, authenticated_at, expires_at,
        trust_rule_revision
      ) VALUES (
        uuidv7(), p_tenant_id, v_session_id, v_level, 'provider',
        p_provider_id, p_binding_id, v_authenticated_at, v_expires_at,
        v_trust_revision
      );
    ELSE
      INSERT INTO public.tenant_post_primary_continuation_evidence (
        id, tenant_id, continuation_id, level, kind,
        provider_id, binding_id, authenticated_at, expires_at,
        trust_rule_revision
      ) VALUES (
        uuidv7(), p_tenant_id, v_continuation_id, v_level, 'provider',
        p_provider_id, p_binding_id, v_authenticated_at, v_expires_at,
        v_trust_revision
      );
    END IF;
  END LOOP;

  IF v_saml_material IS NOT NULL AND v_saml_material <> 'null'::jsonb THEN
    IF p_provider_kind <> 'saml' THEN
      RAISE EXCEPTION 'SAML material is not valid for this provider'
        USING ERRCODE = '22023';
    END IF;
    PERFORM app.private_mfa_assert_json_object_v1(
      v_saml_material, ARRAY['keyVersion','ciphertext'],
      ARRAY['keyVersion','ciphertext'], 32768
    );
    v_material_key_version := (v_saml_material ->> 'keyVersion')::integer;
    v_material_ciphertext := app.private_mfa_decode_base64_v1(
      v_saml_material ->> 'ciphertext', 16, 16384
    );
    IF v_material_key_version NOT BETWEEN 1 AND 32767
       OR NOT EXISTS (
         SELECT 1 FROM public.identity_keyring_versions AS keyring
         WHERE keyring.key_version = v_material_key_version
           AND keyring.is_active AND keyring.retired_at IS NULL
       ) THEN
      RAISE EXCEPTION 'SAML session material key is unavailable'
        USING ERRCODE = '40001';
    END IF;
    INSERT INTO public.tenant_saml_session_materials (
      id, tenant_id, session_id, continuation_id, user_id,
      provider_id, binding_id, provider_kind, external_identity_id,
      session_index_digest, key_version, ciphertext, created_at
    ) VALUES (
      uuidv7(), p_tenant_id,
      CASE WHEN v_disposition = 'session' THEN v_session_id END,
      CASE WHEN v_disposition = 'continuation' THEN v_continuation_id END,
      p_user_id, p_provider_id, p_binding_id, 'saml', p_external_identity_id,
      p_session_index_digest, v_material_key_version,
      v_material_ciphertext, p_applied_at
    );
  END IF;

  RETURN jsonb_strip_nulls(jsonb_build_object(
    'sessionId', v_session_id::text,
    'continuationId', v_continuation_id::text
  ));
END;
$function$;
--> statement-breakpoint

-- Federated profile rows participate in the same field-by-field priority
-- projection as LDAP.  Manual values still win and no provider email becomes
-- an account-link key.
CREATE OR REPLACE FUNCTION app.private_materialize_tenant_user_profile_v1(
  p_tenant_id uuid,
  p_membership_id uuid
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_user_id uuid;
  v_display_name text;
  v_first_name text;
  v_last_name text;
  v_username text;
  v_email text;
BEGIN
  SELECT membership.user_id INTO STRICT v_user_id
  FROM public.tenant_memberships AS membership
  WHERE membership.tenant_id = p_tenant_id
    AND membership.id = p_membership_id
  FOR UPDATE;

  SELECT
    coalesce(manual.display_name, provider_profile.display_name, identity.display_name),
    coalesce(manual.first_name, provider_profile.first_name, identity.first_name),
    coalesce(manual.last_name, provider_profile.last_name, identity.last_name),
    coalesce(manual.username, provider_profile.username),
    coalesce(manual.email, provider_profile.email, identity.email)
  INTO v_display_name, v_first_name, v_last_name, v_username, v_email
  FROM public.users AS identity
  LEFT JOIN public.tenant_user_manual_profile_overrides AS manual
    ON manual.tenant_id = p_tenant_id
   AND manual.membership_id = p_membership_id
   AND manual.user_id = identity.id
  LEFT JOIN LATERAL (
    SELECT
      (array_agg(candidate.display_name
        ORDER BY candidate.profile_priority, candidate.binding_id)
        FILTER (WHERE candidate.display_name IS NOT NULL))[1] AS display_name,
      (array_agg(candidate.first_name
        ORDER BY candidate.profile_priority, candidate.binding_id)
        FILTER (WHERE candidate.first_name IS NOT NULL))[1] AS first_name,
      (array_agg(candidate.last_name
        ORDER BY candidate.profile_priority, candidate.binding_id)
        FILTER (WHERE candidate.last_name IS NOT NULL))[1] AS last_name,
      (array_agg(candidate.username
        ORDER BY candidate.profile_priority, candidate.binding_id)
        FILTER (WHERE candidate.username IS NOT NULL))[1] AS username,
      (array_agg(candidate.email
        ORDER BY candidate.profile_priority, candidate.binding_id)
        FILTER (WHERE candidate.email IS NOT NULL))[1] AS email
    FROM (
      SELECT binding.profile_priority, binding.id AS binding_id,
        contribution.display_name, contribution.first_name,
        contribution.last_name, contribution.username, contribution.email
      FROM public.tenant_ldap_provider_profile_contributions AS contribution
      JOIN public.tenant_ldap_provider_access_grants AS access_grant
        ON access_grant.tenant_id = contribution.tenant_id
       AND access_grant.id = contribution.access_grant_id
      JOIN public.tenant_auth_provider_bindings AS binding
        ON binding.tenant_id = access_grant.tenant_id
       AND binding.id = access_grant.binding_id
      JOIN public.tenant_auth_providers AS provider
        ON provider.tenant_id = binding.tenant_id
       AND provider.id = binding.provider_id
      JOIN public.tenant_authorization_sources AS source
        ON source.tenant_id = access_grant.tenant_id
       AND source.id = access_grant.source_id
      JOIN public.tenant_ldap_external_identities AS external_identity
        ON external_identity.tenant_id = access_grant.tenant_id
       AND external_identity.provider_id = access_grant.provider_id
       AND external_identity.id = access_grant.external_identity_id
       AND external_identity.retired_at IS NULL
      WHERE access_grant.tenant_id = p_tenant_id
        AND access_grant.membership_id = p_membership_id
        AND access_grant.ended_at IS NULL
        AND contribution.retired_at IS NULL
        AND binding.enabled AND binding.archived_at IS NULL
        AND provider.enabled AND provider.archived_at IS NULL
        AND source.kind = 'identity_provider_access'
        AND source.retired_at IS NULL
      UNION ALL
      SELECT binding.profile_priority, binding.id,
        contribution.display_name, NULL::text, NULL::text,
        contribution.username, contribution.email
      FROM public.tenant_federated_provider_profile_contributions AS contribution
      JOIN public.tenant_federated_provider_access_grants AS access_grant
        ON access_grant.tenant_id = contribution.tenant_id
       AND access_grant.id = contribution.access_grant_id
      JOIN public.tenant_auth_provider_bindings AS binding
        ON binding.tenant_id = access_grant.tenant_id
       AND binding.id = access_grant.binding_id
       AND binding.provider_id = access_grant.provider_id
      JOIN public.tenant_auth_providers AS provider
        ON provider.tenant_id = binding.tenant_id
       AND provider.id = binding.provider_id
       AND provider.kind IN ('oidc','saml')
      JOIN public.tenant_authorization_sources AS source
        ON source.tenant_id = access_grant.tenant_id
       AND source.id = access_grant.source_id
      JOIN public.tenant_federated_external_identities AS external_identity
        ON external_identity.tenant_id = access_grant.tenant_id
       AND external_identity.provider_id = access_grant.provider_id
       AND external_identity.id = access_grant.external_identity_id
       AND external_identity.retired_at IS NULL
      WHERE access_grant.tenant_id = p_tenant_id
        AND access_grant.membership_id = p_membership_id
        AND access_grant.ended_at IS NULL
        AND contribution.retired_at IS NULL
        AND binding.enabled AND binding.archived_at IS NULL
        AND provider.enabled AND provider.archived_at IS NULL
        AND source.kind = 'identity_provider_access'
        AND source.retired_at IS NULL
    ) AS candidate
  ) AS provider_profile ON true
  WHERE identity.id = v_user_id;

  INSERT INTO public.tenant_user_profiles (
    tenant_id, membership_id, user_id, display_name, first_name, last_name,
    username, email
  ) VALUES (
    p_tenant_id, p_membership_id, v_user_id, v_display_name,
    v_first_name, v_last_name, v_username, v_email
  )
  ON CONFLICT (tenant_id, membership_id) DO UPDATE
  SET display_name = EXCLUDED.display_name,
      first_name = EXCLUDED.first_name,
      last_name = EXCLUDED.last_name,
      username = EXCLUDED.username,
      email = EXCLUDED.email,
      version = tenant_user_profiles.version + 1,
      updated_at = transaction_timestamp();
EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
  RAISE EXCEPTION 'tenant profile subject is unavailable or ambiguous'
    USING ERRCODE = '40001';
END;
$function$;
--> statement-breakpoint

-- Closing a shared provider-access epoch must close both LDAP and federated
-- sources.  Leaving the federated source live would preserve authorization
-- after an administrator disabled the binding.
CREATE OR REPLACE FUNCTION app.private_close_tenant_identity_access_epoch_v1(
  p_tenant_id uuid,
  p_epoch_id uuid,
  p_actor_membership_id uuid,
  p_reason text
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_epoch public.tenant_identity_provider_access_epochs%ROWTYPE;
  v_membership_ids uuid[];
  v_membership_id uuid;
  v_closed_at timestamptz := transaction_timestamp();
BEGIN
  SELECT epoch.* INTO STRICT v_epoch
  FROM public.tenant_identity_provider_access_epochs AS epoch
  WHERE epoch.tenant_id = p_tenant_id AND epoch.id = p_epoch_id
    AND epoch.ended_at IS NULL
  FOR UPDATE;

  SELECT array_agg(DISTINCT membership_id ORDER BY membership_id)
    INTO v_membership_ids
  FROM (
    SELECT grant_row.membership_id
    FROM public.tenant_ldap_provider_access_grants AS grant_row
    WHERE grant_row.tenant_id = p_tenant_id
      AND grant_row.access_epoch_id = p_epoch_id
      AND grant_row.ended_at IS NULL
    UNION
    SELECT grant_row.membership_id
    FROM public.tenant_federated_provider_access_grants AS grant_row
    WHERE grant_row.tenant_id = p_tenant_id
      AND grant_row.access_epoch_id = p_epoch_id
      AND grant_row.ended_at IS NULL
  ) AS affected;

  UPDATE public.tenant_ldap_provider_profile_contributions AS contribution
  SET retired_at = v_closed_at, retire_reason = p_reason,
      version = contribution.version + 1,
      updated_at = v_closed_at
  FROM public.tenant_ldap_provider_access_grants AS grant_row
  WHERE contribution.tenant_id = p_tenant_id
    AND contribution.access_grant_id = grant_row.id
    AND contribution.retired_at IS NULL
    AND grant_row.tenant_id = contribution.tenant_id
    AND grant_row.access_epoch_id = p_epoch_id;
  UPDATE public.tenant_federated_provider_profile_contributions AS contribution
  SET retired_at = v_closed_at, version = contribution.version + 1
  FROM public.tenant_federated_provider_access_grants AS grant_row
  WHERE contribution.tenant_id = p_tenant_id
    AND contribution.access_grant_id = grant_row.id
    AND contribution.retired_at IS NULL
    AND grant_row.tenant_id = contribution.tenant_id
    AND grant_row.access_epoch_id = p_epoch_id;

  UPDATE public.tenant_ldap_provider_access_grants AS grant_row
  SET ended_at = v_closed_at, end_reason = p_reason,
      version = grant_row.version + 1, updated_at = v_closed_at
  WHERE grant_row.tenant_id = p_tenant_id
    AND grant_row.access_epoch_id = p_epoch_id
    AND grant_row.ended_at IS NULL;
  UPDATE public.tenant_federated_provider_access_grants AS grant_row
  SET ended_at = v_closed_at, version = grant_row.version + 1
  WHERE grant_row.tenant_id = p_tenant_id
    AND grant_row.access_epoch_id = p_epoch_id
    AND grant_row.ended_at IS NULL;

  FOREACH v_membership_id IN ARRAY coalesce(v_membership_ids, ARRAY[]::uuid[])
  LOOP
    PERFORM app.private_materialize_tenant_user_profile_v1(
      p_tenant_id, v_membership_id
    );
  END LOOP;

  UPDATE public.tenant_identity_provider_access_epochs AS epoch
  SET ended_at = v_closed_at,
      ended_by_membership_id = p_actor_membership_id,
      end_reason = p_reason,
      version = epoch.version + 1
  WHERE epoch.tenant_id = p_tenant_id
    AND epoch.id = p_epoch_id
    AND epoch.ended_at IS NULL;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'provider access epoch closure lost CAS'
      USING ERRCODE = '40001';
  END IF;
  UPDATE public.tenant_authorization_sources AS source
  SET retired_at = v_closed_at
  WHERE source.tenant_id = p_tenant_id
    AND source.id = v_epoch.source_id
    AND source.kind = 'identity_provider_access'
    AND source.retired_at IS NULL;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'provider access source could not be retired'
      USING ERRCODE = '55000';
  END IF;
EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
  RAISE EXCEPTION 'live provider access epoch is unavailable or ambiguous'
    USING ERRCODE = '55000';
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_federated_apply_identity_v1(
  p_apply jsonb,
  p_tenant_id uuid,
  p_provider_id uuid,
  p_binding_id uuid,
  p_provider_kind public.auth_provider_kind,
  p_mapping_revision bigint,
  p_configuration_revision bigint,
  p_applied_at timestamptz
)
RETURNS TABLE (
  out_user_id uuid,
  out_membership_id uuid,
  out_external_identity_id uuid,
  out_external_identity_revision bigint,
  out_identity_epoch bigint,
  out_session_invalidation_epoch bigint
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_plan jsonb := p_apply -> 'plan';
  v_mapping jsonb;
  v_subject jsonb;
  v_envelope jsonb;
  v_requested_user_id uuid;
  v_external_identity_id uuid;
  v_existing_identity_ids uuid[];
  v_existing_user_ids uuid[];
  v_alias jsonb;
  v_alias_count integer;
  v_previous_key_version integer := 0;
  v_key_version integer;
  v_digest bytea;
  v_nonce bytea;
  v_ciphertext bytea;
  v_subject_key_version integer;
  v_access_epoch_id uuid;
  v_access_source_id uuid;
  v_access_grant public.tenant_federated_provider_access_grants%ROWTYPE;
  v_access_grant_id uuid;
  v_membership_created boolean := false;
  v_display_name text := 'Federated user';
  v_profile_display_name text;
  v_username text;
  v_email text;
  v_profile jsonb;
  v_profile_item jsonb;
  v_profile_present integer := 0;
  v_profile_fields text[] := ARRAY[]::text[];
  v_matched_rule_ids uuid[];
  v_expected_matched_rule_ids uuid[];
  v_matched_count integer;
  v_live_rule_count integer;
  v_expected_team_count integer;
  v_live_team_count integer;
  v_expected_group_ids jsonb;
  v_expected_role_ids jsonb;
  v_expected_teams jsonb;
  v_change jsonb;
  v_rule record;
BEGIN
  PERFORM app.private_mfa_assert_json_object_v1(
    v_plan,
    ARRAY['planRevision','tenantId','userId','identityEpoch','providerRevision',
      'bindingRevision','configurationRevision','securityRevision','mappingRevision',
      'authorizationRevision','policyRevision','roleIds','securityGroupIds',
      'subject','mapping','requirement','hasEnrollableFactor'],
    ARRAY['planRevision','tenantId','identityEpoch','providerRevision','bindingRevision',
      'configurationRevision','securityRevision','mappingRevision','authorizationRevision',
      'policyRevision','roleIds','securityGroupIds','subject','mapping','requirement',
      'hasEnrollableFactor'],
    2097152
  );
  v_mapping := v_plan -> 'mapping';
  v_subject := v_plan -> 'subject';
  PERFORM app.private_mfa_assert_json_object_v1(
    v_mapping,
    ARRAY['disposition','reason','identityAction','accessAction','matchedRuleIds',
      'securityGroupIds','roleIds','operatorTeams','changes','profile'],
    ARRAY['disposition','reason','identityAction','accessAction','matchedRuleIds',
      'securityGroupIds','roleIds','operatorTeams','changes','profile'],
    1048576
  );
  PERFORM app.private_mfa_assert_json_object_v1(
    v_subject,
    ARRAY['externalIdentityId','aliases','envelope'],
    ARRAY['externalIdentityId','aliases','envelope'],
    262144
  );
  v_envelope := v_subject -> 'envelope';
  PERFORM app.private_mfa_assert_json_object_v1(
    v_envelope,
    ARRAY['keyVersion','format','nonce','ciphertext'],
    ARRAY['keyVersion','format','nonce','ciphertext'],
    65536
  );

  IF v_mapping ->> 'disposition' <> 'admitted'
     OR v_mapping ->> 'reason' NOT IN ('mapped','provider_access_only')
     OR v_mapping ->> 'identityAction' NOT IN ('no_change','create_user_and_external_identity')
     OR v_mapping ->> 'accessAction' NOT IN ('no_change','ensure')
     OR jsonb_typeof(v_mapping -> 'matchedRuleIds') <> 'array'
     OR jsonb_array_length(v_mapping -> 'matchedRuleIds') > 2000
     OR jsonb_typeof(v_mapping -> 'securityGroupIds') <> 'array'
     OR jsonb_array_length(v_mapping -> 'securityGroupIds') > 1024
     OR jsonb_typeof(v_mapping -> 'roleIds') <> 'array'
     OR jsonb_array_length(v_mapping -> 'roleIds') > 1024
     OR jsonb_typeof(v_mapping -> 'operatorTeams') <> 'array'
     OR jsonb_array_length(v_mapping -> 'operatorTeams') > 1024
     OR jsonb_typeof(v_mapping -> 'changes') <> 'array'
     OR jsonb_array_length(v_mapping -> 'changes') > 10000
     OR jsonb_typeof(v_mapping -> 'profile') <> 'array'
     OR jsonb_array_length(v_mapping -> 'profile') <> 6
     OR jsonb_typeof(v_plan -> 'roleIds') <> 'array'
     OR jsonb_typeof(v_plan -> 'securityGroupIds') <> 'array'
     OR v_plan -> 'roleIds' IS DISTINCT FROM v_mapping -> 'roleIds'
     OR v_plan -> 'securityGroupIds' IS DISTINCT FROM
       v_mapping -> 'securityGroupIds'
     OR v_envelope ->> 'format' <> 'utf8_exact' THEN
    RAISE EXCEPTION 'federated mapping plan is invalid' USING ERRCODE = '22023';
  END IF;

  BEGIN
    v_requested_user_id := nullif(v_plan ->> 'userId', '')::uuid;
    v_external_identity_id := (v_subject ->> 'externalIdentityId')::uuid;
    v_subject_key_version := (v_envelope ->> 'keyVersion')::integer;
  EXCEPTION WHEN OTHERS THEN
    RAISE EXCEPTION 'federated identity identifiers are invalid' USING ERRCODE = '22023';
  END;
  IF NOT ((uuid_extract_version(v_external_identity_id) = 7) IS TRUE)
     OR v_subject_key_version NOT BETWEEN 1 AND 32767
     OR NOT EXISTS (
       SELECT 1 FROM public.identity_keyring_versions AS keyring
       WHERE keyring.key_version = v_subject_key_version
         AND keyring.is_active AND keyring.retired_at IS NULL
     ) THEN
    RAISE EXCEPTION 'federated subject envelope key is unavailable'
      USING ERRCODE = '40001';
  END IF;
  v_nonce := app.private_mfa_decode_base64_v1(v_envelope ->> 'nonce', 12, 12);
  v_ciphertext := app.private_mfa_decode_base64_v1(
    v_envelope ->> 'ciphertext', 17, 4112
  );

  IF jsonb_typeof(v_subject -> 'aliases') <> 'array' THEN
    RAISE EXCEPTION 'federated subject aliases are invalid' USING ERRCODE = '22023';
  END IF;
  v_alias_count := jsonb_array_length(v_subject -> 'aliases');
  IF v_alias_count NOT BETWEEN 1 AND 16 THEN
    RAISE EXCEPTION 'federated subject aliases are invalid' USING ERRCODE = '22023';
  END IF;
  FOR v_alias IN SELECT value FROM jsonb_array_elements(v_subject -> 'aliases')
  LOOP
    PERFORM app.private_mfa_assert_json_object_v1(
      v_alias, ARRAY['keyVersion','digest'], ARRAY['keyVersion','digest'], 1024
    );
    BEGIN
      v_key_version := (v_alias ->> 'keyVersion')::integer;
    EXCEPTION WHEN OTHERS THEN
      RAISE EXCEPTION 'federated subject alias version is invalid'
        USING ERRCODE = '22023';
    END;
    v_digest := app.private_mfa_decode_base64_v1(v_alias ->> 'digest', 32, 32);
    IF v_key_version NOT BETWEEN 1 AND 32767
       OR v_key_version <= v_previous_key_version
       OR encode(v_digest, 'hex') = repeat('00', 32)
       OR NOT EXISTS (
         SELECT 1 FROM public.identity_keyring_versions AS keyring
         WHERE keyring.key_version = v_key_version
           AND keyring.is_active AND keyring.retired_at IS NULL
       ) THEN
      RAISE EXCEPTION 'federated subject aliases are stale or non-canonical'
        USING ERRCODE = '40001';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended(
      p_tenant_id::text || ':' || p_provider_id::text || ':' ||
      v_key_version::text || ':' || encode(v_digest, 'hex'), 91287311
    ));
    v_previous_key_version := v_key_version;
  END LOOP;

  SELECT array_agg(DISTINCT alias.external_identity_id ORDER BY alias.external_identity_id),
         array_agg(DISTINCT identity.user_id ORDER BY identity.user_id)
    INTO v_existing_identity_ids, v_existing_user_ids
  FROM jsonb_array_elements(v_subject -> 'aliases') AS supplied(value)
  JOIN public.tenant_federated_external_identity_aliases AS alias
    ON alias.tenant_id = p_tenant_id
   AND alias.provider_id = p_provider_id
   AND alias.key_version = (supplied.value ->> 'keyVersion')::integer
   AND alias.subject_digest = app.private_mfa_decode_base64_v1(
     supplied.value ->> 'digest', 32, 32
   )
   AND alias.retired_at IS NULL
  JOIN public.tenant_federated_external_identities AS identity
    ON identity.tenant_id = alias.tenant_id
   AND identity.provider_id = alias.provider_id
   AND identity.binding_id = p_binding_id
   AND identity.id = alias.external_identity_id
   AND identity.retired_at IS NULL;
  IF coalesce(cardinality(v_existing_identity_ids), 0) > 1
     OR coalesce(cardinality(v_existing_user_ids), 0) > 1 THEN
    RAISE EXCEPTION 'federated immutable subject aliases disagree'
      USING ERRCODE = '23505';
  END IF;

  IF cardinality(v_existing_identity_ids) = 1 THEN
    out_external_identity_id := v_existing_identity_ids[1];
    out_user_id := v_existing_user_ids[1];
    IF out_external_identity_id IS DISTINCT FROM v_external_identity_id
       OR out_user_id IS DISTINCT FROM v_requested_user_id
       OR v_mapping ->> 'identityAction' <> 'no_change' THEN
      RAISE EXCEPTION 'federated subject is linked to another identity'
        USING ERRCODE = '23505';
    END IF;
    SELECT membership.id, subject.identity_epoch,
           subject.session_invalidation_epoch
      INTO STRICT out_membership_id, out_identity_epoch,
        out_session_invalidation_epoch
    FROM public.tenant_federated_external_identities AS identity
    JOIN public.users AS local_user
      ON local_user.id = identity.user_id AND local_user.active
    JOIN public.tenant_memberships AS membership
      ON membership.tenant_id = identity.tenant_id
     AND membership.user_id = identity.user_id
     AND membership.status = 'active'
    JOIN public.tenant_mfa_subjects AS subject
      ON subject.tenant_id = membership.tenant_id
     AND subject.user_id = membership.user_id
    WHERE identity.tenant_id = p_tenant_id
      AND identity.provider_id = p_provider_id
      AND identity.binding_id = p_binding_id
      AND identity.id = out_external_identity_id
      AND identity.user_id = out_user_id
      AND identity.subject_format = 'utf8_exact'
      AND identity.retired_at IS NULL
    FOR UPDATE OF identity, local_user, membership, subject;
    UPDATE public.tenant_federated_external_identities AS identity
    SET subject_ciphertext = v_ciphertext,
        subject_nonce = v_nonce,
        key_version = v_subject_key_version,
        last_observed_at = greatest(identity.last_observed_at, p_applied_at),
        version = identity.version + 1,
        updated_at = transaction_timestamp()
    WHERE identity.tenant_id = p_tenant_id
      AND identity.id = out_external_identity_id
    RETURNING identity.version INTO out_external_identity_revision;
  ELSE
    IF v_requested_user_id IS NOT NULL
       OR v_mapping ->> 'identityAction' <> 'create_user_and_external_identity'
       OR NOT EXISTS (
         SELECT 1 FROM public.tenant_federated_provider_policies AS policy
         WHERE policy.tenant_id = p_tenant_id
           AND policy.provider_id = p_provider_id
           AND policy.binding_id = p_binding_id
           AND policy.provider_kind = p_provider_kind
           AND policy.jit_mode = 'create' AND policy.enabled
       ) THEN
      RAISE EXCEPTION 'federated JIT identity creation is not authorized'
        USING ERRCODE = '42501';
    END IF;
    out_user_id := uuidv7();
    out_membership_id := uuidv7();
    out_external_identity_id := v_external_identity_id;
    out_identity_epoch := 1;
    out_session_invalidation_epoch := 1;

    SELECT item.value ->> 'value' INTO v_display_name
    FROM jsonb_array_elements(v_mapping -> 'profile') AS item(value)
    WHERE item.value ->> 'field' = 'display_name'
      AND (item.value ->> 'present')::boolean;
    v_display_name := coalesce(nullif(v_display_name, ''), 'Federated user');
    IF btrim(v_display_name) = '' OR char_length(v_display_name) > 160
       OR v_display_name ~ '[[:cntrl:]]' THEN
      RAISE EXCEPTION 'federated display name is invalid' USING ERRCODE = '22023';
    END IF;
    INSERT INTO public.users (id, email, display_name)
    VALUES (out_user_id, NULL, v_display_name);
    INSERT INTO public.tenant_memberships (id, tenant_id, user_id, role, status)
    VALUES (out_membership_id, p_tenant_id, out_user_id, 'read_only', 'active');
    INSERT INTO public.tenant_mfa_subjects (
      tenant_id, user_id, webauthn_user_handle,
      identity_epoch, session_invalidation_epoch
    ) VALUES (
      p_tenant_id, out_user_id, gen_random_bytes(32), 1, 1
    );
    INSERT INTO public.tenant_federated_external_identities (
      id, tenant_id, provider_id, binding_id, user_id, subject_format,
      subject_ciphertext, subject_nonce, key_version,
      admitted_configuration_revision, last_observed_at, version,
      created_at, updated_at
    ) VALUES (
      out_external_identity_id, p_tenant_id, p_provider_id, p_binding_id,
      out_user_id,
      'utf8_exact', v_ciphertext, v_nonce, v_subject_key_version,
      p_configuration_revision, p_applied_at, 1, p_applied_at, p_applied_at
    );
    out_external_identity_revision := 1;
    v_membership_created := true;
  END IF;

  FOR v_alias IN SELECT value FROM jsonb_array_elements(v_subject -> 'aliases')
  LOOP
    v_key_version := (v_alias ->> 'keyVersion')::integer;
    v_digest := app.private_mfa_decode_base64_v1(v_alias ->> 'digest', 32, 32);
    INSERT INTO public.tenant_federated_external_identity_aliases (
      id, tenant_id, provider_id, external_identity_id,
      key_version, subject_digest, created_at
    ) VALUES (
      uuidv7(), p_tenant_id, p_provider_id, out_external_identity_id,
      v_key_version, v_digest, p_applied_at
    ) ON CONFLICT (tenant_id, provider_id, key_version, subject_digest)
      DO NOTHING;
    IF NOT EXISTS (
      SELECT 1 FROM public.tenant_federated_external_identity_aliases AS alias
      WHERE alias.tenant_id = p_tenant_id
        AND alias.provider_id = p_provider_id
        AND alias.external_identity_id = out_external_identity_id
        AND alias.key_version = v_key_version
        AND alias.subject_digest = v_digest
    ) THEN
      RAISE EXCEPTION 'federated subject alias collision' USING ERRCODE = '23505';
    END IF;
  END LOOP;

  SELECT epoch.id, epoch.source_id
    INTO STRICT v_access_epoch_id, v_access_source_id
  FROM public.tenant_auth_provider_bindings AS binding
  JOIN public.tenant_identity_provider_access_epochs AS epoch
    ON epoch.tenant_id = binding.tenant_id
   AND epoch.id = binding.current_access_epoch_id
   AND epoch.binding_id = binding.id
   AND epoch.provider_id = binding.provider_id
   AND epoch.ended_at IS NULL
  JOIN public.tenant_authorization_sources AS source
    ON source.tenant_id = epoch.tenant_id
   AND source.id = epoch.source_id
   AND source.kind = 'identity_provider_access'
   AND source.retired_at IS NULL
  WHERE binding.tenant_id = p_tenant_id
    AND binding.id = p_binding_id
    AND binding.provider_id = p_provider_id
    AND binding.enabled AND binding.archived_at IS NULL;

  SELECT grant_row.* INTO v_access_grant
  FROM public.tenant_federated_provider_access_grants AS grant_row
  WHERE grant_row.tenant_id = p_tenant_id
    AND grant_row.binding_id = p_binding_id
    AND grant_row.membership_id = out_membership_id
    AND grant_row.ended_at IS NULL
  FOR UPDATE;
  IF FOUND THEN
    IF v_access_grant.provider_id IS DISTINCT FROM p_provider_id
       OR v_access_grant.external_identity_id IS DISTINCT FROM out_external_identity_id
       OR v_access_grant.user_id IS DISTINCT FROM out_user_id
       OR v_access_grant.access_epoch_id IS DISTINCT FROM v_access_epoch_id
       OR v_access_grant.source_id IS DISTINCT FROM v_access_source_id THEN
      RAISE EXCEPTION 'federated access grant is linked to another authority'
        USING ERRCODE = '23505';
    END IF;
    UPDATE public.tenant_federated_provider_access_grants AS grant_row
    SET last_observed_at = greatest(grant_row.last_observed_at, p_applied_at),
        version = grant_row.version + 1
    WHERE grant_row.tenant_id = p_tenant_id
      AND grant_row.id = v_access_grant.id;
    v_access_grant_id := v_access_grant.id;
  ELSE
    IF v_mapping ->> 'accessAction' <> 'ensure' THEN
      RAISE EXCEPTION 'federated provider access is stale' USING ERRCODE = '40001';
    END IF;
    v_access_grant_id := uuidv7();
    INSERT INTO public.tenant_federated_provider_access_grants (
      id, tenant_id, provider_id, binding_id, access_epoch_id, source_id,
      external_identity_id, membership_id, user_id, owns_membership,
      started_at, last_observed_at, version
    ) VALUES (
      v_access_grant_id, p_tenant_id, p_provider_id, p_binding_id,
      v_access_epoch_id, v_access_source_id, out_external_identity_id,
      out_membership_id, out_user_id, v_membership_created,
      p_applied_at, p_applied_at, 1
    );
  END IF;

  -- Validate the fixed six-field profile envelope before storing the closed
  -- federated subset. Email is profile data only and never an account-link key.
  FOR v_profile_item IN SELECT value FROM jsonb_array_elements(v_mapping -> 'profile')
  LOOP
    PERFORM app.private_mfa_assert_json_object_v1(
      v_profile_item, ARRAY['field','present','value'], ARRAY['field','present'], 4096
    );
    IF v_profile_item ->> 'field' = ANY(v_profile_fields)
       OR v_profile_item ->> 'field' NOT IN (
         'first_name','last_name','display_name','username','alternate_username','email'
       ) THEN
      RAISE EXCEPTION 'federated profile projection is non-canonical'
        USING ERRCODE = '22023';
    END IF;
    v_profile_fields := array_append(v_profile_fields, v_profile_item ->> 'field');
    IF (v_profile_item ->> 'present')::boolean THEN
      IF v_profile_item ->> 'field' NOT IN ('display_name','username','email') THEN
        RAISE EXCEPTION 'federated profile field is not permitted'
          USING ERRCODE = '22023';
      END IF;
      v_profile_present := v_profile_present + 1;
      IF v_profile_item ->> 'field' = 'display_name' THEN
        v_profile_display_name := v_profile_item ->> 'value';
      ELSIF v_profile_item ->> 'field' = 'username' THEN
        v_username := v_profile_item ->> 'value';
      ELSE
        v_email := v_profile_item ->> 'value';
      END IF;
    ELSIF v_profile_item ? 'value' AND v_profile_item ->> 'value' <> '' THEN
      RAISE EXCEPTION 'absent federated profile value is not empty'
        USING ERRCODE = '22023';
    END IF;
  END LOOP;
  UPDATE public.tenant_federated_provider_profile_contributions AS contribution
  SET retired_at = p_applied_at, version = contribution.version + 1
  WHERE contribution.tenant_id = p_tenant_id
    AND contribution.access_grant_id = v_access_grant_id
    AND contribution.retired_at IS NULL;
  IF v_profile_present > 0 THEN
    INSERT INTO public.tenant_federated_provider_profile_contributions (
      id, tenant_id, access_grant_id, display_name, username, email,
      mapping_revision, observed_at, version
    ) VALUES (
      uuidv7(), p_tenant_id, v_access_grant_id,
      v_profile_display_name, v_username, v_email,
      p_mapping_revision, p_applied_at, 1
    );
  END IF;

  SELECT coalesce(
           array_agg((value #>> '{}')::uuid ORDER BY ordinal),
           ARRAY[]::uuid[]
         )
    INTO v_matched_rule_ids
  FROM jsonb_array_elements(v_mapping -> 'matchedRuleIds')
    WITH ORDINALITY AS supplied(value, ordinal);
  SELECT count(DISTINCT id)::integer INTO v_matched_count
  FROM unnest(v_matched_rule_ids) AS id;
  PERFORM 1
  FROM public.tenant_federated_mapping_rule_epochs AS epoch
  JOIN public.tenant_authorization_sources AS source
    ON source.tenant_id = epoch.tenant_id
   AND source.id = epoch.source_id
   AND source.retired_at IS NULL
  JOIN public.tenant_security_groups AS security_group
    ON security_group.tenant_id = epoch.tenant_id
   AND security_group.id = epoch.tenant_security_group_id
   AND security_group.archived_at IS NULL
  WHERE epoch.tenant_id = p_tenant_id
    AND epoch.binding_id = p_binding_id
    AND epoch.provider_id = p_provider_id
    AND epoch.provider_kind = p_provider_kind
    AND epoch.mapping_revision = p_mapping_revision
    AND epoch.rule_id = ANY(v_matched_rule_ids)
    AND epoch.enabled AND epoch.ended_at IS NULL
  FOR SHARE OF epoch, source, security_group;
  GET DIAGNOSTICS v_live_rule_count = ROW_COUNT;
  IF v_live_rule_count IS DISTINCT FROM cardinality(v_matched_rule_ids) THEN
    RAISE EXCEPTION 'federated matched mapping rule authority drifted'
      USING ERRCODE = '40001';
  END IF;
  SELECT count(*)::integer INTO v_expected_team_count
  FROM public.tenant_federated_mapping_rule_epochs AS epoch
  WHERE epoch.tenant_id = p_tenant_id
    AND epoch.binding_id = p_binding_id
    AND epoch.provider_id = p_provider_id
    AND epoch.provider_kind = p_provider_kind
    AND epoch.mapping_revision = p_mapping_revision
    AND epoch.rule_id = ANY(v_matched_rule_ids)
    AND epoch.enabled AND epoch.ended_at IS NULL
    AND epoch.operator_team_id IS NOT NULL;
  PERFORM 1
  FROM public.tenant_federated_mapping_rule_epochs AS epoch
  JOIN public.operator_team_assignment_epochs AS assignment
    ON assignment.tenant_id = epoch.tenant_id
   AND assignment.id = epoch.operator_team_assignment_epoch_id
   AND assignment.operator_team_id = epoch.operator_team_id
   AND assignment.ended_at IS NULL
  JOIN public.operator_teams AS team
    ON team.tenant_id = assignment.tenant_id
   AND team.id = assignment.operator_team_id
   AND team.archived_at IS NULL
  WHERE epoch.tenant_id = p_tenant_id
    AND epoch.binding_id = p_binding_id
    AND epoch.provider_id = p_provider_id
    AND epoch.provider_kind = p_provider_kind
    AND epoch.mapping_revision = p_mapping_revision
    AND epoch.rule_id = ANY(v_matched_rule_ids)
    AND epoch.enabled AND epoch.ended_at IS NULL
    AND epoch.operator_team_id IS NOT NULL
  FOR SHARE OF assignment, team;
  GET DIAGNOSTICS v_live_team_count = ROW_COUNT;
  IF v_live_team_count IS DISTINCT FROM v_expected_team_count THEN
    RAISE EXCEPTION 'federated operator-team authority drifted'
      USING ERRCODE = '40001';
  END IF;
  SELECT coalesce(array_agg(epoch.rule_id ORDER BY epoch.priority, epoch.rule_id),
                  ARRAY[]::uuid[])
    INTO v_expected_matched_rule_ids
  FROM public.tenant_federated_mapping_rule_epochs AS epoch
  WHERE epoch.tenant_id = p_tenant_id
    AND epoch.binding_id = p_binding_id
    AND epoch.provider_id = p_provider_id
    AND epoch.provider_kind = p_provider_kind
    AND epoch.mapping_revision = p_mapping_revision
    AND epoch.rule_id = ANY(v_matched_rule_ids)
    AND epoch.enabled AND epoch.ended_at IS NULL;
  IF to_jsonb(v_matched_rule_ids) IS DISTINCT FROM v_mapping -> 'matchedRuleIds'
     OR v_matched_rule_ids IS DISTINCT FROM v_expected_matched_rule_ids
     OR v_matched_count IS DISTINCT FROM cardinality(v_matched_rule_ids)
     OR EXISTS (
       SELECT 1 FROM unnest(v_matched_rule_ids) AS id
       WHERE NOT EXISTS (
         SELECT 1 FROM public.tenant_federated_mapping_rule_epochs AS epoch
         WHERE epoch.tenant_id = p_tenant_id
           AND epoch.binding_id = p_binding_id
           AND epoch.provider_id = p_provider_id
           AND epoch.provider_kind = p_provider_kind
           AND epoch.mapping_revision = p_mapping_revision
           AND epoch.rule_id = id
           AND epoch.enabled AND epoch.ended_at IS NULL
       )
     ) THEN
    RAISE EXCEPTION 'federated matched mapping rules are stale'
      USING ERRCODE = '40001';
  END IF;

  WITH expected AS (
    SELECT DISTINCT epoch.tenant_security_group_id AS id
    FROM public.tenant_federated_mapping_rule_epochs AS epoch
    WHERE epoch.tenant_id = p_tenant_id
      AND epoch.binding_id = p_binding_id
      AND epoch.provider_id = p_provider_id
      AND epoch.provider_kind = p_provider_kind
      AND epoch.mapping_revision = p_mapping_revision
      AND epoch.rule_id = ANY(v_matched_rule_ids)
      AND epoch.enabled AND epoch.ended_at IS NULL
  )
  SELECT to_jsonb(coalesce(array_agg(id ORDER BY id), ARRAY[]::uuid[]))
    INTO v_expected_group_ids
  FROM expected;

  WITH matched_epochs AS (
    SELECT epoch.id, epoch.tenant_security_group_id
    FROM public.tenant_federated_mapping_rule_epochs AS epoch
    WHERE epoch.tenant_id = p_tenant_id
      AND epoch.binding_id = p_binding_id
      AND epoch.provider_id = p_provider_id
      AND epoch.provider_kind = p_provider_kind
      AND epoch.mapping_revision = p_mapping_revision
      AND epoch.rule_id = ANY(v_matched_rule_ids)
      AND epoch.enabled AND epoch.ended_at IS NULL
  ), effective_roles AS (
    SELECT direct_grant.role_id
    FROM public.tenant_membership_role_grants AS direct_grant
    JOIN public.tenant_authorization_sources AS source
      ON source.tenant_id = direct_grant.tenant_id
     AND source.id = direct_grant.source_id
     AND source.retired_at IS NULL
    WHERE direct_grant.tenant_id = p_tenant_id
      AND direct_grant.membership_id = out_membership_id
      AND direct_grant.revoked_at IS NULL
      AND (direct_grant.expires_at IS NULL
        OR direct_grant.expires_at > p_applied_at)
    UNION
    SELECT group_grant.role_id
    FROM public.tenant_security_group_memberships AS group_member
    JOIN public.tenant_authorization_sources AS member_source
      ON member_source.tenant_id = group_member.tenant_id
     AND member_source.id = group_member.source_id
     AND member_source.retired_at IS NULL
    JOIN public.tenant_security_group_role_grants AS group_grant
      ON group_grant.tenant_id = group_member.tenant_id
     AND group_grant.group_id = group_member.group_id
     AND group_grant.revoked_at IS NULL
     AND (group_grant.expires_at IS NULL
       OR group_grant.expires_at > p_applied_at)
    JOIN public.tenant_authorization_sources AS grant_source
      ON grant_source.tenant_id = group_grant.tenant_id
     AND grant_source.id = group_grant.source_id
     AND grant_source.retired_at IS NULL
    WHERE group_member.tenant_id = p_tenant_id
      AND group_member.membership_id = out_membership_id
      AND group_member.revoked_at IS NULL
      AND (group_member.expires_at IS NULL
        OR group_member.expires_at > p_applied_at)
    UNION
    SELECT target.role_id
    FROM matched_epochs AS epoch
    JOIN public.tenant_federated_mapping_rule_role_targets AS target
      ON target.tenant_id = p_tenant_id
     AND target.rule_epoch_id = epoch.id
    UNION
    SELECT group_grant.role_id
    FROM matched_epochs AS epoch
    JOIN public.tenant_security_group_role_grants AS group_grant
      ON group_grant.tenant_id = p_tenant_id
     AND group_grant.group_id = epoch.tenant_security_group_id
     AND group_grant.revoked_at IS NULL
     AND (group_grant.expires_at IS NULL
       OR group_grant.expires_at > p_applied_at)
    JOIN public.tenant_authorization_sources AS grant_source
      ON grant_source.tenant_id = group_grant.tenant_id
     AND grant_source.id = group_grant.source_id
     AND grant_source.retired_at IS NULL
  ), allowed_roles AS (
    SELECT DISTINCT role.id
    FROM effective_roles AS effective
    JOIN public.tenant_roles AS role
      ON role.tenant_id = p_tenant_id
     AND role.id = effective.role_id
     AND role.principal_kind = 'human'
     AND role.key <> 'platform_super_admin'
     AND role.archived_at IS NULL
    WHERE NOT EXISTS (
      SELECT 1
      FROM public.tenant_role_permissions AS permission
      WHERE permission.tenant_id = role.tenant_id
        AND permission.role_id = role.id
        AND permission.scope = 'platform'
    )
  )
  SELECT to_jsonb(coalesce(array_agg(id ORDER BY id), ARRAY[]::uuid[]))
    INTO v_expected_role_ids
  FROM allowed_roles;

  WITH expected AS (
    SELECT DISTINCT epoch.operator_team_id AS team_id,
      epoch.operator_team_assignment_epoch_id AS assignment_epoch_id
    FROM public.tenant_federated_mapping_rule_epochs AS epoch
    JOIN public.operator_team_assignment_epochs AS assignment
      ON assignment.tenant_id = epoch.tenant_id
     AND assignment.id = epoch.operator_team_assignment_epoch_id
     AND assignment.operator_team_id = epoch.operator_team_id
     AND assignment.ended_at IS NULL
    JOIN public.operator_teams AS team
      ON team.tenant_id = assignment.tenant_id
     AND team.id = assignment.operator_team_id
     AND team.archived_at IS NULL
    WHERE epoch.tenant_id = p_tenant_id
      AND epoch.binding_id = p_binding_id
      AND epoch.provider_id = p_provider_id
      AND epoch.provider_kind = p_provider_kind
      AND epoch.mapping_revision = p_mapping_revision
      AND epoch.rule_id = ANY(v_matched_rule_ids)
      AND epoch.enabled AND epoch.ended_at IS NULL
      AND epoch.operator_team_id IS NOT NULL
      AND epoch.operator_team_assignment_epoch_id IS NOT NULL
  )
  SELECT coalesce(jsonb_agg(jsonb_build_object(
           'teamId', team_id::text,
           'assignmentEpochId', assignment_epoch_id::text
         ) ORDER BY team_id, assignment_epoch_id), '[]'::jsonb)
    INTO v_expected_teams
  FROM expected;

  IF v_mapping -> 'securityGroupIds' IS DISTINCT FROM v_expected_group_ids
     OR v_mapping -> 'roleIds' IS DISTINCT FROM v_expected_role_ids
     OR v_mapping -> 'operatorTeams' IS DISTINCT FROM v_expected_teams THEN
    RAISE EXCEPTION 'federated mapping consequences drifted'
      USING ERRCODE = '40001';
  END IF;

  FOR v_change IN SELECT value FROM jsonb_array_elements(v_mapping -> 'changes')
  LOOP
    PERFORM app.private_mfa_assert_json_object_v1(
      v_change,
      ARRAY['operation','sourceId','ruleEpochId','kind','primaryId','secondaryId'],
      ARRAY['operation','sourceId','ruleEpochId','kind','primaryId'],
      4096
    );
    IF v_change ->> 'operation' NOT IN ('ensure','refresh','revoke')
       OR v_change ->> 'kind' NOT IN (
         'security_group_membership','security_group_role_grant','operator_team_roster'
       )
       OR (v_change ->> 'kind' = 'security_group_membership') <>
          (NOT (v_change ? 'secondaryId'))
       OR NOT EXISTS (
         SELECT 1
         FROM public.tenant_federated_mapping_rule_epochs AS epoch
         WHERE epoch.tenant_id = p_tenant_id
           AND epoch.binding_id = p_binding_id
           AND epoch.provider_id = p_provider_id
           AND epoch.provider_kind = p_provider_kind
           AND epoch.mapping_revision = p_mapping_revision
           AND epoch.id = app.private_mfa_require_uuidv7_v1(
             v_change ->> 'ruleEpochId'
           )
           AND epoch.source_id = app.private_mfa_require_uuidv7_v1(
             v_change ->> 'sourceId'
           )
           AND epoch.enabled AND epoch.ended_at IS NULL
       )
       OR app.private_mfa_require_uuidv7_v1(v_change ->> 'primaryId') IS NULL
       OR ((v_change ? 'secondaryId') AND
         app.private_mfa_require_uuidv7_v1(v_change ->> 'secondaryId') IS NULL) THEN
      RAISE EXCEPTION 'federated mapping change provenance drifted'
        USING ERRCODE = '40001';
    END IF;
  END LOOP;

  FOR v_rule IN
    SELECT epoch.*
    FROM public.tenant_federated_mapping_rule_epochs AS epoch
    WHERE epoch.tenant_id = p_tenant_id
      AND epoch.binding_id = p_binding_id
      AND epoch.provider_id = p_provider_id
      AND epoch.provider_kind = p_provider_kind
      AND epoch.mapping_revision = p_mapping_revision
      AND epoch.rule_id = ANY(v_matched_rule_ids)
      AND epoch.enabled AND epoch.ended_at IS NULL
    ORDER BY epoch.priority, epoch.rule_id
  LOOP
    INSERT INTO public.tenant_security_group_memberships (
      id, tenant_id, group_id, membership_id, source_id,
      granted_by_membership_id, grant_reason
    ) VALUES (
      uuidv7(), p_tenant_id, v_rule.tenant_security_group_id,
      out_membership_id, v_rule.source_id, NULL,
      'federated_mapping_observation'
    ) ON CONFLICT DO NOTHING;

    INSERT INTO public.tenant_security_group_role_grants (
      id, tenant_id, group_id, role_id, source_id,
      granted_by_membership_id, grant_reason
    )
    SELECT uuidv7(), p_tenant_id, v_rule.tenant_security_group_id,
      target.role_id, v_rule.source_id, NULL, 'federated_mapping_target'
    FROM public.tenant_federated_mapping_rule_role_targets AS target
    JOIN public.tenant_roles AS role
      ON role.tenant_id = target.tenant_id
     AND role.id = target.role_id
     AND role.principal_kind = 'human'
     AND role.key <> 'platform_super_admin'
     AND role.archived_at IS NULL
    LEFT JOIN public.tenant_role_permissions AS forbidden
      ON forbidden.tenant_id = role.tenant_id
     AND forbidden.role_id = role.id
     AND forbidden.scope = 'platform'
    WHERE target.tenant_id = p_tenant_id
      AND target.rule_epoch_id = v_rule.id
      AND forbidden.role_id IS NULL
    ON CONFLICT DO NOTHING;

    IF v_rule.operator_team_assignment_epoch_id IS NOT NULL THEN
      INSERT INTO public.operator_team_roster_entries (
        id, tenant_id, assignment_epoch_id, membership_id, source_id,
        granted_by_membership_id, grant_reason
      )
      SELECT uuidv7(), p_tenant_id, v_rule.operator_team_assignment_epoch_id,
        out_membership_id, v_rule.source_id, NULL,
        'federated_mapping_observation'
      FROM public.operator_team_assignment_epochs AS assignment
      JOIN public.operator_teams AS team
        ON team.tenant_id = assignment.tenant_id
       AND team.id = assignment.operator_team_id
      WHERE assignment.tenant_id = p_tenant_id
        AND assignment.id = v_rule.operator_team_assignment_epoch_id
        AND assignment.operator_team_id = v_rule.operator_team_id
        AND assignment.ended_at IS NULL AND team.archived_at IS NULL
      ON CONFLICT DO NOTHING;
    END IF;
  END LOOP;

  -- Authoritative absence is source-scoped; additive and unrelated sources
  -- are never revoked by a login.
  WITH absent AS (
    SELECT epoch.source_id
    FROM public.tenant_federated_mapping_rule_epochs AS epoch
    JOIN public.tenant_authorization_sources AS source
      ON source.tenant_id = epoch.tenant_id
     AND source.id = epoch.source_id
     AND source.retired_at IS NULL
    WHERE epoch.tenant_id = p_tenant_id
      AND epoch.binding_id = p_binding_id
      AND epoch.provider_id = p_provider_id
      AND epoch.provider_kind = p_provider_kind
      AND epoch.mapping_revision = p_mapping_revision
      AND epoch.enabled AND epoch.ended_at IS NULL
      AND epoch.reconciliation_mode = 'authoritative'
      AND NOT (epoch.rule_id = ANY(v_matched_rule_ids))
  )
  UPDATE public.tenant_security_group_memberships AS member
  SET revoked_at = p_applied_at,
      revoke_reason = 'federated_mapping_authoritative_absence',
      version = member.version + 1,
      updated_at = transaction_timestamp()
  FROM absent
  WHERE member.tenant_id = p_tenant_id
    AND member.membership_id = out_membership_id
    AND member.source_id = absent.source_id
    AND member.revoked_at IS NULL;

  WITH absent AS (
    SELECT epoch.source_id
    FROM public.tenant_federated_mapping_rule_epochs AS epoch
    JOIN public.tenant_authorization_sources AS source
      ON source.tenant_id = epoch.tenant_id
     AND source.id = epoch.source_id
     AND source.retired_at IS NULL
    WHERE epoch.tenant_id = p_tenant_id
      AND epoch.binding_id = p_binding_id
      AND epoch.provider_id = p_provider_id
      AND epoch.provider_kind = p_provider_kind
      AND epoch.mapping_revision = p_mapping_revision
      AND epoch.enabled AND epoch.ended_at IS NULL
      AND epoch.reconciliation_mode = 'authoritative'
      AND NOT (epoch.rule_id = ANY(v_matched_rule_ids))
  )
  UPDATE public.operator_team_roster_entries AS roster
  SET revoked_at = p_applied_at,
      revoke_reason = 'federated_mapping_authoritative_absence',
      version = roster.version + 1,
      updated_at = transaction_timestamp()
  FROM absent
  WHERE roster.tenant_id = p_tenant_id
    AND roster.membership_id = out_membership_id
    AND roster.source_id = absent.source_id
    AND roster.revoked_at IS NULL;

  PERFORM app.private_materialize_tenant_user_profile_v1(
    p_tenant_id, out_membership_id
  );
  RETURN NEXT;
EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
  RAISE EXCEPTION 'federated identity authority is unavailable or ambiguous'
    USING ERRCODE = '40001';
END;
$function$;
--> statement-breakpoint

DO $acl$
DECLARE
  v_signature regprocedure;
BEGIN
  FOREACH v_signature IN ARRAY ARRAY[
    'app.private_federated_assurance_requirement_v1(uuid,uuid,uuid,bigint,text,timestamp with time zone)'::regprocedure,
    'app.apply_federated_authentication_v1(jsonb)'::regprocedure,
    'app.private_federated_assurance_decision_v1(jsonb,jsonb,boolean,timestamp with time zone)'::regprocedure,
    'app.private_federated_apply_response_v1(bytea,text,uuid,text,text,uuid,uuid,uuid,text,boolean)'::regprocedure,
    'app.private_federated_replay_live_v1(uuid,uuid,uuid,auth_provider_kind,uuid,uuid,uuid,uuid,timestamp with time zone)'::regprocedure,
    'app.private_federated_issue_authority_v1(jsonb,uuid,uuid,uuid,bigint,bigint,bigint,uuid,uuid,auth_provider_kind,bigint,timestamp with time zone,bytea)'::regprocedure,
    'app.private_materialize_tenant_user_profile_v1(uuid,uuid)'::regprocedure,
    'app.private_close_tenant_identity_access_epoch_v1(uuid,uuid,uuid,text)'::regprocedure,
    'app.private_federated_apply_identity_v1(jsonb,uuid,uuid,uuid,auth_provider_kind,bigint,bigint,timestamp with time zone)'::regprocedure
  ] LOOP
    EXECUTE format('ALTER FUNCTION %s OWNER TO periapsis_migrator',v_signature);
    EXECUTE format(
      'REVOKE ALL ON FUNCTION %s FROM PUBLIC, periapsis_api, periapsis_worker, '
      || 'periapsis_notifier, periapsis_auditor, periapsis_audit_reader_owner, '
      || 'periapsis_notification_dispatch_owner, periapsis_sla_api_owner, '
      || 'periapsis_sla_worker_owner, periapsis_sla_readiness_owner',
      v_signature
    );
  END LOOP;
END;
$acl$;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.apply_federated_authentication_v1(jsonb)
  TO periapsis_api;
--> statement-breakpoint
