-- Live session revalidation for tenant-provider primaries.  Snapshot authority
-- is immutable; live lifecycle, factor, trust and policy state is recomputed on
-- every load and again under lock at commit.

CREATE FUNCTION app.load_federated_session_revalidation_v1(p_lookup jsonb)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_session_id uuid;
  v_tenant_id uuid;
  v_audience text;
  v_session public.auth_sessions%ROWTYPE;
  v_state public.auth_session_mfa_states%ROWTYPE;
  v_provenance public.auth_session_federated_provenance%ROWTYPE;
  v_live_identity_epoch bigint;
  v_live_session_epoch bigint;
  v_user_active boolean;
  v_tenant_active boolean;
  v_membership_active boolean;
  v_membership_id uuid;
  v_live_primary_revision bigint;
  v_primary_active boolean;
  v_requirement jsonb;
  v_evidence jsonb;
  v_policies jsonb;
  v_factors jsonb;
  v_trust jsonb;
BEGIN
  PERFORM app.private_mfa_assert_json_object_v1(
    p_lookup,ARRAY['sessionId','tenantId','audience'],
    ARRAY['sessionId','tenantId','audience'],16384
  );
  IF jsonb_typeof(p_lookup -> 'sessionId') <> 'string'
     OR jsonb_typeof(p_lookup -> 'tenantId') <> 'string'
     OR jsonb_typeof(p_lookup -> 'audience') <> 'string'
     OR NOT app.private_mfa_safe_text_v1(p_lookup ->> 'audience',256) THEN
    RAISE EXCEPTION 'invalid federated session lookup' USING ERRCODE = '22023';
  END IF;
  v_session_id := app.private_mfa_require_uuidv7_v1(p_lookup ->> 'sessionId');
  v_tenant_id := app.private_mfa_require_uuidv7_v1(p_lookup ->> 'tenantId');
  v_audience := p_lookup ->> 'audience';

  SELECT session.* INTO STRICT v_session
  FROM public.auth_sessions AS session
  WHERE session.id = v_session_id AND session.active_tenant_id = v_tenant_id;
  SELECT state.* INTO STRICT v_state
  FROM public.auth_session_mfa_states AS state
  WHERE state.tenant_id = v_tenant_id AND state.session_id = v_session_id
    AND state.user_id = v_session.user_id
    AND state.primary_kind = 'tenant_provider'
    AND state.audience = v_audience;
  SELECT provenance.* INTO STRICT v_provenance
  FROM public.auth_session_federated_provenance AS provenance
  WHERE provenance.tenant_id = v_tenant_id
    AND provenance.session_id = v_session_id
    AND provenance.user_id = v_state.user_id
    AND provenance.primary_kind = 'tenant_provider';

  SELECT subject.identity_epoch,subject.session_invalidation_epoch,
         local_user.active,tenant.status = 'active',membership.status = 'active',
         membership.id
    INTO STRICT v_live_identity_epoch,v_live_session_epoch,v_user_active,
      v_tenant_active,v_membership_active,v_membership_id
  FROM public.tenant_mfa_subjects AS subject
  JOIN public.users AS local_user ON local_user.id = subject.user_id
  JOIN public.tenants AS tenant ON tenant.id = subject.tenant_id
  JOIN public.tenant_memberships AS membership
    ON membership.tenant_id = subject.tenant_id
   AND membership.user_id = subject.user_id
  WHERE subject.tenant_id = v_tenant_id AND subject.user_id = v_state.user_id;
  SELECT identity.version,(
    identity.retired_at IS NULL AND provider.enabled
    AND provider.archived_at IS NULL AND binding.enabled
    AND binding.archived_at IS NULL AND binding.current_access_epoch_id IS NOT NULL
    AND policy.enabled AND access_grant.id IS NOT NULL
    AND access_epoch.id IS NOT NULL AND access_source.id IS NOT NULL
  ) INTO STRICT v_live_primary_revision,v_primary_active
  FROM public.tenant_federated_external_identities AS identity
  JOIN public.tenant_auth_providers AS provider
    ON provider.tenant_id = identity.tenant_id
   AND provider.id = identity.provider_id
  JOIN public.tenant_auth_provider_bindings AS binding
    ON binding.tenant_id = identity.tenant_id
   AND binding.id = identity.binding_id
   AND binding.provider_id = identity.provider_id
  JOIN public.tenant_federated_provider_policies AS policy
    ON policy.tenant_id = identity.tenant_id
   AND policy.provider_id = identity.provider_id
   AND policy.binding_id = identity.binding_id
   AND policy.provider_kind = provider.kind
  LEFT JOIN public.tenant_federated_provider_access_grants AS access_grant
    ON access_grant.tenant_id = identity.tenant_id
   AND access_grant.provider_id = identity.provider_id
   AND access_grant.binding_id = identity.binding_id
   AND access_grant.external_identity_id = identity.id
   AND access_grant.user_id = identity.user_id
   AND access_grant.membership_id = v_membership_id
   AND access_grant.access_epoch_id = binding.current_access_epoch_id
   AND access_grant.started_at <= transaction_timestamp()
   AND access_grant.ended_at IS NULL
  LEFT JOIN public.tenant_identity_provider_access_epochs AS access_epoch
    ON access_epoch.tenant_id = access_grant.tenant_id
   AND access_epoch.id = access_grant.access_epoch_id
   AND access_epoch.binding_id = access_grant.binding_id
   AND access_epoch.provider_id = access_grant.provider_id
   AND access_epoch.source_id = access_grant.source_id
   AND access_epoch.started_at <= transaction_timestamp()
   AND access_epoch.ended_at IS NULL
  LEFT JOIN public.tenant_authorization_sources AS access_source
    ON access_source.tenant_id = access_grant.tenant_id
   AND access_source.id = access_grant.source_id
   AND access_source.retired_at IS NULL
  WHERE identity.tenant_id = v_tenant_id
    AND identity.provider_id = v_provenance.provider_id
    AND identity.binding_id = v_provenance.binding_id
    AND identity.id = v_provenance.external_identity_id
    AND identity.user_id = v_state.user_id
    AND provider.kind = v_provenance.provider_kind;

  SELECT coalesce(jsonb_agg(jsonb_build_object(
    'reference',jsonb_strip_nulls(jsonb_build_object(
      'localCredentialId',evidence.local_credential_id::text,
      'totpFactorId',evidence.totp_factor_id::text,
      'webAuthnCredentialId',evidence.webauthn_credential_id::text,
      'recoveryCodeSetId',evidence.recovery_code_set_id::text
    )),
    'evidence',jsonb_strip_nulls(jsonb_build_object(
      'level',evidence.level,
      'kind',CASE WHEN evidence.kind = 'recovery' THEN 'recovery' ELSE 'factor' END,
      'local',evidence.provider_id IS NULL,
      'providerId',evidence.provider_id::text,
      'bindingId',evidence.binding_id::text,
      'authenticatedAt',to_jsonb(evidence.authenticated_at),
      'expiresAt',CASE WHEN evidence.expires_at IS NULL THEN 'null'::jsonb
        ELSE to_jsonb(evidence.expires_at) END,
      'factorRevision',CASE WHEN evidence.factor_revision IS NULL THEN 'null'::jsonb
        ELSE to_jsonb(evidence.factor_revision) END,
      'trustRuleRevision',CASE WHEN evidence.trust_rule_revision IS NULL THEN 'null'::jsonb
        ELSE to_jsonb(evidence.trust_rule_revision) END
    ))
  ) ORDER BY evidence.authenticated_at,evidence.id),'[]'::jsonb)
    INTO v_evidence
  FROM public.auth_session_mfa_evidence AS evidence
  WHERE evidence.tenant_id = v_tenant_id AND evidence.session_id = v_session_id;
  SELECT coalesce(jsonb_agg(jsonb_build_object(
    'policyId',pin.policy_id::text,'revision',pin.policy_revision
  ) ORDER BY pin.policy_id),'[]'::jsonb) INTO v_policies
  FROM public.auth_session_mfa_policy_pins AS pin
  WHERE pin.tenant_id = v_tenant_id AND pin.session_id = v_session_id;
  IF jsonb_array_length(v_evidence) NOT BETWEEN 1 AND 1024
     OR jsonb_array_length(v_policies) NOT BETWEEN 1 AND 1024 THEN
    RETURN NULL;
  END IF;

  WITH factor_rows AS (
    SELECT evidence.totp_factor_id AS factor_id,'totp'::text AS kind,
      factor.security_revision AS revision,factor.status = 'active' AS active
    FROM public.auth_session_mfa_evidence AS evidence
    JOIN public.tenant_totp_factors AS factor
      ON factor.tenant_id = evidence.tenant_id AND factor.id = evidence.totp_factor_id
    WHERE evidence.tenant_id = v_tenant_id AND evidence.session_id = v_session_id
      AND evidence.totp_factor_id IS NOT NULL
    UNION ALL
    SELECT evidence.webauthn_credential_id,'webauthn',credential.version,
      credential.status = 'active'
    FROM public.auth_session_mfa_evidence AS evidence
    JOIN public.tenant_webauthn_credentials AS credential
      ON credential.tenant_id = evidence.tenant_id
     AND credential.id = evidence.webauthn_credential_id
    WHERE evidence.tenant_id = v_tenant_id AND evidence.session_id = v_session_id
      AND evidence.webauthn_credential_id IS NOT NULL
    UNION ALL
    SELECT evidence.recovery_code_set_id,'recovery',code_set.security_revision,
      code_set.status = 'active'
    FROM public.auth_session_mfa_evidence AS evidence
    JOIN public.tenant_recovery_code_sets AS code_set
      ON code_set.tenant_id = evidence.tenant_id
     AND code_set.id = evidence.recovery_code_set_id
    WHERE evidence.tenant_id = v_tenant_id AND evidence.session_id = v_session_id
      AND evidence.recovery_code_set_id IS NOT NULL
  )
  SELECT coalesce(jsonb_agg(jsonb_build_object(
    'reference',jsonb_build_object(
      CASE factor.kind WHEN 'totp' THEN 'totpFactorId'
        WHEN 'webauthn' THEN 'webAuthnCredentialId'
        ELSE 'recoveryCodeSetId' END,
      factor.factor_id::text
    ),'revision',factor.revision,'active',factor.active
  ) ORDER BY factor.kind,factor.factor_id),'[]'::jsonb) INTO v_factors
  FROM factor_rows AS factor;

  SELECT coalesce(jsonb_agg(jsonb_build_object(
    'provider',jsonb_build_object(
      'scope','tenant','tenantId',v_tenant_id::text,
      'providerId',evidence.provider_id::text,
      'bindingId',evidence.binding_id::text
    ),
    'revision',evidence.trust_rule_revision,
    'active',EXISTS (
      SELECT 1 FROM public.tenant_federated_provider_policies AS policy
      WHERE policy.tenant_id = evidence.tenant_id
        AND policy.provider_id = evidence.provider_id
        AND policy.binding_id = evidence.binding_id
        AND policy.provider_kind = v_provenance.provider_kind
        AND policy.security_revision = evidence.trust_rule_revision
        AND policy.enabled
    )
  ) ORDER BY evidence.provider_id,evidence.binding_id,evidence.trust_rule_revision),
  '[]'::jsonb) INTO v_trust
  FROM (
    SELECT DISTINCT source.tenant_id,source.provider_id,source.binding_id,
      source.trust_rule_revision
    FROM public.auth_session_mfa_evidence AS source
    WHERE source.tenant_id = v_tenant_id
      AND source.session_id = v_session_id
      AND source.provider_id IS NOT NULL
  ) AS evidence;

  SELECT app.private_federated_assurance_requirement_v1(
    v_tenant_id,v_state.user_id,v_provenance.binding_id,binding.mapping_revision,
    'tenant.authentication.login',transaction_timestamp()
  ) INTO v_requirement
  FROM public.tenant_auth_provider_bindings AS binding
  WHERE binding.tenant_id = v_tenant_id AND binding.id = v_provenance.binding_id
    AND binding.provider_id = v_provenance.provider_id;

  RETURN jsonb_build_object(
    'lookup',p_lookup,
    'authenticationMethod',v_session.authentication_method,
    'snapshot',jsonb_build_object(
      'sessionId',v_session.id::text,
      'rotationFamilyId',v_session.rotation_family_id::text,
      'version',v_state.session_version,
      'tenantId',v_tenant_id::text,'userId',v_state.user_id::text,
      'identityEpoch',v_state.identity_epoch,
      'recoveryRestricted',v_state.recovery_restricted,
      'primary',jsonb_build_object(
        'kind','tenant_provider','primaryId',v_provenance.external_identity_id::text,
        'primaryRevision',v_provenance.external_identity_revision,
        'provider',jsonb_build_object(
          'scope','tenant','tenantId',v_tenant_id::text,
          'providerId',v_provenance.provider_id::text,
          'bindingId',v_provenance.binding_id::text
        ),
        'externalIdentityId',v_provenance.external_identity_id::text,
        'sessionInvalidationEpoch',v_state.session_invalidation_epoch,
        'authenticatedAt',to_jsonb(v_provenance.authenticated_at)
      ),
      'evidence',v_evidence,'policyRevisions',v_policies,
      'issuedAt',to_jsonb(v_state.issued_at),
      'idleExpiresAt',to_jsonb(v_session.idle_expires_at),
      'absoluteExpiresAt',to_jsonb(v_session.absolute_expires_at)
    ),
    'live',jsonb_build_object(
      'tenantId',v_tenant_id::text,'userId',v_state.user_id::text,
      'audience',v_audience,
      'sessionActive',v_session.revoked_at IS NULL
        AND v_session.idle_expires_at > transaction_timestamp()
        AND v_session.absolute_expires_at > transaction_timestamp(),
      'rotationFamilyActive',EXISTS (
        SELECT 1 FROM public.auth_sessions AS family
        WHERE family.user_id = v_state.user_id
          AND family.rotation_family_id = v_session.rotation_family_id
          AND family.revoked_at IS NULL
          AND family.idle_expires_at > transaction_timestamp()
          AND family.absolute_expires_at > transaction_timestamp()
      ),
      'userActive',v_user_active,'tenantActive',v_tenant_active,
      'membershipActive',v_membership_active,
      'identityEpoch',v_live_identity_epoch,
      'primaryActive',v_primary_active,
      'primaryRevision',v_live_primary_revision,
      'sessionInvalidationEpoch',v_live_session_epoch,
      'factors',v_factors,'trustRules',v_trust,'requirement',v_requirement
    )
  );
EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
  RETURN NULL;
WHEN invalid_text_representation OR data_exception THEN
  RAISE EXCEPTION 'invalid federated session lookup' USING ERRCODE = '22023';
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.apply_federated_session_revalidation_v1(p_mutation jsonb)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_session_id uuid;
  v_tenant_id uuid;
  v_user_id uuid;
  v_audience text;
  v_authentication_method text;
  v_expected_version bigint;
  v_observed_at timestamptz;
  v_decision text;
  v_reason text;
  v_request_digest bytea;
  v_session public.auth_sessions%ROWTYPE;
  v_state public.auth_session_mfa_states%ROWTYPE;
  v_provenance public.auth_session_federated_provenance%ROWTYPE;
  v_requirement jsonb;
  v_existing public.tenant_federated_session_revalidation_commands%ROWTYPE;
  v_result jsonb;
  v_reservation jsonb;
  v_new_session_id uuid;
  v_new_family_id uuid;
  v_token_digest bytea;
  v_csrf_digest bytea;
  v_idle_expires_at timestamptz;
  v_absolute_expires_at timestamptz;
  v_continuation_id uuid;
  v_receipt_digest bytea;
  v_continuation_expires_at timestamptz;
  v_token_lock bigint;
  v_csrf_lock bigint;
BEGIN
  PERFORM app.private_mfa_assert_json_object_v1(
    p_mutation,
    ARRAY['sessionId','tenantId','userId','audience','authenticationMethod',
      'expectedVersion','observedAt','decision','reason','requirement',
      'session','continuation'],
    ARRAY['sessionId','tenantId','userId','audience','authenticationMethod',
      'expectedVersion','observedAt','decision','reason','requirement'],262144
  );
  v_session_id := app.private_mfa_require_uuidv7_v1(p_mutation ->> 'sessionId');
  v_tenant_id := app.private_mfa_require_uuidv7_v1(p_mutation ->> 'tenantId');
  v_user_id := app.private_mfa_require_uuidv7_v1(p_mutation ->> 'userId');
  v_audience := p_mutation ->> 'audience';
  v_authentication_method := p_mutation ->> 'authenticationMethod';
  v_expected_version := (p_mutation ->> 'expectedVersion')::bigint;
  v_observed_at := (p_mutation ->> 'observedAt')::timestamptz;
  v_decision := p_mutation ->> 'decision';
  v_reason := p_mutation ->> 'reason';
  IF NOT app.private_mfa_safe_text_v1(v_audience,256)
     OR v_authentication_method NOT IN ('passkey','totp','recovery_code','oidc','saml')
     OR v_expected_version < 1 OR NOT isfinite(v_observed_at)
     OR right(p_mutation ->> 'observedAt',1) <> 'Z'
     OR date_trunc('microseconds',v_observed_at) <> v_observed_at
     OR jsonb_typeof(p_mutation -> 'requirement') <> 'object'
     OR NOT (
       (v_decision = 'usable' AND v_reason = 'current')
       OR (v_decision = 'rotate' AND v_reason = 'policy_refresh')
       OR (v_decision = 'step_up' AND v_reason IN (
         'assurance_insufficient','recovery_restricted'))
       OR (v_decision = 'revoke' AND v_reason IN (
         'lifecycle','identity_epoch','primary_drift','factor_drift',
         'trust_drift','expired'))
       OR (v_decision = 'deny' AND v_reason = 'malformed')
     ) OR (v_decision = 'rotate') <> (p_mutation ? 'session')
       OR (v_decision = 'step_up') <> (p_mutation ? 'continuation')
       OR (p_mutation ? 'session' AND p_mutation ? 'continuation') THEN
    RAISE EXCEPTION 'invalid federated session revalidation mutation'
      USING ERRCODE = '22023';
  END IF;

  SELECT session.* INTO STRICT v_session
  FROM public.auth_sessions AS session
  WHERE session.id = v_session_id AND session.user_id = v_user_id
    AND session.active_tenant_id = v_tenant_id
  FOR UPDATE;
  SELECT state.* INTO STRICT v_state
  FROM public.auth_session_mfa_states AS state
  WHERE state.tenant_id = v_tenant_id AND state.session_id = v_session_id
    AND state.user_id = v_user_id AND state.primary_kind = 'tenant_provider'
    AND state.audience = v_audience
  FOR UPDATE;
  SELECT provenance.* INTO STRICT v_provenance
  FROM public.auth_session_federated_provenance AS provenance
  WHERE provenance.tenant_id = v_tenant_id
    AND provenance.session_id = v_session_id
    AND provenance.user_id = v_user_id
    AND provenance.primary_kind = 'tenant_provider';
  IF v_session.authentication_method IS DISTINCT FROM v_authentication_method
     OR v_observed_at < v_state.issued_at
     OR abs(extract(epoch FROM (transaction_timestamp() - v_observed_at))) > 300
     OR NOT EXISTS (
       SELECT 1
       FROM public.tenant_mfa_subjects AS subject
       JOIN public.users AS local_user
         ON local_user.id = subject.user_id AND local_user.active
       JOIN public.tenants AS tenant
         ON tenant.id = subject.tenant_id AND tenant.status = 'active'
       JOIN public.tenant_memberships AS membership
         ON membership.tenant_id = subject.tenant_id
        AND membership.user_id = subject.user_id
        AND membership.status = 'active'
       JOIN public.tenant_federated_external_identities AS identity
         ON identity.tenant_id = subject.tenant_id
        AND identity.user_id = subject.user_id
        AND identity.id = v_provenance.external_identity_id
        AND identity.provider_id = v_provenance.provider_id
        AND identity.binding_id = v_provenance.binding_id
        AND identity.version = v_provenance.external_identity_revision
        AND identity.retired_at IS NULL
       JOIN public.tenant_auth_providers AS provider
         ON provider.tenant_id = identity.tenant_id
        AND provider.id = identity.provider_id
        AND provider.kind = v_provenance.provider_kind
        AND provider.enabled AND provider.archived_at IS NULL
       JOIN public.tenant_auth_provider_bindings AS binding
         ON binding.tenant_id = identity.tenant_id
        AND binding.id = identity.binding_id
        AND binding.provider_id = identity.provider_id
        AND binding.enabled AND binding.archived_at IS NULL
        AND binding.current_access_epoch_id IS NOT NULL
       JOIN public.tenant_federated_provider_policies AS policy
         ON policy.tenant_id = identity.tenant_id
        AND policy.provider_id = identity.provider_id
        AND policy.binding_id = identity.binding_id
        AND policy.provider_kind = provider.kind AND policy.enabled
        AND policy.security_revision = v_provenance.trust_rule_revision
       JOIN public.tenant_federated_provider_access_grants AS access_grant
         ON access_grant.tenant_id = identity.tenant_id
        AND access_grant.provider_id = identity.provider_id
        AND access_grant.binding_id = identity.binding_id
        AND access_grant.external_identity_id = identity.id
        AND access_grant.user_id = identity.user_id
        AND access_grant.membership_id = membership.id
        AND access_grant.access_epoch_id = binding.current_access_epoch_id
        AND access_grant.started_at <= v_observed_at
        AND access_grant.ended_at IS NULL
       JOIN public.tenant_identity_provider_access_epochs AS access_epoch
         ON access_epoch.tenant_id = access_grant.tenant_id
        AND access_epoch.id = access_grant.access_epoch_id
        AND access_epoch.binding_id = access_grant.binding_id
        AND access_epoch.provider_id = access_grant.provider_id
        AND access_epoch.source_id = access_grant.source_id
        AND access_epoch.started_at <= v_observed_at
        AND access_epoch.ended_at IS NULL
       JOIN public.tenant_authorization_sources AS source
         ON source.tenant_id = access_grant.tenant_id
        AND source.id = access_grant.source_id AND source.retired_at IS NULL
       WHERE subject.tenant_id = v_tenant_id AND subject.user_id = v_user_id
         AND subject.identity_epoch = v_state.identity_epoch
         AND subject.session_invalidation_epoch = v_state.session_invalidation_epoch
     ) THEN
    RAISE EXCEPTION 'federated session live authority drifted'
      USING ERRCODE = '40001';
  END IF;
  SELECT app.private_federated_assurance_requirement_v1(
    v_tenant_id,v_user_id,v_provenance.binding_id,binding.mapping_revision,
    'tenant.authentication.login',v_observed_at
  ) INTO STRICT v_requirement
  FROM public.tenant_auth_provider_bindings AS binding
  WHERE binding.tenant_id = v_tenant_id AND binding.id = v_provenance.binding_id
    AND binding.provider_id = v_provenance.provider_id
    AND binding.enabled AND binding.archived_at IS NULL;
  IF p_mutation -> 'requirement' IS DISTINCT FROM v_requirement THEN
    RAISE EXCEPTION 'federated session requirement drifted'
      USING ERRCODE = '40001';
  END IF;

  v_request_digest := sha256(convert_to(p_mutation::text,'UTF8'));
  SELECT command.* INTO v_existing
  FROM public.tenant_federated_session_revalidation_commands AS command
  WHERE command.tenant_id = v_tenant_id AND command.session_id = v_session_id
    AND command.expected_version = v_expected_version;
  IF FOUND THEN
    IF v_existing.request_digest = v_request_digest
       AND v_existing.decision = v_decision THEN
      RETURN v_existing.result_snapshot;
    END IF;
    RAISE EXCEPTION 'federated session command replay mismatch'
      USING ERRCODE = '40001';
  END IF;
  IF v_state.session_version <> v_expected_version THEN
    RAISE EXCEPTION 'federated session command lost CAS'
      USING ERRCODE = '40001';
  END IF;

  IF v_decision = 'rotate' THEN
    v_reservation := p_mutation -> 'session';
    PERFORM app.private_mfa_assert_json_object_v1(
      v_reservation,
      ARRAY['sessionId','familyId','tokenDigest','csrfDigest','authenticationMethod',
        'idleExpiresAt','absoluteExpiresAt'],
      ARRAY['sessionId','familyId','tokenDigest','csrfDigest','authenticationMethod',
        'idleExpiresAt','absoluteExpiresAt'],16384
    );
    v_new_session_id := app.private_mfa_require_uuidv7_v1(v_reservation ->> 'sessionId');
    v_new_family_id := app.private_mfa_require_uuidv7_v1(v_reservation ->> 'familyId');
    v_token_digest := app.private_mfa_decode_base64_v1(v_reservation ->> 'tokenDigest',32,32);
    v_csrf_digest := app.private_mfa_decode_base64_v1(v_reservation ->> 'csrfDigest',32,32);
    v_idle_expires_at := (v_reservation ->> 'idleExpiresAt')::timestamptz;
    v_absolute_expires_at := (v_reservation ->> 'absoluteExpiresAt')::timestamptz;
    IF v_new_session_id = v_new_family_id OR v_new_session_id = v_session_id
       OR v_new_family_id IS DISTINCT FROM v_session.rotation_family_id
       OR v_reservation ->> 'authenticationMethod' IS DISTINCT FROM v_authentication_method
       OR encode(v_token_digest,'hex') = repeat('00',32)
       OR encode(v_csrf_digest,'hex') = repeat('00',32)
       OR v_token_digest = v_csrf_digest
       OR v_idle_expires_at <= v_observed_at
       OR v_absolute_expires_at < v_idle_expires_at
       OR v_idle_expires_at > v_observed_at + interval '24 hours'
       OR v_absolute_expires_at > v_observed_at + interval '31 days'
       OR date_trunc('milliseconds',v_idle_expires_at) <> v_idle_expires_at
       OR date_trunc('milliseconds',v_absolute_expires_at) <> v_absolute_expires_at THEN
      RAISE EXCEPTION 'invalid federated session rotation reservation'
        USING ERRCODE = '22023';
    END IF;
    v_token_lock := hashtextextended(encode(v_token_digest,'hex'),73124201);
    v_csrf_lock := hashtextextended(encode(v_csrf_digest,'hex'),73124201);
    PERFORM pg_advisory_xact_lock(least(v_token_lock,v_csrf_lock));
    IF v_token_lock <> v_csrf_lock THEN
      PERFORM pg_advisory_xact_lock(greatest(v_token_lock,v_csrf_lock));
    END IF;
    IF EXISTS (
      SELECT 1 FROM public.auth_sessions AS collision
      WHERE collision.token_digest IN (v_token_digest,v_csrf_digest)
         OR collision.csrf_secret_digest IN (v_token_digest,v_csrf_digest)
    ) THEN
      RAISE EXCEPTION 'federated session rotation digest collision'
        USING ERRCODE = '40001';
    END IF;
    UPDATE public.auth_sessions AS source_session
    SET revoked_at = v_observed_at,revoke_reason = 'federated_session_rotated'
    WHERE source_session.id = v_session_id AND source_session.revoked_at IS NULL;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'federated session rotation lost CAS'
        USING ERRCODE = '40001';
    END IF;
    INSERT INTO public.auth_sessions (
      id,user_id,rotation_family_id,active_tenant_id,token_digest,
      csrf_secret_digest,authentication_method,mfa_satisfied_at,last_seen_at,
      idle_expires_at,absolute_expires_at,rotated_from_session_id,created_at
    ) VALUES (
      v_new_session_id,v_user_id,v_new_family_id,v_tenant_id,v_token_digest,
      v_csrf_digest,v_authentication_method,v_session.mfa_satisfied_at,
      v_observed_at,v_idle_expires_at,v_absolute_expires_at,v_session_id,
      v_observed_at
    );
    INSERT INTO public.auth_session_mfa_states (
      session_id,tenant_id,user_id,session_version,identity_epoch,
      recovery_restricted,audience,primary_kind,session_invalidation_epoch,issued_at
    ) VALUES (
      v_new_session_id,v_tenant_id,v_user_id,v_expected_version + 1,
      v_state.identity_epoch,v_state.recovery_restricted,v_audience,
      'tenant_provider',v_state.session_invalidation_epoch,v_observed_at
    );
    INSERT INTO public.auth_session_federated_provenance
    SELECT provenance.tenant_id,v_new_session_id,provenance.user_id,
      provenance.primary_kind,provenance.authentication_method,
      provenance.provider_id,provenance.binding_id,provenance.provider_kind,
      provenance.external_identity_id,provenance.external_identity_revision,
      provenance.trust_rule_revision,provenance.authenticated_at
    FROM public.auth_session_federated_provenance AS provenance
    WHERE provenance.tenant_id = v_tenant_id AND provenance.session_id = v_session_id;
    INSERT INTO public.auth_session_mfa_policy_pins
    SELECT pin.tenant_id,v_new_session_id,pin.policy_id,pin.policy_revision
    FROM public.auth_session_mfa_policy_pins AS pin
    WHERE pin.tenant_id = v_tenant_id AND pin.session_id = v_session_id;
    INSERT INTO public.auth_session_mfa_evidence
    SELECT uuidv7(),evidence.tenant_id,v_new_session_id,
      evidence.local_credential_id,evidence.totp_factor_id,
      evidence.webauthn_credential_id,evidence.recovery_code_set_id,
      evidence.level,evidence.kind,evidence.provider_id,evidence.binding_id,
      evidence.authenticated_at,evidence.expires_at,
      evidence.factor_revision,evidence.trust_rule_revision
    FROM public.auth_session_mfa_evidence AS evidence
    WHERE evidence.tenant_id = v_tenant_id AND evidence.session_id = v_session_id;
    UPDATE public.tenant_saml_session_materials AS material
    SET session_id = v_new_session_id
    WHERE material.tenant_id = v_tenant_id AND material.session_id = v_session_id;
  ELSIF v_decision = 'step_up' THEN
    v_reservation := p_mutation -> 'continuation';
    PERFORM app.private_mfa_assert_json_object_v1(
      v_reservation,ARRAY['continuationId','receiptDigest','expiresAt'],
      ARRAY['continuationId','receiptDigest','expiresAt'],8192
    );
    v_continuation_id := app.private_mfa_require_uuidv7_v1(
      v_reservation ->> 'continuationId'
    );
    v_receipt_digest := app.private_mfa_decode_base64_v1(
      v_reservation ->> 'receiptDigest',32,32
    );
    v_continuation_expires_at := (v_reservation ->> 'expiresAt')::timestamptz;
    IF encode(v_receipt_digest,'hex') = repeat('00',32)
       OR v_continuation_expires_at <= v_observed_at
       OR v_continuation_expires_at > v_observed_at + interval '15 minutes'
       OR date_trunc('microseconds',v_continuation_expires_at)
          <> v_continuation_expires_at THEN
      RAISE EXCEPTION 'invalid federated step-up continuation reservation'
        USING ERRCODE = '22023';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended(
      encode(v_receipt_digest,'hex'),77191203
    ));
    INSERT INTO public.tenant_post_primary_continuations (
      id,tenant_id,user_id,receipt_digest,identity_epoch,action,audience,
      primary_kind,provider_id,binding_id,provider_kind,external_identity_id,
      primary_revision,session_invalidation_epoch,state,version,created_at,expires_at
    ) VALUES (
      v_continuation_id,v_tenant_id,v_user_id,v_receipt_digest,
      v_state.identity_epoch,'session.create',v_audience,'tenant_provider',
      v_provenance.provider_id,v_provenance.binding_id,v_provenance.provider_kind,
      v_provenance.external_identity_id,v_provenance.external_identity_revision,
      v_state.session_invalidation_epoch,'pending',1,v_observed_at,
      v_continuation_expires_at
    );
    INSERT INTO public.tenant_post_primary_continuation_policy_pins
    SELECT pin.tenant_id,v_continuation_id,pin.policy_id,pin.policy_revision
    FROM public.auth_session_mfa_policy_pins AS pin
    WHERE pin.tenant_id = v_tenant_id AND pin.session_id = v_session_id;
    INSERT INTO public.tenant_post_primary_continuation_evidence (
      id,tenant_id,continuation_id,local_credential_id,totp_factor_id,
      webauthn_credential_id,recovery_code_set_id,level,kind,
      provider_id,binding_id,authenticated_at,expires_at,
      factor_revision,trust_rule_revision
    ) SELECT uuidv7(),evidence.tenant_id,v_continuation_id,
      evidence.local_credential_id,evidence.totp_factor_id,
      evidence.webauthn_credential_id,evidence.recovery_code_set_id,
      evidence.level,evidence.kind,evidence.provider_id,evidence.binding_id,
      evidence.authenticated_at,evidence.expires_at,
      evidence.factor_revision,evidence.trust_rule_revision
    FROM public.auth_session_mfa_evidence AS evidence
    WHERE evidence.tenant_id = v_tenant_id AND evidence.session_id = v_session_id;
    INSERT INTO public.tenant_saml_session_materials (
      id,tenant_id,continuation_id,user_id,provider_id,binding_id,
      provider_kind,external_identity_id,session_index_digest,
      key_version,ciphertext,created_at
    ) SELECT uuidv7(),material.tenant_id,v_continuation_id,material.user_id,
      material.provider_id,material.binding_id,material.provider_kind,
      material.external_identity_id,NULL,material.key_version,
      material.ciphertext,v_observed_at
    FROM public.tenant_saml_session_materials AS material
    WHERE material.tenant_id = v_tenant_id AND material.session_id = v_session_id;
    UPDATE public.auth_session_mfa_states AS state
    SET session_version = state.session_version + 1
    WHERE state.tenant_id = v_tenant_id AND state.session_id = v_session_id
      AND state.session_version = v_expected_version;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'federated session command lost CAS'
        USING ERRCODE = '40001';
    END IF;
  ELSE
    UPDATE public.auth_session_mfa_states AS state
    SET session_version = state.session_version + 1
    WHERE state.tenant_id = v_tenant_id AND state.session_id = v_session_id
      AND state.session_version = v_expected_version;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'federated session command lost CAS'
        USING ERRCODE = '40001';
    END IF;
    IF v_decision IN ('revoke','deny') THEN
      UPDATE public.auth_sessions AS family
      SET revoked_at = v_observed_at,
          revoke_reason = left('federated_revalidation_' || v_reason,500)
      WHERE family.user_id = v_user_id
        AND family.rotation_family_id = v_session.rotation_family_id
        AND family.revoked_at IS NULL;
    END IF;
  END IF;

  v_result := jsonb_strip_nulls(jsonb_build_object(
    'sessionId',v_session_id::text,'tenantId',v_tenant_id::text,
    'expectedVersion',v_expected_version,'decision',v_decision,
    'applied',true,'newSessionId',v_new_session_id::text,
    'continuationId',v_continuation_id::text
  ));
  IF pg_column_size(v_result) NOT BETWEEN 2 AND 65536 THEN
    RAISE EXCEPTION 'federated session result exceeds bound'
      USING ERRCODE = '54000';
  END IF;
  INSERT INTO public.tenant_federated_session_revalidation_commands (
    tenant_id,session_id,expected_version,request_digest,decision,
    result_snapshot,applied_at
  ) VALUES (
    v_tenant_id,v_session_id,v_expected_version,v_request_digest,v_decision,
    v_result,v_observed_at
  );
  RETURN v_result;
EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
  RAISE EXCEPTION 'federated session authority unavailable'
    USING ERRCODE = '40001';
WHEN invalid_text_representation OR numeric_value_out_of_range
  OR data_exception THEN
  RAISE EXCEPTION 'invalid federated session revalidation mutation'
    USING ERRCODE = '22023';
END;
$function$;
--> statement-breakpoint

ALTER FUNCTION app.load_federated_session_revalidation_v1(jsonb)
  OWNER TO periapsis_migrator;
--> statement-breakpoint
ALTER FUNCTION app.apply_federated_session_revalidation_v1(jsonb)
  OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.load_federated_session_revalidation_v1(jsonb)
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner, periapsis_sla_api_owner,
  periapsis_sla_worker_owner, periapsis_sla_readiness_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.apply_federated_session_revalidation_v1(jsonb)
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner, periapsis_sla_api_owner,
  periapsis_sla_worker_owner, periapsis_sla_readiness_owner;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.load_federated_session_revalidation_v1(jsonb),
  app.apply_federated_session_revalidation_v1(jsonb)
TO periapsis_api;
--> statement-breakpoint
