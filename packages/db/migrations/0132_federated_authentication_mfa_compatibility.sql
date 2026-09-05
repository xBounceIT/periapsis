-- Preserve the sealed MFA ABI while adding the tenant-provider provenance
-- branch introduced by federation.  The legacy implementation remains the
-- sole path for local/passkey primaries.

CREATE FUNCTION app.private_mfa_apply_federated_session_v1(
  p_session jsonb,
  p_anchor_id uuid,
  p_evidence_kind text,
  p_evidence_id uuid,
  p_evidence_revision bigint,
  p_completed_at timestamptz
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_anchor public.tenant_mfa_authority_anchors%ROWTYPE;
  v_binding jsonb;
  v_mutation text;
  v_reservation jsonb;
  v_tenant_id uuid;
  v_user_id uuid;
  v_membership_id uuid;
  v_identity_epoch bigint;
  v_session_epoch bigint;
  v_source_session public.auth_sessions%ROWTYPE;
  v_source_state public.auth_session_mfa_states%ROWTYPE;
  v_continuation public.tenant_post_primary_continuations%ROWTYPE;
  v_new_session_id uuid;
  v_new_family_id uuid;
  v_token_digest bytea;
  v_csrf_digest bytea;
  v_authentication_method text;
  v_idle_expires_at timestamptz;
  v_absolute_expires_at timestamptz;
  v_token_lock bigint;
  v_csrf_lock bigint;
  v_new_version bigint;
  v_provider_id uuid;
  v_binding_id uuid;
  v_provider_kind public.auth_provider_kind;
  v_external_identity_id uuid;
  v_external_identity_revision bigint;
  v_provider_authentication_method text;
  v_provider_security_revision bigint;
  v_primary_authenticated_at timestamptz;
  v_evidence_count bigint;
  v_consumed_continuation_id uuid;
BEGIN
  PERFORM app.private_mfa_assert_json_object_v1(
    p_session,
    ARRAY['mutation','expectedSessionId','expectedFamilyId','expectedContinuationId',
      'expectedAnchorVersion','expectedIdentityEpoch','expectedAnchorExpiry',
      'audience','requirement','recoveryRestricted','reservation'],
    ARRAY['mutation','expectedAnchorVersion','expectedIdentityEpoch',
      'expectedAnchorExpiry','audience','requirement','recoveryRestricted','reservation'],
    131072
  );
  SELECT anchor.* INTO STRICT v_anchor
  FROM public.tenant_mfa_authority_anchors AS anchor
  WHERE anchor.id = p_anchor_id
  FOR UPDATE;
  v_binding := app.private_mfa_anchor_binding_v1(p_anchor_id);
  v_mutation := p_session ->> 'mutation';
  IF v_anchor.flow NOT IN ('session','continuation')
     OR v_mutation NOT IN ('rotate','consume_continuation')
     OR NOT app.private_mfa_safe_text_v1(p_session ->> 'audience',256)
     OR p_session ->> 'audience' IS DISTINCT FROM v_anchor.audience
     OR jsonb_typeof(p_session -> 'requirement') <> 'object'
     OR p_session -> 'requirement' IS DISTINCT FROM v_binding -> 'requirement'
     OR (p_session ->> 'expectedAnchorVersion')::bigint
          IS DISTINCT FROM v_anchor.anchor_version
     OR (p_session ->> 'expectedIdentityEpoch')::bigint
          IS DISTINCT FROM v_anchor.identity_epoch
     OR (p_session ->> 'expectedAnchorExpiry')::timestamptz
          IS DISTINCT FROM v_anchor.anchor_expires_at
     OR p_completed_at IS NULL
     OR abs(extract(epoch FROM (transaction_timestamp() - p_completed_at))) > 300 THEN
    RAISE EXCEPTION 'federated MFA session intent drifted'
      USING ERRCODE = '40001';
  END IF;
  v_tenant_id := v_anchor.tenant_id;
  v_user_id := v_anchor.user_id;
  v_identity_epoch := v_anchor.identity_epoch;
  SELECT subject.session_invalidation_epoch,membership.id
    INTO STRICT v_session_epoch,v_membership_id
  FROM public.tenant_mfa_subjects AS subject
  JOIN public.tenant_memberships AS membership
    ON membership.tenant_id = subject.tenant_id
   AND membership.user_id = subject.user_id AND membership.status = 'active'
  JOIN public.users AS identity
    ON identity.id = subject.user_id AND identity.active
  JOIN public.tenants AS tenant
    ON tenant.id = subject.tenant_id AND tenant.status = 'active'
  WHERE subject.tenant_id = v_tenant_id AND subject.user_id = v_user_id
    AND subject.identity_epoch = v_identity_epoch;

  v_reservation := p_session -> 'reservation';
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
  v_authentication_method := v_reservation ->> 'authenticationMethod';
  v_idle_expires_at := (v_reservation ->> 'idleExpiresAt')::timestamptz;
  v_absolute_expires_at := (v_reservation ->> 'absoluteExpiresAt')::timestamptz;
  IF v_authentication_method NOT IN ('passkey','totp','recovery_code')
     OR encode(v_token_digest,'hex') = repeat('00',32)
     OR encode(v_csrf_digest,'hex') = repeat('00',32)
     OR v_token_digest = v_csrf_digest
     OR v_new_session_id = v_new_family_id
     OR v_idle_expires_at <= p_completed_at
     OR v_absolute_expires_at < v_idle_expires_at
     OR v_idle_expires_at > p_completed_at + interval '24 hours'
     OR v_absolute_expires_at > p_completed_at + interval '31 days'
     OR date_trunc('milliseconds',v_idle_expires_at) <> v_idle_expires_at
     OR date_trunc('milliseconds',v_absolute_expires_at) <> v_absolute_expires_at THEN
    RAISE EXCEPTION 'invalid federated MFA session reservation'
      USING ERRCODE = '22023';
  END IF;
  v_token_lock := hashtextextended(encode(v_token_digest,'hex'),73124201);
  v_csrf_lock := hashtextextended(encode(v_csrf_digest,'hex'),73124201);
  PERFORM pg_advisory_xact_lock(least(v_token_lock,v_csrf_lock));
  IF v_token_lock <> v_csrf_lock THEN
    PERFORM pg_advisory_xact_lock(greatest(v_token_lock,v_csrf_lock));
  END IF;
  IF EXISTS (
    SELECT 1 FROM public.auth_sessions AS session
    WHERE session.token_digest IN (v_token_digest,v_csrf_digest)
       OR session.csrf_secret_digest IN (v_token_digest,v_csrf_digest)
  ) THEN
    RAISE EXCEPTION 'federated MFA session digest collision'
      USING ERRCODE = '40001';
  END IF;

  IF v_anchor.flow = 'session' THEN
    IF v_mutation <> 'rotate'
       OR app.private_mfa_require_uuidv7_v1(p_session ->> 'expectedSessionId')
          IS DISTINCT FROM v_anchor.session_id
       OR app.private_mfa_require_uuidv7_v1(p_session ->> 'expectedFamilyId')
          IS DISTINCT FROM v_anchor.session_family_id
       OR p_session ? 'expectedContinuationId'
       OR v_new_family_id IS DISTINCT FROM v_anchor.session_family_id
       OR v_new_session_id = v_anchor.session_id THEN
      RAISE EXCEPTION 'invalid federated session rotation intent'
        USING ERRCODE = '22023';
    END IF;
    SELECT session.* INTO STRICT v_source_session
    FROM public.auth_sessions AS session
    WHERE session.id = v_anchor.session_id AND session.user_id = v_user_id
      AND session.rotation_family_id = v_anchor.session_family_id
      AND session.active_tenant_id = v_tenant_id
      AND session.revoked_at IS NULL
      AND session.idle_expires_at = v_anchor.anchor_expires_at
      AND session.idle_expires_at > p_completed_at
      AND session.absolute_expires_at > p_completed_at
    FOR UPDATE;
    SELECT state.* INTO STRICT v_source_state
    FROM public.auth_session_mfa_states AS state
    WHERE state.tenant_id = v_tenant_id AND state.session_id = v_anchor.session_id
      AND state.user_id = v_user_id AND state.primary_kind = 'tenant_provider'
      AND state.session_version = v_anchor.anchor_version
      AND state.identity_epoch = v_identity_epoch
      AND state.session_invalidation_epoch = v_session_epoch
    FOR UPDATE;
    SELECT provenance.provider_id,provenance.binding_id,provenance.provider_kind,
      provenance.external_identity_id,provenance.external_identity_revision,
      provenance.authentication_method,provenance.trust_rule_revision,
      provenance.authenticated_at
      INTO STRICT v_provider_id,v_binding_id,v_provider_kind,
        v_external_identity_id,v_external_identity_revision,
        v_provider_authentication_method,v_provider_security_revision,
        v_primary_authenticated_at
    FROM public.auth_session_federated_provenance AS provenance
    WHERE provenance.tenant_id = v_tenant_id
      AND provenance.session_id = v_source_state.session_id
      AND provenance.user_id = v_user_id;
    UPDATE public.auth_sessions AS session
    SET revoked_at = p_completed_at,revoke_reason = 'mfa_session_rotated'
    WHERE session.id = v_source_session.id AND session.revoked_at IS NULL;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'federated session rotation lost CAS'
        USING ERRCODE = '40001';
    END IF;
    v_new_version := v_anchor.anchor_version + 1;
  ELSE
    IF v_mutation <> 'consume_continuation'
       OR app.private_mfa_require_uuidv7_v1(p_session ->> 'expectedContinuationId')
          IS DISTINCT FROM v_anchor.continuation_id
       OR p_session ? 'expectedSessionId' OR p_session ? 'expectedFamilyId' THEN
      RAISE EXCEPTION 'invalid federated continuation consumption intent'
        USING ERRCODE = '22023';
    END IF;
    SELECT continuation.* INTO STRICT v_continuation
    FROM public.tenant_post_primary_continuations AS continuation
    WHERE continuation.tenant_id = v_tenant_id
      AND continuation.id = v_anchor.continuation_id
      AND continuation.user_id = v_user_id
      AND continuation.identity_epoch = v_identity_epoch
      AND continuation.session_invalidation_epoch = v_session_epoch
      AND continuation.primary_kind = 'tenant_provider'
      AND continuation.state = 'pending'
      AND continuation.version = v_anchor.anchor_version
      AND continuation.expires_at = v_anchor.anchor_expires_at
      AND continuation.expires_at > p_completed_at
    FOR UPDATE;
    v_provider_id := v_continuation.provider_id;
    v_binding_id := v_continuation.binding_id;
    v_provider_kind := v_continuation.provider_kind;
    v_provider_authentication_method := v_provider_kind::text;
    v_external_identity_id := v_continuation.external_identity_id;
    v_external_identity_revision := v_continuation.primary_revision;
    v_primary_authenticated_at := v_continuation.created_at;
    SELECT policy.security_revision INTO STRICT v_provider_security_revision
    FROM public.tenant_federated_provider_policies AS policy
    WHERE policy.tenant_id = v_tenant_id AND policy.provider_id = v_provider_id
      AND policy.binding_id = v_binding_id
      AND policy.provider_kind = v_provider_kind AND policy.enabled;
    UPDATE public.tenant_post_primary_continuations AS continuation
    SET state = 'consumed',version = continuation.version + 1,
        consumed_at = p_completed_at
    WHERE continuation.tenant_id = v_tenant_id
      AND continuation.id = v_continuation.id
      AND continuation.state = 'pending'
      AND continuation.version = v_continuation.version
    RETURNING continuation.version,continuation.id
      INTO v_new_version,v_consumed_continuation_id;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'federated continuation consumption lost CAS'
        USING ERRCODE = '40001';
    END IF;
  END IF;

  -- Live provider, binding, identity and access authority are checked after
  -- the anchor is locked and before successor authority is issued.
  IF NOT EXISTS (
    SELECT 1
    FROM public.tenant_auth_providers AS provider
    JOIN public.tenant_auth_provider_bindings AS binding
      ON binding.tenant_id = provider.tenant_id
     AND binding.provider_id = provider.id AND binding.id = v_binding_id
     AND binding.enabled AND binding.archived_at IS NULL
     AND binding.current_access_epoch_id IS NOT NULL
    JOIN public.tenant_federated_provider_policies AS policy
      ON policy.tenant_id = provider.tenant_id
     AND policy.provider_id = provider.id AND policy.binding_id = binding.id
     AND policy.provider_kind = provider.kind AND policy.enabled
    JOIN public.tenant_federated_external_identities AS external_identity
      ON external_identity.tenant_id = provider.tenant_id
     AND external_identity.provider_id = provider.id
     AND external_identity.binding_id = binding.id
     AND external_identity.id = v_external_identity_id
     AND external_identity.user_id = v_user_id
     AND external_identity.version = v_external_identity_revision
     AND external_identity.retired_at IS NULL
    JOIN public.tenant_federated_provider_access_grants AS access_grant
      ON access_grant.tenant_id = external_identity.tenant_id
     AND access_grant.provider_id = external_identity.provider_id
     AND access_grant.binding_id = external_identity.binding_id
     AND access_grant.external_identity_id = external_identity.id
     AND access_grant.user_id = external_identity.user_id
     AND access_grant.membership_id = v_membership_id
     AND access_grant.access_epoch_id = binding.current_access_epoch_id
     AND access_grant.started_at <= p_completed_at
     AND access_grant.ended_at IS NULL
    JOIN public.tenant_identity_provider_access_epochs AS access_epoch
      ON access_epoch.tenant_id = access_grant.tenant_id
     AND access_epoch.id = access_grant.access_epoch_id
     AND access_epoch.binding_id = access_grant.binding_id
     AND access_epoch.provider_id = access_grant.provider_id
     AND access_epoch.source_id = access_grant.source_id
     AND access_epoch.started_at <= p_completed_at
     AND access_epoch.ended_at IS NULL
    JOIN public.tenant_authorization_sources AS source
      ON source.tenant_id = access_grant.tenant_id
     AND source.id = access_grant.source_id AND source.retired_at IS NULL
    WHERE provider.tenant_id = v_tenant_id AND provider.id = v_provider_id
      AND provider.kind = v_provider_kind AND provider.enabled
      AND provider.archived_at IS NULL
      AND policy.security_revision = v_provider_security_revision
  ) THEN
    RAISE EXCEPTION 'federated primary authority is stale'
      USING ERRCODE = '40001';
  END IF;

  INSERT INTO public.auth_sessions (
    id,user_id,rotation_family_id,active_tenant_id,token_digest,
    csrf_secret_digest,authentication_method,mfa_satisfied_at,last_seen_at,
    idle_expires_at,absolute_expires_at,rotated_from_session_id,created_at
  ) VALUES (
    v_new_session_id,v_user_id,v_new_family_id,v_tenant_id,v_token_digest,
    v_csrf_digest,v_authentication_method,p_completed_at,p_completed_at,
    v_idle_expires_at,v_absolute_expires_at,
    CASE WHEN v_anchor.flow = 'session' THEN v_anchor.session_id END,
    p_completed_at
  );
  INSERT INTO public.auth_session_mfa_states (
    session_id,tenant_id,user_id,session_version,identity_epoch,
    recovery_restricted,audience,primary_kind,session_invalidation_epoch,issued_at
  ) VALUES (
    v_new_session_id,v_tenant_id,v_user_id,v_new_version,v_identity_epoch,
    (p_session ->> 'recoveryRestricted')::boolean,v_anchor.audience,
    'tenant_provider',v_session_epoch,p_completed_at
  );
  INSERT INTO public.auth_session_federated_provenance (
    tenant_id,session_id,user_id,primary_kind,authentication_method,
    provider_id,binding_id,provider_kind,external_identity_id,
    external_identity_revision,trust_rule_revision,authenticated_at
  ) VALUES (
    v_tenant_id,v_new_session_id,v_user_id,'tenant_provider',
    v_provider_authentication_method,v_provider_id,v_binding_id,v_provider_kind,
    v_external_identity_id,v_external_identity_revision,
    v_provider_security_revision,v_primary_authenticated_at
  );

  IF v_anchor.flow = 'session' THEN
    UPDATE public.tenant_saml_session_materials AS material
    SET session_id = v_new_session_id
    WHERE material.tenant_id = v_tenant_id
      AND material.session_id = v_anchor.session_id
      AND material.user_id = v_user_id
      AND material.provider_id = v_provider_id
      AND material.binding_id = v_binding_id
      AND material.external_identity_id = v_external_identity_id;
  ELSE
    UPDATE public.tenant_saml_session_materials AS material
    SET session_id = v_new_session_id,continuation_id = NULL
    WHERE material.tenant_id = v_tenant_id
      AND material.continuation_id = v_anchor.continuation_id
      AND material.user_id = v_user_id
      AND material.provider_id = v_provider_id
      AND material.binding_id = v_binding_id
      AND material.external_identity_id = v_external_identity_id;
  END IF;

  INSERT INTO public.auth_session_mfa_policy_pins (
    tenant_id,session_id,policy_id,policy_revision
  ) SELECT pin.tenant_id,v_new_session_id,pin.policy_id,pin.policy_revision
  FROM public.tenant_mfa_authority_policy_pins AS pin
  WHERE pin.tenant_id = v_tenant_id AND pin.anchor_id = v_anchor.id;

  SELECT count(*) INTO v_evidence_count
  FROM public.tenant_mfa_authority_evidence AS evidence
  WHERE evidence.tenant_id = v_tenant_id AND evidence.anchor_id = v_anchor.id;
  IF p_evidence_kind IS NOT NULL THEN v_evidence_count := v_evidence_count + 1; END IF;
  IF v_evidence_count NOT BETWEEN 1 AND 1024 THEN
    RAISE EXCEPTION 'federated MFA evidence snapshot limit reached'
      USING ERRCODE = '22023';
  END IF;
  INSERT INTO public.auth_session_mfa_evidence (
    id,tenant_id,session_id,local_credential_id,totp_factor_id,
    webauthn_credential_id,recovery_code_set_id,level,kind,
    provider_id,binding_id,authenticated_at,expires_at,
    factor_revision,trust_rule_revision
  ) SELECT uuidv7(),evidence.tenant_id,v_new_session_id,
    evidence.local_credential_id,evidence.totp_factor_id,
    evidence.webauthn_credential_id,evidence.recovery_code_set_id,
    evidence.level,evidence.kind,evidence.provider_id,evidence.binding_id,
    evidence.authenticated_at,evidence.expires_at,
    evidence.factor_revision,evidence.trust_rule_revision
  FROM public.tenant_mfa_authority_evidence AS evidence
  WHERE evidence.tenant_id = v_tenant_id AND evidence.anchor_id = v_anchor.id;
  IF p_evidence_kind IS NOT NULL THEN
    IF p_evidence_kind NOT IN ('totp','webauthn','recovery')
       OR p_evidence_id IS NULL OR p_evidence_revision < 1 THEN
      RAISE EXCEPTION 'invalid typed MFA evidence' USING ERRCODE = '22023';
    END IF;
    INSERT INTO public.auth_session_mfa_evidence (
      id,tenant_id,session_id,totp_factor_id,webauthn_credential_id,
      recovery_code_set_id,level,kind,authenticated_at,factor_revision
    ) VALUES (
      uuidv7(),v_tenant_id,v_new_session_id,
      CASE WHEN p_evidence_kind = 'totp' THEN p_evidence_id END,
      CASE WHEN p_evidence_kind = 'webauthn' THEN p_evidence_id END,
      CASE WHEN p_evidence_kind = 'recovery' THEN p_evidence_id END,
      CASE WHEN p_evidence_kind = 'webauthn' THEN 'phishing_resistant' ELSE 'mfa' END,
      p_evidence_kind,p_completed_at,p_evidence_revision
    );
  END IF;
  RETURN jsonb_strip_nulls(jsonb_build_object(
    'mutation',v_mutation,'newSessionId',v_new_session_id::text,
    'newSessionFamilyId',v_new_family_id::text,
    'consumedContinuationId',v_consumed_continuation_id::text,
    'sessionVersion',v_new_version,
    'recoveryRestricted',(p_session ->> 'recoveryRestricted')::boolean
  ));
EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
  RAISE EXCEPTION 'federated MFA session precondition is unavailable or ambiguous'
    USING ERRCODE = '40001';
END;
$function$;
--> statement-breakpoint

ALTER FUNCTION app.private_mfa_apply_session_v1(
  jsonb,uuid,text,uuid,bigint,text,uuid,bigint,timestamptz
) RENAME TO private_mfa_apply_session_legacy_v1;
--> statement-breakpoint

-- sqlc does not update its function catalog for ALTER FUNCTION ... RENAME.
-- PostgreSQL sees this as a no-op because the canonical function was renamed;
-- the disposable sqlc schema sees the old catalog entry removed before the
-- successor with the same signature is created.
DROP FUNCTION IF EXISTS app.private_mfa_apply_session_v1(
  jsonb,uuid,text,uuid,bigint,text,uuid,bigint,timestamptz
);
--> statement-breakpoint

CREATE FUNCTION app.private_mfa_apply_session_v1(
  p_session jsonb,
  p_anchor_id uuid,
  p_primary_kind text,
  p_primary_id uuid,
  p_primary_revision bigint,
  p_evidence_kind text,
  p_evidence_id uuid,
  p_evidence_revision bigint,
  p_completed_at timestamptz
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_flow text;
  v_primary text;
  v_mutation text := p_session ->> 'mutation';
BEGIN
  SELECT anchor.flow INTO STRICT v_flow
  FROM public.tenant_mfa_authority_anchors AS anchor
  WHERE anchor.id = p_anchor_id;
  IF v_flow = 'session' THEN
    SELECT state.primary_kind INTO STRICT v_primary
    FROM public.tenant_mfa_authority_anchors AS anchor
    JOIN public.auth_session_mfa_states AS state
      ON state.tenant_id = anchor.tenant_id
     AND state.session_id = anchor.session_id
     AND state.user_id = anchor.user_id
    WHERE anchor.id = p_anchor_id;
  ELSIF v_flow = 'continuation' THEN
    SELECT continuation.primary_kind INTO STRICT v_primary
    FROM public.tenant_mfa_authority_anchors AS anchor
    JOIN public.tenant_post_primary_continuations AS continuation
      ON continuation.tenant_id = anchor.tenant_id
     AND continuation.id = anchor.continuation_id
     AND continuation.user_id = anchor.user_id
    WHERE anchor.id = p_anchor_id;
  END IF;
  IF v_primary = 'tenant_provider'
     AND ((v_flow = 'session' AND v_mutation = 'rotate')
       OR (v_flow = 'continuation' AND v_mutation = 'consume_continuation')) THEN
    IF p_primary_kind IS NOT NULL OR p_primary_id IS NOT NULL
       OR p_primary_revision IS NOT NULL THEN
      RAISE EXCEPTION 'federated primary override is forbidden'
        USING ERRCODE = '22023';
    END IF;
    RETURN app.private_mfa_apply_federated_session_v1(
      p_session,p_anchor_id,p_evidence_kind,p_evidence_id,
      p_evidence_revision,p_completed_at
    );
  END IF;
  RETURN app.private_mfa_apply_session_legacy_v1(
    p_session,p_anchor_id,p_primary_kind,p_primary_id,p_primary_revision,
    p_evidence_kind,p_evidence_id,p_evidence_revision,p_completed_at
  );
END;
$function$;
--> statement-breakpoint

ALTER FUNCTION app.private_mfa_apply_federated_session_v1(
  jsonb,uuid,text,uuid,bigint,timestamptz
) OWNER TO periapsis_migrator;
--> statement-breakpoint
ALTER FUNCTION app.private_mfa_apply_session_v1(
  jsonb,uuid,text,uuid,bigint,text,uuid,bigint,timestamptz
) OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_mfa_apply_federated_session_v1(
  jsonb,uuid,text,uuid,bigint,timestamptz
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner, periapsis_sla_api_owner,
  periapsis_sla_worker_owner, periapsis_sla_readiness_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_mfa_apply_session_v1(
  jsonb,uuid,text,uuid,bigint,text,uuid,bigint,timestamptz
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner, periapsis_sla_api_owner,
  periapsis_sla_worker_owner, periapsis_sla_readiness_owner;
--> statement-breakpoint
