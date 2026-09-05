-- The MFA runtime receives only bounded, typed JSON projections.  Every
-- mutating entrypoint is SECURITY DEFINER and owns the complete transaction;
-- the API role has no direct table privileges.
CREATE FUNCTION app.private_mfa_assert_json_object_v1(
  p_payload jsonb,
  p_allowed_keys text[],
  p_required_keys text[],
  p_maximum_bytes integer DEFAULT 2097152
)
RETURNS void
LANGUAGE plpgsql
IMMUTABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF p_payload IS NULL
     OR jsonb_typeof(p_payload) <> 'object'
     OR p_maximum_bytes NOT BETWEEN 2 AND 2097152
     OR octet_length(convert_to(p_payload::text, 'UTF8')) > p_maximum_bytes
     OR EXISTS (
       SELECT 1 FROM jsonb_object_keys(p_payload) AS key(value)
       WHERE NOT (key.value = ANY(p_allowed_keys))
     )
     OR EXISTS (
       SELECT 1 FROM unnest(p_required_keys) AS key(value)
       WHERE NOT (p_payload ? key.value) OR p_payload -> key.value = 'null'::jsonb
     ) THEN
    RAISE EXCEPTION 'invalid MFA JSON envelope' USING ERRCODE = '22023';
  END IF;
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_mfa_complete_webauthn_registration_v1(
  p_request jsonb,
  p_display_name text
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_ceremony_id bytea;
  v_ceremony public.tenant_webauthn_ceremonies%ROWTYPE;
  v_anchor public.tenant_mfa_authority_anchors%ROWTYPE;
  v_request_digest bytea;
  v_credential jsonb;
  v_internal_id uuid := uuidv7();
  v_display_name text := p_display_name;
  v_transport jsonb;
  v_result jsonb;
BEGIN
  PERFORM app.private_mfa_assert_json_object_v1(
    p_request,
    ARRAY['ceremonyId','expectedCeremonyVersion','binding','completedAt',
      'credential','aaguid','attestationFormat','attestationType',
      'attestationTrusted','metadataRevision'],
    ARRAY['ceremonyId','expectedCeremonyVersion','binding','completedAt',
      'credential','aaguid','attestationFormat','attestationType',
      'attestationTrusted','metadataRevision']
  );
  v_credential := p_request -> 'credential';
  PERFORM app.private_mfa_assert_json_object_v1(
    v_credential,
    ARRAY['id','publicKey','tenantId','userId','identityEpoch','userHandleDigest',
      'rpId','rpRevision','version','status','signCount','discoverable',
      'userVerification','backupEligible','backedUp','transports'],
    ARRAY['id','publicKey','tenantId','userId','identityEpoch','userHandleDigest',
      'rpId','rpRevision','version','status','signCount','discoverable',
      'userVerification','backupEligible','backedUp','transports']
  );
  v_ceremony_id := app.private_mfa_decode_base64_v1(p_request ->> 'ceremonyId', 32, 32);
  v_request_digest := app.private_mfa_request_digest_v1(p_request);
  SELECT ceremony.* INTO STRICT v_ceremony
  FROM public.tenant_webauthn_ceremonies AS ceremony
  WHERE ceremony.id = v_ceremony_id
  FOR UPDATE;
  IF v_ceremony.state = 'completed' THEN
    IF v_ceremony.completion_request_digest = v_request_digest THEN
      RETURN v_ceremony.result_snapshot;
    END IF;
    RAISE EXCEPTION 'WebAuthn registration replay mismatch' USING ERRCODE = '40001';
  END IF;
  SELECT anchor.* INTO STRICT v_anchor
  FROM public.tenant_mfa_authority_anchors AS anchor
  WHERE anchor.id = v_ceremony.authority_anchor_id;
  IF v_ceremony.state <> 'claimed' OR v_ceremony.purpose <> 'registration'
     OR v_ceremony.version <> (p_request ->> 'expectedCeremonyVersion')::bigint
     OR v_ceremony.expires_at < (p_request ->> 'completedAt')::timestamptz
     OR p_request -> 'binding' IS DISTINCT FROM app.private_mfa_anchor_binding_v1(
       v_ceremony.authority_anchor_id, 'registration'
     )
     OR app.private_mfa_require_uuidv7_v1(v_credential ->> 'tenantId') IS DISTINCT FROM v_anchor.tenant_id
     OR app.private_mfa_require_uuidv7_v1(v_credential ->> 'userId') IS DISTINCT FROM v_anchor.user_id
     OR (v_credential ->> 'identityEpoch')::bigint IS DISTINCT FROM v_anchor.identity_epoch
     OR app.private_mfa_decode_base64_v1(v_credential ->> 'userHandleDigest', 32, 32)
          IS DISTINCT FROM v_ceremony.user_handle_digest
     OR v_credential ->> 'rpId' IS DISTINCT FROM v_ceremony.rp_id
     OR (v_credential ->> 'rpRevision')::bigint IS DISTINCT FROM v_ceremony.rp_revision
     OR (v_credential ->> 'version')::bigint <> 1
     OR v_credential ->> 'status' <> 'active'
     OR (v_credential ->> 'signCount')::bigint NOT BETWEEN 0 AND 4294967295
     OR ((v_credential ->> 'backedUp')::boolean AND NOT (v_credential ->> 'backupEligible')::boolean)
     OR jsonb_typeof(v_credential -> 'transports') <> 'array'
     OR jsonb_array_length(v_credential -> 'transports') > 6
     OR (SELECT count(DISTINCT value) FROM jsonb_array_elements(v_credential -> 'transports'))
          <> jsonb_array_length(v_credential -> 'transports')
     OR NOT app.private_mfa_safe_text_v1(p_request ->> 'attestationFormat', 64)
     OR p_request ->> 'attestationType' NOT IN ('none','self','basic','enterprise')
     OR (p_request ->> 'metadataRevision')::bigint IS DISTINCT FROM v_ceremony.metadata_revision THEN
    RAISE EXCEPTION 'WebAuthn registration completion is stale or invalid' USING ERRCODE = '40001';
  END IF;
  IF NOT app.private_mfa_safe_text_v1(v_display_name, 120) THEN
    RAISE EXCEPTION 'invalid passkey display name' USING ERRCODE = '22023';
  END IF;
  PERFORM 1
  FROM public.tenant_mfa_subjects AS subject
  WHERE subject.tenant_id = v_anchor.tenant_id
    AND subject.user_id = v_anchor.user_id
  FOR UPDATE;
  IF NOT FOUND OR (
    SELECT count(*) FROM public.tenant_webauthn_credentials AS credential
    WHERE credential.tenant_id = v_anchor.tenant_id
      AND credential.user_id = v_anchor.user_id
      AND credential.status = 'active'
  ) >= 128 THEN
    RAISE EXCEPTION 'active passkey limit reached' USING ERRCODE = '22023';
  END IF;
  INSERT INTO public.tenant_webauthn_credentials (
    id, tenant_id, user_id, credential_id, public_key, display_name,
    user_handle_digest, rp_id, rp_revision, sign_count, discoverable,
    user_verification, backup_eligible, backed_up, aaguid,
    attestation_format, attestation_type, attestation_trusted,
    metadata_revision, status, version, created_at, updated_at
  ) VALUES (
    v_internal_id, v_anchor.tenant_id, v_anchor.user_id,
    app.private_mfa_decode_base64_v1(v_credential ->> 'id', 1, 4096),
    app.private_mfa_decode_base64_v1(v_credential ->> 'publicKey', 32, 65536),
    v_display_name,
    app.private_mfa_decode_base64_v1(v_credential ->> 'userHandleDigest', 32, 32),
    v_ceremony.rp_id, v_ceremony.rp_revision,
    (v_credential ->> 'signCount')::bigint,
    (v_credential ->> 'discoverable')::boolean,
    (v_credential ->> 'userVerification')::boolean,
    (v_credential ->> 'backupEligible')::boolean,
    (v_credential ->> 'backedUp')::boolean,
    app.private_mfa_decode_base64_v1(p_request ->> 'aaguid', 16, 16),
    p_request ->> 'attestationFormat', p_request ->> 'attestationType',
    (p_request ->> 'attestationTrusted')::boolean,
    (p_request ->> 'metadataRevision')::bigint,
    'active', 1, (p_request ->> 'completedAt')::timestamptz,
    (p_request ->> 'completedAt')::timestamptz
  );
  FOR v_transport IN SELECT value FROM jsonb_array_elements(v_credential -> 'transports')
  LOOP
    IF jsonb_typeof(v_transport) <> 'string'
       OR v_transport #>> '{}' NOT IN ('usb','nfc','ble','internal','hybrid','smart_card') THEN
      RAISE EXCEPTION 'invalid WebAuthn transport' USING ERRCODE = '22023';
    END IF;
    INSERT INTO public.tenant_webauthn_credential_transports (
      tenant_id, credential_id, transport
    ) VALUES (v_anchor.tenant_id, v_internal_id, v_transport #>> '{}');
  END LOOP;
  v_result := app.private_webauthn_credential_projection_v1(v_internal_id);
  UPDATE public.tenant_webauthn_ceremonies AS ceremony
  SET state = 'completed', version = ceremony.version + 1,
    completed_at = (p_request ->> 'completedAt')::timestamptz,
    completion_request_digest = v_request_digest,
    result_snapshot = v_result
  WHERE ceremony.id = v_ceremony.id AND ceremony.state = 'claimed'
    AND ceremony.version = v_ceremony.version;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'WebAuthn registration completion lost CAS' USING ERRCODE = '40001';
  END IF;
  RETURN v_result;
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_mfa_complete_webauthn_authentication_v1(p_request jsonb)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_ceremony_id bytea;
  v_ceremony public.tenant_webauthn_ceremonies%ROWTYPE;
  v_anchor public.tenant_mfa_authority_anchors%ROWTYPE;
  v_credential public.tenant_webauthn_credentials%ROWTYPE;
  v_request_digest bytea;
  v_resolved_user_id uuid;
  v_identity_epoch bigint;
  v_new_status text;
  v_new_sign_count bigint;
  v_new_version bigint;
  v_result jsonb;
BEGIN
  PERFORM app.private_mfa_assert_json_object_v1(
    p_request,
    ARRAY['ceremonyId','expectedCeremonyVersion','binding','resolvedUserId',
      'expectedIdentityEpoch','credentialId','expectedCredentialVersion',
      'completedAt','expectedSignCount','observedSignCount','expectedBackedUp',
      'counterDisposition','userVerified','backupEligible','backedUp'],
    ARRAY['ceremonyId','expectedCeremonyVersion','binding','resolvedUserId',
      'expectedIdentityEpoch','credentialId','expectedCredentialVersion',
      'completedAt','expectedSignCount','observedSignCount','expectedBackedUp',
      'counterDisposition','userVerified','backupEligible','backedUp']
  );
  v_ceremony_id := app.private_mfa_decode_base64_v1(p_request ->> 'ceremonyId', 32, 32);
  v_request_digest := app.private_mfa_request_digest_v1(p_request);
  v_resolved_user_id := app.private_mfa_require_uuidv7_v1(p_request ->> 'resolvedUserId');
  SELECT ceremony.* INTO STRICT v_ceremony
  FROM public.tenant_webauthn_ceremonies AS ceremony
  WHERE ceremony.id = v_ceremony_id
  FOR UPDATE;
  IF v_ceremony.state = 'completed' THEN
    IF v_ceremony.completion_request_digest = v_request_digest THEN
      RETURN v_ceremony.result_snapshot;
    END IF;
    RAISE EXCEPTION 'WebAuthn authentication replay mismatch' USING ERRCODE = '40001';
  END IF;
  SELECT anchor.* INTO STRICT v_anchor
  FROM public.tenant_mfa_authority_anchors AS anchor
  WHERE anchor.id = v_ceremony.authority_anchor_id;
  SELECT credential.* INTO STRICT v_credential
  FROM public.tenant_webauthn_credentials AS credential
  WHERE credential.tenant_id = v_ceremony.tenant_id
    AND credential.user_id = v_resolved_user_id
    AND credential.credential_id = app.private_mfa_decode_base64_v1(
      p_request ->> 'credentialId', 1, 4096
    )
  FOR UPDATE;
  SELECT subject.identity_epoch INTO STRICT v_identity_epoch
  FROM public.tenant_mfa_subjects AS subject
  JOIN public.tenant_memberships AS membership
    ON membership.tenant_id = subject.tenant_id AND membership.user_id = subject.user_id
  JOIN public.users AS identity ON identity.id = subject.user_id
  WHERE subject.tenant_id = v_credential.tenant_id
    AND subject.user_id = v_credential.user_id
    AND membership.status = 'active' AND identity.active;
  IF v_ceremony.state <> 'claimed' OR v_ceremony.purpose = 'registration'
     OR v_ceremony.version <> (p_request ->> 'expectedCeremonyVersion')::bigint
     OR v_ceremony.expires_at < (p_request ->> 'completedAt')::timestamptz
     OR p_request -> 'binding' IS DISTINCT FROM app.private_mfa_anchor_binding_v1(
       v_ceremony.authority_anchor_id, v_ceremony.purpose
     )
     OR (p_request ->> 'expectedIdentityEpoch')::bigint IS DISTINCT FROM v_identity_epoch
     OR (v_anchor.user_id IS NOT NULL AND v_anchor.user_id IS DISTINCT FROM v_resolved_user_id)
     OR (v_anchor.identity_epoch IS NOT NULL AND v_anchor.identity_epoch IS DISTINCT FROM v_identity_epoch)
     OR v_credential.version <> (p_request ->> 'expectedCredentialVersion')::bigint
     OR v_credential.status <> 'active'
     OR v_credential.sign_count <> (p_request ->> 'expectedSignCount')::bigint
     OR v_credential.backed_up IS DISTINCT FROM (p_request ->> 'expectedBackedUp')::boolean
     OR ((p_request ->> 'backedUp')::boolean AND NOT (p_request ->> 'backupEligible')::boolean)
     OR (v_ceremony.user_verification = 'required' AND NOT (p_request ->> 'userVerified')::boolean)
     OR (v_ceremony.mode = 'known_user' AND NOT EXISTS (
       SELECT 1 FROM public.tenant_webauthn_ceremony_credentials AS allowed
       WHERE allowed.tenant_id = v_ceremony.tenant_id
         AND allowed.ceremony_id = v_ceremony.id
         AND allowed.credential_id = v_credential.credential_id
     ))
     OR (v_ceremony.mode = 'discoverable' AND NOT v_credential.discoverable) THEN
    RAISE EXCEPTION 'WebAuthn authentication completion is stale or invalid' USING ERRCODE = '40001';
  END IF;
  CASE p_request ->> 'counterDisposition'
    WHEN 'unsupported' THEN
      IF (p_request ->> 'expectedSignCount')::bigint <> 0
         OR (p_request ->> 'observedSignCount')::bigint <> 0 THEN
        RAISE EXCEPTION 'invalid unsupported authenticator counter' USING ERRCODE = '22023';
      END IF;
      v_new_status := 'active';
      v_new_sign_count := 0;
    WHEN 'advance' THEN
      IF (p_request ->> 'observedSignCount')::bigint <= (p_request ->> 'expectedSignCount')::bigint
         OR (p_request ->> 'observedSignCount')::bigint > 4294967295 THEN
        RAISE EXCEPTION 'invalid authenticator counter advance' USING ERRCODE = '22023';
      END IF;
      v_new_status := 'active';
      v_new_sign_count := (p_request ->> 'observedSignCount')::bigint;
    WHEN 'clone_suspected' THEN
      IF (p_request ->> 'expectedSignCount')::bigint = 0
         OR (p_request ->> 'observedSignCount')::bigint >= (p_request ->> 'expectedSignCount')::bigint THEN
        RAISE EXCEPTION 'invalid authenticator clone disposition' USING ERRCODE = '22023';
      END IF;
      v_new_status := 'clone_suspected';
      v_new_sign_count := v_credential.sign_count;
    ELSE
      RAISE EXCEPTION 'invalid authenticator counter disposition' USING ERRCODE = '22023';
  END CASE;
  UPDATE public.tenant_webauthn_credentials AS credential
  SET sign_count = v_new_sign_count,
    backup_eligible = (p_request ->> 'backupEligible')::boolean,
    backed_up = (p_request ->> 'backedUp')::boolean,
    status = v_new_status, version = credential.version + 1,
    last_used_at = (p_request ->> 'completedAt')::timestamptz,
    revoked_at = CASE WHEN v_new_status = 'clone_suspected'
      THEN (p_request ->> 'completedAt')::timestamptz ELSE NULL END,
    revoke_reason = CASE WHEN v_new_status = 'clone_suspected'
      THEN 'authenticator_counter_regression' ELSE NULL END,
    updated_at = (p_request ->> 'completedAt')::timestamptz
  WHERE credential.id = v_credential.id AND credential.version = v_credential.version
  RETURNING credential.version INTO STRICT v_new_version;
  v_result := jsonb_build_object(
    'credentialVersion', v_new_version,
    'status', v_new_status, 'signCount', v_new_sign_count,
    'backupEligible', (p_request ->> 'backupEligible')::boolean,
    'backedUp', (p_request ->> 'backedUp')::boolean
  );
  UPDATE public.tenant_webauthn_ceremonies AS ceremony
  SET state = 'completed', version = ceremony.version + 1,
    completed_at = (p_request ->> 'completedAt')::timestamptz,
    completion_request_digest = v_request_digest,
    result_snapshot = v_result
  WHERE ceremony.id = v_ceremony.id AND ceremony.state = 'claimed'
    AND ceremony.version = v_ceremony.version;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'WebAuthn authentication completion lost CAS' USING ERRCODE = '40001';
  END IF;
  RETURN v_result;
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.complete_totp_enrollment_v1(p_request jsonb)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_enrollment_id uuid;
  v_enrollment public.tenant_totp_enrollments%ROWTYPE;
  v_request_digest bytea;
  v_binding jsonb;
  v_session_result jsonb;
  v_audit_id uuid;
  v_result jsonb;
BEGIN
  PERFORM app.private_mfa_assert_json_object_v1(
    p_request,
    ARRAY['enrollmentId','expectedVersion','factorId','binding',
      'acceptedCounter','completedAt','audit','session'],
    ARRAY['enrollmentId','expectedVersion','factorId','binding',
      'acceptedCounter','completedAt','audit','session']
  );
  v_enrollment_id := app.private_mfa_require_uuidv7_v1(p_request ->> 'enrollmentId');
  v_request_digest := app.private_mfa_request_digest_v1(p_request);
  SELECT enrollment.* INTO STRICT v_enrollment
  FROM public.tenant_totp_enrollments AS enrollment
  WHERE enrollment.id = v_enrollment_id
  FOR UPDATE;
  IF v_enrollment.state = 'completed' THEN
    IF v_enrollment.completion_request_digest = v_request_digest THEN
      RETURN v_enrollment.result_snapshot;
    END IF;
    RAISE EXCEPTION 'TOTP enrollment replay mismatch' USING ERRCODE = '40001';
  END IF;
  v_binding := app.private_mfa_anchor_binding_v1(v_enrollment.authority_anchor_id);
  IF v_enrollment.state <> 'claimed'
     OR v_enrollment.version <> (p_request ->> 'expectedVersion')::bigint
     OR v_enrollment.factor_id IS DISTINCT FROM app.private_mfa_require_uuidv7_v1(p_request ->> 'factorId')
     OR p_request -> 'binding' IS DISTINCT FROM v_binding
     OR (p_request ->> 'acceptedCounter')::bigint < 0
     OR v_enrollment.expires_at < (p_request ->> 'completedAt')::timestamptz THEN
    RAISE EXCEPTION 'TOTP enrollment completion is stale' USING ERRCODE = '40001';
  END IF;
  PERFORM 1
  FROM public.tenant_mfa_subjects AS subject
  WHERE subject.tenant_id = v_enrollment.tenant_id
    AND subject.user_id = v_enrollment.user_id
  FOR UPDATE;
  IF NOT FOUND OR (
    SELECT count(*) FROM public.tenant_totp_factors AS factor
    WHERE factor.tenant_id = v_enrollment.tenant_id
      AND factor.user_id = v_enrollment.user_id
      AND factor.status = 'active'
  ) >= 16 THEN
    RAISE EXCEPTION 'active TOTP factor limit reached' USING ERRCODE = '22023';
  END IF;
  INSERT INTO public.tenant_totp_factors (
    id, tenant_id, user_id, secret_envelope, key_version,
    otp_algorithm, digits, period_seconds, last_accepted_counter,
    record_version, security_revision, status, confirmed_at,
    created_at, updated_at
  ) VALUES (
    v_enrollment.factor_id, v_enrollment.tenant_id, v_enrollment.user_id,
    v_enrollment.secret_envelope, v_enrollment.key_version,
    'SHA1', 6, 30, (p_request ->> 'acceptedCounter')::bigint,
    1, 1, 'active', (p_request ->> 'completedAt')::timestamptz,
    v_enrollment.created_at, (p_request ->> 'completedAt')::timestamptz
  );
  v_session_result := app.private_mfa_apply_session_v1(
    p_request -> 'session', v_enrollment.authority_anchor_id,
    NULL, NULL, NULL, 'totp', v_enrollment.factor_id, 1,
    (p_request ->> 'completedAt')::timestamptz
  );
  v_audit_id := app.private_mfa_append_audit_v1(
    p_request -> 'audit', v_enrollment.tenant_id, v_enrollment.user_id,
    'mfa_factor', v_enrollment.factor_id, 'totp'
  );
  v_result := v_session_result || jsonb_build_object(
    'tenantId', v_enrollment.tenant_id::text,
    'userId', v_enrollment.user_id::text,
    'identityEpoch', (p_request -> 'session' ->> 'expectedIdentityEpoch')::bigint,
    'factorId', v_enrollment.factor_id::text,
    'factorSecurityRevision', 1,
    'auditId', v_audit_id::text
  );
  UPDATE public.tenant_totp_enrollments AS enrollment
  SET state = 'completed', version = enrollment.version + 1,
    completed_at = (p_request ->> 'completedAt')::timestamptz,
    completion_request_digest = v_request_digest,
    result_snapshot = v_result
  WHERE enrollment.id = v_enrollment.id AND enrollment.state = 'claimed'
    AND enrollment.version = v_enrollment.version;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'TOTP enrollment completion lost CAS' USING ERRCODE = '40001';
  END IF;
  RETURN v_result;
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.replace_mfa_recovery_codes_v1(p_request jsonb)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_new_set_id uuid;
  v_expected_set_id uuid;
  v_request_digest bytea;
  v_existing public.tenant_recovery_code_sets%ROWTYPE;
  v_anchor_id uuid;
  v_anchor public.tenant_mfa_authority_anchors%ROWTYPE;
  v_session_result jsonb;
  v_audit_id uuid;
  v_result jsonb;
  v_digest jsonb;
  v_decoded bytea;
BEGIN
  PERFORM app.private_mfa_assert_json_object_v1(
    p_request,
    ARRAY['newSetId','digestKeyVersion','expectedSetId','expectedSetVersion',
      'binding','digests','generatedAt','audit','session'],
    ARRAY['newSetId','digestKeyVersion','expectedSetVersion','binding',
      'digests','generatedAt','audit','session']
  );
  v_new_set_id := app.private_mfa_require_uuidv7_v1(p_request ->> 'newSetId');
  v_request_digest := app.private_mfa_request_digest_v1(p_request);
  SELECT code_set.* INTO v_existing
  FROM public.tenant_recovery_code_sets AS code_set
  WHERE code_set.id = v_new_set_id
  FOR UPDATE;
  IF FOUND THEN
    IF v_existing.completion_request_digest = v_request_digest THEN
      RETURN v_existing.result_snapshot;
    END IF;
    RAISE EXCEPTION 'recovery code replacement replay mismatch' USING ERRCODE = '40001';
  END IF;
  IF (p_request ->> 'digestKeyVersion')::integer NOT BETWEEN 1 AND 32767
     OR jsonb_typeof(p_request -> 'digests') <> 'array'
     OR jsonb_array_length(p_request -> 'digests') NOT BETWEEN 8 AND 16
     OR (SELECT count(DISTINCT value) FROM jsonb_array_elements(p_request -> 'digests'))
          <> jsonb_array_length(p_request -> 'digests') THEN
    RAISE EXCEPTION 'invalid recovery code replacement' USING ERRCODE = '22023';
  END IF;
  v_anchor_id := app.private_mfa_anchor_from_stepup_binding_v1(
    p_request -> 'binding', (p_request ->> 'generatedAt')::timestamptz
  );
  SELECT anchor.* INTO STRICT v_anchor
  FROM public.tenant_mfa_authority_anchors AS anchor
  WHERE anchor.id = v_anchor_id AND anchor.flow = 'session';
  IF p_request ? 'expectedSetId' THEN
    v_expected_set_id := app.private_mfa_require_uuidv7_v1(p_request ->> 'expectedSetId');
    UPDATE public.tenant_recovery_code_sets AS code_set
    SET status = 'revoked', record_version = code_set.record_version + 1,
      security_revision = code_set.security_revision + 1,
      revoked_at = (p_request ->> 'generatedAt')::timestamptz,
      revoke_reason = 'recovery_codes_replaced',
      updated_at = (p_request ->> 'generatedAt')::timestamptz
    WHERE code_set.tenant_id = v_anchor.tenant_id
      AND code_set.user_id = v_anchor.user_id
      AND code_set.id = v_expected_set_id
      AND code_set.status = 'active'
      AND code_set.record_version = (p_request ->> 'expectedSetVersion')::bigint;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'recovery code set replacement is stale' USING ERRCODE = '40001';
    END IF;
  ELSIF (p_request ->> 'expectedSetVersion')::bigint <> 0
     OR EXISTS (
       SELECT 1 FROM public.tenant_recovery_code_sets AS code_set
       WHERE code_set.tenant_id = v_anchor.tenant_id
         AND code_set.user_id = v_anchor.user_id AND code_set.status = 'active'
     ) THEN
    RAISE EXCEPTION 'recovery code set precondition is stale' USING ERRCODE = '40001';
  END IF;

  v_session_result := app.private_mfa_apply_session_v1(
    p_request -> 'session', v_anchor.id, NULL, NULL, NULL,
    NULL, NULL, NULL, (p_request ->> 'generatedAt')::timestamptz
  );
  v_audit_id := app.private_mfa_append_audit_v1(
    p_request -> 'audit', v_anchor.tenant_id, v_anchor.user_id,
    'mfa_recovery_code_set', v_new_set_id, 'mfa'
  );
  v_result := v_session_result || jsonb_build_object(
    'tenantId', v_anchor.tenant_id::text,
    'userId', v_anchor.user_id::text,
    'identityEpoch', v_anchor.identity_epoch,
    'setId', v_new_set_id::text,
    'setVersion', 1,
    'auditId', v_audit_id::text
  );
  INSERT INTO public.tenant_recovery_code_sets (
    id, tenant_id, user_id, digest_key_version, record_version,
    security_revision, completion_request_digest, result_snapshot,
    status, generated_at, updated_at
  ) VALUES (
    v_new_set_id, v_anchor.tenant_id, v_anchor.user_id,
    (p_request ->> 'digestKeyVersion')::integer, 1, 1,
    v_request_digest, v_result, 'active',
    (p_request ->> 'generatedAt')::timestamptz,
    (p_request ->> 'generatedAt')::timestamptz
  );
  FOR v_digest IN SELECT value FROM jsonb_array_elements(p_request -> 'digests')
  LOOP
    IF jsonb_typeof(v_digest) <> 'string' THEN
      RAISE EXCEPTION 'invalid recovery code digest' USING ERRCODE = '22023';
    END IF;
    v_decoded := app.private_mfa_decode_base64_v1(v_digest #>> '{}', 32, 32);
    INSERT INTO public.tenant_recovery_codes (
      id, tenant_id, set_id, code_digest, created_at
    ) VALUES (
      uuidv7(), v_anchor.tenant_id, v_new_set_id, v_decoded,
      (p_request ->> 'generatedAt')::timestamptz
    );
  END LOOP;
  RETURN v_result;
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.start_totp_enrollment_v1(p_request jsonb)
RETURNS boolean
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_enrollment_id uuid;
  v_factor_id uuid;
  v_anchor_id uuid;
  v_browser_digest bytea;
  v_secret_envelope bytea;
  v_created_at timestamptz;
  v_expires_at timestamptz;
  v_policy_count integer;
BEGIN
  PERFORM app.private_mfa_assert_json_object_v1(
    p_request,
    ARRAY['enrollmentId','factorId','browserDigest','binding','policyPins',
      'keyVersion','secretEnvelope','createdAt','expiresAt'],
    ARRAY['enrollmentId','factorId','browserDigest','binding','policyPins',
      'keyVersion','secretEnvelope','createdAt','expiresAt']
  );
  v_enrollment_id := app.private_mfa_require_uuidv7_v1(p_request ->> 'enrollmentId');
  v_factor_id := app.private_mfa_require_uuidv7_v1(p_request ->> 'factorId');
  v_browser_digest := app.private_mfa_decode_base64_v1(p_request ->> 'browserDigest', 32, 32);
  v_secret_envelope := app.private_mfa_decode_base64_v1(p_request ->> 'secretEnvelope', 17, 16384);
  v_created_at := (p_request ->> 'createdAt')::timestamptz;
  v_expires_at := (p_request ->> 'expiresAt')::timestamptz;
  IF v_enrollment_id = v_factor_id
     OR (p_request ->> 'keyVersion')::integer NOT BETWEEN 1 AND 32767
     OR jsonb_typeof(p_request -> 'policyPins') <> 'array'
     OR jsonb_array_length(p_request -> 'policyPins') NOT BETWEEN 1 AND 128
     OR v_created_at IS NULL OR v_expires_at <= v_created_at
     OR v_expires_at > v_created_at + interval '30 minutes'
     OR abs(extract(epoch FROM (transaction_timestamp() - v_created_at))) > 300 THEN
    RAISE EXCEPTION 'invalid TOTP enrollment request' USING ERRCODE = '22023';
  END IF;
  v_anchor_id := app.private_mfa_anchor_from_stepup_binding_v1(
    p_request -> 'binding', v_created_at
  );
  SELECT count(*)::integer INTO v_policy_count
  FROM public.tenant_mfa_authority_policy_pins AS pin
  WHERE pin.anchor_id = v_anchor_id;
  IF v_policy_count <> jsonb_array_length(p_request -> 'policyPins')
     OR EXISTS (
       SELECT 1 FROM jsonb_array_elements(p_request -> 'policyPins') AS requested(value)
       WHERE jsonb_typeof(requested.value) <> 'object'
          OR requested.value - ARRAY['scope','targetId','policyId','revision']::text[] <> '{}'::jsonb
          OR NOT (requested.value ?& ARRAY['scope','policyId','revision'])
          OR NOT EXISTS (
            SELECT 1
            FROM public.tenant_mfa_authority_policy_pins AS pin
            WHERE pin.anchor_id = v_anchor_id
              AND pin.scope = requested.value ->> 'scope'
              AND pin.policy_id = (requested.value ->> 'policyId')::uuid
              AND pin.policy_revision = (requested.value ->> 'revision')::bigint
              AND coalesce(pin.role_id, pin.security_group_id)::text
                    IS NOT DISTINCT FROM requested.value ->> 'targetId'
          )
     ) THEN
    RAISE EXCEPTION 'TOTP enrollment policy pins drifted' USING ERRCODE = '40001';
  END IF;
  INSERT INTO public.tenant_totp_enrollments (
    id, tenant_id, user_id, authority_anchor_id, factor_id,
    browser_digest, secret_envelope, key_version, state, version,
    created_at, expires_at
  ) SELECT v_enrollment_id, anchor.tenant_id, anchor.user_id, anchor.id,
    v_factor_id, v_browser_digest, v_secret_envelope,
    (p_request ->> 'keyVersion')::integer, 'pending', 1,
    v_created_at, v_expires_at
  FROM public.tenant_mfa_authority_anchors AS anchor
  WHERE anchor.id = v_anchor_id AND anchor.user_id IS NOT NULL;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'TOTP enrollment authority is unavailable' USING ERRCODE = '42501';
  END IF;
  RETURN true;
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range OR datetime_field_overflow THEN
  RAISE EXCEPTION 'invalid TOTP enrollment request' USING ERRCODE = '22023';
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.claim_totp_enrollment_v1(
  p_enrollment_id uuid,
  p_browser_digest bytea,
  p_claimed_at timestamptz
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_enrollment public.tenant_totp_enrollments%ROWTYPE;
BEGIN
  IF NOT ((uuid_extract_version(p_enrollment_id) = 7) IS TRUE)
     OR octet_length(p_browser_digest) <> 32 OR p_claimed_at IS NULL
     OR abs(extract(epoch FROM (transaction_timestamp() - p_claimed_at))) > 300 THEN
    RAISE EXCEPTION 'invalid TOTP enrollment claim' USING ERRCODE = '22023';
  END IF;
  UPDATE public.tenant_totp_enrollments AS enrollment
  SET state = 'claimed', version = enrollment.version + 1,
    claimed_at = p_claimed_at
  WHERE enrollment.id = p_enrollment_id
    AND enrollment.browser_digest = p_browser_digest
    AND enrollment.state = 'pending' AND enrollment.version = 1
    AND enrollment.expires_at > p_claimed_at
  RETURNING enrollment.* INTO STRICT v_enrollment;
  RETURN jsonb_build_object(
    'enrollmentId', v_enrollment.id::text,
    'factorId', v_enrollment.factor_id::text,
    'version', v_enrollment.version,
    'browserDigest', replace(encode(v_enrollment.browser_digest, 'base64'), E'\n', ''),
    'binding', app.private_mfa_anchor_binding_v1(v_enrollment.authority_anchor_id),
    'keyVersion', v_enrollment.key_version,
    'secretEnvelope', replace(encode(v_enrollment.secret_envelope, 'base64'), E'\n', ''),
    'createdAt', v_enrollment.created_at,
    'expiresAt', v_enrollment.expires_at,
    'claimedAt', v_enrollment.claimed_at
  );
EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
  RAISE EXCEPTION 'TOTP enrollment claim is stale or denied' USING ERRCODE = '40001';
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.fail_totp_enrollment_v1(
  p_enrollment_id uuid,
  p_expected_version bigint,
  p_failed_at timestamptz
)
RETURNS boolean
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF NOT ((uuid_extract_version(p_enrollment_id) = 7) IS TRUE)
     OR p_expected_version < 1 OR p_failed_at IS NULL THEN
    RAISE EXCEPTION 'invalid TOTP enrollment failure' USING ERRCODE = '22023';
  END IF;
  UPDATE public.tenant_totp_enrollments AS enrollment
  SET state = 'failed', version = enrollment.version + 1,
    failed_at = p_failed_at
  WHERE enrollment.id = p_enrollment_id
    AND enrollment.state = 'claimed'
    AND enrollment.version = p_expected_version
    AND enrollment.claimed_at <= p_failed_at;
  RETURN FOUND;
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.create_mfa_step_up_challenge_v1(p_request jsonb)
RETURNS boolean
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_anchor_id uuid;
  v_challenge_id bytea;
  v_browser_digest bytea;
  v_created_at timestamptz;
  v_expires_at timestamptz;
BEGIN
  PERFORM app.private_mfa_assert_json_object_v1(
    p_request,
    ARRAY['id','browserDigest','binding','allowedFactors','createdAt','expiresAt',
      'state','version','claimedAt'],
    ARRAY['id','browserDigest','binding','allowedFactors','createdAt','expiresAt',
      'state','version']
  );
  v_challenge_id := app.private_mfa_decode_base64_v1(p_request ->> 'id', 32, 32);
  v_browser_digest := app.private_mfa_decode_base64_v1(p_request ->> 'browserDigest', 32, 32);
  v_created_at := (p_request ->> 'createdAt')::timestamptz;
  v_expires_at := (p_request ->> 'expiresAt')::timestamptz;
  IF p_request ->> 'state' <> 'pending' OR (p_request ->> 'version')::bigint <> 1
     OR p_request ? 'claimedAt'
     OR p_request -> 'allowedFactors' NOT IN (
       '["totp"]'::jsonb, '["recovery_code"]'::jsonb,
       '["totp","recovery_code"]'::jsonb
     )
     OR v_expires_at <= v_created_at
     OR v_expires_at > v_created_at + interval '15 minutes'
     OR abs(extract(epoch FROM (transaction_timestamp() - v_created_at))) > 300 THEN
    RAISE EXCEPTION 'invalid MFA step-up challenge' USING ERRCODE = '22023';
  END IF;
  v_anchor_id := app.private_mfa_anchor_from_stepup_binding_v1(
    p_request -> 'binding', v_created_at
  );
  INSERT INTO public.tenant_mfa_step_up_challenges (
    id, tenant_id, authority_anchor_id, browser_digest, allowed_factors,
    state, version, created_at, expires_at
  ) SELECT v_challenge_id, anchor.tenant_id, anchor.id, v_browser_digest,
    ARRAY(SELECT jsonb_array_elements_text(p_request -> 'allowedFactors')),
    'pending', 1, v_created_at, v_expires_at
  FROM public.tenant_mfa_authority_anchors AS anchor
  WHERE anchor.id = v_anchor_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'MFA challenge authority is unavailable' USING ERRCODE = '42501';
  END IF;
  RETURN true;
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.claim_mfa_step_up_challenge_v1(
  p_challenge_id bytea,
  p_browser_digest bytea,
  p_factor text,
  p_claimed_at timestamptz
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_challenge public.tenant_mfa_step_up_challenges%ROWTYPE;
BEGIN
  IF octet_length(p_challenge_id) <> 32 OR octet_length(p_browser_digest) <> 32
     OR p_factor NOT IN ('totp','recovery_code') OR p_claimed_at IS NULL THEN
    RAISE EXCEPTION 'invalid MFA challenge claim' USING ERRCODE = '22023';
  END IF;
  UPDATE public.tenant_mfa_step_up_challenges AS challenge
  SET state = 'claimed', version = challenge.version + 1,
    claimed_at = p_claimed_at
  WHERE challenge.id = p_challenge_id
    AND challenge.browser_digest = p_browser_digest
    AND p_factor = ANY(challenge.allowed_factors)
    AND challenge.state = 'pending' AND challenge.version = 1
    AND challenge.expires_at > p_claimed_at
  RETURNING challenge.* INTO STRICT v_challenge;
  RETURN jsonb_build_object(
    'id', replace(encode(v_challenge.id, 'base64'), E'\n', ''),
    'browserDigest', replace(encode(v_challenge.browser_digest, 'base64'), E'\n', ''),
    'binding', app.private_mfa_anchor_binding_v1(v_challenge.authority_anchor_id),
    'allowedFactors', to_jsonb(v_challenge.allowed_factors),
    'createdAt', v_challenge.created_at,
    'expiresAt', v_challenge.expires_at,
    'state', v_challenge.state,
    'version', v_challenge.version,
    'claimedAt', v_challenge.claimed_at
  );
EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
  RAISE EXCEPTION 'MFA challenge claim is stale or denied' USING ERRCODE = '40001';
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.fail_mfa_step_up_challenge_v1(
  p_challenge_id bytea,
  p_expected_version bigint,
  p_state text,
  p_reason text,
  p_failed_at timestamptz
)
RETURNS boolean
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF octet_length(p_challenge_id) <> 32 OR p_expected_version < 1
     OR (p_state, p_reason) NOT IN (('failed','factor_rejected'),('expired','expired'))
     OR p_failed_at IS NULL THEN
    RAISE EXCEPTION 'invalid MFA challenge failure' USING ERRCODE = '22023';
  END IF;
  UPDATE public.tenant_mfa_step_up_challenges AS challenge
  SET state = p_state, failure_reason = p_reason,
    version = challenge.version + 1, failed_at = p_failed_at
  WHERE challenge.id = p_challenge_id
    AND challenge.state = 'claimed'
    AND challenge.version = p_expected_version
    AND challenge.claimed_at <= p_failed_at;
  RETURN FOUND;
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.load_mfa_totp_factor_v1(
  p_tenant_id uuid,
  p_user_id uuid,
  p_factor_id uuid
)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_factor public.tenant_totp_factors%ROWTYPE;
BEGIN
  SELECT factor.* INTO STRICT v_factor
  FROM public.tenant_totp_factors AS factor
  JOIN public.tenant_mfa_subjects AS subject
    ON subject.tenant_id = factor.tenant_id AND subject.user_id = factor.user_id
  WHERE factor.tenant_id = p_tenant_id AND factor.user_id = p_user_id
    AND factor.id = p_factor_id AND factor.status = 'active';
  RETURN jsonb_build_object(
    'id', v_factor.id::text, 'tenantId', v_factor.tenant_id::text,
    'userId', v_factor.user_id::text, 'recordVersion', v_factor.record_version,
    'securityRevision', v_factor.security_revision, 'status', v_factor.status,
    'lastCounter', v_factor.last_accepted_counter, 'keyVersion', v_factor.key_version,
    'secretEnvelope', replace(encode(v_factor.secret_envelope, 'base64'), E'\n', '')
  );
EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
  RAISE EXCEPTION 'MFA TOTP factor is unavailable' USING ERRCODE = '42501';
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.load_mfa_recovery_set_v1(
  p_tenant_id uuid,
  p_user_id uuid
)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_set public.tenant_recovery_code_sets%ROWTYPE;
BEGIN
  SELECT code_set.* INTO STRICT v_set
  FROM public.tenant_recovery_code_sets AS code_set
  WHERE code_set.tenant_id = p_tenant_id AND code_set.user_id = p_user_id
    AND code_set.status = 'active'
    AND EXISTS (
      SELECT 1 FROM public.tenant_recovery_codes AS code
      WHERE code.tenant_id = code_set.tenant_id AND code.set_id = code_set.id
        AND code.consumed_at IS NULL
    );
  RETURN jsonb_build_object(
    'id', v_set.id::text, 'tenantId', v_set.tenant_id::text,
    'userId', v_set.user_id::text, 'recordVersion', v_set.record_version,
    'securityRevision', v_set.security_revision, 'status', v_set.status,
    'digestKeyVersion', v_set.digest_key_version
  );
EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
  RAISE EXCEPTION 'MFA recovery set is unavailable' USING ERRCODE = '42501';
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_complete_mfa_factor_v1(
  p_request jsonb,
  p_factor_kind text
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_challenge_id bytea;
  v_challenge public.tenant_mfa_step_up_challenges%ROWTYPE;
  v_request_digest bytea;
  v_binding jsonb;
  v_anchor public.tenant_mfa_authority_anchors%ROWTYPE;
  v_factor public.tenant_totp_factors%ROWTYPE;
  v_set public.tenant_recovery_code_sets%ROWTYPE;
  v_factor_id uuid;
  v_factor_revision bigint;
  v_session jsonb;
  v_session_result jsonb;
  v_audit jsonb;
  v_audit_id uuid;
  v_result jsonb;
BEGIN
  PERFORM app.private_mfa_assert_json_object_v1(
    p_request,
    ARRAY['challengeId','expectedChallengeVersion','binding','factorId',
      'expectedFactorVersion','expectedSecurityRevision','counter','setId',
      'codeDigest','completedAt','sessionMutation','auditKind',
      'recoveryRestricted','session'],
    ARRAY['challengeId','expectedChallengeVersion','binding','factorId',
      'expectedFactorVersion','expectedSecurityRevision','completedAt',
      'sessionMutation','auditKind','recoveryRestricted','session']
  );
  IF p_factor_kind NOT IN ('totp','recovery') THEN
    RAISE EXCEPTION 'invalid MFA factor completion kind' USING ERRCODE = '22023';
  END IF;
  v_challenge_id := app.private_mfa_decode_base64_v1(p_request ->> 'challengeId', 32, 32);
  v_request_digest := app.private_mfa_request_digest_v1(p_request);
  SELECT challenge.* INTO STRICT v_challenge
  FROM public.tenant_mfa_step_up_challenges AS challenge
  WHERE challenge.id = v_challenge_id
  FOR UPDATE;
  IF v_challenge.state = 'completed' THEN
    IF v_challenge.completion_request_digest = v_request_digest THEN
      RETURN v_challenge.result_snapshot;
    END IF;
    RAISE EXCEPTION 'MFA challenge completion replay mismatch' USING ERRCODE = '40001';
  END IF;
  v_binding := app.private_mfa_anchor_binding_v1(v_challenge.authority_anchor_id);
  SELECT anchor.* INTO STRICT v_anchor
  FROM public.tenant_mfa_authority_anchors AS anchor
  WHERE anchor.id = v_challenge.authority_anchor_id;
  IF v_challenge.state <> 'claimed'
     OR v_challenge.version <> (p_request ->> 'expectedChallengeVersion')::bigint
     OR v_challenge.expires_at < (p_request ->> 'completedAt')::timestamptz
     OR p_request -> 'binding' IS DISTINCT FROM v_binding
     OR (p_factor_kind = 'totp' AND NOT ('totp' = ANY(v_challenge.allowed_factors)))
     OR (p_factor_kind = 'recovery' AND NOT ('recovery_code' = ANY(v_challenge.allowed_factors)))
     OR (v_anchor.flow = 'session' AND p_request ->> 'sessionMutation' <> 'rotate')
     OR (v_anchor.flow = 'continuation' AND p_request ->> 'sessionMutation' <> 'consume_continuation') THEN
    RAISE EXCEPTION 'MFA factor completion is stale' USING ERRCODE = '40001';
  END IF;

  IF p_factor_kind = 'totp' THEN
    v_factor_id := app.private_mfa_require_uuidv7_v1(p_request ->> 'factorId');
    IF p_request ->> 'auditKind' <> 'mfa.totp_step_up_completed'
       OR p_request -> 'counter' IS NULL
       OR p_request ? 'setId' OR p_request ? 'codeDigest'
       OR (p_request ->> 'recoveryRestricted')::boolean THEN
      RAISE EXCEPTION 'invalid TOTP completion intent' USING ERRCODE = '22023';
    END IF;
    SELECT factor.* INTO STRICT v_factor
    FROM public.tenant_totp_factors AS factor
    WHERE factor.tenant_id = v_anchor.tenant_id
      AND factor.user_id = v_anchor.user_id AND factor.id = v_factor_id
      AND factor.status = 'active'
      AND factor.record_version = (p_request ->> 'expectedFactorVersion')::bigint
      AND factor.security_revision = (p_request ->> 'expectedSecurityRevision')::bigint
    FOR UPDATE;
    IF (p_request ->> 'counter')::bigint <= v_factor.last_accepted_counter THEN
      RAISE EXCEPTION 'TOTP counter replayed' USING ERRCODE = '40001';
    END IF;
    UPDATE public.tenant_totp_factors AS factor
    SET last_accepted_counter = (p_request ->> 'counter')::bigint,
      record_version = factor.record_version + 1,
      updated_at = (p_request ->> 'completedAt')::timestamptz
    WHERE factor.id = v_factor.id AND factor.record_version = v_factor.record_version;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'TOTP factor CAS lost' USING ERRCODE = '40001';
    END IF;
    v_factor_revision := v_factor.security_revision;
  ELSE
    IF p_request ->> 'auditKind' <> 'mfa.recovery_code_used'
       OR NOT (p_request ->> 'recoveryRestricted')::boolean
       OR p_request ? 'counter'
       OR p_request ->> 'factorId' <> '' THEN
      RAISE EXCEPTION 'invalid recovery completion intent' USING ERRCODE = '22023';
    END IF;
    v_factor_id := app.private_mfa_require_uuidv7_v1(p_request ->> 'setId');
    SELECT code_set.* INTO STRICT v_set
    FROM public.tenant_recovery_code_sets AS code_set
    WHERE code_set.tenant_id = v_anchor.tenant_id
      AND code_set.user_id = v_anchor.user_id AND code_set.id = v_factor_id
      AND code_set.status = 'active'
      AND code_set.record_version = (p_request ->> 'expectedFactorVersion')::bigint
      AND code_set.security_revision = (p_request ->> 'expectedSecurityRevision')::bigint
    FOR UPDATE;
    UPDATE public.tenant_recovery_codes AS code
    SET consumed_at = (p_request ->> 'completedAt')::timestamptz
    WHERE code.tenant_id = v_set.tenant_id AND code.set_id = v_set.id
      AND code.code_digest = app.private_mfa_decode_base64_v1(p_request ->> 'codeDigest', 32, 32)
      AND code.consumed_at IS NULL;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'recovery code is unavailable or replayed' USING ERRCODE = '40001';
    END IF;
    UPDATE public.tenant_recovery_code_sets AS code_set
    SET record_version = code_set.record_version + 1,
      updated_at = (p_request ->> 'completedAt')::timestamptz
    WHERE code_set.id = v_set.id AND code_set.record_version = v_set.record_version;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'recovery set CAS lost' USING ERRCODE = '40001';
    END IF;
    v_factor_revision := v_set.security_revision;
  END IF;

  v_session := jsonb_build_object(
    'mutation', p_request ->> 'sessionMutation',
    'expectedAnchorVersion', v_anchor.anchor_version,
    'expectedIdentityEpoch', v_anchor.identity_epoch,
    'expectedAnchorExpiry', v_anchor.anchor_expires_at,
    'audience', v_anchor.audience,
    'requirement', v_binding -> 'requirement',
    'recoveryRestricted', (p_request ->> 'recoveryRestricted')::boolean,
    'reservation', p_request -> 'session'
  ) || CASE WHEN v_anchor.flow = 'session' THEN jsonb_build_object(
      'expectedSessionId', v_anchor.session_id::text,
      'expectedFamilyId', v_anchor.session_family_id::text
    ) ELSE jsonb_build_object(
      'expectedContinuationId', v_anchor.continuation_id::text
    ) END;
  v_session_result := app.private_mfa_apply_session_v1(
    v_session, v_anchor.id, NULL, NULL, NULL,
    p_factor_kind, v_factor_id, v_factor_revision,
    (p_request ->> 'completedAt')::timestamptz
  );
  v_audit := jsonb_build_object(
    'kind', p_request ->> 'auditKind',
    'tenantId', v_anchor.tenant_id::text,
    'userId', v_anchor.user_id::text,
    'action', v_anchor.action,
    'occurredAt', (p_request ->> 'completedAt')::timestamptz,
    'policyRevisions', v_binding -> 'requirement' -> 'policyRevisions'
  );
  v_audit_id := app.private_mfa_append_audit_v1(
    v_audit, v_anchor.tenant_id, v_anchor.user_id,
    'mfa_step_up_challenge', v_anchor.id,
    CASE WHEN p_factor_kind = 'totp' THEN 'totp' ELSE 'recovery_code' END
  );
  v_result := v_session_result || jsonb_build_object(
    'tenantId', v_anchor.tenant_id::text,
    'userId', v_anchor.user_id::text,
    'identityEpoch', v_anchor.identity_epoch,
    'factorSecurityRevision', v_factor_revision,
    'auditId', v_audit_id::text
  );
  UPDATE public.tenant_mfa_step_up_challenges AS challenge
  SET state = 'completed', version = challenge.version + 1,
    completed_at = (p_request ->> 'completedAt')::timestamptz,
    completion_request_digest = v_request_digest,
    result_snapshot = v_result
  WHERE challenge.id = v_challenge.id AND challenge.state = 'claimed'
    AND challenge.version = v_challenge.version;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'MFA challenge completion lost CAS' USING ERRCODE = '40001';
  END IF;
  RETURN v_result;
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.complete_mfa_totp_step_up_v1(p_request jsonb)
RETURNS jsonb
LANGUAGE sql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
  SELECT app.private_complete_mfa_factor_v1(p_request, 'totp');
$function$;
--> statement-breakpoint

CREATE FUNCTION app.complete_mfa_recovery_step_up_v1(p_request jsonb)
RETURNS jsonb
LANGUAGE sql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
  SELECT app.private_complete_mfa_factor_v1(p_request, 'recovery');
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_mfa_request_digest_v1(p_request jsonb)
RETURNS bytea
LANGUAGE plpgsql
IMMUTABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  PERFORM app.private_mfa_assert_json_object_v1(
    p_request, ARRAY(SELECT jsonb_object_keys(p_request)), ARRAY[]::text[]
  );
  RETURN sha256(convert_to(p_request::text, 'UTF8'));
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_mfa_append_audit_v1(
  p_audit jsonb,
  p_expected_tenant_id uuid,
  p_expected_user_id uuid,
  p_resource_type text,
  p_resource_id uuid,
  p_authentication_method text
)
RETURNS uuid
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_audit_id uuid := uuidv7();
  v_kind text;
  v_tenant_id uuid;
  v_user_id uuid;
  v_occurred_at timestamptz;
BEGIN
  PERFORM app.private_mfa_assert_json_object_v1(
    p_audit,
    ARRAY['kind','tenantId','userId','action','occurredAt','policyRevisions'],
    ARRAY['kind','tenantId','userId','action','occurredAt','policyRevisions'],
    65536
  );
  v_kind := p_audit ->> 'kind';
  v_tenant_id := app.private_mfa_require_uuidv7_v1(p_audit ->> 'tenantId');
  v_user_id := app.private_mfa_require_uuidv7_v1(p_audit ->> 'userId');
  v_occurred_at := (p_audit ->> 'occurredAt')::timestamptz;
  IF p_expected_tenant_id IS NULL OR p_expected_user_id IS NULL
     OR v_tenant_id IS DISTINCT FROM p_expected_tenant_id
     OR v_user_id IS DISTINCT FROM p_expected_user_id THEN
    RAISE EXCEPTION 'MFA audit actor mismatch' USING ERRCODE = '42501';
  END IF;
  IF (nullif(current_setting('app.tenant_id', true), '') IS NOT NULL
        AND current_setting('app.tenant_id', true) IS DISTINCT FROM p_expected_tenant_id::text)
     OR (nullif(current_setting('app.user_id', true), '') IS NOT NULL
        AND current_setting('app.user_id', true) IS DISTINCT FROM p_expected_user_id::text) THEN
    RAISE EXCEPTION 'MFA audit context mismatch' USING ERRCODE = '42501';
  END IF;
  IF v_kind NOT IN (
       'mfa.passkey_enrolled', 'mfa.passkey_authenticated',
       'mfa.passkey_step_up_completed', 'mfa.passkey_clone_suspected',
       'mfa.totp_enrolled', 'mfa.recovery_codes_created',
       'mfa.recovery_codes_regenerated', 'mfa.totp_step_up_completed',
       'mfa.recovery_code_used'
     )
     OR NOT app.private_mfa_safe_text_v1(p_audit ->> 'action', 256)
     OR jsonb_typeof(p_audit -> 'policyRevisions') <> 'array'
     OR jsonb_array_length(p_audit -> 'policyRevisions') > 128
     OR p_resource_type NOT IN (
       'mfa_factor', 'mfa_recovery_code_set', 'webauthn_credential',
       'mfa_step_up_challenge'
     )
     OR p_resource_id IS NULL
     OR p_authentication_method NOT IN ('passkey','totp','recovery_code','mfa')
     OR v_occurred_at IS NULL
     OR abs(extract(epoch FROM (transaction_timestamp() - v_occurred_at))) > 300
     OR NOT EXISTS (
       SELECT 1
       FROM public.tenant_memberships AS membership
       JOIN public.users AS identity ON identity.id = membership.user_id
       WHERE membership.tenant_id = v_tenant_id
         AND membership.user_id = v_user_id
         AND membership.status = 'active'
         AND identity.active
     )
     OR EXISTS (
       SELECT 1
       FROM jsonb_array_elements(p_audit -> 'policyRevisions') AS revision(value)
       WHERE jsonb_typeof(revision.value) <> 'object'
          OR revision.value - ARRAY['policyId','revision']::text[] <> '{}'::jsonb
          OR NOT (revision.value ?& ARRAY['policyId','revision'])
          OR NOT ((uuid_extract_version((revision.value ->> 'policyId')::uuid) = 7) IS TRUE)
          OR (revision.value ->> 'revision')::bigint < 1
     ) THEN
    RAISE EXCEPTION 'unsafe MFA audit intent' USING ERRCODE = '22023';
  END IF;

  PERFORM set_config('app.tenant_id', p_expected_tenant_id::text, true);
  PERFORM set_config('app.user_id', p_expected_user_id::text, true);

  INSERT INTO public.audit_events (
    id, tenant_id, sequence, occurred_at, actor_type, actor_user_id,
    action, resource_type, resource_id, authentication_method,
    outcome, metadata
  ) VALUES (
    v_audit_id, v_tenant_id, 0, v_occurred_at, 'user', v_user_id,
    'tenant.identity.' || replace(v_kind, '.', '_'), p_resource_type,
    p_resource_id, p_authentication_method, 'success',
    jsonb_build_object(
      'kind', v_kind,
      'policy_revision_count', jsonb_array_length(p_audit -> 'policyRevisions'),
      'secret_material_included', false
    )
  );
  RETURN v_audit_id;
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range OR datetime_field_overflow THEN
  RAISE EXCEPTION 'unsafe MFA audit intent' USING ERRCODE = '22023';
END;
$function$;
--> statement-breakpoint

-- Commits the browser session side of an MFA completion. The caller reserves
-- UUIDv7 identifiers and supplies only SHA-256 token/CSRF digests. Primary
-- provenance, evidence, policy pins, old-session revocation/continuation
-- consumption and the new session are committed by the same transaction.
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
  v_anchor public.tenant_mfa_authority_anchors%ROWTYPE;
  v_binding jsonb;
  v_mutation text;
  v_reservation jsonb;
  v_tenant_id uuid;
  v_user_id uuid;
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
  v_primary_kind text;
  v_primary_id uuid;
  v_primary_revision bigint;
  v_primary_authenticated_at timestamptz;
  v_policy_snapshot jsonb;
  v_policy_entry jsonb;
  v_evidence_count bigint;
  v_consumed_continuation_id uuid;
  v_retained_continuation_id uuid;
  v_revoked_anchor_id uuid;
BEGIN
  PERFORM app.private_mfa_assert_json_object_v1(
    p_session,
    ARRAY['mutation','expectedSessionId','expectedFamilyId','expectedContinuationId',
      'expectedAnchorVersion','expectedIdentityEpoch','expectedAnchorExpiry',
      'audience','requirement','recoveryRestricted','reservation'],
    ARRAY['mutation','expectedAnchorVersion','expectedIdentityEpoch',
      'expectedAnchorExpiry','audience','requirement','recoveryRestricted'],
    131072
  );
  SELECT anchor.* INTO STRICT v_anchor
  FROM public.tenant_mfa_authority_anchors AS anchor
  WHERE anchor.id = p_anchor_id
  FOR UPDATE;
  v_binding := app.private_mfa_anchor_binding_v1(p_anchor_id);
  v_mutation := p_session ->> 'mutation';
  IF v_mutation NOT IN ('create','rotate','consume_continuation','retain_continuation','revoke')
     OR NOT app.private_mfa_safe_text_v1(p_session ->> 'audience', 256)
     OR p_session ->> 'audience' IS DISTINCT FROM v_anchor.audience
     OR jsonb_typeof(p_session -> 'requirement') <> 'object'
     OR p_session -> 'requirement' IS DISTINCT FROM v_binding -> 'requirement'
     OR coalesce((p_session ->> 'expectedAnchorVersion')::bigint, 0)
          IS DISTINCT FROM coalesce(v_anchor.anchor_version, 0)
     OR coalesce((p_session ->> 'expectedAnchorExpiry')::timestamptz, '-infinity'::timestamptz)
          IS DISTINCT FROM coalesce(v_anchor.anchor_expires_at, '-infinity'::timestamptz)
     OR p_completed_at IS NULL
     OR abs(extract(epoch FROM (transaction_timestamp() - p_completed_at))) > 300 THEN
    RAISE EXCEPTION 'MFA session intent drifted' USING ERRCODE = '40001';
  END IF;

  IF v_anchor.flow = 'primary' THEN
    IF v_mutation NOT IN ('create','revoke') OR p_primary_kind <> 'passkey'
       OR p_primary_id IS NULL OR p_primary_revision < 1
       OR p_session ? 'expectedSessionId' OR p_session ? 'expectedFamilyId'
       OR p_session ? 'expectedContinuationId' THEN
      RAISE EXCEPTION 'invalid primary passkey session intent' USING ERRCODE = '22023';
    END IF;
    SELECT credential.tenant_id, credential.user_id, subject.identity_epoch,
      subject.session_invalidation_epoch
      INTO STRICT v_tenant_id, v_user_id, v_identity_epoch, v_session_epoch
    FROM public.tenant_webauthn_credentials AS credential
    JOIN public.tenant_mfa_subjects AS subject
      ON subject.tenant_id = credential.tenant_id AND subject.user_id = credential.user_id
    JOIN public.tenant_memberships AS membership
      ON membership.tenant_id = credential.tenant_id AND membership.user_id = credential.user_id
    JOIN public.users AS identity ON identity.id = credential.user_id
    WHERE credential.id = p_primary_id AND credential.version = p_primary_revision
      AND (credential.status = 'active'
        OR (v_mutation = 'revoke' AND credential.status = 'clone_suspected'))
      AND membership.status = 'active' AND identity.active;
    IF v_anchor.tenant_id IS DISTINCT FROM v_tenant_id
       OR (v_anchor.user_id IS NOT NULL AND v_anchor.user_id IS DISTINCT FROM v_user_id)
       OR (v_anchor.identity_epoch IS NOT NULL AND v_anchor.identity_epoch IS DISTINCT FROM v_identity_epoch)
       OR coalesce((p_session ->> 'expectedIdentityEpoch')::bigint, v_identity_epoch)
          NOT IN (0, v_identity_epoch) THEN
      RAISE EXCEPTION 'primary passkey subject drifted' USING ERRCODE = '40001';
    END IF;
    v_primary_kind := 'passkey';
    v_primary_id := p_primary_id;
    v_primary_revision := p_primary_revision;
    v_primary_authenticated_at := p_completed_at;
    v_policy_snapshot := app.private_mfa_policy_snapshot_v1(
      v_tenant_id, v_user_id, v_anchor.action, p_completed_at
    );
  ELSE
    v_tenant_id := v_anchor.tenant_id;
    v_user_id := v_anchor.user_id;
    v_identity_epoch := v_anchor.identity_epoch;
    SELECT subject.session_invalidation_epoch INTO STRICT v_session_epoch
    FROM public.tenant_mfa_subjects AS subject
    JOIN public.tenant_memberships AS membership
      ON membership.tenant_id = subject.tenant_id AND membership.user_id = subject.user_id
    JOIN public.users AS identity ON identity.id = subject.user_id
    WHERE subject.tenant_id = v_tenant_id AND subject.user_id = v_user_id
      AND subject.identity_epoch = v_identity_epoch
      AND membership.status = 'active' AND identity.active;
    IF (p_session ->> 'expectedIdentityEpoch')::bigint IS DISTINCT FROM v_identity_epoch THEN
      RAISE EXCEPTION 'MFA subject epoch drifted' USING ERRCODE = '40001';
    END IF;
  END IF;

  IF v_mutation = 'retain_continuation' THEN
    IF v_anchor.flow <> 'continuation' OR p_session ? 'reservation'
       OR app.private_mfa_require_uuidv7_v1(p_session ->> 'expectedContinuationId')
          IS DISTINCT FROM v_anchor.continuation_id THEN
      RAISE EXCEPTION 'invalid continuation retention' USING ERRCODE = '22023';
    END IF;
    UPDATE public.tenant_post_primary_continuations AS continuation
    SET version = continuation.version + 1
    WHERE continuation.tenant_id = v_tenant_id
      AND continuation.id = v_anchor.continuation_id
      AND continuation.user_id = v_user_id
      AND continuation.identity_epoch = v_identity_epoch
      AND continuation.session_invalidation_epoch = v_session_epoch
      AND continuation.state = 'pending'
      AND continuation.version = v_anchor.anchor_version
      AND continuation.expires_at = v_anchor.anchor_expires_at
      AND continuation.expires_at > p_completed_at
    RETURNING continuation.version, continuation.id
      INTO v_new_version, v_retained_continuation_id;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'continuation retention is stale' USING ERRCODE = '40001';
    END IF;
    RETURN jsonb_build_object(
      'mutation', v_mutation,
      'retainedContinuationId', v_retained_continuation_id::text,
      'sessionVersion', v_new_version,
      'recoveryRestricted', false
    );
  END IF;

  IF v_mutation = 'revoke' THEN
    IF p_session ? 'reservation' THEN
      RAISE EXCEPTION 'revocation cannot reserve credentials' USING ERRCODE = '22023';
    END IF;
    IF v_anchor.flow = 'session' THEN
      UPDATE public.auth_session_mfa_states AS state
      SET session_version = state.session_version + 1
      WHERE state.tenant_id = v_tenant_id AND state.session_id = v_anchor.session_id
        AND state.session_version = v_anchor.anchor_version
        AND state.identity_epoch = v_identity_epoch
      RETURNING state.session_version INTO v_new_version;
      IF NOT FOUND THEN
        RAISE EXCEPTION 'session revocation is stale' USING ERRCODE = '40001';
      END IF;
      UPDATE public.auth_sessions AS session
      SET revoked_at = p_completed_at, revoke_reason = 'mfa_clone_suspected'
      WHERE session.user_id = v_user_id
        AND session.rotation_family_id = v_anchor.session_family_id
        AND session.revoked_at IS NULL;
      IF NOT FOUND THEN
        RAISE EXCEPTION 'session family is already revoked' USING ERRCODE = '40001';
      END IF;
      v_revoked_anchor_id := v_anchor.id;
    ELSIF v_anchor.flow = 'primary' THEN
      v_new_version := 1;
    ELSE
      RAISE EXCEPTION 'continuation clone revocation is invalid' USING ERRCODE = '22023';
    END IF;
    RETURN jsonb_strip_nulls(jsonb_build_object(
      'mutation', v_mutation,
      'revokedAnchorId', v_revoked_anchor_id::text,
      'sessionVersion', v_new_version,
      'recoveryRestricted', false
    ));
  END IF;

  IF NOT (p_session ? 'reservation') OR p_session -> 'reservation' = 'null'::jsonb THEN
    RAISE EXCEPTION 'session reservation is required' USING ERRCODE = '22023';
  END IF;
  v_reservation := p_session -> 'reservation';
  PERFORM app.private_mfa_assert_json_object_v1(
    v_reservation,
    ARRAY['sessionId','familyId','tokenDigest','csrfDigest','authenticationMethod',
      'idleExpiresAt','absoluteExpiresAt'],
    ARRAY['sessionId','familyId','tokenDigest','csrfDigest','authenticationMethod',
      'idleExpiresAt','absoluteExpiresAt'],
    16384
  );
  v_new_session_id := app.private_mfa_require_uuidv7_v1(v_reservation ->> 'sessionId');
  v_new_family_id := app.private_mfa_require_uuidv7_v1(v_reservation ->> 'familyId');
  v_token_digest := app.private_mfa_decode_base64_v1(v_reservation ->> 'tokenDigest', 32, 32);
  v_csrf_digest := app.private_mfa_decode_base64_v1(v_reservation ->> 'csrfDigest', 32, 32);
  v_authentication_method := v_reservation ->> 'authenticationMethod';
  v_idle_expires_at := (v_reservation ->> 'idleExpiresAt')::timestamptz;
  v_absolute_expires_at := (v_reservation ->> 'absoluteExpiresAt')::timestamptz;
  IF v_authentication_method NOT IN ('passkey','totp','recovery_code')
     OR encode(v_token_digest, 'hex') = repeat('00', 32)
     OR encode(v_csrf_digest, 'hex') = repeat('00', 32)
     OR v_token_digest = v_csrf_digest
     OR v_idle_expires_at <= p_completed_at
     OR v_absolute_expires_at <= p_completed_at
     OR v_idle_expires_at > v_absolute_expires_at
     OR v_idle_expires_at > p_completed_at + interval '24 hours'
     OR v_absolute_expires_at > p_completed_at + interval '31 days'
     OR date_trunc('milliseconds', v_idle_expires_at) <> v_idle_expires_at
     OR date_trunc('milliseconds', v_absolute_expires_at) <> v_absolute_expires_at
     OR v_new_session_id = v_new_family_id THEN
    RAISE EXCEPTION 'invalid session reservation' USING ERRCODE = '22023';
  END IF;

  v_token_lock := hashtextextended(encode(v_token_digest, 'hex'), 73124201);
  v_csrf_lock := hashtextextended(encode(v_csrf_digest, 'hex'), 73124201);
  PERFORM pg_advisory_xact_lock(least(v_token_lock, v_csrf_lock));
  IF v_token_lock <> v_csrf_lock THEN
    PERFORM pg_advisory_xact_lock(greatest(v_token_lock, v_csrf_lock));
  END IF;
  IF EXISTS (
    SELECT 1 FROM public.auth_sessions AS session
    WHERE session.token_digest IN (v_token_digest, v_csrf_digest)
       OR session.csrf_secret_digest IN (v_token_digest, v_csrf_digest)
  ) THEN
    RAISE EXCEPTION 'session reservation digest collision' USING ERRCODE = '40001';
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
      RAISE EXCEPTION 'invalid session rotation intent' USING ERRCODE = '22023';
    END IF;
    SELECT session.* INTO STRICT v_source_session
    FROM public.auth_sessions AS session
    WHERE session.id = v_anchor.session_id
      AND session.user_id = v_user_id
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
      AND state.user_id = v_user_id AND state.session_version = v_anchor.anchor_version
      AND state.identity_epoch = v_identity_epoch
      AND state.session_invalidation_epoch = v_session_epoch
    FOR UPDATE;
    v_primary_kind := v_source_state.primary_kind;
    IF v_primary_kind = 'local_credential' THEN
      SELECT provenance.credential_id, provenance.credential_revision,
        provenance.authenticated_at
        INTO STRICT v_primary_id, v_primary_revision, v_primary_authenticated_at
      FROM public.auth_session_local_credential_provenance AS provenance
      WHERE provenance.tenant_id = v_tenant_id
        AND provenance.session_id = v_source_state.session_id;
    ELSE
      SELECT provenance.credential_id, provenance.credential_revision,
        provenance.authenticated_at
        INTO STRICT v_primary_id, v_primary_revision, v_primary_authenticated_at
      FROM public.auth_session_passkey_provenance AS provenance
      WHERE provenance.tenant_id = v_tenant_id
        AND provenance.session_id = v_source_state.session_id;
    END IF;
    UPDATE public.auth_sessions AS session
    SET revoked_at = p_completed_at, revoke_reason = 'mfa_session_rotated'
    WHERE session.id = v_source_session.id AND session.revoked_at IS NULL;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'session rotation lost CAS' USING ERRCODE = '40001';
    END IF;
    v_new_version := v_anchor.anchor_version + 1;
  ELSIF v_anchor.flow = 'continuation' THEN
    IF v_mutation <> 'consume_continuation'
       OR app.private_mfa_require_uuidv7_v1(p_session ->> 'expectedContinuationId')
          IS DISTINCT FROM v_anchor.continuation_id
       OR p_session ? 'expectedSessionId' OR p_session ? 'expectedFamilyId' THEN
      RAISE EXCEPTION 'invalid continuation consumption intent' USING ERRCODE = '22023';
    END IF;
    SELECT continuation.* INTO STRICT v_continuation
    FROM public.tenant_post_primary_continuations AS continuation
    WHERE continuation.tenant_id = v_tenant_id
      AND continuation.id = v_anchor.continuation_id
      AND continuation.user_id = v_user_id
      AND continuation.identity_epoch = v_identity_epoch
      AND continuation.session_invalidation_epoch = v_session_epoch
      AND continuation.state = 'pending'
      AND continuation.version = v_anchor.anchor_version
      AND continuation.expires_at = v_anchor.anchor_expires_at
      AND continuation.expires_at > p_completed_at
    FOR UPDATE;
    v_primary_kind := v_continuation.primary_kind;
    v_primary_id := coalesce(v_continuation.local_credential_id, v_continuation.passkey_credential_id);
    v_primary_revision := v_continuation.primary_revision;
    v_primary_authenticated_at := v_continuation.created_at;
    UPDATE public.tenant_post_primary_continuations AS continuation
    SET state = 'consumed', version = continuation.version + 1,
      consumed_at = p_completed_at
    WHERE continuation.tenant_id = v_tenant_id
      AND continuation.id = v_continuation.id
      AND continuation.state = 'pending'
      AND continuation.version = v_continuation.version
    RETURNING continuation.version, continuation.id
      INTO v_new_version, v_consumed_continuation_id;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'continuation consumption lost CAS' USING ERRCODE = '40001';
    END IF;
  ELSIF v_anchor.flow = 'primary' THEN
    IF v_mutation <> 'create' OR v_new_family_id = v_new_session_id THEN
      RAISE EXCEPTION 'invalid primary session creation' USING ERRCODE = '22023';
    END IF;
    v_new_version := 1;
  ELSE
    RAISE EXCEPTION 'unsupported MFA authority flow' USING ERRCODE = '22023';
  END IF;

  -- Re-authenticating with the same primary passkey advances that credential's
  -- immutable provenance pin. A different step-up passkey must not rewrite the
  -- original primary source.
  IF p_evidence_kind = 'webauthn' AND v_primary_kind = 'passkey'
     AND v_primary_id = p_evidence_id THEN
    v_primary_revision := p_evidence_revision;
    v_primary_authenticated_at := p_completed_at;
  END IF;

  INSERT INTO public.auth_sessions (
    id, user_id, rotation_family_id, active_tenant_id, token_digest,
    csrf_secret_digest, authentication_method, mfa_satisfied_at,
    last_seen_at, idle_expires_at, absolute_expires_at,
    rotated_from_session_id, created_at
  ) VALUES (
    v_new_session_id, v_user_id, v_new_family_id, v_tenant_id,
    v_token_digest, v_csrf_digest, v_authentication_method, p_completed_at,
    p_completed_at, v_idle_expires_at, v_absolute_expires_at,
    CASE WHEN v_anchor.flow = 'session' THEN v_anchor.session_id ELSE NULL END,
    p_completed_at
  );
  INSERT INTO public.auth_session_mfa_states (
    session_id, tenant_id, user_id, session_version, identity_epoch,
    recovery_restricted, audience, primary_kind,
    session_invalidation_epoch, issued_at
  ) VALUES (
    v_new_session_id, v_tenant_id, v_user_id, v_new_version,
    v_identity_epoch, (p_session ->> 'recoveryRestricted')::boolean,
    v_anchor.audience, v_primary_kind, v_session_epoch, p_completed_at
  );
  IF v_primary_kind = 'local_credential' THEN
    INSERT INTO public.auth_session_local_credential_provenance (
      tenant_id, session_id, user_id, primary_kind, credential_id,
      credential_revision, authenticated_at
    ) VALUES (
      v_tenant_id, v_new_session_id, v_user_id, 'local_credential',
      v_primary_id, v_primary_revision, v_primary_authenticated_at
    );
  ELSIF v_primary_kind = 'passkey' THEN
    INSERT INTO public.auth_session_passkey_provenance (
      tenant_id, session_id, user_id, primary_kind, credential_id,
      credential_revision, authenticated_at
    ) VALUES (
      v_tenant_id, v_new_session_id, v_user_id, 'passkey',
      v_primary_id, v_primary_revision, v_primary_authenticated_at
    );
  ELSE
    RAISE EXCEPTION 'invalid typed primary provenance' USING ERRCODE = '23514';
  END IF;

  IF v_anchor.flow = 'primary' THEN
    FOR v_policy_entry IN SELECT value FROM jsonb_array_elements(v_policy_snapshot -> 'policies')
    LOOP
      INSERT INTO public.auth_session_mfa_policy_pins (
        tenant_id, session_id, policy_id, policy_revision
      ) VALUES (
        v_tenant_id, v_new_session_id,
        (v_policy_entry -> 'policy' ->> 'id')::uuid,
        (v_policy_entry -> 'policy' ->> 'revision')::bigint
      );
    END LOOP;
  ELSE
    INSERT INTO public.auth_session_mfa_policy_pins (
      tenant_id, session_id, policy_id, policy_revision
    ) SELECT pin.tenant_id, v_new_session_id, pin.policy_id, pin.policy_revision
    FROM public.tenant_mfa_authority_policy_pins AS pin
    WHERE pin.tenant_id = v_tenant_id AND pin.anchor_id = v_anchor.id;
  END IF;

  SELECT count(*) INTO v_evidence_count
  FROM public.tenant_mfa_authority_evidence AS evidence
  WHERE evidence.tenant_id = v_tenant_id AND evidence.anchor_id = v_anchor.id;
  IF p_evidence_kind IS NOT NULL THEN
    v_evidence_count := v_evidence_count + 1;
  END IF;
  IF v_evidence_count > 1024 THEN
    RAISE EXCEPTION 'MFA evidence snapshot limit reached' USING ERRCODE = '22023';
  END IF;

  INSERT INTO public.auth_session_mfa_evidence (
    id, tenant_id, session_id, local_credential_id, totp_factor_id,
    webauthn_credential_id, recovery_code_set_id, level, kind,
    provider_id, binding_id, authenticated_at, expires_at,
    factor_revision, trust_rule_revision
  ) SELECT uuidv7(), evidence.tenant_id, v_new_session_id,
    evidence.local_credential_id, evidence.totp_factor_id,
    evidence.webauthn_credential_id, evidence.recovery_code_set_id,
    evidence.level, evidence.kind, evidence.provider_id, evidence.binding_id,
    evidence.authenticated_at, evidence.expires_at,
    evidence.factor_revision, evidence.trust_rule_revision
  FROM public.tenant_mfa_authority_evidence AS evidence
  WHERE evidence.tenant_id = v_tenant_id AND evidence.anchor_id = v_anchor.id;

  IF p_evidence_kind IS NOT NULL THEN
    IF p_evidence_kind NOT IN ('totp','webauthn','recovery')
       OR p_evidence_id IS NULL OR p_evidence_revision < 1 THEN
      RAISE EXCEPTION 'invalid typed MFA evidence' USING ERRCODE = '22023';
    END IF;
    INSERT INTO public.auth_session_mfa_evidence (
      id, tenant_id, session_id, totp_factor_id, webauthn_credential_id,
      recovery_code_set_id, level, kind, authenticated_at, factor_revision
    ) VALUES (
      uuidv7(), v_tenant_id, v_new_session_id,
      CASE WHEN p_evidence_kind = 'totp' THEN p_evidence_id END,
      CASE WHEN p_evidence_kind = 'webauthn' THEN p_evidence_id END,
      CASE WHEN p_evidence_kind = 'recovery' THEN p_evidence_id END,
      CASE WHEN p_evidence_kind = 'webauthn' THEN 'phishing_resistant' ELSE 'mfa' END,
      p_evidence_kind, p_completed_at, p_evidence_revision
    );
  END IF;

  RETURN jsonb_strip_nulls(jsonb_build_object(
    'mutation', v_mutation,
    'newSessionId', v_new_session_id::text,
    'newSessionFamilyId', v_new_family_id::text,
    'consumedContinuationId', v_consumed_continuation_id::text,
    'sessionVersion', v_new_version,
    'recoveryRestricted', (p_session ->> 'recoveryRestricted')::boolean
  ));
EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
  RAISE EXCEPTION 'MFA session precondition is unavailable or ambiguous'
    USING ERRCODE = '40001';
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_mfa_decode_base64_v1(
  p_value text,
  p_minimum_bytes integer,
  p_maximum_bytes integer
)
RETURNS bytea
LANGUAGE plpgsql
IMMUTABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  decoded bytea;
BEGIN
  IF p_value IS NULL OR p_value = ''
     OR p_minimum_bytes < 0 OR p_maximum_bytes < p_minimum_bytes
     OR p_maximum_bytes > 2097152 THEN
    RAISE EXCEPTION 'invalid MFA encoded material' USING ERRCODE = '22023';
  END IF;
  BEGIN
    decoded := decode(p_value, 'base64');
  EXCEPTION WHEN OTHERS THEN
    RAISE EXCEPTION 'invalid MFA encoded material' USING ERRCODE = '22023';
  END;
  IF octet_length(decoded) NOT BETWEEN p_minimum_bytes AND p_maximum_bytes
     OR replace(encode(decoded, 'base64'), E'\n', '') <> p_value THEN
    RAISE EXCEPTION 'non-canonical MFA encoded material' USING ERRCODE = '22023';
  END IF;
  RETURN decoded;
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_mfa_require_uuidv7_v1(p_value text)
RETURNS uuid
LANGUAGE plpgsql
IMMUTABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  parsed uuid;
BEGIN
  BEGIN
    parsed := p_value::uuid;
  EXCEPTION WHEN OTHERS THEN
    RAISE EXCEPTION 'invalid MFA identifier' USING ERRCODE = '22023';
  END;
  IF parsed IS NULL OR NOT ((uuid_extract_version(parsed) = 7) IS TRUE) THEN
    RAISE EXCEPTION 'invalid MFA identifier' USING ERRCODE = '22023';
  END IF;
  RETURN parsed;
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_mfa_safe_text_v1(
  p_value text,
  p_maximum_length integer
)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
  SELECT p_value IS NOT NULL
     AND p_maximum_length BETWEEN 1 AND 1024
     AND btrim(p_value) = p_value
     AND char_length(p_value) BETWEEN 1 AND p_maximum_length
     AND p_value !~ '[[:cntrl:]]';
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_mfa_policy_snapshot_v1(
  p_tenant_id uuid,
  p_user_id uuid,
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
  v_membership_id uuid;
  v_role_ids jsonb := '[]'::jsonb;
  v_group_ids jsonb := '[]'::jsonb;
  v_policies jsonb;
  v_requirement jsonb;
  v_policy_count integer;
  v_baseline_count integer;
BEGIN
  IF p_tenant_id IS NULL OR p_evaluated_at IS NULL
     OR NOT app.private_mfa_safe_text_v1(p_action, 256)
     OR NOT EXISTS (
       SELECT 1 FROM public.tenants AS tenant
       WHERE tenant.id = p_tenant_id AND tenant.status = 'active'
     ) THEN
    RAISE EXCEPTION 'MFA policy context is unavailable' USING ERRCODE = '42501';
  END IF;

  IF p_user_id IS NOT NULL THEN
    SELECT membership.id INTO STRICT v_membership_id
    FROM public.tenant_memberships AS membership
    JOIN public.users AS identity ON identity.id = membership.user_id
    WHERE membership.tenant_id = p_tenant_id
      AND membership.user_id = p_user_id
      AND membership.status = 'active'
      AND identity.active;

    WITH effective_roles AS (
      SELECT grant_row.role_id
      FROM public.tenant_membership_role_grants AS grant_row
      JOIN public.tenant_authorization_sources AS source
        ON source.tenant_id = grant_row.tenant_id
       AND source.id = grant_row.source_id
      JOIN public.tenant_roles AS role
        ON role.tenant_id = grant_row.tenant_id
       AND role.id = grant_row.role_id
      WHERE grant_row.tenant_id = p_tenant_id
        AND grant_row.membership_id = v_membership_id
        AND grant_row.revoked_at IS NULL
        AND (grant_row.expires_at IS NULL OR grant_row.expires_at > p_evaluated_at)
        AND source.retired_at IS NULL
        AND role.archived_at IS NULL
      UNION
      SELECT group_role.role_id
      FROM public.tenant_security_group_memberships AS group_member
      JOIN public.tenant_authorization_sources AS member_source
        ON member_source.tenant_id = group_member.tenant_id
       AND member_source.id = group_member.source_id
      JOIN public.tenant_security_groups AS security_group
        ON security_group.tenant_id = group_member.tenant_id
       AND security_group.id = group_member.group_id
      JOIN public.tenant_security_group_role_grants AS group_role
        ON group_role.tenant_id = group_member.tenant_id
       AND group_role.group_id = group_member.group_id
      JOIN public.tenant_authorization_sources AS role_source
        ON role_source.tenant_id = group_role.tenant_id
       AND role_source.id = group_role.source_id
      JOIN public.tenant_roles AS role
        ON role.tenant_id = group_role.tenant_id
       AND role.id = group_role.role_id
      WHERE group_member.tenant_id = p_tenant_id
        AND group_member.membership_id = v_membership_id
        AND group_member.revoked_at IS NULL
        AND (group_member.expires_at IS NULL OR group_member.expires_at > p_evaluated_at)
        AND member_source.retired_at IS NULL
        AND security_group.archived_at IS NULL
        AND group_role.revoked_at IS NULL
        AND (group_role.expires_at IS NULL OR group_role.expires_at > p_evaluated_at)
        AND role_source.retired_at IS NULL
        AND role.archived_at IS NULL
    )
    SELECT coalesce(jsonb_agg(role_id::text ORDER BY role_id::text), '[]'::jsonb)
      INTO v_role_ids
    FROM effective_roles;

    SELECT coalesce(jsonb_agg(group_member.group_id::text ORDER BY group_member.group_id::text), '[]'::jsonb)
      INTO v_group_ids
    FROM public.tenant_security_group_memberships AS group_member
    JOIN public.tenant_authorization_sources AS source
      ON source.tenant_id = group_member.tenant_id
     AND source.id = group_member.source_id
    JOIN public.tenant_security_groups AS security_group
      ON security_group.tenant_id = group_member.tenant_id
     AND security_group.id = group_member.group_id
    WHERE group_member.tenant_id = p_tenant_id
      AND group_member.membership_id = v_membership_id
      AND group_member.revoked_at IS NULL
      AND (group_member.expires_at IS NULL OR group_member.expires_at > p_evaluated_at)
      AND source.retired_at IS NULL
      AND security_group.archived_at IS NULL;
  END IF;

  WITH applicable AS (
    SELECT revision.*,
      CASE revision.scope
        WHEN 'platform_floor' THEN 1
        WHEN 'tenant_baseline' THEN 2
        WHEN 'security_group' THEN 3
        WHEN 'role' THEN 4
        WHEN 'action' THEN 5
      END AS scope_order,
      CASE revision.scope
        WHEN 'role' THEN revision.role_id
        WHEN 'security_group' THEN revision.security_group_id
        ELSE NULL
      END AS target_id
    FROM public.mfa_policy_revisions AS revision
    WHERE revision.retired_at IS NULL
      AND (
        revision.scope = 'platform_floor'
        OR (revision.scope = 'tenant_baseline' AND revision.tenant_id = p_tenant_id)
        OR (revision.scope = 'action' AND revision.tenant_id = p_tenant_id AND revision.action = p_action)
        OR (revision.scope = 'role' AND revision.tenant_id = p_tenant_id
          AND v_role_ids @> jsonb_build_array(revision.role_id::text))
        OR (revision.scope = 'security_group' AND revision.tenant_id = p_tenant_id
          AND v_group_ids @> jsonb_build_array(revision.security_group_id::text))
      )
  ), inventory AS (
    SELECT count(*)::integer AS policy_count,
      count(*) FILTER (WHERE scope = 'tenant_baseline')::integer AS baseline_count,
      count(DISTINCT id)::integer AS distinct_count
    FROM applicable
  )
  SELECT inventory.policy_count, inventory.baseline_count,
    coalesce(jsonb_agg(
      jsonb_strip_nulls(jsonb_build_object(
        'scope', applicable.scope,
        'tenantId', CASE WHEN applicable.scope = 'platform_floor' THEN NULL ELSE applicable.tenant_id::text END,
        'targetId', applicable.target_id::text,
        'action', applicable.action,
        'policy', jsonb_build_object(
          'id', applicable.id::text,
          'revision', applicable.revision,
          'level', applicable.level,
          'localRequired', applicable.local_required,
          'freshnessNanoseconds', applicable.freshness_nanoseconds,
          'enrollmentDeadline', applicable.enrollment_deadline
        )
      )) ORDER BY applicable.scope_order, applicable.target_id::text NULLS FIRST, applicable.id::text
    ), '[]'::jsonb),
    jsonb_build_object(
      'level', CASE max(CASE applicable.level
        WHEN 'primary' THEN 1 WHEN 'mfa' THEN 2 WHEN 'phishing_resistant' THEN 3 END)
        WHEN 1 THEN 'primary' WHEN 2 THEN 'mfa' WHEN 3 THEN 'phishing_resistant' END,
      'localRequired', coalesce(bool_or(applicable.local_required), false),
      'freshnessNanoseconds', coalesce(min(applicable.freshness_nanoseconds)
        FILTER (WHERE applicable.freshness_nanoseconds > 0), 0),
      'enrollmentDeadline', min(applicable.enrollment_deadline),
      'policyRevisions', coalesce(jsonb_agg(
        jsonb_build_object('policyId', applicable.id::text, 'revision', applicable.revision)
        ORDER BY applicable.id::text
      ), '[]'::jsonb)
    )
  INTO v_policy_count, v_baseline_count, v_policies, v_requirement
  FROM applicable CROSS JOIN inventory
  GROUP BY inventory.policy_count, inventory.baseline_count;

  IF v_policy_count NOT BETWEEN 1 AND 1024 OR v_baseline_count <> 1
     OR (SELECT count(*) FROM jsonb_array_elements(v_policies)) <> v_policy_count
     OR (SELECT count(DISTINCT entry -> 'policy' ->> 'id') FROM jsonb_array_elements(v_policies) AS entry) <> v_policy_count THEN
    RAISE EXCEPTION 'MFA policy set is unavailable or ambiguous' USING ERRCODE = '42501';
  END IF;
  RETURN jsonb_build_object(
    'policyContext', jsonb_build_object(
      'tenantId', p_tenant_id::text,
      'roleIds', v_role_ids,
      'securityGroupIds', v_group_ids,
      'action', p_action
    ),
    'policies', v_policies,
    'requirement', v_requirement
  );
EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
  RAISE EXCEPTION 'MFA policy subject is unavailable or ambiguous' USING ERRCODE = '42501';
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_mfa_evidence_projection_v1(
  p_tenant_id uuid,
  p_source_kind text,
  p_source_id uuid
)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  result jsonb;
BEGIN
  IF p_source_kind = 'session' THEN
    SELECT coalesce(jsonb_agg(jsonb_strip_nulls(jsonb_build_object(
      'level', evidence.level,
      'kind', CASE WHEN evidence.kind = 'recovery' THEN 'recovery' ELSE 'factor' END,
      'local', evidence.kind <> 'provider',
      'providerId', evidence.provider_id::text,
      'bindingId', evidence.binding_id::text,
      'authenticatedAt', evidence.authenticated_at,
      'expiresAt', evidence.expires_at,
      'factorRevision', evidence.factor_revision,
      'trustRuleRevision', evidence.trust_rule_revision
    )) ORDER BY evidence.authenticated_at, evidence.id), '[]'::jsonb)
    INTO result
    FROM public.auth_session_mfa_evidence AS evidence
    WHERE evidence.tenant_id = p_tenant_id AND evidence.session_id = p_source_id;
  ELSIF p_source_kind = 'continuation' THEN
    SELECT coalesce(jsonb_agg(jsonb_strip_nulls(jsonb_build_object(
      'level', evidence.level,
      'kind', CASE WHEN evidence.kind = 'recovery' THEN 'recovery' ELSE 'factor' END,
      'local', evidence.kind <> 'provider',
      'providerId', evidence.provider_id::text,
      'bindingId', evidence.binding_id::text,
      'authenticatedAt', evidence.authenticated_at,
      'expiresAt', evidence.expires_at,
      'factorRevision', evidence.factor_revision,
      'trustRuleRevision', evidence.trust_rule_revision
    )) ORDER BY evidence.authenticated_at, evidence.id), '[]'::jsonb)
    INTO result
    FROM public.tenant_post_primary_continuation_evidence AS evidence
    WHERE evidence.tenant_id = p_tenant_id AND evidence.continuation_id = p_source_id;
  ELSIF p_source_kind = 'anchor' THEN
    SELECT coalesce(jsonb_agg(jsonb_strip_nulls(jsonb_build_object(
      'level', evidence.level,
      'kind', CASE WHEN evidence.kind = 'recovery' THEN 'recovery' ELSE 'factor' END,
      'local', evidence.kind <> 'provider',
      'providerId', evidence.provider_id::text,
      'bindingId', evidence.binding_id::text,
      'authenticatedAt', evidence.authenticated_at,
      'expiresAt', evidence.expires_at,
      'factorRevision', evidence.factor_revision,
      'trustRuleRevision', evidence.trust_rule_revision
    )) ORDER BY evidence.authenticated_at, evidence.id), '[]'::jsonb)
    INTO result
    FROM public.tenant_mfa_authority_evidence AS evidence
    WHERE evidence.tenant_id = p_tenant_id AND evidence.anchor_id = p_source_id;
  ELSE
    RAISE EXCEPTION 'invalid MFA evidence source' USING ERRCODE = '22023';
  END IF;
  RETURN result;
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_mfa_anchor_from_stepup_binding_v1(
  p_binding jsonb,
  p_created_at timestamptz
)
RETURNS uuid
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_flow text;
  v_reference_id uuid;
  v_snapshot jsonb;
  v_anchor_id uuid := uuidv7();
  v_tenant_id uuid;
  v_user_id uuid;
  v_source_id uuid;
  v_policy_entry jsonb;
BEGIN
  PERFORM app.private_mfa_assert_json_object_v1(
    p_binding,
    ARRAY['flow','tenantId','userId','identityEpoch','sessionId','sessionFamilyId',
      'continuationId','anchorVersion','anchorExpiresAt','anchorRecoveryRestricted',
      'action','audience','requirement','baselineEvidence'],
    ARRAY['flow','tenantId','userId','identityEpoch','anchorVersion','anchorExpiresAt',
      'anchorRecoveryRestricted','action','audience','requirement','baselineEvidence']
  );
  v_flow := p_binding ->> 'flow';
  IF v_flow = 'session' THEN
    v_reference_id := app.private_mfa_require_uuidv7_v1(p_binding ->> 'sessionId');
  ELSIF v_flow = 'continuation' THEN
    v_reference_id := app.private_mfa_require_uuidv7_v1(p_binding ->> 'continuationId');
  ELSE
    RAISE EXCEPTION 'invalid MFA binding flow' USING ERRCODE = '22023';
  END IF;
  v_snapshot := app.resolve_mfa_authority_v1(
    v_reference_id, v_flow, p_binding ->> 'action', p_binding ->> 'audience', p_created_at
  );
  IF v_snapshot ->> 'tenantId' IS DISTINCT FROM p_binding ->> 'tenantId'
     OR v_snapshot ->> 'userId' IS DISTINCT FROM p_binding ->> 'userId'
     OR (v_snapshot ->> 'identityEpoch')::bigint IS DISTINCT FROM (p_binding ->> 'identityEpoch')::bigint
     OR v_snapshot ->> 'sessionId' IS DISTINCT FROM p_binding ->> 'sessionId'
     OR v_snapshot ->> 'sessionFamilyId' IS DISTINCT FROM p_binding ->> 'sessionFamilyId'
     OR v_snapshot ->> 'continuationId' IS DISTINCT FROM p_binding ->> 'continuationId'
     OR (v_snapshot ->> 'anchorVersion')::bigint IS DISTINCT FROM (p_binding ->> 'anchorVersion')::bigint
     OR (v_snapshot ->> 'anchorExpiresAt')::timestamptz IS DISTINCT FROM (p_binding ->> 'anchorExpiresAt')::timestamptz
     OR (v_snapshot ->> 'anchorRecoveryRestricted')::boolean IS DISTINCT FROM (p_binding ->> 'anchorRecoveryRestricted')::boolean
     OR v_snapshot -> 'requirement' IS DISTINCT FROM p_binding -> 'requirement'
     OR jsonb_typeof(p_binding -> 'baselineEvidence') <> 'array'
     OR v_snapshot -> 'baselineEvidence' IS DISTINCT FROM p_binding -> 'baselineEvidence'
     OR jsonb_array_length(p_binding -> 'baselineEvidence') > 1024 THEN
    RAISE EXCEPTION 'MFA binding drifted from live authority' USING ERRCODE = '40001';
  END IF;
  v_tenant_id := (v_snapshot ->> 'tenantId')::uuid;
  v_user_id := (v_snapshot ->> 'userId')::uuid;
  v_source_id := v_reference_id;
  INSERT INTO public.tenant_mfa_authority_anchors (
    id, tenant_id, user_id, flow, identity_epoch, session_id,
    session_family_id, continuation_id, anchor_version, anchor_expires_at,
    recovery_restricted, action, audience, requirement_level, local_required,
    freshness_nanoseconds, enrollment_deadline, created_at
  ) VALUES (
    v_anchor_id, v_tenant_id, v_user_id, v_flow,
    (v_snapshot ->> 'identityEpoch')::bigint,
    nullif(v_snapshot ->> 'sessionId', '')::uuid,
    nullif(v_snapshot ->> 'sessionFamilyId', '')::uuid,
    nullif(v_snapshot ->> 'continuationId', '')::uuid,
    (v_snapshot ->> 'anchorVersion')::bigint,
    (v_snapshot ->> 'anchorExpiresAt')::timestamptz,
    (v_snapshot ->> 'anchorRecoveryRestricted')::boolean,
    v_snapshot ->> 'action', v_snapshot ->> 'audience',
    v_snapshot -> 'requirement' ->> 'level',
    (v_snapshot -> 'requirement' ->> 'localRequired')::boolean,
    (v_snapshot -> 'requirement' ->> 'freshnessNanoseconds')::bigint,
    nullif(v_snapshot -> 'requirement' ->> 'enrollmentDeadline', '')::timestamptz,
    p_created_at
  );

  FOR v_policy_entry IN SELECT value FROM jsonb_array_elements(v_snapshot -> 'policies')
  LOOP
    INSERT INTO public.tenant_mfa_authority_policy_pins (
      tenant_id, anchor_id, policy_id, policy_revision, scope,
      role_id, security_group_id, action
    ) VALUES (
      v_tenant_id, v_anchor_id,
      (v_policy_entry -> 'policy' ->> 'id')::uuid,
      (v_policy_entry -> 'policy' ->> 'revision')::bigint,
      v_policy_entry ->> 'scope',
      CASE WHEN v_policy_entry ->> 'scope' = 'role'
        THEN (v_policy_entry ->> 'targetId')::uuid ELSE NULL END,
      CASE WHEN v_policy_entry ->> 'scope' = 'security_group'
        THEN (v_policy_entry ->> 'targetId')::uuid ELSE NULL END,
      CASE WHEN v_policy_entry ->> 'scope' = 'action'
        THEN v_policy_entry ->> 'action' ELSE NULL END
    );
  END LOOP;

  IF v_flow = 'session' THEN
    INSERT INTO public.tenant_mfa_authority_evidence (
      id, tenant_id, anchor_id, local_credential_id, totp_factor_id,
      webauthn_credential_id, recovery_code_set_id, level, kind,
      provider_id, binding_id, authenticated_at, expires_at,
      factor_revision, trust_rule_revision
    ) SELECT uuidv7(), v_tenant_id, v_anchor_id, evidence.local_credential_id,
      evidence.totp_factor_id, evidence.webauthn_credential_id,
      evidence.recovery_code_set_id, evidence.level, evidence.kind,
      evidence.provider_id, evidence.binding_id, evidence.authenticated_at,
      evidence.expires_at, evidence.factor_revision, evidence.trust_rule_revision
    FROM public.auth_session_mfa_evidence AS evidence
    WHERE evidence.tenant_id = v_tenant_id AND evidence.session_id = v_source_id;
  ELSE
    INSERT INTO public.tenant_mfa_authority_evidence (
      id, tenant_id, anchor_id, local_credential_id, totp_factor_id,
      webauthn_credential_id, recovery_code_set_id, level, kind,
      provider_id, binding_id, authenticated_at, expires_at,
      factor_revision, trust_rule_revision
    ) SELECT uuidv7(), v_tenant_id, v_anchor_id, evidence.local_credential_id,
      evidence.totp_factor_id, evidence.webauthn_credential_id,
      evidence.recovery_code_set_id, evidence.level, evidence.kind,
      evidence.provider_id, evidence.binding_id, evidence.authenticated_at,
      evidence.expires_at, evidence.factor_revision, evidence.trust_rule_revision
    FROM public.tenant_post_primary_continuation_evidence AS evidence
    WHERE evidence.tenant_id = v_tenant_id AND evidence.continuation_id = v_source_id;
  END IF;
  RETURN v_anchor_id;
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_mfa_anchor_from_webauthn_binding_v1(
  p_binding jsonb,
  p_created_at timestamptz
)
RETURNS uuid
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_purpose text := p_binding ->> 'purpose';
  v_flow text;
  v_stepup_binding jsonb;
  v_tenant_id uuid;
  v_user_id uuid;
  v_policy_snapshot jsonb;
  v_anchor_id uuid;
  v_policy_entry jsonb;
BEGIN
  PERFORM app.private_mfa_assert_json_object_v1(
    p_binding,
    ARRAY['purpose','tenantId','userId','identityEpoch','sessionId','sessionFamilyId',
      'continuationId','anchorVersion','anchorExpiresAt','anchorRecoveryRestricted',
      'action','audience','requirement','baselineEvidence'],
    ARRAY['purpose','tenantId','identityEpoch','anchorVersion','anchorRecoveryRestricted',
      'action','audience','requirement','baselineEvidence']
  );
  IF v_purpose = 'primary_authentication' THEN
    v_tenant_id := app.private_mfa_require_uuidv7_v1(p_binding ->> 'tenantId');
    IF p_binding ? 'userId' THEN
      v_user_id := app.private_mfa_require_uuidv7_v1(p_binding ->> 'userId');
      IF NOT EXISTS (
        SELECT 1 FROM public.tenant_mfa_subjects AS subject
        JOIN public.tenant_memberships AS membership
          ON membership.tenant_id = subject.tenant_id AND membership.user_id = subject.user_id
        JOIN public.users AS identity ON identity.id = subject.user_id
        WHERE subject.tenant_id = v_tenant_id AND subject.user_id = v_user_id
          AND subject.identity_epoch = (p_binding ->> 'identityEpoch')::bigint
          AND membership.status = 'active' AND identity.active
      ) THEN
        RAISE EXCEPTION 'primary passkey subject is stale' USING ERRCODE = '42501';
      END IF;
    ELSIF (p_binding ->> 'identityEpoch')::bigint <> 0 THEN
      RAISE EXCEPTION 'discoverable passkey binding is invalid' USING ERRCODE = '22023';
    END IF;
    v_policy_snapshot := app.private_mfa_policy_snapshot_v1(
      v_tenant_id, v_user_id, p_binding ->> 'action', p_created_at
    );
    IF v_policy_snapshot -> 'requirement' IS DISTINCT FROM p_binding -> 'requirement'
       OR p_binding ? 'sessionId' OR p_binding ? 'sessionFamilyId'
       OR p_binding ? 'continuationId'
       OR coalesce((p_binding ->> 'anchorVersion')::bigint, 0) <> 0
       OR coalesce((p_binding ->> 'anchorRecoveryRestricted')::boolean, false) THEN
      RAISE EXCEPTION 'primary passkey binding drifted' USING ERRCODE = '40001';
    END IF;
    v_anchor_id := uuidv7();
    INSERT INTO public.tenant_mfa_authority_anchors (
      id, tenant_id, user_id, flow, identity_epoch, recovery_restricted,
      action, audience, requirement_level, local_required,
      freshness_nanoseconds, enrollment_deadline, created_at
    ) VALUES (
      v_anchor_id, v_tenant_id, v_user_id, 'primary',
      CASE WHEN v_user_id IS NULL THEN NULL ELSE (p_binding ->> 'identityEpoch')::bigint END,
      false, p_binding ->> 'action', p_binding ->> 'audience',
      p_binding -> 'requirement' ->> 'level',
      (p_binding -> 'requirement' ->> 'localRequired')::boolean,
      (p_binding -> 'requirement' ->> 'freshnessNanoseconds')::bigint,
      nullif(p_binding -> 'requirement' ->> 'enrollmentDeadline', '')::timestamptz,
      p_created_at
    );
    FOR v_policy_entry IN SELECT value FROM jsonb_array_elements(v_policy_snapshot -> 'policies')
    LOOP
      INSERT INTO public.tenant_mfa_authority_policy_pins (
        tenant_id, anchor_id, policy_id, policy_revision, scope,
        role_id, security_group_id, action
      ) VALUES (
        v_tenant_id, v_anchor_id,
        (v_policy_entry -> 'policy' ->> 'id')::uuid,
        (v_policy_entry -> 'policy' ->> 'revision')::bigint,
        v_policy_entry ->> 'scope',
        CASE WHEN v_policy_entry ->> 'scope' = 'role'
          THEN (v_policy_entry ->> 'targetId')::uuid ELSE NULL END,
        CASE WHEN v_policy_entry ->> 'scope' = 'security_group'
          THEN (v_policy_entry ->> 'targetId')::uuid ELSE NULL END,
        CASE WHEN v_policy_entry ->> 'scope' = 'action'
          THEN v_policy_entry ->> 'action' ELSE NULL END
      );
    END LOOP;
    RETURN v_anchor_id;
  END IF;

  IF v_purpose NOT IN ('registration','continuation_authentication','step_up_authentication') THEN
    RAISE EXCEPTION 'unsupported passkey purpose' USING ERRCODE = '22023';
  END IF;
  v_flow := CASE WHEN p_binding ? 'sessionId' THEN 'session'
    WHEN p_binding ? 'continuationId' THEN 'continuation' END;
  IF v_flow IS NULL THEN
    RAISE EXCEPTION 'passkey binding has no live anchor' USING ERRCODE = '22023';
  END IF;
  v_stepup_binding := (p_binding - 'purpose') || jsonb_build_object('flow', v_flow);
  RETURN app.private_mfa_anchor_from_stepup_binding_v1(v_stepup_binding, p_created_at);
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_mfa_anchor_binding_v1(
  p_anchor_id uuid,
  p_purpose text DEFAULT NULL
)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  anchor public.tenant_mfa_authority_anchors%ROWTYPE;
  revisions jsonb;
  result jsonb;
BEGIN
  SELECT * INTO STRICT anchor
  FROM public.tenant_mfa_authority_anchors
  WHERE id = p_anchor_id;
  SELECT coalesce(jsonb_agg(
    jsonb_build_object('policyId', pin.policy_id::text, 'revision', pin.policy_revision)
    ORDER BY pin.policy_id::text
  ), '[]'::jsonb) INTO revisions
  FROM public.tenant_mfa_authority_policy_pins AS pin
  WHERE pin.tenant_id = anchor.tenant_id AND pin.anchor_id = anchor.id;
  result := jsonb_strip_nulls(jsonb_build_object(
    CASE WHEN p_purpose IS NULL THEN 'flow' ELSE 'purpose' END,
      coalesce(p_purpose, anchor.flow),
    'tenantId', anchor.tenant_id::text,
    'userId', anchor.user_id::text,
    'identityEpoch', coalesce(anchor.identity_epoch, 0),
    'sessionId', anchor.session_id::text,
    'sessionFamilyId', anchor.session_family_id::text,
    'continuationId', anchor.continuation_id::text,
    'anchorVersion', coalesce(anchor.anchor_version, 0),
    'anchorExpiresAt', anchor.anchor_expires_at,
    'anchorRecoveryRestricted', anchor.recovery_restricted,
    'action', anchor.action,
    'audience', anchor.audience,
    'requirement', jsonb_build_object(
      'level', anchor.requirement_level,
      'localRequired', anchor.local_required,
      'freshnessNanoseconds', anchor.freshness_nanoseconds,
      'enrollmentDeadline', anchor.enrollment_deadline,
      'policyRevisions', revisions
    ),
    'baselineEvidence', app.private_mfa_evidence_projection_v1(
      anchor.tenant_id, 'anchor', anchor.id
    )
  ));
  -- The Go WebAuthn wire keeps the nullable expiry key, while the step-up
  -- wire can only represent a live non-primary expiry.
  IF p_purpose IS NOT NULL AND NOT (result ? 'anchorExpiresAt') THEN
    result := result || jsonb_build_object('anchorExpiresAt', NULL);
  END IF;
  RETURN result;
EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
  RAISE EXCEPTION 'MFA authority anchor is unavailable' USING ERRCODE = '42501';
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.resolve_mfa_authority_v1(
  p_reference_id uuid,
  p_flow text,
  p_action text,
  p_audience text,
  p_evaluated_at timestamptz
)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_session_match record;
  v_continuation_match record;
  v_concrete_flow text;
  v_tenant_id uuid;
  v_user_id uuid;
  v_identity_epoch bigint;
  v_session_id uuid;
  v_session_family_id uuid;
  v_continuation_id uuid;
  v_anchor_version bigint;
  v_anchor_expires_at timestamptz;
  v_recovery_restricted boolean;
  v_policy_snapshot jsonb;
  v_evidence jsonb;
  v_totp_ids jsonb;
  v_recovery_set record;
  v_passkey_handle bytea;
  v_passkey_ids jsonb;
  v_session_found boolean := false;
  v_continuation_found boolean := false;
BEGIN
  IF p_reference_id IS NULL OR p_flow NOT IN ('session', 'continuation', 'enrollment')
     OR NOT app.private_mfa_safe_text_v1(p_action, 256)
     OR NOT app.private_mfa_safe_text_v1(p_audience, 256)
     OR p_evaluated_at IS NULL THEN
    RAISE EXCEPTION 'invalid MFA authority lookup' USING ERRCODE = '22023';
  END IF;

  IF p_flow IN ('session', 'enrollment') THEN
    SELECT state.tenant_id, state.user_id, state.identity_epoch,
      state.session_id, session.rotation_family_id AS session_family_id,
      state.session_version AS anchor_version,
      least(session.idle_expires_at, session.absolute_expires_at) AS anchor_expires_at,
      state.recovery_restricted, state.audience,
      subject.session_invalidation_epoch,
      session.revoked_at
    INTO v_session_match
    FROM public.auth_session_mfa_states AS state
    JOIN public.auth_sessions AS session ON session.id = state.session_id
    JOIN public.tenant_mfa_subjects AS subject
      ON subject.tenant_id = state.tenant_id AND subject.user_id = state.user_id
    WHERE state.session_id = p_reference_id
      AND session.active_tenant_id = state.tenant_id
      AND session.user_id = state.user_id;
    v_session_found := FOUND;
    IF v_session_found AND (
      v_session_match.revoked_at IS NOT NULL
      OR v_session_match.anchor_expires_at <= p_evaluated_at
      OR v_session_match.audience <> p_audience
    ) THEN
      v_session_found := false;
    END IF;
  END IF;

  IF p_flow IN ('continuation', 'enrollment') THEN
    SELECT continuation.tenant_id, continuation.user_id,
      continuation.identity_epoch, continuation.id AS continuation_id,
      continuation.version AS anchor_version,
      continuation.expires_at AS anchor_expires_at,
      false AS recovery_restricted, continuation.audience,
      continuation.session_invalidation_epoch,
      subject.session_invalidation_epoch AS live_invalidation_epoch,
      continuation.state
    INTO v_continuation_match
    FROM public.tenant_post_primary_continuations AS continuation
    JOIN public.tenant_mfa_subjects AS subject
      ON subject.tenant_id = continuation.tenant_id
     AND subject.user_id = continuation.user_id
    WHERE continuation.id = p_reference_id;
    v_continuation_found := FOUND;
    IF v_continuation_found AND (
      v_continuation_match.state <> 'pending'
      OR v_continuation_match.anchor_expires_at <= p_evaluated_at
      OR v_continuation_match.audience <> p_audience
      OR v_continuation_match.session_invalidation_epoch <> v_continuation_match.live_invalidation_epoch
    ) THEN
      v_continuation_found := false;
    END IF;
  END IF;

  IF (p_flow = 'session' AND NOT v_session_found)
     OR (p_flow = 'continuation' AND NOT v_continuation_found)
     OR (p_flow = 'enrollment' AND v_session_found = v_continuation_found) THEN
    RAISE EXCEPTION 'MFA authority is unavailable or ambiguous' USING ERRCODE = '42501';
  END IF;

  IF v_session_found THEN
    v_concrete_flow := 'session';
    v_tenant_id := v_session_match.tenant_id;
    v_user_id := v_session_match.user_id;
    v_identity_epoch := v_session_match.identity_epoch;
    v_session_id := v_session_match.session_id;
    v_session_family_id := v_session_match.session_family_id;
    v_anchor_version := v_session_match.anchor_version;
    v_anchor_expires_at := v_session_match.anchor_expires_at;
    v_recovery_restricted := v_session_match.recovery_restricted;
    v_evidence := app.private_mfa_evidence_projection_v1(v_tenant_id, 'session', v_session_id);
  ELSE
    v_concrete_flow := 'continuation';
    v_tenant_id := v_continuation_match.tenant_id;
    v_user_id := v_continuation_match.user_id;
    v_identity_epoch := v_continuation_match.identity_epoch;
    v_continuation_id := v_continuation_match.continuation_id;
    v_anchor_version := v_continuation_match.anchor_version;
    v_anchor_expires_at := v_continuation_match.anchor_expires_at;
    v_recovery_restricted := false;
    v_evidence := app.private_mfa_evidence_projection_v1(v_tenant_id, 'continuation', v_continuation_id);
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM public.tenant_mfa_subjects AS subject
    WHERE subject.tenant_id = v_tenant_id AND subject.user_id = v_user_id
      AND subject.identity_epoch = v_identity_epoch
  ) THEN
    RAISE EXCEPTION 'MFA subject epoch is stale' USING ERRCODE = '42501';
  END IF;

  v_policy_snapshot := app.private_mfa_policy_snapshot_v1(v_tenant_id, v_user_id, p_action, p_evaluated_at);
  SELECT subject.webauthn_user_handle INTO STRICT v_passkey_handle
  FROM public.tenant_mfa_subjects AS subject
  WHERE subject.tenant_id = v_tenant_id AND subject.user_id = v_user_id;
  SELECT coalesce(jsonb_agg(replace(encode(credential.credential_id, 'base64'), E'\n', '') ORDER BY credential.credential_id), '[]'::jsonb)
    INTO v_passkey_ids
  FROM public.tenant_webauthn_credentials AS credential
  WHERE credential.tenant_id = v_tenant_id AND credential.user_id = v_user_id
    AND credential.status = 'active';
  SELECT coalesce(jsonb_agg(factor.id::text ORDER BY factor.id::text), '[]'::jsonb)
    INTO v_totp_ids
  FROM public.tenant_totp_factors AS factor
  WHERE factor.tenant_id = v_tenant_id AND factor.user_id = v_user_id
    AND factor.status = 'active';
  SELECT code_set.id, code_set.record_version INTO v_recovery_set
  FROM public.tenant_recovery_code_sets AS code_set
  WHERE code_set.tenant_id = v_tenant_id AND code_set.user_id = v_user_id
    AND code_set.status = 'active'
    AND EXISTS (
      SELECT 1 FROM public.tenant_recovery_codes AS code
      WHERE code.tenant_id = code_set.tenant_id AND code.set_id = code_set.id
        AND code.consumed_at IS NULL
    );

  RETURN jsonb_strip_nulls(jsonb_build_object(
    'loadedAt', p_evaluated_at,
    'flow', v_concrete_flow,
    'tenantId', v_tenant_id::text,
    'userId', v_user_id::text,
    'identityEpoch', v_identity_epoch,
    'sessionId', v_session_id::text,
    'sessionFamilyId', v_session_family_id::text,
    'continuationId', v_continuation_id::text,
    'anchorVersion', v_anchor_version,
    'anchorExpiresAt', v_anchor_expires_at,
    'anchorRecoveryRestricted', v_recovery_restricted,
    'action', p_action,
    'audience', p_audience,
    'policyContext', v_policy_snapshot -> 'policyContext',
    'policies', v_policy_snapshot -> 'policies',
    'requirement', v_policy_snapshot -> 'requirement',
    'baselineEvidence', v_evidence,
    'totpFactorIds', v_totp_ids,
    'recoveryAvailable', v_recovery_set.id IS NOT NULL,
    'recoverySetId', v_recovery_set.id::text,
    'recoverySetVersion', coalesce(v_recovery_set.record_version, 0),
    'passkeyUserHandle', replace(encode(v_passkey_handle, 'base64'), E'\n', ''),
    'passkeyCredentialIds', v_passkey_ids
  ));
EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
  RAISE EXCEPTION 'MFA authority is unavailable or ambiguous' USING ERRCODE = '42501';
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.resolve_primary_passkey_v1(
  p_reference_id uuid,
  p_action text,
  p_audience text,
  p_evaluated_at timestamptz
)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_subject_match record;
  v_tenant_match uuid;
  v_subject_found boolean := false;
  v_tenant_found boolean := false;
  v_tenant_id uuid;
  v_user_id uuid;
  v_identity_epoch bigint := 0;
  v_policy_snapshot jsonb;
  v_credential_ids jsonb := '[]'::jsonb;
  v_user_handle bytea;
  v_mode text;
BEGIN
  IF p_reference_id IS NULL OR NOT app.private_mfa_safe_text_v1(p_action, 256)
     OR NOT app.private_mfa_safe_text_v1(p_audience, 256) OR p_evaluated_at IS NULL THEN
    RAISE EXCEPTION 'invalid primary passkey lookup' USING ERRCODE = '22023';
  END IF;
  SELECT subject.tenant_id, subject.user_id, subject.identity_epoch,
    subject.webauthn_user_handle
  INTO v_subject_match
  FROM public.tenant_mfa_subjects AS subject
  JOIN public.tenant_memberships AS membership
    ON membership.tenant_id = subject.tenant_id AND membership.user_id = subject.user_id
  JOIN public.users AS identity ON identity.id = subject.user_id
  JOIN public.tenants AS tenant ON tenant.id = subject.tenant_id
  WHERE subject.user_id = p_reference_id
    AND membership.status = 'active' AND identity.active AND tenant.status = 'active';
  v_subject_found := FOUND;

  SELECT tenant.id INTO v_tenant_match
  FROM public.tenants AS tenant
  WHERE tenant.id = p_reference_id AND tenant.status = 'active';
  v_tenant_found := FOUND;
  IF v_subject_found = v_tenant_found THEN
    RAISE EXCEPTION 'primary passkey reference is unavailable or ambiguous' USING ERRCODE = '42501';
  END IF;

  IF v_subject_found THEN
    v_tenant_id := v_subject_match.tenant_id;
    v_user_id := v_subject_match.user_id;
    v_identity_epoch := v_subject_match.identity_epoch;
    v_user_handle := v_subject_match.webauthn_user_handle;
    v_mode := 'known_user';
    SELECT coalesce(jsonb_agg(replace(encode(credential.credential_id, 'base64'), E'\n', '') ORDER BY credential.credential_id), '[]'::jsonb)
      INTO v_credential_ids
    FROM public.tenant_webauthn_credentials AS credential
    WHERE credential.tenant_id = v_tenant_id AND credential.user_id = v_user_id
      AND credential.status = 'active';
    IF jsonb_array_length(v_credential_ids) = 0 THEN
      RAISE EXCEPTION 'primary passkey credential is unavailable' USING ERRCODE = '42501';
    END IF;
  ELSE
    v_tenant_id := v_tenant_match;
    v_mode := 'discoverable';
  END IF;
  v_policy_snapshot := app.private_mfa_policy_snapshot_v1(v_tenant_id, v_user_id, p_action, p_evaluated_at);
  RETURN jsonb_strip_nulls(jsonb_build_object(
    'referenceId', p_reference_id::text,
    'loadedAt', p_evaluated_at,
    'tenantId', v_tenant_id::text,
    'userId', v_user_id::text,
    'identityEpoch', v_identity_epoch,
    'action', p_action,
    'audience', p_audience,
    'policyContext', v_policy_snapshot -> 'policyContext',
    'policies', v_policy_snapshot -> 'policies',
    'mode', v_mode,
    'userHandle', CASE WHEN v_user_handle IS NULL THEN NULL ELSE replace(encode(v_user_handle, 'base64'), E'\n', '') END,
    'credentialIds', v_credential_ids
  ));
EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
  RAISE EXCEPTION 'primary passkey reference is unavailable or ambiguous' USING ERRCODE = '42501';
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.admit_mfa_operation_v1(
  p_operation_id uuid,
  p_network_digest bytea,
  p_principal_digest bytea,
  p_resource_digest bytea,
  p_evaluated_at timestamptz
)
RETURNS TABLE(outcome text, retry_at timestamptz)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  admission record;
BEGIN
  IF p_operation_id IS NULL OR NOT ((uuid_extract_version(p_operation_id) = 7) IS TRUE)
     OR octet_length(p_network_digest) <> 32
     OR octet_length(p_principal_digest) <> 32
     OR octet_length(p_resource_digest) <> 32
     OR p_evaluated_at IS NULL
     OR abs(extract(epoch FROM (transaction_timestamp() - p_evaluated_at))) > 300 THEN
    RAISE EXCEPTION 'invalid MFA admission input' USING ERRCODE = '22023';
  END IF;
  SELECT * INTO STRICT admission
  FROM app.admit_auth_attempts(
    ARRAY['mfa_challenge', 'mfa_challenge', 'mfa_challenge']::public.auth_rate_limit_scope[],
    ARRAY[
      sha256(convert_to('mfa-network-v1:', 'UTF8') || p_network_digest),
      sha256(convert_to('mfa-principal-v1:', 'UTF8') || p_principal_digest),
      sha256(convert_to('mfa-resource-v1:', 'UTF8') || p_resource_digest)
    ]::bytea[],
    ARRAY[60, 300, 300]::integer[],
    ARRAY[30, 12, 12]::integer[],
    ARRAY[60, 300, 300]::integer[]
  );
  IF admission.admitted THEN
    RETURN QUERY SELECT 'allowed'::text, NULL::timestamptz;
  ELSIF admission.blocked_until IS NOT NULL THEN
    RETURN QUERY SELECT 'locked'::text, admission.blocked_until;
  ELSE
    RETURN QUERY SELECT 'rate_limited'::text, transaction_timestamp() + interval '60 seconds';
  END IF;
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.create_webauthn_ceremony_v1(p_request jsonb)
RETURNS boolean
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_ceremony_id bytea;
  v_anchor_id uuid;
  v_challenge_digest bytea;
  v_browser_digest bytea;
  v_user_handle_digest bytea;
  v_created_at timestamptz;
  v_expires_at timestamptz;
  v_mode text;
  v_allowed jsonb;
  v_credential jsonb;
  v_ordinal integer := 0;
BEGIN
  PERFORM app.private_mfa_assert_json_object_v1(
    p_request,
    ARRAY['id','challengeDigest','browserDigest','relyingParty','binding','policy',
      'mode','userHandleDigest','allowedCredentialIds','createdAt','expiresAt',
      'state','version','claimedAt'],
    ARRAY['id','challengeDigest','browserDigest','relyingParty','binding','policy',
      'userHandleDigest','allowedCredentialIds','createdAt','expiresAt','state','version']
  );
  PERFORM app.private_mfa_assert_json_object_v1(
    p_request -> 'relyingParty', ARRAY['id','origins','revision'],
    ARRAY['id','origins','revision'], 65536
  );
  PERFORM app.private_mfa_assert_json_object_v1(
    p_request -> 'policy',
    ARRAY['requireUserPresence','userVerification','residentKey','attestation','metadataRevision'],
    ARRAY['requireUserPresence','userVerification','residentKey','attestation','metadataRevision'],
    16384
  );
  v_ceremony_id := app.private_mfa_decode_base64_v1(p_request ->> 'id', 32, 32);
  v_challenge_digest := app.private_mfa_decode_base64_v1(p_request ->> 'challengeDigest', 32, 32);
  v_browser_digest := app.private_mfa_decode_base64_v1(p_request ->> 'browserDigest', 32, 32);
  v_user_handle_digest := app.private_mfa_decode_base64_v1(p_request ->> 'userHandleDigest', 32, 32);
  v_created_at := (p_request ->> 'createdAt')::timestamptz;
  v_expires_at := (p_request ->> 'expiresAt')::timestamptz;
  v_mode := nullif(p_request ->> 'mode', '');
  v_allowed := p_request -> 'allowedCredentialIds';
  IF p_request ->> 'state' <> 'pending' OR (p_request ->> 'version')::bigint <> 1
     OR p_request ? 'claimedAt'
     OR NOT app.private_mfa_safe_text_v1(p_request -> 'relyingParty' ->> 'id', 253)
     OR (p_request -> 'relyingParty' ->> 'revision')::bigint < 1
     OR jsonb_typeof(p_request -> 'relyingParty' -> 'origins') <> 'array'
     OR jsonb_array_length(p_request -> 'relyingParty' -> 'origins') NOT BETWEEN 1 AND 16
     OR (SELECT count(DISTINCT value) FROM jsonb_array_elements(p_request -> 'relyingParty' -> 'origins'))
          <> jsonb_array_length(p_request -> 'relyingParty' -> 'origins')
     OR jsonb_typeof(v_allowed) <> 'array' OR jsonb_array_length(v_allowed) > 128
     OR NOT (p_request -> 'policy' ->> 'requireUserPresence')::boolean
     OR p_request -> 'policy' ->> 'userVerification' NOT IN ('preferred','required')
     OR p_request -> 'policy' ->> 'residentKey' NOT IN ('preferred','required')
     OR p_request -> 'policy' ->> 'attestation' NOT IN ('none','direct','enterprise')
     OR (p_request -> 'policy' ->> 'metadataRevision')::bigint < 0
     OR ((p_request -> 'policy' ->> 'attestation') = 'none')
          <> ((p_request -> 'policy' ->> 'metadataRevision')::bigint = 0)
     OR v_expires_at <= v_created_at OR v_expires_at > v_created_at + interval '15 minutes'
     OR abs(extract(epoch FROM (transaction_timestamp() - v_created_at))) > 300 THEN
    RAISE EXCEPTION 'invalid WebAuthn ceremony request' USING ERRCODE = '22023';
  END IF;
  v_anchor_id := app.private_mfa_anchor_from_webauthn_binding_v1(
    p_request -> 'binding', v_created_at
  );
  IF (p_request -> 'binding' ->> 'purpose') = 'registration' THEN
    IF v_mode IS NOT NULL OR encode(v_user_handle_digest, 'hex') = repeat('00', 32) THEN
      RAISE EXCEPTION 'invalid registration ceremony mode' USING ERRCODE = '22023';
    END IF;
  ELSIF v_mode = 'discoverable' THEN
    IF v_allowed <> '[]'::jsonb
       OR encode(v_user_handle_digest, 'hex') <> repeat('00', 32)
       OR p_request -> 'policy' ->> 'userVerification' <> 'required'
       OR p_request -> 'policy' ->> 'residentKey' <> 'required' THEN
      RAISE EXCEPTION 'invalid discoverable ceremony mode' USING ERRCODE = '22023';
    END IF;
    v_user_handle_digest := NULL;
  ELSIF v_mode <> 'known_user' OR encode(v_user_handle_digest, 'hex') = repeat('00', 32) THEN
    RAISE EXCEPTION 'invalid known-user ceremony mode' USING ERRCODE = '22023';
  END IF;
  INSERT INTO public.tenant_webauthn_ceremonies (
    id, tenant_id, authority_anchor_id, challenge_digest, browser_digest,
    rp_id, rp_revision, allowed_origins, purpose, mode, user_handle_digest,
    require_user_presence, user_verification, resident_key, attestation,
    metadata_revision, state, version, created_at, expires_at
  ) SELECT v_ceremony_id, anchor.tenant_id, anchor.id,
    v_challenge_digest, v_browser_digest,
    p_request -> 'relyingParty' ->> 'id',
    (p_request -> 'relyingParty' ->> 'revision')::bigint,
    ARRAY(SELECT jsonb_array_elements_text(p_request -> 'relyingParty' -> 'origins')),
    p_request -> 'binding' ->> 'purpose', v_mode, v_user_handle_digest,
    (p_request -> 'policy' ->> 'requireUserPresence')::boolean,
    p_request -> 'policy' ->> 'userVerification',
    p_request -> 'policy' ->> 'residentKey',
    p_request -> 'policy' ->> 'attestation',
    (p_request -> 'policy' ->> 'metadataRevision')::bigint,
    'pending', 1, v_created_at, v_expires_at
  FROM public.tenant_mfa_authority_anchors AS anchor
  WHERE anchor.id = v_anchor_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'WebAuthn ceremony authority is unavailable' USING ERRCODE = '42501';
  END IF;
  FOR v_credential IN SELECT value FROM jsonb_array_elements(v_allowed)
  LOOP
    IF jsonb_typeof(v_credential) <> 'string' THEN
      RAISE EXCEPTION 'invalid WebAuthn credential allow-list' USING ERRCODE = '22023';
    END IF;
    INSERT INTO public.tenant_webauthn_ceremony_credentials (
      tenant_id, ceremony_id, ordinal, credential_id
    ) SELECT anchor.tenant_id, v_ceremony_id, v_ordinal,
      app.private_mfa_decode_base64_v1(v_credential #>> '{}', 1, 4096)
    FROM public.tenant_mfa_authority_anchors AS anchor
    WHERE anchor.id = v_anchor_id;
    v_ordinal := v_ordinal + 1;
  END LOOP;
  RETURN true;
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_webauthn_ceremony_projection_v1(
  p_ceremony_id bytea
)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_ceremony public.tenant_webauthn_ceremonies%ROWTYPE;
  v_allowed jsonb;
BEGIN
  SELECT ceremony.* INTO STRICT v_ceremony
  FROM public.tenant_webauthn_ceremonies AS ceremony
  WHERE ceremony.id = p_ceremony_id;
  SELECT coalesce(jsonb_agg(
    replace(encode(entry.credential_id, 'base64'), E'\n', '')
    ORDER BY entry.ordinal
  ), '[]'::jsonb) INTO v_allowed
  FROM public.tenant_webauthn_ceremony_credentials AS entry
  WHERE entry.tenant_id = v_ceremony.tenant_id
    AND entry.ceremony_id = v_ceremony.id;
  RETURN jsonb_strip_nulls(jsonb_build_object(
    'id', replace(encode(v_ceremony.id, 'base64'), E'\n', ''),
    'challengeDigest', replace(encode(v_ceremony.challenge_digest, 'base64'), E'\n', ''),
    'browserDigest', replace(encode(v_ceremony.browser_digest, 'base64'), E'\n', ''),
    'relyingParty', jsonb_build_object(
      'id', v_ceremony.rp_id, 'origins', to_jsonb(v_ceremony.allowed_origins),
      'revision', v_ceremony.rp_revision
    ),
    'binding', app.private_mfa_anchor_binding_v1(
      v_ceremony.authority_anchor_id, v_ceremony.purpose
    ),
    'policy', jsonb_build_object(
      'requireUserPresence', v_ceremony.require_user_presence,
      'userVerification', v_ceremony.user_verification,
      'residentKey', v_ceremony.resident_key,
      'attestation', v_ceremony.attestation,
      'metadataRevision', v_ceremony.metadata_revision
    ),
    'mode', v_ceremony.mode,
    'userHandleDigest', CASE WHEN v_ceremony.user_handle_digest IS NULL
      THEN NULL ELSE replace(encode(v_ceremony.user_handle_digest, 'base64'), E'\n', '') END,
    'allowedCredentialIds', v_allowed,
    'createdAt', v_ceremony.created_at,
    'expiresAt', v_ceremony.expires_at,
    'state', v_ceremony.state,
    'version', v_ceremony.version,
    'claimedAt', v_ceremony.claimed_at
  ));
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.claim_webauthn_ceremony_v1(
  p_ceremony_id bytea,
  p_browser_digest bytea,
  p_claimed_at timestamptz
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF octet_length(p_ceremony_id) <> 32 OR octet_length(p_browser_digest) <> 32
     OR p_claimed_at IS NULL THEN
    RAISE EXCEPTION 'invalid WebAuthn ceremony claim' USING ERRCODE = '22023';
  END IF;
  UPDATE public.tenant_webauthn_ceremonies AS ceremony
  SET state = 'claimed', version = ceremony.version + 1,
    claimed_at = p_claimed_at
  WHERE ceremony.id = p_ceremony_id
    AND ceremony.browser_digest = p_browser_digest
    AND ceremony.state = 'pending' AND ceremony.version = 1
    AND ceremony.expires_at > p_claimed_at;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'WebAuthn ceremony claim is stale or denied' USING ERRCODE = '40001';
  END IF;
  RETURN app.private_webauthn_ceremony_projection_v1(p_ceremony_id);
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.fail_webauthn_ceremony_v1(
  p_ceremony_id bytea,
  p_expected_version bigint,
  p_state text,
  p_reason text,
  p_failed_at timestamptz
)
RETURNS boolean
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF octet_length(p_ceremony_id) <> 32 OR p_expected_version < 1
     OR (p_state, p_reason) NOT IN (
       ('expired','expired'), ('failed','malformed_response'),
       ('failed','verification_rejected'), ('failed','credential_rejected')
     ) OR p_failed_at IS NULL THEN
    RAISE EXCEPTION 'invalid WebAuthn ceremony failure' USING ERRCODE = '22023';
  END IF;
  UPDATE public.tenant_webauthn_ceremonies AS ceremony
  SET state = p_state, failure_reason = p_reason,
    version = ceremony.version + 1, failed_at = p_failed_at
  WHERE ceremony.id = p_ceremony_id
    AND ceremony.state = 'claimed' AND ceremony.version = p_expected_version
    AND ceremony.claimed_at <= p_failed_at;
  RETURN FOUND;
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_webauthn_credential_projection_v1(
  p_credential_id uuid
)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_credential public.tenant_webauthn_credentials%ROWTYPE;
  v_transports jsonb;
  v_identity_epoch bigint;
BEGIN
  SELECT credential.* INTO STRICT v_credential
  FROM public.tenant_webauthn_credentials AS credential
  WHERE credential.id = p_credential_id;
  SELECT subject.identity_epoch INTO STRICT v_identity_epoch
  FROM public.tenant_mfa_subjects AS subject
  WHERE subject.tenant_id = v_credential.tenant_id
    AND subject.user_id = v_credential.user_id;
  SELECT coalesce(jsonb_agg(transport.transport ORDER BY transport.transport), '[]'::jsonb)
    INTO v_transports
  FROM public.tenant_webauthn_credential_transports AS transport
  WHERE transport.tenant_id = v_credential.tenant_id
    AND transport.credential_id = v_credential.id;
  RETURN jsonb_build_object(
    'id', replace(encode(v_credential.credential_id, 'base64'), E'\n', ''),
    'publicKey', replace(encode(v_credential.public_key, 'base64'), E'\n', ''),
    'tenantId', v_credential.tenant_id::text,
    'userId', v_credential.user_id::text,
    'identityEpoch', v_identity_epoch,
    'userHandleDigest', replace(encode(v_credential.user_handle_digest, 'base64'), E'\n', ''),
    'rpId', v_credential.rp_id, 'rpRevision', v_credential.rp_revision,
    'version', v_credential.version, 'status', v_credential.status,
    'signCount', v_credential.sign_count, 'discoverable', v_credential.discoverable,
    'userVerification', v_credential.user_verification,
    'backupEligible', v_credential.backup_eligible, 'backedUp', v_credential.backed_up,
    'transports', v_transports
  );
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.load_webauthn_credential_v1(
  p_tenant_id uuid,
  p_credential_id bytea,
  p_user_handle bytea,
  p_discoverable boolean
)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_internal_id uuid;
BEGIN
  IF octet_length(p_credential_id) NOT BETWEEN 1 AND 4096
     OR octet_length(p_user_handle) NOT BETWEEN 16 AND 128 THEN
    RAISE EXCEPTION 'invalid WebAuthn credential lookup' USING ERRCODE = '22023';
  END IF;
  SELECT credential.id INTO STRICT v_internal_id
  FROM public.tenant_webauthn_credentials AS credential
  JOIN public.tenant_mfa_subjects AS subject
    ON subject.tenant_id = credential.tenant_id AND subject.user_id = credential.user_id
  JOIN public.tenant_memberships AS membership
    ON membership.tenant_id = credential.tenant_id AND membership.user_id = credential.user_id
  JOIN public.users AS identity ON identity.id = credential.user_id
  WHERE credential.tenant_id = p_tenant_id
    AND credential.credential_id = p_credential_id
    AND credential.user_handle_digest = sha256(p_user_handle)
    AND credential.discoverable = p_discoverable
    AND credential.status = 'active'
    AND membership.status = 'active' AND identity.active;
  RETURN app.private_webauthn_credential_projection_v1(v_internal_id);
EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
  RAISE EXCEPTION 'WebAuthn credential is unavailable' USING ERRCODE = '42501';
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.complete_mfa_passkey_registration_v1(p_request jsonb)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_completion jsonb;
  v_ceremony_id bytea;
  v_ceremony public.tenant_webauthn_ceremonies%ROWTYPE;
  v_request_digest bytea;
  v_credential jsonb;
  v_internal_id uuid;
  v_tenant_id uuid;
  v_user_id uuid;
  v_session_result jsonb;
  v_audit_id uuid;
  v_result jsonb;
BEGIN
  PERFORM app.private_mfa_assert_json_object_v1(
    p_request, ARRAY['completion','displayName','audit','session'],
    ARRAY['completion','displayName','audit','session']
  );
  IF NOT app.private_mfa_safe_text_v1(p_request ->> 'displayName', 120) THEN
    RAISE EXCEPTION 'invalid passkey display name' USING ERRCODE = '22023';
  END IF;
  v_completion := p_request -> 'completion';
  v_ceremony_id := app.private_mfa_decode_base64_v1(v_completion ->> 'ceremonyId', 32, 32);
  v_request_digest := app.private_mfa_request_digest_v1(p_request);
  SELECT ceremony.* INTO STRICT v_ceremony
  FROM public.tenant_webauthn_ceremonies AS ceremony
  WHERE ceremony.id = v_ceremony_id
  FOR UPDATE;
  IF v_ceremony.state = 'completed' THEN
    IF v_ceremony.completion_request_digest = v_request_digest THEN
      RETURN v_ceremony.result_snapshot;
    END IF;
    RAISE EXCEPTION 'passkey registration replay mismatch' USING ERRCODE = '40001';
  END IF;
  v_credential := app.private_mfa_complete_webauthn_registration_v1(
    v_completion, p_request ->> 'displayName'
  );
  SELECT credential.id, credential.tenant_id, credential.user_id
    INTO STRICT v_internal_id, v_tenant_id, v_user_id
  FROM public.tenant_webauthn_credentials AS credential
  WHERE credential.credential_id = app.private_mfa_decode_base64_v1(
    v_completion -> 'credential' ->> 'id', 1, 4096
  );
  v_session_result := app.private_mfa_apply_session_v1(
    p_request -> 'session', v_ceremony.authority_anchor_id,
    NULL, NULL, NULL, NULL, NULL, NULL,
    (v_completion ->> 'completedAt')::timestamptz
  );
  v_audit_id := app.private_mfa_append_audit_v1(
    p_request -> 'audit', v_tenant_id, v_user_id,
    'webauthn_credential', v_internal_id, 'passkey'
  );
  v_result := v_session_result || jsonb_build_object(
    'outcome', 'committed', 'credential', v_credential,
    'auditId', v_audit_id::text
  );
  UPDATE public.tenant_webauthn_ceremonies AS ceremony
  SET completion_request_digest = v_request_digest, result_snapshot = v_result
  WHERE ceremony.id = v_ceremony.id AND ceremony.state = 'completed';
  IF NOT FOUND THEN
    RAISE EXCEPTION 'passkey registration finalization lost CAS' USING ERRCODE = '40001';
  END IF;
  RETURN v_result;
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.complete_mfa_passkey_authentication_v1(p_request jsonb)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_completion jsonb;
  v_ceremony_id bytea;
  v_ceremony public.tenant_webauthn_ceremonies%ROWTYPE;
  v_request_digest bytea;
  v_credential_result jsonb;
  v_internal_id uuid;
  v_tenant_id uuid;
  v_user_id uuid;
  v_identity_epoch bigint;
  v_credential_revision bigint;
  v_clone_suspected boolean;
  v_session_result jsonb;
  v_audit_id uuid;
  v_result jsonb;
BEGIN
  PERFORM app.private_mfa_assert_json_object_v1(
    p_request, ARRAY['completion','audit','session'],
    ARRAY['completion','audit','session']
  );
  v_completion := p_request -> 'completion';
  v_ceremony_id := app.private_mfa_decode_base64_v1(v_completion ->> 'ceremonyId', 32, 32);
  v_request_digest := app.private_mfa_request_digest_v1(p_request);
  SELECT ceremony.* INTO STRICT v_ceremony
  FROM public.tenant_webauthn_ceremonies AS ceremony
  WHERE ceremony.id = v_ceremony_id
  FOR UPDATE;
  IF v_ceremony.state = 'completed' THEN
    IF v_ceremony.completion_request_digest = v_request_digest THEN
      RETURN v_ceremony.result_snapshot;
    END IF;
    RAISE EXCEPTION 'passkey authentication replay mismatch' USING ERRCODE = '40001';
  END IF;
  v_credential_result := app.private_mfa_complete_webauthn_authentication_v1(v_completion);
  SELECT credential.id, credential.tenant_id, credential.user_id,
    subject.identity_epoch, credential.version
    INTO STRICT v_internal_id, v_tenant_id, v_user_id,
      v_identity_epoch, v_credential_revision
  FROM public.tenant_webauthn_credentials AS credential
  JOIN public.tenant_mfa_subjects AS subject
    ON subject.tenant_id = credential.tenant_id AND subject.user_id = credential.user_id
  WHERE credential.credential_id = app.private_mfa_decode_base64_v1(
    v_completion ->> 'credentialId', 1, 4096
  );
  v_clone_suspected := v_credential_result ->> 'status' = 'clone_suspected';
  IF v_clone_suspected <> (p_request -> 'session' ->> 'mutation' = 'revoke')
     OR (v_clone_suspected AND p_request -> 'audit' ->> 'kind' <> 'mfa.passkey_clone_suspected')
     OR (NOT v_clone_suspected AND p_request -> 'audit' ->> 'kind'
          NOT IN ('mfa.passkey_authenticated','mfa.passkey_step_up_completed')) THEN
    RAISE EXCEPTION 'passkey completion intent mismatch' USING ERRCODE = '22023';
  END IF;
  v_session_result := app.private_mfa_apply_session_v1(
    p_request -> 'session', v_ceremony.authority_anchor_id,
    'passkey', v_internal_id, v_credential_revision,
    CASE WHEN v_clone_suspected THEN NULL ELSE 'webauthn' END,
    CASE WHEN v_clone_suspected THEN NULL ELSE v_internal_id END,
    CASE WHEN v_clone_suspected THEN NULL ELSE v_credential_revision END,
    (v_completion ->> 'completedAt')::timestamptz
  );
  v_audit_id := app.private_mfa_append_audit_v1(
    p_request -> 'audit', v_tenant_id, v_user_id,
    'webauthn_credential', v_internal_id, 'passkey'
  );
  v_result := v_session_result || jsonb_build_object(
    'outcome', 'committed', 'credential', v_credential_result,
    'tenantId', v_tenant_id::text, 'userId', v_user_id::text,
    'identityEpoch', v_identity_epoch, 'auditId', v_audit_id::text
  );
  UPDATE public.tenant_webauthn_ceremonies AS ceremony
  SET completion_request_digest = v_request_digest, result_snapshot = v_result
  WHERE ceremony.id = v_ceremony.id AND ceremony.state = 'completed';
  IF NOT FOUND THEN
    RAISE EXCEPTION 'passkey authentication finalization lost CAS' USING ERRCODE = '40001';
  END IF;
  RETURN v_result;
END;
$function$;
--> statement-breakpoint

DO $mfa_function_ownership$
DECLARE
  function_record record;
BEGIN
  FOR function_record IN
    SELECT procedure.oid::regprocedure AS signature
    FROM pg_catalog.pg_proc AS procedure
    JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = procedure.pronamespace
    WHERE namespace.nspname = 'app'
      AND (
        procedure.proname LIKE 'private_mfa_%'
        OR procedure.proname IN (
          'resolve_mfa_authority_v1', 'resolve_primary_passkey_v1',
          'admit_mfa_operation_v1', 'start_totp_enrollment_v1',
          'claim_totp_enrollment_v1', 'complete_totp_enrollment_v1',
          'fail_totp_enrollment_v1', 'replace_mfa_recovery_codes_v1',
          'create_mfa_step_up_challenge_v1', 'claim_mfa_step_up_challenge_v1',
          'fail_mfa_step_up_challenge_v1', 'load_mfa_totp_factor_v1',
          'load_mfa_recovery_set_v1', 'complete_mfa_totp_step_up_v1',
          'complete_mfa_recovery_step_up_v1', 'create_webauthn_ceremony_v1',
          'claim_webauthn_ceremony_v1', 'fail_webauthn_ceremony_v1',
          'load_webauthn_credential_v1',
          'complete_mfa_passkey_registration_v1',
          'complete_mfa_passkey_authentication_v1'
        )
      )
  LOOP
    EXECUTE format('ALTER FUNCTION %s OWNER TO periapsis_migrator', function_record.signature);
    EXECUTE format(
      'REVOKE ALL ON FUNCTION %s FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor, periapsis_audit_reader_owner, periapsis_notification_dispatch_owner, periapsis_sla_api_owner, periapsis_sla_worker_owner, periapsis_sla_readiness_owner',
      function_record.signature
    );
  END LOOP;
END
$mfa_function_ownership$;
--> statement-breakpoint

GRANT EXECUTE ON FUNCTION app.resolve_mfa_authority_v1(uuid, text, text, text, timestamptz) TO periapsis_api;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.resolve_primary_passkey_v1(uuid, text, text, timestamptz) TO periapsis_api;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.admit_mfa_operation_v1(uuid, bytea, bytea, bytea, timestamptz) TO periapsis_api;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.start_totp_enrollment_v1(jsonb) TO periapsis_api;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.claim_totp_enrollment_v1(uuid, bytea, timestamptz) TO periapsis_api;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.complete_totp_enrollment_v1(jsonb) TO periapsis_api;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.fail_totp_enrollment_v1(uuid, bigint, timestamptz) TO periapsis_api;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.replace_mfa_recovery_codes_v1(jsonb) TO periapsis_api;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.create_mfa_step_up_challenge_v1(jsonb) TO periapsis_api;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.claim_mfa_step_up_challenge_v1(bytea, bytea, text, timestamptz) TO periapsis_api;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.fail_mfa_step_up_challenge_v1(bytea, bigint, text, text, timestamptz) TO periapsis_api;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.load_mfa_totp_factor_v1(uuid, uuid, uuid) TO periapsis_api;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.load_mfa_recovery_set_v1(uuid, uuid) TO periapsis_api;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.complete_mfa_totp_step_up_v1(jsonb) TO periapsis_api;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.complete_mfa_recovery_step_up_v1(jsonb) TO periapsis_api;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.create_webauthn_ceremony_v1(jsonb) TO periapsis_api;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.claim_webauthn_ceremony_v1(bytea, bytea, timestamptz) TO periapsis_api;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.fail_webauthn_ceremony_v1(bytea, bigint, text, text, timestamptz) TO periapsis_api;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.load_webauthn_credential_v1(uuid, bytea, bytea, boolean) TO periapsis_api;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.complete_mfa_passkey_registration_v1(jsonb) TO periapsis_api;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.complete_mfa_passkey_authentication_v1(jsonb) TO periapsis_api;
--> statement-breakpoint
