-- Customer-safe self-service inventory and lifecycle for local MFA devices.
-- Existing factor tables remain canonical; only narrow tenant-bound functions
-- are added. Raw credentials, public keys, AAGUIDs, counters, and envelopes
-- never enter a projection.

CREATE FUNCTION app.private_mfa_device_authority_v1(
  p_session_id uuid,
  p_tenant_id uuid,
  p_user_id uuid,
  p_at timestamptz,
  p_require_fresh_local boolean
)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_session public.auth_sessions%ROWTYPE;
  v_state public.auth_session_mfa_states%ROWTYPE;
BEGIN
  IF p_session_id IS NULL OR p_tenant_id IS NULL OR p_user_id IS NULL
     OR p_at IS NULL OR p_require_fresh_local IS NULL
     OR current_setting('app.tenant_id', true)
          IS DISTINCT FROM p_tenant_id::text
     OR current_setting('app.user_id', true)
          IS DISTINCT FROM p_user_id::text
     OR abs(extract(epoch FROM (transaction_timestamp() - p_at))) > 300 THEN
    RAISE EXCEPTION 'live MFA device authority is required'
      USING ERRCODE = '42501';
  END IF;

  SELECT session.* INTO v_session
  FROM public.auth_sessions AS session
  JOIN public.users AS identity ON identity.id = session.user_id
  JOIN public.tenant_memberships AS membership
    ON membership.tenant_id = p_tenant_id
   AND membership.user_id = session.user_id
  WHERE session.id = p_session_id
    AND session.user_id = p_user_id
    AND session.active_tenant_id = p_tenant_id
    AND session.revoked_at IS NULL
    AND session.idle_expires_at > p_at
    AND session.absolute_expires_at > p_at
    AND identity.active
    AND membership.status = 'active';
  IF NOT FOUND THEN
    RAISE EXCEPTION 'live MFA device authority is required'
      USING ERRCODE = '42501';
  END IF;

  SELECT state.* INTO v_state
  FROM public.auth_session_mfa_states AS state
  JOIN public.tenant_mfa_subjects AS subject
    ON subject.tenant_id = state.tenant_id
   AND subject.user_id = state.user_id
  WHERE state.tenant_id = p_tenant_id
    AND state.user_id = p_user_id
    AND state.session_id = p_session_id
    AND state.identity_epoch = subject.identity_epoch
    AND state.session_invalidation_epoch = subject.session_invalidation_epoch;
  IF NOT FOUND OR (
       p_require_fresh_local AND (
         v_state.recovery_restricted
         OR v_session.mfa_satisfied_at IS NULL
         OR v_session.mfa_satisfied_at < p_at - interval '15 minutes'
         OR v_session.authentication_method NOT IN (
           'bootstrap_totp', 'passkey', 'totp'
         )
       )
     ) THEN
    RAISE EXCEPTION 'fresh local MFA device authority is required'
      USING ERRCODE = '42501';
  END IF;

  RETURN jsonb_build_object(
    'sessionId', v_session.id::text,
    'familyId', v_session.rotation_family_id::text,
    'tenantId', p_tenant_id::text,
    'userId', p_user_id::text,
    'authenticationMethod', v_session.authentication_method
  );
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.revoke_my_mfa_device_v1(p_request jsonb)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_session public.auth_sessions%ROWTYPE;
  v_totp public.tenant_totp_factors%ROWTYPE;
  v_passkey public.tenant_webauthn_credentials%ROWTYPE;
  v_session_id uuid;
  v_tenant_id uuid;
  v_user_id uuid;
  v_device_id uuid;
  v_kind text;
  v_expected_version bigint;
  v_occurred_at timestamptz;
  v_revoked_family_count integer := 0;
  v_current_session_revoked boolean := false;
  v_resource_type text;
  v_audit_kind text;
BEGIN
  PERFORM app.private_mfa_assert_json_object_v1(
    p_request,
    ARRAY['sessionId','tenantId','userId','deviceId','kind','expectedVersion','occurredAt'],
    ARRAY['sessionId','tenantId','userId','deviceId','kind','expectedVersion','occurredAt'],
    4096
  );
  v_session_id := app.private_mfa_require_uuidv7_v1(p_request ->> 'sessionId');
  v_tenant_id := app.private_mfa_require_uuidv7_v1(p_request ->> 'tenantId');
  v_user_id := app.private_mfa_require_uuidv7_v1(p_request ->> 'userId');
  v_device_id := app.private_mfa_require_uuidv7_v1(p_request ->> 'deviceId');
  v_kind := p_request ->> 'kind';
  v_expected_version := (p_request ->> 'expectedVersion')::bigint;
  v_occurred_at := (p_request ->> 'occurredAt')::timestamptz;
  IF v_kind NOT IN ('totp', 'passkey') OR v_expected_version < 1 THEN
    RAISE EXCEPTION 'invalid MFA device revocation' USING ERRCODE = '22023';
  END IF;

  SELECT session.* INTO v_session
  FROM public.auth_sessions AS session
  WHERE session.id = v_session_id
    AND session.user_id = v_user_id
    AND session.active_tenant_id = v_tenant_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'fresh local MFA device authority is required'
      USING ERRCODE = '42501';
  END IF;
  PERFORM app.private_mfa_device_authority_v1(
    v_session_id, v_tenant_id, v_user_id, v_occurred_at, true
  );

  IF v_kind = 'totp' THEN
    SELECT factor.* INTO v_totp
    FROM public.tenant_totp_factors AS factor
    WHERE factor.id = v_device_id
      AND factor.tenant_id = v_tenant_id
      AND factor.user_id = v_user_id
    FOR UPDATE;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'MFA device not found' USING ERRCODE = 'P0002';
    END IF;
    IF v_totp.record_version IS DISTINCT FROM v_expected_version THEN
      RAISE EXCEPTION 'TOTP version changed' USING ERRCODE = '40001';
    END IF;
    IF v_totp.status <> 'active' THEN
      RAISE EXCEPTION 'TOTP factor cannot be revoked' USING ERRCODE = '55000';
    END IF;
    UPDATE public.tenant_totp_factors AS factor
    SET status = 'revoked', revoked_at = v_occurred_at,
        revoke_reason = 'user_requested',
        record_version = factor.record_version + 1,
        security_revision = factor.security_revision + 1,
        updated_at = v_occurred_at
    WHERE factor.id = v_device_id;
    v_resource_type := 'mfa_factor';
    v_audit_kind := 'mfa.totp_revoked';
  ELSE
    SELECT credential.* INTO v_passkey
    FROM public.tenant_webauthn_credentials AS credential
    WHERE credential.id = v_device_id
      AND credential.tenant_id = v_tenant_id
      AND credential.user_id = v_user_id
    FOR UPDATE;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'MFA device not found' USING ERRCODE = 'P0002';
    END IF;
    IF v_passkey.version IS DISTINCT FROM v_expected_version THEN
      RAISE EXCEPTION 'passkey version changed' USING ERRCODE = '40001';
    END IF;
    IF v_passkey.status <> 'active' THEN
      RAISE EXCEPTION 'passkey cannot be revoked' USING ERRCODE = '55000';
    END IF;
    UPDATE public.tenant_webauthn_credentials AS credential
    SET status = 'revoked', revoked_at = v_occurred_at,
        revoke_reason = 'user_requested',
        version = credential.version + 1,
        updated_at = v_occurred_at
    WHERE credential.id = v_device_id;
    v_resource_type := 'webauthn_credential';
    v_audit_kind := 'mfa.passkey_revoked';
  END IF;

  WITH impacted_families AS MATERIALIZED (
    SELECT DISTINCT session.rotation_family_id
    FROM public.auth_sessions AS session
    WHERE session.user_id = v_user_id
      AND session.active_tenant_id = v_tenant_id
      AND (
        EXISTS (
          SELECT 1
          FROM public.auth_session_passkey_provenance AS provenance
          WHERE provenance.tenant_id = v_tenant_id
            AND provenance.session_id = session.id
            AND v_kind = 'passkey'
            AND provenance.credential_id = v_device_id
        ) OR EXISTS (
          SELECT 1
          FROM public.auth_session_mfa_evidence AS evidence
          WHERE evidence.tenant_id = v_tenant_id
            AND evidence.session_id = session.id
            AND (
              (v_kind = 'totp' AND evidence.totp_factor_id = v_device_id)
              OR (v_kind = 'passkey' AND evidence.webauthn_credential_id = v_device_id)
            )
        )
      )
  ), revoked_sessions AS (
    UPDATE public.auth_sessions AS session
    SET revoked_at = v_occurred_at,
        revoke_reason = 'mfa_device_revoked'
    WHERE session.user_id = v_user_id
      AND session.revoked_at IS NULL
      AND session.rotation_family_id IN (
        SELECT family.rotation_family_id FROM impacted_families AS family
      )
    RETURNING session.id, session.rotation_family_id
  )
  SELECT count(DISTINCT revoked.rotation_family_id)::integer,
         coalesce(bool_or(revoked.id = v_session_id), false)
  INTO v_revoked_family_count, v_current_session_revoked
  FROM revoked_sessions AS revoked;

  UPDATE public.tenant_mfa_subjects AS subject
  SET identity_epoch = subject.identity_epoch + 1,
      session_invalidation_epoch = subject.session_invalidation_epoch + 1,
      version = subject.version + 1,
      updated_at = v_occurred_at
  WHERE subject.tenant_id = v_tenant_id AND subject.user_id = v_user_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'MFA subject changed' USING ERRCODE = '40001';
  END IF;

  PERFORM app.private_mfa_append_device_audit_v1(
    v_tenant_id, v_user_id, v_session.authentication_method,
    v_audit_kind, v_resource_type, v_device_id, v_occurred_at,
    v_revoked_family_count
  );
  RETURN jsonb_build_object(
    'device', app.private_mfa_device_projection_v1(v_kind, v_device_id),
    'currentSessionRevoked', v_current_session_revoked
  );
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range
  OR datetime_field_overflow THEN
  RAISE EXCEPTION 'invalid MFA device revocation' USING ERRCODE = '22023';
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.rename_my_passkey_v1(p_request jsonb)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_session public.auth_sessions%ROWTYPE;
  v_credential public.tenant_webauthn_credentials%ROWTYPE;
  v_session_id uuid;
  v_tenant_id uuid;
  v_user_id uuid;
  v_device_id uuid;
  v_expected_version bigint;
  v_display_name text;
  v_occurred_at timestamptz;
BEGIN
  PERFORM app.private_mfa_assert_json_object_v1(
    p_request,
    ARRAY['sessionId','tenantId','userId','deviceId','kind','displayName','expectedVersion','occurredAt'],
    ARRAY['sessionId','tenantId','userId','deviceId','kind','displayName','expectedVersion','occurredAt'],
    4096
  );
  v_session_id := app.private_mfa_require_uuidv7_v1(p_request ->> 'sessionId');
  v_tenant_id := app.private_mfa_require_uuidv7_v1(p_request ->> 'tenantId');
  v_user_id := app.private_mfa_require_uuidv7_v1(p_request ->> 'userId');
  v_device_id := app.private_mfa_require_uuidv7_v1(p_request ->> 'deviceId');
  v_expected_version := (p_request ->> 'expectedVersion')::bigint;
  v_display_name := p_request ->> 'displayName';
  v_occurred_at := (p_request ->> 'occurredAt')::timestamptz;
  IF p_request ->> 'kind' <> 'passkey' OR v_expected_version < 1
     OR NOT app.private_mfa_safe_text_v1(v_display_name, 120)
     OR v_display_name <> btrim(v_display_name) OR v_display_name ~ '[<>]' THEN
    RAISE EXCEPTION 'invalid passkey rename' USING ERRCODE = '22023';
  END IF;

  SELECT session.* INTO v_session
  FROM public.auth_sessions AS session
  WHERE session.id = v_session_id
    AND session.user_id = v_user_id
    AND session.active_tenant_id = v_tenant_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'fresh local MFA device authority is required'
      USING ERRCODE = '42501';
  END IF;
  PERFORM app.private_mfa_device_authority_v1(
    v_session_id, v_tenant_id, v_user_id, v_occurred_at, true
  );

  SELECT credential.* INTO v_credential
  FROM public.tenant_webauthn_credentials AS credential
  WHERE credential.id = v_device_id
    AND credential.tenant_id = v_tenant_id
    AND credential.user_id = v_user_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'MFA device not found' USING ERRCODE = 'P0002';
  END IF;
  IF v_credential.version IS DISTINCT FROM v_expected_version THEN
    RAISE EXCEPTION 'passkey version changed' USING ERRCODE = '40001';
  END IF;
  IF v_credential.status <> 'active' OR v_credential.display_name = v_display_name THEN
    RAISE EXCEPTION 'passkey cannot be renamed' USING ERRCODE = '55000';
  END IF;

  UPDATE public.tenant_webauthn_credentials AS credential
  SET display_name = v_display_name,
      version = credential.version + 1,
      updated_at = v_occurred_at
  WHERE credential.id = v_device_id;
  PERFORM app.private_mfa_append_device_audit_v1(
    v_tenant_id, v_user_id, v_session.authentication_method,
    'mfa.passkey_renamed', 'webauthn_credential', v_device_id,
    v_occurred_at, 0
  );
  RETURN jsonb_build_object(
    'device', app.private_mfa_device_projection_v1('passkey', v_device_id),
    'currentSessionRevoked', false
  );
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range
  OR datetime_field_overflow THEN
  RAISE EXCEPTION 'invalid passkey rename' USING ERRCODE = '22023';
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_mfa_device_projection_v1(
  p_kind text,
  p_device_id uuid
)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_projection jsonb;
BEGIN
  IF p_kind = 'totp' THEN
    SELECT jsonb_build_object(
      'id', factor.id::text,
      'kind', 'totp',
      'status', factor.status,
      'displayName', '',
      'version', factor.record_version,
      'discoverable', false,
      'backupEligible', false,
      'backedUp', false,
      'transports', '[]'::jsonb,
      'createdAt', factor.created_at,
      'lastUsedAt', NULL,
      'revokedAt', factor.revoked_at
    ) INTO v_projection
    FROM public.tenant_totp_factors AS factor
    WHERE factor.id = p_device_id;
  ELSIF p_kind = 'passkey' THEN
    SELECT jsonb_build_object(
      'id', credential.id::text,
      'kind', 'passkey',
      'status', credential.status,
      'displayName', credential.display_name,
      'version', credential.version,
      'discoverable', credential.discoverable,
      'backupEligible', credential.backup_eligible,
      'backedUp', credential.backed_up,
      'transports', coalesce((
        SELECT jsonb_agg(transport.transport ORDER BY transport.transport)
        FROM public.tenant_webauthn_credential_transports AS transport
        WHERE transport.tenant_id = credential.tenant_id
          AND transport.credential_id = credential.id
      ), '[]'::jsonb),
      'createdAt', credential.created_at,
      'lastUsedAt', credential.last_used_at,
      'revokedAt', credential.revoked_at
    ) INTO v_projection
    FROM public.tenant_webauthn_credentials AS credential
    WHERE credential.id = p_device_id;
  ELSE
    RAISE EXCEPTION 'unsupported MFA device kind' USING ERRCODE = '22023';
  END IF;
  IF v_projection IS NULL THEN
    RAISE EXCEPTION 'MFA device not found' USING ERRCODE = 'P0002';
  END IF;
  RETURN v_projection;
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_mfa_append_device_audit_v1(
  p_tenant_id uuid,
  p_user_id uuid,
  p_authentication_method text,
  p_kind text,
  p_resource_type text,
  p_resource_id uuid,
  p_occurred_at timestamptz,
  p_revoked_family_count integer
)
RETURNS uuid
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_audit_id uuid := uuidv7();
  v_action text;
BEGIN
  v_action := CASE p_kind
    WHEN 'mfa.passkey_renamed' THEN 'tenant.identity.mfa_passkey_renamed'
    WHEN 'mfa.passkey_revoked' THEN 'tenant.identity.mfa_passkey_revoked'
    WHEN 'mfa.totp_revoked' THEN 'tenant.identity.mfa_totp_revoked'
    ELSE NULL
  END;
  IF p_tenant_id IS NULL OR p_user_id IS NULL OR p_resource_id IS NULL
     OR p_occurred_at IS NULL OR v_action IS NULL
     OR p_resource_type NOT IN ('webauthn_credential', 'mfa_factor')
     OR p_authentication_method NOT IN ('bootstrap_totp', 'passkey', 'totp')
     OR p_revoked_family_count NOT BETWEEN 0 AND 1000000
     OR abs(extract(epoch FROM (transaction_timestamp() - p_occurred_at))) > 300
     OR current_setting('app.tenant_id', true)
          IS DISTINCT FROM p_tenant_id::text
     OR current_setting('app.user_id', true)
          IS DISTINCT FROM p_user_id::text
     OR NOT EXISTS (
       SELECT 1
       FROM public.tenant_memberships AS membership
       JOIN public.users AS identity ON identity.id = membership.user_id
       WHERE membership.tenant_id = p_tenant_id
         AND membership.user_id = p_user_id
         AND membership.status = 'active'
         AND identity.active
     ) THEN
    RAISE EXCEPTION 'unsafe MFA device audit intent' USING ERRCODE = '42501';
  END IF;

  INSERT INTO public.audit_events (
    id, tenant_id, sequence, occurred_at, actor_type, actor_user_id,
    action, resource_type, resource_id, authentication_method,
    outcome, metadata
  ) VALUES (
    v_audit_id, p_tenant_id, 0, p_occurred_at, 'user', p_user_id,
    v_action, p_resource_type, p_resource_id, p_authentication_method,
    'success', jsonb_build_object(
      'kind', p_kind,
      'revoked_session_family_count', p_revoked_family_count,
      'secret_material_included', false
    )
  );
  RETURN v_audit_id;
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.list_my_mfa_devices_v1(
  p_current_session_id uuid,
  p_after_kind text,
  p_after_device_id uuid,
  p_limit integer,
  p_include_revoked boolean
)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_authority jsonb;
  v_tenant_id uuid;
  v_user_id uuid;
  v_cursor_created_at timestamptz;
BEGIN
  IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 101
     OR p_include_revoked IS NULL
     OR ((p_after_kind IS NULL) <> (p_after_device_id IS NULL))
     OR (p_after_kind IS NOT NULL AND p_after_kind NOT IN ('totp', 'passkey')) THEN
    RAISE EXCEPTION 'invalid MFA device page' USING ERRCODE = '22023';
  END IF;
  v_tenant_id := app.private_mfa_require_uuidv7_v1(
    current_setting('app.tenant_id', true)
  );
  v_user_id := app.private_mfa_require_uuidv7_v1(
    current_setting('app.user_id', true)
  );
  v_authority := app.private_mfa_device_authority_v1(
    p_current_session_id, v_tenant_id, v_user_id,
    transaction_timestamp(), false
  );
  IF v_authority ->> 'sessionId' IS DISTINCT FROM p_current_session_id::text THEN
    RAISE EXCEPTION 'invalid MFA device authority projection'
      USING ERRCODE = '42501';
  END IF;

  IF p_after_device_id IS NOT NULL THEN
    SELECT device.created_at INTO v_cursor_created_at
    FROM (
      SELECT factor.id, 'totp'::text AS kind, factor.created_at
      FROM public.tenant_totp_factors AS factor
      WHERE factor.tenant_id = v_tenant_id AND factor.user_id = v_user_id
        AND (p_include_revoked OR factor.status = 'active')
      UNION ALL
      SELECT credential.id, 'passkey'::text, credential.created_at
      FROM public.tenant_webauthn_credentials AS credential
      WHERE credential.tenant_id = v_tenant_id AND credential.user_id = v_user_id
        AND (p_include_revoked OR credential.status = 'active')
    ) AS device
    WHERE device.kind = p_after_kind AND device.id = p_after_device_id;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'invalid MFA device page cursor' USING ERRCODE = '22023';
    END IF;
  END IF;

  RETURN (
    WITH devices AS MATERIALIZED (
      SELECT factor.id, 'totp'::text AS kind, factor.created_at
      FROM public.tenant_totp_factors AS factor
      WHERE factor.tenant_id = v_tenant_id AND factor.user_id = v_user_id
        AND (p_include_revoked OR factor.status = 'active')
      UNION ALL
      SELECT credential.id, 'passkey'::text, credential.created_at
      FROM public.tenant_webauthn_credentials AS credential
      WHERE credential.tenant_id = v_tenant_id AND credential.user_id = v_user_id
        AND (p_include_revoked OR credential.status = 'active')
    ), page AS (
      SELECT device.id, device.kind, device.created_at
      FROM devices AS device
      WHERE p_after_device_id IS NULL
         OR device.created_at < v_cursor_created_at
         OR (
           device.created_at = v_cursor_created_at
           AND (
             device.kind > p_after_kind
             OR (device.kind = p_after_kind AND device.id < p_after_device_id)
           )
         )
      ORDER BY device.created_at DESC, device.kind, device.id DESC
      LIMIT p_limit
    )
    SELECT jsonb_build_object(
      'items', coalesce(jsonb_agg(
        app.private_mfa_device_projection_v1(page.kind, page.id)
        ORDER BY page.created_at DESC, page.kind, page.id DESC
      ), '[]'::jsonb)
    )
    FROM page
  );
END;
$function$;
--> statement-breakpoint

DO $mfa_device_function_ownership$
DECLARE
  function_record record;
BEGIN
  FOR function_record IN
    SELECT procedure.oid::regprocedure AS signature
    FROM pg_proc AS procedure
    JOIN pg_namespace AS namespace ON namespace.oid = procedure.pronamespace
    WHERE namespace.nspname = 'app'
      AND procedure.proname IN (
        'private_mfa_device_authority_v1',
        'private_mfa_device_projection_v1',
        'private_mfa_append_device_audit_v1',
        'list_my_mfa_devices_v1',
        'rename_my_passkey_v1',
        'revoke_my_mfa_device_v1'
      )
  LOOP
    EXECUTE format(
      'ALTER FUNCTION %s OWNER TO periapsis_migrator',
      function_record.signature
    );
    EXECUTE format(
      'REVOKE ALL ON FUNCTION %s FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor, periapsis_audit_reader_owner, periapsis_notification_dispatch_owner, periapsis_sla_api_owner, periapsis_sla_worker_owner, periapsis_sla_readiness_owner',
      function_record.signature
    );
  END LOOP;
END
$mfa_device_function_ownership$;
--> statement-breakpoint

GRANT EXECUTE ON FUNCTION app.list_my_mfa_devices_v1(
  uuid, text, uuid, integer, boolean
) TO periapsis_api;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.rename_my_passkey_v1(jsonb) TO periapsis_api;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.revoke_my_mfa_device_v1(jsonb) TO periapsis_api;
