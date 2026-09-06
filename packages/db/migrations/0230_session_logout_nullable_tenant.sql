-- Forward local logout correction: tenantId is required but nullable.
-- Missing tenantId still enters the strict UUID parser and fails; the global
-- JSON helper, token/session attestation, transaction, replay and ACLs are unchanged.
-- This local logout cutover requires NOLOGIN and drained sessions for every
-- canonical runtime writer principal, including transitive role members.
DO $v50_local_logout_quiesced_cutover$
BEGIN
  IF EXISTS (
    WITH RECURSIVE writer_principal(role_oid) AS (
      SELECT role.oid
      FROM pg_catalog.pg_roles AS role
      WHERE role.rolname IN (
        'periapsis_api','periapsis_worker','periapsis_notifier',
        'periapsis_api_login','periapsis_worker_login',
        'periapsis_notifier_login'
      )
      UNION
      SELECT membership.member
      FROM pg_catalog.pg_auth_members AS membership
      JOIN writer_principal AS granted
        ON granted.role_oid = membership.roleid
    )
    SELECT 1
    FROM writer_principal AS principal
    JOIN pg_catalog.pg_roles AS role ON role.oid = principal.role_oid
    WHERE role.rolcanlogin
  ) THEN
    RAISE EXCEPTION
      'v50 local logout cutover requires every runtime writer login to be NOLOGIN'
      USING ERRCODE = '55000';
  END IF;
  IF EXISTS (
    WITH RECURSIVE writer_principal(role_oid) AS (
      SELECT role.oid
      FROM pg_catalog.pg_roles AS role
      WHERE role.rolname IN (
        'periapsis_api','periapsis_worker','periapsis_notifier',
        'periapsis_api_login','periapsis_worker_login',
        'periapsis_notifier_login'
      )
      UNION
      SELECT membership.member
      FROM pg_catalog.pg_auth_members AS membership
      JOIN writer_principal AS granted
        ON granted.role_oid = membership.roleid
    )
    SELECT 1
    FROM pg_catalog.pg_stat_activity AS activity
    JOIN writer_principal AS principal
      ON principal.role_oid = activity.usesysid
    WHERE activity.pid <> pg_backend_pid()
  ) THEN
    RAISE EXCEPTION
      'v50 local logout cutover requires every runtime writer session to be drained'
      USING ERRCODE = '55000';
  END IF;
END;
$v50_local_logout_quiesced_cutover$;
--> statement-breakpoint
DO $assert_logout_writer_predecessor$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_proc AS routine
    JOIN pg_catalog.pg_roles AS owner ON owner.oid=routine.proowner
    JOIN pg_catalog.pg_language AS language ON language.oid=routine.prolang
    WHERE routine.oid='app.revoke_local_session_for_logout_v1(jsonb)'::pg_catalog.regprocedure
      AND owner.rolname='periapsis_migrator' AND language.lanname='plpgsql'
      AND routine.prokind='f' AND routine.provolatile='v' AND routine.prosecdef
      AND NOT routine.proisstrict AND NOT routine.proleakproof
      AND routine.proparallel='u' AND routine.pronargs=1
      AND routine.pronargdefaults=0 AND routine.prorettype='pg_catalog.jsonb'::pg_catalog.regtype
      AND NOT routine.proretset
      AND routine.proconfig IS NOT DISTINCT FROM ARRAY['search_path=pg_catalog, public, app']::pg_catalog.text[]
      AND pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(routine.prosrc,'UTF8')),'hex')='89fa85a15ceb62c180540bf86fd0e3adbde06f11dfcbce8cb3f5040fff7a05f8'
      AND (
        SELECT count(*)=2 AND coalesce(bool_and(
          acl.grantor=routine.proowner
          AND acl.grantee IN (routine.proowner,'periapsis_api'::pg_catalog.regrole)
          AND acl.privilege_type='EXECUTE' AND NOT acl.is_grantable
        ),false)
        FROM pg_catalog.aclexplode(coalesce(routine.proacl,
          pg_catalog.acldefault('f',routine.proowner))) AS acl
      )
  ) THEN
    RAISE EXCEPTION 'local logout writer predecessor source/catalog mismatch' USING ERRCODE='55000';
  END IF;
END;
$assert_logout_writer_predecessor$;
--> statement-breakpoint
CREATE OR REPLACE FUNCTION app.revoke_local_session_for_logout_v1(p_command jsonb)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_operation_run_id uuid;
  v_session_id uuid;
  v_user_id uuid;
  v_tenant_id uuid;
  v_family_id uuid;
  v_token_digest bytea;
  v_request_digest bytea;
  v_request_upstream boolean;
  v_requested_at timestamptz;
  v_database_now timestamptz;
  v_continuation_id uuid;
  v_continuation_digest bytea;
  v_continuation_expires_at timestamptz;
  v_request_id uuid;
  v_correlation_id uuid;
  v_remote_address inet;
  v_user_agent text;
  v_request_snapshot jsonb;
  v_base_result jsonb;
  v_result jsonb;
  v_command_authority text;
  v_previous_version bigint;
  v_revoked_at timestamptz;
  v_protocol text;
  v_continuation_created boolean := false;
  v_oidc_found boolean := false;
  v_tenant_saml_found boolean := false;
  v_platform_saml_found boolean := false;
  v_schedule_retry boolean := false;
  v_retry_job_id uuid;
  v_session public.auth_sessions%ROWTYPE;
  v_oidc public.tenant_oidc_session_materials%ROWTYPE;
  v_oidc_effective_authority text;
  v_tenant_saml public.tenant_saml_session_materials%ROWTYPE;
  v_platform_saml public.platform_saml_session_materials%ROWTYPE;
  v_platform_saml_effective record;
  v_existing public.tenant_oidc_logout_commands%ROWTYPE;
  v_existing_continuation public.session_logout_continuations%ROWTYPE;
BEGIN
  PERFORM app.private_mfa_assert_json_object_v1(
    p_command,
    ARRAY['operationRunId','sessionId','userId','tenantId','tokenDigest',
      'requestDigest','requestUpstream','requestedAt','continuationId',
      'continuationDigest','continuationExpiresAt','audit'],
    ARRAY['operationRunId','sessionId','userId','tokenDigest',
      'requestDigest','requestUpstream','requestedAt','continuationId',
      'continuationDigest','continuationExpiresAt','audit'],32768
  );
  PERFORM app.private_mfa_assert_json_object_v1(
    p_command -> 'audit',
    ARRAY['requestId','correlationId','remoteAddress','userAgent'],
    ARRAY['requestId','correlationId','remoteAddress','userAgent'],4096
  );
  BEGIN
    v_operation_run_id := app.private_mfa_require_uuidv7_v1(
      p_command ->> 'operationRunId'
    );
    v_session_id := app.private_mfa_require_uuidv7_v1(
      p_command ->> 'sessionId'
    );
    v_user_id := app.private_mfa_require_uuidv7_v1(p_command ->> 'userId');
    IF jsonb_typeof(p_command -> 'tenantId') = 'null' THEN
      v_tenant_id := NULL;
    ELSE
      v_tenant_id := app.private_mfa_require_uuidv7_v1(
        p_command ->> 'tenantId'
      );
    END IF;
    v_token_digest := app.private_mfa_decode_base64_v1(
      p_command ->> 'tokenDigest',32,32
    );
    v_request_digest := app.private_mfa_decode_base64_v1(
      p_command ->> 'requestDigest',32,32
    );
    v_request_upstream := (p_command ->> 'requestUpstream')::boolean;
    v_requested_at := (p_command ->> 'requestedAt')::timestamptz;
    v_continuation_id := app.private_mfa_require_uuidv7_v1(
      p_command ->> 'continuationId'
    );
    v_continuation_digest := app.private_mfa_decode_base64_v1(
      p_command ->> 'continuationDigest',32,32
    );
    v_continuation_expires_at := (
      p_command ->> 'continuationExpiresAt'
    )::timestamptz;
    v_request_id := app.private_mfa_require_uuidv7_v1(
      p_command #>> '{audit,requestId}'
    );
    v_correlation_id := app.private_mfa_require_uuidv7_v1(
      p_command #>> '{audit,correlationId}'
    );
    v_remote_address := (p_command #>> '{audit,remoteAddress}')::inet;
    v_user_agent := p_command #>> '{audit,userAgent}';
  EXCEPTION WHEN OTHERS THEN
    RAISE EXCEPTION 'invalid local session logout command'
      USING ERRCODE = '22023';
  END;
  IF jsonb_typeof(p_command -> 'requestUpstream') <> 'boolean'
     OR v_operation_run_id IN (v_session_id,v_user_id,v_continuation_id)
     OR v_session_id IN (v_user_id,v_continuation_id)
     OR v_user_id = v_continuation_id
     OR (v_tenant_id IS NOT NULL AND v_tenant_id IN (
       v_operation_run_id,v_session_id,v_user_id,v_continuation_id
     ))
     OR encode(v_token_digest,'hex') = repeat('00',32)
     OR encode(v_request_digest,'hex') = repeat('00',32)
     OR encode(v_continuation_digest,'hex') = repeat('00',32)
     OR date_trunc('microseconds',v_requested_at) <> v_requested_at
     OR abs(extract(epoch FROM
       (transaction_timestamp() - v_requested_at))) > 300
     OR date_trunc('microseconds',v_continuation_expires_at)
          <> v_continuation_expires_at
     OR v_continuation_expires_at <= v_requested_at
     OR v_continuation_expires_at > v_requested_at + interval '2 minutes'
     OR v_user_agent IS NULL OR char_length(v_user_agent) NOT BETWEEN 1 AND 512
     OR v_user_agent ~ '[[:cntrl:]]' THEN
    RAISE EXCEPTION 'invalid local session logout command'
      USING ERRCODE = '22023';
  END IF;

  v_request_snapshot := jsonb_build_object(
    'operationRunId',v_operation_run_id::text,
    'sessionId',v_session_id::text,'userId',v_user_id::text,
    'tenantId',to_jsonb(v_tenant_id),
    'requestUpstream',v_request_upstream,
    'requestedAt',to_jsonb(v_requested_at),
    'continuationId',v_continuation_id::text,
    'continuationExpiresAt',to_jsonb(v_continuation_expires_at)
  );
  PERFORM pg_advisory_xact_lock(hashtextextended(
    v_operation_run_id::text,73419022
  ));

  -- Refresh claim/completion serialize on the rotation family before taking
  -- material or session row locks. Discover the immutable family without a
  -- row lock, take that same advisory lock, then re-read and attest the exact
  -- credential under lock. This prevents session->material versus
  -- material->session deadlocks without trusting the optimistic read.
  SELECT session.rotation_family_id INTO v_family_id
  FROM public.auth_sessions AS session
  WHERE session.id = v_session_id AND session.user_id = v_user_id
    AND session.active_tenant_id IS NOT DISTINCT FROM v_tenant_id
    AND session.token_digest = v_token_digest;
  IF NOT FOUND THEN RETURN NULL; END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended(v_family_id::text,90174213));

  SELECT session.* INTO v_session
  FROM public.auth_sessions AS session
  WHERE session.id = v_session_id AND session.user_id = v_user_id
    AND session.active_tenant_id IS NOT DISTINCT FROM v_tenant_id
    AND session.token_digest = v_token_digest
    AND session.rotation_family_id = v_family_id
  FOR UPDATE;
  IF NOT FOUND THEN RETURN NULL; END IF;

  SELECT command.* INTO v_existing
  FROM public.tenant_oidc_logout_commands AS command
  WHERE command.operation_run_id = v_operation_run_id;
  IF FOUND THEN
    IF v_existing.tenant_id IS DISTINCT FROM v_tenant_id
       OR v_existing.session_id IS DISTINCT FROM v_session_id
       OR v_existing.request_upstream IS DISTINCT FROM v_request_upstream
       OR v_existing.request_digest IS DISTINCT FROM v_request_digest
       OR v_existing.request_snapshot IS DISTINCT FROM v_request_snapshot THEN
      RETURN NULL;
    END IF;
    SELECT continuation.* INTO v_existing_continuation
    FROM public.session_logout_continuations AS continuation
    WHERE continuation.operation_run_id = v_operation_run_id
      AND continuation.id = v_continuation_id
      AND continuation.token_digest = v_continuation_digest
      AND continuation.consumed_at IS NULL
      AND transaction_timestamp() < continuation.expires_at;
    IF FOUND THEN
      RETURN v_existing.result_snapshot || jsonb_build_object(
        'category','logout_continuation',
        'continuationId',v_existing_continuation.id::text,
        'continuationExpiresAt',to_jsonb(v_existing_continuation.expires_at)
      );
    END IF;
    RETURN v_existing.result_snapshot;
  END IF;

  -- The caller timestamp participates only in the immutable request digest.
  -- Security-relevant creation, expiry, revocation, and audit time comes from
  -- PostgreSQL so a valid +/- five-minute client skew cannot extend or
  -- prematurely consume the one-time continuation.
  v_database_now := date_trunc('microseconds',transaction_timestamp());
  v_continuation_expires_at := v_database_now
    + (v_continuation_expires_at - v_requested_at);
  v_requested_at := v_database_now;

  v_protocol := v_session.authentication_method;
  IF v_tenant_id IS NOT NULL THEN
    v_protocol := coalesce(
      (
        SELECT provenance.authentication_method
        FROM public.auth_session_tenant_platform_federated_provenance
          AS provenance
        WHERE provenance.tenant_id = v_tenant_id
          AND provenance.session_id = v_session_id
          AND provenance.user_id = v_user_id
          AND provenance.primary_kind = 'tenant_platform_provider'
      ),
      (
        SELECT provenance.authentication_method
        FROM public.auth_session_federated_provenance AS provenance
        WHERE provenance.tenant_id = v_tenant_id
          AND provenance.session_id = v_session_id
          AND provenance.user_id = v_user_id
          AND provenance.primary_kind = 'tenant_provider'
      ),
      v_protocol
    );
  END IF;
  IF v_tenant_id IS NOT NULL THEN
    SELECT state.session_version INTO v_previous_version
    FROM public.auth_session_mfa_states AS state
    WHERE state.tenant_id = v_tenant_id AND state.session_id = v_session_id
      AND state.user_id = v_user_id
    FOR UPDATE;
  ELSIF v_protocol = 'oidc' THEN
    SELECT state.session_version INTO v_previous_version
    FROM public.auth_session_platform_oidc_states AS state
    WHERE state.session_id = v_session_id AND state.user_id = v_user_id
    FOR UPDATE;
  ELSIF v_protocol = 'saml' THEN
    SELECT state.session_version INTO v_previous_version
    FROM public.auth_session_platform_saml_states AS state
    WHERE state.session_id = v_session_id AND state.user_id = v_user_id
    FOR UPDATE;
  END IF;
  v_previous_version := coalesce(v_previous_version,1);
  v_revoked_at := coalesce(v_session.revoked_at,v_requested_at);

  -- The auth-session row is the durable deduplication fence even after its
  -- original command ledger has been pruned. A fresh browser logout request
  -- still receives a valid local-only receipt so the transport can clear its
  -- cookie, but it must not mint another command, audit event, continuation,
  -- retry job, or upstream signing opportunity for an already-revoked session.
  IF v_session.revoked_at IS NOT NULL THEN
    RETURN jsonb_build_object(
      'category','revoked_local_only',
      'operationRunId',v_operation_run_id::text,
      'sessionId',v_session_id::text,'userId',v_user_id::text,
      'tenantId',to_jsonb(v_tenant_id),
      'requestedAt',v_request_snapshot -> 'requestedAt',
      'observedAt',to_jsonb(v_requested_at),
      'previousVersion',v_previous_version,
      'revokedAt',to_jsonb(v_revoked_at)
    );
  END IF;

  IF v_protocol = 'oidc' THEN
    SELECT material.* INTO v_oidc
    FROM public.tenant_oidc_session_materials AS material
    WHERE material.continuation_id IS NULL
      AND material.user_id = v_user_id
      AND EXISTS (
        SELECT 1
        FROM app.private_oidc_material_effective_session_v1(material.id)
          AS effective
        WHERE effective.session_id = v_session_id
          AND effective.tenant_id IS NOT DISTINCT FROM v_tenant_id
      )
    FOR UPDATE;
    v_oidc_found := FOUND;
    IF v_oidc_found THEN
      SELECT effective.authority INTO STRICT v_oidc_effective_authority
      FROM app.private_oidc_material_effective_session_v1(v_oidc.id)
        AS effective
      WHERE effective.session_id = v_session_id
        AND effective.tenant_id IS NOT DISTINCT FROM v_tenant_id;
      v_command_authority := v_oidc_effective_authority;
    END IF;
  ELSIF v_protocol = 'saml' AND v_tenant_id IS NOT NULL THEN
    SELECT material.* INTO v_tenant_saml
    FROM public.tenant_saml_session_materials AS material
    WHERE material.tenant_id = v_tenant_id
      AND material.session_id = v_session_id
      AND material.continuation_id IS NULL
      AND material.user_id = v_user_id
    FOR SHARE;
    v_tenant_saml_found := FOUND;
    IF NOT v_tenant_saml_found THEN
      SELECT material.* INTO v_platform_saml
      FROM public.platform_saml_session_materials AS material
      JOIN LATERAL app.private_platform_saml_material_effective_session_v1(
        material.id
      ) AS effective
        ON effective.session_id = v_session_id
       AND effective.tenant_id = v_tenant_id
       AND effective.authority = 'tenant_platform_provider'
      WHERE material.continuation_id IS NULL
        AND material.user_id = v_user_id
      FOR SHARE OF material;
      v_platform_saml_found := FOUND;
      IF v_platform_saml_found THEN
        SELECT effective.* INTO STRICT v_platform_saml_effective
        FROM app.private_platform_saml_material_effective_session_v1(
          v_platform_saml.id
        ) AS effective
        WHERE effective.session_id = v_session_id
          AND effective.tenant_id = v_tenant_id
          AND effective.authority = 'tenant_platform_provider';
        v_command_authority := v_platform_saml_effective.authority;
      END IF;
    END IF;
  ELSIF v_protocol = 'saml' THEN
    SELECT material.* INTO v_platform_saml
    FROM public.platform_saml_session_materials AS material
    JOIN LATERAL app.private_platform_saml_material_effective_session_v1(
      material.id
    ) AS effective
      ON effective.session_id = v_session_id
     AND effective.tenant_id IS NULL
     AND effective.authority = 'platform_provider'
    WHERE material.session_id = v_session_id
      AND material.continuation_id IS NULL
      AND material.user_id = v_user_id
    FOR SHARE;
    v_platform_saml_found := FOUND;
    IF v_platform_saml_found THEN
      SELECT effective.* INTO STRICT v_platform_saml_effective
      FROM app.private_platform_saml_material_effective_session_v1(
        v_platform_saml.id
      ) AS effective
      WHERE effective.session_id = v_session_id
        AND effective.tenant_id IS NULL
        AND effective.authority = 'platform_provider';
      v_command_authority := v_platform_saml_effective.authority;
    END IF;
  END IF;
  v_command_authority := coalesce(
    v_command_authority,
    CASE WHEN v_tenant_id IS NULL THEN 'platform_session'
      ELSE 'tenant_session' END
  );

  UPDATE public.auth_sessions AS family
  SET revoked_at = v_requested_at,
      revoke_reason = left(coalesce(v_protocol,'session') || '_local_logout',500)
  WHERE family.user_id = v_user_id
    AND family.rotation_family_id = v_session.rotation_family_id
    AND family.revoked_at IS NULL;
  IF v_tenant_id IS NOT NULL THEN
    UPDATE public.auth_session_mfa_states AS state
    SET session_version = CASE
          WHEN state.session_version < 9000000000000000
            THEN state.session_version + 1
          ELSE state.session_version END
    WHERE state.tenant_id = v_tenant_id AND state.session_id = v_session_id
      AND state.user_id = v_user_id
      AND state.session_version = v_previous_version;
  ELSIF v_protocol = 'oidc' THEN
    UPDATE public.auth_session_platform_oidc_states AS state
    SET session_version = CASE
          WHEN state.session_version < 2147483647
            THEN state.session_version + 1
          ELSE state.session_version END
    WHERE state.session_id = v_session_id AND state.user_id = v_user_id
      AND state.session_version = v_previous_version;
  ELSIF v_protocol = 'saml' THEN
    UPDATE public.auth_session_platform_saml_states AS state
    SET session_version = CASE
          WHEN state.session_version < 2147483647
            THEN state.session_version + 1
          ELSE state.session_version END
    WHERE state.session_id = v_session_id AND state.user_id = v_user_id
      AND state.session_version = v_previous_version;
  END IF;

  IF v_oidc_found AND v_oidc.scrubbed_at IS NULL
     AND v_oidc.logout_operation_run_id IS NULL THEN
    v_continuation_created := v_request_upstream
      AND v_session.absolute_expires_at > v_requested_at
      AND v_oidc.expires_at > v_requested_at
      AND v_continuation_expires_at <= v_session.absolute_expires_at
      AND v_continuation_expires_at <= v_oidc.expires_at
      AND v_oidc.end_session_endpoint IS NOT NULL
      AND v_oidc.id_token_key_version IS NOT NULL
      AND v_oidc.id_token_ciphertext IS NOT NULL
      AND v_oidc.id_token_digest IS NOT NULL;
    v_schedule_retry := v_request_upstream
      AND v_session.absolute_expires_at > v_requested_at
      AND v_oidc.expires_at > v_requested_at
      AND v_oidc.refresh_state IN ('ready','claimed')
      AND v_oidc.refresh_token_key_version IS NOT NULL
      AND v_oidc.refresh_token_ciphertext IS NOT NULL
      AND v_oidc.revocation_endpoint IS NOT NULL;
    IF v_schedule_retry THEN v_retry_job_id := uuidv7(); END IF;
    UPDATE public.tenant_oidc_session_materials AS material
    SET logout_disposition = CASE WHEN v_continuation_created
          THEN 'claimed' ELSE 'skipped' END,
        logout_operation_run_id = v_operation_run_id,
        logout_claimed_at = v_requested_at,
        refresh_state = CASE WHEN material.refresh_state = 'unavailable'
          THEN 'unavailable' ELSE 'revoked' END,
        refresh_claimed_at = NULL,refresh_claim_expires_at = NULL,
        refresh_version = CASE
          WHEN material.refresh_version < 8999999999999999
            THEN material.refresh_version + 1
          ELSE material.refresh_version END,
        updated_at = v_requested_at
    WHERE material.id = v_oidc.id
      AND material.logout_operation_run_id IS NULL;
    IF NOT FOUND THEN
      v_continuation_created := false;
      v_schedule_retry := false;
      v_retry_job_id := NULL;
    END IF;
  ELSIF v_tenant_saml_found
      AND v_tenant_saml.logout_operation_run_id IS NULL THEN
    v_continuation_created := v_request_upstream
      AND v_session.absolute_expires_at > v_requested_at
      AND v_continuation_expires_at <= v_session.absolute_expires_at
      AND v_tenant_saml.aad_version = 2
      AND v_tenant_saml.key_version IS NOT NULL
      AND v_tenant_saml.ciphertext IS NOT NULL
      AND v_tenant_saml.logout_configuration IS NOT NULL
      AND NOT EXISTS (
        SELECT 1 FROM public.session_logout_continuations AS continuation
        WHERE continuation.tenant_id = v_tenant_id
          AND continuation.tenant_saml_material_id = v_tenant_saml.id
      );
    PERFORM set_config('app.saml_logout_claim_v1','on',true);
    UPDATE public.tenant_saml_session_materials AS material
    SET logout_disposition = CASE WHEN v_continuation_created
          THEN 'claimed' ELSE 'skipped' END,
        logout_operation_run_id = v_operation_run_id,
        logout_claimed_at = v_requested_at
    WHERE material.id = v_tenant_saml.id
      AND material.tenant_id = v_tenant_saml.tenant_id
      AND material.logout_operation_run_id IS NULL;
    IF NOT FOUND THEN v_continuation_created := false; END IF;
  ELSIF v_platform_saml_found
      AND v_platform_saml.logout_operation_run_id IS NULL THEN
    v_continuation_created := v_request_upstream
      AND v_session.absolute_expires_at > v_requested_at
      AND v_continuation_expires_at <= v_session.absolute_expires_at
      AND v_platform_saml.key_version IS NOT NULL
      AND v_platform_saml.nonce IS NOT NULL
      AND v_platform_saml.ciphertext IS NOT NULL
      AND v_platform_saml.logout_configuration IS NOT NULL
      AND NOT EXISTS (
        SELECT 1 FROM public.session_logout_continuations AS continuation
        WHERE continuation.platform_saml_material_id = v_platform_saml.id
      );
    PERFORM set_config('app.saml_logout_claim_v1','on',true);
    PERFORM set_config('app.platform_saml_direct_runtime_write_v1','on',true);
    UPDATE public.platform_saml_session_materials AS material
    SET logout_disposition = CASE WHEN v_continuation_created
          THEN 'claimed' ELSE 'skipped' END,
        logout_operation_run_id = v_operation_run_id,
        logout_claimed_at = v_requested_at
    WHERE material.id = v_platform_saml.id
      AND material.logout_operation_run_id IS NULL;
    IF NOT FOUND THEN v_continuation_created := false; END IF;
  END IF;

  v_base_result := jsonb_build_object(
    'category','revoked_local_only',
    'operationRunId',v_operation_run_id::text,
    'sessionId',v_session_id::text,'userId',v_user_id::text,
    'tenantId',to_jsonb(v_tenant_id),
    'requestedAt',v_request_snapshot -> 'requestedAt',
    'observedAt',to_jsonb(v_requested_at),
    'previousVersion',v_previous_version,'revokedAt',to_jsonb(v_revoked_at)
  );
  INSERT INTO public.tenant_oidc_logout_commands (
    tenant_id,authority,operation_run_id,session_id,expected_version,
    request_upstream,material_id,request_digest,request_snapshot,
    result_snapshot,applied_at
  ) VALUES (
    v_tenant_id,v_command_authority,v_operation_run_id,v_session_id,
    v_previous_version,v_request_upstream,
    CASE WHEN v_oidc_found THEN v_oidc.id END,
    v_request_digest,v_request_snapshot,v_base_result,v_requested_at
  );
  IF v_schedule_retry THEN
    INSERT INTO public.tenant_oidc_logout_retry_jobs (
      id,tenant_id,authority,operation_run_id,material_id,session_family_id,
      state,attempt,maximum_attempts,not_before,version,created_at,updated_at
    ) VALUES (
      v_retry_job_id,v_oidc.tenant_id,v_oidc.authority,v_operation_run_id,
      v_oidc.id,v_session.rotation_family_id,'pending',0,8,v_requested_at,1,
      v_requested_at,v_requested_at
    );
  END IF;
  IF v_continuation_created THEN
    INSERT INTO public.session_logout_continuations (
      id,token_digest,operation_run_id,session_id,user_id,tenant_id,
      authority,protocol,oidc_material_id,tenant_saml_material_id,
      platform_saml_material_id,created_at,expires_at
    ) VALUES (
      v_continuation_id,v_continuation_digest,v_operation_run_id,v_session_id,
      v_user_id,v_tenant_id,
      CASE WHEN v_oidc_found THEN v_oidc_effective_authority
        WHEN v_tenant_saml_found THEN 'tenant_provider'
        WHEN v_tenant_id IS NOT NULL THEN 'tenant_platform_provider'
        ELSE 'platform_provider' END,
      v_protocol,CASE WHEN v_oidc_found THEN v_oidc.id END,
      CASE WHEN v_tenant_saml_found THEN v_tenant_saml.id END,
      CASE WHEN v_platform_saml_found THEN v_platform_saml.id END,
      v_requested_at,v_continuation_expires_at
    );
  END IF;

  IF v_tenant_id IS NOT NULL THEN
    INSERT INTO public.audit_events (
      id,tenant_id,sequence,occurred_at,actor_type,actor_user_id,action,
      resource_type,resource_id,request_id,correlation_id,ip_address,
      user_agent,authentication_method,outcome,metadata
    ) VALUES (
      uuidv7(),v_tenant_id,0,v_requested_at,'user',v_user_id,
      'tenant.identity.session_local_logout','auth_session',v_session_id,
      v_request_id,v_correlation_id,v_remote_address,v_user_agent,
      v_protocol,'success',jsonb_build_object(
        'upstream_requested',v_request_upstream,
        'continuation_created',v_continuation_created,
        'material_present',v_oidc_found OR v_tenant_saml_found
          OR v_platform_saml_found,
        'material_disclosed',false
      )
    );
  ELSE
    PERFORM app.append_platform_audit_event(
      uuidv7(),'user',v_user_id,'platform.identity.session_local_logout',
      'auth_session',v_session_id,v_request_id,v_correlation_id,
      v_remote_address,v_user_agent,v_protocol,'success',NULL,
      jsonb_build_object(
        'upstream_requested',v_request_upstream,
        'continuation_created',v_continuation_created,
        'material_present',v_oidc_found OR v_platform_saml_found,
        'material_disclosed',false
      )
    );
  END IF;
  IF v_continuation_created THEN
    v_result := v_base_result || jsonb_build_object(
      'category','logout_continuation',
      'continuationId',v_continuation_id::text,
      'continuationExpiresAt',to_jsonb(v_continuation_expires_at)
    );
    RETURN v_result;
  END IF;
  RETURN v_base_result;
EXCEPTION WHEN unique_violation THEN
  -- A digest or material collision never reassigns a live browser proof.
  RETURN NULL;
WHEN invalid_text_representation OR numeric_value_out_of_range
  OR data_exception THEN
  RAISE EXCEPTION 'invalid local session logout command'
    USING ERRCODE = '22023';
END;
$function$;
--> statement-breakpoint
DO $assert_logout_writer_successor$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_proc AS routine
    JOIN pg_catalog.pg_roles AS owner ON owner.oid=routine.proowner
    JOIN pg_catalog.pg_language AS language ON language.oid=routine.prolang
    WHERE routine.oid='app.revoke_local_session_for_logout_v1(jsonb)'::pg_catalog.regprocedure
      AND owner.rolname='periapsis_migrator' AND language.lanname='plpgsql'
      AND routine.prokind='f' AND routine.provolatile='v' AND routine.prosecdef
      AND NOT routine.proisstrict AND NOT routine.proleakproof
      AND routine.proparallel='u' AND routine.pronargs=1
      AND routine.pronargdefaults=0 AND routine.prorettype='pg_catalog.jsonb'::pg_catalog.regtype
      AND NOT routine.proretset
      AND routine.proconfig IS NOT DISTINCT FROM ARRAY['search_path=pg_catalog, public, app']::pg_catalog.text[]
      AND pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(routine.prosrc,'UTF8')),'hex')='260d916d1f9a60d96ebd71f670e08e132e51c44a4240b364a0fb5d1847ee9625'
      AND (
        SELECT count(*)=2 AND coalesce(bool_and(
          acl.grantor=routine.proowner
          AND acl.grantee IN (routine.proowner,'periapsis_api'::pg_catalog.regrole)
          AND acl.privilege_type='EXECUTE' AND NOT acl.is_grantable
        ),false)
        FROM pg_catalog.aclexplode(coalesce(routine.proacl,
          pg_catalog.acldefault('f',routine.proowner))) AS acl
      )
  ) THEN
    RAISE EXCEPTION 'local logout writer successor source/catalog mismatch' USING ERRCODE='55000';
  END IF;
END;
$assert_logout_writer_successor$;
