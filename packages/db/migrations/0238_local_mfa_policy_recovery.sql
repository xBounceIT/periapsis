-- Preserve local break-glass assurance across tenant selection for explicit
-- MFA policy administration. No policy, grant or tenant factor is seeded.
CREATE OR REPLACE FUNCTION app.private_require_recent_local_mfa_policy_session_v1(
  p_session_id uuid,p_tenant_id uuid,p_authentication_method text
)
RETURNS uuid
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog,public,app
AS $function$
DECLARE
  actor_id uuid := app.context_user_id();
  active_tenant_id uuid;
  local_assurance boolean := false;
BEGIN
  IF p_session_id IS NULL
     OR uuid_extract_version(p_session_id) IS DISTINCT FROM 7
     OR p_authentication_method NOT IN (
       'bootstrap_totp','totp','passkey','oidc','saml'
     ) THEN
    RAISE EXCEPTION 'recent local MFA session is required'
      USING ERRCODE = '42501';
  END IF;
  SELECT session.active_tenant_id INTO active_tenant_id
  FROM ONLY public.auth_sessions AS session
  JOIN ONLY public.users AS local_user ON local_user.id = session.user_id
  WHERE session.id = p_session_id
    AND session.user_id = actor_id
    AND session.authentication_method = p_authentication_method
    AND session.revoked_at IS NULL
    AND session.idle_expires_at > transaction_timestamp()
    AND session.absolute_expires_at > transaction_timestamp()
    AND session.mfa_satisfied_at BETWEEN
      transaction_timestamp() - interval '5 minutes'
      AND transaction_timestamp() + interval '30 seconds'
    AND local_user.active
  FOR SHARE OF session,local_user;
  IF NOT FOUND OR (p_tenant_id IS NOT NULL
    AND active_tenant_id IS DISTINCT FROM p_tenant_id) THEN
    RAISE EXCEPTION 'recent local MFA session is required'
      USING ERRCODE = '42501';
  END IF;

  IF active_tenant_id IS NOT NULL THEN
    SELECT EXISTS (
      SELECT 1
      FROM ONLY public.auth_session_mfa_states AS state
      JOIN ONLY public.auth_session_mfa_evidence AS evidence
        ON evidence.tenant_id = state.tenant_id
       AND evidence.session_id = state.session_id
      LEFT JOIN ONLY public.tenant_totp_factors AS totp_factor
        ON evidence.kind = 'totp'
       AND totp_factor.tenant_id = evidence.tenant_id
       AND totp_factor.user_id = state.user_id
       AND totp_factor.id = evidence.totp_factor_id
       AND totp_factor.security_revision = evidence.factor_revision
       AND totp_factor.status = 'active'
       AND totp_factor.revoked_at IS NULL
      LEFT JOIN ONLY public.tenant_webauthn_credentials AS webauthn_credential
        ON evidence.kind = 'webauthn'
       AND webauthn_credential.tenant_id = evidence.tenant_id
       AND webauthn_credential.user_id = state.user_id
       AND webauthn_credential.id = evidence.webauthn_credential_id
       AND webauthn_credential.security_revision = evidence.factor_revision
       AND webauthn_credential.status = 'active'
       AND webauthn_credential.revoked_at IS NULL
       AND webauthn_credential.user_verification
      WHERE state.session_id = p_session_id
        AND state.tenant_id = active_tenant_id
        AND state.user_id = actor_id
        AND NOT state.recovery_restricted
        AND state.issued_at <= transaction_timestamp() + interval '30 seconds'
        AND evidence.kind IN ('totp','webauthn')
        AND evidence.level IN ('mfa','phishing_resistant')
        AND evidence.authenticated_at BETWEEN
          transaction_timestamp() - interval '5 minutes'
          AND transaction_timestamp() + interval '30 seconds'
        AND evidence.authenticated_at <= state.issued_at + interval '30 seconds'
        AND (evidence.expires_at IS NULL
          OR evidence.expires_at > transaction_timestamp())
        AND ((evidence.kind = 'totp' AND totp_factor.id IS NOT NULL)
          OR (evidence.kind = 'webauthn'
            AND webauthn_credential.id IS NOT NULL))
    ) INTO local_assurance;
  ELSE
    SELECT EXISTS (
      SELECT 1
      FROM ONLY public.auth_session_platform_oidc_states AS state
      JOIN ONLY public.auth_session_platform_oidc_evidence AS evidence
        ON evidence.session_id = state.session_id
       AND evidence.user_id = state.user_id
       AND evidence.kind = 'totp'
       AND evidence.level = 'mfa'
      JOIN ONLY public.totp_credentials AS factor
        ON factor.id = evidence.totp_credential_id
       AND factor.user_id = state.user_id
       AND factor.security_revision = evidence.factor_revision
       AND factor.confirmed_at IS NOT NULL
       AND factor.disabled_at IS NULL
       AND factor.last_accepted_counter IS NOT NULL
      WHERE state.session_id = p_session_id
        AND state.user_id = actor_id
        AND NOT state.recovery_restricted
        AND state.issued_at <= transaction_timestamp() + interval '30 seconds'
        AND evidence.authenticated_at BETWEEN
          transaction_timestamp() - interval '5 minutes'
          AND transaction_timestamp() + interval '30 seconds'
        AND evidence.authenticated_at <= state.issued_at + interval '30 seconds'
        AND (evidence.expires_at IS NULL
          OR evidence.expires_at > transaction_timestamp())
    ) INTO local_assurance;

  END IF;

  -- An exact, freshly verified local break-glass TOTP remains local MFA after
  -- tenant selection. The caller still requires live tenant read/manage grants.
  IF NOT local_assurance AND (active_tenant_id IS NULL OR NOT EXISTS (
    SELECT 1 FROM ONLY public.auth_session_mfa_states AS state
    WHERE state.session_id = p_session_id
  )) THEN
    SELECT EXISTS (
      SELECT 1
      FROM ONLY public.local_break_glass_credentials AS credential
      JOIN ONLY public.user_login_identifiers AS identifier
        ON identifier.id = credential.login_identifier_id
       AND identifier.user_id = credential.user_id
       AND identifier.kind = 'local_email'
       AND identifier.verified_at IS NOT NULL
       AND identifier.retired_at IS NULL
      JOIN ONLY public.totp_credentials AS factor
        ON factor.user_id = credential.user_id
       AND factor.confirmed_at IS NOT NULL
       AND factor.disabled_at IS NULL
       AND factor.last_accepted_counter IS NOT NULL
       AND factor.updated_at = (
         SELECT session.mfa_satisfied_at
         FROM ONLY public.auth_sessions AS session
         WHERE session.id = p_session_id
       )
      WHERE credential.user_id = actor_id
        AND credential.disabled_at IS NULL
        AND NOT credential.must_rotate
        AND p_authentication_method IN ('bootstrap_totp','totp')
    ) INTO local_assurance;
  END IF;

  IF NOT local_assurance THEN
    RAISE EXCEPTION 'recent exact local MFA assurance is required'
      USING ERRCODE = '42501';
  END IF;
  RETURN actor_id;
END;
$function$;

--> statement-breakpoint
-- Service-specific projections perform the full release attestation once per
-- invocation. These functions are themselves included in the V54 catalog hash.
-- V54 does not exist until the next migration: this interval fails closed.
CREATE FUNCTION app.api_runtime_schema_readiness_v54()
RETURNS boolean[]
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app
AS $function$
DECLARE
  release_ready boolean;
BEGIN
  release_ready := app.release_runtime_schema_readiness_v54();
  IF release_ready IS DISTINCT FROM true THEN
    RETURN ARRAY[false,false,false,false,false,false,false,false]::boolean[];
  END IF;
  RETURN ARRAY[
    true,
    true,
    true,
    true,
    coalesce(app.platform_local_account_runtime_schema_readiness_v1(),false),
    coalesce(app.ticket_bulk_runtime_schema_readiness_v2(),false),
    coalesce(app.ticket_export_runtime_schema_readiness_v2(),false),
    coalesce(app.ticket_metadata_runtime_schema_readiness_v1(),false)
  ]::boolean[];
EXCEPTION
  WHEN undefined_table OR undefined_function OR insufficient_privilege
    OR invalid_schema_name OR cardinality_violation OR data_exception THEN
    RETURN ARRAY[false,false,false,false,false,false,false,false]::boolean[];
END;
$function$;
ALTER FUNCTION app.api_runtime_schema_readiness_v54() OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.api_runtime_schema_readiness_v54()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,periapsis_auditor;
GRANT EXECUTE ON FUNCTION app.api_runtime_schema_readiness_v54()
  TO periapsis_migrator,periapsis_api;
--> statement-breakpoint
CREATE FUNCTION app.worker_runtime_schema_readiness_v54()
RETURNS boolean[]
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app
AS $function$
DECLARE
  release_ready boolean;
BEGIN
  release_ready := app.release_runtime_schema_readiness_v54();
  IF release_ready IS DISTINCT FROM true THEN
    RETURN ARRAY[false,false,false,false,false]::boolean[];
  END IF;
  RETURN ARRAY[
    true,
    coalesce(app.private_sla_system_principal_catalog_ready_v1(),false),
    coalesce(app.sla_object_event_ingress_schema_readiness_v1(),false),
    coalesce(app.ticket_bulk_runtime_schema_readiness_v2(),false),
    coalesce(app.ticket_export_runtime_schema_readiness_v2(),false)
  ]::boolean[];
EXCEPTION
  WHEN undefined_table OR undefined_function OR insufficient_privilege
    OR invalid_schema_name OR cardinality_violation OR data_exception THEN
    RETURN ARRAY[false,false,false,false,false]::boolean[];
END;
$function$;
ALTER FUNCTION app.worker_runtime_schema_readiness_v54() OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.worker_runtime_schema_readiness_v54()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,periapsis_auditor;
GRANT EXECUTE ON FUNCTION app.worker_runtime_schema_readiness_v54()
  TO periapsis_migrator,periapsis_worker;
--> statement-breakpoint
