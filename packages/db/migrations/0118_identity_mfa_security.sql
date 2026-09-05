-- MFA material is reachable only through the bounded application ABI.  RLS is
-- still forced as a second boundary, but no runtime role receives table access
-- or a permissive policy.
DO $mfa_tables$
DECLARE
  relation_name text;
BEGIN
  FOREACH relation_name IN ARRAY ARRAY[
    'auth_session_local_credential_provenance',
    'auth_session_mfa_evidence',
    'auth_session_mfa_policy_pins',
    'auth_session_mfa_states',
    'auth_session_passkey_provenance',
    'mfa_policy_revisions',
    'tenant_mfa_authority_anchors',
    'tenant_mfa_authority_evidence',
    'tenant_mfa_authority_policy_pins',
    'tenant_mfa_step_up_challenges',
    'tenant_mfa_subjects',
    'tenant_post_primary_continuation_evidence',
    'tenant_post_primary_continuation_policy_pins',
    'tenant_post_primary_continuations',
    'tenant_recovery_code_sets',
    'tenant_recovery_codes',
    'tenant_totp_enrollments',
    'tenant_totp_factors',
    'tenant_webauthn_ceremonies',
    'tenant_webauthn_ceremony_credentials',
    'tenant_webauthn_credential_transports',
    'tenant_webauthn_credentials'
  ] LOOP
    EXECUTE format('ALTER TABLE public.%I OWNER TO periapsis_migrator', relation_name);
    EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY', relation_name);
    EXECUTE format(
      'REVOKE ALL ON TABLE public.%I FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor, periapsis_audit_reader_owner, periapsis_notification_dispatch_owner, periapsis_sla_api_owner, periapsis_sla_worker_owner, periapsis_sla_readiness_owner',
      relation_name
    );
  END LOOP;
END
$mfa_tables$;
--> statement-breakpoint

-- A session state and its primary provenance are committed in one transaction.
-- The deferred check permits either insert order while rejecting zero, mixed,
-- duplicate, or user-substituted provenance at commit.
CREATE FUNCTION app.assert_auth_session_mfa_provenance_v1(
  p_tenant_id uuid,
  p_session_id uuid
)
RETURNS void
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  state_record public.auth_session_mfa_states%ROWTYPE;
  local_count integer;
  passkey_count integer;
BEGIN
  SELECT state.* INTO state_record
  FROM public.auth_session_mfa_states AS state
  WHERE state.tenant_id = p_tenant_id AND state.session_id = p_session_id;
  IF NOT FOUND THEN
    RETURN;
  END IF;

  SELECT count(*)::integer INTO local_count
  FROM public.auth_session_local_credential_provenance AS provenance
  JOIN public.local_break_glass_credentials AS credential
    ON credential.id = provenance.credential_id
  WHERE provenance.tenant_id = p_tenant_id
    AND provenance.session_id = p_session_id
    AND provenance.user_id = state_record.user_id
    AND credential.user_id = state_record.user_id
    AND credential.password_version::bigint = provenance.credential_revision;
  SELECT count(*)::integer INTO passkey_count
  FROM public.auth_session_passkey_provenance AS provenance
  JOIN public.tenant_webauthn_credentials AS credential
    ON credential.tenant_id = provenance.tenant_id
   AND credential.user_id = provenance.user_id
   AND credential.id = provenance.credential_id
  WHERE provenance.tenant_id = p_tenant_id
    AND provenance.session_id = p_session_id
    AND provenance.user_id = state_record.user_id
    AND credential.version = provenance.credential_revision;

  IF (state_record.primary_kind = 'local_credential'
      AND (local_count <> 1 OR passkey_count <> 0))
     OR (state_record.primary_kind = 'passkey'
      AND (local_count <> 0 OR passkey_count <> 1)) THEN
    RAISE EXCEPTION 'auth session has invalid typed primary provenance'
      USING ERRCODE = '23514';
  END IF;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.assert_auth_session_mfa_provenance_v1(uuid, uuid)
  OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.assert_auth_session_mfa_provenance_v1(uuid, uuid)
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor, periapsis_audit_reader_owner,
       periapsis_notification_dispatch_owner, periapsis_sla_api_owner,
       periapsis_sla_worker_owner, periapsis_sla_readiness_owner;
--> statement-breakpoint

CREATE FUNCTION app.enforce_auth_session_mfa_provenance_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  PERFORM app.assert_auth_session_mfa_provenance_v1(
    coalesce(NEW.tenant_id, OLD.tenant_id),
    coalesce(NEW.session_id, OLD.session_id)
  );
  RETURN NULL;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.enforce_auth_session_mfa_provenance_v1()
  OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.enforce_auth_session_mfa_provenance_v1()
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor, periapsis_audit_reader_owner,
       periapsis_notification_dispatch_owner, periapsis_sla_api_owner,
       periapsis_sla_worker_owner, periapsis_sla_readiness_owner;
--> statement-breakpoint

CREATE CONSTRAINT TRIGGER auth_session_mfa_states_provenance_v1
AFTER INSERT OR UPDATE ON public.auth_session_mfa_states
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION app.enforce_auth_session_mfa_provenance_v1();
--> statement-breakpoint
CREATE CONSTRAINT TRIGGER auth_session_local_provenance_parent_v1
AFTER INSERT OR UPDATE OR DELETE ON public.auth_session_local_credential_provenance
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION app.enforce_auth_session_mfa_provenance_v1();
--> statement-breakpoint
CREATE CONSTRAINT TRIGGER auth_session_passkey_provenance_parent_v1
AFTER INSERT OR UPDATE OR DELETE ON public.auth_session_passkey_provenance
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION app.enforce_auth_session_mfa_provenance_v1();
--> statement-breakpoint

-- Typed foreign keys prevent cross-kind references; this trigger additionally
-- pins every local factor to the exact subject and current security revision of
-- its parent snapshot. Provider evidence is already pinned to an exact
-- tenant-scoped provider binding and trust-rule revision.
CREATE FUNCTION app.validate_mfa_evidence_subject_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  subject_user_id uuid;
  referenced_user_id uuid;
  referenced_revision bigint;
BEGIN
  IF TG_TABLE_NAME = 'auth_session_mfa_evidence' THEN
    SELECT state.user_id INTO STRICT subject_user_id
    FROM public.auth_session_mfa_states AS state
    WHERE state.tenant_id = NEW.tenant_id AND state.session_id = NEW.session_id;
  ELSIF TG_TABLE_NAME = 'tenant_mfa_authority_evidence' THEN
    SELECT anchor.user_id INTO STRICT subject_user_id
    FROM public.tenant_mfa_authority_anchors AS anchor
    WHERE anchor.tenant_id = NEW.tenant_id AND anchor.id = NEW.anchor_id;
  ELSIF TG_TABLE_NAME = 'tenant_post_primary_continuation_evidence' THEN
    SELECT continuation.user_id INTO STRICT subject_user_id
    FROM public.tenant_post_primary_continuations AS continuation
    WHERE continuation.tenant_id = NEW.tenant_id
      AND continuation.id = NEW.continuation_id;
  ELSE
    RAISE EXCEPTION 'unsupported MFA evidence relation'
      USING ERRCODE = '55000';
  END IF;

  IF NEW.kind = 'local_credential' THEN
    SELECT credential.user_id, credential.password_version::bigint
    INTO STRICT referenced_user_id, referenced_revision
    FROM public.local_break_glass_credentials AS credential
    WHERE credential.id = NEW.local_credential_id;
  ELSIF NEW.kind = 'totp' THEN
    SELECT factor.user_id, factor.security_revision
    INTO STRICT referenced_user_id, referenced_revision
    FROM public.tenant_totp_factors AS factor
    WHERE factor.tenant_id = NEW.tenant_id AND factor.id = NEW.totp_factor_id;
  ELSIF NEW.kind = 'webauthn' THEN
    SELECT credential.user_id, credential.version
    INTO STRICT referenced_user_id, referenced_revision
    FROM public.tenant_webauthn_credentials AS credential
    WHERE credential.tenant_id = NEW.tenant_id
      AND credential.id = NEW.webauthn_credential_id;
  ELSIF NEW.kind = 'recovery' THEN
    SELECT code_set.user_id, code_set.security_revision
    INTO STRICT referenced_user_id, referenced_revision
    FROM public.tenant_recovery_code_sets AS code_set
    WHERE code_set.tenant_id = NEW.tenant_id
      AND code_set.id = NEW.recovery_code_set_id;
  ELSIF NEW.kind = 'provider' THEN
    IF subject_user_id IS NULL OR NOT EXISTS (
      SELECT 1
      FROM public.tenant_auth_provider_bindings AS binding
      WHERE binding.tenant_id = NEW.tenant_id
        AND binding.id = NEW.binding_id
        AND binding.provider_id = NEW.provider_id
    ) THEN
      RAISE EXCEPTION 'MFA provider evidence is not tenant-bound'
        USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
  ELSE
    RAISE EXCEPTION 'unsupported MFA evidence kind'
      USING ERRCODE = '23514';
  END IF;

  IF subject_user_id IS NULL
     OR referenced_user_id IS DISTINCT FROM subject_user_id
     OR referenced_revision IS DISTINCT FROM NEW.factor_revision THEN
    RAISE EXCEPTION 'MFA evidence subject or revision mismatch'
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.validate_mfa_evidence_subject_v1()
  OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.validate_mfa_evidence_subject_v1()
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor, periapsis_audit_reader_owner,
       periapsis_notification_dispatch_owner, periapsis_sla_api_owner,
       periapsis_sla_worker_owner, periapsis_sla_readiness_owner;
--> statement-breakpoint

CREATE TRIGGER auth_session_mfa_evidence_subject_v1
BEFORE INSERT OR UPDATE ON public.auth_session_mfa_evidence
FOR EACH ROW EXECUTE FUNCTION app.validate_mfa_evidence_subject_v1();
--> statement-breakpoint
CREATE TRIGGER tenant_mfa_authority_evidence_subject_v1
BEFORE INSERT OR UPDATE ON public.tenant_mfa_authority_evidence
FOR EACH ROW EXECUTE FUNCTION app.validate_mfa_evidence_subject_v1();
--> statement-breakpoint
CREATE TRIGGER tenant_continuation_evidence_subject_v1
BEFORE INSERT OR UPDATE ON public.tenant_post_primary_continuation_evidence
FOR EACH ROW EXECUTE FUNCTION app.validate_mfa_evidence_subject_v1();
