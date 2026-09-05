-- Runtime OIDC through an explicit tenant admission to a platform provider.
-- Provider cryptographic scope and tenant admission are deliberately separate
-- in every JSON projection and every persisted provenance row.

-- v35 changes the persisted MFA authority ABI and is intentionally a quiesced
-- cutover. The deployer first disables every supported runtime login and drains
-- all existing sessions. Any unexpected role that can explicitly inherit a
-- writer group is part of the same gate. NOLOGIN closes the reconnect race; the
-- activity check closes already-entered v34 bodies that have not reached a
-- drained table yet.
DO $v35_mfa_quiesced_cutover$
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
      'v35 MFA cutover requires every runtime writer login to be NOLOGIN'
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
      'v35 MFA cutover requires every runtime writer session to be drained'
      USING ERRCODE = '55000';
  END IF;
END;
$v35_mfa_quiesced_cutover$;
--> statement-breakpoint

ALTER TABLE public.tenant_post_primary_passkey_provenance
  OWNER TO periapsis_migrator;
ALTER TABLE public.tenant_post_primary_passkey_provenance
  FORCE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE public.tenant_post_primary_passkey_provenance
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
    periapsis_auditor, periapsis_audit_reader_owner,
    periapsis_notification_dispatch_owner, periapsis_sla_api_owner,
    periapsis_sla_worker_owner, periapsis_sla_readiness_owner,
    periapsis_ticket_saved_view_owner, periapsis_ticket_attribution_owner,
    periapsis_ticket_sla_projection_owner;

ALTER TABLE public.tenant_mfa_webauthn_evidence_copy_capabilities
  OWNER TO periapsis_migrator;
ALTER TABLE public.tenant_mfa_webauthn_evidence_copy_capabilities
  FORCE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE
  public.tenant_mfa_webauthn_evidence_copy_capabilities
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
    periapsis_auditor, periapsis_audit_reader_owner,
    periapsis_notification_dispatch_owner, periapsis_sla_api_owner,
    periapsis_sla_worker_owner, periapsis_sla_readiness_owner,
    periapsis_ticket_saved_view_owner, periapsis_ticket_attribution_owner,
    periapsis_ticket_sla_projection_owner;
--> statement-breakpoint

-- Drain every pre-v35 MFA writer before the security epoch is split or a
-- terminal replay snapshot is scanned. Runtime paths acquire these relations
-- in opposing orders, so every drain lock is NOWAIT: any in-flight writer makes
-- this migration transaction fail for an outer retry instead of forming a lock
-- cycle. Once every lock is held, new writers remain excluded through commit.
LOCK TABLE ONLY public.tenant_webauthn_ceremonies
  IN EXCLUSIVE MODE NOWAIT;
LOCK TABLE ONLY public.tenant_webauthn_credentials
  IN EXCLUSIVE MODE NOWAIT;
LOCK TABLE ONLY public.tenant_totp_enrollments
  IN EXCLUSIVE MODE NOWAIT;
LOCK TABLE ONLY public.tenant_mfa_step_up_challenges
  IN EXCLUSIVE MODE NOWAIT;
LOCK TABLE ONLY public.tenant_post_primary_continuations
  IN EXCLUSIVE MODE NOWAIT;
LOCK TABLE ONLY public.auth_sessions IN EXCLUSIVE MODE NOWAIT;
LOCK TABLE ONLY public.auth_session_mfa_states IN EXCLUSIVE MODE NOWAIT;
LOCK TABLE ONLY public.auth_session_local_credential_provenance
  IN EXCLUSIVE MODE NOWAIT;
LOCK TABLE ONLY public.auth_session_passkey_provenance
  IN EXCLUSIVE MODE NOWAIT;
LOCK TABLE ONLY public.auth_session_federated_provenance
  IN EXCLUSIVE MODE NOWAIT;
LOCK TABLE ONLY public.auth_session_tenant_platform_federated_provenance
  IN EXCLUSIVE MODE NOWAIT;
--> statement-breakpoint

-- A claimed v34 dual-factor challenge did not persist which factor won the
-- claim.  That choice cannot be reconstructed from allowed_factors or from a
-- later completion payload, so invalidate every unbound claimed artifact at
-- cutover.  Pending artifacts remain claimable by v35, and terminal history
-- remains immutable/replay-only.
UPDATE ONLY public.tenant_mfa_step_up_challenges AS challenge
SET state = 'expired',version = challenge.version + 1,
    failure_reason = 'factor_selector_unavailable',
    failed_at = greatest(transaction_timestamp(),challenge.claimed_at)
WHERE challenge.state = 'claimed'
  AND challenge.claimed_factor_kind IS NULL;
--> statement-breakpoint

-- v34 could persist the just-completed factor method instead of the typed
-- primary method.  A method/provenance mismatch cannot be interpreted safely
-- by the v35 revalidation router, so revoke it at cutover rather than
-- relabeling the immutable primary authentication.
UPDATE ONLY public.auth_sessions AS session
SET revoked_at = greatest(transaction_timestamp(),session.created_at),
    revoke_reason = 'typed_primary_method_mismatch_upgrade'
FROM ONLY public.auth_session_mfa_states AS state
WHERE state.session_id = session.id
  AND state.user_id = session.user_id
  AND state.tenant_id = session.active_tenant_id
  AND (
    (state.primary_kind = 'local_credential'
      AND session.authentication_method NOT IN (
        'bootstrap_totp','totp','recovery_code'
      ))
    OR (state.primary_kind = 'passkey'
      AND session.authentication_method <> 'passkey')
    OR (state.primary_kind = 'tenant_provider' AND NOT EXISTS (
      SELECT 1
      FROM ONLY public.auth_session_federated_provenance AS provenance
      WHERE provenance.tenant_id = state.tenant_id
        AND provenance.session_id = state.session_id
        AND provenance.user_id = state.user_id
        AND provenance.primary_kind = 'tenant_provider'
        AND provenance.authentication_method = session.authentication_method
        AND provenance.authentication_method IN ('oidc','saml')
    ))
    OR (state.primary_kind = 'tenant_platform_provider'
      AND session.authentication_method <> 'oidc')
  )
  AND session.revoked_at IS NULL;
--> statement-breakpoint

-- MFA deadlines and reservations are signed and compared at millisecond
-- precision. Observed/authenticated lifecycle instants retain microseconds.
-- Shorten pre-v35 live deadlines by less than one millisecond;
-- pathological sub-millisecond authorities that cannot remain valid are
-- revoked/expired fail closed.  Existing authority artifacts intentionally
-- become stale because their exact source deadline no longer matches.
UPDATE public.auth_sessions AS session
SET idle_expires_at = date_trunc('milliseconds',session.idle_expires_at),
    absolute_expires_at = date_trunc('milliseconds',session.absolute_expires_at)
WHERE session.revoked_at IS NULL
  AND (session.idle_expires_at IS DISTINCT FROM
         date_trunc('milliseconds',session.idle_expires_at)
    OR session.absolute_expires_at IS DISTINCT FROM
         date_trunc('milliseconds',session.absolute_expires_at))
  AND date_trunc('milliseconds',session.idle_expires_at) > session.created_at
  AND date_trunc('milliseconds',session.absolute_expires_at) > session.created_at;

UPDATE public.auth_sessions AS session
SET revoked_at = greatest(transaction_timestamp(),session.created_at),
    revoke_reason = 'noncanonical_session_expiry_upgrade'
WHERE session.revoked_at IS NULL
  AND (session.idle_expires_at IS DISTINCT FROM
         date_trunc('milliseconds',session.idle_expires_at)
    OR session.absolute_expires_at IS DISTINCT FROM
         date_trunc('milliseconds',session.absolute_expires_at));

ALTER TABLE public.tenant_post_primary_continuations
  DISABLE TRIGGER tenant_post_primary_continuations_federated_provenance_v1;
-- A pre-v35 tenant-provider continuation has no immutable epoch/source/grant
-- receipt.  Never backfill it from the *current* grant: that would let an
-- access disable/reactivate cycle revive the old browser receipt.  The cutover
-- expires only pending rows; terminal history remains intact.
UPDATE public.tenant_post_primary_continuations AS continuation
SET state = 'expired', version = continuation.version + 1,
    revoked_at = greatest(transaction_timestamp(),continuation.created_at),
    revoke_reason = 'unsealed_tenant_provider_authority_upgrade'
WHERE continuation.primary_kind = 'tenant_provider'
  AND continuation.state = 'pending';
-- Pre-v35 passkey continuations carry neither the primary authentication time
-- nor an exact source session tuple.  created_at and the current live session
-- are not provenance, so expire these browser receipts before installing the
-- passkey exact-one child invariant.
UPDATE public.tenant_post_primary_continuations AS continuation
SET state = 'expired', version = continuation.version + 1,
    revoked_at = greatest(transaction_timestamp(),continuation.created_at),
    revoke_reason = 'unsealed_passkey_authority_upgrade'
WHERE continuation.primary_kind = 'passkey'
  AND continuation.state = 'pending';
UPDATE public.tenant_post_primary_continuations AS continuation
SET state = 'expired', version = continuation.version + 1,
    revoked_at = greatest(transaction_timestamp(),continuation.created_at),
    revoke_reason = 'noncanonical_continuation_expiry_upgrade'
WHERE continuation.state = 'pending'
  AND continuation.expires_at IS DISTINCT FROM
      date_trunc('milliseconds',continuation.expires_at)
  AND date_trunc('milliseconds',continuation.expires_at) <=
      continuation.created_at;
UPDATE public.tenant_post_primary_continuations AS continuation
SET expires_at = date_trunc('milliseconds',continuation.expires_at)
WHERE continuation.state = 'pending'
  AND continuation.expires_at IS DISTINCT FROM
      date_trunc('milliseconds',continuation.expires_at);

-- Evidence revisions for WebAuthn are lifecycle/security pins in v35.  Replace
-- the v11 record-version validator before normalizing any stored evidence.
CREATE OR REPLACE FUNCTION app.validate_mfa_evidence_subject_v1()
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
  copy_target_revision bigint;
  copy_target_level text;
  copy_target_authenticated_at timestamptz;
BEGIN
  IF TG_TABLE_NAME = 'auth_session_mfa_evidence' THEN
    SELECT state.user_id INTO STRICT subject_user_id
    FROM ONLY public.auth_session_mfa_states AS state
    WHERE state.tenant_id = NEW.tenant_id AND state.session_id = NEW.session_id;
  ELSIF TG_TABLE_NAME = 'tenant_mfa_authority_evidence' THEN
    SELECT anchor.user_id INTO STRICT subject_user_id
    FROM ONLY public.tenant_mfa_authority_anchors AS anchor
    WHERE anchor.tenant_id = NEW.tenant_id AND anchor.id = NEW.anchor_id;
  ELSIF TG_TABLE_NAME = 'tenant_post_primary_continuation_evidence' THEN
    SELECT continuation.user_id INTO STRICT subject_user_id
    FROM ONLY public.tenant_post_primary_continuations AS continuation
    WHERE continuation.tenant_id = NEW.tenant_id
      AND continuation.id = NEW.continuation_id;
  ELSE
    RAISE EXCEPTION 'unsupported MFA evidence relation'
      USING ERRCODE = '55000';
  END IF;

  IF NEW.kind = 'local_credential' THEN
    SELECT credential.user_id,credential.password_version::bigint
      INTO STRICT referenced_user_id,referenced_revision
    FROM ONLY public.local_break_glass_credentials AS credential
    WHERE credential.id = NEW.local_credential_id;
  ELSIF NEW.kind = 'totp' THEN
    SELECT factor.user_id,factor.security_revision
      INTO STRICT referenced_user_id,referenced_revision
    FROM ONLY public.tenant_totp_factors AS factor
    WHERE factor.tenant_id = NEW.tenant_id AND factor.id = NEW.totp_factor_id;
  ELSIF NEW.kind = 'webauthn' THEN
    SELECT credential.user_id,credential.security_revision
      INTO STRICT referenced_user_id,referenced_revision
    FROM ONLY public.tenant_webauthn_credentials AS credential
    WHERE credential.tenant_id = NEW.tenant_id
      AND credential.id = NEW.webauthn_credential_id;
  ELSIF NEW.kind = 'recovery' THEN
    SELECT code_set.user_id,code_set.security_revision
      INTO STRICT referenced_user_id,referenced_revision
    FROM ONLY public.tenant_recovery_code_sets AS code_set
    WHERE code_set.tenant_id = NEW.tenant_id
      AND code_set.id = NEW.recovery_code_set_id;
  ELSIF NEW.kind = 'provider' THEN
    IF subject_user_id IS NULL OR NOT EXISTS (
      SELECT 1
      FROM ONLY public.tenant_auth_provider_bindings AS binding
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

  -- The legacy session copiers run after the credential mutation.  Only an
  -- owner-created capability bound to this backend, transaction, tenant,
  -- anchor source and destination may replace one copied WebAuthn row.  The
  -- atomic consumed_at CAS prevents a second matching INSERT from being
  -- transformed, and the outer dispatcher must delete the capability before
  -- commit.
  IF TG_TABLE_NAME = 'auth_session_mfa_evidence'
     AND NEW.kind = 'webauthn' THEN
    UPDATE ONLY public.tenant_mfa_webauthn_evidence_copy_capabilities
      AS capability
    SET consumed_evidence_id = NEW.id,
        consumed_at = transaction_timestamp()
    FROM ONLY public.tenant_mfa_authority_evidence AS source
    WHERE capability.backend_pid = pg_backend_pid()
      AND capability.transaction_id = txid_current()
      AND capability.tenant_id = NEW.tenant_id
      AND capability.destination_session_id = NEW.session_id
      AND capability.user_id = referenced_user_id
      AND capability.factor_kind = NEW.kind
      AND capability.credential_id = NEW.webauthn_credential_id
      AND capability.source_revision = NEW.factor_revision
      AND capability.source_level = NEW.level
      AND capability.source_authenticated_at = NEW.authenticated_at
      AND capability.source_expires_at IS NOT DISTINCT FROM NEW.expires_at
      AND capability.consumed_evidence_id IS NULL
      AND capability.consumed_at IS NULL
      AND source.tenant_id = capability.tenant_id
      AND source.anchor_id = capability.source_anchor_id
      AND source.id = capability.source_evidence_id
      AND source.kind = capability.factor_kind
      AND source.webauthn_credential_id = capability.credential_id
      AND source.factor_revision = capability.source_revision
      AND source.level = capability.source_level
      AND source.authenticated_at = capability.source_authenticated_at
      AND source.expires_at IS NOT DISTINCT FROM capability.source_expires_at
    RETURNING capability.target_revision,capability.target_level,
      capability.target_authenticated_at
      INTO copy_target_revision,copy_target_level,
        copy_target_authenticated_at;
    IF FOUND THEN
      NEW.factor_revision := copy_target_revision;
      NEW.level := copy_target_level;
      NEW.authenticated_at := copy_target_authenticated_at;
      NEW.expires_at := NULL;
    END IF;
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

CREATE FUNCTION app.assert_mfa_webauthn_evidence_copy_cleanup_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM ONLY public.tenant_mfa_webauthn_evidence_copy_capabilities
      AS capability
    WHERE capability.tenant_id = NEW.tenant_id
      AND capability.source_anchor_id = NEW.source_anchor_id
      AND capability.destination_session_id = NEW.destination_session_id
      AND capability.backend_pid = NEW.backend_pid
      AND capability.transaction_id = NEW.transaction_id
  ) THEN
    RAISE EXCEPTION 'WebAuthn evidence copy capability was not cleared'
      USING ERRCODE = '23514';
  END IF;
  RETURN NULL;
END;
$function$;
CREATE CONSTRAINT TRIGGER tenant_mfa_webauthn_evidence_copy_cleanup_v1
AFTER INSERT OR UPDATE ON
  public.tenant_mfa_webauthn_evidence_copy_capabilities
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION
  app.assert_mfa_webauthn_evidence_copy_cleanup_v1();
--> statement-breakpoint

-- Credential.version is the pre-v35 authority epoch as well as the record CAS.
-- Start the split security epoch at that current record version, then leave all
-- historical physical pins untouched.  A pin that was already stale therefore
-- remains stale at cutover; only the latest exact pin stays live.  Subsequent
-- ordinary assertions/renames advance version alone, while lifecycle or backup
-- state transitions advance both version and security_revision.
UPDATE ONLY public.tenant_webauthn_credentials AS credential
SET security_revision = credential.version
WHERE credential.security_revision IS DISTINCT FROM credential.version;

-- Historical stale factor pins must remain stale, but the conservative level
-- downgrade below still updates those rows.  Suspend only the three subject
-- validators for this controlled cutover; factor_revision itself is untouched.
ALTER TABLE public.auth_session_mfa_evidence
  DISABLE TRIGGER auth_session_mfa_evidence_subject_v1;
ALTER TABLE public.tenant_post_primary_continuation_evidence
  DISABLE TRIGGER tenant_continuation_evidence_subject_v1;
ALTER TABLE public.tenant_mfa_authority_evidence
  DISABLE TRIGGER tenant_mfa_authority_evidence_subject_v1;

-- Completed pre-v35 WebAuthn ceremonies already carry the exact credential
-- identity in their immutable audit event.  Seal both registration and
-- authentication replay snapshots at cutover; replay-time code must never
-- derive an authority pin from the then-current credential row.
DO $passkey_replay_security_revision_upgrade$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM ONLY public.tenant_webauthn_ceremonies AS ceremony
    LEFT JOIN ONLY public.audit_events AS audit
      ON audit.id = (ceremony.result_snapshot ->> 'auditId')::uuid
     AND audit.tenant_id = ceremony.tenant_id
     AND audit.resource_type = 'webauthn_credential'
    LEFT JOIN ONLY public.tenant_webauthn_credentials AS credential
      ON credential.tenant_id = ceremony.tenant_id
     AND credential.id = audit.resource_id
    WHERE ceremony.state = 'completed'
      AND ceremony.purpose IN (
        'registration','primary_authentication',
        'continuation_authentication','step_up_authentication'
      )
      AND (
        credential.id IS NULL
        OR jsonb_typeof(ceremony.result_snapshot) IS DISTINCT FROM 'object'
        OR jsonb_typeof(
             ceremony.result_snapshot #> '{credential}'
           ) IS DISTINCT FROM 'object'
        OR CASE WHEN ceremony.purpose = 'registration'
             THEN ceremony.result_snapshot #>> '{credential,tenantId}'
             ELSE ceremony.result_snapshot ->> 'tenantId' END
             IS DISTINCT FROM ceremony.tenant_id::text
        OR CASE WHEN ceremony.purpose = 'registration'
             THEN ceremony.result_snapshot #>> '{credential,userId}'
             ELSE ceremony.result_snapshot ->> 'userId' END
             IS DISTINCT FROM credential.user_id::text
        OR (ceremony.purpose = 'registration' AND CASE
          WHEN jsonb_typeof(
            ceremony.result_snapshot #> '{credential,id}'
          ) = 'string' THEN
            app.private_mfa_decode_base64_v1(
              ceremony.result_snapshot #>> '{credential,id}',1,4096
            ) IS DISTINCT FROM credential.credential_id
          ELSE true END)
        OR CASE WHEN jsonb_typeof(
             CASE WHEN ceremony.purpose = 'registration'
               THEN ceremony.result_snapshot #> '{credential,version}'
               ELSE ceremony.result_snapshot #>
                 '{credential,credentialVersion}' END
           ) = 'number' THEN
             (CASE WHEN ceremony.purpose = 'registration'
               THEN ceremony.result_snapshot #>> '{credential,version}'
               ELSE ceremony.result_snapshot #>>
                 '{credential,credentialVersion}' END)::bigint
               NOT BETWEEN 1 AND least(
                 credential.version,9007199254740991
               )
           ELSE true END
      )
  ) THEN
    RAISE EXCEPTION
      'pre-v35 WebAuthn replay authority is unavailable or ambiguous'
      USING ERRCODE = '55000';
  END IF;

  UPDATE ONLY public.tenant_webauthn_ceremonies AS ceremony
  SET result_snapshot = jsonb_set(
    ceremony.result_snapshot,'{credential,securityRevision}',
    to_jsonb((CASE WHEN ceremony.purpose = 'registration'
      THEN ceremony.result_snapshot #>> '{credential,version}'
      ELSE ceremony.result_snapshot #>>
        '{credential,credentialVersion}' END)::bigint),true
  )
  FROM ONLY public.audit_events AS audit
  JOIN ONLY public.tenant_webauthn_credentials AS credential
    ON credential.tenant_id = audit.tenant_id
   AND credential.id = audit.resource_id
  WHERE ceremony.state = 'completed'
    AND ceremony.purpose IN (
      'registration','primary_authentication',
      'continuation_authentication','step_up_authentication'
    )
    AND ceremony.result_snapshot ? 'credential'
    AND NOT (ceremony.result_snapshot -> 'credential'
             ? 'securityRevision')
    AND audit.id = (ceremony.result_snapshot ->> 'auditId')::uuid
    AND audit.tenant_id = ceremony.tenant_id
    AND audit.resource_type = 'webauthn_credential';

  -- A primary clone has no session authority to revoke.  The frozen v34 body
  -- returned its local initialization sentinel (1), but v35 reserves zero for
  -- this exact anchorless revoke result.  Normalize only audit-proven terminal
  -- clone snapshots; anchored session/continuation revocations stay positive.
  UPDATE ONLY public.tenant_webauthn_ceremonies AS ceremony
  SET result_snapshot = jsonb_set(
    ceremony.result_snapshot,'{sessionVersion}','0'::jsonb,false
  )
  FROM ONLY public.audit_events AS audit
  WHERE ceremony.state = 'completed'
    AND ceremony.purpose = 'primary_authentication'
    AND audit.id = (ceremony.result_snapshot ->> 'auditId')::uuid
    AND audit.tenant_id = ceremony.tenant_id
    AND audit.action = 'mfa.passkey_clone_suspected'
    AND audit.resource_type = 'webauthn_credential'
    AND ceremony.result_snapshot #>> '{credential,status}' =
        'clone_suspected'
    AND ceremony.result_snapshot ->> 'mutation' = 'revoke'
    AND NOT (ceremony.result_snapshot ? 'newSessionId')
    AND NOT (ceremony.result_snapshot ? 'newSessionFamilyId')
    AND NOT (ceremony.result_snapshot ? 'consumedContinuationId')
    AND NOT (ceremony.result_snapshot ? 'revokedAnchorId')
    AND jsonb_typeof(ceremony.result_snapshot -> 'sessionVersion') = 'number'
    AND (ceremony.result_snapshot ->> 'sessionVersion')::bigint = 1;

  IF EXISTS (
    SELECT 1
    FROM ONLY public.tenant_webauthn_ceremonies AS ceremony
    JOIN ONLY public.audit_events AS audit
      ON audit.id = (ceremony.result_snapshot ->> 'auditId')::uuid
     AND audit.tenant_id = ceremony.tenant_id
     AND audit.action = 'mfa.passkey_clone_suspected'
     AND audit.resource_type = 'webauthn_credential'
    WHERE ceremony.state = 'completed'
      AND ceremony.purpose = 'primary_authentication'
      AND (ceremony.result_snapshot #>> '{credential,status}'
             IS DISTINCT FROM 'clone_suspected'
        OR ceremony.result_snapshot ->> 'mutation' IS DISTINCT FROM 'revoke'
        OR ceremony.result_snapshot ? 'newSessionId'
        OR ceremony.result_snapshot ? 'newSessionFamilyId'
        OR ceremony.result_snapshot ? 'consumedContinuationId'
        OR ceremony.result_snapshot ? 'revokedAnchorId'
        OR jsonb_typeof(ceremony.result_snapshot -> 'sessionVersion')
             IS DISTINCT FROM 'number'
        OR (ceremony.result_snapshot ->> 'sessionVersion')::bigint <> 0)
  ) THEN
    RAISE EXCEPTION 'pre-v35 primary clone replay result is malformed'
      USING ERRCODE = '55000';
  END IF;

  -- v34 did not persist the verified userVerified bit and over-promoted every
  -- WebAuthn evidence row.  Downgrade historical rows conservatively at
  -- cutover; an exact replay is then a true zero-write return.
  IF EXISTS (
    SELECT 1
    FROM ONLY public.tenant_webauthn_ceremonies AS ceremony
    JOIN ONLY public.audit_events AS audit
      ON audit.id = (ceremony.result_snapshot ->> 'auditId')::uuid
     AND audit.tenant_id = ceremony.tenant_id
     AND audit.resource_type = 'webauthn_credential'
    WHERE ceremony.state = 'completed'
      AND ceremony.purpose IN (
        'primary_authentication','continuation_authentication',
        'step_up_authentication'
      )
      AND ceremony.result_snapshot ? 'newSessionId'
      AND (
        SELECT count(*)
        FROM ONLY public.auth_session_mfa_evidence AS evidence
        WHERE evidence.tenant_id = ceremony.tenant_id
          AND evidence.session_id =
              (ceremony.result_snapshot ->> 'newSessionId')::uuid
          AND evidence.webauthn_credential_id = audit.resource_id
          AND evidence.authenticated_at = ceremony.completed_at
      ) <> 1
  ) THEN
    RAISE EXCEPTION
      'pre-v35 WebAuthn session evidence is unavailable or ambiguous'
      USING ERRCODE = '55000';
  END IF;
  UPDATE ONLY public.auth_session_mfa_evidence AS evidence
  SET level = CASE WHEN ceremony.purpose = 'primary_authentication'
    THEN 'primary' ELSE 'mfa' END
  FROM ONLY public.tenant_webauthn_ceremonies AS ceremony
  JOIN ONLY public.audit_events AS audit
    ON audit.id = (ceremony.result_snapshot ->> 'auditId')::uuid
   AND audit.tenant_id = ceremony.tenant_id
   AND audit.resource_type = 'webauthn_credential'
  WHERE ceremony.state = 'completed'
    AND ceremony.purpose IN (
      'primary_authentication','continuation_authentication',
      'step_up_authentication'
    )
    AND ceremony.result_snapshot ? 'newSessionId'
    AND evidence.tenant_id = ceremony.tenant_id
    AND evidence.session_id =
        (ceremony.result_snapshot ->> 'newSessionId')::uuid
    AND evidence.webauthn_credential_id = audit.resource_id
    AND evidence.authenticated_at = ceremony.completed_at;

  -- The legacy completion copied its over-promoted WebAuthn evidence through
  -- later rotations, continuations, and authority anchors.  Those transitive
  -- copies cannot be tied back to the original ceremony's userVerified bit.
  -- Normalize every pre-v35 physical copy conservatively: only the exact
  -- passkey primary remains primary; every other WebAuthn factor is MFA.
  UPDATE ONLY public.auth_session_mfa_evidence AS evidence
  SET level = CASE WHEN EXISTS (
    SELECT 1
    FROM ONLY public.auth_session_passkey_provenance AS provenance
    WHERE provenance.tenant_id = evidence.tenant_id
      AND provenance.session_id = evidence.session_id
      AND provenance.credential_id = evidence.webauthn_credential_id
  ) THEN 'primary' ELSE 'mfa' END
  WHERE evidence.kind = 'webauthn';

  UPDATE ONLY public.tenant_post_primary_continuation_evidence AS evidence
  SET level = CASE WHEN EXISTS (
    SELECT 1
    FROM ONLY public.tenant_post_primary_continuations AS continuation
    WHERE continuation.tenant_id = evidence.tenant_id
      AND continuation.id = evidence.continuation_id
      AND continuation.primary_kind = 'passkey'
      AND continuation.passkey_credential_id =
          evidence.webauthn_credential_id
  ) THEN 'primary' ELSE 'mfa' END
  WHERE evidence.kind = 'webauthn';

  UPDATE ONLY public.tenant_mfa_authority_evidence AS evidence
  SET level = CASE WHEN EXISTS (
    SELECT 1
    FROM ONLY public.tenant_mfa_authority_anchors AS anchor
    LEFT JOIN ONLY public.auth_session_passkey_provenance AS session_primary
      ON anchor.flow = 'session'
     AND session_primary.tenant_id = anchor.tenant_id
     AND session_primary.session_id = anchor.session_id
    LEFT JOIN ONLY public.tenant_post_primary_continuations AS continuation
      ON anchor.flow = 'continuation'
     AND continuation.tenant_id = anchor.tenant_id
     AND continuation.id = anchor.continuation_id
    WHERE anchor.tenant_id = evidence.tenant_id
      AND anchor.id = evidence.anchor_id
      AND (
        session_primary.credential_id = evidence.webauthn_credential_id
        OR (continuation.primary_kind = 'passkey'
          AND continuation.passkey_credential_id =
              evidence.webauthn_credential_id)
      )
  ) THEN 'primary' ELSE 'mfa' END
  WHERE evidence.kind = 'webauthn';

  IF EXISTS (
    SELECT 1
    FROM ONLY public.tenant_webauthn_ceremonies AS ceremony
    WHERE ceremony.state = 'completed'
      AND ceremony.purpose IN (
        'registration','primary_authentication',
        'continuation_authentication','step_up_authentication'
      )
      AND (jsonb_typeof(ceremony.result_snapshot) IS DISTINCT FROM 'object'
        OR jsonb_typeof(
             ceremony.result_snapshot #> '{credential}'
           ) IS DISTINCT FROM 'object'
        OR jsonb_typeof(CASE WHEN ceremony.purpose = 'registration'
             THEN ceremony.result_snapshot #> '{credential,version}'
             ELSE ceremony.result_snapshot #>
               '{credential,credentialVersion}' END
           ) IS DISTINCT FROM 'number'
        OR jsonb_typeof(
             ceremony.result_snapshot #> '{credential,securityRevision}'
           ) IS DISTINCT FROM 'number'
         OR (ceremony.result_snapshot #>>
               '{credential,securityRevision}')::bigint
              NOT BETWEEN 1 AND 9007199254740991
         OR (ceremony.result_snapshot #>>
               '{credential,securityRevision}')::bigint IS DISTINCT FROM
              (CASE WHEN ceremony.purpose = 'registration'
                THEN ceremony.result_snapshot #>> '{credential,version}'
                ELSE ceremony.result_snapshot #>>
                  '{credential,credentialVersion}' END)::bigint)
  ) THEN
    RAISE EXCEPTION 'WebAuthn replay security revision is not sealed'
      USING ERRCODE = '55000';
  END IF;
END;
$passkey_replay_security_revision_upgrade$;
ALTER TABLE public.auth_session_mfa_evidence
  ENABLE TRIGGER auth_session_mfa_evidence_subject_v1;
ALTER TABLE public.tenant_post_primary_continuation_evidence
  ENABLE TRIGGER tenant_continuation_evidence_subject_v1;
ALTER TABLE public.tenant_mfa_authority_evidence
  ENABLE TRIGGER tenant_mfa_authority_evidence_subject_v1;
DO $passkey_evidence_subject_triggers_enabled$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM pg_catalog.pg_trigger AS trigger
    WHERE trigger.tgname IN (
      'auth_session_mfa_evidence_subject_v1',
      'tenant_continuation_evidence_subject_v1',
      'tenant_mfa_authority_evidence_subject_v1'
    )
      AND trigger.tgenabled <> 'O'
  ) THEN
    RAISE EXCEPTION 'MFA evidence subject trigger was not restored'
      USING ERRCODE = '55000';
  END IF;
END;
$passkey_evidence_subject_triggers_enabled$;
ALTER TABLE public.tenant_post_primary_continuations
  ENABLE TRIGGER tenant_post_primary_continuations_federated_provenance_v1;
--> statement-breakpoint

-- A v34 authentication body writes its terminal snapshot before the v35 outer
-- wrapper seals securityRevision.  Re-read the final row at deferred time so
-- the two writes may occur in one transaction, while any old body that resumes
-- after cutover and never performs the seal is rolled back at commit.
CREATE FUNCTION app.validate_webauthn_completed_security_snapshot_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_ceremony public.tenant_webauthn_ceremonies%ROWTYPE;
  v_record_version bigint;
  v_security_revision bigint;
BEGIN
  SELECT ceremony.* INTO v_ceremony
  FROM ONLY public.tenant_webauthn_ceremonies AS ceremony
  WHERE ceremony.id = NEW.id;
  IF NOT FOUND OR v_ceremony.state <> 'completed' THEN RETURN NULL; END IF;
  IF jsonb_typeof(v_ceremony.result_snapshot) IS DISTINCT FROM 'object'
     OR jsonb_typeof(
          v_ceremony.result_snapshot #> '{credential}'
        ) IS DISTINCT FROM 'object'
     OR jsonb_typeof(CASE WHEN v_ceremony.purpose = 'registration'
       THEN v_ceremony.result_snapshot #> '{credential,version}'
       ELSE v_ceremony.result_snapshot #>
         '{credential,credentialVersion}' END) IS DISTINCT FROM 'number'
     OR jsonb_typeof(
          v_ceremony.result_snapshot #> '{credential,securityRevision}'
        ) IS DISTINCT FROM 'number' THEN
    RAISE EXCEPTION 'completed WebAuthn security snapshot is unsealed'
      USING ERRCODE = '23514';
  END IF;
  BEGIN
    v_record_version := (CASE WHEN v_ceremony.purpose = 'registration'
      THEN v_ceremony.result_snapshot #>> '{credential,version}'
      ELSE v_ceremony.result_snapshot #>>
        '{credential,credentialVersion}' END)::bigint;
    v_security_revision := (v_ceremony.result_snapshot #>>
      '{credential,securityRevision}')::bigint;
  EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range THEN
    RAISE EXCEPTION 'completed WebAuthn security snapshot is invalid'
      USING ERRCODE = '23514';
  END;
  IF v_record_version IS NULL OR v_security_revision IS NULL
     OR v_record_version NOT BETWEEN 1 AND 9007199254740991
     OR v_security_revision NOT BETWEEN 1 AND v_record_version THEN
    RAISE EXCEPTION 'completed WebAuthn security snapshot is invalid'
      USING ERRCODE = '23514';
  END IF;
  RETURN NULL;
END;
$function$;
CREATE CONSTRAINT TRIGGER tenant_webauthn_ceremonies_security_snapshot_v1
AFTER INSERT OR UPDATE ON public.tenant_webauthn_ceremonies
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION
  app.validate_webauthn_completed_security_snapshot_v1();
--> statement-breakpoint

CREATE FUNCTION app.guard_webauthn_credential_security_revision_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF NEW.security_revision IS DISTINCT FROM OLD.security_revision THEN
    RAISE EXCEPTION 'WebAuthn security revision is managed internally'
      USING ERRCODE = '23514';
  END IF;
  IF NEW.status IS DISTINCT FROM OLD.status
     OR NEW.backup_eligible IS DISTINCT FROM OLD.backup_eligible
     OR NEW.backed_up IS DISTINCT FROM OLD.backed_up THEN
    IF OLD.security_revision >= 9007199254740991 THEN
      RAISE EXCEPTION 'WebAuthn security revision exhausted'
        USING ERRCODE = '22003';
    END IF;
    NEW.security_revision := OLD.security_revision + 1;
  ELSE
    NEW.security_revision := OLD.security_revision;
  END IF;
  RETURN NEW;
END;
$function$;
CREATE TRIGGER tenant_webauthn_credentials_security_revision_v1
BEFORE UPDATE ON public.tenant_webauthn_credentials
FOR EACH ROW EXECUTE FUNCTION
  app.guard_webauthn_credential_security_revision_v1();
--> statement-breakpoint

-- Namespace (1346457933,35) serializes the singleton platform MFA floor.
-- Tenant-scoped policy writers also bump the existing authorization barrier,
-- which is shared by every role/group/membership/user authority mutation.
CREATE FUNCTION app.touch_mfa_policy_authority_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_tenant record;
BEGIN
  IF (TG_OP <> 'INSERT' AND OLD.scope = 'platform_floor')
     OR (TG_OP <> 'DELETE' AND NEW.scope = 'platform_floor') THEN
    PERFORM pg_advisory_xact_lock(1346457933,35);
  END IF;

  FOR v_tenant IN
    SELECT DISTINCT candidate.tenant_id
    FROM (
      SELECT CASE WHEN TG_OP = 'INSERT' THEN NULL ELSE OLD.tenant_id END
        AS tenant_id
      UNION ALL
      SELECT CASE WHEN TG_OP = 'DELETE' THEN NULL ELSE NEW.tenant_id END
    ) AS candidate
    WHERE candidate.tenant_id IS NOT NULL
    ORDER BY candidate.tenant_id
  LOOP
    PERFORM app.bump_tenant_authorization_revision(v_tenant.tenant_id);
  END LOOP;
  RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END;
$function$;
CREATE TRIGGER mfa_policy_revisions_authority_v1
AFTER INSERT OR UPDATE OR DELETE ON public.mfa_policy_revisions
FOR EACH ROW EXECUTE FUNCTION app.touch_mfa_policy_authority_v1();
--> statement-breakpoint

CREATE FUNCTION app.private_mfa_lock_policy_authority_v1(
  p_tenant_id uuid
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF p_tenant_id IS NULL
     OR NOT pg_try_advisory_xact_lock_shared(1346457933,35) THEN
    RAISE EXCEPTION 'MFA platform policy authority is busy'
      USING ERRCODE = '40001';
  END IF;
  PERFORM 1
  FROM ONLY public.tenant_authorization_states AS authorization_state
  WHERE authorization_state.tenant_id = p_tenant_id
    AND authorization_state.initialized_at IS NOT NULL
  FOR SHARE NOWAIT;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'MFA tenant authorization authority is unavailable'
      USING ERRCODE = '40001';
  END IF;
EXCEPTION WHEN lock_not_available THEN
  RAISE EXCEPTION 'MFA tenant authorization authority is busy'
    USING ERRCODE = '40001';
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_mfa_assert_live_continuation_policy_v1(
  p_continuation_id uuid,
  p_evaluated_at timestamptz
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_continuation public.tenant_post_primary_continuations%ROWTYPE;
  v_snapshot jsonb;
  v_stored_pins jsonb;
  v_live_pins jsonb;
  v_policy_count bigint;
BEGIN
  SELECT continuation.* INTO STRICT v_continuation
  FROM ONLY public.tenant_post_primary_continuations AS continuation
  WHERE continuation.id = p_continuation_id;
  v_snapshot := app.private_mfa_policy_snapshot_v1(
    v_continuation.tenant_id,v_continuation.user_id,
    v_continuation.action,p_evaluated_at
  );
  SELECT coalesce(jsonb_agg(jsonb_build_object(
    'policyId',pin.policy_id::text,'revision',pin.policy_revision
  ) ORDER BY pin.policy_id::text,pin.policy_revision),'[]'::jsonb)
    INTO STRICT v_stored_pins
  FROM ONLY public.tenant_post_primary_continuation_policy_pins AS pin
  WHERE pin.tenant_id = v_continuation.tenant_id
    AND pin.continuation_id = v_continuation.id;
  SELECT coalesce(jsonb_agg(jsonb_build_object(
    'policyId',entry.value -> 'policy' ->> 'id',
    'revision',(entry.value -> 'policy' ->> 'revision')::bigint
  ) ORDER BY entry.value -> 'policy' ->> 'id',
      (entry.value -> 'policy' ->> 'revision')::bigint),'[]'::jsonb)
    INTO STRICT v_live_pins
  FROM jsonb_array_elements(v_snapshot -> 'policies') AS entry(value);
  IF v_stored_pins IS DISTINCT FROM v_live_pins THEN
    RAISE EXCEPTION 'MFA continuation policy authority drifted'
      USING ERRCODE = '40001';
  END IF;
  SELECT count(*) INTO STRICT v_policy_count
  FROM (
    SELECT policy.id
    FROM ONLY public.mfa_policy_revisions AS policy
    JOIN jsonb_array_elements(v_snapshot -> 'policies') AS entry(value)
      ON policy.id = (entry.value -> 'policy' ->> 'id')::uuid
     AND policy.revision =
         (entry.value -> 'policy' ->> 'revision')::bigint
    FOR SHARE OF policy NOWAIT
  ) AS locked_policy;
  IF v_policy_count <> jsonb_array_length(v_snapshot -> 'policies') THEN
    RAISE EXCEPTION 'MFA continuation policy authority drifted'
      USING ERRCODE = '40001';
  END IF;
EXCEPTION WHEN lock_not_available THEN
  RAISE EXCEPTION 'MFA continuation policy authority is busy'
    USING ERRCODE = '40001';
WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
  RAISE EXCEPTION 'MFA continuation policy authority is unavailable'
    USING ERRCODE = '40001';
END;
$function$;
--> statement-breakpoint

-- Validate every baseline local factor captured in an authority anchor.  The
-- factor being completed may be excluded because its WebAuthn backup-state
-- transition is proven separately by the terminal record-version CAS.
CREATE FUNCTION app.private_mfa_assert_live_passkey_anchor_evidence_v1(
  p_anchor_id uuid,
  p_authority_at timestamptz,
  p_transition_kind text DEFAULT NULL,
  p_transition_id uuid DEFAULT NULL
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_anchor public.tenant_mfa_authority_anchors%ROWTYPE;
  v_evidence_count bigint;
BEGIN
  SELECT anchor.* INTO STRICT v_anchor
  FROM ONLY public.tenant_mfa_authority_anchors AS anchor
  WHERE anchor.id = p_anchor_id;
  SELECT count(*) INTO STRICT v_evidence_count
  FROM (
    SELECT evidence.id
    FROM ONLY public.tenant_mfa_authority_evidence AS evidence
    WHERE evidence.tenant_id = v_anchor.tenant_id
      AND evidence.anchor_id = v_anchor.id
    FOR SHARE NOWAIT
  ) AS locked_evidence;
  IF v_evidence_count NOT BETWEEN 1 AND 1024 THEN
    RAISE EXCEPTION 'passkey authority evidence is unavailable or ambiguous'
      USING ERRCODE = '40001';
  END IF;

  PERFORM factor.id
  FROM ONLY public.tenant_mfa_authority_evidence AS evidence
  JOIN ONLY public.local_break_glass_credentials AS factor
    ON factor.id = evidence.local_credential_id
   AND factor.user_id = v_anchor.user_id
  WHERE evidence.tenant_id = v_anchor.tenant_id
    AND evidence.anchor_id = v_anchor.id
    AND evidence.local_credential_id IS NOT NULL
    AND NOT coalesce(p_transition_kind = 'local_credential'
      AND evidence.local_credential_id = p_transition_id,false)
  FOR SHARE OF factor NOWAIT;
  PERFORM factor.id
  FROM ONLY public.tenant_mfa_authority_evidence AS evidence
  JOIN ONLY public.tenant_totp_factors AS factor
    ON factor.tenant_id = evidence.tenant_id
   AND factor.user_id = v_anchor.user_id
   AND factor.id = evidence.totp_factor_id
  WHERE evidence.tenant_id = v_anchor.tenant_id
    AND evidence.anchor_id = v_anchor.id
    AND evidence.totp_factor_id IS NOT NULL
    AND NOT coalesce(p_transition_kind = 'totp'
      AND evidence.totp_factor_id = p_transition_id,false)
  FOR SHARE OF factor NOWAIT;
  PERFORM credential.id
  FROM ONLY public.tenant_mfa_authority_evidence AS evidence
  JOIN ONLY public.tenant_webauthn_credentials AS credential
    ON credential.tenant_id = evidence.tenant_id
   AND credential.user_id = v_anchor.user_id
   AND credential.id = evidence.webauthn_credential_id
  WHERE evidence.tenant_id = v_anchor.tenant_id
    AND evidence.anchor_id = v_anchor.id
    AND evidence.webauthn_credential_id IS NOT NULL
    AND NOT coalesce(p_transition_kind = 'webauthn'
      AND evidence.webauthn_credential_id = p_transition_id,false)
  FOR SHARE OF credential NOWAIT;
  PERFORM code_set.id
  FROM ONLY public.tenant_mfa_authority_evidence AS evidence
  JOIN ONLY public.tenant_recovery_code_sets AS code_set
    ON code_set.tenant_id = evidence.tenant_id
   AND code_set.user_id = v_anchor.user_id
   AND code_set.id = evidence.recovery_code_set_id
  WHERE evidence.tenant_id = v_anchor.tenant_id
    AND evidence.anchor_id = v_anchor.id
    AND evidence.recovery_code_set_id IS NOT NULL
    AND NOT coalesce(p_transition_kind = 'recovery'
      AND evidence.recovery_code_set_id = p_transition_id,false)
  FOR SHARE OF code_set NOWAIT;

  IF EXISTS (
    SELECT 1
    FROM ONLY public.tenant_mfa_authority_evidence AS evidence
    WHERE evidence.tenant_id = v_anchor.tenant_id
      AND evidence.anchor_id = v_anchor.id
      AND (
        (evidence.expires_at IS NOT NULL
          AND evidence.expires_at <= p_authority_at)
        OR (NOT coalesce((
              (p_transition_kind = 'local_credential'
                AND evidence.local_credential_id = p_transition_id)
              OR (p_transition_kind = 'totp'
                AND evidence.totp_factor_id = p_transition_id)
              OR (p_transition_kind = 'webauthn'
                AND evidence.webauthn_credential_id = p_transition_id)
              OR (p_transition_kind = 'recovery'
                AND evidence.recovery_code_set_id = p_transition_id)
            ),false) AND NOT (
              (evidence.kind = 'local_credential' AND EXISTS (
                SELECT 1
                FROM ONLY public.local_break_glass_credentials AS factor
                WHERE factor.id = evidence.local_credential_id
                  AND factor.user_id = v_anchor.user_id
                  AND factor.disabled_at IS NULL
                  AND factor.password_version = evidence.factor_revision
              ))
              OR (evidence.kind = 'totp' AND EXISTS (
                SELECT 1
                FROM ONLY public.tenant_totp_factors AS factor
                WHERE factor.tenant_id = evidence.tenant_id
                  AND factor.user_id = v_anchor.user_id
                  AND factor.id = evidence.totp_factor_id
                  AND factor.status = 'active'
                  AND factor.security_revision = evidence.factor_revision
              ))
              OR (evidence.kind = 'webauthn' AND EXISTS (
                SELECT 1
                FROM ONLY public.tenant_webauthn_credentials AS credential
                WHERE credential.tenant_id = evidence.tenant_id
                  AND credential.user_id = v_anchor.user_id
                  AND credential.id = evidence.webauthn_credential_id
                  AND credential.status = 'active'
                  AND credential.security_revision = evidence.factor_revision
              ))
              OR (evidence.kind = 'recovery' AND EXISTS (
                SELECT 1
                FROM ONLY public.tenant_recovery_code_sets AS code_set
                WHERE code_set.tenant_id = evidence.tenant_id
                  AND code_set.user_id = v_anchor.user_id
                  AND code_set.id = evidence.recovery_code_set_id
                  AND code_set.status = 'active'
                  AND code_set.security_revision = evidence.factor_revision
              ))
            ))
      )
  ) THEN
    RAISE EXCEPTION 'passkey authority factor evidence drifted'
      USING ERRCODE = '40001';
  END IF;
EXCEPTION WHEN lock_not_available THEN
  RAISE EXCEPTION 'passkey authority factor evidence is busy'
    USING ERRCODE = '40001';
WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
  RAISE EXCEPTION 'passkey authority evidence is unavailable'
    USING ERRCODE = '40001';
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_mfa_assert_live_passkey_session_evidence_v1(
  p_tenant_id uuid,
  p_user_id uuid,
  p_session_id uuid,
  p_authority_at timestamptz
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_evidence_count bigint;
BEGIN
  SELECT count(*) INTO STRICT v_evidence_count
  FROM (
    SELECT evidence.id
    FROM ONLY public.auth_session_mfa_evidence AS evidence
    WHERE evidence.tenant_id = p_tenant_id
      AND evidence.session_id = p_session_id
    FOR SHARE NOWAIT
  ) AS locked_evidence;
  IF v_evidence_count NOT BETWEEN 1 AND 1024 THEN
    RAISE EXCEPTION 'passkey session evidence is unavailable or ambiguous'
      USING ERRCODE = '40001';
  END IF;

  PERFORM factor.id
  FROM ONLY public.auth_session_mfa_evidence AS evidence
  JOIN ONLY public.local_break_glass_credentials AS factor
    ON factor.id = evidence.local_credential_id AND factor.user_id = p_user_id
  WHERE evidence.tenant_id = p_tenant_id
    AND evidence.session_id = p_session_id
    AND evidence.local_credential_id IS NOT NULL
  FOR SHARE OF factor NOWAIT;
  PERFORM factor.id
  FROM ONLY public.auth_session_mfa_evidence AS evidence
  JOIN ONLY public.tenant_totp_factors AS factor
    ON factor.tenant_id = evidence.tenant_id
   AND factor.user_id = p_user_id AND factor.id = evidence.totp_factor_id
  WHERE evidence.tenant_id = p_tenant_id
    AND evidence.session_id = p_session_id
    AND evidence.totp_factor_id IS NOT NULL
  FOR SHARE OF factor NOWAIT;
  PERFORM credential.id
  FROM ONLY public.auth_session_mfa_evidence AS evidence
  JOIN ONLY public.tenant_webauthn_credentials AS credential
    ON credential.tenant_id = evidence.tenant_id
   AND credential.user_id = p_user_id
   AND credential.id = evidence.webauthn_credential_id
  WHERE evidence.tenant_id = p_tenant_id
    AND evidence.session_id = p_session_id
    AND evidence.webauthn_credential_id IS NOT NULL
  FOR SHARE OF credential NOWAIT;
  PERFORM code_set.id
  FROM ONLY public.auth_session_mfa_evidence AS evidence
  JOIN ONLY public.tenant_recovery_code_sets AS code_set
    ON code_set.tenant_id = evidence.tenant_id
   AND code_set.user_id = p_user_id
   AND code_set.id = evidence.recovery_code_set_id
  WHERE evidence.tenant_id = p_tenant_id
    AND evidence.session_id = p_session_id
    AND evidence.recovery_code_set_id IS NOT NULL
  FOR SHARE OF code_set NOWAIT;

  IF EXISTS (
    SELECT 1
    FROM ONLY public.auth_session_mfa_evidence AS evidence
    WHERE evidence.tenant_id = p_tenant_id
      AND evidence.session_id = p_session_id
      AND ((evidence.expires_at IS NOT NULL
            AND evidence.expires_at <= p_authority_at)
        OR NOT (
          (evidence.kind = 'local_credential' AND EXISTS (
            SELECT 1 FROM ONLY public.local_break_glass_credentials AS factor
            WHERE factor.id = evidence.local_credential_id
              AND factor.user_id = p_user_id
              AND factor.disabled_at IS NULL
              AND factor.password_version = evidence.factor_revision
          ))
          OR (evidence.kind = 'totp' AND EXISTS (
            SELECT 1 FROM ONLY public.tenant_totp_factors AS factor
            WHERE factor.tenant_id = evidence.tenant_id
              AND factor.user_id = p_user_id
              AND factor.id = evidence.totp_factor_id
              AND factor.status = 'active'
              AND factor.security_revision = evidence.factor_revision
          ))
          OR (evidence.kind = 'webauthn' AND EXISTS (
            SELECT 1 FROM ONLY public.tenant_webauthn_credentials AS credential
            WHERE credential.tenant_id = evidence.tenant_id
              AND credential.user_id = p_user_id
              AND credential.id = evidence.webauthn_credential_id
              AND credential.status = 'active'
              AND credential.security_revision = evidence.factor_revision
          ))
          OR (evidence.kind = 'recovery' AND EXISTS (
            SELECT 1 FROM ONLY public.tenant_recovery_code_sets AS code_set
            WHERE code_set.tenant_id = evidence.tenant_id
              AND code_set.user_id = p_user_id
              AND code_set.id = evidence.recovery_code_set_id
              AND code_set.status = 'active'
              AND code_set.security_revision = evidence.factor_revision
          ))
        ))
  ) THEN
    RAISE EXCEPTION 'passkey session factor evidence drifted'
      USING ERRCODE = '40001';
  END IF;
EXCEPTION WHEN lock_not_available THEN
  RAISE EXCEPTION 'passkey session factor evidence is busy'
    USING ERRCODE = '40001';
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_mfa_assert_live_passkey_continuation_evidence_v1(
  p_tenant_id uuid,
  p_user_id uuid,
  p_continuation_id uuid,
  p_authority_at timestamptz
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_evidence_count bigint;
BEGIN
  SELECT count(*) INTO STRICT v_evidence_count
  FROM (
    SELECT evidence.id
    FROM ONLY public.tenant_post_primary_continuation_evidence AS evidence
    WHERE evidence.tenant_id = p_tenant_id
      AND evidence.continuation_id = p_continuation_id
    FOR SHARE NOWAIT
  ) AS locked_evidence;
  IF v_evidence_count NOT BETWEEN 1 AND 1024 THEN
    RAISE EXCEPTION
      'passkey continuation evidence is unavailable or ambiguous'
      USING ERRCODE = '40001';
  END IF;

  PERFORM factor.id
  FROM ONLY public.tenant_post_primary_continuation_evidence AS evidence
  JOIN ONLY public.local_break_glass_credentials AS factor
    ON factor.id = evidence.local_credential_id AND factor.user_id = p_user_id
  WHERE evidence.tenant_id = p_tenant_id
    AND evidence.continuation_id = p_continuation_id
    AND evidence.local_credential_id IS NOT NULL
  FOR SHARE OF factor NOWAIT;
  PERFORM factor.id
  FROM ONLY public.tenant_post_primary_continuation_evidence AS evidence
  JOIN ONLY public.tenant_totp_factors AS factor
    ON factor.tenant_id = evidence.tenant_id
   AND factor.user_id = p_user_id AND factor.id = evidence.totp_factor_id
  WHERE evidence.tenant_id = p_tenant_id
    AND evidence.continuation_id = p_continuation_id
    AND evidence.totp_factor_id IS NOT NULL
  FOR SHARE OF factor NOWAIT;
  PERFORM credential.id
  FROM ONLY public.tenant_post_primary_continuation_evidence AS evidence
  JOIN ONLY public.tenant_webauthn_credentials AS credential
    ON credential.tenant_id = evidence.tenant_id
   AND credential.user_id = p_user_id
   AND credential.id = evidence.webauthn_credential_id
  WHERE evidence.tenant_id = p_tenant_id
    AND evidence.continuation_id = p_continuation_id
    AND evidence.webauthn_credential_id IS NOT NULL
  FOR SHARE OF credential NOWAIT;
  PERFORM code_set.id
  FROM ONLY public.tenant_post_primary_continuation_evidence AS evidence
  JOIN ONLY public.tenant_recovery_code_sets AS code_set
    ON code_set.tenant_id = evidence.tenant_id
   AND code_set.user_id = p_user_id
   AND code_set.id = evidence.recovery_code_set_id
  WHERE evidence.tenant_id = p_tenant_id
    AND evidence.continuation_id = p_continuation_id
    AND evidence.recovery_code_set_id IS NOT NULL
  FOR SHARE OF code_set NOWAIT;

  IF EXISTS (
    SELECT 1
    FROM ONLY public.tenant_post_primary_continuation_evidence AS evidence
    WHERE evidence.tenant_id = p_tenant_id
      AND evidence.continuation_id = p_continuation_id
      AND ((evidence.expires_at IS NOT NULL
            AND evidence.expires_at <= p_authority_at)
        OR NOT (
          (evidence.kind = 'local_credential' AND EXISTS (
            SELECT 1 FROM ONLY public.local_break_glass_credentials AS factor
            WHERE factor.id = evidence.local_credential_id
              AND factor.user_id = p_user_id
              AND factor.disabled_at IS NULL
              AND factor.password_version = evidence.factor_revision
          ))
          OR (evidence.kind = 'totp' AND EXISTS (
            SELECT 1 FROM ONLY public.tenant_totp_factors AS factor
            WHERE factor.tenant_id = evidence.tenant_id
              AND factor.user_id = p_user_id
              AND factor.id = evidence.totp_factor_id
              AND factor.status = 'active'
              AND factor.security_revision = evidence.factor_revision
          ))
          OR (evidence.kind = 'webauthn' AND EXISTS (
            SELECT 1 FROM ONLY public.tenant_webauthn_credentials AS credential
            WHERE credential.tenant_id = evidence.tenant_id
              AND credential.user_id = p_user_id
              AND credential.id = evidence.webauthn_credential_id
              AND credential.status = 'active'
              AND credential.security_revision = evidence.factor_revision
          ))
          OR (evidence.kind = 'recovery' AND EXISTS (
            SELECT 1 FROM ONLY public.tenant_recovery_code_sets AS code_set
            WHERE code_set.tenant_id = evidence.tenant_id
              AND code_set.user_id = p_user_id
              AND code_set.id = evidence.recovery_code_set_id
              AND code_set.status = 'active'
              AND code_set.security_revision = evidence.factor_revision
          ))
        ))
  ) THEN
    RAISE EXCEPTION 'passkey continuation factor evidence drifted'
      USING ERRCODE = '40001';
  END IF;
EXCEPTION WHEN lock_not_available THEN
  RAISE EXCEPTION 'passkey continuation factor evidence is busy'
    USING ERRCODE = '40001';
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_mfa_lock_live_passkey_session_v1(
  p_tenant_id uuid,
  p_user_id uuid,
  p_session_id uuid,
  p_family_id uuid,
  p_session_version bigint,
  p_identity_epoch bigint,
  p_anchor_expires_at timestamptz,
  p_audience text,
  p_authority_at timestamptz
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF p_session_version >= 9007199254740991 THEN
    RAISE EXCEPTION 'passkey session has no successor headroom'
      USING ERRCODE = '40001';
  END IF;
  PERFORM app.private_mfa_lock_policy_authority_v1(p_tenant_id);
  PERFORM 1
  FROM ONLY public.auth_sessions AS session
  JOIN ONLY public.auth_session_mfa_states AS state
    ON state.tenant_id = p_tenant_id
   AND state.session_id = session.id
   AND state.user_id = p_user_id
   AND state.primary_kind = 'passkey'
   AND state.session_version = p_session_version
   AND state.identity_epoch = p_identity_epoch
   AND state.audience = p_audience
  JOIN ONLY public.auth_session_passkey_provenance AS provenance
    ON provenance.tenant_id = state.tenant_id
   AND provenance.session_id = state.session_id
   AND provenance.user_id = state.user_id
   AND provenance.primary_kind = 'passkey'
  JOIN ONLY public.tenant_mfa_subjects AS subject
    ON subject.tenant_id = state.tenant_id
   AND subject.user_id = state.user_id
   AND subject.identity_epoch = state.identity_epoch
   AND subject.session_invalidation_epoch = state.session_invalidation_epoch
  JOIN ONLY public.users AS local_user
    ON local_user.id = state.user_id AND local_user.active
  JOIN ONLY public.tenants AS tenant
    ON tenant.id = state.tenant_id AND tenant.status = 'active'
  JOIN ONLY public.tenant_memberships AS membership
    ON membership.tenant_id = state.tenant_id
   AND membership.user_id = state.user_id
   AND membership.status = 'active'
  JOIN ONLY public.tenant_webauthn_credentials AS credential
    ON credential.tenant_id = provenance.tenant_id
   AND credential.user_id = provenance.user_id
   AND credential.id = provenance.credential_id
   AND credential.status = 'active'
   AND credential.security_revision = provenance.credential_revision
  WHERE session.id = p_session_id
    AND session.user_id = p_user_id
    AND session.active_tenant_id = p_tenant_id
    AND session.rotation_family_id = p_family_id
    AND session.authentication_method = 'passkey'
    AND session.revoked_at IS NULL
    AND least(session.idle_expires_at,session.absolute_expires_at) =
        p_anchor_expires_at
    AND session.idle_expires_at > p_authority_at
    AND session.absolute_expires_at > p_authority_at
  FOR UPDATE OF session,state NOWAIT
  FOR SHARE OF provenance,subject,local_user,tenant,membership,credential NOWAIT;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'passkey session authority is stale'
      USING ERRCODE = '40001';
  END IF;
  PERFORM app.private_mfa_assert_live_passkey_session_evidence_v1(
    p_tenant_id,p_user_id,p_session_id,p_authority_at
  );
EXCEPTION WHEN lock_not_available THEN
  RAISE EXCEPTION 'passkey session authority is busy'
    USING ERRCODE = '40001';
END;
$function$;
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.private_webauthn_credential_projection_v1(
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
  FROM ONLY public.tenant_webauthn_credentials AS credential
  WHERE credential.id = p_credential_id;
  SELECT subject.identity_epoch INTO STRICT v_identity_epoch
  FROM ONLY public.tenant_mfa_subjects AS subject
  WHERE subject.tenant_id = v_credential.tenant_id
    AND subject.user_id = v_credential.user_id;
  SELECT coalesce(
    jsonb_agg(transport.transport ORDER BY transport.transport),'[]'::jsonb
  ) INTO STRICT v_transports
  FROM ONLY public.tenant_webauthn_credential_transports AS transport
  WHERE transport.tenant_id = v_credential.tenant_id
    AND transport.credential_id = v_credential.id;
  RETURN jsonb_build_object(
    'id',replace(encode(v_credential.credential_id,'base64'),E'\n',''),
    'publicKey',replace(encode(v_credential.public_key,'base64'),E'\n',''),
    'tenantId',v_credential.tenant_id::text,
    'userId',v_credential.user_id::text,
    'identityEpoch',v_identity_epoch,
    'userHandleDigest',replace(
      encode(v_credential.user_handle_digest,'base64'),E'\n',''
    ),
    'rpId',v_credential.rp_id,'rpRevision',v_credential.rp_revision,
    'version',v_credential.version,
    'securityRevision',v_credential.security_revision,
    'status',v_credential.status,'signCount',v_credential.sign_count,
    'discoverable',v_credential.discoverable,
    'userVerification',v_credential.user_verification,
    'backupEligible',v_credential.backup_eligible,
    'backedUp',v_credential.backed_up,'transports',v_transports
  );
END;
$function$;
--> statement-breakpoint

-- Extend the identity-key retirement inventory across the tenant-admitted
-- platform-provider runtime.  The table locks make the dependency snapshot
-- coherent with the V2 verifier's install/retire transaction: a concurrent
-- subject admission or PKCE transaction cannot appear between this inventory
-- and the keyring compare-and-swap.
CREATE OR REPLACE FUNCTION app.verify_identity_keyring_v3(
  p_versions integer[],
  p_verifiers bytea[],
  p_active_version integer
)
RETURNS boolean
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  -- Dependency relations precede the referenced keyring.  Every dependency
  -- INSERT takes its own RowExclusive lock before its FK key-share, so taking
  -- the keyring first here would permit the inverse-lock deadlock.
  BEGIN
    LOCK TABLE public.tenant_ldap_directory_operation_runs,
      public.tenant_ldap_provider_secrets,
      public.tenant_ldap_external_identities,
      public.tenant_ldap_external_identity_subject_aliases,
      public.platform_oidc_client_secrets,
      public.platform_saml_sp_keys,
      public.platform_federated_external_identities,
      public.platform_federated_external_identity_aliases,
      public.tenant_platform_oidc_authentication_transactions
      IN SHARE MODE NOWAIT;
  EXCEPTION WHEN lock_not_available THEN
    -- A writer may already hold an earlier dependency and later need another
    -- relation in this inventory.  Fail closed instead of waiting into an
    -- inverse-lock cycle; the subtransaction releases every partial lock.
    RETURN false;
  END;
  LOCK TABLE public.identity_keyring_versions IN EXCLUSIVE MODE;

  IF EXISTS (
    SELECT 1
    FROM public.tenant_ldap_directory_operation_runs AS operation
    LEFT JOIN public.identity_keyring_versions AS keyring
      ON keyring.key_version = operation.bind_secret_key_version
    WHERE operation.status = 'started'
      AND operation.expires_at > transaction_timestamp()
      AND (
        keyring.key_version IS NULL
        OR keyring.retired_at IS NOT NULL
        OR NOT operation.bind_secret_key_version = ANY(p_versions)
      )
  ) OR EXISTS (
    SELECT 1
    FROM ONLY public.platform_oidc_client_secrets AS secret
    WHERE secret.retired_at IS NULL
      AND NOT secret.key_version = ANY(p_versions)
  ) OR EXISTS (
    SELECT 1
    FROM ONLY public.platform_saml_sp_keys AS sp_key
    WHERE sp_key.retired_at IS NULL
      AND NOT sp_key.key_version = ANY(p_versions)
  ) OR EXISTS (
    SELECT 1
    FROM ONLY public.platform_federated_external_identities AS identity
    WHERE identity.retired_at IS NULL
      AND NOT identity.key_version = ANY(p_versions)
  ) OR EXISTS (
    SELECT 1
    FROM ONLY public.platform_federated_external_identities AS identity
    WHERE NOT EXISTS (
      -- Live aliases and collision tombstones are both part of the subject
      -- namespace.  One retained-key alias per identity is sufficient; an
      -- omitted historical alias may then be retired without making the
      -- upstream subject re-creatable after that key is removed.
      SELECT 1
      FROM ONLY public.platform_federated_external_identity_aliases AS alias
      WHERE alias.platform_provider_id = identity.platform_provider_id
        AND alias.external_identity_id = identity.id
        AND alias.key_version = ANY(p_versions)
        AND (identity.retired_at IS NOT NULL OR alias.retired_at IS NULL)
    )
  ) OR EXISTS (
    SELECT 1
    FROM ONLY public.tenant_platform_oidc_authentication_transactions AS transaction
    WHERE transaction.state IN ('pending','claimed')
      AND transaction.expires_at > transaction_timestamp()
      AND NOT transaction.verifier_key_version = ANY(p_versions)
  ) THEN
    RETURN false;
  END IF;

  RETURN app.verify_identity_keyring_v2(
    p_versions, p_verifiers, p_active_version
  );
END;
$function$;
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.assert_auth_session_mfa_provenance_v1(
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
  tenant_provider_count integer;
  platform_provider_count integer;
  session_revoked boolean;
  session_authentication_method text;
BEGIN
  SELECT state.* INTO state_record
  FROM public.auth_session_mfa_states AS state
  JOIN public.auth_sessions AS session
    ON session.id = state.session_id
   AND session.user_id = state.user_id
   AND session.active_tenant_id = state.tenant_id
  WHERE state.tenant_id = p_tenant_id AND state.session_id = p_session_id;
  IF NOT FOUND THEN RETURN; END IF;
  SELECT session.revoked_at IS NOT NULL,session.authentication_method
    INTO STRICT session_revoked,session_authentication_method
  FROM public.auth_sessions AS session
  WHERE session.id = p_session_id
    AND session.user_id = state_record.user_id
    AND session.active_tenant_id = p_tenant_id;

  SELECT count(*)::integer INTO local_count
  FROM public.auth_session_local_credential_provenance AS provenance
  JOIN public.local_break_glass_credentials AS credential
    ON credential.id = provenance.credential_id
   AND credential.user_id = provenance.user_id
   AND credential.password_version::bigint = provenance.credential_revision
  WHERE provenance.tenant_id = p_tenant_id
    AND provenance.session_id = p_session_id
    AND provenance.user_id = state_record.user_id;

  SELECT count(*)::integer INTO passkey_count
  FROM public.auth_session_passkey_provenance AS provenance
  JOIN public.tenant_webauthn_credentials AS credential
    ON credential.tenant_id = provenance.tenant_id
   AND credential.user_id = provenance.user_id
   AND credential.id = provenance.credential_id
   AND (session_revoked OR (
     credential.status = 'active'
     AND credential.security_revision = provenance.credential_revision
   ))
  WHERE provenance.tenant_id = p_tenant_id
    AND provenance.session_id = p_session_id
    AND provenance.user_id = state_record.user_id;

  SELECT count(*)::integer INTO tenant_provider_count
  FROM public.auth_session_federated_provenance AS provenance
  JOIN public.tenant_federated_external_identities AS identity
    ON identity.tenant_id = provenance.tenant_id
   AND identity.provider_id = provenance.provider_id
   AND identity.binding_id = provenance.binding_id
   AND identity.id = provenance.external_identity_id
   AND identity.user_id = provenance.user_id
   AND identity.version = provenance.external_identity_revision
   AND identity.retired_at IS NULL
  JOIN public.tenant_federated_provider_policies AS policy
    ON policy.tenant_id = provenance.tenant_id
   AND policy.provider_id = provenance.provider_id
   AND policy.binding_id = provenance.binding_id
   AND policy.provider_kind = provenance.provider_kind
   AND policy.security_revision = provenance.trust_rule_revision
   AND policy.enabled
  WHERE provenance.tenant_id = p_tenant_id
    AND provenance.session_id = p_session_id
    AND provenance.user_id = state_record.user_id;

  SELECT count(*)::integer INTO platform_provider_count
  FROM public.auth_session_tenant_platform_federated_provenance AS provenance
  JOIN public.auth_sessions AS session
    ON session.id = provenance.session_id
   AND session.user_id = provenance.user_id
   AND session.active_tenant_id = provenance.tenant_id
  JOIN public.platform_federated_external_identities AS identity
    ON identity.platform_provider_id = provenance.platform_provider_id
   AND identity.id = provenance.external_identity_id
   AND identity.user_id = provenance.user_id
   AND identity.version = provenance.external_identity_revision
   AND identity.retired_at IS NULL
  JOIN public.tenant_platform_auth_provider_bindings AS binding
    ON binding.tenant_id = provenance.tenant_id
   AND binding.id = provenance.binding_id
   AND binding.platform_provider_id = provenance.platform_provider_id
   AND binding.current_access_epoch_id = provenance.access_epoch_id
   AND binding.enabled AND binding.archived_at IS NULL
  JOIN public.platform_auth_providers AS provider
    ON provider.id = provenance.platform_provider_id
   AND provider.kind = 'oidc' AND provider.enabled
   AND provider.archived_at IS NULL
  JOIN public.platform_federated_provider_policies AS policy
    ON policy.provider_id = provenance.platform_provider_id
   AND policy.provider_kind = 'oidc' AND policy.enabled
   AND NOT policy.platform_login_enabled
   AND policy.security_revision = provenance.security_revision
  JOIN public.tenant_platform_federated_provider_access_grants AS grant_record
    ON grant_record.tenant_id = provenance.tenant_id
   AND grant_record.id = provenance.access_grant_id
   AND grant_record.binding_id = provenance.binding_id
   AND grant_record.access_epoch_id = provenance.access_epoch_id
   AND grant_record.source_id = provenance.access_source_id
   AND grant_record.external_identity_id = provenance.external_identity_id
   AND grant_record.membership_id = provenance.membership_id
   AND grant_record.user_id = provenance.user_id
   AND grant_record.ended_at IS NULL
  WHERE provenance.tenant_id = p_tenant_id
    AND provenance.session_id = p_session_id
    AND provenance.user_id = state_record.user_id;

  IF (state_record.primary_kind = 'local_credential'
      AND ROW(local_count, passkey_count, tenant_provider_count,
              platform_provider_count) IS DISTINCT FROM ROW(1, 0, 0, 0))
     OR (state_record.primary_kind = 'passkey'
      AND ROW(local_count, passkey_count, tenant_provider_count,
              platform_provider_count) IS DISTINCT FROM ROW(0, 1, 0, 0))
     OR (state_record.primary_kind = 'tenant_provider'
      AND ROW(local_count, passkey_count, tenant_provider_count,
              platform_provider_count) IS DISTINCT FROM ROW(0, 0, 1, 0))
     OR (state_record.primary_kind = 'tenant_platform_provider'
      AND ROW(local_count, passkey_count, tenant_provider_count,
              platform_provider_count) IS DISTINCT FROM ROW(0, 0, 0, 1))
     OR (NOT session_revoked AND (
       (state_record.primary_kind = 'local_credential'
         AND session_authentication_method NOT IN (
           'bootstrap_totp','totp','recovery_code'
         ))
       OR (state_record.primary_kind = 'passkey'
         AND session_authentication_method <> 'passkey')
       OR (state_record.primary_kind = 'tenant_provider'
         AND NOT EXISTS (
           SELECT 1
           FROM ONLY public.auth_session_federated_provenance AS provenance
           WHERE provenance.tenant_id = p_tenant_id
             AND provenance.session_id = p_session_id
             AND provenance.user_id = state_record.user_id
             AND provenance.authentication_method =
                 session_authentication_method
             AND provenance.authentication_method IN ('oidc','saml')
         ))
       OR (state_record.primary_kind = 'tenant_platform_provider'
         AND session_authentication_method <> 'oidc')
     )) THEN
    RAISE EXCEPTION 'auth session has invalid typed primary provenance'
      USING ERRCODE = '23514';
  END IF;
END;
$function$;

CREATE CONSTRAINT TRIGGER auth_session_tenant_platform_federated_provenance_parent_v1
AFTER INSERT OR UPDATE OR DELETE
ON public.auth_session_tenant_platform_federated_provenance
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION app.enforce_auth_session_mfa_provenance_v1();
--> statement-breakpoint

CREATE FUNCTION app.validate_tenant_platform_continuation_provenance_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF NEW.primary_kind = 'tenant_platform_provider' AND NOT EXISTS (
    SELECT 1
    FROM ONLY public.platform_federated_external_identities AS identity
    JOIN ONLY public.tenants AS tenant
      ON tenant.id = NEW.tenant_id AND tenant.status = 'active'
    JOIN ONLY public.platform_auth_providers AS provider
      ON provider.id = identity.platform_provider_id
     AND provider.kind = 'oidc' AND provider.enabled
     AND provider.archived_at IS NULL
    JOIN ONLY public.platform_federated_provider_policies AS policy
      ON policy.provider_id = provider.id AND policy.provider_kind = 'oidc'
     AND policy.enabled AND NOT policy.platform_login_enabled
    JOIN ONLY public.tenant_platform_auth_provider_bindings AS binding
      ON binding.tenant_id = NEW.tenant_id
     AND binding.id = NEW.binding_id
     AND binding.platform_provider_id = identity.platform_provider_id
     AND binding.enabled AND binding.archived_at IS NULL
     AND binding.current_access_epoch_id IS NOT NULL
    JOIN ONLY public.tenant_mfa_subjects AS subject
      ON subject.tenant_id = NEW.tenant_id
     AND subject.user_id = identity.user_id
     AND subject.identity_epoch = NEW.identity_epoch
     AND subject.session_invalidation_epoch = NEW.session_invalidation_epoch
    JOIN ONLY public.tenant_memberships AS membership
      ON membership.tenant_id = NEW.tenant_id
     AND membership.user_id = identity.user_id
     AND membership.status = 'active'
    JOIN ONLY public.tenant_platform_federated_provider_access_grants AS access_grant
      ON access_grant.tenant_id = NEW.tenant_id
     AND access_grant.platform_provider_id = identity.platform_provider_id
     AND access_grant.binding_id = binding.id
     AND access_grant.access_epoch_id = binding.current_access_epoch_id
     AND access_grant.external_identity_id = identity.id
     AND access_grant.membership_id = membership.id
     AND access_grant.user_id = identity.user_id
     AND access_grant.started_at <= transaction_timestamp()
     AND access_grant.ended_at IS NULL
    JOIN ONLY public.tenant_platform_identity_provider_access_epochs AS access_epoch
      ON access_epoch.tenant_id = access_grant.tenant_id
     AND access_epoch.id = access_grant.access_epoch_id
     AND access_epoch.binding_id = access_grant.binding_id
     AND access_epoch.platform_provider_id = access_grant.platform_provider_id
     AND access_epoch.source_id = access_grant.source_id
     AND access_epoch.started_at <= transaction_timestamp()
     AND access_epoch.ended_at IS NULL
    JOIN ONLY public.tenant_authorization_sources AS access_source
      ON access_source.tenant_id = access_grant.tenant_id
     AND access_source.id = access_grant.source_id
     AND access_source.kind = 'identity_provider_access'
     AND access_source.authoritative AND NOT access_source.protected
     AND access_source.key = format(
       'identity_provider_access:%s:%s', access_epoch.binding_id,
       access_epoch.sequence
     )
     AND access_source.retired_at IS NULL
    WHERE identity.platform_provider_id = NEW.platform_provider_id
      AND identity.id = NEW.external_identity_id
      AND identity.user_id = NEW.user_id
      AND identity.version = NEW.primary_revision
      AND identity.retired_at IS NULL
  ) THEN
    RAISE EXCEPTION 'continuation has invalid tenant platform primary provenance'
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$function$;
CREATE TRIGGER tenant_post_primary_continuations_platform_provenance_v1
BEFORE INSERT OR UPDATE ON public.tenant_post_primary_continuations
FOR EACH ROW EXECUTE FUNCTION app.validate_tenant_platform_continuation_provenance_v1();
--> statement-breakpoint

CREATE FUNCTION app.guard_platform_federated_external_identity_v1()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'platform federated identities are archival records'
      USING ERRCODE = '55000';
  END IF;
  IF TG_OP = 'INSERT' THEN
    IF NEW.version <> 1 OR NEW.retired_at IS NOT NULL
       OR NEW.created_at IS DISTINCT FROM transaction_timestamp()
       OR NEW.updated_at IS DISTINCT FROM transaction_timestamp()
       OR NEW.last_observed_at IS DISTINCT FROM transaction_timestamp() THEN
      RAISE EXCEPTION 'platform federated identity create envelope is invalid'
        USING ERRCODE = '23514';
    END IF;
  ELSE
    IF ROW(NEW.id, NEW.platform_provider_id, NEW.provider_kind, NEW.user_id,
           NEW.subject_format, NEW.subject_ciphertext, NEW.subject_nonce,
           NEW.key_version, NEW.admitted_configuration_revision,
           NEW.admitted_security_revision, NEW.created_at)
       IS DISTINCT FROM
       ROW(OLD.id, OLD.platform_provider_id, OLD.provider_kind, OLD.user_id,
           OLD.subject_format, OLD.subject_ciphertext, OLD.subject_nonce,
           OLD.key_version, OLD.admitted_configuration_revision,
           OLD.admitted_security_revision, OLD.created_at)
       OR NEW.updated_at IS DISTINCT FROM transaction_timestamp()
       OR NEW.last_observed_at IS DISTINCT FROM transaction_timestamp()
       OR NEW.last_observed_at < OLD.last_observed_at
       OR (
         NEW.version <> OLD.version + 1
         AND NOT (
           OLD.retired_at IS NULL
           AND NEW.retired_at IS NULL
           AND NEW.version = OLD.version
         )
       )
       OR (OLD.retired_at IS NOT NULL AND NEW.retired_at IS DISTINCT FROM OLD.retired_at)
       OR (NEW.retired_at IS NOT NULL
         AND NEW.retired_at IS DISTINCT FROM transaction_timestamp()) THEN
      RAISE EXCEPTION 'platform federated identity transition is invalid'
        USING ERRCODE = '23514';
    END IF;
  END IF;
  RETURN NEW;
END;
$function$;
CREATE TRIGGER platform_federated_external_identities_guard_v1
BEFORE INSERT OR UPDATE OR DELETE ON public.platform_federated_external_identities
FOR EACH ROW EXECUTE FUNCTION app.guard_platform_federated_external_identity_v1();

CREATE FUNCTION app.guard_platform_federated_alias_v1()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'platform federated aliases are archival records'
      USING ERRCODE = '55000';
  END IF;
  IF TG_OP = 'INSERT' THEN
    IF NEW.retired_at IS NOT NULL
       OR NEW.created_at IS DISTINCT FROM transaction_timestamp() THEN
      RAISE EXCEPTION 'platform federated alias create envelope is invalid'
        USING ERRCODE = '23514';
    END IF;
  ELSIF ROW(NEW.id, NEW.platform_provider_id, NEW.external_identity_id,
            NEW.key_version, NEW.subject_digest, NEW.created_at)
        IS DISTINCT FROM
        ROW(OLD.id, OLD.platform_provider_id, OLD.external_identity_id,
            OLD.key_version, OLD.subject_digest, OLD.created_at)
     OR OLD.retired_at IS NOT NULL
     OR NEW.retired_at IS DISTINCT FROM transaction_timestamp() THEN
    RAISE EXCEPTION 'platform federated alias transition is invalid'
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$function$;
CREATE TRIGGER platform_federated_external_identity_aliases_guard_v1
BEFORE INSERT OR UPDATE OR DELETE
ON public.platform_federated_external_identity_aliases
FOR EACH ROW EXECUTE FUNCTION app.guard_platform_federated_alias_v1();

CREATE FUNCTION app.guard_tenant_platform_oidc_transaction_v1()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'tenant platform OIDC transactions are retention records'
      USING ERRCODE = '55000';
  END IF;
  IF TG_OP = 'INSERT' THEN
    IF NEW.state <> 'pending' OR NEW.version <> 1
       OR NEW.claim_attempt_id IS NOT NULL OR NEW.claimed_at IS NOT NULL
       OR NEW.completed_at IS NOT NULL OR NEW.failure_reason IS NOT NULL THEN
      RAISE EXCEPTION 'tenant platform OIDC transaction create is invalid'
        USING ERRCODE = '23514';
    END IF;
  ELSE
    IF ROW(NEW.transaction_id, NEW.tenant_id, NEW.platform_provider_id,
           NEW.binding_id, NEW.provider_kind, NEW.protocol,
           NEW.access_epoch_id, NEW.access_source_id, NEW.operation_run_id,
           NEW.operation_digest, NEW.receipt_digest, NEW.network_digest,
           NEW.account_digest, NEW.provider_digest, NEW.state_digest,
           NEW.browser_digest, NEW.nonce_digest, NEW.provider_revision,
           NEW.binding_revision, NEW.configuration_revision,
           NEW.security_revision, NEW.plan_revision, NEW.mapping_revision,
           NEW.authorization_revision, NEW.assurance_policy_revision,
           NEW.client_secret_revision, NEW.discovery_revision,
           NEW.discovery_digest, NEW.jwks_revision, NEW.jwks_digest,
           NEW.verifier_key_version, NEW.verifier_ciphertext, NEW.client_id,
           NEW.tenant_redirect_uri, NEW.post_logout_redirect_uri, NEW.scopes,
           NEW.allow_refresh_token, NEW.use_user_info, NEW.return_path,
           NEW.created_at, NEW.expires_at)
       IS DISTINCT FROM
       ROW(OLD.transaction_id, OLD.tenant_id, OLD.platform_provider_id,
           OLD.binding_id, OLD.provider_kind, OLD.protocol,
           OLD.access_epoch_id, OLD.access_source_id, OLD.operation_run_id,
           OLD.operation_digest, OLD.receipt_digest, OLD.network_digest,
           OLD.account_digest, OLD.provider_digest, OLD.state_digest,
           OLD.browser_digest, OLD.nonce_digest, OLD.provider_revision,
           OLD.binding_revision, OLD.configuration_revision,
           OLD.security_revision, OLD.plan_revision, OLD.mapping_revision,
           OLD.authorization_revision, OLD.assurance_policy_revision,
           OLD.client_secret_revision, OLD.discovery_revision,
           OLD.discovery_digest, OLD.jwks_revision, OLD.jwks_digest,
           OLD.verifier_key_version, OLD.verifier_ciphertext, OLD.client_id,
           OLD.tenant_redirect_uri, OLD.post_logout_redirect_uri, OLD.scopes,
           OLD.allow_refresh_token, OLD.use_user_info, OLD.return_path,
           OLD.created_at, OLD.expires_at)
       OR NEW.version <> OLD.version + 1
       OR NOT (
         (OLD.state = 'pending' AND NEW.state IN ('claimed', 'expired', 'failed'))
         OR (OLD.state = 'claimed'
           AND NEW.state IN ('completed', 'expired', 'failed'))
       ) THEN
      RAISE EXCEPTION 'tenant platform OIDC transaction transition is invalid'
        USING ERRCODE = '23514';
    END IF;
  END IF;
  RETURN NEW;
END;
$function$;
CREATE TRIGGER tenant_platform_oidc_authentication_transactions_guard_v1
BEFORE INSERT OR UPDATE OR DELETE
ON public.tenant_platform_oidc_authentication_transactions
FOR EACH ROW EXECUTE FUNCTION app.guard_tenant_platform_oidc_transaction_v1();

CREATE FUNCTION app.guard_tenant_platform_runtime_immutable_v1()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  RAISE EXCEPTION 'tenant platform runtime receipt is immutable'
    USING ERRCODE = '55000';
END;
$function$;
CREATE TRIGGER tenant_platform_oidc_authentication_applications_immutable_v1
BEFORE UPDATE OR DELETE ON public.tenant_platform_oidc_authentication_applications
FOR EACH ROW EXECUTE FUNCTION app.guard_tenant_platform_runtime_immutable_v1();
CREATE TRIGGER auth_session_tenant_platform_federated_provenance_immutable_v1
BEFORE UPDATE OR DELETE ON public.auth_session_tenant_platform_federated_provenance
FOR EACH ROW EXECUTE FUNCTION app.guard_tenant_platform_runtime_immutable_v1();
CREATE TRIGGER auth_session_tenant_platform_federated_evidence_immutable_v1
BEFORE UPDATE OR DELETE ON public.auth_session_tenant_platform_federated_evidence
FOR EACH ROW EXECUTE FUNCTION app.guard_tenant_platform_runtime_immutable_v1();
CREATE TRIGGER tenant_mfa_authority_platform_federated_evidence_immutable_v1
BEFORE UPDATE OR DELETE
ON public.tenant_mfa_authority_platform_federated_evidence
FOR EACH ROW EXECUTE FUNCTION app.guard_tenant_platform_runtime_immutable_v1();
CREATE TRIGGER tenant_post_primary_platform_federated_evidence_immutable_v1
BEFORE UPDATE OR DELETE ON public.tenant_post_primary_platform_federated_evidence
FOR EACH ROW EXECUTE FUNCTION app.guard_tenant_platform_runtime_immutable_v1();
CREATE TRIGGER tenant_post_primary_platform_federated_provenance_immutable_v1
BEFORE UPDATE OR DELETE
ON public.tenant_post_primary_platform_federated_provenance
FOR EACH ROW EXECUTE FUNCTION app.guard_tenant_platform_runtime_immutable_v1();
CREATE TRIGGER tenant_post_primary_federated_provenance_immutable_v1
BEFORE UPDATE OR DELETE
ON public.tenant_post_primary_federated_provenance
FOR EACH ROW EXECUTE FUNCTION app.guard_tenant_platform_runtime_immutable_v1();
CREATE TRIGGER tenant_platform_federated_session_revalidation_commands_immutable_v1
BEFORE UPDATE OR DELETE ON public.tenant_platform_federated_session_revalidation_commands
FOR EACH ROW EXECUTE FUNCTION app.guard_tenant_platform_runtime_immutable_v1();
--> statement-breakpoint

CREATE FUNCTION app.guard_tenant_platform_continuation_child_v1()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF TG_TABLE_NAME = 'tenant_platform_oidc_authentication_applications'
     AND NEW.continuation_id IS NULL THEN
    RETURN NEW;
  END IF;
  IF NOT EXISTS (
    SELECT 1
    FROM ONLY public.tenant_post_primary_continuations AS continuation
    WHERE continuation.tenant_id = NEW.tenant_id
      AND continuation.id = NEW.continuation_id
      AND continuation.user_id = NEW.user_id
      AND continuation.primary_kind = 'tenant_platform_provider'
      AND continuation.platform_provider_id = NEW.platform_provider_id
      AND continuation.binding_id = NEW.binding_id
      AND continuation.external_identity_id = NEW.external_identity_id
  ) THEN
    RAISE EXCEPTION 'tenant platform continuation child has invalid provenance'
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$function$;
CREATE TRIGGER tenant_platform_oidc_applications_continuation_guard_v1
BEFORE INSERT ON public.tenant_platform_oidc_authentication_applications
FOR EACH ROW EXECUTE FUNCTION app.guard_tenant_platform_continuation_child_v1();
CREATE TRIGGER tenant_post_primary_platform_evidence_continuation_guard_v1
BEFORE INSERT ON public.tenant_post_primary_platform_federated_evidence
FOR EACH ROW EXECUTE FUNCTION app.guard_tenant_platform_continuation_child_v1();
--> statement-breakpoint

CREATE FUNCTION app.validate_tenant_platform_continuation_authority_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM ONLY public.tenant_post_primary_continuations AS continuation
    JOIN ONLY public.tenant_platform_federated_provider_access_grants AS access_grant
      ON access_grant.tenant_id = NEW.tenant_id
     AND access_grant.id = NEW.access_grant_id
     AND access_grant.platform_provider_id = NEW.platform_provider_id
     AND access_grant.binding_id = NEW.binding_id
     AND access_grant.access_epoch_id = NEW.access_epoch_id
     AND access_grant.source_id = NEW.access_source_id
     AND access_grant.external_identity_id = NEW.external_identity_id
     AND access_grant.membership_id = NEW.membership_id
     AND access_grant.user_id = NEW.user_id
    JOIN ONLY public.platform_federated_external_identities AS identity
      ON identity.platform_provider_id = NEW.platform_provider_id
     AND identity.id = NEW.external_identity_id
     AND identity.user_id = NEW.user_id
     AND identity.version = NEW.external_identity_revision
    WHERE continuation.tenant_id = NEW.tenant_id
      AND continuation.id = NEW.continuation_id
      AND continuation.user_id = NEW.user_id
      AND continuation.primary_kind = 'tenant_platform_provider'
      AND continuation.platform_provider_id = NEW.platform_provider_id
      AND continuation.binding_id = NEW.binding_id
      AND continuation.external_identity_id = NEW.external_identity_id
      AND continuation.primary_revision = NEW.external_identity_revision
  ) THEN
    RAISE EXCEPTION 'tenant platform continuation provenance is inconsistent'
      USING ERRCODE = '23514';
  END IF;

  IF NEW.origin = 'session_revalidation' AND NOT EXISTS (
    SELECT 1
    FROM ONLY public.auth_sessions AS session
    JOIN ONLY public.auth_session_mfa_states AS state
      ON state.tenant_id = NEW.tenant_id
     AND state.session_id = session.id AND state.user_id = NEW.user_id
     AND state.primary_kind = 'tenant_platform_provider'
     AND state.session_version = NEW.source_session_version
    JOIN ONLY public.auth_session_tenant_platform_federated_provenance AS provenance
      ON provenance.tenant_id = NEW.tenant_id
     AND provenance.session_id = session.id AND provenance.user_id = NEW.user_id
     AND ROW(provenance.platform_provider_id,provenance.binding_id,
       provenance.access_epoch_id,provenance.access_source_id,
       provenance.access_grant_id,provenance.membership_id,
       provenance.external_identity_id,provenance.external_identity_revision,
       provenance.provider_revision,provenance.binding_revision,
       provenance.security_revision,provenance.mapping_revision,
       provenance.authorization_revision,provenance.subject_alias_key_version,
       provenance.trust_rule_revision,provenance.authenticated_at)
       IS NOT DISTINCT FROM ROW(NEW.platform_provider_id,NEW.binding_id,
       NEW.access_epoch_id,NEW.access_source_id,NEW.access_grant_id,
       NEW.membership_id,NEW.external_identity_id,NEW.external_identity_revision,
       NEW.provider_revision,NEW.binding_revision,NEW.security_revision,
       NEW.mapping_revision,NEW.authorization_revision,
       NEW.subject_alias_key_version,NEW.trust_rule_revision,
       NEW.authenticated_at)
    WHERE session.id = NEW.source_session_id AND session.user_id = NEW.user_id
      AND session.active_tenant_id = NEW.tenant_id
      AND session.rotation_family_id = NEW.source_session_family_id
      AND session.absolute_expires_at = NEW.source_absolute_expires_at
      AND session.revoked_at IS NULL
  ) THEN
    RAISE EXCEPTION 'tenant platform revalidation origin is inconsistent'
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$function$;
CREATE TRIGGER tenant_post_primary_platform_federated_provenance_guard_v1
BEFORE INSERT ON public.tenant_post_primary_platform_federated_provenance
FOR EACH ROW EXECUTE FUNCTION
  app.validate_tenant_platform_continuation_authority_v1();
--> statement-breakpoint

-- Tenant-owned OIDC/SAML continuations predate a normalized access receipt.
-- Bind every newly-issued parent to the exact epoch/source/grant and revision
-- tuple captured by the v35 wrapper; current-row lookups alone would allow a
-- deactivate/reactivate cycle to revive an old continuation.
CREATE FUNCTION app.validate_tenant_federated_continuation_authority_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM ONLY public.tenant_post_primary_continuations AS continuation
    JOIN ONLY public.tenant_auth_providers AS provider
      ON provider.tenant_id = NEW.tenant_id
     AND provider.id = NEW.provider_id
     AND provider.kind = NEW.provider_kind
     AND provider.enabled AND provider.archived_at IS NULL
     AND provider.version = NEW.provider_revision
    JOIN ONLY public.tenant_auth_provider_bindings AS binding
      ON binding.tenant_id = NEW.tenant_id
     AND binding.id = NEW.binding_id
     AND binding.provider_id = NEW.provider_id
     AND binding.enabled AND binding.archived_at IS NULL
     AND binding.version = NEW.binding_revision
     AND binding.mapping_revision = NEW.mapping_revision
     AND binding.auth_revision = NEW.authorization_revision
     AND binding.current_access_epoch_id = NEW.access_epoch_id
    JOIN ONLY public.tenant_federated_provider_policies AS policy
      ON policy.tenant_id = NEW.tenant_id
     AND policy.provider_id = NEW.provider_id
     AND policy.binding_id = NEW.binding_id
     AND policy.provider_kind = NEW.provider_kind
     AND policy.enabled
     AND policy.configuration_revision = NEW.configuration_revision
     AND policy.security_revision = NEW.security_revision
     AND policy.plan_revision = NEW.plan_revision
     AND policy.assurance_policy_revision = NEW.assurance_policy_revision
    JOIN ONLY public.tenant_identity_provider_access_epochs AS epoch
      ON epoch.tenant_id = NEW.tenant_id
     AND epoch.id = NEW.access_epoch_id
     AND epoch.binding_id = NEW.binding_id
     AND epoch.provider_id = NEW.provider_id
     AND epoch.source_id = NEW.access_source_id
     AND epoch.ended_at IS NULL
    JOIN ONLY public.tenant_authorization_sources AS source
      ON source.tenant_id = NEW.tenant_id
     AND source.id = NEW.access_source_id
     AND source.kind = 'identity_provider_access'
     AND source.authoritative AND NOT source.protected
     AND source.key = format(
       'identity_provider_access:%s:%s',epoch.binding_id,epoch.sequence
     )
     AND source.retired_at IS NULL
    JOIN ONLY public.tenant_federated_provider_access_grants AS access_grant
      ON access_grant.tenant_id = NEW.tenant_id
     AND access_grant.id = NEW.access_grant_id
     AND access_grant.provider_id = NEW.provider_id
     AND access_grant.binding_id = NEW.binding_id
     AND access_grant.access_epoch_id = NEW.access_epoch_id
     AND access_grant.source_id = NEW.access_source_id
     AND access_grant.external_identity_id = NEW.external_identity_id
     AND access_grant.membership_id = NEW.membership_id
     AND access_grant.user_id = NEW.user_id
     AND access_grant.ended_at IS NULL
    JOIN ONLY public.tenant_memberships AS membership
      ON membership.tenant_id = NEW.tenant_id
     AND membership.id = NEW.membership_id
     AND membership.user_id = NEW.user_id
     AND membership.status = 'active'
    JOIN ONLY public.tenant_federated_external_identities AS identity
      ON identity.tenant_id = NEW.tenant_id
     AND identity.provider_id = NEW.provider_id
     AND identity.binding_id = NEW.binding_id
     AND identity.id = NEW.external_identity_id
     AND identity.user_id = NEW.user_id
     AND identity.version = NEW.external_identity_revision
     AND identity.retired_at IS NULL
    WHERE continuation.tenant_id = NEW.tenant_id
      AND continuation.id = NEW.continuation_id
      AND continuation.user_id = NEW.user_id
      AND continuation.primary_kind = 'tenant_provider'
      AND continuation.provider_id = NEW.provider_id
      AND continuation.binding_id = NEW.binding_id
      AND continuation.provider_kind = NEW.provider_kind
      AND continuation.external_identity_id = NEW.external_identity_id
      AND continuation.primary_revision = NEW.external_identity_revision
      AND NEW.primary_kind = 'tenant_provider'
      AND NEW.authentication_method = NEW.provider_kind::text
  ) THEN
    RAISE EXCEPTION 'tenant-provider continuation provenance is inconsistent'
      USING ERRCODE = '23514';
  END IF;
  IF NEW.origin = 'session_revalidation' AND NOT EXISTS (
    SELECT 1
    FROM ONLY public.auth_sessions AS source_session
    JOIN ONLY public.auth_session_mfa_states AS source_state
      ON source_state.tenant_id = NEW.tenant_id
     AND source_state.session_id = source_session.id
     AND source_state.user_id = NEW.user_id
     AND source_state.primary_kind = 'tenant_provider'
     AND source_state.session_version = NEW.source_session_version
    JOIN ONLY public.auth_session_federated_provenance AS source_provenance
      ON source_provenance.tenant_id = NEW.tenant_id
     AND source_provenance.session_id = source_session.id
     AND source_provenance.user_id = NEW.user_id
     AND source_provenance.primary_kind = 'tenant_provider'
     AND source_provenance.authentication_method = NEW.authentication_method
     AND source_provenance.provider_id = NEW.provider_id
     AND source_provenance.binding_id = NEW.binding_id
     AND source_provenance.provider_kind = NEW.provider_kind
     AND source_provenance.external_identity_id = NEW.external_identity_id
     AND source_provenance.external_identity_revision =
         NEW.external_identity_revision
     AND source_provenance.trust_rule_revision = NEW.security_revision
     AND source_provenance.authenticated_at = NEW.authenticated_at
    WHERE source_session.id = NEW.source_session_id
      AND source_session.user_id = NEW.user_id
      AND source_session.active_tenant_id = NEW.tenant_id
      AND source_session.rotation_family_id = NEW.source_session_family_id
      AND source_session.absolute_expires_at = NEW.source_absolute_expires_at
      AND source_session.revoked_at IS NULL
  ) THEN
    RAISE EXCEPTION 'tenant-provider revalidation origin is inconsistent'
      USING ERRCODE = '23514';
  ELSIF NEW.origin = 'initial_login' AND (
    NEW.source_session_id IS NOT NULL
    OR NEW.source_session_family_id IS NOT NULL
    OR NEW.source_session_version IS NOT NULL
    OR NEW.source_absolute_expires_at IS NOT NULL
  ) THEN
    RAISE EXCEPTION 'tenant-provider initial origin is inconsistent'
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$function$;
CREATE TRIGGER tenant_post_primary_federated_provenance_guard_v1
BEFORE INSERT ON public.tenant_post_primary_federated_provenance
FOR EACH ROW EXECUTE FUNCTION
  app.validate_tenant_federated_continuation_authority_v1();
--> statement-breakpoint

CREATE FUNCTION app.enforce_tenant_federated_continuation_provenance_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_tenant_id uuid;
  v_continuation_id uuid;
  v_primary_kind text;
  v_state text;
  v_child_count integer;
BEGIN
  IF TG_TABLE_NAME = 'tenant_post_primary_continuations' THEN
    v_tenant_id := coalesce(NEW.tenant_id,OLD.tenant_id);
    v_continuation_id := coalesce(NEW.id,OLD.id);
  ELSE
    v_tenant_id := coalesce(NEW.tenant_id,OLD.tenant_id);
    v_continuation_id := coalesce(NEW.continuation_id,OLD.continuation_id);
  END IF;
  SELECT continuation.primary_kind,continuation.state
    INTO v_primary_kind,v_state
  FROM ONLY public.tenant_post_primary_continuations AS continuation
  WHERE continuation.tenant_id = v_tenant_id
    AND continuation.id = v_continuation_id;
  SELECT count(*)::integer INTO v_child_count
  FROM ONLY public.tenant_post_primary_federated_provenance AS provenance
  WHERE provenance.tenant_id = v_tenant_id
    AND provenance.continuation_id = v_continuation_id;
  IF (v_primary_kind = 'tenant_provider'
       AND (v_state = 'pending' OR v_child_count > 0)
       AND v_child_count <> 1)
     OR (v_primary_kind IS DISTINCT FROM 'tenant_provider'
       AND v_child_count <> 0) THEN
    RAISE EXCEPTION 'tenant-provider continuation requires exact provenance'
      USING ERRCODE = '23514';
  END IF;
  RETURN NULL;
END;
$function$;
CREATE CONSTRAINT TRIGGER tenant_post_primary_continuations_federated_child_v1
AFTER INSERT OR UPDATE ON public.tenant_post_primary_continuations
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION
  app.enforce_tenant_federated_continuation_provenance_v1();
CREATE CONSTRAINT TRIGGER tenant_post_primary_federated_provenance_parent_v1
AFTER INSERT OR UPDATE OR DELETE
ON public.tenant_post_primary_federated_provenance
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION
  app.enforce_tenant_federated_continuation_provenance_v1();
--> statement-breakpoint

-- Passkey continuations use their own closed provenance child.  The parent FK
-- binds the credential identifier physically; this guard pins the revision,
-- authentication discriminator and (for revalidation) the exact source
-- session authority which existed after the step-up command CAS.
CREATE FUNCTION app.validate_tenant_passkey_continuation_authority_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM ONLY public.tenant_post_primary_continuations AS continuation
    JOIN ONLY public.tenant_mfa_subjects AS subject
      ON subject.tenant_id = continuation.tenant_id
     AND subject.user_id = continuation.user_id
     AND subject.identity_epoch = continuation.identity_epoch
     AND subject.session_invalidation_epoch =
         continuation.session_invalidation_epoch
    JOIN ONLY public.tenants AS tenant
      ON tenant.id = continuation.tenant_id AND tenant.status = 'active'
    JOIN ONLY public.users AS local_user
      ON local_user.id = continuation.user_id AND local_user.active
    JOIN ONLY public.tenant_memberships AS membership
      ON membership.tenant_id = continuation.tenant_id
     AND membership.user_id = continuation.user_id
     AND membership.status = 'active'
    JOIN ONLY public.tenant_webauthn_credentials AS credential
      ON credential.tenant_id = continuation.tenant_id
     AND credential.user_id = continuation.user_id
     AND credential.id = continuation.passkey_credential_id
     AND credential.security_revision = continuation.primary_revision
     AND credential.status = 'active'
    WHERE continuation.tenant_id = NEW.tenant_id
      AND continuation.id = NEW.continuation_id
      AND continuation.user_id = NEW.user_id
      AND continuation.primary_kind = 'passkey'
      AND continuation.passkey_credential_id = NEW.credential_id
      AND continuation.primary_revision = NEW.credential_revision
      AND continuation.state = 'pending'
      AND continuation.version = 1
      AND continuation.expires_at > transaction_timestamp()
      AND NEW.primary_kind = 'passkey'
      AND NEW.authentication_method = 'passkey'
      AND NEW.authenticated_at <= continuation.created_at
  ) THEN
    RAISE EXCEPTION 'passkey continuation provenance is inconsistent'
      USING ERRCODE = '23514';
  END IF;

  IF NEW.origin = 'session_revalidation' AND NOT EXISTS (
    SELECT 1
    FROM ONLY public.auth_sessions AS source_session
    JOIN ONLY public.auth_session_mfa_states AS source_state
      ON source_state.tenant_id = NEW.tenant_id
     AND source_state.session_id = source_session.id
     AND source_state.user_id = NEW.user_id
     AND source_state.primary_kind = 'passkey'
     AND source_state.session_version = NEW.source_session_version
    JOIN ONLY public.auth_session_passkey_provenance AS source_provenance
      ON source_provenance.tenant_id = source_state.tenant_id
     AND source_provenance.session_id = source_state.session_id
     AND source_provenance.user_id = source_state.user_id
     AND source_provenance.primary_kind = 'passkey'
     AND source_provenance.credential_id = NEW.credential_id
     AND source_provenance.credential_revision = NEW.credential_revision
     AND source_provenance.authenticated_at = NEW.authenticated_at
    WHERE source_session.id = NEW.source_session_id
      AND source_session.user_id = NEW.user_id
      AND source_session.active_tenant_id = NEW.tenant_id
      AND source_session.rotation_family_id = NEW.source_session_family_id
      AND source_session.authentication_method = 'passkey'
      AND source_session.absolute_expires_at =
          NEW.source_absolute_expires_at
      AND source_session.revoked_at IS NULL
      AND source_session.idle_expires_at > transaction_timestamp()
      AND source_session.absolute_expires_at > transaction_timestamp()
  ) THEN
    RAISE EXCEPTION 'passkey revalidation origin is inconsistent'
      USING ERRCODE = '23514';
  ELSIF NEW.origin = 'initial_login' AND (
    NEW.source_session_id IS NOT NULL
    OR NEW.source_session_family_id IS NOT NULL
    OR NEW.source_session_version IS NOT NULL
    OR NEW.source_absolute_expires_at IS NOT NULL
  ) THEN
    RAISE EXCEPTION 'passkey initial origin is inconsistent'
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$function$;
CREATE TRIGGER tenant_post_primary_passkey_provenance_guard_v1
BEFORE INSERT ON public.tenant_post_primary_passkey_provenance
FOR EACH ROW EXECUTE FUNCTION
  app.validate_tenant_passkey_continuation_authority_v1();
CREATE TRIGGER tenant_post_primary_passkey_provenance_immutable_v1
BEFORE UPDATE OR DELETE ON public.tenant_post_primary_passkey_provenance
FOR EACH ROW EXECUTE FUNCTION app.guard_tenant_platform_runtime_immutable_v1();
--> statement-breakpoint

CREATE FUNCTION app.enforce_tenant_passkey_continuation_provenance_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_tenant_id uuid;
  v_continuation_id uuid;
  v_primary_kind text;
  v_state text;
  v_child_count integer;
BEGIN
  IF TG_TABLE_NAME = 'tenant_post_primary_continuations' THEN
    v_tenant_id := coalesce(NEW.tenant_id,OLD.tenant_id);
    v_continuation_id := coalesce(NEW.id,OLD.id);
  ELSE
    v_tenant_id := coalesce(NEW.tenant_id,OLD.tenant_id);
    v_continuation_id := coalesce(NEW.continuation_id,OLD.continuation_id);
  END IF;
  SELECT continuation.primary_kind,continuation.state
    INTO v_primary_kind,v_state
  FROM ONLY public.tenant_post_primary_continuations AS continuation
  WHERE continuation.tenant_id = v_tenant_id
    AND continuation.id = v_continuation_id;
  SELECT count(*)::integer INTO v_child_count
  FROM ONLY public.tenant_post_primary_passkey_provenance AS provenance
  WHERE provenance.tenant_id = v_tenant_id
    AND provenance.continuation_id = v_continuation_id;
  IF (v_primary_kind = 'passkey'
       AND (v_state = 'pending' OR v_child_count > 0)
       AND v_child_count <> 1)
     OR (v_primary_kind IS DISTINCT FROM 'passkey'
       AND v_child_count <> 0) THEN
    RAISE EXCEPTION 'passkey continuation requires exact provenance'
      USING ERRCODE = '23514';
  END IF;
  RETURN NULL;
END;
$function$;
CREATE CONSTRAINT TRIGGER tenant_post_primary_continuations_passkey_child_v1
AFTER INSERT OR UPDATE ON public.tenant_post_primary_continuations
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION
  app.enforce_tenant_passkey_continuation_provenance_v1();
CREATE CONSTRAINT TRIGGER tenant_post_primary_passkey_provenance_parent_v1
AFTER INSERT OR UPDATE OR DELETE
ON public.tenant_post_primary_passkey_provenance
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION
  app.enforce_tenant_passkey_continuation_provenance_v1();
--> statement-breakpoint

CREATE FUNCTION app.validate_tenant_platform_mfa_authority_evidence_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM ONLY public.tenant_mfa_authority_anchors AS anchor
    WHERE anchor.tenant_id = NEW.tenant_id AND anchor.id = NEW.anchor_id
      AND anchor.user_id = NEW.user_id
      AND (
        (anchor.flow = 'session' AND EXISTS (
          SELECT 1
          FROM ONLY public.auth_session_tenant_platform_federated_evidence AS evidence
          WHERE evidence.tenant_id = NEW.tenant_id
            AND evidence.session_id = anchor.session_id
            AND evidence.user_id = NEW.user_id
            AND evidence.platform_provider_id = NEW.platform_provider_id
            AND evidence.binding_id = NEW.binding_id
            AND evidence.external_identity_id = NEW.external_identity_id
            AND ROW(evidence.level,evidence.authenticated_at,
              evidence.expires_at,evidence.trust_rule_revision)
              IS NOT DISTINCT FROM ROW(NEW.level,NEW.authenticated_at,
                NEW.expires_at,NEW.trust_rule_revision)
        ))
        OR (anchor.flow = 'continuation' AND EXISTS (
          SELECT 1
          FROM ONLY public.tenant_post_primary_platform_federated_evidence AS evidence
          WHERE evidence.tenant_id = NEW.tenant_id
            AND evidence.continuation_id = anchor.continuation_id
            AND evidence.user_id = NEW.user_id
            AND evidence.platform_provider_id = NEW.platform_provider_id
            AND evidence.binding_id = NEW.binding_id
            AND evidence.external_identity_id = NEW.external_identity_id
            AND ROW(evidence.level,evidence.authenticated_at,
              evidence.expires_at,evidence.trust_rule_revision)
              IS NOT DISTINCT FROM ROW(NEW.level,NEW.authenticated_at,
                NEW.expires_at,NEW.trust_rule_revision)
        ))
      )
  ) THEN
    RAISE EXCEPTION 'tenant platform MFA authority evidence is inconsistent'
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$function$;
CREATE TRIGGER tenant_mfa_authority_platform_federated_evidence_guard_v1
BEFORE INSERT ON public.tenant_mfa_authority_platform_federated_evidence
FOR EACH ROW EXECUTE FUNCTION
  app.validate_tenant_platform_mfa_authority_evidence_v1();
--> statement-breakpoint

CREATE FUNCTION app.copy_tenant_platform_mfa_authority_evidence_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_source_is_platform boolean := false;
  v_inserted_count bigint := 0;
BEGIN
  IF NEW.flow = 'session' THEN
    SELECT count(*) = 1 INTO v_source_is_platform
    FROM ONLY public.auth_session_mfa_states AS state
    WHERE state.tenant_id = NEW.tenant_id AND state.session_id = NEW.session_id
      AND state.user_id = NEW.user_id
      AND state.primary_kind = 'tenant_platform_provider';
    IF v_source_is_platform THEN
      INSERT INTO public.tenant_mfa_authority_platform_federated_evidence (
        id,tenant_id,anchor_id,user_id,platform_provider_id,binding_id,
        external_identity_id,level,authenticated_at,expires_at,
        trust_rule_revision
      ) SELECT uuidv7(),evidence.tenant_id,NEW.id,evidence.user_id,
        evidence.platform_provider_id,evidence.binding_id,
        evidence.external_identity_id,evidence.level,evidence.authenticated_at,
        evidence.expires_at,evidence.trust_rule_revision
      FROM ONLY public.auth_session_tenant_platform_federated_evidence AS evidence
      WHERE evidence.tenant_id = NEW.tenant_id
        AND evidence.session_id = NEW.session_id;
      GET DIAGNOSTICS v_inserted_count = ROW_COUNT;
    END IF;
  ELSIF NEW.flow = 'continuation' THEN
    SELECT count(*) = 1 INTO v_source_is_platform
    FROM ONLY public.tenant_post_primary_continuations AS continuation
    WHERE continuation.tenant_id = NEW.tenant_id
      AND continuation.id = NEW.continuation_id AND continuation.user_id = NEW.user_id
      AND continuation.primary_kind = 'tenant_platform_provider';
    IF v_source_is_platform THEN
      INSERT INTO public.tenant_mfa_authority_platform_federated_evidence (
        id,tenant_id,anchor_id,user_id,platform_provider_id,binding_id,
        external_identity_id,level,authenticated_at,expires_at,
        trust_rule_revision
      ) SELECT uuidv7(),evidence.tenant_id,NEW.id,evidence.user_id,
        evidence.platform_provider_id,evidence.binding_id,
        evidence.external_identity_id,evidence.level,evidence.authenticated_at,
        evidence.expires_at,evidence.trust_rule_revision
      FROM ONLY public.tenant_post_primary_platform_federated_evidence AS evidence
      WHERE evidence.tenant_id = NEW.tenant_id
        AND evidence.continuation_id = NEW.continuation_id;
      GET DIAGNOSTICS v_inserted_count = ROW_COUNT;
    END IF;
  END IF;
  IF v_source_is_platform AND v_inserted_count NOT BETWEEN 1 AND 1024 THEN
    RAISE EXCEPTION 'tenant platform MFA authority evidence snapshot is invalid'
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$function$;
CREATE TRIGGER tenant_mfa_authority_platform_federated_evidence_copy_v1
AFTER INSERT ON public.tenant_mfa_authority_anchors
FOR EACH ROW EXECUTE FUNCTION app.copy_tenant_platform_mfa_authority_evidence_v1();
--> statement-breakpoint

-- A continuation identifier is not bearer proof.  Current MFA artifact
-- creation enters a transaction-local receipt context, and the shared anchor
-- producer consumes that context while locking and matching the live receipt.
-- Session/primary artifacts must never carry continuation proof.
ALTER FUNCTION app.private_mfa_anchor_from_stepup_binding_v1(jsonb,timestamptz)
  RENAME TO private_unbound_mfa_anchor_from_stepup_binding_v1;
--> statement-breakpoint

CREATE FUNCTION app.private_mfa_enter_continuation_receipt_v1(
  p_binding jsonb,
  p_receipt text
)
RETURNS text
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_previous text := current_setting(
    'app.mfa_continuation_receipt_digest',true
  );
  v_receipt bytea;
BEGIN
  IF jsonb_typeof(p_binding) <> 'object' THEN
    RAISE EXCEPTION 'invalid MFA receipt binding' USING ERRCODE = '22023';
  END IF;
  IF p_binding ? 'continuationId' THEN
    IF p_binding ? 'sessionId' OR p_receipt IS NULL OR p_receipt = '' THEN
      RAISE EXCEPTION 'continuation receipt is required'
        USING ERRCODE = '22023';
    END IF;
    v_receipt := app.private_mfa_decode_base64_v1(p_receipt,32,32);
    IF encode(v_receipt,'hex') = repeat('00',32) THEN
      RAISE EXCEPTION 'continuation receipt is invalid'
        USING ERRCODE = '22023';
    END IF;
    PERFORM set_config('app.mfa_continuation_receipt_digest',p_receipt,true);
  ELSE
    IF p_receipt IS NOT NULL THEN
      RAISE EXCEPTION 'continuation receipt is forbidden'
        USING ERRCODE = '22023';
    END IF;
    PERFORM set_config('app.mfa_continuation_receipt_digest','',true);
  END IF;
  RETURN v_previous;
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_mfa_restore_continuation_receipt_v1(p_previous text)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  PERFORM set_config(
    'app.mfa_continuation_receipt_digest',coalesce(p_previous,''),true
  );
END;
$function$;
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.private_mfa_anchor_from_stepup_binding_v1(
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
  v_receipt_text text := nullif(current_setting(
    'app.mfa_continuation_receipt_digest',true
  ),'');
  v_receipt bytea;
  v_continuation_id uuid;
  v_session_id uuid;
  v_primary_kind text;
  v_live_binding jsonb;
  v_authority_at timestamptz := greatest(
    p_created_at,transaction_timestamp()
  );
BEGIN
  IF (p_binding ? 'sessionId' OR p_binding ? 'continuationId')
     AND (p_binding ->> 'anchorVersion')::bigint >= 9007199254740991 THEN
    RAISE EXCEPTION 'MFA authority version has no successor headroom'
      USING ERRCODE = '40001';
  END IF;
  IF p_binding ? 'continuationId' THEN
    v_continuation_id := app.private_mfa_require_uuidv7_v1(
      p_binding ->> 'continuationId'
    );
    IF v_receipt_text IS NULL THEN
      RAISE EXCEPTION 'continuation receipt is required'
        USING ERRCODE = '42501';
    END IF;
    v_receipt := app.private_mfa_decode_base64_v1(v_receipt_text,32,32);
    IF encode(v_receipt,'hex') = repeat('00',32) OR NOT EXISTS (
      SELECT 1
      FROM ONLY public.tenant_post_primary_continuations AS continuation
      WHERE continuation.id = v_continuation_id
        AND continuation.tenant_id = (p_binding ->> 'tenantId')::uuid
        AND continuation.user_id = (p_binding ->> 'userId')::uuid
        AND continuation.receipt_digest = v_receipt
      FOR UPDATE
    ) THEN
      RAISE EXCEPTION 'continuation receipt is unavailable'
        USING ERRCODE = '42501';
    END IF;
    v_live_binding := app.resolve_mfa_authority_v2(
      v_continuation_id,'continuation',p_binding ->> 'action',
      p_binding ->> 'audience',v_authority_at,v_receipt
    );
    PERFORM app.private_mfa_lock_continuation_authority_v1(
      v_continuation_id,v_authority_at
    );
    IF jsonb_build_object(
         'flow',v_live_binding -> 'flow',
         'tenantId',v_live_binding -> 'tenantId',
         'userId',v_live_binding -> 'userId',
         'identityEpoch',v_live_binding -> 'identityEpoch',
         'continuationId',v_live_binding -> 'continuationId',
         'anchorVersion',v_live_binding -> 'anchorVersion',
         'anchorExpiresAt',v_live_binding -> 'anchorExpiresAt',
         'anchorRecoveryRestricted',v_live_binding -> 'anchorRecoveryRestricted',
         'action',v_live_binding -> 'action',
         'audience',v_live_binding -> 'audience',
         'requirement',v_live_binding -> 'requirement',
         'baselineEvidence',v_live_binding -> 'baselineEvidence'
       ) IS DISTINCT FROM p_binding THEN
      RAISE EXCEPTION 'MFA binding drifted from live authority'
        USING ERRCODE = '40001';
    END IF;
  ELSIF p_binding ? 'sessionId' THEN
    IF v_receipt_text IS NOT NULL THEN
      RAISE EXCEPTION 'continuation receipt is forbidden'
        USING ERRCODE = '22023';
    END IF;
    v_session_id := app.private_mfa_require_uuidv7_v1(
      p_binding ->> 'sessionId'
    );
    SELECT state.primary_kind INTO STRICT v_primary_kind
    FROM ONLY public.auth_session_mfa_states AS state
    WHERE state.tenant_id = (p_binding ->> 'tenantId')::uuid
      AND state.session_id = v_session_id
      AND state.user_id = (p_binding ->> 'userId')::uuid
      AND state.session_version = (p_binding ->> 'anchorVersion')::bigint
      AND state.identity_epoch = (p_binding ->> 'identityEpoch')::bigint;
    IF v_primary_kind = 'passkey' THEN
      PERFORM app.private_mfa_lock_live_passkey_session_v1(
        (p_binding ->> 'tenantId')::uuid,
        (p_binding ->> 'userId')::uuid,v_session_id,
        app.private_mfa_require_uuidv7_v1(
          p_binding ->> 'sessionFamilyId'
        ),
        (p_binding ->> 'anchorVersion')::bigint,
        (p_binding ->> 'identityEpoch')::bigint,
        (p_binding ->> 'anchorExpiresAt')::timestamptz,
        p_binding ->> 'audience',v_authority_at
      );
      v_live_binding := app.resolve_mfa_authority_v2(
        v_session_id,'session',p_binding ->> 'action',
        p_binding ->> 'audience',v_authority_at,NULL::bytea
      );
      IF jsonb_build_object(
           'flow',v_live_binding -> 'flow',
           'tenantId',v_live_binding -> 'tenantId',
           'userId',v_live_binding -> 'userId',
           'identityEpoch',v_live_binding -> 'identityEpoch',
           'sessionId',v_live_binding -> 'sessionId',
           'sessionFamilyId',v_live_binding -> 'sessionFamilyId',
           'anchorVersion',v_live_binding -> 'anchorVersion',
           'anchorExpiresAt',v_live_binding -> 'anchorExpiresAt',
           'anchorRecoveryRestricted',
             v_live_binding -> 'anchorRecoveryRestricted',
           'action',v_live_binding -> 'action',
           'audience',v_live_binding -> 'audience',
           'requirement',v_live_binding -> 'requirement',
           'baselineEvidence',v_live_binding -> 'baselineEvidence'
         ) IS DISTINCT FROM p_binding THEN
        RAISE EXCEPTION 'MFA binding drifted from live authority'
          USING ERRCODE = '40001';
      END IF;
    END IF;
  ELSIF v_receipt_text IS NOT NULL THEN
    RAISE EXCEPTION 'continuation receipt is forbidden'
      USING ERRCODE = '22023';
  END IF;
  IF jsonb_typeof(p_binding -> 'baselineEvidence') <> 'array'
     OR jsonb_array_length(p_binding -> 'baselineEvidence') > 1023 THEN
    RAISE EXCEPTION 'MFA binding cannot accept another evidence item'
      USING ERRCODE = '22023';
  END IF;
  RETURN app.private_unbound_mfa_anchor_from_stepup_binding_v1(
    p_binding,p_created_at
  );
END;
$function$;
--> statement-breakpoint

ALTER FUNCTION app.start_totp_enrollment_v1(jsonb)
  RENAME TO private_unbound_start_totp_enrollment_v1;
ALTER FUNCTION app.create_mfa_step_up_challenge_v1(jsonb)
  RENAME TO private_unbound_create_mfa_step_up_challenge_v1;
ALTER FUNCTION app.create_webauthn_ceremony_v1(jsonb)
  RENAME TO private_unbound_create_webauthn_ceremony_v1;
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.start_totp_enrollment_v1(p_request jsonb)
RETURNS boolean
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_previous text;
  v_result boolean;
BEGIN
  v_previous := app.private_mfa_enter_continuation_receipt_v1(
    p_request -> 'binding',p_request ->> 'continuationReceiptDigest'
  );
  BEGIN
    v_result := app.private_unbound_start_totp_enrollment_v1(
      p_request - 'continuationReceiptDigest'
    );
  EXCEPTION WHEN OTHERS THEN
    PERFORM app.private_mfa_restore_continuation_receipt_v1(v_previous);
    RAISE;
  END;
  PERFORM app.private_mfa_restore_continuation_receipt_v1(v_previous);
  RETURN v_result;
END;
$function$;
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.create_mfa_step_up_challenge_v1(p_request jsonb)
RETURNS boolean
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_previous text;
  v_result boolean;
BEGIN
  v_previous := app.private_mfa_enter_continuation_receipt_v1(
    p_request -> 'binding',p_request ->> 'continuationReceiptDigest'
  );
  BEGIN
    v_result := app.private_unbound_create_mfa_step_up_challenge_v1(
      p_request - 'continuationReceiptDigest'
    );
  EXCEPTION WHEN OTHERS THEN
    PERFORM app.private_mfa_restore_continuation_receipt_v1(v_previous);
    RAISE;
  END;
  PERFORM app.private_mfa_restore_continuation_receipt_v1(v_previous);
  RETURN v_result;
END;
$function$;
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.create_webauthn_ceremony_v1(p_request jsonb)
RETURNS boolean
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_previous text;
  v_result boolean;
BEGIN
  v_previous := app.private_mfa_enter_continuation_receipt_v1(
    p_request -> 'binding',p_request ->> 'continuationReceiptDigest'
  );
  BEGIN
    v_result := app.private_unbound_create_webauthn_ceremony_v1(
      p_request - 'continuationReceiptDigest'
    );
  EXCEPTION WHEN OTHERS THEN
    PERFORM app.private_mfa_restore_continuation_receipt_v1(v_previous);
    RAISE;
  END;
  PERFORM app.private_mfa_restore_continuation_receipt_v1(v_previous);
  RETURN v_result;
END;
$function$;
--> statement-breakpoint

-- Keep the exact provider/binding/access receipt stable from the receipt-bound
-- live projection through artifact claim or terminal continuation consumption.
-- The shared locks make a concurrent deactivation serialize before or after
-- the command; it cannot commit between admission and mutation.
CREATE FUNCTION app.private_mfa_lock_continuation_authority_v1(
  p_continuation_id uuid,
  p_authority_at timestamptz
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_primary_kind text;
  v_origin text;
  v_tenant_id uuid;
  v_user_id uuid;
  v_source_session_id uuid;
  v_source_family_id uuid;
  v_source_version bigint;
  v_source_absolute_expires_at timestamptz;
  v_passkey_credential_id uuid;
  v_passkey_credential_revision bigint;
  v_passkey_authenticated_at timestamptz;
BEGIN
  SELECT continuation.primary_kind INTO STRICT v_primary_kind
  FROM ONLY public.tenant_post_primary_continuations AS continuation
  WHERE continuation.id = p_continuation_id
    AND continuation.state = 'pending'
    AND continuation.expires_at > p_authority_at;
  IF v_primary_kind = 'passkey' THEN
    SELECT provenance.origin,provenance.tenant_id,provenance.user_id,
           provenance.source_session_id,
           provenance.source_session_family_id,
           provenance.source_session_version,
           provenance.source_absolute_expires_at,provenance.credential_id,
           provenance.credential_revision,provenance.authenticated_at
      INTO STRICT v_origin,v_tenant_id,v_user_id,v_source_session_id,
        v_source_family_id,v_source_version,v_source_absolute_expires_at,
        v_passkey_credential_id,v_passkey_credential_revision,
        v_passkey_authenticated_at
    FROM ONLY public.tenant_post_primary_passkey_provenance AS provenance
    WHERE provenance.continuation_id = p_continuation_id;
    PERFORM app.private_mfa_lock_policy_authority_v1(v_tenant_id);
    PERFORM app.private_mfa_assert_live_continuation_policy_v1(
      p_continuation_id,p_authority_at
    );
    IF v_origin = 'session_revalidation' THEN
      IF v_source_version >= 9007199254740991 THEN
        RAISE EXCEPTION 'passkey MFA source has no successor headroom'
          USING ERRCODE = '40001';
      END IF;
      PERFORM 1
      FROM ONLY public.auth_sessions AS source_session
      JOIN ONLY public.auth_session_mfa_states AS source_state
        ON source_state.tenant_id = v_tenant_id
       AND source_state.session_id = source_session.id
       AND source_state.user_id = v_user_id
       AND source_state.primary_kind = 'passkey'
       AND source_state.session_version = v_source_version
      JOIN ONLY public.auth_session_passkey_provenance AS source_provenance
        ON source_provenance.tenant_id = source_state.tenant_id
       AND source_provenance.session_id = source_state.session_id
       AND source_provenance.user_id = source_state.user_id
       AND source_provenance.primary_kind = 'passkey'
       AND source_provenance.credential_id = v_passkey_credential_id
       AND source_provenance.credential_revision =
           v_passkey_credential_revision
       AND source_provenance.authenticated_at = v_passkey_authenticated_at
      WHERE source_session.id = v_source_session_id
        AND source_session.user_id = v_user_id
        AND source_session.active_tenant_id = v_tenant_id
        AND source_session.rotation_family_id = v_source_family_id
        AND source_session.authentication_method = 'passkey'
        AND source_session.absolute_expires_at =
            v_source_absolute_expires_at
        AND source_session.revoked_at IS NULL
        AND source_session.idle_expires_at > p_authority_at
        AND source_session.absolute_expires_at > p_authority_at
      FOR UPDATE OF source_session,source_state NOWAIT
      FOR SHARE OF source_provenance NOWAIT;
      IF NOT FOUND THEN
        RAISE EXCEPTION 'passkey MFA source session is stale'
          USING ERRCODE = '40001';
      END IF;
      PERFORM app.private_mfa_assert_live_passkey_session_evidence_v1(
        v_tenant_id,v_user_id,v_source_session_id,p_authority_at
      );
    ELSIF v_origin <> 'initial_login' THEN
      RAISE EXCEPTION 'passkey MFA continuation origin is invalid'
        USING ERRCODE = '23514';
    END IF;
    PERFORM 1
    FROM ONLY public.tenant_post_primary_passkey_provenance AS provenance
    JOIN ONLY public.tenant_post_primary_continuations AS continuation
      ON continuation.tenant_id = provenance.tenant_id
     AND continuation.id = provenance.continuation_id
     AND continuation.user_id = provenance.user_id
     AND continuation.primary_kind = 'passkey'
     AND continuation.passkey_credential_id = provenance.credential_id
     AND continuation.primary_revision = provenance.credential_revision
     AND continuation.state = 'pending'
     AND continuation.expires_at > p_authority_at
    JOIN ONLY public.tenant_mfa_subjects AS subject
      ON subject.tenant_id = continuation.tenant_id
     AND subject.user_id = continuation.user_id
     AND subject.identity_epoch = continuation.identity_epoch
     AND subject.session_invalidation_epoch =
         continuation.session_invalidation_epoch
    JOIN ONLY public.tenants AS tenant
      ON tenant.id = provenance.tenant_id AND tenant.status = 'active'
    JOIN ONLY public.users AS local_user
      ON local_user.id = provenance.user_id AND local_user.active
    JOIN ONLY public.tenant_memberships AS membership
      ON membership.tenant_id = provenance.tenant_id
     AND membership.user_id = provenance.user_id
     AND membership.status = 'active'
    JOIN ONLY public.tenant_webauthn_credentials AS credential
      ON credential.tenant_id = provenance.tenant_id
     AND credential.user_id = provenance.user_id
     AND credential.id = provenance.credential_id
     AND credential.security_revision = provenance.credential_revision
     AND credential.status = 'active'
    WHERE provenance.continuation_id = p_continuation_id
      AND provenance.primary_kind = 'passkey'
      AND provenance.authentication_method = 'passkey'
    FOR SHARE OF continuation,subject,tenant,local_user,membership,credential
      NOWAIT;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'passkey MFA continuation authority is stale'
        USING ERRCODE = '40001';
    END IF;
    PERFORM app.private_mfa_assert_live_passkey_continuation_evidence_v1(
      v_tenant_id,v_user_id,p_continuation_id,p_authority_at
    );
  ELSIF v_primary_kind = 'tenant_platform_provider' THEN
    SELECT provenance.origin,provenance.tenant_id,provenance.user_id,
           provenance.source_session_id,
           provenance.source_session_family_id,
           provenance.source_session_version,
           provenance.source_absolute_expires_at
      INTO STRICT v_origin,v_tenant_id,v_user_id,v_source_session_id,
        v_source_family_id,v_source_version,v_source_absolute_expires_at
    FROM ONLY public.tenant_post_primary_platform_federated_provenance
      AS provenance
    WHERE provenance.continuation_id = p_continuation_id;
    IF v_origin = 'session_revalidation' THEN
      PERFORM 1
      FROM ONLY public.auth_sessions AS source_session
      JOIN ONLY public.auth_session_mfa_states AS source_state
        ON source_state.tenant_id = v_tenant_id
       AND source_state.session_id = source_session.id
       AND source_state.user_id = v_user_id
       AND source_state.primary_kind = 'tenant_platform_provider'
       AND source_state.session_version = v_source_version
      WHERE source_session.id = v_source_session_id
        AND source_session.user_id = v_user_id
        AND source_session.active_tenant_id = v_tenant_id
        AND source_session.rotation_family_id = v_source_family_id
        AND source_session.absolute_expires_at =
            v_source_absolute_expires_at
        AND source_session.revoked_at IS NULL
        AND source_session.idle_expires_at > p_authority_at
        AND source_session.absolute_expires_at > p_authority_at
      FOR UPDATE OF source_session,source_state NOWAIT;
      IF NOT FOUND THEN
        RAISE EXCEPTION 'MFA continuation source session is stale'
          USING ERRCODE = '40001';
      END IF;
    END IF;
    PERFORM 1
    FROM ONLY public.tenant_post_primary_platform_federated_provenance
      AS provenance
    JOIN ONLY public.tenant_post_primary_continuations AS continuation
      ON continuation.tenant_id = provenance.tenant_id
     AND continuation.id = provenance.continuation_id
     AND continuation.user_id = provenance.user_id
     AND continuation.primary_kind = 'tenant_platform_provider'
     AND continuation.platform_provider_id = provenance.platform_provider_id
     AND continuation.binding_id = provenance.binding_id
     AND continuation.external_identity_id = provenance.external_identity_id
     AND continuation.primary_revision = provenance.external_identity_revision
     AND continuation.state = 'pending'
     AND continuation.expires_at > p_authority_at
    JOIN ONLY public.tenant_mfa_subjects AS subject
      ON subject.tenant_id = continuation.tenant_id
     AND subject.user_id = continuation.user_id
     AND subject.identity_epoch = continuation.identity_epoch
     AND subject.session_invalidation_epoch =
         continuation.session_invalidation_epoch
    JOIN ONLY public.tenants AS tenant
      ON tenant.id = provenance.tenant_id AND tenant.status = 'active'
    JOIN ONLY public.users AS local_user
      ON local_user.id = provenance.user_id AND local_user.active
    JOIN ONLY public.tenant_memberships AS membership
      ON membership.tenant_id = provenance.tenant_id
     AND membership.id = provenance.membership_id
     AND membership.user_id = provenance.user_id
     AND membership.status = 'active'
    JOIN ONLY public.platform_auth_providers AS provider
      ON provider.id = provenance.platform_provider_id
     AND provider.kind = 'oidc' AND provider.enabled
     AND provider.archived_at IS NULL
    JOIN ONLY public.platform_federated_provider_policies AS policy
      ON policy.provider_id = provider.id AND policy.provider_kind = 'oidc'
     AND policy.enabled AND NOT policy.platform_login_enabled
     AND policy.security_revision = provenance.security_revision
    JOIN ONLY public.tenant_platform_auth_provider_bindings AS binding
      ON binding.tenant_id = provenance.tenant_id
     AND binding.id = provenance.binding_id
     AND binding.platform_provider_id = provider.id
     AND binding.version = provenance.binding_revision
     AND binding.mapping_revision = provenance.mapping_revision
     AND binding.auth_revision = provenance.authorization_revision
     AND binding.current_access_epoch_id = provenance.access_epoch_id
     AND binding.enabled AND binding.archived_at IS NULL
    JOIN ONLY public.tenant_platform_identity_provider_access_epochs AS epoch
      ON epoch.tenant_id = provenance.tenant_id
     AND epoch.id = provenance.access_epoch_id
     AND epoch.binding_id = binding.id
     AND epoch.platform_provider_id = provider.id
     AND epoch.source_id = provenance.access_source_id
     AND epoch.ended_at IS NULL
    JOIN ONLY public.tenant_authorization_sources AS source
      ON source.tenant_id = epoch.tenant_id
     AND source.id = epoch.source_id
     AND source.kind = 'identity_provider_access'
     AND source.authoritative AND NOT source.protected
     AND source.key = format(
       'identity_provider_access:%s:%s',epoch.binding_id,epoch.sequence
     )
     AND source.retired_at IS NULL
    JOIN ONLY public.platform_federated_external_identities AS identity
      ON identity.platform_provider_id = provider.id
     AND identity.id = provenance.external_identity_id
     AND identity.user_id = provenance.user_id
     AND identity.version = provenance.external_identity_revision
     AND identity.retired_at IS NULL
    JOIN ONLY public.platform_federated_external_identity_aliases AS alias
      ON alias.platform_provider_id = provider.id
     AND alias.external_identity_id = identity.id
     AND alias.key_version = provenance.subject_alias_key_version
     AND alias.retired_at IS NULL
    JOIN ONLY public.tenant_platform_federated_provider_access_grants AS grant_row
      ON grant_row.tenant_id = provenance.tenant_id
     AND grant_row.id = provenance.access_grant_id
     AND grant_row.platform_provider_id = provider.id
     AND grant_row.binding_id = binding.id
     AND grant_row.access_epoch_id = epoch.id
     AND grant_row.source_id = source.id
     AND grant_row.external_identity_id = identity.id
     AND grant_row.membership_id = membership.id
     AND grant_row.user_id = provenance.user_id
     AND grant_row.ended_at IS NULL
    WHERE provenance.continuation_id = p_continuation_id
    FOR SHARE OF continuation,subject,tenant,local_user,membership,provider,
      policy,binding,epoch,source,identity,alias,grant_row NOWAIT;
  ELSIF v_primary_kind = 'tenant_provider' THEN
    SELECT provenance.origin,provenance.tenant_id,provenance.user_id,
           provenance.source_session_id,
           provenance.source_session_family_id,
           provenance.source_session_version,
           provenance.source_absolute_expires_at
      INTO STRICT v_origin,v_tenant_id,v_user_id,v_source_session_id,
        v_source_family_id,v_source_version,v_source_absolute_expires_at
    FROM ONLY public.tenant_post_primary_federated_provenance AS provenance
    WHERE provenance.continuation_id = p_continuation_id;
    IF v_origin = 'session_revalidation' THEN
      PERFORM 1
      FROM ONLY public.auth_sessions AS source_session
      JOIN ONLY public.auth_session_mfa_states AS source_state
        ON source_state.tenant_id = v_tenant_id
       AND source_state.session_id = source_session.id
       AND source_state.user_id = v_user_id
       AND source_state.primary_kind = 'tenant_provider'
       AND source_state.session_version = v_source_version
      WHERE source_session.id = v_source_session_id
        AND source_session.user_id = v_user_id
        AND source_session.active_tenant_id = v_tenant_id
        AND source_session.rotation_family_id = v_source_family_id
        AND source_session.absolute_expires_at =
            v_source_absolute_expires_at
        AND source_session.revoked_at IS NULL
        AND source_session.idle_expires_at > p_authority_at
        AND source_session.absolute_expires_at > p_authority_at
      FOR UPDATE OF source_session,source_state NOWAIT;
      IF NOT FOUND THEN
        RAISE EXCEPTION 'MFA continuation source session is stale'
          USING ERRCODE = '40001';
      END IF;
    END IF;
    PERFORM 1
    FROM ONLY public.tenant_post_primary_federated_provenance AS provenance
    JOIN ONLY public.tenant_post_primary_continuations AS continuation
      ON continuation.tenant_id = provenance.tenant_id
     AND continuation.id = provenance.continuation_id
     AND continuation.user_id = provenance.user_id
     AND continuation.primary_kind = 'tenant_provider'
     AND continuation.provider_id = provenance.provider_id
     AND continuation.binding_id = provenance.binding_id
     AND continuation.provider_kind = provenance.provider_kind
     AND continuation.external_identity_id = provenance.external_identity_id
     AND continuation.primary_revision = provenance.external_identity_revision
     AND continuation.state = 'pending'
     AND continuation.expires_at > p_authority_at
    JOIN ONLY public.tenant_mfa_subjects AS subject
      ON subject.tenant_id = continuation.tenant_id
     AND subject.user_id = continuation.user_id
     AND subject.identity_epoch = continuation.identity_epoch
     AND subject.session_invalidation_epoch =
         continuation.session_invalidation_epoch
    JOIN ONLY public.tenants AS tenant
      ON tenant.id = provenance.tenant_id AND tenant.status = 'active'
    JOIN ONLY public.users AS local_user
      ON local_user.id = provenance.user_id AND local_user.active
    JOIN ONLY public.tenant_memberships AS membership
      ON membership.tenant_id = provenance.tenant_id
     AND membership.id = provenance.membership_id
     AND membership.user_id = provenance.user_id
     AND membership.status = 'active'
    JOIN ONLY public.tenant_auth_providers AS provider
      ON provider.tenant_id = provenance.tenant_id
     AND provider.id = provenance.provider_id
     AND provider.kind = provenance.provider_kind
     AND provider.version = provenance.provider_revision
     AND provider.enabled AND provider.archived_at IS NULL
    JOIN ONLY public.tenant_auth_provider_bindings AS binding
      ON binding.tenant_id = provenance.tenant_id
     AND binding.id = provenance.binding_id
     AND binding.provider_id = provider.id
     AND binding.version = provenance.binding_revision
     AND binding.mapping_revision = provenance.mapping_revision
     AND binding.auth_revision = provenance.authorization_revision
     AND binding.current_access_epoch_id = provenance.access_epoch_id
     AND binding.enabled AND binding.archived_at IS NULL
    JOIN ONLY public.tenant_federated_provider_policies AS policy
      ON policy.tenant_id = provenance.tenant_id
     AND policy.provider_id = provider.id
     AND policy.binding_id = binding.id
     AND policy.provider_kind = provenance.provider_kind
     AND policy.configuration_revision = provenance.configuration_revision
     AND policy.security_revision = provenance.security_revision
     AND policy.plan_revision = provenance.plan_revision
     AND policy.assurance_policy_revision = provenance.assurance_policy_revision
     AND policy.enabled
    JOIN ONLY public.tenant_identity_provider_access_epochs AS epoch
      ON epoch.tenant_id = provenance.tenant_id
     AND epoch.id = provenance.access_epoch_id
     AND epoch.binding_id = binding.id
     AND epoch.provider_id = provider.id
     AND epoch.source_id = provenance.access_source_id
     AND epoch.ended_at IS NULL
    JOIN ONLY public.tenant_authorization_sources AS source
      ON source.tenant_id = epoch.tenant_id
     AND source.id = epoch.source_id
     AND source.kind = 'identity_provider_access'
     AND source.authoritative AND NOT source.protected
     AND source.key = format(
       'identity_provider_access:%s:%s',epoch.binding_id,epoch.sequence
     )
     AND source.retired_at IS NULL
    JOIN ONLY public.tenant_federated_external_identities AS identity
      ON identity.tenant_id = provenance.tenant_id
     AND identity.provider_id = provider.id
     AND identity.binding_id = binding.id
     AND identity.id = provenance.external_identity_id
     AND identity.user_id = provenance.user_id
     AND identity.version = provenance.external_identity_revision
     AND identity.retired_at IS NULL
    JOIN ONLY public.tenant_federated_external_identity_aliases AS alias
      ON alias.tenant_id = identity.tenant_id
     AND alias.provider_id = identity.provider_id
     AND alias.external_identity_id = identity.id
     AND alias.retired_at IS NULL
    JOIN ONLY public.tenant_federated_provider_access_grants AS grant_row
      ON grant_row.tenant_id = provenance.tenant_id
     AND grant_row.id = provenance.access_grant_id
     AND grant_row.provider_id = provider.id
     AND grant_row.binding_id = binding.id
     AND grant_row.access_epoch_id = epoch.id
     AND grant_row.source_id = source.id
     AND grant_row.external_identity_id = identity.id
     AND grant_row.membership_id = membership.id
     AND grant_row.user_id = provenance.user_id
     AND grant_row.ended_at IS NULL
    WHERE provenance.continuation_id = p_continuation_id
    FOR SHARE OF continuation,subject,tenant,local_user,membership,provider,
      binding,policy,epoch,source,identity,alias,grant_row NOWAIT;
  ELSE
    RETURN;
  END IF;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'MFA continuation authority is stale'
      USING ERRCODE = '40001';
  END IF;
EXCEPTION WHEN lock_not_available THEN
  RAISE EXCEPTION 'MFA continuation authority is busy'
    USING ERRCODE = '40001';
WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
  RAISE EXCEPTION 'MFA continuation authority is unavailable'
    USING ERRCODE = '40001';
END;
$function$;
--> statement-breakpoint

-- Claiming an artifact is itself a state mutation.  Bind that mutation to the
-- exact continuation receipt so a guessed artifact identifier cannot be moved
-- to claimed before the final completion check.  The v1 wrappers remain safe
-- for session/primary authorities and fail closed for continuations.
CREATE FUNCTION app.private_mfa_assert_artifact_receipt_v1(
  p_anchor_id uuid,
  p_continuation_receipt_digest bytea,
  p_evaluated_at timestamptz
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_anchor public.tenant_mfa_authority_anchors%ROWTYPE;
  v_anchor_binding jsonb;
  v_live_binding jsonb;
  v_primary_kind text;
  v_authority_at timestamptz := greatest(
    p_evaluated_at,transaction_timestamp()
  );
BEGIN
  SELECT anchor.* INTO STRICT v_anchor
  FROM ONLY public.tenant_mfa_authority_anchors AS anchor
  WHERE anchor.id = p_anchor_id;
  IF v_anchor.flow IN ('session','continuation')
     AND v_anchor.anchor_version >= 9007199254740991 THEN
    RAISE EXCEPTION 'MFA artifact authority has no successor headroom'
      USING ERRCODE = '40001';
  END IF;
  IF v_anchor.flow = 'continuation' THEN
    IF p_continuation_receipt_digest IS NULL
       OR octet_length(p_continuation_receipt_digest) <> 32
       OR encode(p_continuation_receipt_digest,'hex') = repeat('00',32) THEN
      RAISE EXCEPTION 'continuation receipt is required'
        USING ERRCODE = '42501';
    END IF;
    PERFORM 1
    FROM ONLY public.tenant_post_primary_continuations AS continuation
    WHERE continuation.tenant_id = v_anchor.tenant_id
      AND continuation.id = v_anchor.continuation_id
      AND continuation.user_id = v_anchor.user_id
      AND continuation.state = 'pending'
      AND continuation.version = v_anchor.anchor_version
      AND continuation.expires_at = v_anchor.anchor_expires_at
      AND continuation.expires_at > v_authority_at
      AND continuation.receipt_digest = p_continuation_receipt_digest;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'continuation receipt is unavailable'
        USING ERRCODE = '42501';
    END IF;
    v_live_binding := app.resolve_mfa_authority_v2(
      v_anchor.continuation_id,'continuation',v_anchor.action,
      v_anchor.audience,v_authority_at,p_continuation_receipt_digest
    );
    PERFORM app.private_mfa_lock_continuation_authority_v1(
      v_anchor.continuation_id,v_authority_at
    );
    v_anchor_binding := app.private_mfa_anchor_binding_v1(v_anchor.id);
    IF jsonb_build_object(
         'flow',v_live_binding -> 'flow',
         'tenantId',v_live_binding -> 'tenantId',
         'userId',v_live_binding -> 'userId',
         'identityEpoch',v_live_binding -> 'identityEpoch',
         'continuationId',v_live_binding -> 'continuationId',
         'anchorVersion',v_live_binding -> 'anchorVersion',
         'anchorExpiresAt',v_live_binding -> 'anchorExpiresAt',
         'anchorRecoveryRestricted',v_live_binding -> 'anchorRecoveryRestricted',
         'action',v_live_binding -> 'action',
         'audience',v_live_binding -> 'audience',
         'requirement',v_live_binding -> 'requirement',
         'baselineEvidence',v_live_binding -> 'baselineEvidence'
       ) IS DISTINCT FROM jsonb_build_object(
         'flow',v_anchor_binding -> 'flow',
         'tenantId',v_anchor_binding -> 'tenantId',
         'userId',v_anchor_binding -> 'userId',
         'identityEpoch',v_anchor_binding -> 'identityEpoch',
         'continuationId',v_anchor_binding -> 'continuationId',
         'anchorVersion',v_anchor_binding -> 'anchorVersion',
         'anchorExpiresAt',v_anchor_binding -> 'anchorExpiresAt',
         'anchorRecoveryRestricted',v_anchor_binding -> 'anchorRecoveryRestricted',
         'action',v_anchor_binding -> 'action',
         'audience',v_anchor_binding -> 'audience',
         'requirement',v_anchor_binding -> 'requirement',
         'baselineEvidence',v_anchor_binding -> 'baselineEvidence'
       ) THEN
      RAISE EXCEPTION 'MFA artifact authority is stale'
        USING ERRCODE = '40001';
    END IF;
  ELSIF v_anchor.flow = 'session' THEN
    IF p_continuation_receipt_digest IS NOT NULL THEN
      RAISE EXCEPTION 'continuation receipt is forbidden'
        USING ERRCODE = '22023';
    END IF;
    SELECT state.primary_kind INTO STRICT v_primary_kind
    FROM ONLY public.auth_session_mfa_states AS state
    WHERE state.tenant_id = v_anchor.tenant_id
      AND state.session_id = v_anchor.session_id
      AND state.user_id = v_anchor.user_id
      AND state.session_version = v_anchor.anchor_version
      AND state.identity_epoch = v_anchor.identity_epoch;
    IF v_primary_kind = 'passkey' THEN
      PERFORM app.private_mfa_lock_live_passkey_session_v1(
        v_anchor.tenant_id,v_anchor.user_id,v_anchor.session_id,
        v_anchor.session_family_id,v_anchor.anchor_version,
        v_anchor.identity_epoch,v_anchor.anchor_expires_at,
        v_anchor.audience,v_authority_at
      );
      PERFORM app.private_mfa_assert_live_policy_anchor_v1(
        v_anchor.id,v_authority_at
      );
      PERFORM app.private_mfa_assert_live_passkey_anchor_evidence_v1(
        v_anchor.id,v_authority_at,NULL,NULL
      );
      v_live_binding := app.resolve_mfa_authority_v2(
        v_anchor.session_id,'session',v_anchor.action,
        v_anchor.audience,v_authority_at,NULL::bytea
      );
      v_anchor_binding := app.private_mfa_anchor_binding_v1(v_anchor.id);
      IF jsonb_build_object(
           'flow',v_live_binding -> 'flow',
           'tenantId',v_live_binding -> 'tenantId',
           'userId',v_live_binding -> 'userId',
           'identityEpoch',v_live_binding -> 'identityEpoch',
           'sessionId',v_live_binding -> 'sessionId',
           'sessionFamilyId',v_live_binding -> 'sessionFamilyId',
           'anchorVersion',v_live_binding -> 'anchorVersion',
           'anchorExpiresAt',v_live_binding -> 'anchorExpiresAt',
           'anchorRecoveryRestricted',
             v_live_binding -> 'anchorRecoveryRestricted',
           'action',v_live_binding -> 'action',
           'audience',v_live_binding -> 'audience',
           'requirement',v_live_binding -> 'requirement',
           'baselineEvidence',v_live_binding -> 'baselineEvidence'
         ) IS DISTINCT FROM jsonb_build_object(
           'flow',v_anchor_binding -> 'flow',
           'tenantId',v_anchor_binding -> 'tenantId',
           'userId',v_anchor_binding -> 'userId',
           'identityEpoch',v_anchor_binding -> 'identityEpoch',
           'sessionId',v_anchor_binding -> 'sessionId',
           'sessionFamilyId',v_anchor_binding -> 'sessionFamilyId',
           'anchorVersion',v_anchor_binding -> 'anchorVersion',
           'anchorExpiresAt',v_anchor_binding -> 'anchorExpiresAt',
           'anchorRecoveryRestricted',
             v_anchor_binding -> 'anchorRecoveryRestricted',
           'action',v_anchor_binding -> 'action',
           'audience',v_anchor_binding -> 'audience',
           'requirement',v_anchor_binding -> 'requirement',
           'baselineEvidence',v_anchor_binding -> 'baselineEvidence'
         ) THEN
        RAISE EXCEPTION 'MFA artifact authority is stale'
          USING ERRCODE = '40001';
      END IF;
    END IF;
  ELSIF p_continuation_receipt_digest IS NOT NULL THEN
    RAISE EXCEPTION 'continuation receipt is forbidden'
      USING ERRCODE = '22023';
  END IF;
EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
  RAISE EXCEPTION 'MFA artifact authority is unavailable or ambiguous'
    USING ERRCODE = '42501';
END;
$function$;
--> statement-breakpoint

ALTER FUNCTION app.claim_totp_enrollment_v1(uuid,bytea,timestamptz)
  RENAME TO private_unbound_claim_totp_enrollment_v1;
ALTER FUNCTION app.claim_mfa_step_up_challenge_v1(bytea,bytea,text,timestamptz)
  RENAME TO private_unbound_claim_mfa_step_up_challenge_v1;
ALTER FUNCTION app.claim_webauthn_ceremony_v1(bytea,bytea,timestamptz)
  RENAME TO private_unbound_claim_webauthn_ceremony_v1;
--> statement-breakpoint

CREATE FUNCTION app.claim_totp_enrollment_v2(
  p_enrollment_id uuid,
  p_browser_digest bytea,
  p_claimed_at timestamptz,
  p_continuation_receipt_digest bytea
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_anchor_id uuid;
  v_effective_at timestamptz := greatest(
    p_claimed_at,transaction_timestamp()
  );
BEGIN
  SELECT enrollment.authority_anchor_id INTO STRICT v_anchor_id
  FROM ONLY public.tenant_totp_enrollments AS enrollment
  WHERE enrollment.id = p_enrollment_id
  FOR UPDATE;
  PERFORM app.private_mfa_assert_artifact_receipt_v1(
    v_anchor_id,p_continuation_receipt_digest,v_effective_at
  );
  RETURN app.private_unbound_claim_totp_enrollment_v1(
    p_enrollment_id,p_browser_digest,v_effective_at
  );
EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
  RAISE EXCEPTION 'TOTP enrollment is unavailable or ambiguous'
    USING ERRCODE = '42501';
END;
$function$;

CREATE OR REPLACE FUNCTION app.claim_totp_enrollment_v1(
  p_enrollment_id uuid,p_browser_digest bytea,p_claimed_at timestamptz
)
RETURNS jsonb
LANGUAGE sql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
  SELECT app.claim_totp_enrollment_v2(
    p_enrollment_id,p_browser_digest,p_claimed_at,NULL::bytea
  )
$function$;
--> statement-breakpoint

CREATE FUNCTION app.claim_mfa_step_up_challenge_v2(
  p_challenge_id bytea,
  p_browser_digest bytea,
  p_factor_kind text,
  p_claimed_at timestamptz,
  p_continuation_receipt_digest bytea
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_anchor_id uuid;
  v_challenge public.tenant_mfa_step_up_challenges%ROWTYPE;
  v_effective_at timestamptz := greatest(
    p_claimed_at,transaction_timestamp()
  );
BEGIN
  IF octet_length(p_challenge_id) <> 32
     OR octet_length(p_browser_digest) <> 32
     OR p_factor_kind NOT IN ('totp','recovery_code')
     OR p_claimed_at IS NULL THEN
    RAISE EXCEPTION 'invalid MFA challenge claim'
      USING ERRCODE = '22023';
  END IF;
  SELECT challenge.authority_anchor_id INTO STRICT v_anchor_id
  FROM ONLY public.tenant_mfa_step_up_challenges AS challenge
  WHERE challenge.id = p_challenge_id
  FOR UPDATE;
  PERFORM app.private_mfa_assert_artifact_receipt_v1(
    v_anchor_id,p_continuation_receipt_digest,v_effective_at
  );
  UPDATE ONLY public.tenant_mfa_step_up_challenges AS challenge
  SET state = 'claimed',version = challenge.version + 1,
      claimed_at = v_effective_at,claimed_factor_kind = p_factor_kind
  WHERE challenge.id = p_challenge_id
    AND challenge.browser_digest = p_browser_digest
    AND p_factor_kind = ANY(challenge.allowed_factors)
    AND challenge.state = 'pending'
    AND challenge.version = 1
    AND challenge.claimed_factor_kind IS NULL
    AND challenge.expires_at > v_effective_at
  RETURNING challenge.* INTO STRICT v_challenge;
  RETURN jsonb_build_object(
    'id',replace(encode(v_challenge.id,'base64'),E'\n',''),
    'browserDigest',replace(
      encode(v_challenge.browser_digest,'base64'),E'\n',''
    ),
    'binding',app.private_mfa_anchor_binding_v1(
      v_challenge.authority_anchor_id
    ),
    'allowedFactors',to_jsonb(v_challenge.allowed_factors),
    'claimedFactorKind',v_challenge.claimed_factor_kind,
    'createdAt',v_challenge.created_at,
    'expiresAt',v_challenge.expires_at,
    'state',v_challenge.state,
    'version',v_challenge.version,
    'claimedAt',v_challenge.claimed_at
  );
EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
  RAISE EXCEPTION 'MFA challenge claim is stale or denied'
    USING ERRCODE = '40001';
END;
$function$;

CREATE OR REPLACE FUNCTION app.claim_mfa_step_up_challenge_v1(
	  p_challenge_id bytea,p_browser_digest bytea,p_factor text,
  p_claimed_at timestamptz
)
RETURNS jsonb
LANGUAGE sql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
  SELECT app.claim_mfa_step_up_challenge_v2(
    p_challenge_id,p_browser_digest,p_factor,p_claimed_at,NULL::bytea
  )
$function$;
--> statement-breakpoint

CREATE FUNCTION app.claim_webauthn_ceremony_v2(
  p_ceremony_id bytea,
  p_browser_digest bytea,
  p_claimed_at timestamptz,
  p_continuation_receipt_digest bytea
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_anchor_id uuid;
  v_effective_at timestamptz := greatest(
    p_claimed_at,transaction_timestamp()
  );
BEGIN
  SELECT ceremony.authority_anchor_id INTO STRICT v_anchor_id
  FROM ONLY public.tenant_webauthn_ceremonies AS ceremony
  WHERE ceremony.id = p_ceremony_id
  FOR UPDATE;
  PERFORM app.private_mfa_assert_artifact_receipt_v1(
    v_anchor_id,p_continuation_receipt_digest,v_effective_at
  );
  RETURN app.private_unbound_claim_webauthn_ceremony_v1(
    p_ceremony_id,p_browser_digest,v_effective_at
  );
EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
  RAISE EXCEPTION 'WebAuthn ceremony is unavailable or ambiguous'
    USING ERRCODE = '42501';
END;
$function$;

CREATE OR REPLACE FUNCTION app.claim_webauthn_ceremony_v1(
  p_ceremony_id bytea,p_browser_digest bytea,p_claimed_at timestamptz
)
RETURNS jsonb
LANGUAGE sql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
  SELECT app.claim_webauthn_ceremony_v2(
    p_ceremony_id,p_browser_digest,p_claimed_at,NULL::bytea
  )
$function$;
--> statement-breakpoint

-- TOTP/recovery carry the receipt beside the local session reservation.  The
-- historical completion implementation is retained unchanged and receives a
-- normalized request with the proof embedded in the session intent consumed
-- by the current dispatcher.
ALTER FUNCTION app.private_complete_mfa_factor_v1(jsonb,text)
  RENAME TO private_complete_mfa_factor_legacy_v1;
-- PostgreSQL has already renamed the routine. The no-op drop also makes the
-- forward-only state transition explicit to static SQL analyzers that do not
-- model ALTER FUNCTION ... RENAME.
DROP FUNCTION IF EXISTS app.private_complete_mfa_factor_v1(jsonb,text);
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
  v_request jsonb := p_request;
  v_receipt bytea;
  v_challenge_state text;
  v_claimed_factor_kind text;
  v_expected_factor_kind text;
BEGIN
  v_expected_factor_kind := CASE p_factor_kind
    WHEN 'totp' THEN 'totp'
    WHEN 'recovery' THEN 'recovery_code'
  END;
  IF v_expected_factor_kind IS NULL THEN
    RAISE EXCEPTION 'invalid MFA factor completion kind'
      USING ERRCODE = '22023';
  END IF;
  SELECT challenge.state,challenge.claimed_factor_kind
    INTO STRICT v_challenge_state,v_claimed_factor_kind
  FROM ONLY public.tenant_mfa_step_up_challenges AS challenge
  WHERE challenge.id = app.private_mfa_decode_base64_v1(
    p_request ->> 'challengeId',32,32
  );
  IF (v_challenge_state <> 'completed'
        AND (v_challenge_state <> 'claimed'
          OR v_claimed_factor_kind IS DISTINCT FROM v_expected_factor_kind))
     OR (v_challenge_state = 'completed'
       AND v_claimed_factor_kind IS NOT NULL
       AND v_claimed_factor_kind IS DISTINCT FROM v_expected_factor_kind) THEN
    RAISE EXCEPTION 'MFA challenge factor selector is stale'
      USING ERRCODE = '40001';
  END IF;
  IF p_request ? 'continuationReceiptDigest' THEN
    IF jsonb_typeof(p_request -> 'session') <> 'object'
       OR p_request -> 'session' ? 'continuationReceiptDigest' THEN
      RAISE EXCEPTION 'invalid MFA completion receipt shape'
        USING ERRCODE = '22023';
    END IF;
    v_receipt := app.private_mfa_decode_base64_v1(
      p_request ->> 'continuationReceiptDigest',32,32
    );
    IF encode(v_receipt,'hex') = repeat('00',32) THEN
      RAISE EXCEPTION 'continuation receipt is invalid'
        USING ERRCODE = '22023';
    END IF;
    v_request := jsonb_set(
      p_request - 'continuationReceiptDigest',
      '{session,continuationReceiptDigest}',
      p_request -> 'continuationReceiptDigest',true
    );
  END IF;
  RETURN app.private_complete_mfa_factor_legacy_v1(
    v_request,p_factor_kind
  );
EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
  RAISE EXCEPTION 'MFA challenge is unavailable or ambiguous'
    USING ERRCODE = '42501';
END;
$function$;
--> statement-breakpoint

-- Receipt-aware current projection.  The legacy resolver remains available
-- only to owner-only helpers; runtime callers must present the exact receipt.
CREATE FUNCTION app.resolve_mfa_authority_v2(
  p_reference_id uuid,
  p_flow text,
  p_action text,
  p_audience text,
  p_evaluated_at timestamptz,
  p_continuation_receipt_digest bytea
)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_result jsonb;
  v_receipt bytea;
  v_primary_kind text;
  v_authority_at timestamptz := greatest(
    p_evaluated_at,transaction_timestamp()
  );
  v_provenance
    public.tenant_post_primary_platform_federated_provenance%ROWTYPE;
  v_tenant_provenance
    public.tenant_post_primary_federated_provenance%ROWTYPE;
  v_passkey_provenance
    public.tenant_post_primary_passkey_provenance%ROWTYPE;
BEGIN
  v_result := app.resolve_mfa_authority_v1(
    p_reference_id,p_flow,p_action,p_audience,v_authority_at
  );
  IF v_result ->> 'flow' = 'continuation' THEN
    SELECT continuation.primary_kind
      INTO STRICT v_primary_kind
    FROM ONLY public.tenant_post_primary_continuations AS continuation
    WHERE continuation.id = (v_result ->> 'continuationId')::uuid
      AND continuation.tenant_id = (v_result ->> 'tenantId')::uuid
      AND continuation.user_id = (v_result ->> 'userId')::uuid
      AND continuation.version = (v_result ->> 'anchorVersion')::bigint
      AND continuation.expires_at = (v_result ->> 'anchorExpiresAt')::timestamptz;
    IF p_continuation_receipt_digest IS NULL
       OR octet_length(p_continuation_receipt_digest) <> 32
       OR encode(p_continuation_receipt_digest,'hex') = repeat('00',32) THEN
      RAISE EXCEPTION 'continuation receipt is required'
        USING ERRCODE = '42501';
    END IF;
    SELECT continuation.receipt_digest
      INTO STRICT v_receipt
    FROM ONLY public.tenant_post_primary_continuations AS continuation
    WHERE continuation.id = (v_result ->> 'continuationId')::uuid
      AND continuation.receipt_digest = p_continuation_receipt_digest;
    v_result := v_result || jsonb_build_object(
      'primaryKind',v_primary_kind,
      'continuationVersion',(v_result ->> 'anchorVersion')::bigint,
      'continuationExpiresAt',(v_result ->> 'anchorExpiresAt')::timestamptz,
      'continuationReceiptDigest',replace(
        encode(v_receipt,'base64'),E'\n',''
      )
    );
    IF v_primary_kind = 'passkey' THEN
      SELECT provenance.* INTO STRICT v_passkey_provenance
      FROM ONLY public.tenant_post_primary_passkey_provenance AS provenance
      JOIN ONLY public.tenant_post_primary_continuations AS continuation
        ON continuation.tenant_id = provenance.tenant_id
       AND continuation.id = provenance.continuation_id
       AND continuation.user_id = provenance.user_id
       AND continuation.primary_kind = 'passkey'
       AND continuation.passkey_credential_id = provenance.credential_id
       AND continuation.primary_revision = provenance.credential_revision
       AND continuation.state = 'pending'
       AND continuation.version = (v_result ->> 'anchorVersion')::bigint
       AND continuation.expires_at =
           (v_result ->> 'anchorExpiresAt')::timestamptz
      JOIN ONLY public.tenant_mfa_subjects AS subject
        ON subject.tenant_id = continuation.tenant_id
       AND subject.user_id = continuation.user_id
       AND subject.identity_epoch = continuation.identity_epoch
       AND subject.session_invalidation_epoch =
           continuation.session_invalidation_epoch
      JOIN ONLY public.tenants AS tenant
        ON tenant.id = provenance.tenant_id AND tenant.status = 'active'
      JOIN ONLY public.users AS local_user
        ON local_user.id = provenance.user_id AND local_user.active
      JOIN ONLY public.tenant_memberships AS membership
        ON membership.tenant_id = provenance.tenant_id
       AND membership.user_id = provenance.user_id
       AND membership.status = 'active'
      JOIN ONLY public.tenant_webauthn_credentials AS credential
        ON credential.tenant_id = provenance.tenant_id
       AND credential.user_id = provenance.user_id
       AND credential.id = provenance.credential_id
       AND credential.security_revision = provenance.credential_revision
       AND credential.status = 'active'
      WHERE provenance.continuation_id =
          (v_result ->> 'continuationId')::uuid
        AND provenance.tenant_id = (v_result ->> 'tenantId')::uuid
        AND provenance.user_id = (v_result ->> 'userId')::uuid
        AND provenance.primary_kind = 'passkey'
        AND provenance.authentication_method = 'passkey';

      IF v_passkey_provenance.origin = 'session_revalidation' THEN
        PERFORM 1
        FROM ONLY public.auth_sessions AS source_session
        JOIN ONLY public.auth_session_mfa_states AS source_state
          ON source_state.tenant_id = v_passkey_provenance.tenant_id
         AND source_state.session_id = source_session.id
         AND source_state.user_id = v_passkey_provenance.user_id
         AND source_state.primary_kind = 'passkey'
         AND source_state.session_version =
             v_passkey_provenance.source_session_version
        JOIN ONLY public.auth_session_passkey_provenance AS source_provenance
          ON source_provenance.tenant_id = source_state.tenant_id
         AND source_provenance.session_id = source_state.session_id
         AND source_provenance.user_id = source_state.user_id
         AND source_provenance.primary_kind = 'passkey'
         AND source_provenance.credential_id =
             v_passkey_provenance.credential_id
         AND source_provenance.credential_revision =
             v_passkey_provenance.credential_revision
         AND source_provenance.authenticated_at =
             v_passkey_provenance.authenticated_at
        WHERE source_session.id = v_passkey_provenance.source_session_id
          AND source_session.user_id = v_passkey_provenance.user_id
          AND source_session.active_tenant_id =
              v_passkey_provenance.tenant_id
          AND source_session.rotation_family_id =
              v_passkey_provenance.source_session_family_id
          AND source_session.authentication_method = 'passkey'
          AND source_session.absolute_expires_at =
              v_passkey_provenance.source_absolute_expires_at
          AND source_session.revoked_at IS NULL
          AND source_session.idle_expires_at > v_authority_at
          AND source_session.absolute_expires_at > v_authority_at;
        IF NOT FOUND THEN
          RAISE EXCEPTION 'passkey MFA source session is stale'
            USING ERRCODE = '42501';
        END IF;
      ELSIF v_passkey_provenance.origin <> 'initial_login'
         OR v_passkey_provenance.source_session_id IS NOT NULL
         OR v_passkey_provenance.source_session_family_id IS NOT NULL
         OR v_passkey_provenance.source_session_version IS NOT NULL
         OR v_passkey_provenance.source_absolute_expires_at IS NOT NULL THEN
        RAISE EXCEPTION 'passkey MFA continuation origin is invalid'
          USING ERRCODE = '42501';
      END IF;

      v_result := v_result || jsonb_strip_nulls(jsonb_build_object(
        'primaryKind','passkey',
        'continuationOrigin',v_passkey_provenance.origin,
        'authenticationMethod','passkey',
        'providerKind','passkey',
        'credentialId',v_passkey_provenance.credential_id,
        'credentialRevision',v_passkey_provenance.credential_revision,
        'authenticatedAt',v_passkey_provenance.authenticated_at,
        'sourceSessionId',v_passkey_provenance.source_session_id,
        'sourceSessionFamilyId',
          v_passkey_provenance.source_session_family_id,
        'sourceSessionVersion',v_passkey_provenance.source_session_version,
        'sourceAbsoluteExpiresAt',
          v_passkey_provenance.source_absolute_expires_at,
        'federatedReservation',jsonb_strip_nulls(jsonb_build_object(
          'origin',v_passkey_provenance.origin,
          'tenantId',v_passkey_provenance.tenant_id,
          'userId',v_passkey_provenance.user_id,
          'primaryKind','passkey',
          'authenticationMethod','passkey',
          'providerKind','passkey',
          'credentialId',v_passkey_provenance.credential_id,
          'credentialRevision',v_passkey_provenance.credential_revision,
          'authenticatedAt',v_passkey_provenance.authenticated_at,
          'sourceSessionId',v_passkey_provenance.source_session_id,
          'sourceSessionFamilyId',
            v_passkey_provenance.source_session_family_id,
          'sourceSessionVersion',v_passkey_provenance.source_session_version,
          'sourceAbsoluteExpiresAt',
            v_passkey_provenance.source_absolute_expires_at
        ))
      ));
    ELSIF v_primary_kind = 'tenant_platform_provider' THEN
      SELECT provenance.* INTO STRICT v_provenance
      FROM ONLY public.tenant_post_primary_platform_federated_provenance
        AS provenance
      JOIN ONLY public.tenant_post_primary_continuations AS continuation
        ON continuation.tenant_id = provenance.tenant_id
       AND continuation.id = provenance.continuation_id
       AND continuation.user_id = provenance.user_id
       AND continuation.primary_kind = 'tenant_platform_provider'
       AND continuation.platform_provider_id = provenance.platform_provider_id
       AND continuation.binding_id = provenance.binding_id
       AND continuation.external_identity_id = provenance.external_identity_id
       AND continuation.primary_revision = provenance.external_identity_revision
       AND continuation.state = 'pending'
       AND continuation.version = (v_result ->> 'anchorVersion')::bigint
       AND continuation.expires_at = (v_result ->> 'anchorExpiresAt')::timestamptz
      JOIN ONLY public.users AS local_user
        ON local_user.id = provenance.user_id AND local_user.active
      JOIN ONLY public.tenants AS tenant
        ON tenant.id = provenance.tenant_id AND tenant.status = 'active'
      JOIN ONLY public.tenant_memberships AS membership
        ON membership.tenant_id = provenance.tenant_id
       AND membership.id = provenance.membership_id
       AND membership.user_id = provenance.user_id
       AND membership.status = 'active'
      JOIN ONLY public.tenant_mfa_subjects AS subject
        ON subject.tenant_id = provenance.tenant_id
       AND subject.user_id = provenance.user_id
       AND subject.identity_epoch = continuation.identity_epoch
       AND subject.session_invalidation_epoch =
           continuation.session_invalidation_epoch
      JOIN ONLY public.platform_auth_providers AS provider
        ON provider.id = provenance.platform_provider_id
       AND provider.kind = 'oidc' AND provider.enabled
       AND provider.archived_at IS NULL
      JOIN ONLY public.platform_federated_provider_policies AS policy
        ON policy.provider_id = provider.id AND policy.provider_kind = 'oidc'
       AND policy.enabled AND NOT policy.platform_login_enabled
       AND policy.security_revision = provenance.security_revision
      JOIN ONLY public.tenant_platform_auth_provider_bindings AS binding
        ON binding.tenant_id = provenance.tenant_id
       AND binding.id = provenance.binding_id
       AND binding.platform_provider_id = provenance.platform_provider_id
       AND binding.enabled AND binding.archived_at IS NULL
       AND binding.version = provenance.binding_revision
       AND binding.mapping_revision = provenance.mapping_revision
       AND binding.auth_revision = provenance.authorization_revision
       AND binding.current_access_epoch_id = provenance.access_epoch_id
      JOIN ONLY public.tenant_platform_identity_provider_access_epochs AS epoch
        ON epoch.tenant_id = provenance.tenant_id
       AND epoch.id = provenance.access_epoch_id
       AND epoch.binding_id = provenance.binding_id
       AND epoch.platform_provider_id = provenance.platform_provider_id
       AND epoch.source_id = provenance.access_source_id
       AND epoch.started_at <= v_authority_at AND epoch.ended_at IS NULL
      JOIN ONLY public.tenant_authorization_sources AS source
        ON source.tenant_id = epoch.tenant_id AND source.id = epoch.source_id
       AND source.kind = 'identity_provider_access'
       AND source.authoritative AND NOT source.protected
       AND source.key = format(
         'identity_provider_access:%s:%s',epoch.binding_id,epoch.sequence
       )
       AND source.retired_at IS NULL
      JOIN ONLY public.platform_federated_external_identities AS identity
        ON identity.platform_provider_id = provenance.platform_provider_id
       AND identity.id = provenance.external_identity_id
       AND identity.user_id = provenance.user_id
       AND identity.version = provenance.external_identity_revision
       AND identity.retired_at IS NULL
      JOIN ONLY public.platform_federated_external_identity_aliases AS alias
        ON alias.platform_provider_id = identity.platform_provider_id
       AND alias.external_identity_id = identity.id
       AND alias.key_version = provenance.subject_alias_key_version
       AND alias.retired_at IS NULL
      JOIN ONLY public.tenant_platform_federated_provider_access_grants AS grant_record
        ON grant_record.tenant_id = provenance.tenant_id
       AND grant_record.id = provenance.access_grant_id
       AND grant_record.platform_provider_id = provenance.platform_provider_id
       AND grant_record.binding_id = provenance.binding_id
       AND grant_record.access_epoch_id = provenance.access_epoch_id
       AND grant_record.source_id = provenance.access_source_id
       AND grant_record.external_identity_id = provenance.external_identity_id
       AND grant_record.membership_id = provenance.membership_id
       AND grant_record.user_id = provenance.user_id
       AND grant_record.started_at <= v_authority_at
       AND grant_record.ended_at IS NULL
      WHERE provenance.continuation_id =
        (v_result ->> 'continuationId')::uuid
        AND provenance.tenant_id = (v_result ->> 'tenantId')::uuid
        AND provenance.user_id = (v_result ->> 'userId')::uuid;

      IF v_provenance.origin = 'session_revalidation' THEN
        PERFORM 1
        FROM ONLY public.auth_sessions AS source_session
        JOIN ONLY public.auth_session_mfa_states AS source_state
          ON source_state.tenant_id = v_provenance.tenant_id
         AND source_state.session_id = source_session.id
         AND source_state.user_id = v_provenance.user_id
         AND source_state.primary_kind = 'tenant_platform_provider'
         AND source_state.session_version = v_provenance.source_session_version
        JOIN ONLY public.auth_session_tenant_platform_federated_provenance
          AS source_provenance
          ON source_provenance.tenant_id = source_state.tenant_id
         AND source_provenance.session_id = source_state.session_id
         AND source_provenance.user_id = source_state.user_id
         AND source_provenance.primary_kind = 'tenant_platform_provider'
         AND source_provenance.authentication_method = 'oidc'
         AND source_provenance.platform_provider_id =
             v_provenance.platform_provider_id
         AND source_provenance.binding_id = v_provenance.binding_id
         AND source_provenance.access_epoch_id = v_provenance.access_epoch_id
         AND source_provenance.access_source_id = v_provenance.access_source_id
         AND source_provenance.access_grant_id = v_provenance.access_grant_id
         AND source_provenance.membership_id = v_provenance.membership_id
         AND source_provenance.external_identity_id =
             v_provenance.external_identity_id
         AND source_provenance.external_identity_revision =
             v_provenance.external_identity_revision
         AND source_provenance.provider_revision = v_provenance.provider_revision
         AND source_provenance.binding_revision = v_provenance.binding_revision
         AND source_provenance.security_revision = v_provenance.security_revision
         AND source_provenance.mapping_revision = v_provenance.mapping_revision
         AND source_provenance.authorization_revision =
             v_provenance.authorization_revision
         AND source_provenance.subject_alias_key_version =
             v_provenance.subject_alias_key_version
         AND source_provenance.trust_rule_revision =
             v_provenance.trust_rule_revision
         AND source_provenance.authenticated_at = v_provenance.authenticated_at
        WHERE source_session.id = v_provenance.source_session_id
          AND source_session.user_id = v_provenance.user_id
          AND source_session.active_tenant_id = v_provenance.tenant_id
          AND source_session.rotation_family_id =
              v_provenance.source_session_family_id
          AND source_session.authentication_method = 'oidc'
          AND source_session.absolute_expires_at =
              v_provenance.source_absolute_expires_at
          AND source_session.revoked_at IS NULL
          AND source_session.idle_expires_at > v_authority_at
          AND source_session.absolute_expires_at > v_authority_at;
        IF NOT FOUND THEN
          RAISE EXCEPTION 'platform MFA source session is stale'
            USING ERRCODE = '42501';
        END IF;
      ELSIF v_provenance.origin <> 'initial_login'
         OR v_provenance.source_session_id IS NOT NULL
         OR v_provenance.source_session_family_id IS NOT NULL
         OR v_provenance.source_session_version IS NOT NULL
         OR v_provenance.source_absolute_expires_at IS NOT NULL THEN
        RAISE EXCEPTION 'platform MFA continuation origin is invalid'
          USING ERRCODE = '42501';
      END IF;

      v_result := v_result || jsonb_strip_nulls(jsonb_build_object(
        'continuationOrigin',v_provenance.origin,
        'authenticationMethod','oidc',
        'providerKind','oidc',
        'platformProviderId',v_provenance.platform_provider_id,
        'bindingId',v_provenance.binding_id,
        'accessEpochId',v_provenance.access_epoch_id,
        'accessSourceId',v_provenance.access_source_id,
        'accessGrantId',v_provenance.access_grant_id,
        'membershipId',v_provenance.membership_id,
        'externalIdentityId',v_provenance.external_identity_id,
        'externalIdentityRevision',v_provenance.external_identity_revision,
        'providerRevision',v_provenance.provider_revision,
        'bindingRevision',v_provenance.binding_revision,
        'securityRevision',v_provenance.security_revision,
        'mappingRevision',v_provenance.mapping_revision,
        'authorizationRevision',v_provenance.authorization_revision,
        'subjectAliasKeyVersion',v_provenance.subject_alias_key_version,
        'trustRuleRevision',v_provenance.trust_rule_revision,
        'authenticatedAt',v_provenance.authenticated_at,
        'sourceSessionId',v_provenance.source_session_id,
        'sourceSessionFamilyId',v_provenance.source_session_family_id,
        'sourceSessionVersion',v_provenance.source_session_version,
        'sourceAbsoluteExpiresAt',v_provenance.source_absolute_expires_at,
        'federatedReservation',jsonb_strip_nulls(jsonb_build_object(
          'origin',v_provenance.origin,
          'tenantId',v_provenance.tenant_id,
          'userId',v_provenance.user_id,
          'authenticationMethod','oidc',
          'providerKind','oidc',
          'platformProviderId',v_provenance.platform_provider_id,
          'bindingId',v_provenance.binding_id,
          'accessEpochId',v_provenance.access_epoch_id,
          'accessSourceId',v_provenance.access_source_id,
          'accessGrantId',v_provenance.access_grant_id,
          'membershipId',v_provenance.membership_id,
          'externalIdentityId',v_provenance.external_identity_id,
          'externalIdentityRevision',v_provenance.external_identity_revision,
          'providerRevision',v_provenance.provider_revision,
          'bindingRevision',v_provenance.binding_revision,
          'securityRevision',v_provenance.security_revision,
          'mappingRevision',v_provenance.mapping_revision,
          'authorizationRevision',v_provenance.authorization_revision,
          'subjectAliasKeyVersion',v_provenance.subject_alias_key_version,
          'trustRuleRevision',v_provenance.trust_rule_revision,
          'authenticatedAt',v_provenance.authenticated_at,
          'sourceSessionId',v_provenance.source_session_id,
          'sourceSessionFamilyId',v_provenance.source_session_family_id,
          'sourceSessionVersion',v_provenance.source_session_version,
          'sourceAbsoluteExpiresAt',v_provenance.source_absolute_expires_at
        ))
      ));
    ELSIF v_primary_kind = 'tenant_provider' THEN
      SELECT provenance.* INTO STRICT v_tenant_provenance
      FROM ONLY public.tenant_post_primary_federated_provenance AS provenance
      JOIN ONLY public.tenant_post_primary_continuations AS continuation
        ON continuation.tenant_id = provenance.tenant_id
       AND continuation.id = provenance.continuation_id
       AND continuation.user_id = provenance.user_id
       AND continuation.primary_kind = 'tenant_provider'
       AND continuation.provider_id = provenance.provider_id
       AND continuation.binding_id = provenance.binding_id
       AND continuation.provider_kind = provenance.provider_kind
       AND continuation.external_identity_id = provenance.external_identity_id
       AND continuation.primary_revision = provenance.external_identity_revision
       AND continuation.state = 'pending'
       AND continuation.version = (v_result ->> 'anchorVersion')::bigint
       AND continuation.expires_at =
           (v_result ->> 'anchorExpiresAt')::timestamptz
      JOIN ONLY public.users AS local_user
        ON local_user.id = provenance.user_id AND local_user.active
      JOIN ONLY public.tenants AS tenant
        ON tenant.id = provenance.tenant_id AND tenant.status = 'active'
      JOIN ONLY public.tenant_memberships AS membership
        ON membership.tenant_id = provenance.tenant_id
       AND membership.id = provenance.membership_id
       AND membership.user_id = provenance.user_id
       AND membership.status = 'active'
      JOIN ONLY public.tenant_mfa_subjects AS subject
        ON subject.tenant_id = provenance.tenant_id
       AND subject.user_id = provenance.user_id
       AND subject.identity_epoch = continuation.identity_epoch
       AND subject.session_invalidation_epoch =
           continuation.session_invalidation_epoch
      JOIN ONLY public.tenant_auth_providers AS provider
        ON provider.tenant_id = provenance.tenant_id
       AND provider.id = provenance.provider_id
       AND provider.kind = provenance.provider_kind
       AND provider.version = provenance.provider_revision
       AND provider.enabled AND provider.archived_at IS NULL
      JOIN ONLY public.tenant_auth_provider_bindings AS binding
        ON binding.tenant_id = provenance.tenant_id
       AND binding.id = provenance.binding_id
       AND binding.provider_id = provenance.provider_id
       AND binding.version = provenance.binding_revision
       AND binding.mapping_revision = provenance.mapping_revision
       AND binding.auth_revision = provenance.authorization_revision
       AND binding.current_access_epoch_id = provenance.access_epoch_id
       AND binding.enabled AND binding.archived_at IS NULL
      JOIN ONLY public.tenant_federated_provider_policies AS policy
        ON policy.tenant_id = provenance.tenant_id
       AND policy.provider_id = provenance.provider_id
       AND policy.binding_id = provenance.binding_id
       AND policy.provider_kind = provenance.provider_kind
       AND policy.configuration_revision = provenance.configuration_revision
       AND policy.security_revision = provenance.security_revision
       AND policy.plan_revision = provenance.plan_revision
       AND policy.assurance_policy_revision =
           provenance.assurance_policy_revision
       AND policy.enabled
      JOIN ONLY public.tenant_identity_provider_access_epochs AS epoch
        ON epoch.tenant_id = provenance.tenant_id
       AND epoch.id = provenance.access_epoch_id
       AND epoch.binding_id = provenance.binding_id
       AND epoch.provider_id = provenance.provider_id
       AND epoch.source_id = provenance.access_source_id
       AND epoch.started_at <= v_authority_at AND epoch.ended_at IS NULL
      JOIN ONLY public.tenant_authorization_sources AS source
        ON source.tenant_id = provenance.tenant_id
       AND source.id = provenance.access_source_id
       AND source.kind = 'identity_provider_access'
       AND source.authoritative AND NOT source.protected
       AND source.key = format(
         'identity_provider_access:%s:%s',epoch.binding_id,epoch.sequence
       )
       AND source.retired_at IS NULL
      JOIN ONLY public.tenant_federated_external_identities AS identity
        ON identity.tenant_id = provenance.tenant_id
       AND identity.provider_id = provenance.provider_id
       AND identity.binding_id = provenance.binding_id
       AND identity.id = provenance.external_identity_id
       AND identity.user_id = provenance.user_id
       AND identity.version = provenance.external_identity_revision
       AND identity.retired_at IS NULL
      JOIN ONLY public.tenant_federated_provider_access_grants AS grant_record
        ON grant_record.tenant_id = provenance.tenant_id
       AND grant_record.id = provenance.access_grant_id
       AND grant_record.provider_id = provenance.provider_id
       AND grant_record.binding_id = provenance.binding_id
       AND grant_record.access_epoch_id = provenance.access_epoch_id
       AND grant_record.source_id = provenance.access_source_id
       AND grant_record.external_identity_id = provenance.external_identity_id
       AND grant_record.membership_id = provenance.membership_id
       AND grant_record.user_id = provenance.user_id
       AND grant_record.started_at <= v_authority_at
       AND grant_record.ended_at IS NULL
      WHERE provenance.continuation_id =
          (v_result ->> 'continuationId')::uuid
        AND provenance.tenant_id = (v_result ->> 'tenantId')::uuid
        AND provenance.user_id = (v_result ->> 'userId')::uuid
        AND EXISTS (
          SELECT 1
          FROM ONLY public.tenant_federated_external_identity_aliases AS alias
          WHERE alias.tenant_id = identity.tenant_id
            AND alias.provider_id = identity.provider_id
            AND alias.external_identity_id = identity.id
            AND alias.retired_at IS NULL
        );

      IF v_tenant_provenance.origin = 'session_revalidation' THEN
        PERFORM 1
        FROM ONLY public.auth_sessions AS source_session
        JOIN ONLY public.auth_session_mfa_states AS source_state
          ON source_state.tenant_id = v_tenant_provenance.tenant_id
         AND source_state.session_id = source_session.id
         AND source_state.user_id = v_tenant_provenance.user_id
         AND source_state.primary_kind = 'tenant_provider'
         AND source_state.session_version =
             v_tenant_provenance.source_session_version
        JOIN ONLY public.auth_session_federated_provenance AS source_provenance
          ON source_provenance.tenant_id = source_state.tenant_id
         AND source_provenance.session_id = source_state.session_id
         AND source_provenance.user_id = source_state.user_id
         AND source_provenance.primary_kind = 'tenant_provider'
         AND source_provenance.authentication_method =
             v_tenant_provenance.authentication_method
         AND source_provenance.provider_id = v_tenant_provenance.provider_id
         AND source_provenance.binding_id = v_tenant_provenance.binding_id
         AND source_provenance.provider_kind =
             v_tenant_provenance.provider_kind
         AND source_provenance.external_identity_id =
             v_tenant_provenance.external_identity_id
         AND source_provenance.external_identity_revision =
             v_tenant_provenance.external_identity_revision
         AND source_provenance.trust_rule_revision =
             v_tenant_provenance.security_revision
         AND source_provenance.authenticated_at =
             v_tenant_provenance.authenticated_at
        WHERE source_session.id = v_tenant_provenance.source_session_id
          AND source_session.user_id = v_tenant_provenance.user_id
          AND source_session.active_tenant_id = v_tenant_provenance.tenant_id
          AND source_session.rotation_family_id =
              v_tenant_provenance.source_session_family_id
          AND source_session.authentication_method =
              v_tenant_provenance.authentication_method
          AND source_session.absolute_expires_at =
              v_tenant_provenance.source_absolute_expires_at
          AND source_session.revoked_at IS NULL
          AND source_session.idle_expires_at > v_authority_at
          AND source_session.absolute_expires_at > v_authority_at;
        IF NOT FOUND THEN
          RAISE EXCEPTION 'tenant-provider MFA source session is stale'
            USING ERRCODE = '42501';
        END IF;
      ELSIF v_tenant_provenance.origin <> 'initial_login'
         OR v_tenant_provenance.source_session_id IS NOT NULL
         OR v_tenant_provenance.source_session_family_id IS NOT NULL
         OR v_tenant_provenance.source_session_version IS NOT NULL
         OR v_tenant_provenance.source_absolute_expires_at IS NOT NULL THEN
        RAISE EXCEPTION 'tenant-provider MFA continuation origin is invalid'
          USING ERRCODE = '42501';
      END IF;

      v_result := v_result || jsonb_strip_nulls(jsonb_build_object(
        'continuationOrigin',v_tenant_provenance.origin,
        'authenticationMethod',v_tenant_provenance.authentication_method,
        'providerKind',v_tenant_provenance.provider_kind,
        'providerId',v_tenant_provenance.provider_id,
        'bindingId',v_tenant_provenance.binding_id,
        'accessEpochId',v_tenant_provenance.access_epoch_id,
        'accessSourceId',v_tenant_provenance.access_source_id,
        'accessGrantId',v_tenant_provenance.access_grant_id,
        'membershipId',v_tenant_provenance.membership_id,
        'externalIdentityId',v_tenant_provenance.external_identity_id,
        'externalIdentityRevision',
          v_tenant_provenance.external_identity_revision,
        'providerRevision',v_tenant_provenance.provider_revision,
        'bindingRevision',v_tenant_provenance.binding_revision,
        'configurationRevision',v_tenant_provenance.configuration_revision,
        'securityRevision',v_tenant_provenance.security_revision,
        'planRevision',v_tenant_provenance.plan_revision,
        'mappingRevision',v_tenant_provenance.mapping_revision,
        'authorizationRevision',v_tenant_provenance.authorization_revision,
        'assurancePolicyRevision',
          v_tenant_provenance.assurance_policy_revision,
        'authenticatedAt',v_tenant_provenance.authenticated_at,
        'sourceSessionId',v_tenant_provenance.source_session_id,
        'sourceSessionFamilyId',v_tenant_provenance.source_session_family_id,
        'sourceSessionVersion',v_tenant_provenance.source_session_version,
        'sourceAbsoluteExpiresAt',
          v_tenant_provenance.source_absolute_expires_at,
        'federatedReservation',jsonb_strip_nulls(jsonb_build_object(
          'origin',v_tenant_provenance.origin,
          'tenantId',v_tenant_provenance.tenant_id,
          'userId',v_tenant_provenance.user_id,
          'authenticationMethod',v_tenant_provenance.authentication_method,
          'providerKind',v_tenant_provenance.provider_kind,
          'providerId',v_tenant_provenance.provider_id,
          'bindingId',v_tenant_provenance.binding_id,
          'accessEpochId',v_tenant_provenance.access_epoch_id,
          'accessSourceId',v_tenant_provenance.access_source_id,
          'accessGrantId',v_tenant_provenance.access_grant_id,
          'membershipId',v_tenant_provenance.membership_id,
          'externalIdentityId',v_tenant_provenance.external_identity_id,
          'externalIdentityRevision',
            v_tenant_provenance.external_identity_revision,
          'providerRevision',v_tenant_provenance.provider_revision,
          'bindingRevision',v_tenant_provenance.binding_revision,
          'configurationRevision',v_tenant_provenance.configuration_revision,
          'securityRevision',v_tenant_provenance.security_revision,
          'planRevision',v_tenant_provenance.plan_revision,
          'mappingRevision',v_tenant_provenance.mapping_revision,
          'authorizationRevision',v_tenant_provenance.authorization_revision,
          'assurancePolicyRevision',
            v_tenant_provenance.assurance_policy_revision,
          'authenticatedAt',v_tenant_provenance.authenticated_at,
          'sourceSessionId',v_tenant_provenance.source_session_id,
          'sourceSessionFamilyId',
            v_tenant_provenance.source_session_family_id,
          'sourceSessionVersion',v_tenant_provenance.source_session_version,
          'sourceAbsoluteExpiresAt',
            v_tenant_provenance.source_absolute_expires_at
        ))
      ));
    END IF;
  ELSE
    SELECT state.primary_kind INTO STRICT v_primary_kind
    FROM ONLY public.auth_session_mfa_states AS state
    WHERE state.session_id = (v_result ->> 'sessionId')::uuid
      AND state.tenant_id = (v_result ->> 'tenantId')::uuid
      AND state.user_id = (v_result ->> 'userId')::uuid
      AND state.session_version = (v_result ->> 'anchorVersion')::bigint;
    v_result := v_result || jsonb_build_object('primaryKind',v_primary_kind);
    IF p_continuation_receipt_digest IS NOT NULL THEN
      RAISE EXCEPTION 'continuation receipt is forbidden'
        USING ERRCODE = '22023';
    END IF;
  END IF;
  RETURN v_result;
EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
  RAISE EXCEPTION 'MFA authority receipt is unavailable or ambiguous'
    USING ERRCODE = '42501';
END;
$function$;
--> statement-breakpoint

-- Resolve the exact authority bound to a still-pending MFA artifact without
-- claiming it.  Completion transports do not carry an action of their own;
-- the action, audience, policy and source tuple therefore come only from the
-- persisted anchor.  Continuation receipt verification intentionally happens
-- before either the anchor or live authority is projected.
CREATE FUNCTION app.resolve_mfa_completion_artifact_v1(p_request jsonb)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_artifact_kind text;
  v_artifact_id_text text;
  v_artifact_id bytea;
  v_artifact_purpose text;
  v_artifact_mode text;
  v_enrollment_id uuid;
  v_browser_digest bytea;
  v_selected_factor_kind text;
  v_selected_factor_id_text text;
  v_selected_factor_id uuid;
  v_selected_credential_id bytea;
  v_selected_credential_user_id uuid;
  v_selected_credential_discoverable boolean;
  v_receipt bytea;
  v_requested_at timestamptz;
  v_authority_at timestamptz;
  v_anchor_id uuid;
  v_anchor public.tenant_mfa_authority_anchors%ROWTYPE;
  v_anchor_binding jsonb;
  v_live_binding jsonb;
  v_primary_kind text;
  v_result_authentication_method text;
  v_reservation_authentication_method text;
  v_reservation_disposition text;
  v_reservation_origin text;
  v_resolved_user_id uuid;
  v_resolved_identity_epoch bigint;
  v_source_session_id uuid;
  v_source_session_family_id uuid;
  v_source_session_version bigint;
  v_source_absolute_expires_at timestamptz;
BEGIN
  PERFORM app.private_mfa_assert_json_object_v1(
    p_request,
    ARRAY['artifactKind','artifactId','browserDigest','selectedFactorKind',
      'selectedFactorId','continuationReceiptDigest','requestedAt'],
    ARRAY['artifactKind','artifactId','browserDigest','selectedFactorKind',
      'requestedAt'],65536
  );
  IF jsonb_typeof(p_request -> 'artifactKind') IS DISTINCT FROM 'string'
     OR jsonb_typeof(p_request -> 'artifactId') IS DISTINCT FROM 'string'
     OR jsonb_typeof(p_request -> 'browserDigest') IS DISTINCT FROM 'string'
     OR jsonb_typeof(p_request -> 'selectedFactorKind')
          IS DISTINCT FROM 'string'
     OR jsonb_typeof(p_request -> 'requestedAt') IS DISTINCT FROM 'string'
     OR (p_request ? 'selectedFactorId'
       AND jsonb_typeof(p_request -> 'selectedFactorId')
         NOT IN ('string','null'))
     OR (p_request ? 'continuationReceiptDigest'
       AND jsonb_typeof(p_request -> 'continuationReceiptDigest')
         NOT IN ('string','null')) THEN
    RAISE EXCEPTION 'invalid MFA completion artifact request shape'
      USING ERRCODE = '22023';
  END IF;

  v_artifact_kind := p_request ->> 'artifactKind';
  v_artifact_id_text := p_request ->> 'artifactId';
  v_selected_factor_kind := p_request ->> 'selectedFactorKind';
  v_selected_factor_id_text := p_request ->> 'selectedFactorId';
  IF v_artifact_kind NOT IN (
       'totp_enrollment','step_up_challenge',
       'webauthn_registration','webauthn_authentication'
     )
     OR v_selected_factor_kind NOT IN (
       'totp','recovery_code','passkey'
     ) THEN
    RAISE EXCEPTION 'invalid MFA completion artifact selector'
      USING ERRCODE = '22023';
  END IF;
  BEGIN
    v_requested_at := (p_request ->> 'requestedAt')::timestamptz;
  EXCEPTION WHEN OTHERS THEN
    RAISE EXCEPTION 'invalid MFA completion artifact instant'
      USING ERRCODE = '22023';
  END;
  IF v_requested_at IS NULL
     OR date_trunc('microseconds',v_requested_at) <> v_requested_at
     OR abs(extract(epoch FROM
          (transaction_timestamp() - v_requested_at))) > 300 THEN
    RAISE EXCEPTION 'invalid MFA completion artifact instant'
      USING ERRCODE = '22023';
  END IF;
  v_authority_at := greatest(v_requested_at,transaction_timestamp());
  v_browser_digest := app.private_mfa_decode_base64_v1(
    p_request ->> 'browserDigest',32,32
  );
  IF jsonb_typeof(p_request -> 'continuationReceiptDigest') = 'string' THEN
    v_receipt := app.private_mfa_decode_base64_v1(
      p_request ->> 'continuationReceiptDigest',32,32
    );
    IF encode(v_receipt,'hex') = repeat('00',32) THEN
      RAISE EXCEPTION 'invalid MFA continuation receipt'
        USING ERRCODE = '22023';
    END IF;
  END IF;

  IF v_artifact_kind = 'totp_enrollment' THEN
    IF v_selected_factor_kind <> 'totp'
       OR v_selected_factor_id_text IS NOT NULL THEN
      RAISE EXCEPTION 'invalid TOTP enrollment selector'
        USING ERRCODE = '22023';
    END IF;
    v_enrollment_id := app.private_mfa_require_uuidv7_v1(
      v_artifact_id_text
    );
    IF v_enrollment_id::text <> v_artifact_id_text THEN
      RAISE EXCEPTION 'non-canonical MFA enrollment selector'
        USING ERRCODE = '22023';
    END IF;
    SELECT enrollment.authority_anchor_id,enrollment.factor_id
      INTO STRICT v_anchor_id,v_selected_factor_id
    FROM ONLY public.tenant_totp_enrollments AS enrollment
    WHERE enrollment.id = v_enrollment_id
      AND enrollment.browser_digest = v_browser_digest
      AND enrollment.state = 'pending'
      AND enrollment.version = 1
      AND enrollment.expires_at > v_authority_at;
  ELSIF v_artifact_kind = 'step_up_challenge' THEN
    IF v_selected_factor_kind NOT IN ('totp','recovery_code')
       OR (v_selected_factor_kind = 'totp'
         AND v_selected_factor_id_text IS NULL)
       OR (v_selected_factor_kind = 'recovery_code'
         AND v_selected_factor_id_text IS NOT NULL) THEN
      RAISE EXCEPTION 'invalid MFA step-up selector'
        USING ERRCODE = '22023';
    END IF;
    v_artifact_id := app.private_mfa_decode_base64_v1(
      v_artifact_id_text,32,32
    );
    IF v_selected_factor_kind = 'totp' THEN
      v_selected_factor_id := app.private_mfa_require_uuidv7_v1(
        v_selected_factor_id_text
      );
      IF v_selected_factor_id::text <> v_selected_factor_id_text THEN
        RAISE EXCEPTION 'non-canonical MFA step-up factor selector'
          USING ERRCODE = '22023';
      END IF;
    END IF;
    SELECT challenge.authority_anchor_id INTO STRICT v_anchor_id
    FROM ONLY public.tenant_mfa_step_up_challenges AS challenge
    WHERE challenge.id = v_artifact_id
      AND challenge.browser_digest = v_browser_digest
      AND challenge.state = 'pending'
      AND challenge.version = 1
      AND challenge.claimed_factor_kind IS NULL
      AND v_selected_factor_kind = ANY(challenge.allowed_factors)
      AND challenge.expires_at > v_authority_at;
  ELSE
    IF v_selected_factor_kind <> 'passkey'
       OR v_selected_factor_id_text IS NULL THEN
      RAISE EXCEPTION 'invalid WebAuthn artifact selector'
        USING ERRCODE = '22023';
    END IF;
    v_artifact_id := app.private_mfa_decode_base64_v1(
      v_artifact_id_text,32,32
    );
    v_selected_credential_id := app.private_mfa_decode_base64_v1(
      v_selected_factor_id_text,1,4096
    );
    SELECT ceremony.authority_anchor_id,ceremony.purpose,ceremony.mode
      INTO STRICT v_anchor_id,v_artifact_purpose,v_artifact_mode
    FROM ONLY public.tenant_webauthn_ceremonies AS ceremony
    WHERE ceremony.id = v_artifact_id
      AND ceremony.browser_digest = v_browser_digest
      AND ceremony.state = 'pending'
      AND ceremony.version = 1
      AND ceremony.expires_at > v_authority_at
      AND ((v_artifact_kind = 'webauthn_registration'
            AND ceremony.purpose = 'registration')
        OR (v_artifact_kind = 'webauthn_authentication'
            AND ceremony.purpose IN (
              'primary_authentication','continuation_authentication',
              'step_up_authentication'
            )));
  END IF;

  SELECT anchor.* INTO STRICT v_anchor
  FROM ONLY public.tenant_mfa_authority_anchors AS anchor
  WHERE anchor.id = v_anchor_id;

  IF (v_artifact_kind = 'webauthn_authentication' AND NOT (
       (v_artifact_purpose = 'primary_authentication'
         AND v_anchor.flow = 'primary')
       OR (v_artifact_purpose = 'step_up_authentication'
         AND v_anchor.flow = 'session')
       OR (v_artifact_purpose = 'continuation_authentication'
         AND v_anchor.flow = 'continuation')
     ))
     OR (v_artifact_kind = 'webauthn_registration' AND (
       v_artifact_purpose <> 'registration'
       OR v_anchor.flow NOT IN ('session','continuation')
     )) THEN
    RAISE EXCEPTION 'WebAuthn ceremony purpose and authority flow disagree'
      USING ERRCODE = '42501';
  END IF;

  -- This assertion checks a continuation receipt before it projects either
  -- the captured binding or its current authority.  It also enforces terminal
  -- headroom and passkey-primary lifecycle locks used by claim.
  PERFORM app.private_mfa_assert_artifact_receipt_v1(
    v_anchor.id,v_receipt,v_authority_at
  );
  PERFORM app.private_mfa_lock_policy_authority_v1(v_anchor.tenant_id);
  PERFORM app.private_mfa_assert_live_policy_anchor_v1(
    v_anchor.id,v_authority_at
  );
  IF v_anchor.flow <> 'primary' THEN
    PERFORM app.private_mfa_assert_live_passkey_anchor_evidence_v1(
      v_anchor.id,v_authority_at,NULL,NULL
    );
  END IF;

  v_anchor_binding := app.private_mfa_anchor_binding_v1(v_anchor.id);
  IF v_anchor.flow = 'primary' THEN
    IF v_artifact_kind <> 'webauthn_authentication'
       OR v_artifact_purpose <> 'primary_authentication' THEN
      RAISE EXCEPTION 'invalid primary MFA completion artifact'
        USING ERRCODE = '22023';
    END IF;
    v_live_binding := app.resolve_primary_passkey_v1(
      coalesce(v_anchor.user_id,v_anchor.tenant_id),v_anchor.action,
      v_anchor.audience,v_authority_at
    );
    IF jsonb_build_object(
         'tenantId',v_live_binding -> 'tenantId',
         'userId',v_live_binding -> 'userId',
         'identityEpoch',v_live_binding -> 'identityEpoch',
         'action',v_live_binding -> 'action',
         'audience',v_live_binding -> 'audience'
       ) IS DISTINCT FROM jsonb_build_object(
         'tenantId',v_anchor_binding -> 'tenantId',
         'userId',v_anchor_binding -> 'userId',
         'identityEpoch',v_anchor_binding -> 'identityEpoch',
         'action',v_anchor_binding -> 'action',
         'audience',v_anchor_binding -> 'audience'
       ) THEN
      RAISE EXCEPTION 'primary MFA artifact binding drifted'
        USING ERRCODE = '40001';
    END IF;
    SELECT credential.user_id,subject.identity_epoch,
      credential.user_id,credential.discoverable
      INTO STRICT v_resolved_user_id,v_resolved_identity_epoch,
        v_selected_credential_user_id,v_selected_credential_discoverable
    FROM ONLY public.tenant_webauthn_credentials AS credential
    JOIN ONLY public.tenant_mfa_subjects AS subject
      ON subject.tenant_id = credential.tenant_id
     AND subject.user_id = credential.user_id
    JOIN ONLY public.users AS local_user
      ON local_user.id = subject.user_id AND local_user.active
    JOIN ONLY public.tenants AS tenant
      ON tenant.id = subject.tenant_id AND tenant.status = 'active'
    JOIN ONLY public.tenant_memberships AS membership
      ON membership.tenant_id = subject.tenant_id
     AND membership.user_id = subject.user_id
     AND membership.status = 'active'
    WHERE credential.tenant_id = v_anchor.tenant_id
      AND credential.credential_id = v_selected_credential_id
      AND credential.status = 'active'
      AND (v_anchor.user_id IS NULL
        OR credential.user_id = v_anchor.user_id)
    FOR SHARE OF credential,subject,local_user,tenant,membership NOWAIT;
    v_primary_kind := 'passkey';
    v_result_authentication_method := 'passkey';
    v_reservation_disposition := 'create';
    v_reservation_origin := 'initial_login';
  ELSE
    v_live_binding := app.resolve_mfa_authority_v2(
      CASE v_anchor.flow
        WHEN 'session' THEN v_anchor.session_id
        ELSE v_anchor.continuation_id
      END,
      v_anchor.flow,v_anchor.action,v_anchor.audience,
      v_authority_at,v_receipt
    );
    IF jsonb_build_object(
         'flow',v_live_binding -> 'flow',
         'tenantId',v_live_binding -> 'tenantId',
         'userId',v_live_binding -> 'userId',
         'identityEpoch',v_live_binding -> 'identityEpoch',
         'sessionId',v_live_binding -> 'sessionId',
         'sessionFamilyId',v_live_binding -> 'sessionFamilyId',
         'continuationId',v_live_binding -> 'continuationId',
         'anchorVersion',v_live_binding -> 'anchorVersion',
         'anchorExpiresAt',v_live_binding -> 'anchorExpiresAt',
         'anchorRecoveryRestricted',
           v_live_binding -> 'anchorRecoveryRestricted',
         'action',v_live_binding -> 'action',
         'audience',v_live_binding -> 'audience',
         'requirement',v_live_binding -> 'requirement',
         'baselineEvidence',v_live_binding -> 'baselineEvidence'
       ) IS DISTINCT FROM jsonb_build_object(
         'flow',v_anchor_binding -> 'flow',
         'tenantId',v_anchor_binding -> 'tenantId',
         'userId',v_anchor_binding -> 'userId',
         'identityEpoch',v_anchor_binding -> 'identityEpoch',
         'sessionId',v_anchor_binding -> 'sessionId',
         'sessionFamilyId',v_anchor_binding -> 'sessionFamilyId',
         'continuationId',v_anchor_binding -> 'continuationId',
         'anchorVersion',v_anchor_binding -> 'anchorVersion',
         'anchorExpiresAt',v_anchor_binding -> 'anchorExpiresAt',
         'anchorRecoveryRestricted',
           v_anchor_binding -> 'anchorRecoveryRestricted',
         'action',v_anchor_binding -> 'action',
         'audience',v_anchor_binding -> 'audience',
         'requirement',v_anchor_binding -> 'requirement',
         'baselineEvidence',v_anchor_binding -> 'baselineEvidence'
       ) THEN
      RAISE EXCEPTION 'MFA completion artifact binding drifted'
        USING ERRCODE = '40001';
    END IF;
    v_resolved_user_id := v_anchor.user_id;
    v_resolved_identity_epoch := v_anchor.identity_epoch;
    IF v_anchor.flow = 'session' THEN
      SELECT state.primary_kind,session.authentication_method,
        session.id,session.rotation_family_id,state.session_version,
        session.absolute_expires_at
        INTO STRICT v_primary_kind,v_result_authentication_method,
          v_source_session_id,v_source_session_family_id,
          v_source_session_version,v_source_absolute_expires_at
      FROM ONLY public.auth_sessions AS session
      JOIN ONLY public.auth_session_mfa_states AS state
        ON state.tenant_id = v_anchor.tenant_id
       AND state.session_id = session.id
       AND state.user_id = v_anchor.user_id
       AND state.identity_epoch = v_anchor.identity_epoch
       AND state.session_version = v_anchor.anchor_version
      JOIN ONLY public.tenant_mfa_subjects AS subject
        ON subject.tenant_id = state.tenant_id
       AND subject.user_id = state.user_id
       AND subject.identity_epoch = state.identity_epoch
       AND subject.session_invalidation_epoch =
           state.session_invalidation_epoch
      JOIN ONLY public.users AS local_user
        ON local_user.id = state.user_id AND local_user.active
      JOIN ONLY public.tenants AS tenant
        ON tenant.id = state.tenant_id AND tenant.status = 'active'
      JOIN ONLY public.tenant_memberships AS membership
        ON membership.tenant_id = state.tenant_id
       AND membership.user_id = state.user_id
       AND membership.status = 'active'
      WHERE session.id = v_anchor.session_id
        AND session.rotation_family_id = v_anchor.session_family_id
        AND session.active_tenant_id = v_anchor.tenant_id
        AND session.user_id = v_anchor.user_id
        AND session.revoked_at IS NULL
        AND session.idle_expires_at > v_authority_at
        AND session.absolute_expires_at > v_authority_at
      FOR SHARE OF session,state,subject,local_user,tenant,membership NOWAIT;
      IF (v_primary_kind = 'local_credential' AND (
            v_result_authentication_method NOT IN (
              'bootstrap_totp','totp','recovery_code'
            ) OR NOT EXISTS (
              SELECT 1
              FROM ONLY public.auth_session_local_credential_provenance
                AS provenance
              WHERE provenance.tenant_id = v_anchor.tenant_id
                AND provenance.session_id = v_anchor.session_id
                AND provenance.user_id = v_anchor.user_id
                AND provenance.primary_kind = 'local_credential'
            )))
         OR (v_primary_kind = 'passkey'
            AND v_result_authentication_method <> 'passkey')
         OR (v_primary_kind = 'tenant_platform_provider' AND (
            v_result_authentication_method <> 'oidc' OR NOT EXISTS (
              SELECT 1
              FROM ONLY public.auth_session_tenant_platform_federated_provenance
                AS provenance
              WHERE provenance.tenant_id = v_anchor.tenant_id
                AND provenance.session_id = v_anchor.session_id
                AND provenance.user_id = v_anchor.user_id
                AND provenance.primary_kind = 'tenant_platform_provider'
                AND provenance.authentication_method = 'oidc'
            )))
         OR (v_primary_kind = 'tenant_provider' AND NOT EXISTS (
           SELECT 1
           FROM ONLY public.auth_session_federated_provenance AS provenance
           WHERE provenance.tenant_id = v_anchor.tenant_id
             AND provenance.session_id = v_anchor.session_id
             AND provenance.user_id = v_anchor.user_id
             AND provenance.primary_kind = 'tenant_provider'
             AND provenance.authentication_method =
                 v_result_authentication_method
             AND provenance.authentication_method IN ('oidc','saml')
         )) THEN
        RAISE EXCEPTION 'MFA session typed primary method is inconsistent'
          USING ERRCODE = '42501';
      END IF;
    ELSE
      SELECT continuation.primary_kind
        INTO STRICT v_primary_kind
      FROM ONLY public.tenant_post_primary_continuations AS continuation
      JOIN ONLY public.tenant_mfa_subjects AS subject
        ON subject.tenant_id = continuation.tenant_id
       AND subject.user_id = continuation.user_id
       AND subject.identity_epoch = continuation.identity_epoch
       AND subject.session_invalidation_epoch =
           continuation.session_invalidation_epoch
      JOIN ONLY public.users AS local_user
        ON local_user.id = continuation.user_id AND local_user.active
      JOIN ONLY public.tenants AS tenant
        ON tenant.id = continuation.tenant_id AND tenant.status = 'active'
      JOIN ONLY public.tenant_memberships AS membership
        ON membership.tenant_id = continuation.tenant_id
       AND membership.user_id = continuation.user_id
       AND membership.status = 'active'
      WHERE continuation.id = v_anchor.continuation_id
        AND continuation.tenant_id = v_anchor.tenant_id
        AND continuation.user_id = v_anchor.user_id
        AND continuation.state = 'pending'
        AND continuation.version = v_anchor.anchor_version
        AND continuation.expires_at = v_anchor.anchor_expires_at
        AND continuation.expires_at > v_authority_at
      FOR SHARE OF continuation,subject,local_user,tenant,membership NOWAIT;
      v_result_authentication_method := CASE v_primary_kind
        WHEN 'local_credential' THEN 'bootstrap_totp'
        WHEN 'passkey' THEN 'passkey'
        WHEN 'tenant_provider' THEN v_live_binding ->> 'authenticationMethod'
        WHEN 'tenant_platform_provider' THEN
          v_live_binding ->> 'authenticationMethod'
      END;
      v_source_session_id := nullif(
        v_live_binding ->> 'sourceSessionId',''
      )::uuid;
      v_source_session_family_id := nullif(
        v_live_binding ->> 'sourceSessionFamilyId',''
      )::uuid;
      v_source_session_version := nullif(
        v_live_binding ->> 'sourceSessionVersion',''
      )::bigint;
      v_source_absolute_expires_at := nullif(
        v_live_binding ->> 'sourceAbsoluteExpiresAt',''
      )::timestamptz;
    END IF;
    IF v_result_authentication_method IS NULL THEN
      RAISE EXCEPTION 'MFA primary authentication method is unavailable'
        USING ERRCODE = '42501';
    END IF;
    v_reservation_origin := coalesce(
      v_live_binding ->> 'continuationOrigin',
      CASE WHEN v_anchor.flow = 'session'
        THEN 'session_rotation' ELSE 'initial_login' END
    );
    IF v_anchor.flow = 'continuation'
       AND v_artifact_kind IN (
         'totp_enrollment','webauthn_registration'
       ) THEN
      v_reservation_disposition := 'none';
    ELSIF v_anchor.flow = 'session' THEN
      v_reservation_disposition := 'rotate';
      IF v_reservation_origin <> 'session_rotation' THEN
        RAISE EXCEPTION 'MFA session reservation origin is invalid'
          USING ERRCODE = '42501';
      END IF;
    ELSIF v_reservation_origin = 'initial_login' THEN
      v_reservation_disposition := 'create';
      IF v_source_session_id IS NOT NULL
         OR v_source_session_family_id IS NOT NULL
         OR v_source_session_version IS NOT NULL
         OR v_source_absolute_expires_at IS NOT NULL THEN
        RAISE EXCEPTION 'initial-login MFA reservation source is invalid'
          USING ERRCODE = '42501';
      END IF;
    ELSIF v_reservation_origin = 'session_revalidation' THEN
      v_reservation_disposition := 'rotate';
    ELSE
      RAISE EXCEPTION 'MFA continuation reservation origin is invalid'
        USING ERRCODE = '42501';
    END IF;
  END IF;

  IF v_artifact_kind = 'totp_enrollment' THEN
    NULL;
  ELSIF v_selected_factor_kind = 'totp' THEN
    IF NOT coalesce(
      (v_live_binding -> 'totpFactorIds') @>
        jsonb_build_array(v_selected_factor_id::text),false
    ) THEN
      RAISE EXCEPTION 'selected TOTP factor is unavailable'
        USING ERRCODE = '42501';
    END IF;
  ELSIF v_selected_factor_kind = 'recovery_code' THEN
    IF NOT coalesce((v_live_binding ->> 'recoveryAvailable')::boolean,false)
       OR v_live_binding ->> 'recoverySetId' IS NULL THEN
      RAISE EXCEPTION 'selected recovery factor is unavailable'
        USING ERRCODE = '42501';
    END IF;
    v_selected_factor_id := app.private_mfa_require_uuidv7_v1(
      v_live_binding ->> 'recoverySetId'
    );
  ELSIF v_anchor.flow <> 'primary'
     AND v_artifact_kind = 'webauthn_authentication' THEN
    SELECT credential.user_id,credential.discoverable
      INTO STRICT v_selected_credential_user_id,
        v_selected_credential_discoverable
    FROM ONLY public.tenant_webauthn_credentials AS credential
    WHERE credential.tenant_id = v_anchor.tenant_id
      AND credential.user_id = v_anchor.user_id
      AND credential.credential_id = v_selected_credential_id
      AND credential.status = 'active'
    FOR SHARE NOWAIT;
    IF NOT coalesce(
      (v_live_binding -> 'passkeyCredentialIds') @>
        jsonb_build_array(v_selected_factor_id_text),false
    ) THEN
      RAISE EXCEPTION 'selected passkey factor is unavailable'
      USING ERRCODE = '42501';
    END IF;
  END IF;

  -- Authentication ceremonies pin the eligible credential population at
  -- creation.  A known-user ceremony may use only its persisted allow-list;
  -- a discoverable ceremony may use only a credential whose discoverable
  -- bit and tenant/user binding were proved by the locked credential row.
  -- Registration ceremonies deliberately have no credential allow-list.
  IF v_artifact_kind = 'webauthn_authentication' THEN
    IF v_selected_credential_user_id IS NULL
       OR v_selected_credential_user_id IS DISTINCT FROM
            v_resolved_user_id THEN
      RAISE EXCEPTION 'selected passkey ceremony binding is unavailable'
        USING ERRCODE = '42501';
    END IF;
    IF v_artifact_mode = 'known_user' THEN
      PERFORM 1
      FROM ONLY public.tenant_webauthn_ceremony_credentials AS allowed
      WHERE allowed.tenant_id = v_anchor.tenant_id
        AND allowed.ceremony_id = v_artifact_id
        AND allowed.credential_id = v_selected_credential_id
      FOR SHARE NOWAIT;
      IF NOT FOUND THEN
        RAISE EXCEPTION 'selected passkey is outside the ceremony snapshot'
          USING ERRCODE = '42501';
      END IF;
    ELSIF v_artifact_mode = 'discoverable' THEN
      IF v_selected_credential_discoverable IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'selected passkey is not discoverable'
          USING ERRCODE = '42501';
      END IF;
    ELSE
      RAISE EXCEPTION 'invalid WebAuthn authentication ceremony mode'
        USING ERRCODE = '42501';
    END IF;
  END IF;

  v_reservation_authentication_method := CASE v_selected_factor_kind
    WHEN 'totp' THEN 'totp'
    WHEN 'recovery_code' THEN 'recovery_code'
    WHEN 'passkey' THEN 'passkey'
  END;
  IF v_reservation_disposition = 'none' THEN
    v_reservation_authentication_method := NULL;
    v_result_authentication_method := NULL;
    v_source_session_id := NULL;
    v_source_session_family_id := NULL;
    v_source_session_version := NULL;
    v_source_absolute_expires_at := NULL;
  ELSIF v_reservation_disposition = 'create' THEN
    IF v_source_session_id IS NOT NULL
       OR v_source_session_family_id IS NOT NULL
       OR v_source_session_version IS NOT NULL
       OR v_source_absolute_expires_at IS NOT NULL THEN
      RAISE EXCEPTION 'MFA create reservation source is invalid'
        USING ERRCODE = '42501';
    END IF;
  ELSIF v_reservation_disposition = 'rotate' THEN
    IF v_source_session_id IS NULL
       OR v_source_session_family_id IS NULL
       OR v_source_session_version IS NULL
       OR v_source_absolute_expires_at IS NULL
       OR v_source_session_id = v_source_session_family_id
       OR v_source_session_version NOT BETWEEN 1 AND 9007199254740990
       OR v_source_absolute_expires_at <= v_authority_at THEN
      RAISE EXCEPTION 'MFA rotate reservation source is invalid'
        USING ERRCODE = '42501';
    END IF;
  END IF;

  RETURN jsonb_build_object(
    'loadedAt',v_authority_at,
    'artifactKind',v_artifact_kind,
    'artifactId',v_artifact_id_text,
    'browserDigest',p_request ->> 'browserDigest',
    'factorKind',v_selected_factor_kind,
    'factorId',CASE WHEN v_selected_factor_kind = 'passkey'
      THEN v_selected_factor_id_text ELSE v_selected_factor_id::text END,
    'flow',v_anchor.flow,
    'tenantId',v_anchor.tenant_id::text,
    'userId',v_anchor.user_id::text,
    'identityEpoch',coalesce(v_anchor.identity_epoch,0),
    'resolvedUserId',v_resolved_user_id::text,
    'resolvedIdentityEpoch',v_resolved_identity_epoch,
    'sessionId',v_anchor.session_id::text,
    'sessionFamilyId',v_anchor.session_family_id::text,
    'continuationId',v_anchor.continuation_id::text,
    'anchorVersion',coalesce(v_anchor.anchor_version,0),
    'anchorExpiresAt',v_anchor.anchor_expires_at,
    'action',v_anchor.action,
    'audience',v_anchor.audience,
    'reservationDisposition',v_reservation_disposition,
    'reservationAuthenticationMethod',
      v_reservation_authentication_method,
    'resultAuthenticationMethod',v_result_authentication_method,
    'sourceSessionId',v_source_session_id::text,
    'sourceSessionFamilyId',v_source_session_family_id::text,
    'sourceSessionVersion',v_source_session_version,
    'sourceAbsoluteExpiresAt',v_source_absolute_expires_at,
    'continuationReceiptDigest',
      CASE WHEN v_receipt IS NULL THEN NULL ELSE replace(
        encode(v_receipt,'base64'),E'\n',''
      ) END
  );
EXCEPTION WHEN lock_not_available THEN
  RAISE EXCEPTION 'MFA completion artifact authority is busy'
    USING ERRCODE = '40001';
WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
  RAISE EXCEPTION 'MFA completion artifact is unavailable or ambiguous'
    USING ERRCODE = '42501';
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_platform_oidc_claim_policy_v1(
  p_provider_id uuid,
  p_source text
)
RETURNS jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
  SELECT jsonb_build_object(
    'Scalars',coalesce((
      SELECT jsonb_agg(jsonb_build_object(
        'Claim',rule.claim_name,'Required',rule.required
      ) ORDER BY rule.sequence)
      FROM ONLY public.platform_oidc_claim_rules AS rule
      WHERE rule.provider_id = p_provider_id
        AND rule.source = p_source AND rule.kind = 'scalar'
    ),'[]'::jsonb),
    'Profiles',coalesce((
      SELECT jsonb_agg(jsonb_build_object(
        'Claim',rule.claim_name,'Field',rule.profile_field,
        'Required',rule.required
      ) ORDER BY rule.sequence)
      FROM ONLY public.platform_oidc_claim_rules AS rule
      WHERE rule.provider_id = p_provider_id
        AND rule.source = p_source AND rule.kind = 'profile'
    ),'[]'::jsonb),
    'Groups',(
      SELECT jsonb_build_object('Claim',rule.claim_name,'Required',rule.required)
      FROM ONLY public.platform_oidc_claim_rules AS rule
      WHERE rule.provider_id = p_provider_id
        AND rule.source = p_source AND rule.kind = 'groups'
    ),
    'ACR',(
      SELECT jsonb_build_object('Claim',rule.claim_name,'Required',rule.required)
      FROM ONLY public.platform_oidc_claim_rules AS rule
      WHERE rule.provider_id = p_provider_id
        AND rule.source = p_source AND rule.kind = 'acr'
    ),
    'AMR',(
      SELECT jsonb_build_object('Claim',rule.claim_name,'Required',rule.required)
      FROM ONLY public.platform_oidc_claim_rules AS rule
      WHERE rule.provider_id = p_provider_id
        AND rule.source = p_source AND rule.kind = 'amr'
    )
  )
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_tenant_platform_oidc_configuration_record_v1(
  p_tenant_id uuid,
  p_provider_id uuid,
  p_binding_id uuid,
  p_expected_pins jsonb DEFAULT NULL
)
RETURNS jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
  WITH live AS (
    SELECT provider.id AS provider_id, provider.version AS provider_revision,
      binding.tenant_id, binding.id AS binding_id,
      binding.version AS binding_revision,
      binding.mapping_revision, binding.auth_revision,
      binding.current_access_epoch_id AS access_epoch_id,
      epoch.source_id AS access_source_id,
      policy.configuration_revision, policy.security_revision,
      policy.plan_revision, policy.assurance_policy_revision,
      policy.account_mode, binding.jit_mode, binding.no_match_policy,
      configuration.issuer, configuration.client_id,
      configuration.tenant_redirect_uri,
      configuration.post_logout_redirect_uri,
      configuration.extra_scopes, configuration.allow_refresh_token,
      configuration.use_user_info, configuration.client_secret_revision,
      configuration.discovery_revision, discovery.document AS discovery_document,
      discovery.document_digest AS discovery_digest,
      discovery.retrieved_at AS discovery_retrieved_at,
      discovery.fresh_until AS discovery_fresh_until,
      discovery.cacheable AS discovery_cacheable,
      discovery.must_revalidate AS discovery_must_revalidate,
      discovery.client_authentication,
      discovery.signing_algorithms,
      configuration.jwks_revision, jwks.document AS jwks_document,
      jwks.document_digest AS jwks_digest,
      jwks.retrieved_at AS jwks_retrieved_at,
      jwks.fresh_until AS jwks_fresh_until,
      jwks.cacheable AS jwks_cacheable,
      jwks.must_revalidate AS jwks_must_revalidate
    FROM ONLY public.tenants AS tenant
    JOIN ONLY public.tenant_platform_auth_provider_bindings AS binding
      ON binding.tenant_id = tenant.id AND binding.id = p_binding_id
     AND binding.platform_provider_id = p_provider_id
     AND binding.enabled AND binding.archived_at IS NULL
     AND binding.current_access_epoch_id IS NOT NULL
    JOIN ONLY public.platform_auth_providers AS provider
      ON provider.id = binding.platform_provider_id
     AND provider.kind = 'oidc' AND provider.enabled
     AND provider.archived_at IS NULL
    JOIN ONLY public.platform_federated_provider_policies AS policy
      ON policy.provider_id = provider.id AND policy.provider_kind = 'oidc'
     AND policy.enabled AND NOT policy.platform_login_enabled
     AND policy.account_mode <> 'disabled'
    JOIN ONLY public.tenant_platform_identity_provider_access_epochs AS epoch
      ON epoch.tenant_id = binding.tenant_id
     AND epoch.id = binding.current_access_epoch_id
     AND epoch.binding_id = binding.id
     AND epoch.platform_provider_id = binding.platform_provider_id
     AND epoch.ended_at IS NULL
    JOIN ONLY public.tenant_authorization_sources AS source
      ON source.tenant_id = epoch.tenant_id AND source.id = epoch.source_id
     AND source.kind = 'identity_provider_access'
     AND source.authoritative AND NOT source.protected
     AND source.key = format(
       'identity_provider_access:%s:%s', epoch.binding_id, epoch.sequence
     )
     AND source.retired_at IS NULL
    JOIN ONLY public.platform_oidc_provider_configurations AS configuration
      ON configuration.provider_id = provider.id
     AND configuration.version = policy.configuration_revision
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
     AND discovery.cacheable AND discovery.fresh_until > statement_timestamp()
    JOIN ONLY public.platform_oidc_jwks_snapshots AS jwks
      ON jwks.provider_id = configuration.provider_id
     AND jwks.revision = configuration.jwks_revision
     AND jwks.cacheable AND jwks.fresh_until > statement_timestamp()
    WHERE tenant.id = p_tenant_id AND tenant.status = 'active'
  ), projected AS (
    SELECT live.*, jsonb_build_object(
      'provider', jsonb_build_object(
        'scope', 'platform', 'providerId', live.provider_id::text
      ),
      'admission', jsonb_build_object(
        'tenantId', live.tenant_id::text, 'bindingId', live.binding_id::text
      ),
      'providerRevision', CASE WHEN p_expected_pins IS NULL
        THEN live.provider_revision
        ELSE (p_expected_pins ->> 'providerRevision')::bigint END,
      'bindingRevision', live.binding_revision,
      'configurationRevision', live.configuration_revision,
      'securityRevision', live.security_revision,
      'mappingRevision', live.mapping_revision,
      'authorizationRevision', live.auth_revision,
      'assurancePolicyRevision', live.assurance_policy_revision,
      'clientSecretRevision', live.client_secret_revision,
      'discoveryRevision', live.discovery_revision,
      'discoveryDigest', replace(encode(live.discovery_digest, 'base64'), E'\n', ''),
      'jwksRevision', live.jwks_revision,
      'jwksDigest', replace(encode(live.jwks_digest, 'base64'), E'\n', '')
    ) AS pins
    FROM live
  )
  SELECT jsonb_build_object(
    'authorization', jsonb_build_object(
      'provider', projected.pins -> 'provider',
      'admission', projected.pins -> 'admission',
      'providerRevision', CASE WHEN p_expected_pins IS NULL
        THEN projected.provider_revision
        ELSE (p_expected_pins ->> 'providerRevision')::bigint END,
      'bindingRevision', projected.binding_revision,
      'configurationRevision', projected.configuration_revision,
      'securityRevision', projected.security_revision,
      'mappingRevision', projected.mapping_revision,
      'authorizationRevision', projected.auth_revision,
      'assurancePolicyRevision', projected.assurance_policy_revision,
      'clientSecretRevision', projected.client_secret_revision,
      'clientId', projected.client_id,
      -- Tenant-bound authorization never projects the future direct redirect.
      'redirectUri', projected.tenant_redirect_uri,
      'postLogoutRedirectUri', projected.post_logout_redirect_uri,
      'extraScopes', to_jsonb(projected.extra_scopes),
      'allowRefreshToken', projected.allow_refresh_token,
      'useUserInfo', projected.use_user_info
    ),
    'issuer', projected.issuer,
    'discoveryRevision', projected.discovery_revision,
    'discoveryDocument', replace(encode(projected.discovery_document, 'base64'), E'\n', ''),
    'discoveryDigest', replace(encode(projected.discovery_digest, 'base64'), E'\n', ''),
    'discoveryCache', jsonb_build_object(
      'retrievedAt', to_jsonb(projected.discovery_retrieved_at),
      'freshUntil', to_jsonb(projected.discovery_fresh_until),
      'cacheable', projected.discovery_cacheable,
      'mustRevalidate', projected.discovery_must_revalidate
    ),
    'discoveryPolicy', jsonb_build_object(
      'clientAuthentication', projected.client_authentication,
      'signingAlgorithms', to_jsonb(projected.signing_algorithms)
    ),
    'jwksDocument', replace(encode(projected.jwks_document, 'base64'), E'\n', ''),
    'jwksDigest', replace(encode(projected.jwks_digest, 'base64'), E'\n', ''),
    'jwksRevision', projected.jwks_revision,
    'jwksCache', jsonb_build_object(
      'retrievedAt', to_jsonb(projected.jwks_retrieved_at),
      'freshUntil', to_jsonb(projected.jwks_fresh_until),
      'cacheable', projected.jwks_cacheable,
      'mustRevalidate', projected.jwks_must_revalidate
    ),
    'idTokenClaims', app.private_platform_oidc_claim_policy_v1(
      projected.provider_id, 'id_token'
    ),
    'userInfoClaims', app.private_platform_oidc_claim_policy_v1(
      projected.provider_id, 'userinfo'
    ),
    -- These values are derived under the same live joins as the public pins.
    -- They never cross the Go-facing configuration boundary; transaction
    -- persistence consumes them and callback/apply revalidate them live.
    'runtime', jsonb_build_object(
      'planRevision', projected.plan_revision,
      'accessEpochId', projected.access_epoch_id::text,
      'accessSourceId', projected.access_source_id::text
    ),
    'runtimeAdmissionPolicy', jsonb_build_object(
      'accountMode', projected.account_mode,
      'jitMode', projected.jit_mode,
      'noMatchPolicy', projected.no_match_policy
    )
  )
  FROM projected
  WHERE p_expected_pins IS NULL OR projected.pins = p_expected_pins;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.create_tenant_platform_oidc_authentication_transaction_v1(
  p_request jsonb
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
#variable_conflict use_variable
DECLARE
  begin_request jsonb;
  current_request jsonb;
  pins jsonb;
  provider_projection jsonb;
  admission jsonb;
  live_record jsonb;
  operation_run_id uuid;
  transaction_id bytea;
  operation_digest bytea;
  receipt_digest bytea;
  network_digest bytea;
  account_digest bytea;
  provider_digest bytea;
  state_digest bytea;
  browser_digest bytea;
  previous_browser_digest bytea;
  nonce_digest bytea;
  verifier_ciphertext bytea;
  discovery_digest bytea;
  jwks_digest bytea;
  tenant_id uuid;
  provider_id uuid;
  binding_id uuid;
  access_epoch_id uuid;
  access_source_id uuid;
  verifier_key_version integer;
  scopes text[];
  created_at timestamptz;
  expires_at timestamptz;
  operation_lock bigint;
  receipt_lock bigint;
  state_lock bigint;
  current_browser_lock bigint;
  previous_browser_lock bigint;
  transaction_lock bigint;
  existing public.tenant_platform_oidc_authentication_transactions%ROWTYPE;
BEGIN
  PERFORM app.private_mfa_assert_json_object_v1(
    p_request, ARRAY['begin','current','previousBrowserDigest'],
    ARRAY['begin','current'], 131072
  );
  begin_request := p_request -> 'begin';
  current_request := p_request -> 'current';
  PERFORM app.private_mfa_assert_json_object_v1(
    begin_request,
    ARRAY['operationRunId','receiptDigest','networkDigest','accountDigest','providerDigest'],
    ARRAY['operationRunId','receiptDigest','networkDigest','accountDigest','providerDigest'],
    8192
  );
  PERFORM app.private_mfa_assert_json_object_v1(
    current_request,
    ARRAY['id','stateDigest','browserDigest','nonceDigest','verifierKeyVersion',
      'verifierCiphertext','pins','clientId','redirectUri','postLogoutRedirectUri',
      'returnPath','scopes','allowRefreshToken','useUserInfo','createdAt',
      'expiresAt','state','version'],
    ARRAY['id','stateDigest','browserDigest','nonceDigest','verifierKeyVersion',
      'verifierCiphertext','pins','clientId','redirectUri','postLogoutRedirectUri',
      'returnPath','scopes','allowRefreshToken','useUserInfo','createdAt',
      'expiresAt','state','version'], 65536
  );
  pins := current_request -> 'pins';
  PERFORM app.private_mfa_assert_json_object_v1(
    pins,
    ARRAY['provider','admission','providerRevision','bindingRevision',
      'configurationRevision','securityRevision',
      'mappingRevision','authorizationRevision','assurancePolicyRevision',
      'clientSecretRevision','discoveryRevision','discoveryDigest',
      'jwksRevision','jwksDigest'],
    ARRAY['provider','admission','providerRevision','bindingRevision',
      'configurationRevision','securityRevision',
      'mappingRevision','authorizationRevision','assurancePolicyRevision',
      'clientSecretRevision','discoveryRevision','discoveryDigest',
      'jwksRevision','jwksDigest'], 32768
  );
  provider_projection := pins -> 'provider';
  admission := pins -> 'admission';
  PERFORM app.private_mfa_assert_json_object_v1(
    provider_projection, ARRAY['scope','providerId'],
    ARRAY['scope','providerId'], 4096
  );
  PERFORM app.private_mfa_assert_json_object_v1(
    admission, ARRAY['tenantId','bindingId'],
    ARRAY['tenantId','bindingId'], 4096
  );
  IF provider_projection ->> 'scope' <> 'platform'
     OR jsonb_typeof(current_request -> 'scopes') <> 'array'
     OR jsonb_typeof(current_request -> 'allowRefreshToken') <> 'boolean'
     OR jsonb_typeof(current_request -> 'useUserInfo') <> 'boolean'
     OR current_request ->> 'state' <> 'pending'
     OR (current_request ->> 'version')::bigint <> 1 THEN
    RAISE EXCEPTION 'invalid tenant platform OIDC transaction request'
      USING ERRCODE = '22023';
  END IF;
  operation_run_id := app.private_mfa_require_uuidv7_v1(
    begin_request ->> 'operationRunId'
  );
  provider_id := app.private_mfa_require_uuidv7_v1(
    provider_projection ->> 'providerId'
  );
  tenant_id := app.private_mfa_require_uuidv7_v1(admission ->> 'tenantId');
  binding_id := app.private_mfa_require_uuidv7_v1(admission ->> 'bindingId');
  transaction_id := app.private_mfa_decode_base64_v1(
    current_request ->> 'id', 32, 32
  );
  receipt_digest := app.private_mfa_decode_base64_v1(
    begin_request ->> 'receiptDigest', 32, 32
  );
  network_digest := app.private_mfa_decode_base64_v1(
    begin_request ->> 'networkDigest', 32, 32
  );
  account_digest := app.private_mfa_decode_base64_v1(
    begin_request ->> 'accountDigest', 32, 32
  );
  provider_digest := app.private_mfa_decode_base64_v1(
    begin_request ->> 'providerDigest', 32, 32
  );
  state_digest := app.private_mfa_decode_base64_v1(
    current_request ->> 'stateDigest', 32, 32
  );
  browser_digest := app.private_mfa_decode_base64_v1(
    current_request ->> 'browserDigest', 32, 32
  );
  nonce_digest := app.private_mfa_decode_base64_v1(
    current_request ->> 'nonceDigest', 32, 32
  );
  verifier_ciphertext := app.private_mfa_decode_base64_v1(
    current_request ->> 'verifierCiphertext', 16, 4096
  );
  discovery_digest := app.private_mfa_decode_base64_v1(
    pins ->> 'discoveryDigest', 32, 32
  );
  jwks_digest := app.private_mfa_decode_base64_v1(
    pins ->> 'jwksDigest', 32, 32
  );
  IF p_request ? 'previousBrowserDigest' THEN
    previous_browser_digest := app.private_mfa_decode_base64_v1(
      p_request ->> 'previousBrowserDigest', 32, 32
    );
  END IF;
  verifier_key_version := (current_request ->> 'verifierKeyVersion')::integer;
  SELECT array_agg(item.value #>> '{}' ORDER BY item.ordinality)
    INTO scopes
  FROM jsonb_array_elements(current_request -> 'scopes') WITH ORDINALITY
    AS item(value, ordinality);
  created_at := (current_request ->> 'createdAt')::timestamptz;
  expires_at := (current_request ->> 'expiresAt')::timestamptz;
  IF encode(transaction_id, 'hex') = repeat('00', 32)
     OR encode(receipt_digest, 'hex') = repeat('00', 32)
     OR encode(state_digest, 'hex') = repeat('00', 32)
     OR encode(browser_digest, 'hex') = repeat('00', 32)
     OR encode(nonce_digest, 'hex') = repeat('00', 32)
     OR state_digest IN (browser_digest, nonce_digest)
     OR browser_digest = nonce_digest
     OR verifier_key_version NOT BETWEEN 1 AND 32767
     OR created_at NOT BETWEEN statement_timestamp() - interval '5 minutes'
                              AND statement_timestamp() + interval '30 seconds'
     OR expires_at - created_at NOT BETWEEN interval '1 minute' AND interval '15 minutes'
     OR cardinality(scopes) NOT BETWEEN 1 AND 64 OR scopes[1] <> 'openid'
     OR cardinality(scopes) <> (SELECT count(DISTINCT value) FROM unnest(scopes) AS scope(value))
     OR current_request ->> 'returnPath' !~ '^/[^\\[:cntrl:]]*$'
     OR left(current_request ->> 'returnPath', 2) = '//' THEN
    RAISE EXCEPTION 'invalid tenant platform OIDC transaction request'
      USING ERRCODE = '22023';
  END IF;
  live_record := app.private_tenant_platform_oidc_configuration_record_v1(
    tenant_id, provider_id, binding_id, pins
  );
  IF live_record IS NULL
     OR live_record #>> '{authorization,clientId}'
        IS DISTINCT FROM current_request ->> 'clientId'
     OR live_record #>> '{authorization,redirectUri}'
        IS DISTINCT FROM current_request ->> 'redirectUri'
     OR live_record #>> '{authorization,postLogoutRedirectUri}'
        IS DISTINCT FROM current_request ->> 'postLogoutRedirectUri'
     OR to_jsonb(ARRAY['openid']::text[] || ARRAY(
          SELECT value #>> '{}'
          FROM jsonb_array_elements(
            live_record #> '{authorization,extraScopes}'
          ) WITH ORDINALITY AS scope(value, ordinality)
          ORDER BY ordinality
        )) IS DISTINCT FROM current_request -> 'scopes'
     OR (live_record #>> '{authorization,allowRefreshToken}')::boolean
        IS DISTINCT FROM (current_request ->> 'allowRefreshToken')::boolean
     OR (live_record #>> '{authorization,useUserInfo}')::boolean
        IS DISTINCT FROM (current_request ->> 'useUserInfo')::boolean
     OR NOT EXISTS (
       SELECT 1 FROM ONLY public.identity_keyring_versions AS keyring
       WHERE keyring.key_version = verifier_key_version
         AND keyring.is_active AND keyring.retired_at IS NULL
     ) THEN
    RETURN NULL;
  END IF;
  access_epoch_id := app.private_mfa_require_uuidv7_v1(
    live_record #>> '{runtime,accessEpochId}'
  );
  access_source_id := app.private_mfa_require_uuidv7_v1(
    live_record #>> '{runtime,accessSourceId}'
  );

  operation_digest := sha256(convert_to(p_request::text, 'UTF8'));
  operation_lock := hashtextextended(
    'federated-transaction:oidc:operation:' || operation_run_id::text, 17283101
  );
  PERFORM pg_advisory_xact_lock(operation_lock);
  SELECT transaction_row.* INTO existing
  FROM ONLY public.tenant_platform_oidc_authentication_transactions AS transaction_row
  WHERE transaction_row.operation_run_id = operation_run_id FOR UPDATE;
  IF FOUND THEN
    IF existing.operation_digest IS DISTINCT FROM operation_digest THEN
      RETURN NULL;
    END IF;
    RETURN jsonb_build_object(
      'transactionId', replace(encode(existing.transaction_id, 'base64'), E'\n', ''),
      'version', existing.version, 'state', existing.state, 'replayed', true
    );
  END IF;
  IF EXISTS (
    SELECT 1
    FROM ONLY public.tenant_federated_authentication_transactions AS legacy
    WHERE legacy.protocol = 'oidc'
      AND legacy.operation_run_id = operation_run_id
  ) OR expires_at <= clock_timestamp() THEN
    RETURN NULL;
  END IF;

  receipt_lock := hashtextextended(
    'federated-transaction:receipt:' || encode(receipt_digest,'hex'), 17283101
  );
  state_lock := hashtextextended(
    'federated-transaction:oidc:state:' || encode(state_digest,'hex'), 17283101
  );
  current_browser_lock := hashtextextended(
    'federated-transaction:oidc:browser:' || encode(browser_digest,'hex'), 17283101
  );
  transaction_lock := hashtextextended(
    'federated-transaction:oidc:id:' || encode(transaction_id,'hex'), 17283101
  );
  PERFORM pg_advisory_xact_lock(receipt_lock);
  PERFORM pg_advisory_xact_lock(state_lock);
  IF previous_browser_digest IS NULL THEN
    PERFORM pg_advisory_xact_lock(current_browser_lock);
  ELSE
    previous_browser_lock := hashtextextended(
      'federated-transaction:oidc:browser:' ||
        encode(previous_browser_digest,'hex'), 17283101
    );
    PERFORM pg_advisory_xact_lock(
      least(current_browser_lock,previous_browser_lock)
    );
    IF current_browser_lock <> previous_browser_lock THEN
      PERFORM pg_advisory_xact_lock(
        greatest(current_browser_lock,previous_browser_lock)
      );
    END IF;
  END IF;
  PERFORM pg_advisory_xact_lock(transaction_lock);

  IF previous_browser_digest IS NOT NULL THEN
    UPDATE ONLY public.tenant_platform_oidc_authentication_transactions AS old_transaction
    SET state = 'expired', version = old_transaction.version + 1,
        completed_at = greatest(statement_timestamp(), old_transaction.created_at),
        failure_reason = 'expired'
    WHERE old_transaction.browser_digest = previous_browser_digest
      AND old_transaction.state IN ('pending','claimed');
    UPDATE ONLY public.tenant_federated_authentication_transactions AS legacy
    SET state = 'expired', version = legacy.version + 1,
        completed_at = greatest(
          created_at, legacy.created_at,
          coalesce(legacy.claimed_at,legacy.created_at)
        ),
        failure_reason = 'expired'
    WHERE legacy.protocol = 'oidc'
      AND legacy.browser_digest = previous_browser_digest
      AND legacy.state IN ('pending','claimed');
  END IF;
  IF EXISTS (
    SELECT 1 FROM ONLY public.tenant_platform_oidc_authentication_transactions AS collision
    WHERE collision.transaction_id = transaction_id
       OR collision.receipt_digest = receipt_digest
       OR collision.state_digest = state_digest
       OR ((previous_browser_digest IS NULL
             OR previous_browser_digest <> browser_digest)
         AND collision.browser_digest = browser_digest
         AND collision.state IN ('pending','claimed'))
  ) OR EXISTS (
    SELECT 1
    FROM ONLY public.tenant_federated_authentication_transactions AS legacy
    WHERE legacy.receipt_digest = receipt_digest
       OR (legacy.protocol = 'oidc' AND (
         legacy.transaction_id = transaction_id
         OR legacy.state_digest = state_digest
         OR ((previous_browser_digest IS NULL
               OR previous_browser_digest <> browser_digest)
           AND legacy.browser_digest = browser_digest
           AND legacy.state IN ('pending','claimed'))
       ))
  ) THEN RETURN NULL; END IF;

  INSERT INTO public.tenant_platform_oidc_authentication_transactions (
    transaction_id, tenant_id, platform_provider_id, binding_id,
    provider_kind, protocol, access_epoch_id, access_source_id,
    operation_run_id, operation_digest, receipt_digest, network_digest,
    account_digest, provider_digest, state_digest, browser_digest,
    nonce_digest, provider_revision, binding_revision,
    configuration_revision, security_revision, plan_revision,
    mapping_revision, authorization_revision, assurance_policy_revision,
    client_secret_revision, discovery_revision, discovery_digest,
    jwks_revision, jwks_digest, verifier_key_version, verifier_ciphertext,
    client_id, tenant_redirect_uri, post_logout_redirect_uri, scopes,
    allow_refresh_token, use_user_info, return_path, state, version,
    created_at, expires_at
  ) VALUES (
    transaction_id, tenant_id, provider_id, binding_id, 'oidc', 'oidc',
    access_epoch_id, access_source_id, operation_run_id, operation_digest,
    receipt_digest, network_digest, account_digest, provider_digest,
    state_digest, browser_digest, nonce_digest,
    (pins ->> 'providerRevision')::bigint,
    (pins ->> 'bindingRevision')::bigint,
    (pins ->> 'configurationRevision')::bigint,
    (pins ->> 'securityRevision')::bigint,
    (live_record #>> '{runtime,planRevision}')::bigint,
    (pins ->> 'mappingRevision')::bigint,
    (pins ->> 'authorizationRevision')::bigint,
    (pins ->> 'assurancePolicyRevision')::bigint,
    (pins ->> 'clientSecretRevision')::bigint,
    (pins ->> 'discoveryRevision')::bigint, discovery_digest,
    (pins ->> 'jwksRevision')::bigint, jwks_digest,
    verifier_key_version, verifier_ciphertext,
    current_request ->> 'clientId', current_request ->> 'redirectUri',
    current_request ->> 'postLogoutRedirectUri', scopes,
    (current_request ->> 'allowRefreshToken')::boolean,
    (current_request ->> 'useUserInfo')::boolean,
    current_request ->> 'returnPath', 'pending', 1, created_at, expires_at
  );
  RETURN jsonb_build_object(
    'transactionId', replace(encode(transaction_id, 'base64'), E'\n', ''),
    'version', 1, 'state', 'pending', 'replayed', false
  );
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range
  OR data_exception THEN
  RAISE EXCEPTION 'invalid tenant platform OIDC transaction request'
    USING ERRCODE = '22023';
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_tenant_platform_session_authority_live_v1(
  p_tenant_id uuid,
  p_session_id uuid,
  p_observed_at timestamptz
)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
  SELECT EXISTS (
    SELECT 1
    FROM ONLY public.auth_sessions AS session
    JOIN ONLY public.auth_session_mfa_states AS state
      ON state.session_id = session.id
     AND state.tenant_id = p_tenant_id
     AND state.primary_kind = 'tenant_platform_provider'
    JOIN ONLY public.auth_session_tenant_platform_federated_provenance AS provenance
      ON provenance.tenant_id = state.tenant_id
     AND provenance.session_id = state.session_id
     AND provenance.user_id = state.user_id
    JOIN ONLY public.users AS local_user
      ON local_user.id = provenance.user_id AND local_user.active
    JOIN ONLY public.tenants AS tenant
      ON tenant.id = provenance.tenant_id AND tenant.status = 'active'
    JOIN ONLY public.tenant_memberships AS membership
      ON membership.tenant_id = provenance.tenant_id
     AND membership.id = provenance.membership_id
     AND membership.user_id = provenance.user_id
     AND membership.status = 'active'
    JOIN ONLY public.tenant_mfa_subjects AS subject
      ON subject.tenant_id = provenance.tenant_id
     AND subject.user_id = provenance.user_id
     AND subject.identity_epoch = state.identity_epoch
     AND subject.session_invalidation_epoch = state.session_invalidation_epoch
    JOIN ONLY public.platform_auth_providers AS provider
      ON provider.id = provenance.platform_provider_id
     AND provider.kind = 'oidc' AND provider.enabled
     AND provider.archived_at IS NULL
    JOIN ONLY public.platform_federated_provider_policies AS policy
      ON policy.provider_id = provider.id AND policy.provider_kind = 'oidc'
     AND policy.enabled AND NOT policy.platform_login_enabled
     AND policy.security_revision = provenance.security_revision
    JOIN ONLY public.tenant_platform_auth_provider_bindings AS binding
      ON binding.tenant_id = provenance.tenant_id
     AND binding.id = provenance.binding_id
     AND binding.platform_provider_id = provenance.platform_provider_id
     AND binding.enabled AND binding.archived_at IS NULL
     AND binding.version = provenance.binding_revision
     AND binding.mapping_revision = provenance.mapping_revision
     AND binding.auth_revision = provenance.authorization_revision
     AND binding.current_access_epoch_id = provenance.access_epoch_id
    JOIN ONLY public.tenant_platform_identity_provider_access_epochs AS epoch
      ON epoch.tenant_id = provenance.tenant_id
     AND epoch.id = provenance.access_epoch_id
     AND epoch.binding_id = provenance.binding_id
     AND epoch.platform_provider_id = provenance.platform_provider_id
     AND epoch.source_id = provenance.access_source_id
     AND epoch.ended_at IS NULL AND epoch.started_at <= p_observed_at
    JOIN ONLY public.tenant_authorization_sources AS source
      ON source.tenant_id = epoch.tenant_id AND source.id = epoch.source_id
     AND source.kind = 'identity_provider_access'
     AND source.authoritative AND NOT source.protected
     AND source.key = format(
       'identity_provider_access:%s:%s', epoch.binding_id, epoch.sequence
     )
     AND source.retired_at IS NULL
    JOIN ONLY public.platform_federated_external_identities AS identity
      ON identity.platform_provider_id = provenance.platform_provider_id
     AND identity.id = provenance.external_identity_id
     AND identity.user_id = provenance.user_id
     AND identity.version = provenance.external_identity_revision
     AND identity.retired_at IS NULL
    JOIN ONLY public.platform_federated_external_identity_aliases AS alias
      ON alias.platform_provider_id = identity.platform_provider_id
     AND alias.external_identity_id = identity.id
     AND alias.key_version = provenance.subject_alias_key_version
     AND alias.retired_at IS NULL
    JOIN ONLY public.tenant_platform_federated_provider_access_grants AS grant_record
      ON grant_record.tenant_id = provenance.tenant_id
     AND grant_record.id = provenance.access_grant_id
     AND grant_record.binding_id = provenance.binding_id
     AND grant_record.access_epoch_id = provenance.access_epoch_id
     AND grant_record.source_id = provenance.access_source_id
     AND grant_record.external_identity_id = provenance.external_identity_id
     AND grant_record.membership_id = provenance.membership_id
     AND grant_record.user_id = provenance.user_id
     AND grant_record.ended_at IS NULL
     AND grant_record.started_at <= p_observed_at
    WHERE session.id = p_session_id
      AND session.active_tenant_id = p_tenant_id
      AND session.user_id = provenance.user_id
      AND session.authentication_method = 'oidc'
      AND session.revoked_at IS NULL
      AND session.idle_expires_at > p_observed_at
      AND session.absolute_expires_at > p_observed_at
  );
$function$;

CREATE FUNCTION app.load_tenant_platform_federated_session_revalidation_v1(
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
  tenant_id uuid;
  session_id uuid;
  audience text;
  session_record public.auth_sessions%ROWTYPE;
  state_record public.auth_session_mfa_states%ROWTYPE;
  provenance_record
    public.auth_session_tenant_platform_federated_provenance%ROWTYPE;
  live_identity_epoch bigint;
  live_session_epoch bigint;
  user_active boolean;
  tenant_active boolean;
  membership_active boolean;
  membership_id uuid;
  policy_user_id uuid;
  live_primary_revision bigint;
  primary_active boolean;
  requirement jsonb;
  evidence jsonb;
  policies jsonb;
  factors jsonb;
  trust jsonb;
BEGIN
  PERFORM app.private_mfa_assert_json_object_v1(
    p_lookup, ARRAY['sessionId','tenantId','audience'],
    ARRAY['sessionId','tenantId','audience'], 16384
  );
  tenant_id := app.private_mfa_require_uuidv7_v1(p_lookup ->> 'tenantId');
  session_id := app.private_mfa_require_uuidv7_v1(p_lookup ->> 'sessionId');
  audience := p_lookup ->> 'audience';
  IF NOT app.private_mfa_safe_text_v1(audience,256) THEN
    RAISE EXCEPTION 'invalid tenant platform session revalidation lookup'
      USING ERRCODE = '22023';
  END IF;

  SELECT session.* INTO STRICT session_record
  FROM ONLY public.auth_sessions AS session
  WHERE session.id = session_id AND session.active_tenant_id = tenant_id;
  SELECT state.* INTO STRICT state_record
  FROM ONLY public.auth_session_mfa_states AS state
  WHERE state.tenant_id = tenant_id AND state.session_id = session_id
    AND state.user_id = session_record.user_id
    AND state.primary_kind = 'tenant_platform_provider'
    AND state.audience = audience;
  SELECT provenance.* INTO STRICT provenance_record
  FROM ONLY public.auth_session_tenant_platform_federated_provenance
    AS provenance
  WHERE provenance.tenant_id = tenant_id
    AND provenance.session_id = session_id
    AND provenance.user_id = state_record.user_id
    AND provenance.primary_kind = 'tenant_platform_provider';

  SELECT subject.identity_epoch,subject.session_invalidation_epoch,
         local_user.active,tenant.status = 'active',membership.status = 'active',
         membership.id
    INTO STRICT live_identity_epoch,live_session_epoch,user_active,
      tenant_active,membership_active,membership_id
  FROM ONLY public.tenant_mfa_subjects AS subject
  JOIN ONLY public.users AS local_user ON local_user.id = subject.user_id
  JOIN ONLY public.tenants AS tenant ON tenant.id = subject.tenant_id
  JOIN ONLY public.tenant_memberships AS membership
    ON membership.tenant_id = subject.tenant_id
   AND membership.user_id = subject.user_id
  WHERE subject.tenant_id = tenant_id AND subject.user_id = state_record.user_id;

  SELECT identity.version,(
    identity.retired_at IS NULL
    AND identity.version = provenance_record.external_identity_revision
    AND provider.enabled
    AND provider.archived_at IS NULL AND binding.enabled
    AND binding.archived_at IS NULL
    AND binding.version = provenance_record.binding_revision
    AND binding.mapping_revision = provenance_record.mapping_revision
    AND binding.auth_revision = provenance_record.authorization_revision
    AND binding.current_access_epoch_id = provenance_record.access_epoch_id
    AND policy.enabled AND NOT policy.platform_login_enabled
    AND policy.security_revision = provenance_record.security_revision
    AND access_grant.id IS NOT NULL AND access_epoch.id IS NOT NULL
    AND access_source.id IS NOT NULL
    AND EXISTS (
      SELECT 1
      FROM ONLY public.platform_federated_external_identity_aliases AS alias
      WHERE alias.platform_provider_id = identity.platform_provider_id
        AND alias.external_identity_id = identity.id
        AND alias.key_version = provenance_record.subject_alias_key_version
        AND alias.retired_at IS NULL
    )
  ) INTO STRICT live_primary_revision,primary_active
  FROM ONLY public.platform_federated_external_identities AS identity
  JOIN ONLY public.platform_auth_providers AS provider
    ON provider.id = identity.platform_provider_id AND provider.kind = 'oidc'
  JOIN ONLY public.tenant_platform_auth_provider_bindings AS binding
    ON binding.tenant_id = tenant_id
   AND binding.id = provenance_record.binding_id
   AND binding.platform_provider_id = identity.platform_provider_id
  JOIN ONLY public.platform_federated_provider_policies AS policy
    ON policy.provider_id = identity.platform_provider_id
   AND policy.provider_kind = 'oidc'
  LEFT JOIN ONLY public.tenant_platform_federated_provider_access_grants
    AS access_grant
    ON access_grant.tenant_id = tenant_id
   AND access_grant.id = provenance_record.access_grant_id
   AND access_grant.binding_id = binding.id
   AND access_grant.access_epoch_id = provenance_record.access_epoch_id
   AND access_grant.source_id = provenance_record.access_source_id
   AND access_grant.external_identity_id = identity.id
   AND access_grant.membership_id = membership_id
   AND access_grant.user_id = identity.user_id
   AND access_grant.started_at <= transaction_timestamp()
   AND access_grant.ended_at IS NULL
  LEFT JOIN ONLY public.tenant_platform_identity_provider_access_epochs
    AS access_epoch
    ON access_epoch.tenant_id = access_grant.tenant_id
   AND access_epoch.id = access_grant.access_epoch_id
   AND access_epoch.binding_id = access_grant.binding_id
   AND access_epoch.platform_provider_id = access_grant.platform_provider_id
   AND access_epoch.source_id = access_grant.source_id
   AND access_epoch.started_at <= transaction_timestamp()
   AND access_epoch.ended_at IS NULL
  LEFT JOIN ONLY public.tenant_authorization_sources AS access_source
    ON access_source.tenant_id = access_epoch.tenant_id
   AND access_source.id = access_epoch.source_id
   AND access_source.kind = 'identity_provider_access'
   AND access_source.authoritative AND NOT access_source.protected
   AND access_source.key = format(
     'identity_provider_access:%s:%s',access_epoch.binding_id,
     access_epoch.sequence
   )
   AND access_source.retired_at IS NULL
  WHERE identity.platform_provider_id = provenance_record.platform_provider_id
    AND identity.id = provenance_record.external_identity_id
    AND identity.user_id = state_record.user_id;

  WITH evidence_rows AS (
    SELECT evidence.authenticated_at,evidence.id,
      jsonb_build_object(
        'reference',jsonb_strip_nulls(jsonb_build_object(
          'localCredentialId',evidence.local_credential_id::text,
          'totpFactorId',evidence.totp_factor_id::text,
          'webAuthnCredentialId',evidence.webauthn_credential_id::text,
          'recoveryCodeSetId',evidence.recovery_code_set_id::text
        )),
        'evidence',jsonb_strip_nulls(jsonb_build_object(
          'level',evidence.level,
          'kind',CASE WHEN evidence.kind = 'recovery'
            THEN 'recovery' ELSE 'factor' END,
          'local',evidence.provider_id IS NULL,
          'providerId',evidence.provider_id::text,
          'bindingId',evidence.binding_id::text,
          'authenticatedAt',to_jsonb(evidence.authenticated_at),
          'expiresAt',CASE WHEN evidence.expires_at IS NULL THEN 'null'::jsonb
            ELSE to_jsonb(evidence.expires_at) END,
          'factorRevision',CASE WHEN evidence.factor_revision IS NULL
            THEN 'null'::jsonb ELSE to_jsonb(evidence.factor_revision) END,
          'trustRuleRevision',CASE WHEN evidence.trust_rule_revision IS NULL
            THEN 'null'::jsonb ELSE to_jsonb(evidence.trust_rule_revision) END
        ))
      ) AS document
    FROM ONLY public.auth_session_mfa_evidence AS evidence
    WHERE evidence.tenant_id = tenant_id AND evidence.session_id = session_id
    UNION ALL
    SELECT evidence.authenticated_at,evidence.id,
      jsonb_build_object(
        'reference','{}'::jsonb,
        'evidence',jsonb_build_object(
          'level',evidence.level,'kind','factor','local',false,
          'providerId',evidence.platform_provider_id::text,
          'bindingId',evidence.binding_id::text,
          'authenticatedAt',to_jsonb(evidence.authenticated_at),
          'expiresAt',CASE WHEN evidence.expires_at IS NULL THEN 'null'::jsonb
            ELSE to_jsonb(evidence.expires_at) END,
          'trustRuleRevision',evidence.trust_rule_revision
        )
      )
    FROM ONLY public.auth_session_tenant_platform_federated_evidence AS evidence
    WHERE evidence.tenant_id = tenant_id AND evidence.session_id = session_id
  )
  SELECT coalesce(jsonb_agg(document ORDER BY authenticated_at,id),'[]'::jsonb)
    INTO evidence FROM evidence_rows;

  SELECT coalesce(jsonb_agg(jsonb_build_object(
    'policyId',pin.policy_id::text,'revision',pin.policy_revision
  ) ORDER BY pin.policy_id),'[]'::jsonb) INTO policies
  FROM ONLY public.auth_session_mfa_policy_pins AS pin
  WHERE pin.tenant_id = tenant_id AND pin.session_id = session_id;
  IF jsonb_array_length(evidence) NOT BETWEEN 1 AND 1024
     OR jsonb_array_length(policies) NOT BETWEEN 1 AND 1024 THEN
    RETURN NULL;
  END IF;

  WITH factor_rows AS (
    SELECT evidence.totp_factor_id AS factor_id,'totp'::text AS kind,
      factor.security_revision AS revision,factor.status = 'active' AS active
    FROM ONLY public.auth_session_mfa_evidence AS evidence
    JOIN ONLY public.tenant_totp_factors AS factor
      ON factor.tenant_id = evidence.tenant_id
     AND factor.id = evidence.totp_factor_id
    WHERE evidence.tenant_id = tenant_id AND evidence.session_id = session_id
      AND evidence.totp_factor_id IS NOT NULL
    UNION ALL
    SELECT evidence.webauthn_credential_id,'webauthn',
      credential.security_revision,
      credential.status = 'active'
    FROM ONLY public.auth_session_mfa_evidence AS evidence
    JOIN ONLY public.tenant_webauthn_credentials AS credential
      ON credential.tenant_id = evidence.tenant_id
     AND credential.id = evidence.webauthn_credential_id
    WHERE evidence.tenant_id = tenant_id AND evidence.session_id = session_id
      AND evidence.webauthn_credential_id IS NOT NULL
    UNION ALL
    SELECT evidence.recovery_code_set_id,'recovery',code_set.security_revision,
      code_set.status = 'active'
    FROM ONLY public.auth_session_mfa_evidence AS evidence
    JOIN ONLY public.tenant_recovery_code_sets AS code_set
      ON code_set.tenant_id = evidence.tenant_id
     AND code_set.id = evidence.recovery_code_set_id
    WHERE evidence.tenant_id = tenant_id AND evidence.session_id = session_id
      AND evidence.recovery_code_set_id IS NOT NULL
  )
  SELECT coalesce(jsonb_agg(jsonb_build_object(
    'reference',jsonb_build_object(
      CASE factor.kind WHEN 'totp' THEN 'totpFactorId'
        WHEN 'webauthn' THEN 'webAuthnCredentialId'
        ELSE 'recoveryCodeSetId' END,factor.factor_id::text
    ),'revision',factor.revision,'active',factor.active
  ) ORDER BY factor.kind,factor.factor_id),'[]'::jsonb) INTO factors
  FROM factor_rows AS factor;

  SELECT coalesce(jsonb_agg(jsonb_build_object(
    'provider',jsonb_build_object(
      'scope','platform','providerId',source.platform_provider_id::text
    ),
    'admission',jsonb_build_object(
      'tenantId',source.tenant_id::text,'bindingId',source.binding_id::text
    ),
    'revision',source.trust_rule_revision,
    'active',source.active
  ) ORDER BY source.platform_provider_id,source.binding_id,
      source.trust_rule_revision),'[]'::jsonb) INTO trust
  FROM (
    SELECT evidence.tenant_id,evidence.platform_provider_id,
      evidence.binding_id,evidence.trust_rule_revision,
      bool_and(EXISTS (
        SELECT 1
        FROM ONLY public.platform_auth_providers AS provider
        JOIN ONLY public.platform_federated_provider_policies AS policy
          ON policy.provider_id = provider.id
         AND policy.provider_kind = 'oidc'
        JOIN ONLY public.tenant_platform_auth_provider_bindings AS binding
          ON binding.tenant_id = evidence.tenant_id
         AND binding.id = evidence.binding_id
         AND binding.platform_provider_id = provider.id
        WHERE provider.id = evidence.platform_provider_id
          AND provider.enabled AND provider.archived_at IS NULL
          AND binding.enabled AND binding.archived_at IS NULL
          AND binding.current_access_epoch_id IS NOT NULL
          AND policy.enabled AND NOT policy.platform_login_enabled
          AND policy.security_revision = evidence.trust_rule_revision
          AND (evidence.level = 'primary' OR EXISTS (
            SELECT 1
            FROM ONLY public.platform_federated_trust_rules AS rule
            WHERE rule.provider_id = evidence.platform_provider_id
              AND rule.provider_kind = 'oidc'
              AND rule.revision = evidence.trust_rule_revision
              AND rule.level = evidence.level AND rule.enabled
              AND rule.retired_at IS NULL
          ))
      )) AS active
    FROM ONLY public.auth_session_tenant_platform_federated_evidence AS evidence
    WHERE evidence.tenant_id = tenant_id AND evidence.session_id = session_id
    GROUP BY evidence.tenant_id,evidence.platform_provider_id,
      evidence.binding_id,evidence.trust_rule_revision
  ) AS source;

  policy_user_id := CASE
    WHEN user_active AND tenant_active AND membership_active
      THEN state_record.user_id
    ELSE NULL
  END;
  requirement := app.private_mfa_policy_snapshot_v1(
    tenant_id,policy_user_id,'session.create',transaction_timestamp()
  ) -> 'requirement';
  RETURN jsonb_build_object(
    'lookup',p_lookup,
    'authenticationMethod',session_record.authentication_method,
    'snapshot',jsonb_build_object(
      'sessionId',session_record.id::text,
      'rotationFamilyId',session_record.rotation_family_id::text,
      'version',state_record.session_version,
      'tenantId',tenant_id::text,'userId',state_record.user_id::text,
      'identityEpoch',state_record.identity_epoch,
      'recoveryRestricted',state_record.recovery_restricted,
      'primary',jsonb_build_object(
        'kind','platform_provider_binding',
        'primaryId',provenance_record.external_identity_id::text,
        'primaryRevision',provenance_record.external_identity_revision,
        'provider',jsonb_build_object(
          'scope','platform',
          'providerId',provenance_record.platform_provider_id::text
        ),
        'admission',jsonb_build_object(
          'tenantId',tenant_id::text,
          'bindingId',provenance_record.binding_id::text
        ),
        'externalIdentityId',provenance_record.external_identity_id::text,
        'sessionInvalidationEpoch',state_record.session_invalidation_epoch,
        'authenticatedAt',to_jsonb(provenance_record.authenticated_at)
      ),
      'evidence',evidence,'policyRevisions',policies,
      'issuedAt',to_jsonb(state_record.issued_at),
      'idleExpiresAt',to_jsonb(session_record.idle_expires_at),
      'absoluteExpiresAt',to_jsonb(session_record.absolute_expires_at)
    ),
    'live',jsonb_build_object(
      'tenantId',tenant_id::text,'userId',state_record.user_id::text,
      'audience',audience,
      'sessionActive',session_record.revoked_at IS NULL
        AND session_record.idle_expires_at > transaction_timestamp()
        AND session_record.absolute_expires_at > transaction_timestamp(),
      'rotationFamilyActive',EXISTS (
        SELECT 1 FROM ONLY public.auth_sessions AS family
        WHERE family.user_id = state_record.user_id
          AND family.rotation_family_id = session_record.rotation_family_id
          AND family.revoked_at IS NULL
          AND family.idle_expires_at > transaction_timestamp()
          AND family.absolute_expires_at > transaction_timestamp()
      ),
      'userActive',user_active,'tenantActive',tenant_active,
      'membershipActive',membership_active,
      'identityEpoch',live_identity_epoch,
      'primaryActive',primary_active,
      'primaryRevision',live_primary_revision,
      'sessionInvalidationEpoch',live_session_epoch,
      'factors',factors,'trustRules',trust,'requirement',requirement
    )
  );
EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
  RETURN NULL;
WHEN invalid_text_representation OR data_exception THEN
  RAISE EXCEPTION 'invalid tenant platform session revalidation lookup'
    USING ERRCODE = '22023';
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.apply_tenant_platform_federated_session_revalidation_v1(
  p_mutation jsonb
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
#variable_conflict use_variable
DECLARE
  tenant_id uuid;
  session_id uuid;
  user_id uuid;
  policy_user_id uuid;
  expected_version bigint;
  observed_at timestamptz;
  decision text;
  reason text;
  request_digest bytea;
  live_authority boolean;
  live_requirement jsonb;
  session_record public.auth_sessions%ROWTYPE;
  state_record public.auth_session_mfa_states%ROWTYPE;
  provenance_record public.auth_session_tenant_platform_federated_provenance%ROWTYPE;
  existing public.tenant_platform_federated_session_revalidation_commands%ROWTYPE;
  reservation jsonb;
  new_session_id uuid;
  new_family_id uuid;
  continuation_id uuid;
  token_digest bytea;
  csrf_digest bytea;
  receipt_digest bytea;
  idle_expires_at timestamptz;
  absolute_expires_at timestamptz;
  continuation_expires_at timestamptz;
  result jsonb;
  authority_at timestamptz;
  evidence_count bigint;
BEGIN
  PERFORM app.private_mfa_assert_json_object_v1(
    p_mutation,
    ARRAY['tenantId','sessionId','userId','audience','authenticationMethod',
      'expectedVersion','observedAt','decision','reason','requirement',
      'session','continuation'],
    ARRAY['tenantId','sessionId','userId','audience','authenticationMethod',
      'expectedVersion','observedAt','decision','reason','requirement'], 262144
  );
  tenant_id := app.private_mfa_require_uuidv7_v1(p_mutation ->> 'tenantId');
  session_id := app.private_mfa_require_uuidv7_v1(p_mutation ->> 'sessionId');
  user_id := app.private_mfa_require_uuidv7_v1(p_mutation ->> 'userId');
  expected_version := (p_mutation ->> 'expectedVersion')::bigint;
  observed_at := (p_mutation ->> 'observedAt')::timestamptz;
  authority_at := greatest(observed_at,transaction_timestamp());
  decision := p_mutation ->> 'decision';
  reason := p_mutation ->> 'reason';
  IF expected_version < 1
     OR observed_at NOT BETWEEN transaction_timestamp() - interval '5 minutes'
                           AND transaction_timestamp() + interval '30 seconds'
     OR right(p_mutation ->> 'observedAt',1) <> 'Z'
     OR date_trunc('microseconds',observed_at) <> observed_at
     OR p_mutation ->> 'authenticationMethod'
        NOT IN ('passkey','totp','recovery_code','oidc','saml')
     OR jsonb_typeof(p_mutation -> 'requirement') <> 'object'
     OR NOT (
       (decision = 'usable' AND reason = 'current')
       OR (decision = 'rotate' AND reason = 'policy_refresh')
       OR (decision = 'step_up'
         AND reason IN ('assurance_insufficient','recovery_restricted'))
       OR (decision = 'revoke'
         AND reason IN ('lifecycle','identity_epoch','primary_drift',
           'factor_drift','trust_drift','expired'))
       OR (decision = 'deny' AND reason = 'malformed')
     ) OR (decision = 'rotate') <> (p_mutation ? 'session')
       OR (decision = 'step_up') <> (p_mutation ? 'continuation')
       OR (p_mutation ? 'session' AND p_mutation ? 'continuation') THEN
    RAISE EXCEPTION 'invalid tenant platform session revalidation mutation'
      USING ERRCODE = '22023';
  END IF;
  SELECT session.* INTO STRICT session_record
  FROM ONLY public.auth_sessions AS session
  WHERE session.id = session_id AND session.user_id = user_id
    AND session.active_tenant_id = tenant_id FOR UPDATE;
  SELECT state.* INTO STRICT state_record
  FROM ONLY public.auth_session_mfa_states AS state
  WHERE state.tenant_id = tenant_id AND state.session_id = session_id
    AND state.user_id = user_id
    AND state.primary_kind = 'tenant_platform_provider'
    AND state.audience = p_mutation ->> 'audience' FOR UPDATE;
  SELECT provenance.* INTO STRICT provenance_record
  FROM ONLY public.auth_session_tenant_platform_federated_provenance AS provenance
  WHERE provenance.tenant_id = tenant_id
    AND provenance.session_id = session_id
    AND provenance.user_id = user_id;
  IF session_record.authentication_method IS DISTINCT FROM
       p_mutation ->> 'authenticationMethod'
     OR observed_at < state_record.issued_at THEN
    RAISE EXCEPTION 'tenant platform session authority drifted'
      USING ERRCODE = '40001';
  END IF;
  request_digest := sha256(convert_to(p_mutation::text, 'UTF8'));
  SELECT command.* INTO existing
  FROM ONLY public.tenant_platform_federated_session_revalidation_commands AS command
  WHERE command.tenant_id = tenant_id AND command.session_id = session_id
    AND command.expected_version = expected_version;
  IF FOUND THEN
    IF existing.request_digest = request_digest
       AND existing.decision = decision THEN
      RETURN existing.result_snapshot;
    END IF;
    RAISE EXCEPTION 'tenant platform session replay mismatch'
      USING ERRCODE = '40001';
  END IF;
  IF state_record.session_version <> expected_version THEN
    RAISE EXCEPTION 'tenant platform session command lost CAS'
      USING ERRCODE = '40001';
  END IF;
  live_authority := app.private_tenant_platform_session_authority_live_v1(
    tenant_id, session_id, authority_at
  );
  policy_user_id := CASE WHEN EXISTS (
    SELECT 1
    FROM ONLY public.users AS local_user
    JOIN ONLY public.tenants AS tenant ON tenant.id = tenant_id
    JOIN ONLY public.tenant_memberships AS membership
      ON membership.tenant_id = tenant_id
     AND membership.user_id = local_user.id
    WHERE local_user.id = user_id AND local_user.active
      AND tenant.status = 'active' AND membership.status = 'active'
  ) THEN user_id ELSE NULL END;
  live_requirement := app.private_mfa_policy_snapshot_v1(
    tenant_id,policy_user_id,'session.create',observed_at
  ) -> 'requirement';
  IF jsonb_strip_nulls(p_mutation -> 'requirement') IS DISTINCT FROM
       jsonb_strip_nulls(live_requirement) THEN
    RAISE EXCEPTION 'tenant platform session requirement drifted'
      USING ERRCODE = '40001';
  END IF;
  IF decision IN ('usable','rotate','step_up') AND (
       NOT live_authority
       OR EXISTS (
         SELECT 1
         FROM ONLY public.auth_session_mfa_evidence AS evidence
         WHERE evidence.tenant_id = tenant_id
           AND evidence.session_id = session_id
           AND ((evidence.totp_factor_id IS NOT NULL AND NOT EXISTS (
             SELECT 1 FROM ONLY public.tenant_totp_factors AS factor
             WHERE factor.tenant_id = evidence.tenant_id
               AND factor.id = evidence.totp_factor_id
               AND factor.security_revision = evidence.factor_revision
               AND factor.status = 'active'
           )) OR (evidence.webauthn_credential_id IS NOT NULL AND NOT EXISTS (
             SELECT 1 FROM ONLY public.tenant_webauthn_credentials AS credential
             WHERE credential.tenant_id = evidence.tenant_id
               AND credential.id = evidence.webauthn_credential_id
               AND credential.security_revision = evidence.factor_revision
               AND credential.status = 'active'
           )) OR (evidence.recovery_code_set_id IS NOT NULL AND NOT EXISTS (
             SELECT 1 FROM ONLY public.tenant_recovery_code_sets AS code_set
             WHERE code_set.tenant_id = evidence.tenant_id
               AND code_set.id = evidence.recovery_code_set_id
               AND code_set.security_revision = evidence.factor_revision
               AND code_set.status = 'active'
           )))
       )
       OR EXISTS (
         SELECT 1
         FROM ONLY public.auth_session_tenant_platform_federated_evidence
           AS evidence
         WHERE evidence.tenant_id = tenant_id
           AND evidence.session_id = session_id
           AND NOT EXISTS (
             SELECT 1
             FROM ONLY public.platform_auth_providers AS provider
             JOIN ONLY public.platform_federated_provider_policies AS policy
               ON policy.provider_id = provider.id
              AND policy.provider_kind = 'oidc'
             JOIN ONLY public.tenant_platform_auth_provider_bindings AS binding
               ON binding.tenant_id = evidence.tenant_id
              AND binding.id = evidence.binding_id
              AND binding.platform_provider_id = provider.id
             WHERE provider.id = evidence.platform_provider_id
               AND provider.enabled AND provider.archived_at IS NULL
               AND binding.enabled AND binding.archived_at IS NULL
               AND binding.current_access_epoch_id IS NOT NULL
               AND policy.enabled AND NOT policy.platform_login_enabled
               AND policy.security_revision = evidence.trust_rule_revision
               AND (evidence.level = 'primary' OR EXISTS (
                 SELECT 1
                 FROM ONLY public.platform_federated_trust_rules AS rule
                 WHERE rule.provider_id = evidence.platform_provider_id
                   AND rule.provider_kind = 'oidc'
                   AND rule.revision = evidence.trust_rule_revision
                   AND rule.level = evidence.level AND rule.enabled
                   AND rule.retired_at IS NULL
               ))
           )
       )
     ) THEN
    RAISE EXCEPTION 'tenant platform session authority drifted'
      USING ERRCODE = '40001';
  END IF;

  IF decision = 'rotate' THEN
    reservation := p_mutation -> 'session';
    PERFORM app.private_mfa_assert_json_object_v1(
      reservation,
      ARRAY['sessionId','familyId','tokenDigest','csrfDigest',
        'authenticationMethod','idleExpiresAt','absoluteExpiresAt'],
      ARRAY['sessionId','familyId','tokenDigest','csrfDigest',
        'authenticationMethod','idleExpiresAt','absoluteExpiresAt'], 32768
    );
    new_session_id := app.private_mfa_require_uuidv7_v1(
      reservation ->> 'sessionId'
    );
    new_family_id := app.private_mfa_require_uuidv7_v1(
      reservation ->> 'familyId'
    );
    token_digest := app.private_mfa_decode_base64_v1(
      reservation ->> 'tokenDigest', 32, 32
    );
    csrf_digest := app.private_mfa_decode_base64_v1(
      reservation ->> 'csrfDigest', 32, 32
    );
    idle_expires_at := (reservation ->> 'idleExpiresAt')::timestamptz;
    absolute_expires_at := (reservation ->> 'absoluteExpiresAt')::timestamptz;
    IF new_session_id = session_id OR new_session_id = new_family_id
       OR new_family_id <> session_record.rotation_family_id
       OR reservation ->> 'authenticationMethod' IS DISTINCT FROM
         session_record.authentication_method
       OR token_digest = csrf_digest
       OR encode(token_digest,'hex') = repeat('00',32)
       OR encode(csrf_digest,'hex') = repeat('00',32)
       OR idle_expires_at <= authority_at
       OR absolute_expires_at < idle_expires_at
       OR absolute_expires_at IS DISTINCT FROM
         session_record.absolute_expires_at
       OR idle_expires_at > observed_at + interval '24 hours'
       OR absolute_expires_at > observed_at + interval '31 days'
       OR EXISTS (
         SELECT 1 FROM public.auth_sessions AS collision
         WHERE collision.token_digest IN (token_digest, csrf_digest)
            OR collision.csrf_secret_digest IN (token_digest, csrf_digest)
       ) THEN
      RAISE EXCEPTION 'invalid tenant platform session rotation reservation'
        USING ERRCODE = '22023';
    END IF;
    PERFORM pg_advisory_xact_lock(least(
      hashtextextended(encode(token_digest,'hex'),73124201),
      hashtextextended(encode(csrf_digest,'hex'),73124201)
    ));
    IF hashtextextended(encode(token_digest,'hex'),73124201)
       <> hashtextextended(encode(csrf_digest,'hex'),73124201) THEN
      PERFORM pg_advisory_xact_lock(greatest(
        hashtextextended(encode(token_digest,'hex'),73124201),
        hashtextextended(encode(csrf_digest,'hex'),73124201)
      ));
    END IF;
    IF EXISTS (
      SELECT 1 FROM public.auth_sessions AS collision
      WHERE collision.token_digest IN (token_digest, csrf_digest)
         OR collision.csrf_secret_digest IN (token_digest, csrf_digest)
    ) THEN
      RAISE EXCEPTION 'tenant platform session rotation digest collision'
        USING ERRCODE = '40001';
    END IF;
    UPDATE ONLY public.auth_sessions AS old_session
    SET revoked_at = observed_at,
        revoke_reason = 'platform_federated_session_rotated'
    WHERE old_session.id = session_id AND old_session.revoked_at IS NULL;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'tenant platform session rotation lost CAS'
        USING ERRCODE = '40001';
    END IF;
    INSERT INTO public.auth_sessions (
      id,user_id,rotation_family_id,active_tenant_id,token_digest,
      csrf_secret_digest,authentication_method,mfa_satisfied_at,last_seen_at,
      idle_expires_at,absolute_expires_at,rotated_from_session_id,created_at
    ) VALUES (
      new_session_id,user_id,new_family_id,tenant_id,token_digest,csrf_digest,
      session_record.authentication_method,session_record.mfa_satisfied_at,
      observed_at,idle_expires_at,absolute_expires_at,session_id,observed_at
    );
    INSERT INTO public.auth_session_mfa_states (
      session_id,tenant_id,user_id,session_version,identity_epoch,
      recovery_restricted,audience,primary_kind,
      session_invalidation_epoch,issued_at
    ) VALUES (
      new_session_id,tenant_id,user_id,expected_version + 1,
      state_record.identity_epoch,state_record.recovery_restricted,
      state_record.audience,'tenant_platform_provider',
      state_record.session_invalidation_epoch,observed_at
    );
    INSERT INTO public.auth_session_tenant_platform_federated_provenance
    SELECT provenance.tenant_id,new_session_id,provenance.user_id,
      provenance.primary_kind,provenance.authentication_method,
      provenance.platform_provider_id,provenance.binding_id,
      provenance.access_epoch_id,provenance.access_source_id,
      provenance.access_grant_id,provenance.membership_id,
      provenance.external_identity_id,provenance.external_identity_revision,
      provenance.provider_revision,provenance.binding_revision,
      provenance.security_revision,provenance.mapping_revision,
      provenance.authorization_revision,provenance.subject_alias_key_version,
      provenance.trust_rule_revision,provenance.authenticated_at
    FROM ONLY public.auth_session_tenant_platform_federated_provenance AS provenance
    WHERE provenance.tenant_id = tenant_id AND provenance.session_id = session_id;
    INSERT INTO public.auth_session_mfa_policy_pins
    SELECT pin.tenant_id,new_session_id,pin.policy_id,pin.policy_revision
    FROM ONLY public.auth_session_mfa_policy_pins AS pin
    WHERE pin.tenant_id = tenant_id AND pin.session_id = session_id;
    INSERT INTO public.auth_session_mfa_evidence
    SELECT uuidv7(),evidence.tenant_id,new_session_id,
      evidence.local_credential_id,evidence.totp_factor_id,
      evidence.webauthn_credential_id,evidence.recovery_code_set_id,
      evidence.level,evidence.kind,evidence.provider_id,evidence.binding_id,
      evidence.authenticated_at,evidence.expires_at,
      evidence.factor_revision,evidence.trust_rule_revision
    FROM ONLY public.auth_session_mfa_evidence AS evidence
    WHERE evidence.tenant_id = tenant_id AND evidence.session_id = session_id;
    INSERT INTO public.auth_session_tenant_platform_federated_evidence (
      id,tenant_id,session_id,user_id,platform_provider_id,binding_id,
      external_identity_id,level,authenticated_at,expires_at,trust_rule_revision
    ) SELECT uuidv7(),evidence.tenant_id,new_session_id,evidence.user_id,
      evidence.platform_provider_id,evidence.binding_id,
      evidence.external_identity_id,evidence.level,evidence.authenticated_at,
      evidence.expires_at,evidence.trust_rule_revision
    FROM ONLY public.auth_session_tenant_platform_federated_evidence AS evidence
    WHERE evidence.tenant_id = tenant_id AND evidence.session_id = session_id;
  ELSIF decision = 'step_up' THEN
    SELECT
      (SELECT count(*)
       FROM ONLY public.auth_session_mfa_evidence AS evidence
       WHERE evidence.tenant_id = tenant_id
         AND evidence.session_id = session_id)
      +
      (SELECT count(*)
       FROM ONLY public.auth_session_tenant_platform_federated_evidence
         AS evidence
       WHERE evidence.tenant_id = tenant_id
         AND evidence.session_id = session_id)
      INTO evidence_count;
    IF evidence_count > 1023 THEN
      RAISE EXCEPTION 'tenant platform MFA evidence snapshot limit reached'
        USING ERRCODE = '22023';
    END IF;
    reservation := p_mutation -> 'continuation';
    PERFORM app.private_mfa_assert_json_object_v1(
      reservation, ARRAY['continuationId','receiptDigest','expiresAt'],
      ARRAY['continuationId','receiptDigest','expiresAt'], 16384
    );
    continuation_id := app.private_mfa_require_uuidv7_v1(
      reservation ->> 'continuationId'
    );
    receipt_digest := app.private_mfa_decode_base64_v1(
      reservation ->> 'receiptDigest', 32, 32
    );
    continuation_expires_at := (reservation ->> 'expiresAt')::timestamptz;
    IF encode(receipt_digest,'hex') = repeat('00',32)
       OR date_trunc('milliseconds',continuation_expires_at)
            IS DISTINCT FROM continuation_expires_at
       OR continuation_expires_at <= authority_at
       OR continuation_expires_at > observed_at + interval '15 minutes' THEN
      RAISE EXCEPTION 'invalid tenant platform step-up reservation'
        USING ERRCODE = '22023';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended(
      encode(receipt_digest,'hex'),77191203
    ));
    INSERT INTO public.tenant_post_primary_continuations (
      id,tenant_id,user_id,receipt_digest,identity_epoch,action,audience,
      primary_kind,platform_provider_id,binding_id,provider_kind,
      external_identity_id,primary_revision,session_invalidation_epoch,
      state,version,created_at,expires_at
    ) VALUES (
      continuation_id,tenant_id,user_id,receipt_digest,
      state_record.identity_epoch,'session.create',state_record.audience,
      'tenant_platform_provider',provenance_record.platform_provider_id,
      provenance_record.binding_id,'oidc',provenance_record.external_identity_id,
      provenance_record.external_identity_revision,
      state_record.session_invalidation_epoch,'pending',1,observed_at,
      continuation_expires_at
    );
    INSERT INTO public.tenant_post_primary_continuation_policy_pins
    SELECT pin.tenant_id,continuation_id,pin.policy_id,pin.policy_revision
    FROM ONLY public.auth_session_mfa_policy_pins AS pin
    WHERE pin.tenant_id = tenant_id AND pin.session_id = session_id;
    INSERT INTO public.tenant_post_primary_continuation_evidence (
      id,tenant_id,continuation_id,local_credential_id,totp_factor_id,
      webauthn_credential_id,recovery_code_set_id,level,kind,
      provider_id,binding_id,authenticated_at,expires_at,
      factor_revision,trust_rule_revision
    ) SELECT uuidv7(),evidence.tenant_id,continuation_id,
      evidence.local_credential_id,evidence.totp_factor_id,
      evidence.webauthn_credential_id,evidence.recovery_code_set_id,
      evidence.level,evidence.kind,evidence.provider_id,evidence.binding_id,
      evidence.authenticated_at,evidence.expires_at,
      evidence.factor_revision,evidence.trust_rule_revision
    FROM ONLY public.auth_session_mfa_evidence AS evidence
    WHERE evidence.tenant_id = tenant_id AND evidence.session_id = session_id;
    INSERT INTO public.tenant_post_primary_platform_federated_evidence (
      id,tenant_id,continuation_id,user_id,platform_provider_id,binding_id,
      external_identity_id,level,authenticated_at,expires_at,trust_rule_revision
    ) SELECT uuidv7(),evidence.tenant_id,continuation_id,evidence.user_id,
      evidence.platform_provider_id,evidence.binding_id,
      evidence.external_identity_id,evidence.level,evidence.authenticated_at,
      evidence.expires_at,evidence.trust_rule_revision
    FROM ONLY public.auth_session_tenant_platform_federated_evidence AS evidence
    WHERE evidence.tenant_id = tenant_id AND evidence.session_id = session_id;
    UPDATE ONLY public.auth_session_mfa_states AS state
    SET session_version = state.session_version + 1
    WHERE state.session_id = session_id
      AND state.session_version = expected_version;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'tenant platform session command lost CAS'
        USING ERRCODE = '40001';
    END IF;
    INSERT INTO public.tenant_post_primary_platform_federated_provenance (
      tenant_id,continuation_id,user_id,origin,platform_provider_id,binding_id,
      access_epoch_id,access_source_id,access_grant_id,membership_id,
      external_identity_id,external_identity_revision,provider_revision,
      binding_revision,security_revision,mapping_revision,
      authorization_revision,subject_alias_key_version,trust_rule_revision,
      authenticated_at,source_session_id,source_session_family_id,
      source_session_version,source_absolute_expires_at
    ) VALUES (
      tenant_id,continuation_id,user_id,'session_revalidation',
      provenance_record.platform_provider_id,provenance_record.binding_id,
      provenance_record.access_epoch_id,provenance_record.access_source_id,
      provenance_record.access_grant_id,provenance_record.membership_id,
      provenance_record.external_identity_id,
      provenance_record.external_identity_revision,
      provenance_record.provider_revision,provenance_record.binding_revision,
      provenance_record.security_revision,provenance_record.mapping_revision,
      provenance_record.authorization_revision,
      provenance_record.subject_alias_key_version,
      provenance_record.trust_rule_revision,provenance_record.authenticated_at,
      session_id,session_record.rotation_family_id,expected_version + 1,
      session_record.absolute_expires_at
    );
  ELSIF decision IN ('revoke','deny') THEN
    UPDATE ONLY public.auth_sessions AS family
    SET revoked_at = observed_at,
        revoke_reason = left('platform_federated_revalidation_' || reason, 500)
    WHERE family.user_id = user_id
      AND family.rotation_family_id = session_record.rotation_family_id
      AND family.revoked_at IS NULL;
  ELSE
    UPDATE ONLY public.auth_session_mfa_states AS state
    SET session_version = state.session_version + 1
    WHERE state.session_id = session_id
      AND state.session_version = expected_version;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'tenant platform session command lost CAS'
        USING ERRCODE = '40001';
    END IF;
  END IF;
  result := jsonb_strip_nulls(jsonb_build_object(
    'tenantId',tenant_id::text,'sessionId',session_id::text,
    'expectedVersion',expected_version,'decision',decision,'applied',true,
    'newSessionId',new_session_id::text,
    'continuationId',continuation_id::text
  ));
  INSERT INTO public.tenant_platform_federated_session_revalidation_commands (
    tenant_id,session_id,expected_version,request_digest,decision,
    result_snapshot,applied_at
  ) VALUES (
    tenant_id,session_id,expected_version,request_digest,decision,result,observed_at
  );
  RETURN result;
EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
  RAISE EXCEPTION 'tenant platform session authority is unavailable'
    USING ERRCODE = '40001';
WHEN invalid_text_representation OR numeric_value_out_of_range
  OR data_exception THEN
  RAISE EXCEPTION 'invalid tenant platform session revalidation mutation'
    USING ERRCODE = '22023';
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.publish_platform_oidc_trust_snapshot_v1(p_publication jsonb)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
#variable_conflict use_variable
DECLARE
  discovery jsonb;
  jwks jsonb;
  publication_provider_id uuid;
  expected_provider_version bigint;
  expected_configuration_revision bigint;
  published_discovery_revision bigint;
  published_jwks_revision bigint;
  discovery_document bytea;
  discovery_digest bytea;
  jwks_document bytea;
  jwks_digest bytea;
  discovery_retrieved_at timestamptz;
  discovery_fresh_until timestamptz;
  jwks_retrieved_at timestamptz;
  jwks_fresh_until timestamptz;
  signing_algorithms text[];
  provider_record public.platform_auth_providers%ROWTYPE;
  policy_record public.platform_federated_provider_policies%ROWTYPE;
  configuration_record public.platform_oidc_provider_configurations%ROWTYPE;
  expected_discovery_revision bigint;
  expected_jwks_revision bigint;
  changed_at timestamptz := transaction_timestamp();
  audit_event_id uuid;
  request_id uuid;
  correlation_id uuid;
  reason text;
BEGIN
  PERFORM app.private_mfa_assert_json_object_v1(
    p_publication,
    ARRAY['providerId','expectedProviderVersion','expectedConfigurationRevision',
      'discovery','jwks','auditEventId','requestId','correlationId','reason'],
    ARRAY['providerId','expectedProviderVersion','expectedConfigurationRevision',
      'discovery','jwks','auditEventId','requestId','correlationId','reason'],
    2097152
  );
  discovery := p_publication -> 'discovery';
  jwks := p_publication -> 'jwks';
  PERFORM app.private_mfa_assert_json_object_v1(
    discovery,
    ARRAY['revision','issuer','document','digest','retrievedAt','freshUntil',
      'cacheable','mustRevalidate','clientAuthentication','signingAlgorithms'],
    ARRAY['revision','issuer','document','digest','retrievedAt','freshUntil',
      'cacheable','mustRevalidate','clientAuthentication','signingAlgorithms'],
    1081344
  );
  PERFORM app.private_mfa_assert_json_object_v1(
    jwks,
    ARRAY['revision','document','digest','retrievedAt','freshUntil',
      'cacheable','mustRevalidate'],
    ARRAY['revision','document','digest','retrievedAt','freshUntil',
      'cacheable','mustRevalidate'], 1081344
  );
  publication_provider_id := app.private_mfa_require_uuidv7_v1(
    p_publication ->> 'providerId'
  );
  audit_event_id := app.private_mfa_require_uuidv7_v1(
    p_publication ->> 'auditEventId'
  );
  request_id := app.private_mfa_require_uuidv7_v1(
    p_publication ->> 'requestId'
  );
  correlation_id := app.private_mfa_require_uuidv7_v1(
    p_publication ->> 'correlationId'
  );
  expected_provider_version := (
    p_publication ->> 'expectedProviderVersion'
  )::bigint;
  expected_configuration_revision := (
    p_publication ->> 'expectedConfigurationRevision'
  )::bigint;
  published_discovery_revision := (discovery ->> 'revision')::bigint;
  published_jwks_revision := (jwks ->> 'revision')::bigint;
  discovery_document := app.private_mfa_decode_base64_v1(
    discovery ->> 'document', 2, 1048576
  );
  discovery_digest := app.private_mfa_decode_base64_v1(
    discovery ->> 'digest', 32, 32
  );
  jwks_document := app.private_mfa_decode_base64_v1(
    jwks ->> 'document', 2, 1048576
  );
  jwks_digest := app.private_mfa_decode_base64_v1(
    jwks ->> 'digest', 32, 32
  );
  discovery_retrieved_at := (discovery ->> 'retrievedAt')::timestamptz;
  discovery_fresh_until := (discovery ->> 'freshUntil')::timestamptz;
  jwks_retrieved_at := (jwks ->> 'retrievedAt')::timestamptz;
  jwks_fresh_until := (jwks ->> 'freshUntil')::timestamptz;
  reason := p_publication ->> 'reason';
  SELECT array_agg(item.value #>> '{}' ORDER BY item.ordinality)
    INTO signing_algorithms
  FROM jsonb_array_elements(discovery -> 'signingAlgorithms') WITH ORDINALITY
    AS item(value, ordinality);
  IF expected_provider_version NOT BETWEEN 1 AND 2147483646
     OR expected_configuration_revision NOT BETWEEN 1 AND 9007199254740990
     OR published_discovery_revision NOT BETWEEN 1 AND 9007199254740991
     OR published_jwks_revision NOT BETWEEN 1 AND 9007199254740991
     OR sha256(discovery_document) <> discovery_digest
     OR sha256(jwks_document) <> jwks_digest
     OR discovery ->> 'clientAuthentication'
        NOT IN ('client_secret_basic','client_secret_post')
     OR cardinality(signing_algorithms) NOT BETWEEN 1 AND 16
     OR discovery_retrieved_at NOT BETWEEN changed_at - interval '5 minutes'
                                      AND changed_at + interval '30 seconds'
     OR jwks_retrieved_at NOT BETWEEN changed_at - interval '5 minutes'
                                 AND changed_at + interval '30 seconds'
     OR discovery_fresh_until NOT BETWEEN discovery_retrieved_at
                                      AND discovery_retrieved_at + interval '7 days'
     OR jwks_fresh_until NOT BETWEEN jwks_retrieved_at
                                 AND jwks_retrieved_at + interval '7 days'
     OR ((discovery ->> 'cacheable')::boolean = false
       AND ((discovery ->> 'mustRevalidate')::boolean = false
         OR discovery_fresh_until <> discovery_retrieved_at))
     OR ((jwks ->> 'cacheable')::boolean = false
       AND ((jwks ->> 'mustRevalidate')::boolean = false
         OR jwks_fresh_until <> jwks_retrieved_at))
     OR reason IS NULL
     OR NOT app.private_platform_lifecycle_reason_is_valid_v1(reason) THEN
    RAISE EXCEPTION 'invalid platform OIDC trust publication'
      USING ERRCODE = '22023';
  END IF;
  SELECT provider.* INTO STRICT provider_record
  FROM ONLY public.platform_auth_providers AS provider
  WHERE provider.id = publication_provider_id AND provider.kind = 'oidc'
    AND provider.archived_at IS NULL FOR UPDATE;
  SELECT policy.* INTO STRICT policy_record
  FROM ONLY public.platform_federated_provider_policies AS policy
  WHERE policy.provider_id = publication_provider_id
    AND policy.provider_kind = 'oidc'
    AND NOT policy.platform_login_enabled FOR UPDATE;
  SELECT configuration.* INTO STRICT configuration_record
  FROM ONLY public.platform_oidc_provider_configurations AS configuration
  WHERE configuration.provider_id = publication_provider_id FOR UPDATE;
  IF provider_record.version <> expected_provider_version
     OR configuration_record.version <> expected_configuration_revision
     OR policy_record.configuration_revision <> expected_configuration_revision
     OR discovery ->> 'issuer' IS DISTINCT FROM configuration_record.issuer THEN
    RAISE EXCEPTION 'platform OIDC trust publication lost CAS'
      USING ERRCODE = '40001';
  END IF;
  SELECT CASE WHEN EXISTS (
    SELECT 1 FROM ONLY public.platform_oidc_discovery_snapshots AS snapshot
    WHERE snapshot.provider_id = publication_provider_id
      AND snapshot.revision = configuration_record.discovery_revision
  ) THEN configuration_record.discovery_revision + 1
  ELSE configuration_record.discovery_revision END
  INTO expected_discovery_revision;
  SELECT CASE WHEN EXISTS (
    SELECT 1 FROM ONLY public.platform_oidc_jwks_snapshots AS snapshot
    WHERE snapshot.provider_id = publication_provider_id
      AND snapshot.revision = configuration_record.jwks_revision
  ) THEN configuration_record.jwks_revision + 1
  ELSE configuration_record.jwks_revision END
  INTO expected_jwks_revision;
  IF published_discovery_revision <> expected_discovery_revision
     OR published_jwks_revision <> expected_jwks_revision THEN
    RAISE EXCEPTION 'platform OIDC trust publication revision is not consecutive'
      USING ERRCODE = '40001';
  END IF;
  INSERT INTO public.platform_oidc_discovery_snapshots (
    provider_id, revision, issuer, document, document_digest, retrieved_at,
    fresh_until, cacheable, must_revalidate, client_authentication,
    signing_algorithms
  ) VALUES (
    publication_provider_id, published_discovery_revision,
    configuration_record.issuer,
    discovery_document, discovery_digest, discovery_retrieved_at,
    discovery_fresh_until, (discovery ->> 'cacheable')::boolean,
    (discovery ->> 'mustRevalidate')::boolean,
    discovery ->> 'clientAuthentication', signing_algorithms
  );
  INSERT INTO public.platform_oidc_jwks_snapshots (
    provider_id, revision, document, document_digest, retrieved_at,
    fresh_until, cacheable, must_revalidate
  ) VALUES (
    publication_provider_id, published_jwks_revision, jwks_document,
    jwks_digest,
    jwks_retrieved_at, jwks_fresh_until,
    (jwks ->> 'cacheable')::boolean,
    (jwks ->> 'mustRevalidate')::boolean
  );
  UPDATE ONLY public.platform_oidc_provider_configurations AS configuration
  SET discovery_revision = published_discovery_revision,
      jwks_revision = published_jwks_revision,
      version = configuration.version + 1, updated_at = changed_at
  WHERE configuration.provider_id = publication_provider_id;
  UPDATE ONLY public.platform_federated_provider_policies AS policy
  SET configuration_revision = policy.configuration_revision + 1,
      security_revision = policy.security_revision + 1,
      updated_at = changed_at
  WHERE policy.provider_id = publication_provider_id;
  UPDATE ONLY public.platform_auth_providers AS provider
  SET version = provider.version + 1, updated_at = changed_at
  WHERE provider.id = publication_provider_id;
  PERFORM app.append_platform_audit_event(
    audit_event_id, 'system', NULL,
    'platform.identity_provider.oidc_trust_published',
    'platform_identity_provider', publication_provider_id, request_id,
    correlation_id,
    NULL, NULL, 'oidc', 'success', reason, jsonb_build_object(
      'provider_version', provider_record.version + 1,
      'configuration_revision', configuration_record.version + 1,
      'security_revision', policy_record.security_revision + 1,
      'discovery_revision', published_discovery_revision,
      'jwks_revision', published_jwks_revision
    )
  );
  RETURN jsonb_build_object(
    'providerId', publication_provider_id::text,
    'providerVersion', provider_record.version + 1,
    'configurationRevision', configuration_record.version + 1,
    'securityRevision', policy_record.security_revision + 1,
    'discoveryRevision', published_discovery_revision,
    'jwksRevision', published_jwks_revision
  );
EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
  RAISE EXCEPTION 'platform OIDC trust publication target is unavailable'
    USING ERRCODE = '40001';
WHEN invalid_text_representation OR numeric_value_out_of_range
  OR data_exception THEN
  RAISE EXCEPTION 'invalid platform OIDC trust publication'
    USING ERRCODE = '22023';
END;
$function$;
--> statement-breakpoint

-- Platform-provider contributions participate in the existing field-by-field
-- profile projection. Manual overrides remain authoritative, and provider
-- email is projection data only; it is never used to link accounts.
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
      UNION ALL
      SELECT binding.profile_priority, binding.id,
        contribution.display_name, NULL::text, NULL::text,
        contribution.username, contribution.email
      FROM public.tenant_platform_federated_provider_profile_contributions AS contribution
      JOIN public.tenant_platform_federated_provider_access_grants AS access_grant
        ON access_grant.tenant_id = contribution.tenant_id
       AND access_grant.id = contribution.access_grant_id
      JOIN public.tenant_platform_auth_provider_bindings AS binding
        ON binding.tenant_id = access_grant.tenant_id
       AND binding.id = access_grant.binding_id
       AND binding.platform_provider_id = access_grant.platform_provider_id
       AND binding.current_access_epoch_id = access_grant.access_epoch_id
      JOIN public.platform_auth_providers AS provider
        ON provider.id = binding.platform_provider_id
       AND provider.kind = 'oidc'
      JOIN public.platform_federated_provider_policies AS policy
        ON policy.provider_id = provider.id AND policy.provider_kind = 'oidc'
       AND policy.enabled AND NOT policy.platform_login_enabled
      JOIN public.tenant_platform_identity_provider_access_epochs AS epoch
        ON epoch.tenant_id = access_grant.tenant_id
       AND epoch.id = access_grant.access_epoch_id
       AND epoch.binding_id = access_grant.binding_id
       AND epoch.platform_provider_id = access_grant.platform_provider_id
       AND epoch.source_id = access_grant.source_id
       AND epoch.ended_at IS NULL
      JOIN public.tenant_authorization_sources AS source
        ON source.tenant_id = epoch.tenant_id AND source.id = epoch.source_id
       AND source.kind = 'identity_provider_access'
       AND source.authoritative AND NOT source.protected
       AND source.key = format(
         'identity_provider_access:%s:%s', epoch.binding_id, epoch.sequence
       )
       AND source.retired_at IS NULL
      JOIN public.platform_federated_external_identities AS external_identity
        ON external_identity.platform_provider_id = access_grant.platform_provider_id
       AND external_identity.id = access_grant.external_identity_id
       AND external_identity.user_id = access_grant.user_id
       AND external_identity.retired_at IS NULL
      WHERE access_grant.tenant_id = p_tenant_id
        AND access_grant.membership_id = p_membership_id
        AND access_grant.ended_at IS NULL
        AND contribution.retired_at IS NULL
        AND binding.enabled AND binding.archived_at IS NULL
        AND provider.enabled AND provider.archived_at IS NULL
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

-- Nullable assurance fields are semantically identical when projected as an
-- explicit JSON null or omitted by jsonb_strip_nulls.  Keep the object closed
-- while accepting both canonical database projections and Go wire structs.
CREATE OR REPLACE FUNCTION app.private_federated_assurance_decision_v1(
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
    ARRAY['level','localRequired','freshnessNanoseconds','policyRevisions'],
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
     OR (p_requirement ? 'enrollmentDeadline'
       AND jsonb_typeof(p_requirement -> 'enrollmentDeadline')
         NOT IN ('string','null'))
     OR jsonb_typeof(p_requirement -> 'policyRevisions') <> 'array'
     OR jsonb_array_length(p_requirement -> 'policyRevisions')
       NOT BETWEEN 1 AND 1024 THEN
    RETURN 'denied';
  END IF;

  FOR v_proof IN SELECT value FROM jsonb_array_elements(p_evidence)
  LOOP
    BEGIN
      PERFORM app.private_mfa_assert_json_object_v1(
        v_proof,
        ARRAY['level','kind','local','providerId','bindingId','authenticatedAt',
          'expiresAt','factorRevision','trustRuleRevision'],
        ARRAY['level','kind','local','authenticatedAt'],
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
    IF NOT (v_proof ?& ARRAY[
         'level','kind','local','authenticatedAt'
       ])
       OR v_proof_rank IS NULL
       OR v_proof ->> 'kind' NOT IN ('factor','recovery')
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

CREATE FUNCTION app.apply_tenant_platform_oidc_authentication_v1(
  p_command jsonb
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
#variable_conflict use_variable
DECLARE
  apply_request jsonb;
  authentication_request jsonb;
  plan_request jsonb;
  oidc_request jsonb;
  mapping_request jsonb;
  requirement jsonb;
  live_policy_snapshot jsonb;
  live_requirement jsonb;
  evidence_array jsonb;
  evidence_record jsonb;
  policy_pin jsonb;
  profile_item jsonb;
  profile_fields text[] := ARRAY[]::text[];
  pins jsonb;
  subject_record jsonb;
  subject_envelope jsonb;
  subject_alias jsonb;
  alias_index integer;
  alias_count integer;
  alias_key_versions integer[] := ARRAY[]::integer[];
  alias_digests bytea[] := ARRAY[]::bytea[];
  alias_digest bytea;
  matched_identity_ids uuid[];
  matched_user_ids uuid[];
  reservation jsonb;
  operation_digest bytea;
  transaction_id bytea;
  subject_digest bytea;
  protected_subject_ciphertext bytea;
  protected_subject_nonce bytea;
  token_digest bytea;
  csrf_digest bytea;
  continuation_receipt bytea;
  subject_key_version integer;
  expected_version bigint;
  planned_identity_epoch bigint;
  authenticated_at timestamptz;
  applied_at timestamptz;
  valid_until timestamptz;
  transaction_record public.tenant_platform_oidc_authentication_transactions%ROWTYPE;
  existing_application public.tenant_platform_oidc_authentication_applications%ROWTYPE;
  provider_record public.platform_auth_providers%ROWTYPE;
  policy_record public.platform_federated_provider_policies%ROWTYPE;
  binding_record public.tenant_platform_auth_provider_bindings%ROWTYPE;
  identity_record public.platform_federated_external_identities%ROWTYPE;
  membership_record public.tenant_memberships%ROWTYPE;
  mfa_subject public.tenant_mfa_subjects%ROWTYPE;
  access_grant public.tenant_platform_federated_provider_access_grants%ROWTYPE;
  external_identity_id uuid;
  requested_external_identity_id uuid;
  request_tenant_id uuid;
  request_provider_id uuid;
  request_binding_id uuid;
  planned_user_id uuid;
  policy_user_id uuid;
  user_id uuid;
  membership_id uuid;
  access_grant_id uuid;
  session_id uuid;
  session_family_id uuid;
  continuation_id uuid;
  owns_membership boolean := false;
  created_identity boolean := false;
  disposition text;
  assurance text;
  assurance_decision text;
  has_enrollable_factor boolean;
  live_has_enrollable_factor boolean;
  evidence_level text;
  evidence_authenticated_at timestamptz;
  evidence_expires_at timestamptz;
  evidence_trust_revision bigint;
  primary_evidence_count integer := 0;
  result jsonb;
  profile_display_name text;
  profile_username text;
  profile_email text;
  idle_expires_at timestamptz;
  absolute_expires_at timestamptz;
  continuation_expires_at timestamptz;
BEGIN
  PERFORM app.private_mfa_assert_json_object_v1(
    p_command, ARRAY['operationDigest','apply'],
    ARRAY['operationDigest','apply'], 2097152
  );
  operation_digest := app.private_mfa_decode_base64_v1(
    p_command ->> 'operationDigest', 32, 32
  );
  apply_request := p_command -> 'apply';
  PERFORM app.private_mfa_assert_json_object_v1(
    apply_request,
    ARRAY['authentication','plan','disposition','assurance','appliedAt',
      'session','continuation'],
    ARRAY['authentication','plan','disposition','assurance','appliedAt'], 2097152
  );
  authentication_request := apply_request -> 'authentication';
  plan_request := apply_request -> 'plan';
  PERFORM app.private_mfa_assert_json_object_v1(
    authentication_request,
    ARRAY['protocol','method','tenantId','admission','authenticatedAt',
      'validUntil','evidence','oidc'],
    ARRAY['protocol','method','tenantId','admission','authenticatedAt',
      'validUntil','evidence','oidc'], 1048576
  );
  PERFORM app.private_mfa_assert_json_object_v1(
    authentication_request -> 'admission', ARRAY['tenantId','bindingId'],
    ARRAY['tenantId','bindingId'], 4096
  );
  PERFORM app.private_mfa_assert_json_object_v1(
    authentication_request -> 'oidc',
    ARRAY['transactionId','expectedVersion','pins','completedAt','returnPath'],
    ARRAY['transactionId','expectedVersion','pins','completedAt','returnPath'],
    32768
  );
  PERFORM app.private_mfa_assert_json_object_v1(
    plan_request,
    ARRAY['planRevision','tenantId','userId','identityEpoch',
      'providerRevision','bindingRevision','configurationRevision',
      'securityRevision','mappingRevision','authorizationRevision',
      'policyRevision','roleIds','securityGroupIds','subject','mapping',
      'requirement','hasEnrollableFactor'],
    ARRAY['planRevision','tenantId','identityEpoch','providerRevision',
      'bindingRevision','configurationRevision','securityRevision',
      'mappingRevision','authorizationRevision','policyRevision','roleIds',
      'securityGroupIds','subject','mapping','requirement',
      'hasEnrollableFactor'], 1048576
  );
  oidc_request := authentication_request -> 'oidc';
  transaction_id := app.private_mfa_decode_base64_v1(
    oidc_request ->> 'transactionId', 32, 32
  );
  expected_version := (oidc_request ->> 'expectedVersion')::bigint;
  authenticated_at := (authentication_request ->> 'authenticatedAt')::timestamptz;
  valid_until := (authentication_request ->> 'validUntil')::timestamptz;
  applied_at := (apply_request ->> 'appliedAt')::timestamptz;
  disposition := apply_request ->> 'disposition';
  assurance := apply_request ->> 'assurance';
  pins := oidc_request -> 'pins';
  subject_record := plan_request -> 'subject';
  mapping_request := plan_request -> 'mapping';
  requirement := plan_request -> 'requirement';
  evidence_array := authentication_request -> 'evidence';
  PERFORM app.private_mfa_assert_json_object_v1(
    pins,
    ARRAY['provider','admission','providerRevision','bindingRevision',
      'configurationRevision','securityRevision','mappingRevision',
      'authorizationRevision','assurancePolicyRevision','clientSecretRevision',
      'discoveryRevision','discoveryDigest','jwksRevision','jwksDigest'],
    ARRAY['provider','admission','providerRevision','bindingRevision',
      'configurationRevision','securityRevision','mappingRevision',
      'authorizationRevision','assurancePolicyRevision','clientSecretRevision',
      'discoveryRevision','discoveryDigest','jwksRevision','jwksDigest'], 32768
  );
  PERFORM app.private_mfa_assert_json_object_v1(
    pins -> 'provider', ARRAY['scope','providerId'],
    ARRAY['scope','providerId'], 4096
  );
  PERFORM app.private_mfa_assert_json_object_v1(
    pins -> 'admission', ARRAY['tenantId','bindingId'],
    ARRAY['tenantId','bindingId'], 4096
  );
  request_tenant_id := app.private_mfa_require_uuidv7_v1(
    authentication_request ->> 'tenantId'
  );
  request_provider_id := app.private_mfa_require_uuidv7_v1(
    pins #>> '{provider,providerId}'
  );
  request_binding_id := app.private_mfa_require_uuidv7_v1(
    pins #>> '{admission,bindingId}'
  );
  IF request_tenant_id IS DISTINCT FROM app.private_mfa_require_uuidv7_v1(
       pins #>> '{admission,tenantId}'
     ) OR request_tenant_id IS DISTINCT FROM app.private_mfa_require_uuidv7_v1(
       authentication_request #>> '{admission,tenantId}'
     ) OR request_binding_id IS DISTINCT FROM app.private_mfa_require_uuidv7_v1(
       authentication_request #>> '{admission,bindingId}'
     ) OR pins #>> '{provider,scope}' <> 'platform' THEN
    RAISE EXCEPTION 'invalid tenant platform OIDC admission projection'
      USING ERRCODE = '22023';
  END IF;
  planned_user_id := nullif(plan_request ->> 'userId','')::uuid;
  planned_identity_epoch := (plan_request ->> 'identityEpoch')::bigint;
  has_enrollable_factor := (plan_request ->> 'hasEnrollableFactor')::boolean;
  IF encode(operation_digest, 'hex') = repeat('00', 32)
     OR expected_version < 1 OR disposition NOT IN ('session','continuation')
     OR (disposition = 'session') <> (apply_request ? 'session')
     OR (disposition = 'continuation') <> (apply_request ? 'continuation')
     OR assurance NOT IN ('satisfied','step_up_required','enrollment_only')
     OR (disposition = 'session') <> (assurance = 'satisfied')
     OR authentication_request ->> 'protocol' <> 'oidc'
     OR authentication_request ->> 'method' <> 'oidc'
     OR authentication_request ->> 'tenantId'
        IS DISTINCT FROM authentication_request #>> '{admission,tenantId}'
     OR authentication_request ->> 'tenantId'
         IS DISTINCT FROM plan_request ->> 'tenantId'
     OR (planned_user_id IS NOT NULL AND
       NOT ((uuid_extract_version(planned_user_id) = 7) IS TRUE))
     OR least(
       (plan_request ->> 'planRevision')::bigint,
       (plan_request ->> 'providerRevision')::bigint,
       (plan_request ->> 'bindingRevision')::bigint,
       (plan_request ->> 'configurationRevision')::bigint,
       (plan_request ->> 'securityRevision')::bigint,
       (plan_request ->> 'mappingRevision')::bigint,
       (plan_request ->> 'authorizationRevision')::bigint,
       (plan_request ->> 'policyRevision')::bigint
     ) < 1
     OR jsonb_typeof(evidence_array) <> 'array'
     OR jsonb_array_length(evidence_array) NOT BETWEEN 1 AND 64
     OR jsonb_typeof(plan_request -> 'roleIds') <> 'array'
     OR jsonb_array_length(plan_request -> 'roleIds') <> 0
     OR jsonb_typeof(plan_request -> 'securityGroupIds') <> 'array'
     OR jsonb_array_length(plan_request -> 'securityGroupIds') <> 0
     OR (planned_user_id IS NULL) <> (planned_identity_epoch = 0)
     OR authenticated_at > applied_at
     OR valid_until <= authenticated_at OR valid_until < applied_at
     OR (oidc_request ->> 'completedAt')::timestamptz
        IS DISTINCT FROM authenticated_at
     OR oidc_request ->> 'returnPath' IS NULL
     OR applied_at NOT BETWEEN transaction_timestamp() - interval '5 minutes'
                           AND transaction_timestamp() + interval '30 seconds'
     OR applied_at - authenticated_at > interval '15 minutes' THEN
    RAISE EXCEPTION 'invalid tenant platform OIDC apply request'
      USING ERRCODE = '22023';
  END IF;
  PERFORM app.private_mfa_assert_json_object_v1(
    subject_record,
    ARRAY['externalIdentityId','aliases','envelope'],
    ARRAY['externalIdentityId','aliases','envelope'], 65536
  );
  PERFORM app.private_mfa_assert_json_object_v1(
    subject_record -> 'envelope', ARRAY['keyVersion','format','nonce','ciphertext'],
    ARRAY['keyVersion','format','nonce','ciphertext'], 32768
  );
  subject_envelope := subject_record -> 'envelope';
  requested_external_identity_id := app.private_mfa_require_uuidv7_v1(
    subject_record ->> 'externalIdentityId'
  );
  IF jsonb_typeof(subject_record -> 'aliases') <> 'array'
     OR subject_envelope ->> 'format' <> 'utf8_exact' THEN
    RAISE EXCEPTION 'invalid tenant platform OIDC subject projection'
      USING ERRCODE = '22023';
  END IF;
  alias_count := jsonb_array_length(subject_record -> 'aliases');
  IF alias_count NOT BETWEEN 1 AND 16 THEN
    RAISE EXCEPTION 'invalid tenant platform OIDC subject projection'
      USING ERRCODE = '22023';
  END IF;
  FOR alias_index IN 0..alias_count - 1 LOOP
    subject_alias := subject_record -> 'aliases' -> alias_index;
    PERFORM app.private_mfa_assert_json_object_v1(
      subject_alias, ARRAY['keyVersion','digest'], ARRAY['keyVersion','digest'], 4096
    );
    IF jsonb_typeof(subject_alias -> 'keyVersion') <> 'number'
       OR jsonb_typeof(subject_alias -> 'digest') <> 'string'
       OR (subject_alias ->> 'keyVersion')::integer NOT BETWEEN 1 AND 32767
       OR (alias_index > 0 AND alias_key_versions[alias_index] >=
         (subject_alias ->> 'keyVersion')::integer) THEN
      RAISE EXCEPTION 'invalid tenant platform OIDC subject projection'
        USING ERRCODE = '22023';
    END IF;
    alias_digest := app.private_mfa_decode_base64_v1(
      subject_alias ->> 'digest', 32, 32
    );
    IF encode(alias_digest, 'hex') = repeat('00', 32)
       OR NOT EXISTS (
         SELECT 1 FROM ONLY public.identity_keyring_versions AS keyring
         WHERE keyring.key_version = (subject_alias ->> 'keyVersion')::integer
           AND keyring.retired_at IS NULL
       ) THEN
      RAISE EXCEPTION 'invalid tenant platform OIDC subject projection'
        USING ERRCODE = '22023';
    END IF;
    alias_key_versions := array_append(
      alias_key_versions, (subject_alias ->> 'keyVersion')::integer
    );
    alias_digests := array_append(alias_digests, alias_digest);
  END LOOP;
  subject_alias := subject_record -> 'aliases' -> (alias_count - 1);
  subject_key_version := (subject_envelope ->> 'keyVersion')::integer;
  subject_digest := alias_digests[alias_count];
  protected_subject_ciphertext := app.private_mfa_decode_base64_v1(
    subject_envelope ->> 'ciphertext', 17, 4112
  );
  protected_subject_nonce := app.private_mfa_decode_base64_v1(
    subject_envelope ->> 'nonce', 12, 12
  );
  IF subject_key_version IS DISTINCT FROM alias_key_versions[alias_count]
     OR NOT EXISTS (
       SELECT 1 FROM ONLY public.identity_keyring_versions AS keyring
       WHERE keyring.key_version = subject_key_version
         AND keyring.is_active AND keyring.retired_at IS NULL
     ) THEN
    RAISE EXCEPTION 'invalid tenant platform OIDC subject projection'
      USING ERRCODE = '22023';
  END IF;
  PERFORM app.private_mfa_assert_json_object_v1(
    mapping_request,
    ARRAY['disposition','reason','identityAction','accessAction','matchedRuleIds',
      'securityGroupIds','roleIds','operatorTeams','changes','profile'],
    ARRAY['disposition','reason','identityAction','accessAction','matchedRuleIds',
      'securityGroupIds','roleIds','operatorTeams','changes','profile'], 262144
  );
  IF mapping_request ->> 'disposition' <> 'admitted'
     OR mapping_request ->> 'reason' <> 'provider_access_only'
     OR mapping_request ->> 'identityAction'
        NOT IN ('no_change','create_user_and_external_identity')
     OR mapping_request ->> 'accessAction' NOT IN ('ensure','no_change')
     OR jsonb_typeof(mapping_request -> 'matchedRuleIds') <> 'array'
     OR jsonb_array_length(mapping_request -> 'matchedRuleIds') <> 0
     OR jsonb_typeof(mapping_request -> 'securityGroupIds') <> 'array'
     OR jsonb_array_length(mapping_request -> 'securityGroupIds') <> 0
     OR jsonb_typeof(mapping_request -> 'roleIds') <> 'array'
     OR jsonb_array_length(mapping_request -> 'roleIds') <> 0
     OR jsonb_typeof(mapping_request -> 'operatorTeams') <> 'array'
     OR jsonb_array_length(mapping_request -> 'operatorTeams') <> 0
     OR jsonb_typeof(mapping_request -> 'changes') <> 'array'
     OR jsonb_array_length(mapping_request -> 'changes') <> 0
     OR jsonb_typeof(mapping_request -> 'profile') <> 'array'
     OR jsonb_array_length(mapping_request -> 'profile') <> 6 THEN
    RAISE EXCEPTION 'platform provider mapping attempted authorization changes'
      USING ERRCODE = '42501';
  END IF;
  FOR profile_item IN SELECT value FROM jsonb_array_elements(mapping_request -> 'profile')
  LOOP
    PERFORM app.private_mfa_assert_json_object_v1(
      profile_item, ARRAY['field','present','value'], ARRAY['field','present'], 4096
    );
    IF profile_item ->> 'field' = ANY(profile_fields)
       OR profile_item ->> 'field' NOT IN (
         'first_name','last_name','display_name','username',
         'alternate_username','email'
       ) OR ((profile_item ->> 'present')::boolean
         AND profile_item ->> 'field' NOT IN ('display_name','username','email'))
       OR ((profile_item ->> 'present')::boolean) <> (profile_item ? 'value') THEN
      RAISE EXCEPTION 'invalid platform provider profile projection'
        USING ERRCODE = '22023';
    END IF;
    profile_fields := array_append(profile_fields, profile_item ->> 'field');
    IF (profile_item ->> 'present')::boolean THEN
      CASE profile_item ->> 'field'
        WHEN 'display_name' THEN profile_display_name := profile_item ->> 'value';
        WHEN 'username' THEN profile_username := profile_item ->> 'value';
        WHEN 'email' THEN profile_email := profile_item ->> 'value';
        ELSE NULL;
      END CASE;
    END IF;
  END LOOP;
  IF subject_key_version NOT BETWEEN 1 AND 32767
     OR encode(subject_digest, 'hex') = repeat('00', 32)
     OR (profile_display_name IS NOT NULL AND (
       char_length(profile_display_name) > 160 OR btrim(profile_display_name) = ''
       OR profile_display_name ~ '[[:cntrl:]]'))
     OR (profile_username IS NOT NULL AND (
       char_length(profile_username) > 320 OR btrim(profile_username) = ''
       OR profile_username ~ '[[:cntrl:]]'))
     OR (profile_email IS NOT NULL AND (
       profile_email <> lower(btrim(profile_email))
       OR position('@' IN profile_email) <= 1
       OR char_length(profile_email) > 320 OR profile_email ~ '[[:cntrl:]]')) THEN
    RAISE EXCEPTION 'invalid tenant platform OIDC subject projection'
      USING ERRCODE = '22023';
  END IF;

  SELECT transaction_row.* INTO STRICT transaction_record
  FROM ONLY public.tenant_platform_oidc_authentication_transactions AS transaction_row
  WHERE transaction_row.transaction_id = transaction_id FOR UPDATE;
  SELECT application.* INTO existing_application
  FROM ONLY public.tenant_platform_oidc_authentication_applications AS application
  WHERE application.tenant_id = transaction_record.tenant_id
    AND application.transaction_id = transaction_record.transaction_id;
  IF FOUND THEN
    IF existing_application.operation_digest = operation_digest
       AND existing_application.request_snapshot = apply_request
       AND (
         (existing_application.session_id IS NOT NULL AND
           app.private_tenant_platform_session_authority_live_v1(
             existing_application.tenant_id, existing_application.session_id,
             statement_timestamp()
           ))
         OR (existing_application.continuation_id IS NOT NULL AND EXISTS (
           SELECT 1
           FROM ONLY public.tenant_post_primary_continuations AS continuation
           JOIN ONLY public.tenant_platform_auth_provider_bindings AS binding
             ON binding.tenant_id = continuation.tenant_id
            AND binding.id = continuation.binding_id
            AND binding.platform_provider_id = continuation.platform_provider_id
            AND binding.enabled AND binding.archived_at IS NULL
            AND binding.current_access_epoch_id IS NOT NULL
           JOIN ONLY public.platform_auth_providers AS provider
             ON provider.id = binding.platform_provider_id
            AND provider.kind = 'oidc' AND provider.enabled
            AND provider.archived_at IS NULL
           JOIN ONLY public.platform_federated_external_identities AS identity
             ON identity.id = continuation.external_identity_id
            AND identity.platform_provider_id = continuation.platform_provider_id
            AND identity.user_id = continuation.user_id
            AND identity.retired_at IS NULL
           JOIN ONLY public.tenant_platform_federated_provider_access_grants AS grant_row
             ON grant_row.tenant_id = continuation.tenant_id
            AND grant_row.binding_id = continuation.binding_id
            AND grant_row.platform_provider_id = continuation.platform_provider_id
            AND grant_row.external_identity_id = continuation.external_identity_id
            AND grant_row.user_id = continuation.user_id
            AND grant_row.access_epoch_id = binding.current_access_epoch_id
            AND grant_row.ended_at IS NULL
           WHERE continuation.tenant_id = existing_application.tenant_id
             AND continuation.id = existing_application.continuation_id
             AND continuation.user_id = existing_application.user_id
             AND continuation.primary_kind = 'tenant_platform_provider'
             AND continuation.state = 'pending'
             AND continuation.expires_at > statement_timestamp()
         ))
       ) THEN
      RETURN jsonb_set(
        existing_application.result_snapshot, '{replayed}', 'true'::jsonb, true
      );
    END IF;
    RETURN jsonb_build_object(
      'category','denied','disposition',disposition,'replayed',false
    );
  END IF;
  IF transaction_record.version <> expected_version
     OR transaction_record.state <> 'claimed'
     OR transaction_record.expires_at <= applied_at
     OR transaction_record.expires_at <= transaction_timestamp() THEN
    RETURN jsonb_build_object(
      'category','stale','disposition',disposition,'replayed',false
    );
  END IF;
  IF pins IS DISTINCT FROM jsonb_build_object(
    'provider', jsonb_build_object(
      'scope','platform','providerId',transaction_record.platform_provider_id::text
    ),
    'admission', jsonb_build_object(
      'tenantId',transaction_record.tenant_id::text,
      'bindingId',transaction_record.binding_id::text
    ),
    'providerRevision',transaction_record.provider_revision,
    'bindingRevision',transaction_record.binding_revision,
    'configurationRevision',transaction_record.configuration_revision,
    'securityRevision',transaction_record.security_revision,
    'mappingRevision',transaction_record.mapping_revision,
    'authorizationRevision',transaction_record.authorization_revision,
    'assurancePolicyRevision',transaction_record.assurance_policy_revision,
    'clientSecretRevision',transaction_record.client_secret_revision,
    'discoveryRevision',transaction_record.discovery_revision,
    'discoveryDigest',replace(encode(transaction_record.discovery_digest,'base64'),E'\n',''),
    'jwksRevision',transaction_record.jwks_revision,
    'jwksDigest',replace(encode(transaction_record.jwks_digest,'base64'),E'\n','')
  ) OR app.private_tenant_platform_oidc_configuration_record_v1(
    transaction_record.tenant_id, transaction_record.platform_provider_id,
    transaction_record.binding_id, pins
  ) IS NULL THEN
    RETURN jsonb_build_object(
      'category','stale','disposition',disposition,'replayed',false
    );
  END IF;
  IF (plan_request ->> 'planRevision')::bigint
       IS DISTINCT FROM transaction_record.plan_revision
     OR (plan_request ->> 'providerRevision')::bigint
       IS DISTINCT FROM transaction_record.provider_revision
     OR (plan_request ->> 'bindingRevision')::bigint
       IS DISTINCT FROM transaction_record.binding_revision
     OR (plan_request ->> 'configurationRevision')::bigint
       IS DISTINCT FROM transaction_record.configuration_revision
     OR (plan_request ->> 'securityRevision')::bigint
       IS DISTINCT FROM transaction_record.security_revision
     OR (plan_request ->> 'mappingRevision')::bigint
       IS DISTINCT FROM transaction_record.mapping_revision
     OR (plan_request ->> 'authorizationRevision')::bigint
       IS DISTINCT FROM transaction_record.authorization_revision
     OR (plan_request ->> 'policyRevision')::bigint
       IS DISTINCT FROM transaction_record.assurance_policy_revision
     OR request_tenant_id IS DISTINCT FROM transaction_record.tenant_id
     OR request_provider_id IS DISTINCT FROM transaction_record.platform_provider_id
     OR request_binding_id IS DISTINCT FROM transaction_record.binding_id
     OR oidc_request ->> 'returnPath' IS DISTINCT FROM transaction_record.return_path THEN
    RETURN jsonb_build_object(
      'category','stale','disposition',disposition,'replayed',false
    );
  END IF;

  SELECT provider.* INTO STRICT provider_record
  FROM ONLY public.platform_auth_providers AS provider
  WHERE provider.id = transaction_record.platform_provider_id
    AND provider.enabled AND provider.archived_at IS NULL FOR UPDATE;
  SELECT policy.* INTO STRICT policy_record
  FROM ONLY public.platform_federated_provider_policies AS policy
  WHERE policy.provider_id = provider_record.id
    AND policy.provider_kind = 'oidc' AND policy.enabled
    AND NOT policy.platform_login_enabled
    AND policy.configuration_revision = transaction_record.configuration_revision
    AND policy.security_revision = transaction_record.security_revision
    AND policy.plan_revision = transaction_record.plan_revision
    AND policy.assurance_policy_revision = transaction_record.assurance_policy_revision
  FOR UPDATE;
  SELECT binding.* INTO STRICT binding_record
  FROM ONLY public.tenant_platform_auth_provider_bindings AS binding
  WHERE binding.tenant_id = transaction_record.tenant_id
    AND binding.id = transaction_record.binding_id
    AND binding.platform_provider_id = transaction_record.platform_provider_id
    AND binding.version = transaction_record.binding_revision
    AND binding.mapping_revision = transaction_record.mapping_revision
    AND binding.auth_revision = transaction_record.authorization_revision
    AND binding.current_access_epoch_id = transaction_record.access_epoch_id
    AND binding.enabled AND binding.archived_at IS NULL FOR UPDATE;
  IF NOT EXISTS (
       SELECT 1
       FROM ONLY public.tenant_platform_identity_provider_access_epochs AS epoch
       JOIN ONLY public.tenant_authorization_sources AS source
         ON source.tenant_id = epoch.tenant_id AND source.id = epoch.source_id
        AND source.kind = 'identity_provider_access'
        AND source.authoritative AND NOT source.protected
        AND source.key = format(
          'identity_provider_access:%s:%s', epoch.binding_id, epoch.sequence
        )
        AND source.retired_at IS NULL
       WHERE epoch.tenant_id = transaction_record.tenant_id
         AND epoch.id = transaction_record.access_epoch_id
         AND epoch.binding_id = transaction_record.binding_id
         AND epoch.platform_provider_id = transaction_record.platform_provider_id
         AND epoch.source_id = transaction_record.access_source_id
         AND epoch.ended_at IS NULL
     ) OR NOT EXISTS (
       SELECT 1 FROM ONLY public.identity_keyring_versions AS keyring
       WHERE keyring.key_version = subject_key_version
         AND keyring.is_active AND keyring.retired_at IS NULL
     ) THEN
    RETURN jsonb_build_object(
      'category','denied','disposition',disposition,'replayed',false
    );
  END IF;

  SELECT planned_user_id INTO policy_user_id
  WHERE planned_user_id IS NOT NULL AND EXISTS (
    SELECT 1
    FROM ONLY public.users AS local_user
    JOIN ONLY public.tenant_memberships AS membership
      ON membership.user_id = local_user.id
     AND membership.tenant_id = transaction_record.tenant_id
     AND membership.status = 'active'
    WHERE local_user.id = planned_user_id AND local_user.active
  );
  live_policy_snapshot := app.private_mfa_policy_snapshot_v1(
    transaction_record.tenant_id, policy_user_id, 'session.create', applied_at
  );
  live_requirement := live_policy_snapshot -> 'requirement';
  live_has_enrollable_factor := false;
  IF planned_user_id IS NOT NULL THEN
    SELECT EXISTS (
      SELECT 1 FROM ONLY public.tenant_totp_factors AS factor
      WHERE factor.tenant_id = transaction_record.tenant_id
        AND factor.user_id = planned_user_id AND factor.status = 'active'
      UNION ALL
      SELECT 1 FROM ONLY public.tenant_webauthn_credentials AS credential
      WHERE credential.tenant_id = transaction_record.tenant_id
        AND credential.user_id = planned_user_id AND credential.status = 'active'
    ) INTO live_has_enrollable_factor;
  END IF;
  IF live_requirement ->> 'level' IS DISTINCT FROM requirement ->> 'level'
     OR (live_requirement ->> 'localRequired')::boolean IS DISTINCT FROM
       (requirement ->> 'localRequired')::boolean
     OR (live_requirement ->> 'freshnessNanoseconds')::bigint IS DISTINCT FROM
       (requirement ->> 'freshnessNanoseconds')::bigint
     OR nullif(live_requirement ->> 'enrollmentDeadline','')::timestamptz
       IS DISTINCT FROM nullif(requirement ->> 'enrollmentDeadline','')::timestamptz
     OR live_requirement -> 'policyRevisions'
       IS DISTINCT FROM requirement -> 'policyRevisions'
     OR live_has_enrollable_factor IS DISTINCT FROM has_enrollable_factor THEN
    RETURN jsonb_build_object(
      'category','stale','disposition',disposition,'replayed',false
    );
  END IF;
  FOR evidence_record IN SELECT value FROM jsonb_array_elements(evidence_array)
  LOOP
    PERFORM app.private_mfa_assert_json_object_v1(
      evidence_record,
      ARRAY['level','kind','local','providerId','bindingId','authenticatedAt',
        'expiresAt','factorRevision','trustRuleRevision'],
      ARRAY['level','kind','local','providerId','bindingId','authenticatedAt',
        'expiresAt','trustRuleRevision'], 8192
    );
    evidence_level := evidence_record ->> 'level';
    evidence_authenticated_at := (evidence_record ->> 'authenticatedAt')::timestamptz;
    evidence_expires_at := nullif(evidence_record ->> 'expiresAt','')::timestamptz;
    evidence_trust_revision := nullif(
      evidence_record ->> 'trustRuleRevision',''
    )::bigint;
    IF evidence_level NOT IN ('primary','mfa','phishing_resistant')
       OR evidence_record ->> 'kind' <> 'factor'
       OR jsonb_typeof(evidence_record -> 'local') <> 'boolean'
       OR (evidence_record ->> 'local')::boolean
       OR app.private_mfa_require_uuidv7_v1(evidence_record ->> 'providerId')
         IS DISTINCT FROM transaction_record.platform_provider_id
       OR app.private_mfa_require_uuidv7_v1(evidence_record ->> 'bindingId')
         IS DISTINCT FROM transaction_record.binding_id
       OR NOT (evidence_record ? 'factorRevision')
       OR evidence_record -> 'factorRevision' <> 'null'::jsonb
       OR evidence_trust_revision IS DISTINCT FROM transaction_record.security_revision
       OR evidence_authenticated_at NOT BETWEEN authenticated_at AND applied_at
       OR evidence_expires_at IS NULL OR evidence_expires_at <= applied_at
       OR evidence_expires_at > valid_until THEN
      RETURN jsonb_build_object(
        'category','denied','disposition',disposition,'replayed',false
      );
    END IF;
    IF evidence_level = 'primary' THEN
      primary_evidence_count := primary_evidence_count + 1;
      IF evidence_authenticated_at IS DISTINCT FROM authenticated_at
         OR evidence_expires_at IS DISTINCT FROM valid_until THEN
        RETURN jsonb_build_object(
          'category','denied','disposition',disposition,'replayed',false
        );
      END IF;
    ELSIF NOT EXISTS (
      SELECT 1 FROM ONLY public.platform_federated_trust_rules AS rule
      WHERE rule.provider_id = transaction_record.platform_provider_id
        AND rule.provider_kind = 'oidc'
        AND rule.revision = transaction_record.security_revision
        AND rule.level = evidence_level
        AND rule.enabled AND rule.retired_at IS NULL
        AND evidence_expires_at = least(
          valid_until,
          evidence_authenticated_at +
            rule.maximum_authentication_age_seconds * interval '1 second'
        )
    ) THEN
      RETURN jsonb_build_object(
        'category','denied','disposition',disposition,'replayed',false
      );
    END IF;
  END LOOP;
  IF primary_evidence_count <> 1 THEN
    RETURN jsonb_build_object(
      'category','denied','disposition',disposition,'replayed',false
    );
  END IF;
  assurance_decision := app.private_federated_assurance_decision_v1(
    live_requirement, evidence_array, live_has_enrollable_factor, applied_at
  );
  IF assurance_decision IS DISTINCT FROM assurance
     OR NOT ((disposition = 'session' AND assurance = 'satisfied') OR
       (disposition = 'continuation' AND assurance IN (
         'step_up_required','enrollment_only'
       ))) THEN
    RETURN jsonb_build_object(
      'category','denied','disposition',disposition,'replayed',false
    );
  END IF;

  WITH wanted AS (
    SELECT alias.key_version, alias.digest
    FROM unnest(alias_key_versions, alias_digests)
      AS alias(key_version,digest)
  ), matches AS (
    SELECT DISTINCT identity.id, identity.user_id
    FROM wanted
    JOIN ONLY public.platform_federated_external_identity_aliases AS alias
      ON alias.platform_provider_id = transaction_record.platform_provider_id
     AND alias.key_version = wanted.key_version
     AND alias.subject_digest = wanted.digest
     AND alias.retired_at IS NULL
    JOIN ONLY public.platform_federated_external_identities AS identity
      ON identity.platform_provider_id = alias.platform_provider_id
     AND identity.id = alias.external_identity_id
     AND identity.retired_at IS NULL
  )
  SELECT array_agg(DISTINCT matches.id ORDER BY matches.id),
         array_agg(DISTINCT matches.user_id ORDER BY matches.user_id)
    INTO matched_identity_ids, matched_user_ids
  FROM matches;
  IF EXISTS (
    SELECT 1
    FROM unnest(alias_key_versions, alias_digests)
      AS wanted(key_version,digest)
    JOIN ONLY public.platform_federated_external_identity_aliases AS alias
      ON alias.platform_provider_id = transaction_record.platform_provider_id
     AND alias.key_version = wanted.key_version
     AND alias.subject_digest = wanted.digest
    LEFT JOIN ONLY public.platform_federated_external_identities AS identity
      ON identity.platform_provider_id = alias.platform_provider_id
     AND identity.id = alias.external_identity_id
    WHERE alias.retired_at IS NOT NULL
       OR identity.id IS NULL
       OR identity.retired_at IS NOT NULL
  ) THEN
    RETURN jsonb_build_object(
      'category','identity_collision','disposition',disposition,'replayed',false
    );
  END IF;
  IF coalesce(cardinality(matched_identity_ids),0) > 1
     OR coalesce(cardinality(matched_user_ids),0) > 1 THEN
    RETURN jsonb_build_object(
      'category','identity_collision','disposition',disposition,'replayed',false
    );
  END IF;
  IF mapping_request ->> 'accessAction' = 'no_change'
     AND (
       mapping_request ->> 'identityAction' <> 'no_change'
       OR NOT EXISTS (
       SELECT 1
       FROM ONLY public.tenant_platform_federated_provider_access_grants AS grant_record
       JOIN ONLY public.tenant_memberships AS membership
         ON membership.tenant_id = grant_record.tenant_id
        AND membership.id = grant_record.membership_id
        AND membership.user_id = grant_record.user_id
        AND membership.status = 'active'
       WHERE grant_record.tenant_id = transaction_record.tenant_id
         AND grant_record.platform_provider_id = transaction_record.platform_provider_id
         AND grant_record.binding_id = transaction_record.binding_id
         AND grant_record.access_epoch_id = transaction_record.access_epoch_id
         AND grant_record.source_id = transaction_record.access_source_id
         AND grant_record.external_identity_id = matched_identity_ids[1]
         AND grant_record.user_id = matched_user_ids[1]
         AND grant_record.ended_at IS NULL
       )
     ) THEN
    RETURN jsonb_build_object(
      'category','stale','disposition',disposition,'replayed',false
    );
  END IF;
  external_identity_id := matched_identity_ids[1];
  user_id := matched_user_ids[1];
  IF external_identity_id IS NOT NULL THEN
    SELECT identity.* INTO STRICT identity_record
    FROM ONLY public.platform_federated_external_identities AS identity
    WHERE identity.platform_provider_id = transaction_record.platform_provider_id
      AND identity.id = external_identity_id
      AND identity.user_id = user_id AND identity.retired_at IS NULL
    FOR UPDATE;
    IF requested_external_identity_id <> identity_record.id
       OR planned_user_id IS DISTINCT FROM identity_record.user_id
       OR mapping_request ->> 'identityAction' <> 'no_change'
       OR EXISTS (
      SELECT 1
      FROM unnest(alias_key_versions, alias_digests)
        AS wanted(key_version,digest)
      JOIN ONLY public.platform_federated_external_identity_aliases AS alias
        ON alias.platform_provider_id = transaction_record.platform_provider_id
       AND alias.key_version = wanted.key_version
       AND alias.subject_digest = wanted.digest
       AND alias.retired_at IS NULL
      WHERE alias.external_identity_id <> identity_record.id
    ) THEN
      RETURN jsonb_build_object(
        'category','identity_collision','disposition',disposition,'replayed',false
      );
    END IF;
    external_identity_id := identity_record.id;
    user_id := identity_record.user_id;
    FOR alias_index IN 1..alias_count LOOP
      INSERT INTO public.platform_federated_external_identity_aliases (
        id, platform_provider_id, external_identity_id, key_version,
        subject_digest, created_at
      ) SELECT uuidv7(), transaction_record.platform_provider_id,
        identity_record.id, alias_key_versions[alias_index],
        alias_digests[alias_index], transaction_timestamp()
      WHERE NOT EXISTS (
        SELECT 1 FROM ONLY public.platform_federated_external_identity_aliases AS alias
        WHERE alias.platform_provider_id = transaction_record.platform_provider_id
          AND alias.external_identity_id = identity_record.id
          AND alias.key_version = alias_key_versions[alias_index]
          AND alias.subject_digest = alias_digests[alias_index]
          AND alias.retired_at IS NULL
      );
    END LOOP;
    UPDATE ONLY public.platform_federated_external_identities AS identity
    SET last_observed_at = transaction_timestamp(),
        updated_at = transaction_timestamp()
    WHERE identity.id = identity_record.id
    RETURNING identity.* INTO identity_record;
  ELSE
    IF binding_record.jit_mode <> 'create'
       OR policy_record.account_mode <> 'create'
       OR planned_user_id IS NOT NULL
       OR mapping_request ->> 'identityAction' <> 'create_user_and_external_identity'
       OR EXISTS (
         SELECT 1 FROM ONLY public.platform_federated_external_identities AS identity
         WHERE identity.id = requested_external_identity_id
       ) THEN
      RAISE EXCEPTION 'tenant platform OIDC apply denied after identity resolution'
        USING ERRCODE = 'P4D01';
    END IF;
    user_id := uuidv7();
    external_identity_id := requested_external_identity_id;
    created_identity := true;
    INSERT INTO public.users (
      id, email, display_name, active, created_at, updated_at
    ) VALUES (
      user_id, NULL, 'Federated user', true,
      transaction_timestamp(), transaction_timestamp()
    );
    INSERT INTO public.platform_federated_external_identities (
      id, platform_provider_id, provider_kind, user_id, subject_format,
      subject_ciphertext, subject_nonce, key_version,
      admitted_configuration_revision, admitted_security_revision,
      last_observed_at, version, created_at, updated_at
    ) VALUES (
      external_identity_id, transaction_record.platform_provider_id, 'oidc',
      user_id, 'utf8_exact', protected_subject_ciphertext, protected_subject_nonce,
      subject_key_version, transaction_record.configuration_revision,
      transaction_record.security_revision, transaction_timestamp(), 1,
      transaction_timestamp(), transaction_timestamp()
    ) RETURNING * INTO identity_record;
    FOR alias_index IN 1..alias_count LOOP
      INSERT INTO public.platform_federated_external_identity_aliases (
        id, platform_provider_id, external_identity_id, key_version,
        subject_digest, created_at
      ) VALUES (
        uuidv7(), transaction_record.platform_provider_id, external_identity_id,
        alias_key_versions[alias_index], alias_digests[alias_index],
        transaction_timestamp()
      );
    END LOOP;
  END IF;

  PERFORM 1 FROM ONLY public.users AS local_user
  WHERE local_user.id = user_id AND local_user.active FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant platform OIDC apply denied after identity mutation'
      USING ERRCODE = 'P4D01';
  END IF;
  SELECT membership.* INTO membership_record
  FROM ONLY public.tenant_memberships AS membership
  WHERE membership.tenant_id = transaction_record.tenant_id
    AND membership.user_id = user_id FOR UPDATE;
  IF NOT FOUND THEN
    IF binding_record.jit_mode <> 'create'
       OR binding_record.no_match_policy <> 'provider_access_only' THEN
      RAISE EXCEPTION 'tenant platform OIDC apply denied after identity mutation'
        USING ERRCODE = 'P4D01';
    END IF;
    membership_id := uuidv7();
    owns_membership := true;
    INSERT INTO public.tenant_memberships (
      id, tenant_id, user_id, role, status, created_at, updated_at
    ) VALUES (
      membership_id, transaction_record.tenant_id, user_id,
      'read_only', 'active', transaction_timestamp(), transaction_timestamp()
    ) RETURNING * INTO membership_record;
  ELSIF membership_record.status <> 'active' THEN
    RAISE EXCEPTION 'tenant platform OIDC apply denied after identity mutation'
      USING ERRCODE = 'P4D01';
  ELSE
    membership_id := membership_record.id;
  END IF;

  SELECT subject.* INTO mfa_subject
  FROM ONLY public.tenant_mfa_subjects AS subject
  WHERE subject.tenant_id = transaction_record.tenant_id
    AND subject.user_id = user_id FOR UPDATE;
  IF NOT FOUND THEN
    IF NOT created_identity AND NOT owns_membership THEN
      RAISE EXCEPTION 'tenant platform OIDC apply denied after identity mutation'
        USING ERRCODE = 'P4D01';
    END IF;
    INSERT INTO public.tenant_mfa_subjects (
      tenant_id, user_id, webauthn_user_handle, identity_epoch,
      session_invalidation_epoch, version, created_at, updated_at
    ) VALUES (
      transaction_record.tenant_id, user_id,
      uuid_send(gen_random_uuid()) || uuid_send(gen_random_uuid()),
      1, 1, 1, transaction_timestamp(), transaction_timestamp()
    ) RETURNING * INTO mfa_subject;
  END IF;
  IF mfa_subject.identity_epoch IS DISTINCT FROM
       (CASE WHEN planned_identity_epoch = 0
         THEN 1 ELSE planned_identity_epoch END) THEN
    RAISE EXCEPTION 'tenant platform OIDC apply became stale after identity mutation'
      USING ERRCODE = 'P4S01';
  END IF;

  SELECT grant_record.* INTO access_grant
  FROM ONLY public.tenant_platform_federated_provider_access_grants AS grant_record
  WHERE grant_record.tenant_id = transaction_record.tenant_id
    AND grant_record.binding_id = transaction_record.binding_id
    AND grant_record.membership_id = membership_id
    AND grant_record.ended_at IS NULL FOR UPDATE;
  IF FOUND THEN
    IF access_grant.external_identity_id <> external_identity_id
       OR access_grant.user_id <> user_id
       OR access_grant.access_epoch_id <> transaction_record.access_epoch_id
       OR access_grant.source_id <> transaction_record.access_source_id THEN
      RAISE EXCEPTION 'tenant platform OIDC access grant identity collision'
        USING ERRCODE = 'P4C01';
    END IF;
    UPDATE ONLY public.tenant_platform_federated_provider_access_grants AS grant_record
    SET last_observed_at = transaction_timestamp(),
        version = grant_record.version + 1
    WHERE grant_record.id = access_grant.id
    RETURNING grant_record.* INTO access_grant;
  ELSE
    IF mapping_request ->> 'accessAction' <> 'ensure' THEN
      RAISE EXCEPTION 'tenant platform OIDC access grant became stale'
        USING ERRCODE = 'P4S01';
    END IF;
    IF binding_record.no_match_policy <> 'provider_access_only' THEN
      RAISE EXCEPTION 'tenant platform OIDC access grant is denied by policy'
        USING ERRCODE = 'P4D01';
    END IF;
    access_grant_id := uuidv7();
    INSERT INTO public.tenant_platform_federated_provider_access_grants (
      id, tenant_id, platform_provider_id, binding_id, access_epoch_id,
      source_id, external_identity_id, membership_id, user_id,
      owns_membership, started_at, last_observed_at, version
    ) VALUES (
      access_grant_id, transaction_record.tenant_id,
      transaction_record.platform_provider_id, transaction_record.binding_id,
      transaction_record.access_epoch_id, transaction_record.access_source_id,
      external_identity_id, membership_id, user_id, owns_membership,
      transaction_timestamp(), transaction_timestamp(), 1
    ) RETURNING * INTO access_grant;
  END IF;
  access_grant_id := access_grant.id;

  UPDATE ONLY public.tenant_platform_federated_provider_profile_contributions AS contribution
  SET retired_at = transaction_timestamp(), version = contribution.version + 1
  WHERE contribution.tenant_id = transaction_record.tenant_id
    AND contribution.access_grant_id = access_grant_id
    AND contribution.retired_at IS NULL;
  IF profile_display_name IS NOT NULL OR profile_username IS NOT NULL
     OR profile_email IS NOT NULL THEN
    INSERT INTO public.tenant_platform_federated_provider_profile_contributions (
      id, tenant_id, access_grant_id, display_name, username, email,
      mapping_revision, observed_at, version
    ) VALUES (
      uuidv7(), transaction_record.tenant_id, access_grant_id,
      profile_display_name, profile_username, profile_email,
      transaction_record.mapping_revision, transaction_timestamp(), 1
    );
  END IF;
  PERFORM app.private_materialize_tenant_user_profile_v1(
    transaction_record.tenant_id, membership_id
  );

  IF disposition = 'session' THEN
    reservation := apply_request -> 'session';
    PERFORM app.private_mfa_assert_json_object_v1(
      reservation,
      ARRAY['sessionId','familyId','tokenDigest','csrfDigest',
        'authenticationMethod','idleExpiresAt','absoluteExpiresAt'],
      ARRAY['sessionId','familyId','tokenDigest','csrfDigest',
        'authenticationMethod','idleExpiresAt','absoluteExpiresAt'], 32768
    );
    session_id := app.private_mfa_require_uuidv7_v1(reservation ->> 'sessionId');
    session_family_id := app.private_mfa_require_uuidv7_v1(reservation ->> 'familyId');
    token_digest := app.private_mfa_decode_base64_v1(
      reservation ->> 'tokenDigest', 32, 32
    );
    csrf_digest := app.private_mfa_decode_base64_v1(
      reservation ->> 'csrfDigest', 32, 32
    );
    idle_expires_at := (reservation ->> 'idleExpiresAt')::timestamptz;
    absolute_expires_at := (reservation ->> 'absoluteExpiresAt')::timestamptz;
    IF session_id = session_family_id OR token_digest = csrf_digest
       OR reservation ->> 'authenticationMethod' <> 'oidc'
       OR encode(token_digest,'hex') = repeat('00',32)
       OR encode(csrf_digest,'hex') = repeat('00',32)
       OR idle_expires_at <= applied_at
       OR idle_expires_at <= transaction_timestamp()
       OR absolute_expires_at <= transaction_timestamp()
       OR absolute_expires_at < idle_expires_at
       OR idle_expires_at > applied_at + interval '24 hours'
       OR absolute_expires_at > applied_at + interval '31 days' THEN
      RAISE EXCEPTION 'invalid tenant platform OIDC session reservation'
        USING ERRCODE = '22023';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended(
      least(encode(token_digest,'hex'),encode(csrf_digest,'hex')), 73124201
    ));
    PERFORM pg_advisory_xact_lock(hashtextextended(
      greatest(encode(token_digest,'hex'),encode(csrf_digest,'hex')), 73124201
    ));
    IF EXISTS (
          SELECT 1 FROM public.auth_sessions AS collision
          WHERE collision.token_digest IN (token_digest, csrf_digest)
             OR collision.csrf_secret_digest IN (token_digest, csrf_digest)
       ) THEN
      RAISE EXCEPTION 'tenant platform OIDC session digest collision'
        USING ERRCODE = '40001';
    END IF;
    INSERT INTO public.auth_sessions (
      id, user_id, rotation_family_id, active_tenant_id, token_digest,
      csrf_secret_digest, authentication_method, mfa_satisfied_at,
      last_seen_at, idle_expires_at, absolute_expires_at, created_at
    ) VALUES (
      session_id, user_id, session_family_id, transaction_record.tenant_id,
      token_digest, csrf_digest, 'oidc', applied_at, applied_at,
      idle_expires_at, absolute_expires_at, applied_at
    );
    INSERT INTO public.auth_session_mfa_states (
      session_id, tenant_id, user_id, session_version, identity_epoch,
      recovery_restricted, audience, primary_kind,
      session_invalidation_epoch, issued_at
    ) VALUES (
      session_id, transaction_record.tenant_id, user_id, 1,
      mfa_subject.identity_epoch, false, 'api',
      'tenant_platform_provider', mfa_subject.session_invalidation_epoch,
      applied_at
    );
    INSERT INTO public.auth_session_tenant_platform_federated_provenance (
      tenant_id, session_id, user_id, primary_kind, authentication_method,
      platform_provider_id, binding_id, access_epoch_id, access_source_id,
      access_grant_id, membership_id, external_identity_id,
      external_identity_revision, provider_revision, binding_revision,
      security_revision, mapping_revision, authorization_revision,
      subject_alias_key_version, trust_rule_revision, authenticated_at
    ) VALUES (
      transaction_record.tenant_id, session_id, user_id,
      'tenant_platform_provider', 'oidc', transaction_record.platform_provider_id,
      transaction_record.binding_id, transaction_record.access_epoch_id,
      transaction_record.access_source_id, access_grant_id, membership_id,
      external_identity_id, identity_record.version,
      transaction_record.provider_revision, transaction_record.binding_revision,
      transaction_record.security_revision, transaction_record.mapping_revision,
      transaction_record.authorization_revision, subject_key_version,
      transaction_record.security_revision, authenticated_at
    );
  ELSE
    reservation := apply_request -> 'continuation';
    PERFORM app.private_mfa_assert_json_object_v1(
      reservation,
      ARRAY['continuationId','receiptDigest','expiresAt'],
      ARRAY['continuationId','receiptDigest','expiresAt'], 16384
    );
    continuation_id := app.private_mfa_require_uuidv7_v1(
      reservation ->> 'continuationId'
    );
    continuation_receipt := app.private_mfa_decode_base64_v1(
      reservation ->> 'receiptDigest', 32, 32
    );
    continuation_expires_at := (reservation ->> 'expiresAt')::timestamptz;
    IF encode(continuation_receipt,'hex') = repeat('00',32)
       OR date_trunc('milliseconds',continuation_expires_at)
            IS DISTINCT FROM continuation_expires_at
       OR continuation_expires_at <= applied_at
       OR continuation_expires_at <= transaction_timestamp()
       OR continuation_expires_at > applied_at + interval '15 minutes' THEN
      RAISE EXCEPTION 'invalid tenant platform OIDC continuation reservation'
        USING ERRCODE = '22023';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended(
      encode(continuation_receipt,'hex'), 77191203
    ));
    INSERT INTO public.tenant_post_primary_continuations (
      id, tenant_id, user_id, receipt_digest, identity_epoch, action,
      audience, primary_kind, platform_provider_id, binding_id, provider_kind,
      external_identity_id, primary_revision, session_invalidation_epoch,
      state, version, created_at, expires_at
    ) VALUES (
      continuation_id, transaction_record.tenant_id, user_id,
      continuation_receipt, mfa_subject.identity_epoch, 'session.create',
      'api', 'tenant_platform_provider',
      transaction_record.platform_provider_id, transaction_record.binding_id,
      'oidc', external_identity_id, identity_record.version,
      mfa_subject.session_invalidation_epoch, 'pending', 1,
      applied_at, continuation_expires_at
    );
    INSERT INTO public.tenant_post_primary_platform_federated_provenance (
      tenant_id,continuation_id,user_id,origin,platform_provider_id,binding_id,
      access_epoch_id,access_source_id,access_grant_id,membership_id,
      external_identity_id,external_identity_revision,provider_revision,
      binding_revision,security_revision,mapping_revision,
      authorization_revision,subject_alias_key_version,trust_rule_revision,
      authenticated_at
    ) VALUES (
      transaction_record.tenant_id,continuation_id,user_id,'initial_login',
      transaction_record.platform_provider_id,transaction_record.binding_id,
      transaction_record.access_epoch_id,transaction_record.access_source_id,
      access_grant_id,membership_id,external_identity_id,identity_record.version,
      transaction_record.provider_revision,transaction_record.binding_revision,
      transaction_record.security_revision,transaction_record.mapping_revision,
      transaction_record.authorization_revision,subject_key_version,
      transaction_record.security_revision,authenticated_at
    );
  END IF;

  FOR policy_pin IN
    SELECT value FROM jsonb_array_elements(live_requirement -> 'policyRevisions')
  LOOP
    PERFORM app.private_mfa_assert_json_object_v1(
      policy_pin, ARRAY['policyId','revision'],
      ARRAY['policyId','revision'], 1024
    );
    IF (policy_pin ->> 'revision')::bigint < 1 THEN
      RAISE EXCEPTION 'tenant platform MFA policy pin is invalid'
        USING ERRCODE = '22023';
    END IF;
    IF disposition = 'session' THEN
      INSERT INTO public.auth_session_mfa_policy_pins (
        tenant_id, session_id, policy_id, policy_revision
      ) VALUES (
        transaction_record.tenant_id, session_id,
        app.private_mfa_require_uuidv7_v1(policy_pin ->> 'policyId'),
        (policy_pin ->> 'revision')::bigint
      );
    ELSE
      INSERT INTO public.tenant_post_primary_continuation_policy_pins (
        tenant_id, continuation_id, policy_id, policy_revision
      ) VALUES (
        transaction_record.tenant_id, continuation_id,
        app.private_mfa_require_uuidv7_v1(policy_pin ->> 'policyId'),
        (policy_pin ->> 'revision')::bigint
      );
    END IF;
  END LOOP;
  FOR evidence_record IN SELECT value FROM jsonb_array_elements(evidence_array)
  LOOP
    evidence_level := evidence_record ->> 'level';
    evidence_authenticated_at := (evidence_record ->> 'authenticatedAt')::timestamptz;
    evidence_expires_at := nullif(evidence_record ->> 'expiresAt','')::timestamptz;
    evidence_trust_revision := (
      evidence_record ->> 'trustRuleRevision'
    )::bigint;
    IF disposition = 'session' THEN
      INSERT INTO public.auth_session_tenant_platform_federated_evidence (
        id, tenant_id, session_id, user_id, platform_provider_id,
        binding_id, external_identity_id, level, authenticated_at,
        expires_at, trust_rule_revision
      ) VALUES (
        uuidv7(), transaction_record.tenant_id, session_id, user_id,
        transaction_record.platform_provider_id, transaction_record.binding_id,
        external_identity_id, evidence_level, evidence_authenticated_at,
        evidence_expires_at, evidence_trust_revision
      );
    ELSE
      INSERT INTO public.tenant_post_primary_platform_federated_evidence (
        id, tenant_id, continuation_id, user_id, platform_provider_id,
        binding_id, external_identity_id, level, authenticated_at,
        expires_at, trust_rule_revision
      ) VALUES (
        uuidv7(), transaction_record.tenant_id, continuation_id, user_id,
        transaction_record.platform_provider_id, transaction_record.binding_id,
        external_identity_id, evidence_level, evidence_authenticated_at,
        evidence_expires_at, evidence_trust_revision
      );
    END IF;
  END LOOP;

  UPDATE ONLY public.tenant_platform_oidc_authentication_transactions AS transaction_row
  SET state = 'completed', version = transaction_row.version + 1,
      completed_at = applied_at, failure_reason = NULL
  WHERE transaction_row.tenant_id = transaction_record.tenant_id
    AND transaction_row.transaction_id = transaction_record.transaction_id
    AND transaction_row.version = expected_version
    AND transaction_row.state = 'claimed';
  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant platform OIDC transaction completion lost CAS'
      USING ERRCODE = '40001';
  END IF;
  result := jsonb_strip_nulls(jsonb_build_object(
    'category','success','disposition',disposition,
    'tenantId',transaction_record.tenant_id::text,
    'userId',user_id::text,'sessionId',session_id::text,
    'continuationId',continuation_id::text,
    'returnPath',transaction_record.return_path,'replayed',false
  ));
  INSERT INTO public.tenant_platform_oidc_authentication_applications (
    id, tenant_id, transaction_id, operation_digest, platform_provider_id,
    binding_id, external_identity_id, category, primary_kind, user_id,
    session_id, continuation_id, request_snapshot, result_snapshot, applied_at
  ) VALUES (
    uuidv7(), transaction_record.tenant_id, transaction_record.transaction_id,
    operation_digest, transaction_record.platform_provider_id,
    transaction_record.binding_id, external_identity_id, 'success',
    'tenant_platform_provider', user_id, session_id, continuation_id,
    apply_request, result, applied_at
  );
  INSERT INTO public.audit_events (
    id, tenant_id, sequence, occurred_at, actor_type, actor_user_id,
    action, resource_type, resource_id, authentication_method,
    outcome, metadata
  ) VALUES (
    uuidv7(), transaction_record.tenant_id, 0, applied_at, 'system', NULL,
    'tenant.identity.platform_federated_login_completed',
    CASE WHEN session_id IS NOT NULL THEN 'auth_session'
         ELSE 'post_primary_continuation' END,
    coalesce(session_id, continuation_id), 'oidc', 'success',
    jsonb_build_object(
      'provider_id', transaction_record.platform_provider_id,
      'binding_id', transaction_record.binding_id,
      'access_epoch_id', transaction_record.access_epoch_id,
      'provider_created_platform_role', false
    )
  );
  RETURN result;
EXCEPTION
  WHEN SQLSTATE 'P4D01' THEN
    RETURN jsonb_build_object(
      'category','denied','disposition',coalesce(disposition,'session'),
      'replayed',false
    );
  WHEN SQLSTATE 'P4S01' THEN
    RETURN jsonb_build_object(
      'category','stale','disposition',coalesce(disposition,'session'),
      'replayed',false
    );
  WHEN SQLSTATE 'P4C01' THEN
    RETURN jsonb_build_object(
      'category','identity_collision','disposition',coalesce(disposition,'session'),
      'replayed',false
    );
  WHEN unique_violation THEN
    RETURN jsonb_build_object(
      'category','identity_collision','disposition',coalesce(disposition,'session'),
      'replayed',false
    );
  WHEN NO_DATA_FOUND OR TOO_MANY_ROWS OR serialization_failure THEN
    RETURN jsonb_build_object(
      'category','stale','disposition',coalesce(disposition,'session'),
      'replayed',false
    );
  WHEN invalid_text_representation OR numeric_value_out_of_range
    OR data_exception THEN
    RAISE EXCEPTION 'invalid tenant platform OIDC apply request'
      USING ERRCODE = '22023';
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.claim_tenant_platform_oidc_authentication_transaction_v1(
  p_request jsonb
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
#variable_conflict use_variable
DECLARE
  attempt_id bytea;
  state_digest bytea;
  browser_digest bytea;
  claimed_at timestamptz;
  transaction_record public.tenant_platform_oidc_authentication_transactions%ROWTYPE;
BEGIN
  PERFORM app.private_mfa_assert_json_object_v1(
    p_request, ARRAY['attemptId','stateDigest','browserDigest','claimedAt'],
    ARRAY['attemptId','stateDigest','browserDigest','claimedAt'], 16384
  );
  attempt_id := app.private_mfa_decode_base64_v1(
    p_request ->> 'attemptId', 32, 32
  );
  state_digest := app.private_mfa_decode_base64_v1(
    p_request ->> 'stateDigest', 32, 32
  );
  browser_digest := app.private_mfa_decode_base64_v1(
    p_request ->> 'browserDigest', 32, 32
  );
  claimed_at := (p_request ->> 'claimedAt')::timestamptz;
  IF encode(attempt_id, 'hex') = repeat('00', 32)
     OR state_digest = browser_digest
     OR claimed_at NOT BETWEEN statement_timestamp() - interval '5 minutes'
                            AND statement_timestamp() + interval '30 seconds' THEN
    RAISE EXCEPTION 'invalid tenant platform OIDC transaction claim'
      USING ERRCODE = '22023';
  END IF;
  SELECT transaction_row.* INTO transaction_record
  FROM ONLY public.tenant_platform_oidc_authentication_transactions AS transaction_row
  WHERE transaction_row.state_digest = state_digest
    AND transaction_row.browser_digest = browser_digest FOR UPDATE;
  IF NOT FOUND THEN RETURN NULL; END IF;
  IF transaction_record.expires_at <= statement_timestamp() THEN
    IF transaction_record.state IN ('pending','claimed') THEN
      UPDATE ONLY public.tenant_platform_oidc_authentication_transactions AS transaction_row
      SET state = 'expired', version = transaction_row.version + 1,
          completed_at = statement_timestamp(), failure_reason = 'expired'
      WHERE transaction_row.tenant_id = transaction_record.tenant_id
        AND transaction_row.transaction_id = transaction_record.transaction_id
        AND transaction_row.version = transaction_record.version;
    END IF;
    RETURN NULL;
  END IF;
  IF transaction_record.state = 'claimed' THEN
    IF transaction_record.claim_attempt_id IS DISTINCT FROM attempt_id
       OR transaction_record.claimed_at IS DISTINCT FROM claimed_at THEN
      RETURN NULL;
    END IF;
  ELSIF transaction_record.state = 'pending' THEN
    IF claimed_at < transaction_record.created_at THEN RETURN NULL; END IF;
    UPDATE ONLY public.tenant_platform_oidc_authentication_transactions AS transaction_row
    SET state = 'claimed', version = transaction_row.version + 1,
        claim_attempt_id = attempt_id, claimed_at = claimed_at
    WHERE transaction_row.tenant_id = transaction_record.tenant_id
      AND transaction_row.transaction_id = transaction_record.transaction_id
      AND transaction_row.state = 'pending'
      AND transaction_row.version = transaction_record.version
    RETURNING transaction_row.* INTO transaction_record;
    IF NOT FOUND THEN RETURN NULL; END IF;
  ELSE
    RETURN NULL;
  END IF;
  RETURN jsonb_build_object(
    'id', replace(encode(transaction_record.transaction_id, 'base64'), E'\n', ''),
    'stateDigest', replace(encode(transaction_record.state_digest, 'base64'), E'\n', ''),
    'browserDigest', replace(encode(transaction_record.browser_digest, 'base64'), E'\n', ''),
    'nonceDigest', replace(encode(transaction_record.nonce_digest, 'base64'), E'\n', ''),
    'verifierKeyVersion', transaction_record.verifier_key_version,
    'verifierCiphertext', replace(encode(transaction_record.verifier_ciphertext, 'base64'), E'\n', ''),
    'pins', jsonb_build_object(
      'provider', jsonb_build_object(
        'scope','platform','providerId',transaction_record.platform_provider_id::text
      ),
      'admission', jsonb_build_object(
        'tenantId',transaction_record.tenant_id::text,
        'bindingId',transaction_record.binding_id::text
      ),
      'providerRevision',transaction_record.provider_revision,
      'bindingRevision',transaction_record.binding_revision,
      'configurationRevision',transaction_record.configuration_revision,
      'securityRevision',transaction_record.security_revision,
      'mappingRevision',transaction_record.mapping_revision,
      'authorizationRevision',transaction_record.authorization_revision,
      'assurancePolicyRevision',transaction_record.assurance_policy_revision,
      'clientSecretRevision',transaction_record.client_secret_revision,
      'discoveryRevision',transaction_record.discovery_revision,
      'discoveryDigest',replace(encode(transaction_record.discovery_digest,'base64'),E'\n',''),
      'jwksRevision',transaction_record.jwks_revision,
      'jwksDigest',replace(encode(transaction_record.jwks_digest,'base64'),E'\n','')
    ),
    'clientId',transaction_record.client_id,
    'redirectUri',transaction_record.tenant_redirect_uri,
    'postLogoutRedirectUri',transaction_record.post_logout_redirect_uri,
    'returnPath',transaction_record.return_path,
    'scopes',to_jsonb(transaction_record.scopes),
    'allowRefreshToken',transaction_record.allow_refresh_token,
    'useUserInfo',transaction_record.use_user_info,
    'createdAt',to_jsonb(transaction_record.created_at),
    'expiresAt',to_jsonb(transaction_record.expires_at),
    'state',transaction_record.state,
    'version',transaction_record.version,
    'claimAttemptId',replace(encode(transaction_record.claim_attempt_id,'base64'),E'\n',''),
    'claimedAt',to_jsonb(transaction_record.claimed_at)
  );
EXCEPTION WHEN invalid_text_representation OR data_exception THEN
  RAISE EXCEPTION 'invalid tenant platform OIDC transaction claim'
    USING ERRCODE = '22023';
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.resolve_tenant_platform_oidc_authentication_v1(
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
  transaction_id bytea;
  expected_version bigint;
  transaction_record public.tenant_platform_oidc_authentication_transactions%ROWTYPE;
  expected_pins jsonb;
BEGIN
  PERFORM app.private_mfa_assert_json_object_v1(
    p_lookup, ARRAY['transactionId','expectedVersion','pins'],
    ARRAY['transactionId','expectedVersion','pins'], 65536
  );
  transaction_id := app.private_mfa_decode_base64_v1(
    p_lookup ->> 'transactionId', 32, 32
  );
  expected_version := (p_lookup ->> 'expectedVersion')::bigint;
  SELECT transaction_row.* INTO transaction_record
  FROM ONLY public.tenant_platform_oidc_authentication_transactions AS transaction_row
  WHERE transaction_row.transaction_id = transaction_id
    AND transaction_row.version = expected_version
    AND transaction_row.state = 'claimed'
    AND transaction_row.expires_at > statement_timestamp();
  IF NOT FOUND THEN RETURN NULL; END IF;
  expected_pins := jsonb_build_object(
    'provider', jsonb_build_object(
      'scope', 'platform',
      'providerId', transaction_record.platform_provider_id::text
    ),
    'admission', jsonb_build_object(
      'tenantId', transaction_record.tenant_id::text,
      'bindingId', transaction_record.binding_id::text
    ),
    'providerRevision', transaction_record.provider_revision,
    'bindingRevision', transaction_record.binding_revision,
    'configurationRevision', transaction_record.configuration_revision,
    'securityRevision', transaction_record.security_revision,
    'mappingRevision', transaction_record.mapping_revision,
    'authorizationRevision', transaction_record.authorization_revision,
    'assurancePolicyRevision', transaction_record.assurance_policy_revision,
    'clientSecretRevision', transaction_record.client_secret_revision,
    'discoveryRevision', transaction_record.discovery_revision,
    'discoveryDigest', replace(encode(transaction_record.discovery_digest, 'base64'), E'\n', ''),
    'jwksRevision', transaction_record.jwks_revision,
    'jwksDigest', replace(encode(transaction_record.jwks_digest, 'base64'), E'\n', '')
  );
  IF p_lookup -> 'pins' IS DISTINCT FROM expected_pins THEN RETURN NULL; END IF;
  RETURN app.private_tenant_platform_oidc_configuration_record_v1(
    transaction_record.tenant_id, transaction_record.platform_provider_id,
    transaction_record.binding_id, expected_pins
  ) - 'runtime' - 'runtimeAdmissionPolicy';
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range
  OR data_exception THEN
  RAISE EXCEPTION 'invalid tenant platform OIDC callback lookup'
    USING ERRCODE = '22023';
END;
$function$;

CREATE FUNCTION app.fail_tenant_platform_oidc_authentication_transaction_v1(
  p_request jsonb
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
#variable_conflict use_variable
DECLARE
  transaction_id bytea;
  expected_version bigint;
  failed_at timestamptz;
  reason text;
  target_state text;
  transaction_record public.tenant_platform_oidc_authentication_transactions%ROWTYPE;
BEGIN
  PERFORM app.private_mfa_assert_json_object_v1(
    p_request, ARRAY['id','expectedVersion','failedAt','reason','state'],
    ARRAY['id','expectedVersion','failedAt','reason','state'], 16384
  );
  transaction_id := app.private_mfa_decode_base64_v1(
    p_request ->> 'id', 32, 32
  );
  expected_version := (p_request ->> 'expectedVersion')::bigint;
  failed_at := (p_request ->> 'failedAt')::timestamptz;
  reason := p_request ->> 'reason';
  target_state := p_request ->> 'state';
  IF expected_version <> 2 OR reason NOT IN (
       'provider_response','stale_configuration','expired','token_exchange',
       'token_validation','identity_application'
     )
     OR target_state NOT IN ('failed','expired')
     OR (reason = 'expired') <> (target_state = 'expired')
     OR failed_at NOT BETWEEN statement_timestamp() - interval '5 minutes'
                           AND statement_timestamp() + interval '30 seconds' THEN
    RAISE EXCEPTION 'invalid tenant platform OIDC transaction failure'
      USING ERRCODE = '22023';
  END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended(
    'federated-transaction:oidc:id:' || encode(transaction_id,'hex'), 17283101
  ));
  SELECT transaction_row.* INTO transaction_record
  FROM ONLY public.tenant_platform_oidc_authentication_transactions AS transaction_row
  WHERE transaction_row.transaction_id = transaction_id FOR UPDATE;
  IF NOT FOUND THEN RETURN NULL; END IF;
  IF transaction_record.state = target_state
     AND transaction_record.version = expected_version + 1
     AND transaction_record.completed_at IS NOT DISTINCT FROM failed_at
     AND transaction_record.failure_reason IS NOT DISTINCT FROM reason THEN
    RETURN jsonb_build_object(
      'transactionId',replace(encode(transaction_id,'base64'),E'\n',''),
      'version',transaction_record.version,'state',transaction_record.state,
      'replayed',true
    );
  END IF;
  IF transaction_record.state <> 'claimed'
     OR transaction_record.version <> expected_version
     OR transaction_record.claimed_at IS NULL
     OR failed_at < transaction_record.claimed_at THEN
    RETURN NULL;
  END IF;
  UPDATE ONLY public.tenant_platform_oidc_authentication_transactions AS transaction_row
  SET state = target_state,
      version = transaction_row.version + 1,
      completed_at = failed_at,
      failure_reason = reason
  WHERE transaction_row.transaction_id = transaction_id
    AND transaction_row.version = expected_version
    AND transaction_row.state = 'claimed'
    AND transaction_row.claim_attempt_id = transaction_record.claim_attempt_id
    AND transaction_row.claimed_at = transaction_record.claimed_at
  RETURNING transaction_row.* INTO transaction_record;
  IF NOT FOUND THEN RETURN NULL; END IF;
  RETURN jsonb_build_object(
    'transactionId',replace(encode(transaction_id,'base64'),E'\n',''),
    'version',transaction_record.version,'state',transaction_record.state,
    'replayed',false
  );
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range
  OR data_exception THEN
  RAISE EXCEPTION 'invalid tenant platform OIDC transaction failure'
    USING ERRCODE = '22023';
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.begin_tenant_platform_oidc_authentication_v1(p_lookup jsonb)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  result jsonb;
BEGIN
  PERFORM app.private_federated_assert_begin_lookup_v1(p_lookup);
  SELECT app.private_tenant_platform_oidc_configuration_record_v1(
    tenant.id, binding.platform_provider_id, binding.id, NULL
  ) - 'runtime' - 'runtimeAdmissionPolicy' INTO result
  FROM ONLY public.tenants AS tenant
  JOIN ONLY public.tenant_auth_provider_login_keys AS login_key
    ON login_key.tenant_id = tenant.id
   AND login_key.binding_family = 'platform_provider'
   AND login_key.key = p_lookup ->> 'loginKey'
  JOIN ONLY public.tenant_platform_auth_provider_bindings AS binding
    ON binding.tenant_id = login_key.tenant_id
   AND binding.id = login_key.binding_id
   AND binding.key = login_key.key
  WHERE tenant.slug = p_lookup ->> 'tenantSlug' AND tenant.status = 'active';
  RETURN result;
EXCEPTION WHEN invalid_text_representation OR data_exception THEN
  RAISE EXCEPTION 'invalid tenant platform OIDC lookup'
    USING ERRCODE = '22023';
END;
$function$;

CREATE FUNCTION app.load_tenant_platform_oidc_client_secret_v1(p_lookup jsonb)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
#variable_conflict use_variable
DECLARE
  provider_id uuid;
  tenant_id uuid;
  binding_id uuid;
  revision bigint;
  result jsonb;
BEGIN
  PERFORM app.private_mfa_assert_json_object_v1(
    p_lookup, ARRAY['provider','admission','revision'],
    ARRAY['provider','admission','revision'], 16384
  );
  PERFORM app.private_mfa_assert_json_object_v1(
    p_lookup -> 'provider', ARRAY['scope','providerId'],
    ARRAY['scope','providerId'], 4096
  );
  PERFORM app.private_mfa_assert_json_object_v1(
    p_lookup -> 'admission', ARRAY['tenantId','bindingId'],
    ARRAY['tenantId','bindingId'], 4096
  );
  IF p_lookup #>> '{provider,scope}' <> 'platform' THEN
    RAISE EXCEPTION 'invalid tenant platform OIDC secret lookup'
      USING ERRCODE = '22023';
  END IF;
  provider_id := app.private_mfa_require_uuidv7_v1(
    p_lookup #>> '{provider,providerId}'
  );
  tenant_id := app.private_mfa_require_uuidv7_v1(
    p_lookup #>> '{admission,tenantId}'
  );
  binding_id := app.private_mfa_require_uuidv7_v1(
    p_lookup #>> '{admission,bindingId}'
  );
  revision := (p_lookup ->> 'revision')::bigint;
  IF revision < 1 THEN
    RAISE EXCEPTION 'invalid tenant platform OIDC secret lookup'
      USING ERRCODE = '22023';
  END IF;
  SELECT jsonb_build_object(
    'lookup', p_lookup,
    'secretId', secret.id::text,
    'keyVersion', secret.key_version,
    'nonce', replace(encode(secret.nonce, 'base64'), E'\n', ''),
    'ciphertext', replace(encode(secret.ciphertext, 'base64'), E'\n', '')
  ) INTO result
  FROM ONLY public.tenant_platform_auth_provider_bindings AS binding
  JOIN ONLY public.platform_auth_providers AS provider
    ON provider.id = binding.platform_provider_id
   AND provider.kind = 'oidc' AND provider.enabled
   AND provider.archived_at IS NULL
  JOIN ONLY public.platform_federated_provider_policies AS policy
    ON policy.provider_id = provider.id AND policy.enabled
   AND NOT policy.platform_login_enabled
  JOIN ONLY public.platform_oidc_provider_configurations AS configuration
    ON configuration.provider_id = provider.id
   AND configuration.client_secret_revision = revision
  JOIN ONLY public.platform_oidc_client_secrets AS secret
    ON secret.provider_id = configuration.provider_id
   AND secret.revision = revision AND secret.retired_at IS NULL
  JOIN ONLY public.identity_keyring_versions AS keyring
    ON keyring.key_version = secret.key_version
   AND keyring.retired_at IS NULL
  WHERE binding.tenant_id = tenant_id AND binding.id = binding_id
    AND binding.platform_provider_id = provider_id
    AND binding.enabled AND binding.archived_at IS NULL;
  RETURN result;
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range
  OR data_exception THEN
  RAISE EXCEPTION 'invalid tenant platform OIDC secret lookup'
    USING ERRCODE = '22023';
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.load_tenant_platform_federated_planning_state_v1(
  p_lookup jsonb
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
#variable_conflict use_variable
DECLARE
  tenant_id uuid;
  provider_id uuid;
  binding_id uuid;
  provider_revision bigint;
  binding_revision bigint;
  configuration_revision bigint;
  security_revision bigint;
  mapping_revision bigint;
  authorization_revision bigint;
  assurance_policy_revision bigint;
  plan_revision bigint;
  jit_mode text;
  no_match_policy text;
  access_epoch_id uuid;
  access_source_id uuid;
  alias_count integer;
  alias_index integer;
  alias_record jsonb;
  alias_key_versions integer[] := ARRAY[]::integer[];
  alias_digests bytea[] := ARRAY[]::bytea[];
  alias_digest bytea;
  identity_ids uuid[];
  user_ids uuid[];
  external_identity_id uuid;
  user_id uuid;
  membership_id uuid;
  identity_epoch bigint := 0;
  subject_match jsonb := 'null'::jsonb;
  user_active boolean := false;
  membership_active boolean := false;
  access_live boolean := false;
  policy_user_id uuid;
  mapping_snapshot jsonb;
  policy_snapshot jsonb;
  requirement jsonb;
  has_factor boolean := false;
BEGIN
  PERFORM app.private_mfa_assert_json_object_v1(
    p_lookup,
    ARRAY['protocol','tenantId','provider','admission','subjectFormat',
      'subjectAliases','providerRevision','bindingRevision',
      'configurationRevision','securityRevision','mappingRevision',
      'authorizationRevision','assurancePolicyRevision'],
    ARRAY['protocol','tenantId','provider','admission','subjectFormat',
      'subjectAliases','providerRevision','bindingRevision',
      'configurationRevision','securityRevision','mappingRevision',
      'authorizationRevision','assurancePolicyRevision'],262144
  );
  PERFORM app.private_mfa_assert_json_object_v1(
    p_lookup -> 'provider', ARRAY['scope','providerId'],
    ARRAY['scope','providerId'],4096
  );
  PERFORM app.private_mfa_assert_json_object_v1(
    p_lookup -> 'admission', ARRAY['tenantId','bindingId'],
    ARRAY['tenantId','bindingId'],4096
  );
  IF p_lookup ->> 'protocol' <> 'oidc'
     OR p_lookup ->> 'subjectFormat' <> 'utf8_exact'
     OR p_lookup #>> '{provider,scope}' <> 'platform'
     OR p_lookup ->> 'tenantId' IS DISTINCT FROM
       p_lookup #>> '{admission,tenantId}'
     OR jsonb_typeof(p_lookup -> 'subjectAliases') <> 'array' THEN
    RAISE EXCEPTION 'invalid tenant platform federated planning lookup'
      USING ERRCODE = '22023';
  END IF;
  tenant_id := app.private_mfa_require_uuidv7_v1(p_lookup ->> 'tenantId');
  provider_id := app.private_mfa_require_uuidv7_v1(
    p_lookup #>> '{provider,providerId}'
  );
  binding_id := app.private_mfa_require_uuidv7_v1(
    p_lookup #>> '{admission,bindingId}'
  );
  provider_revision := (p_lookup ->> 'providerRevision')::bigint;
  binding_revision := (p_lookup ->> 'bindingRevision')::bigint;
  configuration_revision := (p_lookup ->> 'configurationRevision')::bigint;
  security_revision := (p_lookup ->> 'securityRevision')::bigint;
  mapping_revision := (p_lookup ->> 'mappingRevision')::bigint;
  authorization_revision := (p_lookup ->> 'authorizationRevision')::bigint;
  assurance_policy_revision := (p_lookup ->> 'assurancePolicyRevision')::bigint;
  IF least(provider_revision,binding_revision,configuration_revision,
       security_revision,mapping_revision,authorization_revision,
       assurance_policy_revision) < 1 THEN
    RAISE EXCEPTION 'invalid tenant platform federated planning lookup'
      USING ERRCODE = '22023';
  END IF;
  alias_count := jsonb_array_length(p_lookup -> 'subjectAliases');
  IF alias_count NOT BETWEEN 1 AND 16 THEN
    RAISE EXCEPTION 'invalid tenant platform subject aliases'
      USING ERRCODE = '22023';
  END IF;
  FOR alias_index IN 0..alias_count - 1 LOOP
    alias_record := p_lookup -> 'subjectAliases' -> alias_index;
    PERFORM app.private_mfa_assert_json_object_v1(
      alias_record, ARRAY['keyVersion','digest'],
      ARRAY['keyVersion','digest'],4096
    );
    IF jsonb_typeof(alias_record -> 'keyVersion') <> 'number'
       OR jsonb_typeof(alias_record -> 'digest') <> 'string'
       OR (alias_record ->> 'keyVersion')::integer NOT BETWEEN 1 AND 32767
       OR (alias_index > 0 AND alias_key_versions[alias_index] >=
         (alias_record ->> 'keyVersion')::integer) THEN
      RAISE EXCEPTION 'invalid tenant platform subject aliases'
        USING ERRCODE = '22023';
    END IF;
    alias_digest := app.private_mfa_decode_base64_v1(
      alias_record ->> 'digest',32,32
    );
    IF encode(alias_digest,'hex') = repeat('00',32)
       OR NOT EXISTS (
         SELECT 1 FROM ONLY public.identity_keyring_versions AS keyring
         WHERE keyring.key_version = (alias_record ->> 'keyVersion')::integer
           AND keyring.retired_at IS NULL
       ) THEN
      RAISE EXCEPTION 'invalid tenant platform subject aliases'
        USING ERRCODE = '22023';
    END IF;
    alias_key_versions := array_append(
      alias_key_versions,(alias_record ->> 'keyVersion')::integer
    );
    alias_digests := array_append(alias_digests,alias_digest);
  END LOOP;

  SELECT policy.plan_revision,
         CASE WHEN policy.account_mode = 'create' AND binding.jit_mode = 'create'
           THEN 'create' ELSE 'disabled' END,
         binding.no_match_policy,binding.current_access_epoch_id,epoch.source_id
    INTO STRICT plan_revision,jit_mode,no_match_policy,
      access_epoch_id,access_source_id
  FROM ONLY public.tenants AS tenant
  JOIN ONLY public.tenant_platform_auth_provider_bindings AS binding
    ON binding.tenant_id = tenant.id AND binding.id = binding_id
   AND binding.platform_provider_id = provider_id
   AND binding.enabled AND binding.archived_at IS NULL
   AND binding.current_access_epoch_id IS NOT NULL
  JOIN ONLY public.platform_auth_providers AS provider
    ON provider.id = binding.platform_provider_id
   AND provider.kind = 'oidc' AND provider.enabled
   AND provider.archived_at IS NULL
  JOIN ONLY public.platform_federated_provider_policies AS policy
    ON policy.provider_id = provider.id AND policy.provider_kind = 'oidc'
   AND policy.enabled AND NOT policy.platform_login_enabled
   AND policy.account_mode <> 'disabled'
  JOIN ONLY public.tenant_platform_identity_provider_access_epochs AS epoch
    ON epoch.tenant_id = binding.tenant_id
   AND epoch.id = binding.current_access_epoch_id
   AND epoch.binding_id = binding.id
   AND epoch.platform_provider_id = binding.platform_provider_id
   AND epoch.ended_at IS NULL
  JOIN ONLY public.tenant_authorization_sources AS source
    ON source.tenant_id = epoch.tenant_id AND source.id = epoch.source_id
   AND source.kind = 'identity_provider_access'
   AND source.authoritative AND NOT source.protected
   AND source.key = format(
     'identity_provider_access:%s:%s',epoch.binding_id,epoch.sequence
   )
   AND source.retired_at IS NULL
  JOIN ONLY public.platform_oidc_provider_configurations AS configuration
    ON configuration.provider_id = provider.id
   AND configuration.version = policy.configuration_revision
  WHERE tenant.id = tenant_id AND tenant.status = 'active'
    AND binding.version = binding_revision
    AND binding.mapping_revision = mapping_revision
    AND binding.auth_revision = authorization_revision
    AND policy.configuration_revision = configuration_revision
    AND policy.security_revision = security_revision
    AND policy.assurance_policy_revision = assurance_policy_revision;

  WITH wanted AS (
    SELECT alias.key_version,alias.digest
    FROM unnest(alias_key_versions,alias_digests)
      AS alias(key_version,digest)
  ), matches AS (
    SELECT DISTINCT identity.id,identity.user_id
    FROM wanted
    JOIN ONLY public.platform_federated_external_identity_aliases AS alias
      ON alias.platform_provider_id = provider_id
     AND alias.key_version = wanted.key_version
     AND alias.subject_digest = wanted.digest
     AND alias.retired_at IS NULL
    JOIN ONLY public.platform_federated_external_identities AS identity
      ON identity.platform_provider_id = alias.platform_provider_id
     AND identity.id = alias.external_identity_id
     AND identity.retired_at IS NULL
  )
  SELECT array_agg(DISTINCT matches.id ORDER BY matches.id),
         array_agg(DISTINCT matches.user_id ORDER BY matches.user_id)
    INTO identity_ids,user_ids FROM matches;
  IF coalesce(cardinality(identity_ids),0) > 1
     OR coalesce(cardinality(user_ids),0) > 1 THEN
    RAISE EXCEPTION 'tenant platform subject aliases disagree'
      USING ERRCODE = '23505';
  END IF;
  external_identity_id := identity_ids[1];
  user_id := user_ids[1];
  IF external_identity_id IS NULL THEN
    external_identity_id := uuidv7();
  ELSE
    SELECT local_user.active,membership.id,
           coalesce(membership.status = 'active',false),subject.identity_epoch
      INTO STRICT user_active,membership_id,membership_active,identity_epoch
    FROM ONLY public.platform_federated_external_identities AS identity
    JOIN ONLY public.users AS local_user ON local_user.id = identity.user_id
    LEFT JOIN ONLY public.tenant_memberships AS membership
      ON membership.tenant_id = tenant_id AND membership.user_id = local_user.id
    LEFT JOIN ONLY public.tenant_mfa_subjects AS subject
      ON subject.tenant_id = tenant_id AND subject.user_id = local_user.id
    WHERE identity.platform_provider_id = provider_id
      AND identity.id = external_identity_id AND identity.user_id = user_id
      AND identity.retired_at IS NULL;
    IF membership_id IS NOT NULL AND identity_epoch IS NULL THEN
      RETURN NULL;
    END IF;
    identity_epoch := coalesce(identity_epoch,1);
    SELECT jsonb_build_object(
      'externalIdentityId',external_identity_id::text,
      'alias',jsonb_build_object(
        'keyVersion',alias.key_version,
        'digest',replace(encode(alias.subject_digest,'base64'),E'\n','')
      )
    ) INTO STRICT subject_match
    FROM ONLY public.platform_federated_external_identity_aliases AS alias
    JOIN unnest(alias_key_versions,alias_digests)
      WITH ORDINALITY AS wanted(key_version,digest,ordinality)
      ON wanted.key_version = alias.key_version
     AND wanted.digest = alias.subject_digest
    WHERE alias.platform_provider_id = provider_id
      AND alias.external_identity_id = external_identity_id
      AND alias.retired_at IS NULL
    ORDER BY wanted.ordinality DESC LIMIT 1;
    IF membership_id IS NOT NULL THEN
      SELECT EXISTS (
        SELECT 1
        FROM ONLY public.tenant_platform_federated_provider_access_grants AS grant_row
        WHERE grant_row.tenant_id = tenant_id
          AND grant_row.platform_provider_id = provider_id
          AND grant_row.binding_id = binding_id
          AND grant_row.access_epoch_id = access_epoch_id
          AND grant_row.source_id = access_source_id
          AND grant_row.external_identity_id = external_identity_id
          AND grant_row.user_id = user_id
          AND grant_row.membership_id = membership_id
          AND grant_row.ended_at IS NULL
      ) INTO access_live;
    END IF;
  END IF;

  mapping_snapshot := jsonb_build_object(
    'tenantId',tenant_id::text,
    'provider',p_lookup -> 'provider',
    'admission',p_lookup -> 'admission',
    'configurationRevision',configuration_revision,
    'ruleSetRevision',mapping_revision,
    'authorizationRevision',authorization_revision,
    'jitMode',jit_mode,'noMatchPolicy',no_match_policy,
    'effectiveUntil','null'::jsonb,
    'providerAccess',jsonb_build_object(
      'sourceId',access_source_id::text,
      'accessEpochId',access_epoch_id::text,
      'externalIdentityExists',user_id IS NOT NULL,
      'userActive',user_active,
      'tenantMembershipExists',membership_id IS NOT NULL,
      'tenantMembershipActive',membership_active,
      'accessGrantLive',access_live
    ),
    'rules','[]'::jsonb,
    'securityGroups','[]'::jsonb,
    'liveAssignments','[]'::jsonb,
    'rolePolicies','[]'::jsonb,
    'existingEffectiveRoleIds','[]'::jsonb,
    'delegation','[]'::jsonb,
    'liveOwnedEdges','[]'::jsonb
  );
  policy_user_id := CASE WHEN user_active AND membership_active
    THEN user_id ELSE NULL END;
  policy_snapshot := app.private_mfa_policy_snapshot_v1(
    tenant_id,policy_user_id,'session.create',transaction_timestamp()
  );
  requirement := policy_snapshot -> 'requirement';
  IF policy_user_id IS NOT NULL THEN
    SELECT EXISTS (
      SELECT 1 FROM ONLY public.tenant_totp_factors AS factor
      WHERE factor.tenant_id = tenant_id AND factor.user_id = policy_user_id
        AND factor.status = 'active'
      UNION ALL
      SELECT 1 FROM ONLY public.tenant_webauthn_credentials AS credential
      WHERE credential.tenant_id = tenant_id
        AND credential.user_id = policy_user_id
        AND credential.status = 'active'
    ) INTO has_factor;
  END IF;
  RETURN jsonb_build_object(
    'lookup',p_lookup,'planRevision',plan_revision,
    'userId',CASE WHEN user_id IS NULL THEN 'null'::jsonb
      ELSE to_jsonb(user_id::text) END,
    'identityEpoch',identity_epoch,
    'externalIdentityId',external_identity_id::text,
    'subjectMatch',subject_match,
    'providerRevision',provider_revision,
    'bindingRevision',binding_revision,
    'securityRevision',security_revision,
    'assurancePolicyRevision',assurance_policy_revision,
    'mapping',mapping_snapshot,'requirement',requirement,
    'hasEnrollableFactor',has_factor
  );
EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
  RETURN NULL;
WHEN invalid_text_representation OR numeric_value_out_of_range
  OR data_exception THEN
  RAISE EXCEPTION 'invalid tenant platform federated planning lookup'
    USING ERRCODE = '22023';
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.load_tenant_platform_oidc_trust_snapshot_v1(p_lookup jsonb)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
#variable_conflict use_variable
DECLARE
  tenant_id uuid;
  provider_id uuid;
  binding_id uuid;
  provider_revision bigint;
  result jsonb;
BEGIN
  PERFORM app.private_mfa_assert_json_object_v1(
    p_lookup,
    ARRAY['tenantId','provider','admission','providerRevision','bindingRevision',
      'securityRevision','assurancePolicyRevision'],
    ARRAY['tenantId','provider','admission','providerRevision','bindingRevision',
      'securityRevision','assurancePolicyRevision'],32768
  );
  PERFORM app.private_mfa_assert_json_object_v1(
    p_lookup -> 'provider',ARRAY['scope','providerId'],
    ARRAY['scope','providerId'],4096
  );
  PERFORM app.private_mfa_assert_json_object_v1(
    p_lookup -> 'admission',ARRAY['tenantId','bindingId'],
    ARRAY['tenantId','bindingId'],4096
  );
  IF p_lookup #>> '{provider,scope}' <> 'platform'
     OR p_lookup ->> 'tenantId' IS DISTINCT FROM
       p_lookup #>> '{admission,tenantId}' THEN
    RAISE EXCEPTION 'invalid tenant platform OIDC trust lookup'
      USING ERRCODE = '22023';
  END IF;
  tenant_id := app.private_mfa_require_uuidv7_v1(p_lookup ->> 'tenantId');
  provider_id := app.private_mfa_require_uuidv7_v1(
    p_lookup #>> '{provider,providerId}'
  );
  binding_id := app.private_mfa_require_uuidv7_v1(
    p_lookup #>> '{admission,bindingId}'
  );
  provider_revision := (p_lookup ->> 'providerRevision')::bigint;
  IF provider_revision NOT BETWEEN 1 AND 2147483647 THEN
    RAISE EXCEPTION 'invalid tenant platform OIDC trust lookup'
      USING ERRCODE = '22023';
  END IF;
  WITH live AS (
    SELECT provider.id
    FROM ONLY public.tenants AS tenant
    JOIN ONLY public.tenant_platform_auth_provider_bindings AS binding
      ON binding.tenant_id = tenant.id AND binding.id = binding_id
     AND binding.platform_provider_id = provider_id
     AND binding.enabled AND binding.archived_at IS NULL
     AND binding.current_access_epoch_id IS NOT NULL
    JOIN ONLY public.platform_auth_providers AS provider
      ON provider.id = binding.platform_provider_id
     AND provider.kind = 'oidc' AND provider.enabled
     AND provider.archived_at IS NULL
    JOIN ONLY public.platform_federated_provider_policies AS policy
      ON policy.provider_id = provider.id AND policy.provider_kind = 'oidc'
     AND policy.enabled AND NOT policy.platform_login_enabled
    JOIN ONLY public.tenant_platform_identity_provider_access_epochs AS epoch
      ON epoch.tenant_id = binding.tenant_id
     AND epoch.id = binding.current_access_epoch_id
     AND epoch.binding_id = binding.id
     AND epoch.platform_provider_id = provider.id
     AND epoch.ended_at IS NULL
    JOIN ONLY public.tenant_authorization_sources AS source
      ON source.tenant_id = epoch.tenant_id AND source.id = epoch.source_id
     AND source.kind = 'identity_provider_access'
     AND source.authoritative AND NOT source.protected
     AND source.key = format(
       'identity_provider_access:%s:%s',epoch.binding_id,epoch.sequence
     )
     AND source.retired_at IS NULL
    WHERE tenant.id = tenant_id AND tenant.status = 'active'
      AND binding.version = (p_lookup ->> 'bindingRevision')::bigint
      AND policy.security_revision = (p_lookup ->> 'securityRevision')::bigint
      AND policy.assurance_policy_revision =
        (p_lookup ->> 'assurancePolicyRevision')::bigint
  )
  SELECT jsonb_build_object(
    'lookup',p_lookup,
    'rules',coalesce((
      SELECT jsonb_agg(jsonb_build_object(
        'ruleId',rule.id::text,'revision',rule.revision,
        'enabled',rule.enabled,'level',rule.level,
        'acr',CASE WHEN rule.exact_value IS NULL THEN 'null'::jsonb
          ELSE to_jsonb(rule.exact_value) END,
        'requiredAmr',to_jsonb(rule.required_values),
        'maximumAuthenticationAgeSeconds',
          rule.maximum_authentication_age_seconds
      ) ORDER BY rule.id,rule.revision)
      FROM ONLY public.platform_federated_trust_rules AS rule
      WHERE rule.provider_id = provider_id AND rule.provider_kind = 'oidc'
        AND rule.revision = (p_lookup ->> 'securityRevision')::bigint
        AND rule.retired_at IS NULL
    ),'[]'::jsonb)
  ) INTO result FROM live;
  -- An empty rule set is valid only for primary OIDC proof. It can never
  -- synthesize MFA or phishing-resistant evidence.
  RETURN result;
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range
  OR data_exception THEN
  RAISE EXCEPTION 'invalid tenant platform OIDC trust lookup'
    USING ERRCODE = '22023';
END;
$function$;
--> statement-breakpoint

-- The generic MFA authority ABI predates tenant-admitted platform providers.
-- Project their typed evidence alongside the existing local/tenant-provider
-- evidence without ever storing a platform provider in the tenant-provider FK
-- columns.  Anchor projections dereference immutable session/continuation
-- evidence so the ceremony sees the same baseline that was resolved.
CREATE OR REPLACE FUNCTION app.private_mfa_evidence_projection_v1(
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
  v_result jsonb;
BEGIN
  IF p_tenant_id IS NULL OR p_source_id IS NULL
     OR p_source_kind NOT IN ('session','continuation','anchor') THEN
    RAISE EXCEPTION 'invalid MFA evidence source' USING ERRCODE = '22023';
  END IF;

  WITH evidence_rows AS (
    SELECT 1 AS source_family,evidence.id,evidence.level,
      CASE WHEN evidence.kind = 'recovery' THEN 'recovery' ELSE 'factor' END
        AS kind,
      evidence.kind <> 'provider' AS local,evidence.provider_id,
      evidence.binding_id,evidence.authenticated_at,evidence.expires_at,
      evidence.factor_revision,evidence.trust_rule_revision
    FROM ONLY public.auth_session_mfa_evidence AS evidence
    WHERE p_source_kind = 'session' AND evidence.tenant_id = p_tenant_id
      AND evidence.session_id = p_source_id
    UNION ALL
    SELECT 2,evidence.id,evidence.level,'factor',false,
      evidence.platform_provider_id,evidence.binding_id,
      evidence.authenticated_at,evidence.expires_at,NULL::bigint,
      evidence.trust_rule_revision
    FROM ONLY public.auth_session_tenant_platform_federated_evidence AS evidence
    WHERE p_source_kind = 'session' AND evidence.tenant_id = p_tenant_id
      AND evidence.session_id = p_source_id
    UNION ALL
    SELECT 3,evidence.id,evidence.level,
      CASE WHEN evidence.kind = 'recovery' THEN 'recovery' ELSE 'factor' END,
      evidence.kind <> 'provider',evidence.provider_id,evidence.binding_id,
      evidence.authenticated_at,evidence.expires_at,evidence.factor_revision,
      evidence.trust_rule_revision
    FROM ONLY public.tenant_post_primary_continuation_evidence AS evidence
    WHERE p_source_kind = 'continuation'
      AND evidence.tenant_id = p_tenant_id
      AND evidence.continuation_id = p_source_id
    UNION ALL
    SELECT 4,evidence.id,evidence.level,'factor',false,
      evidence.platform_provider_id,evidence.binding_id,
      evidence.authenticated_at,evidence.expires_at,NULL::bigint,
      evidence.trust_rule_revision
    FROM ONLY public.tenant_post_primary_platform_federated_evidence AS evidence
    WHERE p_source_kind = 'continuation'
      AND evidence.tenant_id = p_tenant_id
      AND evidence.continuation_id = p_source_id
    UNION ALL
    SELECT 5,evidence.id,evidence.level,
      CASE WHEN evidence.kind = 'recovery' THEN 'recovery' ELSE 'factor' END,
      evidence.kind <> 'provider',evidence.provider_id,evidence.binding_id,
      evidence.authenticated_at,evidence.expires_at,evidence.factor_revision,
      evidence.trust_rule_revision
    FROM ONLY public.tenant_mfa_authority_evidence AS evidence
    WHERE p_source_kind = 'anchor' AND evidence.tenant_id = p_tenant_id
      AND evidence.anchor_id = p_source_id
    UNION ALL
    SELECT 6,evidence.id,evidence.level,'factor',false,
      evidence.platform_provider_id,evidence.binding_id,
      evidence.authenticated_at,evidence.expires_at,NULL::bigint,
      evidence.trust_rule_revision
    FROM ONLY public.tenant_mfa_authority_platform_federated_evidence AS evidence
    WHERE p_source_kind = 'anchor' AND evidence.tenant_id = p_tenant_id
      AND evidence.anchor_id = p_source_id
  )
  SELECT coalesce(jsonb_agg(jsonb_strip_nulls(jsonb_build_object(
    'level',evidence.level,'kind',evidence.kind,'local',evidence.local,
    'providerId',evidence.provider_id::text,
    'bindingId',evidence.binding_id::text,
    'authenticatedAt',evidence.authenticated_at,
    'expiresAt',evidence.expires_at,
    'factorRevision',evidence.factor_revision,
    'trustRuleRevision',evidence.trust_rule_revision
  )) ORDER BY evidence.authenticated_at,evidence.source_family,evidence.id),
    '[]'::jsonb)
  INTO v_result FROM evidence_rows AS evidence;
  RETURN v_result;
END;
$function$;
--> statement-breakpoint

-- Complete MFA for a tenant-admitted platform primary without crossing the
-- tenant-provider provenance boundary.  Initial-login continuations recover
-- their immutable ceremony pins from the application ledger.  Revalidation
-- continuations recover an exact source session from the immutable command
-- ledger and behave as a rotation: the family and absolute deadline cannot
-- change and the source is revoked before the successor authority is issued.
CREATE FUNCTION app.private_mfa_apply_tenant_platform_federated_session_v1(
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
#variable_conflict use_variable
DECLARE
  anchor_record public.tenant_mfa_authority_anchors%ROWTYPE;
  anchor_binding jsonb;
  mutation text;
  reservation jsonb;
  tenant_id uuid;
  user_id uuid;
  membership_id uuid;
  identity_epoch bigint;
  session_epoch bigint;
  source_session public.auth_sessions%ROWTYPE;
  source_state public.auth_session_mfa_states%ROWTYPE;
  source_provenance
    public.auth_session_tenant_platform_federated_provenance%ROWTYPE;
  continuation_record public.tenant_post_primary_continuations%ROWTYPE;
  continuation_provenance
    public.tenant_post_primary_platform_federated_provenance%ROWTYPE;
  new_session_id uuid;
  new_family_id uuid;
  token_digest bytea;
  csrf_digest bytea;
  authentication_method text;
  idle_expires_at timestamptz;
  absolute_expires_at timestamptz;
  token_lock bigint;
  csrf_lock bigint;
  new_version bigint;
  consumed_continuation_id uuid;
  source_bound boolean := false;
  evidence_count bigint;
BEGIN
  PERFORM app.private_mfa_assert_json_object_v1(
    p_session,
    ARRAY['mutation','expectedSessionId','expectedFamilyId',
      'expectedContinuationId','expectedAnchorVersion','expectedIdentityEpoch',
      'expectedAnchorExpiry','audience','requirement','recoveryRestricted',
      'reservation'],
    ARRAY['mutation','expectedAnchorVersion','expectedIdentityEpoch',
      'expectedAnchorExpiry','audience','requirement','recoveryRestricted',
      'reservation'],131072
  );
  SELECT anchor.* INTO STRICT anchor_record
  FROM ONLY public.tenant_mfa_authority_anchors AS anchor
  WHERE anchor.id = p_anchor_id FOR UPDATE;
  anchor_binding := app.private_mfa_anchor_binding_v1(p_anchor_id);
  mutation := p_session ->> 'mutation';
  IF anchor_record.flow NOT IN ('session','continuation')
     OR mutation NOT IN ('rotate','consume_continuation')
     OR NOT app.private_mfa_safe_text_v1(p_session ->> 'audience',256)
     OR p_session ->> 'audience' IS DISTINCT FROM anchor_record.audience
      OR jsonb_typeof(p_session -> 'requirement') IS DISTINCT FROM 'object'
      OR jsonb_strip_nulls(p_session -> 'requirement') IS DISTINCT FROM
           jsonb_strip_nulls(anchor_binding -> 'requirement')
     OR (p_session ->> 'expectedAnchorVersion')::bigint
          IS DISTINCT FROM anchor_record.anchor_version
     OR (p_session ->> 'expectedIdentityEpoch')::bigint
          IS DISTINCT FROM anchor_record.identity_epoch
     OR (p_session ->> 'expectedAnchorExpiry')::timestamptz
          IS DISTINCT FROM anchor_record.anchor_expires_at
     OR p_completed_at IS NULL
     OR abs(extract(epoch FROM (transaction_timestamp() - p_completed_at))) > 300 THEN
    RAISE EXCEPTION 'tenant platform MFA session intent drifted'
      USING ERRCODE = '40001';
  END IF;
  tenant_id := anchor_record.tenant_id;
  user_id := anchor_record.user_id;
  identity_epoch := anchor_record.identity_epoch;
  SELECT subject.session_invalidation_epoch,membership.id
    INTO STRICT session_epoch,membership_id
  FROM ONLY public.tenant_mfa_subjects AS subject
  JOIN ONLY public.tenant_memberships AS membership
    ON membership.tenant_id = subject.tenant_id
   AND membership.user_id = subject.user_id AND membership.status = 'active'
  JOIN ONLY public.users AS local_user
    ON local_user.id = subject.user_id AND local_user.active
  JOIN ONLY public.tenants AS tenant
    ON tenant.id = subject.tenant_id AND tenant.status = 'active'
  WHERE subject.tenant_id = tenant_id AND subject.user_id = user_id
    AND subject.identity_epoch = identity_epoch;

  reservation := p_session -> 'reservation';
  PERFORM app.private_mfa_assert_json_object_v1(
    reservation,
    ARRAY['sessionId','familyId','tokenDigest','csrfDigest',
      'authenticationMethod','idleExpiresAt','absoluteExpiresAt'],
    ARRAY['sessionId','familyId','tokenDigest','csrfDigest',
      'authenticationMethod','idleExpiresAt','absoluteExpiresAt'],16384
  );
  new_session_id := app.private_mfa_require_uuidv7_v1(
    reservation ->> 'sessionId'
  );
  new_family_id := app.private_mfa_require_uuidv7_v1(
    reservation ->> 'familyId'
  );
  token_digest := app.private_mfa_decode_base64_v1(
    reservation ->> 'tokenDigest',32,32
  );
  csrf_digest := app.private_mfa_decode_base64_v1(
    reservation ->> 'csrfDigest',32,32
  );
  authentication_method := reservation ->> 'authenticationMethod';
  idle_expires_at := (reservation ->> 'idleExpiresAt')::timestamptz;
  absolute_expires_at := (reservation ->> 'absoluteExpiresAt')::timestamptz;
  IF authentication_method NOT IN ('passkey','totp','recovery_code')
     OR encode(token_digest,'hex') = repeat('00',32)
     OR encode(csrf_digest,'hex') = repeat('00',32)
     OR token_digest = csrf_digest OR new_session_id = new_family_id
     OR idle_expires_at <= p_completed_at
     OR absolute_expires_at < idle_expires_at
     OR idle_expires_at > p_completed_at + interval '24 hours'
     OR absolute_expires_at > p_completed_at + interval '31 days'
     OR date_trunc('milliseconds',idle_expires_at) <> idle_expires_at
     OR date_trunc('milliseconds',absolute_expires_at) <> absolute_expires_at THEN
    RAISE EXCEPTION 'invalid tenant platform MFA session reservation'
      USING ERRCODE = '22023';
  END IF;

  IF anchor_record.flow = 'session' THEN
    IF mutation <> 'rotate'
       OR app.private_mfa_require_uuidv7_v1(p_session ->> 'expectedSessionId')
          IS DISTINCT FROM anchor_record.session_id
       OR app.private_mfa_require_uuidv7_v1(p_session ->> 'expectedFamilyId')
          IS DISTINCT FROM anchor_record.session_family_id
       OR p_session ? 'expectedContinuationId' THEN
      RAISE EXCEPTION 'invalid tenant platform session rotation intent'
        USING ERRCODE = '22023';
    END IF;
    SELECT session.* INTO STRICT source_session
    FROM ONLY public.auth_sessions AS session
    WHERE session.id = anchor_record.session_id AND session.user_id = user_id
      AND session.rotation_family_id = anchor_record.session_family_id
      AND session.active_tenant_id = tenant_id AND session.revoked_at IS NULL
      AND session.idle_expires_at = anchor_record.anchor_expires_at
      AND session.idle_expires_at > p_completed_at
      AND session.absolute_expires_at > p_completed_at FOR UPDATE;
    SELECT state.* INTO STRICT source_state
    FROM ONLY public.auth_session_mfa_states AS state
    WHERE state.tenant_id = tenant_id AND state.session_id = source_session.id
      AND state.user_id = user_id
      AND state.primary_kind = 'tenant_platform_provider'
      AND state.session_version = anchor_record.anchor_version
      AND state.identity_epoch = identity_epoch
      AND state.session_invalidation_epoch = session_epoch FOR UPDATE;
    SELECT provenance.* INTO STRICT source_provenance
    FROM ONLY public.auth_session_tenant_platform_federated_provenance
      AS provenance
    WHERE provenance.tenant_id = tenant_id
      AND provenance.session_id = source_session.id
      AND provenance.user_id = user_id;
    source_bound := true;
  ELSE
    IF mutation <> 'consume_continuation'
       OR app.private_mfa_require_uuidv7_v1(
            p_session ->> 'expectedContinuationId'
          ) IS DISTINCT FROM anchor_record.continuation_id
       OR p_session ? 'expectedSessionId' OR p_session ? 'expectedFamilyId' THEN
      RAISE EXCEPTION 'invalid tenant platform continuation consumption intent'
        USING ERRCODE = '22023';
    END IF;
    SELECT continuation.* INTO STRICT continuation_record
    FROM ONLY public.tenant_post_primary_continuations AS continuation
    WHERE continuation.tenant_id = tenant_id
      AND continuation.id = anchor_record.continuation_id
      AND continuation.user_id = user_id
      AND continuation.identity_epoch = identity_epoch
      AND continuation.session_invalidation_epoch = session_epoch
      AND continuation.primary_kind = 'tenant_platform_provider'
      AND continuation.state = 'pending'
      AND continuation.version = anchor_record.anchor_version
      AND continuation.expires_at = anchor_record.anchor_expires_at
      AND continuation.expires_at > p_completed_at FOR UPDATE;

    SELECT provenance.* INTO STRICT continuation_provenance
    FROM ONLY public.tenant_post_primary_platform_federated_provenance
      AS provenance
    WHERE provenance.tenant_id = tenant_id
      AND provenance.continuation_id = continuation_record.id
      AND provenance.user_id = user_id
      AND provenance.platform_provider_id =
        continuation_record.platform_provider_id
      AND provenance.binding_id = continuation_record.binding_id
      AND provenance.external_identity_id =
        continuation_record.external_identity_id
      AND provenance.external_identity_revision =
        continuation_record.primary_revision;

    source_provenance.tenant_id := continuation_provenance.tenant_id;
    source_provenance.user_id := continuation_provenance.user_id;
    source_provenance.primary_kind := 'tenant_platform_provider';
    source_provenance.authentication_method := 'oidc';
    source_provenance.platform_provider_id :=
      continuation_provenance.platform_provider_id;
    source_provenance.binding_id := continuation_provenance.binding_id;
    source_provenance.access_epoch_id := continuation_provenance.access_epoch_id;
    source_provenance.access_source_id := continuation_provenance.access_source_id;
    source_provenance.access_grant_id := continuation_provenance.access_grant_id;
    source_provenance.membership_id := continuation_provenance.membership_id;
    source_provenance.external_identity_id :=
      continuation_provenance.external_identity_id;
    source_provenance.external_identity_revision :=
      continuation_provenance.external_identity_revision;
    source_provenance.provider_revision := continuation_provenance.provider_revision;
    source_provenance.binding_revision := continuation_provenance.binding_revision;
    source_provenance.security_revision := continuation_provenance.security_revision;
    source_provenance.mapping_revision := continuation_provenance.mapping_revision;
    source_provenance.authorization_revision :=
      continuation_provenance.authorization_revision;
    source_provenance.subject_alias_key_version :=
      continuation_provenance.subject_alias_key_version;
    source_provenance.trust_rule_revision :=
      continuation_provenance.trust_rule_revision;
    source_provenance.authenticated_at := continuation_provenance.authenticated_at;

    IF continuation_provenance.origin = 'session_revalidation' THEN
      SELECT session.* INTO STRICT source_session
      FROM ONLY public.auth_sessions AS session
      WHERE session.id = continuation_provenance.source_session_id
        AND session.user_id = user_id AND session.active_tenant_id = tenant_id
        AND session.rotation_family_id =
          continuation_provenance.source_session_family_id
        AND session.absolute_expires_at =
          continuation_provenance.source_absolute_expires_at
        AND session.revoked_at IS NULL
        AND session.idle_expires_at > p_completed_at
        AND session.absolute_expires_at > p_completed_at FOR UPDATE;
      SELECT state.* INTO STRICT source_state
      FROM ONLY public.auth_session_mfa_states AS state
      WHERE state.tenant_id = tenant_id AND state.session_id = source_session.id
        AND state.user_id = user_id
        AND state.primary_kind = 'tenant_platform_provider'
        AND state.session_version = continuation_provenance.source_session_version
        AND state.identity_epoch = identity_epoch
        AND state.session_invalidation_epoch = session_epoch FOR UPDATE;
      SELECT provenance.* INTO STRICT source_provenance
      FROM ONLY public.auth_session_tenant_platform_federated_provenance
        AS provenance
      WHERE provenance.tenant_id = tenant_id
        AND provenance.session_id = source_session.id
        AND provenance.user_id = user_id
        AND ROW(provenance.platform_provider_id,provenance.binding_id,
          provenance.access_epoch_id,provenance.access_source_id,
          provenance.access_grant_id,provenance.membership_id,
          provenance.external_identity_id,provenance.external_identity_revision,
          provenance.provider_revision,provenance.binding_revision,
          provenance.security_revision,provenance.mapping_revision,
          provenance.authorization_revision,provenance.subject_alias_key_version,
          provenance.trust_rule_revision,provenance.authenticated_at)
          IS NOT DISTINCT FROM ROW(
          continuation_provenance.platform_provider_id,
          continuation_provenance.binding_id,
          continuation_provenance.access_epoch_id,
          continuation_provenance.access_source_id,
          continuation_provenance.access_grant_id,
          continuation_provenance.membership_id,
          continuation_provenance.external_identity_id,
          continuation_provenance.external_identity_revision,
          continuation_provenance.provider_revision,
          continuation_provenance.binding_revision,
          continuation_provenance.security_revision,
          continuation_provenance.mapping_revision,
          continuation_provenance.authorization_revision,
          continuation_provenance.subject_alias_key_version,
          continuation_provenance.trust_rule_revision,
          continuation_provenance.authenticated_at);
      source_bound := true;
    ELSIF continuation_provenance.origin = 'initial_login' THEN
      source_bound := false;
    ELSE
      RAISE EXCEPTION 'tenant platform continuation origin is invalid'
        USING ERRCODE = '23514';
    END IF;

    UPDATE ONLY public.tenant_post_primary_continuations AS continuation
    SET state = 'consumed',version = continuation.version + 1,
        consumed_at = p_completed_at
    WHERE continuation.tenant_id = tenant_id
      AND continuation.id = continuation_record.id
      AND continuation.state = 'pending'
      AND continuation.version = continuation_record.version
    RETURNING continuation.id,continuation.version
      INTO consumed_continuation_id,new_version;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'tenant platform continuation consumption lost CAS'
        USING ERRCODE = '40001';
    END IF;
  END IF;

  IF source_bound THEN
    IF new_session_id = source_session.id
       OR new_family_id IS DISTINCT FROM source_session.rotation_family_id
       OR absolute_expires_at IS DISTINCT FROM source_session.absolute_expires_at
       OR source_session.revoked_at IS NOT NULL THEN
      RAISE EXCEPTION 'tenant platform MFA rotation changed family or deadline'
        USING ERRCODE = '22023';
    END IF;
    new_version := source_state.session_version + 1;
  END IF;

  PERFORM 1
  FROM ONLY public.platform_auth_providers AS provider
  JOIN ONLY public.platform_federated_provider_policies AS policy
    ON policy.provider_id = provider.id AND policy.provider_kind = 'oidc'
   AND policy.enabled AND NOT policy.platform_login_enabled
   AND policy.security_revision = source_provenance.security_revision
  JOIN ONLY public.tenant_platform_auth_provider_bindings AS binding
    ON binding.platform_provider_id = provider.id
   AND binding.tenant_id = tenant_id
   AND binding.id = source_provenance.binding_id
   AND binding.version = source_provenance.binding_revision
   AND binding.mapping_revision = source_provenance.mapping_revision
   AND binding.auth_revision = source_provenance.authorization_revision
   AND binding.current_access_epoch_id = source_provenance.access_epoch_id
   AND binding.enabled AND binding.archived_at IS NULL
  JOIN ONLY public.tenant_platform_identity_provider_access_epochs AS epoch
    ON epoch.tenant_id = binding.tenant_id
   AND epoch.id = source_provenance.access_epoch_id
   AND epoch.binding_id = binding.id
   AND epoch.platform_provider_id = provider.id
   AND epoch.source_id = source_provenance.access_source_id
   AND epoch.started_at <= p_completed_at AND epoch.ended_at IS NULL
  JOIN ONLY public.tenant_authorization_sources AS source
    ON source.tenant_id = epoch.tenant_id AND source.id = epoch.source_id
   AND source.kind = 'identity_provider_access'
   AND source.authoritative AND NOT source.protected
   AND source.key = format(
     'identity_provider_access:%s:%s',epoch.binding_id,epoch.sequence
   ) AND source.retired_at IS NULL
  JOIN ONLY public.platform_federated_external_identities AS identity
    ON identity.platform_provider_id = provider.id
   AND identity.id = source_provenance.external_identity_id
   AND identity.user_id = user_id
   AND identity.version = source_provenance.external_identity_revision
   AND identity.retired_at IS NULL
  JOIN ONLY public.platform_federated_external_identity_aliases AS alias
    ON alias.platform_provider_id = identity.platform_provider_id
   AND alias.external_identity_id = identity.id
   AND alias.key_version = source_provenance.subject_alias_key_version
   AND alias.retired_at IS NULL
  JOIN ONLY public.tenant_platform_federated_provider_access_grants AS grant_row
    ON grant_row.tenant_id = tenant_id
   AND grant_row.id = source_provenance.access_grant_id
   AND grant_row.platform_provider_id = provider.id
   AND grant_row.binding_id = binding.id
   AND grant_row.access_epoch_id = epoch.id
   AND grant_row.source_id = source.id
   AND grant_row.external_identity_id = identity.id
   AND grant_row.membership_id = membership_id
   AND grant_row.user_id = user_id
   AND grant_row.started_at <= p_completed_at AND grant_row.ended_at IS NULL
  WHERE provider.id = source_provenance.platform_provider_id
    AND provider.kind = 'oidc' AND provider.enabled
    AND provider.archived_at IS NULL
    AND source_provenance.tenant_id = tenant_id
    AND source_provenance.user_id = user_id
    AND source_provenance.primary_kind = 'tenant_platform_provider'
    AND source_provenance.authentication_method = 'oidc'
    AND source_provenance.membership_id = membership_id
    AND source_provenance.trust_rule_revision =
      source_provenance.security_revision;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant platform primary authority is stale'
      USING ERRCODE = '40001';
  END IF;

  token_lock := hashtextextended(encode(token_digest,'hex'),73124201);
  csrf_lock := hashtextextended(encode(csrf_digest,'hex'),73124201);
  PERFORM pg_advisory_xact_lock(least(token_lock,csrf_lock));
  IF token_lock <> csrf_lock THEN
    PERFORM pg_advisory_xact_lock(greatest(token_lock,csrf_lock));
  END IF;
  IF EXISTS (
    SELECT 1 FROM ONLY public.auth_sessions AS session
    WHERE session.token_digest IN (token_digest,csrf_digest)
       OR session.csrf_secret_digest IN (token_digest,csrf_digest)
  ) THEN
    RAISE EXCEPTION 'tenant platform MFA session digest collision'
      USING ERRCODE = '40001';
  END IF;
  IF source_bound THEN
    UPDATE ONLY public.auth_sessions AS session
    SET revoked_at = p_completed_at,revoke_reason = 'mfa_session_rotated'
    WHERE session.id = source_session.id AND session.revoked_at IS NULL;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'tenant platform MFA session rotation lost CAS'
        USING ERRCODE = '40001';
    END IF;
  END IF;

  INSERT INTO public.auth_sessions (
    id,user_id,rotation_family_id,active_tenant_id,token_digest,
    csrf_secret_digest,authentication_method,mfa_satisfied_at,last_seen_at,
    idle_expires_at,absolute_expires_at,rotated_from_session_id,created_at
  ) VALUES (
    new_session_id,user_id,new_family_id,tenant_id,token_digest,csrf_digest,
    authentication_method,p_completed_at,p_completed_at,idle_expires_at,
    absolute_expires_at,CASE WHEN source_bound THEN source_session.id END,
    p_completed_at
  );
  INSERT INTO public.auth_session_mfa_states (
    session_id,tenant_id,user_id,session_version,identity_epoch,
    recovery_restricted,audience,primary_kind,session_invalidation_epoch,issued_at
  ) VALUES (
    new_session_id,tenant_id,user_id,new_version,identity_epoch,
    (p_session ->> 'recoveryRestricted')::boolean,anchor_record.audience,
    'tenant_platform_provider',session_epoch,p_completed_at
  );
  INSERT INTO public.auth_session_tenant_platform_federated_provenance (
    tenant_id,session_id,user_id,primary_kind,authentication_method,
    platform_provider_id,binding_id,access_epoch_id,access_source_id,
    access_grant_id,membership_id,external_identity_id,
    external_identity_revision,provider_revision,binding_revision,
    security_revision,mapping_revision,authorization_revision,
    subject_alias_key_version,trust_rule_revision,authenticated_at
  ) VALUES (
    tenant_id,new_session_id,user_id,'tenant_platform_provider','oidc',
    source_provenance.platform_provider_id,source_provenance.binding_id,
    source_provenance.access_epoch_id,source_provenance.access_source_id,
    source_provenance.access_grant_id,source_provenance.membership_id,
    source_provenance.external_identity_id,
    source_provenance.external_identity_revision,
    source_provenance.provider_revision,source_provenance.binding_revision,
    source_provenance.security_revision,source_provenance.mapping_revision,
    source_provenance.authorization_revision,
    source_provenance.subject_alias_key_version,
    source_provenance.trust_rule_revision,source_provenance.authenticated_at
  );
  INSERT INTO public.auth_session_mfa_policy_pins (
    tenant_id,session_id,policy_id,policy_revision
  ) SELECT pin.tenant_id,new_session_id,pin.policy_id,pin.policy_revision
  FROM ONLY public.tenant_mfa_authority_policy_pins AS pin
  WHERE pin.tenant_id = tenant_id AND pin.anchor_id = anchor_record.id;

  evidence_count := jsonb_array_length(
    app.private_mfa_evidence_projection_v1(
      anchor_record.tenant_id,'anchor',anchor_record.id
    )
  );
  IF p_evidence_kind IS NOT NULL THEN evidence_count := evidence_count + 1; END IF;
  IF evidence_count NOT BETWEEN 1 AND 1024 THEN
    RAISE EXCEPTION 'tenant platform MFA evidence snapshot limit reached'
      USING ERRCODE = '22023';
  END IF;
  INSERT INTO public.auth_session_mfa_evidence (
    id,tenant_id,session_id,local_credential_id,totp_factor_id,
    webauthn_credential_id,recovery_code_set_id,level,kind,
    provider_id,binding_id,authenticated_at,expires_at,
    factor_revision,trust_rule_revision
  ) SELECT uuidv7(),evidence.tenant_id,new_session_id,
    evidence.local_credential_id,evidence.totp_factor_id,
    evidence.webauthn_credential_id,evidence.recovery_code_set_id,
    evidence.level,evidence.kind,evidence.provider_id,evidence.binding_id,
    evidence.authenticated_at,evidence.expires_at,
    evidence.factor_revision,evidence.trust_rule_revision
  FROM ONLY public.tenant_mfa_authority_evidence AS evidence
  WHERE evidence.tenant_id = tenant_id AND evidence.anchor_id = anchor_record.id;
  IF p_evidence_kind IS NOT NULL THEN
    IF p_evidence_kind NOT IN ('totp','webauthn','recovery')
       OR p_evidence_id IS NULL OR p_evidence_revision < 1 THEN
      RAISE EXCEPTION 'invalid typed MFA evidence' USING ERRCODE = '22023';
    END IF;
    INSERT INTO public.auth_session_mfa_evidence (
      id,tenant_id,session_id,totp_factor_id,webauthn_credential_id,
      recovery_code_set_id,level,kind,authenticated_at,factor_revision
    ) VALUES (
      uuidv7(),tenant_id,new_session_id,
      CASE WHEN p_evidence_kind = 'totp' THEN p_evidence_id END,
      CASE WHEN p_evidence_kind = 'webauthn' THEN p_evidence_id END,
      CASE WHEN p_evidence_kind = 'recovery' THEN p_evidence_id END,
      CASE WHEN p_evidence_kind = 'webauthn'
        THEN 'phishing_resistant' ELSE 'mfa' END,
      p_evidence_kind,p_completed_at,p_evidence_revision
    );
  END IF;
  INSERT INTO public.auth_session_tenant_platform_federated_evidence (
    id,tenant_id,session_id,user_id,platform_provider_id,binding_id,
    external_identity_id,level,authenticated_at,expires_at,trust_rule_revision
  ) SELECT uuidv7(),evidence.tenant_id,new_session_id,evidence.user_id,
    evidence.platform_provider_id,evidence.binding_id,
    evidence.external_identity_id,evidence.level,evidence.authenticated_at,
    evidence.expires_at,evidence.trust_rule_revision
  FROM ONLY public.tenant_mfa_authority_platform_federated_evidence AS evidence
  WHERE evidence.tenant_id = tenant_id AND evidence.anchor_id = anchor_record.id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant platform primary evidence is unavailable'
      USING ERRCODE = '40001';
  END IF;
  RETURN jsonb_strip_nulls(jsonb_build_object(
    'mutation',mutation,'newSessionId',new_session_id::text,
    'newSessionFamilyId',new_family_id::text,
    'consumedContinuationId',consumed_continuation_id::text,
    'sessionVersion',new_version,
    'recoveryRestricted',(p_session ->> 'recoveryRestricted')::boolean
  ));
EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
  RAISE EXCEPTION
    'tenant platform MFA session precondition is unavailable or ambiguous'
    USING ERRCODE = '40001';
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_mfa_assert_live_policy_anchor_v1(
  p_anchor_id uuid,
  p_evaluated_at timestamptz
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_anchor public.tenant_mfa_authority_anchors%ROWTYPE;
  v_snapshot jsonb;
  v_anchor_pins jsonb;
  v_live_pins jsonb;
  v_policy_count bigint;
BEGIN
  SELECT anchor.* INTO STRICT v_anchor
  FROM ONLY public.tenant_mfa_authority_anchors AS anchor
  WHERE anchor.id = p_anchor_id;
  v_snapshot := app.private_mfa_policy_snapshot_v1(
    v_anchor.tenant_id,v_anchor.user_id,v_anchor.action,p_evaluated_at
  );
  SELECT coalesce(jsonb_agg(jsonb_build_object(
    'policyId',pin.policy_id::text,'revision',pin.policy_revision
  ) ORDER BY pin.policy_id::text,pin.policy_revision),'[]'::jsonb)
    INTO STRICT v_anchor_pins
  FROM ONLY public.tenant_mfa_authority_policy_pins AS pin
  WHERE pin.tenant_id = v_anchor.tenant_id AND pin.anchor_id = v_anchor.id;
  SELECT coalesce(jsonb_agg(jsonb_build_object(
    'policyId',entry.value -> 'policy' ->> 'id',
    'revision',(entry.value -> 'policy' ->> 'revision')::bigint
  ) ORDER BY entry.value -> 'policy' ->> 'id',
      (entry.value -> 'policy' ->> 'revision')::bigint),'[]'::jsonb)
    INTO STRICT v_live_pins
  FROM jsonb_array_elements(v_snapshot -> 'policies') AS entry(value);
  IF jsonb_strip_nulls(
       app.private_mfa_anchor_binding_v1(v_anchor.id) -> 'requirement'
     ) IS DISTINCT FROM jsonb_strip_nulls(v_snapshot -> 'requirement')
     OR v_anchor_pins IS DISTINCT FROM v_live_pins THEN
    RAISE EXCEPTION 'MFA completion policy authority drifted'
      USING ERRCODE = '40001';
  END IF;
  SELECT count(*) INTO STRICT v_policy_count
  FROM (
    SELECT policy.id
    FROM ONLY public.mfa_policy_revisions AS policy
    JOIN jsonb_array_elements(v_snapshot -> 'policies') AS entry(value)
      ON policy.id = (entry.value -> 'policy' ->> 'id')::uuid
     AND policy.revision =
         (entry.value -> 'policy' ->> 'revision')::bigint
    FOR SHARE OF policy NOWAIT
  ) AS locked_policy;
  IF v_policy_count <> jsonb_array_length(v_snapshot -> 'policies') THEN
    RAISE EXCEPTION 'MFA completion policy authority drifted'
      USING ERRCODE = '40001';
  END IF;
EXCEPTION WHEN lock_not_available THEN
  RAISE EXCEPTION 'MFA completion policy authority is busy'
    USING ERRCODE = '40001';
WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
  RAISE EXCEPTION 'MFA completion policy authority is unavailable'
    USING ERRCODE = '40001';
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_mfa_apply_passkey_continuation_v1(
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
  v_continuation public.tenant_post_primary_continuations%ROWTYPE;
  v_provenance public.tenant_post_primary_passkey_provenance%ROWTYPE;
  v_source_session public.auth_sessions%ROWTYPE;
  v_source_state public.auth_session_mfa_states%ROWTYPE;
  v_primary_credential public.tenant_webauthn_credentials%ROWTYPE;
  v_factor_credential public.tenant_webauthn_credentials%ROWTYPE;
  v_existing_factor_evidence
    public.tenant_post_primary_continuation_evidence%ROWTYPE;
  v_mutation text := p_session ->> 'mutation';
  v_same_primary boolean := false;
  v_refresh_evidence boolean := false;
  v_transform_evidence_copy boolean := false;
  v_result jsonb;
  v_successor_id uuid;
  v_reservation jsonb;
  v_successor_family_id uuid;
  v_successor_idle_expires_at timestamptz;
  v_successor_absolute_expires_at timestamptz;
  v_terminal_version bigint;
  v_expected_factor_method text;
  v_primary_evidence_count bigint;
  v_exact_primary_evidence_count bigint;
  v_factor_evidence_count bigint;
  v_factor_security_revision bigint;
  v_authority_at timestamptz := greatest(
    p_completed_at,transaction_timestamp()
  );
BEGIN
  PERFORM app.private_mfa_assert_json_object_v1(
    p_session,
    ARRAY['mutation','expectedSessionId','expectedFamilyId',
      'expectedContinuationId','expectedAnchorVersion',
      'expectedIdentityEpoch','expectedAnchorExpiry','audience','requirement',
      'recoveryRestricted','reservation'],
    ARRAY['mutation','expectedContinuationId','expectedAnchorVersion',
      'expectedIdentityEpoch','expectedAnchorExpiry','audience','requirement',
      'recoveryRestricted'],131072
  );
  SELECT anchor.* INTO STRICT v_anchor
  FROM ONLY public.tenant_mfa_authority_anchors AS anchor
  WHERE anchor.id = p_anchor_id
    AND anchor.flow = 'continuation';
  PERFORM app.private_mfa_lock_policy_authority_v1(v_anchor.tenant_id);
  SELECT anchor.* INTO STRICT v_anchor
  FROM ONLY public.tenant_mfa_authority_anchors AS anchor
  WHERE anchor.id = p_anchor_id
    AND anchor.flow = 'continuation'
  FOR UPDATE NOWAIT;
  IF v_mutation NOT IN ('consume_continuation','revoke')
     OR app.private_mfa_require_uuidv7_v1(
          p_session ->> 'expectedContinuationId'
        ) IS DISTINCT FROM v_anchor.continuation_id
     OR p_session ? 'expectedSessionId' OR p_session ? 'expectedFamilyId'
     OR (p_session ->> 'expectedAnchorVersion')::bigint
          IS DISTINCT FROM v_anchor.anchor_version
     OR (p_session ->> 'expectedIdentityEpoch')::bigint
          IS DISTINCT FROM v_anchor.identity_epoch
     OR (p_session ->> 'expectedAnchorExpiry')::timestamptz
          IS DISTINCT FROM v_anchor.anchor_expires_at
     OR p_session ->> 'audience' IS DISTINCT FROM v_anchor.audience
      OR jsonb_strip_nulls(p_session -> 'requirement') IS DISTINCT FROM
           jsonb_strip_nulls(
             app.private_mfa_anchor_binding_v1(p_anchor_id) -> 'requirement'
           )
     OR v_anchor.anchor_version >= 9007199254740991
     OR p_completed_at IS NULL
     OR abs(extract(epoch FROM
          (transaction_timestamp() - p_completed_at))) > 300 THEN
    RAISE EXCEPTION 'passkey continuation session intent drifted'
      USING ERRCODE = '40001';
  END IF;

  SELECT continuation.* INTO STRICT v_continuation
  FROM ONLY public.tenant_post_primary_continuations AS continuation
  JOIN ONLY public.tenant_post_primary_passkey_provenance AS provenance
    ON provenance.tenant_id = continuation.tenant_id
   AND provenance.continuation_id = continuation.id
   AND provenance.user_id = continuation.user_id
   AND provenance.credential_id = continuation.passkey_credential_id
  WHERE continuation.id = v_anchor.continuation_id
    AND continuation.tenant_id = v_anchor.tenant_id
    AND continuation.user_id = v_anchor.user_id
    AND continuation.identity_epoch = v_anchor.identity_epoch
    AND continuation.primary_kind = 'passkey'
    AND continuation.primary_revision = provenance.credential_revision
    AND continuation.session_invalidation_epoch = (
      SELECT subject.session_invalidation_epoch
      FROM ONLY public.tenant_mfa_subjects AS subject
      JOIN ONLY public.users AS local_user
        ON local_user.id = subject.user_id AND local_user.active
      JOIN ONLY public.tenants AS tenant
        ON tenant.id = subject.tenant_id AND tenant.status = 'active'
      JOIN ONLY public.tenant_memberships AS membership
        ON membership.tenant_id = subject.tenant_id
       AND membership.user_id = subject.user_id
       AND membership.status = 'active'
      WHERE subject.tenant_id = continuation.tenant_id
        AND subject.user_id = continuation.user_id
        AND subject.identity_epoch = continuation.identity_epoch
    )
    AND continuation.state = 'pending'
    AND continuation.version = v_anchor.anchor_version
    AND continuation.expires_at = v_anchor.anchor_expires_at
    AND continuation.expires_at > v_authority_at
    AND provenance.primary_kind = 'passkey'
    AND provenance.authentication_method = 'passkey'
  FOR UPDATE OF continuation NOWAIT
  FOR SHARE OF provenance NOWAIT;
  SELECT provenance.* INTO STRICT v_provenance
  FROM ONLY public.tenant_post_primary_passkey_provenance AS provenance
  WHERE provenance.tenant_id = v_continuation.tenant_id
    AND provenance.continuation_id = v_continuation.id
    AND provenance.user_id = v_continuation.user_id
    AND provenance.credential_id = v_continuation.passkey_credential_id
    AND provenance.credential_revision = v_continuation.primary_revision
    AND provenance.primary_kind = 'passkey'
    AND provenance.authentication_method = 'passkey'
  FOR SHARE NOWAIT;

  PERFORM 1
  FROM ONLY public.tenant_mfa_subjects AS subject
  JOIN ONLY public.users AS local_user
    ON local_user.id = subject.user_id AND local_user.active
  JOIN ONLY public.tenants AS tenant
    ON tenant.id = subject.tenant_id AND tenant.status = 'active'
  JOIN ONLY public.tenant_memberships AS membership
    ON membership.tenant_id = subject.tenant_id
   AND membership.user_id = subject.user_id
   AND membership.status = 'active'
  WHERE subject.tenant_id = v_continuation.tenant_id
    AND subject.user_id = v_continuation.user_id
    AND subject.identity_epoch = v_continuation.identity_epoch
    AND subject.session_invalidation_epoch =
        v_continuation.session_invalidation_epoch
  FOR SHARE OF subject,local_user,tenant,membership NOWAIT;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'passkey continuation lifecycle authority drifted'
      USING ERRCODE = '40001';
  END IF;

  IF v_provenance.origin = 'session_revalidation' THEN
    IF v_provenance.source_session_version >= 9007199254740991 THEN
      RAISE EXCEPTION 'passkey source session version is exhausted'
        USING ERRCODE = '40001';
    END IF;
    SELECT source_session.* INTO STRICT v_source_session
    FROM ONLY public.auth_sessions AS source_session
    JOIN ONLY public.auth_session_mfa_states AS source_state
      ON source_state.tenant_id = v_provenance.tenant_id
     AND source_state.session_id = source_session.id
     AND source_state.user_id = v_provenance.user_id
     AND source_state.primary_kind = 'passkey'
     AND source_state.session_version = v_provenance.source_session_version
    JOIN ONLY public.auth_session_passkey_provenance AS source_provenance
      ON source_provenance.tenant_id = source_state.tenant_id
     AND source_provenance.session_id = source_state.session_id
     AND source_provenance.user_id = source_state.user_id
     AND source_provenance.primary_kind = 'passkey'
     AND source_provenance.credential_id = v_provenance.credential_id
     AND source_provenance.credential_revision =
         v_provenance.credential_revision
     AND source_provenance.authenticated_at = v_provenance.authenticated_at
    WHERE source_session.id = v_provenance.source_session_id
      AND source_session.user_id = v_provenance.user_id
      AND source_session.active_tenant_id = v_provenance.tenant_id
      AND source_session.rotation_family_id =
          v_provenance.source_session_family_id
      AND source_session.authentication_method = 'passkey'
      AND source_session.absolute_expires_at =
          v_provenance.source_absolute_expires_at
      AND source_session.revoked_at IS NULL
      AND source_session.idle_expires_at > v_authority_at
      AND source_session.absolute_expires_at > v_authority_at
    FOR UPDATE OF source_session,source_state NOWAIT
    FOR SHARE OF source_provenance NOWAIT;
    SELECT source_state.* INTO STRICT v_source_state
    FROM ONLY public.auth_session_mfa_states AS source_state
    WHERE source_state.tenant_id = v_provenance.tenant_id
      AND source_state.session_id = v_source_session.id
      AND source_state.user_id = v_provenance.user_id
      AND source_state.primary_kind = 'passkey'
      AND source_state.session_version = v_provenance.source_session_version
    FOR UPDATE NOWAIT;
  ELSIF v_provenance.origin <> 'initial_login' THEN
    RAISE EXCEPTION 'passkey continuation origin is invalid'
      USING ERRCODE = '23514';
  END IF;

  PERFORM app.private_mfa_assert_live_policy_anchor_v1(
    v_anchor.id,v_authority_at
  );
  PERFORM app.private_mfa_assert_live_continuation_policy_v1(
    v_continuation.id,v_authority_at
  );
  PERFORM app.private_mfa_assert_live_passkey_anchor_evidence_v1(
    v_anchor.id,v_authority_at,
    CASE WHEN v_mutation = 'revoke' THEN 'webauthn'
      ELSE p_evidence_kind END,
    CASE WHEN v_mutation = 'revoke' THEN p_primary_id
      ELSE p_evidence_id END
  );

  IF v_mutation = 'revoke' THEN
    IF p_session ? 'reservation' OR p_evidence_kind IS NOT NULL
       OR p_evidence_id IS NOT NULL OR p_evidence_revision IS NOT NULL
       OR p_primary_kind IS DISTINCT FROM 'passkey'
       OR p_primary_id IS NULL OR p_primary_revision IS NULL THEN
      RAISE EXCEPTION 'invalid passkey continuation clone intent'
        USING ERRCODE = '22023';
    END IF;
    SELECT credential.* INTO STRICT v_factor_credential
    FROM ONLY public.tenant_webauthn_credentials AS credential
    WHERE credential.tenant_id = v_provenance.tenant_id
      AND credential.user_id = v_provenance.user_id
      AND credential.id = p_primary_id
      AND credential.version = p_primary_revision
      AND credential.status = 'clone_suspected'
      AND credential.revoked_at = p_completed_at
      AND credential.updated_at = p_completed_at
      AND credential.revoke_reason = 'authenticator_counter_regression'
    FOR SHARE;
    v_same_primary := p_primary_id = v_provenance.credential_id;
    IF v_same_primary THEN
      IF v_factor_credential.security_revision <>
           v_provenance.credential_revision + 1 THEN
        RAISE EXCEPTION 'passkey clone primary revision drifted'
          USING ERRCODE = '40001';
      END IF;
    ELSE
      SELECT credential.* INTO STRICT v_primary_credential
      FROM ONLY public.tenant_webauthn_credentials AS credential
      WHERE credential.tenant_id = v_provenance.tenant_id
        AND credential.user_id = v_provenance.user_id
        AND credential.id = v_provenance.credential_id
        AND credential.security_revision =
            v_provenance.credential_revision
        AND credential.status = 'active'
      FOR SHARE;
    END IF;
    UPDATE ONLY public.tenant_post_primary_continuations AS continuation
    SET state = 'revoked',version = continuation.version + 1,
        revoked_at = p_completed_at,
        revoke_reason = 'passkey_clone_suspected'
    WHERE continuation.tenant_id = v_continuation.tenant_id
      AND continuation.id = v_continuation.id
      AND continuation.state = 'pending'
      AND continuation.version = v_continuation.version
    RETURNING continuation.version INTO v_terminal_version;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'passkey clone continuation lost CAS'
        USING ERRCODE = '40001';
    END IF;
    IF v_provenance.origin = 'session_revalidation' THEN
      UPDATE ONLY public.auth_sessions AS family
      SET revoked_at = p_completed_at,
          revoke_reason = 'mfa_clone_suspected'
      WHERE family.user_id = v_provenance.user_id
        AND family.rotation_family_id = v_provenance.source_session_family_id
        AND family.revoked_at IS NULL;
      IF NOT FOUND THEN
        RAISE EXCEPTION 'passkey clone source family lost CAS'
          USING ERRCODE = '40001';
      END IF;
    END IF;
    RETURN jsonb_build_object(
      'mutation','revoke','revokedAnchorId',v_continuation.id::text,
      'sessionVersion',v_terminal_version,
      'recoveryRestricted',false
    );
  END IF;

  IF NOT (p_session ? 'reservation')
     OR p_session -> 'reservation' = 'null'::jsonb
     OR p_evidence_kind NOT IN ('totp','webauthn','recovery')
     OR p_evidence_id IS NULL OR p_evidence_revision < 1 THEN
    RAISE EXCEPTION 'passkey continuation evidence is invalid'
      USING ERRCODE = '22023';
  END IF;
  v_expected_factor_method := CASE p_evidence_kind
    WHEN 'totp' THEN 'totp'
    WHEN 'webauthn' THEN 'passkey'
    WHEN 'recovery' THEN 'recovery_code'
  END;
  v_same_primary := p_evidence_kind = 'webauthn'
    AND p_evidence_id = v_provenance.credential_id;
  IF v_same_primary THEN
    SELECT count(*),count(*) FILTER (
      WHERE evidence.factor_revision = v_provenance.credential_revision
        AND evidence.authenticated_at = v_provenance.authenticated_at
    )
      INTO STRICT v_primary_evidence_count,v_exact_primary_evidence_count
    FROM (
      SELECT evidence.factor_revision,evidence.authenticated_at
      FROM ONLY public.tenant_post_primary_continuation_evidence AS evidence
      WHERE evidence.tenant_id = v_provenance.tenant_id
        AND evidence.continuation_id = v_provenance.continuation_id
        AND evidence.webauthn_credential_id = v_provenance.credential_id
      FOR SHARE NOWAIT
    ) AS evidence;
    IF v_primary_evidence_count <> 1
       OR v_exact_primary_evidence_count <> 1 THEN
      RAISE EXCEPTION 'passkey continuation primary evidence is ambiguous'
        USING ERRCODE = '40001';
    END IF;
  END IF;
  IF p_evidence_kind = 'webauthn' THEN
    IF p_primary_kind IS DISTINCT FROM 'passkey'
       OR p_primary_id IS DISTINCT FROM p_evidence_id
       OR p_primary_revision IS DISTINCT FROM p_evidence_revision THEN
      RAISE EXCEPTION 'passkey evidence identity is inconsistent'
        USING ERRCODE = '22023';
    END IF;
    SELECT credential.* INTO STRICT v_factor_credential
    FROM ONLY public.tenant_webauthn_credentials AS credential
    WHERE credential.tenant_id = v_provenance.tenant_id
      AND credential.user_id = v_provenance.user_id
      AND credential.id = p_evidence_id
      AND credential.version = p_evidence_revision
      AND credential.status = 'active'
      AND credential.last_used_at = p_completed_at
      AND credential.updated_at = p_completed_at
    FOR SHARE;
  ELSIF p_primary_kind IS NOT NULL OR p_primary_id IS NOT NULL
     OR p_primary_revision IS NOT NULL THEN
    RAISE EXCEPTION 'non-passkey factor supplied a primary override'
      USING ERRCODE = '22023';
  END IF;
  v_factor_security_revision := CASE p_evidence_kind
    WHEN 'webauthn' THEN v_factor_credential.security_revision
    ELSE p_evidence_revision
  END;
  SELECT count(*) INTO STRICT v_factor_evidence_count
  FROM (
    SELECT evidence.id
    FROM ONLY public.tenant_post_primary_continuation_evidence AS evidence
    WHERE evidence.tenant_id = v_provenance.tenant_id
      AND evidence.continuation_id = v_provenance.continuation_id
      AND ((p_evidence_kind = 'totp'
            AND evidence.totp_factor_id = p_evidence_id)
        OR (p_evidence_kind = 'webauthn'
            AND evidence.webauthn_credential_id = p_evidence_id)
        OR (p_evidence_kind = 'recovery'
            AND evidence.recovery_code_set_id = p_evidence_id))
    FOR SHARE NOWAIT
  ) AS matching_evidence;
  IF v_factor_evidence_count > 1 THEN
    RAISE EXCEPTION 'passkey continuation factor evidence is ambiguous'
      USING ERRCODE = '40001';
  ELSIF v_factor_evidence_count = 1 THEN
    SELECT evidence.* INTO STRICT v_existing_factor_evidence
    FROM ONLY public.tenant_post_primary_continuation_evidence AS evidence
    WHERE evidence.tenant_id = v_provenance.tenant_id
      AND evidence.continuation_id = v_provenance.continuation_id
      AND ((p_evidence_kind = 'totp'
            AND evidence.totp_factor_id = p_evidence_id)
        OR (p_evidence_kind = 'webauthn'
            AND evidence.webauthn_credential_id = p_evidence_id)
        OR (p_evidence_kind = 'recovery'
            AND evidence.recovery_code_set_id = p_evidence_id))
    FOR SHARE NOWAIT;
    v_refresh_evidence := true;
  END IF;
  v_transform_evidence_copy := v_refresh_evidence
    AND p_evidence_kind = 'webauthn'
    AND EXISTS (
      SELECT 1
      FROM ONLY public.tenant_mfa_webauthn_evidence_copy_capabilities
        AS capability
      WHERE capability.backend_pid = pg_backend_pid()
        AND capability.transaction_id = txid_current()
        AND capability.tenant_id = v_provenance.tenant_id
        AND capability.source_anchor_id = p_anchor_id
        AND capability.destination_session_id =
            app.private_mfa_require_uuidv7_v1(
              p_session #>> '{reservation,sessionId}'
            )
        AND capability.credential_id = p_evidence_id
        AND capability.source_revision =
            v_existing_factor_evidence.factor_revision
        AND capability.target_revision = v_factor_security_revision
        AND capability.target_authenticated_at = p_completed_at
    );
  SELECT credential.* INTO STRICT v_primary_credential
  FROM ONLY public.tenant_webauthn_credentials AS credential
  WHERE credential.tenant_id = v_provenance.tenant_id
    AND credential.user_id = v_provenance.user_id
    AND credential.id = v_provenance.credential_id
    AND credential.security_revision BETWEEN
        v_provenance.credential_revision
        AND v_provenance.credential_revision
          + CASE WHEN v_same_primary THEN 1 ELSE 0 END
    AND credential.status = 'active'
  FOR SHARE;

  v_reservation := p_session -> 'reservation';
  IF v_reservation ->> 'authenticationMethod' IS DISTINCT FROM
       v_expected_factor_method THEN
    RAISE EXCEPTION 'passkey successor factor method drifted'
      USING ERRCODE = '22023';
  END IF;
  v_successor_idle_expires_at :=
    (v_reservation ->> 'idleExpiresAt')::timestamptz;
  v_successor_absolute_expires_at :=
    (v_reservation ->> 'absoluteExpiresAt')::timestamptz;
  IF v_successor_idle_expires_at <= v_authority_at
     OR v_successor_absolute_expires_at <= v_authority_at THEN
    RAISE EXCEPTION 'passkey successor session is already expired'
      USING ERRCODE = '22023';
  END IF;
  IF v_provenance.origin = 'session_revalidation' THEN
    v_successor_id := app.private_mfa_require_uuidv7_v1(
      v_reservation ->> 'sessionId'
    );
    v_successor_family_id := app.private_mfa_require_uuidv7_v1(
      v_reservation ->> 'familyId'
    );
    IF v_successor_id = v_source_session.id
       OR v_successor_family_id IS DISTINCT FROM
            v_source_session.rotation_family_id
       OR v_successor_absolute_expires_at IS DISTINCT FROM
            v_source_session.absolute_expires_at THEN
      RAISE EXCEPTION 'passkey MFA rotation changed family or deadline'
        USING ERRCODE = '22023';
    END IF;
  END IF;

  v_result := app.private_mfa_apply_session_legacy_v1(
    p_session,p_anchor_id,p_primary_kind,p_primary_id,p_primary_revision,
    CASE WHEN v_refresh_evidence THEN NULL ELSE p_evidence_kind END,
    CASE WHEN v_refresh_evidence THEN NULL ELSE p_evidence_id END,
    CASE WHEN v_refresh_evidence THEN NULL
      ELSE v_factor_security_revision END,
    p_completed_at
  );
  v_successor_id := (v_result ->> 'newSessionId')::uuid;
  UPDATE ONLY public.auth_session_passkey_provenance AS successor
  SET credential_revision = CASE WHEN v_same_primary
        THEN v_primary_credential.security_revision
        ELSE v_provenance.credential_revision END,
      authenticated_at = CASE WHEN v_same_primary
        THEN p_completed_at ELSE v_provenance.authenticated_at END
  WHERE successor.tenant_id = v_provenance.tenant_id
    AND successor.session_id = v_successor_id
    AND successor.user_id = v_provenance.user_id
    AND successor.credential_id = v_provenance.credential_id
    AND successor.credential_revision = v_provenance.credential_revision
    AND successor.authenticated_at = v_continuation.created_at;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'passkey successor provenance is unavailable'
      USING ERRCODE = '23514';
  END IF;
  IF v_refresh_evidence AND NOT v_transform_evidence_copy THEN
    UPDATE ONLY public.auth_session_mfa_evidence AS evidence
    SET factor_revision = v_factor_security_revision,
        authenticated_at = p_completed_at,expires_at = NULL
    WHERE evidence.tenant_id = v_provenance.tenant_id
      AND evidence.session_id = v_successor_id
      AND evidence.kind = v_existing_factor_evidence.kind
      AND evidence.totp_factor_id IS NOT DISTINCT FROM
          v_existing_factor_evidence.totp_factor_id
      AND evidence.webauthn_credential_id IS NOT DISTINCT FROM
          v_existing_factor_evidence.webauthn_credential_id
      AND evidence.recovery_code_set_id IS NOT DISTINCT FROM
          v_existing_factor_evidence.recovery_code_set_id
      AND evidence.factor_revision = v_existing_factor_evidence.factor_revision
      AND evidence.authenticated_at =
          v_existing_factor_evidence.authenticated_at;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'passkey successor factor evidence is unavailable'
      USING ERRCODE = '23514';
    END IF;
  ELSIF v_transform_evidence_copy AND (
    SELECT count(*)
    FROM ONLY public.auth_session_mfa_evidence AS evidence
    WHERE evidence.tenant_id = v_provenance.tenant_id
      AND evidence.session_id = v_successor_id
      AND evidence.kind = 'webauthn'
      AND evidence.webauthn_credential_id = p_evidence_id
      AND evidence.factor_revision = v_factor_security_revision
      AND evidence.authenticated_at = p_completed_at
  ) <> 1 THEN
    RAISE EXCEPTION 'passkey successor transformed evidence is ambiguous'
      USING ERRCODE = '23514';
  END IF;
  UPDATE ONLY public.auth_sessions AS successor
  SET authentication_method = 'passkey'
  WHERE successor.id = v_successor_id
    AND successor.user_id = v_provenance.user_id
    AND successor.active_tenant_id = v_provenance.tenant_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'passkey successor session is unavailable'
      USING ERRCODE = '23514';
  END IF;
  IF v_provenance.origin = 'session_revalidation' THEN
    UPDATE ONLY public.auth_sessions AS family
    SET revoked_at = p_completed_at,revoke_reason = 'mfa_session_rotated'
    WHERE family.user_id = v_provenance.user_id
      AND family.rotation_family_id = v_provenance.source_session_family_id
      AND family.id <> v_successor_id
      AND family.revoked_at IS NULL;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'passkey MFA source rotation lost CAS'
        USING ERRCODE = '40001';
    END IF;
    UPDATE ONLY public.auth_sessions AS successor
    SET rotated_from_session_id = v_source_session.id
    WHERE successor.id = v_successor_id
      AND successor.rotation_family_id = v_source_session.rotation_family_id
      AND successor.absolute_expires_at = v_source_session.absolute_expires_at;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'passkey MFA successor rotation drifted'
        USING ERRCODE = '40001';
    END IF;
    UPDATE ONLY public.auth_session_mfa_states AS successor_state
    SET session_version = v_provenance.source_session_version + 1
    WHERE successor_state.tenant_id = v_provenance.tenant_id
      AND successor_state.session_id = v_successor_id
      AND successor_state.user_id = v_provenance.user_id
      AND successor_state.primary_kind = 'passkey';
    IF NOT FOUND THEN
      RAISE EXCEPTION 'passkey MFA successor state is unavailable'
        USING ERRCODE = '40001';
    END IF;
    v_result := jsonb_set(
      v_result,'{sessionVersion}',
      to_jsonb(v_provenance.source_session_version + 1),true
    );
  END IF;
  RETURN v_result;
EXCEPTION WHEN lock_not_available THEN
  RAISE EXCEPTION 'passkey continuation authority is busy'
    USING ERRCODE = '40001';
WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
  RAISE EXCEPTION 'passkey continuation authority is unavailable'
    USING ERRCODE = '40001';
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_mfa_apply_passkey_session_v1(
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
  v_source_session public.auth_sessions%ROWTYPE;
  v_source_state public.auth_session_mfa_states%ROWTYPE;
  v_provenance public.auth_session_passkey_provenance%ROWTYPE;
  v_primary_credential public.tenant_webauthn_credentials%ROWTYPE;
  v_factor_credential public.tenant_webauthn_credentials%ROWTYPE;
  v_existing_factor_evidence public.auth_session_mfa_evidence%ROWTYPE;
  v_mutation text := p_session ->> 'mutation';
  v_same_primary boolean := false;
  v_refresh_evidence boolean := false;
  v_transform_evidence_copy boolean := false;
  v_baseline_only boolean := false;
  v_expected_factor_method text;
  v_reservation jsonb;
  v_successor_id uuid;
  v_result jsonb;
  v_primary_evidence_count bigint;
  v_exact_primary_evidence_count bigint;
  v_evidence_count bigint;
  v_factor_evidence_count bigint;
  v_factor_security_revision bigint;
  v_authority_at timestamptz := greatest(
    p_completed_at,transaction_timestamp()
  );
BEGIN
  PERFORM app.private_mfa_assert_json_object_v1(
    p_session,
    ARRAY['mutation','expectedSessionId','expectedFamilyId',
      'expectedContinuationId','expectedAnchorVersion',
      'expectedIdentityEpoch','expectedAnchorExpiry','audience','requirement',
      'recoveryRestricted','reservation'],
    ARRAY['mutation','expectedSessionId','expectedFamilyId',
      'expectedAnchorVersion','expectedIdentityEpoch','expectedAnchorExpiry',
      'audience','requirement','recoveryRestricted'],131072
  );
  SELECT anchor.* INTO STRICT v_anchor
  FROM ONLY public.tenant_mfa_authority_anchors AS anchor
  WHERE anchor.id = p_anchor_id AND anchor.flow = 'session';
  PERFORM app.private_mfa_lock_policy_authority_v1(v_anchor.tenant_id);
  SELECT anchor.* INTO STRICT v_anchor
  FROM ONLY public.tenant_mfa_authority_anchors AS anchor
  WHERE anchor.id = p_anchor_id AND anchor.flow = 'session'
  FOR UPDATE NOWAIT;
  IF v_mutation NOT IN ('rotate','revoke')
     OR app.private_mfa_require_uuidv7_v1(
          p_session ->> 'expectedSessionId'
        ) IS DISTINCT FROM v_anchor.session_id
     OR app.private_mfa_require_uuidv7_v1(
          p_session ->> 'expectedFamilyId'
        ) IS DISTINCT FROM v_anchor.session_family_id
     OR p_session ? 'expectedContinuationId'
     OR (p_session ->> 'expectedAnchorVersion')::bigint
          IS DISTINCT FROM v_anchor.anchor_version
     OR (p_session ->> 'expectedIdentityEpoch')::bigint
          IS DISTINCT FROM v_anchor.identity_epoch
     OR (p_session ->> 'expectedAnchorExpiry')::timestamptz
          IS DISTINCT FROM v_anchor.anchor_expires_at
     OR p_session ->> 'audience' IS DISTINCT FROM v_anchor.audience
      OR jsonb_strip_nulls(p_session -> 'requirement') IS DISTINCT FROM
           jsonb_strip_nulls(
             app.private_mfa_anchor_binding_v1(p_anchor_id) -> 'requirement'
           )
     OR v_anchor.anchor_version >= 9007199254740991
     OR p_completed_at IS NULL
     OR abs(extract(epoch FROM
          (transaction_timestamp() - p_completed_at))) > 300 THEN
    RAISE EXCEPTION 'passkey session completion intent drifted'
      USING ERRCODE = '40001';
  END IF;

  SELECT source_session.* INTO STRICT v_source_session
  FROM ONLY public.auth_sessions AS source_session
  JOIN ONLY public.auth_session_mfa_states AS source_state
    ON source_state.tenant_id = v_anchor.tenant_id
   AND source_state.session_id = source_session.id
   AND source_state.user_id = v_anchor.user_id
   AND source_state.primary_kind = 'passkey'
   AND source_state.session_version = v_anchor.anchor_version
   AND source_state.identity_epoch = v_anchor.identity_epoch
  JOIN ONLY public.auth_session_passkey_provenance AS provenance
    ON provenance.tenant_id = source_state.tenant_id
   AND provenance.session_id = source_state.session_id
   AND provenance.user_id = source_state.user_id
   AND provenance.primary_kind = 'passkey'
  JOIN ONLY public.tenant_mfa_subjects AS subject
    ON subject.tenant_id = source_state.tenant_id
   AND subject.user_id = source_state.user_id
   AND subject.identity_epoch = source_state.identity_epoch
   AND subject.session_invalidation_epoch =
       source_state.session_invalidation_epoch
  JOIN ONLY public.users AS local_user
    ON local_user.id = source_state.user_id AND local_user.active
  JOIN ONLY public.tenants AS tenant
    ON tenant.id = source_state.tenant_id AND tenant.status = 'active'
  JOIN ONLY public.tenant_memberships AS membership
    ON membership.tenant_id = source_state.tenant_id
   AND membership.user_id = source_state.user_id
   AND membership.status = 'active'
  WHERE source_session.id = v_anchor.session_id
    AND source_session.user_id = v_anchor.user_id
    AND source_session.active_tenant_id = v_anchor.tenant_id
    AND source_session.rotation_family_id = v_anchor.session_family_id
    AND source_session.authentication_method = 'passkey'
    AND source_session.revoked_at IS NULL
    AND source_session.idle_expires_at = v_anchor.anchor_expires_at
    AND source_session.idle_expires_at > v_authority_at
    AND source_session.absolute_expires_at > v_authority_at
  FOR UPDATE OF source_session,source_state NOWAIT
  FOR SHARE OF provenance,subject,local_user,tenant,membership NOWAIT;
  SELECT source_state.* INTO STRICT v_source_state
  FROM ONLY public.auth_session_mfa_states AS source_state
  WHERE source_state.tenant_id = v_anchor.tenant_id
    AND source_state.session_id = v_source_session.id
    AND source_state.user_id = v_anchor.user_id
    AND source_state.primary_kind = 'passkey'
    AND source_state.session_version = v_anchor.anchor_version
    AND source_state.identity_epoch = v_anchor.identity_epoch
  FOR UPDATE NOWAIT;
  SELECT provenance.* INTO STRICT v_provenance
  FROM ONLY public.auth_session_passkey_provenance AS provenance
  WHERE provenance.tenant_id = v_anchor.tenant_id
    AND provenance.session_id = v_source_session.id
    AND provenance.user_id = v_anchor.user_id
    AND provenance.primary_kind = 'passkey'
  FOR SHARE NOWAIT;

  SELECT count(*),count(*) FILTER (
      WHERE evidence.factor_revision = v_provenance.credential_revision
        AND evidence.authenticated_at = v_provenance.authenticated_at
    )
    INTO STRICT v_primary_evidence_count,v_exact_primary_evidence_count
  FROM (
    SELECT evidence.factor_revision,evidence.authenticated_at
    FROM ONLY public.auth_session_mfa_evidence AS evidence
    WHERE evidence.tenant_id = v_provenance.tenant_id
      AND evidence.session_id = v_provenance.session_id
      AND evidence.webauthn_credential_id = v_provenance.credential_id
    FOR SHARE NOWAIT
  ) AS evidence;
  SELECT count(*) INTO STRICT v_evidence_count
  FROM (
    SELECT evidence.id
    FROM ONLY public.auth_session_mfa_evidence AS evidence
    WHERE evidence.tenant_id = v_provenance.tenant_id
      AND evidence.session_id = v_provenance.session_id
    FOR SHARE NOWAIT
  ) AS evidence;
  IF v_primary_evidence_count <> 1
     OR v_exact_primary_evidence_count <> 1
     OR v_evidence_count NOT BETWEEN 1 AND 1024 THEN
    RAISE EXCEPTION 'passkey session primary evidence is ambiguous'
      USING ERRCODE = '40001';
  END IF;

  PERFORM app.private_mfa_assert_live_policy_anchor_v1(
    v_anchor.id,v_authority_at
  );
  PERFORM app.private_mfa_assert_live_passkey_anchor_evidence_v1(
    v_anchor.id,v_authority_at,
    CASE WHEN v_mutation = 'revoke' THEN 'webauthn'
      ELSE p_evidence_kind END,
    CASE WHEN v_mutation = 'revoke' THEN p_primary_id
      ELSE p_evidence_id END
  );

  IF v_mutation = 'revoke' THEN
    IF p_session ? 'reservation' OR p_evidence_kind IS NOT NULL
       OR p_evidence_id IS NOT NULL OR p_evidence_revision IS NOT NULL
       OR p_primary_kind IS DISTINCT FROM 'passkey'
       OR p_primary_id IS NULL OR p_primary_revision IS NULL THEN
      RAISE EXCEPTION 'invalid passkey session clone intent'
        USING ERRCODE = '22023';
    END IF;
    SELECT credential.* INTO STRICT v_factor_credential
    FROM ONLY public.tenant_webauthn_credentials AS credential
    WHERE credential.tenant_id = v_provenance.tenant_id
      AND credential.user_id = v_provenance.user_id
      AND credential.id = p_primary_id
      AND credential.version = p_primary_revision
      AND credential.status = 'clone_suspected'
      AND credential.revoked_at = p_completed_at
      AND credential.updated_at = p_completed_at
      AND credential.revoke_reason = 'authenticator_counter_regression'
    FOR SHARE;
    v_same_primary := p_primary_id = v_provenance.credential_id;
    IF v_same_primary
       AND v_factor_credential.security_revision <>
           v_provenance.credential_revision + 1 THEN
      RAISE EXCEPTION 'passkey session clone revision drifted'
        USING ERRCODE = '40001';
    END IF;
  ELSE
    v_baseline_only := p_evidence_kind IS NULL
      AND p_evidence_id IS NULL
      AND p_evidence_revision IS NULL
      AND p_primary_kind IS NULL
      AND p_primary_id IS NULL
      AND p_primary_revision IS NULL;
    IF NOT (p_session ? 'reservation')
       OR p_session -> 'reservation' = 'null'::jsonb
       OR (NOT v_baseline_only AND (
         p_evidence_kind NOT IN ('totp','webauthn','recovery')
         OR p_evidence_id IS NULL OR p_evidence_revision < 1
       )) THEN
      RAISE EXCEPTION 'passkey session evidence is invalid'
        USING ERRCODE = '22023';
    END IF;
    IF v_baseline_only THEN
      -- Registration and recovery-code replacement rotate an already-assured
      -- session without authenticating an additional factor.  The exact live
      -- baseline/policy was locked above; copy it once and preserve the passkey
      -- primary instead of manufacturing a duplicate evidence item.
      v_same_primary := false;
    ELSE
    v_same_primary := p_evidence_kind = 'webauthn'
      AND p_evidence_id = v_provenance.credential_id;
    IF p_evidence_kind = 'webauthn' THEN
      IF p_primary_kind IS DISTINCT FROM 'passkey'
         OR p_primary_id IS DISTINCT FROM p_evidence_id
         OR p_primary_revision IS DISTINCT FROM p_evidence_revision THEN
        RAISE EXCEPTION 'passkey session evidence identity is inconsistent'
          USING ERRCODE = '22023';
      END IF;
      SELECT credential.* INTO STRICT v_factor_credential
      FROM ONLY public.tenant_webauthn_credentials AS credential
      WHERE credential.tenant_id = v_provenance.tenant_id
        AND credential.user_id = v_provenance.user_id
        AND credential.id = p_evidence_id
        AND credential.version = p_evidence_revision
        AND credential.status = 'active'
        AND credential.last_used_at = p_completed_at
        AND credential.updated_at = p_completed_at
      FOR SHARE;
    ELSIF p_primary_kind IS NOT NULL OR p_primary_id IS NOT NULL
       OR p_primary_revision IS NOT NULL THEN
      RAISE EXCEPTION 'non-passkey factor supplied a primary override'
        USING ERRCODE = '22023';
    END IF;
    v_factor_security_revision := CASE p_evidence_kind
      WHEN 'webauthn' THEN v_factor_credential.security_revision
      ELSE p_evidence_revision
    END;
    SELECT count(*) INTO STRICT v_factor_evidence_count
    FROM (
      SELECT evidence.id
      FROM ONLY public.auth_session_mfa_evidence AS evidence
      WHERE evidence.tenant_id = v_provenance.tenant_id
        AND evidence.session_id = v_provenance.session_id
        AND ((p_evidence_kind = 'totp'
              AND evidence.totp_factor_id = p_evidence_id)
          OR (p_evidence_kind = 'webauthn'
              AND evidence.webauthn_credential_id = p_evidence_id)
          OR (p_evidence_kind = 'recovery'
              AND evidence.recovery_code_set_id = p_evidence_id))
      FOR SHARE NOWAIT
    ) AS matching_evidence;
    IF v_factor_evidence_count > 1 THEN
      RAISE EXCEPTION 'passkey session factor evidence is ambiguous'
        USING ERRCODE = '40001';
    ELSIF v_factor_evidence_count = 1 THEN
      SELECT evidence.* INTO STRICT v_existing_factor_evidence
      FROM ONLY public.auth_session_mfa_evidence AS evidence
      WHERE evidence.tenant_id = v_provenance.tenant_id
        AND evidence.session_id = v_provenance.session_id
        AND ((p_evidence_kind = 'totp'
              AND evidence.totp_factor_id = p_evidence_id)
          OR (p_evidence_kind = 'webauthn'
              AND evidence.webauthn_credential_id = p_evidence_id)
          OR (p_evidence_kind = 'recovery'
              AND evidence.recovery_code_set_id = p_evidence_id))
      FOR SHARE NOWAIT;
      v_refresh_evidence := true;
    ELSIF v_evidence_count >= 1024 THEN
      RAISE EXCEPTION 'passkey session MFA evidence snapshot limit reached'
        USING ERRCODE = '22023';
    END IF;
    v_transform_evidence_copy := v_refresh_evidence
      AND p_evidence_kind = 'webauthn'
      AND EXISTS (
        SELECT 1
        FROM ONLY public.tenant_mfa_webauthn_evidence_copy_capabilities
          AS capability
        WHERE capability.backend_pid = pg_backend_pid()
          AND capability.transaction_id = txid_current()
          AND capability.tenant_id = v_provenance.tenant_id
          AND capability.source_anchor_id = p_anchor_id
          AND capability.destination_session_id =
              app.private_mfa_require_uuidv7_v1(
                p_session #>> '{reservation,sessionId}'
              )
          AND capability.credential_id = p_evidence_id
          AND capability.source_revision =
              v_existing_factor_evidence.factor_revision
          AND capability.target_revision = v_factor_security_revision
          AND capability.target_authenticated_at = p_completed_at
      );
    END IF;
  END IF;

  SELECT credential.* INTO STRICT v_primary_credential
  FROM ONLY public.tenant_webauthn_credentials AS credential
  WHERE credential.tenant_id = v_provenance.tenant_id
    AND credential.user_id = v_provenance.user_id
    AND credential.id = v_provenance.credential_id
    AND credential.security_revision BETWEEN
        v_provenance.credential_revision
        AND v_provenance.credential_revision
          + CASE WHEN v_same_primary THEN 1 ELSE 0 END
    AND credential.status = CASE WHEN v_mutation = 'revoke' AND v_same_primary
      THEN 'clone_suspected' ELSE 'active' END
  FOR SHARE;

  IF v_mutation = 'rotate' THEN
    v_expected_factor_method := CASE
      WHEN v_baseline_only THEN 'passkey'
      ELSE CASE p_evidence_kind
        WHEN 'totp' THEN 'totp'
        WHEN 'webauthn' THEN 'passkey'
        WHEN 'recovery' THEN 'recovery_code'
      END
    END;
    v_reservation := p_session -> 'reservation';
    IF v_reservation ->> 'authenticationMethod' IS DISTINCT FROM
         v_expected_factor_method
       OR app.private_mfa_require_uuidv7_v1(
            v_reservation ->> 'familyId'
          ) IS DISTINCT FROM v_source_session.rotation_family_id
       OR (v_reservation ->> 'absoluteExpiresAt')::timestamptz
            IS DISTINCT FROM v_source_session.absolute_expires_at
       OR (v_reservation ->> 'idleExpiresAt')::timestamptz <= v_authority_at
       OR (v_reservation ->> 'absoluteExpiresAt')::timestamptz <=
            v_authority_at THEN
      RAISE EXCEPTION 'passkey session successor authority drifted'
        USING ERRCODE = '22023';
    END IF;
  END IF;

  v_result := app.private_mfa_apply_session_legacy_v1(
    p_session,p_anchor_id,p_primary_kind,p_primary_id,p_primary_revision,
    CASE WHEN v_refresh_evidence THEN NULL ELSE p_evidence_kind END,
    CASE WHEN v_refresh_evidence THEN NULL ELSE p_evidence_id END,
    CASE WHEN v_refresh_evidence THEN NULL ELSE v_factor_security_revision END,
    p_completed_at
  );
  IF v_mutation = 'revoke' THEN RETURN v_result; END IF;

  v_successor_id := (v_result ->> 'newSessionId')::uuid;
  UPDATE ONLY public.auth_session_passkey_provenance AS successor
  SET credential_revision = CASE WHEN v_same_primary
        THEN v_primary_credential.security_revision
        ELSE v_provenance.credential_revision END,
      authenticated_at = CASE WHEN v_same_primary
        THEN p_completed_at ELSE v_provenance.authenticated_at END
  WHERE successor.tenant_id = v_provenance.tenant_id
    AND successor.session_id = v_successor_id
    AND successor.user_id = v_provenance.user_id
    AND successor.credential_id = v_provenance.credential_id
    AND successor.credential_revision = v_provenance.credential_revision
    AND successor.authenticated_at = v_provenance.authenticated_at;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'passkey session successor provenance is unavailable'
      USING ERRCODE = '23514';
  END IF;
  IF v_refresh_evidence AND NOT v_transform_evidence_copy THEN
    UPDATE ONLY public.auth_session_mfa_evidence AS evidence
    SET factor_revision = v_factor_security_revision,
        authenticated_at = p_completed_at,expires_at = NULL
    WHERE evidence.tenant_id = v_provenance.tenant_id
      AND evidence.session_id = v_successor_id
      AND evidence.kind = v_existing_factor_evidence.kind
      AND evidence.totp_factor_id IS NOT DISTINCT FROM
          v_existing_factor_evidence.totp_factor_id
      AND evidence.webauthn_credential_id IS NOT DISTINCT FROM
          v_existing_factor_evidence.webauthn_credential_id
      AND evidence.recovery_code_set_id IS NOT DISTINCT FROM
          v_existing_factor_evidence.recovery_code_set_id
      AND evidence.factor_revision = v_existing_factor_evidence.factor_revision
      AND evidence.authenticated_at =
          v_existing_factor_evidence.authenticated_at;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'passkey session successor evidence is unavailable'
      USING ERRCODE = '23514';
    END IF;
  ELSIF v_transform_evidence_copy AND (
    SELECT count(*)
    FROM ONLY public.auth_session_mfa_evidence AS evidence
    WHERE evidence.tenant_id = v_provenance.tenant_id
      AND evidence.session_id = v_successor_id
      AND evidence.kind = 'webauthn'
      AND evidence.webauthn_credential_id = p_evidence_id
      AND evidence.factor_revision = v_factor_security_revision
      AND evidence.authenticated_at = p_completed_at
  ) <> 1 THEN
    RAISE EXCEPTION 'passkey session transformed evidence is ambiguous'
      USING ERRCODE = '23514';
  END IF;
  UPDATE ONLY public.auth_sessions AS successor
  SET authentication_method = 'passkey'
  WHERE successor.id = v_successor_id
    AND successor.user_id = v_provenance.user_id
    AND successor.active_tenant_id = v_provenance.tenant_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'passkey session successor is unavailable'
      USING ERRCODE = '23514';
  END IF;
  RETURN v_result;
EXCEPTION WHEN lock_not_available THEN
  RAISE EXCEPTION 'passkey session completion authority is busy'
    USING ERRCODE = '40001';
WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
  RAISE EXCEPTION 'passkey session completion authority is unavailable'
    USING ERRCODE = '40001';
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_mfa_prepare_webauthn_evidence_copy_v1(
  p_request jsonb,
  p_ceremony_id bytea
)
RETURNS boolean
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_ceremony public.tenant_webauthn_ceremonies%ROWTYPE;
  v_anchor public.tenant_mfa_authority_anchors%ROWTYPE;
  v_credential public.tenant_webauthn_credentials%ROWTYPE;
  v_source public.tenant_mfa_authority_evidence%ROWTYPE;
  v_source_count bigint;
  v_destination_session_id uuid;
  v_resolved_user_id uuid;
  v_completed_at timestamptz;
  v_target_revision bigint;
  v_target_level text;
  v_backup_changed boolean;
BEGIN
  SELECT ceremony.* INTO STRICT v_ceremony
  FROM ONLY public.tenant_webauthn_ceremonies AS ceremony
  WHERE ceremony.id = p_ceremony_id
  FOR UPDATE;
  -- A concurrent exact completion can cross the outer lock-free replay
  -- preflight while this call waits for the first writer.  Once the row lock
  -- is acquired, let the sealed v34 replay branch return the immutable
  -- snapshot without trying to reconstruct a copy capability from live state.
  IF v_ceremony.state = 'completed' THEN
    RETURN false;
  END IF;
  IF v_ceremony.state <> 'claimed'
     OR v_ceremony.purpose NOT IN (
       'primary_authentication','continuation_authentication',
       'step_up_authentication'
     ) THEN
    RAISE EXCEPTION 'WebAuthn evidence copy ceremony is unavailable'
      USING ERRCODE = '40001';
  END IF;
  SELECT anchor.* INTO STRICT v_anchor
  FROM ONLY public.tenant_mfa_authority_anchors AS anchor
  WHERE anchor.id = v_ceremony.authority_anchor_id
    AND anchor.tenant_id = v_ceremony.tenant_id
  FOR SHARE;

  IF p_request #>> '{completion,counterDisposition}' = 'clone_suspected'
     OR p_request #>> '{session,mutation}' = 'revoke' THEN
    RETURN false;
  END IF;
  IF p_request #>> '{session,mutation}' NOT IN (
       'create','rotate','consume_continuation'
     ) OR jsonb_typeof(p_request #> '{session,reservation}') <> 'object' THEN
    RAISE EXCEPTION 'WebAuthn evidence copy destination is invalid'
      USING ERRCODE = '22023';
  END IF;
  v_destination_session_id := app.private_mfa_require_uuidv7_v1(
    p_request #>> '{session,reservation,sessionId}'
  );
  v_resolved_user_id := app.private_mfa_require_uuidv7_v1(
    p_request #>> '{completion,resolvedUserId}'
  );
  v_completed_at := (p_request #>> '{completion,completedAt}')::timestamptz;

  SELECT credential.* INTO STRICT v_credential
  FROM ONLY public.tenant_webauthn_credentials AS credential
  WHERE credential.tenant_id = v_ceremony.tenant_id
    AND credential.user_id = v_resolved_user_id
    AND credential.credential_id = app.private_mfa_decode_base64_v1(
      p_request #>> '{completion,credentialId}',1,4096
    )
    AND credential.status = 'active'
    AND credential.version =
        (p_request #>> '{completion,expectedCredentialVersion}')::bigint
    AND credential.backed_up IS NOT DISTINCT FROM
        (p_request #>> '{completion,expectedBackedUp}')::boolean
    AND credential.security_revision BETWEEN 1 AND credential.version
  FOR UPDATE;

  SELECT count(*) INTO STRICT v_source_count
  FROM (
    SELECT evidence.id
    FROM ONLY public.tenant_mfa_authority_evidence AS evidence
    WHERE evidence.tenant_id = v_ceremony.tenant_id
      AND evidence.anchor_id = v_ceremony.authority_anchor_id
      AND evidence.kind = 'webauthn'
      AND evidence.webauthn_credential_id = v_credential.id
    FOR SHARE
  ) AS matching_evidence;
  IF v_source_count = 0 THEN RETURN false; END IF;
  IF v_source_count <> 1 THEN
    RAISE EXCEPTION 'WebAuthn source evidence is ambiguous'
      USING ERRCODE = '40001';
  END IF;
  SELECT evidence.* INTO STRICT v_source
  FROM ONLY public.tenant_mfa_authority_evidence AS evidence
  WHERE evidence.tenant_id = v_ceremony.tenant_id
    AND evidence.anchor_id = v_ceremony.authority_anchor_id
    AND evidence.kind = 'webauthn'
    AND evidence.webauthn_credential_id = v_credential.id
  FOR SHARE;
  IF v_anchor.user_id IS DISTINCT FROM v_credential.user_id
     OR v_source.factor_revision IS DISTINCT FROM
          v_credential.security_revision THEN
    RAISE EXCEPTION 'WebAuthn source evidence is stale'
      USING ERRCODE = '40001';
  END IF;

  v_backup_changed := v_credential.backup_eligible IS DISTINCT FROM
        (p_request #>> '{completion,backupEligible}')::boolean
    OR v_credential.backed_up IS DISTINCT FROM
        (p_request #>> '{completion,backedUp}')::boolean;
  IF v_backup_changed
     AND v_credential.security_revision >= 9007199254740991 THEN
    RAISE EXCEPTION 'WebAuthn security revision exhausted'
      USING ERRCODE = '22003';
  END IF;
  v_target_revision := v_credential.security_revision
    + CASE WHEN v_backup_changed THEN 1 ELSE 0 END;
  v_target_level := CASE
    WHEN (p_request #>> '{completion,userVerified}')::boolean
      THEN 'phishing_resistant'
    WHEN v_ceremony.purpose = 'primary_authentication' THEN 'primary'
    ELSE 'mfa'
  END;

  INSERT INTO public.tenant_mfa_webauthn_evidence_copy_capabilities (
    tenant_id,source_anchor_id,source_evidence_id,destination_session_id,
    backend_pid,transaction_id,user_id,factor_kind,credential_id,
    source_revision,target_revision,source_level,target_level,
    source_authenticated_at,source_expires_at,target_authenticated_at,
    created_at
  ) VALUES (
    v_ceremony.tenant_id,v_ceremony.authority_anchor_id,v_source.id,
    v_destination_session_id,pg_backend_pid(),txid_current(),
    v_credential.user_id,'webauthn',v_credential.id,
    v_source.factor_revision,v_target_revision,v_source.level,v_target_level,
    v_source.authenticated_at,v_source.expires_at,v_completed_at,
    transaction_timestamp()
  );
  RETURN true;
EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
  RAISE EXCEPTION 'WebAuthn evidence copy authority is unavailable'
    USING ERRCODE = '40001';
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_mfa_finish_webauthn_evidence_copy_v1(
  p_result jsonb,
  p_anchor_id uuid,
  p_credential_id uuid,
  p_completed_at timestamptz
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_destination_session_id uuid;
  v_capability
    public.tenant_mfa_webauthn_evidence_copy_capabilities%ROWTYPE;
  v_target_count bigint;
BEGIN
  SELECT capability.* INTO v_capability
  FROM ONLY public.tenant_mfa_webauthn_evidence_copy_capabilities AS capability
  WHERE capability.backend_pid = pg_backend_pid()
    AND capability.transaction_id = txid_current()
    AND capability.source_anchor_id = p_anchor_id
    AND capability.credential_id = p_credential_id
  FOR UPDATE;
  IF NOT FOUND THEN RETURN p_result; END IF;
  IF NOT (p_result ? 'newSessionId') THEN
    RAISE EXCEPTION 'WebAuthn evidence copy destination is unavailable'
      USING ERRCODE = '40001';
  END IF;
  v_destination_session_id := app.private_mfa_require_uuidv7_v1(
    p_result ->> 'newSessionId'
  );
  IF v_capability.destination_session_id IS DISTINCT FROM
       v_destination_session_id
     OR v_capability.target_authenticated_at IS DISTINCT FROM p_completed_at
     OR v_capability.consumed_evidence_id IS NULL
     OR v_capability.consumed_at IS NULL THEN
    RAISE EXCEPTION 'WebAuthn evidence copy was not consumed exactly once'
      USING ERRCODE = '40001';
  END IF;
  SELECT count(*) INTO STRICT v_target_count
  FROM (
    SELECT evidence.id
    FROM ONLY public.auth_session_mfa_evidence AS evidence
    JOIN ONLY public.auth_sessions AS session
      ON session.id = evidence.session_id
     AND session.active_tenant_id = evidence.tenant_id
    WHERE evidence.tenant_id = v_capability.tenant_id
      AND evidence.session_id = v_destination_session_id
      AND evidence.id = v_capability.consumed_evidence_id
      AND evidence.kind = 'webauthn'
      AND evidence.webauthn_credential_id = v_capability.credential_id
      AND evidence.factor_revision = v_capability.target_revision
      AND evidence.level = v_capability.target_level
      AND evidence.authenticated_at = v_capability.target_authenticated_at
      AND evidence.expires_at IS NULL
      AND session.user_id = v_capability.user_id
    FOR SHARE OF evidence,session
  ) AS exact_target;
  IF v_target_count <> 1 OR (
    SELECT count(*)
    FROM ONLY public.auth_session_mfa_evidence AS evidence
    WHERE evidence.tenant_id = v_capability.tenant_id
      AND evidence.session_id = v_destination_session_id
      AND evidence.webauthn_credential_id = v_capability.credential_id
  ) <> 1 THEN
    RAISE EXCEPTION 'WebAuthn successor evidence is ambiguous'
      USING ERRCODE = '40001';
  END IF;
  DELETE FROM ONLY public.tenant_mfa_webauthn_evidence_copy_capabilities
    AS capability
  WHERE capability.tenant_id = v_capability.tenant_id
    AND capability.source_anchor_id = v_capability.source_anchor_id
    AND capability.destination_session_id =
        v_capability.destination_session_id
    AND capability.backend_pid = v_capability.backend_pid
    AND capability.transaction_id = v_capability.transaction_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'WebAuthn evidence copy cleanup lost CAS'
      USING ERRCODE = '40001';
  END IF;
  RETURN p_result;
END;
$function$;
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.private_mfa_apply_session_v1(
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
  flow text;
  primary_kind text;
  anchor_action text;
  anchor_audience text;
  anchor_tenant_id uuid;
  anchor_user_id uuid;
  anchor_session_id uuid;
  anchor_continuation_id uuid;
  mutation text := p_session ->> 'mutation';
  normalized_session jsonb := p_session;
  top_level_receipt boolean := p_session ? 'continuationReceiptDigest';
  reservation_receipt boolean := coalesce(
    p_session -> 'reservation' ? 'continuationReceiptDigest',false
  );
  v_continuation_receipt_digest bytea;
  result jsonb;
  expected_factor_method text;
  authority_at timestamptz := greatest(
    p_completed_at,transaction_timestamp()
  );
  tenant_continuation_provenance
    public.tenant_post_primary_federated_provenance%ROWTYPE;
  tenant_source_session public.auth_sessions%ROWTYPE;
  tenant_source_state public.auth_session_mfa_states%ROWTYPE;
  tenant_source_bound boolean := false;
  v_primary_credential public.tenant_webauthn_credentials%ROWTYPE;
  v_primary_policy_snapshot jsonb;
  v_primary_policy_count bigint;
  v_effective_evidence_revision bigint := p_evidence_revision;
  v_consumer_evidence_kind text := p_evidence_kind;
  v_consumer_evidence_id uuid := p_evidence_id;
  v_consumer_evidence_revision bigint := p_evidence_revision;
  v_copy_destination_session_id uuid;
  v_copy_capability_count bigint := 0;
  v_copy_source_count bigint := 0;
  v_copy_capability boolean := false;
  v_local_result_authentication_method text;
BEGIN
  SELECT anchor.flow,anchor.action,anchor.audience,anchor.tenant_id,
         anchor.user_id,anchor.session_id,anchor.continuation_id
    INTO STRICT flow,anchor_action,anchor_audience,anchor_tenant_id,
      anchor_user_id,anchor_session_id,anchor_continuation_id
  FROM ONLY public.tenant_mfa_authority_anchors AS anchor
  WHERE anchor.id = p_anchor_id
  FOR UPDATE;
  PERFORM app.private_mfa_lock_policy_authority_v1(anchor_tenant_id);
  IF flow = 'session' THEN
    SELECT state.primary_kind INTO STRICT primary_kind
    FROM ONLY public.tenant_mfa_authority_anchors AS anchor
    JOIN ONLY public.auth_session_mfa_states AS state
      ON state.tenant_id = anchor.tenant_id
     AND state.session_id = anchor.session_id
     AND state.user_id = anchor.user_id
    WHERE anchor.id = p_anchor_id;
  ELSIF flow = 'continuation' THEN
    SELECT continuation.primary_kind INTO STRICT primary_kind
    FROM ONLY public.tenant_mfa_authority_anchors AS anchor
    JOIN ONLY public.tenant_post_primary_continuations AS continuation
      ON continuation.tenant_id = anchor.tenant_id
     AND continuation.id = anchor.continuation_id
     AND continuation.user_id = anchor.user_id
    WHERE anchor.id = p_anchor_id;
  END IF;

  IF flow = 'continuation' THEN
    IF top_level_receipt = reservation_receipt THEN
      RAISE EXCEPTION 'exactly one continuation receipt is required'
        USING ERRCODE = '22023';
    END IF;
    v_continuation_receipt_digest := app.private_mfa_decode_base64_v1(
      CASE WHEN top_level_receipt
        THEN p_session ->> 'continuationReceiptDigest'
        ELSE p_session -> 'reservation' ->> 'continuationReceiptDigest'
      END,32,32
    );
    IF encode(v_continuation_receipt_digest,'hex') = repeat('00',32) THEN
      RAISE EXCEPTION 'continuation receipt is invalid'
        USING ERRCODE = '22023';
    END IF;
    PERFORM 1
    FROM ONLY public.tenant_mfa_authority_anchors AS anchor
    JOIN ONLY public.tenant_post_primary_continuations AS continuation
      ON continuation.tenant_id = anchor.tenant_id
     AND continuation.id = anchor.continuation_id
     AND continuation.user_id = anchor.user_id
     AND continuation.version = anchor.anchor_version
     AND continuation.expires_at = anchor.anchor_expires_at
     AND continuation.state = 'pending'
     AND continuation.receipt_digest = v_continuation_receipt_digest
    WHERE anchor.id = p_anchor_id
    FOR UPDATE OF continuation;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'continuation receipt is stale'
        USING ERRCODE = '40001';
    END IF;
    normalized_session := p_session - 'continuationReceiptDigest';
    IF reservation_receipt THEN
      normalized_session := jsonb_set(
        normalized_session,'{reservation}',
        (p_session -> 'reservation') - 'continuationReceiptDigest',false
      );
    END IF;
  ELSIF top_level_receipt OR reservation_receipt THEN
    RAISE EXCEPTION 'continuation receipt is forbidden'
      USING ERRCODE = '22023';
  END IF;

  IF p_evidence_kind = 'webauthn' AND mutation <> 'revoke' THEN
    IF jsonb_typeof(normalized_session -> 'reservation') <> 'object' THEN
      RAISE EXCEPTION 'WebAuthn evidence copy destination is invalid'
        USING ERRCODE = '22023';
    END IF;
    v_copy_destination_session_id := app.private_mfa_require_uuidv7_v1(
      normalized_session #>> '{reservation,sessionId}'
    );
    SELECT count(*) INTO STRICT v_copy_capability_count
    FROM (
      SELECT capability.source_evidence_id
      FROM ONLY public.tenant_mfa_webauthn_evidence_copy_capabilities
        AS capability
      WHERE capability.backend_pid = pg_backend_pid()
        AND capability.transaction_id = txid_current()
        AND capability.tenant_id = anchor_tenant_id
        AND capability.source_anchor_id = p_anchor_id
        AND capability.destination_session_id =
            v_copy_destination_session_id
        AND capability.credential_id = p_evidence_id
        AND capability.target_authenticated_at = p_completed_at
        AND capability.consumed_evidence_id IS NULL
        AND capability.consumed_at IS NULL
      FOR UPDATE
    ) AS exact_capability;
    IF v_copy_capability_count > 1 THEN
      RAISE EXCEPTION 'WebAuthn evidence copy capability is ambiguous'
        USING ERRCODE = '40001';
    END IF;
    SELECT count(*) INTO STRICT v_copy_source_count
    FROM (
      SELECT evidence.id
      FROM ONLY public.tenant_mfa_authority_evidence AS evidence
      WHERE evidence.tenant_id = anchor_tenant_id
        AND evidence.anchor_id = p_anchor_id
        AND evidence.kind = 'webauthn'
        AND evidence.webauthn_credential_id = p_evidence_id
      FOR SHARE
    ) AS source_evidence;
    IF v_copy_source_count > 1
       OR (v_copy_capability_count = 1 AND v_copy_source_count <> 1)
       OR (v_copy_capability_count = 0 AND v_copy_source_count <> 0) THEN
      RAISE EXCEPTION 'WebAuthn evidence copy authority is stale or ambiguous'
        USING ERRCODE = '40001';
    END IF;
    v_copy_capability := v_copy_capability_count = 1;
    IF v_copy_capability THEN
      v_consumer_evidence_kind := NULL;
      v_consumer_evidence_id := NULL;
      v_consumer_evidence_revision := NULL;
    END IF;
  END IF;

  -- Primary passkey login is not a session/continuation authority lookup.  The
  -- completed ceremony has already advanced the record-version CAS; bridge it
  -- directly to the legacy primary creator while persisting the separate live
  -- security revision in provenance/evidence.
  IF flow = 'primary' AND p_primary_kind = 'passkey'
     AND mutation IN ('create','revoke') THEN
    PERFORM app.private_mfa_lock_policy_authority_v1(anchor_tenant_id);
    SELECT credential.* INTO STRICT v_primary_credential
    FROM ONLY public.tenant_webauthn_credentials AS credential
    WHERE credential.tenant_id = anchor_tenant_id
      AND credential.id = p_primary_id
      AND credential.version = p_primary_revision
      AND credential.version BETWEEN 1 AND 9007199254740991
      AND credential.security_revision BETWEEN 1 AND credential.version
      AND (
        (mutation = 'create'
          AND credential.status = 'active'
          AND credential.last_used_at = p_completed_at
          AND credential.updated_at = p_completed_at)
        OR (mutation = 'revoke'
          AND credential.status = 'clone_suspected'
          AND credential.revoked_at = p_completed_at
          AND credential.updated_at = p_completed_at
          AND credential.revoke_reason =
              'authenticator_counter_regression')
      )
    FOR SHARE;
    PERFORM 1
    FROM ONLY public.tenants AS tenant
    JOIN ONLY public.tenant_mfa_subjects AS subject
      ON subject.tenant_id = tenant.id
     AND subject.user_id = v_primary_credential.user_id
    JOIN ONLY public.users AS local_user
      ON local_user.id = subject.user_id
    JOIN ONLY public.tenant_memberships AS membership
      ON membership.tenant_id = subject.tenant_id
     AND membership.user_id = subject.user_id
    WHERE tenant.id = anchor_tenant_id
      AND tenant.status = 'active'
      AND local_user.active
      AND membership.status = 'active'
      AND (anchor_user_id IS NULL
        OR anchor_user_id = v_primary_credential.user_id)
      AND coalesce(
        (normalized_session ->> 'expectedIdentityEpoch')::bigint,
        subject.identity_epoch
      ) IN (0,subject.identity_epoch)
    FOR SHARE OF tenant,subject,local_user,membership;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'primary passkey lifecycle authority drifted'
        USING ERRCODE = '40001';
    END IF;
    IF mutation = 'create' THEN
      IF p_evidence_kind IS DISTINCT FROM 'webauthn'
         OR p_evidence_id IS DISTINCT FROM p_primary_id
         OR p_evidence_revision IS DISTINCT FROM p_primary_revision
         OR normalized_session #>> '{reservation,authenticationMethod}'
              IS DISTINCT FROM 'passkey'
         OR (normalized_session #>> '{reservation,idleExpiresAt}')::timestamptz
              <= authority_at
         OR (normalized_session #>>
               '{reservation,absoluteExpiresAt}')::timestamptz <= authority_at
      THEN
        RAISE EXCEPTION 'primary passkey completion proof drifted'
          USING ERRCODE = '40001';
      END IF;
      v_primary_policy_snapshot := app.private_mfa_policy_snapshot_v1(
        anchor_tenant_id,v_primary_credential.user_id,anchor_action,authority_at
      );
      IF jsonb_strip_nulls(normalized_session -> 'requirement') IS DISTINCT FROM
           jsonb_strip_nulls(v_primary_policy_snapshot -> 'requirement') THEN
        RAISE EXCEPTION 'primary passkey policy authority drifted'
          USING ERRCODE = '40001';
      END IF;
      SELECT count(*) INTO STRICT v_primary_policy_count
      FROM (
        SELECT policy.id
        FROM ONLY public.mfa_policy_revisions AS policy
        JOIN jsonb_array_elements(
          v_primary_policy_snapshot -> 'policies'
        ) AS pin(value)
          ON policy.id = (pin.value -> 'policy' ->> 'id')::uuid
         AND policy.revision =
             (pin.value -> 'policy' ->> 'revision')::bigint
        FOR SHARE OF policy
      ) AS locked_policy;
      IF v_primary_policy_count <> jsonb_array_length(
           v_primary_policy_snapshot -> 'policies'
         ) THEN
        RAISE EXCEPTION 'primary passkey policy authority is unavailable'
          USING ERRCODE = '40001';
      END IF;
      v_effective_evidence_revision :=
        v_primary_credential.security_revision;
    ELSIF p_evidence_kind IS NOT NULL OR p_evidence_id IS NOT NULL
       OR p_evidence_revision IS NOT NULL THEN
      RAISE EXCEPTION 'primary passkey clone evidence is forbidden'
        USING ERRCODE = '22023';
    END IF;
    result := app.private_mfa_apply_session_legacy_v1(
      normalized_session,p_anchor_id,p_primary_kind,p_primary_id,
      p_primary_revision,p_evidence_kind,p_evidence_id,
      v_effective_evidence_revision,p_completed_at
    );
    IF v_copy_capability THEN
      result := app.private_mfa_finish_webauthn_evidence_copy_v1(
        result,p_anchor_id,p_evidence_id,p_completed_at
      );
    END IF;
    RETURN result;
  END IF;

  -- A passkey-primary session needs a final CAS over the exact source
  -- provenance even when the step-up factor is different.  Same-primary
  -- WebAuthn has already advanced the credential here, so the specialized
  -- branch is also responsible for refreshing (not duplicating) its one
  -- provenance/evidence pin.
  IF flow = 'session' AND primary_kind = 'passkey'
     AND mutation IN ('rotate','revoke') THEN
    result := app.private_mfa_apply_passkey_session_v1(
      normalized_session,p_anchor_id,p_primary_kind,p_primary_id,
      p_primary_revision,p_evidence_kind,p_evidence_id,p_evidence_revision,
      p_completed_at
    );
    IF v_copy_capability THEN
      result := app.private_mfa_finish_webauthn_evidence_copy_v1(
        result,p_anchor_id,p_evidence_id,p_completed_at
      );
    END IF;
    RETURN result;
  END IF;

  -- WebAuthn completion advances (or revokes) the credential before the
  -- continuation mutation.  The specialized final CAS proves that exact
  -- transition against the immutable child.
  IF flow = 'continuation' AND primary_kind = 'passkey'
     AND mutation IN ('consume_continuation','revoke') THEN
    result := app.private_mfa_apply_passkey_continuation_v1(
      normalized_session,p_anchor_id,p_primary_kind,p_primary_id,
      p_primary_revision,p_evidence_kind,p_evidence_id,p_evidence_revision,
      p_completed_at
    );
    IF v_copy_capability THEN
      result := app.private_mfa_finish_webauthn_evidence_copy_v1(
        result,p_anchor_id,p_evidence_id,p_completed_at
      );
    END IF;
    RETURN result;
  END IF;

  PERFORM app.resolve_mfa_authority_v2(
    CASE WHEN flow = 'continuation'
      THEN anchor_continuation_id ELSE anchor_session_id END,
    flow,anchor_action,anchor_audience,authority_at,
    CASE WHEN flow = 'continuation'
      THEN v_continuation_receipt_digest ELSE NULL::bytea END
  );
  IF flow = 'continuation' THEN
    PERFORM app.private_mfa_lock_continuation_authority_v1(
      anchor_continuation_id,authority_at
    );
  END IF;
  IF p_evidence_kind = 'webauthn' THEN
    SELECT credential.security_revision
      INTO STRICT v_effective_evidence_revision
    FROM ONLY public.tenant_webauthn_credentials AS credential
    WHERE credential.tenant_id = anchor_tenant_id
      AND credential.user_id = anchor_user_id
      AND credential.id = p_evidence_id
      AND credential.version = p_evidence_revision
      AND credential.status = 'active'
      AND credential.last_used_at = p_completed_at
      AND credential.updated_at = p_completed_at
      AND credential.security_revision BETWEEN 1 AND credential.version
    FOR SHARE;
    IF v_copy_capability AND NOT EXISTS (
      SELECT 1
      FROM ONLY public.tenant_mfa_webauthn_evidence_copy_capabilities
        AS capability
      WHERE capability.backend_pid = pg_backend_pid()
        AND capability.transaction_id = txid_current()
        AND capability.tenant_id = anchor_tenant_id
        AND capability.source_anchor_id = p_anchor_id
        AND capability.destination_session_id =
            v_copy_destination_session_id
        AND capability.credential_id = p_evidence_id
        AND capability.target_revision = v_effective_evidence_revision
        AND capability.target_authenticated_at = p_completed_at
    ) THEN
      RAISE EXCEPTION 'WebAuthn evidence copy target drifted'
        USING ERRCODE = '40001';
    END IF;
  END IF;
  IF mutation IN ('rotate','consume_continuation') AND (
    (normalized_session #>> '{reservation,idleExpiresAt}')::timestamptz
      <= authority_at
    OR (normalized_session #>> '{reservation,absoluteExpiresAt}')::timestamptz
      <= authority_at
  ) THEN
    RAISE EXCEPTION 'MFA successor session is already expired'
      USING ERRCODE = '22023';
  END IF;

  IF flow = 'continuation' AND mutation = 'retain_continuation'
     AND primary_kind IN ('tenant_provider','tenant_platform_provider') THEN
    -- Retention advances the continuation CAS and is therefore an authority
    -- mutation, not a factor-only write.  Revalidate the exact receipt and
    -- typed live authority before the legacy retention branch can mutate it.
    PERFORM app.resolve_mfa_authority_v2(
      anchor_continuation_id,'continuation',anchor_action,anchor_audience,
      authority_at,v_continuation_receipt_digest
    );
  END IF;

  IF primary_kind IN ('tenant_provider','tenant_platform_provider')
     AND ((flow = 'session' AND mutation = 'rotate')
       OR (flow = 'continuation' AND mutation = 'consume_continuation')) THEN
    IF p_primary_kind IS NOT NULL OR p_primary_id IS NOT NULL
       OR p_primary_revision IS NOT NULL THEN
      RAISE EXCEPTION 'federated primary override is forbidden'
        USING ERRCODE = '22023';
    END IF;
    expected_factor_method := CASE p_evidence_kind
      WHEN 'totp' THEN 'totp'
      WHEN 'webauthn' THEN 'passkey'
      WHEN 'recovery' THEN 'recovery_code'
    END;
    IF expected_factor_method IS NULL
       OR normalized_session -> 'reservation' ->> 'authenticationMethod'
            IS DISTINCT FROM expected_factor_method THEN
      RAISE EXCEPTION 'federated MFA factor method is inconsistent'
        USING ERRCODE = '22023';
    END IF;
    IF primary_kind = 'tenant_platform_provider' THEN
      result := app.private_mfa_apply_tenant_platform_federated_session_v1(
        normalized_session,p_anchor_id,v_consumer_evidence_kind,
        v_consumer_evidence_id,
        CASE WHEN v_copy_capability THEN NULL
          ELSE v_effective_evidence_revision END,p_completed_at
      );
      UPDATE ONLY public.auth_sessions AS session
      SET authentication_method = provenance.authentication_method
      FROM ONLY public.auth_session_tenant_platform_federated_provenance
        AS provenance
      WHERE session.id = (result ->> 'newSessionId')::uuid
        AND provenance.session_id = session.id
        AND provenance.user_id = session.user_id
        AND provenance.tenant_id = session.active_tenant_id;
    ELSE
      IF flow = 'continuation' THEN
        -- Re-run the receipt-bound live projection at the same instant as the
        -- terminal consumer.  In particular, an old tenant-provider
        -- continuation cannot be revived by disabling and reactivating a new
        -- access epoch/grant during its TTL.
        PERFORM app.resolve_mfa_authority_v2(
          anchor_continuation_id,'continuation',anchor_action,anchor_audience,
          authority_at,v_continuation_receipt_digest
        );
        SELECT provenance.* INTO STRICT tenant_continuation_provenance
        FROM ONLY public.tenant_post_primary_federated_provenance AS provenance
        WHERE provenance.continuation_id = anchor_continuation_id;
        IF tenant_continuation_provenance.origin = 'session_revalidation' THEN
          SELECT session.* INTO STRICT tenant_source_session
          FROM ONLY public.auth_sessions AS session
          WHERE session.id = tenant_continuation_provenance.source_session_id
            AND session.active_tenant_id =
                tenant_continuation_provenance.tenant_id
            AND session.user_id = tenant_continuation_provenance.user_id
            AND session.rotation_family_id =
                tenant_continuation_provenance.source_session_family_id
            AND session.absolute_expires_at =
                tenant_continuation_provenance.source_absolute_expires_at
            AND session.revoked_at IS NULL
            AND session.idle_expires_at > authority_at
            AND session.absolute_expires_at > authority_at
          FOR UPDATE;
          SELECT state.* INTO STRICT tenant_source_state
          FROM ONLY public.auth_session_mfa_states AS state
          WHERE state.tenant_id = tenant_continuation_provenance.tenant_id
            AND state.session_id = tenant_source_session.id
            AND state.user_id = tenant_continuation_provenance.user_id
            AND state.primary_kind = 'tenant_provider'
            AND state.session_version =
                tenant_continuation_provenance.source_session_version
          FOR UPDATE;
          IF app.private_mfa_require_uuidv7_v1(
               normalized_session #>> '{reservation,familyId}'
             ) IS DISTINCT FROM tenant_source_session.rotation_family_id
             OR (normalized_session #>>
                   '{reservation,absoluteExpiresAt}')::timestamptz
                  IS DISTINCT FROM tenant_source_session.absolute_expires_at
             OR app.private_mfa_require_uuidv7_v1(
                  normalized_session #>> '{reservation,sessionId}'
                ) = tenant_source_session.id THEN
            RAISE EXCEPTION
              'tenant-provider MFA rotation changed family or deadline'
              USING ERRCODE = '22023';
          END IF;
          tenant_source_bound := true;
        ELSIF tenant_continuation_provenance.origin <> 'initial_login' THEN
          RAISE EXCEPTION 'tenant-provider continuation origin is invalid'
            USING ERRCODE = '23514';
        END IF;
      END IF;
      result := app.private_mfa_apply_federated_session_v1(
        normalized_session,p_anchor_id,v_consumer_evidence_kind,
        v_consumer_evidence_id,
        CASE WHEN v_copy_capability THEN NULL
          ELSE v_effective_evidence_revision END,p_completed_at
      );
      IF flow = 'continuation' THEN
        UPDATE ONLY public.auth_session_federated_provenance AS provenance
        SET authentication_method =
              tenant_continuation_provenance.authentication_method,
            provider_id = tenant_continuation_provenance.provider_id,
            binding_id = tenant_continuation_provenance.binding_id,
            provider_kind = tenant_continuation_provenance.provider_kind,
            external_identity_id =
              tenant_continuation_provenance.external_identity_id,
            external_identity_revision =
              tenant_continuation_provenance.external_identity_revision,
            trust_rule_revision =
              tenant_continuation_provenance.security_revision,
            authenticated_at = tenant_continuation_provenance.authenticated_at
        WHERE provenance.tenant_id =
              tenant_continuation_provenance.tenant_id
          AND provenance.session_id = (result ->> 'newSessionId')::uuid
          AND provenance.user_id = tenant_continuation_provenance.user_id;
        IF NOT FOUND THEN
          RAISE EXCEPTION
            'tenant-provider successor provenance is unavailable'
            USING ERRCODE = '23514';
        END IF;
      END IF;
      IF tenant_source_bound THEN
        UPDATE ONLY public.auth_sessions AS source_session
        SET revoked_at = p_completed_at,
            revoke_reason = 'mfa_session_rotated'
        WHERE source_session.id = tenant_source_session.id
          AND source_session.revoked_at IS NULL;
        IF NOT FOUND THEN
          RAISE EXCEPTION 'tenant-provider MFA source rotation lost CAS'
            USING ERRCODE = '40001';
        END IF;
        UPDATE ONLY public.auth_sessions AS successor
        SET rotated_from_session_id = tenant_source_session.id
        WHERE successor.id = (result ->> 'newSessionId')::uuid
          AND successor.rotation_family_id =
              tenant_source_session.rotation_family_id
          AND successor.absolute_expires_at =
              tenant_source_session.absolute_expires_at;
        IF NOT FOUND THEN
          RAISE EXCEPTION 'tenant-provider MFA successor rotation drifted'
            USING ERRCODE = '40001';
        END IF;
        UPDATE ONLY public.auth_session_mfa_states AS successor_state
        SET session_version = tenant_source_state.session_version + 1
        WHERE successor_state.session_id = (result ->> 'newSessionId')::uuid
          AND successor_state.tenant_id =
              tenant_continuation_provenance.tenant_id
          AND successor_state.user_id = tenant_continuation_provenance.user_id
          AND successor_state.primary_kind = 'tenant_provider';
        IF NOT FOUND THEN
          RAISE EXCEPTION 'tenant-provider MFA successor state is unavailable'
            USING ERRCODE = '40001';
        END IF;
        result := jsonb_set(
          result,'{sessionVersion}',
          to_jsonb(tenant_source_state.session_version + 1),true
        );
      END IF;
      UPDATE ONLY public.auth_sessions AS session
      SET authentication_method = provenance.authentication_method
      FROM ONLY public.auth_session_federated_provenance AS provenance
      WHERE session.id = (result ->> 'newSessionId')::uuid
        AND provenance.session_id = session.id
        AND provenance.user_id = session.user_id
        AND provenance.tenant_id = session.active_tenant_id;
    END IF;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'federated primary session provenance is unavailable'
        USING ERRCODE = '23514';
    END IF;
    IF v_copy_capability THEN
      result := app.private_mfa_finish_webauthn_evidence_copy_v1(
        result,p_anchor_id,p_evidence_id,p_completed_at
      );
    END IF;
    RETURN result;
  END IF;
  IF primary_kind = 'passkey'
     AND ((flow = 'session' AND mutation = 'rotate')
       OR (flow = 'continuation' AND mutation = 'consume_continuation')) THEN
    result := app.private_mfa_apply_session_legacy_v1(
      normalized_session,p_anchor_id,p_primary_kind,p_primary_id,
      p_primary_revision,v_consumer_evidence_kind,v_consumer_evidence_id,
      CASE WHEN v_copy_capability THEN NULL
        ELSE v_effective_evidence_revision END,
      p_completed_at
    );
    UPDATE ONLY public.auth_sessions AS session
    SET authentication_method = 'passkey'
    FROM ONLY public.auth_session_passkey_provenance AS provenance
    WHERE session.id = (result ->> 'newSessionId')::uuid
      AND provenance.session_id = session.id
      AND provenance.user_id = session.user_id
      AND provenance.tenant_id = session.active_tenant_id
      AND provenance.primary_kind = 'passkey';
    IF NOT FOUND THEN
      RAISE EXCEPTION 'passkey primary session provenance is unavailable'
        USING ERRCODE = '23514';
    END IF;
    IF v_copy_capability THEN
      result := app.private_mfa_finish_webauthn_evidence_copy_v1(
        result,p_anchor_id,p_evidence_id,p_completed_at
      );
    END IF;
    RETURN result;
  END IF;
  IF primary_kind = 'local_credential'
     AND ((flow = 'session' AND mutation = 'rotate')
       OR (flow = 'continuation' AND mutation = 'consume_continuation')) THEN
    IF flow = 'session' THEN
      SELECT session.authentication_method
        INTO STRICT v_local_result_authentication_method
      FROM ONLY public.auth_sessions AS session
      JOIN ONLY public.auth_session_mfa_states AS state
        ON state.tenant_id = anchor_tenant_id
       AND state.session_id = session.id
       AND state.user_id = anchor_user_id
       AND state.primary_kind = 'local_credential'
      JOIN ONLY public.auth_session_local_credential_provenance AS provenance
        ON provenance.tenant_id = state.tenant_id
       AND provenance.session_id = state.session_id
       AND provenance.user_id = state.user_id
       AND provenance.primary_kind = 'local_credential'
      WHERE session.id = anchor_session_id
        AND session.active_tenant_id = anchor_tenant_id
        AND session.user_id = anchor_user_id
        AND session.revoked_at IS NULL
        AND session.idle_expires_at > authority_at
        AND session.absolute_expires_at > authority_at
        AND session.authentication_method IN (
          'bootstrap_totp','totp','recovery_code'
        )
      FOR SHARE OF session,state,provenance;
    ELSE
      v_local_result_authentication_method := 'bootstrap_totp';
    END IF;
    result := app.private_mfa_apply_session_legacy_v1(
      normalized_session,p_anchor_id,p_primary_kind,p_primary_id,
      p_primary_revision,v_consumer_evidence_kind,v_consumer_evidence_id,
      CASE WHEN v_copy_capability THEN NULL
        ELSE v_effective_evidence_revision END,p_completed_at
    );
    UPDATE ONLY public.auth_sessions AS session
    SET authentication_method = v_local_result_authentication_method
    FROM ONLY public.auth_session_local_credential_provenance AS provenance
    WHERE session.id = (result ->> 'newSessionId')::uuid
      AND provenance.session_id = session.id
      AND provenance.user_id = session.user_id
      AND provenance.tenant_id = session.active_tenant_id
      AND provenance.primary_kind = 'local_credential';
    IF NOT FOUND THEN
      RAISE EXCEPTION 'local primary session provenance is unavailable'
        USING ERRCODE = '23514';
    END IF;
    IF v_copy_capability THEN
      result := app.private_mfa_finish_webauthn_evidence_copy_v1(
        result,p_anchor_id,p_evidence_id,p_completed_at
      );
    END IF;
    RETURN result;
  END IF;
  result := app.private_mfa_apply_session_legacy_v1(
    normalized_session,p_anchor_id,p_primary_kind,p_primary_id,p_primary_revision,
    v_consumer_evidence_kind,v_consumer_evidence_id,
    CASE WHEN v_copy_capability THEN NULL
      ELSE v_effective_evidence_revision END,p_completed_at
  );
  IF v_copy_capability THEN
    result := app.private_mfa_finish_webauthn_evidence_copy_v1(
      result,p_anchor_id,p_evidence_id,p_completed_at
    );
  END IF;
  RETURN result;
END;
$function$;
--> statement-breakpoint

-- Completed WebAuthn replay is physically read-only.  The cutover above seals
-- every historical registration snapshot, and new registrations project the
-- security revision directly, so a terminal exact replay need not take the
-- legacy FOR UPDATE row lock.
ALTER FUNCTION app.complete_mfa_passkey_registration_v1(jsonb)
  RENAME TO private_v34_complete_mfa_passkey_registration_v1;
CREATE OR REPLACE FUNCTION app.complete_mfa_passkey_registration_v1(p_request jsonb)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_ceremony_id bytea;
  v_request_digest bytea;
  v_private_request jsonb;
  v_private_request_digest bytea;
  v_ceremony public.tenant_webauthn_ceremonies%ROWTYPE;
  v_result jsonb;
BEGIN
  v_ceremony_id := app.private_mfa_decode_base64_v1(
    p_request #>> '{completion,ceremonyId}',32,32
  );
  v_request_digest := app.private_mfa_request_digest_v1(p_request);
  SELECT ceremony.* INTO v_ceremony
  FROM ONLY public.tenant_webauthn_ceremonies AS ceremony
  WHERE ceremony.id = v_ceremony_id
    AND ceremony.purpose = 'registration'
    AND ceremony.state = 'completed';
  IF FOUND THEN
    IF v_ceremony.completion_request_digest IS DISTINCT FROM v_request_digest
       OR jsonb_typeof(v_ceremony.result_snapshot) IS DISTINCT FROM 'object'
       OR jsonb_typeof(
            v_ceremony.result_snapshot #> '{credential}'
          ) IS DISTINCT FROM 'object'
       OR jsonb_typeof(
            v_ceremony.result_snapshot #> '{credential,securityRevision}'
          ) IS DISTINCT FROM 'number' THEN
      RAISE EXCEPTION 'passkey registration replay mismatch'
        USING ERRCODE = '40001';
    END IF;
    RETURN v_ceremony.result_snapshot;
  END IF;

  -- v35 makes the authority epoch explicit on the registration wire, while
  -- the frozen v34 body owns the record insert and rejects that new strict
  -- credential key.  Hash the original request for public replay identity,
  -- validate the new invariant, and strip only that one field for the private
  -- body.  The terminal snapshot is then re-sealed with the original digest.
  IF jsonb_typeof(p_request #> '{completion,credential}') <> 'object'
     OR p_request #> '{completion,credential,securityRevision}'
          IS DISTINCT FROM '1'::jsonb THEN
    RAISE EXCEPTION 'passkey registration security revision is invalid'
      USING ERRCODE = '22023';
  END IF;
  v_private_request := jsonb_set(
    p_request,'{completion,credential}',
    (p_request #> '{completion,credential}') - 'securityRevision',false
  );
  v_private_request_digest :=
    app.private_mfa_request_digest_v1(v_private_request);
  v_result := app.private_v34_complete_mfa_passkey_registration_v1(
    v_private_request
  );
  IF v_result #> '{credential,securityRevision}'
       IS DISTINCT FROM '1'::jsonb THEN
    RAISE EXCEPTION 'passkey registration security revision is unavailable'
      USING ERRCODE = '40001';
  END IF;
  UPDATE ONLY public.tenant_webauthn_ceremonies AS ceremony
  SET completion_request_digest = v_request_digest,
      result_snapshot = v_result
  WHERE ceremony.id = v_ceremony_id
    AND ceremony.purpose = 'registration'
    AND ceremony.state = 'completed'
    AND ceremony.completion_request_digest = v_private_request_digest
    AND ceremony.result_snapshot = v_result;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'passkey registration replay sealing lost CAS'
      USING ERRCODE = '40001';
  END IF;
  RETURN v_result;
END;
$function$;
--> statement-breakpoint

-- The v11 completion hard-coded every WebAuthn evidence row to
-- phishing_resistant.  Derive the assurance from the verified ceremony and
-- assertion instead: a non-UV primary is primary, a non-UV step-up is MFA,
-- and only a server-verified UV assertion is phishing resistant.
ALTER FUNCTION app.complete_mfa_passkey_authentication_v1(jsonb)
  RENAME TO private_v34_complete_mfa_passkey_authentication_v1;
CREATE OR REPLACE FUNCTION app.complete_mfa_passkey_authentication_v1(
  p_request jsonb
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_result jsonb;
  v_ceremony public.tenant_webauthn_ceremonies%ROWTYPE;
  v_ceremony_id bytea;
  v_request_digest bytea;
  v_credential_id uuid;
  v_successor_id uuid;
  v_completed_at timestamptz;
  v_security_revision bigint;
  v_primary_credential_id uuid;
  v_expected_level text;
  v_target_count bigint;
  v_successor_user_id uuid;
  v_policy_action text;
  v_policy_snapshot jsonb;
  v_stored_policy_pins jsonb;
  v_live_policy_pins jsonb;
  v_has_enrollable_factor boolean;
  v_assurance_decision text;
  v_authority_at timestamptz;
BEGIN
  v_ceremony_id := app.private_mfa_decode_base64_v1(
    p_request #>> '{completion,ceremonyId}',32,32
  );
  v_request_digest := app.private_mfa_request_digest_v1(p_request);
  SELECT ceremony.* INTO v_ceremony
  FROM ONLY public.tenant_webauthn_ceremonies AS ceremony
  WHERE ceremony.id = v_ceremony_id
    AND ceremony.purpose IN (
      'primary_authentication','continuation_authentication',
      'step_up_authentication'
    )
    AND ceremony.state = 'completed';
  IF FOUND THEN
    IF v_ceremony.completion_request_digest IS DISTINCT FROM v_request_digest
       OR jsonb_typeof(v_ceremony.result_snapshot) IS DISTINCT FROM 'object'
       OR jsonb_typeof(
            v_ceremony.result_snapshot #> '{credential}'
          ) IS DISTINCT FROM 'object'
       OR jsonb_typeof(
            v_ceremony.result_snapshot #> '{credential,securityRevision}'
          ) IS DISTINCT FROM 'number' THEN
      RAISE EXCEPTION 'passkey completion replay mismatch'
        USING ERRCODE = '40001';
    END IF;
    RETURN v_ceremony.result_snapshot;
  END IF;
  PERFORM app.private_mfa_prepare_webauthn_evidence_copy_v1(
    p_request,v_ceremony_id
  );
  v_result := app.private_v34_complete_mfa_passkey_authentication_v1(
    p_request
  );
  IF v_result #> '{credential,securityRevision}' IS NOT NULL THEN
    RETURN v_result;
  END IF;
  v_completed_at := (p_request #>> '{completion,completedAt}')::timestamptz;
  v_authority_at := greatest(v_completed_at,transaction_timestamp());
  SELECT ceremony.* INTO STRICT v_ceremony
  FROM ONLY public.tenant_webauthn_ceremonies AS ceremony
  WHERE ceremony.id = v_ceremony_id
    AND ceremony.state = 'completed'
    AND ceremony.completed_at = v_completed_at
  FOR SHARE;
  IF v_ceremony.purpose = 'primary_authentication'
     AND p_request #>> '{session,mutation}' = 'revoke' THEN
    IF v_result #>> '{credential,status}' IS DISTINCT FROM 'clone_suspected'
       OR v_result ->> 'mutation' IS DISTINCT FROM 'revoke'
       OR v_result ? 'newSessionId'
       OR v_result ? 'newSessionFamilyId'
       OR v_result ? 'consumedContinuationId'
       OR v_result ? 'revokedAnchorId'
       OR jsonb_typeof(v_result -> 'sessionVersion') IS DISTINCT FROM 'number'
       OR (v_result ->> 'sessionVersion')::bigint <> 1 THEN
      RAISE EXCEPTION 'primary passkey clone result is malformed'
        USING ERRCODE = '40001';
    END IF;
    v_result := jsonb_set(
      v_result,'{sessionVersion}','0'::jsonb,false
    );
  END IF;
  SELECT credential.id,credential.security_revision
    INTO STRICT v_credential_id,v_security_revision
  FROM ONLY public.tenant_webauthn_credentials AS credential
  WHERE credential.tenant_id = v_ceremony.tenant_id
    AND credential.credential_id = app.private_mfa_decode_base64_v1(
      p_request #>> '{completion,credentialId}',1,4096
    );
  v_result := jsonb_set(
    v_result,'{credential,securityRevision}',to_jsonb(v_security_revision),true
  );
  UPDATE ONLY public.tenant_webauthn_ceremonies AS ceremony
  SET result_snapshot = v_result
  WHERE ceremony.id = v_ceremony.id
    AND ceremony.state = 'completed'
    AND ceremony.completion_request_digest = v_request_digest;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'passkey completion result lost CAS'
      USING ERRCODE = '40001';
  END IF;
  IF NOT (v_result ? 'newSessionId') THEN RETURN v_result; END IF;

  v_successor_id := app.private_mfa_require_uuidv7_v1(
    v_result ->> 'newSessionId'
  );
  v_expected_level := CASE
    WHEN (p_request #>> '{completion,userVerified}')::boolean
      THEN 'phishing_resistant'
    WHEN v_ceremony.purpose = 'primary_authentication' THEN 'primary'
    ELSE 'mfa'
  END;

  SELECT count(*) INTO STRICT v_target_count
  FROM (
    SELECT evidence.id
    FROM ONLY public.auth_session_mfa_evidence AS evidence
    WHERE evidence.tenant_id = v_ceremony.tenant_id
      AND evidence.session_id = v_successor_id
      AND evidence.webauthn_credential_id = v_credential_id
      AND evidence.authenticated_at = v_completed_at
    FOR UPDATE
  ) AS target;
  IF v_target_count <> 1 THEN
    RAISE EXCEPTION 'passkey completion evidence is unavailable or ambiguous'
      USING ERRCODE = '40001';
  END IF;
  SELECT provenance.credential_id INTO STRICT v_primary_credential_id
  FROM ONLY public.auth_session_passkey_provenance AS provenance
  WHERE provenance.tenant_id = v_ceremony.tenant_id
    AND provenance.session_id = v_successor_id;
  IF v_primary_credential_id = v_credential_id THEN
    UPDATE ONLY public.auth_session_passkey_provenance AS provenance
    SET credential_revision = v_security_revision
    WHERE provenance.tenant_id = v_ceremony.tenant_id
      AND provenance.session_id = v_successor_id
      AND provenance.credential_id = v_credential_id;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'passkey completion provenance is unavailable'
        USING ERRCODE = '40001';
    END IF;
  END IF;
  UPDATE ONLY public.auth_session_mfa_evidence AS evidence
  SET level = v_expected_level,factor_revision = v_security_revision
  WHERE evidence.tenant_id = v_ceremony.tenant_id
    AND evidence.session_id = v_successor_id
    AND evidence.webauthn_credential_id = v_credential_id
    AND evidence.authenticated_at = v_completed_at;
  SELECT state.user_id,anchor.action
    INTO STRICT v_successor_user_id,v_policy_action
  FROM ONLY public.auth_session_mfa_states AS state
  JOIN ONLY public.tenant_mfa_authority_anchors AS anchor
    ON anchor.id = v_ceremony.authority_anchor_id
   AND anchor.tenant_id = state.tenant_id
  WHERE state.tenant_id = v_ceremony.tenant_id
    AND state.session_id = v_successor_id;
  v_policy_snapshot := app.private_mfa_policy_snapshot_v1(
    v_ceremony.tenant_id,v_successor_user_id,v_policy_action,v_authority_at
  );
  SELECT coalesce(jsonb_agg(jsonb_build_object(
    'policyId',pin.policy_id::text,'revision',pin.policy_revision
  ) ORDER BY pin.policy_id::text,pin.policy_revision),'[]'::jsonb)
    INTO STRICT v_stored_policy_pins
  FROM ONLY public.auth_session_mfa_policy_pins AS pin
  WHERE pin.tenant_id = v_ceremony.tenant_id
    AND pin.session_id = v_successor_id;
  SELECT coalesce(jsonb_agg(jsonb_build_object(
    'policyId',entry.value -> 'policy' ->> 'id',
    'revision',(entry.value -> 'policy' ->> 'revision')::bigint
  ) ORDER BY entry.value -> 'policy' ->> 'id',
    (entry.value -> 'policy' ->> 'revision')::bigint),'[]'::jsonb)
    INTO STRICT v_live_policy_pins
  FROM jsonb_array_elements(v_policy_snapshot -> 'policies') AS entry(value);
  SELECT EXISTS (
    SELECT 1 FROM ONLY public.tenant_totp_factors AS factor
    WHERE factor.tenant_id = v_ceremony.tenant_id
      AND factor.user_id = v_successor_user_id
      AND factor.status = 'active'
    UNION ALL
    SELECT 1 FROM ONLY public.tenant_webauthn_credentials AS credential
    WHERE credential.tenant_id = v_ceremony.tenant_id
      AND credential.user_id = v_successor_user_id
      AND credential.status = 'active'
  ) INTO STRICT v_has_enrollable_factor;
  v_assurance_decision := app.private_federated_assurance_decision_v1(
    v_policy_snapshot -> 'requirement',
    app.private_mfa_evidence_projection_v1(
      v_ceremony.tenant_id,'session',v_successor_id
    ),
    v_has_enrollable_factor,v_authority_at
  );
  IF v_stored_policy_pins IS DISTINCT FROM v_live_policy_pins
     OR v_assurance_decision IS DISTINCT FROM 'satisfied' THEN
    RAISE EXCEPTION 'passkey completion assurance is insufficient'
      USING ERRCODE = '40001';
  END IF;
  RETURN v_result;
EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
  RAISE EXCEPTION 'passkey completion evidence is unavailable or ambiguous'
    USING ERRCODE = '40001';
END;
$function$;
--> statement-breakpoint

ALTER FUNCTION app.private_mfa_apply_tenant_platform_federated_session_v1(
  jsonb,uuid,text,uuid,bigint,timestamptz
) OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION
  app.private_mfa_apply_tenant_platform_federated_session_v1(
    jsonb,uuid,text,uuid,bigint,timestamptz
  ) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
    periapsis_auditor, periapsis_audit_reader_owner,
    periapsis_notification_dispatch_owner, periapsis_sla_api_owner,
    periapsis_sla_worker_owner, periapsis_sla_readiness_owner,
    periapsis_ticket_saved_view_owner, periapsis_ticket_attribution_owner,
    periapsis_ticket_sla_projection_owner;
--> statement-breakpoint

-- Preserve the exact tenant-provider implementation behind private v34 names.
-- The public ABI becomes a family-aware v35 dispatcher. Tenant calls are passed
-- through byte-for-byte; platform calls require the separate admission object.
ALTER FUNCTION app.load_federated_session_revalidation_v1(jsonb)
  RENAME TO private_v34_load_federated_session_revalidation_v1;
--> statement-breakpoint
DROP FUNCTION IF EXISTS app.load_federated_session_revalidation_v1(jsonb);
--> statement-breakpoint
ALTER FUNCTION app.apply_federated_session_revalidation_v1(jsonb)
  RENAME TO private_v34_apply_federated_session_revalidation_v1;
--> statement-breakpoint
DROP FUNCTION IF EXISTS app.apply_federated_session_revalidation_v1(jsonb);
--> statement-breakpoint

CREATE FUNCTION app.private_load_passkey_session_revalidation_v1(
  p_lookup jsonb
)
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
  v_provenance public.auth_session_passkey_provenance%ROWTYPE;
  v_live_identity_epoch bigint;
  v_live_session_epoch bigint;
  v_user_active boolean;
  v_tenant_active boolean;
  v_membership_active boolean;
  v_live_primary_revision bigint;
  v_primary_active boolean;
  v_policy_snapshot jsonb;
  v_evidence jsonb;
  v_policies jsonb;
  v_factors jsonb;
BEGIN
  PERFORM app.private_mfa_assert_json_object_v1(
    p_lookup,ARRAY['sessionId','tenantId','audience'],
    ARRAY['sessionId','tenantId','audience'],16384
  );
  IF jsonb_typeof(p_lookup -> 'sessionId') <> 'string'
     OR jsonb_typeof(p_lookup -> 'tenantId') <> 'string'
     OR jsonb_typeof(p_lookup -> 'audience') <> 'string'
     OR NOT app.private_mfa_safe_text_v1(p_lookup ->> 'audience',256) THEN
    RAISE EXCEPTION 'invalid passkey session lookup' USING ERRCODE = '22023';
  END IF;
  v_session_id := app.private_mfa_require_uuidv7_v1(
    p_lookup ->> 'sessionId'
  );
  v_tenant_id := app.private_mfa_require_uuidv7_v1(
    p_lookup ->> 'tenantId'
  );
  v_audience := p_lookup ->> 'audience';

  SELECT session.* INTO STRICT v_session
  FROM ONLY public.auth_sessions AS session
  WHERE session.id = v_session_id
    AND session.active_tenant_id = v_tenant_id
    AND session.authentication_method = 'passkey';
  SELECT state.* INTO STRICT v_state
  FROM ONLY public.auth_session_mfa_states AS state
  WHERE state.tenant_id = v_tenant_id
    AND state.session_id = v_session_id
    AND state.user_id = v_session.user_id
    AND state.primary_kind = 'passkey'
    AND state.audience = v_audience;
  SELECT provenance.* INTO STRICT v_provenance
  FROM ONLY public.auth_session_passkey_provenance AS provenance
  WHERE provenance.tenant_id = v_tenant_id
    AND provenance.session_id = v_session_id
    AND provenance.user_id = v_state.user_id
    AND provenance.primary_kind = 'passkey';

  SELECT subject.identity_epoch,subject.session_invalidation_epoch,
         local_user.active,tenant.status = 'active',
         membership.status = 'active'
    INTO STRICT v_live_identity_epoch,v_live_session_epoch,v_user_active,
      v_tenant_active,v_membership_active
  FROM ONLY public.tenant_mfa_subjects AS subject
  JOIN ONLY public.users AS local_user ON local_user.id = subject.user_id
  JOIN ONLY public.tenants AS tenant ON tenant.id = subject.tenant_id
  JOIN ONLY public.tenant_memberships AS membership
    ON membership.tenant_id = subject.tenant_id
   AND membership.user_id = subject.user_id
  WHERE subject.tenant_id = v_tenant_id
    AND subject.user_id = v_state.user_id;
  SELECT credential.security_revision,
         credential.status = 'active'
           AND credential.security_revision =
               v_provenance.credential_revision
    INTO STRICT v_live_primary_revision,v_primary_active
  FROM ONLY public.tenant_webauthn_credentials AS credential
  WHERE credential.tenant_id = v_tenant_id
    AND credential.user_id = v_state.user_id
    AND credential.id = v_provenance.credential_id;

  SELECT coalesce(jsonb_agg(jsonb_build_object(
    'reference',jsonb_strip_nulls(jsonb_build_object(
      'localCredentialId',evidence.local_credential_id::text,
      'totpFactorId',evidence.totp_factor_id::text,
      'webAuthnCredentialId',evidence.webauthn_credential_id::text,
      'recoveryCodeSetId',evidence.recovery_code_set_id::text
    )),
    'evidence',jsonb_strip_nulls(jsonb_build_object(
      'level',evidence.level,
      'kind',CASE WHEN evidence.kind = 'recovery'
        THEN 'recovery' ELSE 'factor' END,
      'local',evidence.provider_id IS NULL,
      'providerId',evidence.provider_id::text,
      'bindingId',evidence.binding_id::text,
      'authenticatedAt',to_jsonb(evidence.authenticated_at),
      'expiresAt',CASE WHEN evidence.expires_at IS NULL THEN 'null'::jsonb
        ELSE to_jsonb(evidence.expires_at) END,
      'factorRevision',CASE WHEN evidence.factor_revision IS NULL
        THEN 'null'::jsonb ELSE to_jsonb(evidence.factor_revision) END,
      'trustRuleRevision',CASE WHEN evidence.trust_rule_revision IS NULL
        THEN 'null'::jsonb ELSE to_jsonb(evidence.trust_rule_revision) END
    ))
  ) ORDER BY evidence.authenticated_at,evidence.id),'[]'::jsonb)
    INTO v_evidence
  FROM ONLY public.auth_session_mfa_evidence AS evidence
  WHERE evidence.tenant_id = v_tenant_id
    AND evidence.session_id = v_session_id;
  SELECT coalesce(jsonb_agg(jsonb_build_object(
    'policyId',pin.policy_id::text,'revision',pin.policy_revision
  ) ORDER BY pin.policy_id),'[]'::jsonb) INTO v_policies
  FROM ONLY public.auth_session_mfa_policy_pins AS pin
  WHERE pin.tenant_id = v_tenant_id AND pin.session_id = v_session_id;
  IF jsonb_array_length(v_evidence) NOT BETWEEN 1 AND 1024
     OR jsonb_array_length(v_policies) NOT BETWEEN 1 AND 1024 THEN
    RETURN NULL;
  END IF;

  WITH factor_rows AS (
    SELECT evidence.totp_factor_id AS factor_id,'totp'::text AS kind,
      factor.security_revision AS revision,
      factor.status = 'active' AS active
    FROM ONLY public.auth_session_mfa_evidence AS evidence
    JOIN ONLY public.tenant_totp_factors AS factor
      ON factor.tenant_id = evidence.tenant_id
     AND factor.id = evidence.totp_factor_id
    WHERE evidence.tenant_id = v_tenant_id
      AND evidence.session_id = v_session_id
      AND evidence.totp_factor_id IS NOT NULL
    UNION ALL
    SELECT evidence.webauthn_credential_id,'webauthn',
      credential.security_revision,
      credential.status = 'active'
    FROM ONLY public.auth_session_mfa_evidence AS evidence
    JOIN ONLY public.tenant_webauthn_credentials AS credential
      ON credential.tenant_id = evidence.tenant_id
     AND credential.id = evidence.webauthn_credential_id
    WHERE evidence.tenant_id = v_tenant_id
      AND evidence.session_id = v_session_id
      AND evidence.webauthn_credential_id IS NOT NULL
    UNION ALL
    SELECT evidence.recovery_code_set_id,'recovery',
      code_set.security_revision,code_set.status = 'active'
    FROM ONLY public.auth_session_mfa_evidence AS evidence
    JOIN ONLY public.tenant_recovery_code_sets AS code_set
      ON code_set.tenant_id = evidence.tenant_id
     AND code_set.id = evidence.recovery_code_set_id
    WHERE evidence.tenant_id = v_tenant_id
      AND evidence.session_id = v_session_id
      AND evidence.recovery_code_set_id IS NOT NULL
  )
  SELECT coalesce(jsonb_agg(jsonb_build_object(
    'reference',jsonb_build_object(
      CASE factor.kind WHEN 'totp' THEN 'totpFactorId'
        WHEN 'webauthn' THEN 'webAuthnCredentialId'
        ELSE 'recoveryCodeSetId' END,factor.factor_id::text
    ),'revision',factor.revision,'active',factor.active
  ) ORDER BY factor.kind,factor.factor_id),'[]'::jsonb) INTO v_factors
  FROM factor_rows AS factor;
  v_policy_snapshot := app.private_mfa_policy_snapshot_v1(
    v_tenant_id,v_state.user_id,'tenant.authentication.login',
    transaction_timestamp()
  );

  RETURN jsonb_build_object(
    'lookup',p_lookup,
    'authenticationMethod','passkey',
    'snapshot',jsonb_build_object(
      'sessionId',v_session.id::text,
      'rotationFamilyId',v_session.rotation_family_id::text,
      'version',v_state.session_version,
      'tenantId',v_tenant_id::text,'userId',v_state.user_id::text,
      'identityEpoch',v_state.identity_epoch,
      'recoveryRestricted',v_state.recovery_restricted,
      'primary',jsonb_build_object(
        'kind','passkey','primaryId',v_provenance.credential_id::text,
        'credentialId',v_provenance.credential_id::text,
        'primaryRevision',v_provenance.credential_revision,
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
        SELECT 1 FROM ONLY public.auth_sessions AS family
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
      'factors',v_factors,'trustRules','[]'::jsonb,
      'requirement',v_policy_snapshot -> 'requirement'
    )
  );
EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
  RETURN NULL;
WHEN invalid_text_representation OR data_exception THEN
  RAISE EXCEPTION 'invalid passkey session lookup' USING ERRCODE = '22023';
END;
$function$;
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.load_federated_session_revalidation_v1(
  p_lookup jsonb
)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  lookup_tenant_id uuid;
  lookup_session_id uuid;
  primary_kind text;
BEGIN
  PERFORM app.private_mfa_assert_json_object_v1(
    p_lookup,ARRAY['sessionId','tenantId','audience'],
    ARRAY['sessionId','tenantId','audience'],16384
  );
  lookup_tenant_id := app.private_mfa_require_uuidv7_v1(
    p_lookup ->> 'tenantId'
  );
  lookup_session_id := app.private_mfa_require_uuidv7_v1(
    p_lookup ->> 'sessionId'
  );
  SELECT state.primary_kind INTO primary_kind
  FROM ONLY public.auth_session_mfa_states AS state
  WHERE state.tenant_id = lookup_tenant_id
    AND state.session_id = lookup_session_id
    AND state.audience = p_lookup ->> 'audience';
  IF NOT FOUND THEN RETURN NULL; END IF;
  IF primary_kind = 'tenant_provider' THEN
    RETURN app.private_v34_load_federated_session_revalidation_v1(p_lookup);
  ELSIF primary_kind = 'tenant_platform_provider' THEN
    RETURN app.load_tenant_platform_federated_session_revalidation_v1(p_lookup);
  ELSIF primary_kind = 'passkey' THEN
    RETURN app.private_load_passkey_session_revalidation_v1(p_lookup);
  END IF;
  RETURN NULL;
EXCEPTION WHEN invalid_text_representation OR data_exception THEN
  RAISE EXCEPTION 'invalid federated session lookup' USING ERRCODE = '22023';
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_capture_tenant_federated_revalidation_authority_v1(
  p_mutation jsonb,
  p_result jsonb
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_tenant_id uuid;
  v_session_id uuid;
  v_user_id uuid;
  v_continuation_id uuid;
  v_expected_version bigint;
  v_live record;
BEGIN
  IF p_mutation ->> 'decision' IS DISTINCT FROM 'step_up'
     OR p_result ->> 'decision' IS DISTINCT FROM 'step_up'
     OR coalesce((p_result ->> 'applied')::boolean,false) IS NOT TRUE THEN
    RETURN;
  END IF;
  v_tenant_id := app.private_mfa_require_uuidv7_v1(
    p_mutation ->> 'tenantId'
  );
  v_session_id := app.private_mfa_require_uuidv7_v1(
    p_mutation ->> 'sessionId'
  );
  v_user_id := app.private_mfa_require_uuidv7_v1(p_mutation ->> 'userId');
  v_continuation_id := app.private_mfa_require_uuidv7_v1(
    p_result ->> 'continuationId'
  );
  v_expected_version := (p_mutation ->> 'expectedVersion')::bigint;

  IF EXISTS (
    SELECT 1
    FROM ONLY public.tenant_post_primary_federated_provenance AS provenance
    WHERE provenance.tenant_id = v_tenant_id
      AND provenance.continuation_id = v_continuation_id
      AND provenance.user_id = v_user_id
  ) THEN
    IF NOT EXISTS (
      SELECT 1
      FROM ONLY public.tenant_post_primary_federated_provenance AS provenance
      WHERE provenance.tenant_id = v_tenant_id
        AND provenance.continuation_id = v_continuation_id
        AND provenance.user_id = v_user_id
        AND provenance.origin = 'session_revalidation'
        AND provenance.primary_kind = 'tenant_provider'
        AND provenance.source_session_id = v_session_id
        AND provenance.source_session_version = v_expected_version + 1
    ) THEN
      RAISE EXCEPTION 'tenant-provider revalidation replay drifted'
        USING ERRCODE = '40001';
    END IF;
    RETURN;
  END IF;

  SELECT source_session.rotation_family_id AS source_family_id,
         source_session.absolute_expires_at AS source_absolute_expires_at,
         source_provenance.authentication_method,
         source_provenance.provider_id,source_provenance.binding_id,
         source_provenance.provider_kind,
         source_provenance.external_identity_id,
         source_provenance.external_identity_revision,
         source_provenance.authenticated_at,
         provider.version AS provider_revision,
         binding.version AS binding_revision,
         binding.mapping_revision,binding.auth_revision,
         policy.configuration_revision,policy.security_revision,
         policy.plan_revision,policy.assurance_policy_revision,
         epoch.id AS access_epoch_id,epoch.source_id AS access_source_id,
         access_grant.id AS access_grant_id,
         membership.id AS membership_id
    INTO STRICT v_live
  FROM ONLY public.auth_sessions AS source_session
  JOIN ONLY public.auth_session_mfa_states AS source_state
    ON source_state.tenant_id = v_tenant_id
   AND source_state.session_id = source_session.id
   AND source_state.user_id = v_user_id
   AND source_state.primary_kind = 'tenant_provider'
   AND source_state.session_version = v_expected_version + 1
  JOIN ONLY public.auth_session_federated_provenance AS source_provenance
    ON source_provenance.tenant_id = source_state.tenant_id
   AND source_provenance.session_id = source_state.session_id
   AND source_provenance.user_id = source_state.user_id
   AND source_provenance.primary_kind = 'tenant_provider'
  JOIN ONLY public.tenant_auth_providers AS provider
    ON provider.tenant_id = source_provenance.tenant_id
   AND provider.id = source_provenance.provider_id
   AND provider.kind = source_provenance.provider_kind
   AND provider.enabled AND provider.archived_at IS NULL
  JOIN ONLY public.tenant_auth_provider_bindings AS binding
    ON binding.tenant_id = provider.tenant_id
   AND binding.id = source_provenance.binding_id
   AND binding.provider_id = provider.id
   AND binding.enabled AND binding.archived_at IS NULL
   AND binding.current_access_epoch_id IS NOT NULL
  JOIN ONLY public.tenant_federated_provider_policies AS policy
    ON policy.tenant_id = provider.tenant_id
   AND policy.provider_id = provider.id
   AND policy.binding_id = binding.id
   AND policy.provider_kind = provider.kind
   AND policy.enabled
   AND policy.security_revision = source_provenance.trust_rule_revision
  JOIN ONLY public.tenant_identity_provider_access_epochs AS epoch
    ON epoch.tenant_id = binding.tenant_id
   AND epoch.id = binding.current_access_epoch_id
   AND epoch.binding_id = binding.id
   AND epoch.provider_id = provider.id
   AND epoch.source_id IS NOT NULL
   AND epoch.ended_at IS NULL
  JOIN ONLY public.tenant_authorization_sources AS source
    ON source.tenant_id = epoch.tenant_id
   AND source.id = epoch.source_id
   AND source.kind = 'identity_provider_access'
   AND source.authoritative AND NOT source.protected
   AND source.key = format(
     'identity_provider_access:%s:%s',epoch.binding_id,epoch.sequence
   )
   AND source.retired_at IS NULL
  JOIN ONLY public.tenant_memberships AS membership
    ON membership.tenant_id = v_tenant_id
   AND membership.user_id = v_user_id
   AND membership.status = 'active'
  JOIN ONLY public.tenant_federated_external_identities AS identity
    ON identity.tenant_id = v_tenant_id
   AND identity.provider_id = provider.id
   AND identity.binding_id = binding.id
   AND identity.id = source_provenance.external_identity_id
   AND identity.user_id = v_user_id
   AND identity.version = source_provenance.external_identity_revision
   AND identity.retired_at IS NULL
  JOIN ONLY public.tenant_federated_provider_access_grants AS access_grant
    ON access_grant.tenant_id = v_tenant_id
   AND access_grant.provider_id = provider.id
   AND access_grant.binding_id = binding.id
   AND access_grant.access_epoch_id = epoch.id
   AND access_grant.source_id = source.id
   AND access_grant.external_identity_id = identity.id
   AND access_grant.membership_id = membership.id
   AND access_grant.user_id = v_user_id
   AND access_grant.ended_at IS NULL
  JOIN ONLY public.tenant_post_primary_continuations AS continuation
    ON continuation.tenant_id = v_tenant_id
   AND continuation.id = v_continuation_id
   AND continuation.user_id = v_user_id
   AND continuation.primary_kind = 'tenant_provider'
   AND continuation.provider_id = provider.id
   AND continuation.binding_id = binding.id
   AND continuation.provider_kind = provider.kind
   AND continuation.external_identity_id = identity.id
   AND continuation.primary_revision = identity.version
   AND continuation.state = 'pending'
   AND continuation.version = 1
  WHERE source_session.id = v_session_id
    AND source_session.user_id = v_user_id
    AND source_session.active_tenant_id = v_tenant_id
    AND source_session.authentication_method =
        source_provenance.authentication_method
    AND source_session.revoked_at IS NULL
  FOR SHARE OF source_session,source_state,source_provenance,provider,binding,
    policy,epoch,source,membership,identity,access_grant,continuation;

  INSERT INTO public.tenant_post_primary_federated_provenance (
    tenant_id,continuation_id,user_id,origin,primary_kind,
    authentication_method,provider_id,binding_id,provider_kind,
    access_epoch_id,access_source_id,access_grant_id,membership_id,
    external_identity_id,external_identity_revision,provider_revision,
    binding_revision,configuration_revision,security_revision,plan_revision,
    mapping_revision,authorization_revision,assurance_policy_revision,
    authenticated_at,source_session_id,source_session_family_id,
    source_session_version,source_absolute_expires_at
  ) VALUES (
    v_tenant_id,v_continuation_id,v_user_id,'session_revalidation',
    'tenant_provider',v_live.authentication_method,v_live.provider_id,
    v_live.binding_id,v_live.provider_kind,v_live.access_epoch_id,
    v_live.access_source_id,v_live.access_grant_id,v_live.membership_id,
    v_live.external_identity_id,v_live.external_identity_revision,
    v_live.provider_revision,v_live.binding_revision,
    v_live.configuration_revision,v_live.security_revision,
    v_live.plan_revision,v_live.mapping_revision,v_live.auth_revision,
    v_live.assurance_policy_revision,v_live.authenticated_at,v_session_id,
    v_live.source_family_id,v_expected_version + 1,
    v_live.source_absolute_expires_at
  );
EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
  RAISE EXCEPTION 'tenant-provider revalidation authority is unavailable'
    USING ERRCODE = '40001';
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_apply_passkey_session_revalidation_v1(
  p_mutation jsonb
)
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
  v_expected_version bigint;
  v_observed_at timestamptz;
  v_authority_at timestamptz;
  v_decision text;
  v_reason text;
  v_request_digest bytea;
  v_session public.auth_sessions%ROWTYPE;
  v_state public.auth_session_mfa_states%ROWTYPE;
  v_provenance public.auth_session_passkey_provenance%ROWTYPE;
  v_credential public.tenant_webauthn_credentials%ROWTYPE;
  v_existing public.tenant_federated_session_revalidation_commands%ROWTYPE;
  v_policy_snapshot jsonb;
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
  v_lifecycle_active boolean;
  v_evidence_count bigint;
  v_policy_count bigint;
  v_source_policy_pins jsonb;
  v_live_policy_pins jsonb;
  v_assurance_decision text;
  v_has_enrollable_factor boolean;
BEGIN
  PERFORM app.private_mfa_assert_json_object_v1(
    p_mutation,
    ARRAY['sessionId','tenantId','userId','audience','authenticationMethod',
      'expectedVersion','observedAt','decision','reason','requirement',
      'session','continuation'],
    ARRAY['sessionId','tenantId','userId','audience','authenticationMethod',
      'expectedVersion','observedAt','decision','reason','requirement'],262144
  );
  v_session_id := app.private_mfa_require_uuidv7_v1(
    p_mutation ->> 'sessionId'
  );
  v_tenant_id := app.private_mfa_require_uuidv7_v1(
    p_mutation ->> 'tenantId'
  );
  v_user_id := app.private_mfa_require_uuidv7_v1(
    p_mutation ->> 'userId'
  );
  v_audience := p_mutation ->> 'audience';
  v_expected_version := (p_mutation ->> 'expectedVersion')::bigint;
  v_observed_at := (p_mutation ->> 'observedAt')::timestamptz;
  v_decision := p_mutation ->> 'decision';
  v_reason := p_mutation ->> 'reason';
  IF NOT app.private_mfa_safe_text_v1(v_audience,256)
     OR p_mutation ->> 'authenticationMethod' IS DISTINCT FROM 'passkey'
     OR v_expected_version NOT BETWEEN 1 AND 9007199254740990
     OR (v_decision = 'step_up'
       AND v_expected_version > 9007199254740989)
     OR v_observed_at IS NULL
     OR NOT isfinite(v_observed_at)
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
     )
     OR (v_decision = 'rotate') <> (p_mutation ? 'session')
     OR (v_decision = 'step_up') <> (p_mutation ? 'continuation')
     OR (p_mutation ? 'session' AND p_mutation ? 'continuation') THEN
    RAISE EXCEPTION 'invalid passkey session revalidation mutation'
      USING ERRCODE = '22023';
  END IF;
  v_authority_at := greatest(v_observed_at,transaction_timestamp());

  v_request_digest := sha256(convert_to(p_mutation::text,'UTF8'));
  SELECT command.* INTO v_existing
  FROM ONLY public.tenant_federated_session_revalidation_commands AS command
  WHERE command.tenant_id = v_tenant_id
    AND command.session_id = v_session_id
    AND command.expected_version = v_expected_version;
  IF FOUND THEN
    IF v_existing.request_digest IS DISTINCT FROM v_request_digest
       OR v_existing.decision IS DISTINCT FROM v_decision THEN
      RAISE EXCEPTION 'passkey session command replay mismatch'
        USING ERRCODE = '40001';
    END IF;
    IF v_existing.result_snapshot ->> 'sessionId' IS DISTINCT FROM
         v_session_id::text
       OR v_existing.result_snapshot ->> 'tenantId' IS DISTINCT FROM
            v_tenant_id::text
       OR (v_existing.result_snapshot ->> 'expectedVersion')::bigint
            IS DISTINCT FROM v_expected_version
       OR v_existing.result_snapshot ->> 'decision' IS DISTINCT FROM
            v_decision
       OR coalesce(
            (v_existing.result_snapshot ->> 'applied')::boolean,false
          ) IS NOT TRUE
       OR (v_decision = 'rotate' AND (
         v_existing.result_snapshot ->> 'newSessionId' IS DISTINCT FROM
           p_mutation #>> '{session,sessionId}'
         OR v_existing.result_snapshot ? 'continuationId'
       ))
       OR (v_decision = 'step_up' AND (
         v_existing.result_snapshot ->> 'continuationId' IS DISTINCT FROM
           p_mutation #>> '{continuation,continuationId}'
         OR v_existing.result_snapshot ? 'newSessionId'
       ))
       OR (v_decision NOT IN ('rotate','step_up') AND (
         v_existing.result_snapshot ? 'newSessionId'
         OR v_existing.result_snapshot ? 'continuationId'
       )) THEN
      RAISE EXCEPTION 'passkey session command replay ledger drifted'
        USING ERRCODE = '40001';
    END IF;
    RETURN v_existing.result_snapshot;
  END IF;

  PERFORM app.private_mfa_lock_policy_authority_v1(v_tenant_id);
  SELECT session.* INTO STRICT v_session
  FROM ONLY public.auth_sessions AS session
  WHERE session.id = v_session_id
    AND session.user_id = v_user_id
    AND session.active_tenant_id = v_tenant_id
    AND session.authentication_method = 'passkey'
  FOR UPDATE NOWAIT;
  SELECT state.* INTO STRICT v_state
  FROM ONLY public.auth_session_mfa_states AS state
  WHERE state.tenant_id = v_tenant_id
    AND state.session_id = v_session_id
    AND state.user_id = v_user_id
    AND state.primary_kind = 'passkey'
    AND state.audience = v_audience
  FOR UPDATE NOWAIT;
  SELECT provenance.* INTO STRICT v_provenance
  FROM ONLY public.auth_session_passkey_provenance AS provenance
  WHERE provenance.tenant_id = v_tenant_id
    AND provenance.session_id = v_session_id
    AND provenance.user_id = v_user_id
    AND provenance.primary_kind = 'passkey'
  FOR SHARE NOWAIT;
  SELECT credential.* INTO STRICT v_credential
  FROM ONLY public.tenant_webauthn_credentials AS credential
  WHERE credential.tenant_id = v_tenant_id
    AND credential.user_id = v_user_id
    AND credential.id = v_provenance.credential_id
  FOR SHARE NOWAIT;
  SELECT local_user.active AND tenant.status = 'active'
           AND membership.status = 'active'
           AND subject.identity_epoch = v_state.identity_epoch
           AND subject.session_invalidation_epoch =
               v_state.session_invalidation_epoch
    INTO STRICT v_lifecycle_active
  FROM ONLY public.tenant_mfa_subjects AS subject
  JOIN ONLY public.users AS local_user ON local_user.id = subject.user_id
  JOIN ONLY public.tenants AS tenant ON tenant.id = subject.tenant_id
  JOIN ONLY public.tenant_memberships AS membership
    ON membership.tenant_id = subject.tenant_id
   AND membership.user_id = subject.user_id
  WHERE subject.tenant_id = v_tenant_id AND subject.user_id = v_user_id
  FOR SHARE OF subject,local_user,tenant,membership NOWAIT;
  IF v_state.session_version <> v_expected_version
     OR v_authority_at < v_state.issued_at
     OR abs(extract(epoch FROM
          (transaction_timestamp() - v_observed_at))) > 300 THEN
    RAISE EXCEPTION 'passkey session command lost CAS'
      USING ERRCODE = '40001';
  END IF;
  IF v_decision IN ('usable','rotate','step_up') THEN
    PERFORM app.private_mfa_assert_live_passkey_session_evidence_v1(
      v_tenant_id,v_user_id,v_session_id,v_authority_at
    );
    SELECT count(*) INTO STRICT v_evidence_count
    FROM (
      SELECT evidence.id
      FROM ONLY public.auth_session_mfa_evidence AS evidence
      WHERE evidence.tenant_id = v_tenant_id
        AND evidence.session_id = v_session_id
      FOR SHARE NOWAIT
    ) AS locked_evidence;
    IF NOT v_lifecycle_active
       OR v_session.revoked_at IS NOT NULL
       OR v_session.idle_expires_at <= v_authority_at
       OR v_session.absolute_expires_at <= v_authority_at
       OR v_credential.status <> 'active'
       OR v_credential.security_revision <>
            v_provenance.credential_revision
       OR v_evidence_count NOT BETWEEN 1 AND 1024
       OR (v_decision = 'step_up' AND v_evidence_count > 1023) THEN
      RAISE EXCEPTION 'passkey session live authority drifted'
        USING ERRCODE = '40001';
    END IF;
    v_policy_snapshot := app.private_mfa_policy_snapshot_v1(
      v_tenant_id,v_user_id,'tenant.authentication.login',v_authority_at
    );
    IF jsonb_strip_nulls(p_mutation -> 'requirement') IS DISTINCT FROM
         jsonb_strip_nulls(v_policy_snapshot -> 'requirement') THEN
      RAISE EXCEPTION 'passkey session requirement drifted'
        USING ERRCODE = '40001';
    END IF;
    SELECT count(*) INTO STRICT v_policy_count
    FROM (
      SELECT policy.id
      FROM ONLY public.mfa_policy_revisions AS policy
      JOIN jsonb_array_elements(v_policy_snapshot -> 'policies') AS pin(value)
        ON policy.id = (pin.value -> 'policy' ->> 'id')::uuid
       AND policy.revision =
           (pin.value -> 'policy' ->> 'revision')::bigint
      FOR SHARE OF policy NOWAIT
    ) AS locked_policy;
    IF v_policy_count <> jsonb_array_length(
         v_policy_snapshot -> 'policies'
       ) THEN
      RAISE EXCEPTION 'passkey session policy authority drifted'
        USING ERRCODE = '40001';
    END IF;
    SELECT coalesce(jsonb_agg(jsonb_build_object(
      'policyId',pin.policy_id::text,'revision',pin.policy_revision
    ) ORDER BY pin.policy_id::text,pin.policy_revision),'[]'::jsonb)
      INTO STRICT v_source_policy_pins
    FROM ONLY public.auth_session_mfa_policy_pins AS pin
    WHERE pin.tenant_id = v_tenant_id
      AND pin.session_id = v_session_id;
    SELECT coalesce(jsonb_agg(jsonb_build_object(
      'policyId',entry.value -> 'policy' ->> 'id',
      'revision',(entry.value -> 'policy' ->> 'revision')::bigint
    ) ORDER BY entry.value -> 'policy' ->> 'id',
      (entry.value -> 'policy' ->> 'revision')::bigint),'[]'::jsonb)
      INTO STRICT v_live_policy_pins
    FROM jsonb_array_elements(v_policy_snapshot -> 'policies') AS entry(value);
    SELECT EXISTS (
      SELECT 1
      FROM ONLY public.tenant_totp_factors AS factor
      WHERE factor.tenant_id = v_tenant_id
        AND factor.user_id = v_user_id
        AND factor.status = 'active'
      UNION ALL
      SELECT 1
      FROM ONLY public.tenant_webauthn_credentials AS credential
      WHERE credential.tenant_id = v_tenant_id
        AND credential.user_id = v_user_id
        AND credential.status = 'active'
    ) INTO STRICT v_has_enrollable_factor;
    v_assurance_decision := app.private_federated_assurance_decision_v1(
      v_policy_snapshot -> 'requirement',
      app.private_mfa_evidence_projection_v1(
        v_tenant_id,'session',v_session_id
      ),
      v_has_enrollable_factor,v_authority_at
    );
    IF (v_decision = 'usable' AND (
          v_state.recovery_restricted
          OR v_assurance_decision IS DISTINCT FROM 'satisfied'
          OR v_source_policy_pins IS DISTINCT FROM v_live_policy_pins
        ))
       OR (v_decision = 'rotate' AND (
          v_state.recovery_restricted
          OR v_assurance_decision IS DISTINCT FROM 'satisfied'
          OR v_source_policy_pins IS NOT DISTINCT FROM v_live_policy_pins
        ))
       OR (v_decision = 'step_up'
         AND v_reason = 'recovery_restricted'
         AND NOT v_state.recovery_restricted)
       OR (v_decision = 'step_up'
         AND v_reason = 'assurance_insufficient'
         AND (v_state.recovery_restricted
           OR v_assurance_decision IS NOT DISTINCT FROM 'satisfied')) THEN
      RAISE EXCEPTION 'passkey session decision drifted'
        USING ERRCODE = '40001';
    END IF;
  END IF;

  IF v_decision = 'rotate' THEN
    v_reservation := p_mutation -> 'session';
    PERFORM app.private_mfa_assert_json_object_v1(
      v_reservation,
      ARRAY['sessionId','familyId','tokenDigest','csrfDigest',
        'authenticationMethod','idleExpiresAt','absoluteExpiresAt'],
      ARRAY['sessionId','familyId','tokenDigest','csrfDigest',
        'authenticationMethod','idleExpiresAt','absoluteExpiresAt'],16384
    );
    v_new_session_id := app.private_mfa_require_uuidv7_v1(
      v_reservation ->> 'sessionId'
    );
    v_new_family_id := app.private_mfa_require_uuidv7_v1(
      v_reservation ->> 'familyId'
    );
    v_token_digest := app.private_mfa_decode_base64_v1(
      v_reservation ->> 'tokenDigest',32,32
    );
    v_csrf_digest := app.private_mfa_decode_base64_v1(
      v_reservation ->> 'csrfDigest',32,32
    );
    v_idle_expires_at := (v_reservation ->> 'idleExpiresAt')::timestamptz;
    v_absolute_expires_at :=
      (v_reservation ->> 'absoluteExpiresAt')::timestamptz;
    IF v_new_session_id IN (v_new_family_id,v_session_id)
       OR v_new_family_id IS DISTINCT FROM v_session.rotation_family_id
       OR v_reservation ->> 'authenticationMethod' IS DISTINCT FROM 'passkey'
       OR encode(v_token_digest,'hex') = repeat('00',32)
       OR encode(v_csrf_digest,'hex') = repeat('00',32)
       OR v_token_digest = v_csrf_digest
       OR v_idle_expires_at <= v_authority_at
       OR v_absolute_expires_at IS DISTINCT FROM v_session.absolute_expires_at
       OR v_absolute_expires_at < v_idle_expires_at
       OR v_idle_expires_at > v_authority_at + interval '24 hours'
       OR date_trunc('milliseconds',v_idle_expires_at) <> v_idle_expires_at
       OR date_trunc('milliseconds',v_absolute_expires_at) <>
            v_absolute_expires_at THEN
      RAISE EXCEPTION 'invalid passkey session rotation reservation'
        USING ERRCODE = '22023';
    END IF;
    v_token_lock := hashtextextended(encode(v_token_digest,'hex'),73124201);
    v_csrf_lock := hashtextextended(encode(v_csrf_digest,'hex'),73124201);
    PERFORM pg_advisory_xact_lock(least(v_token_lock,v_csrf_lock));
    IF v_token_lock <> v_csrf_lock THEN
      PERFORM pg_advisory_xact_lock(greatest(v_token_lock,v_csrf_lock));
    END IF;
    IF EXISTS (
      SELECT 1 FROM ONLY public.auth_sessions AS collision
      WHERE collision.token_digest IN (v_token_digest,v_csrf_digest)
         OR collision.csrf_secret_digest IN (v_token_digest,v_csrf_digest)
    ) THEN
      RAISE EXCEPTION 'passkey session rotation digest collision'
        USING ERRCODE = '40001';
    END IF;
    UPDATE ONLY public.auth_sessions AS source_session
    SET revoked_at = v_authority_at,
        revoke_reason = 'passkey_session_rotated'
    WHERE source_session.id = v_session_id
      AND source_session.revoked_at IS NULL;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'passkey session rotation lost CAS'
        USING ERRCODE = '40001';
    END IF;
    INSERT INTO public.auth_sessions (
      id,user_id,rotation_family_id,active_tenant_id,token_digest,
      csrf_secret_digest,authentication_method,mfa_satisfied_at,last_seen_at,
      idle_expires_at,absolute_expires_at,rotated_from_session_id,created_at
    ) VALUES (
      v_new_session_id,v_user_id,v_new_family_id,v_tenant_id,v_token_digest,
      v_csrf_digest,'passkey',v_session.mfa_satisfied_at,v_authority_at,
      v_idle_expires_at,v_absolute_expires_at,v_session_id,v_authority_at
    );
    INSERT INTO public.auth_session_mfa_states (
      session_id,tenant_id,user_id,session_version,identity_epoch,
      recovery_restricted,audience,primary_kind,session_invalidation_epoch,
      issued_at
    ) VALUES (
      v_new_session_id,v_tenant_id,v_user_id,v_expected_version + 1,
      v_state.identity_epoch,v_state.recovery_restricted,v_audience,'passkey',
      v_state.session_invalidation_epoch,v_authority_at
    );
    INSERT INTO public.auth_session_passkey_provenance
    SELECT provenance.tenant_id,v_new_session_id,provenance.user_id,
      provenance.primary_kind,provenance.credential_id,
      provenance.credential_revision,provenance.authenticated_at
    FROM ONLY public.auth_session_passkey_provenance AS provenance
    WHERE provenance.tenant_id = v_tenant_id
      AND provenance.session_id = v_session_id;
    INSERT INTO public.auth_session_mfa_policy_pins (
      tenant_id,session_id,policy_id,policy_revision
    ) SELECT v_tenant_id,v_new_session_id,
      (policy.value -> 'policy' ->> 'id')::uuid,
      (policy.value -> 'policy' ->> 'revision')::bigint
    FROM jsonb_array_elements(v_policy_snapshot -> 'policies') AS policy(value);
    INSERT INTO public.auth_session_mfa_evidence
    SELECT uuidv7(),evidence.tenant_id,v_new_session_id,
      evidence.local_credential_id,evidence.totp_factor_id,
      evidence.webauthn_credential_id,evidence.recovery_code_set_id,
      evidence.level,evidence.kind,evidence.provider_id,evidence.binding_id,
      evidence.authenticated_at,evidence.expires_at,
      evidence.factor_revision,evidence.trust_rule_revision
    FROM ONLY public.auth_session_mfa_evidence AS evidence
    WHERE evidence.tenant_id = v_tenant_id
      AND evidence.session_id = v_session_id;
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
    v_continuation_expires_at :=
      (v_reservation ->> 'expiresAt')::timestamptz;
    IF encode(v_receipt_digest,'hex') = repeat('00',32)
       OR v_continuation_expires_at <= v_authority_at
       OR v_continuation_expires_at > v_authority_at + interval '15 minutes'
       OR date_trunc('milliseconds',v_continuation_expires_at) <>
            v_continuation_expires_at THEN
      RAISE EXCEPTION 'invalid passkey step-up continuation reservation'
        USING ERRCODE = '22023';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended(
      encode(v_receipt_digest,'hex'),77191203
    ));
    INSERT INTO public.tenant_post_primary_continuations (
      id,tenant_id,user_id,receipt_digest,identity_epoch,action,audience,
      primary_kind,passkey_credential_id,primary_revision,
      session_invalidation_epoch,state,version,created_at,expires_at
    ) VALUES (
      v_continuation_id,v_tenant_id,v_user_id,v_receipt_digest,
      v_state.identity_epoch,'session.create',v_audience,'passkey',
      v_provenance.credential_id,v_provenance.credential_revision,
      v_state.session_invalidation_epoch,'pending',1,v_authority_at,
      v_continuation_expires_at
    );
    INSERT INTO public.tenant_post_primary_continuation_policy_pins (
      tenant_id,continuation_id,policy_id,policy_revision
    ) SELECT v_tenant_id,v_continuation_id,
      (policy.value -> 'policy' ->> 'id')::uuid,
      (policy.value -> 'policy' ->> 'revision')::bigint
    FROM jsonb_array_elements(v_policy_snapshot -> 'policies') AS policy(value);
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
    FROM ONLY public.auth_session_mfa_evidence AS evidence
    WHERE evidence.tenant_id = v_tenant_id
      AND evidence.session_id = v_session_id;
    UPDATE ONLY public.auth_session_mfa_states AS state
    SET session_version = state.session_version + 1
    WHERE state.tenant_id = v_tenant_id AND state.session_id = v_session_id
      AND state.session_version = v_expected_version;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'passkey session command lost CAS'
        USING ERRCODE = '40001';
    END IF;
    INSERT INTO public.tenant_post_primary_passkey_provenance (
      tenant_id,continuation_id,user_id,origin,primary_kind,
      authentication_method,credential_id,credential_revision,
      authenticated_at,source_session_id,source_session_family_id,
      source_session_version,source_absolute_expires_at
    ) VALUES (
      v_tenant_id,v_continuation_id,v_user_id,'session_revalidation',
      'passkey','passkey',v_provenance.credential_id,
      v_provenance.credential_revision,v_provenance.authenticated_at,
      v_session_id,v_session.rotation_family_id,v_expected_version + 1,
      v_session.absolute_expires_at
    );
  ELSIF v_decision IN ('revoke','deny') THEN
    UPDATE ONLY public.auth_sessions AS family
    SET revoked_at = v_authority_at,
        revoke_reason = left('passkey_revalidation_' || v_reason,500)
    WHERE family.user_id = v_user_id
      AND family.rotation_family_id = v_session.rotation_family_id
      AND family.revoked_at IS NULL;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'passkey session family is already revoked'
        USING ERRCODE = '40001';
    END IF;
  ELSE
    UPDATE ONLY public.auth_session_mfa_states AS state
    SET session_version = state.session_version + 1
    WHERE state.tenant_id = v_tenant_id AND state.session_id = v_session_id
      AND state.session_version = v_expected_version;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'passkey session command lost CAS'
        USING ERRCODE = '40001';
    END IF;
  END IF;

  v_result := jsonb_strip_nulls(jsonb_build_object(
    'sessionId',v_session_id::text,'tenantId',v_tenant_id::text,
    'expectedVersion',v_expected_version,'decision',v_decision,
    'applied',true,'newSessionId',v_new_session_id::text,
    'continuationId',v_continuation_id::text
  ));
  IF pg_column_size(v_result) NOT BETWEEN 2 AND 65536 THEN
    RAISE EXCEPTION 'passkey session result exceeds bound'
      USING ERRCODE = '54000';
  END IF;
  INSERT INTO public.tenant_federated_session_revalidation_commands (
    tenant_id,session_id,expected_version,request_digest,decision,
    result_snapshot,applied_at
  ) VALUES (
    v_tenant_id,v_session_id,v_expected_version,v_request_digest,v_decision,
    v_result,v_authority_at
  );
  RETURN v_result;
EXCEPTION WHEN lock_not_available THEN
  RAISE EXCEPTION 'passkey session authority is busy'
    USING ERRCODE = '40001';
WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
  RAISE EXCEPTION 'passkey session authority unavailable'
    USING ERRCODE = '40001';
WHEN invalid_text_representation OR numeric_value_out_of_range
  OR data_exception THEN
  RAISE EXCEPTION 'invalid passkey session revalidation mutation'
    USING ERRCODE = '22023';
END;
$function$;
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.apply_federated_session_revalidation_v1(
  p_mutation jsonb
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  mutation_tenant_id uuid;
  mutation_session_id uuid;
  mutation_user_id uuid;
  primary_kind text;
  result jsonb;
  baseline_count bigint;
  source_session_record public.auth_sessions%ROWTYPE;
  mutation_expected_version bigint;
  request_digest bytea;
  existing_command
    public.tenant_federated_session_revalidation_commands%ROWTYPE;
BEGIN
  mutation_tenant_id := app.private_mfa_require_uuidv7_v1(
    p_mutation ->> 'tenantId'
  );
  mutation_session_id := app.private_mfa_require_uuidv7_v1(
    p_mutation ->> 'sessionId'
  );
  mutation_user_id := app.private_mfa_require_uuidv7_v1(
    p_mutation ->> 'userId'
  );
  SELECT state.primary_kind INTO primary_kind
  FROM ONLY public.auth_session_mfa_states AS state
  WHERE state.tenant_id = mutation_tenant_id
    AND state.session_id = mutation_session_id
    AND state.user_id = mutation_user_id
    AND state.audience = p_mutation ->> 'audience';
  IF NOT FOUND THEN
    RAISE EXCEPTION 'federated session authority unavailable'
      USING ERRCODE = '40001';
  END IF;
  mutation_expected_version := (p_mutation ->> 'expectedVersion')::bigint;
  IF primary_kind = 'passkey' THEN
    RETURN app.private_apply_passkey_session_revalidation_v1(p_mutation);
  END IF;
  IF primary_kind = 'tenant_provider' THEN
    -- A command receipt is terminal and immutable.  Resolve it before any
    -- mutable live-authority check so an exact retry is a zero-write read of
    -- the original outcome; a different payload at the same CAS never reaches
    -- the legacy implementation.
    request_digest := sha256(convert_to(p_mutation::text,'UTF8'));
    SELECT command.* INTO existing_command
    FROM ONLY public.tenant_federated_session_revalidation_commands AS command
    WHERE command.tenant_id = mutation_tenant_id
      AND command.session_id = mutation_session_id
      AND command.expected_version = mutation_expected_version;
    IF FOUND THEN
      IF existing_command.request_digest IS DISTINCT FROM request_digest
         OR existing_command.decision IS DISTINCT FROM
              p_mutation ->> 'decision' THEN
        RAISE EXCEPTION 'federated session command replay mismatch'
          USING ERRCODE = '40001';
      END IF;
      IF existing_command.decision = 'step_up' AND NOT EXISTS (
        SELECT 1
        FROM ONLY public.tenant_post_primary_federated_provenance AS provenance
        WHERE provenance.tenant_id = mutation_tenant_id
          AND provenance.continuation_id =
              (existing_command.result_snapshot ->> 'continuationId')::uuid
          AND provenance.user_id = mutation_user_id
          AND provenance.origin = 'session_revalidation'
          AND provenance.primary_kind = 'tenant_provider'
          AND provenance.source_session_id = mutation_session_id
          AND provenance.source_session_version = mutation_expected_version + 1
      ) THEN
        RAISE EXCEPTION 'tenant-provider revalidation replay drifted'
          USING ERRCODE = '40001';
      END IF;
      RETURN existing_command.result_snapshot;
    END IF;
  END IF;
  -- A terminal command replay is authorized by its immutable ledger row even
  -- after the first execution revoked the source session.  Only a new command
  -- may rely on the live source-session check below; the typed implementation
  -- still validates the exact request digest before returning a stored result.
  IF primary_kind <> 'tenant_provider'
     AND p_mutation ->> 'decision' NOT IN ('revoke','deny')
     AND NOT (
       (primary_kind = 'tenant_platform_provider' AND EXISTS (
         SELECT 1
         FROM ONLY public.tenant_platform_federated_session_revalidation_commands
           AS command
         WHERE command.tenant_id = mutation_tenant_id
           AND command.session_id = mutation_session_id
           AND command.expected_version =
               (p_mutation ->> 'expectedVersion')::bigint
       ))
       OR (primary_kind = 'tenant_provider' AND EXISTS (
         SELECT 1
         FROM ONLY public.tenant_federated_session_revalidation_commands
           AS command
         WHERE command.tenant_id = mutation_tenant_id
           AND command.session_id = mutation_session_id
           AND command.expected_version =
               (p_mutation ->> 'expectedVersion')::bigint
       ))
     ) THEN
    SELECT session.* INTO STRICT source_session_record
    FROM ONLY public.auth_sessions AS session
    WHERE session.id = mutation_session_id
      AND session.user_id = mutation_user_id
      AND session.active_tenant_id = mutation_tenant_id
      AND session.revoked_at IS NULL
      AND session.idle_expires_at > transaction_timestamp()
      AND session.absolute_expires_at > transaction_timestamp()
    FOR SHARE;
    IF p_mutation ->> 'decision' = 'rotate'
       AND ((p_mutation #>> '{session,idleExpiresAt}')::timestamptz
              <= transaction_timestamp()
         OR (p_mutation #>> '{session,absoluteExpiresAt}')::timestamptz
              IS DISTINCT FROM source_session_record.absolute_expires_at) THEN
      RAISE EXCEPTION
        'tenant-provider rotation changed deadline or is already expired'
        USING ERRCODE = '22023';
    END IF;
  END IF;
  IF primary_kind = 'tenant_provider' THEN
    -- Lock the exact source session and state before counting/copying evidence
    -- or entering v34.  NOWAIT makes concurrent lifecycle/device operations a
    -- retry instead of creating a source/state lock-upgrade cycle.
    SELECT source_session.* INTO STRICT source_session_record
    FROM ONLY public.auth_sessions AS source_session
    JOIN ONLY public.auth_session_mfa_states AS source_state
      ON source_state.tenant_id = mutation_tenant_id
     AND source_state.session_id = source_session.id
     AND source_state.user_id = mutation_user_id
     AND source_state.primary_kind = 'tenant_provider'
     AND source_state.audience = p_mutation ->> 'audience'
     AND source_state.session_version = mutation_expected_version
    WHERE source_session.id = mutation_session_id
      AND source_session.user_id = mutation_user_id
      AND source_session.active_tenant_id = mutation_tenant_id
      AND (
        p_mutation ->> 'decision' IN ('revoke','deny')
        OR (
          source_session.revoked_at IS NULL
          AND source_session.idle_expires_at > transaction_timestamp()
          AND source_session.absolute_expires_at > transaction_timestamp()
        )
      )
    FOR UPDATE OF source_session,source_state NOWAIT;
    IF p_mutation ->> 'decision' = 'rotate'
       AND ((p_mutation #>> '{session,idleExpiresAt}')::timestamptz
              <= transaction_timestamp()
         OR (p_mutation #>> '{session,absoluteExpiresAt}')::timestamptz
              IS DISTINCT FROM source_session_record.absolute_expires_at) THEN
      RAISE EXCEPTION
        'tenant-provider rotation changed deadline or is already expired'
        USING ERRCODE = '22023';
    ELSIF p_mutation ->> 'decision' = 'step_up'
       AND (p_mutation #>> '{continuation,expiresAt}')::timestamptz
              <= transaction_timestamp() THEN
      RAISE EXCEPTION 'tenant-provider continuation is already expired'
        USING ERRCODE = '22023';
    END IF;
    IF p_mutation ->> 'decision' = 'step_up'
       THEN
      PERFORM 1
      FROM ONLY public.auth_sessions AS source_session
      JOIN ONLY public.auth_session_mfa_states AS source_state
        ON source_state.tenant_id = mutation_tenant_id
       AND source_state.session_id = source_session.id
       AND source_state.user_id = mutation_user_id
       AND source_state.primary_kind = 'tenant_provider'
       AND source_state.session_version =
           (p_mutation ->> 'expectedVersion')::bigint
      JOIN ONLY public.auth_session_federated_provenance AS source_provenance
        ON source_provenance.tenant_id = source_state.tenant_id
       AND source_provenance.session_id = source_state.session_id
       AND source_provenance.user_id = source_state.user_id
       AND source_provenance.primary_kind = 'tenant_provider'
      JOIN ONLY public.tenant_auth_providers AS provider
        ON provider.tenant_id = mutation_tenant_id
       AND provider.id = source_provenance.provider_id
       AND provider.kind = source_provenance.provider_kind
       AND provider.enabled AND provider.archived_at IS NULL
      JOIN ONLY public.tenant_auth_provider_bindings AS binding
        ON binding.tenant_id = provider.tenant_id
       AND binding.id = source_provenance.binding_id
       AND binding.provider_id = provider.id
       AND binding.enabled AND binding.archived_at IS NULL
       AND binding.current_access_epoch_id IS NOT NULL
      JOIN ONLY public.tenant_federated_provider_policies AS policy
        ON policy.tenant_id = provider.tenant_id
       AND policy.provider_id = provider.id
       AND policy.binding_id = binding.id
       AND policy.provider_kind = provider.kind
       AND policy.enabled
       AND policy.security_revision = source_provenance.trust_rule_revision
      JOIN ONLY public.tenant_identity_provider_access_epochs AS epoch
        ON epoch.tenant_id = binding.tenant_id
       AND epoch.id = binding.current_access_epoch_id
       AND epoch.binding_id = binding.id
       AND epoch.provider_id = provider.id
       AND epoch.ended_at IS NULL
      JOIN ONLY public.tenant_authorization_sources AS source
        ON source.tenant_id = epoch.tenant_id
       AND source.id = epoch.source_id
       AND source.kind = 'identity_provider_access'
       AND source.authoritative AND NOT source.protected
       AND source.key = format(
         'identity_provider_access:%s:%s',epoch.binding_id,epoch.sequence
       )
       AND source.retired_at IS NULL
      JOIN ONLY public.tenant_memberships AS membership
        ON membership.tenant_id = mutation_tenant_id
       AND membership.user_id = mutation_user_id
       AND membership.status = 'active'
      JOIN ONLY public.tenant_federated_external_identities AS identity
        ON identity.tenant_id = mutation_tenant_id
       AND identity.provider_id = provider.id
       AND identity.binding_id = binding.id
       AND identity.id = source_provenance.external_identity_id
       AND identity.user_id = mutation_user_id
       AND identity.version = source_provenance.external_identity_revision
       AND identity.retired_at IS NULL
      JOIN ONLY public.tenant_federated_provider_access_grants AS access_grant
        ON access_grant.tenant_id = mutation_tenant_id
       AND access_grant.provider_id = provider.id
       AND access_grant.binding_id = binding.id
       AND access_grant.access_epoch_id = epoch.id
       AND access_grant.source_id = source.id
       AND access_grant.external_identity_id = identity.id
       AND access_grant.membership_id = membership.id
       AND access_grant.user_id = mutation_user_id
       AND access_grant.ended_at IS NULL
      WHERE source_session.id = mutation_session_id
        AND source_session.user_id = mutation_user_id
        AND source_session.active_tenant_id = mutation_tenant_id
        AND source_session.authentication_method =
            source_provenance.authentication_method
        AND source_session.revoked_at IS NULL
        AND source_session.idle_expires_at > transaction_timestamp()
        AND source_session.absolute_expires_at > transaction_timestamp()
      FOR SHARE OF provider,binding,policy,epoch,source,membership,identity,
        access_grant;
      IF NOT FOUND THEN
        RAISE EXCEPTION 'tenant-provider revalidation authority is stale'
          USING ERRCODE = '40001';
      END IF;
      SELECT count(*) INTO baseline_count
      FROM ONLY public.auth_session_mfa_evidence AS evidence
      WHERE evidence.tenant_id = mutation_tenant_id
        AND evidence.session_id = mutation_session_id;
      IF baseline_count > 1023 THEN
        RAISE EXCEPTION 'tenant-provider MFA evidence snapshot limit reached'
          USING ERRCODE = '22023';
      END IF;
    END IF;
    result := app.private_v34_apply_federated_session_revalidation_v1(
      p_mutation
    );
    PERFORM app.private_capture_tenant_federated_revalidation_authority_v1(
      p_mutation,result
    );
    RETURN result;
  ELSIF primary_kind = 'tenant_platform_provider' THEN
    RETURN app.apply_tenant_platform_federated_session_revalidation_v1(
      p_mutation
    );
  END IF;
  RAISE EXCEPTION 'federated session authority unavailable'
    USING ERRCODE = '40001';
EXCEPTION WHEN lock_not_available THEN
  RAISE EXCEPTION 'tenant-provider revalidation authority is busy'
    USING ERRCODE = '40001';
WHEN invalid_text_representation OR data_exception THEN
  RAISE EXCEPTION 'invalid federated session revalidation mutation'
    USING ERRCODE = '22023';
END;
$function$;
--> statement-breakpoint

ALTER FUNCTION app.begin_tenant_oidc_authentication_v1(jsonb)
  RENAME TO private_v34_begin_tenant_oidc_authentication_v1;
--> statement-breakpoint
DROP FUNCTION IF EXISTS app.begin_tenant_oidc_authentication_v1(jsonb);
--> statement-breakpoint
ALTER FUNCTION app.resolve_tenant_oidc_authentication_v1(jsonb)
  RENAME TO private_v34_resolve_tenant_oidc_authentication_v1;
--> statement-breakpoint
DROP FUNCTION IF EXISTS app.resolve_tenant_oidc_authentication_v1(jsonb);
--> statement-breakpoint
ALTER FUNCTION app.create_oidc_authentication_transaction_v1(jsonb)
  RENAME TO private_v34_create_oidc_authentication_transaction_v1;
--> statement-breakpoint
DROP FUNCTION IF EXISTS app.create_oidc_authentication_transaction_v1(jsonb);
--> statement-breakpoint
ALTER FUNCTION app.claim_oidc_authentication_transaction_v1(jsonb)
  RENAME TO private_v34_claim_oidc_authentication_transaction_v1;
--> statement-breakpoint
DROP FUNCTION IF EXISTS app.claim_oidc_authentication_transaction_v1(jsonb);
--> statement-breakpoint
ALTER FUNCTION app.fail_oidc_authentication_transaction_v1(jsonb)
  RENAME TO private_v34_fail_oidc_authentication_transaction_v1;
--> statement-breakpoint
DROP FUNCTION IF EXISTS app.fail_oidc_authentication_transaction_v1(jsonb);
--> statement-breakpoint
ALTER FUNCTION app.apply_federated_authentication_v1(jsonb)
  RENAME TO private_v34_apply_federated_authentication_v1;
--> statement-breakpoint
DROP FUNCTION IF EXISTS app.apply_federated_authentication_v1(jsonb);
--> statement-breakpoint
ALTER FUNCTION app.load_federated_authentication_planning_state_v1(jsonb)
  RENAME TO private_v34_load_federated_authentication_planning_state_v1;
--> statement-breakpoint
DROP FUNCTION IF EXISTS app.load_federated_authentication_planning_state_v1(jsonb);
--> statement-breakpoint
ALTER FUNCTION app.load_oidc_trust_snapshot_v1(jsonb)
  RENAME TO private_v34_load_oidc_trust_snapshot_v1;
--> statement-breakpoint
DROP FUNCTION IF EXISTS app.load_oidc_trust_snapshot_v1(jsonb);
--> statement-breakpoint
ALTER FUNCTION app.load_oidc_client_secret_envelope_v1(jsonb)
  RENAME TO private_v34_load_oidc_client_secret_envelope_v1;
--> statement-breakpoint
DROP FUNCTION IF EXISTS app.load_oidc_client_secret_envelope_v1(jsonb);
--> statement-breakpoint

-- The v34 generic planning/apply helpers joined the platform-global
-- operator_teams relation through a nonexistent tenant_id column. Repair the
-- two historical bodies after their public dispatcher has been retired. The
-- exact match counts make upstream body drift fail the migration closed.
DO $repair_tenant_federated_operator_team_joins$
DECLARE
  helper regprocedure;
  definition text;
  expected_matches integer;
  pattern constant text :=
    'ON team\.tenant_id = assignment\.tenant_id[[:space:]]+AND team\.id = assignment\.operator_team_id';
BEGIN
  FOR helper,expected_matches IN
    SELECT * FROM (VALUES
      ('app.private_v34_load_federated_authentication_planning_state_v1(jsonb)'::regprocedure,1),
      ('app.private_federated_apply_identity_v1(jsonb,uuid,uuid,uuid,public.auth_provider_kind,bigint,bigint,timestamp with time zone)'::regprocedure,3)
    ) AS expected(helper,expected_matches)
  LOOP
    definition := pg_get_functiondef(helper);
    IF regexp_count(definition,pattern) <> expected_matches THEN
      RAISE EXCEPTION 'tenant-provider operator-team helper shape drifted'
        USING ERRCODE = '55000';
    END IF;
    EXECUTE regexp_replace(
      definition,pattern,'ON team.id = assignment.operator_team_id','g'
    );
  END LOOP;
END;
$repair_tenant_federated_operator_team_joins$;
--> statement-breakpoint

-- A routine observation of an already-linked subject must not advance the
-- administrative identity revision or rewrite its protected immutable
-- material. Session provenance pins that revision, so the predecessor update
-- otherwise revoked every earlier session on the next login.
DO $repair_tenant_federated_identity_observation$
DECLARE
  definition text;
  old_fragment constant text := $old$
    UPDATE public.tenant_federated_external_identities AS identity
    SET subject_ciphertext = v_ciphertext,
        subject_nonce = v_nonce,
        key_version = v_subject_key_version,
        last_observed_at = greatest(identity.last_observed_at, p_applied_at),
        version = identity.version + 1,
        updated_at = transaction_timestamp()
    WHERE identity.tenant_id = p_tenant_id
      AND identity.id = out_external_identity_id
    RETURNING identity.version INTO out_external_identity_revision;$old$;
  new_fragment constant text := $new$
    UPDATE public.tenant_federated_external_identities AS identity
    SET last_observed_at = greatest(identity.last_observed_at, p_applied_at),
        updated_at = greatest(identity.updated_at, transaction_timestamp())
    WHERE identity.tenant_id = p_tenant_id
      AND identity.id = out_external_identity_id
    RETURNING identity.version INTO out_external_identity_revision;$new$;
BEGIN
  definition := pg_get_functiondef(
    'app.private_federated_apply_identity_v1(jsonb,uuid,uuid,uuid,public.auth_provider_kind,bigint,bigint,timestamp with time zone)'::regprocedure
  );
  IF strpos(definition,old_fragment) = 0
     OR strpos(
       substr(definition,strpos(definition,old_fragment) + length(old_fragment)),
       old_fragment
     ) > 0 THEN
    RAISE EXCEPTION 'tenant-provider identity observation helper shape drifted'
      USING ERRCODE = '55000';
  END IF;
  EXECUTE replace(definition,old_fragment,new_fragment);
END;
$repair_tenant_federated_identity_observation$;
--> statement-breakpoint

-- Both predecessor apply layers passed a maximum larger than the shared
-- JSON-envelope helper's own hard ceiling, so every generic OIDC/SAML apply
-- failed before parsing. Preserve the established 2 MiB ceiling exactly.
DO $repair_tenant_federated_apply_envelope_limit$
DECLARE
  helper regprocedure;
  definition text;
  oversized_limit constant text := '216' || '2688';
BEGIN
  FOREACH helper IN ARRAY ARRAY[
    'app.private_apply_federated_authentication_v30(jsonb)'::regprocedure,
    'app.private_v34_apply_federated_authentication_v1(jsonb)'::regprocedure
  ]
  LOOP
    definition := pg_get_functiondef(helper);
    IF regexp_count(definition,oversized_limit) <> 1 THEN
      RAISE EXCEPTION 'tenant-provider apply envelope helper shape drifted'
        USING ERRCODE = '55000';
    END IF;
    EXECUTE replace(definition,oversized_limit,'2097152');
  END LOOP;
END;
$repair_tenant_federated_apply_envelope_limit$;
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.begin_tenant_oidc_authentication_v1(p_lookup jsonb)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  binding_family text;
BEGIN
  PERFORM app.private_federated_assert_begin_lookup_v1(p_lookup);
  SELECT login_key.binding_family INTO binding_family
  FROM ONLY public.tenants AS tenant
  JOIN ONLY public.tenant_auth_provider_login_keys AS login_key
    ON login_key.tenant_id = tenant.id
   AND login_key.key = p_lookup ->> 'loginKey'
  WHERE tenant.slug = p_lookup ->> 'tenantSlug'
    AND tenant.status = 'active';
  IF NOT FOUND THEN RETURN NULL; END IF;
  IF binding_family = 'tenant_provider' THEN
    RETURN app.private_v34_begin_tenant_oidc_authentication_v1(p_lookup);
  ELSIF binding_family = 'platform_provider' THEN
    RETURN app.begin_tenant_platform_oidc_authentication_v1(p_lookup);
  END IF;
  RETURN NULL;
EXCEPTION WHEN invalid_text_representation OR data_exception THEN
  RAISE EXCEPTION 'invalid tenant OIDC lookup' USING ERRCODE = '22023';
END;
$function$;
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.resolve_tenant_oidc_authentication_v1(p_lookup jsonb)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  provider_scope text := p_lookup #>> '{pins,provider,scope}';
BEGIN
  IF provider_scope = 'tenant' THEN
    RETURN app.private_v34_resolve_tenant_oidc_authentication_v1(p_lookup);
  ELSIF provider_scope = 'platform' THEN
    RETURN app.resolve_tenant_platform_oidc_authentication_v1(p_lookup);
  END IF;
  RAISE EXCEPTION 'invalid tenant OIDC callback lookup' USING ERRCODE = '22023';
END;
$function$;
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.create_oidc_authentication_transaction_v1(p_request jsonb)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  provider_scope text := p_request #>> '{current,pins,provider,scope}';
  requested_operation_run_id uuid;
  requested_transaction_id bytea;
  requested_receipt_digest bytea;
  requested_state_digest bytea;
  requested_browser_digest bytea;
  requested_previous_browser_digest bytea;
  receipt_lock bigint;
  state_lock bigint;
  current_browser_lock bigint;
  previous_browser_lock bigint;
  transaction_lock bigint;
BEGIN
  IF provider_scope = 'platform' THEN
    RETURN app.create_tenant_platform_oidc_authentication_transaction_v1(
      p_request
    );
  ELSIF provider_scope <> 'tenant' THEN
    RAISE EXCEPTION 'invalid federated authentication transaction request'
      USING ERRCODE = '22023';
  END IF;

  requested_operation_run_id := app.private_mfa_require_uuidv7_v1(
    p_request #>> '{begin,operationRunId}'
  );
  requested_transaction_id := app.private_mfa_decode_base64_v1(
    p_request #>> '{current,id}',32,32
  );
  requested_receipt_digest := app.private_mfa_decode_base64_v1(
    p_request #>> '{begin,receiptDigest}',32,32
  );
  requested_state_digest := app.private_mfa_decode_base64_v1(
    p_request #>> '{current,stateDigest}',32,32
  );
  requested_browser_digest := app.private_mfa_decode_base64_v1(
    p_request #>> '{current,browserDigest}',32,32
  );
  IF p_request ? 'previousBrowserDigest' THEN
    requested_previous_browser_digest := app.private_mfa_decode_base64_v1(
      p_request ->> 'previousBrowserDigest',32,32
    );
  END IF;

  PERFORM pg_advisory_xact_lock(hashtextextended(
    'federated-transaction:oidc:operation:' || requested_operation_run_id::text,
    17283101
  ));
  IF EXISTS (
    SELECT 1
    FROM ONLY public.tenant_platform_oidc_authentication_transactions AS platform
    WHERE platform.operation_run_id = requested_operation_run_id
  ) THEN RETURN NULL; END IF;

  receipt_lock := hashtextextended(
    'federated-transaction:receipt:' ||
      encode(requested_receipt_digest,'hex'),17283101
  );
  state_lock := hashtextextended(
    'federated-transaction:oidc:state:' ||
      encode(requested_state_digest,'hex'),17283101
  );
  current_browser_lock := hashtextextended(
    'federated-transaction:oidc:browser:' ||
      encode(requested_browser_digest,'hex'),
    17283101
  );
  transaction_lock := hashtextextended(
    'federated-transaction:oidc:id:' ||
      encode(requested_transaction_id,'hex'),17283101
  );
  PERFORM pg_advisory_xact_lock(receipt_lock);
  PERFORM pg_advisory_xact_lock(state_lock);
  IF requested_previous_browser_digest IS NULL THEN
    PERFORM pg_advisory_xact_lock(current_browser_lock);
  ELSE
    previous_browser_lock := hashtextextended(
      'federated-transaction:oidc:browser:' ||
        encode(requested_previous_browser_digest,'hex'),17283101
    );
    PERFORM pg_advisory_xact_lock(
      least(current_browser_lock,previous_browser_lock)
    );
    IF current_browser_lock <> previous_browser_lock THEN
      PERFORM pg_advisory_xact_lock(
        greatest(current_browser_lock,previous_browser_lock)
      );
    END IF;
  END IF;
  PERFORM pg_advisory_xact_lock(transaction_lock);

  IF EXISTS (
    SELECT 1
    FROM ONLY public.tenant_platform_oidc_authentication_transactions AS platform
    WHERE platform.receipt_digest = requested_receipt_digest
       OR platform.transaction_id = requested_transaction_id
       OR platform.state_digest = requested_state_digest
       OR ((requested_previous_browser_digest IS NULL
             OR requested_previous_browser_digest <> requested_browser_digest)
         AND platform.browser_digest = requested_browser_digest
         AND platform.state IN ('pending','claimed'))
  ) THEN RETURN NULL; END IF;
  IF requested_previous_browser_digest IS NOT NULL THEN
    UPDATE ONLY public.tenant_platform_oidc_authentication_transactions
      AS platform
    SET state = 'expired', version = platform.version + 1,
        completed_at = greatest(
          statement_timestamp(),platform.created_at,
          coalesce(platform.claimed_at,platform.created_at)
        ), failure_reason = 'expired'
    WHERE platform.browser_digest = requested_previous_browser_digest
      AND platform.state IN ('pending','claimed');
  END IF;
  RETURN app.private_v34_create_oidc_authentication_transaction_v1(p_request);
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range
  OR data_exception THEN
  RAISE EXCEPTION 'invalid federated authentication transaction request'
    USING ERRCODE = '22023';
END;
$function$;
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.claim_oidc_authentication_transaction_v1(p_request jsonb)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  requested_state_digest bytea;
  requested_browser_digest bytea;
  legacy_matches integer;
  platform_matches integer;
BEGIN
  requested_state_digest := app.private_mfa_decode_base64_v1(
    p_request ->> 'stateDigest',32,32
  );
  requested_browser_digest := app.private_mfa_decode_base64_v1(
    p_request ->> 'browserDigest',32,32
  );
  PERFORM pg_advisory_xact_lock(hashtextextended(
    'federated-transaction:oidc:state:' ||
      encode(requested_state_digest,'hex'),17283101
  ));
  PERFORM pg_advisory_xact_lock(hashtextextended(
    'federated-transaction:oidc:browser:' ||
      encode(requested_browser_digest,'hex'),
    17283101
  ));
  SELECT count(*)::integer INTO legacy_matches
  FROM ONLY public.tenant_federated_authentication_transactions AS legacy
  WHERE legacy.protocol = 'oidc'
    AND legacy.state_digest = requested_state_digest
    AND legacy.browser_digest = requested_browser_digest;
  SELECT count(*)::integer INTO platform_matches
  FROM ONLY public.tenant_platform_oidc_authentication_transactions AS platform
  WHERE platform.state_digest = requested_state_digest
    AND platform.browser_digest = requested_browser_digest;
  IF legacy_matches + platform_matches <> 1 THEN RETURN NULL; END IF;
  IF legacy_matches = 1 THEN
    RETURN app.private_v34_claim_oidc_authentication_transaction_v1(p_request);
  END IF;
  RETURN app.claim_tenant_platform_oidc_authentication_transaction_v1(p_request);
EXCEPTION WHEN invalid_text_representation OR data_exception THEN
  RAISE EXCEPTION 'invalid federated authentication transaction claim'
    USING ERRCODE = '22023';
END;
$function$;
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.fail_oidc_authentication_transaction_v1(p_request jsonb)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  requested_transaction_id bytea;
  legacy_matches integer;
  platform_matches integer;
BEGIN
  requested_transaction_id := app.private_mfa_decode_base64_v1(
    p_request ->> 'id',32,32
  );
  PERFORM pg_advisory_xact_lock(hashtextextended(
    'federated-transaction:oidc:id:' ||
      encode(requested_transaction_id,'hex'),17283101
  ));
  SELECT count(*)::integer INTO legacy_matches
  FROM ONLY public.tenant_federated_authentication_transactions AS legacy
  WHERE legacy.protocol = 'oidc'
    AND legacy.transaction_id = requested_transaction_id;
  SELECT count(*)::integer INTO platform_matches
  FROM ONLY public.tenant_platform_oidc_authentication_transactions AS platform
  WHERE platform.transaction_id = requested_transaction_id;
  IF legacy_matches + platform_matches <> 1 THEN RETURN NULL; END IF;
  IF legacy_matches = 1 THEN
    RETURN app.private_v34_fail_oidc_authentication_transaction_v1(p_request);
  END IF;
  RETURN app.fail_tenant_platform_oidc_authentication_transaction_v1(p_request);
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range
  OR data_exception THEN
  RAISE EXCEPTION 'invalid federated authentication transaction failure'
    USING ERRCODE = '22023';
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_capture_tenant_federated_login_authority_v1(
  p_command jsonb,
  p_result jsonb
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_operation_digest bytea;
  v_continuation_id uuid;
  v_receipt_digest bytea;
  v_action text;
  v_audience text;
  v_live record;
BEGIN
  IF p_result ->> 'category' IS DISTINCT FROM 'success'
     OR p_result ->> 'disposition' IS DISTINCT FROM 'continuation' THEN
    RETURN;
  END IF;
  v_operation_digest := app.private_mfa_decode_base64_v1(
    p_command ->> 'operationDigest',32,32
  );
  v_continuation_id := app.private_mfa_require_uuidv7_v1(
    p_result ->> 'continuationId'
  );
  IF coalesce((p_result ->> 'replayed')::boolean,false) THEN
    v_receipt_digest := app.private_mfa_decode_base64_v1(
      p_command #>> '{apply,continuation,receiptDigest}',32,32
    );
    SELECT continuation.action,continuation.audience
      INTO STRICT v_action,v_audience
    FROM ONLY public.tenant_post_primary_continuations AS continuation
    WHERE continuation.id = v_continuation_id
      AND continuation.user_id = (p_result ->> 'userId')::uuid;
    PERFORM app.resolve_mfa_authority_v2(
      v_continuation_id,'continuation',v_action,v_audience,
      transaction_timestamp(),v_receipt_digest
    );
    RETURN;
  END IF;
  SELECT application.tenant_id,application.user_id,application.provider_id,
         application.binding_id,application.provider_kind,
         application.request_snapshot,
         continuation.external_identity_id,
         continuation.primary_revision AS external_identity_revision,
         provider.version AS provider_revision,
         binding.version AS binding_revision,binding.mapping_revision,
         binding.auth_revision,
         policy.configuration_revision,policy.security_revision,
         policy.plan_revision,policy.assurance_policy_revision,
         epoch.id AS access_epoch_id,epoch.source_id AS access_source_id,
         access_grant.id AS access_grant_id,
         membership.id AS membership_id
    INTO STRICT v_live
  FROM ONLY public.tenant_federated_authentication_applications AS application
  JOIN ONLY public.tenant_post_primary_continuations AS continuation
    ON continuation.tenant_id = application.tenant_id
   AND continuation.id = application.continuation_id
   AND continuation.user_id = application.user_id
   AND continuation.primary_kind = 'tenant_provider'
   AND continuation.provider_id = application.provider_id
   AND continuation.binding_id = application.binding_id
   AND continuation.provider_kind = application.provider_kind
   AND continuation.state = 'pending'
   AND continuation.version = 1
  JOIN ONLY public.tenant_auth_providers AS provider
    ON provider.tenant_id = application.tenant_id
   AND provider.id = application.provider_id
   AND provider.kind = application.provider_kind
   AND provider.enabled AND provider.archived_at IS NULL
  JOIN ONLY public.tenant_auth_provider_bindings AS binding
    ON binding.tenant_id = provider.tenant_id
   AND binding.id = application.binding_id
   AND binding.provider_id = provider.id
   AND binding.enabled AND binding.archived_at IS NULL
   AND binding.current_access_epoch_id IS NOT NULL
  JOIN ONLY public.tenant_federated_provider_policies AS policy
    ON policy.tenant_id = provider.tenant_id
   AND policy.provider_id = provider.id
   AND policy.binding_id = binding.id
   AND policy.provider_kind = provider.kind
   AND policy.enabled
  JOIN ONLY public.tenant_identity_provider_access_epochs AS epoch
    ON epoch.tenant_id = binding.tenant_id
   AND epoch.id = binding.current_access_epoch_id
   AND epoch.binding_id = binding.id
   AND epoch.provider_id = provider.id
   AND epoch.ended_at IS NULL
  JOIN ONLY public.tenant_authorization_sources AS source
    ON source.tenant_id = epoch.tenant_id
   AND source.id = epoch.source_id
   AND source.kind = 'identity_provider_access'
   AND source.authoritative AND NOT source.protected
   AND source.key = format(
     'identity_provider_access:%s:%s',epoch.binding_id,epoch.sequence
   )
   AND source.retired_at IS NULL
  JOIN ONLY public.tenant_memberships AS membership
    ON membership.tenant_id = application.tenant_id
   AND membership.user_id = application.user_id
   AND membership.status = 'active'
  JOIN ONLY public.tenant_federated_external_identities AS identity
    ON identity.tenant_id = application.tenant_id
   AND identity.provider_id = provider.id
   AND identity.binding_id = binding.id
   AND identity.id = continuation.external_identity_id
   AND identity.user_id = application.user_id
   AND identity.version = continuation.primary_revision
   AND identity.retired_at IS NULL
  JOIN ONLY public.tenant_federated_provider_access_grants AS access_grant
    ON access_grant.tenant_id = application.tenant_id
   AND access_grant.provider_id = provider.id
   AND access_grant.binding_id = binding.id
   AND access_grant.access_epoch_id = epoch.id
   AND access_grant.source_id = source.id
   AND access_grant.external_identity_id = identity.id
   AND access_grant.membership_id = membership.id
   AND access_grant.user_id = application.user_id
   AND access_grant.ended_at IS NULL
  WHERE application.operation_digest = v_operation_digest
    AND application.continuation_id = v_continuation_id
    AND application.category = 'success'
    AND application.primary_kind = 'tenant_provider'
  FOR SHARE OF application,continuation,provider,binding,policy,epoch,source,
    membership,identity,access_grant;

  IF v_live.provider_revision IS DISTINCT FROM
       (v_live.request_snapshot #>> '{plan,providerRevision}')::bigint
     OR v_live.binding_revision IS DISTINCT FROM
       (v_live.request_snapshot #>> '{plan,bindingRevision}')::bigint
     OR v_live.configuration_revision IS DISTINCT FROM
       (v_live.request_snapshot #>> '{plan,configurationRevision}')::bigint
     OR v_live.security_revision IS DISTINCT FROM
       (v_live.request_snapshot #>> '{plan,securityRevision}')::bigint
     OR v_live.plan_revision IS DISTINCT FROM
       (v_live.request_snapshot #>> '{plan,planRevision}')::bigint
     OR v_live.mapping_revision IS DISTINCT FROM
       (v_live.request_snapshot #>> '{plan,mappingRevision}')::bigint
     OR v_live.auth_revision IS DISTINCT FROM
       (v_live.request_snapshot #>> '{plan,authorizationRevision}')::bigint
     OR v_live.assurance_policy_revision IS DISTINCT FROM
       (v_live.request_snapshot #>> '{plan,policyRevision}')::bigint THEN
    RAISE EXCEPTION 'tenant-provider login authority drifted after apply'
      USING ERRCODE = '40001';
  END IF;

  INSERT INTO public.tenant_post_primary_federated_provenance (
    tenant_id,continuation_id,user_id,origin,primary_kind,
    authentication_method,provider_id,binding_id,provider_kind,
    access_epoch_id,access_source_id,access_grant_id,membership_id,
    external_identity_id,external_identity_revision,provider_revision,
    binding_revision,configuration_revision,security_revision,plan_revision,
    mapping_revision,authorization_revision,assurance_policy_revision,
    authenticated_at,source_session_id,source_session_family_id,
    source_session_version,source_absolute_expires_at
  ) VALUES (
    v_live.tenant_id,v_continuation_id,v_live.user_id,'initial_login',
    'tenant_provider',v_live.provider_kind::text,v_live.provider_id,
    v_live.binding_id,v_live.provider_kind,v_live.access_epoch_id,
    v_live.access_source_id,v_live.access_grant_id,v_live.membership_id,
    v_live.external_identity_id,v_live.external_identity_revision,
    v_live.provider_revision,v_live.binding_revision,
    v_live.configuration_revision,v_live.security_revision,
    v_live.plan_revision,v_live.mapping_revision,v_live.auth_revision,
    v_live.assurance_policy_revision,
    (v_live.request_snapshot #>> '{authentication,authenticatedAt}')::timestamptz,
    NULL,NULL,NULL,NULL
  );
EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
  RAISE EXCEPTION 'tenant-provider login authority is unavailable'
    USING ERRCODE = '40001';
END;
$function$;
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.apply_federated_authentication_v1(p_command jsonb)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  provider_scope text := coalesce(
    p_command #>> '{apply,authentication,oidc,pins,provider,scope}',
    p_command #>> '{apply,authentication,saml,pins,provider,scope}'
  );
  result jsonb;
  disposition text := p_command #>> '{apply,disposition}';
  authority_at timestamptz := transaction_timestamp();
BEGIN
  IF provider_scope = 'tenant' THEN
    IF disposition = 'session' AND (
         (p_command #>> '{apply,session,idleExpiresAt}')::timestamptz
           <= authority_at
         OR (p_command #>> '{apply,session,absoluteExpiresAt}')::timestamptz
           <= authority_at
       ) THEN
      RAISE EXCEPTION 'tenant-provider session is already expired'
        USING ERRCODE = '22023';
    ELSIF disposition = 'continuation'
       AND (p_command #>> '{apply,continuation,expiresAt}')::timestamptz
             <= authority_at THEN
      RAISE EXCEPTION 'tenant-provider continuation is already expired'
        USING ERRCODE = '22023';
    END IF;
    result := app.private_v34_apply_federated_authentication_v1(p_command);
    PERFORM app.private_capture_tenant_federated_login_authority_v1(
      p_command,result
    );
    RETURN result;
  ELSIF provider_scope = 'platform' THEN
    RETURN app.apply_tenant_platform_oidc_authentication_v1(p_command);
  END IF;
  RAISE EXCEPTION 'invalid federated authentication apply request'
    USING ERRCODE = '22023';
EXCEPTION WHEN invalid_text_representation OR data_exception THEN
  RAISE EXCEPTION 'invalid federated authentication apply request'
    USING ERRCODE = '22023';
END;
$function$;
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.load_federated_authentication_planning_state_v1(
  p_lookup jsonb
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  provider_scope text := p_lookup #>> '{provider,scope}';
BEGIN
  IF provider_scope = 'tenant' THEN
    RETURN app.private_v34_load_federated_authentication_planning_state_v1(
      p_lookup
    );
  ELSIF provider_scope = 'platform' THEN
    RETURN app.load_tenant_platform_federated_planning_state_v1(p_lookup);
  END IF;
  RAISE EXCEPTION 'invalid federated authentication planning lookup'
    USING ERRCODE = '22023';
END;
$function$;
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.load_oidc_trust_snapshot_v1(p_lookup jsonb)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  provider_scope text := p_lookup #>> '{provider,scope}';
BEGIN
  IF provider_scope = 'tenant' THEN
    RETURN app.private_v34_load_oidc_trust_snapshot_v1(p_lookup);
  ELSIF provider_scope = 'platform' THEN
    RETURN app.load_tenant_platform_oidc_trust_snapshot_v1(p_lookup);
  END IF;
  RAISE EXCEPTION 'invalid OIDC trust lookup' USING ERRCODE = '22023';
END;
$function$;
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.load_oidc_client_secret_envelope_v1(p_lookup jsonb)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  provider_scope text := p_lookup #>> '{provider,scope}';
BEGIN
  IF provider_scope = 'tenant' THEN
    RETURN app.private_v34_load_oidc_client_secret_envelope_v1(p_lookup);
  ELSIF provider_scope = 'platform' THEN
    RETURN app.load_tenant_platform_oidc_client_secret_v1(p_lookup);
  END IF;
  RAISE EXCEPTION 'invalid OIDC client secret lookup' USING ERRCODE = '22023';
END;
$function$;
--> statement-breakpoint

-- The legacy tenant switch only rotates the auth_sessions row. Federated
-- sessions carry normalized MFA and exact provider/binding provenance that
-- cannot be transferred by that ABI, so it must fail before revoking the old
-- session or writing its replacement.
ALTER FUNCTION app.rotate_auth_session_tenant(
  bytea,uuid,bytea,bytea,uuid,timestamptz,timestamptz,
  uuid,uuid,uuid,inet,text
) RENAME TO private_unprovenanced_rotate_auth_session_tenant_v1;
-- The old identity no longer exists after the rename. Keep the transition
-- visible to parsers that otherwise retain the stale catalog entry.
DROP FUNCTION IF EXISTS app.rotate_auth_session_tenant(
  bytea,uuid,bytea,bytea,uuid,timestamptz,timestamptz,
  uuid,uuid,uuid,inet,text
);
--> statement-breakpoint

CREATE FUNCTION app.rotate_auth_session_tenant(
  p_old_token_digest bytea,
  p_new_session_id uuid,
  p_new_token_digest bytea,
  p_new_csrf_secret_digest bytea,
  p_tenant_id uuid,
  p_new_idle_expires_at timestamptz,
  p_new_absolute_expires_at timestamptz,
  p_platform_audit_event_id uuid,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text
)
RETURNS uuid
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  actor_id uuid := app.context_user_id();
  old_session_id uuid;
  old_tenant_id uuid;
BEGIN
  SELECT session.id,session.active_tenant_id
    INTO old_session_id,old_tenant_id
  FROM ONLY public.auth_sessions AS session
  WHERE session.token_digest = p_old_token_digest
    AND session.user_id = actor_id
    AND session.revoked_at IS NULL
    AND session.idle_expires_at > transaction_timestamp()
    AND session.absolute_expires_at > transaction_timestamp()
  FOR UPDATE;
  IF FOUND AND old_tenant_id IS DISTINCT FROM p_tenant_id AND (
       EXISTS (
         SELECT 1 FROM ONLY public.auth_session_mfa_states AS state
         WHERE state.session_id = old_session_id
       )
       OR EXISTS (
         SELECT 1
         FROM ONLY public.auth_session_federated_provenance AS provenance
         WHERE provenance.session_id = old_session_id
       )
       OR EXISTS (
         SELECT 1
         FROM ONLY public.auth_session_tenant_platform_federated_provenance
           AS provenance
         WHERE provenance.session_id = old_session_id
       )
     ) THEN
    RAISE EXCEPTION
      'typed-provenance session tenant switch requires provenance-aware rotation'
      USING ERRCODE = '42501';
  END IF;
  RETURN app.private_unprovenanced_rotate_auth_session_tenant_v1(
    p_old_token_digest,p_new_session_id,p_new_token_digest,
    p_new_csrf_secret_digest,p_tenant_id,p_new_idle_expires_at,
    p_new_absolute_expires_at,p_platform_audit_event_id,p_request_id,
    p_correlation_id,p_ip_address,p_user_agent
  );
END;
$function$;
--> statement-breakpoint

ALTER FUNCTION app.validate_mfa_evidence_subject_v1()
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.assert_mfa_webauthn_evidence_copy_cleanup_v1()
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_mfa_prepare_webauthn_evidence_copy_v1(jsonb,bytea)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_mfa_finish_webauthn_evidence_copy_v1(
  jsonb,uuid,uuid,timestamptz
) OWNER TO periapsis_migrator;
ALTER FUNCTION app.validate_webauthn_completed_security_snapshot_v1()
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.guard_webauthn_credential_security_revision_v1()
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.touch_mfa_policy_authority_v1()
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_mfa_lock_policy_authority_v1(uuid)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_mfa_assert_live_continuation_policy_v1(
  uuid,timestamptz
) OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_mfa_assert_live_passkey_anchor_evidence_v1(
  uuid,timestamptz,text,uuid
) OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_mfa_assert_live_passkey_session_evidence_v1(
  uuid,uuid,uuid,timestamptz
) OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_mfa_assert_live_passkey_continuation_evidence_v1(
  uuid,uuid,uuid,timestamptz
) OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_mfa_lock_live_passkey_session_v1(
  uuid,uuid,uuid,uuid,bigint,bigint,timestamptz,text,timestamptz
) OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_webauthn_credential_projection_v1(uuid)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_mfa_assert_live_policy_anchor_v1(
  uuid,timestamptz
) OWNER TO periapsis_migrator;
ALTER FUNCTION app.assert_auth_session_mfa_provenance_v1(uuid,uuid)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.validate_tenant_platform_continuation_provenance_v1()
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.validate_tenant_platform_continuation_authority_v1()
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.validate_tenant_federated_continuation_authority_v1()
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.enforce_tenant_federated_continuation_provenance_v1()
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.validate_tenant_passkey_continuation_authority_v1()
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.enforce_tenant_passkey_continuation_provenance_v1()
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.validate_tenant_platform_mfa_authority_evidence_v1()
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.copy_tenant_platform_mfa_authority_evidence_v1()
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_mfa_enter_continuation_receipt_v1(jsonb,text)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_mfa_restore_continuation_receipt_v1(text)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_mfa_anchor_from_stepup_binding_v1(jsonb,timestamptz)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_mfa_lock_continuation_authority_v1(
  uuid,timestamptz
) OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_mfa_apply_passkey_continuation_v1(
  jsonb,uuid,text,uuid,bigint,text,uuid,bigint,timestamptz
) OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_mfa_apply_passkey_session_v1(
  jsonb,uuid,text,uuid,bigint,text,uuid,bigint,timestamptz
) OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_v34_complete_mfa_passkey_registration_v1(jsonb)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.complete_mfa_passkey_registration_v1(jsonb)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_v34_complete_mfa_passkey_authentication_v1(jsonb)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.complete_mfa_passkey_authentication_v1(jsonb)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.start_totp_enrollment_v1(jsonb)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.create_mfa_step_up_challenge_v1(jsonb)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.create_webauthn_ceremony_v1(jsonb)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_mfa_assert_artifact_receipt_v1(uuid,bytea,timestamptz)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_unbound_claim_totp_enrollment_v1(
  uuid,bytea,timestamptz
) OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_unbound_claim_mfa_step_up_challenge_v1(
  bytea,bytea,text,timestamptz
) OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_unbound_claim_webauthn_ceremony_v1(
  bytea,bytea,timestamptz
) OWNER TO periapsis_migrator;
ALTER FUNCTION app.claim_totp_enrollment_v1(uuid,bytea,timestamptz)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.claim_totp_enrollment_v2(uuid,bytea,timestamptz,bytea)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.claim_mfa_step_up_challenge_v1(
  bytea,bytea,text,timestamptz
) OWNER TO periapsis_migrator;
ALTER FUNCTION app.claim_mfa_step_up_challenge_v2(
  bytea,bytea,text,timestamptz,bytea
) OWNER TO periapsis_migrator;
ALTER FUNCTION app.claim_webauthn_ceremony_v1(bytea,bytea,timestamptz)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.claim_webauthn_ceremony_v2(bytea,bytea,timestamptz,bytea)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_complete_mfa_factor_v1(jsonb,text)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.complete_mfa_totp_step_up_v1(jsonb)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.complete_mfa_recovery_step_up_v1(jsonb)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.resolve_mfa_authority_v2(
  uuid,text,text,text,timestamptz,bytea
) OWNER TO periapsis_migrator;
ALTER FUNCTION app.resolve_mfa_completion_artifact_v1(jsonb)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.guard_platform_federated_external_identity_v1()
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.guard_platform_federated_alias_v1()
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.guard_tenant_platform_oidc_transaction_v1()
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.guard_tenant_platform_runtime_immutable_v1()
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.guard_tenant_platform_continuation_child_v1()
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_platform_oidc_claim_policy_v1(uuid,text)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_tenant_platform_oidc_configuration_record_v1(uuid,uuid,uuid,jsonb)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.create_tenant_platform_oidc_authentication_transaction_v1(jsonb)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_tenant_platform_session_authority_live_v1(uuid,uuid,timestamptz)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.load_tenant_platform_federated_session_revalidation_v1(jsonb)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.apply_tenant_platform_federated_session_revalidation_v1(jsonb)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_v34_load_federated_session_revalidation_v1(jsonb)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_v34_apply_federated_session_revalidation_v1(jsonb)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_load_passkey_session_revalidation_v1(jsonb)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_apply_passkey_session_revalidation_v1(jsonb)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.load_federated_session_revalidation_v1(jsonb)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.apply_federated_session_revalidation_v1(jsonb)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_capture_tenant_federated_revalidation_authority_v1(
  jsonb,jsonb
) OWNER TO periapsis_migrator;
ALTER FUNCTION app.publish_platform_oidc_trust_snapshot_v1(jsonb)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_materialize_tenant_user_profile_v1(uuid,uuid)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.apply_tenant_platform_oidc_authentication_v1(jsonb)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.claim_tenant_platform_oidc_authentication_transaction_v1(jsonb)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.resolve_tenant_platform_oidc_authentication_v1(jsonb)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.fail_tenant_platform_oidc_authentication_transaction_v1(jsonb)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.begin_tenant_platform_oidc_authentication_v1(jsonb)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.load_tenant_platform_oidc_client_secret_v1(jsonb)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.load_tenant_platform_federated_planning_state_v1(jsonb)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.load_tenant_platform_oidc_trust_snapshot_v1(jsonb)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_v34_begin_tenant_oidc_authentication_v1(jsonb)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_v34_resolve_tenant_oidc_authentication_v1(jsonb)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_v34_create_oidc_authentication_transaction_v1(jsonb)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_v34_claim_oidc_authentication_transaction_v1(jsonb)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_v34_fail_oidc_authentication_transaction_v1(jsonb)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_v34_apply_federated_authentication_v1(jsonb)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_v34_load_federated_authentication_planning_state_v1(jsonb)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_v34_load_oidc_trust_snapshot_v1(jsonb)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_v34_load_oidc_client_secret_envelope_v1(jsonb)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.begin_tenant_oidc_authentication_v1(jsonb)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.resolve_tenant_oidc_authentication_v1(jsonb)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.create_oidc_authentication_transaction_v1(jsonb)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.claim_oidc_authentication_transaction_v1(jsonb)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.fail_oidc_authentication_transaction_v1(jsonb)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.apply_federated_authentication_v1(jsonb)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_capture_tenant_federated_login_authority_v1(
  jsonb,jsonb
) OWNER TO periapsis_migrator;
ALTER FUNCTION app.load_federated_authentication_planning_state_v1(jsonb)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.load_oidc_trust_snapshot_v1(jsonb)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.load_oidc_client_secret_envelope_v1(jsonb)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_unprovenanced_rotate_auth_session_tenant_v1(
  bytea,uuid,bytea,bytea,uuid,timestamptz,timestamptz,
  uuid,uuid,uuid,inet,text
) OWNER TO periapsis_migrator;
ALTER FUNCTION app.rotate_auth_session_tenant(
  bytea,uuid,bytea,bytea,uuid,timestamptz,timestamptz,
  uuid,uuid,uuid,inet,text
) OWNER TO periapsis_migrator;
--> statement-breakpoint

REVOKE ALL ON FUNCTION
  app.validate_mfa_evidence_subject_v1(),
  app.assert_mfa_webauthn_evidence_copy_cleanup_v1(),
  app.private_mfa_prepare_webauthn_evidence_copy_v1(jsonb,bytea),
  app.private_mfa_finish_webauthn_evidence_copy_v1(
    jsonb,uuid,uuid,timestamptz
  ),
  app.validate_webauthn_completed_security_snapshot_v1(),
  app.guard_webauthn_credential_security_revision_v1(),
  app.touch_mfa_policy_authority_v1(),
  app.private_mfa_lock_policy_authority_v1(uuid),
  app.private_mfa_assert_live_continuation_policy_v1(uuid,timestamptz),
  app.private_mfa_assert_live_passkey_anchor_evidence_v1(
    uuid,timestamptz,text,uuid
  ),
  app.private_mfa_assert_live_passkey_session_evidence_v1(
    uuid,uuid,uuid,timestamptz
  ),
  app.private_mfa_assert_live_passkey_continuation_evidence_v1(
    uuid,uuid,uuid,timestamptz
  ),
  app.private_mfa_lock_live_passkey_session_v1(
    uuid,uuid,uuid,uuid,bigint,bigint,timestamptz,text,timestamptz
  ),
  app.private_webauthn_credential_projection_v1(uuid),
  app.private_mfa_assert_live_policy_anchor_v1(uuid,timestamptz),
  app.assert_auth_session_mfa_provenance_v1(uuid,uuid),
  app.validate_tenant_platform_continuation_provenance_v1(),
  app.validate_tenant_platform_continuation_authority_v1(),
  app.validate_tenant_federated_continuation_authority_v1(),
  app.enforce_tenant_federated_continuation_provenance_v1(),
  app.validate_tenant_passkey_continuation_authority_v1(),
  app.enforce_tenant_passkey_continuation_provenance_v1(),
  app.validate_tenant_platform_mfa_authority_evidence_v1(),
  app.copy_tenant_platform_mfa_authority_evidence_v1(),
  app.private_mfa_enter_continuation_receipt_v1(jsonb,text),
  app.private_mfa_restore_continuation_receipt_v1(text),
  app.private_mfa_anchor_from_stepup_binding_v1(jsonb,timestamptz),
  app.private_mfa_lock_continuation_authority_v1(uuid,timestamptz),
  app.private_mfa_apply_passkey_continuation_v1(
    jsonb,uuid,text,uuid,bigint,text,uuid,bigint,timestamptz
  ),
  app.private_mfa_apply_passkey_session_v1(
    jsonb,uuid,text,uuid,bigint,text,uuid,bigint,timestamptz
  ),
  app.private_v34_complete_mfa_passkey_registration_v1(jsonb),
  app.complete_mfa_passkey_registration_v1(jsonb),
  app.private_v34_complete_mfa_passkey_authentication_v1(jsonb),
  app.complete_mfa_passkey_authentication_v1(jsonb),
  app.private_unbound_mfa_anchor_from_stepup_binding_v1(jsonb,timestamptz),
  app.start_totp_enrollment_v1(jsonb),
  app.create_mfa_step_up_challenge_v1(jsonb),
  app.create_webauthn_ceremony_v1(jsonb),
  app.private_unbound_start_totp_enrollment_v1(jsonb),
  app.private_unbound_create_mfa_step_up_challenge_v1(jsonb),
  app.private_unbound_create_webauthn_ceremony_v1(jsonb),
  app.private_mfa_assert_artifact_receipt_v1(uuid,bytea,timestamptz),
  app.private_unbound_claim_totp_enrollment_v1(uuid,bytea,timestamptz),
  app.private_unbound_claim_mfa_step_up_challenge_v1(
    bytea,bytea,text,timestamptz
  ),
  app.private_unbound_claim_webauthn_ceremony_v1(bytea,bytea,timestamptz),
  app.claim_totp_enrollment_v1(uuid,bytea,timestamptz),
  app.claim_totp_enrollment_v2(uuid,bytea,timestamptz,bytea),
  app.claim_mfa_step_up_challenge_v1(bytea,bytea,text,timestamptz),
  app.claim_mfa_step_up_challenge_v2(bytea,bytea,text,timestamptz,bytea),
  app.claim_webauthn_ceremony_v1(bytea,bytea,timestamptz),
  app.claim_webauthn_ceremony_v2(bytea,bytea,timestamptz,bytea),
  app.private_complete_mfa_factor_v1(jsonb,text),
  app.private_complete_mfa_factor_legacy_v1(jsonb,text),
  app.complete_mfa_totp_step_up_v1(jsonb),
  app.complete_mfa_recovery_step_up_v1(jsonb),
  app.resolve_mfa_authority_v1(uuid,text,text,text,timestamptz),
  app.resolve_mfa_authority_v2(uuid,text,text,text,timestamptz,bytea),
  app.resolve_mfa_completion_artifact_v1(jsonb),
  app.guard_platform_federated_external_identity_v1(),
  app.guard_platform_federated_alias_v1(),
  app.guard_tenant_platform_oidc_transaction_v1(),
  app.guard_tenant_platform_runtime_immutable_v1(),
  app.guard_tenant_platform_continuation_child_v1(),
  app.private_platform_oidc_claim_policy_v1(uuid,text),
  app.private_tenant_platform_oidc_configuration_record_v1(uuid,uuid,uuid,jsonb),
  app.create_tenant_platform_oidc_authentication_transaction_v1(jsonb),
  app.private_tenant_platform_session_authority_live_v1(uuid,uuid,timestamptz),
  app.load_tenant_platform_federated_session_revalidation_v1(jsonb),
  app.apply_tenant_platform_federated_session_revalidation_v1(jsonb),
  app.private_v34_load_federated_session_revalidation_v1(jsonb),
  app.private_v34_apply_federated_session_revalidation_v1(jsonb),
  app.private_load_passkey_session_revalidation_v1(jsonb),
  app.private_apply_passkey_session_revalidation_v1(jsonb),
  app.load_federated_session_revalidation_v1(jsonb),
  app.apply_federated_session_revalidation_v1(jsonb),
  app.private_capture_tenant_federated_revalidation_authority_v1(jsonb,jsonb),
  app.publish_platform_oidc_trust_snapshot_v1(jsonb),
  app.private_materialize_tenant_user_profile_v1(uuid,uuid),
  app.apply_tenant_platform_oidc_authentication_v1(jsonb),
  app.claim_tenant_platform_oidc_authentication_transaction_v1(jsonb),
  app.resolve_tenant_platform_oidc_authentication_v1(jsonb),
  app.fail_tenant_platform_oidc_authentication_transaction_v1(jsonb),
  app.begin_tenant_platform_oidc_authentication_v1(jsonb),
  app.load_tenant_platform_oidc_client_secret_v1(jsonb),
  app.load_tenant_platform_federated_planning_state_v1(jsonb),
  app.load_tenant_platform_oidc_trust_snapshot_v1(jsonb),
  app.private_v34_begin_tenant_oidc_authentication_v1(jsonb),
  app.private_v34_resolve_tenant_oidc_authentication_v1(jsonb),
  app.private_v34_create_oidc_authentication_transaction_v1(jsonb),
  app.private_v34_claim_oidc_authentication_transaction_v1(jsonb),
  app.private_v34_fail_oidc_authentication_transaction_v1(jsonb),
  app.private_v34_apply_federated_authentication_v1(jsonb),
  app.private_v34_load_federated_authentication_planning_state_v1(jsonb),
  app.private_v34_load_oidc_trust_snapshot_v1(jsonb),
  app.private_v34_load_oidc_client_secret_envelope_v1(jsonb),
  app.begin_tenant_oidc_authentication_v1(jsonb),
  app.resolve_tenant_oidc_authentication_v1(jsonb),
  app.create_oidc_authentication_transaction_v1(jsonb),
  app.claim_oidc_authentication_transaction_v1(jsonb),
  app.fail_oidc_authentication_transaction_v1(jsonb),
  app.apply_federated_authentication_v1(jsonb),
  app.private_capture_tenant_federated_login_authority_v1(jsonb,jsonb),
  app.load_federated_authentication_planning_state_v1(jsonb),
  app.load_oidc_trust_snapshot_v1(jsonb),
  app.load_oidc_client_secret_envelope_v1(jsonb),
  app.private_unprovenanced_rotate_auth_session_tenant_v1(
    bytea,uuid,bytea,bytea,uuid,timestamptz,timestamptz,
    uuid,uuid,uuid,inet,text
  ),
  app.rotate_auth_session_tenant(
    bytea,uuid,bytea,bytea,uuid,timestamptz,timestamptz,
    uuid,uuid,uuid,inet,text
  )
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner, periapsis_sla_api_owner,
  periapsis_sla_worker_owner, periapsis_sla_readiness_owner,
  periapsis_ticket_saved_view_owner, periapsis_ticket_attribution_owner,
  periapsis_ticket_sla_projection_owner;
--> statement-breakpoint

GRANT EXECUTE ON FUNCTION
  app.load_federated_session_revalidation_v1(jsonb),
  app.apply_federated_session_revalidation_v1(jsonb),
  app.begin_tenant_oidc_authentication_v1(jsonb),
  app.resolve_tenant_oidc_authentication_v1(jsonb),
  app.create_oidc_authentication_transaction_v1(jsonb),
  app.claim_oidc_authentication_transaction_v1(jsonb),
  app.fail_oidc_authentication_transaction_v1(jsonb),
  app.apply_federated_authentication_v1(jsonb),
  app.load_federated_authentication_planning_state_v1(jsonb),
  app.load_oidc_trust_snapshot_v1(jsonb),
  app.load_oidc_client_secret_envelope_v1(jsonb),
  app.rotate_auth_session_tenant(
    bytea,uuid,bytea,bytea,uuid,timestamptz,timestamptz,
    uuid,uuid,uuid,inet,text
  )
TO periapsis_api;
GRANT EXECUTE ON FUNCTION app.publish_platform_oidc_trust_snapshot_v1(jsonb)
TO periapsis_worker;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION
  app.start_totp_enrollment_v1(jsonb),
  app.create_mfa_step_up_challenge_v1(jsonb),
  app.create_webauthn_ceremony_v1(jsonb),
  app.claim_totp_enrollment_v2(uuid,bytea,timestamptz,bytea),
  app.claim_mfa_step_up_challenge_v2(bytea,bytea,text,timestamptz,bytea),
  app.claim_webauthn_ceremony_v2(bytea,bytea,timestamptz,bytea),
  app.resolve_mfa_authority_v2(uuid,text,text,text,timestamptz,bytea),
  app.resolve_mfa_completion_artifact_v1(jsonb),
  app.complete_mfa_totp_step_up_v1(jsonb),
  app.complete_mfa_recovery_step_up_v1(jsonb),
  app.complete_mfa_passkey_registration_v1(jsonb),
  app.complete_mfa_passkey_authentication_v1(jsonb)
TO periapsis_api;
--> statement-breakpoint
ALTER TABLE public.tenant_post_primary_continuations
  DROP CONSTRAINT tenant_post_primary_continuations_lifecycle_check;
ALTER TABLE public.tenant_post_primary_continuations
  ADD CONSTRAINT tenant_post_primary_continuations_lifecycle_check CHECK (
    (state = 'pending' AND version >= 1 AND consumed_at IS NULL
      AND revoked_at IS NULL AND revoke_reason IS NULL)
    OR (state = 'consumed' AND version >= 2 AND consumed_at IS NOT NULL
      AND revoked_at IS NULL AND revoke_reason IS NULL)
    OR (state IN ('revoked','expired') AND version >= 2
      AND consumed_at IS NULL AND revoked_at IS NOT NULL
      AND revoke_reason IS NOT NULL AND btrim(revoke_reason) <> ''
      AND char_length(revoke_reason) <= 500
      AND revoke_reason !~ '[[:cntrl:]]')
  );
--> statement-breakpoint
