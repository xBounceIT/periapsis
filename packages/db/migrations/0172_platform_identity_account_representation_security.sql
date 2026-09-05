-- Identity security/provenance revision and HTTP representation revision
-- deliberately diverge. Observations may change the safe administrative
-- document without revoking already-issued sessions, while retirement advances
-- both revisions. The joined user projection carries its own local revision so
-- a strong composite validator never requires a users -> identity lock edge.
COMMENT ON COLUMN public.platform_federated_external_identities.version IS
  'Security/provenance revision pinned by sessions and continuations; observations do not advance it.';
COMMENT ON COLUMN public.platform_federated_external_identities.resource_version IS
  'Safe account-representation revision; encoded in the platform identity-account composite ETag.';
COMMENT ON COLUMN public.users.version IS
  'Global safe-user projection revision; advances only when display_name, email, or active changes.';
--> statement-breakpoint

CREATE FUNCTION app.guard_platform_federated_external_identity_v3()
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
    IF NEW.version <> 1 OR NEW.resource_version <> 1
       OR NEW.retired_at IS NOT NULL
       OR NEW.created_at IS DISTINCT FROM transaction_timestamp()
       OR NEW.updated_at IS DISTINCT FROM transaction_timestamp()
       OR NEW.last_observed_at IS DISTINCT FROM transaction_timestamp() THEN
      RAISE EXCEPTION 'platform federated identity create envelope is invalid'
        USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
  END IF;

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
     OR NEW.last_observed_at < OLD.last_observed_at
     OR OLD.retired_at IS NOT NULL
     OR OLD.resource_version >= 2147483647
     OR NEW.resource_version NOT IN (
       OLD.resource_version, OLD.resource_version + 1
     ) THEN
    RAISE EXCEPTION 'platform federated identity transition is invalid'
      USING ERRCODE = '23514';
  END IF;

  IF NEW.retired_at IS NULL THEN
    IF NEW.version <> OLD.version
       OR NEW.last_observed_at IS DISTINCT FROM transaction_timestamp() THEN
      RAISE EXCEPTION 'platform federated identity observation is invalid'
        USING ERRCODE = '23514';
    END IF;
  ELSE
    IF OLD.version >= 2147483647
       OR NEW.version <> OLD.version + 1
       OR NEW.retired_at IS DISTINCT FROM transaction_timestamp()
       OR (
         NEW.last_observed_at IS DISTINCT FROM OLD.last_observed_at
         AND NEW.last_observed_at IS DISTINCT FROM transaction_timestamp()
       ) THEN
      RAISE EXCEPTION 'platform federated identity retirement is invalid'
        USING ERRCODE = '23514';
    END IF;
    NEW.last_observed_at := OLD.last_observed_at;
  END IF;
  NEW.resource_version := OLD.resource_version + 1;
  RETURN NEW;
END;
$function$;
--> statement-breakpoint

DROP TRIGGER platform_federated_external_identities_guard_v2
  ON public.platform_federated_external_identities;
--> statement-breakpoint

CREATE TRIGGER platform_federated_external_identities_guard_v3
BEFORE INSERT OR UPDATE OR DELETE
ON public.platform_federated_external_identities
FOR EACH ROW
EXECUTE FUNCTION app.guard_platform_federated_external_identity_v3();
--> statement-breakpoint

CREATE FUNCTION app.guard_user_platform_identity_projection_v1()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  projection_changed boolean;
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.version <> 1 THEN
      RAISE EXCEPTION 'user projection create version is invalid'
        USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
  END IF;

  projection_changed :=
    ROW(NEW.display_name, NEW.email, NEW.active)
      IS DISTINCT FROM ROW(OLD.display_name, OLD.email, OLD.active);
  IF projection_changed THEN
    IF OLD.version >= 2147483647
       OR NEW.version NOT IN (OLD.version, OLD.version + 1) THEN
      RAISE EXCEPTION 'user projection revision is exhausted or invalid'
        USING ERRCODE = '55000';
    END IF;
    NEW.version := OLD.version + 1;
    NEW.updated_at := transaction_timestamp();
  ELSIF NEW.version IS DISTINCT FROM OLD.version THEN
    RAISE EXCEPTION 'user projection version changed without its representation'
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$function$;
--> statement-breakpoint

CREATE TRIGGER users_platform_identity_projection_insert_guard_v1
BEFORE INSERT ON public.users
FOR EACH ROW
EXECUTE FUNCTION app.guard_user_platform_identity_projection_v1();
--> statement-breakpoint

CREATE TRIGGER users_platform_identity_projection_update_guard_v1
BEFORE UPDATE OF display_name, email, active, version ON public.users
FOR EACH ROW
EXECUTE FUNCTION app.guard_user_platform_identity_projection_v1();
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.private_platform_identity_account_document_v1(
  p_provider_id uuid,
  p_account_id uuid
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
  SELECT jsonb_build_object(
    'id', identity.id,
    'providerId', identity.platform_provider_id,
    'user', jsonb_build_object(
      'id', local_user.id,
      'displayName', local_user.display_name,
      'email', local_user.email,
      'active', local_user.active,
      'version', local_user.version
    ),
    'state', CASE WHEN identity.retired_at IS NULL
      THEN 'active' ELSE 'retired' END,
    'admittedConfigurationRevision',
      identity.admitted_configuration_revision,
    'admittedSecurityRevision', identity.admitted_security_revision,
    'lastObservedAt', identity.last_observed_at,
    'retiredAt', identity.retired_at,
    'version', identity.resource_version,
    'createdAt', identity.created_at,
    'updatedAt', identity.updated_at
  ) INTO result
  FROM ONLY public.platform_federated_external_identities AS identity
  JOIN ONLY public.users AS local_user ON local_user.id = identity.user_id
  WHERE identity.platform_provider_id = p_provider_id
    AND identity.id = p_account_id;
  IF result IS NULL THEN
    RAISE EXCEPTION 'platform identity account does not exist'
      USING ERRCODE = 'P0002';
  END IF;
  RETURN result;
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.retire_platform_identity_account_v2(
  p_session_id uuid,
  p_provider_id uuid,
  p_account_id uuid,
  p_expected_version bigint,
  p_expected_user_version bigint,
  p_audit_event_id uuid,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text,
  p_reason text
)
RETURNS TABLE (
  account_id uuid,
  version bigint,
  document jsonb
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  actor_id uuid;
  read_actor_id uuid;
  provider_record public.platform_auth_providers%ROWTYPE;
  identity_record public.platform_federated_external_identities%ROWTYPE;
  user_record public.users%ROWTYPE;
  changed_at timestamptz := transaction_timestamp();
  affected_tenant_ids uuid[] := ARRAY[]::uuid[];
  affected_membership_ids uuid[] := ARRAY[]::uuid[];
  owned_membership_ids uuid[] := ARRAY[]::uuid[];
  affected_membership_id uuid;
  affected_tenant_id uuid;
  affected_tenant_grant_count integer;
  revoked_session_count integer := 0;
  revoked_continuation_count integer := 0;
  ended_grant_count integer := 0;
  account_document jsonb;
BEGIN
  IF p_provider_id IS NULL
     OR uuid_extract_version(p_provider_id) IS DISTINCT FROM 7
     OR p_account_id IS NULL
     OR uuid_extract_version(p_account_id) IS DISTINCT FROM 7
     OR p_expected_version IS NULL
     OR p_expected_version NOT BETWEEN 1 AND 2147483646
     OR p_expected_user_version IS NULL
     OR p_expected_user_version NOT BETWEEN 1 AND 2147483647
     OR p_audit_event_id IS NULL
     OR uuid_extract_version(p_audit_event_id) IS DISTINCT FROM 7
     OR p_request_id IS NULL
     OR uuid_extract_version(p_request_id) IS DISTINCT FROM 7
     OR p_correlation_id IS NULL
     OR uuid_extract_version(p_correlation_id) IS DISTINCT FROM 7
     OR p_ip_address IS NULL
     OR p_user_agent IS NULL
     OR octet_length(p_user_agent) NOT BETWEEN 1 AND 512
     OR NOT app.private_platform_identity_text_is_safe_v1(p_user_agent, false)
     OR p_reason IS NULL
     OR NOT app.private_platform_lifecycle_reason_is_valid_v1(p_reason) THEN
    RAISE EXCEPTION 'invalid platform identity account retirement command'
      USING ERRCODE = '22023';
  END IF;
  actor_id := app.private_require_platform_identity_permission_v1(
    p_session_id, 'platform.identity_account.manage', p_authentication_method
  );
  read_actor_id := app.private_require_platform_identity_permission_v1(
    p_session_id, 'platform.identity_account.read', p_authentication_method
  );
  IF read_actor_id IS DISTINCT FROM actor_id THEN
    RAISE EXCEPTION 'live platform identity account read authority is required'
      USING ERRCODE = '42501';
  END IF;

  SELECT provider.* INTO provider_record
  FROM ONLY public.platform_auth_providers AS provider
  WHERE provider.id = p_provider_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'platform identity provider does not exist'
      USING ERRCODE = 'P0002';
  END IF;
  SELECT identity.* INTO identity_record
  FROM ONLY public.platform_federated_external_identities AS identity
  WHERE identity.platform_provider_id = p_provider_id
    AND identity.id = p_account_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'platform identity account does not exist'
      USING ERRCODE = 'P0002';
  END IF;
  -- Match the OIDC apply path's identity-then-user row-lock order. The
  -- composite HTTP validator is checked only after both representation sources
  -- are stable in this transaction.
  SELECT local_user.* INTO user_record
  FROM ONLY public.users AS local_user
  WHERE local_user.id = identity_record.user_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'platform identity account user is unavailable'
      USING ERRCODE = 'XX000';
  END IF;
  IF identity_record.resource_version <> p_expected_version
     OR user_record.version <> p_expected_user_version THEN
    RAISE EXCEPTION 'platform identity account revision conflict'
      USING ERRCODE = '40001';
  END IF;
  IF identity_record.retired_at IS NOT NULL THEN
    RAISE EXCEPTION 'platform identity account is already retired'
      USING ERRCODE = '55000';
  END IF;
  IF identity_record.version >= 2147483647 THEN
    RAISE EXCEPTION 'platform identity account security revision is exhausted'
      USING ERRCODE = '55000';
  END IF;

  -- Lock all tenant admission paths before changing any of them. Provider
  -- authentication takes the provider lock first, so this order cannot invert
  -- the login/apply path.
  PERFORM 1
  FROM ONLY public.tenant_platform_federated_provider_access_grants AS grant_row
  WHERE grant_row.platform_provider_id = p_provider_id
    AND grant_row.external_identity_id = p_account_id
    AND grant_row.ended_at IS NULL
  ORDER BY grant_row.tenant_id, grant_row.id
  FOR UPDATE;
  SELECT coalesce(array_agg(DISTINCT grant_row.tenant_id
             ORDER BY grant_row.tenant_id), ARRAY[]::uuid[]),
         coalesce(array_agg(DISTINCT grant_row.membership_id
             ORDER BY grant_row.membership_id), ARRAY[]::uuid[]),
         coalesce(array_agg(DISTINCT grant_row.membership_id
             ORDER BY grant_row.membership_id)
           FILTER (WHERE grant_row.owns_membership), ARRAY[]::uuid[])
    INTO affected_tenant_ids, affected_membership_ids, owned_membership_ids
  FROM ONLY public.tenant_platform_federated_provider_access_grants AS grant_row
  WHERE grant_row.platform_provider_id = p_provider_id
    AND grant_row.external_identity_id = p_account_id
    AND grant_row.ended_at IS NULL;
  PERFORM 1
  FROM ONLY public.tenant_authorization_states AS authorization_state
  WHERE authorization_state.tenant_id = ANY(affected_tenant_ids)
  ORDER BY authorization_state.tenant_id
  FOR UPDATE;
  -- Profile materialization and every admission/apply path acquire membership
  -- before MFA subject.  Pre-lock the full affected set in that same canonical
  -- order so two provider retirements cannot form a membership/subject cycle,
  -- and keep the revision-headroom check stable through the updates below.
  PERFORM 1
  FROM ONLY public.tenant_memberships AS membership
  WHERE membership.id = ANY(affected_membership_ids)
    AND membership.user_id = identity_record.user_id
  ORDER BY membership.tenant_id, membership.id
  FOR UPDATE;
  PERFORM 1
  FROM ONLY public.tenant_mfa_subjects AS subject
  WHERE subject.tenant_id = ANY(affected_tenant_ids)
    AND subject.user_id = identity_record.user_id
  ORDER BY subject.tenant_id, subject.user_id
  FOR UPDATE;
  IF EXISTS (
    SELECT 1
    FROM ONLY public.tenant_mfa_subjects AS subject
    WHERE subject.tenant_id = ANY(affected_tenant_ids)
      AND subject.user_id = identity_record.user_id
      AND (subject.identity_epoch >= 9007199254740991
        OR subject.session_invalidation_epoch >= 9007199254740991
        OR subject.version >= 2147483647)
  ) THEN
    RAISE EXCEPTION 'platform identity account invalidation revision is exhausted'
      USING ERRCODE = '55000';
  END IF;

  UPDATE ONLY public.tenant_post_primary_continuations AS continuation
  SET state = 'revoked', version = continuation.version + 1,
      revoked_at = changed_at,
      revoke_reason = 'platform_identity_account_retired'
  WHERE continuation.platform_provider_id = p_provider_id
    AND continuation.external_identity_id = p_account_id
    AND continuation.user_id = identity_record.user_id
    AND continuation.primary_kind = 'tenant_platform_provider'
    AND continuation.state = 'pending';
  GET DIAGNOSTICS revoked_continuation_count = ROW_COUNT;

  WITH affected_families AS (
    SELECT DISTINCT source_session.rotation_family_id
    FROM ONLY public.auth_session_tenant_platform_federated_provenance
      AS provenance
    JOIN ONLY public.auth_sessions AS source_session
      ON source_session.id = provenance.session_id
     AND source_session.user_id = provenance.user_id
    WHERE provenance.platform_provider_id = p_provider_id
      AND provenance.external_identity_id = p_account_id
      AND provenance.user_id = identity_record.user_id
  )
  UPDATE ONLY public.auth_sessions AS session
  SET revoked_at = greatest(changed_at, session.created_at),
      revoke_reason = 'platform_identity_account_retired'
  FROM affected_families
  WHERE session.rotation_family_id = affected_families.rotation_family_id
    AND session.user_id = identity_record.user_id
    AND session.revoked_at IS NULL;
  GET DIAGNOSTICS revoked_session_count = ROW_COUNT;

  UPDATE ONLY public.tenant_platform_federated_provider_profile_contributions
    AS contribution
  SET retired_at = changed_at, version = contribution.version + 1
  FROM ONLY public.tenant_platform_federated_provider_access_grants AS grant_row
  WHERE grant_row.platform_provider_id = p_provider_id
    AND grant_row.external_identity_id = p_account_id
    AND grant_row.ended_at IS NULL
    AND contribution.tenant_id = grant_row.tenant_id
    AND contribution.access_grant_id = grant_row.id
    AND contribution.retired_at IS NULL;
  UPDATE ONLY public.tenant_platform_federated_provider_access_grants AS grant_row
  SET ended_at = changed_at, version = grant_row.version + 1
  WHERE grant_row.platform_provider_id = p_provider_id
    AND grant_row.external_identity_id = p_account_id
    AND grant_row.ended_at IS NULL;
  GET DIAGNOSTICS ended_grant_count = ROW_COUNT;

  UPDATE ONLY public.tenant_mfa_subjects AS subject
  SET identity_epoch = subject.identity_epoch + 1,
      session_invalidation_epoch = subject.session_invalidation_epoch + 1,
      version = subject.version + 1,
      updated_at = changed_at
  WHERE subject.tenant_id = ANY(affected_tenant_ids)
    AND subject.user_id = identity_record.user_id;

  FOREACH affected_membership_id IN ARRAY affected_membership_ids LOOP
    SELECT grant_row.tenant_id INTO affected_tenant_id
    FROM ONLY public.tenant_platform_federated_provider_access_grants AS grant_row
    WHERE grant_row.platform_provider_id = p_provider_id
      AND grant_row.external_identity_id = p_account_id
      AND grant_row.membership_id = affected_membership_id
    ORDER BY grant_row.tenant_id
    LIMIT 1;
    IF affected_tenant_id IS NOT NULL THEN
      PERFORM app.private_materialize_tenant_user_profile_v1(
        affected_tenant_id, affected_membership_id
      );
    END IF;
  END LOOP;

  -- A membership created solely by this admission must not survive the last
  -- live identity source. Additive/manual memberships remain untouched.
  UPDATE ONLY public.tenant_memberships AS membership
  SET status = 'suspended', updated_at = changed_at
  WHERE membership.id = ANY(owned_membership_ids)
    AND membership.user_id = identity_record.user_id
    AND membership.status = 'active'
    AND NOT EXISTS (
      SELECT 1
      FROM ONLY public.tenant_platform_federated_provider_access_grants AS other
      WHERE other.tenant_id = membership.tenant_id
        AND other.membership_id = membership.id
        AND other.ended_at IS NULL
    )
    AND NOT EXISTS (
      SELECT 1
      FROM ONLY public.tenant_ldap_provider_access_grants AS other
      WHERE other.tenant_id = membership.tenant_id
        AND other.membership_id = membership.id
        AND other.ended_at IS NULL
    )
    AND NOT EXISTS (
      SELECT 1
      FROM ONLY public.tenant_federated_provider_access_grants AS other
      WHERE other.tenant_id = membership.tenant_id
        AND other.membership_id = membership.id
        AND other.ended_at IS NULL
    )
    AND NOT EXISTS (
      SELECT 1
      FROM ONLY public.user_login_identifiers AS identifier
      WHERE identifier.user_id = membership.user_id
        AND identifier.retired_at IS NULL
    );

  UPDATE ONLY public.platform_federated_external_identity_aliases AS alias
  SET retired_at = changed_at
  WHERE alias.platform_provider_id = p_provider_id
    AND alias.external_identity_id = p_account_id
    AND alias.retired_at IS NULL;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'platform identity account aliases are unavailable'
      USING ERRCODE = '55000';
  END IF;
  UPDATE ONLY public.platform_federated_external_identities AS identity
  SET retired_at = changed_at,
      last_observed_at = identity.last_observed_at,
      version = identity.version + 1,
      resource_version = identity.resource_version + 1,
      updated_at = changed_at
  WHERE identity.platform_provider_id = p_provider_id
    AND identity.id = p_account_id
    AND identity.version = identity_record.version
    AND identity.resource_version = p_expected_version
    AND identity.retired_at IS NULL;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'platform identity account revision conflict'
      USING ERRCODE = '40001';
  END IF;

  FOREACH affected_tenant_id IN ARRAY affected_tenant_ids LOOP
    SELECT count(*)::integer INTO affected_tenant_grant_count
    FROM ONLY public.tenant_platform_federated_provider_access_grants AS grant_row
    WHERE grant_row.tenant_id = affected_tenant_id
      AND grant_row.platform_provider_id = p_provider_id
      AND grant_row.external_identity_id = p_account_id
      AND grant_row.ended_at = changed_at;
    PERFORM app.private_append_platform_identity_account_tenant_audit_v1(
      affected_tenant_id, actor_id, p_audit_event_id, p_provider_id,
      p_account_id, p_request_id, p_correlation_id, p_ip_address,
      p_user_agent, p_authentication_method, p_reason,
      affected_tenant_grant_count
    );
  END LOOP;

  PERFORM app.append_platform_audit_event(
    p_audit_event_id, 'user', actor_id,
    'platform.identity_account.retired', 'platform_identity_account',
    p_account_id, p_request_id, p_correlation_id, p_ip_address, p_user_agent,
    p_authentication_method, 'success', p_reason,
    jsonb_build_object(
      'provider_id', p_provider_id,
      'user_id', identity_record.user_id,
      'previous_version', identity_record.resource_version,
      'version', identity_record.resource_version + 1,
      'user_version', user_record.version,
      'previous_security_revision', identity_record.version,
      'security_revision', identity_record.version + 1,
      'affected_tenant_count', cardinality(affected_tenant_ids),
      'ended_access_grant_count', ended_grant_count,
      'revoked_session_count', revoked_session_count,
      'revoked_continuation_count', revoked_continuation_count,
      'subject_material_included', false
    )
  );
  account_document := app.private_platform_identity_account_document_v1(
    p_provider_id, p_account_id
  );
  RETURN QUERY SELECT p_account_id, identity_record.resource_version + 1,
    account_document;
END;
$function$;
--> statement-breakpoint

ALTER FUNCTION app.guard_platform_federated_external_identity_v3()
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.guard_user_platform_identity_projection_v1()
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_platform_identity_account_document_v1(uuid, uuid)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.retire_platform_identity_account_v2(
  uuid, uuid, uuid, bigint, bigint, uuid, uuid, uuid, inet, text, text, text
) OWNER TO periapsis_migrator;
--> statement-breakpoint

REVOKE ALL ON FUNCTION
  app.guard_platform_federated_external_identity_v3(),
  app.guard_user_platform_identity_projection_v1(),
  app.private_platform_identity_account_document_v1(uuid, uuid),
  app.retire_platform_identity_account_v1(
    uuid, uuid, uuid, bigint, uuid, uuid, uuid, inet, text, text, text
  ),
  app.retire_platform_identity_account_v2(
    uuid, uuid, uuid, bigint, bigint, uuid, uuid, uuid, inet, text, text, text
  )
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner, periapsis_sla_api_owner,
  periapsis_sla_worker_owner, periapsis_sla_readiness_owner,
  periapsis_ticket_saved_view_owner, periapsis_ticket_attribution_owner,
  periapsis_ticket_sla_projection_owner;
--> statement-breakpoint

GRANT EXECUTE ON FUNCTION app.retire_platform_identity_account_v2(
  uuid, uuid, uuid, bigint, bigint, uuid, uuid, uuid, inet, text, text, text
) TO periapsis_api;
