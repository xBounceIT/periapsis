-- Lease/fence upgrade for the LDAP sync worker. No raw directory value is
-- persisted: claim receipts and observations remain digest-only.
DO $identity_sync_lease_upgrade$
DECLARE
  legacy_run record;
  legacy_audit_id uuid;
BEGIN
  FOR legacy_run IN
    SELECT run.*
    FROM public.tenant_ldap_sync_runs AS run
    WHERE run.status IN ('enumerating', 'applying')
    ORDER BY run.tenant_id, run.id
    FOR UPDATE
  LOOP
    PERFORM set_config('app.tenant_id', legacy_run.tenant_id::text, true);
    legacy_audit_id := uuidv7();
    UPDATE public.tenant_ldap_sync_runs AS run
    SET status = 'stale', failure_category = 'worker_lease_upgrade',
        completed_at = transaction_timestamp(), version = run.version + 1
    WHERE run.tenant_id = legacy_run.tenant_id AND run.id = legacy_run.id;
    PERFORM app.private_append_tenant_ldap_runtime_audit_v1(
      legacy_audit_id, legacy_run.tenant_id,
      'tenant.identity.ldap_sync_stale', 'ldap_sync_run', legacy_run.id,
      legacy_run.request_id, legacy_run.correlation_id, NULL,
      'schema-migration', 'ldap_sync', 'failure', 'worker_lease_upgrade',
      jsonb_build_object(
        'run_id', legacy_run.id, 'provider_id', legacy_run.provider_id,
        'binding_id', legacy_run.binding_id, 'status', 'stale',
        'category', 'worker_lease_upgrade'
      )
    );
  END LOOP;
END;
$identity_sync_lease_upgrade$;--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.guard_tenant_ldap_sync_run_v1()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  exact_claim boolean;
  renewed_claim boolean;
  rotated_claim boolean;
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'tenant LDAP sync runs are append-only'
      USING ERRCODE = '55000';
  END IF;
  IF TG_OP = 'INSERT' THEN
    IF NEW.status <> 'queued' OR NEW.version <> 1 OR NEW.claim_fence <> 0
       OR NEW.claim_id IS NOT NULL OR NEW.claim_receipt_digest IS NOT NULL
       OR NEW.claim_acquired_at IS NOT NULL OR NEW.claim_expires_at IS NOT NULL THEN
      RAISE EXCEPTION 'tenant LDAP sync run must begin unclaimed and queued'
        USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
  END IF;
  IF ROW(
    NEW.id, NEW.tenant_id, NEW.provider_id, NEW.provider_kind,
    NEW.binding_id, NEW.trigger, NEW.provider_version,
    NEW.configuration_version, NEW.binding_version,
    NEW.binding_auth_revision, NEW.binding_access_epoch_id,
    NEW.rule_set_revision, NEW.authorization_revision,
    NEW.bind_secret_id, NEW.bind_secret_version,
    NEW.bind_secret_key_version, NEW.bind_secret_algorithm,
    NEW.endpoint_snapshot_digest, NEW.reason,
    NEW.started_by_membership_id, NEW.request_id, NEW.correlation_id,
    NEW.queued_at
  ) IS DISTINCT FROM ROW(
    OLD.id, OLD.tenant_id, OLD.provider_id, OLD.provider_kind,
    OLD.binding_id, OLD.trigger, OLD.provider_version,
    OLD.configuration_version, OLD.binding_version,
    OLD.binding_auth_revision, OLD.binding_access_epoch_id,
    OLD.rule_set_revision, OLD.authorization_revision,
    OLD.bind_secret_id, OLD.bind_secret_version,
    OLD.bind_secret_key_version, OLD.bind_secret_algorithm,
    OLD.endpoint_snapshot_digest, OLD.reason,
    OLD.started_by_membership_id, OLD.request_id, OLD.correlation_id,
    OLD.queued_at
  ) THEN
    RAISE EXCEPTION 'tenant LDAP sync run pins are immutable'
      USING ERRCODE = '55000';
  END IF;
  IF OLD.status IN ('succeeded', 'failed', 'cancelled', 'stale') THEN
    RAISE EXCEPTION 'terminal tenant LDAP sync run cannot change'
      USING ERRCODE = '55000';
  END IF;

  exact_claim := ROW(
    NEW.claim_id, NEW.claim_receipt_digest, NEW.claim_fence,
    NEW.claim_acquired_at, NEW.claim_expires_at
  ) IS NOT DISTINCT FROM ROW(
    OLD.claim_id, OLD.claim_receipt_digest, OLD.claim_fence,
    OLD.claim_acquired_at, OLD.claim_expires_at
  );
  renewed_claim := OLD.claim_fence > 0
    AND NEW.claim_id IS NOT DISTINCT FROM OLD.claim_id
    AND NEW.claim_receipt_digest IS NOT DISTINCT FROM OLD.claim_receipt_digest
    AND NEW.claim_fence = OLD.claim_fence
    AND NEW.claim_acquired_at IS NOT DISTINCT FROM OLD.claim_acquired_at
    AND NEW.claim_expires_at >= OLD.claim_expires_at;
  rotated_claim := NEW.claim_id IS NOT NULL
    AND (uuid_extract_version(NEW.claim_id) = 7) IS TRUE
    AND octet_length(NEW.claim_receipt_digest) = 32
    AND NEW.claim_fence = OLD.claim_fence + 1
    AND NEW.claim_acquired_at IS NOT NULL
    AND NEW.claim_expires_at > NEW.claim_acquired_at;

  IF OLD.status = 'queued' AND NEW.status = 'enumerating' THEN
    IF NEW.version <> OLD.version + 1 OR NOT rotated_claim THEN
      RAISE EXCEPTION 'tenant LDAP sync initial claim is invalid'
        USING ERRCODE = '55000';
    END IF;
  ELSIF OLD.status = NEW.status
        AND OLD.status IN ('enumerating', 'applying') THEN
    IF NEW.version <> OLD.version
       OR NOT (renewed_claim OR rotated_claim OR exact_claim) THEN
      RAISE EXCEPTION 'tenant LDAP sync live claim transition is invalid'
        USING ERRCODE = '55000';
    END IF;
  ELSIF OLD.status = 'queued'
        AND NEW.status IN ('failed', 'cancelled', 'stale') THEN
    IF NEW.version <> OLD.version + 1 OR NOT exact_claim THEN
      RAISE EXCEPTION 'tenant LDAP sync queued terminal transition is invalid'
        USING ERRCODE = '55000';
    END IF;
  ELSIF OLD.status = 'enumerating'
        AND NEW.status IN ('applying', 'failed', 'cancelled', 'stale') THEN
    IF NEW.version <> OLD.version + 1 OR NOT exact_claim THEN
      RAISE EXCEPTION 'tenant LDAP sync enumeration transition is invalid'
        USING ERRCODE = '55000';
    END IF;
  ELSIF OLD.status = 'applying'
        AND NEW.status IN ('succeeded', 'failed', 'cancelled', 'stale') THEN
    IF NEW.version <> OLD.version + 1 OR NOT exact_claim THEN
      RAISE EXCEPTION 'tenant LDAP sync application transition is invalid'
        USING ERRCODE = '55000';
    END IF;
  ELSE
    RAISE EXCEPTION 'tenant LDAP sync run transition is invalid'
      USING ERRCODE = '55000';
  END IF;
  RETURN NEW;
END;
$function$;--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.private_append_tenant_ldap_runtime_audit_v1(
  p_event_id uuid,
  p_tenant_id uuid,
  p_action text,
  p_resource_type text,
  p_resource_id uuid,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text,
  p_outcome public.audit_outcome,
  p_reason text,
  p_metadata jsonb
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  safe_metadata jsonb := coalesce(p_metadata, '{}'::jsonb);
BEGIN
  IF p_tenant_id IS DISTINCT FROM app.context_tenant_id()
     OR p_action NOT IN (
       'tenant.identity.ldap_plan_applied',
       'tenant.identity.ldap_plan_denied',
       'tenant.identity.ldap_jit_started',
       'tenant.identity.ldap_jit_failed',
       'tenant.identity.ldap_jit_stale',
       'tenant.identity.ldap_jit_expired',
       'tenant.identity.ldap_sync_queued',
       'tenant.identity.ldap_sync_claimed',
       'tenant.identity.ldap_sync_reclaimed',
       'tenant.identity.ldap_sync_stale',
       'tenant.identity.ldap_sync_failed',
       'tenant.identity.ldap_sync_cancelled',
       'tenant.identity.ldap_sync_enumeration_completed',
       'tenant.identity.ldap_sync_completed',
       'tenant.identity.ldap_sync_absence_applied'
     )
     OR p_resource_type NOT IN (
       'ldap_identity_plan_application', 'ldap_jit_authentication_run',
       'ldap_sync_run'
     )
     OR p_authentication_method NOT IN ('ldap', 'ldap_sync')
     OR p_user_agent IS NULL OR length(p_user_agent) NOT BETWEEN 1 AND 1024
     OR octet_length(convert_to(safe_metadata::text, 'UTF8')) > 8192
     OR safe_metadata::text ~* (
       'subject|ciphertext|nonce|password|secret|bind_dn|distinguished_name|'
       'directory_value|profile|email|username|first_name|last_name|display_name|'
       'filter|cursor'
     )
     OR (p_reason IS NOT NULL AND (
       btrim(p_reason) = '' OR char_length(p_reason) > 500
       OR p_reason ~ '[[:cntrl:]]'
     )) THEN
    RAISE EXCEPTION 'LDAP runtime audit input is unsafe'
      USING ERRCODE = '22023';
  END IF;
  INSERT INTO public.audit_events (
    id, tenant_id, sequence, actor_type, action, resource_type, resource_id,
    request_id, correlation_id, ip_address, user_agent,
    authentication_method, outcome, reason, metadata
  ) VALUES (
    p_event_id, p_tenant_id, 0, 'system', p_action, p_resource_type,
    p_resource_id, p_request_id, p_correlation_id, p_ip_address,
    p_user_agent, p_authentication_method, p_outcome, p_reason, safe_metadata
  );
END;
$function$;--> statement-breakpoint

CREATE FUNCTION app.stage_tenant_ldap_sync_observation_v2(
  p_sync_run_id uuid,
  p_claim_id uuid,
  p_claim_receipt_digest bytea,
  p_claim_fence bigint,
  p_observation_id uuid,
  p_ordinal integer,
  p_digest_key_version integer,
  p_subject_digest bytea,
  p_observation_digest bytea
)
RETURNS uuid
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  PERFORM app.private_lock_tenant_ldap_sync_claim_v2(
    p_sync_run_id, p_claim_id, p_claim_receipt_digest, p_claim_fence, false
  );
  RETURN app.stage_tenant_ldap_sync_observation_v1(
    p_sync_run_id, p_observation_id, p_ordinal, p_digest_key_version,
    p_subject_digest, p_observation_digest
  );
END;
$function$;--> statement-breakpoint

CREATE FUNCTION app.complete_tenant_ldap_sync_enumeration_v2(
  p_sync_run_id uuid,
  p_claim_id uuid,
  p_claim_receipt_digest bytea,
  p_claim_fence bigint,
  p_expected_version integer,
  p_enumeration_complete boolean,
  p_result_truncated boolean,
  p_cursor_digest bytea,
  p_failure_category text,
  p_audit_event_id uuid,
  p_request_id uuid,
  p_correlation_id uuid,
  p_user_agent text
)
RETURNS TABLE (
  status public.ldap_sync_run_status,
  version integer,
  observed_count integer,
  absence_allowed boolean
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  PERFORM app.private_lock_tenant_ldap_sync_claim_v2(
    p_sync_run_id, p_claim_id, p_claim_receipt_digest, p_claim_fence, true
  );
  RETURN QUERY SELECT * FROM app.complete_tenant_ldap_sync_enumeration_v1(
    p_sync_run_id, p_expected_version, p_enumeration_complete,
    p_result_truncated, p_cursor_digest, p_failure_category,
    p_audit_event_id, p_request_id, p_correlation_id, p_user_agent
  );
END;
$function$;--> statement-breakpoint

CREATE FUNCTION app.apply_tenant_ldap_sync_identity_plan_v2(
  p_sync_run_id uuid,
  p_sync_observation_id uuid,
  p_claim_id uuid,
  p_claim_receipt_digest bytea,
  p_claim_fence bigint,
  p_application_id uuid,
  p_plan_digest bytea,
  p_binding_id uuid,
  p_provider_version integer,
  p_configuration_version integer,
  p_binding_version integer,
  p_binding_auth_revision integer,
  p_access_epoch_id uuid,
  p_rule_set_revision bigint,
  p_authorization_revision bigint,
  p_decision public.ldap_identity_apply_decision,
  p_denial_category text,
  p_external_identity_id uuid,
  p_user_id uuid,
  p_membership_id uuid,
  p_access_grant_id uuid,
  p_profile_contribution_id uuid,
  p_subject_format public.identity_subject_format,
  p_subject_ciphertext bytea,
  p_subject_nonce bytea,
  p_subject_key_version integer,
  p_alias_ids uuid[],
  p_alias_key_versions integer[],
  p_alias_digests bytea[],
  p_display_name text,
  p_first_name text,
  p_last_name text,
  p_username text,
  p_email text,
  p_matched_mapping_epoch_ids uuid[],
  p_observed_at timestamptz,
  p_audit_event_id uuid,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text
)
RETURNS TABLE (
  application_id uuid,
  decision public.ldap_identity_apply_decision,
  external_identity_id uuid,
  user_id uuid,
  membership_id uuid,
  access_grant_id uuid,
  ensured_edge_count integer,
  revoked_edge_count integer,
  replayed boolean
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid;
BEGIN
  context_tenant := app.private_lock_tenant_ldap_sync_claim_v2(
    p_sync_run_id, p_claim_id, p_claim_receipt_digest, p_claim_fence, false
  );
  IF NOT EXISTS (
    SELECT 1
    FROM public.tenant_ldap_sync_staged_observations AS observation
    WHERE observation.tenant_id = context_tenant
      AND observation.sync_run_id = p_sync_run_id
      AND observation.id = p_sync_observation_id
      AND observation.planning_fence = p_claim_fence
      AND observation.observation_digest = p_plan_digest
  ) THEN
    RAISE EXCEPTION 'LDAP sync plan was not claimed by the current fence'
      USING ERRCODE = '40001';
  END IF;
  RETURN QUERY SELECT * FROM app.apply_tenant_ldap_identity_plan_v1(
    p_application_id, p_plan_digest, 'sync', p_sync_run_id,
    p_sync_observation_id, p_binding_id, p_provider_version,
    p_configuration_version, p_binding_version, p_binding_auth_revision,
    p_access_epoch_id, p_rule_set_revision, p_authorization_revision,
    p_decision, p_denial_category, p_external_identity_id, p_user_id,
    p_membership_id, p_access_grant_id, p_profile_contribution_id,
    p_subject_format, p_subject_ciphertext, p_subject_nonce,
    p_subject_key_version, p_alias_ids, p_alias_key_versions,
    p_alias_digests, p_display_name, p_first_name, p_last_name,
    p_username, p_email, p_matched_mapping_epoch_ids, p_observed_at,
    p_audit_event_id, p_request_id, p_correlation_id, p_ip_address,
    p_user_agent
  );
END;
$function$;--> statement-breakpoint

CREATE FUNCTION app.apply_tenant_ldap_sync_absence_chunk_v2(
  p_sync_run_id uuid,
  p_claim_id uuid,
  p_claim_receipt_digest bytea,
  p_claim_fence bigint,
  p_limit integer,
  p_audit_event_id uuid,
  p_request_id uuid,
  p_correlation_id uuid,
  p_user_agent text
)
RETURNS TABLE (
  inspected_count integer,
  revoked_count integer,
  remaining_count integer
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  PERFORM app.private_lock_tenant_ldap_sync_claim_v2(
    p_sync_run_id, p_claim_id, p_claim_receipt_digest, p_claim_fence, true
  );
  RETURN QUERY SELECT * FROM app.apply_tenant_ldap_sync_absence_chunk_v1(
    p_sync_run_id, p_limit, p_audit_event_id, p_request_id,
    p_correlation_id, p_user_agent
  );
END;
$function$;--> statement-breakpoint

CREATE FUNCTION app.complete_tenant_ldap_sync_run_v2(
  p_sync_run_id uuid,
  p_claim_id uuid,
  p_claim_receipt_digest bytea,
  p_claim_fence bigint,
  p_expected_version integer,
  p_audit_event_id uuid,
  p_request_id uuid,
  p_correlation_id uuid,
  p_user_agent text
)
RETURNS integer
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  PERFORM app.private_lock_tenant_ldap_sync_claim_v2(
    p_sync_run_id, p_claim_id, p_claim_receipt_digest, p_claim_fence, true
  );
  RETURN app.complete_tenant_ldap_sync_run_v1(
    p_sync_run_id, p_expected_version, p_audit_event_id, p_request_id,
    p_correlation_id, p_user_agent
  );
END;
$function$;--> statement-breakpoint

CREATE FUNCTION app.fail_tenant_ldap_sync_run_v2(
  p_sync_run_id uuid,
  p_claim_id uuid,
  p_claim_receipt_digest bytea,
  p_claim_fence bigint,
  p_expected_version integer,
  p_failure_category text,
  p_audit_event_id uuid,
  p_request_id uuid,
  p_correlation_id uuid,
  p_user_agent text
)
RETURNS TABLE (
  status public.ldap_sync_run_status,
  version integer,
  replayed boolean
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  PERFORM app.private_lock_tenant_ldap_sync_claim_v2(
    p_sync_run_id, p_claim_id, p_claim_receipt_digest, p_claim_fence, true
  );
  RETURN QUERY SELECT * FROM app.fail_tenant_ldap_sync_run_v1(
    p_sync_run_id, p_expected_version, p_failure_category,
    p_audit_event_id, p_request_id, p_correlation_id, p_user_agent
  );
END;
$function$;--> statement-breakpoint

CREATE FUNCTION app.claim_next_tenant_ldap_sync_run_v2(
  p_claim_id uuid,
  p_claim_receipt_digest bytea,
  p_lease_seconds integer,
  p_user_agent text
)
RETURNS TABLE (
  sync_run_id uuid,
  tenant_id uuid,
  claim_id uuid,
  claim_fence bigint,
  claim_expires_at timestamptz,
  run_status public.ldap_sync_run_status,
  run_version integer,
  provider_id uuid,
  provider_version integer,
  configuration_version integer,
  endpoint_snapshot_digest bytea,
  configuration jsonb,
  endpoints jsonb,
  bind_secret_id uuid,
  bind_secret_ciphertext bytea,
  bind_secret_nonce bytea,
  bind_secret_version integer,
  bind_secret_key_version integer,
  bind_secret_algorithm text,
  binding_id uuid,
  binding_version integer,
  binding_auth_revision integer,
  binding_access_epoch_id uuid,
  rule_set_revision bigint,
  authorization_revision bigint,
  mapping_revisions jsonb,
  staged_observations jsonb,
  queued_at timestamptz,
  enumeration_started_at timestamptz
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  locked_run public.tenant_ldap_sync_runs%ROWTYPE;
  candidate_number integer;
  stale_audit_event_id uuid;
  claim_was_replayed boolean := false;
  claim_action text;
BEGIN
  IF p_claim_id IS NULL OR (uuid_extract_version(p_claim_id) = 7) IS NOT TRUE
     OR p_claim_receipt_digest IS NULL
     OR octet_length(p_claim_receipt_digest) <> 32
     OR p_lease_seconds NOT BETWEEN 1 AND 600
     OR p_user_agent IS NULL OR length(p_user_agent) NOT BETWEEN 1 AND 1024 THEN
    RAISE EXCEPTION 'LDAP sync worker claim input is invalid'
      USING ERRCODE = '22023';
  END IF;

  -- The same opaque proof can recover a committed response that the worker
  -- did not receive. It may renew its lease but never changes its fence.
  SELECT run.* INTO locked_run
  FROM public.tenant_ldap_sync_runs AS run
  WHERE run.claim_id = p_claim_id
  FOR UPDATE;
  IF FOUND THEN
    IF locked_run.claim_receipt_digest IS DISTINCT FROM p_claim_receipt_digest
       OR locked_run.status NOT IN ('enumerating', 'applying') THEN
      RETURN;
    END IF;
    UPDATE public.tenant_ldap_sync_runs AS run
    SET claim_expires_at = greatest(
      run.claim_expires_at,
      transaction_timestamp() + make_interval(secs => p_lease_seconds)
    )
    WHERE run.tenant_id = locked_run.tenant_id AND run.id = locked_run.id
    RETURNING run.* INTO locked_run;
    claim_was_replayed := true;
  ELSIF EXISTS (
    SELECT 1 FROM public.audit_events AS audit WHERE audit.id = p_claim_id
  ) THEN
    -- Claim IDs are one-time UUIDv7 values even after their run is terminal.
    RETURN;
  END IF;

  IF NOT claim_was_replayed THEN
    -- A bounded loop retires stale queue/lease heads without letting one
    -- poisoned binding starve every tenant.
    FOR candidate_number IN 1..32 LOOP
      SELECT run.* INTO locked_run
      FROM public.tenant_ldap_sync_runs AS run
      WHERE run.status = 'queued'
         OR (run.status IN ('enumerating', 'applying')
           AND run.claim_expires_at <= transaction_timestamp())
      ORDER BY CASE WHEN run.status = 'queued' THEN 0 ELSE 1 END,
               run.queued_at, run.id
      LIMIT 1
      FOR UPDATE SKIP LOCKED;
      IF NOT FOUND THEN RETURN; END IF;
      PERFORM set_config('app.tenant_id', locked_run.tenant_id::text, true);

      IF NOT app.private_tenant_ldap_sync_run_is_current_v1(
        locked_run.tenant_id, locked_run.id
      ) THEN
        stale_audit_event_id := uuidv7();
        UPDATE public.tenant_ldap_sync_runs AS run
        SET status = 'stale', failure_category = 'stale_configuration',
            completed_at = transaction_timestamp(), version = run.version + 1
        WHERE run.tenant_id = locked_run.tenant_id AND run.id = locked_run.id;
        PERFORM app.private_append_tenant_ldap_runtime_audit_v1(
          stale_audit_event_id, locked_run.tenant_id,
          'tenant.identity.ldap_sync_stale', 'ldap_sync_run', locked_run.id,
          locked_run.request_id, locked_run.correlation_id, NULL,
          p_user_agent, 'ldap_sync', 'failure', 'stale_configuration',
          jsonb_build_object(
            'run_id', locked_run.id, 'provider_id', locked_run.provider_id,
            'binding_id', locked_run.binding_id, 'status', 'stale',
            'category', 'stale_configuration'
          )
        );
        CONTINUE;
      END IF;

      claim_action := CASE WHEN locked_run.status = 'queued'
        THEN 'tenant.identity.ldap_sync_claimed'
        ELSE 'tenant.identity.ldap_sync_reclaimed' END;
      UPDATE public.tenant_ldap_sync_runs AS run
      SET status = CASE WHEN run.status = 'queued'
            THEN 'enumerating'::public.ldap_sync_run_status ELSE run.status END,
          enumeration_started_at = CASE WHEN run.status = 'queued'
            THEN transaction_timestamp() ELSE run.enumeration_started_at END,
          version = CASE WHEN run.status = 'queued'
            THEN run.version + 1 ELSE run.version END,
          claim_id = p_claim_id,
          claim_receipt_digest = p_claim_receipt_digest,
          claim_fence = run.claim_fence + 1,
          claim_acquired_at = transaction_timestamp(),
          claim_expires_at = transaction_timestamp()
            + make_interval(secs => p_lease_seconds)
      WHERE run.tenant_id = locked_run.tenant_id AND run.id = locked_run.id
      RETURNING run.* INTO locked_run;
      PERFORM app.private_append_tenant_ldap_runtime_audit_v1(
        p_claim_id, locked_run.tenant_id, claim_action, 'ldap_sync_run',
        locked_run.id, locked_run.request_id, locked_run.correlation_id, NULL,
        p_user_agent, 'ldap_sync', 'success', NULL,
        jsonb_build_object(
          'run_id', locked_run.id, 'provider_id', locked_run.provider_id,
          'binding_id', locked_run.binding_id, 'status', locked_run.status,
          'claim_fence', locked_run.claim_fence,
          'lease_seconds', p_lease_seconds
        )
      );
      EXIT;
    END LOOP;
  END IF;

  PERFORM set_config('app.tenant_id', locked_run.tenant_id::text, true);
  RETURN QUERY
  SELECT locked_run.id, locked_run.tenant_id, locked_run.claim_id,
         locked_run.claim_fence, locked_run.claim_expires_at,
         locked_run.status, locked_run.version, locked_run.provider_id,
         locked_run.provider_version, locked_run.configuration_version,
         locked_run.endpoint_snapshot_digest,
         jsonb_build_object(
           'template', configuration.template,
           'verifyCertificate', configuration.verify_certificate,
           'customCaPem', configuration.custom_ca_pem,
           'connectTimeoutMs', configuration.connect_timeout_ms,
           'operationTimeoutMs', configuration.operation_timeout_ms,
           'bindDn', configuration.bind_dn,
           'userBaseDn', configuration.user_base_dn,
           'groupBaseDn', configuration.group_base_dn,
           'userSearchFilter', configuration.user_search_filter,
           'groupSearchFilter', configuration.group_search_filter,
           'pageSize', configuration.page_size,
           'maxPages', configuration.max_pages,
           'maxEntries', configuration.max_entries,
           'maxResponseBytes', configuration.max_response_bytes,
           'referralMode', configuration.referral_mode,
           'maxReferralHops', configuration.max_referral_hops,
           'nestedGroupMode', configuration.nested_group_mode,
           'maxNestedGroupDepth', configuration.max_nested_group_depth,
           'maxGroups', configuration.max_groups,
           'firstNameAttribute', configuration.first_name_attribute,
           'lastNameAttribute', configuration.last_name_attribute,
           'displayNameAttribute', configuration.display_name_attribute,
           'usernameAttribute', configuration.username_attribute,
           'alternateUsernameAttribute', configuration.alternate_username_attribute,
           'emailAttribute', configuration.email_attribute,
           'immutableSubjectAttribute', configuration.immutable_subject_attribute,
           'immutableSubjectFormat', configuration.immutable_subject_format,
           'groupMembershipAttribute', configuration.group_membership_attribute,
           'posixMemberUidAttribute', configuration.posix_member_uid_attribute,
           'posixGidNumberAttribute', configuration.posix_gid_number_attribute,
           'accountStatusMode', configuration.account_status_mode,
           'accountStatusAttribute', configuration.account_status_attribute,
           'accountDisabledValue', configuration.account_disabled_value,
           'jitMode', configuration.jit_mode,
           'noMatchPolicy', configuration.no_match_policy,
           'deprovisionMode', configuration.deprovision_mode,
           'deprovisionGraceSeconds', configuration.deprovision_grace_seconds,
           'syncIntervalSeconds', configuration.sync_interval_seconds
         ), endpoint_snapshot.endpoints,
         secret.id, secret.secret_ciphertext, secret.secret_nonce,
         secret.version, secret.key_version, secret.encryption_algorithm,
         locked_run.binding_id, locked_run.binding_version,
         locked_run.binding_auth_revision, locked_run.binding_access_epoch_id,
         locked_run.rule_set_revision, locked_run.authorization_revision,
         coalesce((
           SELECT jsonb_agg(jsonb_build_object(
             'mappingId', pinned.mapping_rule_id,
             'mappingVersion', pinned.mapping_version,
             'configurationRevision', pinned.configuration_revision,
             'sourceEpochId', pinned.source_epoch_id,
             'sourceId', pinned.source_id,
             'priority', pinned.priority
           ) ORDER BY pinned.priority, pinned.mapping_rule_id)
           FROM public.tenant_ldap_sync_run_mappings AS pinned
           WHERE pinned.tenant_id = locked_run.tenant_id
             AND pinned.sync_run_id = locked_run.id
         ), '[]'::jsonb),
         coalesce((
           SELECT jsonb_agg(jsonb_build_object(
             'observationId', observation.id,
             'ordinal', observation.ordinal,
             'digestKeyVersion', observation.digest_key_version,
             'subjectDigest', encode(observation.subject_digest, 'hex'),
             'observationDigest', encode(observation.observation_digest, 'hex'),
             'externalIdentityId', observation.external_identity_id,
             'planningFence', observation.planning_fence,
             'applied', observation.applied_at IS NOT NULL
           ) ORDER BY observation.ordinal)
           FROM public.tenant_ldap_sync_staged_observations AS observation
           WHERE observation.tenant_id = locked_run.tenant_id
             AND observation.sync_run_id = locked_run.id
         ), '[]'::jsonb), locked_run.queued_at,
         locked_run.enumeration_started_at
  FROM public.tenant_ldap_provider_configs AS configuration
  JOIN public.tenant_ldap_provider_secrets AS secret
    ON secret.tenant_id = configuration.tenant_id
   AND secret.provider_id = configuration.provider_id
   AND secret.id = locked_run.bind_secret_id
   AND secret.version = locked_run.bind_secret_version
   AND secret.key_version = locked_run.bind_secret_key_version
   AND secret.encryption_algorithm = locked_run.bind_secret_algorithm
  CROSS JOIN LATERAL app.private_tenant_ldap_endpoint_snapshot_v1(
    locked_run.tenant_id, locked_run.provider_id
  ) AS endpoint_snapshot
  WHERE configuration.tenant_id = locked_run.tenant_id
    AND configuration.provider_id = locked_run.provider_id
    AND configuration.version = locked_run.configuration_version
    AND endpoint_snapshot.endpoint_digest = locked_run.endpoint_snapshot_digest;
END;
$function$;--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.guard_tenant_ldap_sync_staged_observation_v1()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  run_record public.tenant_ldap_sync_runs%ROWTYPE;
  immutable_shape boolean;
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'tenant LDAP sync observations are append-only'
      USING ERRCODE = '55000';
  END IF;
  SELECT run.* INTO run_record
  FROM public.tenant_ldap_sync_runs AS run
  WHERE run.tenant_id = coalesce(NEW.tenant_id, OLD.tenant_id)
    AND run.id = coalesce(NEW.sync_run_id, OLD.sync_run_id);
  IF TG_OP = 'INSERT' THEN
    IF run_record.status IS DISTINCT FROM 'enumerating'
       OR NEW.planning_fence IS NOT NULL
       OR NEW.planning_claimed_at IS NOT NULL THEN
      RAISE EXCEPTION 'tenant LDAP observation requires an enumerating run'
        USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
  END IF;
  immutable_shape := ROW(
    NEW.id, NEW.tenant_id, NEW.sync_run_id, NEW.provider_id,
    NEW.ordinal, NEW.digest_key_version, NEW.subject_digest,
    NEW.observation_digest, NEW.staged_at
  ) IS NOT DISTINCT FROM ROW(
    OLD.id, OLD.tenant_id, OLD.sync_run_id, OLD.provider_id,
    OLD.ordinal, OLD.digest_key_version, OLD.subject_digest,
    OLD.observation_digest, OLD.staged_at
  );
  IF NOT immutable_shape THEN
    RAISE EXCEPTION 'tenant LDAP observation immutable shape changed'
      USING ERRCODE = '55000';
  END IF;
  IF run_record.status IN ('enumerating', 'applying')
     AND NEW.planning_fence = run_record.claim_fence
     AND NEW.planning_claimed_at >= NEW.staged_at
     AND NEW.external_identity_id IS NOT DISTINCT FROM OLD.external_identity_id
     AND NEW.applied_at IS NOT DISTINCT FROM OLD.applied_at
     AND NEW.apply_attempt = OLD.apply_attempt THEN
    RETURN NEW;
  END IF;
  IF run_record.status = 'applying'
     AND NEW.planning_fence IS NOT DISTINCT FROM OLD.planning_fence
     AND NEW.planning_claimed_at IS NOT DISTINCT FROM OLD.planning_claimed_at
     AND OLD.applied_at IS NULL AND NEW.applied_at IS NOT NULL
     AND NEW.apply_attempt = OLD.apply_attempt + 1 THEN
    RETURN NEW;
  END IF;
  RAISE EXCEPTION 'tenant LDAP observation transition is invalid'
    USING ERRCODE = '55000';
END;
$function$;--> statement-breakpoint

CREATE FUNCTION app.private_lock_tenant_ldap_sync_claim_v2(
  p_sync_run_id uuid,
  p_claim_id uuid,
  p_claim_receipt_digest bytea,
  p_claim_fence bigint,
  p_allow_terminal boolean DEFAULT false
)
RETURNS uuid
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  locked_run public.tenant_ldap_sync_runs%ROWTYPE;
BEGIN
  IF p_sync_run_id IS NULL OR p_claim_id IS NULL
     OR (uuid_extract_version(p_claim_id) = 7) IS NOT TRUE
     OR p_claim_receipt_digest IS NULL
     OR octet_length(p_claim_receipt_digest) <> 32
     OR p_claim_fence IS NULL OR p_claim_fence < 1 THEN
    RAISE EXCEPTION 'LDAP sync claim proof is invalid'
      USING ERRCODE = '22023';
  END IF;
  SELECT run.* INTO locked_run
  FROM public.tenant_ldap_sync_runs AS run
  WHERE run.id = p_sync_run_id AND run.claim_id = p_claim_id
    AND run.claim_receipt_digest = p_claim_receipt_digest
    AND run.claim_fence = p_claim_fence
  FOR UPDATE;
  IF NOT FOUND
     OR (locked_run.status IN ('queued', 'enumerating', 'applying')
       AND (locked_run.status = 'queued'
         OR locked_run.claim_expires_at <= transaction_timestamp()))
     OR (locked_run.status IN ('succeeded', 'failed', 'cancelled', 'stale')
       AND NOT p_allow_terminal) THEN
    RAISE EXCEPTION 'LDAP sync claim is unavailable'
      USING ERRCODE = '40001';
  END IF;
  PERFORM set_config('app.tenant_id', locked_run.tenant_id::text, true);
  RETURN locked_run.tenant_id;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION app.claim_tenant_ldap_sync_observation_planning_v2(
  p_sync_run_id uuid,
  p_observation_id uuid,
  p_claim_id uuid,
  p_claim_receipt_digest bytea,
  p_claim_fence bigint,
  p_digest_key_versions integer[],
  p_subject_digests bytea[]
)
RETURNS TABLE (
  sync_run_id uuid,
  observation_id uuid,
  tenant_id uuid,
  claim_fence bigint,
  provider_id uuid,
  provider_version integer,
  binding_id uuid,
  binding_version integer,
  binding_auth_revision integer,
  binding_access_epoch_id uuid,
  configuration_revision integer,
  rule_set_revision bigint,
  authorization_revision bigint,
  jit_mode public.identity_jit_mode,
  no_match_policy public.identity_no_match_policy,
  provider_access_source_id uuid,
  external_identity_id uuid,
  user_id uuid,
  membership_id uuid,
  external_identity_exists boolean,
  user_active boolean,
  tenant_membership_exists boolean,
  tenant_membership_active boolean,
  access_grant_live boolean,
  rules jsonb,
  security_groups jsonb,
  live_assignments jsonb,
  role_policies jsonb,
  existing_effective_role_ids uuid[],
  delegation jsonb,
  live_owned_edges jsonb
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid;
  locked_run public.tenant_ldap_sync_runs%ROWTYPE;
  locked_observation public.tenant_ldap_sync_staged_observations%ROWTYPE;
  digest_count integer := coalesce(array_length(p_digest_key_versions, 1), 0);
  digest_index integer;
  found_identity_ids uuid[];
  found_user_ids uuid[];
  found_identity_id uuid;
  found_user_id uuid;
  found_membership_id uuid;
  found_user_active boolean := false;
  found_membership_active boolean := false;
  current_access_source_id uuid;
  live_access boolean := false;
BEGIN
  context_tenant := app.private_lock_tenant_ldap_sync_claim_v2(
    p_sync_run_id, p_claim_id, p_claim_receipt_digest, p_claim_fence, false
  );
  IF p_observation_id IS NULL OR digest_count < 1 OR digest_count > 16
     OR coalesce(array_length(p_subject_digests, 1), 0) <> digest_count
     OR coalesce(array_ndims(p_digest_key_versions), 0) <> 1
     OR coalesce(array_ndims(p_subject_digests), 0) <> 1
     OR array_lower(p_digest_key_versions, 1) <> 1
     OR array_lower(p_subject_digests, 1) <> 1 THEN
    RAISE EXCEPTION 'LDAP sync planning input is invalid'
      USING ERRCODE = '22023';
  END IF;
  FOR digest_index IN 1..digest_count LOOP
    IF p_digest_key_versions[digest_index] IS NULL
       OR p_digest_key_versions[digest_index] NOT BETWEEN 1 AND 32767
       OR p_subject_digests[digest_index] IS NULL
       OR octet_length(p_subject_digests[digest_index]) <> 32
       OR (digest_index > 1 AND p_digest_key_versions[digest_index - 1]
           >= p_digest_key_versions[digest_index])
       OR NOT EXISTS (
         SELECT 1 FROM public.identity_keyring_versions AS keyring
         WHERE keyring.key_version = p_digest_key_versions[digest_index]
           AND keyring.retired_at IS NULL
       ) THEN
      RAISE EXCEPTION 'LDAP sync immutable-subject digest lookup is invalid'
        USING ERRCODE = '22023';
    END IF;
  END LOOP;

  SELECT run.* INTO locked_run
  FROM public.tenant_ldap_sync_runs AS run
  WHERE run.tenant_id = context_tenant AND run.id = p_sync_run_id;
  SELECT observation.* INTO locked_observation
  FROM public.tenant_ldap_sync_staged_observations AS observation
  WHERE observation.tenant_id = context_tenant
    AND observation.sync_run_id = p_sync_run_id
    AND observation.id = p_observation_id
  FOR UPDATE;
  IF NOT FOUND OR locked_run.status NOT IN ('enumerating', 'applying')
     OR locked_observation.applied_at IS NOT NULL
     OR NOT EXISTS (
       SELECT 1
       FROM unnest(p_digest_key_versions, p_subject_digests)
            AS lookup(key_version, subject_digest)
       WHERE lookup.key_version = locked_observation.digest_key_version
         AND lookup.subject_digest = locked_observation.subject_digest
     ) OR NOT app.private_tenant_ldap_sync_run_is_current_v1(
       context_tenant, p_sync_run_id
     ) THEN
    RAISE EXCEPTION 'LDAP sync planning claim is stale or unavailable'
      USING ERRCODE = '40001';
  END IF;
  IF EXISTS (
    SELECT 1
    FROM public.tenant_ldap_sync_run_mappings AS pinned
    JOIN public.tenant_ldap_mapping_rule_epochs AS epoch
      ON epoch.tenant_id = pinned.tenant_id
     AND epoch.id = pinned.source_epoch_id
    LEFT JOIN public.tenant_ldap_mapping_rule_role_targets AS target
      ON target.tenant_id = epoch.tenant_id
     AND target.mapping_rule_id = epoch.mapping_rule_id
     AND target.configuration_revision = epoch.configuration_revision
    LEFT JOIN public.tenant_roles AS role
      ON role.tenant_id = target.tenant_id AND role.id = target.role_id
    LEFT JOIN public.tenant_role_permissions AS policy
      ON policy.tenant_id = role.tenant_id AND policy.role_id = role.id
     AND policy.scope = 'platform'
    WHERE pinned.tenant_id = context_tenant
      AND pinned.sync_run_id = p_sync_run_id
      AND target.role_id IS NOT NULL
      AND (role.id IS NULL OR role.principal_kind <> 'human'
        OR role.archived_at IS NOT NULL OR role.key = 'platform_super_admin'
        OR policy.role_id IS NOT NULL)
  ) THEN
    RAISE EXCEPTION 'LDAP sync planning target is forbidden'
      USING ERRCODE = '42501';
  END IF;

  UPDATE public.tenant_ldap_sync_staged_observations AS observation
  SET planning_fence = p_claim_fence,
      planning_claimed_at = transaction_timestamp()
  WHERE observation.tenant_id = context_tenant
    AND observation.sync_run_id = p_sync_run_id
    AND observation.id = p_observation_id
    AND observation.planning_fence IS DISTINCT FROM p_claim_fence;

  SELECT array_agg(DISTINCT identity.id ORDER BY identity.id),
         array_agg(DISTINCT identity.user_id ORDER BY identity.user_id)
  INTO found_identity_ids, found_user_ids
  FROM unnest(p_digest_key_versions, p_subject_digests)
       AS lookup(key_version, subject_digest)
  JOIN public.tenant_ldap_external_identity_subject_aliases AS alias
    ON alias.tenant_id = context_tenant
   AND alias.provider_id = locked_run.provider_id
   AND alias.digest_key_version = lookup.key_version
   AND alias.subject_digest = lookup.subject_digest
   AND alias.retired_at IS NULL
  JOIN public.tenant_ldap_external_identities AS identity
    ON identity.tenant_id = alias.tenant_id
   AND identity.provider_id = alias.provider_id
   AND identity.id = alias.external_identity_id
   AND identity.retired_at IS NULL;
  IF coalesce(cardinality(found_identity_ids), 0) > 1
     OR coalesce(cardinality(found_user_ids), 0) > 1 THEN
    RAISE EXCEPTION 'LDAP sync immutable-subject aliases disagree'
      USING ERRCODE = '23505';
  END IF;
  found_identity_id := found_identity_ids[1];
  found_user_id := found_user_ids[1];
  IF found_user_id IS NOT NULL THEN
    SELECT local_user.active, membership.id,
           coalesce(membership.status = 'active', false)
    INTO found_user_active, found_membership_id, found_membership_active
    FROM public.users AS local_user
    LEFT JOIN public.tenant_memberships AS membership
      ON membership.tenant_id = context_tenant
     AND membership.user_id = local_user.id
    WHERE local_user.id = found_user_id;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'tenant LDAP external identity user is unavailable'
        USING ERRCODE = '55000';
    END IF;
  END IF;
  SELECT epoch.source_id INTO current_access_source_id
  FROM public.tenant_identity_provider_access_epochs AS epoch
  WHERE epoch.tenant_id = context_tenant
    AND epoch.id = locked_run.binding_access_epoch_id
    AND epoch.binding_id = locked_run.binding_id
    AND epoch.provider_id = locked_run.provider_id
    AND epoch.ended_at IS NULL;
  IF current_access_source_id IS NULL THEN
    RAISE EXCEPTION 'tenant LDAP provider access epoch is unavailable'
      USING ERRCODE = '40001';
  END IF;
  IF found_identity_id IS NOT NULL AND found_user_active
     AND found_membership_id IS NOT NULL AND found_membership_active THEN
    SELECT EXISTS (
      SELECT 1 FROM public.tenant_ldap_provider_access_grants AS access_grant
      WHERE access_grant.tenant_id = context_tenant
        AND access_grant.provider_id = locked_run.provider_id
        AND access_grant.binding_id = locked_run.binding_id
        AND access_grant.access_epoch_id = locked_run.binding_access_epoch_id
        AND access_grant.source_id = current_access_source_id
        AND access_grant.external_identity_id = found_identity_id
        AND access_grant.membership_id = found_membership_id
        AND access_grant.user_id = found_user_id
        AND access_grant.ended_at IS NULL
    ) INTO live_access;
  END IF;

  RETURN QUERY
  WITH selected_rules AS (
    SELECT pinned.mapping_rule_id, pinned.mapping_version,
           pinned.source_epoch_id, pinned.source_id, pinned.priority,
           epoch.configuration_revision, epoch.matcher_type,
           epoch.matcher_value, epoch.case_mode, epoch.reconciliation_mode,
           epoch.tenant_security_group_id AS security_group_id,
           epoch.operator_team_id,
           epoch.operator_team_assignment_epoch_id
    FROM public.tenant_ldap_sync_run_mappings AS pinned
    JOIN public.tenant_ldap_mapping_rule_epochs AS epoch
      ON epoch.tenant_id = pinned.tenant_id
     AND epoch.id = pinned.source_epoch_id
     AND epoch.mapping_rule_id = pinned.mapping_rule_id
     AND epoch.binding_id = pinned.binding_id
     AND epoch.source_id = pinned.source_id
     AND epoch.ended_at IS NULL
    WHERE pinned.tenant_id = context_tenant
      AND pinned.sync_run_id = p_sync_run_id
  ), rule_roles AS (
    SELECT selected.mapping_rule_id,
           coalesce(array_agg(target.role_id ORDER BY target.role_id)
             FILTER (WHERE target.role_id IS NOT NULL), ARRAY[]::uuid[]) AS role_ids
    FROM selected_rules AS selected
    LEFT JOIN public.tenant_ldap_mapping_rule_role_targets AS target
      ON target.tenant_id = context_tenant
     AND target.mapping_rule_id = selected.mapping_rule_id
     AND target.configuration_revision = selected.configuration_revision
    GROUP BY selected.mapping_rule_id
  ), target_groups AS (
    SELECT DISTINCT selected.security_group_id FROM selected_rules AS selected
  ), group_policy_roles AS (
    SELECT target_group.security_group_id,
           coalesce(array_agg(DISTINCT group_grant.role_id
             ORDER BY group_grant.role_id)
             FILTER (WHERE group_role.id IS NOT NULL), ARRAY[]::uuid[]) AS role_ids
    FROM target_groups AS target_group
    JOIN public.tenant_security_groups AS security_group
      ON security_group.tenant_id = context_tenant
     AND security_group.id = target_group.security_group_id
     AND security_group.archived_at IS NULL
    LEFT JOIN public.tenant_security_group_role_grants AS group_grant
      ON group_grant.tenant_id = context_tenant
     AND group_grant.group_id = target_group.security_group_id
     AND group_grant.revoked_at IS NULL
     AND (group_grant.expires_at IS NULL
       OR group_grant.expires_at > transaction_timestamp())
    LEFT JOIN public.tenant_authorization_sources AS group_source
      ON group_source.tenant_id = group_grant.tenant_id
     AND group_source.id = group_grant.source_id
     AND group_source.retired_at IS NULL
    LEFT JOIN public.tenant_roles AS group_role
      ON group_role.tenant_id = group_grant.tenant_id
     AND group_role.id = group_grant.role_id
     AND group_role.principal_kind = 'human'
     AND group_role.key <> 'platform_super_admin'
     AND group_role.archived_at IS NULL
    WHERE group_grant.id IS NULL
       OR (group_source.id IS NOT NULL AND group_role.id IS NOT NULL)
    GROUP BY target_group.security_group_id
  ), effective_role_ids AS (
    SELECT direct_grant.role_id
    FROM public.tenant_membership_role_grants AS direct_grant
    JOIN public.tenant_authorization_sources AS source
      ON source.tenant_id = direct_grant.tenant_id
     AND source.id = direct_grant.source_id AND source.retired_at IS NULL
    JOIN public.tenant_roles AS role
      ON role.tenant_id = direct_grant.tenant_id
     AND role.id = direct_grant.role_id
     AND role.principal_kind = 'human' AND role.archived_at IS NULL
    WHERE direct_grant.tenant_id = context_tenant
      AND direct_grant.membership_id = found_membership_id
      AND direct_grant.revoked_at IS NULL
      AND (direct_grant.expires_at IS NULL
        OR direct_grant.expires_at > transaction_timestamp())
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
       OR group_grant.expires_at > transaction_timestamp())
    JOIN public.tenant_roles AS role
      ON role.tenant_id = group_grant.tenant_id
     AND role.id = group_grant.role_id
     AND role.principal_kind = 'human' AND role.archived_at IS NULL
    WHERE group_member.tenant_id = context_tenant
      AND group_member.membership_id = found_membership_id
      AND group_member.revoked_at IS NULL
      AND (group_member.expires_at IS NULL
        OR group_member.expires_at > transaction_timestamp())
  ), needed_roles AS (
    SELECT unnest(rule_roles.role_ids) AS role_id FROM rule_roles
    UNION SELECT unnest(group_policy_roles.role_ids) FROM group_policy_roles
    UNION SELECT effective.role_id FROM effective_role_ids AS effective
  ), role_policy_rows AS (
    SELECT role.id AS role_id,
           coalesce(jsonb_agg(jsonb_build_object(
             'permission', permission.key, 'scope', policy.scope
           ) ORDER BY permission.key, policy.scope)
           FILTER (WHERE permission.id IS NOT NULL), '[]'::jsonb) AS policy
    FROM needed_roles AS needed
    JOIN public.tenant_roles AS role
      ON role.tenant_id = context_tenant AND role.id = needed.role_id
     AND role.principal_kind = 'human'
     AND role.key <> 'platform_super_admin' AND role.archived_at IS NULL
    LEFT JOIN public.tenant_role_permissions AS policy
      ON policy.tenant_id = role.tenant_id AND policy.role_id = role.id
     AND policy.scope <> 'platform'
    LEFT JOIN public.tenant_permissions AS permission
      ON permission.id = policy.permission_id
    GROUP BY role.id
  ), delegation_rows AS (
    SELECT DISTINCT permission.key AS permission_key, policy.scope
    FROM needed_roles AS needed
    JOIN public.tenant_roles AS role
      ON role.tenant_id = context_tenant AND role.id = needed.role_id
     AND role.principal_kind = 'human'
     AND role.key <> 'platform_super_admin' AND role.archived_at IS NULL
    JOIN public.tenant_role_permissions AS policy
      ON policy.tenant_id = role.tenant_id AND policy.role_id = role.id
     AND policy.scope <> 'platform'
    JOIN public.tenant_permissions AS permission
      ON permission.id = policy.permission_id
  ), owned_edges AS (
    SELECT pinned.source_id, pinned.source_epoch_id AS rule_epoch_id,
           'security_group_membership'::text AS kind,
           member.group_id AS primary_id, NULL::uuid AS secondary_id
    FROM public.tenant_ldap_sync_run_mappings AS pinned
    JOIN public.tenant_security_group_memberships AS member
      ON member.tenant_id = pinned.tenant_id
     AND member.source_id = pinned.source_id
     AND member.membership_id = found_membership_id
     AND member.revoked_at IS NULL
    WHERE pinned.tenant_id = context_tenant
      AND pinned.sync_run_id = p_sync_run_id
    UNION ALL
    SELECT pinned.source_id, pinned.source_epoch_id,
           'security_group_role_grant', grant_row.group_id, grant_row.role_id
    FROM public.tenant_ldap_sync_run_mappings AS pinned
    JOIN public.tenant_security_group_role_grants AS grant_row
      ON grant_row.tenant_id = pinned.tenant_id
     AND grant_row.source_id = pinned.source_id
     AND grant_row.revoked_at IS NULL
    WHERE pinned.tenant_id = context_tenant
      AND pinned.sync_run_id = p_sync_run_id
    UNION ALL
    SELECT pinned.source_id, pinned.source_epoch_id,
           'operator_team_roster', assignment.operator_team_id,
           roster.assignment_epoch_id
    FROM public.tenant_ldap_sync_run_mappings AS pinned
    JOIN public.operator_team_roster_entries AS roster
      ON roster.tenant_id = pinned.tenant_id
     AND roster.source_id = pinned.source_id
     AND roster.membership_id = found_membership_id
     AND roster.revoked_at IS NULL
    JOIN public.operator_team_assignment_epochs AS assignment
      ON assignment.tenant_id = roster.tenant_id
     AND assignment.id = roster.assignment_epoch_id
    WHERE pinned.tenant_id = context_tenant
      AND pinned.sync_run_id = p_sync_run_id
  )
  SELECT locked_run.id, locked_observation.id, context_tenant,
         p_claim_fence, locked_run.provider_id, locked_run.provider_version,
         locked_run.binding_id, locked_run.binding_version,
         locked_run.binding_auth_revision, locked_run.binding_access_epoch_id,
         locked_run.configuration_version, locked_run.rule_set_revision,
         locked_run.authorization_revision, configuration.jit_mode,
         configuration.no_match_policy, current_access_source_id,
         found_identity_id, found_user_id, found_membership_id,
         found_identity_id IS NOT NULL, found_user_active,
         found_membership_id IS NOT NULL, found_membership_active, live_access,
         coalesce((SELECT jsonb_agg(jsonb_build_object(
           'ruleId', selected.mapping_rule_id,
           'ruleEpochId', selected.source_epoch_id,
           'sourceId', selected.source_id,
           'revision', selected.mapping_version,
           'priority', selected.priority, 'enabled', true,
           'matcherType', selected.matcher_type,
           'matcherValue', selected.matcher_value,
           'caseMode', selected.case_mode,
           'reconciliationMode', selected.reconciliation_mode,
           'securityGroupId', selected.security_group_id,
           'roleIds', roles.role_ids,
           'operatorTeamId', selected.operator_team_id,
           'operatorTeamAssignmentEpochId',
             selected.operator_team_assignment_epoch_id,
           'administrativeNote', ''
         ) ORDER BY selected.priority, selected.mapping_rule_id)
         FROM selected_rules AS selected
         JOIN rule_roles AS roles
           ON roles.mapping_rule_id = selected.mapping_rule_id), '[]'::jsonb),
         coalesce((SELECT jsonb_agg(jsonb_build_object(
           'securityGroupId', group_policy.security_group_id,
           'activeRoleIds', group_policy.role_ids
         ) ORDER BY group_policy.security_group_id)
         FROM group_policy_roles AS group_policy), '[]'::jsonb),
         coalesce((SELECT jsonb_agg(jsonb_build_object(
           'operatorTeamId', selected.operator_team_id,
           'assignmentEpochId', selected.operator_team_assignment_epoch_id,
           'live', assignment.id IS NOT NULL AND assignment.ended_at IS NULL
             AND team.archived_at IS NULL
         ) ORDER BY selected.operator_team_id,
                    selected.operator_team_assignment_epoch_id)
         FROM (SELECT DISTINCT operator_team_id,
                 operator_team_assignment_epoch_id
               FROM selected_rules WHERE operator_team_id IS NOT NULL) AS selected
         LEFT JOIN public.operator_team_assignment_epochs AS assignment
           ON assignment.tenant_id = context_tenant
          AND assignment.id = selected.operator_team_assignment_epoch_id
          AND assignment.operator_team_id = selected.operator_team_id
         LEFT JOIN public.operator_teams AS team
           ON team.id = selected.operator_team_id), '[]'::jsonb),
         coalesce((SELECT jsonb_agg(jsonb_build_object(
           'roleId', role_policy.role_id, 'policy', role_policy.policy
         ) ORDER BY role_policy.role_id)
         FROM role_policy_rows AS role_policy), '[]'::jsonb),
         coalesce((SELECT array_agg(role_id ORDER BY role_id)
           FROM effective_role_ids), ARRAY[]::uuid[]),
         coalesce((SELECT jsonb_agg(jsonb_build_object(
           'permission', delegation.permission_key,
           'scope', delegation.scope, 'notAfter', NULL
         ) ORDER BY delegation.permission_key, delegation.scope)
         FROM delegation_rows AS delegation), '[]'::jsonb),
         coalesce((SELECT jsonb_agg(jsonb_build_object(
           'sourceId', edge.source_id, 'ruleEpochId', edge.rule_epoch_id,
           'kind', edge.kind, 'primaryId', edge.primary_id,
           'secondaryId', edge.secondary_id
         ) ORDER BY edge.source_id, edge.kind, edge.primary_id,
                    edge.secondary_id NULLS FIRST)
         FROM owned_edges AS edge), '[]'::jsonb)
  FROM public.tenant_ldap_provider_configs AS configuration
  WHERE configuration.tenant_id = context_tenant
    AND configuration.provider_id = locked_run.provider_id
    AND configuration.version = locked_run.configuration_version;
END;
$function$;--> statement-breakpoint

ALTER FUNCTION app.private_lock_tenant_ldap_sync_claim_v2(uuid, uuid, bytea, bigint, boolean) OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.claim_next_tenant_ldap_sync_run_v2(uuid, bytea, integer, text) OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.stage_tenant_ldap_sync_observation_v2(uuid, uuid, bytea, bigint, uuid, integer, integer, bytea, bytea) OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.claim_tenant_ldap_sync_observation_planning_v2(uuid, uuid, uuid, bytea, bigint, integer[], bytea[]) OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.complete_tenant_ldap_sync_enumeration_v2(uuid, uuid, bytea, bigint, integer, boolean, boolean, bytea, text, uuid, uuid, uuid, text) OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.apply_tenant_ldap_sync_identity_plan_v2(uuid, uuid, uuid, bytea, bigint, uuid, bytea, uuid, integer, integer, integer, integer, uuid, bigint, bigint, public.ldap_identity_apply_decision, text, uuid, uuid, uuid, uuid, uuid, public.identity_subject_format, bytea, bytea, integer, uuid[], integer[], bytea[], text, text, text, text, text, uuid[], timestamptz, uuid, uuid, uuid, inet, text) OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.apply_tenant_ldap_sync_absence_chunk_v2(uuid, uuid, bytea, bigint, integer, uuid, uuid, uuid, text) OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.complete_tenant_ldap_sync_run_v2(uuid, uuid, bytea, bigint, integer, uuid, uuid, uuid, text) OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.fail_tenant_ldap_sync_run_v2(uuid, uuid, bytea, bigint, integer, text, uuid, uuid, uuid, text) OWNER TO periapsis_migrator;--> statement-breakpoint

REVOKE ALL ON FUNCTION app.private_lock_tenant_ldap_sync_claim_v2(uuid, uuid, bytea, bigint, boolean) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.claim_next_tenant_ldap_sync_run_v2(uuid, bytea, integer, text) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.stage_tenant_ldap_sync_observation_v2(uuid, uuid, bytea, bigint, uuid, integer, integer, bytea, bytea) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.claim_tenant_ldap_sync_observation_planning_v2(uuid, uuid, uuid, bytea, bigint, integer[], bytea[]) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.complete_tenant_ldap_sync_enumeration_v2(uuid, uuid, bytea, bigint, integer, boolean, boolean, bytea, text, uuid, uuid, uuid, text) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.apply_tenant_ldap_sync_identity_plan_v2(uuid, uuid, uuid, bytea, bigint, uuid, bytea, uuid, integer, integer, integer, integer, uuid, bigint, bigint, public.ldap_identity_apply_decision, text, uuid, uuid, uuid, uuid, uuid, public.identity_subject_format, bytea, bytea, integer, uuid[], integer[], bytea[], text, text, text, text, text, uuid[], timestamptz, uuid, uuid, uuid, inet, text) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.apply_tenant_ldap_sync_absence_chunk_v2(uuid, uuid, bytea, bigint, integer, uuid, uuid, uuid, text) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.complete_tenant_ldap_sync_run_v2(uuid, uuid, bytea, bigint, integer, uuid, uuid, uuid, text) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.fail_tenant_ldap_sync_run_v2(uuid, uuid, bytea, bigint, integer, text, uuid, uuid, uuid, text) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint

GRANT EXECUTE ON FUNCTION app.claim_next_tenant_ldap_sync_run_v2(uuid, bytea, integer, text) TO periapsis_worker;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.stage_tenant_ldap_sync_observation_v2(uuid, uuid, bytea, bigint, uuid, integer, integer, bytea, bytea) TO periapsis_worker;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.claim_tenant_ldap_sync_observation_planning_v2(uuid, uuid, uuid, bytea, bigint, integer[], bytea[]) TO periapsis_worker;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.complete_tenant_ldap_sync_enumeration_v2(uuid, uuid, bytea, bigint, integer, boolean, boolean, bytea, text, uuid, uuid, uuid, text) TO periapsis_worker;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.apply_tenant_ldap_sync_identity_plan_v2(uuid, uuid, uuid, bytea, bigint, uuid, bytea, uuid, integer, integer, integer, integer, uuid, bigint, bigint, public.ldap_identity_apply_decision, text, uuid, uuid, uuid, uuid, uuid, public.identity_subject_format, bytea, bytea, integer, uuid[], integer[], bytea[], text, text, text, text, text, uuid[], timestamptz, uuid, uuid, uuid, inet, text) TO periapsis_worker;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.apply_tenant_ldap_sync_absence_chunk_v2(uuid, uuid, bytea, bigint, integer, uuid, uuid, uuid, text) TO periapsis_worker;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.complete_tenant_ldap_sync_run_v2(uuid, uuid, bytea, bigint, integer, uuid, uuid, uuid, text) TO periapsis_worker;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.fail_tenant_ldap_sync_run_v2(uuid, uuid, bytea, bigint, integer, text, uuid, uuid, uuid, text) TO periapsis_worker;--> statement-breakpoint

REVOKE EXECUTE ON FUNCTION app.claim_next_tenant_ldap_sync_run_v1(text) FROM periapsis_worker;--> statement-breakpoint
REVOKE EXECUTE ON FUNCTION app.start_tenant_ldap_sync_enumeration_v1(uuid, integer) FROM periapsis_worker;--> statement-breakpoint
REVOKE EXECUTE ON FUNCTION app.stage_tenant_ldap_sync_observation_v1(uuid, uuid, integer, integer, bytea, bytea) FROM periapsis_worker;--> statement-breakpoint
REVOKE EXECUTE ON FUNCTION app.complete_tenant_ldap_sync_enumeration_v1(uuid, integer, boolean, boolean, bytea, text, uuid, uuid, uuid, text) FROM periapsis_worker;--> statement-breakpoint
REVOKE EXECUTE ON FUNCTION app.apply_tenant_ldap_sync_absence_chunk_v1(uuid, integer, uuid, uuid, uuid, text) FROM periapsis_worker;--> statement-breakpoint
REVOKE EXECUTE ON FUNCTION app.complete_tenant_ldap_sync_run_v1(uuid, integer, uuid, uuid, uuid, text) FROM periapsis_worker;--> statement-breakpoint
REVOKE EXECUTE ON FUNCTION app.fail_tenant_ldap_sync_run_v1(uuid, integer, text, uuid, uuid, uuid, text) FROM periapsis_worker;--> statement-breakpoint
REVOKE EXECUTE ON FUNCTION app.apply_tenant_ldap_identity_plan_v1(uuid, bytea, public.ldap_identity_apply_mode, uuid, uuid, uuid, integer, integer, integer, integer, uuid, bigint, bigint, public.ldap_identity_apply_decision, text, uuid, uuid, uuid, uuid, uuid, public.identity_subject_format, bytea, bytea, integer, uuid[], integer[], bytea[], text, text, text, text, text, uuid[], timestamptz, uuid, uuid, uuid, inet, text) FROM periapsis_api, periapsis_worker;
