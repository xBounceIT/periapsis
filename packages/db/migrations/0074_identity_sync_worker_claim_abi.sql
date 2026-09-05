CREATE FUNCTION app.claim_next_tenant_ldap_sync_run_v1(
  p_user_agent text
)
RETURNS TABLE (
  sync_run_id uuid,
  tenant_id uuid,
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
  enumeration_version integer,
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
BEGIN
  IF p_user_agent IS NULL OR length(p_user_agent) NOT BETWEEN 1 AND 1024 THEN
    RAISE EXCEPTION 'LDAP sync worker claim input is invalid'
      USING ERRCODE = '22023';
  END IF;

  -- A bounded loop retires stale head-of-queue entries without allowing one
  -- poisoned binding to starve other tenants. SKIP LOCKED makes status=queued
  -- itself the one-winner claim; no caller-provided tenant is consulted.
  FOR candidate_number IN 1..32 LOOP
    SELECT run.* INTO locked_run
    FROM public.tenant_ldap_sync_runs AS run
    WHERE run.status = 'queued'
    ORDER BY run.queued_at, run.id
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
          'provider_id', locked_run.provider_id,
          'binding_id', locked_run.binding_id,
          'status', 'stale'
        )
      );
      CONTINUE;
    END IF;

    UPDATE public.tenant_ldap_sync_runs AS run
    SET status = 'enumerating',
        enumeration_started_at = transaction_timestamp(),
        version = run.version + 1
    WHERE run.tenant_id = locked_run.tenant_id AND run.id = locked_run.id
      AND run.status = 'queued' AND run.version = locked_run.version
    RETURNING run.version, run.enumeration_started_at
    INTO locked_run.version, locked_run.enumeration_started_at;
    IF NOT FOUND THEN CONTINUE; END IF;

    RETURN QUERY
    SELECT locked_run.id, locked_run.tenant_id, locked_run.provider_id,
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
           locked_run.binding_auth_revision,
           locked_run.binding_access_epoch_id, locked_run.rule_set_revision,
           locked_run.authorization_revision,
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
           ), '[]'::jsonb), locked_run.version, locked_run.queued_at,
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
    RETURN;
  END LOOP;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION app.fail_tenant_ldap_sync_run_v1(
  p_sync_run_id uuid,
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
DECLARE
  context_tenant uuid := app.context_tenant_id();
  locked_run public.tenant_ldap_sync_runs%ROWTYPE;
  effective_status public.ldap_sync_run_status;
  effective_category text;
  effective_action text;
BEGIN
  IF p_sync_run_id IS NULL OR p_expected_version IS NULL
     OR p_failure_category NOT IN (
       'network_error', 'directory_error', 'planning_error',
       'apply_error', 'cancelled'
     ) OR p_audit_event_id IS NULL OR p_request_id IS NULL
     OR p_correlation_id IS NULL OR p_user_agent IS NULL
     OR length(p_user_agent) NOT BETWEEN 1 AND 1024 THEN
    RAISE EXCEPTION 'tenant LDAP sync failure input is invalid'
      USING ERRCODE = '22023';
  END IF;

  SELECT run.* INTO locked_run
  FROM public.tenant_ldap_sync_runs AS run
  WHERE run.tenant_id = context_tenant AND run.id = p_sync_run_id
  FOR UPDATE;
  IF NOT FOUND THEN RETURN; END IF;
  IF locked_run.status IN ('failed', 'cancelled', 'stale') THEN
    RETURN QUERY
    SELECT locked_run.status, locked_run.version, true
    WHERE EXISTS (
      SELECT 1 FROM public.audit_events AS audit
      WHERE audit.tenant_id = context_tenant
        AND audit.id = p_audit_event_id
        AND audit.resource_type = 'ldap_sync_run'
        AND audit.resource_id = locked_run.id
        AND audit.request_id = p_request_id
        AND audit.correlation_id = p_correlation_id
        AND audit.metadata->>'requested_category' = p_failure_category
    );
    RETURN;
  END IF;
  IF locked_run.status NOT IN ('queued', 'enumerating', 'applying')
     OR locked_run.version <> p_expected_version THEN
    RETURN;
  END IF;

  IF NOT app.private_tenant_ldap_sync_run_is_current_v1(
    context_tenant, locked_run.id
  ) THEN
    effective_status := 'stale';
    effective_category := 'stale_configuration';
    effective_action := 'tenant.identity.ldap_sync_stale';
  ELSIF p_failure_category = 'cancelled' THEN
    effective_status := 'cancelled';
    effective_category := 'cancelled';
    effective_action := 'tenant.identity.ldap_sync_cancelled';
  ELSE
    effective_status := 'failed';
    effective_category := p_failure_category;
    effective_action := 'tenant.identity.ldap_sync_failed';
  END IF;

  UPDATE public.tenant_ldap_sync_runs AS run
  SET status = effective_status, failure_category = effective_category,
      completed_at = transaction_timestamp(), version = run.version + 1
  WHERE run.tenant_id = context_tenant AND run.id = locked_run.id;
  PERFORM app.private_append_tenant_ldap_runtime_audit_v1(
    p_audit_event_id, context_tenant, effective_action, 'ldap_sync_run',
    locked_run.id, p_request_id, p_correlation_id, NULL, p_user_agent,
    'ldap_sync', 'failure', effective_category,
    jsonb_build_object(
      'run_id', locked_run.id, 'provider_id', locked_run.provider_id,
      'binding_id', locked_run.binding_id, 'status', effective_status,
      'category', effective_category,
      'requested_category', p_failure_category,
      'observed_count', locked_run.observed_count,
      'applied_count', locked_run.applied_count
    )
  );
  RETURN QUERY SELECT effective_status, locked_run.version + 1, false;
END;
$function$;--> statement-breakpoint

ALTER FUNCTION app.claim_next_tenant_ldap_sync_run_v1(text)
  OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.fail_tenant_ldap_sync_run_v1(
  uuid, integer, text, uuid, uuid, uuid, text
) OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.claim_next_tenant_ldap_sync_run_v1(text)
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.fail_tenant_ldap_sync_run_v1(
  uuid, integer, text, uuid, uuid, uuid, text
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.claim_next_tenant_ldap_sync_run_v1(text)
  TO periapsis_worker;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.fail_tenant_ldap_sync_run_v1(
  uuid, integer, text, uuid, uuid, uuid, text
) TO periapsis_worker;
