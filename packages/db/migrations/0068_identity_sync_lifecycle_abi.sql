-- Bounded, pinned lifecycle for manual and scheduled LDAP reconciliation.
CREATE FUNCTION app.private_tenant_ldap_sync_run_is_current_v1(
  p_tenant_id uuid,
  p_sync_run_id uuid
)
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  RETURN EXISTS (
    SELECT 1
    FROM public.tenant_ldap_sync_runs AS run
    JOIN public.tenants AS tenant ON tenant.id = run.tenant_id
    JOIN public.tenant_auth_providers AS provider
      ON provider.tenant_id = run.tenant_id
     AND provider.id = run.provider_id AND provider.kind = 'ldap'
    JOIN public.tenant_ldap_provider_configs AS config
      ON config.tenant_id = provider.tenant_id
     AND config.provider_id = provider.id
    JOIN public.tenant_ldap_provider_secrets AS secret
      ON secret.tenant_id = provider.tenant_id
     AND secret.provider_id = provider.id
     AND secret.id = run.bind_secret_id
    JOIN public.identity_keyring_versions AS keyring
      ON keyring.key_version = secret.key_version
     AND keyring.retired_at IS NULL
    JOIN public.tenant_auth_provider_bindings AS binding
      ON binding.tenant_id = run.tenant_id
     AND binding.id = run.binding_id
     AND binding.provider_id = run.provider_id
    JOIN public.tenant_identity_provider_access_epochs AS access_epoch
      ON access_epoch.tenant_id = binding.tenant_id
     AND access_epoch.id = binding.current_access_epoch_id
     AND access_epoch.binding_id = binding.id
     AND access_epoch.provider_id = binding.provider_id
    JOIN public.tenant_authorization_sources AS access_source
      ON access_source.tenant_id = access_epoch.tenant_id
     AND access_source.id = access_epoch.source_id
    JOIN public.tenant_authorization_states AS authorization_state
      ON authorization_state.tenant_id = run.tenant_id
    CROSS JOIN LATERAL app.private_tenant_ldap_endpoint_snapshot_v1(
      run.tenant_id, run.provider_id
    ) AS endpoint_snapshot
    WHERE run.tenant_id = p_tenant_id AND run.id = p_sync_run_id
      AND tenant.status = 'active'
      AND provider.enabled AND provider.archived_at IS NULL
      AND provider.version = run.provider_version
      AND config.version = run.configuration_version
      AND secret.version = run.bind_secret_version
      AND secret.key_version = run.bind_secret_key_version
      AND secret.encryption_algorithm = run.bind_secret_algorithm
      AND binding.enabled AND binding.archived_at IS NULL
      AND binding.version = run.binding_version
      AND binding.auth_revision = run.binding_auth_revision
      AND binding.mapping_revision = run.rule_set_revision
      AND binding.current_access_epoch_id = run.binding_access_epoch_id
      AND access_epoch.ended_at IS NULL
      AND access_source.kind = 'identity_provider_access'
      AND access_source.retired_at IS NULL
      AND authorization_state.revision = run.authorization_progress_revision
      AND endpoint_snapshot.endpoint_count > 0
      AND endpoint_snapshot.endpoint_digest = run.endpoint_snapshot_digest
      AND NOT EXISTS (
        SELECT 1
        FROM public.tenant_ldap_sync_run_mappings AS pinned
        LEFT JOIN public.tenant_ldap_mapping_rules AS rule
          ON rule.tenant_id = pinned.tenant_id
         AND rule.id = pinned.mapping_rule_id
         AND rule.binding_id = pinned.binding_id
         AND rule.version = pinned.mapping_version
         AND rule.configuration_revision = pinned.configuration_revision
         AND rule.current_source_epoch_id = pinned.source_epoch_id
         AND rule.enabled AND rule.archived_at IS NULL
        LEFT JOIN public.tenant_ldap_mapping_rule_epochs AS epoch
          ON epoch.tenant_id = pinned.tenant_id
         AND epoch.id = pinned.source_epoch_id
         AND epoch.mapping_rule_id = pinned.mapping_rule_id
         AND epoch.binding_id = pinned.binding_id
         AND epoch.source_id = pinned.source_id
         AND epoch.ended_at IS NULL
        LEFT JOIN public.tenant_authorization_sources AS mapping_source
          ON mapping_source.tenant_id = pinned.tenant_id
         AND mapping_source.id = pinned.source_id
         AND mapping_source.kind = 'identity_mapping'
         AND mapping_source.retired_at IS NULL
        WHERE pinned.tenant_id = run.tenant_id
          AND pinned.sync_run_id = run.id
          AND (rule.id IS NULL OR epoch.id IS NULL OR mapping_source.id IS NULL)
      )
      AND (
        SELECT count(*)
        FROM public.tenant_ldap_sync_run_mappings AS pinned
        WHERE pinned.tenant_id = run.tenant_id AND pinned.sync_run_id = run.id
      ) = (
        SELECT count(*)
        FROM public.tenant_ldap_mapping_rules AS rule
        WHERE rule.tenant_id = run.tenant_id
          AND rule.binding_id = run.binding_id
          AND rule.enabled AND rule.archived_at IS NULL
      )
  );
END;
$function$;--> statement-breakpoint

CREATE FUNCTION app.private_begin_tenant_ldap_sync_run_v1(
  p_sync_run_id uuid,
  p_binding_id uuid,
  p_trigger public.ldap_sync_trigger,
  p_reason text,
  p_actor_membership_id uuid,
  p_request_id uuid,
  p_correlation_id uuid
)
RETURNS TABLE (
  sync_run_id uuid,
  provider_id uuid,
  provider_version integer,
  configuration_version integer,
  binding_version integer,
  binding_auth_revision integer,
  binding_access_epoch_id uuid,
  rule_set_revision bigint,
  authorization_revision bigint,
  endpoint_snapshot_digest bytea,
  status public.ldap_sync_run_status,
  replayed boolean
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  existing_run public.tenant_ldap_sync_runs%ROWTYPE;
  locked_binding public.tenant_auth_provider_bindings%ROWTYPE;
  locked_provider public.tenant_auth_providers%ROWTYPE;
  locked_config public.tenant_ldap_provider_configs%ROWTYPE;
  locked_secret public.tenant_ldap_provider_secrets%ROWTYPE;
  current_authorization_revision bigint;
  endpoint_digest bytea;
  endpoint_count integer;
BEGIN
  IF p_sync_run_id IS NULL
     OR (uuid_extract_version(p_sync_run_id) = 7) IS NOT TRUE
     OR p_binding_id IS NULL OR p_trigger IS NULL
     OR p_request_id IS NULL OR p_correlation_id IS NULL
     OR p_reason IS NULL OR btrim(p_reason) = ''
     OR char_length(p_reason) > 500 OR p_reason ~ '[[:cntrl:]]'
     OR (p_trigger = 'manual') IS DISTINCT FROM
        (p_actor_membership_id IS NOT NULL) THEN
    RAISE EXCEPTION 'tenant LDAP sync run input is invalid'
      USING ERRCODE = '22023';
  END IF;

  SELECT run.* INTO existing_run
  FROM public.tenant_ldap_sync_runs AS run
  WHERE run.tenant_id = context_tenant AND run.id = p_sync_run_id
  FOR UPDATE;
  IF FOUND THEN
    IF existing_run.binding_id IS DISTINCT FROM p_binding_id
       OR existing_run.trigger IS DISTINCT FROM p_trigger
       OR existing_run.reason IS DISTINCT FROM p_reason
       OR existing_run.request_id IS DISTINCT FROM p_request_id
       OR existing_run.correlation_id IS DISTINCT FROM p_correlation_id
       OR existing_run.started_by_membership_id IS DISTINCT FROM
          p_actor_membership_id THEN
      RAISE EXCEPTION 'LDAP sync run replay differs'
        USING ERRCODE = '23505',
              CONSTRAINT = 'tenant_ldap_sync_runs_tenant_id_key';
    END IF;
    RETURN QUERY SELECT existing_run.id, existing_run.provider_id,
      existing_run.provider_version, existing_run.configuration_version,
      existing_run.binding_version, existing_run.binding_auth_revision,
      existing_run.binding_access_epoch_id, existing_run.rule_set_revision,
      existing_run.authorization_revision,
      existing_run.endpoint_snapshot_digest, existing_run.status, true;
    RETURN;
  END IF;

  PERFORM pg_advisory_xact_lock(hashtextextended(
    'tenant_ldap_sync_binding:' || context_tenant::text || ':' ||
    p_binding_id::text, 0
  ));
  SELECT binding.* INTO locked_binding
  FROM public.tenant_auth_provider_bindings AS binding
  JOIN public.tenant_identity_provider_access_epochs AS epoch
    ON epoch.tenant_id = binding.tenant_id
   AND epoch.id = binding.current_access_epoch_id
   AND epoch.binding_id = binding.id
   AND epoch.provider_id = binding.provider_id
   AND epoch.ended_at IS NULL
  JOIN public.tenant_authorization_sources AS source
    ON source.tenant_id = epoch.tenant_id AND source.id = epoch.source_id
   AND source.kind = 'identity_provider_access' AND source.retired_at IS NULL
  WHERE binding.tenant_id = context_tenant AND binding.id = p_binding_id
    AND binding.enabled AND binding.archived_at IS NULL
  FOR UPDATE OF binding, epoch, source;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'live tenant LDAP binding was not found'
      USING ERRCODE = 'P0002';
  END IF;

  SELECT provider.* INTO locked_provider
  FROM public.tenant_auth_providers AS provider
  JOIN public.tenants AS tenant ON tenant.id = provider.tenant_id
  WHERE provider.tenant_id = context_tenant
    AND provider.id = locked_binding.provider_id
    AND provider.kind = 'ldap' AND provider.enabled
    AND provider.archived_at IS NULL AND tenant.status = 'active'
  FOR SHARE OF provider;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'live tenant LDAP provider was not found'
      USING ERRCODE = 'P0002';
  END IF;
  SELECT config.* INTO locked_config
  FROM public.tenant_ldap_provider_configs AS config
  WHERE config.tenant_id = context_tenant
    AND config.provider_id = locked_provider.id
  FOR SHARE;
  IF NOT FOUND OR (p_trigger = 'scheduled'
       AND locked_config.sync_interval_seconds IS NULL) THEN
    RAISE EXCEPTION 'tenant LDAP sync configuration is unavailable'
      USING ERRCODE = '55000';
  END IF;
  SELECT secret.* INTO locked_secret
  FROM public.tenant_ldap_provider_secrets AS secret
  JOIN public.identity_keyring_versions AS keyring
    ON keyring.key_version = secret.key_version
   AND keyring.retired_at IS NULL
  WHERE secret.tenant_id = context_tenant
    AND secret.provider_id = locked_provider.id
  FOR SHARE OF secret, keyring;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant LDAP sync bind secret is unavailable'
      USING ERRCODE = '55000';
  END IF;
  SELECT snapshot.endpoint_digest, snapshot.endpoint_count
  INTO endpoint_digest, endpoint_count
  FROM app.private_tenant_ldap_endpoint_snapshot_v1(
    context_tenant, locked_provider.id
  ) AS snapshot;
  IF endpoint_count IS NULL OR endpoint_count < 1 THEN
    RAISE EXCEPTION 'tenant LDAP sync has no enabled endpoint'
      USING ERRCODE = '55000';
  END IF;
  SELECT state.revision INTO current_authorization_revision
  FROM public.tenant_authorization_states AS state
  WHERE state.tenant_id = context_tenant AND state.initialized_at IS NOT NULL
  FOR UPDATE;
  IF current_authorization_revision IS NULL THEN
    RAISE EXCEPTION 'initialized tenant authorization state is required'
      USING ERRCODE = '42501';
  END IF;

  INSERT INTO public.tenant_ldap_sync_runs (
    id, tenant_id, provider_id, binding_id, trigger, provider_version,
    configuration_version, binding_version, binding_auth_revision,
    binding_access_epoch_id, rule_set_revision, authorization_revision,
    authorization_progress_revision, bind_secret_id, bind_secret_version,
    bind_secret_key_version, bind_secret_algorithm,
    endpoint_snapshot_digest, reason,
    started_by_membership_id, request_id, correlation_id
  ) VALUES (
    p_sync_run_id, context_tenant, locked_provider.id, p_binding_id,
    p_trigger, locked_provider.version, locked_config.version,
    locked_binding.version, locked_binding.auth_revision,
    locked_binding.current_access_epoch_id, locked_binding.mapping_revision,
    current_authorization_revision, current_authorization_revision,
    locked_secret.id, locked_secret.version, locked_secret.key_version,
    locked_secret.encryption_algorithm, endpoint_digest, p_reason,
    p_actor_membership_id, p_request_id,
    p_correlation_id
  );
  INSERT INTO public.tenant_ldap_sync_run_mappings (
    tenant_id, sync_run_id, binding_id, mapping_rule_id, mapping_version,
    configuration_revision, source_epoch_id, source_id, priority
  )
  SELECT context_tenant, p_sync_run_id, p_binding_id, rule.id, rule.version,
         rule.configuration_revision, epoch.id, epoch.source_id, epoch.priority
  FROM public.tenant_ldap_mapping_rules AS rule
  JOIN public.tenant_ldap_mapping_rule_epochs AS epoch
    ON epoch.tenant_id = rule.tenant_id
   AND epoch.id = rule.current_source_epoch_id
   AND epoch.mapping_rule_id = rule.id
   AND epoch.binding_id = rule.binding_id
   AND epoch.ended_at IS NULL
  JOIN public.tenant_authorization_sources AS source
    ON source.tenant_id = epoch.tenant_id AND source.id = epoch.source_id
   AND source.kind = 'identity_mapping' AND source.retired_at IS NULL
  WHERE rule.tenant_id = context_tenant AND rule.binding_id = p_binding_id
    AND rule.enabled AND rule.archived_at IS NULL
  ORDER BY rule.priority, rule.id;

  RETURN QUERY SELECT p_sync_run_id, locked_provider.id,
    locked_provider.version, locked_config.version, locked_binding.version,
    locked_binding.auth_revision, locked_binding.current_access_epoch_id,
    locked_binding.mapping_revision, current_authorization_revision,
    endpoint_digest, 'queued'::public.ldap_sync_run_status, false;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION app.begin_tenant_ldap_manual_sync_run_v1(
  p_sync_run_id uuid,
  p_binding_id uuid,
  p_reason text,
  p_audit_event_id uuid,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text
)
RETURNS TABLE (
  sync_run_id uuid, provider_id uuid, provider_version integer,
  configuration_version integer, binding_version integer,
  binding_auth_revision integer, binding_access_epoch_id uuid,
  rule_set_revision bigint, authorization_revision bigint,
  endpoint_snapshot_digest bytea, status public.ldap_sync_run_status,
  replayed boolean
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  actor_membership uuid;
  result_row record;
  recent_count integer;
BEGIN
  PERFORM app.lock_current_tenant_authorization_state();
  actor_membership := app.current_tenant_membership_id();
  IF NOT app.current_tenant_human_has_exact_permission_v3(
    'identity_sync.run', 'tenant'
  ) THEN
    RAISE EXCEPTION 'identity_sync.run tenant scope is required'
      USING ERRCODE = '42501';
  END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended(
    'tenant_ldap_manual_sync_rate:' || context_tenant::text || ':' ||
    actor_membership::text, 0
  ));
  SELECT count(*)::integer INTO recent_count
  FROM public.tenant_ldap_sync_runs AS run
  WHERE run.tenant_id = context_tenant
    AND run.started_by_membership_id = actor_membership
    AND run.trigger = 'manual'
    AND run.queued_at >= transaction_timestamp() - interval '1 hour';
  IF recent_count >= 10 THEN
    RAISE EXCEPTION 'tenant LDAP manual sync rate limit exceeded'
      USING ERRCODE = '53300';
  END IF;
  SELECT * INTO result_row
  FROM app.private_begin_tenant_ldap_sync_run_v1(
    p_sync_run_id, p_binding_id, 'manual', p_reason,
    actor_membership, p_request_id, p_correlation_id
  );
  IF NOT result_row.replayed THEN
    PERFORM app.append_tenant_authorization_audit(
      p_audit_event_id, 'tenant.identity.ldap_sync_queued', 'ldap_sync_run',
      p_sync_run_id, p_request_id, p_correlation_id, p_ip_address,
      p_user_agent, p_authentication_method, NULL,
      jsonb_build_object(
        'run_id', p_sync_run_id, 'binding_id', p_binding_id,
        'provider_id', result_row.provider_id, 'trigger', 'manual',
        'configuration_version', result_row.configuration_version,
        'rule_set_revision', result_row.rule_set_revision,
        'authorization_revision', result_row.authorization_revision
      ), jsonb_build_object('reason', p_reason)
    );
  END IF;
  RETURN QUERY SELECT result_row.sync_run_id, result_row.provider_id,
    result_row.provider_version, result_row.configuration_version,
    result_row.binding_version, result_row.binding_auth_revision,
    result_row.binding_access_epoch_id, result_row.rule_set_revision,
    result_row.authorization_revision, result_row.endpoint_snapshot_digest,
    result_row.status, result_row.replayed;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION app.begin_tenant_ldap_scheduled_sync_run_v1(
  p_sync_run_id uuid,
  p_binding_id uuid,
  p_reason text,
  p_audit_event_id uuid,
  p_request_id uuid,
  p_correlation_id uuid,
  p_user_agent text
)
RETURNS TABLE (
  sync_run_id uuid, provider_id uuid, provider_version integer,
  configuration_version integer, binding_version integer,
  binding_auth_revision integer, binding_access_epoch_id uuid,
  rule_set_revision bigint, authorization_revision bigint,
  endpoint_snapshot_digest bytea, status public.ldap_sync_run_status,
  replayed boolean
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  result_row record;
BEGIN
  SELECT * INTO result_row
  FROM app.private_begin_tenant_ldap_sync_run_v1(
    p_sync_run_id, p_binding_id, 'scheduled', p_reason,
    NULL, p_request_id, p_correlation_id
  );
  IF NOT result_row.replayed THEN
    PERFORM app.private_append_tenant_ldap_runtime_audit_v1(
      p_audit_event_id, app.context_tenant_id(),
      'tenant.identity.ldap_sync_queued', 'ldap_sync_run', p_sync_run_id,
      p_request_id, p_correlation_id, NULL, p_user_agent, 'ldap_sync',
      'success', NULL, jsonb_build_object(
        'run_id', p_sync_run_id, 'binding_id', p_binding_id,
        'provider_id', result_row.provider_id, 'trigger', 'scheduled',
        'configuration_version', result_row.configuration_version,
        'rule_set_revision', result_row.rule_set_revision,
        'authorization_revision', result_row.authorization_revision
      )
    );
  END IF;
  RETURN QUERY SELECT result_row.sync_run_id, result_row.provider_id,
    result_row.provider_version, result_row.configuration_version,
    result_row.binding_version, result_row.binding_auth_revision,
    result_row.binding_access_epoch_id, result_row.rule_set_revision,
    result_row.authorization_revision, result_row.endpoint_snapshot_digest,
    result_row.status, result_row.replayed;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION app.start_tenant_ldap_sync_enumeration_v1(
  p_sync_run_id uuid,
  p_expected_version integer
)
RETURNS integer
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF NOT app.private_tenant_ldap_sync_run_is_current_v1(
    app.context_tenant_id(), p_sync_run_id
  ) THEN
    UPDATE public.tenant_ldap_sync_runs AS run
    SET status = 'stale', failure_category = 'stale_configuration',
        completed_at = transaction_timestamp(), version = run.version + 1
    WHERE run.tenant_id = app.context_tenant_id()
      AND run.id = p_sync_run_id AND run.status = 'queued'
      AND run.version = p_expected_version
    RETURNING run.version INTO p_expected_version;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'queued tenant LDAP sync run version does not match'
        USING ERRCODE = '40001';
    END IF;
    RETURN p_expected_version;
  END IF;
  UPDATE public.tenant_ldap_sync_runs AS run
  SET status = 'enumerating', enumeration_started_at = transaction_timestamp(),
      version = run.version + 1
  WHERE run.tenant_id = app.context_tenant_id()
    AND run.id = p_sync_run_id AND run.status = 'queued'
    AND run.version = p_expected_version
  RETURNING run.version INTO p_expected_version;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'queued tenant LDAP sync run version does not match'
      USING ERRCODE = '40001';
  END IF;
  RETURN p_expected_version;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION app.stage_tenant_ldap_sync_observation_v1(
  p_sync_run_id uuid,
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
DECLARE
  context_tenant uuid := app.context_tenant_id();
  run_record public.tenant_ldap_sync_runs%ROWTYPE;
  existing_observation public.tenant_ldap_sync_staged_observations%ROWTYPE;
  matched_identity_ids uuid[];
  matched_identity_id uuid;
BEGIN
  SELECT run.* INTO run_record
  FROM public.tenant_ldap_sync_runs AS run
  WHERE run.tenant_id = context_tenant AND run.id = p_sync_run_id
  FOR UPDATE;
  IF NOT FOUND OR p_observation_id IS NULL
     OR (uuid_extract_version(p_observation_id) = 7) IS NOT TRUE
     OR p_ordinal NOT BETWEEN 1 AND 5000
     OR p_digest_key_version NOT BETWEEN 1 AND 32767
     OR p_subject_digest IS NULL OR octet_length(p_subject_digest) <> 32
     OR p_observation_digest IS NULL OR octet_length(p_observation_digest) <> 32 THEN
    RAISE EXCEPTION 'tenant LDAP sync observation input is invalid'
      USING ERRCODE = '22023';
  END IF;
  SELECT observation.* INTO existing_observation
  FROM public.tenant_ldap_sync_staged_observations AS observation
  WHERE observation.tenant_id = context_tenant
    AND observation.sync_run_id = p_sync_run_id
    AND observation.id = p_observation_id
  FOR UPDATE;
  IF FOUND THEN
    IF existing_observation.provider_id IS DISTINCT FROM run_record.provider_id
       OR existing_observation.ordinal IS DISTINCT FROM p_ordinal
       OR existing_observation.digest_key_version IS DISTINCT FROM
          p_digest_key_version
       OR existing_observation.subject_digest IS DISTINCT FROM p_subject_digest
       OR existing_observation.observation_digest IS DISTINCT FROM
          p_observation_digest THEN
      RAISE EXCEPTION 'tenant LDAP sync observation replay differs'
        USING ERRCODE = '23505',
              CONSTRAINT = 'tenant_ldap_sync_staged_observations_pkey';
    END IF;
    RETURN existing_observation.external_identity_id;
  END IF;
  IF run_record.status <> 'enumerating'
     OR NOT app.private_tenant_ldap_sync_run_is_current_v1(
       context_tenant, p_sync_run_id
     ) THEN
    RAISE EXCEPTION 'tenant LDAP sync observation pins are stale'
      USING ERRCODE = '40001';
  END IF;
  SELECT array_agg(DISTINCT alias.external_identity_id)
  INTO matched_identity_ids
  FROM public.tenant_ldap_external_identity_subject_aliases AS alias
  WHERE alias.tenant_id = context_tenant
    AND alias.provider_id = run_record.provider_id
    AND alias.digest_key_version = p_digest_key_version
    AND alias.subject_digest = p_subject_digest
    AND alias.retired_at IS NULL;
  IF coalesce(cardinality(matched_identity_ids), 0) > 1 THEN
    RAISE EXCEPTION 'tenant LDAP sync immutable subject is ambiguous'
      USING ERRCODE = '23505';
  END IF;
  matched_identity_id := matched_identity_ids[1];
  INSERT INTO public.tenant_ldap_sync_staged_observations (
    id, tenant_id, sync_run_id, provider_id, ordinal, digest_key_version,
    subject_digest, observation_digest, external_identity_id
  ) VALUES (
    p_observation_id, context_tenant, p_sync_run_id, run_record.provider_id,
    p_ordinal, p_digest_key_version, p_subject_digest,
    p_observation_digest, matched_identity_id
  );
  RETURN matched_identity_id;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION app.complete_tenant_ldap_sync_enumeration_v1(
  p_sync_run_id uuid,
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
DECLARE
  context_tenant uuid := app.context_tenant_id();
  run_record public.tenant_ldap_sync_runs%ROWTYPE;
  staged_count integer;
  effective_status public.ldap_sync_run_status;
  effective_failure text;
BEGIN
  SELECT run.* INTO run_record
  FROM public.tenant_ldap_sync_runs AS run
  WHERE run.tenant_id = context_tenant AND run.id = p_sync_run_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant LDAP sync run was not found'
      USING ERRCODE = 'P0002';
  END IF;
  IF run_record.status IN ('applying', 'failed', 'cancelled', 'stale')
     AND run_record.version = p_expected_version + 1
     AND run_record.enumeration_complete IS NOT DISTINCT FROM
         p_enumeration_complete
     AND run_record.result_truncated IS NOT DISTINCT FROM p_result_truncated
     AND run_record.cursor_digest IS NOT DISTINCT FROM p_cursor_digest
     AND EXISTS (
       SELECT 1 FROM public.audit_events AS audit
       WHERE audit.tenant_id = context_tenant
         AND audit.id = p_audit_event_id
         AND audit.action = 'tenant.identity.ldap_sync_enumeration_completed'
         AND audit.resource_type = 'ldap_sync_run'
         AND audit.resource_id = p_sync_run_id
         AND audit.request_id = p_request_id
         AND audit.correlation_id = p_correlation_id
     ) THEN
    RETURN QUERY SELECT run_record.status, run_record.version,
      run_record.observed_count, run_record.status = 'applying';
    RETURN;
  END IF;
  IF run_record.status <> 'enumerating'
     OR run_record.version <> p_expected_version
     OR p_enumeration_complete IS NULL OR p_result_truncated IS NULL
     OR p_audit_event_id IS NULL OR p_request_id IS NULL
     OR p_correlation_id IS NULL OR p_user_agent IS NULL
     OR length(p_user_agent) NOT BETWEEN 1 AND 1024
     OR (p_cursor_digest IS NOT NULL AND octet_length(p_cursor_digest) <> 32)
     OR (p_enumeration_complete AND NOT p_result_truncated
       AND p_failure_category IS NOT NULL)
     OR (NOT (p_enumeration_complete AND NOT p_result_truncated)
       AND (p_failure_category IS NULL
         OR p_failure_category !~ '^[a-z][a-z0-9_]{1,63}$')) THEN
    RAISE EXCEPTION 'tenant LDAP sync enumeration completion is invalid'
      USING ERRCODE = '22023';
  END IF;
  SELECT count(*)::integer INTO staged_count
  FROM public.tenant_ldap_sync_staged_observations AS observation
  WHERE observation.tenant_id = context_tenant
    AND observation.sync_run_id = p_sync_run_id;
  IF staged_count > 5000 THEN
    RAISE EXCEPTION 'tenant LDAP sync observation bound was exceeded'
      USING ERRCODE = '54000';
  END IF;
  IF NOT app.private_tenant_ldap_sync_run_is_current_v1(
    context_tenant, p_sync_run_id
  ) THEN
    effective_status := 'stale';
    effective_failure := 'stale_configuration';
  ELSIF p_enumeration_complete AND NOT p_result_truncated THEN
    effective_status := 'applying';
    effective_failure := NULL;
  ELSIF p_failure_category = 'cancelled' THEN
    effective_status := 'cancelled';
    effective_failure := 'cancelled';
  ELSE
    effective_status := 'failed';
    effective_failure := p_failure_category;
  END IF;
  UPDATE public.tenant_ldap_sync_runs AS run
  SET status = effective_status,
      enumeration_complete = p_enumeration_complete,
      result_truncated = p_result_truncated,
      cursor_digest = p_cursor_digest,
      observed_count = staged_count,
      enumeration_completed_at = transaction_timestamp(),
      completed_at = CASE WHEN effective_status = 'applying'
        THEN NULL ELSE transaction_timestamp() END,
      failure_category = effective_failure,
      version = run.version + 1
  WHERE run.tenant_id = context_tenant AND run.id = p_sync_run_id;
  IF effective_status = 'applying' THEN
    UPDATE public.tenant_ldap_sync_absences AS absence
    SET status = 'cleared', resolved_at = transaction_timestamp(),
        latest_missing_run_id = p_sync_run_id, version = absence.version + 1
    WHERE absence.tenant_id = context_tenant
      AND absence.binding_id = run_record.binding_id
      AND absence.status = 'pending'
      AND EXISTS (
        SELECT 1 FROM public.tenant_ldap_sync_staged_observations AS observation
        WHERE observation.tenant_id = absence.tenant_id
          AND observation.sync_run_id = p_sync_run_id
          AND observation.external_identity_id = absence.external_identity_id
      );
  END IF;
  PERFORM app.private_append_tenant_ldap_runtime_audit_v1(
    p_audit_event_id, context_tenant,
    'tenant.identity.ldap_sync_enumeration_completed', 'ldap_sync_run',
    p_sync_run_id, p_request_id, p_correlation_id, NULL, p_user_agent,
    'ldap_sync', (CASE WHEN effective_status = 'applying'
      THEN 'success' ELSE 'failure' END)::public.audit_outcome,
    effective_failure,
    jsonb_build_object(
      'run_id', p_sync_run_id, 'binding_id', run_record.binding_id,
      'provider_id', run_record.provider_id,
      'enumeration_complete', p_enumeration_complete,
      'result_truncated', p_result_truncated,
      'observed_count', staged_count, 'status', effective_status
    )
  );
  RETURN QUERY SELECT effective_status, p_expected_version + 1,
    staged_count, effective_status = 'applying';
END;
$function$;--> statement-breakpoint

CREATE FUNCTION app.apply_tenant_ldap_sync_absence_chunk_v1(
  p_sync_run_id uuid,
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
DECLARE
  context_tenant uuid := app.context_tenant_id();
  run_record public.tenant_ldap_sync_runs%ROWTYPE;
  config_record public.tenant_ldap_provider_configs%ROWTYPE;
  candidate record;
  inspected integer := 0;
  revoked integer := 0;
  should_revoke boolean;
  absence_record public.tenant_ldap_sync_absences%ROWTYPE;
  changed integer;
  replay_metadata jsonb;
BEGIN
  IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 200
     OR p_audit_event_id IS NULL OR p_request_id IS NULL
     OR p_correlation_id IS NULL OR p_user_agent IS NULL
     OR length(p_user_agent) NOT BETWEEN 1 AND 1024 THEN
    RAISE EXCEPTION 'LDAP sync absence chunk input is invalid'
      USING ERRCODE = '22023';
  END IF;
  SELECT audit.metadata INTO replay_metadata
  FROM public.audit_events AS audit
  WHERE audit.tenant_id = context_tenant
    AND audit.id = p_audit_event_id
    AND audit.action = 'tenant.identity.ldap_sync_absence_applied'
    AND audit.resource_type = 'ldap_sync_run'
    AND audit.resource_id = p_sync_run_id
    AND audit.request_id = p_request_id
    AND audit.correlation_id = p_correlation_id
    AND (audit.metadata->>'limit')::integer = p_limit;
  IF FOUND THEN
    RETURN QUERY SELECT
      (replay_metadata->>'inspected_count')::integer,
      (replay_metadata->>'revoked_count')::integer,
      (replay_metadata->>'remaining_count')::integer;
    RETURN;
  END IF;
  SELECT run.* INTO run_record
  FROM public.tenant_ldap_sync_runs AS run
  WHERE run.tenant_id = context_tenant AND run.id = p_sync_run_id
  FOR UPDATE;
  IF NOT FOUND OR run_record.status <> 'applying'
     OR NOT run_record.enumeration_complete OR run_record.result_truncated
     OR NOT app.private_tenant_ldap_sync_run_is_current_v1(
       context_tenant, p_sync_run_id
     ) THEN
    RAISE EXCEPTION 'LDAP sync absence requires a complete current run'
      USING ERRCODE = '40001';
  END IF;
  SELECT config.* INTO config_record
  FROM public.tenant_ldap_provider_configs AS config
  WHERE config.tenant_id = context_tenant
    AND config.provider_id = run_record.provider_id;
  IF config_record.deprovision_mode = 'retain' THEN
    RETURN QUERY SELECT 0, 0, 0;
    RETURN;
  END IF;

  FOR candidate IN
    SELECT grant_row.*
    FROM public.tenant_ldap_provider_access_grants AS grant_row
    WHERE grant_row.tenant_id = context_tenant
      AND grant_row.binding_id = run_record.binding_id
      AND grant_row.ended_at IS NULL
      AND NOT EXISTS (
        SELECT 1 FROM public.tenant_ldap_sync_staged_observations AS observation
        WHERE observation.tenant_id = context_tenant
          AND observation.sync_run_id = p_sync_run_id
          AND observation.external_identity_id = grant_row.external_identity_id
      )
    ORDER BY grant_row.id
    FOR UPDATE SKIP LOCKED
    LIMIT p_limit
  LOOP
    inspected := inspected + 1;
    should_revoke := config_record.deprovision_mode = 'immediate';
    IF config_record.deprovision_mode = 'grace' THEN
      SELECT absence.* INTO absence_record
      FROM public.tenant_ldap_sync_absences AS absence
      WHERE absence.tenant_id = context_tenant
        AND absence.binding_id = run_record.binding_id
        AND absence.external_identity_id = candidate.external_identity_id
      FOR UPDATE;
      IF NOT FOUND THEN
        INSERT INTO public.tenant_ldap_sync_absences (
          tenant_id, binding_id, external_identity_id, membership_id,
          first_missing_run_id, latest_missing_run_id, first_missing_at,
          apply_after
        ) VALUES (
          context_tenant, run_record.binding_id,
          candidate.external_identity_id, candidate.membership_id,
          p_sync_run_id, p_sync_run_id, transaction_timestamp(),
          transaction_timestamp() +
            make_interval(secs => config_record.deprovision_grace_seconds)
        );
        should_revoke := false;
      ELSE
        should_revoke := absence_record.status = 'pending'
          AND absence_record.apply_after <= transaction_timestamp();
      END IF;
    END IF;
    IF should_revoke THEN
      UPDATE public.tenant_security_group_memberships AS member
      SET revoked_at = transaction_timestamp(),
          revoked_by_membership_id = epoch.activated_by_membership_id,
          revoke_reason = 'identity_sync_authoritative_absence',
          version = member.version + 1, updated_at = transaction_timestamp()
      FROM public.tenant_ldap_sync_run_mappings AS pinned
      JOIN public.tenant_ldap_mapping_rule_epochs AS epoch
        ON epoch.tenant_id = pinned.tenant_id
       AND epoch.id = pinned.source_epoch_id
       AND epoch.reconciliation_mode = 'authoritative'
      WHERE pinned.tenant_id = context_tenant
        AND pinned.sync_run_id = p_sync_run_id
        AND member.tenant_id = context_tenant
        AND member.membership_id = candidate.membership_id
        AND member.source_id = pinned.source_id
        AND member.revoked_at IS NULL;
      UPDATE public.operator_team_roster_entries AS roster
      SET revoked_at = transaction_timestamp(),
          revoked_by_membership_id = epoch.activated_by_membership_id,
          revoke_reason = 'identity_sync_authoritative_absence',
          version = roster.version + 1, updated_at = transaction_timestamp()
      FROM public.tenant_ldap_sync_run_mappings AS pinned
      JOIN public.tenant_ldap_mapping_rule_epochs AS epoch
        ON epoch.tenant_id = pinned.tenant_id
       AND epoch.id = pinned.source_epoch_id
       AND epoch.reconciliation_mode = 'authoritative'
      WHERE pinned.tenant_id = context_tenant
        AND pinned.sync_run_id = p_sync_run_id
        AND roster.tenant_id = context_tenant
        AND roster.membership_id = candidate.membership_id
        AND roster.source_id = pinned.source_id
        AND roster.revoked_at IS NULL;
      UPDATE public.tenant_ldap_provider_profile_contributions AS contribution
      SET retired_at = transaction_timestamp(),
          retire_reason = 'identity_sync_authoritative_absence',
          version = contribution.version + 1,
          updated_at = transaction_timestamp()
      WHERE contribution.tenant_id = context_tenant
        AND contribution.access_grant_id = candidate.id
        AND contribution.retired_at IS NULL;
      UPDATE public.tenant_ldap_provider_access_grants AS grant_row
      SET ended_at = transaction_timestamp(),
          end_reason = 'identity_sync_authoritative_absence',
          version = grant_row.version + 1,
          updated_at = transaction_timestamp()
      WHERE grant_row.tenant_id = context_tenant AND grant_row.id = candidate.id;
      IF candidate.owns_membership
         AND NOT EXISTS (
           SELECT 1 FROM public.tenant_ldap_provider_access_grants AS other
           WHERE other.tenant_id = context_tenant
             AND other.membership_id = candidate.membership_id
             AND other.id <> candidate.id AND other.ended_at IS NULL
         ) AND NOT EXISTS (
           SELECT 1 FROM public.user_login_identifiers AS identifier
           WHERE identifier.user_id = candidate.user_id
             AND identifier.retired_at IS NULL
         ) THEN
        UPDATE public.tenant_memberships AS membership
        SET status = 'suspended', updated_at = transaction_timestamp()
        WHERE membership.tenant_id = context_tenant
          AND membership.id = candidate.membership_id
          AND membership.status = 'active';
      END IF;
      UPDATE public.tenant_ldap_sync_absences AS absence
      SET status = 'applied', resolved_at = transaction_timestamp(),
          latest_missing_run_id = p_sync_run_id,
          version = absence.version + 1
      WHERE absence.tenant_id = context_tenant
        AND absence.binding_id = run_record.binding_id
        AND absence.external_identity_id = candidate.external_identity_id
        AND absence.status = 'pending';
      revoked := revoked + 1;
    END IF;
  END LOOP;

  SELECT state.revision INTO run_record.authorization_progress_revision
  FROM public.tenant_authorization_states AS state
  WHERE state.tenant_id = context_tenant;
  UPDATE public.tenant_ldap_sync_runs AS run
  SET revoked_count = run.revoked_count + revoked,
      authorization_progress_revision = run_record.authorization_progress_revision
  WHERE run.tenant_id = context_tenant AND run.id = p_sync_run_id;
  SELECT count(*)::integer INTO changed
  FROM public.tenant_ldap_provider_access_grants AS grant_row
  WHERE grant_row.tenant_id = context_tenant
    AND grant_row.binding_id = run_record.binding_id
    AND grant_row.ended_at IS NULL
    AND NOT EXISTS (
      SELECT 1 FROM public.tenant_ldap_sync_staged_observations AS observation
      WHERE observation.tenant_id = context_tenant
        AND observation.sync_run_id = p_sync_run_id
        AND observation.external_identity_id = grant_row.external_identity_id
    )
    AND (config_record.deprovision_mode = 'immediate' OR EXISTS (
      SELECT 1 FROM public.tenant_ldap_sync_absences AS absence
      WHERE absence.tenant_id = context_tenant
        AND absence.binding_id = run_record.binding_id
        AND absence.external_identity_id = grant_row.external_identity_id
        AND absence.status = 'pending'
        AND absence.apply_after <= transaction_timestamp()
    ));
  PERFORM app.private_append_tenant_ldap_runtime_audit_v1(
    p_audit_event_id, context_tenant,
    'tenant.identity.ldap_sync_absence_applied', 'ldap_sync_run',
    p_sync_run_id, p_request_id, p_correlation_id, NULL, p_user_agent,
    'ldap_sync', 'success', NULL, jsonb_build_object(
      'run_id', p_sync_run_id, 'binding_id', run_record.binding_id,
      'provider_id', run_record.provider_id, 'inspected_count', inspected,
      'revoked_count', revoked, 'remaining_count', changed,
      'limit', p_limit,
      'deprovision_mode', config_record.deprovision_mode
    )
  );
  RETURN QUERY SELECT inspected, revoked, changed;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION app.complete_tenant_ldap_sync_run_v1(
  p_sync_run_id uuid,
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
DECLARE
  context_tenant uuid := app.context_tenant_id();
  run_record public.tenant_ldap_sync_runs%ROWTYPE;
  deprovision_mode public.identity_deprovision_mode;
BEGIN
  IF p_sync_run_id IS NULL OR p_expected_version IS NULL
     OR p_audit_event_id IS NULL OR p_request_id IS NULL
     OR p_correlation_id IS NULL OR p_user_agent IS NULL
     OR length(p_user_agent) NOT BETWEEN 1 AND 1024 THEN
    RAISE EXCEPTION 'tenant LDAP sync completion input is invalid'
      USING ERRCODE = '22023';
  END IF;
  SELECT run.* INTO run_record
  FROM public.tenant_ldap_sync_runs AS run
  WHERE run.tenant_id = context_tenant AND run.id = p_sync_run_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant LDAP sync run was not found'
      USING ERRCODE = 'P0002';
  END IF;
  IF run_record.status = 'succeeded'
     AND run_record.version = p_expected_version + 1
     AND EXISTS (
       SELECT 1 FROM public.audit_events AS audit
       WHERE audit.tenant_id = context_tenant
         AND audit.id = p_audit_event_id
         AND audit.action = 'tenant.identity.ldap_sync_completed'
         AND audit.resource_type = 'ldap_sync_run'
         AND audit.resource_id = p_sync_run_id
         AND audit.request_id = p_request_id
         AND audit.correlation_id = p_correlation_id
     ) THEN
    RETURN run_record.version;
  END IF;
  SELECT config.deprovision_mode INTO deprovision_mode
  FROM public.tenant_ldap_provider_configs AS config
  WHERE config.tenant_id = context_tenant
    AND config.provider_id = run_record.provider_id;
  IF NOT FOUND OR run_record.status <> 'applying'
     OR run_record.version <> p_expected_version
     OR run_record.applied_count <> run_record.observed_count
     OR EXISTS (
       SELECT 1 FROM public.tenant_ldap_sync_staged_observations AS observation
       WHERE observation.tenant_id = context_tenant
         AND observation.sync_run_id = p_sync_run_id
         AND observation.applied_at IS NULL
     ) OR NOT app.private_tenant_ldap_sync_run_is_current_v1(
       context_tenant, p_sync_run_id
     ) OR (deprovision_mode <> 'retain' AND EXISTS (
       SELECT 1
       FROM public.tenant_ldap_provider_access_grants AS grant_row
       WHERE grant_row.tenant_id = context_tenant
         AND grant_row.binding_id = run_record.binding_id
         AND grant_row.ended_at IS NULL
         AND NOT EXISTS (
           SELECT 1
           FROM public.tenant_ldap_sync_staged_observations AS observation
           WHERE observation.tenant_id = context_tenant
             AND observation.sync_run_id = p_sync_run_id
             AND observation.external_identity_id = grant_row.external_identity_id
         ) AND (deprovision_mode = 'immediate' OR EXISTS (
           SELECT 1 FROM public.tenant_ldap_sync_absences AS absence
           WHERE absence.tenant_id = context_tenant
             AND absence.binding_id = run_record.binding_id
             AND absence.external_identity_id = grant_row.external_identity_id
             AND absence.status = 'pending'
             AND absence.apply_after <= transaction_timestamp()
         ))
     )) THEN
    RAISE EXCEPTION 'tenant LDAP sync run is incomplete, stale, or has due absence work'
      USING ERRCODE = '40001';
  END IF;
  UPDATE public.tenant_ldap_sync_runs AS run
  SET status = 'succeeded', completed_at = transaction_timestamp(),
      version = run.version + 1
  WHERE run.tenant_id = context_tenant AND run.id = p_sync_run_id
  RETURNING run.version INTO p_expected_version;
  PERFORM app.private_append_tenant_ldap_runtime_audit_v1(
    p_audit_event_id, context_tenant,
    'tenant.identity.ldap_sync_completed', 'ldap_sync_run', p_sync_run_id,
    p_request_id, p_correlation_id, NULL, p_user_agent, 'ldap_sync',
    'success', NULL, jsonb_build_object(
      'run_id', p_sync_run_id, 'binding_id', run_record.binding_id,
      'provider_id', run_record.provider_id,
      'observed_count', run_record.observed_count,
      'applied_count', run_record.applied_count,
      'revoked_count', run_record.revoked_count,
      'enumeration_complete', true, 'result_truncated', false
    )
  );
  RETURN p_expected_version;
END;
$function$;--> statement-breakpoint

ALTER FUNCTION app.private_tenant_ldap_sync_run_is_current_v1(uuid, uuid) OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.private_begin_tenant_ldap_sync_run_v1(uuid, uuid, public.ldap_sync_trigger, text, uuid, uuid, uuid) OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.begin_tenant_ldap_manual_sync_run_v1(uuid, uuid, text, uuid, uuid, uuid, inet, text, text) OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.begin_tenant_ldap_scheduled_sync_run_v1(uuid, uuid, text, uuid, uuid, uuid, text) OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.start_tenant_ldap_sync_enumeration_v1(uuid, integer) OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.stage_tenant_ldap_sync_observation_v1(uuid, uuid, integer, integer, bytea, bytea) OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.complete_tenant_ldap_sync_enumeration_v1(uuid, integer, boolean, boolean, bytea, text, uuid, uuid, uuid, text) OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.apply_tenant_ldap_sync_absence_chunk_v1(uuid, integer, uuid, uuid, uuid, text) OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.complete_tenant_ldap_sync_run_v1(uuid, integer, uuid, uuid, uuid, text) OWNER TO periapsis_migrator;--> statement-breakpoint

REVOKE ALL ON FUNCTION app.private_tenant_ldap_sync_run_is_current_v1(uuid, uuid) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_begin_tenant_ldap_sync_run_v1(uuid, uuid, public.ldap_sync_trigger, text, uuid, uuid, uuid) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.begin_tenant_ldap_manual_sync_run_v1(uuid, uuid, text, uuid, uuid, uuid, inet, text, text) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.begin_tenant_ldap_scheduled_sync_run_v1(uuid, uuid, text, uuid, uuid, uuid, text) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.start_tenant_ldap_sync_enumeration_v1(uuid, integer) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.stage_tenant_ldap_sync_observation_v1(uuid, uuid, integer, integer, bytea, bytea) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.complete_tenant_ldap_sync_enumeration_v1(uuid, integer, boolean, boolean, bytea, text, uuid, uuid, uuid, text) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.apply_tenant_ldap_sync_absence_chunk_v1(uuid, integer, uuid, uuid, uuid, text) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.complete_tenant_ldap_sync_run_v1(uuid, integer, uuid, uuid, uuid, text) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint

GRANT EXECUTE ON FUNCTION app.begin_tenant_ldap_manual_sync_run_v1(uuid, uuid, text, uuid, uuid, uuid, inet, text, text) TO periapsis_api;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.begin_tenant_ldap_scheduled_sync_run_v1(uuid, uuid, text, uuid, uuid, uuid, text) TO periapsis_worker;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.start_tenant_ldap_sync_enumeration_v1(uuid, integer) TO periapsis_worker;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.stage_tenant_ldap_sync_observation_v1(uuid, uuid, integer, integer, bytea, bytea) TO periapsis_worker;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.complete_tenant_ldap_sync_enumeration_v1(uuid, integer, boolean, boolean, bytea, text, uuid, uuid, uuid, text) TO periapsis_worker;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.apply_tenant_ldap_sync_absence_chunk_v1(uuid, integer, uuid, uuid, uuid, text) TO periapsis_worker;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.complete_tenant_ldap_sync_run_v1(uuid, integer, uuid, uuid, uuid, text) TO periapsis_worker;
