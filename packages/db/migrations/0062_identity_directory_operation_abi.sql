-- Custom SQL migration file, put your code below! --
-- Deterministic endpoint projection used both when a run begins and when its
-- exact revision pins are rechecked. Only enabled configured endpoints can be
-- used for network work.
CREATE FUNCTION app.private_tenant_ldap_endpoint_snapshot_v1(
  p_tenant_id uuid,
  p_provider_id uuid
)
RETURNS TABLE (endpoints jsonb, endpoint_digest bytea, endpoint_count integer)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
  WITH endpoint_rows AS (
    SELECT jsonb_build_object(
      'priority', endpoint.priority,
      'host', endpoint.host,
      'port', endpoint.port,
      'transport', endpoint.transport,
      'tlsServerName', endpoint.tls_server_name,
      'referralAllowed', endpoint.referral_allowed,
      'enabled', true
    ) AS value,
    endpoint.priority
    FROM public.tenant_ldap_provider_urls AS endpoint
    WHERE endpoint.tenant_id = p_tenant_id
      AND endpoint.provider_id = p_provider_id
      AND endpoint.enabled
  ), snapshot AS (
    SELECT coalesce(
      jsonb_agg(endpoint_rows.value ORDER BY endpoint_rows.priority),
      '[]'::jsonb
    ) AS value,
    count(*)::integer AS item_count
    FROM endpoint_rows
  )
  SELECT snapshot.value,
         sha256(convert_to(snapshot.value::text, 'UTF8')),
         snapshot.item_count
  FROM snapshot
$function$;--> statement-breakpoint

-- Recheck every database-owned pin without observing or logging any directory
-- value. A false result is converted to the stable stale_configuration result
-- by completion and rejects post-network planner acquisition.
CREATE FUNCTION app.private_tenant_ldap_directory_run_is_current_v1(
  p_tenant_id uuid,
  p_operation_run_id uuid
)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
  SELECT EXISTS (
    SELECT 1
    FROM public.tenant_ldap_directory_operation_runs AS operation
    JOIN public.tenant_auth_providers AS provider
      ON provider.tenant_id = operation.tenant_id
     AND provider.id = operation.provider_id
     AND provider.kind = 'ldap'
    JOIN public.tenant_ldap_provider_configs AS configuration
      ON configuration.tenant_id = provider.tenant_id
     AND configuration.provider_id = provider.id
    JOIN public.tenant_ldap_provider_secrets AS secret
      ON secret.tenant_id = provider.tenant_id
     AND secret.provider_id = provider.id
    JOIN public.identity_keyring_versions AS keyring
      ON keyring.key_version = secret.key_version
     AND keyring.retired_at IS NULL
    CROSS JOIN LATERAL app.private_tenant_ldap_endpoint_snapshot_v1(
      operation.tenant_id, operation.provider_id
    ) AS endpoint_snapshot
    LEFT JOIN public.tenant_auth_provider_bindings AS binding
      ON binding.tenant_id = operation.tenant_id
     AND binding.id = operation.binding_id
     AND binding.provider_id = operation.provider_id
    LEFT JOIN public.tenant_identity_provider_access_epochs AS access_epoch
      ON access_epoch.tenant_id = binding.tenant_id
     AND access_epoch.id = binding.current_access_epoch_id
     AND access_epoch.binding_id = binding.id
     AND access_epoch.provider_id = binding.provider_id
    LEFT JOIN public.tenant_authorization_sources AS access_source
      ON access_source.tenant_id = access_epoch.tenant_id
     AND access_source.id = access_epoch.source_id
    LEFT JOIN public.tenant_authorization_states AS authorization_state
      ON authorization_state.tenant_id = operation.tenant_id
    WHERE operation.tenant_id = p_tenant_id
      AND operation.id = p_operation_run_id
      AND provider.archived_at IS NULL
      AND provider.version = operation.provider_version
      AND configuration.version = operation.configuration_version
      AND secret.id = operation.bind_secret_id
      AND secret.version = operation.bind_secret_version
      AND secret.key_version = operation.bind_secret_key_version
      AND secret.encryption_algorithm = operation.bind_secret_algorithm
      AND endpoint_snapshot.endpoint_count > 0
      AND endpoint_snapshot.endpoint_digest = operation.endpoint_snapshot_digest
      AND (
        operation.binding_id IS NULL
        OR (
          provider.enabled
          AND binding.enabled
          AND binding.archived_at IS NULL
          AND binding.version = operation.binding_version
          AND binding.auth_revision = operation.binding_auth_revision
          AND binding.mapping_revision = operation.rule_set_revision
          AND binding.current_access_epoch_id = operation.binding_access_epoch_id
          AND access_epoch.ended_at IS NULL
          AND access_source.kind = 'identity_provider_access'
          AND access_source.retired_at IS NULL
          AND authorization_state.initialized_at IS NOT NULL
          AND authorization_state.revision = operation.authorization_revision
          AND NOT EXISTS (
            SELECT 1
            FROM public.tenant_ldap_directory_run_mappings AS pinned
            LEFT JOIN public.tenant_ldap_mapping_rules AS rule
              ON rule.tenant_id = pinned.tenant_id
             AND rule.id = pinned.mapping_rule_id
             AND rule.binding_id = pinned.binding_id
            LEFT JOIN public.tenant_ldap_mapping_rule_epochs AS epoch
              ON epoch.tenant_id = rule.tenant_id
             AND epoch.id = rule.current_source_epoch_id
            LEFT JOIN public.tenant_authorization_sources AS source
              ON source.tenant_id = epoch.tenant_id
             AND source.id = epoch.source_id
            WHERE pinned.tenant_id = operation.tenant_id
              AND pinned.operation_run_id = operation.id
              AND (
                rule.id IS NULL
                OR rule.version <> pinned.mapping_version
                OR rule.configuration_revision <> pinned.configuration_revision
                OR rule.archived_at IS NOT NULL
                OR (
                  NOT pinned.included_disabled
                  AND (
                    NOT rule.enabled
                    OR epoch.id IS DISTINCT FROM pinned.source_epoch_id
                    OR epoch.sequence IS DISTINCT FROM pinned.source_epoch_sequence
                    OR epoch.ended_at IS NOT NULL
                    OR source.id IS DISTINCT FROM pinned.authorization_source_id
                    OR source.kind <> 'identity_mapping'
                    OR source.retired_at IS NOT NULL
                  )
                )
                OR (
                  pinned.included_disabled
                  AND (rule.enabled OR rule.current_source_epoch_id IS NOT NULL)
                )
              )
          )
        )
      )
  )
$function$;--> statement-breakpoint

CREATE FUNCTION app.private_begin_tenant_ldap_directory_operation_v1(
  p_operation_run_id uuid,
  p_provider_id uuid,
  p_operation_kind public.ldap_directory_operation_kind,
  p_binding_id uuid,
  p_include_disabled_mapping_ids uuid[],
  p_reason text,
  p_actor_membership_id uuid,
  p_request_id uuid,
  p_correlation_id uuid
)
RETURNS TABLE (
  operation_run_id uuid,
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
  started_at timestamptz,
  expires_at timestamptz
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  locked_provider public.tenant_auth_providers%ROWTYPE;
  locked_configuration public.tenant_ldap_provider_configs%ROWTYPE;
  locked_secret public.tenant_ldap_provider_secrets%ROWTYPE;
  locked_binding public.tenant_auth_provider_bindings%ROWTYPE;
  current_authorization_revision bigint;
  endpoint_snapshot jsonb;
  endpoint_digest bytea;
  enabled_endpoint_count integer;
  selected_mapping_count integer;
  requested_disabled_count integer := coalesce(cardinality(p_include_disabled_mapping_ids), 0);
  recent_actor_provider_count integer;
  recent_provider_count integer;
  recent_tenant_count integer;
  run_started_at timestamptz := transaction_timestamp();
  run_expires_at timestamptz := transaction_timestamp() + interval '2 minutes';
BEGIN
  IF p_operation_run_id IS NULL
     OR (uuid_extract_version(p_operation_run_id) = 7) IS NOT TRUE
     OR p_provider_id IS NULL OR p_operation_kind IS NULL
     OR p_actor_membership_id IS NULL
     OR p_request_id IS NULL OR p_correlation_id IS NULL
     OR p_reason IS NULL OR btrim(p_reason) = ''
     OR char_length(p_reason) > 500 OR p_reason ~ '[[:cntrl:]]'
     OR requested_disabled_count > 32
     OR (requested_disabled_count > 0 AND (
       coalesce(array_ndims(p_include_disabled_mapping_ids), 0) <> 1
       OR array_lower(p_include_disabled_mapping_ids, 1) <> 1
     ))
     OR (p_binding_id IS NULL AND requested_disabled_count <> 0)
     OR (p_binding_id IS NOT NULL AND p_operation_kind <> 'search_user') THEN
    RAISE EXCEPTION 'tenant LDAP directory operation input is invalid'
      USING ERRCODE = '22023';
  END IF;
  IF requested_disabled_count > 0 AND EXISTS (
    SELECT 1
    FROM unnest(p_include_disabled_mapping_ids) AS requested(mapping_rule_id)
    WHERE requested.mapping_rule_id IS NULL
    GROUP BY requested.mapping_rule_id
    HAVING count(*) > 0
  ) OR requested_disabled_count > 0 AND EXISTS (
    SELECT 1
    FROM unnest(p_include_disabled_mapping_ids) AS requested(mapping_rule_id)
    GROUP BY requested.mapping_rule_id
    HAVING count(*) > 1
  ) THEN
    RAISE EXCEPTION 'disabled LDAP mapping selection must be unique'
      USING ERRCODE = '22023';
  END IF;

  SELECT provider.* INTO locked_provider
  FROM public.tenant_auth_providers AS provider
  WHERE provider.tenant_id = context_tenant
    AND provider.id = p_provider_id
    AND provider.kind = 'ldap'
    AND provider.archived_at IS NULL
  FOR SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant LDAP provider was not found'
      USING ERRCODE = 'P0002';
  END IF;

  SELECT provider_configuration.* INTO locked_configuration
  FROM public.tenant_ldap_provider_configs AS provider_configuration
  WHERE provider_configuration.tenant_id = context_tenant
    AND provider_configuration.provider_id = p_provider_id
  FOR SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant LDAP provider configuration is unavailable'
      USING ERRCODE = '55000';
  END IF;

  SELECT provider_secret.* INTO locked_secret
  FROM public.tenant_ldap_provider_secrets AS provider_secret
  JOIN public.identity_keyring_versions AS keyring
    ON keyring.key_version = provider_secret.key_version
   AND keyring.retired_at IS NULL
  WHERE provider_secret.tenant_id = context_tenant
    AND provider_secret.provider_id = p_provider_id
  FOR SHARE OF provider_secret, keyring;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant LDAP provider bind secret is unavailable'
      USING ERRCODE = '55000';
  END IF;

  SELECT snapshot.endpoints, snapshot.endpoint_digest, snapshot.endpoint_count
  INTO endpoint_snapshot, endpoint_digest, enabled_endpoint_count
  FROM app.private_tenant_ldap_endpoint_snapshot_v1(
    context_tenant, p_provider_id
  ) AS snapshot;
  IF enabled_endpoint_count IS NULL OR enabled_endpoint_count < 1 THEN
    RAISE EXCEPTION 'tenant LDAP provider has no enabled endpoint'
      USING ERRCODE = '55000';
  END IF;

  IF p_binding_id IS NOT NULL THEN
    SELECT binding.* INTO locked_binding
    FROM public.tenant_auth_provider_bindings AS binding
    JOIN public.tenant_identity_provider_access_epochs AS access_epoch
      ON access_epoch.tenant_id = binding.tenant_id
     AND access_epoch.id = binding.current_access_epoch_id
     AND access_epoch.binding_id = binding.id
     AND access_epoch.provider_id = binding.provider_id
     AND access_epoch.ended_at IS NULL
    JOIN public.tenant_authorization_sources AS access_source
      ON access_source.tenant_id = access_epoch.tenant_id
     AND access_source.id = access_epoch.source_id
     AND access_source.kind = 'identity_provider_access'
     AND access_source.retired_at IS NULL
    WHERE binding.tenant_id = context_tenant
      AND binding.id = p_binding_id
      AND binding.provider_id = p_provider_id
      AND binding.enabled
      AND binding.archived_at IS NULL
      AND locked_provider.enabled
    FOR SHARE OF binding, access_epoch, access_source;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'live tenant LDAP binding was not found'
        USING ERRCODE = 'P0002';
    END IF;
    SELECT state.revision INTO current_authorization_revision
    FROM public.tenant_authorization_states AS state
    WHERE state.tenant_id = context_tenant
      AND state.initialized_at IS NOT NULL
    FOR SHARE;
    IF NOT FOUND OR current_authorization_revision < 1 THEN
      RAISE EXCEPTION 'tenant authorization state is unavailable'
        USING ERRCODE = '55000';
    END IF;
    IF requested_disabled_count <> (
      SELECT count(*)::integer
      FROM public.tenant_ldap_mapping_rules AS rule
      WHERE rule.tenant_id = context_tenant
        AND rule.binding_id = p_binding_id
        AND rule.id = ANY(p_include_disabled_mapping_ids)
        AND NOT rule.enabled
        AND rule.current_source_epoch_id IS NULL
        AND rule.archived_at IS NULL
    ) THEN
      RAISE EXCEPTION 'explicit disabled LDAP mapping was not found'
        USING ERRCODE = 'P0002';
    END IF;
    SELECT count(*)::integer INTO selected_mapping_count
    FROM public.tenant_ldap_mapping_rules AS rule
    WHERE rule.tenant_id = context_tenant
      AND rule.binding_id = p_binding_id
      AND rule.archived_at IS NULL
      AND (rule.enabled OR rule.id = ANY(p_include_disabled_mapping_ids));
    IF selected_mapping_count > 1000 THEN
      RAISE EXCEPTION 'tenant LDAP dry-run mapping snapshot exceeds its bound'
        USING ERRCODE = '54000';
    END IF;
  END IF;

  -- One tenant-wide lock makes every count-and-admit decision serializable.
  PERFORM pg_advisory_xact_lock(hashtextextended(
    'tenant_ldap_directory_rate:' || context_tenant::text, 0
  ));
  SELECT
    count(*) FILTER (
      WHERE recent.provider_id = p_provider_id
        AND recent.started_by_membership_id = p_actor_membership_id
    )::integer,
    count(*) FILTER (WHERE recent.provider_id = p_provider_id)::integer,
    count(*)::integer
  INTO recent_actor_provider_count, recent_provider_count, recent_tenant_count
  FROM public.tenant_ldap_directory_operation_runs AS recent
  WHERE recent.tenant_id = context_tenant
    AND recent.started_at >= run_started_at - interval '1 minute';
  IF recent_actor_provider_count >= 5
     OR recent_provider_count >= 20
     OR recent_tenant_count >= 50 THEN
    RAISE EXCEPTION 'tenant LDAP directory operations are temporarily rate limited'
      USING ERRCODE = '53300';
  END IF;

  INSERT INTO public.tenant_ldap_directory_operation_runs (
    id, tenant_id, provider_id, provider_kind, operation_kind, binding_id,
    provider_version, configuration_version, endpoint_snapshot_digest,
    bind_secret_id, bind_secret_version, bind_secret_key_version,
    bind_secret_algorithm, binding_version, binding_auth_revision,
    binding_access_epoch_id, rule_set_revision, authorization_revision,
    reason, started_by_membership_id, request_id, correlation_id,
    started_at, expires_at
  ) VALUES (
    p_operation_run_id, context_tenant, p_provider_id, 'ldap',
    p_operation_kind, p_binding_id, locked_provider.version,
    locked_configuration.version, endpoint_digest, locked_secret.id,
    locked_secret.version, locked_secret.key_version,
    locked_secret.encryption_algorithm,
    CASE WHEN p_binding_id IS NULL THEN NULL ELSE locked_binding.version END,
    CASE WHEN p_binding_id IS NULL THEN NULL ELSE locked_binding.auth_revision END,
    CASE WHEN p_binding_id IS NULL THEN NULL ELSE locked_binding.current_access_epoch_id END,
    CASE WHEN p_binding_id IS NULL THEN NULL ELSE locked_binding.mapping_revision END,
    current_authorization_revision, p_reason, p_actor_membership_id,
    p_request_id, p_correlation_id, run_started_at, run_expires_at
  );

  IF p_binding_id IS NOT NULL THEN
    INSERT INTO public.tenant_ldap_directory_run_mappings (
      tenant_id, operation_run_id, binding_id, mapping_rule_id,
      mapping_version, configuration_revision, source_epoch_id,
      source_epoch_sequence, authorization_source_id,
      planning_epoch_id, planning_source_id, included_disabled, priority
    )
    SELECT rule.tenant_id, p_operation_run_id, rule.binding_id, rule.id,
           rule.version, rule.configuration_revision,
           CASE WHEN rule.enabled THEN epoch.id ELSE NULL END,
           CASE WHEN rule.enabled THEN epoch.sequence ELSE NULL END,
           CASE WHEN rule.enabled THEN epoch.source_id ELSE NULL END,
           CASE WHEN rule.enabled THEN epoch.id ELSE uuidv7() END,
           CASE WHEN rule.enabled THEN epoch.source_id ELSE uuidv7() END,
           NOT rule.enabled, rule.priority
    FROM public.tenant_ldap_mapping_rules AS rule
    LEFT JOIN public.tenant_ldap_mapping_rule_epochs AS epoch
      ON epoch.tenant_id = rule.tenant_id
     AND epoch.id = rule.current_source_epoch_id
     AND epoch.mapping_rule_id = rule.id
     AND epoch.binding_id = rule.binding_id
     AND epoch.configuration_revision = rule.configuration_revision
    WHERE rule.tenant_id = context_tenant
      AND rule.binding_id = p_binding_id
      AND rule.archived_at IS NULL
      AND (rule.enabled OR rule.id = ANY(p_include_disabled_mapping_ids))
    ORDER BY rule.priority, rule.id;
  END IF;

  RETURN QUERY
  SELECT p_operation_run_id, context_tenant, p_provider_id,
         locked_provider.version, locked_configuration.version,
         endpoint_digest,
         jsonb_build_object(
           'template', locked_configuration.template,
           'verifyCertificate', locked_configuration.verify_certificate,
           'customCaPem', locked_configuration.custom_ca_pem,
           'connectTimeoutMs', locked_configuration.connect_timeout_ms,
           'operationTimeoutMs', locked_configuration.operation_timeout_ms,
           'bindDn', locked_configuration.bind_dn,
           'userBaseDn', locked_configuration.user_base_dn,
           'groupBaseDn', locked_configuration.group_base_dn,
           'userSearchFilter', locked_configuration.user_search_filter,
           'groupSearchFilter', locked_configuration.group_search_filter,
           'userDnTemplate', locked_configuration.user_dn_template,
           'pageSize', locked_configuration.page_size,
           'maxPages', locked_configuration.max_pages,
           'maxEntries', locked_configuration.max_entries,
           'maxResponseBytes', locked_configuration.max_response_bytes,
           'referralMode', locked_configuration.referral_mode,
           'maxReferralHops', locked_configuration.max_referral_hops,
           'nestedGroupMode', locked_configuration.nested_group_mode,
           'maxNestedGroupDepth', locked_configuration.max_nested_group_depth,
           'maxGroups', locked_configuration.max_groups,
           'firstNameAttribute', locked_configuration.first_name_attribute,
           'lastNameAttribute', locked_configuration.last_name_attribute,
           'displayNameAttribute', locked_configuration.display_name_attribute,
           'usernameAttribute', locked_configuration.username_attribute,
           'alternateUsernameAttribute', locked_configuration.alternate_username_attribute,
           'emailAttribute', locked_configuration.email_attribute,
           'immutableSubjectAttribute', locked_configuration.immutable_subject_attribute,
           'immutableSubjectFormat', locked_configuration.immutable_subject_format,
           'groupMembershipAttribute', locked_configuration.group_membership_attribute,
           'posixMemberUidAttribute', locked_configuration.posix_member_uid_attribute,
           'posixGidNumberAttribute', locked_configuration.posix_gid_number_attribute,
           'accountStatusMode', locked_configuration.account_status_mode,
           'accountStatusAttribute', locked_configuration.account_status_attribute,
           'accountDisabledValue', locked_configuration.account_disabled_value,
           'jitMode', locked_configuration.jit_mode,
           'noMatchPolicy', locked_configuration.no_match_policy,
           'deprovisionMode', locked_configuration.deprovision_mode,
           'deprovisionGraceSeconds', locked_configuration.deprovision_grace_seconds,
           'syncIntervalSeconds', locked_configuration.sync_interval_seconds
         ), endpoint_snapshot, locked_secret.id,
         locked_secret.secret_ciphertext, locked_secret.secret_nonce,
         locked_secret.version, locked_secret.key_version,
         locked_secret.encryption_algorithm, p_binding_id,
         CASE WHEN p_binding_id IS NULL THEN NULL ELSE locked_binding.version END,
         CASE WHEN p_binding_id IS NULL THEN NULL ELSE locked_binding.auth_revision END,
         CASE WHEN p_binding_id IS NULL THEN NULL ELSE locked_binding.current_access_epoch_id END,
         CASE WHEN p_binding_id IS NULL THEN NULL ELSE locked_binding.mapping_revision END,
         current_authorization_revision,
         coalesce((
           SELECT jsonb_agg(jsonb_build_object(
             'mappingId', pinned.mapping_rule_id,
             'mappingVersion', pinned.mapping_version,
             'sourceEpochId', pinned.source_epoch_id,
             'sourceEpochSequence', pinned.source_epoch_sequence,
             'includedDisabled', pinned.included_disabled
           ) ORDER BY pinned.priority, pinned.mapping_rule_id)
           FROM public.tenant_ldap_directory_run_mappings AS pinned
           WHERE pinned.tenant_id = context_tenant
             AND pinned.operation_run_id = p_operation_run_id
         ), '[]'::jsonb), run_started_at, run_expires_at;
END;
$function$;--> statement-breakpoint

-- A mutation may return its current representation without implicitly adding
-- identity_provider.read to the mutation authorization contract.
CREATE FUNCTION app.get_tenant_auth_provider_binding_mutation_result_v1(
  p_binding_id uuid
)
RETURNS TABLE (
  id uuid,
  provider_id uuid,
  key text,
  enabled boolean,
  profile_priority integer,
  auth_revision integer,
  current_access_epoch_id uuid,
  archived_at timestamptz,
  version integer,
  created_at timestamptz,
  updated_at timestamptz
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
BEGIN
  PERFORM app.current_tenant_membership_id();
  IF NOT app.current_tenant_human_has_exact_permission_v3(
    'identity_provider.manage', 'tenant'
  ) THEN
    RAISE EXCEPTION 'identity_provider.manage tenant scope is required'
      USING ERRCODE = '42501';
  END IF;

  RETURN QUERY
  SELECT binding.id, binding.provider_id, binding.key, binding.enabled,
         binding.profile_priority, binding.auth_revision,
         binding.current_access_epoch_id, binding.archived_at,
         binding.version, binding.created_at, binding.updated_at
  FROM public.tenant_auth_provider_bindings AS binding
  WHERE binding.tenant_id = context_tenant
    AND binding.id = p_binding_id;
END;
$function$;--> statement-breakpoint

-- Mapping mutations have the same projection need, including exact role and
-- source-epoch consequences. The mutation permissions are sufficient; read is
-- deliberately not required as an accidental extra capability.
CREATE FUNCTION app.get_tenant_ldap_mapping_rule_mutation_result_v1(
  p_mapping_rule_id uuid
)
RETURNS TABLE (
  id uuid,
  binding_id uuid,
  matcher_type public.ldap_mapping_matcher_type,
  matcher_value text,
  case_mode public.ldap_mapping_case_mode,
  priority integer,
  security_group_id uuid,
  reconciliation_mode public.ldap_mapping_reconciliation_mode,
  role_ids uuid[],
  operator_team_id uuid,
  operator_team_assignment_epoch_id uuid,
  enabled boolean,
  current_source_epoch_id uuid,
  current_source_epoch_sequence integer,
  current_source_epoch_activated_at timestamptz,
  configuration_revision integer,
  notes text,
  last_matched_at timestamptz,
  archived_at timestamptz,
  version integer,
  created_at timestamptz,
  updated_at timestamptz
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
BEGIN
  PERFORM app.current_tenant_membership_id();
  IF NOT app.current_tenant_human_has_exact_permission_v3(
    'identity_mapping.manage', 'tenant'
  ) OR NOT app.current_tenant_human_has_exact_permission_v3(
    'role.grant', 'tenant'
  ) THEN
    RAISE EXCEPTION 'identity_mapping.manage and role.grant tenant scopes are required'
      USING ERRCODE = '42501';
  END IF;

  RETURN QUERY
  SELECT rule.id, rule.binding_id, rule.matcher_type, rule.matcher_value,
         rule.case_mode, rule.priority, rule.tenant_security_group_id,
         rule.reconciliation_mode, targets.role_ids,
         rule.operator_team_id, rule.operator_team_assignment_epoch_id,
         rule.enabled, rule.current_source_epoch_id, epoch.sequence,
         epoch.activated_at, rule.configuration_revision, rule.notes,
         rule.last_matched_at, rule.archived_at, rule.version,
         rule.created_at, rule.updated_at
  FROM public.tenant_ldap_mapping_rules AS rule
  JOIN LATERAL (
    SELECT array_agg(target.role_id ORDER BY target.role_id)::uuid[] AS role_ids
    FROM public.tenant_ldap_mapping_rule_role_targets AS target
    WHERE target.tenant_id = rule.tenant_id
      AND target.mapping_rule_id = rule.id
      AND target.configuration_revision = rule.configuration_revision
  ) AS targets ON true
  LEFT JOIN public.tenant_ldap_mapping_rule_epochs AS epoch
    ON epoch.tenant_id = rule.tenant_id
   AND epoch.id = rule.current_source_epoch_id
  WHERE rule.tenant_id = context_tenant
    AND rule.id = p_mapping_rule_id;
END;
$function$;--> statement-breakpoint

-- Successor for the sealed v1 mapping create. v1 included notes in the
-- idempotency fingerprint but omitted the value from INSERT. New creates repair
-- that omission before returning a manage-authorized full current row; exact
-- replays return the current representation without overwriting later edits.
CREATE FUNCTION app.create_tenant_ldap_mapping_rule_v2(
  p_idempotency_key_digest bytea,
  p_binding_id uuid,
  p_matcher_type public.ldap_mapping_matcher_type,
  p_matcher_value text,
  p_case_mode public.ldap_mapping_case_mode,
  p_priority integer,
  p_security_group_id uuid,
  p_reconciliation_mode public.ldap_mapping_reconciliation_mode,
  p_role_ids uuid[],
  p_operator_team_id uuid,
  p_operator_team_assignment_epoch_id uuid,
  p_notes text,
  p_reason text,
  p_audit_event_id uuid,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text
)
RETURNS TABLE (
  id uuid,
  binding_id uuid,
  matcher_type public.ldap_mapping_matcher_type,
  matcher_value text,
  case_mode public.ldap_mapping_case_mode,
  priority integer,
  security_group_id uuid,
  reconciliation_mode public.ldap_mapping_reconciliation_mode,
  role_ids uuid[],
  operator_team_id uuid,
  operator_team_assignment_epoch_id uuid,
  enabled boolean,
  current_source_epoch_id uuid,
  current_source_epoch_sequence integer,
  current_source_epoch_activated_at timestamptz,
  configuration_revision integer,
  notes text,
  last_matched_at timestamptz,
  archived_at timestamptz,
  version integer,
  created_at timestamptz,
  updated_at timestamptz,
  replayed boolean
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  created record;
  current_result record;
BEGIN
  SELECT * INTO created
  FROM app.create_tenant_ldap_mapping_rule_v1(
    p_idempotency_key_digest, p_binding_id, p_matcher_type,
    p_matcher_value, p_case_mode, p_priority, p_security_group_id,
    p_reconciliation_mode, p_role_ids, p_operator_team_id,
    p_operator_team_assignment_epoch_id, p_notes, p_reason,
    p_audit_event_id, p_request_id, p_correlation_id, p_ip_address,
    p_user_agent, p_authentication_method
  );

  IF NOT created.replayed AND p_notes <> '' THEN
    UPDATE public.tenant_ldap_mapping_rules AS rule
    SET notes = p_notes
    WHERE rule.tenant_id = context_tenant
      AND rule.id = created.result_resource_id
      AND rule.version = created.result_version;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'new tenant LDAP mapping result is unavailable'
        USING ERRCODE = '55000';
    END IF;
  END IF;

  SELECT * INTO current_result
  FROM app.get_tenant_ldap_mapping_rule_mutation_result_v1(
    created.result_resource_id
  );
  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant LDAP mapping mutation result is unavailable'
      USING ERRCODE = '55000';
  END IF;

  RETURN QUERY SELECT
    current_result.id, current_result.binding_id,
    current_result.matcher_type, current_result.matcher_value,
    current_result.case_mode, current_result.priority,
    current_result.security_group_id, current_result.reconciliation_mode,
    current_result.role_ids, current_result.operator_team_id,
    current_result.operator_team_assignment_epoch_id,
    current_result.enabled, current_result.current_source_epoch_id,
    current_result.current_source_epoch_sequence,
    current_result.current_source_epoch_activated_at,
    current_result.configuration_revision, current_result.notes,
    current_result.last_matched_at, current_result.archived_at,
    current_result.version, current_result.created_at,
    current_result.updated_at, created.replayed;
END;
$function$;--> statement-breakpoint

-- A rotated provider secret may leave an already committed network operation
-- holding the prior ciphertext until its bounded expiry. v3 inventories those
-- transient pins before delegating the permanent bind/subject inventory to v2.
CREATE FUNCTION app.verify_identity_keyring_v3(
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
  ) THEN
    RETURN false;
  END IF;
  RETURN app.verify_identity_keyring_v2(
    p_versions, p_verifiers, p_active_version
  );
END;
$function$;--> statement-breakpoint

-- Post-network, digest-only acquisition of every relational input required by
-- identity.LDAPPlanningSnapshot. It is pure, short-lived, and rejects any pin
-- changed since the committed begin operation.
CREATE FUNCTION app.get_tenant_ldap_dry_run_planning_snapshot_v1(
  p_operation_run_id uuid,
  p_digest_key_versions integer[],
  p_subject_digests bytea[]
)
RETURNS TABLE (
  operation_run_id uuid,
  tenant_id uuid,
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
  effective_until timestamptz,
  provider_access_source_id uuid,
  provider_access_epoch_id uuid,
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
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  actor_membership uuid;
  locked_run public.tenant_ldap_directory_operation_runs%ROWTYPE;
  found_identity_ids uuid[];
  found_user_ids uuid[];
  found_identity_id uuid;
  found_user_id uuid;
  found_membership_id uuid;
  found_user_active boolean := false;
  found_membership_active boolean := false;
  current_access_source_id uuid;
  digest_count integer := coalesce(array_length(p_digest_key_versions, 1), 0);
  digest_index integer;
  live_access boolean := false;
BEGIN
  actor_membership := app.current_tenant_membership_id();
  IF NOT app.current_tenant_human_has_exact_permission_v3(
    'identity_provider.test', 'tenant'
  ) OR NOT app.current_tenant_human_has_exact_permission_v3(
    'identity_mapping.manage', 'tenant'
  ) THEN
    RAISE EXCEPTION 'identity_provider.test and identity_mapping.manage tenant scopes are required'
      USING ERRCODE = '42501';
  END IF;
  IF digest_count < 1 OR digest_count > 16
     OR coalesce(array_length(p_subject_digests, 1), 0) <> digest_count
     OR coalesce(array_ndims(p_digest_key_versions), 0) <> 1
     OR coalesce(array_ndims(p_subject_digests), 0) <> 1
     OR array_lower(p_digest_key_versions, 1) <> 1
     OR array_lower(p_subject_digests, 1) <> 1 THEN
    RAISE EXCEPTION 'immutable-subject digest lookup is invalid'
      USING ERRCODE = '22023';
  END IF;
  FOR digest_index IN 1..digest_count LOOP
    IF p_digest_key_versions[digest_index] IS NULL
       OR p_subject_digests[digest_index] IS NULL
       OR octet_length(p_subject_digests[digest_index]) <> 32
       OR (digest_index > 1 AND
           p_digest_key_versions[digest_index - 1] >=
             p_digest_key_versions[digest_index])
       OR NOT EXISTS (
         SELECT 1 FROM public.identity_keyring_versions AS keyring
         WHERE keyring.key_version = p_digest_key_versions[digest_index]
           AND keyring.retired_at IS NULL
       ) THEN
      RAISE EXCEPTION 'immutable-subject digest lookup is invalid'
        USING ERRCODE = '22023';
    END IF;
  END LOOP;

  SELECT operation.* INTO locked_run
  FROM public.tenant_ldap_directory_operation_runs AS operation
  WHERE operation.tenant_id = context_tenant
    AND operation.id = p_operation_run_id;
  IF NOT FOUND OR locked_run.binding_id IS NULL THEN
    RAISE EXCEPTION 'tenant LDAP mapping dry run was not found'
      USING ERRCODE = 'P0002';
  END IF;
  IF locked_run.started_by_membership_id <> actor_membership THEN
    RAISE EXCEPTION 'tenant LDAP mapping dry run belongs to another actor'
      USING ERRCODE = '42501';
  END IF;
  IF locked_run.status <> 'started'
     OR transaction_timestamp() > locked_run.expires_at
     OR NOT app.private_tenant_ldap_directory_run_is_current_v1(
       context_tenant, p_operation_run_id
     ) THEN
    RAISE EXCEPTION 'tenant LDAP mapping dry-run snapshot is stale'
      USING ERRCODE = '40001';
  END IF;

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
    RAISE EXCEPTION 'immutable-subject digest aliases disagree'
      USING ERRCODE = '23505';
  END IF;
  found_identity_id := found_identity_ids[1];
  found_user_id := found_user_ids[1];
  IF found_user_id IS NOT NULL THEN
    SELECT local_user.active, membership.id,
           coalesce(membership.status = 'active', false)
    INTO found_user_active, found_membership_id,
         found_membership_active
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
  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant LDAP provider access epoch is stale'
      USING ERRCODE = '40001';
  END IF;
  IF found_identity_id IS NOT NULL
     AND found_user_active
     AND found_membership_id IS NOT NULL
     AND found_membership_active THEN
    SELECT EXISTS (
      SELECT 1
      FROM public.tenant_ldap_provider_access_grants AS access_grant
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
           pinned.planning_epoch_id, pinned.planning_source_id,
           pinned.included_disabled, pinned.priority,
           CASE WHEN pinned.included_disabled THEN rule.matcher_type
                ELSE epoch.matcher_type END AS matcher_type,
           CASE WHEN pinned.included_disabled THEN rule.matcher_value
                ELSE epoch.matcher_value END AS matcher_value,
           CASE WHEN pinned.included_disabled THEN rule.case_mode
                ELSE epoch.case_mode END AS case_mode,
           CASE WHEN pinned.included_disabled THEN rule.reconciliation_mode
                ELSE epoch.reconciliation_mode END AS reconciliation_mode,
           CASE WHEN pinned.included_disabled THEN rule.tenant_security_group_id
                ELSE epoch.tenant_security_group_id END AS security_group_id,
           CASE WHEN pinned.included_disabled THEN rule.operator_team_id
                ELSE epoch.operator_team_id END AS operator_team_id,
           CASE WHEN pinned.included_disabled THEN rule.operator_team_assignment_epoch_id
                ELSE epoch.operator_team_assignment_epoch_id END
             AS operator_team_assignment_epoch_id,
           pinned.configuration_revision
    FROM public.tenant_ldap_directory_run_mappings AS pinned
    JOIN public.tenant_ldap_mapping_rules AS rule
      ON rule.tenant_id = pinned.tenant_id
     AND rule.id = pinned.mapping_rule_id
     AND rule.binding_id = pinned.binding_id
    LEFT JOIN public.tenant_ldap_mapping_rule_epochs AS epoch
      ON epoch.tenant_id = pinned.tenant_id
     AND epoch.id = pinned.source_epoch_id
    WHERE pinned.tenant_id = context_tenant
      AND pinned.operation_run_id = p_operation_run_id
  ), rule_roles AS (
    SELECT selected.mapping_rule_id,
           coalesce(array_agg(target.role_id ORDER BY target.role_id),
                    ARRAY[]::uuid[]) AS role_ids
    FROM selected_rules AS selected
    LEFT JOIN public.tenant_ldap_mapping_rule_role_targets AS target
      ON target.tenant_id = context_tenant
     AND target.mapping_rule_id = selected.mapping_rule_id
     AND target.configuration_revision = selected.configuration_revision
    GROUP BY selected.mapping_rule_id
  ), target_groups AS (
    SELECT DISTINCT selected.security_group_id
    FROM selected_rules AS selected
  ), group_policy_roles AS (
    SELECT target_group.security_group_id,
           coalesce(array_agg(DISTINCT group_grant.role_id
                              ORDER BY group_grant.role_id)
                    FILTER (WHERE group_grant.role_id IS NOT NULL),
                    ARRAY[]::uuid[]) AS role_ids
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
     AND group_role.archived_at IS NULL
    WHERE group_grant.id IS NULL
       OR (group_source.id IS NOT NULL AND group_role.id IS NOT NULL)
    GROUP BY target_group.security_group_id
  ), effective_role_ids AS (
    SELECT direct_grant.role_id
    FROM public.tenant_membership_role_grants AS direct_grant
    JOIN public.tenant_authorization_sources AS source
      ON source.tenant_id = direct_grant.tenant_id
     AND source.id = direct_grant.source_id
     AND source.retired_at IS NULL
    JOIN public.tenant_roles AS role
      ON role.tenant_id = direct_grant.tenant_id
     AND role.id = direct_grant.role_id
     AND role.principal_kind = 'human'
     AND role.archived_at IS NULL
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
    JOIN public.tenant_security_groups AS security_group
      ON security_group.tenant_id = group_member.tenant_id
     AND security_group.id = group_member.group_id
     AND security_group.archived_at IS NULL
    JOIN public.tenant_security_group_role_grants AS group_grant
      ON group_grant.tenant_id = group_member.tenant_id
     AND group_grant.group_id = group_member.group_id
     AND group_grant.revoked_at IS NULL
     AND (group_grant.expires_at IS NULL
          OR group_grant.expires_at > transaction_timestamp())
    JOIN public.tenant_authorization_sources AS grant_source
      ON grant_source.tenant_id = group_grant.tenant_id
     AND grant_source.id = group_grant.source_id
     AND grant_source.retired_at IS NULL
    JOIN public.tenant_roles AS role
      ON role.tenant_id = group_grant.tenant_id
     AND role.id = group_grant.role_id
     AND role.principal_kind = 'human'
     AND role.archived_at IS NULL
    WHERE group_member.tenant_id = context_tenant
      AND group_member.membership_id = found_membership_id
      AND group_member.revoked_at IS NULL
      AND (group_member.expires_at IS NULL
           OR group_member.expires_at > transaction_timestamp())
  ), needed_roles AS (
    SELECT unnest(rule_roles.role_ids) AS role_id FROM rule_roles
    UNION SELECT unnest(group_policy_roles.role_ids) FROM group_policy_roles
    UNION SELECT effective_role_ids.role_id FROM effective_role_ids
  ), role_policy_rows AS (
    SELECT role.id AS role_id,
           coalesce(jsonb_agg(jsonb_build_object(
             'permission', permission.key,
             'scope', policy.scope
           ) ORDER BY permission.key, policy.scope)
           FILTER (WHERE permission.id IS NOT NULL), '[]'::jsonb) AS policy
    FROM needed_roles AS needed
    JOIN public.tenant_roles AS role
      ON role.tenant_id = context_tenant
     AND role.id = needed.role_id
     AND role.principal_kind = 'human'
     AND role.archived_at IS NULL
    LEFT JOIN public.tenant_role_permissions AS policy
      ON policy.tenant_id = role.tenant_id AND policy.role_id = role.id
    LEFT JOIN public.tenant_permissions AS permission
      ON permission.id = policy.permission_id
    GROUP BY role.id
  ), actor_role_paths AS (
    SELECT direct_grant.role_id, direct_grant.expires_at
    FROM public.tenant_membership_role_grants AS direct_grant
    JOIN public.tenant_authorization_sources AS source
      ON source.tenant_id = direct_grant.tenant_id
     AND source.id = direct_grant.source_id
     AND source.retired_at IS NULL
    WHERE direct_grant.tenant_id = context_tenant
      AND direct_grant.membership_id = actor_membership
      AND direct_grant.revoked_at IS NULL
      AND (direct_grant.expires_at IS NULL
           OR direct_grant.expires_at > transaction_timestamp())
    UNION ALL
    SELECT group_grant.role_id,
           app.earliest_authorization_expiry(
             group_member.expires_at, group_grant.expires_at
           )
    FROM public.tenant_security_group_memberships AS group_member
    JOIN public.tenant_authorization_sources AS member_source
      ON member_source.tenant_id = group_member.tenant_id
     AND member_source.id = group_member.source_id
     AND member_source.retired_at IS NULL
    JOIN public.tenant_security_groups AS security_group
      ON security_group.tenant_id = group_member.tenant_id
     AND security_group.id = group_member.group_id
     AND security_group.archived_at IS NULL
    JOIN public.tenant_security_group_role_grants AS group_grant
      ON group_grant.tenant_id = group_member.tenant_id
     AND group_grant.group_id = group_member.group_id
     AND group_grant.revoked_at IS NULL
     AND (group_grant.expires_at IS NULL
          OR group_grant.expires_at > transaction_timestamp())
    JOIN public.tenant_authorization_sources AS grant_source
      ON grant_source.tenant_id = group_grant.tenant_id
     AND grant_source.id = group_grant.source_id
     AND grant_source.retired_at IS NULL
    WHERE group_member.tenant_id = context_tenant
      AND group_member.membership_id = actor_membership
      AND group_member.revoked_at IS NULL
      AND (group_member.expires_at IS NULL
           OR group_member.expires_at > transaction_timestamp())
  ), delegation_rows AS (
    SELECT permission.key AS permission_key, ceiling.scope,
           actor_path.expires_at AS not_after
    FROM actor_role_paths AS actor_path
    JOIN public.tenant_roles AS role
      ON role.tenant_id = context_tenant
     AND role.id = actor_path.role_id
     AND role.principal_kind = 'human'
     AND role.archived_at IS NULL
    JOIN public.tenant_role_delegation_ceilings AS ceiling
      ON ceiling.tenant_id = role.tenant_id AND ceiling.role_id = role.id
    JOIN public.tenant_permissions AS permission
      ON permission.id = ceiling.permission_id
    WHERE ceiling.scope <> 'platform'
  ), owned_edges AS (
    SELECT pinned.planning_source_id AS source_id,
           pinned.planning_epoch_id AS rule_epoch_id,
           'security_group_membership'::text AS kind,
           group_member.group_id AS primary_id,
           NULL::uuid AS secondary_id
    FROM public.tenant_ldap_directory_run_mappings AS pinned
    JOIN public.tenant_security_group_memberships AS group_member
      ON group_member.tenant_id = pinned.tenant_id
     AND group_member.source_id = pinned.authorization_source_id
     AND group_member.membership_id = found_membership_id
     AND group_member.revoked_at IS NULL
     AND (group_member.expires_at IS NULL
          OR group_member.expires_at > transaction_timestamp())
    WHERE pinned.tenant_id = context_tenant
      AND pinned.operation_run_id = p_operation_run_id
      AND NOT pinned.included_disabled
    UNION ALL
    SELECT pinned.planning_source_id, pinned.planning_epoch_id,
           'security_group_role_grant', group_grant.group_id,
           group_grant.role_id
    FROM public.tenant_ldap_directory_run_mappings AS pinned
    JOIN public.tenant_security_group_role_grants AS group_grant
      ON group_grant.tenant_id = pinned.tenant_id
     AND group_grant.source_id = pinned.authorization_source_id
     AND group_grant.revoked_at IS NULL
     AND (group_grant.expires_at IS NULL
          OR group_grant.expires_at > transaction_timestamp())
    WHERE pinned.tenant_id = context_tenant
      AND pinned.operation_run_id = p_operation_run_id
      AND NOT pinned.included_disabled
    UNION ALL
    SELECT pinned.planning_source_id, pinned.planning_epoch_id,
           'operator_team_roster', assignment.operator_team_id,
           roster.assignment_epoch_id
    FROM public.tenant_ldap_directory_run_mappings AS pinned
    JOIN public.operator_team_roster_entries AS roster
      ON roster.tenant_id = pinned.tenant_id
     AND roster.source_id = pinned.authorization_source_id
     AND roster.membership_id = found_membership_id
     AND roster.revoked_at IS NULL
     AND (roster.expires_at IS NULL
          OR roster.expires_at > transaction_timestamp())
    JOIN public.operator_team_assignment_epochs AS assignment
      ON assignment.tenant_id = roster.tenant_id
     AND assignment.id = roster.assignment_epoch_id
    WHERE pinned.tenant_id = context_tenant
      AND pinned.operation_run_id = p_operation_run_id
      AND NOT pinned.included_disabled
  )
  SELECT locked_run.id, context_tenant, locked_run.provider_id,
         locked_run.provider_version, locked_run.binding_id,
         locked_run.binding_version, locked_run.binding_auth_revision,
         locked_run.binding_access_epoch_id,
         locked_run.configuration_version, locked_run.rule_set_revision,
         locked_run.authorization_revision, configuration.jit_mode,
         configuration.no_match_policy, NULL::timestamptz,
         current_access_source_id, locked_run.binding_access_epoch_id,
         found_identity_id, found_user_id, found_membership_id,
         found_identity_id IS NOT NULL, found_user_active,
         found_membership_id IS NOT NULL, found_membership_active, live_access,
         coalesce((
           SELECT jsonb_agg(jsonb_build_object(
             'ruleId', selected.mapping_rule_id,
             'ruleEpochId', selected.planning_epoch_id,
             'sourceId', selected.planning_source_id,
             'revision', selected.mapping_version,
             'priority', selected.priority,
             'enabled', true,
             'matcherType', selected.matcher_type,
             'matcherValue', selected.matcher_value,
             'caseMode', selected.case_mode,
             'reconciliationMode', selected.reconciliation_mode,
             'securityGroupId', selected.security_group_id,
             'roleIds', rule_roles.role_ids,
             'operatorTeamId', selected.operator_team_id,
             'operatorTeamAssignmentEpochId',
               selected.operator_team_assignment_epoch_id,
             'administrativeNote', ''
           ) ORDER BY selected.priority, selected.mapping_rule_id)
           FROM selected_rules AS selected
           JOIN rule_roles ON rule_roles.mapping_rule_id = selected.mapping_rule_id
         ), '[]'::jsonb),
         coalesce((
           SELECT jsonb_agg(jsonb_build_object(
             'securityGroupId', group_policy.security_group_id,
             'activeRoleIds', group_policy.role_ids
           ) ORDER BY group_policy.security_group_id)
           FROM group_policy_roles AS group_policy
         ), '[]'::jsonb),
         coalesce((
           SELECT jsonb_agg(jsonb_build_object(
             'operatorTeamId', selected.operator_team_id,
             'assignmentEpochId', selected.operator_team_assignment_epoch_id,
             'live', assignment.id IS NOT NULL
                     AND assignment.ended_at IS NULL
                     AND team.archived_at IS NULL
           ) ORDER BY selected.operator_team_id,
                      selected.operator_team_assignment_epoch_id)
           FROM (
             SELECT DISTINCT operator_team_id,
                    operator_team_assignment_epoch_id
             FROM selected_rules
             WHERE operator_team_id IS NOT NULL
           ) AS selected
           LEFT JOIN public.operator_team_assignment_epochs AS assignment
             ON assignment.tenant_id = context_tenant
            AND assignment.id = selected.operator_team_assignment_epoch_id
            AND assignment.operator_team_id = selected.operator_team_id
           LEFT JOIN public.operator_teams AS team
             ON team.id = selected.operator_team_id
         ), '[]'::jsonb),
         coalesce((
           SELECT jsonb_agg(jsonb_build_object(
             'roleId', role_policy.role_id, 'policy', role_policy.policy
           ) ORDER BY role_policy.role_id)
           FROM role_policy_rows AS role_policy
         ), '[]'::jsonb),
         coalesce((
           SELECT array_agg(role_id ORDER BY role_id) FROM effective_role_ids
         ), ARRAY[]::uuid[]),
         coalesce((
           SELECT jsonb_agg(jsonb_build_object(
             'permission', delegation.permission_key,
             'scope', delegation.scope,
             'notAfter', delegation.not_after
           ) ORDER BY delegation.permission_key, delegation.scope,
                      delegation.not_after NULLS LAST)
           FROM delegation_rows AS delegation
         ), '[]'::jsonb),
         coalesce((
           SELECT jsonb_agg(jsonb_build_object(
             'sourceId', edge.source_id,
             'ruleEpochId', edge.rule_epoch_id,
             'kind', edge.kind,
             'primaryId', edge.primary_id,
             'secondaryId', edge.secondary_id
           ) ORDER BY edge.source_id, edge.kind, edge.primary_id,
                      edge.secondary_id NULLS FIRST)
           FROM owned_edges AS edge
         ), '[]'::jsonb)
  FROM public.tenant_ldap_provider_configs AS configuration
  WHERE configuration.tenant_id = context_tenant
    AND configuration.provider_id = locked_run.provider_id;
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.begin_tenant_ldap_administrative_search_v1(
  p_operation_run_id uuid,
  p_provider_id uuid,
  p_operation_kind public.ldap_directory_operation_kind,
  p_reason text,
  p_audit_event_id uuid,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text
)
RETURNS TABLE (
  operation_run_id uuid,
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
  started_at timestamptz,
  expires_at timestamptz
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  actor_membership uuid;
  snapshot record;
BEGIN
  PERFORM app.lock_current_tenant_authorization_state();
  actor_membership := app.current_tenant_membership_id();
  IF NOT app.current_tenant_human_has_exact_permission_v3(
    'identity_provider.test', 'tenant'
  ) THEN
    RAISE EXCEPTION 'identity_provider.test tenant scope is required'
      USING ERRCODE = '42501';
  END IF;
  SELECT * INTO snapshot
  FROM app.private_begin_tenant_ldap_directory_operation_v1(
    p_operation_run_id, p_provider_id, p_operation_kind, NULL,
    ARRAY[]::uuid[], p_reason, actor_membership,
    p_request_id, p_correlation_id
  );

  PERFORM app.append_tenant_authorization_audit(
    p_audit_event_id, 'tenant.identity_provider.directory_test_started',
    'identity_provider_test', p_operation_run_id,
    p_request_id, p_correlation_id, p_ip_address, p_user_agent,
    p_authentication_method, NULL,
    jsonb_build_object(
      'provider_id', p_provider_id,
      'operation_kind', p_operation_kind,
      'provider_version', snapshot.provider_version,
      'configuration_version', snapshot.configuration_version,
      'bind_secret_version', snapshot.bind_secret_version,
      'bind_secret_key_version', snapshot.bind_secret_key_version,
      'status', 'started'
    ),
    jsonb_build_object('reason', p_reason)
  );

  RETURN QUERY SELECT
    snapshot.operation_run_id, snapshot.tenant_id, snapshot.provider_id,
    snapshot.provider_version, snapshot.configuration_version,
    snapshot.endpoint_snapshot_digest, snapshot.configuration,
    snapshot.endpoints, snapshot.bind_secret_id,
    snapshot.bind_secret_ciphertext, snapshot.bind_secret_nonce,
    snapshot.bind_secret_version, snapshot.bind_secret_key_version,
    snapshot.bind_secret_algorithm, snapshot.binding_id,
    snapshot.binding_version, snapshot.binding_auth_revision,
    snapshot.binding_access_epoch_id, snapshot.rule_set_revision,
    snapshot.authorization_revision, snapshot.mapping_revisions,
    snapshot.started_at, snapshot.expires_at;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION app.begin_tenant_ldap_mapping_dry_run_v1(
  p_operation_run_id uuid,
  p_binding_id uuid,
  p_include_disabled_mapping_ids uuid[],
  p_reason text,
  p_audit_event_id uuid,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text
)
RETURNS TABLE (
  operation_run_id uuid,
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
  started_at timestamptz,
  expires_at timestamptz
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  actor_membership uuid;
  target_provider_id uuid;
  snapshot record;
BEGIN
  PERFORM app.lock_current_tenant_authorization_state();
  actor_membership := app.current_tenant_membership_id();
  IF NOT app.current_tenant_human_has_exact_permission_v3(
    'identity_provider.test', 'tenant'
  ) OR NOT app.current_tenant_human_has_exact_permission_v3(
    'identity_mapping.manage', 'tenant'
  ) THEN
    RAISE EXCEPTION 'identity_provider.test and identity_mapping.manage tenant scopes are required'
      USING ERRCODE = '42501';
  END IF;
  SELECT binding.provider_id INTO target_provider_id
  FROM public.tenant_auth_provider_bindings AS binding
  WHERE binding.tenant_id = context_tenant AND binding.id = p_binding_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant LDAP binding was not found'
      USING ERRCODE = 'P0002';
  END IF;

  SELECT * INTO snapshot
  FROM app.private_begin_tenant_ldap_directory_operation_v1(
    p_operation_run_id, target_provider_id, 'search_user', p_binding_id,
    p_include_disabled_mapping_ids, p_reason, actor_membership,
    p_request_id, p_correlation_id
  );

  PERFORM app.append_tenant_authorization_audit(
    p_audit_event_id, 'tenant.identity_mapping.dry_run_started',
    'identity_mapping_dry_run', p_operation_run_id,
    p_request_id, p_correlation_id, p_ip_address, p_user_agent,
    p_authentication_method, NULL,
    jsonb_build_object(
      'provider_id', target_provider_id,
      'binding_id', p_binding_id,
      'provider_version', snapshot.provider_version,
      'binding_version', snapshot.binding_version,
      'binding_auth_revision', snapshot.binding_auth_revision,
      'configuration_version', snapshot.configuration_version,
      'rule_set_revision', snapshot.rule_set_revision,
      'authorization_revision', snapshot.authorization_revision,
      'mapping_count', jsonb_array_length(snapshot.mapping_revisions),
      'status', 'started'
    ),
    jsonb_build_object('reason', p_reason)
  );

  RETURN QUERY SELECT
    snapshot.operation_run_id, snapshot.tenant_id, snapshot.provider_id,
    snapshot.provider_version, snapshot.configuration_version,
    snapshot.endpoint_snapshot_digest, snapshot.configuration,
    snapshot.endpoints, snapshot.bind_secret_id,
    snapshot.bind_secret_ciphertext, snapshot.bind_secret_nonce,
    snapshot.bind_secret_version, snapshot.bind_secret_key_version,
    snapshot.bind_secret_algorithm, snapshot.binding_id,
    snapshot.binding_version, snapshot.binding_auth_revision,
    snapshot.binding_access_epoch_id, snapshot.rule_set_revision,
    snapshot.authorization_revision, snapshot.mapping_revisions,
    snapshot.started_at, snapshot.expires_at;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION app.complete_tenant_ldap_directory_operation_v1(
  p_operation_run_id uuid,
  p_reported_outcome public.ldap_provider_test_outcome,
  p_reported_category public.ldap_provider_test_category,
  p_endpoint_priority integer,
  p_duration_ms integer,
  p_matched_entry_count integer,
  p_truncated boolean,
  p_audit_event_id uuid,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text
)
RETURNS TABLE (
  operation_run_id uuid,
  outcome public.ldap_provider_test_outcome,
  category public.ldap_provider_test_category,
  endpoint_priority integer,
  duration_ms integer,
  matched_entry_count integer,
  truncated boolean,
  stale boolean,
  completed_at timestamptz
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  actor_membership uuid;
  locked_run public.tenant_ldap_directory_operation_runs%ROWTYPE;
  result_is_stale boolean;
  result_is_expired boolean;
  effective_outcome public.ldap_provider_test_outcome;
  effective_category public.ldap_provider_test_category;
  effective_count integer;
  effective_truncated boolean;
  effective_endpoint_priority integer;
  operation_completed_at timestamptz := transaction_timestamp();
  audit_action text;
  audit_object_type text;
BEGIN
  PERFORM app.lock_current_tenant_authorization_state();
  actor_membership := app.current_tenant_membership_id();
  IF p_reported_outcome IS NULL OR p_reported_category IS NULL
     OR p_duration_ms IS NULL OR p_duration_ms NOT BETWEEN 0 AND 120000
     OR p_matched_entry_count IS NULL OR p_matched_entry_count NOT BETWEEN 0 AND 10
     OR p_truncated IS NULL
     OR p_request_id IS NULL OR p_correlation_id IS NULL
     OR (p_endpoint_priority IS NOT NULL AND p_endpoint_priority NOT BETWEEN 1 AND 8)
     OR NOT (
       (p_reported_outcome = 'success'
        AND p_reported_category = 'success'
        AND p_endpoint_priority IS NOT NULL)
       OR (p_reported_outcome = 'failure'
           AND p_reported_category NOT IN ('success', 'stale_configuration')
           AND p_matched_entry_count = 0
           AND NOT p_truncated
           AND ((p_reported_category = 'cancelled'
                 AND p_endpoint_priority IS NULL)
                OR (p_reported_category <> 'cancelled'
                    AND p_endpoint_priority IS NOT NULL)))
     ) THEN
    RAISE EXCEPTION 'tenant LDAP directory operation result is invalid'
      USING ERRCODE = '22023';
  END IF;

  SELECT operation.* INTO locked_run
  FROM public.tenant_ldap_directory_operation_runs AS operation
  WHERE operation.tenant_id = context_tenant
    AND operation.id = p_operation_run_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant LDAP directory operation was not found'
      USING ERRCODE = 'P0002';
  END IF;
  IF locked_run.status <> 'started' THEN
    RAISE EXCEPTION 'tenant LDAP directory operation is already completed'
      USING ERRCODE = '55000';
  END IF;
  IF locked_run.started_by_membership_id <> actor_membership THEN
    RAISE EXCEPTION 'tenant LDAP directory operation belongs to another actor'
      USING ERRCODE = '42501';
  END IF;
  IF locked_run.request_id IS DISTINCT FROM p_request_id
     OR locked_run.correlation_id IS DISTINCT FROM p_correlation_id THEN
    RAISE EXCEPTION 'tenant LDAP directory operation correlation does not match'
      USING ERRCODE = '22023';
  END IF;
  IF locked_run.binding_id IS NULL THEN
    IF NOT app.current_tenant_human_has_exact_permission_v3(
      'identity_provider.test', 'tenant'
    ) THEN
      RAISE EXCEPTION 'identity_provider.test tenant scope is required'
        USING ERRCODE = '42501';
    END IF;
    audit_action := 'tenant.identity_provider.directory_test_completed';
    audit_object_type := 'identity_provider_test';
  ELSE
    IF NOT app.current_tenant_human_has_exact_permission_v3(
      'identity_provider.test', 'tenant'
    ) OR NOT app.current_tenant_human_has_exact_permission_v3(
      'identity_mapping.manage', 'tenant'
    ) THEN
      RAISE EXCEPTION 'identity_provider.test and identity_mapping.manage tenant scopes are required'
        USING ERRCODE = '42501';
    END IF;
    audit_action := 'tenant.identity_mapping.dry_run_completed';
    audit_object_type := 'identity_mapping_dry_run';
  END IF;
  IF locked_run.operation_kind = 'search_user'
     AND p_matched_entry_count > 1 THEN
    RAISE EXCEPTION 'tenant LDAP user search result exceeds one entry'
      USING ERRCODE = '22023';
  END IF;

  result_is_stale := NOT app.private_tenant_ldap_directory_run_is_current_v1(
    context_tenant, p_operation_run_id
  );
  result_is_expired := operation_completed_at > locked_run.expires_at;
  IF result_is_stale THEN
    effective_outcome := 'inconclusive';
    effective_category := 'stale_configuration';
    effective_endpoint_priority := NULL;
    effective_count := 0;
    effective_truncated := false;
  ELSIF result_is_expired THEN
    effective_outcome := 'failure';
    effective_category := 'cancelled';
    effective_endpoint_priority := NULL;
    effective_count := 0;
    effective_truncated := false;
  ELSE
    effective_outcome := p_reported_outcome;
    effective_category := p_reported_category;
    effective_endpoint_priority := p_endpoint_priority;
    effective_count := p_matched_entry_count;
    effective_truncated := p_truncated;
  END IF;

  UPDATE public.tenant_ldap_directory_operation_runs AS operation
  SET status = 'completed', outcome = effective_outcome,
      category = effective_category,
      endpoint_priority = effective_endpoint_priority,
      duration_ms = p_duration_ms, matched_entry_count = effective_count,
      result_truncated = effective_truncated,
      completed_by_membership_id = actor_membership,
      completed_at = operation_completed_at, version = 2
  WHERE operation.tenant_id = context_tenant
    AND operation.id = p_operation_run_id;

  PERFORM app.append_tenant_authorization_audit(
    p_audit_event_id, audit_action, audit_object_type,
    p_operation_run_id, p_request_id, p_correlation_id,
    p_ip_address, p_user_agent, p_authentication_method,
    jsonb_build_object(
      'provider_id', locked_run.provider_id,
      'operation_kind', locked_run.operation_kind,
      'status', 'started',
      'provider_version', locked_run.provider_version,
      'configuration_version', locked_run.configuration_version,
      'binding_id', locked_run.binding_id,
      'binding_version', locked_run.binding_version,
      'rule_set_revision', locked_run.rule_set_revision,
      'authorization_revision', locked_run.authorization_revision
    ),
    jsonb_build_object(
      'status', 'completed', 'outcome', effective_outcome,
      'category', effective_category,
      'endpoint_priority', effective_endpoint_priority,
      'matched_entry_count', effective_count,
      'truncated', effective_truncated
    ),
    jsonb_build_object(
      'reason', locked_run.reason,
      'stale_configuration', result_is_stale,
      'expired_operation', result_is_expired
    )
  );

  RETURN QUERY SELECT p_operation_run_id, effective_outcome,
    effective_category, effective_endpoint_priority, p_duration_ms,
    effective_count, effective_truncated, result_is_stale,
    operation_completed_at;
END;
$function$;--> statement-breakpoint

ALTER FUNCTION app.private_tenant_ldap_endpoint_snapshot_v1(uuid, uuid)
  OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.private_tenant_ldap_directory_run_is_current_v1(uuid, uuid)
  OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.private_begin_tenant_ldap_directory_operation_v1(uuid, uuid, public.ldap_directory_operation_kind, uuid, uuid[], text, uuid, uuid, uuid)
  OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.get_tenant_ldap_dry_run_planning_snapshot_v1(uuid, integer[], bytea[])
  OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.begin_tenant_ldap_administrative_search_v1(uuid, uuid, public.ldap_directory_operation_kind, text, uuid, uuid, uuid, inet, text, text)
  OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.begin_tenant_ldap_mapping_dry_run_v1(uuid, uuid, uuid[], text, uuid, uuid, uuid, inet, text, text)
  OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.complete_tenant_ldap_directory_operation_v1(uuid, public.ldap_provider_test_outcome, public.ldap_provider_test_category, integer, integer, integer, boolean, uuid, uuid, uuid, inet, text, text)
  OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.get_tenant_auth_provider_binding_mutation_result_v1(uuid)
  OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.get_tenant_ldap_mapping_rule_mutation_result_v1(uuid)
  OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.create_tenant_ldap_mapping_rule_v2(bytea, uuid, public.ldap_mapping_matcher_type, text, public.ldap_mapping_case_mode, integer, uuid, public.ldap_mapping_reconciliation_mode, uuid[], uuid, uuid, text, text, uuid, uuid, uuid, inet, text, text)
  OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.verify_identity_keyring_v3(integer[], bytea[], integer)
  OWNER TO periapsis_migrator;--> statement-breakpoint

REVOKE ALL ON FUNCTION app.private_tenant_ldap_endpoint_snapshot_v1(uuid, uuid)
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_tenant_ldap_directory_run_is_current_v1(uuid, uuid)
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_begin_tenant_ldap_directory_operation_v1(uuid, uuid, public.ldap_directory_operation_kind, uuid, uuid[], text, uuid, uuid, uuid)
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.get_tenant_ldap_dry_run_planning_snapshot_v1(uuid, integer[], bytea[])
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.begin_tenant_ldap_administrative_search_v1(uuid, uuid, public.ldap_directory_operation_kind, text, uuid, uuid, uuid, inet, text, text)
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.begin_tenant_ldap_mapping_dry_run_v1(uuid, uuid, uuid[], text, uuid, uuid, uuid, inet, text, text)
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.complete_tenant_ldap_directory_operation_v1(uuid, public.ldap_provider_test_outcome, public.ldap_provider_test_category, integer, integer, integer, boolean, uuid, uuid, uuid, inet, text, text)
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.get_tenant_auth_provider_binding_mutation_result_v1(uuid)
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.get_tenant_ldap_mapping_rule_mutation_result_v1(uuid)
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.create_tenant_ldap_mapping_rule_v2(bytea, uuid, public.ldap_mapping_matcher_type, text, public.ldap_mapping_case_mode, integer, uuid, public.ldap_mapping_reconciliation_mode, uuid[], uuid, uuid, text, text, uuid, uuid, uuid, inet, text, text)
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.verify_identity_keyring_v3(integer[], bytea[], integer)
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint

-- Retire unsafe/non-canonical predecessors from runtime execution.
REVOKE EXECUTE ON FUNCTION app.create_tenant_auth_provider_binding_v1(uuid, uuid, text, boolean, integer, uuid, uuid, inet, text, text)
  FROM periapsis_api;--> statement-breakpoint
REVOKE EXECUTE ON FUNCTION app.create_tenant_ldap_mapping_rule_v1(bytea, uuid, public.ldap_mapping_matcher_type, text, public.ldap_mapping_case_mode, integer, uuid, public.ldap_mapping_reconciliation_mode, uuid[], uuid, uuid, text, text, uuid, uuid, uuid, inet, text, text)
  FROM periapsis_api;--> statement-breakpoint
REVOKE EXECUTE ON FUNCTION app.verify_identity_keyring_v2(integer[], bytea[], integer)
  FROM periapsis_api, periapsis_worker;--> statement-breakpoint

GRANT EXECUTE ON FUNCTION app.begin_tenant_ldap_administrative_search_v1(uuid, uuid, public.ldap_directory_operation_kind, text, uuid, uuid, uuid, inet, text, text)
  TO periapsis_api;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.begin_tenant_ldap_mapping_dry_run_v1(uuid, uuid, uuid[], text, uuid, uuid, uuid, inet, text, text)
  TO periapsis_api;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.complete_tenant_ldap_directory_operation_v1(uuid, public.ldap_provider_test_outcome, public.ldap_provider_test_category, integer, integer, integer, boolean, uuid, uuid, uuid, inet, text, text)
  TO periapsis_api;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.get_tenant_ldap_dry_run_planning_snapshot_v1(uuid, integer[], bytea[])
  TO periapsis_api;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.get_tenant_auth_provider_binding_mutation_result_v1(uuid)
  TO periapsis_api;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.get_tenant_ldap_mapping_rule_mutation_result_v1(uuid)
  TO periapsis_api;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.create_tenant_ldap_mapping_rule_v2(bytea, uuid, public.ldap_mapping_matcher_type, text, public.ldap_mapping_case_mode, integer, uuid, public.ldap_mapping_reconciliation_mode, uuid[], uuid, uuid, text, text, uuid, uuid, uuid, inet, text, text)
  TO periapsis_api;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.verify_identity_keyring_v3(integer[], bytea[], integer)
  TO periapsis_api, periapsis_worker;
