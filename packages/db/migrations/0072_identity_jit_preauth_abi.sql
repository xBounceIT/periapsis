CREATE FUNCTION app.private_tenant_ldap_jit_run_is_current_v1(
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
    FROM public.tenant_ldap_jit_authentication_runs AS run
    JOIN public.tenants AS tenant
      ON tenant.id = run.tenant_id AND tenant.status = 'active'
    JOIN public.tenant_auth_providers AS provider
      ON provider.tenant_id = run.tenant_id
     AND provider.id = run.provider_id
     AND provider.kind = 'ldap'
     AND provider.enabled AND provider.archived_at IS NULL
    JOIN public.tenant_ldap_provider_configs AS configuration
      ON configuration.tenant_id = provider.tenant_id
     AND configuration.provider_id = provider.id
     AND configuration.jit_mode <> 'disabled'
    JOIN public.tenant_ldap_provider_secrets AS secret
      ON secret.tenant_id = provider.tenant_id
     AND secret.provider_id = provider.id
     AND secret.id = run.bind_secret_id
    JOIN public.identity_keyring_versions AS keyring
      ON keyring.key_version = secret.key_version
     AND keyring.retired_at IS NULL
    JOIN public.tenant_auth_provider_bindings AS binding
      ON binding.tenant_id = provider.tenant_id
     AND binding.id = run.binding_id
     AND binding.provider_id = provider.id
     AND binding.enabled AND binding.archived_at IS NULL
    JOIN public.tenant_identity_provider_access_epochs AS access_epoch
      ON access_epoch.tenant_id = binding.tenant_id
     AND access_epoch.id = binding.current_access_epoch_id
     AND access_epoch.binding_id = binding.id
     AND access_epoch.provider_id = provider.id
     AND access_epoch.ended_at IS NULL
    JOIN public.tenant_authorization_sources AS access_source
      ON access_source.tenant_id = access_epoch.tenant_id
     AND access_source.id = access_epoch.source_id
     AND access_source.kind = 'identity_provider_access'
     AND access_source.retired_at IS NULL
    JOIN public.tenant_authorization_states AS authorization_state
      ON authorization_state.tenant_id = binding.tenant_id
     AND authorization_state.initialized_at IS NOT NULL
    CROSS JOIN LATERAL app.private_tenant_ldap_endpoint_snapshot_v1(
      run.tenant_id, run.provider_id
    ) AS endpoint_snapshot
    WHERE run.tenant_id = p_tenant_id
      AND run.id = p_operation_run_id
      AND provider.version = run.provider_version
      AND configuration.version = run.configuration_version
      AND secret.version = run.bind_secret_version
      AND secret.key_version = run.bind_secret_key_version
      AND secret.encryption_algorithm = run.bind_secret_algorithm
      AND binding.version = run.binding_version
      AND binding.auth_revision = run.binding_auth_revision
      AND binding.mapping_revision = run.rule_set_revision
      AND binding.current_access_epoch_id = run.binding_access_epoch_id
      AND authorization_state.revision = run.authorization_revision
      AND endpoint_snapshot.endpoint_count > 0
      AND endpoint_snapshot.endpoint_digest = run.endpoint_snapshot_digest
      AND NOT EXISTS (
        SELECT 1
        FROM public.tenant_ldap_mapping_rules AS current_rule
        JOIN public.tenant_ldap_mapping_rule_epochs AS current_epoch
          ON current_epoch.tenant_id = current_rule.tenant_id
         AND current_epoch.id = current_rule.current_source_epoch_id
         AND current_epoch.mapping_rule_id = current_rule.id
         AND current_epoch.binding_id = current_rule.binding_id
         AND current_epoch.ended_at IS NULL
        JOIN public.tenant_authorization_sources AS source
          ON source.tenant_id = current_epoch.tenant_id
         AND source.id = current_epoch.source_id
         AND source.kind = 'identity_mapping'
         AND source.retired_at IS NULL
        LEFT JOIN public.tenant_ldap_jit_run_mappings AS pinned
          ON pinned.tenant_id = current_rule.tenant_id
         AND pinned.jit_run_id = run.id
         AND pinned.mapping_rule_id = current_rule.id
         AND pinned.binding_id = current_rule.binding_id
         AND pinned.mapping_version = current_rule.version
         AND pinned.configuration_revision = current_rule.configuration_revision
         AND pinned.source_epoch_id = current_epoch.id
         AND pinned.source_id = current_epoch.source_id
         AND pinned.priority = current_rule.priority
        WHERE current_rule.tenant_id = run.tenant_id
          AND current_rule.binding_id = run.binding_id
          AND current_rule.enabled AND current_rule.archived_at IS NULL
          AND pinned.mapping_rule_id IS NULL
      )
      AND NOT EXISTS (
        SELECT 1
        FROM public.tenant_ldap_jit_run_mappings AS pinned
        LEFT JOIN public.tenant_ldap_mapping_rules AS current_rule
          ON current_rule.tenant_id = pinned.tenant_id
         AND current_rule.id = pinned.mapping_rule_id
         AND current_rule.binding_id = pinned.binding_id
         AND current_rule.enabled AND current_rule.archived_at IS NULL
         AND current_rule.version = pinned.mapping_version
         AND current_rule.configuration_revision = pinned.configuration_revision
         AND current_rule.current_source_epoch_id = pinned.source_epoch_id
         AND current_rule.priority = pinned.priority
        LEFT JOIN public.tenant_ldap_mapping_rule_epochs AS current_epoch
          ON current_epoch.tenant_id = pinned.tenant_id
         AND current_epoch.id = pinned.source_epoch_id
         AND current_epoch.mapping_rule_id = pinned.mapping_rule_id
         AND current_epoch.binding_id = pinned.binding_id
         AND current_epoch.source_id = pinned.source_id
         AND current_epoch.ended_at IS NULL
        WHERE pinned.tenant_id = run.tenant_id
          AND pinned.jit_run_id = run.id
          AND (current_rule.id IS NULL OR current_epoch.id IS NULL)
      )
  )
$function$;--> statement-breakpoint

CREATE FUNCTION app.private_get_tenant_ldap_jit_network_snapshot_v1(
  p_operation_run_id uuid,
  p_receipt_digest bytea
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
  started_at timestamptz,
  expires_at timestamptz
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  locked_run public.tenant_ldap_jit_authentication_runs%ROWTYPE;
BEGIN
  IF p_operation_run_id IS NULL OR p_receipt_digest IS NULL
     OR octet_length(p_receipt_digest) <> 32 THEN
    RETURN;
  END IF;
  SELECT run.* INTO locked_run
  FROM public.tenant_ldap_jit_authentication_runs AS run
  WHERE run.id = p_operation_run_id
    AND run.receipt_digest = p_receipt_digest
  FOR SHARE;
  IF NOT FOUND OR locked_run.status <> 'network_pending'
     OR transaction_timestamp() > locked_run.expires_at THEN
    RETURN;
  END IF;
  PERFORM set_config('app.tenant_id', locked_run.tenant_id::text, true);
  IF NOT app.private_tenant_ldap_jit_run_is_current_v1(
    locked_run.tenant_id, locked_run.id
  ) THEN
    RETURN;
  END IF;

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
           'userDnTemplate', configuration.user_dn_template,
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
           'noMatchPolicy', configuration.no_match_policy
         ), endpoint_snapshot.endpoints,
         secret.id, secret.secret_ciphertext, secret.secret_nonce,
         secret.version, secret.key_version, secret.encryption_algorithm,
         locked_run.binding_id, locked_run.binding_version,
         locked_run.binding_auth_revision, locked_run.binding_access_epoch_id,
         locked_run.rule_set_revision, locked_run.authorization_revision,
         locked_run.started_at, locked_run.expires_at
  FROM public.tenant_ldap_provider_configs AS configuration
  JOIN public.tenant_ldap_provider_secrets AS secret
    ON secret.tenant_id = configuration.tenant_id
   AND secret.provider_id = configuration.provider_id
   AND secret.id = locked_run.bind_secret_id
  CROSS JOIN LATERAL app.private_tenant_ldap_endpoint_snapshot_v1(
    locked_run.tenant_id, locked_run.provider_id
  ) AS endpoint_snapshot
  WHERE configuration.tenant_id = locked_run.tenant_id
    AND configuration.provider_id = locked_run.provider_id;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION app.begin_tenant_ldap_jit_authentication_v1(
  p_operation_run_id uuid,
  p_receipt_digest bytea,
  p_tenant_slug text,
  p_login_key text,
  p_network_rate_key_digest bytea,
  p_account_rate_key_digest bytea,
  p_provider_rate_key_digest bytea,
  p_audit_event_id uuid,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text
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
  started_at timestamptz,
  expires_at timestamptz
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  locked_tenant public.tenants%ROWTYPE;
  locked_binding public.tenant_auth_provider_bindings%ROWTYPE;
  locked_provider public.tenant_auth_providers%ROWTYPE;
  locked_configuration public.tenant_ldap_provider_configs%ROWTYPE;
  locked_secret public.tenant_ldap_provider_secrets%ROWTYPE;
  access_source_id uuid;
  current_authorization_revision bigint;
  endpoint_digest bytea;
  endpoint_count integer;
  selected_mapping_count integer;
  inserted_mapping_count integer;
  inserted_run_count integer;
  admission record;
  run_started_at timestamptz := transaction_timestamp();
BEGIN
  IF p_operation_run_id IS NULL
     OR (uuid_extract_version(p_operation_run_id) = 7) IS NOT TRUE
     OR p_receipt_digest IS NULL OR octet_length(p_receipt_digest) <> 32
     OR p_network_rate_key_digest IS NULL
     OR octet_length(p_network_rate_key_digest) <> 32
     OR p_account_rate_key_digest IS NULL
     OR octet_length(p_account_rate_key_digest) <> 32
     OR p_provider_rate_key_digest IS NULL
     OR octet_length(p_provider_rate_key_digest) <> 32
     OR p_audit_event_id IS NULL OR p_request_id IS NULL
     OR p_correlation_id IS NULL OR p_user_agent IS NULL
     OR length(p_user_agent) NOT BETWEEN 1 AND 1024 THEN
    RAISE EXCEPTION 'LDAP JIT pre-authentication input is invalid'
      USING ERRCODE = '22023';
  END IF;

  -- Concurrent delivery of the same opaque receipt is a retry, not another
  -- authentication attempt. Serialize before reading durable state so only
  -- the first delivery consumes the shared DB-backed rate meters.
  PERFORM pg_advisory_xact_lock(hashtextextended(
    'tenant_ldap_jit_begin:' || p_operation_run_id::text, 0
  ));

  -- The receipt itself is the retry authority. A valid unclaimed run can be
  -- read again without incrementing a shared rate meter a second time.
  RETURN QUERY SELECT *
  FROM app.private_get_tenant_ldap_jit_network_snapshot_v1(
    p_operation_run_id, p_receipt_digest
  );
  IF FOUND THEN
    RETURN;
  END IF;
  IF EXISTS (
    SELECT 1 FROM public.tenant_ldap_jit_authentication_runs AS run
    WHERE run.id = p_operation_run_id
       OR run.receipt_digest = p_receipt_digest
  ) THEN
    RETURN;
  END IF;

  SELECT * INTO admission
  FROM app.admit_auth_attempts(
    ARRAY['ldap_network', 'ldap_account', 'ldap_provider']::public.auth_rate_limit_scope[],
    ARRAY[p_network_rate_key_digest, p_account_rate_key_digest,
          p_provider_rate_key_digest]::bytea[],
    ARRAY[60, 900, 60]::integer[],
    ARRAY[30, 10, 100]::integer[],
    ARRAY[300, 900, 300]::integer[]
  );
  IF NOT admission.admitted THEN
    RETURN;
  END IF;
  IF p_tenant_slug IS NULL OR p_login_key IS NULL
     OR p_tenant_slug <> lower(p_tenant_slug)
     OR p_tenant_slug !~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'
     OR p_login_key <> lower(btrim(p_login_key))
     OR p_login_key !~ '^[a-z][a-z0-9_-]{2,63}$' THEN
    RETURN;
  END IF;

  SELECT tenant.* INTO locked_tenant
  FROM public.tenants AS tenant
  WHERE tenant.slug = p_tenant_slug AND tenant.status = 'active'
  FOR SHARE;
  IF NOT FOUND THEN RETURN; END IF;
  PERFORM set_config('app.tenant_id', locked_tenant.id::text, true);

  SELECT binding.* INTO locked_binding
  FROM public.tenant_auth_provider_bindings AS binding
  WHERE binding.tenant_id = locked_tenant.id
    AND binding.key = p_login_key
    AND binding.enabled AND binding.archived_at IS NULL
  FOR SHARE;
  IF NOT FOUND THEN RETURN; END IF;

  SELECT provider.* INTO locked_provider
  FROM public.tenant_auth_providers AS provider
  WHERE provider.tenant_id = locked_tenant.id
    AND provider.id = locked_binding.provider_id
    AND provider.kind = 'ldap'
    AND provider.enabled AND provider.archived_at IS NULL
  FOR SHARE;
  IF NOT FOUND THEN RETURN; END IF;

  SELECT configuration.* INTO locked_configuration
  FROM public.tenant_ldap_provider_configs AS configuration
  WHERE configuration.tenant_id = locked_tenant.id
    AND configuration.provider_id = locked_provider.id
    AND configuration.jit_mode <> 'disabled'
  FOR SHARE;
  IF NOT FOUND THEN RETURN; END IF;

  SELECT secret.* INTO locked_secret
  FROM public.tenant_ldap_provider_secrets AS secret
  JOIN public.identity_keyring_versions AS keyring
    ON keyring.key_version = secret.key_version
   AND keyring.retired_at IS NULL
  WHERE secret.tenant_id = locked_tenant.id
    AND secret.provider_id = locked_provider.id
  FOR SHARE OF secret, keyring;
  IF NOT FOUND THEN RETURN; END IF;

  SELECT epoch.source_id INTO access_source_id
  FROM public.tenant_identity_provider_access_epochs AS epoch
  JOIN public.tenant_authorization_sources AS source
    ON source.tenant_id = epoch.tenant_id AND source.id = epoch.source_id
   AND source.kind = 'identity_provider_access'
   AND source.retired_at IS NULL
  WHERE epoch.tenant_id = locked_tenant.id
    AND epoch.id = locked_binding.current_access_epoch_id
    AND epoch.binding_id = locked_binding.id
    AND epoch.provider_id = locked_provider.id
    AND epoch.ended_at IS NULL
  FOR SHARE OF epoch, source;
  IF access_source_id IS NULL THEN RETURN; END IF;

  SELECT state.revision INTO current_authorization_revision
  FROM public.tenant_authorization_states AS state
  WHERE state.tenant_id = locked_tenant.id
    AND state.initialized_at IS NOT NULL
  FOR SHARE;
  IF current_authorization_revision IS NULL THEN RETURN; END IF;

  SELECT snapshot.endpoint_digest, snapshot.endpoint_count
  INTO endpoint_digest, endpoint_count
  FROM app.private_tenant_ldap_endpoint_snapshot_v1(
    locked_tenant.id, locked_provider.id
  ) AS snapshot;
  IF endpoint_count IS NULL OR endpoint_count < 1 THEN RETURN; END IF;

  SELECT count(*)::integer INTO selected_mapping_count
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
  WHERE rule.tenant_id = locked_tenant.id
    AND rule.binding_id = locked_binding.id
    AND rule.enabled AND rule.archived_at IS NULL;
  IF selected_mapping_count > 1000 THEN
    RAISE EXCEPTION 'tenant LDAP JIT mapping snapshot exceeds its bound'
      USING ERRCODE = '54000';
  END IF;

  INSERT INTO public.tenant_ldap_jit_authentication_runs (
    id, tenant_id, receipt_digest, provider_id, provider_kind, binding_id,
    provider_version, configuration_version, bind_secret_id,
    bind_secret_version, bind_secret_key_version, bind_secret_algorithm,
    endpoint_snapshot_digest, binding_version, binding_auth_revision,
    binding_access_epoch_id, rule_set_revision, authorization_revision,
    network_rate_key_digest, account_rate_key_digest,
    provider_rate_key_digest, begin_audit_event_id, request_id,
    correlation_id, started_at, expires_at
  ) VALUES (
    p_operation_run_id, locked_tenant.id, p_receipt_digest,
    locked_provider.id, 'ldap', locked_binding.id, locked_provider.version,
    locked_configuration.version, locked_secret.id, locked_secret.version,
    locked_secret.key_version, locked_secret.encryption_algorithm,
    endpoint_digest, locked_binding.version, locked_binding.auth_revision,
    locked_binding.current_access_epoch_id, locked_binding.mapping_revision,
    current_authorization_revision, p_network_rate_key_digest,
    p_account_rate_key_digest, p_provider_rate_key_digest, p_audit_event_id,
    p_request_id, p_correlation_id, run_started_at,
    run_started_at + interval '2 minutes'
  ) ON CONFLICT DO NOTHING;
  GET DIAGNOSTICS inserted_run_count = ROW_COUNT;
  IF inserted_run_count <> 1 THEN RETURN; END IF;

  INSERT INTO public.tenant_ldap_jit_run_mappings (
    tenant_id, jit_run_id, binding_id, mapping_rule_id,
    mapping_version, configuration_revision, source_epoch_id,
    source_id, priority
  )
  SELECT rule.tenant_id, p_operation_run_id, rule.binding_id, rule.id,
         rule.version, rule.configuration_revision, epoch.id,
         epoch.source_id, rule.priority
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
  WHERE rule.tenant_id = locked_tenant.id
    AND rule.binding_id = locked_binding.id
    AND rule.enabled AND rule.archived_at IS NULL
  ORDER BY rule.priority, rule.id;
  GET DIAGNOSTICS inserted_mapping_count = ROW_COUNT;
  IF inserted_mapping_count <> selected_mapping_count THEN
    RAISE EXCEPTION 'tenant LDAP JIT mapping snapshot changed during begin'
      USING ERRCODE = '40001';
  END IF;

  PERFORM app.private_append_tenant_ldap_runtime_audit_v1(
    p_audit_event_id, locked_tenant.id,
    'tenant.identity.ldap_jit_started', 'ldap_jit_authentication_run',
    p_operation_run_id, p_request_id, p_correlation_id, p_ip_address,
    p_user_agent, 'ldap', 'success', NULL,
    jsonb_build_object(
      'provider_id', locked_provider.id,
      'binding_id', locked_binding.id,
      'provider_version', locked_provider.version,
      'config_version', locked_configuration.version,
      'binding_version', locked_binding.version,
      'rule_revision', locked_binding.mapping_revision,
      'auth_revision', current_authorization_revision,
      'mapping_count', selected_mapping_count,
      'status', 'network_pending'
    )
  );

  RETURN QUERY SELECT *
  FROM app.private_get_tenant_ldap_jit_network_snapshot_v1(
    p_operation_run_id, p_receipt_digest
  );
END;
$function$;--> statement-breakpoint

CREATE FUNCTION app.read_tenant_ldap_jit_network_snapshot_v1(
  p_operation_run_id uuid,
  p_receipt_digest bytea
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
  started_at timestamptz,
  expires_at timestamptz
)
LANGUAGE sql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
  SELECT * FROM app.private_get_tenant_ldap_jit_network_snapshot_v1(
    p_operation_run_id, p_receipt_digest
  )
$function$;--> statement-breakpoint

CREATE FUNCTION app.claim_tenant_ldap_jit_planning_v1(
  p_operation_run_id uuid,
  p_receipt_digest bytea,
  p_digest_key_versions integer[],
  p_subject_digests bytea[],
  p_terminal_audit_event_id uuid,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text
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
  role_policies jsonb,
  existing_effective_role_ids uuid[],
  live_owned_edges jsonb
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  locked_run public.tenant_ldap_jit_authentication_runs%ROWTYPE;
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
  terminal_status public.ldap_jit_run_status;
  effective_terminal_category text;
  terminal_action text;
BEGIN
  IF p_operation_run_id IS NULL OR p_receipt_digest IS NULL
     OR octet_length(p_receipt_digest) <> 32
     OR p_terminal_audit_event_id IS NULL OR p_request_id IS NULL
     OR p_correlation_id IS NULL OR p_user_agent IS NULL
     OR length(p_user_agent) NOT BETWEEN 1 AND 1024
     OR digest_count < 1 OR digest_count > 16
     OR coalesce(array_length(p_subject_digests, 1), 0) <> digest_count
     OR coalesce(array_ndims(p_digest_key_versions), 0) <> 1
     OR coalesce(array_ndims(p_subject_digests), 0) <> 1
     OR array_lower(p_digest_key_versions, 1) <> 1
     OR array_lower(p_subject_digests, 1) <> 1 THEN
    RAISE EXCEPTION 'LDAP JIT planning claim input is invalid'
      USING ERRCODE = '22023';
  END IF;
  FOR digest_index IN 1..digest_count LOOP
    IF p_digest_key_versions[digest_index] IS NULL
       OR p_digest_key_versions[digest_index] NOT BETWEEN 1 AND 32767
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
      RAISE EXCEPTION 'LDAP JIT immutable-subject digest lookup is invalid'
        USING ERRCODE = '22023';
    END IF;
  END LOOP;

  SELECT run.* INTO locked_run
  FROM public.tenant_ldap_jit_authentication_runs AS run
  WHERE run.id = p_operation_run_id
    AND run.receipt_digest = p_receipt_digest
  FOR UPDATE;
  IF NOT FOUND OR locked_run.status <> 'network_pending' THEN
    RETURN;
  END IF;
  PERFORM set_config('app.tenant_id', locked_run.tenant_id::text, true);

  IF transaction_timestamp() > locked_run.expires_at THEN
    terminal_status := 'expired';
    effective_terminal_category := 'expired';
    terminal_action := 'tenant.identity.ldap_jit_expired';
  ELSIF NOT app.private_tenant_ldap_jit_run_is_current_v1(
    locked_run.tenant_id, locked_run.id
  ) THEN
    terminal_status := 'stale';
    effective_terminal_category := 'stale_snapshot';
    terminal_action := 'tenant.identity.ldap_jit_stale';
  ELSIF EXISTS (
    SELECT 1
    FROM public.tenant_ldap_jit_run_mappings AS pinned
    JOIN public.tenant_ldap_mapping_rule_epochs AS epoch
      ON epoch.tenant_id = pinned.tenant_id
     AND epoch.id = pinned.source_epoch_id
    LEFT JOIN public.tenant_ldap_mapping_rule_role_targets AS target
      ON target.tenant_id = epoch.tenant_id
     AND target.mapping_rule_id = epoch.mapping_rule_id
     AND target.configuration_revision = epoch.configuration_revision
    LEFT JOIN public.tenant_roles AS target_role
      ON target_role.tenant_id = target.tenant_id
     AND target_role.id = target.role_id
    LEFT JOIN public.tenant_role_permissions AS target_policy
      ON target_policy.tenant_id = target_role.tenant_id
     AND target_policy.role_id = target_role.id
     AND target_policy.scope = 'platform'
    WHERE pinned.tenant_id = locked_run.tenant_id
      AND pinned.jit_run_id = locked_run.id
      AND target.role_id IS NOT NULL
      AND (target_role.id IS NULL OR target_role.principal_kind <> 'human'
        OR target_role.archived_at IS NOT NULL
        OR target_role.key = 'platform_super_admin'
        OR target_policy.role_id IS NOT NULL)
  ) OR EXISTS (
    SELECT 1
    FROM public.tenant_ldap_jit_run_mappings AS pinned
    JOIN public.tenant_ldap_mapping_rule_epochs AS epoch
      ON epoch.tenant_id = pinned.tenant_id
     AND epoch.id = pinned.source_epoch_id
    JOIN public.tenant_security_group_role_grants AS group_grant
      ON group_grant.tenant_id = epoch.tenant_id
     AND group_grant.group_id = epoch.tenant_security_group_id
     AND group_grant.revoked_at IS NULL
     AND (group_grant.expires_at IS NULL
          OR group_grant.expires_at > transaction_timestamp())
    JOIN public.tenant_roles AS group_role
      ON group_role.tenant_id = group_grant.tenant_id
     AND group_role.id = group_grant.role_id
    LEFT JOIN public.tenant_role_permissions AS group_policy
      ON group_policy.tenant_id = group_role.tenant_id
     AND group_policy.role_id = group_role.id
     AND group_policy.scope = 'platform'
    WHERE pinned.tenant_id = locked_run.tenant_id
      AND pinned.jit_run_id = locked_run.id
      AND (group_role.principal_kind <> 'human'
        OR group_role.archived_at IS NOT NULL
        OR group_role.key = 'platform_super_admin'
        OR group_policy.role_id IS NOT NULL)
  ) THEN
    terminal_status := 'stale';
    effective_terminal_category := 'forbidden_mapping_target';
    terminal_action := 'tenant.identity.ldap_jit_stale';
  END IF;

  IF terminal_status IS NOT NULL THEN
    UPDATE public.tenant_ldap_jit_authentication_runs AS run
    SET status = terminal_status,
        terminal_category = effective_terminal_category,
        terminal_audit_event_id = p_terminal_audit_event_id,
        completed_at = transaction_timestamp(), version = run.version + 1
    WHERE run.tenant_id = locked_run.tenant_id AND run.id = locked_run.id;
    PERFORM app.private_append_tenant_ldap_runtime_audit_v1(
      p_terminal_audit_event_id, locked_run.tenant_id, terminal_action,
      'ldap_jit_authentication_run', locked_run.id, p_request_id,
      p_correlation_id, p_ip_address, p_user_agent, 'ldap', 'failure',
      effective_terminal_category,
      jsonb_build_object(
        'provider_id', locked_run.provider_id,
        'binding_id', locked_run.binding_id,
        'status', terminal_status::text,
        'category', effective_terminal_category
      )
    );
    RETURN;
  END IF;

  SELECT array_agg(DISTINCT identity.id ORDER BY identity.id),
         array_agg(DISTINCT identity.user_id ORDER BY identity.user_id)
  INTO found_identity_ids, found_user_ids
  FROM unnest(p_digest_key_versions, p_subject_digests)
       AS lookup(key_version, subject_digest)
  JOIN public.tenant_ldap_external_identity_subject_aliases AS alias
    ON alias.tenant_id = locked_run.tenant_id
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
    RAISE EXCEPTION 'LDAP JIT immutable-subject aliases disagree'
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
      ON membership.tenant_id = locked_run.tenant_id
     AND membership.user_id = local_user.id
    WHERE local_user.id = found_user_id;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'tenant LDAP external identity user is unavailable'
        USING ERRCODE = '55000';
    END IF;
  END IF;

  SELECT epoch.source_id INTO current_access_source_id
  FROM public.tenant_identity_provider_access_epochs AS epoch
  WHERE epoch.tenant_id = locked_run.tenant_id
    AND epoch.id = locked_run.binding_access_epoch_id
    AND epoch.binding_id = locked_run.binding_id
    AND epoch.provider_id = locked_run.provider_id
    AND epoch.ended_at IS NULL;
  IF current_access_source_id IS NULL THEN
    RAISE EXCEPTION 'tenant LDAP provider access epoch is unavailable'
      USING ERRCODE = '55000';
  END IF;
  IF found_identity_id IS NOT NULL AND found_user_active
     AND found_membership_id IS NOT NULL AND found_membership_active THEN
    SELECT EXISTS (
      SELECT 1
      FROM public.tenant_ldap_provider_access_grants AS access_grant
      WHERE access_grant.tenant_id = locked_run.tenant_id
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

  UPDATE public.tenant_ldap_jit_authentication_runs AS run
  SET status = 'planning', claimed_at = transaction_timestamp(),
      version = run.version + 1
  WHERE run.tenant_id = locked_run.tenant_id AND run.id = locked_run.id;

  RETURN QUERY
  WITH selected_rules AS (
    SELECT pinned.mapping_rule_id, pinned.mapping_version,
           pinned.source_epoch_id, pinned.source_id, pinned.priority,
           epoch.configuration_revision, epoch.matcher_type,
           epoch.matcher_value, epoch.case_mode, epoch.reconciliation_mode,
           epoch.tenant_security_group_id AS security_group_id,
           epoch.operator_team_id,
           epoch.operator_team_assignment_epoch_id
    FROM public.tenant_ldap_jit_run_mappings AS pinned
    JOIN public.tenant_ldap_mapping_rule_epochs AS epoch
      ON epoch.tenant_id = pinned.tenant_id
     AND epoch.id = pinned.source_epoch_id
     AND epoch.mapping_rule_id = pinned.mapping_rule_id
     AND epoch.binding_id = pinned.binding_id
     AND epoch.source_id = pinned.source_id
    WHERE pinned.tenant_id = locked_run.tenant_id
      AND pinned.jit_run_id = locked_run.id
  ), rule_projection AS (
    SELECT selected.*,
           coalesce((
             SELECT array_agg(target.role_id ORDER BY target.role_id)
             FROM public.tenant_ldap_mapping_rule_role_targets AS target
             WHERE target.tenant_id = locked_run.tenant_id
               AND target.mapping_rule_id = selected.mapping_rule_id
               AND target.configuration_revision = selected.configuration_revision
           ), ARRAY[]::uuid[]) AS role_ids,
           coalesce((
             SELECT array_agg(grant_row.role_id ORDER BY grant_row.role_id)
             FROM public.tenant_security_group_role_grants AS grant_row
             JOIN public.tenant_authorization_sources AS source
               ON source.tenant_id = grant_row.tenant_id
              AND source.id = grant_row.source_id
              AND source.retired_at IS NULL
             WHERE grant_row.tenant_id = locked_run.tenant_id
               AND grant_row.group_id = selected.security_group_id
               AND grant_row.revoked_at IS NULL
               AND (grant_row.expires_at IS NULL
                    OR grant_row.expires_at > transaction_timestamp())
           ), ARRAY[]::uuid[]) AS active_group_role_ids,
           EXISTS (
             SELECT 1
             FROM public.operator_team_assignment_epochs AS assignment
             JOIN public.operator_teams AS team
               ON team.id = assignment.operator_team_id
              AND team.archived_at IS NULL
             WHERE assignment.tenant_id = locked_run.tenant_id
               AND assignment.id = selected.operator_team_assignment_epoch_id
               AND assignment.operator_team_id = selected.operator_team_id
               AND assignment.ended_at IS NULL
           ) AS assignment_live
    FROM selected_rules AS selected
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
    WHERE direct_grant.tenant_id = locked_run.tenant_id
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
    WHERE group_member.tenant_id = locked_run.tenant_id
      AND group_member.membership_id = found_membership_id
      AND group_member.revoked_at IS NULL
      AND (group_member.expires_at IS NULL
           OR group_member.expires_at > transaction_timestamp())
  ), needed_roles AS (
    SELECT unnest(projected.role_ids) AS role_id FROM rule_projection AS projected
    UNION SELECT unnest(projected.active_group_role_ids) FROM rule_projection AS projected
    UNION SELECT effective.role_id FROM effective_role_ids AS effective
  ), role_policy_rows AS (
    SELECT role.id AS role_id,
           coalesce(jsonb_agg(jsonb_build_object(
             'permission', permission.key, 'scope', policy.scope
           ) ORDER BY permission.key, policy.scope)
           FILTER (WHERE permission.id IS NOT NULL), '[]'::jsonb) AS policy
    FROM needed_roles AS needed
    JOIN public.tenant_roles AS role
      ON role.tenant_id = locked_run.tenant_id
     AND role.id = needed.role_id
     AND role.principal_kind = 'human'
     AND role.key <> 'platform_super_admin'
     AND role.archived_at IS NULL
    LEFT JOIN public.tenant_role_permissions AS policy
      ON policy.tenant_id = role.tenant_id AND policy.role_id = role.id
     AND policy.scope <> 'platform'
    LEFT JOIN public.tenant_permissions AS permission
      ON permission.id = policy.permission_id
    GROUP BY role.id
  ), owned_edges AS (
    SELECT pinned.source_id, pinned.source_epoch_id AS rule_epoch_id,
           'security_group_membership'::text AS kind,
           group_member.group_id AS primary_id, NULL::uuid AS secondary_id
    FROM public.tenant_ldap_jit_run_mappings AS pinned
    JOIN public.tenant_security_group_memberships AS group_member
      ON group_member.tenant_id = pinned.tenant_id
     AND group_member.source_id = pinned.source_id
     AND group_member.membership_id = found_membership_id
     AND group_member.revoked_at IS NULL
    WHERE pinned.tenant_id = locked_run.tenant_id
      AND pinned.jit_run_id = locked_run.id
    UNION ALL
    SELECT pinned.source_id, pinned.source_epoch_id,
           'security_group_role_grant', group_grant.group_id,
           group_grant.role_id
    FROM public.tenant_ldap_jit_run_mappings AS pinned
    JOIN public.tenant_security_group_role_grants AS group_grant
      ON group_grant.tenant_id = pinned.tenant_id
     AND group_grant.source_id = pinned.source_id
     AND group_grant.revoked_at IS NULL
    WHERE pinned.tenant_id = locked_run.tenant_id
      AND pinned.jit_run_id = locked_run.id
    UNION ALL
    SELECT pinned.source_id, pinned.source_epoch_id,
           'operator_team_roster', assignment.operator_team_id,
           roster.assignment_epoch_id
    FROM public.tenant_ldap_jit_run_mappings AS pinned
    JOIN public.operator_team_roster_entries AS roster
      ON roster.tenant_id = pinned.tenant_id
     AND roster.source_id = pinned.source_id
     AND roster.membership_id = found_membership_id
     AND roster.revoked_at IS NULL
    JOIN public.operator_team_assignment_epochs AS assignment
      ON assignment.tenant_id = roster.tenant_id
     AND assignment.id = roster.assignment_epoch_id
    WHERE pinned.tenant_id = locked_run.tenant_id
      AND pinned.jit_run_id = locked_run.id
  )
  SELECT locked_run.id, locked_run.tenant_id, locked_run.provider_id,
         locked_run.provider_version, locked_run.binding_id,
         locked_run.binding_version, locked_run.binding_auth_revision,
         locked_run.binding_access_epoch_id,
         locked_run.configuration_version, locked_run.rule_set_revision,
         locked_run.authorization_revision, configuration.jit_mode,
         configuration.no_match_policy, current_access_source_id,
         found_identity_id, found_user_id, found_membership_id,
         found_identity_id IS NOT NULL, found_user_active,
         found_membership_id IS NOT NULL, found_membership_active, live_access,
         coalesce((
           SELECT jsonb_agg(jsonb_build_object(
             'ruleId', projected.mapping_rule_id,
             'ruleEpochId', projected.source_epoch_id,
             'sourceId', projected.source_id,
             'revision', projected.mapping_version,
             'priority', projected.priority,
             'matcherType', projected.matcher_type,
             'matcherValue', projected.matcher_value,
             'caseMode', projected.case_mode,
             'reconciliationMode', projected.reconciliation_mode,
             'securityGroupId', projected.security_group_id,
             'roleIds', projected.role_ids,
             'activeGroupRoleIds', projected.active_group_role_ids,
             'operatorTeamId', projected.operator_team_id,
             'operatorTeamAssignmentEpochId',
               projected.operator_team_assignment_epoch_id,
             'operatorTeamAssignmentLive', projected.assignment_live
           ) ORDER BY projected.priority, projected.mapping_rule_id)
           FROM rule_projection AS projected
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
  WHERE configuration.tenant_id = locked_run.tenant_id
    AND configuration.provider_id = locked_run.provider_id;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION app.apply_tenant_ldap_jit_identity_plan_v1(
  p_operation_run_id uuid,
  p_receipt_digest bytea,
  p_application_id uuid,
  p_plan_digest bytea,
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
  locked_run public.tenant_ldap_jit_authentication_runs%ROWTYPE;
  applied record;
  selected_epoch_count integer;
  effective_terminal_status public.ldap_jit_run_status;
  effective_terminal_category text;
  effective_terminal_action text;
BEGIN
  IF p_operation_run_id IS NULL OR p_receipt_digest IS NULL
     OR octet_length(p_receipt_digest) <> 32
     OR p_application_id IS NULL OR p_plan_digest IS NULL
     OR octet_length(p_plan_digest) <> 32
     OR p_decision IS NULL OR p_audit_event_id IS NULL
     OR p_request_id IS NULL OR p_correlation_id IS NULL
     OR p_user_agent IS NULL OR length(p_user_agent) NOT BETWEEN 1 AND 1024 THEN
    RAISE EXCEPTION 'LDAP JIT apply wrapper input is invalid'
      USING ERRCODE = '22023';
  END IF;

  SELECT run.* INTO locked_run
  FROM public.tenant_ldap_jit_authentication_runs AS run
  WHERE run.id = p_operation_run_id
    AND run.receipt_digest = p_receipt_digest
  FOR UPDATE;
  IF NOT FOUND THEN RETURN; END IF;
  PERFORM set_config('app.tenant_id', locked_run.tenant_id::text, true);

  IF locked_run.status IN ('succeeded', 'denied') THEN
    IF locked_run.application_id IS DISTINCT FROM p_application_id
       OR locked_run.plan_digest IS DISTINCT FROM p_plan_digest
       OR (locked_run.status = 'succeeded' AND p_decision <> 'admitted')
       OR (locked_run.status = 'denied' AND p_decision <> 'denied') THEN
      RETURN;
    END IF;
    RETURN QUERY
    SELECT result.application_id, result.decision,
           result.external_identity_id, result.user_id,
           result.membership_id, result.access_grant_id,
           result.ensured_edge_count, result.revoked_edge_count,
           result.replayed
    FROM app.apply_tenant_ldap_identity_plan_v1(
      p_application_id, p_plan_digest, 'jit', NULL, NULL,
      locked_run.binding_id, locked_run.provider_version,
      locked_run.configuration_version, locked_run.binding_version,
      locked_run.binding_auth_revision, locked_run.binding_access_epoch_id,
      locked_run.rule_set_revision, locked_run.authorization_revision,
      p_decision, p_denial_category, p_external_identity_id, p_user_id,
      p_membership_id, p_access_grant_id, p_profile_contribution_id,
      p_subject_format, p_subject_ciphertext, p_subject_nonce,
      p_subject_key_version, p_alias_ids, p_alias_key_versions,
      p_alias_digests, p_display_name, p_first_name, p_last_name,
      p_username, p_email, p_matched_mapping_epoch_ids, p_observed_at,
      p_audit_event_id, p_request_id, p_correlation_id, p_ip_address,
      p_user_agent
    ) AS result;
    RETURN;
  END IF;
  IF locked_run.status <> 'planning' THEN RETURN; END IF;

  IF transaction_timestamp() > locked_run.expires_at THEN
    effective_terminal_status := 'expired';
    effective_terminal_category := 'expired';
    effective_terminal_action := 'tenant.identity.ldap_jit_expired';
  ELSIF NOT app.private_tenant_ldap_jit_run_is_current_v1(
    locked_run.tenant_id, locked_run.id
  ) THEN
    effective_terminal_status := 'stale';
    effective_terminal_category := 'stale_snapshot';
    effective_terminal_action := 'tenant.identity.ldap_jit_stale';
  END IF;
  IF effective_terminal_status IS NOT NULL THEN
    UPDATE public.tenant_ldap_jit_authentication_runs AS run
    SET status = effective_terminal_status,
        terminal_category = effective_terminal_category,
        terminal_audit_event_id = p_audit_event_id,
        completed_at = transaction_timestamp(), version = run.version + 1
    WHERE run.tenant_id = locked_run.tenant_id AND run.id = locked_run.id;
    PERFORM app.private_append_tenant_ldap_runtime_audit_v1(
      p_audit_event_id, locked_run.tenant_id, effective_terminal_action,
      'ldap_jit_authentication_run', locked_run.id, p_request_id,
      p_correlation_id, p_ip_address, p_user_agent, 'ldap', 'failure',
      effective_terminal_category,
      jsonb_build_object(
        'provider_id', locked_run.provider_id,
        'binding_id', locked_run.binding_id,
        'status', effective_terminal_status::text,
        'category', effective_terminal_category
      )
    );
    RETURN;
  END IF;

  IF p_matched_mapping_epoch_ids IS NULL
     OR cardinality(p_matched_mapping_epoch_ids) > 1000
     OR EXISTS (
       SELECT 1 FROM unnest(p_matched_mapping_epoch_ids) AS item(id)
       WHERE item.id IS NULL
     ) OR cardinality(p_matched_mapping_epoch_ids) IS DISTINCT FROM (
       SELECT count(DISTINCT item.id)::integer
       FROM unnest(p_matched_mapping_epoch_ids) AS item(id)
     ) THEN
    RAISE EXCEPTION 'LDAP JIT matched mapping selection is invalid'
      USING ERRCODE = '22023';
  END IF;
  SELECT count(*)::integer INTO selected_epoch_count
  FROM public.tenant_ldap_jit_run_mappings AS pinned
  WHERE pinned.tenant_id = locked_run.tenant_id
    AND pinned.jit_run_id = locked_run.id
    AND pinned.source_epoch_id = ANY(p_matched_mapping_epoch_ids);
  IF selected_epoch_count IS DISTINCT FROM
       cardinality(p_matched_mapping_epoch_ids) THEN
    RAISE EXCEPTION 'LDAP JIT plan references an unpinned mapping epoch'
      USING ERRCODE = '42501';
  END IF;

  SELECT result.* INTO applied
  FROM app.apply_tenant_ldap_identity_plan_v1(
    p_application_id, p_plan_digest, 'jit', NULL, NULL,
    locked_run.binding_id, locked_run.provider_version,
    locked_run.configuration_version, locked_run.binding_version,
    locked_run.binding_auth_revision, locked_run.binding_access_epoch_id,
    locked_run.rule_set_revision, locked_run.authorization_revision,
    p_decision, p_denial_category, p_external_identity_id, p_user_id,
    p_membership_id, p_access_grant_id, p_profile_contribution_id,
    p_subject_format, p_subject_ciphertext, p_subject_nonce,
    p_subject_key_version, p_alias_ids, p_alias_key_versions,
    p_alias_digests, p_display_name, p_first_name, p_last_name,
    p_username, p_email, p_matched_mapping_epoch_ids, p_observed_at,
    p_audit_event_id, p_request_id, p_correlation_id, p_ip_address,
    p_user_agent
  ) AS result;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'LDAP JIT identity plan produced no result'
      USING ERRCODE = '55000';
  END IF;

  UPDATE public.tenant_ldap_jit_authentication_runs AS run
  SET status = CASE WHEN p_decision = 'admitted'
                    THEN 'succeeded'::public.ldap_jit_run_status
                    ELSE 'denied'::public.ldap_jit_run_status END,
      application_id = p_application_id, plan_digest = p_plan_digest,
      terminal_audit_event_id = p_audit_event_id,
      completed_at = transaction_timestamp(), version = run.version + 1
  WHERE run.tenant_id = locked_run.tenant_id AND run.id = locked_run.id;

  PERFORM app.clear_auth_rate_limit(
    'ldap_account', locked_run.account_rate_key_digest
  );

  RETURN QUERY SELECT
    applied.application_id, applied.decision, applied.external_identity_id,
    applied.user_id, applied.membership_id, applied.access_grant_id,
    applied.ensured_edge_count, applied.revoked_edge_count, applied.replayed;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION app.complete_tenant_ldap_jit_authentication_v1(
  p_operation_run_id uuid,
  p_receipt_digest bytea,
  p_failure_category text,
  p_audit_event_id uuid,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text
)
RETURNS boolean
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  locked_run public.tenant_ldap_jit_authentication_runs%ROWTYPE;
  effective_status public.ldap_jit_run_status := 'failed';
  effective_category text := p_failure_category;
  effective_action text := 'tenant.identity.ldap_jit_failed';
  effective_outcome public.audit_outcome := 'failure';
BEGIN
  IF p_operation_run_id IS NULL OR p_receipt_digest IS NULL
     OR octet_length(p_receipt_digest) <> 32
     OR p_failure_category NOT IN (
       'invalid_credentials', 'network_error', 'directory_error',
       'account_disabled', 'cancelled'
     ) OR p_audit_event_id IS NULL OR p_request_id IS NULL
     OR p_correlation_id IS NULL OR p_user_agent IS NULL
     OR length(p_user_agent) NOT BETWEEN 1 AND 1024 THEN
    RAISE EXCEPTION 'LDAP JIT terminal completion input is invalid'
      USING ERRCODE = '22023';
  END IF;

  SELECT run.* INTO locked_run
  FROM public.tenant_ldap_jit_authentication_runs AS run
  WHERE run.id = p_operation_run_id
    AND run.receipt_digest = p_receipt_digest
  FOR UPDATE;
  IF NOT FOUND THEN RETURN false; END IF;
  PERFORM set_config('app.tenant_id', locked_run.tenant_id::text, true);
  IF locked_run.status IN ('failed', 'stale', 'expired') THEN
    RETURN locked_run.terminal_audit_event_id = p_audit_event_id
       AND EXISTS (
         SELECT 1 FROM public.audit_events AS audit
         WHERE audit.tenant_id = locked_run.tenant_id
           AND audit.id = p_audit_event_id
           AND audit.resource_type = 'ldap_jit_authentication_run'
           AND audit.resource_id = locked_run.id
           AND audit.request_id = p_request_id
           AND audit.correlation_id = p_correlation_id
           AND audit.metadata->>'requested_category' = p_failure_category
       );
  END IF;
  IF locked_run.status NOT IN ('network_pending', 'planning') THEN
    RETURN false;
  END IF;

  IF transaction_timestamp() > locked_run.expires_at THEN
    effective_status := 'expired';
    effective_category := 'expired';
    effective_action := 'tenant.identity.ldap_jit_expired';
  ELSIF NOT app.private_tenant_ldap_jit_run_is_current_v1(
    locked_run.tenant_id, locked_run.id
  ) THEN
    effective_status := 'stale';
    effective_category := 'stale_snapshot';
    effective_action := 'tenant.identity.ldap_jit_stale';
  ELSIF p_failure_category = 'account_disabled' THEN
    effective_outcome := 'denied';
  END IF;

  UPDATE public.tenant_ldap_jit_authentication_runs AS run
  SET status = effective_status, terminal_category = effective_category,
      terminal_audit_event_id = p_audit_event_id,
      completed_at = transaction_timestamp(), version = run.version + 1
  WHERE run.tenant_id = locked_run.tenant_id AND run.id = locked_run.id;

  PERFORM app.private_append_tenant_ldap_runtime_audit_v1(
    p_audit_event_id, locked_run.tenant_id, effective_action,
    'ldap_jit_authentication_run', locked_run.id, p_request_id,
    p_correlation_id, p_ip_address, p_user_agent, 'ldap',
    effective_outcome, effective_category,
    jsonb_build_object(
      'provider_id', locked_run.provider_id,
      'binding_id', locked_run.binding_id,
      'status', effective_status::text,
      'category', effective_category,
      'requested_category', p_failure_category
    )
  );
  RETURN true;
END;
$function$;--> statement-breakpoint

ALTER FUNCTION app.private_tenant_ldap_jit_run_is_current_v1(uuid, uuid)
  OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.private_get_tenant_ldap_jit_network_snapshot_v1(uuid, bytea)
  OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.begin_tenant_ldap_jit_authentication_v1(
  uuid, bytea, text, text, bytea, bytea, bytea, uuid, uuid, uuid, inet, text
) OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.read_tenant_ldap_jit_network_snapshot_v1(uuid, bytea)
  OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.claim_tenant_ldap_jit_planning_v1(
  uuid, bytea, integer[], bytea[], uuid, uuid, uuid, inet, text
) OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.apply_tenant_ldap_jit_identity_plan_v1(
  uuid, bytea, uuid, bytea, public.ldap_identity_apply_decision, text,
  uuid, uuid, uuid, uuid, uuid, public.identity_subject_format,
  bytea, bytea, integer, uuid[], integer[], bytea[], text, text, text,
  text, text, uuid[], timestamptz, uuid, uuid, uuid, inet, text
) OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.complete_tenant_ldap_jit_authentication_v1(
  uuid, bytea, text, uuid, uuid, uuid, inet, text
) OWNER TO periapsis_migrator;--> statement-breakpoint

REVOKE ALL ON FUNCTION app.private_tenant_ldap_jit_run_is_current_v1(uuid, uuid)
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_get_tenant_ldap_jit_network_snapshot_v1(uuid, bytea)
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.begin_tenant_ldap_jit_authentication_v1(
  uuid, bytea, text, text, bytea, bytea, bytea, uuid, uuid, uuid, inet, text
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.read_tenant_ldap_jit_network_snapshot_v1(uuid, bytea)
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.claim_tenant_ldap_jit_planning_v1(
  uuid, bytea, integer[], bytea[], uuid, uuid, uuid, inet, text
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.apply_tenant_ldap_jit_identity_plan_v1(
  uuid, bytea, uuid, bytea, public.ldap_identity_apply_decision, text,
  uuid, uuid, uuid, uuid, uuid, public.identity_subject_format,
  bytea, bytea, integer, uuid[], integer[], bytea[], text, text, text,
  text, text, uuid[], timestamptz, uuid, uuid, uuid, inet, text
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.complete_tenant_ldap_jit_authentication_v1(
  uuid, bytea, text, uuid, uuid, uuid, inet, text
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint

GRANT EXECUTE ON FUNCTION app.begin_tenant_ldap_jit_authentication_v1(
  uuid, bytea, text, text, bytea, bytea, bytea, uuid, uuid, uuid, inet, text
) TO periapsis_api;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.read_tenant_ldap_jit_network_snapshot_v1(uuid, bytea)
  TO periapsis_api;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.claim_tenant_ldap_jit_planning_v1(
  uuid, bytea, integer[], bytea[], uuid, uuid, uuid, inet, text
) TO periapsis_api;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.apply_tenant_ldap_jit_identity_plan_v1(
  uuid, bytea, uuid, bytea, public.ldap_identity_apply_decision, text,
  uuid, uuid, uuid, uuid, uuid, public.identity_subject_format,
  bytea, bytea, integer, uuid[], integer[], bytea[], text, text, text,
  text, text, uuid[], timestamptz, uuid, uuid, uuid, inet, text
) TO periapsis_api;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.complete_tenant_ldap_jit_authentication_v1(
  uuid, bytea, text, uuid, uuid, uuid, inet, text
) TO periapsis_api;
