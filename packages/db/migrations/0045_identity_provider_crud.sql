-- Extend the existing generic authorization-command tombstone to the first
-- identity-provider creation command. The row remains append-only and its
-- result must identify the exact tenant provider/version it created.
CREATE OR REPLACE FUNCTION app.guard_tenant_authorization_command()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF TG_OP = 'UPDATE' THEN
    RAISE EXCEPTION 'tenant authorization command rows are append-only'
      USING ERRCODE = '55000';
  END IF;

  IF TG_OP = 'DELETE' THEN
    IF OLD.expires_at > transaction_timestamp() THEN
      RAISE EXCEPTION 'unexpired tenant authorization commands cannot be pruned'
        USING ERRCODE = '55000';
    END IF;
    RETURN OLD;
  END IF;

  IF NEW.operation = 'tenant_role.create' THEN
    IF NOT EXISTS (
      SELECT 1 FROM public.tenant_roles AS resource
      WHERE resource.tenant_id = NEW.tenant_id
        AND resource.id = NEW.result_resource_id
        AND resource.version = NEW.result_version
    ) THEN
      RAISE EXCEPTION 'tenant role idempotency result is invalid'
        USING ERRCODE = '23503',
              CONSTRAINT = 'tenant_authorization_commands_result_fk';
    END IF;
  ELSIF NEW.operation = 'tenant_role_grant.create' THEN
    IF NOT EXISTS (
      SELECT 1 FROM public.tenant_membership_role_grants AS resource
      WHERE resource.tenant_id = NEW.tenant_id
        AND resource.id = NEW.result_resource_id
        AND resource.version = NEW.result_version
    ) THEN
      RAISE EXCEPTION 'tenant role grant idempotency result is invalid'
        USING ERRCODE = '23503',
              CONSTRAINT = 'tenant_authorization_commands_result_fk';
    END IF;
  ELSIF NEW.operation = 'tenant_security_group.create' THEN
    IF NOT EXISTS (
      SELECT 1 FROM public.tenant_security_groups AS resource
      WHERE resource.tenant_id = NEW.tenant_id
        AND resource.id = NEW.result_resource_id
        AND resource.version = NEW.result_version
    ) THEN
      RAISE EXCEPTION 'tenant security group idempotency result is invalid'
        USING ERRCODE = '23503',
              CONSTRAINT = 'tenant_authorization_commands_result_fk';
    END IF;
  ELSIF NEW.operation = 'tenant_security_group_membership.create' THEN
    IF NOT EXISTS (
      SELECT 1 FROM public.tenant_security_group_memberships AS resource
      WHERE resource.tenant_id = NEW.tenant_id
        AND resource.id = NEW.result_resource_id
        AND resource.version = NEW.result_version
    ) THEN
      RAISE EXCEPTION 'tenant security group membership idempotency result is invalid'
        USING ERRCODE = '23503',
              CONSTRAINT = 'tenant_authorization_commands_result_fk';
    END IF;
  ELSIF NEW.operation = 'tenant_security_group_role_grant.create' THEN
    IF NOT EXISTS (
      SELECT 1 FROM public.tenant_security_group_role_grants AS resource
      WHERE resource.tenant_id = NEW.tenant_id
        AND resource.id = NEW.result_resource_id
        AND resource.version = NEW.result_version
    ) THEN
      RAISE EXCEPTION 'tenant security group role grant idempotency result is invalid'
        USING ERRCODE = '23503',
              CONSTRAINT = 'tenant_authorization_commands_result_fk';
    END IF;
  ELSIF NEW.operation = 'operator_team_assignment.create' THEN
    IF NOT EXISTS (
      SELECT 1 FROM public.operator_team_assignment_epochs AS resource
      WHERE resource.tenant_id = NEW.tenant_id
        AND resource.id = NEW.result_resource_id
        AND resource.version = NEW.result_version
    ) THEN
      RAISE EXCEPTION 'operator-team assignment idempotency result is invalid'
        USING ERRCODE = '23503',
              CONSTRAINT = 'tenant_authorization_commands_result_fk';
    END IF;
  ELSIF NEW.operation = 'operator_team_roster_entry.create' THEN
    IF NOT EXISTS (
      SELECT 1 FROM public.operator_team_roster_entries AS resource
      WHERE resource.tenant_id = NEW.tenant_id
        AND resource.id = NEW.result_resource_id
        AND resource.version = NEW.result_version
    ) THEN
      RAISE EXCEPTION 'operator-team roster idempotency result is invalid'
        USING ERRCODE = '23503',
              CONSTRAINT = 'tenant_authorization_commands_result_fk';
    END IF;
  ELSIF NEW.operation = 'identity_provider.create' THEN
    IF NOT EXISTS (
      SELECT 1 FROM public.tenant_auth_providers AS resource
      WHERE resource.tenant_id = NEW.tenant_id
        AND resource.id = NEW.result_resource_id
        AND resource.version = NEW.result_version
    ) THEN
      RAISE EXCEPTION 'identity-provider idempotency result is invalid'
        USING ERRCODE = '23503',
              CONSTRAINT = 'tenant_authorization_commands_result_fk';
    END IF;
  ELSE
    RAISE EXCEPTION 'unsupported tenant authorization command operation'
      USING ERRCODE = '22023';
  END IF;

  RETURN NEW;
END;
$function$;--> statement-breakpoint

ALTER FUNCTION app.guard_tenant_authorization_command() OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.guard_tenant_authorization_command() FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint

-- Parse one exact allowlisted JSON document into the typed relational config.
-- This helper is private: it assumes the caller already locked and authorized
-- the provider, but independently rejects mass assignment and the not-yet-live
-- JIT/sync modes.
CREATE FUNCTION app.private_replace_tenant_ldap_configuration_v1(
  p_tenant_id uuid,
  p_provider_id uuid,
  p_actor_membership_id uuid,
  p_configuration jsonb,
  p_endpoints jsonb
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  expected_configuration_keys text[] := ARRAY[
    'accountDisabledValue',
    'accountStatusAttribute',
    'accountStatusMode',
    'alternateUsernameAttribute',
    'bindDn',
    'connectTimeoutMs',
    'customCaPem',
    'deprovisionGraceSeconds',
    'deprovisionMode',
    'displayNameAttribute',
    'emailAttribute',
    'firstNameAttribute',
    'groupBaseDn',
    'groupMembershipAttribute',
    'groupSearchFilter',
    'immutableSubjectAttribute',
    'immutableSubjectFormat',
    'jitMode',
    'lastNameAttribute',
    'maxEntries',
    'maxGroups',
    'maxNestedGroupDepth',
    'maxPages',
    'maxReferralHops',
    'maxResponseBytes',
    'nestedGroupMode',
    'noMatchPolicy',
    'operationTimeoutMs',
    'pageSize',
    'posixGidNumberAttribute',
    'posixMemberUidAttribute',
    'referralMode',
    'syncIntervalSeconds',
    'template',
    'userBaseDn',
    'userDnTemplate',
    'userSearchFilter',
    'usernameAttribute',
    'verifyCertificate'
  ]::text[];
  actual_configuration_keys text[];
  expected_endpoint_keys text[] := ARRAY[
    'enabled',
    'host',
    'port',
    'priority',
    'referralAllowed',
    'tlsServerName',
    'transport'
  ]::text[];
  endpoint_document jsonb;
  actual_endpoint_keys text[];
BEGIN
  IF jsonb_typeof(p_configuration) <> 'object'
     OR jsonb_typeof(p_endpoints) <> 'array'
     OR jsonb_array_length(p_endpoints) NOT BETWEEN 1 AND 8 THEN
    RAISE EXCEPTION 'invalid LDAP provider configuration document'
      USING ERRCODE = '22023';
  END IF;

  SELECT array_agg(configuration_key ORDER BY configuration_key)
  INTO actual_configuration_keys
  FROM jsonb_object_keys(p_configuration) AS configuration_key;
  IF actual_configuration_keys IS DISTINCT FROM expected_configuration_keys THEN
    RAISE EXCEPTION 'LDAP provider configuration fields are incomplete or unsupported'
      USING ERRCODE = '22023';
  END IF;

  IF p_configuration->'verifyCertificate' IS DISTINCT FROM 'true'::jsonb
     OR p_configuration->>'jitMode' <> 'disabled'
     OR p_configuration->>'noMatchPolicy' <> 'deny'
     OR p_configuration->>'deprovisionMode' <> 'retain'
     OR p_configuration->'deprovisionGraceSeconds' <> '0'::jsonb
     OR p_configuration->'syncIntervalSeconds' <> 'null'::jsonb THEN
    RAISE EXCEPTION 'LDAP certificate verification, disabled JIT, deny-only admission, retained deprovisioning, and disabled sync are required in the provider foundation'
      USING ERRCODE = '0A000';
  END IF;

  FOR endpoint_document IN
    SELECT endpoint.value
    FROM jsonb_array_elements(p_endpoints) AS endpoint(value)
  LOOP
    IF jsonb_typeof(endpoint_document) <> 'object' THEN
      RAISE EXCEPTION 'LDAP endpoint must be an object'
        USING ERRCODE = '22023';
    END IF;
    SELECT array_agg(endpoint_key ORDER BY endpoint_key)
    INTO actual_endpoint_keys
    FROM jsonb_object_keys(endpoint_document) AS endpoint_key;
    IF actual_endpoint_keys IS DISTINCT FROM expected_endpoint_keys THEN
      RAISE EXCEPTION 'LDAP endpoint fields are incomplete or unsupported'
        USING ERRCODE = '22023';
    END IF;
  END LOOP;

  INSERT INTO public.tenant_ldap_provider_configs (
    tenant_id, provider_id, provider_kind, template,
    verify_certificate, custom_ca_pem, connect_timeout_ms,
    operation_timeout_ms, bind_dn, user_base_dn, group_base_dn,
    user_search_filter, group_search_filter, user_dn_template,
    page_size, max_pages, max_entries, max_response_bytes,
    referral_mode, max_referral_hops, nested_group_mode,
    max_nested_group_depth, max_groups, first_name_attribute,
    last_name_attribute, display_name_attribute, username_attribute,
    alternate_username_attribute, email_attribute,
    immutable_subject_attribute, immutable_subject_format,
    group_membership_attribute, posix_member_uid_attribute,
    posix_gid_number_attribute, account_status_mode,
    account_status_attribute, account_disabled_value, jit_mode,
    no_match_policy, deprovision_mode, deprovision_grace_seconds,
    sync_interval_seconds, updated_by_membership_id
  )
  SELECT p_tenant_id,
         p_provider_id,
         'ldap'::public.auth_provider_kind,
         parsed."template"::public.ldap_provider_template,
         parsed."verifyCertificate",
         parsed."customCaPem",
         parsed."connectTimeoutMs",
         parsed."operationTimeoutMs",
         parsed."bindDn",
         parsed."userBaseDn",
         parsed."groupBaseDn",
         parsed."userSearchFilter",
         parsed."groupSearchFilter",
         parsed."userDnTemplate",
         parsed."pageSize",
         parsed."maxPages",
         parsed."maxEntries",
         parsed."maxResponseBytes",
         parsed."referralMode"::public.ldap_referral_mode,
         parsed."maxReferralHops",
         parsed."nestedGroupMode"::public.ldap_nested_group_mode,
         parsed."maxNestedGroupDepth",
         parsed."maxGroups",
         parsed."firstNameAttribute",
         parsed."lastNameAttribute",
         parsed."displayNameAttribute",
         parsed."usernameAttribute",
         parsed."alternateUsernameAttribute",
         parsed."emailAttribute",
         parsed."immutableSubjectAttribute",
         parsed."immutableSubjectFormat"::public.identity_subject_format,
         parsed."groupMembershipAttribute",
         parsed."posixMemberUidAttribute",
         parsed."posixGidNumberAttribute",
         parsed."accountStatusMode"::public.ldap_account_status_mode,
         parsed."accountStatusAttribute",
         parsed."accountDisabledValue",
         parsed."jitMode"::public.identity_jit_mode,
         parsed."noMatchPolicy"::public.identity_no_match_policy,
         parsed."deprovisionMode"::public.identity_deprovision_mode,
         parsed."deprovisionGraceSeconds",
         parsed."syncIntervalSeconds",
         p_actor_membership_id
  FROM jsonb_to_record(p_configuration) AS parsed(
    "template" text,
    "verifyCertificate" boolean,
    "customCaPem" text,
    "connectTimeoutMs" integer,
    "operationTimeoutMs" integer,
    "bindDn" text,
    "userBaseDn" text,
    "groupBaseDn" text,
    "userSearchFilter" text,
    "groupSearchFilter" text,
    "userDnTemplate" text,
    "pageSize" integer,
    "maxPages" integer,
    "maxEntries" integer,
    "maxResponseBytes" integer,
    "referralMode" text,
    "maxReferralHops" integer,
    "nestedGroupMode" text,
    "maxNestedGroupDepth" integer,
    "maxGroups" integer,
    "firstNameAttribute" text,
    "lastNameAttribute" text,
    "displayNameAttribute" text,
    "usernameAttribute" text,
    "alternateUsernameAttribute" text,
    "emailAttribute" text,
    "immutableSubjectAttribute" text,
    "immutableSubjectFormat" text,
    "groupMembershipAttribute" text,
    "posixMemberUidAttribute" text,
    "posixGidNumberAttribute" text,
    "accountStatusMode" text,
    "accountStatusAttribute" text,
    "accountDisabledValue" text,
    "jitMode" text,
    "noMatchPolicy" text,
    "deprovisionMode" text,
    "deprovisionGraceSeconds" integer,
    "syncIntervalSeconds" integer
  )
  ON CONFLICT (tenant_id, provider_id) DO UPDATE
  SET template = EXCLUDED.template,
      verify_certificate = EXCLUDED.verify_certificate,
      custom_ca_pem = EXCLUDED.custom_ca_pem,
      connect_timeout_ms = EXCLUDED.connect_timeout_ms,
      operation_timeout_ms = EXCLUDED.operation_timeout_ms,
      bind_dn = EXCLUDED.bind_dn,
      user_base_dn = EXCLUDED.user_base_dn,
      group_base_dn = EXCLUDED.group_base_dn,
      user_search_filter = EXCLUDED.user_search_filter,
      group_search_filter = EXCLUDED.group_search_filter,
      user_dn_template = EXCLUDED.user_dn_template,
      page_size = EXCLUDED.page_size,
      max_pages = EXCLUDED.max_pages,
      max_entries = EXCLUDED.max_entries,
      max_response_bytes = EXCLUDED.max_response_bytes,
      referral_mode = EXCLUDED.referral_mode,
      max_referral_hops = EXCLUDED.max_referral_hops,
      nested_group_mode = EXCLUDED.nested_group_mode,
      max_nested_group_depth = EXCLUDED.max_nested_group_depth,
      max_groups = EXCLUDED.max_groups,
      first_name_attribute = EXCLUDED.first_name_attribute,
      last_name_attribute = EXCLUDED.last_name_attribute,
      display_name_attribute = EXCLUDED.display_name_attribute,
      username_attribute = EXCLUDED.username_attribute,
      alternate_username_attribute = EXCLUDED.alternate_username_attribute,
      email_attribute = EXCLUDED.email_attribute,
      immutable_subject_attribute = EXCLUDED.immutable_subject_attribute,
      immutable_subject_format = EXCLUDED.immutable_subject_format,
      group_membership_attribute = EXCLUDED.group_membership_attribute,
      posix_member_uid_attribute = EXCLUDED.posix_member_uid_attribute,
      posix_gid_number_attribute = EXCLUDED.posix_gid_number_attribute,
      account_status_mode = EXCLUDED.account_status_mode,
      account_status_attribute = EXCLUDED.account_status_attribute,
      account_disabled_value = EXCLUDED.account_disabled_value,
      jit_mode = EXCLUDED.jit_mode,
      no_match_policy = EXCLUDED.no_match_policy,
      deprovision_mode = EXCLUDED.deprovision_mode,
      deprovision_grace_seconds = EXCLUDED.deprovision_grace_seconds,
      sync_interval_seconds = EXCLUDED.sync_interval_seconds,
      updated_by_membership_id = EXCLUDED.updated_by_membership_id,
      version = tenant_ldap_provider_configs.version + 1,
      updated_at = transaction_timestamp();

  DELETE FROM public.tenant_ldap_provider_urls AS endpoint
  WHERE endpoint.tenant_id = p_tenant_id
    AND endpoint.provider_id = p_provider_id;

  INSERT INTO public.tenant_ldap_provider_urls (
    id, tenant_id, provider_id, provider_kind, priority, host, port,
    transport, tls_server_name, referral_allowed, enabled
  )
  SELECT uuidv7(),
         p_tenant_id,
         p_provider_id,
         'ldap'::public.auth_provider_kind,
         endpoint."priority",
         endpoint."host",
         endpoint."port",
         endpoint."transport"::public.ldap_transport,
         endpoint."tlsServerName",
         endpoint."referralAllowed",
         endpoint."enabled"
  FROM jsonb_to_recordset(p_endpoints) AS endpoint(
    "priority" integer,
    "host" text,
    "port" integer,
    "transport" text,
    "tlsServerName" text,
    "referralAllowed" boolean,
    "enabled" boolean
  );
END;
$function$;--> statement-breakpoint

ALTER FUNCTION app.private_replace_tenant_ldap_configuration_v1(uuid, uuid, uuid, jsonb, jsonb) OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_replace_tenant_ldap_configuration_v1(uuid, uuid, uuid, jsonb, jsonb) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint

CREATE FUNCTION app.list_tenant_ldap_providers_v1(
  p_after_provider_id uuid,
  p_include_archived boolean,
  p_limit integer
)
RETURNS TABLE (
  provider_id uuid,
  provider_key text,
  display_name text,
  description text,
  enabled boolean,
  template public.ldap_provider_template,
  bind_secret_configured boolean,
  enabled_endpoint_count integer,
  archived_at timestamp with time zone,
  version integer,
  created_at timestamp with time zone,
  updated_at timestamp with time zone
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
    'identity_provider.read', 'tenant'
  ) THEN
    RAISE EXCEPTION 'identity_provider.read tenant scope is required'
      USING ERRCODE = '42501';
  END IF;
  IF p_include_archived IS NULL OR p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 101 THEN
    RAISE EXCEPTION 'invalid identity-provider inventory request'
      USING ERRCODE = '22023';
  END IF;

  RETURN QUERY
  SELECT provider.id,
         provider.key,
         provider.display_name,
         provider.description,
         provider.enabled,
         configuration.template,
         EXISTS (
           SELECT 1
           FROM public.tenant_ldap_provider_secrets AS secret
           WHERE secret.tenant_id = provider.tenant_id
             AND secret.provider_id = provider.id
         ),
         (
           SELECT count(*)::integer
           FROM public.tenant_ldap_provider_urls AS endpoint
           WHERE endpoint.tenant_id = provider.tenant_id
             AND endpoint.provider_id = provider.id
             AND endpoint.enabled
         ),
         provider.archived_at,
         provider.version,
         provider.created_at,
         provider.updated_at
  FROM public.tenant_auth_providers AS provider
  JOIN public.tenant_ldap_provider_configs AS configuration
    ON configuration.tenant_id = provider.tenant_id
   AND configuration.provider_id = provider.id
  WHERE provider.tenant_id = context_tenant
    AND provider.kind = 'ldap'
    AND (p_include_archived OR provider.archived_at IS NULL)
    AND (p_after_provider_id IS NULL OR provider.id > p_after_provider_id)
  ORDER BY provider.id
  LIMIT p_limit;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION app.get_tenant_ldap_provider_v1(p_provider_id uuid)
RETURNS TABLE (
  provider_id uuid,
  provider_key text,
  display_name text,
  description text,
  enabled boolean,
  configuration jsonb,
  endpoints jsonb,
  bind_secret_configured boolean,
  bind_secret_rotated_at timestamp with time zone,
  archived_at timestamp with time zone,
  archive_reason text,
  version integer,
  created_at timestamp with time zone,
  updated_at timestamp with time zone
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
    'identity_provider.read', 'tenant'
  ) THEN
    RAISE EXCEPTION 'identity_provider.read tenant scope is required'
      USING ERRCODE = '42501';
  END IF;

  RETURN QUERY
  SELECT provider.id,
         provider.key,
         provider.display_name,
         provider.description,
         provider.enabled,
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
           'noMatchPolicy', configuration.no_match_policy,
           'deprovisionMode', configuration.deprovision_mode,
           'deprovisionGraceSeconds', configuration.deprovision_grace_seconds,
           'syncIntervalSeconds', configuration.sync_interval_seconds
         ),
         COALESCE((
           SELECT jsonb_agg(
             jsonb_build_object(
               'priority', endpoint.priority,
               'host', endpoint.host,
               'port', endpoint.port,
               'transport', endpoint.transport,
               'tlsServerName', endpoint.tls_server_name,
               'referralAllowed', endpoint.referral_allowed,
               'enabled', endpoint.enabled
             ) ORDER BY endpoint.priority
           )
           FROM public.tenant_ldap_provider_urls AS endpoint
           WHERE endpoint.tenant_id = provider.tenant_id
             AND endpoint.provider_id = provider.id
         ), '[]'::jsonb),
         secret.provider_id IS NOT NULL,
         secret.rotated_at,
         provider.archived_at,
         provider.archive_reason,
         provider.version,
         provider.created_at,
         provider.updated_at
  FROM public.tenant_auth_providers AS provider
  JOIN public.tenant_ldap_provider_configs AS configuration
    ON configuration.tenant_id = provider.tenant_id
   AND configuration.provider_id = provider.id
  LEFT JOIN public.tenant_ldap_provider_secrets AS secret
    ON secret.tenant_id = provider.tenant_id
   AND secret.provider_id = provider.id
  WHERE provider.tenant_id = context_tenant
    AND provider.id = p_provider_id
    AND provider.kind = 'ldap';
END;
$function$;--> statement-breakpoint

CREATE FUNCTION app.create_tenant_ldap_provider_v1(
  p_provider_id uuid,
  p_idempotency_key_digest bytea,
  p_provider_key text,
  p_display_name text,
  p_description text,
  p_configuration jsonb,
  p_endpoints jsonb,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text
)
RETURNS TABLE (provider_id uuid, result_version integer, replayed boolean)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  actor_membership uuid;
  canonical_request_digest bytea;
  existing_command public.tenant_authorization_commands%ROWTYPE;
BEGIN
  PERFORM app.lock_current_tenant_authorization_state();

  actor_membership := app.current_tenant_membership_id();
  IF NOT app.current_tenant_human_has_exact_permission_v3(
    'identity_provider.manage', 'tenant'
  ) THEN
    RAISE EXCEPTION 'identity_provider.manage tenant scope is required'
      USING ERRCODE = '42501';
  END IF;
  IF p_idempotency_key_digest IS NULL
     OR octet_length(p_idempotency_key_digest) <> 32 THEN
    RAISE EXCEPTION 'invalid identity-provider idempotency digest'
      USING ERRCODE = '22023';
  END IF;

  SELECT sha256(convert_to(jsonb_build_object(
    'key', p_provider_key,
    'displayName', p_display_name,
    'description', coalesce(p_description, ''),
    'configuration', p_configuration,
    'endpoints', p_endpoints
  )::text, 'UTF8'))
  INTO canonical_request_digest;

  DELETE FROM public.tenant_authorization_commands AS command
  WHERE command.tenant_id = context_tenant
    AND command.actor_membership_id = actor_membership
    AND command.operation = 'identity_provider.create'
    AND command.key_digest = p_idempotency_key_digest
    AND command.expires_at <= transaction_timestamp();

  SELECT command.*
  INTO existing_command
  FROM public.tenant_authorization_commands AS command
  WHERE command.tenant_id = context_tenant
    AND command.actor_membership_id = actor_membership
    AND command.operation = 'identity_provider.create'
    AND command.key_digest = p_idempotency_key_digest
  FOR UPDATE;

  IF FOUND THEN
    IF existing_command.request_digest IS DISTINCT FROM canonical_request_digest THEN
      RAISE EXCEPTION 'identity-provider idempotency key was reused with another request'
        USING ERRCODE = '23505',
              CONSTRAINT = 'tenant_authorization_commands_replay_key';
    END IF;
    RETURN QUERY
    SELECT existing_command.result_resource_id,
           existing_command.result_version,
           true;
    RETURN;
  END IF;

  INSERT INTO public.tenant_auth_providers (
    id, tenant_id, key, display_name, description, kind, enabled,
    created_by_membership_id, updated_by_membership_id
  ) VALUES (
    p_provider_id, context_tenant, p_provider_key, p_display_name,
    coalesce(p_description, ''), 'ldap', false,
    actor_membership, actor_membership
  );

  PERFORM app.private_replace_tenant_ldap_configuration_v1(
    context_tenant, p_provider_id, actor_membership,
    p_configuration, p_endpoints
  );

  INSERT INTO public.tenant_authorization_commands (
    id, tenant_id, actor_membership_id, operation, key_digest,
    request_digest, result_resource_id, result_version
  ) VALUES (
    uuidv7(), context_tenant, actor_membership,
    'identity_provider.create', p_idempotency_key_digest,
    canonical_request_digest, p_provider_id, 1
  );

  PERFORM app.append_tenant_authorization_audit(
    uuidv7(), 'tenant.identity_provider.created', 'identity_provider',
    p_provider_id, p_request_id, p_correlation_id, p_ip_address,
    p_user_agent, p_authentication_method, NULL,
    jsonb_build_object(
      'key', p_provider_key,
      'display_name', p_display_name,
      'kind', 'ldap',
      'enabled', false,
      'template', p_configuration->>'template',
      'endpoint_count', jsonb_array_length(p_endpoints),
      'bind_secret_configured', false,
      'version', 1
    ),
    jsonb_build_object('idempotent_replay', false)
  );

  RETURN QUERY SELECT p_provider_id, 1, false;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION app.update_tenant_ldap_provider_v1(
  p_provider_id uuid,
  p_expected_version integer,
  p_provider_key text,
  p_display_name text,
  p_description text,
  p_enabled boolean,
  p_configuration jsonb,
  p_endpoints jsonb,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text
)
RETURNS integer
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  actor_membership uuid;
  locked_provider public.tenant_auth_providers%ROWTYPE;
  next_version integer;
BEGIN
  PERFORM app.lock_current_tenant_authorization_state();
  actor_membership := app.current_tenant_membership_id();
  IF NOT app.current_tenant_human_has_exact_permission_v3(
    'identity_provider.manage', 'tenant'
  ) THEN
    RAISE EXCEPTION 'identity_provider.manage tenant scope is required'
      USING ERRCODE = '42501';
  END IF;

  SELECT provider.*
  INTO locked_provider
  FROM public.tenant_auth_providers AS provider
  WHERE provider.tenant_id = context_tenant
    AND provider.id = p_provider_id
    AND provider.kind = 'ldap'
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant LDAP provider was not found'
      USING ERRCODE = 'P0002';
  END IF;
  IF locked_provider.archived_at IS NOT NULL THEN
    RAISE EXCEPTION 'archived tenant LDAP provider cannot be changed'
      USING ERRCODE = '55000';
  END IF;
  IF p_expected_version IS NULL OR p_expected_version <> locked_provider.version THEN
    RAISE EXCEPTION 'tenant LDAP provider version does not match'
      USING ERRCODE = '40001';
  END IF;
  IF p_enabled IS NULL THEN
    RAISE EXCEPTION 'tenant LDAP provider enabled state is required'
      USING ERRCODE = '22023';
  END IF;
  IF locked_provider.version >= 2147483647 THEN
    RAISE EXCEPTION 'tenant LDAP provider version is exhausted'
      USING ERRCODE = '55000';
  END IF;

  PERFORM app.private_replace_tenant_ldap_configuration_v1(
    context_tenant, p_provider_id, actor_membership,
    p_configuration, p_endpoints
  );

  IF p_enabled AND NOT EXISTS (
    SELECT 1
    FROM public.tenant_ldap_provider_secrets AS secret
    WHERE secret.tenant_id = context_tenant
      AND secret.provider_id = p_provider_id
  ) THEN
    RAISE EXCEPTION 'tenant LDAP provider requires a bind secret before enablement'
      USING ERRCODE = '55000';
  END IF;
  IF p_enabled AND NOT EXISTS (
    SELECT 1
    FROM public.tenant_ldap_provider_urls AS endpoint
    WHERE endpoint.tenant_id = context_tenant
      AND endpoint.provider_id = p_provider_id
      AND endpoint.enabled
  ) THEN
    RAISE EXCEPTION 'tenant LDAP provider requires an enabled endpoint'
      USING ERRCODE = '55000';
  END IF;

  next_version := locked_provider.version + 1;
  UPDATE public.tenant_auth_providers AS provider
  SET key = p_provider_key,
      display_name = p_display_name,
      description = coalesce(p_description, ''),
      enabled = p_enabled,
      updated_by_membership_id = actor_membership,
      version = next_version,
      updated_at = transaction_timestamp()
  WHERE provider.tenant_id = context_tenant
    AND provider.id = p_provider_id;

  PERFORM app.append_tenant_authorization_audit(
    uuidv7(), 'tenant.identity_provider.updated', 'identity_provider',
    p_provider_id, p_request_id, p_correlation_id, p_ip_address,
    p_user_agent, p_authentication_method,
    jsonb_build_object(
      'key', locked_provider.key,
      'display_name', locked_provider.display_name,
      'enabled', locked_provider.enabled,
      'version', locked_provider.version
    ),
    jsonb_build_object(
      'key', p_provider_key,
      'display_name', p_display_name,
      'enabled', p_enabled,
      'template', p_configuration->>'template',
      'endpoint_count', jsonb_array_length(p_endpoints),
      'version', next_version
    ),
    '{}'::jsonb
  );

  RETURN next_version;
END;
$function$;--> statement-breakpoint

-- Rotation needs the stable row identity before encryption. The opaque
-- envelope itself is available only to the explicit provider-test surface;
-- neither function can be used by a service account or another tenant.
CREATE FUNCTION app.get_tenant_ldap_bind_secret_id_v1(p_provider_id uuid)
RETURNS uuid
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  secret_id uuid;
BEGIN
  PERFORM app.current_tenant_membership_id();
  IF NOT app.current_tenant_human_has_exact_permission_v3(
    'identity_provider.manage', 'tenant'
  ) THEN
    RAISE EXCEPTION 'identity_provider.manage tenant scope is required'
      USING ERRCODE = '42501';
  END IF;

  IF NOT EXISTS (
    SELECT 1
    FROM public.tenant_auth_providers AS provider
    WHERE provider.tenant_id = context_tenant
      AND provider.id = p_provider_id
      AND provider.kind = 'ldap'
      AND provider.archived_at IS NULL
  ) THEN
    RAISE EXCEPTION 'tenant LDAP provider was not found'
      USING ERRCODE = 'P0002';
  END IF;

  SELECT secret.id
  INTO secret_id
  FROM public.tenant_ldap_provider_secrets AS secret
  WHERE secret.tenant_id = context_tenant
    AND secret.provider_id = p_provider_id;

  RETURN secret_id;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION app.get_tenant_ldap_bind_secret_envelope_v1(p_provider_id uuid)
RETURNS TABLE (
  secret_id uuid,
  secret_ciphertext bytea,
  secret_nonce bytea,
  key_version integer,
  encryption_algorithm text
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
    'identity_provider.test', 'tenant'
  ) THEN
    RAISE EXCEPTION 'identity_provider.test tenant scope is required'
      USING ERRCODE = '42501';
  END IF;

  RETURN QUERY
  SELECT secret.id,
         secret.secret_ciphertext,
         secret.secret_nonce,
         secret.key_version,
         secret.encryption_algorithm
  FROM public.tenant_auth_providers AS provider
  JOIN public.tenant_ldap_provider_secrets AS secret
    ON secret.tenant_id = provider.tenant_id
   AND secret.provider_id = provider.id
  WHERE provider.tenant_id = context_tenant
    AND provider.id = p_provider_id
    AND provider.kind = 'ldap'
    AND provider.archived_at IS NULL;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION app.rotate_tenant_ldap_bind_secret_v1(
  p_provider_id uuid,
  p_expected_version integer,
  p_secret_id uuid,
  p_secret_ciphertext bytea,
  p_secret_nonce bytea,
  p_key_version integer,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text
)
RETURNS integer
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  actor_membership uuid;
  locked_provider public.tenant_auth_providers%ROWTYPE;
  existing_secret_id uuid;
  existing_secret_version integer;
  bind_secret_was_configured boolean;
  next_version integer;
BEGIN
  PERFORM app.lock_current_tenant_authorization_state();
  actor_membership := app.current_tenant_membership_id();
  IF NOT app.current_tenant_human_has_exact_permission_v3(
    'identity_provider.manage', 'tenant'
  ) THEN
    RAISE EXCEPTION 'identity_provider.manage tenant scope is required'
      USING ERRCODE = '42501';
  END IF;

  SELECT provider.*
  INTO locked_provider
  FROM public.tenant_auth_providers AS provider
  WHERE provider.tenant_id = context_tenant
    AND provider.id = p_provider_id
    AND provider.kind = 'ldap'
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant LDAP provider was not found'
      USING ERRCODE = 'P0002';
  END IF;
  IF locked_provider.archived_at IS NOT NULL THEN
    RAISE EXCEPTION 'archived tenant LDAP provider secret cannot be changed'
      USING ERRCODE = '55000';
  END IF;
  IF p_expected_version IS NULL OR p_expected_version <> locked_provider.version THEN
    RAISE EXCEPTION 'tenant LDAP provider version does not match'
      USING ERRCODE = '40001';
  END IF;
  IF locked_provider.version >= 2147483647 THEN
    RAISE EXCEPTION 'tenant LDAP provider version is exhausted'
      USING ERRCODE = '55000';
  END IF;
  IF p_secret_id IS NULL
     OR (uuid_extract_version(p_secret_id) = 7) IS NOT TRUE THEN
    RAISE EXCEPTION 'tenant LDAP bind-secret row ID must be UUIDv7'
      USING ERRCODE = '22023';
  END IF;

  PERFORM keyring.key_version
  FROM public.identity_keyring_versions AS keyring
  WHERE keyring.key_version = p_key_version
    AND keyring.retired_at IS NULL
  FOR KEY SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'identity key version is not verified'
      USING ERRCODE = '55000';
  END IF;

  SELECT secret.id, secret.version
  INTO existing_secret_id, existing_secret_version
  FROM public.tenant_ldap_provider_secrets AS secret
  WHERE secret.tenant_id = context_tenant
    AND secret.provider_id = p_provider_id
  FOR UPDATE;
  bind_secret_was_configured := FOUND;
  IF bind_secret_was_configured THEN
    IF existing_secret_id <> p_secret_id THEN
      RAISE EXCEPTION 'tenant LDAP bind-secret row identity cannot change'
        USING ERRCODE = '55000';
    END IF;
    IF existing_secret_version >= 2147483647 THEN
      RAISE EXCEPTION 'tenant LDAP bind-secret version is exhausted'
        USING ERRCODE = '55000';
    END IF;
  END IF;

  INSERT INTO public.tenant_ldap_provider_secrets (
    id, tenant_id, provider_id, provider_kind, secret_ciphertext,
    secret_nonce, key_version, encryption_algorithm,
    rotated_by_membership_id
  ) VALUES (
    p_secret_id, context_tenant, p_provider_id, 'ldap', p_secret_ciphertext,
    p_secret_nonce, p_key_version, 'aes-256-gcm',
    actor_membership
  )
  ON CONFLICT (tenant_id, provider_id) DO UPDATE
  SET secret_ciphertext = EXCLUDED.secret_ciphertext,
      secret_nonce = EXCLUDED.secret_nonce,
      key_version = EXCLUDED.key_version,
      encryption_algorithm = EXCLUDED.encryption_algorithm,
      rotated_by_membership_id = EXCLUDED.rotated_by_membership_id,
      rotated_at = transaction_timestamp(),
      version = tenant_ldap_provider_secrets.version + 1,
      updated_at = transaction_timestamp();

  next_version := locked_provider.version + 1;
  UPDATE public.tenant_auth_providers AS provider
  SET updated_by_membership_id = actor_membership,
      version = next_version,
      updated_at = transaction_timestamp()
  WHERE provider.tenant_id = context_tenant
    AND provider.id = p_provider_id;

  PERFORM app.append_tenant_authorization_audit(
    uuidv7(), 'tenant.identity_provider.bind_secret_rotated',
    'identity_provider', p_provider_id, p_request_id, p_correlation_id,
    p_ip_address, p_user_agent, p_authentication_method,
    jsonb_build_object(
      'bind_secret_configured', bind_secret_was_configured,
      'version', locked_provider.version
    ),
    jsonb_build_object(
      'bind_secret_configured', true,
      'key_version', p_key_version,
      'version', next_version
    ),
    '{}'::jsonb
  );

  RETURN next_version;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION app.clear_tenant_ldap_bind_secret_v1(
  p_provider_id uuid,
  p_expected_version integer,
  p_reason text,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text
)
RETURNS integer
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  actor_membership uuid;
  locked_provider public.tenant_auth_providers%ROWTYPE;
  next_version integer;
BEGIN
  PERFORM app.lock_current_tenant_authorization_state();
  actor_membership := app.current_tenant_membership_id();
  IF NOT app.current_tenant_human_has_exact_permission_v3(
    'identity_provider.manage', 'tenant'
  ) THEN
    RAISE EXCEPTION 'identity_provider.manage tenant scope is required'
      USING ERRCODE = '42501';
  END IF;

  SELECT provider.*
  INTO locked_provider
  FROM public.tenant_auth_providers AS provider
  WHERE provider.tenant_id = context_tenant
    AND provider.id = p_provider_id
    AND provider.kind = 'ldap'
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant LDAP provider was not found'
      USING ERRCODE = 'P0002';
  END IF;
  IF locked_provider.archived_at IS NOT NULL THEN
    RAISE EXCEPTION 'archived tenant LDAP provider secret cannot be changed'
      USING ERRCODE = '55000';
  END IF;
  IF locked_provider.enabled THEN
    RAISE EXCEPTION 'disable the tenant LDAP provider before clearing its bind secret'
      USING ERRCODE = '55000';
  END IF;
  IF p_expected_version IS NULL OR p_expected_version <> locked_provider.version THEN
    RAISE EXCEPTION 'tenant LDAP provider version does not match'
      USING ERRCODE = '40001';
  END IF;
  IF p_reason IS NULL OR btrim(p_reason) = ''
     OR char_length(p_reason) > 500 OR p_reason ~ '[[:cntrl:]]' THEN
    RAISE EXCEPTION 'bind-secret clear reason is invalid'
      USING ERRCODE = '22023';
  END IF;
  IF locked_provider.version >= 2147483647 THEN
    RAISE EXCEPTION 'tenant LDAP provider version is exhausted'
      USING ERRCODE = '55000';
  END IF;

  DELETE FROM public.tenant_ldap_provider_secrets AS secret
  WHERE secret.tenant_id = context_tenant
    AND secret.provider_id = p_provider_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant LDAP provider has no bind secret'
      USING ERRCODE = 'P0002';
  END IF;

  next_version := locked_provider.version + 1;
  UPDATE public.tenant_auth_providers AS provider
  SET updated_by_membership_id = actor_membership,
      version = next_version,
      updated_at = transaction_timestamp()
  WHERE provider.tenant_id = context_tenant
    AND provider.id = p_provider_id;

  PERFORM app.append_tenant_authorization_audit(
    uuidv7(), 'tenant.identity_provider.bind_secret_cleared',
    'identity_provider', p_provider_id, p_request_id, p_correlation_id,
    p_ip_address, p_user_agent, p_authentication_method,
    jsonb_build_object(
      'bind_secret_configured', true,
      'version', locked_provider.version
    ),
    jsonb_build_object(
      'bind_secret_configured', false,
      'version', next_version
    ),
    jsonb_build_object('reason', p_reason)
  );

  RETURN next_version;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION app.archive_tenant_ldap_provider_v1(
  p_provider_id uuid,
  p_expected_version integer,
  p_reason text,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text
)
RETURNS integer
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  actor_membership uuid;
  locked_provider public.tenant_auth_providers%ROWTYPE;
  next_version integer;
BEGIN
  PERFORM app.lock_current_tenant_authorization_state();
  actor_membership := app.current_tenant_membership_id();
  IF NOT app.current_tenant_human_has_exact_permission_v3(
    'identity_provider.manage', 'tenant'
  ) THEN
    RAISE EXCEPTION 'identity_provider.manage tenant scope is required'
      USING ERRCODE = '42501';
  END IF;

  SELECT provider.*
  INTO locked_provider
  FROM public.tenant_auth_providers AS provider
  WHERE provider.tenant_id = context_tenant
    AND provider.id = p_provider_id
    AND provider.kind = 'ldap'
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant LDAP provider was not found'
      USING ERRCODE = 'P0002';
  END IF;
  IF locked_provider.archived_at IS NOT NULL THEN
    RAISE EXCEPTION 'tenant LDAP provider is already archived'
      USING ERRCODE = '55000';
  END IF;
  IF p_expected_version IS NULL OR p_expected_version <> locked_provider.version THEN
    RAISE EXCEPTION 'tenant LDAP provider version does not match'
      USING ERRCODE = '40001';
  END IF;
  IF p_reason IS NULL OR btrim(p_reason) = ''
     OR char_length(p_reason) > 500 OR p_reason ~ '[[:cntrl:]]' THEN
    RAISE EXCEPTION 'identity-provider archive reason is invalid'
      USING ERRCODE = '22023';
  END IF;
  IF locked_provider.version >= 2147483647 THEN
    RAISE EXCEPTION 'tenant LDAP provider version is exhausted'
      USING ERRCODE = '55000';
  END IF;

  next_version := locked_provider.version + 1;
  UPDATE public.tenant_auth_providers AS provider
  SET enabled = false,
      archived_at = transaction_timestamp(),
      archived_by_membership_id = actor_membership,
      archive_reason = p_reason,
      updated_by_membership_id = actor_membership,
      version = next_version,
      updated_at = transaction_timestamp()
  WHERE provider.tenant_id = context_tenant
    AND provider.id = p_provider_id;

  PERFORM app.append_tenant_authorization_audit(
    uuidv7(), 'tenant.identity_provider.archived', 'identity_provider',
    p_provider_id, p_request_id, p_correlation_id, p_ip_address,
    p_user_agent, p_authentication_method,
    jsonb_build_object(
      'enabled', locked_provider.enabled,
      'archived', false,
      'version', locked_provider.version
    ),
    jsonb_build_object(
      'enabled', false,
      'archived', true,
      'version', next_version
    ),
    jsonb_build_object('reason', p_reason)
  );

  RETURN next_version;
END;
$function$;--> statement-breakpoint

ALTER FUNCTION app.list_tenant_ldap_providers_v1(uuid, boolean, integer) OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.get_tenant_ldap_provider_v1(uuid) OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.create_tenant_ldap_provider_v1(uuid, bytea, text, text, text, jsonb, jsonb, uuid, uuid, inet, text, text) OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.update_tenant_ldap_provider_v1(uuid, integer, text, text, text, boolean, jsonb, jsonb, uuid, uuid, inet, text, text) OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.get_tenant_ldap_bind_secret_id_v1(uuid) OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.get_tenant_ldap_bind_secret_envelope_v1(uuid) OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.rotate_tenant_ldap_bind_secret_v1(uuid, integer, uuid, bytea, bytea, integer, uuid, uuid, inet, text, text) OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.clear_tenant_ldap_bind_secret_v1(uuid, integer, text, uuid, uuid, inet, text, text) OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.archive_tenant_ldap_provider_v1(uuid, integer, text, uuid, uuid, inet, text, text) OWNER TO periapsis_migrator;--> statement-breakpoint

REVOKE ALL ON FUNCTION app.list_tenant_ldap_providers_v1(uuid, boolean, integer) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.get_tenant_ldap_provider_v1(uuid) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.create_tenant_ldap_provider_v1(uuid, bytea, text, text, text, jsonb, jsonb, uuid, uuid, inet, text, text) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.update_tenant_ldap_provider_v1(uuid, integer, text, text, text, boolean, jsonb, jsonb, uuid, uuid, inet, text, text) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.get_tenant_ldap_bind_secret_id_v1(uuid) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.get_tenant_ldap_bind_secret_envelope_v1(uuid) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.rotate_tenant_ldap_bind_secret_v1(uuid, integer, uuid, bytea, bytea, integer, uuid, uuid, inet, text, text) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.clear_tenant_ldap_bind_secret_v1(uuid, integer, text, uuid, uuid, inet, text, text) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.archive_tenant_ldap_provider_v1(uuid, integer, text, uuid, uuid, inet, text, text) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint

GRANT EXECUTE ON FUNCTION app.list_tenant_ldap_providers_v1(uuid, boolean, integer) TO periapsis_api;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.get_tenant_ldap_provider_v1(uuid) TO periapsis_api;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.create_tenant_ldap_provider_v1(uuid, bytea, text, text, text, jsonb, jsonb, uuid, uuid, inet, text, text) TO periapsis_api;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.update_tenant_ldap_provider_v1(uuid, integer, text, text, text, boolean, jsonb, jsonb, uuid, uuid, inet, text, text) TO periapsis_api;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.get_tenant_ldap_bind_secret_id_v1(uuid) TO periapsis_api;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.get_tenant_ldap_bind_secret_envelope_v1(uuid) TO periapsis_api;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.rotate_tenant_ldap_bind_secret_v1(uuid, integer, uuid, bytea, bytea, integer, uuid, uuid, inet, text, text) TO periapsis_api;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.clear_tenant_ldap_bind_secret_v1(uuid, integer, text, uuid, uuid, inet, text, text) TO periapsis_api;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.archive_tenant_ldap_provider_v1(uuid, integer, text, uuid, uuid, inet, text, text) TO periapsis_api;
