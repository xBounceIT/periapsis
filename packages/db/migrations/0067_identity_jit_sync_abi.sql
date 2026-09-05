CREATE FUNCTION app.private_append_tenant_ldap_runtime_audit_v1(
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

CREATE FUNCTION app.apply_tenant_ldap_identity_plan_v1(
  p_application_id uuid,
  p_plan_digest bytea,
  p_apply_mode public.ldap_identity_apply_mode,
  p_sync_run_id uuid,
  p_sync_observation_id uuid,
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
  context_tenant uuid := app.context_tenant_id();
  existing_application public.tenant_ldap_identity_plan_applications%ROWTYPE;
  locked_binding public.tenant_auth_provider_bindings%ROWTYPE;
  locked_provider public.tenant_auth_providers%ROWTYPE;
  locked_config public.tenant_ldap_provider_configs%ROWTYPE;
  locked_sync_run public.tenant_ldap_sync_runs%ROWTYPE;
  current_authorization_revision bigint;
  access_source_id uuid;
  found_external_identity_id uuid;
  found_user_id uuid;
  found_identity_count integer;
  effective_external_identity_id uuid;
  effective_user_id uuid;
  effective_membership_id uuid;
  effective_access_grant_id uuid;
  membership_was_created boolean := false;
  existing_membership record;
  existing_access_grant public.tenant_ldap_provider_access_grants%ROWTYPE;
  selected_epoch record;
  alias_index integer;
  alias_count integer;
  selected_epoch_count integer;
  changed_count integer;
  ensured_count integer := 0;
  revoked_count integer := 0;
BEGIN
  IF p_plan_digest IS NULL OR octet_length(p_plan_digest) <> 32
     OR p_observed_at IS NULL
     OR p_observed_at > transaction_timestamp() + interval '5 minutes'
     OR p_observed_at < transaction_timestamp() - interval '24 hours'
     OR p_apply_mode IS NULL OR p_decision IS NULL
     OR p_user_agent IS NULL OR length(p_user_agent) NOT BETWEEN 1 AND 1024
     OR p_matched_mapping_epoch_ids IS NULL
     OR cardinality(p_matched_mapping_epoch_ids) > 1000
     OR EXISTS (
       SELECT 1 FROM unnest(p_matched_mapping_epoch_ids) AS item(id)
       WHERE item.id IS NULL
     ) OR cardinality(p_matched_mapping_epoch_ids) IS DISTINCT FROM (
       SELECT count(DISTINCT item.id)::integer
       FROM unnest(p_matched_mapping_epoch_ids) AS item(id)
     ) THEN
    RAISE EXCEPTION 'LDAP identity plan input is invalid'
      USING ERRCODE = '22023';
  END IF;

  SELECT application.* INTO existing_application
  FROM public.tenant_ldap_identity_plan_applications AS application
  WHERE application.tenant_id = context_tenant
    AND application.id = p_application_id
  FOR UPDATE;
  IF FOUND THEN
    IF existing_application.plan_digest IS DISTINCT FROM p_plan_digest
       OR existing_application.binding_id IS DISTINCT FROM p_binding_id
       OR existing_application.apply_mode IS DISTINCT FROM p_apply_mode
       OR existing_application.decision IS DISTINCT FROM p_decision THEN
      RAISE EXCEPTION 'LDAP identity plan application replay differs'
        USING ERRCODE = '23505',
              CONSTRAINT = 'tenant_ldap_identity_plan_applications_tenant_id_key';
    END IF;
    RETURN QUERY SELECT
      existing_application.id, existing_application.decision,
      existing_application.external_identity_id,
      existing_application.user_id, existing_application.membership_id,
      existing_application.access_grant_id,
      existing_application.ensured_edge_count,
      existing_application.revoked_edge_count, true;
    RETURN;
  END IF;

  SELECT binding.* INTO locked_binding
  FROM public.tenant_auth_provider_bindings AS binding
  WHERE binding.tenant_id = context_tenant AND binding.id = p_binding_id
  FOR UPDATE;
  IF NOT FOUND OR NOT locked_binding.enabled
     OR locked_binding.archived_at IS NOT NULL
     OR locked_binding.version IS DISTINCT FROM p_binding_version
     OR locked_binding.auth_revision IS DISTINCT FROM p_binding_auth_revision
     OR locked_binding.mapping_revision IS DISTINCT FROM p_rule_set_revision
     OR locked_binding.current_access_epoch_id IS DISTINCT FROM p_access_epoch_id THEN
    RAISE EXCEPTION 'LDAP identity plan binding pins are stale'
      USING ERRCODE = '40001';
  END IF;

  SELECT provider.* INTO locked_provider
  FROM public.tenant_auth_providers AS provider
  JOIN public.tenants AS tenant ON tenant.id = provider.tenant_id
  WHERE provider.tenant_id = context_tenant
    AND provider.id = locked_binding.provider_id
    AND provider.kind = 'ldap'
    AND provider.enabled AND provider.archived_at IS NULL
    AND tenant.status = 'active'
  FOR UPDATE OF provider;
  IF NOT FOUND OR locked_provider.version IS DISTINCT FROM p_provider_version THEN
    RAISE EXCEPTION 'LDAP identity plan provider pins are stale'
      USING ERRCODE = '40001';
  END IF;

  SELECT config.* INTO locked_config
  FROM public.tenant_ldap_provider_configs AS config
  WHERE config.tenant_id = context_tenant
    AND config.provider_id = locked_provider.id
  FOR UPDATE;
  IF NOT FOUND OR locked_config.version IS DISTINCT FROM p_configuration_version THEN
    RAISE EXCEPTION 'LDAP identity plan configuration pins are stale'
      USING ERRCODE = '40001';
  END IF;

  SELECT epoch.source_id INTO access_source_id
  FROM public.tenant_identity_provider_access_epochs AS epoch
  JOIN public.tenant_authorization_sources AS source
    ON source.tenant_id = epoch.tenant_id AND source.id = epoch.source_id
  WHERE epoch.tenant_id = context_tenant
    AND epoch.id = p_access_epoch_id
    AND epoch.binding_id = p_binding_id
    AND epoch.provider_id = locked_provider.id
    AND epoch.ended_at IS NULL
    AND source.kind = 'identity_provider_access'
    AND source.retired_at IS NULL
  FOR UPDATE OF epoch, source;
  IF access_source_id IS NULL THEN
    RAISE EXCEPTION 'LDAP identity plan access source is stale'
      USING ERRCODE = '40001';
  END IF;

  SELECT state.revision INTO current_authorization_revision
  FROM public.tenant_authorization_states AS state
  WHERE state.tenant_id = context_tenant AND state.initialized_at IS NOT NULL
  FOR UPDATE;
  IF current_authorization_revision IS NULL THEN
    RAISE EXCEPTION 'initialized tenant authorization state is required'
      USING ERRCODE = '42501';
  END IF;

  IF p_apply_mode = 'jit' THEN
    IF p_sync_run_id IS NOT NULL OR p_sync_observation_id IS NOT NULL
       OR current_authorization_revision IS DISTINCT FROM p_authorization_revision THEN
      RAISE EXCEPTION 'LDAP JIT plan authorization pins are stale'
        USING ERRCODE = '40001';
    END IF;
  ELSE
    SELECT run.* INTO locked_sync_run
    FROM public.tenant_ldap_sync_runs AS run
    WHERE run.tenant_id = context_tenant AND run.id = p_sync_run_id
    FOR UPDATE;
    IF NOT FOUND OR locked_sync_run.status <> 'applying'
       OR locked_sync_run.binding_id IS DISTINCT FROM p_binding_id
       OR locked_sync_run.provider_id IS DISTINCT FROM locked_provider.id
       OR locked_sync_run.provider_version IS DISTINCT FROM p_provider_version
       OR locked_sync_run.configuration_version IS DISTINCT FROM p_configuration_version
       OR locked_sync_run.binding_version IS DISTINCT FROM p_binding_version
       OR locked_sync_run.binding_auth_revision IS DISTINCT FROM p_binding_auth_revision
       OR locked_sync_run.binding_access_epoch_id IS DISTINCT FROM p_access_epoch_id
       OR locked_sync_run.rule_set_revision IS DISTINCT FROM p_rule_set_revision
       OR locked_sync_run.authorization_revision IS DISTINCT FROM p_authorization_revision
       OR locked_sync_run.authorization_progress_revision IS DISTINCT FROM
          current_authorization_revision
       OR NOT EXISTS (
         SELECT 1
         FROM public.tenant_ldap_sync_staged_observations AS observation
         WHERE observation.tenant_id = context_tenant
           AND observation.sync_run_id = p_sync_run_id
           AND observation.id = p_sync_observation_id
           AND observation.observation_digest = p_plan_digest
           AND observation.applied_at IS NULL
       ) THEN
      RAISE EXCEPTION 'LDAP sync plan pins are stale or already consumed'
        USING ERRCODE = '40001';
    END IF;
  END IF;

  IF p_apply_mode = 'sync' THEN
    SELECT count(*)::integer INTO selected_epoch_count
    FROM public.tenant_ldap_sync_run_mappings AS pinned
    WHERE pinned.tenant_id = context_tenant
      AND pinned.sync_run_id = p_sync_run_id
      AND pinned.source_epoch_id = ANY(p_matched_mapping_epoch_ids);
  ELSE
    SELECT count(*)::integer INTO selected_epoch_count
    FROM public.tenant_ldap_mapping_rule_epochs AS epoch
    JOIN public.tenant_ldap_mapping_rules AS rule
      ON rule.tenant_id = epoch.tenant_id
     AND rule.id = epoch.mapping_rule_id
     AND rule.binding_id = epoch.binding_id
     AND rule.current_source_epoch_id = epoch.id
    JOIN public.tenant_authorization_sources AS source
      ON source.tenant_id = epoch.tenant_id AND source.id = epoch.source_id
    WHERE epoch.tenant_id = context_tenant
      AND epoch.binding_id = p_binding_id
      AND epoch.id = ANY(p_matched_mapping_epoch_ids)
      AND epoch.ended_at IS NULL AND rule.enabled
      AND rule.archived_at IS NULL
      AND source.kind = 'identity_mapping' AND source.retired_at IS NULL;
  END IF;
  IF selected_epoch_count IS DISTINCT FROM cardinality(p_matched_mapping_epoch_ids)
     OR EXISTS (
       SELECT 1
       FROM public.tenant_ldap_mapping_rule_epochs AS epoch
       JOIN public.tenant_ldap_mapping_rule_role_targets AS target
         ON target.tenant_id = epoch.tenant_id
        AND target.mapping_rule_id = epoch.mapping_rule_id
        AND target.configuration_revision = epoch.configuration_revision
       JOIN public.tenant_roles AS role
         ON role.tenant_id = target.tenant_id AND role.id = target.role_id
       LEFT JOIN public.tenant_role_permissions AS policy
         ON policy.tenant_id = role.tenant_id AND policy.role_id = role.id
        AND policy.scope = 'platform'
       WHERE epoch.tenant_id = context_tenant
         AND epoch.id = ANY(p_matched_mapping_epoch_ids)
         AND (role.principal_kind <> 'human' OR role.archived_at IS NOT NULL
           OR role.key = 'platform_super_admin' OR policy.role_id IS NOT NULL)
     ) OR EXISTS (
       SELECT 1
       FROM public.tenant_ldap_mapping_rule_epochs AS epoch
       JOIN public.tenant_security_group_role_grants AS group_grant
         ON group_grant.tenant_id = epoch.tenant_id
        AND group_grant.group_id = epoch.tenant_security_group_id
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
       LEFT JOIN public.tenant_role_permissions AS policy
         ON policy.tenant_id = role.tenant_id AND policy.role_id = role.id
        AND policy.scope = 'platform'
       WHERE epoch.tenant_id = context_tenant
         AND epoch.id = ANY(p_matched_mapping_epoch_ids)
         AND (role.principal_kind <> 'human' OR role.archived_at IS NOT NULL
           OR role.key = 'platform_super_admin' OR policy.role_id IS NOT NULL)
     ) THEN
    RAISE EXCEPTION 'LDAP identity plan contains a stale or forbidden mapping target'
      USING ERRCODE = '42501';
  END IF;

  IF p_decision = 'denied' THEN
    IF p_denial_category IS NULL OR p_denial_category !~ '^[a-z][a-z0-9_]{1,63}$'
       OR p_external_identity_id IS NOT NULL OR p_user_id IS NOT NULL
       OR p_membership_id IS NOT NULL OR p_access_grant_id IS NOT NULL
       OR p_profile_contribution_id IS NOT NULL OR p_subject_format IS NOT NULL
       OR p_subject_ciphertext IS NOT NULL OR p_subject_nonce IS NOT NULL
       OR p_subject_key_version IS NOT NULL
       OR cardinality(coalesce(p_alias_ids, ARRAY[]::uuid[])) <> 0
       OR cardinality(coalesce(p_alias_key_versions, ARRAY[]::integer[])) <> 0
       OR cardinality(coalesce(p_alias_digests, ARRAY[]::bytea[])) <> 0
       OR p_display_name IS NOT NULL OR p_first_name IS NOT NULL
       OR p_last_name IS NOT NULL OR p_username IS NOT NULL OR p_email IS NOT NULL
       OR cardinality(p_matched_mapping_epoch_ids) <> 0 THEN
      RAISE EXCEPTION 'denied LDAP plan must not carry identity or access material'
        USING ERRCODE = '22023';
    END IF;
    IF p_apply_mode = 'sync' THEN
      UPDATE public.tenant_ldap_sync_staged_observations AS observation
      SET applied_at = transaction_timestamp(), apply_attempt = apply_attempt + 1
      WHERE observation.tenant_id = context_tenant
        AND observation.sync_run_id = p_sync_run_id
        AND observation.id = p_sync_observation_id;
      UPDATE public.tenant_ldap_sync_runs AS run
      SET applied_count = run.applied_count + 1
      WHERE run.tenant_id = context_tenant AND run.id = p_sync_run_id;
    END IF;
    INSERT INTO public.tenant_ldap_identity_plan_applications (
      id, tenant_id, plan_digest, apply_mode, decision, denial_category,
      provider_id, binding_id, sync_run_id, sync_observation_id,
      provider_version, configuration_version, binding_version,
      binding_auth_revision, binding_access_epoch_id, rule_set_revision,
      authorization_revision, audit_event_id, request_id, correlation_id,
      observed_at
    ) VALUES (
      p_application_id, context_tenant, p_plan_digest, p_apply_mode,
      p_decision, p_denial_category, locked_provider.id, p_binding_id,
      p_sync_run_id, p_sync_observation_id, p_provider_version,
      p_configuration_version, p_binding_version, p_binding_auth_revision,
      p_access_epoch_id, p_rule_set_revision, p_authorization_revision,
      p_audit_event_id, p_request_id, p_correlation_id, p_observed_at
    );
    PERFORM app.private_append_tenant_ldap_runtime_audit_v1(
      p_audit_event_id, context_tenant, 'tenant.identity.ldap_plan_denied',
      'ldap_identity_plan_application', p_application_id, p_request_id,
      p_correlation_id, p_ip_address, p_user_agent,
      CASE WHEN p_apply_mode = 'jit' THEN 'ldap' ELSE 'ldap_sync' END,
      'denied', p_denial_category,
      jsonb_build_object(
        'application_id', p_application_id, 'binding_id', p_binding_id,
        'provider_id', locked_provider.id, 'mode', p_apply_mode,
        'configuration_version', p_configuration_version,
        'rule_set_revision', p_rule_set_revision,
        'authorization_revision', p_authorization_revision
      )
    );
    RETURN QUERY SELECT p_application_id, p_decision,
      NULL::uuid, NULL::uuid, NULL::uuid, NULL::uuid, 0, 0, false;
    RETURN;
  END IF;

  alias_count := coalesce(cardinality(p_alias_ids), 0);
  IF p_denial_category IS NOT NULL
     OR p_external_identity_id IS NULL OR p_user_id IS NULL
     OR p_membership_id IS NULL OR p_access_grant_id IS NULL
     OR p_profile_contribution_id IS NULL OR p_subject_format IS NULL
     OR p_subject_ciphertext IS NULL
     OR octet_length(p_subject_ciphertext) NOT BETWEEN 17 AND 4112
     OR p_subject_nonce IS NULL OR octet_length(p_subject_nonce) <> 12
     OR p_subject_key_version IS NULL
     OR p_display_name IS NULL OR btrim(p_display_name) = ''
     OR char_length(p_display_name) > 160 OR p_display_name ~ '[[:cntrl:]]'
     OR alias_count NOT BETWEEN 1 AND 16
     OR cardinality(p_alias_key_versions) IS DISTINCT FROM alias_count
     OR cardinality(p_alias_digests) IS DISTINCT FROM alias_count
     OR EXISTS (
       SELECT 1
       FROM unnest(p_alias_ids, p_alias_key_versions, p_alias_digests)
         AS alias(id, key_version, digest)
       WHERE alias.id IS NULL OR alias.key_version IS NULL
         OR alias.key_version NOT BETWEEN 1 AND 32767
         OR alias.digest IS NULL OR octet_length(alias.digest) <> 32
     ) OR alias_count IS DISTINCT FROM (
       SELECT count(DISTINCT (alias.key_version, alias.digest))::integer
       FROM unnest(p_alias_key_versions, p_alias_digests)
         AS alias(key_version, digest)
     ) OR NOT EXISTS (
       SELECT 1 FROM public.identity_keyring_versions AS keyring
       WHERE keyring.key_version = p_subject_key_version
         AND keyring.is_active AND keyring.retired_at IS NULL
     ) OR NOT EXISTS (
       SELECT 1
       FROM unnest(p_alias_key_versions) AS alias(key_version)
       JOIN public.identity_keyring_versions AS keyring
         ON keyring.key_version = alias.key_version
       WHERE keyring.is_active AND keyring.retired_at IS NULL
     ) THEN
    RAISE EXCEPTION 'admitted LDAP plan identity material is invalid'
      USING ERRCODE = '22023';
  END IF;

  SELECT count(DISTINCT alias.external_identity_id)::integer,
         (array_agg(DISTINCT alias.external_identity_id))[1]
  INTO found_identity_count, found_external_identity_id
  FROM public.tenant_ldap_external_identity_subject_aliases AS alias
  JOIN unnest(p_alias_key_versions, p_alias_digests)
    AS supplied(key_version, digest)
    ON supplied.key_version = alias.digest_key_version
   AND supplied.digest = alias.subject_digest
  WHERE alias.tenant_id = context_tenant
    AND alias.provider_id = locked_provider.id
    AND alias.retired_at IS NULL;
  IF found_identity_count > 1 THEN
    RAISE EXCEPTION 'LDAP immutable subject aliases are ambiguous'
      USING ERRCODE = '23505';
  END IF;
  IF found_external_identity_id IS NOT NULL THEN
    SELECT identity.user_id INTO found_user_id
    FROM public.tenant_ldap_external_identities AS identity
    WHERE identity.tenant_id = context_tenant
      AND identity.provider_id = locked_provider.id
      AND identity.id = found_external_identity_id
      AND identity.retired_at IS NULL
    FOR UPDATE;
    IF found_external_identity_id IS DISTINCT FROM p_external_identity_id
       OR found_user_id IS DISTINCT FROM p_user_id THEN
      RAISE EXCEPTION 'LDAP immutable subject is linked to another identity'
        USING ERRCODE = '23505';
    END IF;
    effective_external_identity_id := found_external_identity_id;
    effective_user_id := found_user_id;
  ELSE
    IF locked_config.jit_mode <> 'create' THEN
      RAISE EXCEPTION 'LDAP JIT identity creation is not enabled'
        USING ERRCODE = '42501';
    END IF;
    INSERT INTO public.users (
      id, email, display_name, first_name, last_name
    ) VALUES (
      p_user_id, NULL, p_display_name, p_first_name, p_last_name
    );
    INSERT INTO public.tenant_ldap_external_identities (
      id, tenant_id, provider_id, user_id, subject_format,
      subject_ciphertext, subject_nonce, key_version,
      admitted_configuration_version, admitted_at, last_observed_at,
      updated_at
    ) VALUES (
      p_external_identity_id, context_tenant, locked_provider.id, p_user_id,
      p_subject_format, p_subject_ciphertext, p_subject_nonce,
      p_subject_key_version, p_configuration_version, p_observed_at,
      p_observed_at, transaction_timestamp()
    );
    effective_external_identity_id := p_external_identity_id;
    effective_user_id := p_user_id;
  END IF;

  IF found_external_identity_id IS NOT NULL THEN
    UPDATE public.tenant_ldap_external_identities AS identity
    SET subject_ciphertext = p_subject_ciphertext,
        subject_nonce = p_subject_nonce,
        key_version = p_subject_key_version,
        last_observed_at = greatest(identity.last_observed_at, p_observed_at),
        version = identity.version + 1,
        updated_at = transaction_timestamp()
    WHERE identity.tenant_id = context_tenant
      AND identity.id = effective_external_identity_id
      AND identity.subject_format = p_subject_format;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'LDAP immutable subject format cannot change'
        USING ERRCODE = '23514';
    END IF;
  END IF;

  FOR alias_index IN 1..alias_count LOOP
    IF EXISTS (
      SELECT 1 FROM public.identity_keyring_versions AS keyring
      WHERE keyring.key_version = p_alias_key_versions[alias_index]
        AND keyring.is_active AND keyring.retired_at IS NULL
    ) THEN
      INSERT INTO public.tenant_ldap_external_identity_subject_aliases (
        id, tenant_id, provider_id, external_identity_id,
        digest_key_version, subject_digest
      ) VALUES (
        p_alias_ids[alias_index], context_tenant, locked_provider.id,
        effective_external_identity_id, p_alias_key_versions[alias_index],
        p_alias_digests[alias_index]
      ) ON CONFLICT (
        tenant_id, provider_id, digest_key_version, subject_digest
      ) WHERE retired_at IS NULL DO NOTHING;
    END IF;
  END LOOP;

  SELECT membership.id, membership.status
  INTO existing_membership
  FROM public.tenant_memberships AS membership
  JOIN public.users AS identity ON identity.id = membership.user_id
  WHERE membership.tenant_id = context_tenant
    AND membership.user_id = effective_user_id
    AND identity.active
  FOR UPDATE OF membership, identity;
  IF FOUND THEN
    IF existing_membership.id IS DISTINCT FROM p_membership_id
       OR existing_membership.status <> 'active' THEN
      RAISE EXCEPTION 'LDAP tenant membership is inactive or mismatched'
        USING ERRCODE = '42501';
    END IF;
    effective_membership_id := existing_membership.id;
  ELSE
    IF EXISTS (SELECT 1 FROM public.users WHERE id = effective_user_id AND NOT active) THEN
      RAISE EXCEPTION 'LDAP user is inactive' USING ERRCODE = '42501';
    END IF;
    INSERT INTO public.tenant_memberships (
      id, tenant_id, user_id, role, status
    ) VALUES (
      p_membership_id, context_tenant, effective_user_id,
      'read_only', 'active'
    );
    effective_membership_id := p_membership_id;
    membership_was_created := true;
  END IF;

  SELECT grant_row.* INTO existing_access_grant
  FROM public.tenant_ldap_provider_access_grants AS grant_row
  WHERE grant_row.tenant_id = context_tenant
    AND grant_row.binding_id = p_binding_id
    AND grant_row.membership_id = effective_membership_id
    AND grant_row.ended_at IS NULL
  FOR UPDATE;
  IF FOUND THEN
    IF existing_access_grant.id IS DISTINCT FROM p_access_grant_id
       OR existing_access_grant.external_identity_id IS DISTINCT FROM
          effective_external_identity_id
       OR existing_access_grant.access_epoch_id IS DISTINCT FROM p_access_epoch_id
       OR existing_access_grant.source_id IS DISTINCT FROM access_source_id THEN
      RAISE EXCEPTION 'LDAP provider access grant is linked to another source'
        USING ERRCODE = '23505';
    END IF;
    UPDATE public.tenant_ldap_provider_access_grants AS grant_row
    SET configuration_version = p_configuration_version,
        last_observed_at = greatest(grant_row.last_observed_at, p_observed_at),
        version = grant_row.version + 1,
        updated_at = transaction_timestamp()
    WHERE grant_row.tenant_id = context_tenant
      AND grant_row.id = existing_access_grant.id;
    effective_access_grant_id := existing_access_grant.id;
  ELSE
    INSERT INTO public.tenant_ldap_provider_access_grants (
      id, tenant_id, provider_id, binding_id, access_epoch_id, source_id,
      external_identity_id, membership_id, user_id, configuration_version,
      owns_membership, started_at, last_observed_at, updated_at
    ) VALUES (
      p_access_grant_id, context_tenant, locked_provider.id, p_binding_id,
      p_access_epoch_id, access_source_id, effective_external_identity_id,
      effective_membership_id, effective_user_id, p_configuration_version,
      membership_was_created, p_observed_at, p_observed_at,
      transaction_timestamp()
    );
    effective_access_grant_id := p_access_grant_id;
  END IF;

  UPDATE public.tenant_ldap_provider_profile_contributions AS contribution
  SET retired_at = transaction_timestamp(), retire_reason = 'superseded_observation',
      version = contribution.version + 1, updated_at = transaction_timestamp()
  WHERE contribution.tenant_id = context_tenant
    AND contribution.access_grant_id = effective_access_grant_id
    AND contribution.retired_at IS NULL;
  INSERT INTO public.tenant_ldap_provider_profile_contributions (
    id, tenant_id, access_grant_id, display_name, first_name, last_name,
    username, email, configuration_version, observed_at, updated_at
  ) VALUES (
    p_profile_contribution_id, context_tenant, effective_access_grant_id,
    p_display_name, p_first_name, p_last_name, p_username, p_email,
    p_configuration_version, p_observed_at, transaction_timestamp()
  );

  FOR selected_epoch IN
    SELECT epoch.*
    FROM public.tenant_ldap_mapping_rule_epochs AS epoch
    WHERE epoch.tenant_id = context_tenant
      AND epoch.id = ANY(p_matched_mapping_epoch_ids)
    ORDER BY epoch.priority, epoch.id
  LOOP
    INSERT INTO public.tenant_security_group_memberships (
      id, tenant_id, group_id, membership_id, source_id,
      granted_by_membership_id, grant_reason
    ) VALUES (
      uuidv7(), context_tenant, selected_epoch.tenant_security_group_id,
      effective_membership_id, selected_epoch.source_id, NULL,
      'identity_mapping_observation'
    ) ON CONFLICT DO NOTHING;
    GET DIAGNOSTICS changed_count = ROW_COUNT;
    ensured_count := ensured_count + changed_count;

    INSERT INTO public.tenant_security_group_role_grants (
      id, tenant_id, group_id, role_id, source_id,
      granted_by_membership_id, grant_reason
    )
    SELECT uuidv7(), context_tenant,
           selected_epoch.tenant_security_group_id, target.role_id,
           selected_epoch.source_id, NULL, 'identity_mapping_target'
    FROM public.tenant_ldap_mapping_rule_role_targets AS target
    JOIN public.tenant_roles AS role
      ON role.tenant_id = target.tenant_id AND role.id = target.role_id
    WHERE target.tenant_id = context_tenant
      AND target.mapping_rule_id = selected_epoch.mapping_rule_id
      AND target.configuration_revision = selected_epoch.configuration_revision
      AND role.principal_kind = 'human' AND role.archived_at IS NULL
      AND role.key <> 'platform_super_admin'
    ON CONFLICT DO NOTHING;
    GET DIAGNOSTICS changed_count = ROW_COUNT;
    ensured_count := ensured_count + changed_count;

    IF selected_epoch.operator_team_assignment_epoch_id IS NOT NULL THEN
      INSERT INTO public.operator_team_roster_entries (
        id, tenant_id, assignment_epoch_id, membership_id, source_id,
        granted_by_membership_id, grant_reason
      )
      SELECT uuidv7(), context_tenant,
             selected_epoch.operator_team_assignment_epoch_id,
             effective_membership_id, selected_epoch.source_id, NULL,
             'identity_mapping_observation'
      FROM public.operator_team_assignment_epochs AS assignment
      JOIN public.operator_teams AS team
        ON team.id = assignment.operator_team_id
      WHERE assignment.tenant_id = context_tenant
        AND assignment.id = selected_epoch.operator_team_assignment_epoch_id
        AND assignment.operator_team_id = selected_epoch.operator_team_id
        AND assignment.ended_at IS NULL AND team.archived_at IS NULL
      ON CONFLICT DO NOTHING;
      GET DIAGNOSTICS changed_count = ROW_COUNT;
      IF changed_count <> 1 AND NOT EXISTS (
        SELECT 1 FROM public.operator_team_roster_entries AS roster
        WHERE roster.tenant_id = context_tenant
          AND roster.assignment_epoch_id =
              selected_epoch.operator_team_assignment_epoch_id
          AND roster.membership_id = effective_membership_id
          AND roster.source_id = selected_epoch.source_id
          AND roster.revoked_at IS NULL
      ) THEN
        RAISE EXCEPTION 'LDAP mapping operator-team epoch is not live'
          USING ERRCODE = '40001';
      END IF;
      ensured_count := ensured_count + changed_count;
    END IF;
  END LOOP;

  WITH eligible AS (
    SELECT epoch.source_id, epoch.activated_by_membership_id
    FROM public.tenant_ldap_mapping_rule_epochs AS epoch
    JOIN public.tenant_ldap_mapping_rules AS rule
      ON rule.tenant_id = epoch.tenant_id AND rule.id = epoch.mapping_rule_id
    WHERE epoch.tenant_id = context_tenant
      AND epoch.binding_id = p_binding_id
      AND epoch.reconciliation_mode = 'authoritative'
      AND epoch.ended_at IS NULL
      AND epoch.id <> ALL(p_matched_mapping_epoch_ids)
      AND (
        (p_apply_mode = 'jit' AND rule.current_source_epoch_id = epoch.id
          AND rule.enabled AND rule.archived_at IS NULL)
        OR (p_apply_mode = 'sync' AND EXISTS (
          SELECT 1 FROM public.tenant_ldap_sync_run_mappings AS pinned
          WHERE pinned.tenant_id = context_tenant
            AND pinned.sync_run_id = p_sync_run_id
            AND pinned.source_epoch_id = epoch.id
        ))
      )
  )
  UPDATE public.tenant_security_group_memberships AS member
  SET revoked_at = transaction_timestamp(),
      revoked_by_membership_id = eligible.activated_by_membership_id,
      revoke_reason = 'identity_mapping_authoritative_absence',
      version = member.version + 1, updated_at = transaction_timestamp()
  FROM eligible
  WHERE member.tenant_id = context_tenant
    AND member.membership_id = effective_membership_id
    AND member.source_id = eligible.source_id
    AND member.revoked_at IS NULL;
  GET DIAGNOSTICS changed_count = ROW_COUNT;
  revoked_count := revoked_count + changed_count;

  WITH eligible AS (
    SELECT epoch.source_id, epoch.activated_by_membership_id
    FROM public.tenant_ldap_mapping_rule_epochs AS epoch
    JOIN public.tenant_ldap_mapping_rules AS rule
      ON rule.tenant_id = epoch.tenant_id AND rule.id = epoch.mapping_rule_id
    WHERE epoch.tenant_id = context_tenant
      AND epoch.binding_id = p_binding_id
      AND epoch.reconciliation_mode = 'authoritative'
      AND epoch.ended_at IS NULL
      AND epoch.id <> ALL(p_matched_mapping_epoch_ids)
      AND (
        (p_apply_mode = 'jit' AND rule.current_source_epoch_id = epoch.id
          AND rule.enabled AND rule.archived_at IS NULL)
        OR (p_apply_mode = 'sync' AND EXISTS (
          SELECT 1 FROM public.tenant_ldap_sync_run_mappings AS pinned
          WHERE pinned.tenant_id = context_tenant
            AND pinned.sync_run_id = p_sync_run_id
            AND pinned.source_epoch_id = epoch.id
        ))
      )
  )
  UPDATE public.operator_team_roster_entries AS roster
  SET revoked_at = transaction_timestamp(),
      revoked_by_membership_id = eligible.activated_by_membership_id,
      revoke_reason = 'identity_mapping_authoritative_absence',
      version = roster.version + 1, updated_at = transaction_timestamp()
  FROM eligible
  WHERE roster.tenant_id = context_tenant
    AND roster.membership_id = effective_membership_id
    AND roster.source_id = eligible.source_id
    AND roster.revoked_at IS NULL;
  GET DIAGNOSTICS changed_count = ROW_COUNT;
  revoked_count := revoked_count + changed_count;

  PERFORM app.private_materialize_tenant_user_profile_v1(
    context_tenant, effective_membership_id
  );

  IF p_apply_mode = 'sync' THEN
    UPDATE public.tenant_ldap_sync_staged_observations AS observation
    SET external_identity_id = effective_external_identity_id,
        applied_at = transaction_timestamp(), apply_attempt = apply_attempt + 1
    WHERE observation.tenant_id = context_tenant
      AND observation.sync_run_id = p_sync_run_id
      AND observation.id = p_sync_observation_id;
    SELECT state.revision INTO current_authorization_revision
    FROM public.tenant_authorization_states AS state
    WHERE state.tenant_id = context_tenant;
    UPDATE public.tenant_ldap_sync_runs AS run
    SET applied_count = run.applied_count + 1,
        authorization_progress_revision = current_authorization_revision
    WHERE run.tenant_id = context_tenant AND run.id = p_sync_run_id;
  END IF;

  INSERT INTO public.tenant_ldap_identity_plan_applications (
    id, tenant_id, plan_digest, apply_mode, decision, provider_id,
    binding_id, sync_run_id, sync_observation_id, provider_version,
    configuration_version, binding_version, binding_auth_revision,
    binding_access_epoch_id, rule_set_revision, authorization_revision,
    external_identity_id, user_id, membership_id, access_grant_id,
    ensured_edge_count, revoked_edge_count, audit_event_id, request_id,
    correlation_id, observed_at
  ) VALUES (
    p_application_id, context_tenant, p_plan_digest, p_apply_mode, p_decision,
    locked_provider.id, p_binding_id, p_sync_run_id, p_sync_observation_id,
    p_provider_version, p_configuration_version, p_binding_version,
    p_binding_auth_revision, p_access_epoch_id, p_rule_set_revision,
    p_authorization_revision, effective_external_identity_id,
    effective_user_id, effective_membership_id, effective_access_grant_id,
    ensured_count, revoked_count, p_audit_event_id, p_request_id,
    p_correlation_id, p_observed_at
  );
  PERFORM app.private_append_tenant_ldap_runtime_audit_v1(
    p_audit_event_id, context_tenant, 'tenant.identity.ldap_plan_applied',
    'ldap_identity_plan_application', p_application_id, p_request_id,
    p_correlation_id, p_ip_address, p_user_agent,
    CASE WHEN p_apply_mode = 'jit' THEN 'ldap' ELSE 'ldap_sync' END,
    'success', NULL,
    jsonb_build_object(
      'application_id', p_application_id, 'binding_id', p_binding_id,
      'provider_id', locked_provider.id, 'mode', p_apply_mode,
      'configuration_version', p_configuration_version,
      'rule_set_revision', p_rule_set_revision,
      'authorization_revision', p_authorization_revision,
      'ensured_edge_count', ensured_count,
      'revoked_edge_count', revoked_count,
      'identity_created', found_external_identity_id IS NULL,
      'membership_created', membership_was_created
    )
  );
  RETURN QUERY SELECT p_application_id, p_decision,
    effective_external_identity_id, effective_user_id,
    effective_membership_id, effective_access_grant_id,
    ensured_count, revoked_count, false;
END;
$function$;--> statement-breakpoint

ALTER FUNCTION app.private_append_tenant_ldap_runtime_audit_v1(uuid, uuid, text, text, uuid, uuid, uuid, inet, text, text, public.audit_outcome, text, jsonb) OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.apply_tenant_ldap_identity_plan_v1(uuid, bytea, public.ldap_identity_apply_mode, uuid, uuid, uuid, integer, integer, integer, integer, uuid, bigint, bigint, public.ldap_identity_apply_decision, text, uuid, uuid, uuid, uuid, uuid, public.identity_subject_format, bytea, bytea, integer, uuid[], integer[], bytea[], text, text, text, text, text, uuid[], timestamptz, uuid, uuid, uuid, inet, text) OWNER TO periapsis_migrator;--> statement-breakpoint

REVOKE ALL ON FUNCTION app.private_append_tenant_ldap_runtime_audit_v1(uuid, uuid, text, text, uuid, uuid, uuid, inet, text, text, public.audit_outcome, text, jsonb) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.apply_tenant_ldap_identity_plan_v1(uuid, bytea, public.ldap_identity_apply_mode, uuid, uuid, uuid, integer, integer, integer, integer, uuid, bigint, bigint, public.ldap_identity_apply_decision, text, uuid, uuid, uuid, uuid, uuid, public.identity_subject_format, bytea, bytea, integer, uuid[], integer[], bytea[], text, text, text, text, text, uuid[], timestamptz, uuid, uuid, uuid, inet, text) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.apply_tenant_ldap_identity_plan_v1(uuid, bytea, public.ldap_identity_apply_mode, uuid, uuid, uuid, integer, integer, integer, integer, uuid, bigint, bigint, public.ldap_identity_apply_decision, text, uuid, uuid, uuid, uuid, uuid, public.identity_subject_format, bytea, bytea, integer, uuid[], integer[], bytea[], text, text, text, text, text, uuid[], timestamptz, uuid, uuid, uuid, inet, text) TO periapsis_api, periapsis_worker;
