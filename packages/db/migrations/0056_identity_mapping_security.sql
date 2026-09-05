-- Custom SQL migration file, put your code below! --
-- Custom SQL migration file, put your code below! --
-- Tenant LDAP mapping authority is a protected database aggregate. Runtime
-- roles receive no table privileges: all reads and mutations use the bounded
-- SECURITY DEFINER ABI below, which rechecks tenant-human authorization.
ALTER TYPE public.ldap_mapping_case_mode OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TYPE public.ldap_mapping_matcher_type OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TYPE public.ldap_mapping_reconciliation_mode OWNER TO periapsis_migrator;--> statement-breakpoint

ALTER TABLE public.tenant_ldap_mapping_rules OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TABLE public.tenant_ldap_mapping_rule_epochs OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TABLE public.tenant_ldap_mapping_rule_role_targets OWNER TO periapsis_migrator;--> statement-breakpoint

ALTER TABLE public.tenant_ldap_mapping_rules FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE public.tenant_ldap_mapping_rule_epochs FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE public.tenant_ldap_mapping_rule_role_targets FORCE ROW LEVEL SECURITY;--> statement-breakpoint

REVOKE ALL ON TABLE public.tenant_ldap_mapping_rules FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON TABLE public.tenant_ldap_mapping_rule_epochs FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON TABLE public.tenant_ldap_mapping_rule_role_targets FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint

-- The current projection may move only through disabled intermediate states.
-- An enabled row must reference its own exact live source epoch and immutable
-- target revision, so neither scalar targets nor role targets are reinterpreted.
CREATE FUNCTION app.guard_tenant_ldap_mapping_rule_v1()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  target_count integer;
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'tenant LDAP mapping rules are archival records'
      USING ERRCODE = '55000';
  END IF;

  IF TG_OP = 'INSERT' THEN
    IF NEW.enabled OR NEW.current_source_epoch_id IS NOT NULL
       OR NEW.archived_at IS NOT NULL OR NEW.configuration_revision <> 1
       OR NEW.version <> 1 THEN
      RAISE EXCEPTION 'new tenant LDAP mapping rule must be disabled version one'
        USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
  END IF;

  IF ROW(NEW.id, NEW.tenant_id, NEW.binding_id,
         NEW.created_by_membership_id, NEW.created_at)
     IS DISTINCT FROM
     ROW(OLD.id, OLD.tenant_id, OLD.binding_id,
         OLD.created_by_membership_id, OLD.created_at) THEN
    RAISE EXCEPTION 'tenant LDAP mapping rule identity is immutable'
      USING ERRCODE = '55000';
  END IF;
  IF OLD.archived_at IS NOT NULL THEN
    RAISE EXCEPTION 'archived tenant LDAP mapping rule is immutable'
      USING ERRCODE = '55000';
  END IF;
  IF OLD.enabled AND ROW(
       NEW.matcher_type, NEW.matcher_value, NEW.case_mode, NEW.priority,
       NEW.tenant_security_group_id, NEW.reconciliation_mode,
       NEW.operator_team_id, NEW.operator_team_assignment_epoch_id,
       NEW.configuration_revision
     ) IS DISTINCT FROM ROW(
       OLD.matcher_type, OLD.matcher_value, OLD.case_mode, OLD.priority,
       OLD.tenant_security_group_id, OLD.reconciliation_mode,
       OLD.operator_team_id, OLD.operator_team_assignment_epoch_id,
       OLD.configuration_revision
     ) THEN
    RAISE EXCEPTION 'detach the live mapping epoch before changing semantics'
      USING ERRCODE = '55000';
  END IF;
  IF NEW.configuration_revision < OLD.configuration_revision
     OR NEW.configuration_revision > OLD.configuration_revision + 1 THEN
    RAISE EXCEPTION 'tenant LDAP mapping configuration revision is invalid'
      USING ERRCODE = '55000';
  END IF;

  IF NEW.enabled THEN
    SELECT count(*) INTO target_count
    FROM public.tenant_ldap_mapping_rule_role_targets AS target
    WHERE target.tenant_id = NEW.tenant_id
      AND target.mapping_rule_id = NEW.id
      AND target.configuration_revision = NEW.configuration_revision;
    IF target_count NOT BETWEEN 1 AND 32 OR NOT EXISTS (
      SELECT 1
      FROM public.tenant_ldap_mapping_rule_epochs AS epoch
      JOIN public.tenant_authorization_sources AS source
        ON source.tenant_id = epoch.tenant_id AND source.id = epoch.source_id
      JOIN public.tenant_auth_provider_bindings AS binding
        ON binding.tenant_id = epoch.tenant_id AND binding.id = epoch.binding_id
      WHERE epoch.tenant_id = NEW.tenant_id
        AND epoch.id = NEW.current_source_epoch_id
        AND epoch.mapping_rule_id = NEW.id
        AND epoch.binding_id = NEW.binding_id
        AND epoch.configuration_revision = NEW.configuration_revision
        AND epoch.matcher_type = NEW.matcher_type
        AND epoch.matcher_value = NEW.matcher_value
        AND epoch.case_mode = NEW.case_mode
        AND epoch.priority = NEW.priority
        AND epoch.tenant_security_group_id = NEW.tenant_security_group_id
        AND epoch.reconciliation_mode = NEW.reconciliation_mode
        AND epoch.operator_team_id IS NOT DISTINCT FROM NEW.operator_team_id
        AND epoch.operator_team_assignment_epoch_id IS NOT DISTINCT FROM NEW.operator_team_assignment_epoch_id
        AND epoch.ended_at IS NULL
        AND source.kind = 'identity_mapping'
        AND source.authoritative = (NEW.reconciliation_mode = 'authoritative')
        AND NOT source.protected AND source.retired_at IS NULL
        AND binding.enabled AND binding.archived_at IS NULL
    ) THEN
      RAISE EXCEPTION 'enabled tenant LDAP mapping has no exact live source epoch'
        USING ERRCODE = '23514',
              CONSTRAINT = 'tenant_ldap_mapping_rules_live_epoch_source_check';
    END IF;
  END IF;
  RETURN NEW;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION app.list_tenant_ldap_mapping_rules_v1(
  p_binding_id uuid,
  p_after_priority integer,
  p_after_id uuid,
  p_include_archived boolean,
  p_limit integer
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
    'identity_mapping.read', 'tenant'
  ) THEN
    RAISE EXCEPTION 'identity_mapping.read tenant scope is required'
      USING ERRCODE = '42501';
  END IF;
  IF p_include_archived IS NULL
     OR p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 200
     OR (p_after_id IS NULL) <> (p_after_priority IS NULL) THEN
    RAISE EXCEPTION 'LDAP mapping page input is invalid'
      USING ERRCODE = '22023';
  END IF;
  RETURN QUERY
  SELECT rule.id, rule.binding_id, rule.matcher_type, rule.matcher_value,
         rule.case_mode, rule.priority, rule.tenant_security_group_id,
         rule.reconciliation_mode, targets.role_ids,
         rule.operator_team_id, rule.operator_team_assignment_epoch_id,
         rule.enabled, rule.current_source_epoch_id, epoch.sequence,
         epoch.activated_at,
         rule.configuration_revision, rule.notes, rule.last_matched_at,
         rule.archived_at, rule.version, rule.created_at, rule.updated_at
  FROM public.tenant_ldap_mapping_rules AS rule
  JOIN LATERAL (
    SELECT array_agg(target.role_id ORDER BY target.role_id)::uuid[] AS role_ids
    FROM public.tenant_ldap_mapping_rule_role_targets AS target
    WHERE target.tenant_id = rule.tenant_id
      AND target.mapping_rule_id = rule.id
      AND target.configuration_revision = rule.configuration_revision
  ) AS targets ON true
  LEFT JOIN public.tenant_ldap_mapping_rule_epochs AS epoch
    ON epoch.tenant_id = rule.tenant_id AND epoch.id = rule.current_source_epoch_id
  WHERE rule.tenant_id = context_tenant
    AND (p_binding_id IS NULL OR rule.binding_id = p_binding_id)
    AND (p_include_archived OR rule.archived_at IS NULL)
    AND (p_after_id IS NULL OR (rule.priority, rule.id) > (p_after_priority, p_after_id))
  ORDER BY rule.priority, rule.id
  LIMIT p_limit;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION app.get_tenant_ldap_mapping_rule_v1(p_mapping_rule_id uuid)
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
    'identity_mapping.read', 'tenant'
  ) THEN
    RAISE EXCEPTION 'identity_mapping.read tenant scope is required'
      USING ERRCODE = '42501';
  END IF;
  RETURN QUERY
  SELECT rule.id, rule.binding_id, rule.matcher_type, rule.matcher_value,
         rule.case_mode, rule.priority, rule.tenant_security_group_id,
         rule.reconciliation_mode, targets.role_ids,
         rule.operator_team_id, rule.operator_team_assignment_epoch_id,
         rule.enabled, rule.current_source_epoch_id, epoch.sequence,
         epoch.activated_at,
         rule.configuration_revision, rule.notes, rule.last_matched_at,
         rule.archived_at, rule.version, rule.created_at, rule.updated_at
  FROM public.tenant_ldap_mapping_rules AS rule
  JOIN LATERAL (
    SELECT array_agg(target.role_id ORDER BY target.role_id)::uuid[] AS role_ids
    FROM public.tenant_ldap_mapping_rule_role_targets AS target
    WHERE target.tenant_id = rule.tenant_id
      AND target.mapping_rule_id = rule.id
      AND target.configuration_revision = rule.configuration_revision
  ) AS targets ON true
  LEFT JOIN public.tenant_ldap_mapping_rule_epochs AS epoch
    ON epoch.tenant_id = rule.tenant_id AND epoch.id = rule.current_source_epoch_id
  WHERE rule.tenant_id = context_tenant AND rule.id = p_mapping_rule_id;
END;
$function$;--> statement-breakpoint

-- Pure relational projection for login, dry-run and sync planners. It never
-- applies authority or writes provenance and is tenant-filtered by DB context.
CREATE FUNCTION app.snapshot_tenant_ldap_mapping_rules_v1(p_binding_id uuid)
RETURNS TABLE (
  tenant_id uuid,
  provider_id uuid,
  binding_id uuid,
  binding_auth_revision integer,
  binding_access_epoch_id uuid,
  mapping_rule_id uuid,
  mapping_rule_version integer,
  configuration_revision integer,
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
  source_epoch_id uuid,
  source_epoch_sequence integer,
  authorization_source_id uuid,
  source_activated_at timestamptz
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
  SELECT rule.tenant_id, binding.provider_id, rule.binding_id,
         binding.auth_revision, binding.current_access_epoch_id,
         rule.id, rule.version, rule.configuration_revision,
         rule.matcher_type, rule.matcher_value, rule.case_mode, rule.priority,
         rule.tenant_security_group_id, rule.reconciliation_mode,
         targets.role_ids, rule.operator_team_id,
         rule.operator_team_assignment_epoch_id, rule.enabled,
         epoch.id, epoch.sequence, epoch.source_id, epoch.activated_at
  FROM public.tenant_ldap_mapping_rules AS rule
  JOIN public.tenant_auth_provider_bindings AS binding
    ON binding.tenant_id = rule.tenant_id AND binding.id = rule.binding_id
  JOIN LATERAL (
    SELECT array_agg(target.role_id ORDER BY target.role_id)::uuid[] AS role_ids
    FROM public.tenant_ldap_mapping_rule_role_targets AS target
    WHERE target.tenant_id = rule.tenant_id
      AND target.mapping_rule_id = rule.id
      AND target.configuration_revision = rule.configuration_revision
  ) AS targets ON true
  LEFT JOIN public.tenant_ldap_mapping_rule_epochs AS epoch
    ON epoch.tenant_id = rule.tenant_id AND epoch.id = rule.current_source_epoch_id
  WHERE rule.tenant_id = app.context_tenant_id()
    AND rule.binding_id = p_binding_id AND rule.archived_at IS NULL
  ORDER BY rule.priority, rule.id
$function$;--> statement-breakpoint

CREATE FUNCTION app.create_tenant_ldap_mapping_rule_v1(
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
RETURNS TABLE (result_resource_id uuid, result_version integer, replayed boolean)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  actor_membership uuid;
  canonical_roles uuid[];
  canonical_request_digest bytea;
  replay record;
  new_rule_id uuid;
BEGIN
  PERFORM app.lock_current_tenant_authorization_state();
  actor_membership := app.current_tenant_membership_id();
  IF NOT app.current_tenant_human_has_exact_permission_v3(
    'identity_mapping.manage', 'tenant'
  ) OR NOT app.current_tenant_human_has_exact_permission_v3(
    'role.grant', 'tenant'
  ) THEN
    RAISE EXCEPTION 'identity_mapping.manage and role.grant tenant scopes are required'
      USING ERRCODE = '42501';
  END IF;
  IF p_idempotency_key_digest IS NULL OR octet_length(p_idempotency_key_digest) <> 32
     OR p_matcher_type IS NULL OR p_matcher_value IS NULL
     OR btrim(p_matcher_value) = '' OR p_matcher_value ~ '[[:cntrl:]]'
     OR (p_matcher_type = 'exact_dn' AND
         (char_length(p_matcher_value) > 2048 OR octet_length(p_matcher_value) > 8192))
     OR (p_matcher_type IN ('exact_cn', 'regex') AND char_length(p_matcher_value) > 512)
     OR p_case_mode IS NULL OR p_priority IS NULL OR p_priority NOT BETWEEN 0 AND 1000000
     OR p_reconciliation_mode IS NULL OR p_notes IS NULL
     OR char_length(p_notes) > 2000 OR p_notes ~ '[[:cntrl:]]'
     OR p_reason IS NULL OR btrim(p_reason) = '' OR char_length(p_reason) > 500
     OR p_reason ~ '[[:cntrl:]]' THEN
    RAISE EXCEPTION 'tenant LDAP mapping create input is invalid'
      USING ERRCODE = '22023';
  END IF;
  PERFORM 1
  FROM public.tenant_auth_provider_bindings AS binding
  JOIN public.tenant_auth_providers AS provider
    ON provider.tenant_id = binding.tenant_id AND provider.id = binding.provider_id
  WHERE binding.tenant_id = context_tenant AND binding.id = p_binding_id
    AND binding.archived_at IS NULL AND provider.kind = 'ldap'
    AND provider.archived_at IS NULL
  FOR KEY SHARE OF binding, provider;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'eligible tenant LDAP provider binding was not found'
      USING ERRCODE = 'P0002';
  END IF;
  canonical_roles := app.private_validate_tenant_ldap_mapping_targets_v1(
    context_tenant, p_security_group_id, p_role_ids,
    p_operator_team_id, p_operator_team_assignment_epoch_id
  );
  SELECT sha256(convert_to(jsonb_build_object(
    'binding_id', p_binding_id, 'matcher_type', p_matcher_type,
    'matcher_value', p_matcher_value, 'case_mode', p_case_mode,
    'priority', p_priority, 'security_group_id', p_security_group_id,
    'reconciliation_mode', p_reconciliation_mode, 'role_ids', canonical_roles,
    'operator_team_id', p_operator_team_id,
    'operator_team_assignment_epoch_id', p_operator_team_assignment_epoch_id,
    'notes', p_notes, 'reason', p_reason
  )::text, 'UTF8')) INTO canonical_request_digest;
  PERFORM pg_advisory_xact_lock(hashtextextended(
    context_tenant::text || actor_membership::text ||
    encode(p_idempotency_key_digest, 'hex'), 0
  ));
  DELETE FROM public.tenant_authorization_commands AS command
  WHERE command.tenant_id = context_tenant
    AND command.actor_membership_id = actor_membership
    AND command.operation = 'identity_mapping.create'
    AND command.key_digest = p_idempotency_key_digest
    AND command.expires_at <= transaction_timestamp();
  SELECT command.request_digest, command.result_resource_id,
         command.result_version
  INTO replay
  FROM public.tenant_authorization_commands AS command
  WHERE command.tenant_id = context_tenant
    AND command.actor_membership_id = actor_membership
    AND command.operation = 'identity_mapping.create'
    AND command.key_digest = p_idempotency_key_digest;
  IF FOUND THEN
    IF replay.request_digest <> canonical_request_digest THEN
      RAISE EXCEPTION 'idempotency key was reused with different mapping input'
        USING ERRCODE = '23505';
    END IF;
    RETURN QUERY SELECT replay.result_resource_id::uuid,
                        replay.result_version::integer, true;
    RETURN;
  END IF;

  new_rule_id := uuidv7();
  INSERT INTO public.tenant_ldap_mapping_rules (
    id, tenant_id, binding_id, matcher_type, matcher_value, case_mode,
    priority, tenant_security_group_id, reconciliation_mode,
    operator_team_id, operator_team_assignment_epoch_id,
    created_by_membership_id, updated_by_membership_id
  ) VALUES (
    new_rule_id, context_tenant, p_binding_id, p_matcher_type, p_matcher_value,
    p_case_mode, p_priority, p_security_group_id, p_reconciliation_mode,
    p_operator_team_id, p_operator_team_assignment_epoch_id,
    actor_membership, actor_membership
  );
  INSERT INTO public.tenant_ldap_mapping_rule_role_targets (
    tenant_id, mapping_rule_id, configuration_revision, role_id
  ) SELECT context_tenant, new_rule_id, 1, role_id
    FROM unnest(canonical_roles) AS role_id;
  INSERT INTO public.tenant_authorization_commands (
    tenant_id, actor_membership_id, operation, key_digest, request_digest,
    result_resource_id, result_version
  ) VALUES (
    context_tenant, actor_membership, 'identity_mapping.create',
    p_idempotency_key_digest, canonical_request_digest, new_rule_id, 1
  );
  PERFORM app.append_tenant_authorization_audit(
    p_audit_event_id, 'tenant.identity_mapping.created', 'identity_mapping',
    new_rule_id, p_request_id, p_correlation_id, p_ip_address, p_user_agent,
    p_authentication_method, NULL,
    jsonb_build_object(
      'binding_id', p_binding_id, 'matcher_type', p_matcher_type,
      'case_mode', p_case_mode, 'priority', p_priority,
      'security_group_id', p_security_group_id,
      'reconciliation_mode', p_reconciliation_mode,
      'role_count', cardinality(canonical_roles),
      'operator_team_id', p_operator_team_id,
      'operator_team_assignment_epoch_id', p_operator_team_assignment_epoch_id,
      'enabled', false, 'configuration_revision', 1, 'version', 1
    ), jsonb_build_object('reason', p_reason)
  );
  RETURN QUERY SELECT new_rule_id, 1, false;
END;
$function$;--> statement-breakpoint

CREATE TRIGGER tenant_ldap_mapping_rules_guard_v1
BEFORE INSERT OR UPDATE OR DELETE ON public.tenant_ldap_mapping_rules
FOR EACH ROW EXECUTE FUNCTION app.guard_tenant_ldap_mapping_rule_v1();--> statement-breakpoint

CREATE FUNCTION app.guard_tenant_ldap_mapping_role_target_v1()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF TG_OP <> 'INSERT' THEN
    RAISE EXCEPTION 'tenant LDAP mapping role targets are append-only'
      USING ERRCODE = '55000';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM public.tenant_ldap_mapping_rules AS rule
    WHERE rule.tenant_id = NEW.tenant_id
      AND rule.id = NEW.mapping_rule_id
      AND rule.configuration_revision = NEW.configuration_revision
      AND NOT rule.enabled AND rule.archived_at IS NULL
  ) THEN
    RAISE EXCEPTION 'mapping role target does not belong to the pending revision'
      USING ERRCODE = '55000';
  END IF;
  RETURN NEW;
END;
$function$;--> statement-breakpoint

CREATE TRIGGER tenant_ldap_mapping_role_targets_guard_v1
BEFORE INSERT OR UPDATE OR DELETE ON public.tenant_ldap_mapping_rule_role_targets
FOR EACH ROW EXECUTE FUNCTION app.guard_tenant_ldap_mapping_role_target_v1();--> statement-breakpoint

CREATE FUNCTION app.guard_tenant_ldap_mapping_rule_epoch_v1()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'tenant LDAP mapping source epochs are append-only'
      USING ERRCODE = '55000';
  END IF;
  IF TG_OP = 'INSERT' THEN
    IF NOT EXISTS (
      SELECT 1
      FROM public.tenant_ldap_mapping_rules AS rule
      JOIN public.tenant_authorization_sources AS source
        ON source.tenant_id = rule.tenant_id AND source.id = NEW.source_id
      WHERE rule.tenant_id = NEW.tenant_id
        AND rule.id = NEW.mapping_rule_id
        AND rule.binding_id = NEW.binding_id
        AND NOT rule.enabled AND rule.archived_at IS NULL
        AND rule.configuration_revision = NEW.configuration_revision
        AND rule.matcher_type = NEW.matcher_type
        AND rule.matcher_value = NEW.matcher_value
        AND rule.case_mode = NEW.case_mode
        AND rule.priority = NEW.priority
        AND rule.tenant_security_group_id = NEW.tenant_security_group_id
        AND rule.reconciliation_mode = NEW.reconciliation_mode
        AND rule.operator_team_id IS NOT DISTINCT FROM NEW.operator_team_id
        AND rule.operator_team_assignment_epoch_id IS NOT DISTINCT FROM NEW.operator_team_assignment_epoch_id
        AND source.kind = 'identity_mapping'
        AND source.key = format('identity_mapping:%s:%s', NEW.mapping_rule_id, NEW.sequence)
        AND source.authoritative = (NEW.reconciliation_mode = 'authoritative')
        AND NOT source.protected AND source.retired_at IS NULL
        AND (SELECT count(*)
             FROM public.tenant_ldap_mapping_rule_role_targets AS target
             WHERE target.tenant_id = NEW.tenant_id
               AND target.mapping_rule_id = NEW.mapping_rule_id
               AND target.configuration_revision = NEW.configuration_revision)
            BETWEEN 1 AND 32
    ) THEN
      RAISE EXCEPTION 'tenant LDAP mapping source epoch snapshot is invalid'
        USING ERRCODE = '23514',
              CONSTRAINT = 'tenant_ldap_mapping_rule_epochs_source_snapshot_check';
    END IF;
    RETURN NEW;
  END IF;

  IF ROW(NEW.id, NEW.tenant_id, NEW.mapping_rule_id, NEW.binding_id,
         NEW.source_id, NEW.sequence, NEW.configuration_revision,
         NEW.matcher_type, NEW.matcher_value, NEW.case_mode, NEW.priority,
         NEW.tenant_security_group_id, NEW.reconciliation_mode,
         NEW.operator_team_id, NEW.operator_team_assignment_epoch_id,
         NEW.activated_by_membership_id, NEW.activated_at)
     IS DISTINCT FROM
     ROW(OLD.id, OLD.tenant_id, OLD.mapping_rule_id, OLD.binding_id,
         OLD.source_id, OLD.sequence, OLD.configuration_revision,
         OLD.matcher_type, OLD.matcher_value, OLD.case_mode, OLD.priority,
         OLD.tenant_security_group_id, OLD.reconciliation_mode,
         OLD.operator_team_id, OLD.operator_team_assignment_epoch_id,
         OLD.activated_by_membership_id, OLD.activated_at)
     OR OLD.ended_at IS NOT NULL OR NEW.ended_at IS NULL
     OR NEW.ended_by_membership_id IS NULL OR NEW.end_reason IS NULL
     OR NEW.version <> 2 OR EXISTS (
       SELECT 1 FROM public.tenant_ldap_mapping_rules AS rule
       WHERE rule.tenant_id = OLD.tenant_id AND rule.id = OLD.mapping_rule_id
         AND rule.current_source_epoch_id = OLD.id
     ) THEN
    RAISE EXCEPTION 'tenant LDAP mapping source epoch transition is invalid'
      USING ERRCODE = '55000';
  END IF;
  RETURN NEW;
END;
$function$;--> statement-breakpoint

CREATE TRIGGER tenant_ldap_mapping_rule_epochs_guard_v1
BEFORE INSERT OR UPDATE OR DELETE ON public.tenant_ldap_mapping_rule_epochs
FOR EACH ROW EXECUTE FUNCTION app.guard_tenant_ldap_mapping_rule_epoch_v1();--> statement-breakpoint

-- Live mappings must be disabled before their referenced authority objects can
-- be disabled, archived, ended or deleted.
CREATE FUNCTION app.guard_tenant_ldap_mapping_binding_dependency_v1()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF (TG_OP = 'DELETE' OR (OLD.enabled AND NOT NEW.enabled)
      OR (OLD.archived_at IS NULL AND NEW.archived_at IS NOT NULL))
     AND EXISTS (
       SELECT 1 FROM public.tenant_ldap_mapping_rules AS rule
       WHERE rule.tenant_id = OLD.tenant_id AND rule.binding_id = OLD.id
         AND rule.enabled
     ) THEN
    RAISE EXCEPTION 'disable LDAP mappings before changing the provider binding lifecycle'
      USING ERRCODE = '55000';
  END IF;
  RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END;
$function$;--> statement-breakpoint

CREATE TRIGGER tenant_auth_provider_bindings_mapping_dependency_v1
BEFORE UPDATE OF enabled, archived_at OR DELETE ON public.tenant_auth_provider_bindings
FOR EACH ROW EXECUTE FUNCTION app.guard_tenant_ldap_mapping_binding_dependency_v1();--> statement-breakpoint

CREATE FUNCTION app.guard_tenant_ldap_mapping_group_dependency_v1()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF (TG_OP = 'DELETE' OR (OLD.archived_at IS NULL AND NEW.archived_at IS NOT NULL))
     AND EXISTS (
       SELECT 1 FROM public.tenant_ldap_mapping_rules AS rule
       WHERE rule.tenant_id = OLD.tenant_id
         AND rule.tenant_security_group_id = OLD.id AND rule.enabled
     ) THEN
    RAISE EXCEPTION 'disable LDAP mappings before archiving their security group'
      USING ERRCODE = '55000';
  END IF;
  RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END;
$function$;--> statement-breakpoint

CREATE TRIGGER tenant_security_groups_mapping_dependency_v1
BEFORE UPDATE OF archived_at OR DELETE ON public.tenant_security_groups
FOR EACH ROW EXECUTE FUNCTION app.guard_tenant_ldap_mapping_group_dependency_v1();--> statement-breakpoint

CREATE FUNCTION app.guard_tenant_ldap_mapping_role_dependency_v1()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF (TG_OP = 'DELETE' OR (OLD.archived_at IS NULL AND NEW.archived_at IS NOT NULL))
     AND EXISTS (
       SELECT 1
       FROM public.tenant_ldap_mapping_rules AS rule
       JOIN public.tenant_ldap_mapping_rule_role_targets AS target
         ON target.tenant_id = rule.tenant_id
        AND target.mapping_rule_id = rule.id
        AND target.configuration_revision = rule.configuration_revision
       WHERE rule.tenant_id = OLD.tenant_id AND target.role_id = OLD.id
         AND rule.enabled
     ) THEN
    RAISE EXCEPTION 'disable LDAP mappings before archiving their tenant role'
      USING ERRCODE = '55000';
  END IF;
  RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END;
$function$;--> statement-breakpoint

CREATE TRIGGER tenant_roles_mapping_dependency_v1
BEFORE UPDATE OF archived_at OR DELETE ON public.tenant_roles
FOR EACH ROW EXECUTE FUNCTION app.guard_tenant_ldap_mapping_role_dependency_v1();--> statement-breakpoint

CREATE FUNCTION app.guard_tenant_ldap_mapping_team_epoch_dependency_v1()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF (TG_OP = 'DELETE' OR (OLD.ended_at IS NULL AND NEW.ended_at IS NOT NULL))
     AND EXISTS (
       SELECT 1 FROM public.tenant_ldap_mapping_rules AS rule
       WHERE rule.tenant_id = OLD.tenant_id
         AND rule.operator_team_id = OLD.operator_team_id
         AND rule.operator_team_assignment_epoch_id = OLD.id
         AND rule.enabled
     ) THEN
    RAISE EXCEPTION 'disable LDAP mappings before ending their operator-team assignment epoch'
      USING ERRCODE = '55000';
  END IF;
  RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END;
$function$;--> statement-breakpoint

CREATE TRIGGER operator_team_assignment_epochs_mapping_dependency_v1
BEFORE UPDATE OF ended_at OR DELETE ON public.operator_team_assignment_epochs
FOR EACH ROW EXECUTE FUNCTION app.guard_tenant_ldap_mapping_team_epoch_dependency_v1();--> statement-breakpoint

-- Extend the generic idempotency tombstone with an exact tenant/kind/version
-- result check. This prevents result IDs from being rebound cross-tenant or to
-- another aggregate kind.
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
    IF NOT EXISTS (SELECT 1 FROM public.tenant_roles r WHERE r.tenant_id = NEW.tenant_id AND r.id = NEW.result_resource_id AND r.version = NEW.result_version) THEN
      RAISE EXCEPTION 'tenant role idempotency result is invalid' USING ERRCODE = '23503', CONSTRAINT = 'tenant_authorization_commands_result_fk';
    END IF;
  ELSIF NEW.operation = 'tenant_role_grant.create' THEN
    IF NOT EXISTS (SELECT 1 FROM public.tenant_membership_role_grants r WHERE r.tenant_id = NEW.tenant_id AND r.id = NEW.result_resource_id AND r.version = NEW.result_version) THEN
      RAISE EXCEPTION 'tenant role grant idempotency result is invalid' USING ERRCODE = '23503', CONSTRAINT = 'tenant_authorization_commands_result_fk';
    END IF;
  ELSIF NEW.operation = 'tenant_security_group.create' THEN
    IF NOT EXISTS (SELECT 1 FROM public.tenant_security_groups r WHERE r.tenant_id = NEW.tenant_id AND r.id = NEW.result_resource_id AND r.version = NEW.result_version) THEN
      RAISE EXCEPTION 'tenant security group idempotency result is invalid' USING ERRCODE = '23503', CONSTRAINT = 'tenant_authorization_commands_result_fk';
    END IF;
  ELSIF NEW.operation = 'tenant_security_group_membership.create' THEN
    IF NOT EXISTS (SELECT 1 FROM public.tenant_security_group_memberships r WHERE r.tenant_id = NEW.tenant_id AND r.id = NEW.result_resource_id AND r.version = NEW.result_version) THEN
      RAISE EXCEPTION 'tenant security group membership idempotency result is invalid' USING ERRCODE = '23503', CONSTRAINT = 'tenant_authorization_commands_result_fk';
    END IF;
  ELSIF NEW.operation = 'tenant_security_group_role_grant.create' THEN
    IF NOT EXISTS (SELECT 1 FROM public.tenant_security_group_role_grants r WHERE r.tenant_id = NEW.tenant_id AND r.id = NEW.result_resource_id AND r.version = NEW.result_version) THEN
      RAISE EXCEPTION 'tenant security group role grant idempotency result is invalid' USING ERRCODE = '23503', CONSTRAINT = 'tenant_authorization_commands_result_fk';
    END IF;
  ELSIF NEW.operation = 'operator_team_assignment.create' THEN
    IF NOT EXISTS (SELECT 1 FROM public.operator_team_assignment_epochs r WHERE r.tenant_id = NEW.tenant_id AND r.id = NEW.result_resource_id AND r.version = NEW.result_version) THEN
      RAISE EXCEPTION 'operator-team assignment idempotency result is invalid' USING ERRCODE = '23503', CONSTRAINT = 'tenant_authorization_commands_result_fk';
    END IF;
  ELSIF NEW.operation = 'operator_team_roster_entry.create' THEN
    IF NOT EXISTS (SELECT 1 FROM public.operator_team_roster_entries r WHERE r.tenant_id = NEW.tenant_id AND r.id = NEW.result_resource_id AND r.version = NEW.result_version) THEN
      RAISE EXCEPTION 'operator-team roster idempotency result is invalid' USING ERRCODE = '23503', CONSTRAINT = 'tenant_authorization_commands_result_fk';
    END IF;
  ELSIF NEW.operation = 'identity_provider.create' THEN
    IF NOT EXISTS (SELECT 1 FROM public.tenant_auth_providers r WHERE r.tenant_id = NEW.tenant_id AND r.id = NEW.result_resource_id AND r.version = NEW.result_version) THEN
      RAISE EXCEPTION 'identity-provider idempotency result is invalid' USING ERRCODE = '23503', CONSTRAINT = 'tenant_authorization_commands_result_fk';
    END IF;
  ELSIF NEW.operation = 'identity_provider_binding.create' THEN
    IF NOT EXISTS (SELECT 1 FROM public.tenant_auth_provider_bindings r WHERE r.tenant_id = NEW.tenant_id AND r.id = NEW.result_resource_id AND r.version = NEW.result_version) THEN
      RAISE EXCEPTION 'identity-provider binding idempotency result is invalid' USING ERRCODE = '23503', CONSTRAINT = 'tenant_authorization_commands_result_fk';
    END IF;
  ELSIF NEW.operation = 'identity_mapping.create' THEN
    IF NOT EXISTS (SELECT 1 FROM public.tenant_ldap_mapping_rules r WHERE r.tenant_id = NEW.tenant_id AND r.id = NEW.result_resource_id AND r.version = NEW.result_version) THEN
      RAISE EXCEPTION 'identity-mapping idempotency result is invalid' USING ERRCODE = '23503', CONSTRAINT = 'tenant_authorization_commands_result_fk';
    END IF;
  ELSE
    RAISE EXCEPTION 'unsupported tenant authorization command operation'
      USING ERRCODE = '22023';
  END IF;
  RETURN NEW;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION app.private_validate_tenant_ldap_mapping_targets_v1(
  p_tenant_id uuid,
  p_security_group_id uuid,
  p_role_ids uuid[],
  p_operator_team_id uuid,
  p_assignment_epoch_id uuid
)
RETURNS uuid[]
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  canonical_roles uuid[];
  role_id uuid;
BEGIN
  IF p_tenant_id IS DISTINCT FROM context_tenant
     OR p_role_ids IS NULL OR cardinality(p_role_ids) NOT BETWEEN 1 AND 32
     OR array_position(p_role_ids, NULL) IS NOT NULL THEN
    RAISE EXCEPTION 'LDAP mapping target is invalid' USING ERRCODE = '22023';
  END IF;
  SELECT array_agg(DISTINCT value ORDER BY value) INTO canonical_roles
  FROM unnest(p_role_ids) AS value;
  IF cardinality(canonical_roles) <> cardinality(p_role_ids) THEN
    RAISE EXCEPTION 'LDAP mapping role targets must be unique'
      USING ERRCODE = '22023';
  END IF;

  PERFORM 1 FROM public.tenant_security_groups AS security_group
  WHERE security_group.tenant_id = context_tenant
    AND security_group.id = p_security_group_id
    AND security_group.archived_at IS NULL
  FOR KEY SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'active tenant security group was not found'
      USING ERRCODE = 'P0002';
  END IF;
  PERFORM app.assert_actor_can_change_security_group_member(
    p_security_group_id, NULL
  );

  FOREACH role_id IN ARRAY canonical_roles LOOP
    PERFORM 1 FROM public.tenant_roles AS role
    WHERE role.tenant_id = context_tenant AND role.id = role_id
      AND role.principal_kind = 'human' AND role.archived_at IS NULL
    FOR KEY SHARE;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'active human tenant role was not found'
        USING ERRCODE = 'P0002';
    END IF;
    PERFORM app.assert_actor_can_grant_role(role_id, NULL);
  END LOOP;

  IF (p_operator_team_id IS NULL) <> (p_assignment_epoch_id IS NULL) THEN
    RAISE EXCEPTION 'operator team and assignment epoch must be supplied together'
      USING ERRCODE = '22023';
  END IF;
  IF p_operator_team_id IS NOT NULL THEN
    IF NOT app.current_tenant_can_manage_operator_team_roster(
      p_operator_team_id, p_assignment_epoch_id
    ) THEN
      RAISE EXCEPTION 'operator_team.roster.manage authority is required for the exact team epoch'
        USING ERRCODE = '42501';
    END IF;
    PERFORM 1
    FROM public.operator_team_assignment_epochs AS assignment
    JOIN public.operator_teams AS team ON team.id = assignment.operator_team_id
    WHERE assignment.tenant_id = context_tenant
      AND assignment.id = p_assignment_epoch_id
      AND assignment.operator_team_id = p_operator_team_id
      AND assignment.ended_at IS NULL AND team.archived_at IS NULL
    FOR KEY SHARE OF assignment, team;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'exact live operator-team assignment epoch was not found'
        USING ERRCODE = 'P0002';
    END IF;
  END IF;
  RETURN canonical_roles;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION app.private_close_tenant_ldap_mapping_epoch_v1(
  p_tenant_id uuid,
  p_mapping_rule_id uuid,
  p_epoch_id uuid,
  p_actor_membership_id uuid,
  p_reason text
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  locked_epoch public.tenant_ldap_mapping_rule_epochs%ROWTYPE;
BEGIN
  SELECT epoch.* INTO locked_epoch
  FROM public.tenant_ldap_mapping_rule_epochs AS epoch
  WHERE epoch.tenant_id = p_tenant_id AND epoch.id = p_epoch_id
    AND epoch.mapping_rule_id = p_mapping_rule_id
  FOR UPDATE;
  IF NOT FOUND OR locked_epoch.ended_at IS NOT NULL THEN
    RAISE EXCEPTION 'live tenant LDAP mapping epoch was not found'
      USING ERRCODE = '55000';
  END IF;
  IF EXISTS (
    SELECT 1 FROM public.tenant_ldap_mapping_rules AS rule
    WHERE rule.tenant_id = p_tenant_id AND rule.id = p_mapping_rule_id
      AND rule.current_source_epoch_id = p_epoch_id
  ) THEN
    RAISE EXCEPTION 'detach tenant LDAP mapping epoch before closing it'
      USING ERRCODE = '55000';
  END IF;
  UPDATE public.tenant_ldap_mapping_rule_epochs AS epoch
  SET ended_at = transaction_timestamp(),
      ended_by_membership_id = p_actor_membership_id,
      end_reason = p_reason,
      version = 2
  WHERE epoch.tenant_id = p_tenant_id AND epoch.id = p_epoch_id;
  UPDATE public.tenant_authorization_sources AS source
  SET retired_at = transaction_timestamp()
  WHERE source.tenant_id = p_tenant_id AND source.id = locked_epoch.source_id
    AND source.kind = 'identity_mapping' AND source.retired_at IS NULL;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant LDAP mapping authorization source could not be retired'
      USING ERRCODE = '55000';
  END IF;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION app.update_tenant_ldap_mapping_rule_v1(
  p_mapping_rule_id uuid,
  p_expected_version integer,
  p_matcher_type public.ldap_mapping_matcher_type,
  p_matcher_value text,
  p_case_mode public.ldap_mapping_case_mode,
  p_priority integer,
  p_security_group_id uuid,
  p_reconciliation_mode public.ldap_mapping_reconciliation_mode,
  p_role_ids uuid[],
  p_operator_team_id uuid,
  p_operator_team_assignment_epoch_id uuid,
  p_enabled boolean,
  p_notes text,
  p_reason text,
  p_audit_event_id uuid,
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
  locked_rule public.tenant_ldap_mapping_rules%ROWTYPE;
  canonical_roles uuid[];
  old_roles uuid[];
  semantic_change boolean;
  next_configuration_revision integer;
  next_epoch_sequence integer;
  next_version integer;
  new_source_id uuid;
  new_epoch_id uuid;
  resulting_epoch_id uuid;
BEGIN
  PERFORM app.lock_current_tenant_authorization_state();
  actor_membership := app.current_tenant_membership_id();
  IF NOT app.current_tenant_human_has_exact_permission_v3(
    'identity_mapping.manage', 'tenant'
  ) OR NOT app.current_tenant_human_has_exact_permission_v3(
    'role.grant', 'tenant'
  ) THEN
    RAISE EXCEPTION 'identity_mapping.manage and role.grant tenant scopes are required'
      USING ERRCODE = '42501';
  END IF;
  SELECT rule.* INTO locked_rule
  FROM public.tenant_ldap_mapping_rules AS rule
  WHERE rule.tenant_id = context_tenant AND rule.id = p_mapping_rule_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant LDAP mapping rule was not found'
      USING ERRCODE = 'P0002';
  END IF;
  IF locked_rule.archived_at IS NOT NULL THEN
    RAISE EXCEPTION 'archived tenant LDAP mapping rule cannot be changed'
      USING ERRCODE = '55000';
  END IF;
  IF p_expected_version IS NULL OR p_expected_version <> locked_rule.version THEN
    RAISE EXCEPTION 'tenant LDAP mapping rule version does not match'
      USING ERRCODE = '40001';
  END IF;
  IF locked_rule.version >= 2147483647
     OR locked_rule.configuration_revision >= 2147483647
     OR p_enabled IS NULL OR p_matcher_type IS NULL OR p_matcher_value IS NULL
     OR btrim(p_matcher_value) = '' OR p_matcher_value ~ '[[:cntrl:]]'
     OR (p_matcher_type = 'exact_dn' AND
         (char_length(p_matcher_value) > 2048 OR octet_length(p_matcher_value) > 8192))
     OR (p_matcher_type IN ('exact_cn', 'regex') AND char_length(p_matcher_value) > 512)
     OR p_case_mode IS NULL OR p_priority IS NULL OR p_priority NOT BETWEEN 0 AND 1000000
     OR p_reconciliation_mode IS NULL OR p_notes IS NULL
     OR char_length(p_notes) > 2000 OR p_notes ~ '[[:cntrl:]]'
     OR p_reason IS NULL OR btrim(p_reason) = '' OR char_length(p_reason) > 500
     OR p_reason ~ '[[:cntrl:]]' THEN
    RAISE EXCEPTION 'tenant LDAP mapping update input is invalid'
      USING ERRCODE = '22023';
  END IF;
  canonical_roles := app.private_validate_tenant_ldap_mapping_targets_v1(
    context_tenant, p_security_group_id, p_role_ids,
    p_operator_team_id, p_operator_team_assignment_epoch_id
  );
  SELECT array_agg(target.role_id ORDER BY target.role_id)::uuid[]
  INTO old_roles
  FROM public.tenant_ldap_mapping_rule_role_targets AS target
  WHERE target.tenant_id = context_tenant
    AND target.mapping_rule_id = p_mapping_rule_id
    AND target.configuration_revision = locked_rule.configuration_revision;
  semantic_change := ROW(
    locked_rule.matcher_type, locked_rule.matcher_value, locked_rule.case_mode,
    locked_rule.priority, locked_rule.tenant_security_group_id,
    locked_rule.reconciliation_mode, locked_rule.operator_team_id,
    locked_rule.operator_team_assignment_epoch_id, old_roles
  ) IS DISTINCT FROM ROW(
    p_matcher_type, p_matcher_value, p_case_mode, p_priority,
    p_security_group_id, p_reconciliation_mode, p_operator_team_id,
    p_operator_team_assignment_epoch_id, canonical_roles
  );
  next_configuration_revision := locked_rule.configuration_revision
    + CASE WHEN semantic_change THEN 1 ELSE 0 END;
  next_version := locked_rule.version + 1;
  resulting_epoch_id := locked_rule.current_source_epoch_id;

  IF locked_rule.enabled AND (semantic_change OR NOT p_enabled) THEN
    UPDATE public.tenant_ldap_mapping_rules AS rule
    SET enabled = false, current_source_epoch_id = NULL
    WHERE rule.tenant_id = context_tenant AND rule.id = p_mapping_rule_id;
    PERFORM app.private_close_tenant_ldap_mapping_epoch_v1(
      context_tenant, p_mapping_rule_id, locked_rule.current_source_epoch_id,
      actor_membership, p_reason
    );
    resulting_epoch_id := NULL;
  END IF;

  IF semantic_change THEN
    UPDATE public.tenant_ldap_mapping_rules AS rule
    SET matcher_type = p_matcher_type, matcher_value = p_matcher_value,
        case_mode = p_case_mode, priority = p_priority,
        tenant_security_group_id = p_security_group_id,
        reconciliation_mode = p_reconciliation_mode,
        operator_team_id = p_operator_team_id,
        operator_team_assignment_epoch_id = p_operator_team_assignment_epoch_id,
        configuration_revision = next_configuration_revision
    WHERE rule.tenant_id = context_tenant AND rule.id = p_mapping_rule_id;
    INSERT INTO public.tenant_ldap_mapping_rule_role_targets (
      tenant_id, mapping_rule_id, configuration_revision, role_id
    ) SELECT context_tenant, p_mapping_rule_id,
             next_configuration_revision, role_id
      FROM unnest(canonical_roles) AS role_id;
  END IF;

  IF p_enabled AND (NOT locked_rule.enabled OR semantic_change) THEN
    PERFORM 1
    FROM public.tenant_auth_provider_bindings AS binding
    JOIN public.tenant_auth_providers AS provider
      ON provider.tenant_id = binding.tenant_id AND provider.id = binding.provider_id
    WHERE binding.tenant_id = context_tenant
      AND binding.id = locked_rule.binding_id
      AND binding.enabled AND binding.archived_at IS NULL
      AND provider.kind = 'ldap' AND provider.enabled
      AND provider.archived_at IS NULL
    FOR KEY SHARE OF binding, provider;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'live tenant LDAP provider binding was not found'
        USING ERRCODE = 'P0002';
    END IF;
    SELECT coalesce(max(epoch.sequence), 0) + 1 INTO next_epoch_sequence
    FROM public.tenant_ldap_mapping_rule_epochs AS epoch
    WHERE epoch.tenant_id = context_tenant
      AND epoch.mapping_rule_id = p_mapping_rule_id;
    new_source_id := uuidv7();
    new_epoch_id := uuidv7();
    INSERT INTO public.tenant_authorization_sources (
      id, tenant_id, kind, key, authoritative, protected
    ) VALUES (
      new_source_id, context_tenant, 'identity_mapping',
      format('identity_mapping:%s:%s', p_mapping_rule_id, next_epoch_sequence),
      p_reconciliation_mode = 'authoritative', false
    );
    INSERT INTO public.tenant_ldap_mapping_rule_epochs (
      id, tenant_id, mapping_rule_id, binding_id, source_id, sequence,
      configuration_revision, matcher_type, matcher_value, case_mode,
      priority, tenant_security_group_id, reconciliation_mode,
      operator_team_id, operator_team_assignment_epoch_id,
      activated_by_membership_id
    ) VALUES (
      new_epoch_id, context_tenant, p_mapping_rule_id, locked_rule.binding_id,
      new_source_id, next_epoch_sequence, next_configuration_revision,
      p_matcher_type, p_matcher_value, p_case_mode, p_priority,
      p_security_group_id, p_reconciliation_mode, p_operator_team_id,
      p_operator_team_assignment_epoch_id, actor_membership
    );
    resulting_epoch_id := new_epoch_id;
  END IF;

  UPDATE public.tenant_ldap_mapping_rules AS rule
  SET matcher_type = p_matcher_type, matcher_value = p_matcher_value,
      case_mode = p_case_mode, priority = p_priority,
      tenant_security_group_id = p_security_group_id,
      reconciliation_mode = p_reconciliation_mode,
      operator_team_id = p_operator_team_id,
      operator_team_assignment_epoch_id = p_operator_team_assignment_epoch_id,
      configuration_revision = next_configuration_revision,
      enabled = p_enabled, current_source_epoch_id = resulting_epoch_id,
      notes = p_notes, updated_by_membership_id = actor_membership,
      version = next_version, updated_at = transaction_timestamp()
  WHERE rule.tenant_id = context_tenant AND rule.id = p_mapping_rule_id;

  PERFORM app.append_tenant_authorization_audit(
    p_audit_event_id, 'tenant.identity_mapping.updated', 'identity_mapping',
    p_mapping_rule_id, p_request_id, p_correlation_id, p_ip_address,
    p_user_agent, p_authentication_method,
    jsonb_build_object(
      'matcher_type', locked_rule.matcher_type,
      'case_mode', locked_rule.case_mode, 'priority', locked_rule.priority,
      'security_group_id', locked_rule.tenant_security_group_id,
      'reconciliation_mode', locked_rule.reconciliation_mode,
      'role_count', cardinality(old_roles),
      'operator_team_id', locked_rule.operator_team_id,
      'operator_team_assignment_epoch_id', locked_rule.operator_team_assignment_epoch_id,
      'enabled', locked_rule.enabled,
      'configuration_revision', locked_rule.configuration_revision,
      'version', locked_rule.version
    ),
    jsonb_build_object(
      'matcher_type', p_matcher_type, 'case_mode', p_case_mode,
      'priority', p_priority, 'security_group_id', p_security_group_id,
      'reconciliation_mode', p_reconciliation_mode,
      'role_count', cardinality(canonical_roles),
      'operator_team_id', p_operator_team_id,
      'operator_team_assignment_epoch_id', p_operator_team_assignment_epoch_id,
      'enabled', p_enabled,
      'configuration_revision', next_configuration_revision,
      'source_epoch_sequence', CASE WHEN resulting_epoch_id IS NULL THEN NULL
        ELSE (SELECT epoch.sequence FROM public.tenant_ldap_mapping_rule_epochs epoch
              WHERE epoch.tenant_id = context_tenant AND epoch.id = resulting_epoch_id)
        END,
      'version', next_version
    ), jsonb_build_object('reason', p_reason, 'semantic_change', semantic_change)
  );
  RETURN next_version;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION app.archive_tenant_ldap_mapping_rule_v1(
  p_mapping_rule_id uuid,
  p_expected_version integer,
  p_reason text,
  p_audit_event_id uuid,
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
  locked_rule public.tenant_ldap_mapping_rules%ROWTYPE;
  current_roles uuid[];
  next_version integer;
BEGIN
  PERFORM app.lock_current_tenant_authorization_state();
  actor_membership := app.current_tenant_membership_id();
  IF NOT app.current_tenant_human_has_exact_permission_v3(
    'identity_mapping.manage', 'tenant'
  ) OR NOT app.current_tenant_human_has_exact_permission_v3(
    'role.grant', 'tenant'
  ) THEN
    RAISE EXCEPTION 'identity_mapping.manage and role.grant tenant scopes are required'
      USING ERRCODE = '42501';
  END IF;
  SELECT rule.* INTO locked_rule
  FROM public.tenant_ldap_mapping_rules AS rule
  WHERE rule.tenant_id = context_tenant AND rule.id = p_mapping_rule_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant LDAP mapping rule was not found'
      USING ERRCODE = 'P0002';
  END IF;
  IF locked_rule.archived_at IS NOT NULL THEN
    RAISE EXCEPTION 'tenant LDAP mapping rule is already archived'
      USING ERRCODE = '55000';
  END IF;
  IF p_expected_version IS NULL OR p_expected_version <> locked_rule.version THEN
    RAISE EXCEPTION 'tenant LDAP mapping rule version does not match'
      USING ERRCODE = '40001';
  END IF;
  IF locked_rule.version >= 2147483647 OR p_reason IS NULL
     OR btrim(p_reason) = '' OR char_length(p_reason) > 500
     OR p_reason ~ '[[:cntrl:]]' THEN
    RAISE EXCEPTION 'tenant LDAP mapping archive input is invalid'
      USING ERRCODE = '22023';
  END IF;
  SELECT array_agg(target.role_id ORDER BY target.role_id)::uuid[]
  INTO current_roles
  FROM public.tenant_ldap_mapping_rule_role_targets AS target
  WHERE target.tenant_id = context_tenant
    AND target.mapping_rule_id = p_mapping_rule_id
    AND target.configuration_revision = locked_rule.configuration_revision;
  PERFORM app.private_validate_tenant_ldap_mapping_targets_v1(
    context_tenant, locked_rule.tenant_security_group_id, current_roles,
    locked_rule.operator_team_id, locked_rule.operator_team_assignment_epoch_id
  );
  IF locked_rule.enabled THEN
    UPDATE public.tenant_ldap_mapping_rules AS rule
    SET enabled = false, current_source_epoch_id = NULL
    WHERE rule.tenant_id = context_tenant AND rule.id = p_mapping_rule_id;
    PERFORM app.private_close_tenant_ldap_mapping_epoch_v1(
      context_tenant, p_mapping_rule_id, locked_rule.current_source_epoch_id,
      actor_membership, p_reason
    );
  END IF;
  next_version := locked_rule.version + 1;
  UPDATE public.tenant_ldap_mapping_rules AS rule
  SET enabled = false, current_source_epoch_id = NULL,
      archived_at = transaction_timestamp(),
      archived_by_membership_id = actor_membership,
      archive_reason = p_reason,
      updated_by_membership_id = actor_membership,
      version = next_version, updated_at = transaction_timestamp()
  WHERE rule.tenant_id = context_tenant AND rule.id = p_mapping_rule_id;
  PERFORM app.append_tenant_authorization_audit(
    p_audit_event_id, 'tenant.identity_mapping.archived', 'identity_mapping',
    p_mapping_rule_id, p_request_id, p_correlation_id, p_ip_address,
    p_user_agent, p_authentication_method,
    jsonb_build_object(
      'enabled', locked_rule.enabled,
      'configuration_revision', locked_rule.configuration_revision,
      'role_count', cardinality(current_roles), 'archived', false,
      'version', locked_rule.version
    ),
    jsonb_build_object(
      'enabled', false, 'configuration_revision', locked_rule.configuration_revision,
      'role_count', cardinality(current_roles), 'archived', true,
      'version', next_version
    ), jsonb_build_object('reason', p_reason)
  );
  RETURN next_version;
END;
$function$;--> statement-breakpoint

ALTER FUNCTION app.guard_tenant_ldap_mapping_rule_v1() OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.guard_tenant_ldap_mapping_role_target_v1() OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.guard_tenant_ldap_mapping_rule_epoch_v1() OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.guard_tenant_ldap_mapping_binding_dependency_v1() OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.guard_tenant_ldap_mapping_group_dependency_v1() OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.guard_tenant_ldap_mapping_role_dependency_v1() OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.guard_tenant_ldap_mapping_team_epoch_dependency_v1() OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.guard_tenant_authorization_command() OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.private_validate_tenant_ldap_mapping_targets_v1(uuid, uuid, uuid[], uuid, uuid) OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.private_close_tenant_ldap_mapping_epoch_v1(uuid, uuid, uuid, uuid, text) OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.list_tenant_ldap_mapping_rules_v1(uuid, integer, uuid, boolean, integer) OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.get_tenant_ldap_mapping_rule_v1(uuid) OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.snapshot_tenant_ldap_mapping_rules_v1(uuid) OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.create_tenant_ldap_mapping_rule_v1(bytea, uuid, public.ldap_mapping_matcher_type, text, public.ldap_mapping_case_mode, integer, uuid, public.ldap_mapping_reconciliation_mode, uuid[], uuid, uuid, text, text, uuid, uuid, uuid, inet, text, text) OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.update_tenant_ldap_mapping_rule_v1(uuid, integer, public.ldap_mapping_matcher_type, text, public.ldap_mapping_case_mode, integer, uuid, public.ldap_mapping_reconciliation_mode, uuid[], uuid, uuid, boolean, text, text, uuid, uuid, uuid, inet, text, text) OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.archive_tenant_ldap_mapping_rule_v1(uuid, integer, text, uuid, uuid, uuid, inet, text, text) OWNER TO periapsis_migrator;--> statement-breakpoint

REVOKE ALL ON FUNCTION app.guard_tenant_ldap_mapping_rule_v1() FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.guard_tenant_ldap_mapping_role_target_v1() FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.guard_tenant_ldap_mapping_rule_epoch_v1() FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.guard_tenant_ldap_mapping_binding_dependency_v1() FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.guard_tenant_ldap_mapping_group_dependency_v1() FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.guard_tenant_ldap_mapping_role_dependency_v1() FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.guard_tenant_ldap_mapping_team_epoch_dependency_v1() FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.guard_tenant_authorization_command() FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_validate_tenant_ldap_mapping_targets_v1(uuid, uuid, uuid[], uuid, uuid) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_close_tenant_ldap_mapping_epoch_v1(uuid, uuid, uuid, uuid, text) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.list_tenant_ldap_mapping_rules_v1(uuid, integer, uuid, boolean, integer) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.get_tenant_ldap_mapping_rule_v1(uuid) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.snapshot_tenant_ldap_mapping_rules_v1(uuid) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.create_tenant_ldap_mapping_rule_v1(bytea, uuid, public.ldap_mapping_matcher_type, text, public.ldap_mapping_case_mode, integer, uuid, public.ldap_mapping_reconciliation_mode, uuid[], uuid, uuid, text, text, uuid, uuid, uuid, inet, text, text) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.update_tenant_ldap_mapping_rule_v1(uuid, integer, public.ldap_mapping_matcher_type, text, public.ldap_mapping_case_mode, integer, uuid, public.ldap_mapping_reconciliation_mode, uuid[], uuid, uuid, boolean, text, text, uuid, uuid, uuid, inet, text, text) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.archive_tenant_ldap_mapping_rule_v1(uuid, integer, text, uuid, uuid, uuid, inet, text, text) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint

GRANT EXECUTE ON FUNCTION app.list_tenant_ldap_mapping_rules_v1(uuid, integer, uuid, boolean, integer) TO periapsis_api;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.get_tenant_ldap_mapping_rule_v1(uuid) TO periapsis_api;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.snapshot_tenant_ldap_mapping_rules_v1(uuid) TO periapsis_api, periapsis_worker;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.create_tenant_ldap_mapping_rule_v1(bytea, uuid, public.ldap_mapping_matcher_type, text, public.ldap_mapping_case_mode, integer, uuid, public.ldap_mapping_reconciliation_mode, uuid[], uuid, uuid, text, text, uuid, uuid, uuid, inet, text, text) TO periapsis_api;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.update_tenant_ldap_mapping_rule_v1(uuid, integer, public.ldap_mapping_matcher_type, text, public.ldap_mapping_case_mode, integer, uuid, public.ldap_mapping_reconciliation_mode, uuid[], uuid, uuid, boolean, text, text, uuid, uuid, uuid, inet, text, text) TO periapsis_api;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.archive_tenant_ldap_mapping_rule_v1(uuid, integer, text, uuid, uuid, uuid, inet, text, text) TO periapsis_api;

