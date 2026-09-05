ALTER TABLE "tenant_authorization_commands" DROP CONSTRAINT "tenant_authorization_commands_operation_check";--> statement-breakpoint
ALTER TABLE "tenant_authorization_commands" ADD CONSTRAINT "tenant_authorization_commands_operation_check" CHECK ("tenant_authorization_commands"."operation" in (
        'tenant_role.create',
        'tenant_role_grant.create',
        'tenant_security_group.create',
        'tenant_security_group_membership.create',
        'tenant_security_group_role_grant.create',
        'operator_team_assignment.create',
        'operator_team_roster_entry.create',
        'identity_provider.create',
        'identity_provider_binding.create',
        'identity_mapping.create',
        'identity_sync.run'
      ));
--> statement-breakpoint

-- LDAP synchronization administration is exposed only through this dedicated
-- non-login, non-BYPASSRLS owner. Runtime roles keep no table privileges.
DO $ldap_administration_owner$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_roles
    WHERE rolname = 'periapsis_ldap_administration_owner'
  ) THEN
    CREATE ROLE periapsis_ldap_administration_owner
      NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT
      NOREPLICATION NOBYPASSRLS;
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_catalog.pg_roles
    WHERE rolname = 'periapsis_ldap_administration_owner'
      AND (rolcanlogin OR rolsuper OR rolcreatedb OR rolcreaterole
        OR rolinherit OR rolreplication OR rolbypassrls)
  ) THEN
    RAISE EXCEPTION 'LDAP administration function owner is privileged'
      USING ERRCODE = '55000';
  END IF;
END
$ldap_administration_owner$;
--> statement-breakpoint

GRANT USAGE ON SCHEMA app, public
  TO periapsis_ldap_administration_owner;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.context_tenant_id(),
  app.current_tenant_membership_id(),
  app.current_tenant_human_has_exact_permission_v3(text, public.authorization_scope),
  app.lock_current_tenant_authorization_state(),
  app.begin_tenant_ldap_manual_sync_run_v1(
    uuid, uuid, text, uuid, uuid, uuid, inet, text, text
  )
  TO periapsis_ldap_administration_owner;
--> statement-breakpoint

GRANT SELECT ON TABLE
  public.tenant_auth_provider_bindings,
  public.tenant_auth_providers,
  public.tenant_ldap_provider_configs,
  public.tenant_ldap_mapping_rule_epochs,
  public.tenant_ldap_sync_runs,
  public.tenant_ldap_sync_run_mappings,
  public.tenant_ldap_sync_staged_observations
TO periapsis_ldap_administration_owner;
--> statement-breakpoint
GRANT SELECT, INSERT, DELETE ON TABLE public.tenant_authorization_commands
  TO periapsis_ldap_administration_owner;
--> statement-breakpoint

CREATE POLICY ldap_admin_owner_bindings_v1
ON public.tenant_auth_provider_bindings
AS PERMISSIVE FOR SELECT TO periapsis_ldap_administration_owner
USING (
  tenant_id = app.context_tenant_id()
  AND app.current_tenant_membership_id() IS NOT NULL
);
--> statement-breakpoint
CREATE POLICY ldap_admin_owner_providers_v1
ON public.tenant_auth_providers
AS PERMISSIVE FOR SELECT TO periapsis_ldap_administration_owner
USING (
  tenant_id = app.context_tenant_id()
  AND app.current_tenant_membership_id() IS NOT NULL
);
--> statement-breakpoint
CREATE POLICY ldap_admin_owner_configs_v1
ON public.tenant_ldap_provider_configs
AS PERMISSIVE FOR SELECT TO periapsis_ldap_administration_owner
USING (
  tenant_id = app.context_tenant_id()
  AND app.current_tenant_membership_id() IS NOT NULL
);
--> statement-breakpoint
CREATE POLICY ldap_admin_owner_mapping_epochs_v1
ON public.tenant_ldap_mapping_rule_epochs
AS PERMISSIVE FOR SELECT TO periapsis_ldap_administration_owner
USING (
  tenant_id = app.context_tenant_id()
  AND app.current_tenant_membership_id() IS NOT NULL
);
--> statement-breakpoint
CREATE POLICY ldap_admin_owner_sync_runs_v1
ON public.tenant_ldap_sync_runs
AS PERMISSIVE FOR SELECT TO periapsis_ldap_administration_owner
USING (
  tenant_id = app.context_tenant_id()
  AND app.current_tenant_membership_id() IS NOT NULL
);
--> statement-breakpoint
CREATE POLICY ldap_admin_owner_sync_mappings_v1
ON public.tenant_ldap_sync_run_mappings
AS PERMISSIVE FOR SELECT TO periapsis_ldap_administration_owner
USING (
  tenant_id = app.context_tenant_id()
  AND app.current_tenant_membership_id() IS NOT NULL
);
--> statement-breakpoint
CREATE POLICY ldap_admin_owner_sync_staging_v1
ON public.tenant_ldap_sync_staged_observations
AS PERMISSIVE FOR SELECT TO periapsis_ldap_administration_owner
USING (
  tenant_id = app.context_tenant_id()
  AND app.current_tenant_membership_id() IS NOT NULL
);
--> statement-breakpoint
CREATE POLICY ldap_admin_owner_commands_v1
ON public.tenant_authorization_commands
AS PERMISSIVE FOR ALL TO periapsis_ldap_administration_owner
USING (
  tenant_id = app.context_tenant_id()
  AND actor_membership_id = app.current_tenant_membership_id()
  AND operation = 'identity_sync.run'
)
WITH CHECK (
  tenant_id = app.context_tenant_id()
  AND actor_membership_id = app.current_tenant_membership_id()
  AND operation = 'identity_sync.run'
);
--> statement-breakpoint

-- Extend the generic authorization-command result guard with the exact
-- same-tenant synchronization run/version invariant.
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
  ELSIF NEW.operation = 'identity_sync.run' THEN
    IF NOT EXISTS (
      SELECT 1 FROM public.tenant_ldap_sync_runs r
      WHERE r.tenant_id = NEW.tenant_id
        AND r.id = NEW.result_resource_id
        AND r.version = NEW.result_version
        AND r.trigger = 'manual'
        AND r.started_by_membership_id = NEW.actor_membership_id
    ) THEN
      RAISE EXCEPTION 'identity-sync idempotency result is invalid'
        USING ERRCODE = '23503',
              CONSTRAINT = 'tenant_authorization_commands_result_fk';
    END IF;
  ELSE
    RAISE EXCEPTION 'unsupported tenant authorization command operation'
      USING ERRCODE = '22023';
  END IF;
  RETURN NEW;
END;
$function$;
--> statement-breakpoint

ALTER FUNCTION app.guard_tenant_authorization_command()
  OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.guard_tenant_authorization_command()
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor, periapsis_ldap_administration_owner;
--> statement-breakpoint

-- Shared, redacted run projection. No LDAP values, ciphertext, endpoint
-- material, subject digests, filters, or cursor bytes leave this function.
CREATE FUNCTION app.private_tenant_ldap_sync_run_projection_v1(
  p_binding_id uuid,
  p_run_id uuid,
  p_after_run_id uuid,
  p_page_size integer
)
RETURNS TABLE (
  id uuid, tenant_id uuid, binding_id uuid, provider_id uuid,
  trigger text, manual_reason text, state text,
  provider_version integer, binding_version integer,
  configuration_revision integer, access_epoch_id uuid,
  mapping_revisions jsonb, enumeration_state text,
  enumeration_complete boolean, result_truncated boolean,
  absence_allowed boolean, entry_count integer, page_count integer,
  response_bytes integer, cursor_state text,
  enumeration_error_category text, observed integer, staged integer,
  identities_created integer, identities_linked integer,
  provider_access_added integer, provider_access_suspended integer,
  group_edges_added integer, group_edges_refreshed integer,
  group_edges_revoked integer, role_edges_added integer,
  role_edges_refreshed integer, role_edges_revoked integer,
  roster_edges_added integer, roster_edges_refreshed integer,
  roster_edges_revoked integer, failed integer,
  run_error_category text, created_at timestamptz, started_at timestamptz,
  completed_at timestamptz, version integer, updated_at timestamptz
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
  SELECT run.id, run.tenant_id, run.binding_id, run.provider_id,
         run.trigger::text,
         CASE WHEN run.trigger = 'manual' THEN run.reason ELSE NULL END,
         run.status::text,
         run.provider_version, run.binding_version,
         run.configuration_version, run.binding_access_epoch_id,
         coalesce(pins.mapping_revisions, '[]'::jsonb),
         CASE
           WHEN run.enumeration_complete IS TRUE
             AND run.result_truncated IS FALSE THEN 'complete'
           WHEN run.result_truncated IS TRUE THEN 'truncated'
           WHEN run.status = 'queued' THEN 'not_started'
           WHEN run.status = 'enumerating' THEN 'enumerating'
           ELSE 'incomplete'
         END,
         run.enumeration_complete IS TRUE,
         run.result_truncated IS TRUE,
         run.enumeration_complete IS TRUE
           AND run.result_truncated IS FALSE,
         run.observed_count,
         0::integer,
         0::integer,
         CASE
           WHEN run.enumeration_complete IS TRUE
             AND run.result_truncated IS FALSE THEN 'terminal'
           WHEN run.result_truncated IS TRUE
             OR (run.status IN ('failed', 'cancelled', 'stale')
               AND run.enumeration_complete IS NOT TRUE) THEN 'discarded'
           WHEN run.cursor_digest IS NOT NULL THEN 'present'
           ELSE 'none'
         END,
         CASE
           WHEN run.enumeration_complete IS TRUE
             AND run.result_truncated IS FALSE THEN NULL
           WHEN run.failure_category = 'cancelled' THEN 'cancelled'
           WHEN run.failure_category = 'connect_timeout' THEN 'timeout'
           WHEN run.failure_category = 'destination_blocked' THEN 'destination_blocked'
           WHEN run.failure_category IN (
             'dns_failed', 'connect_failed', 'tls_failed',
             'certificate_rejected', 'service_bind_rejected',
             'network_error', 'directory_error'
           ) THEN 'directory_unavailable'
           WHEN run.failure_category = 'referral_rejected' THEN 'referral_rejected'
           WHEN run.failure_category IN ('user_ambiguous', 'duplicate_subject')
             THEN 'duplicate_subject'
           WHEN run.failure_category = 'limit_exceeded' THEN 'limit_exceeded'
           WHEN run.failure_category = 'invalid_entry' THEN 'parse_failed'
           WHEN run.failure_category IN (
             'stale_configuration', 'worker_lease_upgrade', 'planning_error'
           ) THEN 'stale_snapshot'
           ELSE 'protocol_failed'
         END,
         run.observed_count,
         coalesce(staging.staged_count, 0)::integer,
         0::integer, 0::integer, 0::integer, 0::integer,
         0::integer, 0::integer, 0::integer,
         0::integer, 0::integer, 0::integer,
         0::integer, 0::integer, 0::integer,
         0::integer,
         CASE
           WHEN run.status = 'succeeded' THEN NULL
           WHEN run.status NOT IN ('failed', 'cancelled', 'stale') THEN NULL
           WHEN run.failure_category = 'cancelled' THEN 'cancelled'
           WHEN run.failure_category = 'connect_timeout' THEN 'timeout'
           WHEN run.failure_category IN (
             'dns_failed', 'destination_blocked', 'connect_failed',
             'tls_failed', 'certificate_rejected', 'service_bind_rejected',
             'network_error', 'directory_error', 'protocol_failed'
           ) THEN 'directory_unavailable'
           WHEN run.failure_category IN (
             'limit_exceeded', 'referral_rejected', 'invalid_entry',
             'user_ambiguous', 'duplicate_subject'
           ) THEN 'incomplete_enumeration'
           WHEN run.failure_category IN (
             'stale_configuration', 'worker_lease_upgrade', 'planning_error'
           ) THEN 'stale_snapshot'
           WHEN run.failure_category = 'apply_error' THEN 'apply_conflict'
           WHEN run.failure_category = 'authorization_denied'
             THEN 'authorization_denied'
           ELSE 'internal_failure'
         END,
         run.queued_at, run.enumeration_started_at, run.completed_at,
         run.version,
         greatest(
           run.queued_at,
           coalesce(run.enumeration_started_at, run.queued_at),
           coalesce(run.enumeration_completed_at, run.queued_at),
           coalesce(run.completed_at, run.queued_at)
         )
  FROM public.tenant_ldap_sync_runs AS run
  LEFT JOIN LATERAL (
    SELECT jsonb_agg(
      jsonb_build_object(
        'mappingId', pinned.mapping_rule_id,
        'mappingVersion', pinned.mapping_version,
        'sourceEpochId', pinned.source_epoch_id,
        'sourceEpochSequence', epoch.sequence,
        'includedDisabled', false
      ) ORDER BY pinned.priority, pinned.mapping_rule_id
    ) AS mapping_revisions
    FROM public.tenant_ldap_sync_run_mappings AS pinned
    JOIN public.tenant_ldap_mapping_rule_epochs AS epoch
      ON epoch.tenant_id = pinned.tenant_id
     AND epoch.id = pinned.source_epoch_id
     AND epoch.mapping_rule_id = pinned.mapping_rule_id
     AND epoch.binding_id = pinned.binding_id
    WHERE pinned.tenant_id = run.tenant_id
      AND pinned.sync_run_id = run.id
  ) AS pins ON true
  LEFT JOIN LATERAL (
    SELECT count(*)::integer AS staged_count
    FROM public.tenant_ldap_sync_staged_observations AS observation
    WHERE observation.tenant_id = run.tenant_id
      AND observation.sync_run_id = run.id
  ) AS staging ON true
  WHERE run.tenant_id = app.context_tenant_id()
    AND run.binding_id = p_binding_id
    AND (p_run_id IS NULL OR run.id = p_run_id)
    AND (p_after_run_id IS NULL OR run.id > p_after_run_id)
  ORDER BY run.id
  LIMIT p_page_size
$function$;
--> statement-breakpoint

CREATE FUNCTION app.list_tenant_ldap_sync_runs_v1(
  p_binding_id uuid,
  p_after_run_id uuid,
  p_page_size integer
)
RETURNS TABLE (
  id uuid, tenant_id uuid, binding_id uuid, provider_id uuid,
  trigger text, manual_reason text, state text,
  provider_version integer, binding_version integer,
  configuration_revision integer, access_epoch_id uuid,
  mapping_revisions jsonb, enumeration_state text,
  enumeration_complete boolean, result_truncated boolean,
  absence_allowed boolean, entry_count integer, page_count integer,
  response_bytes integer, cursor_state text,
  enumeration_error_category text, observed integer, staged integer,
  identities_created integer, identities_linked integer,
  provider_access_added integer, provider_access_suspended integer,
  group_edges_added integer, group_edges_refreshed integer,
  group_edges_revoked integer, role_edges_added integer,
  role_edges_refreshed integer, role_edges_revoked integer,
  roster_edges_added integer, roster_edges_refreshed integer,
  roster_edges_revoked integer, failed integer,
  run_error_category text, created_at timestamptz, started_at timestamptz,
  completed_at timestamptz, version integer, updated_at timestamptz
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
BEGIN
  IF p_binding_id IS NULL
     OR (uuid_extract_version(p_binding_id) = 7) IS NOT TRUE
     OR p_after_run_id IS NOT NULL
       AND (uuid_extract_version(p_after_run_id) = 7) IS NOT TRUE
     OR p_page_size IS NULL OR p_page_size NOT BETWEEN 1 AND 101 THEN
    RAISE EXCEPTION 'tenant LDAP sync-run page input is invalid'
      USING ERRCODE = '22023';
  END IF;
  IF NOT app.current_tenant_human_has_exact_permission_v3(
    'identity_provider.read', 'tenant'
  ) THEN
    RAISE EXCEPTION 'identity_provider.read tenant scope is required'
      USING ERRCODE = '42501';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM public.tenant_auth_provider_bindings AS binding
    WHERE binding.tenant_id = context_tenant AND binding.id = p_binding_id
  ) THEN
    RAISE EXCEPTION 'tenant LDAP binding was not found'
      USING ERRCODE = 'P0002';
  END IF;
  RETURN QUERY
  SELECT * FROM app.private_tenant_ldap_sync_run_projection_v1(
    p_binding_id, NULL, p_after_run_id, p_page_size
  );
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.get_tenant_ldap_sync_run_v1(
  p_binding_id uuid,
  p_sync_run_id uuid
)
RETURNS TABLE (
  id uuid, tenant_id uuid, binding_id uuid, provider_id uuid,
  trigger text, manual_reason text, state text,
  provider_version integer, binding_version integer,
  configuration_revision integer, access_epoch_id uuid,
  mapping_revisions jsonb, enumeration_state text,
  enumeration_complete boolean, result_truncated boolean,
  absence_allowed boolean, entry_count integer, page_count integer,
  response_bytes integer, cursor_state text,
  enumeration_error_category text, observed integer, staged integer,
  identities_created integer, identities_linked integer,
  provider_access_added integer, provider_access_suspended integer,
  group_edges_added integer, group_edges_refreshed integer,
  group_edges_revoked integer, role_edges_added integer,
  role_edges_refreshed integer, role_edges_revoked integer,
  roster_edges_added integer, roster_edges_refreshed integer,
  roster_edges_revoked integer, failed integer,
  run_error_category text, created_at timestamptz, started_at timestamptz,
  completed_at timestamptz, version integer, updated_at timestamptz
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
BEGIN
  IF p_binding_id IS NULL OR p_sync_run_id IS NULL
     OR (uuid_extract_version(p_binding_id) = 7) IS NOT TRUE
     OR (uuid_extract_version(p_sync_run_id) = 7) IS NOT TRUE THEN
    RAISE EXCEPTION 'tenant LDAP sync-run lookup input is invalid'
      USING ERRCODE = '22023';
  END IF;
  IF NOT app.current_tenant_human_has_exact_permission_v3(
    'identity_provider.read', 'tenant'
  ) THEN
    RAISE EXCEPTION 'identity_provider.read tenant scope is required'
      USING ERRCODE = '42501';
  END IF;
  RETURN QUERY
  SELECT * FROM app.private_tenant_ldap_sync_run_projection_v1(
    p_binding_id, p_sync_run_id, NULL, 1
  );
  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant LDAP sync run was not found'
      USING ERRCODE = 'P0002';
  END IF;
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.get_tenant_ldap_sync_status_v1(p_binding_id uuid)
RETURNS TABLE (
  binding_id uuid, schedule_state text, sync_interval_seconds integer,
  active_run_id uuid, last_run_id uuid, last_run_state text,
  last_completed_at timestamptz, next_scheduled_at timestamptz,
  version integer, updated_at timestamptz
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
BEGIN
  IF p_binding_id IS NULL
     OR (uuid_extract_version(p_binding_id) = 7) IS NOT TRUE THEN
    RAISE EXCEPTION 'tenant LDAP sync status input is invalid'
      USING ERRCODE = '22023';
  END IF;
  IF NOT app.current_tenant_human_has_exact_permission_v3(
    'identity_provider.read', 'tenant'
  ) THEN
    RAISE EXCEPTION 'identity_provider.read tenant scope is required'
      USING ERRCODE = '42501';
  END IF;
  RETURN QUERY
  WITH status_base AS (
    SELECT binding.id AS selected_binding_id,
           binding.version AS selected_binding_version,
           greatest(binding.updated_at, config.updated_at) AS configured_at,
           binding.enabled AND binding.archived_at IS NULL
             AND provider.enabled AND provider.archived_at IS NULL
             AND provider.kind = 'ldap'
             AND config.sync_interval_seconds IS NOT NULL AS schedule_enabled,
           config.sync_interval_seconds,
           active_run.id AS selected_active_run_id,
           active_run.status AS selected_active_state,
           last_run.id AS selected_last_run_id,
           last_run.status AS selected_last_state,
           last_run.queued_at AS last_queued_at,
           last_run.enumeration_started_at AS last_started_at,
           last_run.enumeration_completed_at AS last_enumerated_at,
           last_run.completed_at AS selected_last_completed_at
    FROM public.tenant_auth_provider_bindings AS binding
    JOIN public.tenant_auth_providers AS provider
      ON provider.tenant_id = binding.tenant_id
     AND provider.id = binding.provider_id
    JOIN public.tenant_ldap_provider_configs AS config
      ON config.tenant_id = provider.tenant_id
     AND config.provider_id = provider.id
    LEFT JOIN LATERAL (
      SELECT run.id, run.status
      FROM public.tenant_ldap_sync_runs AS run
      WHERE run.tenant_id = binding.tenant_id
        AND run.binding_id = binding.id
        AND run.status IN ('queued', 'enumerating', 'applying')
      ORDER BY run.queued_at, run.id
      LIMIT 1
    ) AS active_run ON true
    LEFT JOIN LATERAL (
      SELECT run.id, run.status, run.queued_at,
             run.enumeration_started_at, run.enumeration_completed_at,
             run.completed_at
      FROM public.tenant_ldap_sync_runs AS run
      WHERE run.tenant_id = binding.tenant_id
        AND run.binding_id = binding.id
      ORDER BY run.queued_at DESC, run.id DESC
      LIMIT 1
    ) AS last_run ON true
    WHERE binding.tenant_id = context_tenant
      AND binding.id = p_binding_id
  ), calculated AS (
    SELECT status_base.*,
           CASE
             WHEN status_base.schedule_enabled
               AND status_base.selected_active_run_id IS NULL THEN
               coalesce(
                 status_base.selected_last_completed_at,
                 status_base.last_enumerated_at,
                 status_base.last_started_at,
                 status_base.last_queued_at,
                 status_base.configured_at
               ) + make_interval(
                 secs => status_base.sync_interval_seconds
               )
             ELSE NULL
           END AS due_at,
           greatest(
             status_base.configured_at,
             coalesce(status_base.last_queued_at, status_base.configured_at),
             coalesce(status_base.last_started_at, status_base.configured_at),
             coalesce(status_base.last_enumerated_at, status_base.configured_at),
             coalesce(
               status_base.selected_last_completed_at,
               status_base.configured_at
             )
           ) AS status_updated_at
    FROM status_base
  )
  SELECT calculated.selected_binding_id,
         CASE
           WHEN NOT calculated.schedule_enabled THEN 'disabled'
           WHEN calculated.selected_active_state = 'queued' THEN 'queued'
           WHEN calculated.selected_active_state IN ('enumerating', 'applying')
             THEN 'running'
           WHEN calculated.selected_last_state IN ('failed', 'cancelled', 'stale')
             AND calculated.due_at > transaction_timestamp() THEN 'backoff'
           ELSE 'idle'
         END,
         CASE WHEN calculated.schedule_enabled
           THEN calculated.sync_interval_seconds ELSE NULL END,
         CASE WHEN calculated.schedule_enabled
           THEN calculated.selected_active_run_id ELSE NULL END,
         calculated.selected_last_run_id,
         calculated.selected_last_state::text,
         calculated.selected_last_completed_at,
         calculated.due_at,
         calculated.selected_binding_version,
         calculated.status_updated_at
  FROM calculated;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant LDAP binding was not found'
      USING ERRCODE = 'P0002';
  END IF;
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.begin_tenant_ldap_manual_sync_run_v2(
  p_idempotency_key_digest bytea,
  p_request_digest bytea,
  p_sync_run_id uuid,
  p_binding_id uuid,
  p_expected_binding_version integer,
  p_reason text,
  p_audit_event_id uuid,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text
)
RETURNS TABLE (sync_run_id uuid, replayed boolean)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  actor_membership uuid;
  command_row public.tenant_authorization_commands%ROWTYPE;
  existing_run public.tenant_ldap_sync_runs%ROWTYPE;
  current_binding_version integer;
  started record;
BEGIN
  IF p_idempotency_key_digest IS NULL
     OR octet_length(p_idempotency_key_digest) <> 32
     OR p_idempotency_key_digest = decode(repeat('00', 32), 'hex')
     OR p_request_digest IS NULL OR octet_length(p_request_digest) <> 32
     OR p_request_digest = decode(repeat('00', 32), 'hex')
     OR p_sync_run_id IS NULL OR p_binding_id IS NULL
     OR p_audit_event_id IS NULL OR p_request_id IS NULL
     OR p_correlation_id IS NULL
     OR (uuid_extract_version(p_sync_run_id) = 7) IS NOT TRUE
     OR (uuid_extract_version(p_binding_id) = 7) IS NOT TRUE
     OR (uuid_extract_version(p_audit_event_id) = 7) IS NOT TRUE
     OR (uuid_extract_version(p_request_id) = 7) IS NOT TRUE
     OR (uuid_extract_version(p_correlation_id) = 7) IS NOT TRUE
     OR p_expected_binding_version IS NULL
     OR p_expected_binding_version NOT BETWEEN 1 AND 2147483647
     OR p_reason IS NULL OR p_reason <> btrim(p_reason)
     OR char_length(p_reason) NOT BETWEEN 1 AND 500
     OR p_reason ~ '[[:cntrl:]]' THEN
    RAISE EXCEPTION 'tenant LDAP manual sync input is invalid'
      USING ERRCODE = '22023';
  END IF;

  PERFORM app.lock_current_tenant_authorization_state();
  actor_membership := app.current_tenant_membership_id();
  IF NOT app.current_tenant_human_has_exact_permission_v3(
    'identity_sync.run', 'tenant'
  ) THEN
    RAISE EXCEPTION 'identity_sync.run tenant scope is required'
      USING ERRCODE = '42501';
  END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended(
    'tenant_ldap_manual_sync_idempotency:' || context_tenant::text || ':' ||
    actor_membership::text || ':' || encode(p_idempotency_key_digest, 'hex'),
    0
  ));

  DELETE FROM public.tenant_authorization_commands AS command
  WHERE command.tenant_id = context_tenant
    AND command.actor_membership_id = actor_membership
    AND command.operation = 'identity_sync.run'
    AND command.key_digest = p_idempotency_key_digest
    AND command.expires_at <= transaction_timestamp();

  SELECT command.* INTO command_row
  FROM public.tenant_authorization_commands AS command
  WHERE command.tenant_id = context_tenant
    AND command.actor_membership_id = actor_membership
    AND command.operation = 'identity_sync.run'
    AND command.key_digest = p_idempotency_key_digest;
  IF FOUND THEN
    IF command_row.request_digest IS DISTINCT FROM p_request_digest THEN
      RAISE EXCEPTION 'idempotency key was already used for a different request'
        USING ERRCODE = '23505',
              CONSTRAINT = 'tenant_authorization_commands_replay_key';
    END IF;
    SELECT run.* INTO existing_run
    FROM public.tenant_ldap_sync_runs AS run
    WHERE run.tenant_id = context_tenant
      AND run.id = command_row.result_resource_id;
    IF NOT FOUND
       OR command_row.result_version IS DISTINCT FROM 1
       OR existing_run.version < command_row.result_version
       OR existing_run.binding_id IS DISTINCT FROM p_binding_id
       OR existing_run.binding_version IS DISTINCT FROM p_expected_binding_version
       OR existing_run.trigger IS DISTINCT FROM 'manual'
       OR existing_run.reason IS DISTINCT FROM p_reason
       OR existing_run.started_by_membership_id IS DISTINCT FROM actor_membership THEN
      RAISE EXCEPTION 'identity-sync idempotency result is invalid'
        USING ERRCODE = '23503',
              CONSTRAINT = 'tenant_authorization_commands_result_fk';
    END IF;
    RETURN QUERY SELECT existing_run.id, true;
    RETURN;
  END IF;

  SELECT binding.version INTO current_binding_version
  FROM public.tenant_auth_provider_bindings AS binding
  WHERE binding.tenant_id = context_tenant AND binding.id = p_binding_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant LDAP binding was not found'
      USING ERRCODE = 'P0002';
  END IF;
  IF current_binding_version IS DISTINCT FROM p_expected_binding_version THEN
    RAISE EXCEPTION 'tenant LDAP binding version does not match If-Match'
      USING ERRCODE = '40001';
  END IF;

  SELECT * INTO started
  FROM app.begin_tenant_ldap_manual_sync_run_v1(
    p_sync_run_id, p_binding_id, p_reason, p_audit_event_id,
    p_request_id, p_correlation_id, p_ip_address,
    p_user_agent, p_authentication_method
  );
  IF started.replayed
     OR started.sync_run_id IS DISTINCT FROM p_sync_run_id
     OR started.binding_version IS DISTINCT FROM p_expected_binding_version
     OR started.status IS DISTINCT FROM 'queued' THEN
    RAISE EXCEPTION 'tenant LDAP manual sync identifier collided'
      USING ERRCODE = '23505',
            CONSTRAINT = 'tenant_ldap_sync_runs_tenant_id_key';
  END IF;

  INSERT INTO public.tenant_authorization_commands (
    tenant_id, actor_membership_id, operation, key_digest, request_digest,
    result_resource_id, result_version
  ) VALUES (
    context_tenant, actor_membership, 'identity_sync.run',
    p_idempotency_key_digest, p_request_digest, p_sync_run_id, 1
  );
  RETURN QUERY SELECT p_sync_run_id, false;
END;
$function$;
--> statement-breakpoint

ALTER FUNCTION app.private_tenant_ldap_sync_run_projection_v1(
  uuid, uuid, uuid, integer
) OWNER TO periapsis_ldap_administration_owner;
--> statement-breakpoint
ALTER FUNCTION app.list_tenant_ldap_sync_runs_v1(uuid, uuid, integer)
  OWNER TO periapsis_ldap_administration_owner;
--> statement-breakpoint
ALTER FUNCTION app.get_tenant_ldap_sync_run_v1(uuid, uuid)
  OWNER TO periapsis_ldap_administration_owner;
--> statement-breakpoint
ALTER FUNCTION app.get_tenant_ldap_sync_status_v1(uuid)
  OWNER TO periapsis_ldap_administration_owner;
--> statement-breakpoint
ALTER FUNCTION app.begin_tenant_ldap_manual_sync_run_v2(
  bytea, bytea, uuid, uuid, integer, text, uuid, uuid, uuid, inet, text, text
) OWNER TO periapsis_ldap_administration_owner;
--> statement-breakpoint

REVOKE ALL ON FUNCTION app.private_tenant_ldap_sync_run_projection_v1(
  uuid, uuid, uuid, integer
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.list_tenant_ldap_sync_runs_v1(uuid, uuid, integer),
  app.get_tenant_ldap_sync_run_v1(uuid, uuid),
  app.get_tenant_ldap_sync_status_v1(uuid),
  app.begin_tenant_ldap_manual_sync_run_v2(
    bytea, bytea, uuid, uuid, integer, text, uuid, uuid, uuid,
    inet, text, text
  )
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
     periapsis_auditor;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION
  app.list_tenant_ldap_sync_runs_v1(uuid, uuid, integer),
  app.get_tenant_ldap_sync_run_v1(uuid, uuid),
  app.get_tenant_ldap_sync_status_v1(uuid),
  app.begin_tenant_ldap_manual_sync_run_v2(
    bytea, bytea, uuid, uuid, integer, text, uuid, uuid, uuid,
    inet, text, text
  )
TO periapsis_api;
--> statement-breakpoint

-- v2 is the sole API mutation. The worker's scheduled v1 start remains
-- untouched; the API can no longer bypass the idempotency/version wrapper.
REVOKE EXECUTE ON FUNCTION app.begin_tenant_ldap_manual_sync_run_v1(
  uuid, uuid, text, uuid, uuid, uuid, inet, text, text
) FROM periapsis_api;
--> statement-breakpoint

-- v15 is the exact 91-migration projection. v14 is retained only as the
-- sealed 90-row rolling predecessor and v13 is retired.
CREATE FUNCTION app.schema_compatibility_v15()
RETURNS TABLE (
  applied_count bigint,
  latest_created_at bigint,
  latest_hash text,
  migration_fingerprint text
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
  journal_count bigint;
  journal_latest_created_at bigint;
  migration_0090_rows bigint;
BEGIN
  EXECUTE $query$
    SELECT count(*)::bigint, max(migration.created_at)::bigint,
           count(*) FILTER (
             WHERE migration.created_at = 1787673489517
           )::bigint
    FROM drizzle.__drizzle_migrations AS migration
  $query$ INTO journal_count, journal_latest_created_at, migration_0090_rows;
  IF journal_count = 91
     AND journal_latest_created_at = 1787673489517
     AND migration_0090_rows = 1 THEN
    RETURN QUERY EXECUTE $query$
      SELECT count(*)::bigint, max(migration.created_at)::bigint,
             (SELECT lower(latest.hash::text)
              FROM drizzle.__drizzle_migrations AS latest
              ORDER BY latest.created_at DESC, latest.id DESC LIMIT 1),
             string_agg(
               migration.created_at::text || '@' || lower(migration.hash::text),
               ':' ORDER BY migration.created_at, migration.id
             )
      FROM drizzle.__drizzle_migrations AS migration
    $query$;
    RETURN;
  END IF;
  RETURN QUERY SELECT 0::bigint, 0::bigint,
                      'UNSUPPORTED'::text, 'UNSUPPORTED'::text;
END;
$function$;
--> statement-breakpoint

ALTER FUNCTION app.schema_compatibility_v15() OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.schema_compatibility_v15()
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.schema_compatibility_v15()
  TO periapsis_api, periapsis_worker;
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.schema_compatibility_v14()
RETURNS TABLE (
  applied_count bigint,
  latest_created_at bigint,
  latest_hash text,
  migration_fingerprint text
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
SET app.schema_compatibility_fingerprint = 'UNSEALED'
AS $function$
DECLARE
  full_count bigint;
  full_latest_created_at bigint;
  full_fingerprint text;
BEGIN
  SELECT compatibility.applied_count, compatibility.latest_created_at,
         compatibility.migration_fingerprint
  INTO full_count, full_latest_created_at, full_fingerprint
  FROM app.schema_compatibility_v15() AS compatibility;
  IF full_count = 91
     AND full_latest_created_at = 1787673489517
     AND full_fingerprint = current_setting(
       'app.schema_compatibility_fingerprint', true
     ) THEN
    RETURN QUERY EXECUTE $query$
      WITH ordered_migrations AS (
        SELECT migration.id, migration.created_at,
               lower(migration.hash::text) AS migration_hash,
               row_number() OVER (
                 ORDER BY migration.created_at, migration.id
               ) AS migration_ordinal
        FROM drizzle.__drizzle_migrations AS migration
      )
      SELECT count(*)::bigint, max(migration.created_at)::bigint,
             (SELECT prefix.migration_hash
              FROM ordered_migrations AS prefix
              WHERE prefix.migration_ordinal = 90),
             string_agg(
               migration.created_at::text || '@' || migration.migration_hash,
               ':' ORDER BY migration.created_at, migration.id
             )
      FROM ordered_migrations AS migration
      WHERE migration.migration_ordinal <= 90
    $query$;
    RETURN;
  END IF;
  RETURN QUERY SELECT 0::bigint, 0::bigint,
                      'UNSUPPORTED'::text, 'UNSUPPORTED'::text;
END;
$function$;
--> statement-breakpoint

ALTER FUNCTION app.schema_compatibility_v14() OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.schema_compatibility_v14()
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.schema_compatibility_v14()
  TO periapsis_api, periapsis_worker;
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.schema_compatibility_v13()
RETURNS TABLE (
  applied_count bigint,
  latest_created_at bigint,
  latest_hash text,
  migration_fingerprint text
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
BEGIN
  RETURN QUERY SELECT 0::bigint, 0::bigint,
                      'UNSUPPORTED'::text, 'UNSUPPORTED'::text;
END;
$function$;
--> statement-breakpoint

ALTER FUNCTION app.schema_compatibility_v13() OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.schema_compatibility_v13()
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.schema_compatibility_v13()
  TO periapsis_api, periapsis_worker;
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.seal_schema_compatibility_manifest(
  p_expected_count bigint,
  p_expected_latest_created_at bigint,
  p_expected_latest_hash text,
  p_expected_migration_fingerprint text
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
  fingerprint_entries text[];
  fingerprint_created_at bigint[];
  actual_count bigint;
  actual_latest_created_at bigint;
  actual_latest_hash text;
  actual_fingerprint text;
  predecessor_count bigint;
  predecessor_latest_created_at bigint;
  predecessor_latest_hash text;
  predecessor_fingerprint text;
  expected_predecessor_hash text;
  expected_predecessor_fingerprint text;
  retired_count bigint;
BEGIN
  fingerprint_entries := string_to_array(
    p_expected_migration_fingerprint, ':'
  );
  IF p_expected_count IS DISTINCT FROM 91
     OR p_expected_latest_created_at IS DISTINCT FROM 1787673489517
     OR p_expected_latest_hash IS NULL
     OR p_expected_latest_hash !~ '^[0-9a-f]{64}$'
     OR p_expected_migration_fingerprint IS NULL
     OR p_expected_migration_fingerprint !~
          '^[1-9][0-9]*@[0-9a-f]{64}(:[1-9][0-9]*@[0-9a-f]{64})*$'
     OR cardinality(fingerprint_entries) IS DISTINCT FROM 91
     OR fingerprint_entries[91] IS DISTINCT FROM (
       p_expected_latest_created_at::text || '@' || p_expected_latest_hash
     ) THEN
    RAISE EXCEPTION 'invalid schema compatibility v15 manifest'
      USING ERRCODE = '22023';
  END IF;

  SELECT array_agg(
    split_part(entry.value, '@', 1)::bigint ORDER BY entry.ordinality
  ) INTO fingerprint_created_at
  FROM unnest(fingerprint_entries) WITH ORDINALITY
       AS entry(value, ordinality);
  IF fingerprint_created_at IS DISTINCT FROM ARRAY[
    1787472409685, 1787472415216, 1787473527702, 1787473536723,
    1787474082034, 1787474089267, 1787475027656, 1787475184077,
    1787488565252, 1787488569966, 1787492910536, 1787493031146,
    1787494284382, 1787495115125, 1787495293635, 1787495819997,
    1787495999394, 1787496124539, 1787496880587, 1787496982733,
    1787496987011, 1787501702276, 1787506296280, 1787507888755,
    1787508523197, 1787516694668, 1787571776845, 1787581350373,
    1787581530382, 1787582150087, 1787591930962, 1787591938733,
    1787592230466, 1787612620574, 1787613580320, 1787613592459,
    1787613744526, 1787613746038, 1787613747552, 1787613749000,
    1787635396524, 1787635417084, 1787635433516, 1787635452090,
    1787635459707, 1787635471570, 1787635525474, 1787635788324,
    1787635828723, 1787637794128, 1787637795761, 1787643146844,
    1787643153628, 1787643609827, 1787648180127, 1787648190820,
    1787648201836, 1787648215689, 1787648225321, 1787649465766,
    1787649478666, 1787649523649, 1787649541586, 1787650610199,
    1787650730983, 1787653130160, 1787653143051, 1787653149806,
    1787653151267, 1787653305313, 1787655186569, 1787655192148,
    1787655197869, 1787655813403, 1787655819028, 1787655824109,
    1787657661213, 1787657666680, 1787658281433, 1787658434202,
    1787659622481, 1787659623982, 1787664581262, 1787664767505,
    1787664955067, 1787665119323, 1787665128173, 1787672101246,
    1787672114811, 1787672134042, 1787673489517
  ]::bigint[] THEN
    RAISE EXCEPTION 'invalid schema compatibility v15 timestamp sequence'
      USING ERRCODE = '22023';
  END IF;

  SELECT compatibility.applied_count, compatibility.latest_created_at,
         compatibility.latest_hash, compatibility.migration_fingerprint
  INTO actual_count, actual_latest_created_at, actual_latest_hash,
       actual_fingerprint
  FROM app.schema_compatibility_v15() AS compatibility;
  IF actual_count IS DISTINCT FROM p_expected_count
     OR actual_latest_created_at IS DISTINCT FROM p_expected_latest_created_at
     OR actual_latest_hash IS DISTINCT FROM p_expected_latest_hash
     OR actual_fingerprint IS DISTINCT FROM p_expected_migration_fingerprint THEN
    RAISE EXCEPTION 'schema compatibility v15 manifest does not match the applied journal'
      USING ERRCODE = '55000';
  END IF;

  PERFORM set_config(
    'app.schema_compatibility_fingerprint',
    p_expected_migration_fingerprint, true
  );
  EXECUTE $statement$
    ALTER FUNCTION app.schema_compatibility_v14()
      SET app.schema_compatibility_fingerprint FROM CURRENT
  $statement$;
  expected_predecessor_hash := split_part(fingerprint_entries[90], '@', 2);
  expected_predecessor_fingerprint := array_to_string(
    fingerprint_entries[1:90], ':'
  );
  SELECT compatibility.applied_count, compatibility.latest_created_at,
         compatibility.latest_hash, compatibility.migration_fingerprint
  INTO predecessor_count, predecessor_latest_created_at,
       predecessor_latest_hash, predecessor_fingerprint
  FROM app.schema_compatibility_v14() AS compatibility;
  IF predecessor_count IS DISTINCT FROM 90
     OR predecessor_latest_created_at IS DISTINCT FROM 1787672134042
     OR predecessor_latest_hash IS DISTINCT FROM expected_predecessor_hash
     OR predecessor_fingerprint IS DISTINCT FROM expected_predecessor_fingerprint THEN
    RAISE EXCEPTION 'sealed schema compatibility v14 prefix is not exact'
      USING ERRCODE = '55000';
  END IF;
  SELECT compatibility.applied_count INTO retired_count
  FROM app.schema_compatibility_v13() AS compatibility;
  IF retired_count IS DISTINCT FROM 0 THEN
    RAISE EXCEPTION 'schema compatibility v13 must be retired'
      USING ERRCODE = '55000';
  END IF;
END;
$function$;
--> statement-breakpoint

ALTER FUNCTION app.seal_schema_compatibility_manifest(bigint, bigint, text, text)
  OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.seal_schema_compatibility_manifest(
  bigint, bigint, text, text
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor;
--> statement-breakpoint

CREATE FUNCTION app.ldap_administration_schema_readiness_v1()
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  relation_name text;
  relation_owner text;
  relation_rls boolean;
  relation_force_rls boolean;
  expected_function record;
  function_oid regprocedure;
  function_owner text;
  function_security_definer boolean;
  function_configuration text[];
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_roles AS role
    WHERE role.rolname = 'periapsis_ldap_administration_owner'
      AND NOT role.rolcanlogin AND NOT role.rolsuper
      AND NOT role.rolcreatedb AND NOT role.rolcreaterole
      AND NOT role.rolinherit AND NOT role.rolreplication
      AND NOT role.rolbypassrls
  ) THEN
    RETURN false;
  END IF;

  FOREACH relation_name IN ARRAY ARRAY[
    'tenant_authorization_commands',
    'tenant_auth_provider_bindings',
    'tenant_auth_providers',
    'tenant_ldap_provider_configs',
    'tenant_ldap_mapping_rule_epochs',
    'tenant_ldap_sync_runs',
    'tenant_ldap_sync_run_mappings',
    'tenant_ldap_sync_staged_observations'
  ] LOOP
    SELECT pg_get_userbyid(class.relowner), class.relrowsecurity,
           class.relforcerowsecurity
    INTO relation_owner, relation_rls, relation_force_rls
    FROM pg_class AS class
    JOIN pg_namespace AS namespace ON namespace.oid = class.relnamespace
    WHERE namespace.nspname = 'public'
      AND class.relname = relation_name
      AND class.relkind = 'r';
    IF NOT FOUND OR relation_owner IS DISTINCT FROM 'periapsis_migrator'
       OR relation_rls IS NOT TRUE OR relation_force_rls IS NOT TRUE THEN
      RETURN false;
    END IF;
    IF NOT EXISTS (
      SELECT 1
      FROM pg_attribute AS attribute
      JOIN pg_class AS class ON class.oid = attribute.attrelid
      JOIN pg_namespace AS namespace ON namespace.oid = class.relnamespace
      WHERE namespace.nspname = 'public'
        AND class.relname = relation_name
        AND attribute.attname = 'tenant_id'
        AND attribute.attnotnull
        AND NOT attribute.attisdropped
    ) THEN
      RETURN false;
    END IF;
    IF NOT has_table_privilege(
      'periapsis_ldap_administration_owner',
      format('public.%I', relation_name), 'SELECT'
    ) OR relation_name = 'tenant_authorization_commands' AND (
      NOT has_table_privilege(
        'periapsis_ldap_administration_owner',
        'public.tenant_authorization_commands', 'INSERT'
      ) OR NOT has_table_privilege(
        'periapsis_ldap_administration_owner',
        'public.tenant_authorization_commands', 'DELETE'
      )
    ) THEN
      RETURN false;
    END IF;
    IF has_table_privilege(
      'periapsis_api', format('public.%I', relation_name),
      'SELECT,INSERT,UPDATE,DELETE'
    ) OR has_table_privilege(
      'periapsis_worker', format('public.%I', relation_name),
      'SELECT,INSERT,UPDATE,DELETE'
    ) OR has_table_privilege(
      'periapsis_notifier', format('public.%I', relation_name),
      'SELECT,INSERT,UPDATE,DELETE'
    ) THEN
      RETURN false;
    END IF;
  END LOOP;

  IF (
    SELECT count(*)
    FROM pg_policy AS policy
    JOIN pg_class AS class ON class.oid = policy.polrelid
    JOIN pg_namespace AS namespace ON namespace.oid = class.relnamespace
    WHERE namespace.nspname = 'public'
      AND policy.polname IN (
        'ldap_admin_owner_bindings_v1', 'ldap_admin_owner_providers_v1',
        'ldap_admin_owner_configs_v1', 'ldap_admin_owner_mapping_epochs_v1',
        'ldap_admin_owner_sync_runs_v1', 'ldap_admin_owner_sync_mappings_v1',
        'ldap_admin_owner_sync_staging_v1', 'ldap_admin_owner_commands_v1'
      )
      AND (SELECT oid FROM pg_roles
           WHERE rolname = 'periapsis_ldap_administration_owner') = ANY(policy.polroles)
  ) <> 8 THEN
    RETURN false;
  END IF;

  FOR expected_function IN
    SELECT * FROM (VALUES
      ('app.private_tenant_ldap_sync_run_projection_v1(uuid,uuid,uuid,integer)', 'periapsis_ldap_administration_owner', false, false, 'search_path=pg_catalog, public, app', false),
      ('app.list_tenant_ldap_sync_runs_v1(uuid,uuid,integer)', 'periapsis_ldap_administration_owner', true, false, 'search_path=pg_catalog, public, app', false),
      ('app.get_tenant_ldap_sync_run_v1(uuid,uuid)', 'periapsis_ldap_administration_owner', true, false, 'search_path=pg_catalog, public, app', false),
      ('app.get_tenant_ldap_sync_status_v1(uuid)', 'periapsis_ldap_administration_owner', true, false, 'search_path=pg_catalog, public, app', false),
      ('app.begin_tenant_ldap_manual_sync_run_v2(bytea,bytea,uuid,uuid,integer,text,uuid,uuid,uuid,inet,text,text)', 'periapsis_ldap_administration_owner', true, false, 'search_path=pg_catalog, public, app', false),
      ('app.schema_compatibility_v15()', 'periapsis_migrator', true, true, 'search_path=pg_catalog', false),
      ('app.schema_compatibility_v14()', 'periapsis_migrator', true, true, 'search_path=pg_catalog', true),
      ('app.schema_compatibility_v13()', 'periapsis_migrator', true, true, 'search_path=pg_catalog', false),
      ('app.seal_schema_compatibility_manifest(bigint,bigint,text,text)', 'periapsis_migrator', false, false, 'search_path=pg_catalog', false)
    ) AS expected(
      signature, expected_owner, api_execute, worker_execute,
      expected_search_path, allow_fingerprint
    )
  LOOP
    function_oid := to_regprocedure(expected_function.signature);
    IF function_oid IS NULL THEN
      RETURN false;
    END IF;
    SELECT pg_get_userbyid(procedure.proowner), procedure.prosecdef,
           procedure.proconfig
    INTO function_owner, function_security_definer, function_configuration
    FROM pg_proc AS procedure
    WHERE procedure.oid = function_oid;
    IF function_owner IS DISTINCT FROM expected_function.expected_owner
       OR function_security_definer IS NOT TRUE
       OR function_configuration[1] IS DISTINCT FROM
          expected_function.expected_search_path
       OR NOT expected_function.allow_fingerprint
          AND cardinality(function_configuration) IS DISTINCT FROM 1
       OR expected_function.allow_fingerprint AND (
         cardinality(function_configuration) IS DISTINCT FROM 2
         OR function_configuration[2] !~
            '^app\.schema_compatibility_fingerprint=(UNSEALED|[1-9][0-9]*@[0-9a-f]{64}(:[1-9][0-9]*@[0-9a-f]{64})*)$'
       ) THEN
      RETURN false;
    END IF;
    IF EXISTS (
      SELECT 1
      FROM pg_proc AS procedure
      CROSS JOIN LATERAL aclexplode(
        coalesce(procedure.proacl, acldefault('f', procedure.proowner))
      ) AS privilege
      WHERE procedure.oid = function_oid
        AND privilege.grantee = 0
        AND privilege.privilege_type = 'EXECUTE'
    ) OR has_function_privilege(
      'periapsis_api', function_oid, 'EXECUTE'
    ) IS DISTINCT FROM expected_function.api_execute
      OR has_function_privilege(
        'periapsis_worker', function_oid, 'EXECUTE'
      ) IS DISTINCT FROM expected_function.worker_execute
      OR has_function_privilege(
        'periapsis_notifier', function_oid, 'EXECUTE'
      ) OR has_function_privilege(
        'periapsis_auditor', function_oid, 'EXECUTE'
      ) THEN
      RETURN false;
    END IF;
  END LOOP;

  IF has_function_privilege(
    'periapsis_api',
    'app.begin_tenant_ldap_manual_sync_run_v1(uuid,uuid,text,uuid,uuid,uuid,inet,text,text)',
    'EXECUTE'
  ) OR (
    SELECT count(*)
    FROM public.tenant_permissions AS permission
    JOIN public.tenant_permission_scopes AS scope
      ON scope.permission_id = permission.id
    WHERE permission.key = 'identity_sync.run'
      AND permission.service_account_allowed IS FALSE
      AND scope.scope = 'tenant'
  ) <> 1 OR pg_get_constraintdef(
    (SELECT constraint_row.oid
     FROM pg_constraint AS constraint_row
     WHERE constraint_row.conname =
       'tenant_authorization_commands_operation_check')
  ) NOT LIKE '%identity_sync.run%'
    OR (SELECT procedure.prosrc
        FROM pg_proc AS procedure
        WHERE procedure.oid =
          'app.guard_tenant_authorization_command()'::regprocedure)
       NOT LIKE '%NEW.operation = ''identity_sync.run''%' THEN
    RETURN false;
  END IF;
  RETURN true;
END;
$function$;
--> statement-breakpoint

ALTER FUNCTION app.ldap_administration_schema_readiness_v1()
  OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.ldap_administration_schema_readiness_v1()
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.ldap_administration_schema_readiness_v1()
  TO periapsis_api, periapsis_worker;
--> statement-breakpoint

DO $ldap_administration_readiness_assertion$
BEGIN
  IF NOT app.ldap_administration_schema_readiness_v1() THEN
    RAISE EXCEPTION 'LDAP administration schema readiness invariants are incomplete'
      USING ERRCODE = '55000';
  END IF;
END;
$ldap_administration_readiness_assertion$;
