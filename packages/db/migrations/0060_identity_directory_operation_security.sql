-- Custom SQL migration file, put your code below! --
ALTER TYPE public.ldap_directory_operation_kind OWNER TO periapsis_migrator;--> statement-breakpoint

ALTER TABLE public.tenant_ldap_directory_operation_runs OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TABLE public.tenant_ldap_directory_run_mappings OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TABLE public.tenant_ldap_directory_operation_runs FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE public.tenant_ldap_directory_run_mappings FORCE ROW LEVEL SECURITY;--> statement-breakpoint

REVOKE ALL ON TABLE public.tenant_ldap_directory_operation_runs
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON TABLE public.tenant_ldap_directory_run_mappings
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint

-- Establish a non-zero revision for every pre-existing rule set before the
-- trigger begins maintaining the hidden binding-level planner revision.
UPDATE public.tenant_auth_provider_bindings AS binding
SET mapping_revision = 1 + (
  SELECT count(*)::integer
  FROM public.tenant_ldap_mapping_rules AS rule
  WHERE rule.tenant_id = binding.tenant_id
    AND rule.binding_id = binding.id
);--> statement-breakpoint

CREATE FUNCTION app.bump_tenant_ldap_mapping_rule_set_revision_v1()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  target_tenant uuid := CASE WHEN TG_OP = 'DELETE' THEN OLD.tenant_id ELSE NEW.tenant_id END;
  target_binding uuid := CASE WHEN TG_OP = 'DELETE' THEN OLD.binding_id ELSE NEW.binding_id END;
BEGIN
  IF TG_OP = 'UPDATE'
     AND (NEW.tenant_id, NEW.binding_id) IS DISTINCT FROM
         (OLD.tenant_id, OLD.binding_id) THEN
    RAISE EXCEPTION 'tenant LDAP mapping binding identity is immutable'
      USING ERRCODE = '55000';
  END IF;

  UPDATE public.tenant_auth_provider_bindings AS binding
  SET mapping_revision = binding.mapping_revision + 1
  WHERE binding.tenant_id = target_tenant
    AND binding.id = target_binding
    AND binding.mapping_revision < 9223372036854775807;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant LDAP mapping rule-set revision cannot advance'
      USING ERRCODE = '54000';
  END IF;
  IF TG_OP = 'DELETE' THEN
    RETURN OLD;
  END IF;
  RETURN NEW;
END;
$function$;--> statement-breakpoint

CREATE TRIGGER tenant_ldap_mapping_rules_bump_rule_set_revision
AFTER INSERT OR UPDATE OR DELETE ON public.tenant_ldap_mapping_rules
FOR EACH ROW
EXECUTE FUNCTION app.bump_tenant_ldap_mapping_rule_set_revision_v1();--> statement-breakpoint

CREATE FUNCTION app.guard_tenant_ldap_directory_operation_run_v1()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'tenant LDAP directory operation runs are append-only'
      USING ERRCODE = '55000';
  END IF;

  IF TG_OP = 'INSERT' THEN
    IF NOT EXISTS (
      SELECT 1
      FROM public.identity_keyring_versions AS keyring
      WHERE keyring.key_version = NEW.bind_secret_key_version
        AND keyring.retired_at IS NULL
    ) THEN
      RAISE EXCEPTION 'tenant LDAP directory snapshot key is unavailable'
        USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
  END IF;

  IF OLD.status <> 'started'
     OR NEW.status <> 'completed'
     OR NEW.version <> 2
     OR (
       to_jsonb(NEW) - ARRAY[
         'status', 'outcome', 'category', 'endpoint_priority', 'duration_ms',
         'matched_entry_count', 'result_truncated',
         'completed_by_membership_id', 'completed_at', 'version'
       ]::text[]
     ) IS DISTINCT FROM (
       to_jsonb(OLD) - ARRAY[
         'status', 'outcome', 'category', 'endpoint_priority', 'duration_ms',
         'matched_entry_count', 'result_truncated',
         'completed_by_membership_id', 'completed_at', 'version'
       ]::text[]
     )
     OR NOT (
       (NEW.outcome = 'success'
        AND NEW.category = 'success'
        AND NEW.endpoint_priority IS NOT NULL
        AND (NEW.operation_kind <> 'search_user'
             OR NEW.matched_entry_count <= 1))
       OR (NEW.outcome = 'inconclusive'
           AND NEW.category = 'stale_configuration'
           AND NEW.endpoint_priority IS NULL
           AND NEW.matched_entry_count = 0
           AND NOT NEW.result_truncated)
       OR (NEW.outcome = 'failure'
           AND NEW.category NOT IN ('success', 'stale_configuration')
           AND NEW.matched_entry_count = 0
           AND NOT NEW.result_truncated
           AND ((NEW.category = 'cancelled'
                 AND NEW.endpoint_priority IS NULL)
                OR (NEW.category <> 'cancelled'
                    AND NEW.endpoint_priority IS NOT NULL)))
     ) THEN
    RAISE EXCEPTION 'tenant LDAP directory operation transition is invalid'
      USING ERRCODE = '55000';
  END IF;
  RETURN NEW;
END;
$function$;--> statement-breakpoint

CREATE TRIGGER tenant_ldap_directory_operation_runs_guard
BEFORE INSERT OR UPDATE OR DELETE
ON public.tenant_ldap_directory_operation_runs
FOR EACH ROW
EXECUTE FUNCTION app.guard_tenant_ldap_directory_operation_run_v1();--> statement-breakpoint

CREATE FUNCTION app.guard_tenant_ldap_directory_run_mapping_v1()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF TG_OP <> 'INSERT' THEN
    RAISE EXCEPTION 'tenant LDAP directory mapping snapshots are immutable'
      USING ERRCODE = '55000';
  END IF;
  IF NOT EXISTS (
    SELECT 1
    FROM public.tenant_ldap_directory_operation_runs AS operation
    JOIN public.tenant_ldap_mapping_rules AS rule
      ON rule.tenant_id = operation.tenant_id
     AND rule.id = NEW.mapping_rule_id
     AND rule.binding_id = operation.binding_id
    LEFT JOIN public.tenant_ldap_mapping_rule_epochs AS epoch
      ON epoch.tenant_id = rule.tenant_id
     AND epoch.id = rule.current_source_epoch_id
    LEFT JOIN public.tenant_authorization_sources AS source
      ON source.tenant_id = epoch.tenant_id
     AND source.id = epoch.source_id
    WHERE operation.tenant_id = NEW.tenant_id
      AND operation.id = NEW.operation_run_id
      AND operation.binding_id = NEW.binding_id
      AND operation.status = 'started'
      AND operation.operation_kind = 'search_user'
      AND rule.version = NEW.mapping_version
      AND rule.configuration_revision = NEW.configuration_revision
      AND rule.archived_at IS NULL
      AND (
        (NOT NEW.included_disabled
         AND rule.enabled
         AND epoch.id = NEW.source_epoch_id
         AND epoch.sequence = NEW.source_epoch_sequence
         AND epoch.ended_at IS NULL
         AND source.id = NEW.authorization_source_id
         AND source.kind = 'identity_mapping'
         AND source.retired_at IS NULL)
        OR (NEW.included_disabled
            AND NOT rule.enabled
            AND rule.current_source_epoch_id IS NULL)
      )
  ) THEN
    RAISE EXCEPTION 'tenant LDAP directory mapping snapshot is not exact'
      USING ERRCODE = '23514',
            CONSTRAINT = 'tenant_ldap_directory_run_mappings_exact_check';
  END IF;
  RETURN NEW;
END;
$function$;--> statement-breakpoint

CREATE TRIGGER tenant_ldap_directory_run_mappings_guard
BEFORE INSERT OR UPDATE OR DELETE
ON public.tenant_ldap_directory_run_mappings
FOR EACH ROW
EXECUTE FUNCTION app.guard_tenant_ldap_directory_run_mapping_v1();--> statement-breakpoint

ALTER FUNCTION app.bump_tenant_ldap_mapping_rule_set_revision_v1()
  OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.guard_tenant_ldap_directory_operation_run_v1()
  OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.guard_tenant_ldap_directory_run_mapping_v1()
  OWNER TO periapsis_migrator;--> statement-breakpoint

REVOKE ALL ON FUNCTION app.bump_tenant_ldap_mapping_rule_set_revision_v1()
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.guard_tenant_ldap_directory_operation_run_v1()
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.guard_tenant_ldap_directory_run_mapping_v1()
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;
