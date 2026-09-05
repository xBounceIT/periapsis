ALTER TYPE public.ldap_jit_run_status OWNER TO periapsis_migrator;--> statement-breakpoint

ALTER TABLE public.tenant_ldap_jit_authentication_runs OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TABLE public.tenant_ldap_jit_run_mappings OWNER TO periapsis_migrator;--> statement-breakpoint

ALTER TABLE public.tenant_ldap_jit_authentication_runs FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE public.tenant_ldap_jit_run_mappings FORCE ROW LEVEL SECURITY;--> statement-breakpoint

REVOKE ALL ON TABLE public.tenant_ldap_jit_authentication_runs
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON TABLE public.tenant_ldap_jit_run_mappings
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint

CREATE POLICY tenant_ldap_jit_runs_migrator_all
ON public.tenant_ldap_jit_authentication_runs
FOR ALL TO periapsis_migrator
USING (true) WITH CHECK (true);--> statement-breakpoint

CREATE POLICY tenant_ldap_jit_run_mappings_migrator_all
ON public.tenant_ldap_jit_run_mappings
FOR ALL TO periapsis_migrator
USING (true) WITH CHECK (true);--> statement-breakpoint

CREATE FUNCTION app.guard_tenant_ldap_jit_run_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'tenant LDAP JIT authentication runs are append-only'
      USING ERRCODE = '42501';
  END IF;
  IF TG_OP = 'INSERT' THEN
    IF NEW.status <> 'network_pending' OR NEW.version <> 1 THEN
      RAISE EXCEPTION 'tenant LDAP JIT authentication run must begin pending'
        USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
  END IF;

  IF ROW(
    NEW.id, NEW.tenant_id, NEW.receipt_digest, NEW.provider_id,
    NEW.provider_kind, NEW.binding_id, NEW.provider_version,
    NEW.configuration_version, NEW.bind_secret_id,
    NEW.bind_secret_version, NEW.bind_secret_key_version,
    NEW.bind_secret_algorithm, NEW.endpoint_snapshot_digest,
    NEW.binding_version, NEW.binding_auth_revision,
    NEW.binding_access_epoch_id, NEW.rule_set_revision,
    NEW.authorization_revision, NEW.network_rate_key_digest,
    NEW.account_rate_key_digest, NEW.provider_rate_key_digest,
    NEW.begin_audit_event_id, NEW.request_id, NEW.correlation_id,
    NEW.started_at, NEW.expires_at
  ) IS DISTINCT FROM ROW(
    OLD.id, OLD.tenant_id, OLD.receipt_digest, OLD.provider_id,
    OLD.provider_kind, OLD.binding_id, OLD.provider_version,
    OLD.configuration_version, OLD.bind_secret_id,
    OLD.bind_secret_version, OLD.bind_secret_key_version,
    OLD.bind_secret_algorithm, OLD.endpoint_snapshot_digest,
    OLD.binding_version, OLD.binding_auth_revision,
    OLD.binding_access_epoch_id, OLD.rule_set_revision,
    OLD.authorization_revision, OLD.network_rate_key_digest,
    OLD.account_rate_key_digest, OLD.provider_rate_key_digest,
    OLD.begin_audit_event_id, OLD.request_id, OLD.correlation_id,
    OLD.started_at, OLD.expires_at
  ) OR NEW.version <> OLD.version + 1
     OR NOT (
       (OLD.status = 'network_pending' AND NEW.status = 'planning')
       OR (OLD.status IN ('network_pending', 'planning')
           AND NEW.status IN ('failed', 'stale', 'expired'))
       OR (OLD.status = 'planning'
           AND NEW.status IN ('succeeded', 'denied'))
     ) THEN
    RAISE EXCEPTION 'tenant LDAP JIT authentication transition is invalid'
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION app.guard_tenant_ldap_jit_run_mapping_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF TG_OP <> 'INSERT' THEN
    RAISE EXCEPTION 'tenant LDAP JIT mapping pins are append-only'
      USING ERRCODE = '42501';
  END IF;
  IF NOT EXISTS (
    SELECT 1
    FROM public.tenant_ldap_jit_authentication_runs AS run
    JOIN public.tenant_ldap_mapping_rules AS rule
      ON rule.tenant_id = NEW.tenant_id
     AND rule.id = NEW.mapping_rule_id
     AND rule.binding_id = NEW.binding_id
    JOIN public.tenant_ldap_mapping_rule_epochs AS epoch
      ON epoch.tenant_id = rule.tenant_id
     AND epoch.id = NEW.source_epoch_id
     AND epoch.mapping_rule_id = rule.id
     AND epoch.binding_id = rule.binding_id
     AND epoch.source_id = NEW.source_id
    WHERE run.tenant_id = NEW.tenant_id
      AND run.id = NEW.jit_run_id
      AND run.binding_id = NEW.binding_id
      AND run.status = 'network_pending'
      AND rule.enabled AND rule.archived_at IS NULL
      AND rule.current_source_epoch_id = epoch.id
      AND rule.version = NEW.mapping_version
      AND rule.configuration_revision = NEW.configuration_revision
      AND rule.priority = NEW.priority
      AND epoch.configuration_revision = NEW.configuration_revision
      AND epoch.ended_at IS NULL
  ) THEN
    RAISE EXCEPTION 'tenant LDAP JIT mapping pin is not exact'
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$function$;--> statement-breakpoint

CREATE TRIGGER tenant_ldap_jit_runs_guard
BEFORE INSERT OR UPDATE OR DELETE
ON public.tenant_ldap_jit_authentication_runs
FOR EACH ROW EXECUTE FUNCTION app.guard_tenant_ldap_jit_run_v1();--> statement-breakpoint

CREATE TRIGGER tenant_ldap_jit_run_mappings_guard
BEFORE INSERT OR UPDATE OR DELETE
ON public.tenant_ldap_jit_run_mappings
FOR EACH ROW EXECUTE FUNCTION app.guard_tenant_ldap_jit_run_mapping_v1();--> statement-breakpoint

ALTER FUNCTION app.guard_tenant_ldap_jit_run_v1() OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.guard_tenant_ldap_jit_run_mapping_v1() OWNER TO periapsis_migrator;--> statement-breakpoint

REVOKE ALL ON FUNCTION app.guard_tenant_ldap_jit_run_v1()
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.guard_tenant_ldap_jit_run_mapping_v1()
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint

GRANT USAGE ON TYPE public.ldap_jit_run_status TO periapsis_api;
