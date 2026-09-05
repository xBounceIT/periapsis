-- LDAP JIT/sync relations remain opaque to runtime roles. Every mutation is
-- performed through the bounded SECURITY DEFINER ABI added by 0067.
ALTER TABLE public.tenant_ldap_sync_runs OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TABLE public.tenant_ldap_sync_run_mappings OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TABLE public.tenant_ldap_sync_staged_observations OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TABLE public.tenant_ldap_identity_plan_applications OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TABLE public.tenant_ldap_sync_absences OWNER TO periapsis_migrator;--> statement-breakpoint

ALTER TABLE public.tenant_ldap_sync_runs FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE public.tenant_ldap_sync_run_mappings FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE public.tenant_ldap_sync_staged_observations FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE public.tenant_ldap_identity_plan_applications FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE public.tenant_ldap_sync_absences FORCE ROW LEVEL SECURITY;--> statement-breakpoint

REVOKE ALL ON TABLE public.tenant_ldap_sync_runs FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON TABLE public.tenant_ldap_sync_run_mappings FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON TABLE public.tenant_ldap_sync_staged_observations FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON TABLE public.tenant_ldap_identity_plan_applications FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON TABLE public.tenant_ldap_sync_absences FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint

CREATE POLICY tenant_ldap_sync_runs_migrator_all
ON public.tenant_ldap_sync_runs
AS PERMISSIVE FOR ALL TO periapsis_migrator
USING (true) WITH CHECK (true);--> statement-breakpoint
CREATE POLICY tenant_ldap_sync_run_mappings_migrator_all
ON public.tenant_ldap_sync_run_mappings
AS PERMISSIVE FOR ALL TO periapsis_migrator
USING (true) WITH CHECK (true);--> statement-breakpoint
CREATE POLICY tenant_ldap_sync_staged_observations_migrator_all
ON public.tenant_ldap_sync_staged_observations
AS PERMISSIVE FOR ALL TO periapsis_migrator
USING (true) WITH CHECK (true);--> statement-breakpoint
CREATE POLICY tenant_ldap_identity_plan_applications_migrator_all
ON public.tenant_ldap_identity_plan_applications
AS PERMISSIVE FOR ALL TO periapsis_migrator
USING (true) WITH CHECK (true);--> statement-breakpoint
CREATE POLICY tenant_ldap_sync_absences_migrator_all
ON public.tenant_ldap_sync_absences
AS PERMISSIVE FOR ALL TO periapsis_migrator
USING (true) WITH CHECK (true);--> statement-breakpoint

CREATE FUNCTION app.guard_tenant_ldap_sync_run_v1()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'tenant LDAP sync runs are append-only'
      USING ERRCODE = '55000';
  END IF;
  IF TG_OP = 'INSERT' THEN
    IF NEW.status <> 'queued' OR NEW.version <> 1 THEN
      RAISE EXCEPTION 'tenant LDAP sync run must begin queued'
        USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
  END IF;
  IF ROW(
    NEW.id, NEW.tenant_id, NEW.provider_id, NEW.provider_kind,
    NEW.binding_id, NEW.trigger, NEW.provider_version,
    NEW.configuration_version, NEW.binding_version,
    NEW.binding_auth_revision, NEW.binding_access_epoch_id,
    NEW.rule_set_revision, NEW.authorization_revision,
    NEW.bind_secret_id, NEW.bind_secret_version,
    NEW.bind_secret_key_version, NEW.bind_secret_algorithm,
    NEW.endpoint_snapshot_digest, NEW.reason,
    NEW.started_by_membership_id, NEW.request_id, NEW.correlation_id,
    NEW.queued_at
  ) IS DISTINCT FROM ROW(
    OLD.id, OLD.tenant_id, OLD.provider_id, OLD.provider_kind,
    OLD.binding_id, OLD.trigger, OLD.provider_version,
    OLD.configuration_version, OLD.binding_version,
    OLD.binding_auth_revision, OLD.binding_access_epoch_id,
    OLD.rule_set_revision, OLD.authorization_revision,
    OLD.bind_secret_id, OLD.bind_secret_version,
    OLD.bind_secret_key_version, OLD.bind_secret_algorithm,
    OLD.endpoint_snapshot_digest, OLD.reason,
    OLD.started_by_membership_id, OLD.request_id, OLD.correlation_id,
    OLD.queued_at
  ) THEN
    RAISE EXCEPTION 'tenant LDAP sync run pins are immutable'
      USING ERRCODE = '55000';
  END IF;
  IF OLD.status IN ('succeeded', 'failed', 'cancelled', 'stale') THEN
    RAISE EXCEPTION 'terminal tenant LDAP sync run cannot change'
      USING ERRCODE = '55000';
  END IF;
  IF NOT (
    (OLD.status = 'queued' AND NEW.status IN (
      'enumerating', 'failed', 'cancelled', 'stale'
    )) OR
    (OLD.status = 'enumerating' AND NEW.status IN (
      'applying', 'failed', 'cancelled', 'stale'
    )) OR
    (OLD.status = 'applying' AND NEW.status IN (
      'applying', 'succeeded', 'failed', 'cancelled', 'stale'
    ))
  ) THEN
    RAISE EXCEPTION 'tenant LDAP sync run transition is invalid'
      USING ERRCODE = '55000';
  END IF;
  IF NEW.version <> OLD.version + 1
     AND NOT (OLD.status = 'applying' AND NEW.status = 'applying'
       AND NEW.version = OLD.version) THEN
    RAISE EXCEPTION 'tenant LDAP sync run version transition is invalid'
      USING ERRCODE = '55000';
  END IF;
  RETURN NEW;
END;
$function$;--> statement-breakpoint

CREATE TRIGGER tenant_ldap_sync_runs_guard_v1
BEFORE INSERT OR UPDATE OR DELETE ON public.tenant_ldap_sync_runs
FOR EACH ROW EXECUTE FUNCTION app.guard_tenant_ldap_sync_run_v1();--> statement-breakpoint

CREATE FUNCTION app.guard_tenant_ldap_sync_run_mapping_v1()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF TG_OP <> 'INSERT' THEN
    RAISE EXCEPTION 'tenant LDAP sync mapping pins are append-only'
      USING ERRCODE = '55000';
  END IF;
  IF NOT EXISTS (
    SELECT 1
    FROM public.tenant_ldap_sync_runs AS run
    WHERE run.tenant_id = NEW.tenant_id
      AND run.id = NEW.sync_run_id
      AND run.binding_id = NEW.binding_id
      AND run.status = 'queued'
  ) THEN
    RAISE EXCEPTION 'tenant LDAP sync mapping requires a queued exact run'
      USING ERRCODE = '55000';
  END IF;
  RETURN NEW;
END;
$function$;--> statement-breakpoint

CREATE TRIGGER tenant_ldap_sync_run_mappings_guard_v1
BEFORE INSERT OR UPDATE OR DELETE ON public.tenant_ldap_sync_run_mappings
FOR EACH ROW EXECUTE FUNCTION app.guard_tenant_ldap_sync_run_mapping_v1();--> statement-breakpoint

CREATE FUNCTION app.guard_tenant_ldap_sync_staged_observation_v1()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  run_status public.ldap_sync_run_status;
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'tenant LDAP sync observations are append-only'
      USING ERRCODE = '55000';
  END IF;
  SELECT run.status INTO run_status
  FROM public.tenant_ldap_sync_runs AS run
  WHERE run.tenant_id = coalesce(NEW.tenant_id, OLD.tenant_id)
    AND run.id = coalesce(NEW.sync_run_id, OLD.sync_run_id);
  IF TG_OP = 'INSERT' THEN
    IF run_status IS DISTINCT FROM 'enumerating' THEN
      RAISE EXCEPTION 'tenant LDAP observation requires an enumerating run'
        USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
  END IF;
  IF run_status IS DISTINCT FROM 'applying'
     OR ROW(
       NEW.id, NEW.tenant_id, NEW.sync_run_id, NEW.provider_id,
       NEW.ordinal, NEW.digest_key_version, NEW.subject_digest,
       NEW.observation_digest, NEW.staged_at
     ) IS DISTINCT FROM ROW(
       OLD.id, OLD.tenant_id, OLD.sync_run_id, OLD.provider_id,
       OLD.ordinal, OLD.digest_key_version, OLD.subject_digest,
       OLD.observation_digest, OLD.staged_at
     ) OR OLD.applied_at IS NOT NULL OR NEW.applied_at IS NULL
     OR NEW.apply_attempt <> OLD.apply_attempt + 1 THEN
    RAISE EXCEPTION 'tenant LDAP observation apply transition is invalid'
      USING ERRCODE = '55000';
  END IF;
  RETURN NEW;
END;
$function$;--> statement-breakpoint

CREATE TRIGGER tenant_ldap_sync_staged_observations_guard_v1
BEFORE INSERT OR UPDATE OR DELETE ON public.tenant_ldap_sync_staged_observations
FOR EACH ROW EXECUTE FUNCTION app.guard_tenant_ldap_sync_staged_observation_v1();--> statement-breakpoint

CREATE FUNCTION app.guard_tenant_ldap_identity_plan_application_v1()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF TG_OP <> 'INSERT' THEN
    RAISE EXCEPTION 'tenant LDAP identity plan applications are append-only'
      USING ERRCODE = '55000';
  END IF;
  IF NEW.apply_mode = 'sync' AND NOT EXISTS (
    SELECT 1
    FROM public.tenant_ldap_sync_runs AS run
    JOIN public.tenant_ldap_sync_staged_observations AS observation
      ON observation.tenant_id = run.tenant_id
     AND observation.sync_run_id = run.id
     AND observation.id = NEW.sync_observation_id
    WHERE run.tenant_id = NEW.tenant_id
      AND run.id = NEW.sync_run_id
      AND run.binding_id = NEW.binding_id
      AND run.provider_id = NEW.provider_id
      AND run.status = 'applying'
      AND observation.observation_digest = NEW.plan_digest
  ) THEN
    RAISE EXCEPTION 'sync plan application has no exact staged observation'
      USING ERRCODE = '55000';
  END IF;
  RETURN NEW;
END;
$function$;--> statement-breakpoint

CREATE TRIGGER tenant_ldap_identity_plan_applications_guard_v1
BEFORE INSERT OR UPDATE OR DELETE ON public.tenant_ldap_identity_plan_applications
FOR EACH ROW EXECUTE FUNCTION app.guard_tenant_ldap_identity_plan_application_v1();--> statement-breakpoint

CREATE FUNCTION app.guard_tenant_ldap_sync_absence_v1()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'tenant LDAP sync absences are archival records'
      USING ERRCODE = '55000';
  END IF;
  IF TG_OP = 'INSERT' THEN
    IF NEW.status <> 'pending' OR NOT EXISTS (
      SELECT 1 FROM public.tenant_ldap_sync_runs AS run
      WHERE run.tenant_id = NEW.tenant_id
        AND run.id = NEW.latest_missing_run_id
        AND run.binding_id = NEW.binding_id
        AND run.status = 'applying'
        AND run.enumeration_complete
        AND NOT run.result_truncated
    ) THEN
      RAISE EXCEPTION 'tenant LDAP absence requires a complete applying run'
        USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
  END IF;
  IF ROW(
    NEW.tenant_id, NEW.binding_id, NEW.external_identity_id,
    NEW.membership_id, NEW.first_missing_run_id, NEW.first_missing_at,
    NEW.apply_after
  ) IS DISTINCT FROM ROW(
    OLD.tenant_id, OLD.binding_id, OLD.external_identity_id,
    OLD.membership_id, OLD.first_missing_run_id, OLD.first_missing_at,
    OLD.apply_after
  ) OR OLD.status <> 'pending' OR NEW.status NOT IN ('cleared', 'applied')
     OR NEW.version <> OLD.version + 1 THEN
    RAISE EXCEPTION 'tenant LDAP absence transition is invalid'
      USING ERRCODE = '55000';
  END IF;
  RETURN NEW;
END;
$function$;--> statement-breakpoint

CREATE TRIGGER tenant_ldap_sync_absences_guard_v1
BEFORE INSERT OR UPDATE OR DELETE ON public.tenant_ldap_sync_absences
FOR EACH ROW EXECUTE FUNCTION app.guard_tenant_ldap_sync_absence_v1();--> statement-breakpoint

CREATE FUNCTION app.guard_tenant_ldap_access_grant_membership_ownership_v1()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF NEW.owns_membership IS DISTINCT FROM OLD.owns_membership THEN
    RAISE EXCEPTION 'provider membership ownership is immutable'
      USING ERRCODE = '55000';
  END IF;
  RETURN NEW;
END;
$function$;--> statement-breakpoint

CREATE TRIGGER tenant_ldap_provider_access_grants_ownership_guard_v1
BEFORE UPDATE OF owns_membership ON public.tenant_ldap_provider_access_grants
FOR EACH ROW EXECUTE FUNCTION app.guard_tenant_ldap_access_grant_membership_ownership_v1();--> statement-breakpoint

ALTER FUNCTION app.guard_tenant_ldap_sync_run_v1() OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.guard_tenant_ldap_sync_run_mapping_v1() OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.guard_tenant_ldap_sync_staged_observation_v1() OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.guard_tenant_ldap_identity_plan_application_v1() OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.guard_tenant_ldap_sync_absence_v1() OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.guard_tenant_ldap_access_grant_membership_ownership_v1() OWNER TO periapsis_migrator;--> statement-breakpoint

REVOKE ALL ON FUNCTION app.guard_tenant_ldap_sync_run_v1() FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.guard_tenant_ldap_sync_run_mapping_v1() FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.guard_tenant_ldap_sync_staged_observation_v1() FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.guard_tenant_ldap_identity_plan_application_v1() FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.guard_tenant_ldap_sync_absence_v1() FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.guard_tenant_ldap_access_grant_membership_ownership_v1() FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;
