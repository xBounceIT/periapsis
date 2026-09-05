-- Phase 5 SLA security boundary. The generated 0104 migration contains only
-- canonical relational shape. This successor freezes least privilege, tenant
-- authorization, append-only evidence, and cross-table runtime identities.

DO $sla_owners$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_roles
    WHERE rolname = 'periapsis_sla_api_owner'
  ) THEN
    CREATE ROLE periapsis_sla_api_owner
      NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT
      NOREPLICATION NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_roles
    WHERE rolname = 'periapsis_sla_worker_owner'
  ) THEN
    CREATE ROLE periapsis_sla_worker_owner
      NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT
      NOREPLICATION NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_roles
    WHERE rolname = 'periapsis_sla_readiness_owner'
  ) THEN
    CREATE ROLE periapsis_sla_readiness_owner
      NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT
      NOREPLICATION NOBYPASSRLS;
  END IF;
  IF EXISTS (
    SELECT 1
    FROM pg_catalog.pg_roles
    WHERE rolname IN (
      'periapsis_sla_api_owner', 'periapsis_sla_worker_owner',
      'periapsis_sla_readiness_owner'
    ) AND (
      rolcanlogin OR rolsuper OR rolcreatedb OR rolcreaterole OR rolinherit
      OR rolreplication OR rolbypassrls
    )
  ) THEN
    RAISE EXCEPTION 'SLA function owner is privileged'
      USING ERRCODE = '55000';
  END IF;
END
$sla_owners$;
--> statement-breakpoint

DO $sla_tables$
DECLARE
  table_name text;
BEGIN
  FOREACH table_name IN ARRAY ARRAY[
    'sla_business_calendars', 'sla_business_calendar_versions',
    'sla_policies', 'sla_policy_versions', 'sla_metric_definitions',
    'sla_trigger_definitions', 'sla_columns', 'sla_column_versions',
    'sla_configuration_commands', 'sla_instances', 'sla_metric_instances',
    'sla_trigger_cursors', 'sla_trigger_occurrences',
    'sla_materialized_column_values', 'sla_object_event_ledger',
    'sla_evaluation_jobs', 'sla_overrides'
  ] LOOP
    EXECUTE format('ALTER TABLE public.%I OWNER TO periapsis_migrator', table_name);
    EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', table_name);
    EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY', table_name);
    EXECUTE format(
      'REVOKE ALL ON TABLE public.%I FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor',
      table_name
    );
    EXECUTE format(
      'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.%I TO periapsis_sla_api_owner',
      table_name
    );
    EXECUTE format(
      'CREATE POLICY %I ON public.%I AS PERMISSIVE FOR ALL TO periapsis_sla_api_owner USING (tenant_id = app.context_tenant_id() AND app.current_tenant_membership_id() IS NOT NULL) WITH CHECK (tenant_id = app.context_tenant_id() AND app.current_tenant_membership_id() IS NOT NULL)',
      table_name || '_sla_api_owner_v1', table_name
    );
  END LOOP;
END
$sla_tables$;
--> statement-breakpoint

DO $sla_worker_tables$
DECLARE
  table_name text;
BEGIN
  FOREACH table_name IN ARRAY ARRAY[
    'sla_business_calendar_versions', 'sla_policy_versions',
    'sla_metric_definitions', 'sla_trigger_definitions',
    'sla_column_versions', 'sla_instances', 'sla_metric_instances',
    'sla_trigger_cursors', 'sla_trigger_occurrences',
    'sla_materialized_column_values', 'sla_evaluation_jobs'
  ] LOOP
    EXECUTE format(
      'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.%I TO periapsis_sla_worker_owner',
      table_name
    );
    EXECUTE format(
      'CREATE POLICY %I ON public.%I AS PERMISSIVE FOR ALL TO periapsis_sla_worker_owner USING (true) WITH CHECK (true)',
      table_name || '_sla_worker_owner_v1', table_name
    );
  END LOOP;
END
$sla_worker_tables$;
--> statement-breakpoint

-- Claims join active column shells to their immutable revisions. The worker
-- owner may read that catalog but cannot publish, archive, or otherwise write it.
GRANT SELECT ON TABLE public.sla_columns TO periapsis_sla_worker_owner;
--> statement-breakpoint
CREATE POLICY sla_columns_sla_worker_owner_read_v1
ON public.sla_columns AS PERMISSIVE FOR SELECT
TO periapsis_sla_worker_owner USING (true);
--> statement-breakpoint

GRANT USAGE ON SCHEMA app, public
TO periapsis_sla_api_owner, periapsis_sla_worker_owner,
   periapsis_sla_readiness_owner;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.context_tenant_id(), app.context_user_id(),
  app.current_tenant_membership_id(),
  app.current_tenant_human_has_exact_permission_v3(
    text, public.authorization_scope
  ), app.private_current_ticket_scope_allows_v1(
    text, uuid, uuid, uuid, uuid
  ), app.append_tenant_authorization_audit(
    uuid, text, text, uuid, uuid, uuid, inet, text, text,
    jsonb, jsonb, jsonb
  )
TO periapsis_sla_api_owner;
--> statement-breakpoint

GRANT SELECT, INSERT ON TABLE public.outbox_events
TO periapsis_sla_api_owner, periapsis_sla_worker_owner;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.private_notification_trace_context_is_safe_v1(
  text, text
) TO periapsis_sla_worker_owner;
--> statement-breakpoint
GRANT SELECT ON TABLE public.alerts, public.cases,
  public.tenant_authorization_states, public.tenant_user_profiles
TO periapsis_sla_api_owner;
--> statement-breakpoint
GRANT SELECT ON TABLE public.tenant_permissions,
  public.tenant_permission_scopes
TO periapsis_sla_readiness_owner;
--> statement-breakpoint
CREATE POLICY tenant_permissions_sla_readiness_owner_v1
ON public.tenant_permissions AS PERMISSIVE FOR SELECT
TO periapsis_sla_readiness_owner USING (true);
--> statement-breakpoint
CREATE POLICY tenant_permission_scopes_sla_readiness_owner_v1
ON public.tenant_permission_scopes AS PERMISSIVE FOR SELECT
TO periapsis_sla_readiness_owner USING (true);
--> statement-breakpoint
CREATE POLICY alerts_sla_api_owner_v1
ON public.alerts AS PERMISSIVE FOR SELECT TO periapsis_sla_api_owner
USING (
  tenant_id = app.context_tenant_id()
  AND app.current_tenant_membership_id() IS NOT NULL
);
--> statement-breakpoint
CREATE POLICY cases_sla_api_owner_v1
ON public.cases AS PERMISSIVE FOR SELECT TO periapsis_sla_api_owner
USING (
  tenant_id = app.context_tenant_id()
  AND app.current_tenant_membership_id() IS NOT NULL
);
--> statement-breakpoint
CREATE POLICY tenant_authorization_states_sla_api_owner_v1
ON public.tenant_authorization_states AS PERMISSIVE FOR SELECT
TO periapsis_sla_api_owner
USING (
  tenant_id = app.context_tenant_id()
  AND app.current_tenant_membership_id() IS NOT NULL
);
--> statement-breakpoint
CREATE POLICY tenant_user_profiles_sla_api_owner_v1
ON public.tenant_user_profiles AS PERMISSIVE FOR SELECT
TO periapsis_sla_api_owner
USING (
  tenant_id = app.context_tenant_id()
  AND membership_id = app.current_tenant_membership_id()
);
--> statement-breakpoint
CREATE POLICY outbox_events_sla_api_owner_v1
ON public.outbox_events AS PERMISSIVE FOR ALL TO periapsis_sla_api_owner
USING (
  tenant_id = app.context_tenant_id() AND event_type LIKE 'sla.%'
)
WITH CHECK (
  tenant_id = app.context_tenant_id() AND event_type LIKE 'sla.%'
);
--> statement-breakpoint
CREATE POLICY outbox_events_sla_worker_owner_v1
ON public.outbox_events AS PERMISSIVE FOR ALL TO periapsis_sla_worker_owner
USING (event_type LIKE 'sla.%')
WITH CHECK (event_type LIKE 'sla.%');
--> statement-breakpoint

INSERT INTO public.tenant_permissions (
  id, key, display_name, description, service_account_allowed
)
VALUES
  (uuidv7(), 'sla.read', 'Read SLA configuration',
   'Read tenant SLA calendars, policies, columns, and authorized object projections.', false),
  (uuidv7(), 'sla.manage', 'Manage SLA configuration',
   'Publish and archive tenant SLA calendars, policies, metrics, triggers, and columns.', false),
  (uuidv7(), 'sla.simulate', 'Simulate SLA policy',
   'Run a bounded tenant SLA policy simulation without persisting runtime state.', false),
  (uuidv7(), 'alert.sla.override', 'Override Alert SLA',
   'Apply an audited resource-scoped override to an Alert SLA.', false),
  (uuidv7(), 'case.sla.override', 'Override Case SLA',
   'Apply an audited resource-scoped override to a Case SLA.', false)
ON CONFLICT (key) DO NOTHING;
--> statement-breakpoint

INSERT INTO public.tenant_permission_scopes (permission_id, scope)
SELECT permission.id, allowed.scope
FROM public.tenant_permissions AS permission
CROSS JOIN LATERAL (
  SELECT 'tenant'::public.authorization_scope AS scope
  WHERE permission.key IN ('sla.read', 'sla.manage', 'sla.simulate')
  UNION ALL
  SELECT scope
  FROM unnest(ARRAY[
    'own'::public.authorization_scope,
    'assigned'::public.authorization_scope,
    'operator_team'::public.authorization_scope,
    'tenant'::public.authorization_scope
  ]) AS override_scope(scope)
  WHERE permission.key IN ('alert.sla.override', 'case.sla.override')
) AS allowed
WHERE permission.key IN (
  'sla.read', 'sla.manage', 'sla.simulate',
  'alert.sla.override', 'case.sla.override'
)
ON CONFLICT DO NOTHING;
--> statement-breakpoint

CREATE FUNCTION app.private_seed_tenant_sla_authorization_v1(
  p_tenant_id uuid
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  changed_role_ids uuid[];
  changed_role record;
BEGIN
  IF p_tenant_id IS NULL OR NOT EXISTS (
    SELECT 1 FROM public.tenants AS tenant WHERE tenant.id = p_tenant_id
  ) THEN
    RAISE EXCEPTION 'SLA authorization tenant is unavailable'
      USING ERRCODE = 'P0002';
  END IF;

  WITH inserted AS (
    INSERT INTO public.tenant_role_permissions (
      tenant_id, role_id, permission_id, scope, created_by_membership_id
    )
    SELECT p_tenant_id, role.id, permission.id, scope.scope, NULL
    FROM public.tenant_roles AS role
    JOIN public.tenant_permissions AS permission
      ON permission.key IN (
        'sla.read', 'sla.manage', 'sla.simulate',
        'alert.sla.override', 'case.sla.override'
      )
    JOIN public.tenant_permission_scopes AS scope
      ON scope.permission_id = permission.id
    WHERE role.tenant_id = p_tenant_id
      AND role.key = 'tenant_admin'
      AND role.principal_kind = 'human'
      AND role.system_role AND role.archived_at IS NULL
    ON CONFLICT DO NOTHING
    RETURNING role_id
  )
  SELECT coalesce(array_agg(DISTINCT role_id), ARRAY[]::uuid[])
  INTO changed_role_ids
  FROM inserted;

  INSERT INTO public.tenant_role_delegation_ceilings (
    tenant_id, role_id, permission_id, scope, created_by_membership_id
  )
  SELECT p_tenant_id, role.id, permission.id, scope.scope, NULL
  FROM public.tenant_roles AS role
  JOIN public.tenant_permissions AS permission
    ON permission.key IN (
      'sla.read', 'sla.manage', 'sla.simulate',
      'alert.sla.override', 'case.sla.override'
    )
  JOIN public.tenant_permission_scopes AS scope
    ON scope.permission_id = permission.id
  WHERE role.tenant_id = p_tenant_id
    AND role.key = 'tenant_admin'
    AND role.principal_kind = 'human'
    AND role.system_role AND role.archived_at IS NULL
  ON CONFLICT DO NOTHING;

  FOR changed_role IN
    SELECT role.id, role.version
    FROM public.tenant_roles AS role
    WHERE role.tenant_id = p_tenant_id
      AND role.id = ANY(changed_role_ids)
    FOR UPDATE
  LOOP
    IF changed_role.version >= 2147483647 THEN
      RAISE EXCEPTION 'SLA authorization role version is exhausted'
        USING ERRCODE = '55000';
    END IF;
    UPDATE public.tenant_roles
    SET version = changed_role.version + 1,
        updated_at = transaction_timestamp()
    WHERE tenant_id = p_tenant_id AND id = changed_role.id;
  END LOOP;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.private_seed_tenant_sla_authorization_v1(uuid)
  OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_seed_tenant_sla_authorization_v1(uuid)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_sla_api_owner, periapsis_sla_worker_owner;
--> statement-breakpoint

SELECT app.private_seed_tenant_sla_authorization_v1(tenant.id)
FROM public.tenants AS tenant
ORDER BY tenant.id;
--> statement-breakpoint

-- Keep the static name distinct for sqlc's migration parser. PostgreSQL applies
-- both renames atomically after the successor body has been compiled.
CREATE FUNCTION app.seed_tenant_authorization_sla_successor(
  p_tenant_id uuid,
  p_bootstrap_user_id uuid
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  PERFORM app.seed_tenant_authorization_sla_compatibility_impl(
    p_tenant_id, p_bootstrap_user_id
  );
  PERFORM app.private_seed_tenant_sla_authorization_v1(p_tenant_id);
END;
$function$;
--> statement-breakpoint
DO $sla_seed_successor$
BEGIN
  EXECUTE 'ALTER FUNCTION app.seed_tenant_authorization(uuid, uuid) RENAME TO seed_tenant_authorization_sla_compatibility_impl';
  EXECUTE 'ALTER FUNCTION app.seed_tenant_authorization_sla_successor(uuid, uuid) RENAME TO seed_tenant_authorization';
END
$sla_seed_successor$;
--> statement-breakpoint
ALTER FUNCTION app.seed_tenant_authorization(uuid, uuid)
  OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.seed_tenant_authorization(uuid, uuid),
  app.seed_tenant_authorization_sla_compatibility_impl(uuid, uuid)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_sla_api_owner, periapsis_sla_worker_owner;
--> statement-breakpoint

CREATE FUNCTION app.private_sla_context_allows_v1(
  p_permission_key text,
  p_tenant_id uuid,
  p_object_type public.sla_object_type DEFAULT NULL,
  p_object_id uuid DEFAULT NULL
)
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  ticket record;
BEGIN
  IF p_tenant_id IS NULL OR p_tenant_id IS DISTINCT FROM app.context_tenant_id()
     OR app.current_tenant_membership_id() IS NULL THEN
    RETURN false;
  END IF;
  IF p_permission_key IN ('sla.read', 'sla.manage', 'sla.simulate') THEN
    RETURN p_object_type IS NULL AND p_object_id IS NULL
      AND app.current_tenant_human_has_exact_permission_v3(
        p_permission_key, 'tenant'
      );
  END IF;
  IF p_object_type = 'alert' AND p_permission_key IN (
    'alert.read', 'alert.sla.override'
  ) THEN
    SELECT alert.assigned_team_id, alert.created_by AS owner_user_id,
           alert.assignee_user_id, alert.claimed_by_user_id
    INTO ticket
    FROM public.alerts AS alert
    WHERE alert.tenant_id = p_tenant_id AND alert.id = p_object_id;
  ELSIF p_object_type = 'case' AND p_permission_key IN (
    'case.read', 'case.sla.override'
  ) THEN
    SELECT case_row.assigned_team_id,
           case_row.created_by_user_id AS owner_user_id,
           case_row.assignee_user_id, case_row.claimed_by_user_id
    INTO ticket
    FROM public.cases AS case_row
    WHERE case_row.tenant_id = p_tenant_id AND case_row.id = p_object_id;
  ELSE
    RETURN false;
  END IF;
  IF NOT FOUND THEN
    RETURN false;
  END IF;
  RETURN app.private_current_ticket_scope_allows_v1(
    p_permission_key, ticket.assigned_team_id, ticket.owner_user_id,
    ticket.assignee_user_id, ticket.claimed_by_user_id
  );
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.private_sla_context_allows_v1(
  text, uuid, public.sla_object_type, uuid
) OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_sla_context_allows_v1(
  text, uuid, public.sla_object_type, uuid
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_sla_worker_owner;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.private_sla_context_allows_v1(
  text, uuid, public.sla_object_type, uuid
) TO periapsis_sla_api_owner;
--> statement-breakpoint

CREATE FUNCTION app.guard_sla_append_only_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
BEGIN
  RAISE EXCEPTION 'SLA evidence is append-only' USING ERRCODE = '55000';
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.guard_sla_append_only_v1() OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.guard_sla_append_only_v1()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_sla_api_owner, periapsis_sla_worker_owner;
--> statement-breakpoint

CREATE TRIGGER sla_business_calendar_versions_immutable_v1
BEFORE UPDATE OR DELETE ON public.sla_business_calendar_versions
FOR EACH ROW EXECUTE FUNCTION app.guard_sla_append_only_v1();
--> statement-breakpoint
CREATE TRIGGER sla_policy_versions_immutable_v1
BEFORE UPDATE OR DELETE ON public.sla_policy_versions
FOR EACH ROW EXECUTE FUNCTION app.guard_sla_append_only_v1();
--> statement-breakpoint
CREATE TRIGGER sla_metric_definitions_immutable_v1
BEFORE UPDATE OR DELETE ON public.sla_metric_definitions
FOR EACH ROW EXECUTE FUNCTION app.guard_sla_append_only_v1();
--> statement-breakpoint
CREATE TRIGGER sla_trigger_definitions_immutable_v1
BEFORE UPDATE OR DELETE ON public.sla_trigger_definitions
FOR EACH ROW EXECUTE FUNCTION app.guard_sla_append_only_v1();
--> statement-breakpoint
CREATE TRIGGER sla_column_versions_immutable_v1
BEFORE UPDATE OR DELETE ON public.sla_column_versions
FOR EACH ROW EXECUTE FUNCTION app.guard_sla_append_only_v1();
--> statement-breakpoint
CREATE TRIGGER sla_configuration_commands_immutable_v1
BEFORE UPDATE OR DELETE ON public.sla_configuration_commands
FOR EACH ROW EXECUTE FUNCTION app.guard_sla_append_only_v1();
--> statement-breakpoint
CREATE TRIGGER sla_object_event_ledger_immutable_v1
BEFORE UPDATE OR DELETE ON public.sla_object_event_ledger
FOR EACH ROW EXECUTE FUNCTION app.guard_sla_append_only_v1();
--> statement-breakpoint
CREATE TRIGGER sla_trigger_occurrences_immutable_v1
BEFORE UPDATE OR DELETE ON public.sla_trigger_occurrences
FOR EACH ROW EXECUTE FUNCTION app.guard_sla_append_only_v1();
--> statement-breakpoint
CREATE TRIGGER sla_overrides_immutable_v1
BEFORE UPDATE OR DELETE ON public.sla_overrides
FOR EACH ROW EXECUTE FUNCTION app.guard_sla_append_only_v1();
--> statement-breakpoint

CREATE FUNCTION app.guard_sla_runtime_identity_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
BEGIN
  IF TG_TABLE_NAME = 'sla_metric_instances' THEN
    IF NOT EXISTS (
      SELECT 1 FROM public.sla_metric_definitions AS definition
      WHERE definition.tenant_id = NEW.tenant_id
        AND definition.id = NEW.definition_id
        AND definition.policy_id = NEW.policy_id
        AND definition.policy_version = NEW.policy_version
    ) THEN
      RAISE EXCEPTION 'SLA metric definition projection is inconsistent'
        USING ERRCODE = '23503';
    END IF;
  ELSIF TG_TABLE_NAME = 'sla_trigger_cursors' THEN
    IF NOT EXISTS (
      SELECT 1
      FROM public.sla_metric_instances AS metric
      JOIN public.sla_trigger_definitions AS definition
        ON definition.tenant_id = metric.tenant_id
       AND definition.id = NEW.trigger_definition_id
       AND definition.policy_id = metric.policy_id
       AND definition.policy_version = metric.policy_version
       AND definition.metric_definition_id = metric.definition_id
      WHERE metric.tenant_id = NEW.tenant_id
        AND metric.id = NEW.metric_instance_id
    ) THEN
      RAISE EXCEPTION 'SLA trigger cursor projection is inconsistent'
        USING ERRCODE = '23503';
    END IF;
  ELSIF TG_TABLE_NAME = 'sla_trigger_occurrences' THEN
    IF NOT EXISTS (
      SELECT 1
      FROM public.sla_instances AS aggregate
      JOIN public.sla_metric_instances AS metric
        ON metric.tenant_id = aggregate.tenant_id
       AND metric.sla_instance_id = aggregate.id
      JOIN public.sla_trigger_definitions AS definition
        ON definition.tenant_id = metric.tenant_id
       AND definition.id = NEW.trigger_definition_id
       AND definition.policy_id = metric.policy_id
       AND definition.policy_version = metric.policy_version
       AND definition.metric_definition_id = metric.definition_id
      WHERE aggregate.tenant_id = NEW.tenant_id
        AND aggregate.id = NEW.sla_instance_id
        AND metric.id = NEW.metric_instance_id
    ) THEN
      RAISE EXCEPTION 'SLA trigger occurrence projection is inconsistent'
        USING ERRCODE = '23503';
    END IF;
  ELSIF TG_TABLE_NAME = 'sla_materialized_column_values' THEN
    IF NOT EXISTS (
      SELECT 1
      FROM public.sla_instances AS aggregate
      JOIN public.sla_metric_instances AS metric
        ON metric.tenant_id = aggregate.tenant_id
       AND metric.sla_instance_id = aggregate.id
      JOIN public.sla_column_versions AS column_version
        ON column_version.tenant_id = metric.tenant_id
       AND column_version.column_id = NEW.column_id
       AND column_version.version = NEW.column_version
       AND column_version.metric_definition_id = metric.definition_id
      WHERE aggregate.tenant_id = NEW.tenant_id
        AND aggregate.id = NEW.sla_instance_id
        AND aggregate.object_type = NEW.object_type
        AND aggregate.object_id = NEW.object_id
        AND metric.id = NEW.metric_instance_id
    ) THEN
      RAISE EXCEPTION 'SLA materialized column projection is inconsistent'
        USING ERRCODE = '23503';
    END IF;
  ELSIF TG_TABLE_NAME = 'sla_object_event_ledger'
        AND NEW.sla_instance_id IS NOT NULL THEN
    IF NOT EXISTS (
      SELECT 1 FROM public.sla_instances AS aggregate
      WHERE aggregate.tenant_id = NEW.tenant_id
        AND aggregate.id = NEW.sla_instance_id
        AND aggregate.object_type = NEW.object_type
        AND aggregate.object_id = NEW.object_id
        AND aggregate.policy_id = NEW.policy_id
        AND aggregate.policy_version = NEW.policy_version
        AND aggregate.aggregate_version = NEW.aggregate_version
    ) THEN
      RAISE EXCEPTION 'SLA event receipt projection is inconsistent'
        USING ERRCODE = '23503';
    END IF;
  ELSIF TG_TABLE_NAME = 'sla_evaluation_jobs' THEN
    IF NOT EXISTS (
      SELECT 1 FROM public.sla_instances AS aggregate
      WHERE aggregate.tenant_id = NEW.tenant_id
        AND aggregate.id = NEW.sla_instance_id
        AND aggregate.aggregate_version >= NEW.expected_aggregate_version
    ) THEN
      RAISE EXCEPTION 'SLA evaluation job projection is inconsistent'
        USING ERRCODE = '23503';
    END IF;
  ELSIF TG_TABLE_NAME = 'sla_overrides' THEN
    IF NOT EXISTS (
      SELECT 1
      FROM public.sla_instances AS aggregate
      LEFT JOIN public.sla_metric_instances AS metric
        ON metric.tenant_id = aggregate.tenant_id
       AND metric.sla_instance_id = aggregate.id
       AND metric.id = NEW.metric_instance_id
      WHERE aggregate.tenant_id = NEW.tenant_id
        AND aggregate.id = NEW.sla_instance_id
        AND aggregate.object_type = NEW.object_type
        AND aggregate.object_id = NEW.object_id
        AND aggregate.policy_id = NEW.policy_id
        AND aggregate.policy_version = NEW.policy_version
        AND (
          NEW.metric_instance_id IS NULL
          OR metric.id IS NOT NULL
        )
    ) THEN
      RAISE EXCEPTION 'SLA override projection is inconsistent'
        USING ERRCODE = '23503';
    END IF;
  END IF;
  RETURN NEW;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.guard_sla_runtime_identity_v1()
  OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.guard_sla_runtime_identity_v1()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_sla_api_owner, periapsis_sla_worker_owner;
--> statement-breakpoint

CREATE TRIGGER sla_metric_instances_identity_v1
BEFORE INSERT OR UPDATE ON public.sla_metric_instances
FOR EACH ROW EXECUTE FUNCTION app.guard_sla_runtime_identity_v1();
--> statement-breakpoint
CREATE TRIGGER sla_trigger_cursors_identity_v1
BEFORE INSERT OR UPDATE ON public.sla_trigger_cursors
FOR EACH ROW EXECUTE FUNCTION app.guard_sla_runtime_identity_v1();
--> statement-breakpoint
CREATE TRIGGER sla_trigger_occurrences_identity_v1
BEFORE INSERT ON public.sla_trigger_occurrences
FOR EACH ROW EXECUTE FUNCTION app.guard_sla_runtime_identity_v1();
--> statement-breakpoint
CREATE TRIGGER sla_materialized_columns_identity_v1
BEFORE INSERT OR UPDATE ON public.sla_materialized_column_values
FOR EACH ROW EXECUTE FUNCTION app.guard_sla_runtime_identity_v1();
--> statement-breakpoint
CREATE TRIGGER sla_object_event_ledger_identity_v1
BEFORE INSERT ON public.sla_object_event_ledger
FOR EACH ROW EXECUTE FUNCTION app.guard_sla_runtime_identity_v1();
--> statement-breakpoint
CREATE TRIGGER sla_evaluation_jobs_identity_v1
BEFORE INSERT OR UPDATE ON public.sla_evaluation_jobs
FOR EACH ROW EXECUTE FUNCTION app.guard_sla_runtime_identity_v1();
--> statement-breakpoint
CREATE TRIGGER sla_overrides_identity_v1
BEFORE INSERT ON public.sla_overrides
FOR EACH ROW EXECUTE FUNCTION app.guard_sla_runtime_identity_v1();
