-- Phase 3 ticketing foundation: closed authorization catalog, immutable
-- published workflows, rolling Alert backfill, and least-privilege reads.

ALTER TABLE public.ticket_number_counters OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TABLE public.ticket_workflows OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TABLE public.ticket_workflow_versions OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TABLE public.cases OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TABLE public.ticket_comments OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TABLE public.ticket_activities OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TABLE public.alert_case_links OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TABLE public.ticket_assignment_history OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TABLE public.ticket_commands OWNER TO periapsis_migrator;--> statement-breakpoint

ALTER TABLE public.alerts FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE public.ticket_number_counters FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE public.ticket_workflows FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE public.ticket_workflow_versions FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE public.cases FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE public.ticket_comments FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE public.ticket_activities FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE public.alert_case_links FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE public.ticket_assignment_history FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE public.ticket_commands FORCE ROW LEVEL SECURITY;--> statement-breakpoint

REVOKE ALL ON TABLE public.ticket_number_counters FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON TABLE public.ticket_workflows FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON TABLE public.ticket_workflow_versions FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON TABLE public.cases FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON TABLE public.ticket_comments FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON TABLE public.ticket_activities FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON TABLE public.alert_case_links FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON TABLE public.ticket_assignment_history FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON TABLE public.ticket_commands FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint

DROP POLICY IF EXISTS alerts_api_tenant ON public.alerts;--> statement-breakpoint
CREATE POLICY alerts_api_tenant
ON public.alerts
AS PERMISSIVE
FOR SELECT
TO periapsis_api
USING (
  tenant_id = app.context_tenant_id()
  AND EXISTS (
    SELECT 1
    FROM public.tenant_memberships AS membership
    WHERE membership.tenant_id = alerts.tenant_id
      AND membership.user_id = app.context_user_id()
      AND membership.status = 'active'
  )
);--> statement-breakpoint

GRANT SELECT ON TABLE public.alerts TO periapsis_api;--> statement-breakpoint
GRANT SELECT ON TABLE public.ticket_workflows TO periapsis_api;--> statement-breakpoint
GRANT SELECT ON TABLE public.ticket_workflow_versions TO periapsis_api;--> statement-breakpoint
GRANT SELECT ON TABLE public.cases TO periapsis_api;--> statement-breakpoint
GRANT SELECT ON TABLE public.ticket_comments TO periapsis_api;--> statement-breakpoint
GRANT SELECT ON TABLE public.ticket_activities TO periapsis_api;--> statement-breakpoint
GRANT SELECT ON TABLE public.alert_case_links TO periapsis_api;--> statement-breakpoint

CREATE FUNCTION app.guard_published_ticket_workflow_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  RAISE EXCEPTION 'published ticket workflow versions are immutable'
    USING ERRCODE = '55000';
END;
$function$;--> statement-breakpoint

ALTER FUNCTION app.guard_published_ticket_workflow_v1() OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.guard_published_ticket_workflow_v1() FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint

CREATE TRIGGER ticket_workflow_versions_immutable_v1
BEFORE UPDATE OR DELETE ON public.ticket_workflow_versions
FOR EACH ROW EXECUTE FUNCTION app.guard_published_ticket_workflow_v1();--> statement-breakpoint

INSERT INTO public.tenant_permissions (
  id, key, display_name, description, service_account_allowed
)
VALUES
  (uuidv7(), 'alert.read', 'Read alerts', 'Read authorized Alert projections.', false),
  (uuidv7(), 'alert.activity.read', 'Read alert activity', 'Read authorized Alert activity.', false),
  (uuidv7(), 'alert.comment.read', 'Read alert comments', 'Read authorized Alert comments.', false),
  (uuidv7(), 'alert.link.read', 'Read alert links', 'Read authorized Alert-to-Case links.', false),
  (uuidv7(), 'alert.update', 'Update alerts', 'Apply an admitted Alert workflow transition.', false),
  (uuidv7(), 'alert.assign', 'Assign alerts', 'Assign or transfer an Alert.', false),
  (uuidv7(), 'alert.claim', 'Claim alerts', 'Claim or release an Alert.', false),
  (uuidv7(), 'alert.escalate', 'Escalate alerts', 'Escalate one or more Alerts to a Case.', false),
  (uuidv7(), 'alert.comment.public', 'Comment publicly on alerts', 'Create a customer-visible Alert comment.', false),
  (uuidv7(), 'alert.comment.private', 'Comment privately on alerts', 'Create an operator-only Alert comment.', false),
  (uuidv7(), 'case.read', 'Read cases', 'Read authorized Case projections.', false),
  (uuidv7(), 'case.activity.read', 'Read case activity', 'Read authorized Case activity.', false),
  (uuidv7(), 'case.comment.read', 'Read case comments', 'Read authorized Case comments.', false),
  (uuidv7(), 'case.link.read', 'Read case links', 'Read authorized Case-to-Alert links.', false),
  (uuidv7(), 'case.create', 'Create cases', 'Create a Case in a published workflow.', false),
  (uuidv7(), 'case.update', 'Update cases', 'Update or link a Case.', false),
  (uuidv7(), 'case.claim', 'Claim cases', 'Claim or release a Case.', false),
  (uuidv7(), 'case.transfer', 'Transfer cases', 'Assign or transfer a Case.', false),
  (uuidv7(), 'case.transition', 'Transition cases', 'Apply an admitted Case workflow transition.', false),
  (uuidv7(), 'case.comment.public', 'Comment publicly on cases', 'Create a customer-visible Case comment.', false),
  (uuidv7(), 'case.comment.private', 'Comment privately on cases', 'Create an operator-only Case comment.', false)
ON CONFLICT (key) DO NOTHING;--> statement-breakpoint

INSERT INTO public.tenant_permission_scopes (permission_id, scope)
SELECT permission.id, scope.value
FROM public.tenant_permissions AS permission
CROSS JOIN LATERAL unnest(
  CASE
    WHEN permission.key = 'case.create'
      THEN ARRAY['tenant'::public.authorization_scope]
    WHEN permission.key IN (
      'alert.update', 'alert.assign', 'alert.escalate', 'alert.comment.private',
      'case.update', 'case.transfer', 'case.transition', 'case.comment.private'
    ) THEN ARRAY[
      'assigned'::public.authorization_scope,
      'operator_team'::public.authorization_scope,
      'tenant'::public.authorization_scope
    ]
    ELSE ARRAY[
      'own'::public.authorization_scope,
      'assigned'::public.authorization_scope,
      'operator_team'::public.authorization_scope,
      'tenant'::public.authorization_scope
    ]
  END
) AS scope(value)
WHERE permission.key IN (
  'alert.read', 'alert.activity.read', 'alert.comment.read', 'alert.link.read',
  'alert.update', 'alert.assign', 'alert.claim', 'alert.escalate',
  'alert.comment.public', 'alert.comment.private',
  'case.read', 'case.activity.read', 'case.comment.read', 'case.link.read',
  'case.create', 'case.update', 'case.claim', 'case.transfer',
  'case.transition', 'case.comment.public', 'case.comment.private'
)
ON CONFLICT DO NOTHING;--> statement-breakpoint

CREATE FUNCTION app.private_seed_tenant_ticketing_workflows_v1(
  p_tenant_id uuid
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  alert_workflow_id uuid;
  case_workflow_id uuid;
  all_effects jsonb := '["activity","audit","sla","notification"]'::jsonb;
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM public.tenants AS tenant WHERE tenant.id = p_tenant_id
  ) THEN
    RAISE EXCEPTION 'ticket workflow seed requires an existing tenant'
      USING ERRCODE = '23503';
  END IF;

  INSERT INTO public.ticket_workflows (
    id, tenant_id, aggregate_kind, key, display_name, description,
    is_default, current_version
  ) VALUES (
    uuidv7(), p_tenant_id, 'alert', 'default_alert', 'Default Alert workflow',
    'Built-in Alert triage and closure workflow.', true, 1
  ) ON CONFLICT (tenant_id, aggregate_kind, key) DO NOTHING;

  SELECT workflow.id INTO STRICT alert_workflow_id
  FROM public.ticket_workflows AS workflow
  WHERE workflow.tenant_id = p_tenant_id
    AND workflow.aggregate_kind = 'alert'
    AND workflow.key = 'default_alert'
    AND workflow.is_default
    AND workflow.archived_at IS NULL;

  INSERT INTO public.ticket_workflow_versions (
    id, tenant_id, workflow_id, aggregate_kind, version, states, transitions
  ) VALUES (
    uuidv7(), p_tenant_id, alert_workflow_id, 'alert', 1,
    jsonb_build_array(
      jsonb_build_object(
        'key', 'new', 'initial', true, 'terminal', false,
        'visibility', 'customer',
        'actions', jsonb_build_array(
          jsonb_build_object('action', 'create', 'effects', all_effects),
          jsonb_build_object('action', 'assign', 'effects', all_effects),
          jsonb_build_object('action', 'claim', 'effects', all_effects),
          jsonb_build_object('action', 'release', 'effects', all_effects),
          jsonb_build_object('action', 'transfer', 'effects', all_effects),
          jsonb_build_object('action', 'escalate', 'effects', all_effects)
        )
      ),
      jsonb_build_object(
        'key', 'in_progress', 'initial', false, 'terminal', false,
        'visibility', 'customer',
        'actions', jsonb_build_array(
          jsonb_build_object('action', 'assign', 'effects', all_effects),
          jsonb_build_object('action', 'claim', 'effects', all_effects),
          jsonb_build_object('action', 'release', 'effects', all_effects),
          jsonb_build_object('action', 'transfer', 'effects', all_effects),
          jsonb_build_object('action', 'escalate', 'effects', all_effects)
        )
      ),
      jsonb_build_object(
        'key', 'closed', 'initial', false, 'terminal', true,
        'visibility', 'customer', 'actions', '[]'::jsonb
      )
    ),
    jsonb_build_array(
      jsonb_build_object('key', 'start_investigation', 'from', 'new', 'to', 'in_progress', 'requiredComment', false, 'reopen', false, 'requiredRoles', '[]'::jsonb, 'requiredPermissions', '["alert.update"]'::jsonb, 'requiredCustomFields', '[]'::jsonb, 'effects', all_effects),
      jsonb_build_object('key', 'close_alert', 'from', 'new', 'to', 'closed', 'requiredComment', false, 'reopen', false, 'requiredRoles', '[]'::jsonb, 'requiredPermissions', '["alert.update"]'::jsonb, 'requiredCustomFields', '[]'::jsonb, 'effects', all_effects),
      jsonb_build_object('key', 'close_investigation', 'from', 'in_progress', 'to', 'closed', 'requiredComment', false, 'reopen', false, 'requiredRoles', '[]'::jsonb, 'requiredPermissions', '["alert.update"]'::jsonb, 'requiredCustomFields', '[]'::jsonb, 'effects', all_effects),
      jsonb_build_object('key', 'reopen_alert', 'from', 'closed', 'to', 'in_progress', 'requiredComment', true, 'reopen', true, 'requiredRoles', '[]'::jsonb, 'requiredPermissions', '["alert.update"]'::jsonb, 'requiredCustomFields', '[]'::jsonb, 'effects', all_effects)
    )
  ) ON CONFLICT (tenant_id, workflow_id, version) DO NOTHING;

  INSERT INTO public.ticket_workflows (
    id, tenant_id, aggregate_kind, key, display_name, description,
    is_default, current_version
  ) VALUES (
    uuidv7(), p_tenant_id, 'case', 'default_case', 'Default Case workflow',
    'Built-in Case investigation and closure workflow.', true, 1
  ) ON CONFLICT (tenant_id, aggregate_kind, key) DO NOTHING;

  SELECT workflow.id INTO STRICT case_workflow_id
  FROM public.ticket_workflows AS workflow
  WHERE workflow.tenant_id = p_tenant_id
    AND workflow.aggregate_kind = 'case'
    AND workflow.key = 'default_case'
    AND workflow.is_default
    AND workflow.archived_at IS NULL;

  INSERT INTO public.ticket_workflow_versions (
    id, tenant_id, workflow_id, aggregate_kind, version, states, transitions
  ) VALUES (
    uuidv7(), p_tenant_id, case_workflow_id, 'case', 1,
    jsonb_build_array(
      jsonb_build_object(
        'key', 'open', 'initial', true, 'terminal', false,
        'visibility', 'customer',
        'actions', jsonb_build_array(
          jsonb_build_object('action', 'create', 'effects', all_effects),
          jsonb_build_object('action', 'assign', 'effects', all_effects),
          jsonb_build_object('action', 'claim', 'effects', all_effects),
          jsonb_build_object('action', 'release', 'effects', all_effects),
          jsonb_build_object('action', 'transfer', 'effects', all_effects),
          jsonb_build_object('action', 'link', 'effects', all_effects)
        )
      ),
      jsonb_build_object(
        'key', 'closed', 'initial', false, 'terminal', true,
        'visibility', 'customer', 'actions', '[]'::jsonb
      )
    ),
    jsonb_build_array(
      jsonb_build_object('key', 'close_case', 'from', 'open', 'to', 'closed', 'requiredComment', false, 'reopen', false, 'requiredRoles', '[]'::jsonb, 'requiredPermissions', '["case.transition"]'::jsonb, 'requiredCustomFields', '[]'::jsonb, 'effects', all_effects),
      jsonb_build_object('key', 'reopen_case', 'from', 'closed', 'to', 'open', 'requiredComment', true, 'reopen', true, 'requiredRoles', '[]'::jsonb, 'requiredPermissions', '["case.transition"]'::jsonb, 'requiredCustomFields', '[]'::jsonb, 'effects', all_effects)
    )
  ) ON CONFLICT (tenant_id, workflow_id, version) DO NOTHING;
END;
$function$;--> statement-breakpoint

ALTER FUNCTION app.private_seed_tenant_ticketing_workflows_v1(uuid) OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_seed_tenant_ticketing_workflows_v1(uuid) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint

CREATE FUNCTION app.private_seed_tenant_ticketing_authorization_v1(
  p_tenant_id uuid
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  administrator_role record;
  inserted_policies integer;
  inserted_ceilings integer;
BEGIN
  SELECT role.* INTO STRICT administrator_role
  FROM public.tenant_roles AS role
  WHERE role.tenant_id = p_tenant_id
    AND role.key = 'tenant_admin'
    AND role.principal_kind = 'human'
    AND role.system_role
    AND role.protected_role
    AND role.archived_at IS NULL
  FOR UPDATE;

  INSERT INTO public.tenant_role_permissions (
    tenant_id, role_id, permission_id, scope, created_by_membership_id
  )
  SELECT p_tenant_id, administrator_role.id, permission_scope.permission_id,
         permission_scope.scope, NULL
  FROM public.tenant_permission_scopes AS permission_scope
  JOIN public.tenant_permissions AS permission
    ON permission.id = permission_scope.permission_id
  WHERE permission.key IN (
    'alert.read', 'alert.activity.read', 'alert.comment.read', 'alert.link.read',
    'alert.update', 'alert.assign', 'alert.claim', 'alert.escalate',
    'alert.comment.public', 'alert.comment.private',
    'case.read', 'case.activity.read', 'case.comment.read', 'case.link.read',
    'case.create', 'case.update', 'case.claim', 'case.transfer',
    'case.transition', 'case.comment.public', 'case.comment.private'
  )
  ON CONFLICT DO NOTHING;
  GET DIAGNOSTICS inserted_policies = ROW_COUNT;

  INSERT INTO public.tenant_role_delegation_ceilings (
    tenant_id, role_id, permission_id, scope, created_by_membership_id
  )
  SELECT p_tenant_id, administrator_role.id, permission_scope.permission_id,
         permission_scope.scope, NULL
  FROM public.tenant_permission_scopes AS permission_scope
  JOIN public.tenant_permissions AS permission
    ON permission.id = permission_scope.permission_id
  WHERE permission.key IN (
    'alert.read', 'alert.activity.read', 'alert.comment.read', 'alert.link.read',
    'alert.update', 'alert.assign', 'alert.claim', 'alert.escalate',
    'alert.comment.public', 'alert.comment.private',
    'case.read', 'case.activity.read', 'case.comment.read', 'case.link.read',
    'case.create', 'case.update', 'case.claim', 'case.transfer',
    'case.transition', 'case.comment.public', 'case.comment.private'
  )
  ON CONFLICT DO NOTHING;
  GET DIAGNOSTICS inserted_ceilings = ROW_COUNT;

  IF inserted_policies > 0 OR inserted_ceilings > 0 THEN
    IF administrator_role.version >= 2147483647 THEN
      RAISE EXCEPTION 'tenant_admin ticketing authorization version exhausted'
        USING ERRCODE = '55000';
    END IF;
    UPDATE public.tenant_roles
    SET version = administrator_role.version + 1,
        updated_at = transaction_timestamp()
    WHERE tenant_id = p_tenant_id AND id = administrator_role.id;

    INSERT INTO public.audit_events (
      id, tenant_id, sequence, actor_type, action, resource_type,
      resource_id, authentication_method, outcome, after, metadata
    ) VALUES (
      uuidv7(), p_tenant_id, 0, 'system',
      'tenant.authorization.ticketing_enabled', 'tenant_role',
      administrator_role.id, 'database_migration', 'success',
      jsonb_build_object(
        'permission_family', 'ticketing',
        'prior_version', administrator_role.version,
        'result_version', administrator_role.version + 1
      ),
      jsonb_build_object('migration', '0083_ticketing_foundation_security')
    );
  END IF;
END;
$function$;--> statement-breakpoint

ALTER FUNCTION app.private_seed_tenant_ticketing_authorization_v1(uuid) OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_seed_tenant_ticketing_authorization_v1(uuid) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint

DO $ticketing_seed$
DECLARE
  tenant_record record;
BEGIN
  FOR tenant_record IN SELECT tenant.id FROM public.tenants AS tenant ORDER BY tenant.id LOOP
    PERFORM app.private_seed_tenant_ticketing_workflows_v1(tenant_record.id);
    PERFORM app.private_seed_tenant_ticketing_authorization_v1(tenant_record.id);
  END LOOP;
END;
$ticketing_seed$;--> statement-breakpoint

ALTER FUNCTION app.seed_tenant_authorization(uuid, uuid)
  RENAME TO seed_tenant_authorization_ticketing_compatibility_impl;--> statement-breakpoint
DROP FUNCTION IF EXISTS app.seed_tenant_authorization(uuid, uuid);--> statement-breakpoint
ALTER FUNCTION app.seed_tenant_authorization_ticketing_compatibility_impl(uuid, uuid) OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.seed_tenant_authorization_ticketing_compatibility_impl(uuid, uuid) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint

CREATE FUNCTION app.seed_tenant_authorization(
  p_tenant_id uuid,
  p_initial_admin_membership_id uuid
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  PERFORM app.seed_tenant_authorization_ticketing_compatibility_impl(
    p_tenant_id, p_initial_admin_membership_id
  );
  PERFORM app.private_seed_tenant_ticketing_workflows_v1(p_tenant_id);
  PERFORM app.private_seed_tenant_ticketing_authorization_v1(p_tenant_id);
END;
$function$;--> statement-breakpoint

ALTER FUNCTION app.seed_tenant_authorization(uuid, uuid) OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.seed_tenant_authorization(uuid, uuid) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint

CREATE FUNCTION app.private_next_ticket_number_v1(
  p_tenant_id uuid,
  p_aggregate_kind public.ticket_aggregate_kind,
  p_at timestamp with time zone
)
RETURNS text
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  target_period integer;
  allocated integer;
  prefix text;
BEGIN
  IF p_tenant_id IS NULL OR p_aggregate_kind IS NULL OR p_at IS NULL THEN
    RAISE EXCEPTION 'ticket number allocation inputs are required'
      USING ERRCODE = '22023';
  END IF;
  target_period := extract(year FROM p_at AT TIME ZONE 'UTC')::integer;
  prefix := CASE p_aggregate_kind WHEN 'alert' THEN 'ALT' ELSE 'CAS' END;

  INSERT INTO public.ticket_number_counters (
    tenant_id, aggregate_kind, period, next_value
  ) VALUES (p_tenant_id, p_aggregate_kind, target_period, 2)
  ON CONFLICT (tenant_id, aggregate_kind, period)
  DO UPDATE SET next_value = public.ticket_number_counters.next_value + 1,
                updated_at = transaction_timestamp()
  WHERE public.ticket_number_counters.next_value < 2147483647
  RETURNING next_value - 1 INTO allocated;

  IF allocated IS NULL THEN
    RAISE EXCEPTION 'ticket number sequence is exhausted'
      USING ERRCODE = '54000';
  END IF;
  RETURN format('%s-%s-%s', prefix, target_period, lpad(allocated::text, 6, '0'));
END;
$function$;--> statement-breakpoint

ALTER FUNCTION app.private_next_ticket_number_v1(uuid, public.ticket_aggregate_kind, timestamp with time zone) OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_next_ticket_number_v1(uuid, public.ticket_aggregate_kind, timestamp with time zone) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint

CREATE FUNCTION app.prepare_alert_ticketing_defaults_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  requested_workflow_id uuid;
  selected_workflow record;
  initial_state text;
BEGIN
  requested_workflow_id := coalesce(
    NEW.workflow_id,
    nullif(current_setting('app.ticketing_alert_workflow_id', true), '')::uuid
  );

  SELECT workflow.id, workflow.current_version, version.states
    INTO selected_workflow
  FROM public.ticket_workflows AS workflow
  JOIN public.ticket_workflow_versions AS version
    ON version.tenant_id = workflow.tenant_id
   AND version.workflow_id = workflow.id
   AND version.aggregate_kind = workflow.aggregate_kind
   AND version.version = workflow.current_version
  WHERE workflow.tenant_id = NEW.tenant_id
    AND workflow.aggregate_kind = 'alert'
    AND workflow.archived_at IS NULL
    AND (
      requested_workflow_id IS NOT NULL AND workflow.id = requested_workflow_id
      OR requested_workflow_id IS NULL AND workflow.is_default
    );
  IF NOT FOUND THEN
    RAISE EXCEPTION 'published Alert workflow is unavailable'
      USING ERRCODE = '23503';
  END IF;

  SELECT state.value ->> 'key' INTO STRICT initial_state
  FROM jsonb_array_elements(selected_workflow.states) AS state(value)
  WHERE (state.value ->> 'initial')::boolean;

  NEW.workflow_id := selected_workflow.id;
  NEW.workflow_version := selected_workflow.current_version;
  NEW.state_key := initial_state;
  NEW.number := coalesce(
    NEW.number,
    app.private_next_ticket_number_v1(NEW.tenant_id, 'alert', NEW.created_at)
  );
  RETURN NEW;
END;
$function$;--> statement-breakpoint

ALTER FUNCTION app.prepare_alert_ticketing_defaults_v1() OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.prepare_alert_ticketing_defaults_v1() FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint

CREATE TRIGGER alerts_ticketing_defaults_v1
BEFORE INSERT ON public.alerts
FOR EACH ROW EXECUTE FUNCTION app.prepare_alert_ticketing_defaults_v1();--> statement-breakpoint

CREATE FUNCTION app.append_alert_ticketing_create_effects_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  principal public.ticket_principal_kind;
BEGIN
  principal := CASE
    WHEN NEW.created_by_membership_id IS NOT NULL THEN 'human'
    ELSE 'service_account'
  END;
  INSERT INTO public.ticket_activities (
    tenant_id, alert_id, sequence, kind, summary,
    actor_principal_kind, actor_membership_id, actor_user_id,
    actor_service_account_id, origin, details, occurred_at
  ) VALUES (
    NEW.tenant_id, NEW.id, 1, 'alert.created', 'Alert created',
    principal, NEW.created_by_membership_id, NEW.created_by,
    NEW.created_by_service_account_id, 'api',
    jsonb_build_object('severity', NEW.severity, 'version', 1), NEW.created_at
  );

  INSERT INTO public.outbox_events (
    tenant_id, aggregate_type, aggregate_id, event_type, schema_version,
    payload, deduplication_key, occurred_at
  ) VALUES
    (
      NEW.tenant_id, 'alert', NEW.id, 'sla.alert.created', 1,
      jsonb_build_object('alert_id', NEW.id, 'version', 1),
      'sla.alert.created:' || NEW.id::text, NEW.created_at
    ),
    (
      NEW.tenant_id, 'alert', NEW.id, 'notification.alert.created', 1,
      jsonb_build_object('alert_id', NEW.id, 'version', 1),
      'notification.alert.created:' || NEW.id::text, NEW.created_at
    );
  RETURN NEW;
END;
$function$;--> statement-breakpoint

ALTER FUNCTION app.append_alert_ticketing_create_effects_v1() OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.append_alert_ticketing_create_effects_v1() FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint

CREATE TRIGGER alerts_ticketing_create_effects_v1
AFTER INSERT ON public.alerts
FOR EACH ROW EXECUTE FUNCTION app.append_alert_ticketing_create_effects_v1();--> statement-breakpoint

WITH ranked_alerts AS (
  SELECT alert.id,
         alert.tenant_id,
         extract(year FROM alert.created_at AT TIME ZONE 'UTC')::integer AS period,
         row_number() OVER (
           PARTITION BY alert.tenant_id,
                        extract(year FROM alert.created_at AT TIME ZONE 'UTC')::integer
           ORDER BY alert.created_at, alert.id
         )::integer AS sequence
  FROM public.alerts AS alert
), default_workflows AS (
  SELECT workflow.tenant_id, workflow.id, workflow.current_version
  FROM public.ticket_workflows AS workflow
  WHERE workflow.aggregate_kind = 'alert'
    AND workflow.is_default
    AND workflow.archived_at IS NULL
)
UPDATE public.alerts AS alert
SET number = coalesce(
      alert.number,
      format('ALT-%s-%s', ranked.period, to_char(ranked.sequence, 'FM000000'))
    ),
    workflow_id = coalesce(alert.workflow_id, default_workflows.id),
    workflow_version = default_workflows.current_version,
    state_key = CASE alert.status
      WHEN 'new' THEN 'new'
      WHEN 'in_progress' THEN 'in_progress'
      WHEN 'closed' THEN 'closed'
    END
FROM ranked_alerts AS ranked
JOIN default_workflows ON default_workflows.tenant_id = ranked.tenant_id
WHERE alert.tenant_id = ranked.tenant_id
  AND alert.id = ranked.id;--> statement-breakpoint

INSERT INTO public.ticket_number_counters (
  tenant_id, aggregate_kind, period, next_value
)
SELECT alert.tenant_id,
       'alert'::public.ticket_aggregate_kind,
       extract(year FROM alert.created_at AT TIME ZONE 'UTC')::integer,
       count(*)::integer + 1
FROM public.alerts AS alert
GROUP BY alert.tenant_id,
         extract(year FROM alert.created_at AT TIME ZONE 'UTC')::integer
ON CONFLICT (tenant_id, aggregate_kind, period)
DO UPDATE SET next_value = greatest(
  public.ticket_number_counters.next_value,
  excluded.next_value
), updated_at = transaction_timestamp();--> statement-breakpoint

DO $ticketing_foundation_assertions$
DECLARE
  permission_count integer;
BEGIN
  SELECT count(*) INTO permission_count
  FROM public.tenant_permissions AS permission
  WHERE permission.key IN (
    'alert.read', 'alert.activity.read', 'alert.comment.read', 'alert.link.read',
    'alert.update', 'alert.assign', 'alert.claim', 'alert.escalate',
    'alert.comment.public', 'alert.comment.private',
    'case.read', 'case.activity.read', 'case.comment.read', 'case.link.read',
    'case.create', 'case.update', 'case.claim', 'case.transfer',
    'case.transition', 'case.comment.public', 'case.comment.private'
  );
  IF permission_count <> 21 THEN
    RAISE EXCEPTION 'ticketing permission catalog is incomplete'
      USING ERRCODE = '55000';
  END IF;
  IF EXISTS (
    SELECT 1
    FROM public.tenant_permission_scopes AS permission_scope
    JOIN public.tenant_permissions AS permission
      ON permission.id = permission_scope.permission_id
    WHERE permission.key LIKE ANY(ARRAY['alert.%', 'case.%'])
      AND permission_scope.scope = 'platform'
  ) THEN
    RAISE EXCEPTION 'ticketing permissions cannot grant platform scope'
      USING ERRCODE = '55000';
  END IF;
  IF EXISTS (
    SELECT 1 FROM public.alerts
    WHERE number IS NULL OR workflow_id IS NULL
  ) THEN
    RAISE EXCEPTION 'rolling Alert ticketing backfill is incomplete'
      USING ERRCODE = '55000';
  END IF;
END;
$ticketing_foundation_assertions$;
