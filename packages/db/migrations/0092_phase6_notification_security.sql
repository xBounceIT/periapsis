-- Phase 6 notification persistence security boundary. Generated table shape is
-- kept in 0091-0092; this successor adds forced RLS, least-privilege function
-- owners, append-only evidence, catalog grants, and the canonical v2 producer.

DO $notification_owners$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'periapsis_notification_admin_owner') THEN
    CREATE ROLE periapsis_notification_admin_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'periapsis_notification_dispatch_owner') THEN
    CREATE ROLE periapsis_notification_dispatch_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'periapsis_notification_readiness_owner') THEN
    CREATE ROLE periapsis_notification_readiness_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_catalog.pg_roles
    WHERE rolname IN (
      'periapsis_notification_admin_owner',
      'periapsis_notification_dispatch_owner',
      'periapsis_notification_readiness_owner'
    ) AND (rolcanlogin OR rolsuper OR rolcreatedb OR rolcreaterole OR rolinherit OR rolreplication OR rolbypassrls)
  ) THEN
    RAISE EXCEPTION 'notification function owner is privileged' USING ERRCODE = '55000';
  END IF;
END
$notification_owners$;--> statement-breakpoint

ALTER TABLE public.platform_notification_commands OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TABLE public.platform_notification_secret_versions OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TABLE public.platform_notification_smtp_configuration_versions OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TABLE public.platform_notification_smtp_configurations OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TABLE public.tenant_notification_commands OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TABLE public.tenant_notification_deliveries OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TABLE public.tenant_notification_delivery_attempts OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TABLE public.tenant_notification_fanout_snapshots OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TABLE public.tenant_notification_rule_versions OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TABLE public.tenant_notification_rules OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TABLE public.tenant_notification_secret_versions OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TABLE public.tenant_notification_smtp_configuration_versions OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TABLE public.tenant_notification_smtp_configurations OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TABLE public.tenant_notification_template_versions OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TABLE public.tenant_notification_templates OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TABLE public.tenant_notification_webhook_configuration_versions OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TABLE public.tenant_notification_webhook_configurations OWNER TO periapsis_migrator;--> statement-breakpoint

ALTER TABLE public.platform_notification_commands ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE public.platform_notification_commands FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE public.platform_notification_secret_versions ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE public.platform_notification_secret_versions FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE public.platform_notification_smtp_configuration_versions ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE public.platform_notification_smtp_configuration_versions FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE public.platform_notification_smtp_configurations ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE public.platform_notification_smtp_configurations FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE public.tenant_notification_commands FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE public.tenant_notification_deliveries FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE public.tenant_notification_delivery_attempts FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE public.tenant_notification_fanout_snapshots FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE public.tenant_notification_rule_versions FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE public.tenant_notification_rules FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE public.tenant_notification_secret_versions FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE public.tenant_notification_smtp_configuration_versions FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE public.tenant_notification_smtp_configurations FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE public.tenant_notification_template_versions FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE public.tenant_notification_templates FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE public.tenant_notification_webhook_configuration_versions FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE public.tenant_notification_webhook_configurations FORCE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE UNIQUE INDEX platform_notification_smtp_one_live_idx ON public.platform_notification_smtp_configurations ((true)) WHERE revoked_at IS NULL;--> statement-breakpoint

REVOKE ALL ON TABLE
  public.platform_notification_commands,
  public.platform_notification_secret_versions,
  public.platform_notification_smtp_configuration_versions,
  public.platform_notification_smtp_configurations,
  public.tenant_notification_commands,
  public.tenant_notification_deliveries,
  public.tenant_notification_delivery_attempts,
  public.tenant_notification_fanout_snapshots,
  public.tenant_notification_rule_versions,
  public.tenant_notification_rules,
  public.tenant_notification_secret_versions,
  public.tenant_notification_smtp_configuration_versions,
  public.tenant_notification_smtp_configurations,
  public.tenant_notification_template_versions,
  public.tenant_notification_templates,
  public.tenant_notification_webhook_configuration_versions,
  public.tenant_notification_webhook_configurations
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint

REVOKE SELECT, UPDATE ON TABLE public.outbox_events FROM periapsis_notifier;--> statement-breakpoint
REVOKE SELECT ON TABLE public.outbox_events FROM periapsis_api;--> statement-breakpoint

GRANT USAGE ON SCHEMA app, public TO periapsis_notification_admin_owner, periapsis_notification_dispatch_owner, periapsis_notification_readiness_owner;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.context_tenant_id(), app.context_user_id(), app.current_tenant_membership_id(), app.current_tenant_human_has_exact_permission_v3(text, public.authorization_scope), app.platform_user_has_permission(uuid, text), app.append_tenant_authorization_audit(uuid, text, text, uuid, uuid, uuid, inet, text, text, jsonb, jsonb, jsonb), app.append_platform_audit_event(uuid, public.audit_actor_type, uuid, text, text, uuid, uuid, uuid, inet, text, text, public.audit_outcome, text, jsonb)
TO periapsis_notification_admin_owner;--> statement-breakpoint

-- Phase 4 ticket RLS policies invoke these bounded context readers under the
-- caller. The API needs EXECUTE to evaluate those policies, but receives no
-- direct notification-table privilege or authorization bypass.
GRANT EXECUTE ON FUNCTION app.context_tenant_id(), app.context_user_id(),
  app.current_tenant_membership_id()
TO periapsis_api;--> statement-breakpoint

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE
  public.tenant_notification_commands,
  public.tenant_notification_deliveries,
  public.tenant_notification_rule_versions,
  public.tenant_notification_rules,
  public.tenant_notification_secret_versions,
  public.tenant_notification_smtp_configuration_versions,
  public.tenant_notification_smtp_configurations,
  public.tenant_notification_template_versions,
  public.tenant_notification_templates,
  public.tenant_notification_webhook_configuration_versions,
  public.tenant_notification_webhook_configurations
TO periapsis_notification_admin_owner;--> statement-breakpoint
GRANT SELECT ON TABLE public.tenant_notification_delivery_attempts, public.tenant_notification_fanout_snapshots TO periapsis_notification_admin_owner;--> statement-breakpoint
GRANT SELECT, INSERT ON TABLE public.outbox_events TO periapsis_notification_admin_owner;--> statement-breakpoint
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.platform_notification_commands, public.platform_notification_secret_versions, public.platform_notification_smtp_configuration_versions, public.platform_notification_smtp_configurations TO periapsis_notification_admin_owner;--> statement-breakpoint

GRANT SELECT, UPDATE ON TABLE public.outbox_events TO periapsis_notification_dispatch_owner;--> statement-breakpoint
GRANT SELECT ON TABLE public.tenants, public.tenant_memberships, public.tenant_user_profiles, public.users, public.tenant_roles, public.tenant_role_permissions, public.tenant_membership_role_grants, public.tenant_authorization_sources, public.operator_team_roster_entries TO periapsis_notification_dispatch_owner;--> statement-breakpoint
GRANT SELECT ON TABLE public.tenant_notification_rule_versions, public.tenant_notification_rules, public.tenant_notification_template_versions, public.tenant_notification_templates, public.tenant_notification_smtp_configuration_versions, public.tenant_notification_smtp_configurations, public.tenant_notification_secret_versions, public.tenant_notification_webhook_configuration_versions, public.tenant_notification_webhook_configurations, public.platform_notification_smtp_configuration_versions, public.platform_notification_smtp_configurations, public.platform_notification_secret_versions TO periapsis_notification_dispatch_owner;--> statement-breakpoint
GRANT SELECT, INSERT, UPDATE ON TABLE public.tenant_notification_fanout_snapshots, public.tenant_notification_deliveries TO periapsis_notification_dispatch_owner;--> statement-breakpoint
GRANT SELECT, INSERT, UPDATE ON TABLE public.tenant_notification_delivery_attempts TO periapsis_notification_dispatch_owner;--> statement-breakpoint
GRANT SELECT (key_version) ON TABLE public.tenant_notification_secret_versions, public.platform_notification_secret_versions TO periapsis_notification_readiness_owner;--> statement-breakpoint

CREATE POLICY notification_admin_owner_tenant_commands_v1 ON public.tenant_notification_commands AS PERMISSIVE FOR ALL TO periapsis_notification_admin_owner USING (tenant_id = app.context_tenant_id() AND actor_membership_id = app.current_tenant_membership_id()) WITH CHECK (tenant_id = app.context_tenant_id() AND actor_membership_id = app.current_tenant_membership_id());--> statement-breakpoint
CREATE POLICY notification_admin_owner_tenant_deliveries_v1 ON public.tenant_notification_deliveries AS PERMISSIVE FOR ALL TO periapsis_notification_admin_owner USING (tenant_id = app.context_tenant_id() AND app.current_tenant_membership_id() IS NOT NULL) WITH CHECK (tenant_id = app.context_tenant_id() AND app.current_tenant_membership_id() IS NOT NULL);--> statement-breakpoint
CREATE POLICY notification_admin_owner_delivery_attempts_v1 ON public.tenant_notification_delivery_attempts AS PERMISSIVE FOR SELECT TO periapsis_notification_admin_owner USING (tenant_id = app.context_tenant_id() AND app.current_tenant_membership_id() IS NOT NULL);--> statement-breakpoint
CREATE POLICY notification_admin_owner_fanout_snapshots_v1 ON public.tenant_notification_fanout_snapshots AS PERMISSIVE FOR SELECT TO periapsis_notification_admin_owner USING (tenant_id = app.context_tenant_id() AND app.current_tenant_membership_id() IS NOT NULL);--> statement-breakpoint
CREATE POLICY notification_admin_owner_rules_v1 ON public.tenant_notification_rules AS PERMISSIVE FOR ALL TO periapsis_notification_admin_owner USING (tenant_id = app.context_tenant_id() AND app.current_tenant_membership_id() IS NOT NULL) WITH CHECK (tenant_id = app.context_tenant_id() AND app.current_tenant_membership_id() IS NOT NULL);--> statement-breakpoint
CREATE POLICY notification_admin_owner_rule_versions_v1 ON public.tenant_notification_rule_versions AS PERMISSIVE FOR ALL TO periapsis_notification_admin_owner USING (tenant_id = app.context_tenant_id() AND app.current_tenant_membership_id() IS NOT NULL) WITH CHECK (tenant_id = app.context_tenant_id() AND app.current_tenant_membership_id() IS NOT NULL);--> statement-breakpoint
CREATE POLICY notification_admin_owner_secrets_v1 ON public.tenant_notification_secret_versions AS PERMISSIVE FOR ALL TO periapsis_notification_admin_owner USING (tenant_id = app.context_tenant_id() AND app.current_tenant_membership_id() IS NOT NULL) WITH CHECK (tenant_id = app.context_tenant_id() AND app.current_tenant_membership_id() IS NOT NULL);--> statement-breakpoint
CREATE POLICY notification_admin_owner_smtp_v1 ON public.tenant_notification_smtp_configurations AS PERMISSIVE FOR ALL TO periapsis_notification_admin_owner USING (tenant_id = app.context_tenant_id() AND app.current_tenant_membership_id() IS NOT NULL) WITH CHECK (tenant_id = app.context_tenant_id() AND app.current_tenant_membership_id() IS NOT NULL);--> statement-breakpoint
CREATE POLICY notification_admin_owner_smtp_versions_v1 ON public.tenant_notification_smtp_configuration_versions AS PERMISSIVE FOR ALL TO periapsis_notification_admin_owner USING (tenant_id = app.context_tenant_id() AND app.current_tenant_membership_id() IS NOT NULL) WITH CHECK (tenant_id = app.context_tenant_id() AND app.current_tenant_membership_id() IS NOT NULL);--> statement-breakpoint
CREATE POLICY notification_admin_owner_templates_v1 ON public.tenant_notification_templates AS PERMISSIVE FOR ALL TO periapsis_notification_admin_owner USING (tenant_id = app.context_tenant_id() AND app.current_tenant_membership_id() IS NOT NULL) WITH CHECK (tenant_id = app.context_tenant_id() AND app.current_tenant_membership_id() IS NOT NULL);--> statement-breakpoint
CREATE POLICY notification_admin_owner_template_versions_v1 ON public.tenant_notification_template_versions AS PERMISSIVE FOR ALL TO periapsis_notification_admin_owner USING (tenant_id = app.context_tenant_id() AND app.current_tenant_membership_id() IS NOT NULL) WITH CHECK (tenant_id = app.context_tenant_id() AND app.current_tenant_membership_id() IS NOT NULL);--> statement-breakpoint
CREATE POLICY notification_admin_owner_webhooks_v1 ON public.tenant_notification_webhook_configurations AS PERMISSIVE FOR ALL TO periapsis_notification_admin_owner USING (tenant_id = app.context_tenant_id() AND app.current_tenant_membership_id() IS NOT NULL) WITH CHECK (tenant_id = app.context_tenant_id() AND app.current_tenant_membership_id() IS NOT NULL);--> statement-breakpoint
CREATE POLICY notification_admin_owner_webhook_versions_v1 ON public.tenant_notification_webhook_configuration_versions AS PERMISSIVE FOR ALL TO periapsis_notification_admin_owner USING (tenant_id = app.context_tenant_id() AND app.current_tenant_membership_id() IS NOT NULL) WITH CHECK (tenant_id = app.context_tenant_id() AND app.current_tenant_membership_id() IS NOT NULL);--> statement-breakpoint

CREATE POLICY notification_admin_owner_platform_commands_v1 ON public.platform_notification_commands AS PERMISSIVE FOR ALL TO periapsis_notification_admin_owner USING (app.platform_user_has_permission(app.context_user_id(), 'platform.notification.manage')) WITH CHECK (app.platform_user_has_permission(app.context_user_id(), 'platform.notification.manage'));--> statement-breakpoint
CREATE POLICY notification_admin_owner_platform_secrets_v1 ON public.platform_notification_secret_versions AS PERMISSIVE FOR ALL TO periapsis_notification_admin_owner USING (app.platform_user_has_permission(app.context_user_id(), 'platform.notification.manage')) WITH CHECK (app.platform_user_has_permission(app.context_user_id(), 'platform.notification.manage'));--> statement-breakpoint
CREATE POLICY notification_admin_owner_platform_smtp_v1 ON public.platform_notification_smtp_configurations AS PERMISSIVE FOR ALL TO periapsis_notification_admin_owner USING (app.platform_user_has_permission(app.context_user_id(), 'platform.notification.manage')) WITH CHECK (app.platform_user_has_permission(app.context_user_id(), 'platform.notification.manage'));--> statement-breakpoint
CREATE POLICY notification_admin_owner_platform_smtp_versions_v1 ON public.platform_notification_smtp_configuration_versions AS PERMISSIVE FOR ALL TO periapsis_notification_admin_owner USING (app.platform_user_has_permission(app.context_user_id(), 'platform.notification.manage')) WITH CHECK (app.platform_user_has_permission(app.context_user_id(), 'platform.notification.manage'));--> statement-breakpoint

CREATE POLICY notification_dispatch_owner_outbox_v1 ON public.outbox_events AS PERMISSIVE FOR ALL TO periapsis_notification_dispatch_owner USING (event_type LIKE 'notification.%') WITH CHECK (event_type LIKE 'notification.%');--> statement-breakpoint
CREATE POLICY notification_admin_owner_outbox_v1 ON public.outbox_events AS PERMISSIVE FOR ALL TO periapsis_notification_admin_owner USING (tenant_id = app.context_tenant_id() AND event_type LIKE 'notification.%') WITH CHECK (tenant_id = app.context_tenant_id() AND event_type LIKE 'notification.%');--> statement-breakpoint
CREATE POLICY notification_dispatch_owner_deliveries_v1 ON public.tenant_notification_deliveries AS PERMISSIVE FOR ALL TO periapsis_notification_dispatch_owner USING (tenant_id = app.context_tenant_id()) WITH CHECK (tenant_id = app.context_tenant_id());--> statement-breakpoint
CREATE POLICY notification_dispatch_owner_delivery_claim_global_v1 ON public.tenant_notification_deliveries AS PERMISSIVE FOR ALL TO periapsis_notification_dispatch_owner USING (true) WITH CHECK (true);--> statement-breakpoint
CREATE POLICY notification_dispatch_owner_attempts_v1 ON public.tenant_notification_delivery_attempts AS PERMISSIVE FOR ALL TO periapsis_notification_dispatch_owner USING (tenant_id = app.context_tenant_id()) WITH CHECK (tenant_id = app.context_tenant_id());--> statement-breakpoint
CREATE POLICY notification_dispatch_owner_attempts_global_claim_v1 ON public.tenant_notification_delivery_attempts AS PERMISSIVE FOR ALL TO periapsis_notification_dispatch_owner USING (true) WITH CHECK (true);--> statement-breakpoint
CREATE POLICY notification_dispatch_owner_snapshots_v1 ON public.tenant_notification_fanout_snapshots AS PERMISSIVE FOR ALL TO periapsis_notification_dispatch_owner USING (tenant_id = app.context_tenant_id()) WITH CHECK (tenant_id = app.context_tenant_id());--> statement-breakpoint
CREATE POLICY notification_dispatch_owner_rules_v1 ON public.tenant_notification_rules AS PERMISSIVE FOR SELECT TO periapsis_notification_dispatch_owner USING (tenant_id = app.context_tenant_id());--> statement-breakpoint
CREATE POLICY notification_dispatch_owner_rule_versions_v1 ON public.tenant_notification_rule_versions AS PERMISSIVE FOR SELECT TO periapsis_notification_dispatch_owner USING (tenant_id = app.context_tenant_id());--> statement-breakpoint
CREATE POLICY notification_dispatch_owner_templates_v1 ON public.tenant_notification_templates AS PERMISSIVE FOR SELECT TO periapsis_notification_dispatch_owner USING (tenant_id = app.context_tenant_id());--> statement-breakpoint
CREATE POLICY notification_dispatch_owner_template_versions_v1 ON public.tenant_notification_template_versions AS PERMISSIVE FOR SELECT TO periapsis_notification_dispatch_owner USING (tenant_id = app.context_tenant_id());--> statement-breakpoint
CREATE POLICY notification_dispatch_owner_template_versions_global_claim_v1 ON public.tenant_notification_template_versions AS PERMISSIVE FOR SELECT TO periapsis_notification_dispatch_owner USING (true);--> statement-breakpoint
CREATE POLICY notification_dispatch_owner_smtp_v1 ON public.tenant_notification_smtp_configurations AS PERMISSIVE FOR SELECT TO periapsis_notification_dispatch_owner USING (tenant_id = app.context_tenant_id());--> statement-breakpoint
CREATE POLICY notification_dispatch_owner_smtp_versions_v1 ON public.tenant_notification_smtp_configuration_versions AS PERMISSIVE FOR SELECT TO periapsis_notification_dispatch_owner USING (tenant_id = app.context_tenant_id());--> statement-breakpoint
CREATE POLICY notification_dispatch_owner_secrets_v1 ON public.tenant_notification_secret_versions AS PERMISSIVE FOR SELECT TO periapsis_notification_dispatch_owner USING (tenant_id = app.context_tenant_id());--> statement-breakpoint
CREATE POLICY notification_dispatch_owner_secrets_global_claim_v1 ON public.tenant_notification_secret_versions AS PERMISSIVE FOR SELECT TO periapsis_notification_dispatch_owner USING (true);--> statement-breakpoint
CREATE POLICY notification_dispatch_owner_webhooks_v1 ON public.tenant_notification_webhook_configurations AS PERMISSIVE FOR SELECT TO periapsis_notification_dispatch_owner USING (tenant_id = app.context_tenant_id());--> statement-breakpoint
CREATE POLICY notification_dispatch_owner_webhooks_global_claim_v1 ON public.tenant_notification_webhook_configurations AS PERMISSIVE FOR SELECT TO periapsis_notification_dispatch_owner USING (true);--> statement-breakpoint
CREATE POLICY notification_dispatch_owner_webhook_versions_v1 ON public.tenant_notification_webhook_configuration_versions AS PERMISSIVE FOR SELECT TO periapsis_notification_dispatch_owner USING (tenant_id = app.context_tenant_id());--> statement-breakpoint
CREATE POLICY notification_dispatch_owner_webhook_versions_global_claim_v1 ON public.tenant_notification_webhook_configuration_versions AS PERMISSIVE FOR SELECT TO periapsis_notification_dispatch_owner USING (true);--> statement-breakpoint
CREATE POLICY notification_dispatch_owner_platform_smtp_v1 ON public.platform_notification_smtp_configurations AS PERMISSIVE FOR SELECT TO periapsis_notification_dispatch_owner USING (true);--> statement-breakpoint
CREATE POLICY notification_dispatch_owner_platform_smtp_versions_v1 ON public.platform_notification_smtp_configuration_versions AS PERMISSIVE FOR SELECT TO periapsis_notification_dispatch_owner USING (true);--> statement-breakpoint
CREATE POLICY notification_dispatch_owner_platform_secrets_v1 ON public.platform_notification_secret_versions AS PERMISSIVE FOR SELECT TO periapsis_notification_dispatch_owner USING (true);--> statement-breakpoint
CREATE POLICY notification_readiness_owner_tenant_secrets_v1 ON public.tenant_notification_secret_versions AS PERMISSIVE FOR SELECT TO periapsis_notification_readiness_owner USING (true);--> statement-breakpoint
CREATE POLICY notification_readiness_owner_platform_secrets_v1 ON public.platform_notification_secret_versions AS PERMISSIVE FOR SELECT TO periapsis_notification_readiness_owner USING (true);--> statement-breakpoint

CREATE POLICY notification_dispatch_owner_tenants_v1 ON public.tenants AS PERMISSIVE FOR SELECT TO periapsis_notification_dispatch_owner USING (id = app.context_tenant_id());--> statement-breakpoint
CREATE POLICY notification_dispatch_owner_memberships_v1 ON public.tenant_memberships AS PERMISSIVE FOR SELECT TO periapsis_notification_dispatch_owner USING (tenant_id = app.context_tenant_id());--> statement-breakpoint
CREATE POLICY notification_dispatch_owner_profiles_v1 ON public.tenant_user_profiles AS PERMISSIVE FOR SELECT TO periapsis_notification_dispatch_owner USING (tenant_id = app.context_tenant_id());--> statement-breakpoint
CREATE POLICY notification_dispatch_owner_users_v1 ON public.users AS PERMISSIVE FOR SELECT TO periapsis_notification_dispatch_owner USING (EXISTS (SELECT 1 FROM public.tenant_memberships AS membership WHERE membership.tenant_id = app.context_tenant_id() AND membership.user_id = users.id));--> statement-breakpoint
CREATE POLICY notification_dispatch_owner_tenant_roles_v1 ON public.tenant_roles AS PERMISSIVE FOR SELECT TO periapsis_notification_dispatch_owner USING (tenant_id = app.context_tenant_id());--> statement-breakpoint
CREATE POLICY notification_dispatch_owner_role_permissions_v1 ON public.tenant_role_permissions AS PERMISSIVE FOR SELECT TO periapsis_notification_dispatch_owner USING (tenant_id = app.context_tenant_id());--> statement-breakpoint
CREATE POLICY notification_dispatch_owner_membership_grants_v1 ON public.tenant_membership_role_grants AS PERMISSIVE FOR SELECT TO periapsis_notification_dispatch_owner USING (tenant_id = app.context_tenant_id());--> statement-breakpoint
CREATE POLICY notification_dispatch_owner_authorization_sources_v1 ON public.tenant_authorization_sources AS PERMISSIVE FOR SELECT TO periapsis_notification_dispatch_owner USING (tenant_id = app.context_tenant_id());--> statement-breakpoint
CREATE POLICY notification_dispatch_owner_operator_team_roster_v1 ON public.operator_team_roster_entries AS PERMISSIVE FOR SELECT TO periapsis_notification_dispatch_owner USING (tenant_id = app.context_tenant_id());--> statement-breakpoint

CREATE FUNCTION app.guard_notification_event_tenant_equivalence_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF NEW.tenant_id IS NULL
     OR NEW.event_id IS NULL
     OR NOT EXISTS (
       SELECT 1
       FROM public.outbox_events AS event
       WHERE event.id = NEW.event_id
         AND event.tenant_id = NEW.tenant_id
         AND event.event_type LIKE 'notification.%'
     ) THEN
    RAISE EXCEPTION 'notification event reference is invalid'
      USING ERRCODE = '23514';
  END IF;

  RETURN NEW;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.guard_notification_event_tenant_equivalence_v1() OWNER TO periapsis_notification_dispatch_owner;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.guard_notification_event_tenant_equivalence_v1() FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint

CREATE TRIGGER tenant_notification_deliveries_event_tenant_guard_v1
BEFORE INSERT OR UPDATE OF tenant_id, event_id ON public.tenant_notification_deliveries
FOR EACH ROW EXECUTE FUNCTION app.guard_notification_event_tenant_equivalence_v1();--> statement-breakpoint
CREATE TRIGGER tenant_notification_fanout_snapshots_event_tenant_guard_v1
BEFORE INSERT OR UPDATE OF tenant_id, event_id ON public.tenant_notification_fanout_snapshots
FOR EACH ROW EXECUTE FUNCTION app.guard_notification_event_tenant_equivalence_v1();--> statement-breakpoint

CREATE FUNCTION app.guard_notification_outbox_identity_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF (OLD.event_type LIKE 'notification.%' OR NEW.event_type LIKE 'notification.%')
     AND (
       NEW.id IS DISTINCT FROM OLD.id
       OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.event_type IS DISTINCT FROM OLD.event_type
     ) THEN
    RAISE EXCEPTION 'notification outbox identity is immutable'
      USING ERRCODE = '23514';
  END IF;

  RETURN NEW;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.guard_notification_outbox_identity_v1() OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.guard_notification_outbox_identity_v1() FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
CREATE TRIGGER outbox_events_notification_identity_guard_v1
BEFORE UPDATE OF id, tenant_id, event_type ON public.outbox_events
FOR EACH ROW EXECUTE FUNCTION app.guard_notification_outbox_identity_v1();--> statement-breakpoint

INSERT INTO public.tenant_permissions (id, key, display_name, description, service_account_allowed)
VALUES (uuidv7(), 'notification.manage', 'Manage notifications', 'Manage tenant notification rules, templates, delivery history, SMTP, and webhooks.', false)
ON CONFLICT (key) DO NOTHING;--> statement-breakpoint
INSERT INTO public.tenant_permission_scopes (permission_id, scope)
SELECT permission.id, 'tenant'::public.authorization_scope
FROM public.tenant_permissions AS permission
WHERE permission.key = 'notification.manage'
ON CONFLICT DO NOTHING;--> statement-breakpoint
INSERT INTO public.platform_permissions (id, key, description)
VALUES (uuidv7(), 'platform.notification.manage', 'Manage platform notification transport configuration.')
ON CONFLICT (key) DO NOTHING;--> statement-breakpoint
INSERT INTO public.platform_role_permissions (role_id, permission_id)
SELECT role.id, permission.id
FROM public.platform_roles AS role
CROSS JOIN public.platform_permissions AS permission
WHERE role.key = 'platform_super_admin'
  AND permission.key = 'platform.notification.manage'
ON CONFLICT DO NOTHING;--> statement-breakpoint

CREATE FUNCTION app.private_seed_tenant_notification_authorization_v1(p_tenant_id uuid)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF p_tenant_id IS NULL OR NOT EXISTS (SELECT 1 FROM public.tenants AS tenant WHERE tenant.id = p_tenant_id) THEN
    RAISE EXCEPTION 'tenant not found' USING ERRCODE = 'P0002';
  END IF;
  INSERT INTO public.tenant_role_permissions (tenant_id, role_id, permission_id, scope)
  SELECT p_tenant_id, role.id, permission.id, 'tenant'::public.authorization_scope
  FROM public.tenant_roles AS role
  CROSS JOIN public.tenant_permissions AS permission
  WHERE role.tenant_id = p_tenant_id
    AND role.key = 'tenant_admin'
    AND role.system_role
    AND role.archived_at IS NULL
    AND permission.key = 'notification.manage'
  ON CONFLICT DO NOTHING;
  INSERT INTO public.tenant_role_delegation_ceilings (tenant_id, role_id, permission_id, scope)
  SELECT grant_row.tenant_id, grant_row.role_id, grant_row.permission_id, grant_row.scope
  FROM public.tenant_role_permissions AS grant_row
  JOIN public.tenant_roles AS role
    ON role.tenant_id = grant_row.tenant_id AND role.id = grant_row.role_id
  JOIN public.tenant_permissions AS permission ON permission.id = grant_row.permission_id
  WHERE grant_row.tenant_id = p_tenant_id
    AND role.key = 'tenant_admin'
    AND permission.key = 'notification.manage'
  ON CONFLICT DO NOTHING;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.private_seed_tenant_notification_authorization_v1(uuid) OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_seed_tenant_notification_authorization_v1(uuid) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint

DO $notification_permission_seed$
DECLARE tenant_record record;
BEGIN
  FOR tenant_record IN SELECT tenant.id FROM public.tenants AS tenant ORDER BY tenant.id LOOP
    PERFORM app.private_seed_tenant_notification_authorization_v1(tenant_record.id);
  END LOOP;
END
$notification_permission_seed$;--> statement-breakpoint

-- Give sqlc a static, non-colliding name while the runtime rename remains
-- transactional. PL/pgSQL resolves the compatibility delegate at execution
-- time, after the block below has renamed both functions.
CREATE FUNCTION app.seed_tenant_authorization_phase6_successor(p_tenant_id uuid, p_initial_admin_membership_id uuid)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  PERFORM app.seed_tenant_authorization_phase6_compatibility_impl(p_tenant_id, p_initial_admin_membership_id);
  PERFORM app.private_seed_tenant_notification_authorization_v1(p_tenant_id);
END;
$function$;--> statement-breakpoint
DO $notification_seed_successor$
BEGIN
  EXECUTE 'ALTER FUNCTION app.seed_tenant_authorization(uuid, uuid) RENAME TO seed_tenant_authorization_phase6_compatibility_impl';
  EXECUTE 'ALTER FUNCTION app.seed_tenant_authorization_phase6_successor(uuid, uuid) RENAME TO seed_tenant_authorization';
END
$notification_seed_successor$;--> statement-breakpoint
ALTER FUNCTION app.seed_tenant_authorization(uuid, uuid) OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.seed_tenant_authorization(uuid, uuid), app.seed_tenant_authorization_phase6_compatibility_impl(uuid, uuid) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint

CREATE FUNCTION app.guard_notification_append_only_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  RAISE EXCEPTION 'notification evidence is append-only' USING ERRCODE = '55000';
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.guard_notification_append_only_v1() OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.guard_notification_append_only_v1() FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
CREATE TRIGGER tenant_notification_template_versions_immutable_v1 BEFORE UPDATE OR DELETE ON public.tenant_notification_template_versions FOR EACH ROW EXECUTE FUNCTION app.guard_notification_append_only_v1();--> statement-breakpoint
CREATE TRIGGER tenant_notification_rule_versions_immutable_v1 BEFORE UPDATE OR DELETE ON public.tenant_notification_rule_versions FOR EACH ROW EXECUTE FUNCTION app.guard_notification_append_only_v1();--> statement-breakpoint
CREATE TRIGGER tenant_notification_secret_versions_immutable_v1 BEFORE UPDATE OR DELETE ON public.tenant_notification_secret_versions FOR EACH ROW EXECUTE FUNCTION app.guard_notification_append_only_v1();--> statement-breakpoint
CREATE TRIGGER platform_notification_secret_versions_immutable_v1 BEFORE UPDATE OR DELETE ON public.platform_notification_secret_versions FOR EACH ROW EXECUTE FUNCTION app.guard_notification_append_only_v1();--> statement-breakpoint
CREATE TRIGGER tenant_notification_smtp_versions_immutable_v1 BEFORE UPDATE OR DELETE ON public.tenant_notification_smtp_configuration_versions FOR EACH ROW EXECUTE FUNCTION app.guard_notification_append_only_v1();--> statement-breakpoint
CREATE TRIGGER platform_notification_smtp_versions_immutable_v1 BEFORE UPDATE OR DELETE ON public.platform_notification_smtp_configuration_versions FOR EACH ROW EXECUTE FUNCTION app.guard_notification_append_only_v1();--> statement-breakpoint
CREATE TRIGGER tenant_notification_webhook_versions_immutable_v1 BEFORE UPDATE OR DELETE ON public.tenant_notification_webhook_configuration_versions FOR EACH ROW EXECUTE FUNCTION app.guard_notification_append_only_v1();--> statement-breakpoint
CREATE FUNCTION app.guard_notification_delivery_attempt_transition_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF TG_OP = 'DELETE'
     OR OLD.completed_at IS NOT NULL
     OR OLD.outcome IS NOT NULL
     OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
     OR NEW.delivery_id IS DISTINCT FROM OLD.delivery_id
     OR NEW.attempt IS DISTINCT FROM OLD.attempt
     OR NEW.fence_token IS DISTINCT FROM OLD.fence_token
     OR NEW.started_at IS DISTINCT FROM OLD.started_at
     OR NEW.completed_at IS NULL
     OR NEW.outcome IS NULL THEN
    RAISE EXCEPTION 'notification delivery attempt is immutable'
      USING ERRCODE = '55000';
  END IF;
  RETURN NEW;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.guard_notification_delivery_attempt_transition_v1() OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.guard_notification_delivery_attempt_transition_v1() FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
CREATE TRIGGER tenant_notification_delivery_attempts_transition_v1
BEFORE UPDATE OR DELETE ON public.tenant_notification_delivery_attempts
FOR EACH ROW EXECUTE FUNCTION app.guard_notification_delivery_attempt_transition_v1();--> statement-breakpoint
CREATE TRIGGER tenant_notification_commands_immutable_v1 BEFORE UPDATE OR DELETE ON public.tenant_notification_commands FOR EACH ROW EXECUTE FUNCTION app.guard_notification_append_only_v1();--> statement-breakpoint
CREATE TRIGGER platform_notification_commands_immutable_v1 BEFORE UPDATE OR DELETE ON public.platform_notification_commands FOR EACH ROW EXECUTE FUNCTION app.guard_notification_append_only_v1();--> statement-breakpoint

CREATE FUNCTION app.private_notification_context_is_safe_v1(p_context jsonb)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog, public, app
AS $function$
  WITH RECURSIVE walk(node, depth) AS (
    SELECT p_context, 0
    UNION ALL
    SELECT child.value, walk.depth + 1
    FROM walk
    CROSS JOIN LATERAL jsonb_path_query(walk.node, '$.*') AS child(value)
    WHERE walk.depth < 9
  ), facts AS (
    SELECT
      count(*) AS node_count,
      coalesce(max(depth), 0) AS maximum_depth,
      bool_and(
        CASE jsonb_typeof(node)
          WHEN 'object' THEN (
            SELECT count(*) <= 100
            FROM jsonb_object_keys(node)
          )
          WHEN 'array' THEN jsonb_array_length(node) <= 100
          WHEN 'string' THEN char_length(node #>> '{}') <= 8192
          ELSE true
        END
      ) AS bounded_nodes
    FROM walk
  ), keys AS (
    SELECT key.value
    FROM walk
    CROSS JOIN LATERAL jsonb_object_keys(
      CASE WHEN jsonb_typeof(walk.node) = 'object' THEN walk.node ELSE '{}'::jsonb END
    ) AS key(value)
  )
  SELECT p_context IS NOT NULL
    AND jsonb_typeof(p_context) = 'object'
    AND octet_length(p_context::text) <= 262144
    AND facts.node_count <= 4096
    AND facts.maximum_depth <= 8
    AND facts.bounded_nodes
    AND NOT EXISTS (
      SELECT 1 FROM keys
      WHERE keys.value !~ '^[A-Za-z][A-Za-z0-9_-]{0,63}$'
         OR keys.value IN ('constructor', 'prototype', '__proto__')
    )
  FROM facts;
$function$;--> statement-breakpoint
ALTER FUNCTION app.private_notification_context_is_safe_v1(jsonb) OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_notification_context_is_safe_v1(jsonb) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.private_notification_context_is_safe_v1(jsonb) TO periapsis_notification_admin_owner;--> statement-breakpoint

CREATE FUNCTION app.private_append_tenant_notification_event_v2(
  p_event_id uuid,
  p_event_type public.notification_event_type,
  p_object_type public.notification_object_type,
  p_object_id uuid,
  p_object_version integer,
  p_occurred_at timestamp with time zone,
  p_actor_kind public.ticket_principal_kind,
  p_actor_id uuid,
  p_source text,
  p_maximum_audience public.notification_audience,
  p_operator_context jsonb,
  p_customer_context jsonb,
  p_deduplication_key text,
  p_correlation_id uuid,
  p_causation_id uuid
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  event_prefix text := split_part(p_event_type::text, '.', 1);
BEGIN
  IF context_tenant IS NULL OR app.current_tenant_membership_id() IS NULL
     OR p_event_id IS NULL OR uuid_extract_version(p_event_id) <> 7
     OR p_object_id IS NULL OR uuid_extract_version(p_object_id) <> 7
     OR p_object_version NOT BETWEEN 1 AND 2147483647
     OR p_occurred_at IS NULL
     OR p_occurred_at > transaction_timestamp() + interval '1 minute'
     OR p_occurred_at < transaction_timestamp() - interval '30 days'
     OR p_actor_kind IS NULL
     OR ((p_actor_kind = 'system') IS DISTINCT FROM (p_actor_id IS NULL))
     OR p_source IS NULL OR p_source !~ '^[a-z][a-z0-9_.-]{1,127}$'
     OR NOT app.private_notification_context_is_safe_v1(p_operator_context)
     OR p_operator_context ? 'customer'
     OR (p_maximum_audience = 'customer') IS DISTINCT FROM (p_customer_context IS NOT NULL)
     OR (p_customer_context IS NOT NULL
       AND NOT app.private_notification_context_is_safe_v1(p_customer_context))
     OR p_event_type = 'comment.private_added' AND p_maximum_audience <> 'operator'
     OR p_deduplication_key IS NULL OR char_length(p_deduplication_key) NOT BETWEEN 1 AND 240
     OR p_deduplication_key ~ '[[:cntrl:]]'
     OR p_correlation_id IS NULL OR p_causation_id IS NULL
     OR (event_prefix = 'alert' AND p_object_type <> 'alert')
     OR (event_prefix = 'case' AND p_object_type <> 'case')
     OR (event_prefix = 'task' AND p_object_type <> 'task')
     OR (event_prefix = 'evidence' AND p_object_type <> 'evidence')
     OR (event_prefix = 'contact' AND p_object_type <> 'contact')
     OR (event_prefix = 'comment' AND p_object_type NOT IN ('alert', 'case'))
     OR (event_prefix = 'sla' AND p_object_type NOT IN ('alert', 'case', 'task')) THEN
    RAISE EXCEPTION 'notification event envelope is invalid' USING ERRCODE = '22023';
  END IF;

  INSERT INTO public.outbox_events (
    id, tenant_id, aggregate_type, aggregate_id, aggregate_version,
    event_type, schema_version, payload, deduplication_key,
    correlation_id, causation_id, actor_kind, actor_id, producer,
    maximum_audience, occurred_at, available_at
  ) VALUES (
    p_event_id, context_tenant, p_object_type::text, p_object_id,
    p_object_version, 'notification.' || p_event_type::text, 2,
    jsonb_build_object('operatorContext', p_operator_context)
      || CASE WHEN p_customer_context IS NULL THEN '{}'::jsonb
              ELSE jsonb_build_object('customerContext', p_customer_context) END,
    p_deduplication_key, p_correlation_id, p_causation_id,
    p_actor_kind, p_actor_id, p_source, p_maximum_audience,
    p_occurred_at, greatest(p_occurred_at, transaction_timestamp())
  );
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.private_append_tenant_notification_event_v2(uuid, public.notification_event_type, public.notification_object_type, uuid, integer, timestamp with time zone, public.ticket_principal_kind, uuid, text, public.notification_audience, jsonb, jsonb, text, uuid, uuid) OWNER TO periapsis_notification_admin_owner;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_append_tenant_notification_event_v2(uuid, public.notification_event_type, public.notification_object_type, uuid, integer, timestamp with time zone, public.ticket_principal_kind, uuid, text, public.notification_audience, jsonb, jsonb, text, uuid, uuid) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.private_append_tenant_notification_event_v2(uuid, public.notification_event_type, public.notification_object_type, uuid, integer, timestamp with time zone, public.ticket_principal_kind, uuid, text, public.notification_audience, jsonb, jsonb, text, uuid, uuid) TO periapsis_migrator;--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.private_append_ticket_side_effects_v1(
  p_aggregate_kind public.ticket_aggregate_kind,
  p_aggregate_id uuid,
  p_action text,
  p_version integer,
  p_effects text[],
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text,
  p_before jsonb,
  p_after jsonb,
  p_metadata jsonb
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  actor_membership uuid := app.current_tenant_membership_id();
  actor_user uuid := app.context_user_id();
  event_type text := p_aggregate_kind::text || '.' || p_action;
  activity_id uuid := uuidv7();
  activity_sequence bigint;
  notification_type public.notification_event_type;
  notification_audience public.notification_audience := 'operator';
  customer_visible boolean := false;
  customer_context jsonb;
  routing_assignee_user_id uuid;
  routing_previous_assignee_user_id uuid;
  routing_operator_team_id uuid;
  routing_operator_team_epoch_id uuid;
BEGIN
  PERFORM app.private_validate_ticket_effects_v1(p_effects);
  IF p_aggregate_id IS NULL OR p_version NOT BETWEEN 1 AND 2147483647
     OR p_action IS NULL OR p_action !~ '^[a-z][a-z0-9_]{1,63}$'
     OR p_request_id IS NULL OR p_correlation_id IS NULL
     OR p_ip_address IS NULL OR p_authentication_method IS NULL
     OR p_before IS NOT NULL AND jsonb_typeof(p_before) <> 'object'
     OR p_after IS NOT NULL AND jsonb_typeof(p_after) <> 'object'
     OR p_metadata IS NULL OR jsonb_typeof(p_metadata) <> 'object' THEN
    RAISE EXCEPTION 'ticket side-effect input is invalid' USING ERRCODE = '22023';
  END IF;

  SELECT coalesce(max(activity.sequence), 0) + 1 INTO activity_sequence
  FROM public.ticket_activities AS activity
  WHERE activity.tenant_id = context_tenant
    AND (p_aggregate_kind = 'alert' AND activity.alert_id = p_aggregate_id
      OR p_aggregate_kind = 'case' AND activity.case_id = p_aggregate_id);
  IF activity_sequence > 2147483647 THEN
    RAISE EXCEPTION 'ticket activity sequence is exhausted' USING ERRCODE = '54000';
  END IF;

  INSERT INTO public.ticket_activities (
    id, tenant_id, alert_id, case_id, sequence, kind, summary,
    actor_principal_kind, actor_membership_id, actor_user_id, origin, details
  ) VALUES (
    activity_id, context_tenant,
    CASE WHEN p_aggregate_kind = 'alert' THEN p_aggregate_id END,
    CASE WHEN p_aggregate_kind = 'case' THEN p_aggregate_id END,
    activity_sequence, event_type,
    CASE p_action WHEN 'created' THEN initcap(p_aggregate_kind::text) || ' created'
      WHEN 'transitioned' THEN initcap(p_aggregate_kind::text) || ' transitioned'
      ELSE initcap(p_aggregate_kind::text) || ' ' || replace(p_action, '_', ' ') END,
    'human', actor_membership, actor_user, 'api',
    p_metadata || jsonb_build_object('version', p_version, 'content_redacted', true)
  );

  PERFORM app.append_tenant_authorization_audit(
    uuidv7(), 'tenant.' || p_aggregate_kind::text || '.' || p_action,
    p_aggregate_kind::text, p_aggregate_id, p_request_id, p_correlation_id,
    p_ip_address, nullif(p_user_agent, ''), p_authentication_method,
    p_before, p_after,
    p_metadata || jsonb_build_object('actor_membership_id', actor_membership, 'content_redacted', true)
  );

  INSERT INTO public.outbox_events (
    tenant_id, aggregate_type, aggregate_id, event_type, schema_version,
    payload, deduplication_key, correlation_id, causation_id
  ) VALUES (
    context_tenant, p_aggregate_kind::text, p_aggregate_id, event_type, 1,
    jsonb_build_object(p_aggregate_kind::text || '_id', p_aggregate_id, 'version', p_version),
    event_type || ':' || activity_id::text, p_correlation_id, p_request_id
  );

  IF p_effects @> ARRAY['sla']::text[] THEN
    INSERT INTO public.outbox_events (
      tenant_id, aggregate_type, aggregate_id, event_type, schema_version,
      payload, deduplication_key, correlation_id, causation_id
    ) VALUES (
      context_tenant, p_aggregate_kind::text, p_aggregate_id,
      'sla.' || event_type, 1,
      jsonb_build_object(p_aggregate_kind::text || '_id', p_aggregate_id, 'version', p_version, 'action', p_action),
      'sla.' || event_type || ':' || activity_id::text,
      p_correlation_id, p_request_id
    );
  END IF;

  IF p_effects @> ARRAY['notification']::text[] THEN
    notification_type := CASE
      WHEN p_aggregate_kind = 'alert' AND p_action = 'created' THEN 'alert.created'::public.notification_event_type
      WHEN p_aggregate_kind = 'alert' AND p_action = 'assigned' THEN 'alert.assigned'::public.notification_event_type
      WHEN p_aggregate_kind = 'alert' AND p_action = 'claimed' THEN 'alert.claimed'::public.notification_event_type
      WHEN p_aggregate_kind = 'alert' AND p_action = 'transitioned' THEN 'alert.status_changed'::public.notification_event_type
      WHEN p_aggregate_kind = 'alert' AND p_action = 'escalated' THEN 'alert.escalated'::public.notification_event_type
      WHEN p_aggregate_kind = 'case' AND p_action = 'created' THEN 'case.created'::public.notification_event_type
      WHEN p_aggregate_kind = 'case' AND p_action = 'assigned' THEN 'case.assigned'::public.notification_event_type
      WHEN p_aggregate_kind = 'case' AND p_action = 'claimed' THEN 'case.claimed'::public.notification_event_type
      WHEN p_aggregate_kind = 'case' AND p_action = 'transferred' THEN 'case.transferred'::public.notification_event_type
      WHEN p_aggregate_kind = 'case' AND p_action = 'transitioned' THEN 'case.status_changed'::public.notification_event_type
      WHEN p_action = 'commented' AND p_metadata ->> 'visibility' = 'public' THEN 'comment.public_added'::public.notification_event_type
      WHEN p_action = 'commented' AND p_metadata ->> 'visibility' = 'private' THEN 'comment.private_added'::public.notification_event_type
      ELSE NULL
    END;
    IF notification_type IS NOT NULL THEN
      IF p_aggregate_kind = 'alert' THEN
        SELECT alert.customer_visible INTO STRICT customer_visible
        FROM public.alerts AS alert
        WHERE alert.tenant_id = context_tenant AND alert.id = p_aggregate_id;
      ELSE
        SELECT case_row.customer_visible INTO STRICT customer_visible
        FROM public.cases AS case_row
        WHERE case_row.tenant_id = context_tenant AND case_row.id = p_aggregate_id;
      END IF;
      IF notification_type = 'comment.public_added' AND customer_visible THEN
        notification_audience := 'customer';
        customer_context := jsonb_build_object(
          p_aggregate_kind::text, jsonb_build_object('id', p_aggregate_id, 'version', p_version),
          'comment', jsonb_build_object('id', p_metadata ->> 'comment_id', 'visibility', 'public')
        );
      END IF;
      routing_previous_assignee_user_id := nullif(
        p_before ->> 'assignee_user_id', ''
      )::uuid;
      IF p_aggregate_kind = 'alert' THEN
        SELECT alert.assignee_user_id, alert.assigned_team_id,
               alert.assigned_team_epoch_id
        INTO routing_assignee_user_id, routing_operator_team_id,
             routing_operator_team_epoch_id
        FROM public.alerts AS alert
        WHERE alert.tenant_id = context_tenant AND alert.id = p_aggregate_id;
      ELSE
        SELECT case_row.assignee_user_id, case_row.assigned_team_id,
               case_row.assigned_team_epoch_id
        INTO routing_assignee_user_id, routing_operator_team_id,
             routing_operator_team_epoch_id
        FROM public.cases AS case_row
        WHERE case_row.tenant_id = context_tenant AND case_row.id = p_aggregate_id;
      END IF;
      PERFORM app.private_append_tenant_notification_event_v2(
        uuidv7(), notification_type, p_aggregate_kind::text::public.notification_object_type,
        p_aggregate_id, p_version, transaction_timestamp(), 'human', actor_user,
        'ticketing', notification_audience,
        jsonb_build_object(
          p_aggregate_kind::text, jsonb_build_object('id', p_aggregate_id, 'version', p_version),
          'actor', jsonb_build_object('id', actor_user),
          'action', p_action,
          'metadata', p_metadata || jsonb_build_object('content_redacted', true),
          'routing', jsonb_strip_nulls(jsonb_build_object(
            'assigneeUserId', routing_assignee_user_id,
            'previousAssigneeUserId', routing_previous_assignee_user_id,
            'operatorTeamId', routing_operator_team_id,
            'operatorTeamEpochId', routing_operator_team_epoch_id
          ))
        ),
        customer_context,
        'notification:v2:' || p_aggregate_kind::text || ':' || p_aggregate_id::text || ':' || p_version::text || ':' || notification_type::text,
        p_correlation_id, p_request_id
      );
    END IF;
  END IF;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.private_append_ticket_side_effects_v1(public.ticket_aggregate_kind, uuid, text, integer, text[], uuid, uuid, inet, text, text, jsonb, jsonb, jsonb) OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_append_ticket_side_effects_v1(public.ticket_aggregate_kind, uuid, text, integer, text[], uuid, uuid, inet, text, text, jsonb, jsonb, jsonb) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
