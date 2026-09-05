-- Purpose-built platform administration boundary. The runtime API receives
-- EXECUTE on closed projections only; it never inherits the NOLOGIN owner and
-- never receives direct access to the source relations below.

DO $function$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'periapsis_platform_operations_owner') THEN
    CREATE ROLE periapsis_platform_operations_owner
      NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
  ELSE
    ALTER ROLE periapsis_platform_operations_owner
      NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
  END IF;
END;
$function$;
--> statement-breakpoint
REVOKE periapsis_platform_operations_owner
FROM periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;
--> statement-breakpoint

CREATE TABLE public.platform_global_settings (
  singleton boolean PRIMARY KEY DEFAULT true NOT NULL,
  platform_name text DEFAULT 'Periapsis' NOT NULL,
  default_locale text DEFAULT 'en' NOT NULL,
  default_timezone text DEFAULT 'UTC' NOT NULL,
  support_url text,
  version integer DEFAULT 1 NOT NULL,
  updated_by_user_id uuid REFERENCES public.users(id) ON DELETE RESTRICT,
  created_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
  updated_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
  CONSTRAINT platform_global_settings_singleton_check CHECK (singleton IS TRUE),
  CONSTRAINT platform_global_settings_name_check CHECK (
    platform_name = btrim(platform_name)
    AND char_length(platform_name) BETWEEN 1 AND 120
    AND platform_name !~ '[[:cntrl:]]'
    AND platform_name !~ U&'[\00AD\061C\180E\200B-\200F\202A-\202E\2060-\206F\FEFF]'
  ),
  CONSTRAINT platform_global_settings_locale_check CHECK (
    default_locale ~ '^[a-z]{2,3}(-[A-Z]{2})?$'
  ),
  CONSTRAINT platform_global_settings_timezone_check CHECK (
    default_timezone = btrim(default_timezone)
    AND char_length(default_timezone) BETWEEN 1 AND 64
    AND default_timezone !~ '[[:cntrl:]]'
    AND default_timezone !~ U&'[\00AD\061C\180E\200B-\200F\202A-\202E\2060-\206F\FEFF]'
  ),
  CONSTRAINT platform_global_settings_support_url_check CHECK (
    support_url IS NULL OR (
      support_url = btrim(support_url)
      AND octet_length(support_url) BETWEEN 9 AND 2048
      AND support_url ~ '^https://[^[:space:]/?#@]+(:[0-9]{1,5})?([/?#][^[:space:]]*)?$'
      AND support_url !~ '[[:cntrl:]]'
      AND support_url !~ U&'[\00AD\061C\180E\200B-\200F\202A-\202E\2060-\206F\FEFF]'
    )
  ),
  CONSTRAINT platform_global_settings_version_check CHECK (version BETWEEN 1 AND 2147483647),
  CONSTRAINT platform_global_settings_timestamps_check CHECK (updated_at >= created_at),
  CONSTRAINT platform_global_settings_updater_check CHECK (
    (version = 1 AND updated_by_user_id IS NULL)
    OR (version > 1 AND updated_by_user_id IS NOT NULL)
  )
);
--> statement-breakpoint

CREATE TABLE public.platform_feature_flags (
  key text PRIMARY KEY,
  enabled boolean DEFAULT true NOT NULL,
  version integer DEFAULT 1 NOT NULL,
  updated_by_user_id uuid REFERENCES public.users(id) ON DELETE RESTRICT,
  created_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
  updated_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
  CONSTRAINT platform_feature_flags_key_check CHECK (
    key = 'platform_failed_notifications_view'
  ),
  CONSTRAINT platform_feature_flags_version_check CHECK (version BETWEEN 1 AND 2147483647),
  CONSTRAINT platform_feature_flags_timestamps_check CHECK (updated_at >= created_at),
  CONSTRAINT platform_feature_flags_updater_check CHECK (
    (version = 1 AND updated_by_user_id IS NULL)
    OR (version > 1 AND updated_by_user_id IS NOT NULL)
  )
);
--> statement-breakpoint

INSERT INTO public.platform_global_settings(singleton)
VALUES (true);
--> statement-breakpoint
INSERT INTO public.platform_feature_flags(key, enabled)
VALUES ('platform_failed_notifications_view', true);
--> statement-breakpoint

ALTER TABLE public.platform_global_settings ENABLE ROW LEVEL SECURITY;
--> statement-breakpoint
ALTER TABLE public.platform_global_settings FORCE ROW LEVEL SECURITY;
--> statement-breakpoint
ALTER TABLE public.platform_feature_flags ENABLE ROW LEVEL SECURITY;
--> statement-breakpoint
ALTER TABLE public.platform_feature_flags FORCE ROW LEVEL SECURITY;
--> statement-breakpoint
CREATE POLICY platform_global_settings_owner_access
ON public.platform_global_settings AS PERMISSIVE FOR ALL
TO periapsis_platform_operations_owner USING (true) WITH CHECK (true);
--> statement-breakpoint
CREATE POLICY platform_feature_flags_owner_access
ON public.platform_feature_flags AS PERMISSIVE FOR ALL
TO periapsis_platform_operations_owner USING (true) WITH CHECK (true);
--> statement-breakpoint
REVOKE ALL ON TABLE public.platform_global_settings, public.platform_feature_flags
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;
--> statement-breakpoint
GRANT SELECT, INSERT, UPDATE ON TABLE
  public.platform_global_settings, public.platform_feature_flags
TO periapsis_platform_operations_owner;
--> statement-breakpoint
ALTER TABLE public.platform_global_settings OWNER TO periapsis_platform_operations_owner;
--> statement-breakpoint
ALTER TABLE public.platform_feature_flags OWNER TO periapsis_platform_operations_owner;
--> statement-breakpoint

-- New permissions are intentionally granted only to the protected system
-- super-admin role. Platform auditors retain their audit permissions only.
INSERT INTO public.platform_permissions(id, key, description)
VALUES
  (uuidv7(), 'platform.user.read', 'Read the redacted global user inventory.'),
  (uuidv7(), 'platform.operations.read', 'Read redacted platform health, queue, and failed-notification projections.'),
  (uuidv7(), 'platform.settings.read', 'Read typed global platform settings.'),
  (uuidv7(), 'platform.settings.manage', 'Change typed global platform settings.'),
  (uuidv7(), 'platform.feature_flag.read', 'Read the closed platform feature-flag catalog.'),
  (uuidv7(), 'platform.feature_flag.manage', 'Change allowlisted non-security platform feature flags.')
ON CONFLICT (key) DO NOTHING;
--> statement-breakpoint
DELETE FROM public.platform_role_permissions AS role_permission
USING public.platform_permissions AS permission, public.platform_roles AS role
WHERE role_permission.permission_id = permission.id
  AND role_permission.role_id = role.id
  AND permission.key IN (
    'platform.user.read', 'platform.operations.read',
    'platform.settings.read', 'platform.settings.manage',
    'platform.feature_flag.read', 'platform.feature_flag.manage'
  )
  AND role.key <> 'platform_super_admin';
--> statement-breakpoint
INSERT INTO public.platform_role_permissions(role_id, permission_id)
SELECT role.id, permission.id
FROM public.platform_roles AS role
CROSS JOIN public.platform_permissions AS permission
WHERE role.key = 'platform_super_admin' AND role.system
  AND permission.key IN (
    'platform.user.read', 'platform.operations.read',
    'platform.settings.read', 'platform.settings.manage',
    'platform.feature_flag.read', 'platform.feature_flag.manage'
  )
ON CONFLICT DO NOTHING;
--> statement-breakpoint

-- The owner can see only the relations needed to build finite aggregate or
-- allowlisted projections. No runtime role receives any new table privilege.
CREATE POLICY users_platform_operations_select
ON public.users AS PERMISSIVE FOR SELECT
TO periapsis_platform_operations_owner USING (true);
--> statement-breakpoint
CREATE POLICY tenant_memberships_platform_operations_select
ON public.tenant_memberships AS PERMISSIVE FOR SELECT
TO periapsis_platform_operations_owner USING (true);
--> statement-breakpoint
CREATE POLICY tenants_platform_operations_select
ON public.tenants AS PERMISSIVE FOR SELECT
TO periapsis_platform_operations_owner USING (true);
--> statement-breakpoint
CREATE POLICY auth_sessions_platform_operations_select
ON public.auth_sessions AS PERMISSIVE FOR SELECT
TO periapsis_platform_operations_owner USING (true);
--> statement-breakpoint
CREATE POLICY platform_roles_platform_operations_select
ON public.platform_roles AS PERMISSIVE FOR SELECT
TO periapsis_platform_operations_owner USING (true);
--> statement-breakpoint
CREATE POLICY user_platform_roles_platform_operations_select
ON public.user_platform_roles AS PERMISSIVE FOR SELECT
TO periapsis_platform_operations_owner USING (true);
--> statement-breakpoint
CREATE POLICY platform_audit_chain_head_platform_operations_select
ON public.platform_audit_chain_head AS PERMISSIVE FOR SELECT
TO periapsis_platform_operations_owner USING (true);
--> statement-breakpoint
CREATE POLICY outbox_events_platform_operations_select
ON public.outbox_events AS PERMISSIVE FOR SELECT
TO periapsis_platform_operations_owner USING (true);
--> statement-breakpoint
CREATE POLICY tenant_notification_deliveries_platform_operations_select
ON public.tenant_notification_deliveries AS PERMISSIVE FOR SELECT
TO periapsis_platform_operations_owner USING (true);
--> statement-breakpoint
CREATE POLICY ticket_bulk_jobs_platform_operations_select
ON public.ticket_bulk_jobs AS PERMISSIVE FOR SELECT
TO periapsis_platform_operations_owner USING (true);
--> statement-breakpoint
CREATE POLICY ticket_export_jobs_platform_operations_select
ON public.ticket_export_jobs AS PERMISSIVE FOR SELECT
TO periapsis_platform_operations_owner USING (true);
--> statement-breakpoint
CREATE POLICY ticket_export_artifact_cleanups_platform_operations_select
ON public.ticket_export_artifact_cleanups AS PERMISSIVE FOR SELECT
TO periapsis_platform_operations_owner USING (true);
--> statement-breakpoint
CREATE POLICY tenant_audit_export_jobs_platform_operations_select
ON public.tenant_audit_export_jobs AS PERMISSIVE FOR SELECT
TO periapsis_platform_operations_owner USING (true);
--> statement-breakpoint
CREATE POLICY platform_audit_export_jobs_platform_operations_select
ON public.platform_audit_export_jobs AS PERMISSIVE FOR SELECT
TO periapsis_platform_operations_owner USING (true);
--> statement-breakpoint
CREATE POLICY sla_evaluation_jobs_platform_operations_select
ON public.sla_evaluation_jobs AS PERMISSIVE FOR SELECT
TO periapsis_platform_operations_owner USING (true);
--> statement-breakpoint
CREATE POLICY sla_trigger_action_executions_platform_operations_select
ON public.sla_trigger_action_executions AS PERMISSIVE FOR SELECT
TO periapsis_platform_operations_owner USING (true);
--> statement-breakpoint
CREATE POLICY sla_object_event_ingress_platform_operations_select
ON public.sla_object_event_ingress AS PERMISSIVE FOR SELECT
TO periapsis_platform_operations_owner USING (true);
--> statement-breakpoint
CREATE POLICY dfir_storage_objects_platform_operations_select
ON public.dfir_storage_objects AS PERMISSIVE FOR SELECT
TO periapsis_platform_operations_owner USING (true);
--> statement-breakpoint
CREATE POLICY tenant_ldap_sync_runs_platform_operations_select
ON public.tenant_ldap_sync_runs AS PERMISSIVE FOR SELECT
TO periapsis_platform_operations_owner USING (true);
--> statement-breakpoint

GRANT SELECT ON TABLE
  public.users, public.tenants, public.tenant_memberships, public.auth_sessions,
  public.platform_roles, public.user_platform_roles,
  public.platform_audit_chain_head, public.outbox_events,
  public.tenant_notification_deliveries, public.ticket_bulk_jobs,
  public.ticket_export_jobs, public.ticket_export_artifact_cleanups,
  public.tenant_audit_export_jobs, public.platform_audit_export_jobs,
  public.sla_evaluation_jobs, public.sla_trigger_action_executions,
  public.sla_object_event_ingress, public.dfir_storage_objects,
  public.tenant_ldap_sync_runs
TO periapsis_platform_operations_owner;
--> statement-breakpoint
GRANT USAGE ON SCHEMA public, app TO periapsis_platform_operations_owner;
--> statement-breakpoint

-- This migrator-owned helper is the sole privileged lock/authorization step.
-- Its permission input is closed and every caller remains tenantless.
CREATE FUNCTION app.private_require_platform_operations_actor_v1(
  p_session_id uuid,
  p_permission text,
  p_require_fresh_mfa boolean
)
RETURNS TABLE(
  actor_user_id uuid,
  permission_epoch bigint,
  authentication_method text
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_user uuid := app.context_user_id();
  context_tenant text := nullif(current_setting('app.tenant_id', true), '');
  locked_epoch bigint;
  locked_session public.auth_sessions%ROWTYPE;
BEGIN
  IF context_user IS NULL OR uuid_extract_version(context_user) IS DISTINCT FROM 7
     OR context_tenant IS NOT NULL
     OR p_session_id IS NULL OR uuid_extract_version(p_session_id) IS DISTINCT FROM 7
     OR p_require_fresh_mfa IS NULL
     OR p_permission NOT IN (
       'platform.user.read', 'platform.operations.read',
       'platform.settings.read', 'platform.settings.manage',
       'platform.feature_flag.read', 'platform.feature_flag.manage'
     ) THEN
    RAISE EXCEPTION 'invalid platform operations authority'
      USING ERRCODE = '22023';
  END IF;

  INSERT INTO public.platform_user_authorization_epochs(user_id)
  VALUES (context_user) ON CONFLICT (user_id) DO NOTHING;
  SELECT epoch.permission_epoch INTO locked_epoch
  FROM public.platform_user_authorization_epochs AS epoch
  WHERE epoch.user_id = context_user
    AND epoch.permission_epoch BETWEEN 1 AND 9007199254740991
  FOR SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'platform authorization epoch is unavailable'
      USING ERRCODE = '42501';
  END IF;

  SELECT session.* INTO locked_session
  FROM public.auth_sessions AS session
  JOIN public.users AS identity ON identity.id = session.user_id
  WHERE session.id = p_session_id
    AND session.user_id = context_user
    AND session.active_tenant_id IS NULL
    AND session.authentication_method IN (
      'bootstrap_totp', 'totp', 'passkey', 'oidc', 'saml', 'ldap'
    )
    AND session.revoked_at IS NULL
    AND session.created_at <= transaction_timestamp()
    AND session.last_seen_at <= transaction_timestamp()
    AND session.idle_expires_at > transaction_timestamp()
    AND session.absolute_expires_at > transaction_timestamp()
    AND session.mfa_satisfied_at IS NOT NULL
    AND session.mfa_satisfied_at <= transaction_timestamp()
    AND (
      NOT p_require_fresh_mfa
      OR session.mfa_satisfied_at >= transaction_timestamp() - interval '15 minutes'
    )
    AND identity.active
  FOR SHARE OF session, identity;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'live tenantless platform session authority is required'
      USING ERRCODE = '42501';
  END IF;

  PERFORM 1
  FROM public.user_platform_roles AS role_grant
  JOIN public.platform_roles AS role
    ON role.id = role_grant.role_id
   AND role.key = 'platform_super_admin'
   AND role.system
  JOIN public.platform_role_permissions AS role_permission
    ON role_permission.role_id = role.id
  JOIN public.platform_permissions AS permission
    ON permission.id = role_permission.permission_id
   AND permission.key = p_permission
  WHERE role_grant.user_id = context_user
    AND role_grant.revoked_at IS NULL
  FOR SHARE OF role_grant, role, role_permission, permission;
  IF NOT FOUND
     OR NOT app.platform_user_has_permission(context_user, p_permission) THEN
    RAISE EXCEPTION 'platform operation permission is required'
      USING ERRCODE = '42501';
  END IF;

  RETURN QUERY SELECT context_user, locked_epoch,
    locked_session.authentication_method;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.private_require_platform_operations_actor_v1(uuid, text, boolean)
OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_require_platform_operations_actor_v1(uuid, text, boolean)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_platform_operations_owner;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.private_require_platform_operations_actor_v1(uuid, text, boolean)
TO periapsis_platform_operations_owner;
--> statement-breakpoint

CREATE FUNCTION app.private_validate_platform_operations_trace_v1(
  p_audit_event_id uuid,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text
)
RETURNS void
LANGUAGE plpgsql
IMMUTABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
BEGIN
  IF p_audit_event_id IS NULL
     OR uuid_extract_version(p_audit_event_id) IS DISTINCT FROM 7
     OR p_request_id IS NULL
     OR uuid_extract_version(p_request_id) IS DISTINCT FROM 7
     OR p_correlation_id IS NULL
     OR uuid_extract_version(p_correlation_id) IS DISTINCT FROM 7
     OR p_ip_address IS NULL
     OR p_user_agent IS NULL
     OR octet_length(p_user_agent) NOT BETWEEN 1 AND 512
     OR p_user_agent ~ '[[:cntrl:]]' THEN
    RAISE EXCEPTION 'invalid platform operations audit envelope'
      USING ERRCODE = '22023';
  END IF;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.private_validate_platform_operations_trace_v1(uuid, uuid, uuid, inet, text)
OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_validate_platform_operations_trace_v1(uuid, uuid, uuid, inet, text)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_platform_operations_owner;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.private_validate_platform_operations_trace_v1(uuid, uuid, uuid, inet, text)
TO periapsis_platform_operations_owner;
--> statement-breakpoint
CREATE FUNCTION app.private_platform_operations_reason_is_valid_v1(p_reason text)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
STRICT
SECURITY DEFINER
SET search_path = pg_catalog, app
AS $function$
  SELECT app.private_platform_lifecycle_reason_is_valid_v1(p_reason);
$function$;
--> statement-breakpoint
ALTER FUNCTION app.private_platform_operations_reason_is_valid_v1(text)
OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_platform_operations_reason_is_valid_v1(text)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_platform_operations_owner;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.private_platform_operations_reason_is_valid_v1(text)
TO periapsis_platform_operations_owner;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.append_platform_audit_event(
  uuid, public.audit_actor_type, uuid, text, text, uuid, uuid, uuid, inet,
  text, text, public.audit_outcome, text, jsonb
) TO periapsis_platform_operations_owner;
--> statement-breakpoint

-- Fixed-source queue aggregation. Each branch emits only finite state counts
-- and the age of the oldest eligible row; payloads, destinations, errors,
-- receipts, object keys, directory attributes, and customer content are never
-- selected into the returned document.
CREATE FUNCTION app.private_platform_queue_metrics_v1()
RETURNS jsonb
LANGUAGE sql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public
SET TimeZone = 'UTC'
AS $function$
  WITH observed AS MATERIALIZED (
    SELECT date_trunc('microseconds', clock_timestamp()) AS checked_at
  ), metrics(ordinal, key, pending_count, in_flight_count, failed_count, oldest_pending_at) AS (
    SELECT 1, 'outbox',
      count(*) FILTER (WHERE event.processed_at IS NULL
        AND event.dead_lettered_at IS NULL
        AND event.available_at <= observed.checked_at
        AND (event.lease_until IS NULL OR event.lease_until <= observed.checked_at)),
      count(*) FILTER (WHERE event.processed_at IS NULL
        AND event.dead_lettered_at IS NULL
        AND event.lease_until > observed.checked_at),
      count(*) FILTER (WHERE event.dead_lettered_at IS NOT NULL),
      min(event.available_at) FILTER (WHERE event.processed_at IS NULL
        AND event.dead_lettered_at IS NULL
        AND event.available_at <= observed.checked_at
        AND (event.lease_until IS NULL OR event.lease_until <= observed.checked_at))
    FROM public.outbox_events AS event CROSS JOIN observed

    UNION ALL
    SELECT 2, 'notification_delivery',
      count(*) FILTER (WHERE (
        delivery.status IN ('queued','retry_scheduled')
          AND coalesce(delivery.next_attempt_at, delivery.created_at) <= observed.checked_at
        ) OR (
          delivery.status IN ('leased','reserved')
          AND delivery.lease_until <= observed.checked_at
        )),
      count(*) FILTER (WHERE delivery.status IN ('leased','reserved')
        AND delivery.lease_until > observed.checked_at),
      count(*) FILTER (WHERE delivery.status = 'dead_lettered'),
      min(CASE
        WHEN delivery.status IN ('leased','reserved') THEN delivery.lease_until
        ELSE coalesce(delivery.next_attempt_at, delivery.created_at)
      END) FILTER (WHERE (
        delivery.status IN ('queued','retry_scheduled')
          AND coalesce(delivery.next_attempt_at, delivery.created_at) <= observed.checked_at
        ) OR (
          delivery.status IN ('leased','reserved')
          AND delivery.lease_until <= observed.checked_at
        ))
    FROM public.tenant_notification_deliveries AS delivery CROSS JOIN observed

    UNION ALL
    SELECT 3, 'ticket_bulk',
      count(*) FILTER (WHERE job.state = 'pending' AND job.available_at <= observed.checked_at),
      count(*) FILTER (WHERE job.state IN ('running','cancellation_requested')),
      count(*) FILTER (WHERE job.state IN ('failed','authorization_revoked')),
      min(job.available_at) FILTER (WHERE job.state = 'pending'
        AND job.available_at <= observed.checked_at)
    FROM public.ticket_bulk_jobs AS job CROSS JOIN observed

    UNION ALL
    SELECT 4, 'ticket_export',
      count(*) FILTER (WHERE (job.state = 'pending'
        AND job.available_at <= observed.checked_at)
        OR (job.state IN ('running','cancellation_requested')
          AND (job.lease_expires_at IS NULL
            OR job.lease_expires_at <= observed.checked_at))),
      count(*) FILTER (WHERE job.state IN ('running','cancellation_requested')
        AND job.lease_expires_at > observed.checked_at),
      count(*) FILTER (WHERE job.state = 'failed'),
      min(CASE WHEN job.state IN ('running','cancellation_requested')
        THEN coalesce(job.lease_expires_at, job.updated_at)
        ELSE job.available_at END) FILTER (
        WHERE (job.state = 'pending' AND job.available_at <= observed.checked_at)
          OR (job.state IN ('running','cancellation_requested')
            AND (job.lease_expires_at IS NULL
              OR job.lease_expires_at <= observed.checked_at)))
    FROM public.ticket_export_jobs AS job CROSS JOIN observed

    UNION ALL
    SELECT 5, 'ticket_export_cleanup',
      count(*) FILTER (WHERE cleanup.state IN ('pending','retry_scheduled')
        AND coalesce(cleanup.retry_at, cleanup.eligible_at) <= observed.checked_at),
      count(*) FILTER (WHERE cleanup.state = 'leased'
        AND cleanup.lease_expires_at > observed.checked_at),
      count(*) FILTER (WHERE cleanup.state = 'dead_lettered'),
      min(coalesce(cleanup.retry_at, cleanup.eligible_at)) FILTER (
        WHERE cleanup.state IN ('pending','retry_scheduled')
          AND coalesce(cleanup.retry_at, cleanup.eligible_at) <= observed.checked_at)
    FROM public.ticket_export_artifact_cleanups AS cleanup CROSS JOIN observed

    UNION ALL
    SELECT 6, 'tenant_audit_export',
      count(*) FILTER (WHERE (job.state = 'pending'
        AND job.available_at <= observed.checked_at)
        OR (job.state IN ('running','cancellation_requested')
          AND (job.lease_expires_at IS NULL
            OR job.lease_expires_at <= observed.checked_at))),
      count(*) FILTER (WHERE job.state IN ('running','cancellation_requested')
        AND job.lease_expires_at > observed.checked_at),
      count(*) FILTER (WHERE job.state IN ('failed','authorization_revoked')),
      min(CASE WHEN job.state IN ('running','cancellation_requested')
        THEN coalesce(job.lease_expires_at, job.updated_at)
        ELSE job.available_at END) FILTER (
        WHERE (job.state = 'pending' AND job.available_at <= observed.checked_at)
          OR (job.state IN ('running','cancellation_requested')
            AND (job.lease_expires_at IS NULL
              OR job.lease_expires_at <= observed.checked_at)))
    FROM public.tenant_audit_export_jobs AS job CROSS JOIN observed

    UNION ALL
    SELECT 7, 'platform_audit_export',
      count(*) FILTER (WHERE (job.state = 'pending'
        AND job.available_at <= observed.checked_at)
        OR (job.state IN ('running','cancellation_requested')
          AND (job.lease_expires_at IS NULL
            OR job.lease_expires_at <= observed.checked_at))),
      count(*) FILTER (WHERE job.state IN ('running','cancellation_requested')
        AND job.lease_expires_at > observed.checked_at),
      count(*) FILTER (WHERE job.state IN ('failed','authorization_revoked')),
      min(CASE WHEN job.state IN ('running','cancellation_requested')
        THEN coalesce(job.lease_expires_at, job.updated_at)
        ELSE job.available_at END) FILTER (
        WHERE (job.state = 'pending' AND job.available_at <= observed.checked_at)
          OR (job.state IN ('running','cancellation_requested')
            AND (job.lease_expires_at IS NULL
              OR job.lease_expires_at <= observed.checked_at)))
    FROM public.platform_audit_export_jobs AS job CROSS JOIN observed

    UNION ALL
    SELECT 8, 'sla_evaluation',
      count(*) FILTER (WHERE (job.status IN ('queued','retry_scheduled')
        AND job.available_at <= observed.checked_at)
        OR (job.status = 'leased' AND job.lease_expires_at <= observed.checked_at)),
      count(*) FILTER (WHERE job.status = 'leased'
        AND job.lease_expires_at > observed.checked_at),
      count(*) FILTER (WHERE job.status = 'dead_lettered'),
      min(CASE WHEN job.status = 'leased' THEN job.lease_expires_at
        ELSE job.available_at END) FILTER (
        WHERE (job.status IN ('queued','retry_scheduled')
          AND job.available_at <= observed.checked_at)
          OR (job.status = 'leased' AND job.lease_expires_at <= observed.checked_at))
    FROM public.sla_evaluation_jobs AS job CROSS JOIN observed

    UNION ALL
    SELECT 9, 'sla_trigger_action',
      count(*) FILTER (WHERE (execution.status IN ('queued','retry_scheduled')
        AND execution.available_at <= observed.checked_at)
        OR (execution.status = 'leased'
          AND execution.lease_expires_at <= observed.checked_at)),
      count(*) FILTER (WHERE execution.status = 'leased'
        AND execution.lease_expires_at > observed.checked_at),
      count(*) FILTER (WHERE execution.status = 'dead_lettered'),
      min(CASE WHEN execution.status = 'leased' THEN execution.lease_expires_at
        ELSE execution.available_at END) FILTER (
        WHERE (execution.status IN ('queued','retry_scheduled')
          AND execution.available_at <= observed.checked_at)
          OR (execution.status = 'leased'
            AND execution.lease_expires_at <= observed.checked_at))
    FROM public.sla_trigger_action_executions AS execution CROSS JOIN observed

    UNION ALL
    SELECT 10, 'sla_event_ingress',
      count(*) FILTER (WHERE (ingress.status IN ('queued','retry_scheduled')
        AND ingress.available_at <= observed.checked_at)
        OR (ingress.status = 'leased'
          AND ingress.lease_expires_at <= observed.checked_at)),
      count(*) FILTER (WHERE ingress.status = 'leased'
        AND ingress.lease_expires_at > observed.checked_at),
      count(*) FILTER (WHERE ingress.status = 'dead_lettered'),
      min(CASE WHEN ingress.status = 'leased' THEN ingress.lease_expires_at
        ELSE ingress.available_at END) FILTER (
        WHERE (ingress.status IN ('queued','retry_scheduled')
          AND ingress.available_at <= observed.checked_at)
          OR (ingress.status = 'leased'
            AND ingress.lease_expires_at <= observed.checked_at))
    FROM public.sla_object_event_ingress AS ingress CROSS JOIN observed

    UNION ALL
    SELECT 11, 'dfir_evidence_scan',
      count(*) FILTER (WHERE object.state IN ('uploaded','quarantined')),
      count(*) FILTER (WHERE object.state IN ('verifying','scanning')),
      count(*) FILTER (WHERE object.state = 'scan_failed'),
      min(object.updated_at) FILTER (WHERE object.state IN ('uploaded','quarantined'))
    FROM public.dfir_storage_objects AS object CROSS JOIN observed

    UNION ALL
    SELECT 12, 'dfir_evidence_cleanup',
      count(*) FILTER (WHERE object.state = 'pending_upload'
        AND NOT object.legal_hold
        AND object.upload_expires_at <= observed.checked_at
        AND (object.cleanup_lease_expires_at IS NULL
          OR object.cleanup_lease_expires_at <= observed.checked_at)),
      count(*) FILTER (WHERE object.state = 'pending_upload'
        AND object.cleanup_lease_expires_at > observed.checked_at),
      count(*) FILTER (WHERE object.state = 'pending_upload'
        AND object.cleanup_last_failure_code IS NOT NULL),
      min(object.upload_expires_at) FILTER (WHERE object.state = 'pending_upload'
        AND NOT object.legal_hold
        AND object.upload_expires_at <= observed.checked_at
        AND (object.cleanup_lease_expires_at IS NULL
          OR object.cleanup_lease_expires_at <= observed.checked_at))
    FROM public.dfir_storage_objects AS object CROSS JOIN observed

    UNION ALL
    SELECT 13, 'ldap_sync',
      count(*) FILTER (WHERE run.status = 'queued'
        OR (run.status IN ('enumerating','applying')
          AND run.claim_expires_at <= observed.checked_at)),
      count(*) FILTER (WHERE run.status IN ('enumerating','applying')
        AND run.claim_expires_at > observed.checked_at),
      count(*) FILTER (WHERE run.status IN ('failed','stale')),
      min(CASE WHEN run.status IN ('enumerating','applying')
        THEN run.claim_expires_at ELSE run.queued_at END) FILTER (
        WHERE run.status = 'queued'
          OR (run.status IN ('enumerating','applying')
            AND run.claim_expires_at <= observed.checked_at))
    FROM public.tenant_ldap_sync_runs AS run CROSS JOIN observed
  )
  SELECT jsonb_build_object(
    'projectionVersion', 1,
    'checkedAt', observed.checked_at,
    'sources', jsonb_agg(
      jsonb_build_object(
        'key', metrics.key,
        'pendingCount', metrics.pending_count,
        'inFlightCount', metrics.in_flight_count,
        'failedCount', metrics.failed_count,
        'oldestPendingSeconds', CASE
          WHEN metrics.oldest_pending_at IS NULL THEN 0
          ELSE greatest(0, floor(extract(epoch FROM
            observed.checked_at - metrics.oldest_pending_at))::bigint)
        END
      ) ORDER BY metrics.ordinal
    )
  )
  FROM observed CROSS JOIN metrics
  GROUP BY observed.checked_at;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.private_platform_queue_metrics_v1()
OWNER TO periapsis_platform_operations_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_platform_queue_metrics_v1()
FROM PUBLIC, periapsis_migrator, periapsis_api, periapsis_worker,
  periapsis_notifier, periapsis_auditor;
--> statement-breakpoint

CREATE FUNCTION app.list_platform_operation_queues_v1(
  p_session_id uuid,
  p_audit_event_id uuid,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  actor record;
  document jsonb;
BEGIN
  SELECT * INTO STRICT actor
  FROM app.private_require_platform_operations_actor_v1(
    p_session_id, 'platform.operations.read', false
  );
  PERFORM app.private_validate_platform_operations_trace_v1(
    p_audit_event_id, p_request_id, p_correlation_id, p_ip_address, p_user_agent
  );
  document := app.private_platform_queue_metrics_v1();
  IF document IS NULL OR jsonb_array_length(document -> 'sources') <> 13 THEN
    RAISE EXCEPTION 'platform queue projection is incomplete'
      USING ERRCODE = '55000';
  END IF;
  PERFORM app.append_platform_audit_event(
    p_audit_event_id, 'user', actor.actor_user_id,
    'platform.operations.queues.read', 'platform_queue_inventory', NULL,
    p_request_id, p_correlation_id, p_ip_address, p_user_agent,
    actor.authentication_method, 'success', NULL,
    jsonb_build_object('projectionVersion', 1, 'sourceCount', 13)
  );
  RETURN document;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.list_platform_operation_queues_v1(uuid, uuid, uuid, uuid, inet, text)
OWNER TO periapsis_platform_operations_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.list_platform_operation_queues_v1(uuid, uuid, uuid, uuid, inet, text)
FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.list_platform_operation_queues_v1(uuid, uuid, uuid, uuid, inet, text)
TO periapsis_api;
--> statement-breakpoint

CREATE FUNCTION app.get_platform_operation_health_v1(
  p_session_id uuid,
  p_audit_event_id uuid,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  actor record;
  queue_document jsonb;
  checked_at timestamp with time zone;
  source_count integer;
  pending_total bigint;
  failed_total bigint;
  oldest_pending_seconds bigint;
  audit_head_live boolean;
  overall_status text;
BEGIN
  SELECT * INTO STRICT actor
  FROM app.private_require_platform_operations_actor_v1(
    p_session_id, 'platform.operations.read', false
  );
  PERFORM app.private_validate_platform_operations_trace_v1(
    p_audit_event_id, p_request_id, p_correlation_id, p_ip_address, p_user_agent
  );
  queue_document := app.private_platform_queue_metrics_v1();
  checked_at := (queue_document ->> 'checkedAt')::timestamp with time zone;
  SELECT count(*)::integer,
         coalesce(sum((source ->> 'pendingCount')::bigint), 0),
         coalesce(sum((source ->> 'failedCount')::bigint), 0),
         coalesce(max((source ->> 'oldestPendingSeconds')::bigint), 0)
  INTO source_count, pending_total, failed_total, oldest_pending_seconds
  FROM jsonb_array_elements(queue_document -> 'sources') AS queue(source);
  SELECT EXISTS (
    SELECT 1 FROM public.platform_audit_chain_head AS head
    WHERE head.singleton AND head.last_sequence >= 0
      AND head.last_event_hash ~ '^[0-9a-f]{64}$'
  ) INTO audit_head_live;
  IF source_count <> 13 THEN
    RAISE EXCEPTION 'platform health source set is incomplete'
      USING ERRCODE = '55000';
  END IF;
  overall_status := CASE
    WHEN NOT audit_head_live OR failed_total > 0 OR oldest_pending_seconds > 300
      THEN 'degraded'
    ELSE 'healthy'
  END;
  PERFORM app.append_platform_audit_event(
    p_audit_event_id, 'user', actor.actor_user_id,
    'platform.operations.health.read', 'platform_health', NULL,
    p_request_id, p_correlation_id, p_ip_address, p_user_agent,
    actor.authentication_method, 'success', NULL,
    jsonb_build_object('projectionVersion', 1, 'status', overall_status,
      'sourceCount', source_count)
  );
  RETURN jsonb_build_object(
    'projectionVersion', 1,
    'checkedAt', checked_at,
    'status', overall_status,
    'checks', jsonb_build_array(
      jsonb_build_object('key', 'database', 'status', 'healthy'),
      jsonb_build_object('key', 'platform_audit_chain',
        'status', CASE WHEN audit_head_live THEN 'healthy' ELSE 'degraded' END),
      jsonb_build_object('key', 'queue_backlog',
        'status', CASE WHEN oldest_pending_seconds > 300 THEN 'degraded' ELSE 'healthy' END,
        'pendingCount', pending_total,
        'oldestPendingSeconds', oldest_pending_seconds),
      jsonb_build_object('key', 'queue_failures',
        'status', CASE WHEN failed_total > 0 THEN 'degraded' ELSE 'healthy' END,
        'failedCount', failed_total)
    )
  );
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.get_platform_operation_health_v1(uuid, uuid, uuid, uuid, inet, text)
OWNER TO periapsis_platform_operations_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.get_platform_operation_health_v1(uuid, uuid, uuid, uuid, inet, text)
FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.get_platform_operation_health_v1(uuid, uuid, uuid, uuid, inet, text)
TO periapsis_api;
--> statement-breakpoint

CREATE FUNCTION app.list_platform_users_v1(
  p_session_id uuid,
  p_after_user_id uuid,
  p_limit integer,
  p_audit_event_id uuid,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  actor record;
  document jsonb;
  returned_count integer;
  has_more boolean;
BEGIN
  IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 100
     OR (p_after_user_id IS NOT NULL
       AND uuid_extract_version(p_after_user_id) IS DISTINCT FROM 7) THEN
    RAISE EXCEPTION 'invalid platform user inventory page'
      USING ERRCODE = '22023';
  END IF;
  SELECT * INTO STRICT actor
  FROM app.private_require_platform_operations_actor_v1(
    p_session_id, 'platform.user.read', false
  );
  PERFORM app.private_validate_platform_operations_trace_v1(
    p_audit_event_id, p_request_id, p_correlation_id, p_ip_address, p_user_agent
  );

  WITH candidates AS MATERIALIZED (
    SELECT identity.id, identity.email, identity.display_name, identity.active
    FROM public.users AS identity
    WHERE p_after_user_id IS NULL OR identity.id > p_after_user_id
    ORDER BY identity.id
    LIMIT p_limit + 1
  ), page AS MATERIALIZED (
    SELECT candidate.* FROM candidates AS candidate
    ORDER BY candidate.id LIMIT p_limit
  ), page_shape AS (
    SELECT page.id,
      jsonb_build_object(
        'id', page.id,
        'email', page.email,
        'displayName', page.display_name,
        'active', page.active,
        'platformRoles', coalesce((
          SELECT jsonb_agg(role.key ORDER BY role.key)
          FROM public.user_platform_roles AS role_grant
          JOIN public.platform_roles AS role ON role.id = role_grant.role_id
          WHERE role_grant.user_id = page.id
            AND role_grant.revoked_at IS NULL
        ), '[]'::jsonb),
        'activeTenantMembershipCount', (
          SELECT count(*)::integer
          FROM public.tenant_memberships AS membership
          JOIN public.tenants AS tenant ON tenant.id = membership.tenant_id
          WHERE membership.user_id = page.id
            AND membership.status = 'active'
            AND tenant.status = 'active'
        ),
        'totalTenantMembershipCount', (
          SELECT count(*)::integer
          FROM public.tenant_memberships AS membership
          WHERE membership.user_id = page.id
        ),
        'liveSessionsByAuthenticationMethod', coalesce((
          SELECT jsonb_agg(jsonb_build_object(
            'method', method_summary.authentication_method,
            'liveSessionCount', method_summary.live_session_count
          ) ORDER BY method_summary.authentication_method)
          FROM (
            SELECT session.authentication_method,
                   count(*)::integer AS live_session_count
            FROM public.auth_sessions AS session
            WHERE session.user_id = page.id
              AND session.revoked_at IS NULL
              AND session.idle_expires_at > transaction_timestamp()
              AND session.absolute_expires_at > transaction_timestamp()
            GROUP BY session.authentication_method
          ) AS method_summary
        ), '[]'::jsonb)
      ) AS item
    FROM page
  ), summary AS (
    SELECT count(*)::integer AS returned_count,
      (SELECT count(*) > p_limit FROM candidates) AS has_more,
      coalesce(jsonb_agg(page_shape.item ORDER BY page_shape.id), '[]'::jsonb) AS items,
      (SELECT page.id FROM page ORDER BY page.id DESC LIMIT 1) AS last_page_id
    FROM page_shape
  )
  SELECT jsonb_build_object(
      'projectionVersion', 1,
      'items', summary.items,
      'nextCursor', CASE WHEN summary.has_more THEN summary.last_page_id ELSE NULL END
    ), summary.returned_count, summary.has_more
  INTO document, returned_count, has_more
  FROM summary;

  PERFORM app.append_platform_audit_event(
    p_audit_event_id, 'user', actor.actor_user_id,
    'platform.users.read', 'platform_user_inventory', NULL,
    p_request_id, p_correlation_id, p_ip_address, p_user_agent,
    actor.authentication_method, 'success', NULL,
    jsonb_build_object('projectionVersion', 1, 'limit', p_limit,
      'afterUserId', p_after_user_id, 'returnedCount', returned_count,
      'hasMore', has_more)
  );
  RETURN document;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.list_platform_users_v1(uuid, uuid, integer, uuid, uuid, uuid, inet, text)
OWNER TO periapsis_platform_operations_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.list_platform_users_v1(uuid, uuid, integer, uuid, uuid, uuid, inet, text)
FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.list_platform_users_v1(uuid, uuid, integer, uuid, uuid, uuid, inet, text)
TO periapsis_api;
--> statement-breakpoint

CREATE FUNCTION app.get_platform_global_settings_v1(
  p_session_id uuid,
  p_audit_event_id uuid,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text
)
RETURNS TABLE(
  platform_name text,
  default_locale text,
  default_timezone text,
  support_url text,
  version integer,
  updated_at timestamp with time zone
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  actor record;
  settings_record public.platform_global_settings%ROWTYPE;
BEGIN
  SELECT * INTO STRICT actor
  FROM app.private_require_platform_operations_actor_v1(
    p_session_id, 'platform.settings.read', false
  );
  PERFORM app.private_validate_platform_operations_trace_v1(
    p_audit_event_id, p_request_id, p_correlation_id, p_ip_address, p_user_agent
  );
  SELECT settings.* INTO settings_record
  FROM public.platform_global_settings AS settings
  WHERE settings.singleton;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'platform settings singleton is unavailable'
      USING ERRCODE = '55000';
  END IF;
  PERFORM app.append_platform_audit_event(
    p_audit_event_id, 'user', actor.actor_user_id,
    'platform.settings.read', 'platform_global_settings', NULL,
    p_request_id, p_correlation_id, p_ip_address, p_user_agent,
    actor.authentication_method, 'success', NULL,
    jsonb_build_object('projectionVersion', 1, 'version', settings_record.version)
  );
  RETURN QUERY SELECT settings_record.platform_name,
    settings_record.default_locale, settings_record.default_timezone,
    settings_record.support_url, settings_record.version,
    settings_record.updated_at;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.get_platform_global_settings_v1(uuid, uuid, uuid, uuid, inet, text)
OWNER TO periapsis_platform_operations_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.get_platform_global_settings_v1(uuid, uuid, uuid, uuid, inet, text)
FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.get_platform_global_settings_v1(uuid, uuid, uuid, uuid, inet, text)
TO periapsis_api;
--> statement-breakpoint

CREATE FUNCTION app.update_platform_global_settings_v1(
  p_session_id uuid,
  p_expected_version integer,
  p_platform_name text,
  p_default_locale text,
  p_default_timezone text,
  p_support_url text,
  p_reason text,
  p_audit_event_id uuid,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text
)
RETURNS TABLE(
  platform_name text,
  default_locale text,
  default_timezone text,
  support_url text,
  version integer,
  updated_at timestamp with time zone
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  actor record;
  settings_record public.platform_global_settings%ROWTYPE;
  previous_settings public.platform_global_settings%ROWTYPE;
BEGIN
  IF p_expected_version NOT BETWEEN 1 AND 2147483646
     OR p_platform_name IS NULL OR p_platform_name <> btrim(p_platform_name)
     OR char_length(p_platform_name) NOT BETWEEN 1 AND 120
     OR p_platform_name ~ '[[:cntrl:]]'
     OR p_platform_name ~ U&'[\00AD\061C\180E\200B-\200F\202A-\202E\2060-\206F\FEFF]'
     OR p_default_locale IS NULL
     OR p_default_locale !~ '^[a-z]{2,3}(-[A-Z]{2})?$'
     OR p_default_timezone IS NULL
     OR p_default_timezone <> btrim(p_default_timezone)
     OR char_length(p_default_timezone) NOT BETWEEN 1 AND 64
     OR p_default_timezone ~ '[[:cntrl:]]'
     OR p_default_timezone ~ U&'[\00AD\061C\180E\200B-\200F\202A-\202E\2060-\206F\FEFF]'
     OR (p_support_url IS NOT NULL AND (
       p_support_url <> btrim(p_support_url)
       OR octet_length(p_support_url) NOT BETWEEN 9 AND 2048
       OR p_support_url !~ '^https://[^[:space:]/?#@]+(:[0-9]{1,5})?([/?#][^[:space:]]*)?$'
       OR p_support_url ~ '[[:cntrl:]]'
       OR p_support_url ~ U&'[\00AD\061C\180E\200B-\200F\202A-\202E\2060-\206F\FEFF]'
     ))
     OR p_reason IS NULL
     OR NOT app.private_platform_operations_reason_is_valid_v1(p_reason) THEN
    RAISE EXCEPTION 'invalid typed platform settings update'
      USING ERRCODE = '22023';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_timezone_names AS timezone
    WHERE timezone.name = p_default_timezone
  ) THEN
    RAISE EXCEPTION 'unknown platform default timezone'
      USING ERRCODE = '22023';
  END IF;
  SELECT * INTO STRICT actor
  FROM app.private_require_platform_operations_actor_v1(
    p_session_id, 'platform.settings.manage', true
  );
  PERFORM app.private_validate_platform_operations_trace_v1(
    p_audit_event_id, p_request_id, p_correlation_id, p_ip_address, p_user_agent
  );
  SELECT settings.* INTO settings_record
  FROM public.platform_global_settings AS settings
  WHERE settings.singleton
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'platform settings singleton is unavailable'
      USING ERRCODE = '55000';
  END IF;
  IF settings_record.version IS DISTINCT FROM p_expected_version THEN
    RAISE EXCEPTION 'platform settings version conflict'
      USING ERRCODE = '40001';
  END IF;
  IF settings_record.platform_name IS NOT DISTINCT FROM p_platform_name
     AND settings_record.default_locale IS NOT DISTINCT FROM p_default_locale
     AND settings_record.default_timezone IS NOT DISTINCT FROM p_default_timezone
     AND settings_record.support_url IS NOT DISTINCT FROM p_support_url THEN
    RAISE EXCEPTION 'platform settings update must change at least one field'
      USING ERRCODE = '22023';
  END IF;
  previous_settings := settings_record;
  UPDATE public.platform_global_settings AS settings
  SET platform_name = p_platform_name,
      default_locale = p_default_locale,
      default_timezone = p_default_timezone,
      support_url = p_support_url,
      version = settings.version + 1,
      updated_by_user_id = actor.actor_user_id,
      updated_at = greatest(settings.updated_at,
        date_trunc('microseconds', clock_timestamp()))
  WHERE settings.singleton
  RETURNING * INTO settings_record;
  PERFORM app.append_platform_audit_event(
    p_audit_event_id, 'user', actor.actor_user_id,
    'platform.settings.updated', 'platform_global_settings', NULL,
    p_request_id, p_correlation_id, p_ip_address, p_user_agent,
    actor.authentication_method, 'success', p_reason,
    jsonb_build_object(
      'before', jsonb_build_object(
        'platformName', previous_settings.platform_name,
        'defaultLocale', previous_settings.default_locale,
        'defaultTimezone', previous_settings.default_timezone,
        'supportUrl', previous_settings.support_url,
        'version', previous_settings.version
      ),
      'after', jsonb_build_object(
        'platformName', settings_record.platform_name,
        'defaultLocale', settings_record.default_locale,
        'defaultTimezone', settings_record.default_timezone,
        'supportUrl', settings_record.support_url,
        'version', settings_record.version
      )
    )
  );
  RETURN QUERY SELECT settings_record.platform_name,
    settings_record.default_locale, settings_record.default_timezone,
    settings_record.support_url, settings_record.version,
    settings_record.updated_at;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.update_platform_global_settings_v1(
  uuid, integer, text, text, text, text, text, uuid, uuid, uuid, inet, text
) OWNER TO periapsis_platform_operations_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.update_platform_global_settings_v1(
  uuid, integer, text, text, text, text, text, uuid, uuid, uuid, inet, text
) FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.update_platform_global_settings_v1(
  uuid, integer, text, text, text, text, text, uuid, uuid, uuid, inet, text
) TO periapsis_api;
--> statement-breakpoint

CREATE FUNCTION app.list_platform_feature_flags_v1(
  p_session_id uuid,
  p_audit_event_id uuid,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  actor record;
  document jsonb;
BEGIN
  SELECT * INTO STRICT actor
  FROM app.private_require_platform_operations_actor_v1(
    p_session_id, 'platform.feature_flag.read', false
  );
  PERFORM app.private_validate_platform_operations_trace_v1(
    p_audit_event_id, p_request_id, p_correlation_id, p_ip_address, p_user_agent
  );
  SELECT jsonb_build_object(
    'projectionVersion', 1,
    'items', coalesce(jsonb_agg(jsonb_build_object(
      'key', flag.key,
      'enabled', flag.enabled,
      'version', flag.version,
      'updatedAt', flag.updated_at
    ) ORDER BY flag.key), '[]'::jsonb)
  ) INTO document
  FROM public.platform_feature_flags AS flag;
  IF jsonb_array_length(document -> 'items') <> 1 THEN
    RAISE EXCEPTION 'platform feature flag catalog is incomplete'
      USING ERRCODE = '55000';
  END IF;
  PERFORM app.append_platform_audit_event(
    p_audit_event_id, 'user', actor.actor_user_id,
    'platform.feature_flags.read', 'platform_feature_flag_catalog', NULL,
    p_request_id, p_correlation_id, p_ip_address, p_user_agent,
    actor.authentication_method, 'success', NULL,
    jsonb_build_object('projectionVersion', 1, 'flagCount', 1)
  );
  RETURN document;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.list_platform_feature_flags_v1(uuid, uuid, uuid, uuid, inet, text)
OWNER TO periapsis_platform_operations_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.list_platform_feature_flags_v1(uuid, uuid, uuid, uuid, inet, text)
FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.list_platform_feature_flags_v1(uuid, uuid, uuid, uuid, inet, text)
TO periapsis_api;
--> statement-breakpoint

CREATE FUNCTION app.update_platform_feature_flag_v1(
  p_session_id uuid,
  p_flag_key text,
  p_expected_version integer,
  p_enabled boolean,
  p_reason text,
  p_audit_event_id uuid,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text
)
RETURNS TABLE(
  key text,
  enabled boolean,
  version integer,
  updated_at timestamp with time zone
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  actor record;
  flag_record public.platform_feature_flags%ROWTYPE;
  previous_flag public.platform_feature_flags%ROWTYPE;
BEGIN
  IF p_flag_key IS DISTINCT FROM 'platform_failed_notifications_view'
     OR p_expected_version NOT BETWEEN 1 AND 2147483646
     OR p_enabled IS NULL
     OR p_reason IS NULL
     OR NOT app.private_platform_operations_reason_is_valid_v1(p_reason) THEN
    RAISE EXCEPTION 'invalid platform feature flag update'
      USING ERRCODE = '22023';
  END IF;
  SELECT * INTO STRICT actor
  FROM app.private_require_platform_operations_actor_v1(
    p_session_id, 'platform.feature_flag.manage', true
  );
  PERFORM app.private_validate_platform_operations_trace_v1(
    p_audit_event_id, p_request_id, p_correlation_id, p_ip_address, p_user_agent
  );
  SELECT flag.* INTO flag_record
  FROM public.platform_feature_flags AS flag
  WHERE flag.key = p_flag_key
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'platform feature flag does not exist'
      USING ERRCODE = 'P0002';
  END IF;
  IF flag_record.version IS DISTINCT FROM p_expected_version THEN
    RAISE EXCEPTION 'platform feature flag version conflict'
      USING ERRCODE = '40001';
  END IF;
  IF flag_record.enabled IS NOT DISTINCT FROM p_enabled THEN
    RAISE EXCEPTION 'platform feature flag update must change enabled state'
      USING ERRCODE = '22023';
  END IF;
  previous_flag := flag_record;
  UPDATE public.platform_feature_flags AS flag
  SET enabled = p_enabled,
      version = flag.version + 1,
      updated_by_user_id = actor.actor_user_id,
      updated_at = greatest(flag.updated_at,
        date_trunc('microseconds', clock_timestamp()))
  WHERE flag.key = p_flag_key
  RETURNING * INTO flag_record;
  PERFORM app.append_platform_audit_event(
    p_audit_event_id, 'user', actor.actor_user_id,
    'platform.feature_flag.updated', 'platform_feature_flag', NULL,
    p_request_id, p_correlation_id, p_ip_address, p_user_agent,
    actor.authentication_method, 'success', p_reason,
    jsonb_build_object(
      'key', p_flag_key,
      'before', jsonb_build_object('enabled', previous_flag.enabled,
        'version', previous_flag.version),
      'after', jsonb_build_object('enabled', flag_record.enabled,
        'version', flag_record.version)
    )
  );
  RETURN QUERY SELECT flag_record.key, flag_record.enabled,
    flag_record.version, flag_record.updated_at;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.update_platform_feature_flag_v1(
  uuid, text, integer, boolean, text, uuid, uuid, uuid, inet, text
) OWNER TO periapsis_platform_operations_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.update_platform_feature_flag_v1(
  uuid, text, integer, boolean, text, uuid, uuid, uuid, inet, text
) FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.update_platform_feature_flag_v1(
  uuid, text, integer, boolean, text, uuid, uuid, uuid, inet, text
) TO periapsis_api;
--> statement-breakpoint

CREATE FUNCTION app.list_platform_failed_notifications_v1(
  p_session_id uuid,
  p_after_failure_at timestamp with time zone,
  p_after_delivery_id uuid,
  p_limit integer,
  p_audit_event_id uuid,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  actor record;
  document jsonb;
  returned_count integer;
  has_more boolean;
  feature_enabled boolean;
BEGIN
  IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 100
     OR ((p_after_failure_at IS NULL) <> (p_after_delivery_id IS NULL))
     OR (p_after_delivery_id IS NOT NULL
       AND uuid_extract_version(p_after_delivery_id) IS DISTINCT FROM 7) THEN
    RAISE EXCEPTION 'invalid failed notification page'
      USING ERRCODE = '22023';
  END IF;
  SELECT * INTO STRICT actor
  FROM app.private_require_platform_operations_actor_v1(
    p_session_id, 'platform.operations.read', false
  );
  PERFORM app.private_validate_platform_operations_trace_v1(
    p_audit_event_id, p_request_id, p_correlation_id, p_ip_address, p_user_agent
  );
  SELECT flag.enabled INTO feature_enabled
  FROM public.platform_feature_flags AS flag
  WHERE flag.key = 'platform_failed_notifications_view';
  IF feature_enabled IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'platform failed notification view is disabled'
      USING ERRCODE = '42501';
  END IF;

  WITH candidates AS MATERIALIZED (
    SELECT delivery.id, delivery.tenant_id, delivery.channel,
      delivery.failure_class, delivery.failure_code, delivery.failure_at,
      delivery.created_at, delivery.updated_at, delivery.attempt_count
    FROM public.tenant_notification_deliveries AS delivery
    WHERE delivery.status = 'dead_lettered'
      AND delivery.failure_at IS NOT NULL
      AND (
        p_after_failure_at IS NULL
        OR (delivery.failure_at, delivery.id)
          < (p_after_failure_at, p_after_delivery_id)
      )
    ORDER BY delivery.failure_at DESC, delivery.id DESC
    LIMIT p_limit + 1
  ), page AS MATERIALIZED (
    SELECT candidate.* FROM candidates AS candidate
    ORDER BY candidate.failure_at DESC, candidate.id DESC
    LIMIT p_limit
  ), page_shape AS (
    SELECT page.id, page.failure_at,
      jsonb_build_object(
        'id', page.id,
        'tenantId', page.tenant_id,
        'channel', page.channel,
        'failureClass', coalesce(page.failure_class::text, 'unknown'),
        'failureCode', CASE
          WHEN page.failure_code IN (
            'retry_scheduled','terminal_failure','submission_uncertain',
            'configuration_revoked','tenant_suspended'
          ) THEN page.failure_code
          ELSE 'unknown'
        END,
        'failureAt', page.failure_at,
        'createdAt', page.created_at,
        'updatedAt', page.updated_at,
        'attemptCount', page.attempt_count
      ) AS item
    FROM page
  ), summary AS (
    SELECT count(*)::integer AS returned_count,
      (SELECT count(*) > p_limit FROM candidates) AS has_more,
      coalesce(jsonb_agg(page_shape.item ORDER BY page_shape.failure_at DESC,
        page_shape.id DESC), '[]'::jsonb) AS items,
      (SELECT jsonb_build_object('failureAt', page.failure_at, 'id', page.id)
       FROM page ORDER BY page.failure_at ASC, page.id ASC LIMIT 1) AS last_cursor
    FROM page_shape
  )
  SELECT jsonb_build_object(
      'projectionVersion', 1,
      'items', summary.items,
      'nextCursor', CASE WHEN summary.has_more THEN summary.last_cursor ELSE NULL END
    ), summary.returned_count, summary.has_more
  INTO document, returned_count, has_more
  FROM summary;

  PERFORM app.append_platform_audit_event(
    p_audit_event_id, 'user', actor.actor_user_id,
    'platform.operations.failed_notifications.read',
    'platform_failed_notification_inventory', NULL,
    p_request_id, p_correlation_id, p_ip_address, p_user_agent,
    actor.authentication_method, 'success', NULL,
    jsonb_build_object('projectionVersion', 1, 'limit', p_limit,
      'returnedCount', returned_count, 'hasMore', has_more)
  );
  RETURN document;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.list_platform_failed_notifications_v1(
  uuid, timestamp with time zone, uuid, integer, uuid, uuid, uuid, inet, text
) OWNER TO periapsis_platform_operations_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.list_platform_failed_notifications_v1(
  uuid, timestamp with time zone, uuid, integer, uuid, uuid, uuid, inet, text
) FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.list_platform_failed_notifications_v1(
  uuid, timestamp with time zone, uuid, integer, uuid, uuid, uuid, inet, text
) TO periapsis_api;
--> statement-breakpoint
