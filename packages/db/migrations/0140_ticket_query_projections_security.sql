-- Narrow, tenant-shaped read projections for ticket queries. Runtime API
-- sessions never receive SELECT on the private service-account or SLA tables;
-- each security-barrier view runs as a dedicated NOLOGIN/NOBYPASSRLS owner
-- with column-level source grants and a matching tenant/membership RLS policy.

ALTER ROLE periapsis_ticket_attribution_owner
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOLOGIN NOREPLICATION
  NOBYPASSRLS NOINHERIT;
ALTER ROLE periapsis_ticket_attribution_owner
  SET search_path = pg_catalog, app, public;
ALTER ROLE periapsis_ticket_sla_projection_owner
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOLOGIN NOREPLICATION
  NOBYPASSRLS NOINHERIT;
ALTER ROLE periapsis_ticket_sla_projection_owner
  SET search_path = pg_catalog, app, public;
REVOKE periapsis_ticket_attribution_owner,
  periapsis_ticket_sla_projection_owner
FROM periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner, periapsis_sla_api_owner,
  periapsis_sla_worker_owner, periapsis_sla_readiness_owner,
  periapsis_ticket_saved_view_owner;
--> statement-breakpoint

GRANT USAGE ON SCHEMA app, public
TO periapsis_ticket_attribution_owner,
   periapsis_ticket_sla_projection_owner;
GRANT EXECUTE ON FUNCTION app.context_tenant_id(),
  app.current_tenant_membership_id()
TO periapsis_ticket_attribution_owner,
   periapsis_ticket_sla_projection_owner;
--> statement-breakpoint

REVOKE ALL ON TABLE public.tenant_service_accounts
FROM periapsis_ticket_attribution_owner;
GRANT SELECT (tenant_id, id, display_name)
ON TABLE public.tenant_service_accounts
TO periapsis_ticket_attribution_owner;

REVOKE ALL ON TABLE public.sla_column_versions,
  public.sla_materialized_column_values
FROM periapsis_ticket_sla_projection_owner;
GRANT SELECT (tenant_id, column_id, version, format, sortable)
ON TABLE public.sla_column_versions
TO periapsis_ticket_sla_projection_owner;
GRANT SELECT (
  tenant_id, object_type, object_id, column_id, column_version,
  state_value, instant_value, duration_micros_value, percentage_value,
  style_key, materialized_at
)
ON TABLE public.sla_materialized_column_values
TO periapsis_ticket_sla_projection_owner;
--> statement-breakpoint

CREATE VIEW app.ticket_service_account_attributions_v1
WITH (security_barrier = true, security_invoker = false)
AS
SELECT account.tenant_id, account.id, account.display_name
FROM public.tenant_service_accounts AS account
WHERE account.tenant_id = app.context_tenant_id()
  AND app.current_tenant_membership_id() IS NOT NULL;
ALTER VIEW app.ticket_service_account_attributions_v1
  OWNER TO periapsis_ticket_attribution_owner;
REVOKE ALL ON TABLE app.ticket_service_account_attributions_v1
FROM PUBLIC, periapsis_migrator, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner, periapsis_sla_api_owner,
  periapsis_sla_worker_owner, periapsis_sla_readiness_owner,
  periapsis_ticket_saved_view_owner, periapsis_ticket_sla_projection_owner;
GRANT SELECT ON TABLE app.ticket_service_account_attributions_v1
TO periapsis_api;
COMMENT ON VIEW app.ticket_service_account_attributions_v1 IS
  'Tenant-shaped service-account display attribution for operator ticket reads; no credential, role, lifecycle, or description data.';
--> statement-breakpoint

CREATE VIEW app.ticket_sla_column_revisions_v1
WITH (security_barrier = true, security_invoker = false)
AS
SELECT revision.tenant_id, revision.column_id, revision.version,
       revision.format, revision.sortable
FROM public.sla_column_versions AS revision
WHERE revision.tenant_id = app.context_tenant_id()
  AND app.current_tenant_membership_id() IS NOT NULL;
ALTER VIEW app.ticket_sla_column_revisions_v1
  OWNER TO periapsis_ticket_sla_projection_owner;
REVOKE ALL ON TABLE app.ticket_sla_column_revisions_v1
FROM PUBLIC, periapsis_migrator, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner, periapsis_sla_api_owner,
  periapsis_sla_worker_owner, periapsis_sla_readiness_owner,
  periapsis_ticket_saved_view_owner, periapsis_ticket_attribution_owner;
GRANT SELECT ON TABLE app.ticket_sla_column_revisions_v1
TO periapsis_api;
COMMENT ON VIEW app.ticket_sla_column_revisions_v1 IS
  'Tenant-shaped sortable SLA revision metadata for saved-ticket-view compilation.';
--> statement-breakpoint

CREATE VIEW app.ticket_sla_materialized_values_v1
WITH (security_barrier = true, security_invoker = false)
AS
SELECT value.tenant_id, value.object_type, value.object_id,
       value.column_id, value.column_version, revision.format,
       value.state_value, value.instant_value,
       value.duration_micros_value, value.percentage_value,
       value.style_key, value.materialized_at
FROM public.sla_materialized_column_values AS value
JOIN public.sla_column_versions AS revision
  ON revision.tenant_id = value.tenant_id
 AND revision.column_id = value.column_id
 AND revision.version = value.column_version
WHERE value.tenant_id = app.context_tenant_id()
  AND app.current_tenant_membership_id() IS NOT NULL;
ALTER VIEW app.ticket_sla_materialized_values_v1
  OWNER TO periapsis_ticket_sla_projection_owner;
REVOKE ALL ON TABLE app.ticket_sla_materialized_values_v1
FROM PUBLIC, periapsis_migrator, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner, periapsis_sla_api_owner,
  periapsis_sla_worker_owner, periapsis_sla_readiness_owner,
  periapsis_ticket_saved_view_owner, periapsis_ticket_attribution_owner;
GRANT SELECT ON TABLE app.ticket_sla_materialized_values_v1
TO periapsis_api;
COMMENT ON VIEW app.ticket_sla_materialized_values_v1 IS
  'Tenant-shaped typed SLA values and exact revision format for saved-ticket-view sort and list projection.';
--> statement-breakpoint

-- Sort paths are operation-shaped by scalar format. Keeping the type predicate
-- inside each barrier lets PostgreSQL use the matching typed index without
-- exposing the private table or relaxing the security fence.
CREATE VIEW app.ticket_sla_instant_sort_values_v1
WITH (security_barrier = true, security_invoker = false)
AS
SELECT value.tenant_id, value.object_type, value.object_id,
       value.column_id, value.column_version, value.instant_value
FROM public.sla_materialized_column_values AS value
JOIN public.sla_column_versions AS revision
  ON revision.tenant_id = value.tenant_id
 AND revision.column_id = value.column_id
 AND revision.version = value.column_version
WHERE value.tenant_id = app.context_tenant_id()
  AND app.current_tenant_membership_id() IS NOT NULL
  AND revision.format = 'datetime'
  AND value.instant_value IS NOT NULL;
ALTER VIEW app.ticket_sla_instant_sort_values_v1
  OWNER TO periapsis_ticket_sla_projection_owner;
REVOKE ALL ON TABLE app.ticket_sla_instant_sort_values_v1
FROM PUBLIC, periapsis_migrator, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner, periapsis_sla_api_owner,
  periapsis_sla_worker_owner, periapsis_sla_readiness_owner,
  periapsis_ticket_saved_view_owner, periapsis_ticket_attribution_owner;
GRANT SELECT ON TABLE app.ticket_sla_instant_sort_values_v1
TO periapsis_api;
COMMENT ON VIEW app.ticket_sla_instant_sort_values_v1 IS
  'Tenant-shaped datetime SLA values for index-preserving saved-view sorts.';
--> statement-breakpoint

CREATE VIEW app.ticket_sla_duration_sort_values_v1
WITH (security_barrier = true, security_invoker = false)
AS
SELECT value.tenant_id, value.object_type, value.object_id,
       value.column_id, value.column_version, value.duration_micros_value
FROM public.sla_materialized_column_values AS value
JOIN public.sla_column_versions AS revision
  ON revision.tenant_id = value.tenant_id
 AND revision.column_id = value.column_id
 AND revision.version = value.column_version
WHERE value.tenant_id = app.context_tenant_id()
  AND app.current_tenant_membership_id() IS NOT NULL
  AND revision.format = 'duration'
  AND value.duration_micros_value IS NOT NULL;
ALTER VIEW app.ticket_sla_duration_sort_values_v1
  OWNER TO periapsis_ticket_sla_projection_owner;
REVOKE ALL ON TABLE app.ticket_sla_duration_sort_values_v1
FROM PUBLIC, periapsis_migrator, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner, periapsis_sla_api_owner,
  periapsis_sla_worker_owner, periapsis_sla_readiness_owner,
  periapsis_ticket_saved_view_owner, periapsis_ticket_attribution_owner;
GRANT SELECT ON TABLE app.ticket_sla_duration_sort_values_v1
TO periapsis_api;
COMMENT ON VIEW app.ticket_sla_duration_sort_values_v1 IS
  'Tenant-shaped duration SLA values for index-preserving saved-view sorts.';
--> statement-breakpoint

CREATE VIEW app.ticket_sla_percentage_sort_values_v1
WITH (security_barrier = true, security_invoker = false)
AS
SELECT value.tenant_id, value.object_type, value.object_id,
       value.column_id, value.column_version, value.percentage_value
FROM public.sla_materialized_column_values AS value
JOIN public.sla_column_versions AS revision
  ON revision.tenant_id = value.tenant_id
 AND revision.column_id = value.column_id
 AND revision.version = value.column_version
WHERE value.tenant_id = app.context_tenant_id()
  AND app.current_tenant_membership_id() IS NOT NULL
  AND revision.format = 'percentage'
  AND value.percentage_value IS NOT NULL;
ALTER VIEW app.ticket_sla_percentage_sort_values_v1
  OWNER TO periapsis_ticket_sla_projection_owner;
REVOKE ALL ON TABLE app.ticket_sla_percentage_sort_values_v1
FROM PUBLIC, periapsis_migrator, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner, periapsis_sla_api_owner,
  periapsis_sla_worker_owner, periapsis_sla_readiness_owner,
  periapsis_ticket_saved_view_owner, periapsis_ticket_attribution_owner;
GRANT SELECT ON TABLE app.ticket_sla_percentage_sort_values_v1
TO periapsis_api;
COMMENT ON VIEW app.ticket_sla_percentage_sort_values_v1 IS
  'Tenant-shaped percentage SLA values for index-preserving saved-view sorts.';
--> statement-breakpoint

CREATE VIEW app.ticket_sla_state_sort_values_v1
WITH (security_barrier = true, security_invoker = false)
AS
SELECT value.tenant_id, value.object_type, value.object_id,
       value.column_id, value.column_version, value.state_value
FROM public.sla_materialized_column_values AS value
JOIN public.sla_column_versions AS revision
  ON revision.tenant_id = value.tenant_id
 AND revision.column_id = value.column_id
 AND revision.version = value.column_version
WHERE value.tenant_id = app.context_tenant_id()
  AND app.current_tenant_membership_id() IS NOT NULL
  AND revision.format = 'state_badge'
  AND value.state_value IS NOT NULL;
ALTER VIEW app.ticket_sla_state_sort_values_v1
  OWNER TO periapsis_ticket_sla_projection_owner;
REVOKE ALL ON TABLE app.ticket_sla_state_sort_values_v1
FROM PUBLIC, periapsis_migrator, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner, periapsis_sla_api_owner,
  periapsis_sla_worker_owner, periapsis_sla_readiness_owner,
  periapsis_ticket_saved_view_owner, periapsis_ticket_attribution_owner;
GRANT SELECT ON TABLE app.ticket_sla_state_sort_values_v1
TO periapsis_api;
COMMENT ON VIEW app.ticket_sla_state_sort_values_v1 IS
  'Tenant-shaped state SLA values for index-preserving saved-view sorts.';
--> statement-breakpoint

-- Reinforce the runtime boundary explicitly. Only the barrier views above are
-- granted to the API role; source table access remains denied at table and
-- column level.
REVOKE ALL ON TABLE public.tenant_service_accounts,
  public.sla_column_versions, public.sla_materialized_column_values
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner, periapsis_sla_readiness_owner,
  periapsis_ticket_saved_view_owner;

-- Table-level revocation does not remove an older column-level grant. Revoke
-- every source column explicitly so an upgraded installation cannot retain a
-- stale bypass around the projections.
REVOKE SELECT (
  id, tenant_id, key, display_name, description,
  created_by_membership_id, archived_at, archived_by_membership_id,
  archive_reason, version, created_at, updated_at
) ON TABLE public.tenant_service_accounts
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner, periapsis_sla_readiness_owner,
  periapsis_ticket_saved_view_owner;
REVOKE SELECT (
  tenant_id, column_id, version, label, metric_definition_id,
  calculation, format, sortable, filterable, customer_visible,
  visible_role_keys, position, style_rules, revision_digest,
  created_by_membership_id, created_at
) ON TABLE public.sla_column_versions
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner, periapsis_sla_readiness_owner,
  periapsis_ticket_saved_view_owner;
REVOKE SELECT (
  tenant_id, object_type, object_id, sla_instance_id, metric_instance_id,
  column_id, column_version, state_value, instant_value,
  duration_micros_value, percentage_value, style_key, next_refresh_at,
  materialized_at
) ON TABLE public.sla_materialized_column_values
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner, periapsis_sla_readiness_owner,
  periapsis_ticket_saved_view_owner;
