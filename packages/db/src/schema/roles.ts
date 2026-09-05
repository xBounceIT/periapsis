import { pgRole } from "drizzle-orm/pg-core";

/** Group roles only: deployments grant these roles to separately provisioned logins. */
export const migratorRole = pgRole("periapsis_migrator");
export const apiRole = pgRole("periapsis_api");
export const workerRole = pgRole("periapsis_worker");
export const notifierRole = pgRole("periapsis_notifier");
export const auditorRole = pgRole("periapsis_auditor");
/**
 * Internal NOLOGIN owner for the bounded audit reader functions. Runtime
 * logins never inherit this role; SECURITY DEFINER entry points are its only
 * exposed capability.
 */
export const auditReaderOwnerRole = pgRole("periapsis_audit_reader_owner", {
  inherit: false,
});
/**
 * Internal NOLOGIN owner for asynchronous audit exports and the guarded
 * retention/legal-hold protocol. API and worker logins receive EXECUTE on the
 * closed ABI only; neither role inherits this owner or reads its tables.
 */
export const auditOperationsOwnerRole = pgRole(
  "periapsis_audit_operations_owner",
  { inherit: false },
);
/**
 * Internal NOLOGIN owner for the bounded tenant branding/settings ABI.
 * Runtime API logins receive only EXECUTE on the closed read/update functions
 * and never inherit this role or receive direct table privileges.
 */
export const tenantSettingsOwnerRole = pgRole(
  "periapsis_tenant_settings_owner",
  { inherit: false },
);
/**
 * Internal NOLOGIN owner for bounded, redacted platform-administration
 * projections and the typed global-settings/feature-flag aggregates. Runtime
 * roles receive only EXECUTE on the closed ABI and never inherit this role or
 * receive direct table privileges.
 */
export const platformOperationsOwnerRole = pgRole(
  "periapsis_platform_operations_owner",
  { inherit: false },
);
/**
 * Internal NOLOGIN owner for private ticket saved-view tables and bounded ABI
 * functions. Runtime logins receive function execution only and never inherit
 * this role or direct table privileges.
 */
export const ticketSavedViewOwnerRole = pgRole(
  "periapsis_ticket_saved_view_owner",
  { inherit: false },
);
/**
 * Internal NOLOGIN owner for the tenant-shaped service-account attribution
 * projection used by operator ticket reads. It receives only the three source
 * columns needed by that projection and is never inherited by a runtime role.
 */
export const ticketAttributionOwnerRole = pgRole(
  "periapsis_ticket_attribution_owner",
  { inherit: false },
);
/**
 * Internal NOLOGIN owner for the ticket-shaped SLA column/value projections.
 * Runtime roles query the barrier views and never inherit this role or read the
 * private SLA tables directly.
 */
export const ticketSlaProjectionOwnerRole = pgRole(
  "periapsis_ticket_sla_projection_owner",
  { inherit: false },
);
/**
 * Internal NOLOGIN owner for fenced SLA timer, action, and object-event worker
 * ABIs. Runtime workers receive EXECUTE on bounded functions only.
 */
export const slaWorkerOwnerRole = pgRole("periapsis_sla_worker_owner", {
  inherit: false,
});
/**
 * Internal NOLOGIN owner for the durable ticket bulk/export runtime. The API
 * and worker roles receive only the closed SECURITY DEFINER ABI and never
 * inherit this role or direct privileges on its tenant-owned tables.
 */
export const ticketRuntimeOwnerRole = pgRole("periapsis_ticket_runtime_owner", {
  inherit: false,
});
/**
 * Internal NOLOGIN owner for bounded custom-field import jobs. API and worker
 * runtimes receive EXECUTE on the closed JSON ABI only and never inherit this
 * role or receive direct privileges on import metadata or row payloads.
 */
export const customFieldImportOwnerRole = pgRole(
  "periapsis_custom_field_import_owner",
  { inherit: false },
).existing();
/**
 * Internal NOLOGIN owner for immutable tenant webhook URL policies and the
 * atomic configuration-pin trigger. Runtime roles receive only the closed
 * administration ABI and never inherit this role.
 */
export const webhookURLPolicyOwnerRole = pgRole(
  "periapsis_webhook_url_policy_owner",
  { inherit: false },
).existing();
/** Existing bounded notification dispatch owner used by webhook claims. */
export const notificationDispatchOwnerRole = pgRole(
  "periapsis_notification_dispatch_owner",
  { inherit: false },
).existing();

export const databaseRoles = {
  migratorRole,
  apiRole,
  workerRole,
  notifierRole,
  auditorRole,
  auditReaderOwnerRole,
  auditOperationsOwnerRole,
  tenantSettingsOwnerRole,
  platformOperationsOwnerRole,
  ticketSavedViewOwnerRole,
  ticketAttributionOwnerRole,
  ticketSlaProjectionOwnerRole,
  slaWorkerOwnerRole,
  ticketRuntimeOwnerRole,
  customFieldImportOwnerRole,
  webhookURLPolicyOwnerRole,
  notificationDispatchOwnerRole,
} as const;
