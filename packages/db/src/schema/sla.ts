import { sql } from "drizzle-orm";
import {
  bigint,
  boolean,
  check,
  doublePrecision,
  foreignKey,
  index,
  integer,
  jsonb,
  pgEnum,
  pgPolicy,
  pgTable,
  primaryKey,
  text,
  timestamp,
  unique,
  uniqueIndex,
  uuid,
} from "drizzle-orm/pg-core";

import { bytea } from "./binary.js";
import { alerts } from "./alerts.js";
import { currentTenantId } from "./context.js";
import { activeActorMembershipFor, tenantMemberships } from "./identity.js";
import { outboxEvents } from "./outbox.js";
import {
  apiRole,
  slaWorkerOwnerRole,
  ticketSlaProjectionOwnerRole,
  workerRole,
} from "./roles.js";
import { tenants } from "./tenancy.js";

type JSONRecord = Record<string, unknown>;

export const slaObjectType = pgEnum("sla_object_type", [
  "alert",
  "case",
  "task",
]);
export const slaClockType = pgEnum("sla_clock_type", ["elapsed", "business"]);
export const slaResetPolicy = pgEnum("sla_reset_policy", [
  "ignore",
  "clear",
  "restart",
]);
export const slaWarningKind = pgEnum("sla_warning_kind", [
  "none",
  "consumed_percent",
  "remaining_duration",
]);
export const slaMetricLifecycle = pgEnum("sla_metric_lifecycle", [
  "pending",
  "running",
  "paused",
  "completed",
]);
export const slaMetricState = pgEnum("sla_metric_state", [
  "pending",
  "on_track",
  "at_risk",
  "paused",
  "breached",
  "completed",
]);
export const slaTriggerKind = pgEnum("sla_trigger_kind", [
  "consumed_percent",
  "remaining_duration",
  "due",
  "after_breach",
  "repeated_after_breach",
  "state_changed",
  "resumed",
]);
export const slaTriggerActionKind = pgEnum("sla_trigger_action_kind", [
  "email",
  "webhook",
  "add_tag",
  "change_priority",
  "assign_operator_team",
  "create_task",
  "create_system_alert",
  "domain_event",
]);
export const slaColumnCalculation = pgEnum("sla_column_calculation", [
  "due_at",
  "remaining_seconds",
  "state",
  "consumed_percentage",
  "breached_at",
]);
export const slaColumnFormat = pgEnum("sla_column_format", [
  "datetime",
  "duration",
  "state_badge",
  "percentage",
]);
export const slaOverrideKind = pgEnum("sla_override_kind", [
  "extend",
  "suspend",
  "resume",
  "complete",
  "change_calendar",
  "change_policy",
  "recalculate",
]);
export const slaEventOutcome = pgEnum("sla_event_outcome", [
  "no_policy",
  "assigned",
  "updated",
]);
export const slaOverrideOutcome = pgEnum("sla_override_outcome", [
  "metric_updated",
  "policy_changed",
]);
export const slaJobStatus = pgEnum("sla_job_status", [
  "queued",
  "leased",
  "retry_scheduled",
  "completed",
  "dead_lettered",
]);

const tenantAllPolicy = (name: string, tenantId: unknown) =>
  pgPolicy(name, {
    as: "permissive",
    for: "all",
    to: apiRole,
    using: activeActorMembershipFor(tenantId),
    withCheck: activeActorMembershipFor(tenantId),
  });

const workerTenantPolicy = (name: string, tenantId: unknown) =>
  pgPolicy(name, {
    as: "permissive",
    for: "all",
    to: workerRole,
    using: sql`${tenantId} = ${currentTenantId}
      and app.tenant_is_active_v1(${tenantId})`,
    withCheck: sql`${tenantId} = ${currentTenantId}
      and app.tenant_is_active_v1(${tenantId})`,
  });

const ticketProjectionPolicy = (name: string, tenantId: unknown) =>
  pgPolicy(name, {
    as: "permissive",
    for: "select",
    to: ticketSlaProjectionOwnerRole,
    using: sql`${tenantId} = app.context_tenant_id()
      and app.current_tenant_membership_id() is not null`,
  });

const uuidV7 = (value: unknown) =>
  sql`(uuid_extract_version(${value}) = 7) is true`;
const keyCheck = (value: unknown) =>
  sql`${value} ~ '^[a-z][a-z0-9_.-]{0,62}[a-z0-9]$'`;
const versionCheck = (value: unknown) => sql`${value} between 1 and 2147483646`;

export const slaBusinessCalendars = pgTable(
  "sla_business_calendars",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    key: text("key").notNull(),
    activeVersion: integer("active_version").notNull().default(1),
    resourceVersion: integer("resource_version").notNull().default(1),
    createdByMembershipId: uuid("created_by_membership_id").notNull(),
    updatedByMembershipId: uuid("updated_by_membership_id").notNull(),
    archivedByMembershipId: uuid("archived_by_membership_id"),
    archivedAt: timestamp("archived_at", { withTimezone: true, mode: "date" }),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    unique("sla_business_calendars_tenant_id_id_key").on(
      table.tenantId,
      table.id,
    ),
    unique("sla_business_calendars_tenant_key_key").on(
      table.tenantId,
      table.key,
    ),
    index("sla_business_calendars_inventory_idx").on(
      table.tenantId,
      table.archivedAt,
      table.key,
      table.id,
    ),
    foreignKey({
      name: "sla_business_calendars_creator_fk",
      columns: [table.tenantId, table.createdByMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    }).onDelete("restrict"),
    foreignKey({
      name: "sla_business_calendars_updater_fk",
      columns: [table.tenantId, table.updatedByMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    }).onDelete("restrict"),
    foreignKey({
      name: "sla_business_calendars_archiver_fk",
      columns: [table.tenantId, table.archivedByMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    }).onDelete("restrict"),
    check("sla_business_calendars_id_check", uuidV7(table.id)),
    check("sla_business_calendars_key_check", keyCheck(table.key)),
    check(
      "sla_business_calendars_version_check",
      sql`${versionCheck(table.activeVersion)} and ${versionCheck(table.resourceVersion)}`,
    ),
    check(
      "sla_business_calendars_lifecycle_check",
      sql`${table.updatedAt} >= ${table.createdAt}
        and (${table.archivedAt} is null or ${table.archivedAt} between ${table.createdAt} and ${table.updatedAt})
        and (${table.archivedAt} is null) = (${table.archivedByMembershipId} is null)`,
    ),
    tenantAllPolicy("sla_business_calendars_api_tenant", table.tenantId),
  ],
).enableRLS();

export const slaBusinessCalendarVersions = pgTable(
  "sla_business_calendar_versions",
  {
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    calendarId: uuid("calendar_id").notNull(),
    version: integer("version").notNull(),
    label: text("label").notNull(),
    timezone: text("timezone").notNull(),
    weeklySchedule: jsonb("weekly_schedule").$type<JSONRecord[]>().notNull(),
    exceptions: jsonb("exceptions").$type<JSONRecord[]>().notNull(),
    revisionDigest: bytea("revision_digest").notNull(),
    createdByMembershipId: uuid("created_by_membership_id").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    primaryKey({
      name: "sla_business_calendar_versions_pkey",
      columns: [table.tenantId, table.calendarId, table.version],
    }),
    foreignKey({
      name: "sla_business_calendar_versions_shell_fk",
      columns: [table.tenantId, table.calendarId],
      foreignColumns: [slaBusinessCalendars.tenantId, slaBusinessCalendars.id],
    }).onDelete("restrict"),
    foreignKey({
      name: "sla_business_calendar_versions_creator_fk",
      columns: [table.tenantId, table.createdByMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    }).onDelete("restrict"),
    check(
      "sla_business_calendar_versions_version_check",
      versionCheck(table.version),
    ),
    check(
      "sla_business_calendar_versions_text_check",
      sql`btrim(${table.label}) <> '' and octet_length(${table.label}) <= 256
        and ${table.label} !~ '[[:cntrl:]]'
        and char_length(${table.timezone}) <= 128
        and (${table.timezone} = 'UTC' or ${table.timezone} ~ '^[A-Za-z][A-Za-z0-9_+.-]{0,62}(/[A-Za-z0-9_+.-]{1,63}){1,3}$')`,
    ),
    check(
      "sla_business_calendar_versions_payload_check",
      sql`jsonb_typeof(${table.weeklySchedule}) = 'array'
        and jsonb_array_length(${table.weeklySchedule}) between 1 and 7
        and pg_column_size(${table.weeklySchedule}) <= 65536
        and jsonb_typeof(${table.exceptions}) = 'array'
        and jsonb_array_length(${table.exceptions}) <= 36600
        and pg_column_size(${table.exceptions}) <= 4194304
        and octet_length(${table.revisionDigest}) = 32`,
    ),
    tenantAllPolicy(
      "sla_business_calendar_versions_api_tenant",
      table.tenantId,
    ),
  ],
).enableRLS();

export const slaPolicies = pgTable(
  "sla_policies",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    key: text("key").notNull(),
    activeVersion: integer("active_version").notNull().default(1),
    resourceVersion: integer("resource_version").notNull().default(1),
    createdByMembershipId: uuid("created_by_membership_id").notNull(),
    updatedByMembershipId: uuid("updated_by_membership_id").notNull(),
    archivedByMembershipId: uuid("archived_by_membership_id"),
    archivedAt: timestamp("archived_at", { withTimezone: true, mode: "date" }),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    unique("sla_policies_tenant_id_id_key").on(table.tenantId, table.id),
    unique("sla_policies_tenant_key_key").on(table.tenantId, table.key),
    index("sla_policies_inventory_idx").on(
      table.tenantId,
      table.archivedAt,
      table.key,
      table.id,
    ),
    foreignKey({
      name: "sla_policies_creator_fk",
      columns: [table.tenantId, table.createdByMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    }).onDelete("restrict"),
    foreignKey({
      name: "sla_policies_updater_fk",
      columns: [table.tenantId, table.updatedByMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    }).onDelete("restrict"),
    foreignKey({
      name: "sla_policies_archiver_fk",
      columns: [table.tenantId, table.archivedByMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    }).onDelete("restrict"),
    check("sla_policies_id_check", uuidV7(table.id)),
    check("sla_policies_key_check", keyCheck(table.key)),
    check(
      "sla_policies_version_check",
      sql`${versionCheck(table.activeVersion)} and ${versionCheck(table.resourceVersion)}`,
    ),
    check(
      "sla_policies_lifecycle_check",
      sql`${table.updatedAt} >= ${table.createdAt}
        and (${table.archivedAt} is null or ${table.archivedAt} between ${table.createdAt} and ${table.updatedAt})
        and (${table.archivedAt} is null) = (${table.archivedByMembershipId} is null)`,
    ),
    tenantAllPolicy("sla_policies_api_tenant", table.tenantId),
  ],
).enableRLS();

export const slaPolicyVersions = pgTable(
  "sla_policy_versions",
  {
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    policyId: uuid("policy_id").notNull(),
    version: integer("version").notNull(),
    name: text("name").notNull(),
    description: text("description").notNull().default(""),
    priority: integer("priority").notNull(),
    objectTypes: slaObjectType("object_types").array().notNull(),
    matchRule: jsonb("match_rule").$type<JSONRecord>().notNull(),
    effectiveFrom: timestamp("effective_from", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    effectiveUntil: timestamp("effective_until", {
      withTimezone: true,
      mode: "date",
    }),
    enabled: boolean("enabled").notNull(),
    applyToSlaEngineSource: boolean("apply_to_sla_engine_source")
      .notNull()
      .default(false),
    revisionDigest: bytea("revision_digest").notNull(),
    createdByMembershipId: uuid("created_by_membership_id").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    primaryKey({
      name: "sla_policy_versions_pkey",
      columns: [table.tenantId, table.policyId, table.version],
    }),
    foreignKey({
      name: "sla_policy_versions_shell_fk",
      columns: [table.tenantId, table.policyId],
      foreignColumns: [slaPolicies.tenantId, slaPolicies.id],
    }).onDelete("restrict"),
    foreignKey({
      name: "sla_policy_versions_creator_fk",
      columns: [table.tenantId, table.createdByMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    }).onDelete("restrict"),
    index("sla_policy_versions_match_idx").on(
      table.tenantId,
      table.enabled,
      table.priority,
      table.effectiveFrom,
      table.policyId,
      table.version,
    ),
    check("sla_policy_versions_version_check", versionCheck(table.version)),
    check(
      "sla_policy_versions_text_check",
      sql`btrim(${table.name}) <> '' and octet_length(${table.name}) <= 256
        and ${table.name} !~ '[[:cntrl:]]'
        and octet_length(${table.description}) <= 8192
        and ${table.description} !~ '[[:cntrl:]]'`,
    ),
    check(
      "sla_policy_versions_payload_check",
      sql`${table.priority} between -1000000 and 1000000
        and cardinality(${table.objectTypes}) between 1 and 3
        and array_position(${table.objectTypes}, null) is null
        and jsonb_typeof(${table.matchRule}) = 'object'
        and pg_column_size(${table.matchRule}) <= 262144
        and (${table.effectiveUntil} is null or ${table.effectiveUntil} > ${table.effectiveFrom})
        and octet_length(${table.revisionDigest}) = 32`,
    ),
    tenantAllPolicy("sla_policy_versions_api_tenant", table.tenantId),
  ],
).enableRLS();

export const slaMetricDefinitions = pgTable(
  "sla_metric_definitions",
  {
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    policyId: uuid("policy_id").notNull(),
    policyVersion: integer("policy_version").notNull(),
    id: uuid("id")
      .notNull()
      .default(sql`uuidv7()`),
    key: text("key").notNull(),
    label: text("label").notNull(),
    description: text("description").notNull().default(""),
    durationMicros: bigint("duration_micros", { mode: "number" }).notNull(),
    clock: slaClockType("clock").notNull(),
    calendarId: uuid("calendar_id"),
    calendarVersion: integer("calendar_version"),
    startEvent: text("start_event").notNull(),
    pauseEvent: text("pause_event"),
    resumeEvent: text("resume_event"),
    completionEvent: text("completion_event").notNull(),
    resetEvent: text("reset_event"),
    resetPolicy: slaResetPolicy("reset_policy").notNull(),
    warningKind: slaWarningKind("warning_kind").notNull(),
    warningConsumedPercent: integer("warning_consumed_percent"),
    warningRemainingMicros: bigint("warning_remaining_micros", {
      mode: "number",
    }),
    breachGraceMicros: bigint("breach_grace_micros", {
      mode: "number",
    }).notNull(),
    displayFormat: text("display_format").notNull(),
    customerVisible: boolean("customer_visible").notNull(),
    apiVisible: boolean("api_visible").notNull(),
    position: integer("position").notNull(),
    definitionDigest: bytea("definition_digest").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    primaryKey({
      name: "sla_metric_definitions_pkey",
      columns: [table.tenantId, table.policyId, table.policyVersion, table.id],
    }),
    unique("sla_metric_definitions_tenant_id_id_key").on(
      table.tenantId,
      table.id,
    ),
    unique("sla_metric_definitions_policy_key_key").on(
      table.tenantId,
      table.policyId,
      table.policyVersion,
      table.key,
    ),
    unique("sla_metric_definitions_policy_position_key").on(
      table.tenantId,
      table.policyId,
      table.policyVersion,
      table.position,
    ),
    foreignKey({
      name: "sla_metric_definitions_policy_fk",
      columns: [table.tenantId, table.policyId, table.policyVersion],
      foreignColumns: [
        slaPolicyVersions.tenantId,
        slaPolicyVersions.policyId,
        slaPolicyVersions.version,
      ],
    }).onDelete("restrict"),
    foreignKey({
      name: "sla_metric_definitions_calendar_fk",
      columns: [table.tenantId, table.calendarId, table.calendarVersion],
      foreignColumns: [
        slaBusinessCalendarVersions.tenantId,
        slaBusinessCalendarVersions.calendarId,
        slaBusinessCalendarVersions.version,
      ],
    }).onDelete("restrict"),
    check("sla_metric_definitions_id_check", uuidV7(table.id)),
    check(
      "sla_metric_definitions_identity_check",
      sql`${keyCheck(table.key)} and ${versionCheck(table.policyVersion)}
        and ${table.position} between 0 and 31`,
    ),
    check(
      "sla_metric_definitions_text_check",
      sql`btrim(${table.label}) <> '' and octet_length(${table.label}) <= 256
        and ${table.label} !~ '[[:cntrl:]]'
        and octet_length(${table.description}) <= 8192
        and ${table.description} !~ '[[:cntrl:]]'
        and ${table.displayFormat} ~ '^[a-z][a-z0-9_.-]{0,127}$'`,
    ),
    check(
      "sla_metric_definitions_duration_check",
      sql`${table.durationMicros} between 1 and 3153600000000000
        and ${table.breachGraceMicros} between 0 and ${table.durationMicros}`,
    ),
    check(
      "sla_metric_definitions_calendar_check",
      sql`(${table.clock} = 'elapsed' and ${table.calendarId} is null and ${table.calendarVersion} is null)
        or (${table.clock} = 'business' and ${table.calendarId} is not null and ${table.calendarVersion} between 1 and 2147483646)`,
    ),
    check(
      "sla_metric_definitions_events_check",
      sql`${keyCheck(table.startEvent)} and ${keyCheck(table.completionEvent)}
        and ${table.startEvent} <> ${table.completionEvent}
        and (${table.pauseEvent} is null) = (${table.resumeEvent} is null)
        and (${table.pauseEvent} is null or (${keyCheck(table.pauseEvent)} and ${keyCheck(table.resumeEvent)}))
        and (${table.resetPolicy} = 'ignore') = (${table.resetEvent} is null)
        and (${table.resetEvent} is null or ${keyCheck(table.resetEvent)})
        and (${table.pauseEvent} is null or (
          ${table.pauseEvent} <> ${table.startEvent}
          and ${table.pauseEvent} <> ${table.completionEvent}
          and ${table.resumeEvent} <> ${table.startEvent}
          and ${table.resumeEvent} <> ${table.completionEvent}
          and ${table.pauseEvent} <> ${table.resumeEvent}
        ))
        and (${table.resetEvent} is null or (
          ${table.resetEvent} <> ${table.startEvent}
          and ${table.resetEvent} <> ${table.completionEvent}
          and (${table.pauseEvent} is null or (
            ${table.resetEvent} <> ${table.pauseEvent}
            and ${table.resetEvent} <> ${table.resumeEvent}
          ))
        ))`,
    ),
    check(
      "sla_metric_definitions_warning_check",
      sql`(${table.warningKind} = 'none'
          and ${table.warningConsumedPercent} is null
          and ${table.warningRemainingMicros} is null)
        or (${table.warningKind} = 'consumed_percent'
          and ${table.warningConsumedPercent} between 1 and 99
          and ${table.warningRemainingMicros} is null)
        or (${table.warningKind} = 'remaining_duration'
          and ${table.warningConsumedPercent} is null
          and ${table.warningRemainingMicros} between 1 and ${table.durationMicros} - 1)`,
    ),
    check(
      "sla_metric_definitions_digest_check",
      sql`octet_length(${table.definitionDigest}) = 32`,
    ),
    tenantAllPolicy("sla_metric_definitions_api_tenant", table.tenantId),
    workerTenantPolicy("sla_metric_definitions_worker_tenant", table.tenantId),
  ],
).enableRLS();

export const slaTriggerDefinitions = pgTable(
  "sla_trigger_definitions",
  {
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    policyId: uuid("policy_id").notNull(),
    policyVersion: integer("policy_version").notNull(),
    id: uuid("id")
      .notNull()
      .default(sql`uuidv7()`),
    metricDefinitionId: uuid("metric_definition_id").notNull(),
    key: text("key").notNull(),
    kind: slaTriggerKind("kind").notNull(),
    consumedPercent: integer("consumed_percent"),
    remainingMicros: bigint("remaining_micros", { mode: "number" }),
    offsetMicros: bigint("offset_micros", { mode: "number" }),
    repeatIntervalMicros: bigint("repeat_interval_micros", { mode: "number" }),
    targetState: slaMetricState("target_state"),
    actionKind: slaTriggerActionKind("action_kind").notNull(),
    actionConfigurationId: uuid("action_configuration_id"),
    actionValue: text("action_value"),
    allowRecursiveSla: boolean("allow_recursive_sla").notNull().default(false),
    position: integer("position").notNull(),
    definitionDigest: bytea("definition_digest").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    primaryKey({
      name: "sla_trigger_definitions_pkey",
      columns: [table.tenantId, table.policyId, table.policyVersion, table.id],
    }),
    unique("sla_trigger_definitions_tenant_id_id_key").on(
      table.tenantId,
      table.id,
    ),
    unique("sla_trigger_definitions_policy_key_key").on(
      table.tenantId,
      table.policyId,
      table.policyVersion,
      table.key,
    ),
    unique("sla_trigger_definitions_policy_position_key").on(
      table.tenantId,
      table.policyId,
      table.policyVersion,
      table.position,
    ),
    foreignKey({
      name: "sla_trigger_definitions_metric_fk",
      columns: [
        table.tenantId,
        table.policyId,
        table.policyVersion,
        table.metricDefinitionId,
      ],
      foreignColumns: [
        slaMetricDefinitions.tenantId,
        slaMetricDefinitions.policyId,
        slaMetricDefinitions.policyVersion,
        slaMetricDefinitions.id,
      ],
    }).onDelete("restrict"),
    check("sla_trigger_definitions_id_check", uuidV7(table.id)),
    check(
      "sla_trigger_definitions_identity_check",
      sql`${keyCheck(table.key)} and ${versionCheck(table.policyVersion)}
        and ${table.position} between 0 and 255 and octet_length(${table.definitionDigest}) = 32`,
    ),
    check(
      "sla_trigger_definitions_threshold_check",
      sql`(${table.kind} = 'consumed_percent' and ${table.consumedPercent} between 1 and 100
          and ${table.remainingMicros} is null and ${table.offsetMicros} is null
          and ${table.repeatIntervalMicros} is null and ${table.targetState} is null)
        or (${table.kind} = 'remaining_duration' and ${table.consumedPercent} is null
          and ${table.remainingMicros} >= 0 and ${table.offsetMicros} is null
          and ${table.repeatIntervalMicros} is null and ${table.targetState} is null)
        or (${table.kind} = 'due' and ${table.consumedPercent} is null
          and ${table.remainingMicros} is null and ${table.offsetMicros} is null
          and ${table.repeatIntervalMicros} is null and ${table.targetState} is null)
        or (${table.kind} = 'after_breach' and ${table.consumedPercent} is null
          and ${table.remainingMicros} is null and ${table.offsetMicros} >= 0
          and ${table.repeatIntervalMicros} is null and ${table.targetState} is null)
        or (${table.kind} = 'repeated_after_breach' and ${table.consumedPercent} is null
          and ${table.remainingMicros} is null and ${table.offsetMicros} >= 0
          and ${table.repeatIntervalMicros} > 0 and ${table.targetState} is null)
        or (${table.kind} = 'state_changed' and ${table.consumedPercent} is null
          and ${table.remainingMicros} is null and ${table.offsetMicros} is null
          and ${table.repeatIntervalMicros} is null and ${table.targetState} is not null)
        or (${table.kind} = 'resumed' and ${table.consumedPercent} is null
          and ${table.remainingMicros} is null and ${table.offsetMicros} is null
          and ${table.repeatIntervalMicros} is null and ${table.targetState} is null)`,
    ),
    check(
      "sla_trigger_definitions_action_check",
      sql`((${table.actionKind} in ('email', 'webhook') and ${table.actionConfigurationId} is not null and ${table.actionValue} is null)
          or (${table.actionKind} in ('add_tag', 'change_priority', 'domain_event')
            and ${table.actionConfigurationId} is null and ${table.actionValue} is not null
            and ${keyCheck(table.actionValue)})
          or (${table.actionKind} = 'assign_operator_team' and ${table.actionConfigurationId} is not null and ${table.actionValue} is null)
          or (${table.actionKind} = 'create_task' and ${table.actionConfigurationId} is null
            and ${table.actionValue} is not null and octet_length(${table.actionValue}) <= 2048)
          or (${table.actionKind} = 'create_system_alert' and ${table.actionConfigurationId} is null
            and ${table.actionValue} is not null and ${keyCheck(table.actionValue)}))
        and (${table.allowRecursiveSla} is false or ${table.actionKind} = 'create_system_alert')`,
    ),
    tenantAllPolicy("sla_trigger_definitions_api_tenant", table.tenantId),
    workerTenantPolicy("sla_trigger_definitions_worker_tenant", table.tenantId),
  ],
).enableRLS();

export const slaColumns = pgTable(
  "sla_columns",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    key: text("key").notNull(),
    activeVersion: integer("active_version").notNull().default(1),
    resourceVersion: integer("resource_version").notNull().default(1),
    createdByMembershipId: uuid("created_by_membership_id").notNull(),
    updatedByMembershipId: uuid("updated_by_membership_id").notNull(),
    archivedByMembershipId: uuid("archived_by_membership_id"),
    archivedAt: timestamp("archived_at", { withTimezone: true, mode: "date" }),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    unique("sla_columns_tenant_id_id_key").on(table.tenantId, table.id),
    unique("sla_columns_tenant_key_key").on(table.tenantId, table.key),
    index("sla_columns_inventory_idx").on(
      table.tenantId,
      table.archivedAt,
      table.key,
      table.id,
    ),
    foreignKey({
      name: "sla_columns_creator_fk",
      columns: [table.tenantId, table.createdByMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    }).onDelete("restrict"),
    foreignKey({
      name: "sla_columns_updater_fk",
      columns: [table.tenantId, table.updatedByMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    }).onDelete("restrict"),
    foreignKey({
      name: "sla_columns_archiver_fk",
      columns: [table.tenantId, table.archivedByMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    }).onDelete("restrict"),
    check("sla_columns_id_check", uuidV7(table.id)),
    check("sla_columns_key_check", keyCheck(table.key)),
    check(
      "sla_columns_version_check",
      sql`${versionCheck(table.activeVersion)} and ${versionCheck(table.resourceVersion)}`,
    ),
    check(
      "sla_columns_lifecycle_check",
      sql`${table.updatedAt} >= ${table.createdAt}
        and (${table.archivedAt} is null or ${table.archivedAt} between ${table.createdAt} and ${table.updatedAt})
        and (${table.archivedAt} is null) = (${table.archivedByMembershipId} is null)`,
    ),
    tenantAllPolicy("sla_columns_api_tenant", table.tenantId),
  ],
).enableRLS();

export const slaColumnVersions = pgTable(
  "sla_column_versions",
  {
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    columnId: uuid("column_id").notNull(),
    version: integer("version").notNull(),
    label: text("label").notNull(),
    metricDefinitionId: uuid("metric_definition_id").notNull(),
    calculation: slaColumnCalculation("calculation").notNull(),
    format: slaColumnFormat("format").notNull(),
    sortable: boolean("sortable").notNull(),
    filterable: boolean("filterable").notNull(),
    customerVisible: boolean("customer_visible").notNull(),
    visibleRoleKeys: text("visible_role_keys").array().notNull(),
    position: integer("position").notNull(),
    styleRules: jsonb("style_rules").$type<JSONRecord[]>().notNull(),
    revisionDigest: bytea("revision_digest").notNull(),
    createdByMembershipId: uuid("created_by_membership_id").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    primaryKey({
      name: "sla_column_versions_pkey",
      columns: [table.tenantId, table.columnId, table.version],
    }),
    foreignKey({
      name: "sla_column_versions_shell_fk",
      columns: [table.tenantId, table.columnId],
      foreignColumns: [slaColumns.tenantId, slaColumns.id],
    }).onDelete("restrict"),
    foreignKey({
      name: "sla_column_versions_metric_fk",
      columns: [table.tenantId, table.metricDefinitionId],
      foreignColumns: [slaMetricDefinitions.tenantId, slaMetricDefinitions.id],
    }).onDelete("restrict"),
    foreignKey({
      name: "sla_column_versions_creator_fk",
      columns: [table.tenantId, table.createdByMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    }).onDelete("restrict"),
    index("sla_column_versions_metric_idx").on(
      table.tenantId,
      table.metricDefinitionId,
      table.position,
      table.columnId,
    ),
    check("sla_column_versions_version_check", versionCheck(table.version)),
    check(
      "sla_column_versions_shape_check",
      sql`btrim(${table.label}) <> '' and octet_length(${table.label}) <= 256
        and ${table.label} !~ '[[:cntrl:]]'
        and ${table.position} between 0 and 255
        and cardinality(${table.visibleRoleKeys}) <= 128
        and array_position(${table.visibleRoleKeys}, null) is null
        and array_to_string(${table.visibleRoleKeys}, ',') ~ '^([a-z][a-z0-9_.-]{0,63}(,[a-z][a-z0-9_.-]{0,63})*)?$'
        and jsonb_typeof(${table.styleRules}) = 'array'
        and jsonb_array_length(${table.styleRules}) <= 64
        and pg_column_size(${table.styleRules}) <= 65536
        and octet_length(${table.revisionDigest}) = 32`,
    ),
    tenantAllPolicy("sla_column_versions_api_tenant", table.tenantId),
    workerTenantPolicy("sla_column_versions_worker_tenant", table.tenantId),
    ticketProjectionPolicy(
      "sla_column_versions_ticket_projection",
      table.tenantId,
    ),
  ],
).enableRLS();

export const slaConfigurationCommands = pgTable(
  "sla_configuration_commands",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    actorMembershipId: uuid("actor_membership_id").notNull(),
    operation: text("operation").notNull(),
    keyDigest: bytea("key_digest").notNull(),
    requestDigest: bytea("request_digest").notNull(),
    resourceId: uuid("resource_id").notNull(),
    resourceVersion: integer("resource_version").notNull(),
    activeVersion: integer("active_version"),
    archived: boolean("archived").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    expiresAt: timestamp("expires_at", { withTimezone: true, mode: "date" })
      .notNull()
      .default(sql`now() + interval '24 hours'`),
  },
  (table) => [
    unique("sla_configuration_commands_tenant_id_id_key").on(
      table.tenantId,
      table.id,
    ),
    unique("sla_configuration_commands_replay_key").on(
      table.tenantId,
      table.actorMembershipId,
      table.operation,
      table.keyDigest,
    ),
    foreignKey({
      name: "sla_configuration_commands_actor_fk",
      columns: [table.tenantId, table.actorMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    }).onDelete("restrict"),
    index("sla_configuration_commands_expiry_idx").on(table.expiresAt),
    check("sla_configuration_commands_id_check", uuidV7(table.id)),
    check(
      "sla_configuration_commands_operation_check",
      sql`${table.operation} in (
        'sla.calendar.publish', 'sla.calendar.archive',
        'sla.policy.publish', 'sla.policy.archive',
        'sla.column.publish', 'sla.column.archive'
      )`,
    ),
    check(
      "sla_configuration_commands_digest_check",
      sql`octet_length(${table.keyDigest}) = 32 and octet_length(${table.requestDigest}) = 32`,
    ),
    check(
      "sla_configuration_commands_result_check",
      sql`${versionCheck(table.resourceVersion)}
        and (${table.archived} = (${table.activeVersion} is null))
        and (${table.activeVersion} is null or ${versionCheck(table.activeVersion)})`,
    ),
    check(
      "sla_configuration_commands_retention_check",
      sql`${table.expiresAt} > ${table.createdAt}
        and ${table.expiresAt} <= ${table.createdAt} + interval '7 days'`,
    ),
    tenantAllPolicy("sla_configuration_commands_api_tenant", table.tenantId),
  ],
).enableRLS();

export const slaInstances = pgTable(
  "sla_instances",
  {
    id: uuid("id").primaryKey(),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    objectType: slaObjectType("object_type").notNull(),
    objectId: uuid("object_id").notNull(),
    policyId: uuid("policy_id").notNull(),
    policyVersion: integer("policy_version").notNull(),
    aggregateVersion: integer("aggregate_version").notNull(),
    assignmentEventId: uuid("assignment_event_id").notNull(),
    createdAt: timestamp("created_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    updatedAt: timestamp("updated_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    completedAt: timestamp("completed_at", {
      withTimezone: true,
      mode: "date",
    }),
  },
  (table) => [
    unique("sla_instances_tenant_id_id_key").on(table.tenantId, table.id),
    unique("sla_instances_tenant_id_policy_key").on(
      table.tenantId,
      table.id,
      table.policyId,
      table.policyVersion,
    ),
    unique("sla_instances_tenant_object_key").on(
      table.tenantId,
      table.objectType,
      table.objectId,
    ),
    unique("sla_instances_tenant_assignment_event_key").on(
      table.tenantId,
      table.assignmentEventId,
    ),
    foreignKey({
      name: "sla_instances_policy_fk",
      columns: [table.tenantId, table.policyId, table.policyVersion],
      foreignColumns: [
        slaPolicyVersions.tenantId,
        slaPolicyVersions.policyId,
        slaPolicyVersions.version,
      ],
    }).onDelete("restrict"),
    index("sla_instances_object_projection_idx").on(
      table.tenantId,
      table.objectType,
      table.objectId,
      table.aggregateVersion,
    ),
    check("sla_instances_id_check", uuidV7(table.id)),
    check("sla_instances_assignment_id_check", uuidV7(table.assignmentEventId)),
    check(
      "sla_instances_version_check",
      sql`${versionCheck(table.policyVersion)} and ${versionCheck(table.aggregateVersion)}`,
    ),
    check(
      "sla_instances_lifecycle_check",
      sql`${table.updatedAt} >= ${table.createdAt}
        and (${table.completedAt} is null or ${table.completedAt} between ${table.createdAt} and ${table.updatedAt})`,
    ),
    tenantAllPolicy("sla_instances_api_tenant", table.tenantId),
    workerTenantPolicy("sla_instances_worker_tenant", table.tenantId),
  ],
).enableRLS();

export const slaMetricInstances = pgTable(
  "sla_metric_instances",
  {
    id: uuid("id").primaryKey(),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    slaInstanceId: uuid("sla_instance_id").notNull(),
    definitionId: uuid("definition_id").notNull(),
    policyId: uuid("policy_id").notNull(),
    policyVersion: integer("policy_version").notNull(),
    version: integer("version").notNull(),
    lifecycle: slaMetricLifecycle("lifecycle").notNull(),
    state: slaMetricState("state").notNull(),
    createdAt: timestamp("created_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    updatedAt: timestamp("updated_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    extensionMicros: bigint("extension_micros", { mode: "number" }).notNull(),
    consumedMicros: bigint("consumed_micros", { mode: "number" }).notNull(),
    startedAt: timestamp("started_at", { withTimezone: true, mode: "date" }),
    lastResumedAt: timestamp("last_resumed_at", {
      withTimezone: true,
      mode: "date",
    }),
    pausedAt: timestamp("paused_at", { withTimezone: true, mode: "date" }),
    completedAt: timestamp("completed_at", {
      withTimezone: true,
      mode: "date",
    }),
    dueAt: timestamp("due_at", { withTimezone: true, mode: "date" }),
    breachThresholdAt: timestamp("breach_threshold_at", {
      withTimezone: true,
      mode: "date",
    }),
    breachedAt: timestamp("breached_at", { withTimezone: true, mode: "date" }),
    lastEventId: uuid("last_event_id"),
    lastEventKey: text("last_event_key"),
    lastEventAt: timestamp("last_event_at", {
      withTimezone: true,
      mode: "date",
    }),
    lastOverrideId: uuid("last_override_id"),
    lastOverrideDigest: bytea("last_override_digest"),
  },
  (table) => [
    unique("sla_metric_instances_tenant_id_id_key").on(
      table.tenantId,
      table.id,
    ),
    unique("sla_metric_instances_sla_definition_key").on(
      table.tenantId,
      table.slaInstanceId,
      table.definitionId,
    ),
    foreignKey({
      name: "sla_metric_instances_sla_fk",
      columns: [
        table.tenantId,
        table.slaInstanceId,
        table.policyId,
        table.policyVersion,
      ],
      foreignColumns: [
        slaInstances.tenantId,
        slaInstances.id,
        slaInstances.policyId,
        slaInstances.policyVersion,
      ],
    }).onDelete("restrict"),
    foreignKey({
      name: "sla_metric_instances_definition_fk",
      columns: [table.tenantId, table.definitionId],
      foreignColumns: [slaMetricDefinitions.tenantId, slaMetricDefinitions.id],
    }).onDelete("restrict"),
    foreignKey({
      name: "sla_metric_instances_policy_fk",
      columns: [table.tenantId, table.policyId, table.policyVersion],
      foreignColumns: [
        slaPolicyVersions.tenantId,
        slaPolicyVersions.policyId,
        slaPolicyVersions.version,
      ],
    }).onDelete("restrict"),
    index("sla_metric_instances_schedule_idx").on(
      table.tenantId,
      table.lifecycle,
      table.dueAt,
      table.id,
    ),
    index("sla_metric_instances_state_idx").on(
      table.tenantId,
      table.state,
      table.dueAt,
      table.id,
    ),
    check("sla_metric_instances_id_check", uuidV7(table.id)),
    check(
      "sla_metric_instances_version_check",
      sql`${versionCheck(table.policyVersion)} and ${versionCheck(table.version)}`,
    ),
    check(
      "sla_metric_instances_duration_check",
      sql`${table.extensionMicros} between 0 and 3153600000000000
        and ${table.consumedMicros} between 0 and 3153600000000000`,
    ),
    check(
      "sla_metric_instances_event_check",
      sql`(${table.lastEventId} is null) = (${table.lastEventKey} is null)
        and (${table.lastEventId} is null) = (${table.lastEventAt} is null)
        and (${table.lastEventId} is null or (${uuidV7(table.lastEventId)} and ${keyCheck(table.lastEventKey)}))`,
    ),
    check(
      "sla_metric_instances_override_check",
      sql`(${table.lastOverrideId} is null) = (${table.lastOverrideDigest} is null)
        and (${table.lastOverrideId} is null or (${uuidV7(table.lastOverrideId)} and octet_length(${table.lastOverrideDigest}) = 32))`,
    ),
    check(
      "sla_metric_instances_lifecycle_check",
      sql`${table.updatedAt} >= ${table.createdAt}
        and (${table.lifecycle} = 'pending'
          and ${table.startedAt} is null and ${table.lastResumedAt} is null
          and ${table.pausedAt} is null and ${table.completedAt} is null
          and ${table.dueAt} is null and ${table.breachThresholdAt} is null
        or ${table.lifecycle} = 'running'
          and ${table.startedAt} is not null and ${table.lastResumedAt} is not null
          and ${table.pausedAt} is null and ${table.completedAt} is null
          and ${table.dueAt} is not null and ${table.breachThresholdAt} is not null
        or ${table.lifecycle} = 'paused'
          and ${table.startedAt} is not null and ${table.lastResumedAt} is null
          and ${table.pausedAt} is not null and ${table.completedAt} is null
          and ${table.dueAt} is not null and ${table.breachThresholdAt} is not null
        or ${table.lifecycle} = 'completed'
          and ${table.startedAt} is not null and ${table.lastResumedAt} is null
          and ${table.pausedAt} is null and ${table.completedAt} is not null)
        and (${table.breachedAt} is null or ${table.startedAt} is not null)`,
    ),
    tenantAllPolicy("sla_metric_instances_api_tenant", table.tenantId),
    workerTenantPolicy("sla_metric_instances_worker_tenant", table.tenantId),
  ],
).enableRLS();

export const slaTriggerCursors = pgTable(
  "sla_trigger_cursors",
  {
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    metricInstanceId: uuid("metric_instance_id").notNull(),
    triggerDefinitionId: uuid("trigger_definition_id").notNull(),
    initialized: boolean("initialized").notNull(),
    lastObservedAt: timestamp("last_observed_at", {
      withTimezone: true,
      mode: "date",
    }),
    lastState: slaMetricState("last_state"),
    lastPercentage: doublePrecision("last_percentage").notNull().default(0),
    lastRemainingMicros: bigint("last_remaining_micros", { mode: "number" })
      .notNull()
      .default(0),
    lastRepeatWindow: bigint("last_repeat_window", { mode: "number" })
      .notNull()
      .default(-1),
    lastFiredAt: timestamp("last_fired_at", {
      withTimezone: true,
      mode: "date",
    }),
    fireCount: bigint("fire_count", { mode: "bigint" })
      .notNull()
      .default(sql`0`),
    updatedAt: timestamp("updated_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    primaryKey({
      name: "sla_trigger_cursors_pkey",
      columns: [
        table.tenantId,
        table.metricInstanceId,
        table.triggerDefinitionId,
      ],
    }),
    foreignKey({
      name: "sla_trigger_cursors_metric_fk",
      columns: [table.tenantId, table.metricInstanceId],
      foreignColumns: [slaMetricInstances.tenantId, slaMetricInstances.id],
    }).onDelete("restrict"),
    foreignKey({
      name: "sla_trigger_cursors_definition_fk",
      columns: [table.tenantId, table.triggerDefinitionId],
      foreignColumns: [
        slaTriggerDefinitions.tenantId,
        slaTriggerDefinitions.id,
      ],
    }).onDelete("restrict"),
    check(
      "sla_trigger_cursors_bounds_check",
      sql`${table.lastPercentage} between 0 and 100
        and ${table.lastRemainingMicros} between 0 and 3153600000000000
        and ${table.lastRepeatWindow} between -1 and 3153600000000000
        and ${table.fireCount} between 0 and 9223372036854775806`,
    ),
    check(
      "sla_trigger_cursors_state_check",
      sql`(not ${table.initialized}
          and ${table.lastObservedAt} is null and ${table.lastState} is null
          and ${table.lastPercentage} = 0 and ${table.lastRemainingMicros} = 0
          and ${table.lastRepeatWindow} = -1 and ${table.lastFiredAt} is null and ${table.fireCount} = 0)
        or (${table.initialized} and ${table.lastObservedAt} is not null and ${table.lastState} is not null
          and (${table.lastFiredAt} is null) = (${table.fireCount} = 0)
          and (${table.lastFiredAt} is null or ${table.lastFiredAt} <= ${table.lastObservedAt})
          and (${table.lastRepeatWindow} < 0 or ${table.fireCount} > 0))`,
    ),
    tenantAllPolicy("sla_trigger_cursors_api_tenant", table.tenantId),
    workerTenantPolicy("sla_trigger_cursors_worker_tenant", table.tenantId),
  ],
).enableRLS();

export const slaTriggerOccurrences = pgTable(
  "sla_trigger_occurrences",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    slaInstanceId: uuid("sla_instance_id").notNull(),
    metricInstanceId: uuid("metric_instance_id").notNull(),
    triggerDefinitionId: uuid("trigger_definition_id").notNull(),
    scheduledAt: timestamp("scheduled_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    deduplicationDigest: bytea("deduplication_digest").notNull(),
    actionKind: slaTriggerActionKind("action_kind").notNull(),
    actionConfigurationId: uuid("action_configuration_id"),
    actionValue: text("action_value"),
    allowRecursiveSla: boolean("allow_recursive_sla").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    unique("sla_trigger_occurrences_tenant_id_id_key").on(
      table.tenantId,
      table.id,
    ),
    unique("sla_trigger_occurrences_dedup_key").on(
      table.tenantId,
      table.deduplicationDigest,
    ),
    foreignKey({
      name: "sla_trigger_occurrences_sla_fk",
      columns: [table.tenantId, table.slaInstanceId],
      foreignColumns: [slaInstances.tenantId, slaInstances.id],
    }).onDelete("restrict"),
    foreignKey({
      name: "sla_trigger_occurrences_metric_fk",
      columns: [table.tenantId, table.metricInstanceId],
      foreignColumns: [slaMetricInstances.tenantId, slaMetricInstances.id],
    }).onDelete("restrict"),
    foreignKey({
      name: "sla_trigger_occurrences_definition_fk",
      columns: [table.tenantId, table.triggerDefinitionId],
      foreignColumns: [
        slaTriggerDefinitions.tenantId,
        slaTriggerDefinitions.id,
      ],
    }).onDelete("restrict"),
    index("sla_trigger_occurrences_history_idx").on(
      table.tenantId,
      table.slaInstanceId,
      table.scheduledAt,
      table.id,
    ),
    check("sla_trigger_occurrences_id_check", uuidV7(table.id)),
    check(
      "sla_trigger_occurrences_digest_check",
      sql`octet_length(${table.deduplicationDigest}) = 32`,
    ),
    tenantAllPolicy("sla_trigger_occurrences_api_tenant", table.tenantId),
    workerTenantPolicy("sla_trigger_occurrences_worker_tenant", table.tenantId),
  ],
).enableRLS();

/**
 * Mutable lease/fence state is deliberately separated from immutable trigger
 * occurrences. Every occurrence receives exactly one execution row through a
 * protected insert trigger; worker entry points are the only writers.
 */
export const slaTriggerActionExecutions = pgTable(
  "sla_trigger_action_executions",
  {
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    occurrenceId: uuid("occurrence_id").notNull(),
    status: slaJobStatus("status").notNull().default("queued"),
    availableAt: timestamp("available_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    attempt: integer("attempt").notNull().default(0),
    maximumAttempts: integer("maximum_attempts").notNull().default(8),
    workerId: uuid("worker_id"),
    leaseExpiresAt: timestamp("lease_expires_at", {
      withTimezone: true,
      mode: "date",
    }),
    fence: bigint("fence", { mode: "bigint" })
      .notNull()
      .default(sql`0`),
    lastFailureCode: text("last_failure_code"),
    completedAt: timestamp("completed_at", {
      withTimezone: true,
      mode: "date",
    }),
    deadLetteredAt: timestamp("dead_lettered_at", {
      withTimezone: true,
      mode: "date",
    }),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    primaryKey({
      name: "sla_trigger_action_executions_pkey",
      columns: [table.tenantId, table.occurrenceId],
    }),
    foreignKey({
      name: "sla_trigger_action_executions_occurrence_fk",
      columns: [table.tenantId, table.occurrenceId],
      foreignColumns: [
        slaTriggerOccurrences.tenantId,
        slaTriggerOccurrences.id,
      ],
    }).onDelete("restrict"),
    index("sla_trigger_action_executions_queue_idx").on(
      table.tenantId,
      table.status,
      table.availableAt,
      table.leaseExpiresAt,
      table.occurrenceId,
    ),
    index("sla_trigger_action_executions_metrics_idx").on(
      table.status,
      table.availableAt,
      table.createdAt,
    ),
    check(
      "sla_trigger_action_executions_bounds_check",
      sql`${table.attempt} between 0 and 65535
        and ${table.maximumAttempts} between 1 and 65535
        and ${table.attempt} <= ${table.maximumAttempts}
        and ${table.fence} between 0 and 9223372036854775806
        and (${table.workerId} is null
          or (uuid_extract_version(${table.workerId}) = 7) is true)
        and (${table.lastFailureCode} is null
          or ${table.lastFailureCode} ~ '^[a-z][a-z0-9_.-]{0,127}$')`,
    ),
    check(
      "sla_trigger_action_executions_state_check",
      sql`(${table.status} = 'leased'
          and ${table.workerId} is not null
          and ${table.leaseExpiresAt} is not null
          and ${table.attempt} > 0
          and ${table.fence} > 0
          and ${table.completedAt} is null
          and ${table.deadLetteredAt} is null)
        or (${table.status} in ('queued', 'retry_scheduled')
          and ${table.workerId} is null
          and ${table.leaseExpiresAt} is null
          and ${table.completedAt} is null
          and ${table.deadLetteredAt} is null)
        or (${table.status} = 'completed'
          and ${table.workerId} is null
          and ${table.leaseExpiresAt} is null
          and ${table.completedAt} is not null
          and ${table.deadLetteredAt} is null)
        or (${table.status} = 'dead_lettered'
          and ${table.workerId} is null
          and ${table.leaseExpiresAt} is null
          and ${table.completedAt} is null
          and ${table.deadLetteredAt} is not null)`,
    ),
    check(
      "sla_trigger_action_executions_timestamps_check",
      sql`${table.availableAt} >= ${table.createdAt}
        and ${table.updatedAt} >= ${table.createdAt}
        and (${table.leaseExpiresAt} is null
          or ${table.leaseExpiresAt} > ${table.updatedAt})
        and (${table.completedAt} is null
          or ${table.completedAt} between ${table.createdAt} and ${table.updatedAt})
        and (${table.deadLetteredAt} is null
          or ${table.deadLetteredAt} between ${table.createdAt} and ${table.updatedAt})`,
    ),
    workerTenantPolicy(
      "sla_trigger_action_executions_worker_tenant",
      table.tenantId,
    ),
  ],
).enableRLS();

/** Immutable exactly-once receipt for a successfully applied SLA action. */
export const slaTriggerActionReceipts = pgTable(
  "sla_trigger_action_receipts",
  {
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    occurrenceId: uuid("occurrence_id").notNull(),
    workerId: uuid("worker_id").notNull(),
    actionKind: slaTriggerActionKind("action_kind").notNull(),
    deduplicationDigest: bytea("deduplication_digest").notNull(),
    fence: bigint("fence", { mode: "bigint" }).notNull(),
    effectKind: text("effect_kind").notNull(),
    effectId: uuid("effect_id"),
    effectVersion: bigint("effect_version", { mode: "bigint" }),
    effectDigest: bytea("effect_digest").notNull(),
    appliedAt: timestamp("applied_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
  },
  (table) => [
    primaryKey({
      name: "sla_trigger_action_receipts_pkey",
      columns: [table.tenantId, table.occurrenceId],
    }),
    foreignKey({
      name: "sla_trigger_action_receipts_occurrence_fk",
      columns: [table.tenantId, table.occurrenceId],
      foreignColumns: [
        slaTriggerOccurrences.tenantId,
        slaTriggerOccurrences.id,
      ],
    }).onDelete("restrict"),
    check(
      "sla_trigger_action_receipts_identity_check",
      sql`(uuid_extract_version(${table.workerId}) = 7) is true
        and ${table.fence} between 1 and 9223372036854775806
        and ${table.effectKind} ~ '^[a-z][a-z0-9_.-]{0,127}$'
        and (${table.effectId} is null
          or (uuid_extract_version(${table.effectId}) = 7) is true)
        and (${table.effectVersion} is null
          or ${table.effectVersion} between 1 and 9223372036854775807)
        and octet_length(${table.deduplicationDigest}) = 32
        and octet_length(${table.effectDigest}) = 32`,
    ),
    workerTenantPolicy(
      "sla_trigger_action_receipts_worker_tenant",
      table.tenantId,
    ),
  ],
).enableRLS();

/**
 * Immutable provenance for alerts emitted by create_system_alert actions.
 * The runtime guard uses this row to make recursive SLA admission an explicit,
 * durable decision rather than an outbox convention.
 */
export const slaSystemAlertOrigins = pgTable(
  "sla_system_alert_origins",
  {
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    alertId: uuid("alert_id").notNull(),
    sourceOccurrenceId: uuid("source_occurrence_id").notNull(),
    allowRecursiveSla: boolean("allow_recursive_sla").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    primaryKey({
      name: "sla_system_alert_origins_pkey",
      columns: [table.tenantId, table.alertId],
    }),
    unique("sla_system_alert_origins_source_key").on(
      table.tenantId,
      table.sourceOccurrenceId,
    ),
    foreignKey({
      name: "sla_system_alert_origins_alert_fk",
      columns: [table.tenantId, table.alertId],
      foreignColumns: [alerts.tenantId, alerts.id],
    }).onDelete("restrict"),
    foreignKey({
      name: "sla_system_alert_origins_occurrence_fk",
      columns: [table.tenantId, table.sourceOccurrenceId],
      foreignColumns: [
        slaTriggerOccurrences.tenantId,
        slaTriggerOccurrences.id,
      ],
    }).onDelete("restrict"),
    workerTenantPolicy(
      "sla_system_alert_origins_worker_tenant",
      table.tenantId,
    ),
  ],
).enableRLS();

/**
 * Transaction-scoped owner capability used only while provisioning the
 * non-login SLA action principal. Runtime roles have no policy or table ACL;
 * a custom GUC would be forgeable by any database client.
 */
export const slaSystemPrincipalWriteCapabilities = pgTable(
  "sla_system_principal_write_capabilities",
  {
    backendPid: integer("backend_pid").notNull(),
    transactionId: bigint("transaction_id", { mode: "bigint" }).notNull(),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    primaryKey({
      name: "sla_system_principal_write_capabilities_pkey",
      columns: [table.backendPid, table.transactionId, table.tenantId],
    }),
    check(
      "sla_system_principal_write_capabilities_identity_check",
      sql`${table.backendPid} > 0 and ${table.transactionId} > 0`,
    ),
  ],
).enableRLS();

export const slaMaterializedColumnValues = pgTable(
  "sla_materialized_column_values",
  {
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    objectType: slaObjectType("object_type").notNull(),
    objectId: uuid("object_id").notNull(),
    slaInstanceId: uuid("sla_instance_id").notNull(),
    metricInstanceId: uuid("metric_instance_id").notNull(),
    columnId: uuid("column_id").notNull(),
    columnVersion: integer("column_version").notNull(),
    stateValue: slaMetricState("state_value"),
    instantValue: timestamp("instant_value", {
      withTimezone: true,
      mode: "date",
    }),
    durationMicrosValue: bigint("duration_micros_value", { mode: "number" }),
    percentageValue: doublePrecision("percentage_value"),
    styleKey: text("style_key"),
    nextRefreshAt: timestamp("next_refresh_at", {
      withTimezone: true,
      mode: "date",
    }),
    materializedAt: timestamp("materialized_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
  },
  (table) => [
    primaryKey({
      name: "sla_materialized_column_values_pkey",
      columns: [
        table.tenantId,
        table.objectType,
        table.objectId,
        table.columnId,
      ],
    }),
    foreignKey({
      name: "sla_materialized_column_values_sla_fk",
      columns: [table.tenantId, table.slaInstanceId],
      foreignColumns: [slaInstances.tenantId, slaInstances.id],
    }).onDelete("restrict"),
    foreignKey({
      name: "sla_materialized_column_values_metric_fk",
      columns: [table.tenantId, table.metricInstanceId],
      foreignColumns: [slaMetricInstances.tenantId, slaMetricInstances.id],
    }).onDelete("restrict"),
    foreignKey({
      name: "sla_materialized_column_values_column_fk",
      columns: [table.tenantId, table.columnId, table.columnVersion],
      foreignColumns: [
        slaColumnVersions.tenantId,
        slaColumnVersions.columnId,
        slaColumnVersions.version,
      ],
    }).onDelete("restrict"),
    index("sla_materialized_column_instant_sort_idx").on(
      table.tenantId,
      table.objectType,
      table.columnId,
      table.instantValue,
      table.objectId,
    ),
    index("sla_materialized_column_duration_sort_idx").on(
      table.tenantId,
      table.objectType,
      table.columnId,
      table.durationMicrosValue,
      table.objectId,
    ),
    index("sla_materialized_column_percent_sort_idx").on(
      table.tenantId,
      table.objectType,
      table.columnId,
      table.percentageValue,
      table.objectId,
    ),
    index("sla_materialized_column_state_filter_idx").on(
      table.tenantId,
      table.objectType,
      table.columnId,
      table.stateValue,
      table.objectId,
    ),
    // The API reads through a FORCE-RLS security-barrier projection. The enum
    // object-type predicate cannot be pushed through that barrier, so these
    // operation-shaped peers lead with the leakproof tenant/column keys and
    // keep each dynamic order indexable under the runtime role.
    index("sla_materialized_projection_instant_sort_idx")
      .on(table.tenantId, table.columnId, table.instantValue, table.objectId)
      .where(sql`${table.instantValue} is not null`),
    index("sla_materialized_projection_duration_sort_idx")
      .on(
        table.tenantId,
        table.columnId,
        table.durationMicrosValue,
        table.objectId,
      )
      .where(sql`${table.durationMicrosValue} is not null`),
    index("sla_materialized_projection_percent_sort_idx")
      .on(table.tenantId, table.columnId, table.percentageValue, table.objectId)
      .where(sql`${table.percentageValue} is not null`),
    index("sla_materialized_projection_state_sort_idx")
      .on(table.tenantId, table.columnId, table.stateValue, table.objectId)
      .where(sql`${table.stateValue} is not null`),
    check(
      "sla_materialized_column_version_check",
      versionCheck(table.columnVersion),
    ),
    check(
      "sla_materialized_column_typed_value_check",
      sql`num_nonnulls(${table.stateValue}, ${table.instantValue}, ${table.durationMicrosValue}, ${table.percentageValue}) = 1
        and (${table.durationMicrosValue} is null or ${table.durationMicrosValue} between 0 and 3153600000000000)
        and (${table.percentageValue} is null or ${table.percentageValue} between 0 and 100)
        and (${table.styleKey} is null or ${keyCheck(table.styleKey)})
        and (${table.nextRefreshAt} is null or ${table.nextRefreshAt} > ${table.materializedAt})`,
    ),
    tenantAllPolicy("sla_materialized_columns_api_tenant", table.tenantId),
    workerTenantPolicy(
      "sla_materialized_columns_worker_tenant",
      table.tenantId,
    ),
    ticketProjectionPolicy(
      "sla_materialized_columns_ticket_projection",
      table.tenantId,
    ),
  ],
).enableRLS();

export const slaObjectEventLedger = pgTable(
  "sla_object_event_ledger",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    eventId: uuid("event_id").notNull(),
    objectType: slaObjectType("object_type").notNull(),
    objectId: uuid("object_id").notNull(),
    origin: text("origin").notNull(),
    originId: uuid("origin_id").notNull(),
    keyDigest: bytea("key_digest").notNull(),
    requestDigest: bytea("request_digest").notNull(),
    outcome: slaEventOutcome("outcome").notNull(),
    slaInstanceId: uuid("sla_instance_id"),
    aggregateVersion: integer("aggregate_version").notNull(),
    policyId: uuid("policy_id"),
    policyVersion: integer("policy_version").notNull(),
    occurredAt: timestamp("occurred_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    committedAt: timestamp("committed_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    unique("sla_object_event_ledger_tenant_id_id_key").on(
      table.tenantId,
      table.id,
    ),
    unique("sla_object_event_ledger_event_key").on(
      table.tenantId,
      table.eventId,
    ),
    unique("sla_object_event_ledger_replay_key").on(
      table.tenantId,
      table.keyDigest,
    ),
    foreignKey({
      name: "sla_object_event_ledger_sla_fk",
      columns: [table.tenantId, table.slaInstanceId],
      foreignColumns: [slaInstances.tenantId, slaInstances.id],
    }).onDelete("restrict"),
    index("sla_object_event_ledger_object_idx").on(
      table.tenantId,
      table.objectType,
      table.objectId,
      table.occurredAt,
      table.eventId,
    ),
    check("sla_object_event_ledger_id_check", uuidV7(table.id)),
    check("sla_object_event_ledger_event_id_check", uuidV7(table.eventId)),
    check(
      "sla_object_event_ledger_origin_check",
      sql`${table.origin} ~ '^[a-z][a-z0-9_.-]{0,127}$' and ${uuidV7(table.originId)}`,
    ),
    check(
      "sla_object_event_ledger_digest_check",
      sql`octet_length(${table.keyDigest}) = 32 and octet_length(${table.requestDigest}) = 32`,
    ),
    check(
      "sla_object_event_ledger_outcome_check",
      sql`(${table.outcome} = 'no_policy' and ${table.slaInstanceId} is null
          and ${table.aggregateVersion} = 0 and ${table.policyId} is null and ${table.policyVersion} = 0)
        or (${table.outcome} = 'assigned' and ${table.slaInstanceId} is not null
          and ${table.aggregateVersion} = 1 and ${table.policyId} is not null and ${versionCheck(table.policyVersion)})
        or (${table.outcome} = 'updated' and ${table.slaInstanceId} is not null
          and ${table.aggregateVersion} between 2 and 2147483646
          and ${table.policyId} is not null and ${versionCheck(table.policyVersion)})`,
    ),
    tenantAllPolicy("sla_object_event_ledger_api_tenant", table.tenantId),
    pgPolicy("sla_object_event_ledger_sla_event_owner_read_v1", {
      as: "permissive",
      for: "select",
      to: slaWorkerOwnerRole,
      using: sql`${table.tenantId} = app.context_tenant_id()
        and ${table.origin} = 'ticket_outbox'
        and ${table.eventId} = ${table.originId}`,
    }),
    pgPolicy("sla_object_event_ledger_sla_event_owner_insert_v1", {
      as: "permissive",
      for: "insert",
      to: slaWorkerOwnerRole,
      withCheck: sql`${table.tenantId} = app.context_tenant_id()
        and ${table.origin} = 'ticket_outbox'
        and ${table.eventId} = ${table.originId}`,
    }),
  ],
).enableRLS();

/**
 * Immutable, per-object production ingress stream sourced from transactional
 * ticket outbox rows. Only lease/status/receipt fields are mutable after
 * enqueue; the source envelope, mapped metric event, sequence, and initial
 * assignment snapshot are protected by a database immutability trigger.
 */
export const slaObjectEventIngress = pgTable(
  "sla_object_event_ingress",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    objectType: slaObjectType("object_type").notNull(),
    objectId: uuid("object_id").notNull(),
    objectSequence: integer("object_sequence").notNull(),
    sourceEventId: uuid("source_event_id").notNull(),
    sourceEventType: text("source_event_type").notNull(),
    sourceSchemaVersion: integer("source_schema_version").notNull(),
    sourceAggregateVersion: integer("source_aggregate_version"),
    sourceDigest: bytea("source_digest").notNull(),
    eventKey: text("event_key").notNull(),
    occurredAt: timestamp("occurred_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    assignmentSnapshot: jsonb("assignment_snapshot").$type<JSONRecord>(),
    assignmentSnapshotDigest: bytea("assignment_snapshot_digest"),
    status: slaJobStatus("status").notNull().default("queued"),
    availableAt: timestamp("available_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    attempt: integer("attempt").notNull().default(0),
    maximumAttempts: integer("maximum_attempts").notNull().default(12),
    workerId: uuid("worker_id"),
    leaseExpiresAt: timestamp("lease_expires_at", {
      withTimezone: true,
      mode: "date",
    }),
    fence: bigint("fence", { mode: "number" }).notNull().default(0),
    lastFailureCode: text("last_failure_code"),
    completedAt: timestamp("completed_at", {
      withTimezone: true,
      mode: "date",
    }),
    deadLetteredAt: timestamp("dead_lettered_at", {
      withTimezone: true,
      mode: "date",
    }),
    planDigest: bytea("plan_digest"),
    receiptDigest: bytea("receipt_digest"),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    unique("sla_object_event_ingress_tenant_id_id_key").on(
      table.tenantId,
      table.id,
    ),
    unique("sla_object_event_ingress_source_key").on(
      table.tenantId,
      table.sourceEventId,
    ),
    unique("sla_object_event_ingress_sequence_key").on(
      table.tenantId,
      table.objectType,
      table.objectId,
      table.objectSequence,
    ),
    foreignKey({
      name: "sla_object_event_ingress_source_fk",
      columns: [table.tenantId, table.sourceEventId],
      foreignColumns: [outboxEvents.tenantId, outboxEvents.id],
    }).onDelete("restrict"),
    index("sla_object_event_ingress_claim_idx")
      .on(table.availableAt, table.tenantId, table.objectType, table.objectId)
      .where(sql`${table.status} in ('queued', 'retry_scheduled')`),
    index("sla_object_event_ingress_reclaim_idx")
      .on(
        table.leaseExpiresAt,
        table.tenantId,
        table.objectType,
        table.objectId,
      )
      .where(sql`${table.status} = 'leased'`),
    index("sla_object_event_ingress_object_idx").on(
      table.tenantId,
      table.objectType,
      table.objectId,
      table.objectSequence,
    ),
    check("sla_object_event_ingress_id_check", uuidV7(table.id)),
    check(
      "sla_object_event_ingress_source_id_check",
      uuidV7(table.sourceEventId),
    ),
    check("sla_object_event_ingress_object_id_check", uuidV7(table.objectId)),
    check(
      "sla_object_event_ingress_source_check",
      sql`${table.objectType} in ('alert', 'case')
        and ${table.objectSequence} between 1 and 2147483646
        and ${table.sourceEventType} ~ '^(sla\.)?(alert|case)\.[a-z][a-z0-9_.-]{1,63}$'
        and ${table.sourceSchemaVersion} between 1 and 2147483646
        and (${table.sourceAggregateVersion} is null
          or ${table.sourceAggregateVersion} between 1 and 2147483646)
        and octet_length(${table.sourceDigest}) = 32
        and ${table.sourceDigest} <> decode(repeat('00', 32), 'hex')
        and ${keyCheck(table.eventKey)}`,
    ),
    check(
      "sla_object_event_ingress_snapshot_check",
      sql`(${table.objectSequence} = 1
          and ${table.eventKey} = 'ticket.created'
          and jsonb_typeof(${table.assignmentSnapshot}) = 'object'
          and pg_column_size(${table.assignmentSnapshot}) <= 16777216
          and octet_length(${table.assignmentSnapshotDigest}) = 32
          and ${table.assignmentSnapshotDigest} <> decode(repeat('00', 32), 'hex'))
        or (${table.assignmentSnapshot} is null
          and ${table.assignmentSnapshotDigest} is null
          and (${table.objectSequence} > 1
            or ${table.eventKey} <> 'ticket.created'))`,
    ),
    check(
      "sla_object_event_ingress_bounds_check",
      sql`${table.attempt} between 0 and 65535
        and ${table.maximumAttempts} between 1 and 65535
        and ${table.attempt} <= ${table.maximumAttempts}
        and ${table.fence} between 0 and 9223372036854775806
        and ${table.updatedAt} >= ${table.createdAt}
        and (${table.lastFailureCode} is null
          or ${table.lastFailureCode} ~ '^[a-z][a-z0-9_.-]{0,127}$')
        and (${table.planDigest} is null or octet_length(${table.planDigest}) = 32)
        and (${table.receiptDigest} is null or octet_length(${table.receiptDigest}) = 32)`,
    ),
    check(
      "sla_object_event_ingress_state_check",
      sql`(${table.status} in ('queued', 'retry_scheduled')
          and ${table.workerId} is null and ${table.leaseExpiresAt} is null
          and ${table.completedAt} is null and ${table.deadLetteredAt} is null
          and ${table.planDigest} is null and ${table.receiptDigest} is null)
        or (${table.status} = 'leased'
          and ${table.workerId} is not null and ${table.leaseExpiresAt} is not null
          and ${table.leaseExpiresAt} > ${table.updatedAt}
          and ${table.completedAt} is null and ${table.deadLetteredAt} is null
          and ${table.planDigest} is null and ${table.receiptDigest} is null)
        or (${table.status} = 'completed'
          and ${table.workerId} is null and ${table.leaseExpiresAt} is null
          and ${table.completedAt} is not null and ${table.deadLetteredAt} is null
          and ${table.planDigest} is not null and ${table.receiptDigest} is not null)
        or (${table.status} = 'dead_lettered'
          and ${table.workerId} is null and ${table.leaseExpiresAt} is null
          and ${table.completedAt} is null and ${table.deadLetteredAt} is not null
          and ${table.lastFailureCode} is not null
          and ${table.planDigest} is null and ${table.receiptDigest} is null)`,
    ),
    pgPolicy("sla_object_event_ingress_owner_access", {
      as: "permissive",
      for: "all",
      to: slaWorkerOwnerRole,
      using: sql`true`,
      withCheck: sql`true`,
    }),
  ],
).enableRLS();

export const slaEvaluationJobs = pgTable(
  "sla_evaluation_jobs",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    slaInstanceId: uuid("sla_instance_id").notNull(),
    expectedAggregateVersion: integer("expected_aggregate_version").notNull(),
    status: slaJobStatus("status").notNull().default("queued"),
    availableAt: timestamp("available_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    attempt: integer("attempt").notNull().default(0),
    maximumAttempts: integer("maximum_attempts").notNull().default(12),
    workerId: uuid("worker_id"),
    leaseExpiresAt: timestamp("lease_expires_at", {
      withTimezone: true,
      mode: "date",
    }),
    fence: bigint("fence", { mode: "bigint" })
      .notNull()
      .default(sql`0`),
    lastFailureCode: text("last_failure_code"),
    completedAt: timestamp("completed_at", {
      withTimezone: true,
      mode: "date",
    }),
    deadLetteredAt: timestamp("dead_lettered_at", {
      withTimezone: true,
      mode: "date",
    }),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    unique("sla_evaluation_jobs_tenant_id_id_key").on(table.tenantId, table.id),
    uniqueIndex("sla_evaluation_jobs_live_aggregate_key")
      .on(table.tenantId, table.slaInstanceId)
      .where(sql`${table.status} in ('queued', 'leased', 'retry_scheduled')`),
    foreignKey({
      name: "sla_evaluation_jobs_sla_fk",
      columns: [table.tenantId, table.slaInstanceId],
      foreignColumns: [slaInstances.tenantId, slaInstances.id],
    }).onDelete("restrict"),
    index("sla_evaluation_jobs_claim_idx")
      .on(table.availableAt, table.tenantId, table.id)
      .where(sql`${table.status} in ('queued', 'retry_scheduled')`),
    index("sla_evaluation_jobs_reclaim_idx")
      .on(table.leaseExpiresAt, table.tenantId, table.id)
      .where(sql`${table.status} = 'leased'`),
    check("sla_evaluation_jobs_id_check", uuidV7(table.id)),
    check(
      "sla_evaluation_jobs_bounds_check",
      sql`${versionCheck(table.expectedAggregateVersion)}
        and ${table.attempt} between 0 and 65535
        and ${table.maximumAttempts} between 1 and 65535
        and ${table.attempt} <= ${table.maximumAttempts}
        and ${table.fence} between 0 and 9223372036854775806
        and ${table.updatedAt} >= ${table.createdAt}
        and (${table.lastFailureCode} is null or ${table.lastFailureCode} ~ '^[a-z][a-z0-9_.-]{0,127}$')`,
    ),
    check(
      "sla_evaluation_jobs_state_check",
      sql`(${table.status} in ('queued', 'retry_scheduled')
          and ${table.workerId} is null and ${table.leaseExpiresAt} is null
          and ${table.completedAt} is null and ${table.deadLetteredAt} is null)
        or (${table.status} = 'leased' and ${table.workerId} is not null
          and ${table.leaseExpiresAt} is not null and ${table.leaseExpiresAt} > ${table.updatedAt}
          and ${table.completedAt} is null and ${table.deadLetteredAt} is null)
        or (${table.status} = 'completed' and ${table.workerId} is null and ${table.leaseExpiresAt} is null
          and ${table.completedAt} is not null and ${table.deadLetteredAt} is null)
        or (${table.status} = 'dead_lettered' and ${table.workerId} is null and ${table.leaseExpiresAt} is null
          and ${table.completedAt} is null and ${table.deadLetteredAt} is not null)`,
    ),
    workerTenantPolicy("sla_evaluation_jobs_worker_tenant", table.tenantId),
  ],
).enableRLS();

export const slaOverrides = pgTable(
  "sla_overrides",
  {
    id: uuid("id").primaryKey(),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    actorMembershipId: uuid("actor_membership_id").notNull(),
    objectType: slaObjectType("object_type").notNull(),
    objectId: uuid("object_id").notNull(),
    slaInstanceId: uuid("sla_instance_id").notNull(),
    metricInstanceId: uuid("metric_instance_id"),
    kind: slaOverrideKind("kind").notNull(),
    reason: text("reason").notNull(),
    keyDigest: bytea("key_digest").notNull(),
    requestDigest: bytea("request_digest").notNull(),
    commandDigest: bytea("command_digest").notNull(),
    simulationDigest: bytea("simulation_digest"),
    outcome: slaOverrideOutcome("outcome").notNull(),
    previousVersion: integer("previous_version").notNull(),
    currentVersion: integer("current_version").notNull(),
    aggregateVersion: integer("aggregate_version").notNull(),
    policyId: uuid("policy_id").notNull(),
    policyVersion: integer("policy_version").notNull(),
    // API authority snapshots read both live epochs through the tenant-bound
    // read_sla_authority_epochs_v1 ABI; runtime roles cannot query identity state.
    permissionEpoch: bigint("permission_epoch", { mode: "bigint" }).notNull(),
    subjectEpoch: bigint("subject_epoch", { mode: "bigint" }).notNull(),
    previousSnapshot: jsonb("previous_snapshot").$type<JSONRecord>().notNull(),
    currentSnapshot: jsonb("current_snapshot").$type<JSONRecord>().notNull(),
    occurredAt: timestamp("occurred_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    unique("sla_overrides_tenant_id_id_key").on(table.tenantId, table.id),
    unique("sla_overrides_replay_key").on(
      table.tenantId,
      table.actorMembershipId,
      table.keyDigest,
    ),
    foreignKey({
      name: "sla_overrides_actor_fk",
      columns: [table.tenantId, table.actorMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    }).onDelete("restrict"),
    foreignKey({
      name: "sla_overrides_sla_fk",
      columns: [table.tenantId, table.slaInstanceId],
      foreignColumns: [slaInstances.tenantId, slaInstances.id],
    }).onDelete("restrict"),
    foreignKey({
      name: "sla_overrides_metric_fk",
      columns: [table.tenantId, table.metricInstanceId],
      foreignColumns: [slaMetricInstances.tenantId, slaMetricInstances.id],
    }).onDelete("restrict"),
    foreignKey({
      name: "sla_overrides_policy_fk",
      columns: [table.tenantId, table.policyId, table.policyVersion],
      foreignColumns: [
        slaPolicyVersions.tenantId,
        slaPolicyVersions.policyId,
        slaPolicyVersions.version,
      ],
    }).onDelete("restrict"),
    index("sla_overrides_object_history_idx").on(
      table.tenantId,
      table.objectType,
      table.objectId,
      table.occurredAt,
      table.id,
    ),
    check("sla_overrides_id_check", uuidV7(table.id)),
    check(
      "sla_overrides_reason_check",
      sql`btrim(${table.reason}) <> '' and octet_length(${table.reason}) <= 2048
        and ${table.reason} !~ '[[:cntrl:]]'`,
    ),
    check(
      "sla_overrides_digest_check",
      sql`octet_length(${table.keyDigest}) = 32 and octet_length(${table.requestDigest}) = 32
        and octet_length(${table.commandDigest}) = 32
        and (${table.simulationDigest} is null or octet_length(${table.simulationDigest}) = 32)`,
    ),
    check(
      "sla_overrides_result_check",
      sql`${versionCheck(table.previousVersion)} and ${versionCheck(table.currentVersion)}
        and ${versionCheck(table.aggregateVersion)} and ${versionCheck(table.policyVersion)}
        and ${table.currentVersion} = ${table.previousVersion} + 1
        and ${table.permissionEpoch} between 1 and 9223372036854775806
        and ${table.subjectEpoch} between 1 and 9223372036854775806
        and jsonb_typeof(${table.previousSnapshot}) = 'object'
        and jsonb_typeof(${table.currentSnapshot}) = 'object'
        and pg_column_size(${table.previousSnapshot}) <= 65536
        and pg_column_size(${table.currentSnapshot}) <= 65536
        and ((${table.outcome} = 'metric_updated' and ${table.metricInstanceId} is not null)
          or (${table.outcome} = 'policy_changed' and ${table.metricInstanceId} is null
            and ${table.aggregateVersion} = ${table.currentVersion}))`,
    ),
    tenantAllPolicy("sla_overrides_api_tenant", table.tenantId),
  ],
).enableRLS();
