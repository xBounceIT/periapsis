import { sql } from "drizzle-orm";
import {
  boolean,
  check,
  foreignKey,
  index,
  integer,
  jsonb,
  pgPolicy,
  pgTable,
  text,
  timestamp,
  unique,
  uniqueIndex,
  uuid,
} from "drizzle-orm/pg-core";

import { bytea } from "./binary.js";
import { alertSeverity, alertStatus, tenantPrincipalKind } from "./enums.js";
import {
  activeActorMembershipFor,
  tenantMemberships,
  users,
} from "./identity.js";
import { apiRole } from "./roles.js";
import { tenantServiceAccounts } from "./service-accounts.js";
import { operatorTeamAssignmentEpochs } from "./operator-teams.js";
import { ticketWorkflowVersions } from "./ticket-workflows.js";
import { tenants } from "./tenancy.js";

/** Minimal Phase 1 tenant resource; Phase 3 extends the aggregate without replacing it. */
export const alerts = pgTable(
  "alerts",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    number: text("number").notNull(),
    workflowId: uuid("workflow_id").notNull(),
    workflowVersion: integer("workflow_version").notNull().default(1),
    stateKey: text("state_key").notNull().default("new"),
    customerVisible: boolean("customer_visible").notNull().default(false),
    externalId: text("external_id"),
    deduplicationKey: text("deduplication_key"),
    title: text("title").notNull(),
    description: text("description"),
    status: alertStatus("status").notNull().default("new"),
    severity: alertSeverity("severity").notNull().default("medium"),
    priority: text("priority").notNull().default("medium"),
    category: text("category").notNull().default("general"),
    classification: text("classification"),
    source: text("source").notNull().default("manual"),
    sourceType: text("source_type").notNull().default("manual"),
    tags: text("tags")
      .array()
      .notNull()
      .default(sql`ARRAY[]::text[]`),
    customFields: jsonb("custom_fields")
      .$type<Record<string, unknown>>()
      .notNull()
      .default({}),
    customerCustomFields: jsonb("customer_custom_fields")
      .$type<Record<string, unknown>>()
      .notNull()
      .default({}),
    rawPayload: jsonb("raw_payload")
      .$type<Record<string, unknown>>()
      .notNull()
      .default({}),
    assignedTeamId: uuid("assigned_team_id"),
    assignedTeamEpochId: uuid("assigned_team_epoch_id"),
    assigneeUserId: uuid("assignee_user_id"),
    claimedByUserId: uuid("claimed_by_user_id"),
    createdBy: uuid("created_by").references(() => users.id, {
      onDelete: "restrict",
    }),
    createdByMembershipId: uuid("created_by_membership_id"),
    createdByServiceAccountId: uuid("created_by_service_account_id"),
    detectedAt: timestamp("detected_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    receivedAt: timestamp("received_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    acknowledgedAt: timestamp("acknowledged_at", {
      withTimezone: true,
      mode: "date",
    }),
    closedAt: timestamp("closed_at", { withTimezone: true, mode: "date" }),
    assignedAt: timestamp("assigned_at", { withTimezone: true, mode: "date" }),
    firstResponseAt: timestamp("first_response_at", {
      withTimezone: true,
      mode: "date",
    }),
    resolvedAt: timestamp("resolved_at", { withTimezone: true, mode: "date" }),
    claimedAt: timestamp("claimed_at", { withTimezone: true, mode: "date" }),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    version: integer("version").notNull().default(1),
    deletedAt: timestamp("deleted_at", { withTimezone: true, mode: "date" }),
    deletedByMembershipId: uuid("deleted_by_membership_id"),
    deletionReason: text("deletion_reason"),
  },
  (table) => [
    unique("alerts_tenant_id_key").on(table.tenantId, table.id),
    unique("alerts_tenant_number_key").on(table.tenantId, table.number),
    unique("alerts_tenant_external_id_key").on(
      table.tenantId,
      table.externalId,
    ),
    index("alerts_tenant_created_idx").on(
      table.tenantId,
      table.createdAt,
      table.id,
    ),
    index("alerts_tenant_updated_idx").on(
      table.tenantId,
      table.updatedAt,
      table.id,
    ),
    index("alerts_tenant_live_id_idx")
      .on(table.tenantId, table.id)
      .where(sql`${table.deletedAt} is null`),
    index("alerts_tenant_status_severity_idx").on(
      table.tenantId,
      table.status,
      table.severity,
    ),
    uniqueIndex("alerts_tenant_source_deduplication_key")
      .on(table.tenantId, table.source, table.deduplicationKey)
      .where(sql`${table.deduplicationKey} is not null`),
    index("alerts_tenant_state_priority_idx").on(
      table.tenantId,
      table.stateKey,
      table.priority,
      table.id,
    ),
    index("alerts_tenant_assignment_idx").on(
      table.tenantId,
      table.assignedTeamId,
      table.assigneeUserId,
      table.id,
    ),
    index("alerts_ticket_search_idx").using(
      "gin",
      sql`to_tsvector('simple'::regconfig,
        coalesce(${table.number}, '') || ' ' ||
        coalesce(${table.title}, '') || ' ' ||
        coalesce(${table.description}, ''))`,
    ),
    foreignKey({
      name: "alerts_workflow_version_fk",
      columns: [table.tenantId, table.workflowId, table.workflowVersion],
      foreignColumns: [
        ticketWorkflowVersions.tenantId,
        ticketWorkflowVersions.workflowId,
        ticketWorkflowVersions.version,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "alerts_assignment_epoch_fk",
      columns: [
        table.tenantId,
        table.assignedTeamEpochId,
        table.assignedTeamId,
      ],
      foreignColumns: [
        operatorTeamAssignmentEpochs.tenantId,
        operatorTeamAssignmentEpochs.id,
        operatorTeamAssignmentEpochs.operatorTeamId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "alerts_assignee_membership_fk",
      columns: [table.tenantId, table.assigneeUserId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.userId],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "alerts_claimant_membership_fk",
      columns: [table.tenantId, table.claimedByUserId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.userId],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "alerts_creator_membership_fk",
      columns: [table.tenantId, table.createdBy],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.userId],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "alerts_creator_membership_id_fk",
      columns: [table.tenantId, table.createdByMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "alerts_creator_human_attribution_fk",
      columns: [table.tenantId, table.createdByMembershipId, table.createdBy],
      foreignColumns: [
        tenantMemberships.tenantId,
        tenantMemberships.id,
        tenantMemberships.userId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "alerts_deleter_membership_fk",
      columns: [table.tenantId, table.deletedByMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "alerts_creator_service_account_fk",
      columns: [table.tenantId, table.createdByServiceAccountId],
      foreignColumns: [
        tenantServiceAccounts.tenantId,
        tenantServiceAccounts.id,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "alerts_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "alerts_number_check",
      sql`btrim(${table.number}) = ${table.number}
        and octet_length(${table.number}) between 6 and 42
        and (
          ${table.number} ~ '^[A-Z][A-Z0-9]{0,11}-([0-9]{4}-)?[0-9]{4,12}$'
          or ${table.number} ~ '^[A-Z][A-Z0-9]{0,11}/([0-9]{4}/)?[0-9]{4,12}$'
          or ${table.number} ~ '^[A-Z][A-Z0-9]{0,11}\\.([0-9]{4}\\.)?[0-9]{4,12}$'
          or ${table.number} ~ '^[A-Z][A-Z0-9]{0,11}_([0-9]{4}_)?[0-9]{4,12}$'
        )
        and ${table.number} !~ '[[:cntrl:]]'
        and ${table.number} !~ U&'[\\202A-\\202E\\2066-\\2069\\200E\\200F\\061C]'`,
    ),
    check(
      "alerts_state_key_check",
      sql`${table.stateKey} ~ '^[a-z][a-z0-9_.-]{0,63}$'`,
    ),
    check(
      "alerts_creator_attribution_check",
      sql`(${table.createdByMembershipId} is not null
          and ${table.createdBy} is not null
          and ${table.createdByServiceAccountId} is null)
        or (${table.createdByMembershipId} is null
          and ${table.createdBy} is null
          and ${table.createdByServiceAccountId} is not null)`,
    ),
    check(
      "alerts_external_id_check",
      sql`${table.externalId} is null or (btrim(${table.externalId}) <> '' and char_length(${table.externalId}) <= 200 and ${table.externalId} !~ '[[:cntrl:]]')`,
    ),
    check(
      "alerts_title_not_blank_check",
      sql`btrim(${table.title}) <> '' and char_length(${table.title}) <= 240 and ${table.title} !~ '[[:cntrl:]]'`,
    ),
    check(
      "alerts_description_check",
      sql`${table.description} is null or (char_length(${table.description}) <= 10000 and ${table.description} !~ '[[:cntrl:]]')`,
    ),
    check(
      "alerts_business_text_check",
      sql`btrim(${table.priority}) <> '' and char_length(${table.priority}) <= 64
        and btrim(${table.category}) <> '' and char_length(${table.category}) <= 120
        and btrim(${table.source}) <> '' and char_length(${table.source}) <= 120
        and ${table.sourceType} ~ '^[a-z][a-z0-9_-]{0,79}$'
        and (${table.classification} is null or char_length(${table.classification}) <= 120)
        and (${table.deduplicationKey} is null or (btrim(${table.deduplicationKey}) <> '' and char_length(${table.deduplicationKey}) <= 240))`,
    ),
    check("alerts_tags_check", sql`cardinality(${table.tags}) <= 100`),
    check(
      "alerts_json_check",
      sql`jsonb_typeof(${table.customFields}) = 'object'
        and jsonb_typeof(${table.customerCustomFields}) = 'object'
        and jsonb_typeof(${table.rawPayload}) = 'object'`,
    ),
    check(
      "alerts_assignment_shape_check",
      sql`(${table.assignedTeamId} is null) = (${table.assignedTeamEpochId} is null)
        and (${table.assignedTeamId} is not null or (${table.assigneeUserId} is null and ${table.claimedByUserId} is null))
        and (${table.claimedByUserId} is null or ${table.claimedByUserId} = ${table.assigneeUserId})`,
    ),
    check("alerts_version_positive_check", sql`${table.version} > 0`),
    check(
      "alerts_tombstone_shape_check",
      sql`(${table.deletedAt} is null
          and ${table.deletedByMembershipId} is null
          and ${table.deletionReason} is null)
        or (${table.deletedAt} is not null
          and ${table.deletedByMembershipId} is not null
          and ${table.deletionReason} is not null
          and btrim(${table.deletionReason}) <> ''
          and char_length(${table.deletionReason}) <= 2000
          and ${table.deletionReason} !~ '[[:cntrl:]]'
          and ${table.deletedAt} >= ${table.createdAt})`,
    ),
    check(
      "alerts_updated_after_created_check",
      sql`${table.updatedAt} >= ${table.createdAt}
        and ${table.receivedAt} >= ${table.detectedAt}
        and (${table.closedAt} is null or ${table.closedAt} >= ${table.createdAt})`,
    ),
    pgPolicy("alerts_api_tenant", {
      as: "permissive",
      for: "all",
      to: apiRole,
      using: sql`${activeActorMembershipFor(table.tenantId)} and ${table.deletedAt} is null`,
      withCheck: sql`${activeActorMembershipFor(table.tenantId)} and ${table.deletedAt} is null`,
    }),
  ],
).enableRLS();

export const alertActivities = pgTable(
  "alert_activities",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    alertId: uuid("alert_id").notNull(),
    sequence: integer("sequence").notNull(),
    activityType: text("activity_type").notNull(),
    actorPrincipalKind: tenantPrincipalKind("actor_principal_kind").notNull(),
    actorMembershipId: uuid("actor_membership_id"),
    actorServiceAccountId: uuid("actor_service_account_id"),
    metadata: jsonb("metadata")
      .$type<Record<string, unknown>>()
      .notNull()
      .default({}),
    occurredAt: timestamp("occurred_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    unique("alert_activities_tenant_id_key").on(table.tenantId, table.id),
    unique("alert_activities_alert_sequence_key").on(
      table.tenantId,
      table.alertId,
      table.sequence,
    ),
    index("alert_activities_alert_time_idx").on(
      table.tenantId,
      table.alertId,
      table.occurredAt,
      table.id,
    ),
    foreignKey({
      name: "alert_activities_alert_fk",
      columns: [table.tenantId, table.alertId],
      foreignColumns: [alerts.tenantId, alerts.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "alert_activities_actor_membership_fk",
      columns: [table.tenantId, table.actorMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "alert_activities_actor_service_account_fk",
      columns: [table.tenantId, table.actorServiceAccountId],
      foreignColumns: [
        tenantServiceAccounts.tenantId,
        tenantServiceAccounts.id,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "alert_activities_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check("alert_activities_sequence_check", sql`${table.sequence} > 0`),
    check(
      "alert_activities_type_check",
      sql`${table.activityType} ~ '^[a-z][a-z0-9_]*(\\.[a-z][a-z0-9_]*)+$'`,
    ),
    check(
      "alert_activities_actor_check",
      sql`(${table.actorPrincipalKind} = 'human'
          and ${table.actorMembershipId} is not null
          and ${table.actorServiceAccountId} is null)
        or (${table.actorPrincipalKind} = 'service_account'
          and ${table.actorMembershipId} is null
          and ${table.actorServiceAccountId} is not null)`,
    ),
    check(
      "alert_activities_metadata_object_check",
      sql`jsonb_typeof(${table.metadata}) = 'object'`,
    ),
  ],
).enableRLS();

export const alertCommands = pgTable(
  "alert_commands",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    operation: text("operation").notNull(),
    principalKind: tenantPrincipalKind("principal_kind").notNull(),
    actorMembershipId: uuid("actor_membership_id"),
    actorServiceAccountId: uuid("actor_service_account_id"),
    keyDigest: bytea("key_digest").notNull(),
    requestDigest: bytea("request_digest").notNull(),
    resultAlertId: uuid("result_alert_id").notNull(),
    resultVersion: integer("result_version").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    unique("alert_commands_tenant_id_key").on(table.tenantId, table.id),
    uniqueIndex("alert_commands_human_replay_key")
      .on(
        table.tenantId,
        table.operation,
        table.actorMembershipId,
        table.keyDigest,
      )
      .where(sql`${table.principalKind} = 'human'`),
    uniqueIndex("alert_commands_service_account_replay_key")
      .on(
        table.tenantId,
        table.operation,
        table.actorServiceAccountId,
        table.keyDigest,
      )
      .where(sql`${table.principalKind} = 'service_account'`),
    foreignKey({
      name: "alert_commands_actor_membership_fk",
      columns: [table.tenantId, table.actorMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "alert_commands_actor_service_account_fk",
      columns: [table.tenantId, table.actorServiceAccountId],
      foreignColumns: [
        tenantServiceAccounts.tenantId,
        tenantServiceAccounts.id,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "alert_commands_result_fk",
      columns: [table.tenantId, table.resultAlertId],
      foreignColumns: [alerts.tenantId, alerts.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "alert_commands_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "alert_commands_operation_check",
      sql`${table.operation} in ('alert.create', 'alert.delete')`,
    ),
    check(
      "alert_commands_actor_check",
      sql`(${table.principalKind} = 'human'
          and ${table.actorMembershipId} is not null
          and ${table.actorServiceAccountId} is null)
        or (${table.principalKind} = 'service_account'
          and ${table.actorMembershipId} is null
          and ${table.actorServiceAccountId} is not null)`,
    ),
    check(
      "alert_commands_digest_check",
      sql`octet_length(${table.keyDigest}) = 32 and octet_length(${table.requestDigest}) = 32`,
    ),
    check(
      "alert_commands_result_version_check",
      sql`${table.resultVersion} > 0`,
    ),
  ],
).enableRLS();
