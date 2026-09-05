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

import { alerts } from "./alerts.js";
import { bytea } from "./binary.js";
import {
  alertSeverity,
  ticketCommentVisibility,
  ticketPrincipalKind,
} from "./enums.js";
import { activeActorMembershipFor, tenantMemberships } from "./identity.js";
import { operatorTeamAssignmentEpochs } from "./operator-teams.js";
import { apiRole, ticketRuntimeOwnerRole } from "./roles.js";
import { tenantServiceAccounts } from "./service-accounts.js";
import { ticketWorkflowVersions } from "./ticket-workflows.js";
import { tenants } from "./tenancy.js";

const tenantSelectPolicy = (tenantId: unknown) =>
  activeActorMembershipFor(tenantId);

export const cases = pgTable(
  "cases",
  {
    id: uuid("id").primaryKey(),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    number: text("number").notNull(),
    workflowId: uuid("workflow_id").notNull(),
    workflowVersion: integer("workflow_version").notNull(),
    stateKey: text("state_key").notNull(),
    customerVisible: boolean("customer_visible").notNull().default(false),
    title: text("title").notNull(),
    description: text("description").notNull().default(""),
    summary: text("summary").notNull().default(""),
    severity: alertSeverity("severity").notNull().default("medium"),
    priority: text("priority").notNull().default("medium"),
    category: text("category").notNull().default("general"),
    classification: text("classification"),
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
    assignedTeamId: uuid("assigned_team_id"),
    assignedTeamEpochId: uuid("assigned_team_epoch_id"),
    assigneeUserId: uuid("assignee_user_id"),
    claimedByUserId: uuid("claimed_by_user_id"),
    createdByMembershipId: uuid("created_by_membership_id").notNull(),
    createdByUserId: uuid("created_by_user_id").notNull(),
    detectionTime: timestamp("detection_time", {
      withTimezone: true,
      mode: "date",
    })
      .notNull()
      .defaultNow(),
    openedAt: timestamp("opened_at", { withTimezone: true, mode: "date" })
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
  },
  (table) => [
    unique("cases_tenant_id_key").on(table.tenantId, table.id),
    unique("cases_tenant_number_key").on(table.tenantId, table.number),
    foreignKey({
      name: "cases_workflow_version_fk",
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
      name: "cases_assignment_epoch_fk",
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
      name: "cases_assignee_membership_fk",
      columns: [table.tenantId, table.assigneeUserId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.userId],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "cases_claimant_membership_fk",
      columns: [table.tenantId, table.claimedByUserId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.userId],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "cases_creator_membership_fk",
      columns: [table.tenantId, table.createdByMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "cases_creator_user_membership_fk",
      columns: [table.tenantId, table.createdByUserId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.userId],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    index("cases_tenant_updated_idx").on(
      table.tenantId,
      table.updatedAt,
      table.id,
    ),
    index("cases_tenant_state_priority_idx").on(
      table.tenantId,
      table.stateKey,
      table.priority,
      table.id,
    ),
    index("cases_tenant_assignment_idx").on(
      table.tenantId,
      table.assignedTeamId,
      table.assigneeUserId,
      table.id,
    ),
    index("cases_ticket_search_idx").using(
      "gin",
      sql`to_tsvector('simple'::regconfig,
        coalesce(${table.number}, '') || ' ' ||
        coalesce(${table.title}, '') || ' ' ||
        coalesce(${table.description}, ''))`,
    ),
    check(
      "cases_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "cases_number_check",
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
      "cases_state_key_check",
      sql`${table.stateKey} ~ '^[a-z][a-z0-9_.-]{0,63}$'`,
    ),
    check(
      "cases_title_check",
      sql`btrim(${table.title}) <> '' and char_length(${table.title}) <= 240 and ${table.title} !~ '[[:cntrl:]]'`,
    ),
    check(
      "cases_text_check",
      sql`char_length(${table.description}) <= 20000 and char_length(${table.summary}) <= 2000`,
    ),
    check("cases_tags_check", sql`cardinality(${table.tags}) <= 100`),
    check(
      "cases_custom_fields_check",
      sql`jsonb_typeof(${table.customFields}) = 'object' and jsonb_typeof(${table.customerCustomFields}) = 'object'`,
    ),
    check(
      "cases_assignment_shape_check",
      sql`(${table.assignedTeamId} is null) = (${table.assignedTeamEpochId} is null) and (${table.assignedTeamId} is not null or (${table.assigneeUserId} is null and ${table.claimedByUserId} is null)) and (${table.claimedByUserId} is null or ${table.claimedByUserId} = ${table.assigneeUserId})`,
    ),
    check("cases_version_check", sql`${table.version} > 0`),
    check(
      "cases_timestamps_check",
      sql`${table.updatedAt} >= ${table.createdAt} and ${table.openedAt} >= ${table.createdAt} and (${table.closedAt} is null or ${table.closedAt} >= ${table.createdAt})`,
    ),
    pgPolicy("cases_api_tenant", {
      as: "permissive",
      for: "select",
      to: apiRole,
      using: tenantSelectPolicy(table.tenantId),
    }),
  ],
).enableRLS();

export const ticketComments = pgTable(
  "ticket_comments",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    alertId: uuid("alert_id"),
    caseId: uuid("case_id"),
    visibility: ticketCommentVisibility("visibility").notNull(),
    bodyMarkdown: text("body_markdown").notNull(),
    bodyHtml: text("body_html").notNull(),
    authorMembershipId: uuid("author_membership_id").notNull(),
    authorUserId: uuid("author_user_id").notNull(),
    origin: text("origin").notNull().default("api"),
    revision: integer("revision").notNull().default(1),
    mentionedUserIds: uuid("mentioned_user_ids")
      .array()
      .notNull()
      .default(sql`ARRAY[]::uuid[]`),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    unique("ticket_comments_tenant_id_key").on(table.tenantId, table.id),
    foreignKey({
      name: "ticket_comments_alert_fk",
      columns: [table.tenantId, table.alertId],
      foreignColumns: [alerts.tenantId, alerts.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "ticket_comments_case_fk",
      columns: [table.tenantId, table.caseId],
      foreignColumns: [cases.tenantId, cases.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "ticket_comments_author_membership_fk",
      columns: [table.tenantId, table.authorMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "ticket_comments_author_user_fk",
      columns: [table.tenantId, table.authorUserId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.userId],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    index("ticket_comments_alert_idx").on(
      table.tenantId,
      table.alertId,
      table.createdAt,
      table.id,
    ),
    index("ticket_comments_case_idx").on(
      table.tenantId,
      table.caseId,
      table.createdAt,
      table.id,
    ),
    check(
      "ticket_comments_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "ticket_comments_resource_check",
      sql`(${table.alertId} is null) <> (${table.caseId} is null)`,
    ),
    check(
      "ticket_comments_body_check",
      sql`app.private_ticket_comment_markdown_valid_v1(${table.bodyMarkdown})
        and app.private_ticket_comment_html_valid_v1(${table.bodyHtml})`,
    ),
    check(
      "ticket_comments_origin_check",
      sql`${table.origin} in ('api', 'customer_portal', 'escalation_copy', 'system')`,
    ),
    check(
      "ticket_comments_origin_visibility_check",
      sql`${table.origin} not in ('customer_portal','escalation_copy')
        or ${table.visibility} = 'public'`,
    ),
    check(
      "ticket_comments_revision_check",
      sql`${table.revision} between 1 and 2147483647`,
    ),
    check(
      "ticket_comments_mentions_check",
      sql`app.private_ticket_comment_uuid_array_valid_v1(${table.mentionedUserIds},50)`,
    ),
    check(
      "ticket_comments_timestamps_check",
      sql`app.private_ticket_comment_timestamp_valid_v1(${table.createdAt})
        and app.private_ticket_comment_timestamp_valid_v1(${table.updatedAt})
        and ${table.updatedAt} >= ${table.createdAt}`,
    ),
    pgPolicy("ticket_comments_owner_access", {
      as: "permissive",
      for: "all",
      to: ticketRuntimeOwnerRole,
      using: sql`true`,
      withCheck: sql`true`,
    }),
  ],
).enableRLS();

export const ticketCommentCommands = pgTable(
  "ticket_comment_commands",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    operation: text("operation").notNull(),
    actorMembershipId: uuid("actor_membership_id").notNull(),
    actorUserId: uuid("actor_user_id").notNull(),
    keyDigest: bytea("key_digest").notNull(),
    requestDigest: bytea("request_digest").notNull(),
    resultCommentId: uuid("result_comment_id").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    unique("ticket_comment_commands_tenant_id_key").on(
      table.tenantId,
      table.id,
    ),
    unique("ticket_comment_commands_replay_key").on(
      table.tenantId,
      table.actorMembershipId,
      table.operation,
      table.keyDigest,
    ),
    foreignKey({
      name: "ticket_comment_commands_actor_membership_fk",
      columns: [table.tenantId, table.actorMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "ticket_comment_commands_actor_user_fk",
      columns: [table.tenantId, table.actorUserId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.userId],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "ticket_comment_commands_result_fk",
      columns: [table.tenantId, table.resultCommentId],
      foreignColumns: [ticketComments.tenantId, ticketComments.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    index("ticket_comment_commands_result_idx").on(
      table.tenantId,
      table.resultCommentId,
    ),
    check(
      "ticket_comment_commands_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "ticket_comment_commands_operation_check",
      sql`${table.operation} in ('alert.comment.create', 'case.comment.create')`,
    ),
    check(
      "ticket_comment_commands_digest_check",
      sql`octet_length(${table.keyDigest}) = 32 and octet_length(${table.requestDigest}) = 32`,
    ),
  ],
).enableRLS();

export const ticketActivities = pgTable(
  "ticket_activities",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    alertId: uuid("alert_id"),
    caseId: uuid("case_id"),
    sequence: integer("sequence").notNull(),
    kind: text("kind").notNull(),
    summary: text("summary").notNull(),
    actorPrincipalKind: ticketPrincipalKind("actor_principal_kind").notNull(),
    actorMembershipId: uuid("actor_membership_id"),
    actorUserId: uuid("actor_user_id"),
    actorServiceAccountId: uuid("actor_service_account_id"),
    origin: text("origin").notNull().default("api"),
    details: jsonb("details")
      .$type<Record<string, unknown>>()
      .notNull()
      .default({}),
    occurredAt: timestamp("occurred_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    unique("ticket_activities_tenant_id_key").on(table.tenantId, table.id),
    uniqueIndex("ticket_activities_alert_sequence_key")
      .on(table.tenantId, table.alertId, table.sequence)
      .where(sql`${table.alertId} is not null`),
    uniqueIndex("ticket_activities_case_sequence_key")
      .on(table.tenantId, table.caseId, table.sequence)
      .where(sql`${table.caseId} is not null`),
    foreignKey({
      name: "ticket_activities_alert_fk",
      columns: [table.tenantId, table.alertId],
      foreignColumns: [alerts.tenantId, alerts.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "ticket_activities_case_fk",
      columns: [table.tenantId, table.caseId],
      foreignColumns: [cases.tenantId, cases.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "ticket_activities_actor_membership_fk",
      columns: [table.tenantId, table.actorMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "ticket_activities_actor_user_fk",
      columns: [table.tenantId, table.actorUserId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.userId],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "ticket_activities_actor_service_account_fk",
      columns: [table.tenantId, table.actorServiceAccountId],
      foreignColumns: [
        tenantServiceAccounts.tenantId,
        tenantServiceAccounts.id,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    index("ticket_activities_alert_idx").on(
      table.tenantId,
      table.alertId,
      table.occurredAt,
      table.id,
    ),
    index("ticket_activities_case_idx").on(
      table.tenantId,
      table.caseId,
      table.occurredAt,
      table.id,
    ),
    check(
      "ticket_activities_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "ticket_activities_resource_check",
      sql`(${table.alertId} is null) <> (${table.caseId} is null)`,
    ),
    check("ticket_activities_sequence_check", sql`${table.sequence} > 0`),
    check(
      "ticket_activities_kind_check",
      sql`${table.kind} ~ '^[a-z][a-z0-9_]*(\\.[a-z][a-z0-9_]*)+$'`,
    ),
    check(
      "ticket_activities_actor_check",
      sql`(${table.actorPrincipalKind} = 'human' and ${table.actorMembershipId} is not null and ${table.actorUserId} is not null and ${table.actorServiceAccountId} is null) or (${table.actorPrincipalKind} = 'service_account' and ${table.actorMembershipId} is null and ${table.actorUserId} is null and ${table.actorServiceAccountId} is not null) or (${table.actorPrincipalKind} = 'system' and ${table.actorMembershipId} is null and ${table.actorUserId} is null and ${table.actorServiceAccountId} is null)`,
    ),
    check(
      "ticket_activities_origin_check",
      sql`${table.origin} in ('api', 'customer_portal', 'escalation_copy', 'system')`,
    ),
    check(
      "ticket_activities_details_check",
      sql`jsonb_typeof(${table.details}) = 'object'`,
    ),
    pgPolicy("ticket_activities_api_tenant", {
      as: "permissive",
      for: "select",
      to: apiRole,
      using: tenantSelectPolicy(table.tenantId),
    }),
  ],
).enableRLS();

export const alertCaseLinks = pgTable(
  "alert_case_links",
  {
    id: uuid("id").primaryKey(),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    alertId: uuid("alert_id").notNull(),
    caseId: uuid("case_id").notNull(),
    relation: text("relation").notNull(),
    reason: text("reason").notNull(),
    linkedByMembershipId: uuid("linked_by_membership_id").notNull(),
    linkedByUserId: uuid("linked_by_user_id").notNull(),
    sourceAlertVersion: integer("source_alert_version").notNull(),
    copyFields: text("copy_fields")
      .array()
      .notNull()
      .default(sql`ARRAY[]::text[]`),
    customFieldKeys: text("custom_field_keys")
      .array()
      .notNull()
      .default(sql`ARRAY[]::text[]`),
    itemIds: jsonb("item_ids")
      .$type<Record<string, string[]>>()
      .notNull()
      .default({}),
    publicCommentIds: uuid("public_comment_ids")
      .array()
      .notNull()
      .default(sql`ARRAY[]::uuid[]`),
    copiedFieldSnapshot: jsonb("copied_field_snapshot")
      .$type<Record<string, unknown>>()
      .notNull()
      .default({}),
    linkedAt: timestamp("linked_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
  },
  (table) => [
    unique("alert_case_links_tenant_id_key").on(table.tenantId, table.id),
    unique("alert_case_links_exact_key").on(
      table.tenantId,
      table.alertId,
      table.caseId,
    ),
    unique("alert_case_links_identity_key").on(
      table.tenantId,
      table.id,
      table.alertId,
      table.caseId,
    ),
    foreignKey({
      name: "alert_case_links_alert_fk",
      columns: [table.tenantId, table.alertId],
      foreignColumns: [alerts.tenantId, alerts.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "alert_case_links_case_fk",
      columns: [table.tenantId, table.caseId],
      foreignColumns: [cases.tenantId, cases.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "alert_case_links_actor_membership_fk",
      columns: [table.tenantId, table.linkedByMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "alert_case_links_actor_user_fk",
      columns: [table.tenantId, table.linkedByUserId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.userId],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    index("alert_case_links_alert_idx").on(
      table.tenantId,
      table.alertId,
      table.linkedAt,
      table.id,
    ),
    index("alert_case_links_case_idx").on(
      table.tenantId,
      table.caseId,
      table.linkedAt,
      table.id,
    ),
    check(
      "alert_case_links_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "alert_case_links_relation_check",
      sql`${table.relation} in ('escalation', 'correlation')`,
    ),
    check(
      "alert_case_links_reason_check",
      sql`btrim(${table.reason}) <> '' and char_length(${table.reason}) <= 2000`,
    ),
    check(
      "alert_case_links_source_version_check",
      sql`${table.sourceAlertVersion} > 0`,
    ),
    check(
      "alert_case_links_selection_check",
      sql`cardinality(${table.copyFields}) <= 12 and cardinality(${table.customFieldKeys}) <= 100 and cardinality(${table.publicCommentIds}) <= 100 and jsonb_typeof(${table.itemIds}) = 'object' and jsonb_typeof(${table.copiedFieldSnapshot}) = 'object'`,
    ),
    pgPolicy("alert_case_links_api_tenant", {
      as: "permissive",
      for: "select",
      to: apiRole,
      using: tenantSelectPolicy(table.tenantId),
    }),
  ],
).enableRLS();

// A link is immutable evidence even after it stops participating in live
// projections. Unlink therefore appends exactly one retraction instead of
// updating or deleting alert_case_links. The four-column FK binds the
// retraction to the exact historical tuple, not merely to independently valid
// identifiers from the same tenant.
export const alertCaseLinkRetractions = pgTable(
  "alert_case_link_retractions",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    linkId: uuid("link_id").notNull(),
    alertId: uuid("alert_id").notNull(),
    caseId: uuid("case_id").notNull(),
    unlinkedByMembershipId: uuid("unlinked_by_membership_id").notNull(),
    unlinkedByUserId: uuid("unlinked_by_user_id").notNull(),
    reason: text("reason").notNull(),
    priorAlertVersion: integer("prior_alert_version").notNull(),
    resultAlertVersion: integer("result_alert_version").notNull(),
    priorCaseVersion: integer("prior_case_version").notNull(),
    resultCaseVersion: integer("result_case_version").notNull(),
    unlinkedAt: timestamp("unlinked_at", {
      withTimezone: true,
      mode: "date",
    })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    unique("alert_case_link_retractions_tenant_id_key").on(
      table.tenantId,
      table.id,
    ),
    unique("alert_case_link_retractions_link_key").on(
      table.tenantId,
      table.linkId,
    ),
    unique("alert_case_link_retractions_pair_key").on(
      table.tenantId,
      table.alertId,
      table.caseId,
    ),
    foreignKey({
      name: "alert_case_link_retractions_link_identity_fk",
      columns: [table.tenantId, table.linkId, table.alertId, table.caseId],
      foreignColumns: [
        alertCaseLinks.tenantId,
        alertCaseLinks.id,
        alertCaseLinks.alertId,
        alertCaseLinks.caseId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "alert_case_link_retractions_actor_membership_fk",
      columns: [table.tenantId, table.unlinkedByMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "alert_case_link_retractions_actor_user_fk",
      columns: [table.tenantId, table.unlinkedByUserId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.userId],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    index("alert_case_link_retractions_alert_idx").on(
      table.tenantId,
      table.alertId,
      table.unlinkedAt,
      table.id,
    ),
    index("alert_case_link_retractions_case_idx").on(
      table.tenantId,
      table.caseId,
      table.unlinkedAt,
      table.id,
    ),
    check(
      "alert_case_link_retractions_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "alert_case_link_retractions_reason_check",
      sql`btrim(${table.reason}) <> '' and char_length(${table.reason}) <= 2000 and ${table.reason} !~ '[[:cntrl:]]'`,
    ),
    check(
      "alert_case_link_retractions_version_check",
      sql`${table.priorAlertVersion} between 1 and 2147483646 and ${table.resultAlertVersion} = ${table.priorAlertVersion} + 1 and ${table.priorCaseVersion} between 1 and 2147483646 and ${table.resultCaseVersion} = ${table.priorCaseVersion} + 1`,
    ),
    pgPolicy("alert_case_link_retractions_api_tenant", {
      as: "permissive",
      for: "select",
      to: apiRole,
      using: tenantSelectPolicy(table.tenantId),
    }),
  ],
).enableRLS();

export const ticketAssignmentHistory = pgTable(
  "ticket_assignment_history",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    alertId: uuid("alert_id"),
    caseId: uuid("case_id"),
    version: integer("version").notNull(),
    action: text("action").notNull(),
    priorTeamId: uuid("prior_team_id"),
    resultingTeamId: uuid("resulting_team_id"),
    priorAssigneeUserId: uuid("prior_assignee_user_id"),
    resultingAssigneeUserId: uuid("resulting_assignee_user_id"),
    priorClaimantUserId: uuid("prior_claimant_user_id"),
    resultingClaimantUserId: uuid("resulting_claimant_user_id"),
    actorMembershipId: uuid("actor_membership_id").notNull(),
    actorUserId: uuid("actor_user_id").notNull(),
    reason: text("reason").notNull().default(""),
    occurredAt: timestamp("occurred_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    unique("ticket_assignment_history_tenant_id_key").on(
      table.tenantId,
      table.id,
    ),
    uniqueIndex("ticket_assignment_history_alert_version_key")
      .on(table.tenantId, table.alertId, table.version)
      .where(sql`${table.alertId} is not null`),
    uniqueIndex("ticket_assignment_history_case_version_key")
      .on(table.tenantId, table.caseId, table.version)
      .where(sql`${table.caseId} is not null`),
    foreignKey({
      name: "ticket_assignment_history_alert_fk",
      columns: [table.tenantId, table.alertId],
      foreignColumns: [alerts.tenantId, alerts.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "ticket_assignment_history_case_fk",
      columns: [table.tenantId, table.caseId],
      foreignColumns: [cases.tenantId, cases.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "ticket_assignment_history_actor_membership_fk",
      columns: [table.tenantId, table.actorMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "ticket_assignment_history_actor_user_fk",
      columns: [table.tenantId, table.actorUserId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.userId],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    index("ticket_assignment_history_alert_idx").on(
      table.tenantId,
      table.alertId,
      table.version,
    ),
    index("ticket_assignment_history_case_idx").on(
      table.tenantId,
      table.caseId,
      table.version,
    ),
    check(
      "ticket_assignment_history_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "ticket_assignment_history_resource_check",
      sql`(${table.alertId} is null) <> (${table.caseId} is null)`,
    ),
    check("ticket_assignment_history_version_check", sql`${table.version} > 0`),
    check(
      "ticket_assignment_history_action_check",
      sql`${table.action} in ('assign', 'claim', 'release', 'transfer')`,
    ),
  ],
).enableRLS();

export const ticketCommands = pgTable(
  "ticket_commands",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    operation: text("operation").notNull(),
    actorMembershipId: uuid("actor_membership_id").notNull(),
    actorUserId: uuid("actor_user_id").notNull(),
    keyDigest: bytea("key_digest").notNull(),
    requestDigest: bytea("request_digest").notNull(),
    resultAlertId: uuid("result_alert_id"),
    resultCaseId: uuid("result_case_id"),
    resultVersion: integer("result_version").notNull(),
    resultMetadata: jsonb("result_metadata")
      .$type<Record<string, unknown>>()
      .notNull()
      .default({}),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    unique("ticket_commands_tenant_id_key").on(table.tenantId, table.id),
    unique("ticket_commands_dfir_retention_coordinate_key").on(
      table.tenantId,
      table.id,
      table.operation,
      table.createdAt,
    ),
    unique("ticket_commands_replay_key").on(
      table.tenantId,
      table.actorMembershipId,
      table.operation,
      table.keyDigest,
    ),
    uniqueIndex("ticket_commands_dfir_user_replay_key")
      .on(table.tenantId, table.actorUserId, table.operation, table.keyDigest)
      .where(
        sql`${table.operation} in (
          'case.dfir.task.create','case.dfir.task.transition',
          'case.dfir.task.replace_details','case.dfir.task.assign',
          'case.dfir.task.reschedule','case.dfir.task.replace_checklist',
          'case.dfir.task.comments.replace'
        )`,
      ),
    foreignKey({
      name: "ticket_commands_actor_membership_fk",
      columns: [table.tenantId, table.actorMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "ticket_commands_actor_user_fk",
      columns: [table.tenantId, table.actorUserId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.userId],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "ticket_commands_result_alert_fk",
      columns: [table.tenantId, table.resultAlertId],
      foreignColumns: [alerts.tenantId, alerts.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "ticket_commands_result_case_fk",
      columns: [table.tenantId, table.resultCaseId],
      foreignColumns: [cases.tenantId, cases.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    index("ticket_commands_result_alert_idx").on(
      table.tenantId,
      table.resultAlertId,
    ),
    index("ticket_commands_result_case_idx").on(
      table.tenantId,
      table.resultCaseId,
    ),
    check(
      "ticket_commands_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "ticket_commands_operation_check",
      sql`${table.operation} ~ '^(alert|case|ticket)\\.[a-z][a-z0-9_.-]{1,63}$'`,
    ),
    check(
      "ticket_commands_digest_check",
      sql`octet_length(${table.keyDigest}) = 32 and octet_length(${table.requestDigest}) = 32`,
    ),
    check(
      "ticket_commands_result_version_check",
      sql`${table.resultVersion} > 0`,
    ),
    check(
      "ticket_commands_result_shape_check",
      sql`${table.resultAlertId} is not null or ${table.resultCaseId} is not null`,
    ),
    check(
      "ticket_commands_metadata_check",
      sql`jsonb_typeof(${table.resultMetadata}) = 'object'`,
    ),
  ],
).enableRLS();
