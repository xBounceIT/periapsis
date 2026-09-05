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
  primaryKey,
  text,
  timestamp,
  unique,
  uniqueIndex,
  uuid,
} from "drizzle-orm/pg-core";

import { alerts } from "./alerts.js";
import { bytea } from "./binary.js";
import { activeActorMembershipFor, tenantMemberships } from "./identity.js";
import { apiRole, ticketRuntimeOwnerRole } from "./roles.js";
import { tenants } from "./tenancy.js";
import { cases, ticketActivities, ticketComments } from "./ticketing.js";

const tenantSelectPolicy = (tenantId: unknown) =>
  activeActorMembershipFor(tenantId);

export interface ContactRecipientRuleNode {
  kind: "all" | "any" | "not" | "predicate";
  children?: ContactRecipientRuleNode[];
  field?:
    | "active"
    | "email_allowed"
    | "contact_class"
    | "tag"
    | "notification_category"
    | "language"
    | "timezone"
    | "escalation_priority"
    | "linked_account";
  operator?:
    | "equals"
    | "not_equals"
    | "one_of"
    | "none_of"
    | "contains"
    | "not_contains"
    | "greater_than_or_equal"
    | "less_than_or_equal"
    | "exists"
    | "not_exists";
  values?: string[];
}

export interface CustomerContactCommandResultSnapshot {
  schemaVersion: 1;
  operation: string;
  projection: "operator" | "customer" | "unavailable";
  resource: Record<string, unknown> | null;
}

export const customerContacts = pgTable(
  "customer_contacts",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    firstName: text("first_name").notNull(),
    lastName: text("last_name").notNull(),
    email: text("email").notNull(),
    phone: text("phone"),
    function: text("function").notNull(),
    language: text("language").notNull(),
    timezone: text("timezone").notNull(),
    escalationPriority: integer("escalation_priority").notNull().default(0),
    contactClass: text("contact_class").notNull(),
    notificationCategories: text("notification_categories")
      .array()
      .notNull()
      .default(sql`ARRAY[]::text[]`),
    emailAllowed: boolean("email_allowed").notNull().default(true),
    active: boolean("active").notNull().default(true),
    tags: text("tags")
      .array()
      .notNull()
      .default(sql`ARRAY[]::text[]`),
    linkedMembershipId: uuid("linked_membership_id"),
    linkedUserId: uuid("linked_user_id"),
    version: integer("version").notNull().default(1),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    archivedAt: timestamp("archived_at", {
      withTimezone: true,
      mode: "date",
    }),
  },
  (table) => [
    unique("customer_contacts_tenant_id_key").on(table.tenantId, table.id),
    unique("customer_contacts_link_snapshot_key").on(
      table.tenantId,
      table.id,
      table.linkedMembershipId,
      table.linkedUserId,
    ),
    uniqueIndex("customer_contacts_tenant_membership_key")
      .on(table.tenantId, table.linkedMembershipId)
      .where(sql`${table.linkedMembershipId} is not null`),
    index("customer_contacts_tenant_active_name_idx").on(
      table.tenantId,
      table.active,
      table.lastName,
      table.firstName,
      table.id,
    ),
    index("customer_contacts_tenant_email_idx").on(
      table.tenantId,
      table.email,
      table.id,
    ),
    foreignKey({
      name: "customer_contacts_linked_membership_fk",
      columns: [table.tenantId, table.linkedMembershipId, table.linkedUserId],
      foreignColumns: [
        tenantMemberships.tenantId,
        tenantMemberships.id,
        tenantMemberships.userId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "customer_contacts_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "customer_contacts_link_shape_check",
      sql`(${table.linkedMembershipId} is null) = (${table.linkedUserId} is null)`,
    ),
    check(
      "customer_contacts_name_check",
      sql`btrim(${table.firstName}) <> ''
        and btrim(${table.lastName}) <> ''
        and char_length(${table.firstName}) <= 160
        and char_length(${table.lastName}) <= 160
        and ${table.firstName} !~ '[[:cntrl:]]'
        and ${table.lastName} !~ '[[:cntrl:]]'`,
    ),
    check(
      "customer_contacts_email_check",
      sql`${table.email} = lower(btrim(${table.email}))
        and position('@' in ${table.email}) > 1
        and char_length(${table.email}) <= 320
        and ${table.email} !~ '[[:cntrl:]]'`,
    ),
    check(
      "customer_contacts_phone_check",
      sql`${table.phone} is null or (
        btrim(${table.phone}) <> ''
        and char_length(${table.phone}) <= 64
        and ${table.phone} !~ '[[:cntrl:]<>]'
      )`,
    ),
    check(
      "customer_contacts_function_check",
      sql`btrim(${table.function}) <> ''
        and char_length(${table.function}) <= 160
        and ${table.function} !~ '[[:cntrl:]]'`,
    ),
    check(
      "customer_contacts_language_check",
      sql`${table.language} ~ '^[a-z]{2,3}(-[A-Z][a-z]{3})?(-([A-Z]{2}|[0-9]{3}))?$'`,
    ),
    check(
      "customer_contacts_timezone_check",
      sql`char_length(${table.timezone}) <= 64
        and (${table.timezone} = 'UTC'
          or ${table.timezone} ~ '^[A-Za-z][A-Za-z0-9_+.-]{0,62}(/[A-Za-z0-9_+.-]{1,63}){1,3}$')`,
    ),
    check(
      "customer_contacts_escalation_priority_check",
      sql`${table.escalationPriority} between 0 and 100`,
    ),
    check(
      "customer_contacts_class_check",
      sql`${table.contactClass} ~ '^[a-z][a-z0-9_.-]{0,63}$'`,
    ),
    check(
      "customer_contacts_category_check",
      sql`cardinality(${table.notificationCategories}) <= 64
        and array_position(${table.notificationCategories}, null) is null
        and array_to_string(${table.notificationCategories}, ',')
          ~ '^([a-z][a-z0-9_.-]{0,63}(,[a-z][a-z0-9_.-]{0,63})*)?$'`,
    ),
    check(
      "customer_contacts_tags_check",
      sql`cardinality(${table.tags}) <= 100
        and array_position(${table.tags}, null) is null
        and array_to_string(${table.tags}, ',')
          ~ '^([a-z][a-z0-9_.-]{0,63}(,[a-z][a-z0-9_.-]{0,63})*)?$'`,
    ),
    check("customer_contacts_version_check", sql`${table.version} > 0`),
    check(
      "customer_contacts_lifecycle_check",
      sql`${table.updatedAt} >= ${table.createdAt}
        and (${table.archivedAt} is null or (
          ${table.archivedAt} >= ${table.createdAt}
          and ${table.updatedAt} >= ${table.archivedAt}
          and ${table.active} is false
        ))`,
    ),
    pgPolicy("customer_contacts_api_tenant", {
      as: "permissive",
      for: "select",
      to: apiRole,
      using: tenantSelectPolicy(table.tenantId),
    }),
  ],
).enableRLS();

export const customerContactNotificationWindows = pgTable(
  "customer_contact_notification_windows",
  {
    tenantId: uuid("tenant_id").notNull(),
    contactId: uuid("contact_id").notNull(),
    isoWeekday: integer("iso_weekday").notNull(),
    startMinute: integer("start_minute").notNull(),
    endMinute: integer("end_minute").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    primaryKey({
      name: "customer_contact_notification_windows_pkey",
      columns: [
        table.tenantId,
        table.contactId,
        table.isoWeekday,
        table.startMinute,
      ],
    }),
    foreignKey({
      name: "customer_contact_notification_windows_contact_fk",
      columns: [table.tenantId, table.contactId],
      foreignColumns: [customerContacts.tenantId, customerContacts.id],
    })
      .onUpdate("cascade")
      .onDelete("cascade"),
    check(
      "customer_contact_notification_windows_bounds_check",
      sql`${table.isoWeekday} between 1 and 7
        and ${table.startMinute} between 0 and 1439
        and ${table.endMinute} between 1 and 1440
        and ${table.startMinute} < ${table.endMinute}`,
    ),
    pgPolicy("customer_contact_notification_windows_api_tenant", {
      as: "permissive",
      for: "select",
      to: apiRole,
      using: tenantSelectPolicy(table.tenantId),
    }),
  ],
).enableRLS();

export const customerContactGroups = pgTable(
  "customer_contact_groups",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    key: text("key").notNull(),
    currentVersion: integer("current_version").notNull().default(1),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    archivedAt: timestamp("archived_at", {
      withTimezone: true,
      mode: "date",
    }),
  },
  (table) => [
    unique("customer_contact_groups_tenant_id_key").on(
      table.tenantId,
      table.id,
    ),
    unique("customer_contact_groups_tenant_key_key").on(
      table.tenantId,
      table.key,
    ),
    index("customer_contact_groups_tenant_active_idx")
      .on(table.tenantId, table.key, table.id)
      .where(sql`${table.archivedAt} is null`),
    check(
      "customer_contact_groups_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "customer_contact_groups_key_check",
      sql`${table.key} ~ '^[a-z][a-z0-9_.-]{0,63}$'`,
    ),
    check(
      "customer_contact_groups_version_check",
      sql`${table.currentVersion} > 0`,
    ),
    check(
      "customer_contact_groups_lifecycle_check",
      sql`${table.updatedAt} >= ${table.createdAt}
        and (${table.archivedAt} is null or (
          ${table.archivedAt} >= ${table.createdAt}
          and ${table.updatedAt} >= ${table.archivedAt}
        ))`,
    ),
    pgPolicy("customer_contact_groups_api_tenant", {
      as: "permissive",
      for: "select",
      to: apiRole,
      using: tenantSelectPolicy(table.tenantId),
    }),
  ],
).enableRLS();

export const customerContactGroupVersions = pgTable(
  "customer_contact_group_versions",
  {
    tenantId: uuid("tenant_id").notNull(),
    groupId: uuid("group_id").notNull(),
    version: integer("version").notNull(),
    name: text("name").notNull(),
    description: text("description").notNull().default(""),
    mode: text("mode").notNull(),
    ruleSchemaVersion: integer("rule_schema_version").notNull().default(1),
    rule: jsonb("rule").$type<ContactRecipientRuleNode>(),
    createdByMembershipId: uuid("created_by_membership_id").notNull(),
    createdByUserId: uuid("created_by_user_id").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    primaryKey({
      name: "customer_contact_group_versions_pkey",
      columns: [table.tenantId, table.groupId, table.version],
    }),
    foreignKey({
      name: "customer_contact_group_versions_group_fk",
      columns: [table.tenantId, table.groupId],
      foreignColumns: [
        customerContactGroups.tenantId,
        customerContactGroups.id,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "customer_contact_group_versions_actor_fk",
      columns: [
        table.tenantId,
        table.createdByMembershipId,
        table.createdByUserId,
      ],
      foreignColumns: [
        tenantMemberships.tenantId,
        tenantMemberships.id,
        tenantMemberships.userId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "customer_contact_group_versions_version_check",
      sql`${table.version} > 0 and ${table.ruleSchemaVersion} = 1`,
    ),
    check(
      "customer_contact_group_versions_name_check",
      sql`btrim(${table.name}) <> ''
        and char_length(${table.name}) <= 160
        and char_length(${table.description}) <= 2000
        and ${table.name} !~ '[[:cntrl:]]'
        and ${table.description} !~ '[[:cntrl:]]'`,
    ),
    check(
      "customer_contact_group_versions_shape_check",
      sql`(${table.mode} = 'manual' and ${table.rule} is null)
        or (${table.mode} = 'dynamic'
          and jsonb_typeof(${table.rule}) = 'object'
          and octet_length(${table.rule}::text) <= 32768)`,
    ),
    pgPolicy("customer_contact_group_versions_api_tenant", {
      as: "permissive",
      for: "select",
      to: apiRole,
      using: tenantSelectPolicy(table.tenantId),
    }),
  ],
).enableRLS();

export const customerContactGroupVersionMembers = pgTable(
  "customer_contact_group_version_members",
  {
    tenantId: uuid("tenant_id").notNull(),
    groupId: uuid("group_id").notNull(),
    groupVersion: integer("group_version").notNull(),
    contactId: uuid("contact_id").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    primaryKey({
      name: "customer_contact_group_version_members_pkey",
      columns: [
        table.tenantId,
        table.groupId,
        table.groupVersion,
        table.contactId,
      ],
    }),
    foreignKey({
      name: "customer_contact_group_version_members_version_fk",
      columns: [table.tenantId, table.groupId, table.groupVersion],
      foreignColumns: [
        customerContactGroupVersions.tenantId,
        customerContactGroupVersions.groupId,
        customerContactGroupVersions.version,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "customer_contact_group_version_members_contact_fk",
      columns: [table.tenantId, table.contactId],
      foreignColumns: [customerContacts.tenantId, customerContacts.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    index("customer_contact_group_version_members_contact_idx").on(
      table.tenantId,
      table.contactId,
      table.groupId,
      table.groupVersion,
    ),
    pgPolicy("customer_contact_group_version_members_api_tenant", {
      as: "permissive",
      for: "select",
      to: apiRole,
      using: tenantSelectPolicy(table.tenantId),
    }),
  ],
).enableRLS();

export const ticketCustomerContacts = pgTable(
  "ticket_customer_contacts",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id").notNull(),
    alertId: uuid("alert_id"),
    caseId: uuid("case_id"),
    contactId: uuid("contact_id").notNull(),
    role: text("role").notNull(),
    origin: text("origin").notNull().default("manual"),
    sourceAlertId: uuid("source_alert_id"),
    sourceAlertVersion: integer("source_alert_version"),
    version: integer("version").notNull().default(1),
    createdByMembershipId: uuid("created_by_membership_id").notNull(),
    createdByUserId: uuid("created_by_user_id").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    archivedAt: timestamp("archived_at", {
      withTimezone: true,
      mode: "date",
    }),
  },
  (table) => [
    unique("ticket_customer_contacts_tenant_id_key").on(
      table.tenantId,
      table.id,
    ),
    uniqueIndex("ticket_customer_contacts_active_alert_contact_key")
      .on(table.tenantId, table.alertId, table.contactId)
      .where(sql`${table.alertId} is not null and ${table.archivedAt} is null`),
    uniqueIndex("ticket_customer_contacts_active_case_contact_key")
      .on(table.tenantId, table.caseId, table.contactId)
      .where(sql`${table.caseId} is not null and ${table.archivedAt} is null`),
    foreignKey({
      name: "ticket_customer_contacts_alert_fk",
      columns: [table.tenantId, table.alertId],
      foreignColumns: [alerts.tenantId, alerts.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "ticket_customer_contacts_case_fk",
      columns: [table.tenantId, table.caseId],
      foreignColumns: [cases.tenantId, cases.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "ticket_customer_contacts_contact_fk",
      columns: [table.tenantId, table.contactId],
      foreignColumns: [customerContacts.tenantId, customerContacts.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "ticket_customer_contacts_source_alert_fk",
      columns: [table.tenantId, table.sourceAlertId],
      foreignColumns: [alerts.tenantId, alerts.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "ticket_customer_contacts_actor_fk",
      columns: [
        table.tenantId,
        table.createdByMembershipId,
        table.createdByUserId,
      ],
      foreignColumns: [
        tenantMemberships.tenantId,
        tenantMemberships.id,
        tenantMemberships.userId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    index("ticket_customer_contacts_contact_idx").on(
      table.tenantId,
      table.contactId,
      table.id,
    ),
    check(
      "ticket_customer_contacts_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "ticket_customer_contacts_resource_check",
      sql`(${table.alertId} is null) <> (${table.caseId} is null)`,
    ),
    check(
      "ticket_customer_contacts_role_check",
      sql`${table.role} in ('primary', 'escalation', 'watcher')`,
    ),
    check(
      "ticket_customer_contacts_origin_check",
      sql`(${table.origin} = 'manual'
          and ${table.sourceAlertId} is null
          and ${table.sourceAlertVersion} is null)
        or (${table.origin} = 'escalation_copy'
          and ${table.caseId} is not null
          and ${table.sourceAlertId} is not null
          and ${table.sourceAlertVersion} > 0)`,
    ),
    check("ticket_customer_contacts_version_check", sql`${table.version} > 0`),
    check(
      "ticket_customer_contacts_archive_check",
      sql`${table.archivedAt} is null or ${table.archivedAt} >= ${table.createdAt}`,
    ),
    pgPolicy("ticket_customer_contacts_api_tenant", {
      as: "permissive",
      for: "select",
      to: apiRole,
      using: tenantSelectPolicy(table.tenantId),
    }),
  ],
).enableRLS();

// This one-to-one companion row snapshots the author audience and exact
// customer-contact identity at comment commit. It is never inferred from a
// later membership role or contact link.
export const ticketCommentAuthorSnapshots = pgTable(
  "ticket_comment_author_snapshots",
  {
    tenantId: uuid("tenant_id").notNull(),
    commentId: uuid("comment_id").notNull(),
    audience: text("audience").notNull(),
    authorMembershipId: uuid("author_membership_id").notNull(),
    authorUserId: uuid("author_user_id").notNull(),
    authorContactId: uuid("author_contact_id"),
    displayName: text("display_name").notNull(),
    origin: text("origin").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    editableUntil: timestamp("editable_until", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
  },
  (table) => [
    primaryKey({
      name: "ticket_comment_author_snapshots_pkey",
      columns: [table.tenantId, table.commentId],
    }),
    foreignKey({
      name: "ticket_comment_author_snapshots_comment_fk",
      columns: [table.tenantId, table.commentId],
      foreignColumns: [ticketComments.tenantId, ticketComments.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "ticket_comment_author_snapshots_customer_contact_fk",
      columns: [table.tenantId, table.authorContactId],
      foreignColumns: [customerContacts.tenantId, customerContacts.id],
    })
      .onUpdate("restrict")
      .onDelete("restrict"),
    foreignKey({
      name: "ticket_comment_author_snapshots_author_fk",
      columns: [table.tenantId, table.authorMembershipId, table.authorUserId],
      foreignColumns: [
        tenantMemberships.tenantId,
        tenantMemberships.id,
        tenantMemberships.userId,
      ],
    })
      .onUpdate("restrict")
      .onDelete("restrict"),
    check(
      "ticket_comment_author_snapshots_shape_check",
      sql`(${table.audience} = 'operator' and ${table.authorContactId} is null)
        or (${table.audience} = 'customer' and ${table.authorContactId} is not null)`,
    ),
    check(
      "ticket_comment_author_snapshots_origin_check",
      sql`${table.origin} in ('api','customer_portal','escalation_copy','system')
        and (${table.origin} <> 'api' or ${table.audience} = 'operator')
        and (${table.origin} <> 'customer_portal' or ${table.audience} = 'customer')
        and (${table.origin} <> 'system' or ${table.audience} = 'operator')`,
    ),
    check(
      "ticket_comment_author_snapshots_display_name_check",
      sql`app.private_ticket_comment_display_name_valid_v1(${table.displayName})`,
    ),
    check(
      "ticket_comment_author_snapshots_window_check",
      sql`app.private_ticket_comment_timestamp_valid_v1(${table.createdAt})
        and app.private_ticket_comment_timestamp_valid_v1(${table.editableUntil})
        and ${table.editableUntil} = ${table.createdAt} + interval '15 minutes'`,
    ),
    pgPolicy("ticket_comment_author_snapshots_owner_access", {
      as: "permissive",
      for: "all",
      to: ticketRuntimeOwnerRole,
      using: sql`true`,
      withCheck: sql`true`,
    }),
  ],
).enableRLS();

// Activity projections pin the audience and customer author, if any, at the
// same commit as the activity. A later role or contact-link change cannot
// reclassify historical activity.
export const ticketActivityAuthorSnapshots = pgTable(
  "ticket_activity_author_snapshots",
  {
    tenantId: uuid("tenant_id").notNull(),
    activityId: uuid("activity_id").notNull(),
    audience: text("audience").notNull(),
    authorContactId: uuid("author_contact_id"),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    primaryKey({
      name: "ticket_activity_author_snapshots_pkey",
      columns: [table.tenantId, table.activityId],
    }),
    foreignKey({
      name: "ticket_activity_author_snapshots_activity_fk",
      columns: [table.tenantId, table.activityId],
      foreignColumns: [ticketActivities.tenantId, ticketActivities.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "ticket_activity_author_snapshots_customer_contact_fk",
      columns: [table.tenantId, table.authorContactId],
      foreignColumns: [customerContacts.tenantId, customerContacts.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "ticket_activity_author_snapshots_shape_check",
      sql`(${table.audience} = 'operator' and ${table.authorContactId} is null)
        or (${table.audience} = 'customer' and ${table.authorContactId} is not null)`,
    ),
    pgPolicy("ticket_activity_author_snapshots_api_tenant", {
      as: "permissive",
      for: "select",
      to: apiRole,
      using: tenantSelectPolicy(table.tenantId),
    }),
  ],
).enableRLS();

export const customerContactCommands = pgTable(
  "customer_contact_commands",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    actorMembershipId: uuid("actor_membership_id").notNull(),
    actorUserId: uuid("actor_user_id").notNull(),
    operation: text("operation").notNull(),
    keyDigest: bytea("key_digest").notNull(),
    requestDigest: bytea("request_digest").notNull(),
    resultResourceId: uuid("result_resource_id").notNull(),
    resultVersion: integer("result_version").notNull(),
    resultSnapshot: jsonb("result_snapshot")
      .$type<CustomerContactCommandResultSnapshot>()
      .notNull()
      .default(
        sql`'{"schemaVersion":1,"operation":"legacy.unavailable","projection":"unavailable","resource":null}'::jsonb`,
      ),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    expiresAt: timestamp("expires_at", { withTimezone: true, mode: "date" })
      .notNull()
      .default(sql`now() + interval '24 hours'`),
  },
  (table) => [
    unique("customer_contact_commands_tenant_id_key").on(
      table.tenantId,
      table.id,
    ),
    unique("customer_contact_commands_replay_key").on(
      table.tenantId,
      table.actorMembershipId,
      table.operation,
      table.keyDigest,
    ),
    foreignKey({
      name: "customer_contact_commands_actor_fk",
      columns: [table.tenantId, table.actorMembershipId, table.actorUserId],
      foreignColumns: [
        tenantMemberships.tenantId,
        tenantMemberships.id,
        tenantMemberships.userId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    index("customer_contact_commands_expiry_idx").on(table.expiresAt),
    check(
      "customer_contact_commands_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "customer_contact_commands_operation_check",
      sql`${table.operation} in (
        'contact.create',
        'contact.replace',
        'contact.archive',
        'portal.preference.replace',
        'contact_group.create',
        'contact_group.version',
        'contact_group.archive',
        'ticket_contact.link',
        'ticket_contact.archive'
      )`,
    ),
    check(
      "customer_contact_commands_digest_check",
      sql`octet_length(${table.keyDigest}) = 32
        and octet_length(${table.requestDigest}) = 32`,
    ),
    check(
      "customer_contact_commands_result_check",
      sql`${table.resultVersion} > 0
        and jsonb_typeof(${table.resultSnapshot}) = 'object'
        and pg_column_size(${table.resultSnapshot}) <= 524288
        and jsonb_array_length(jsonb_path_query_array(
          ${table.resultSnapshot}, '$.keyvalue().key'
        )) = 4
        and ${table.resultSnapshot} ?& array[
          'schemaVersion', 'operation', 'projection', 'resource'
        ]
        and (${table.resultSnapshot} ->> 'schemaVersion')::integer = 1
        and ${table.resultSnapshot} ->> 'projection' in (
          'operator', 'customer', 'unavailable'
        )
        and (
          (${table.resultSnapshot} ->> 'projection' = 'unavailable'
            and ${table.resultSnapshot} -> 'resource' = 'null'::jsonb)
          or
          (${table.resultSnapshot} ->> 'projection' <> 'unavailable'
            and ${table.resultSnapshot} ->> 'operation' = ${table.operation}
            and jsonb_typeof(${table.resultSnapshot} -> 'resource') = 'object')
        )
        and (
          (${table.operation} = 'portal.preference.replace'
            and ${table.resultSnapshot} ->> 'projection' in (
              'customer', 'unavailable'
            ))
          or
          (${table.operation} <> 'portal.preference.replace'
            and ${table.resultSnapshot} ->> 'projection' in (
              'operator', 'unavailable'
            ))
        )
        and (
          ${table.resultSnapshot} ->> 'projection' <> 'customer'
          or (
            jsonb_array_length(jsonb_path_query_array(
              ${table.resultSnapshot} -> 'resource', '$.keyvalue().key'
            )) = 13
            and ${table.resultSnapshot} -> 'resource' ?& array[
              'id', 'firstName', 'lastName', 'email', 'phone', 'function',
              'language', 'timezone', 'notificationCategories',
              'notificationWindows', 'emailAllowed', 'active', 'version'
            ]
            and ${table.resultSnapshot} -> 'resource' ->> 'id' = ${table.resultResourceId}::text
          )
        )
        and (
          ${table.resultSnapshot} ->> 'projection' = 'unavailable'
          and ${table.resultSnapshot} ->> 'operation' = 'legacy.unavailable'
          or ${table.resultSnapshot} ->> 'projection' <> 'unavailable'
          and (${table.resultSnapshot} #>> '{resource,version}')::integer = ${table.resultVersion}
        )
        and (
          ${table.resultSnapshot} ->> 'projection' <> 'operator'
          or ${table.operation} like 'contact.%'
          and jsonb_array_length(jsonb_path_query_array(
            ${table.resultSnapshot} -> 'resource', '$.keyvalue().key'
          )) = 20
          and ${table.resultSnapshot} -> 'resource' ?& array[
            'firstName', 'lastName', 'email', 'phone', 'function',
            'language', 'timezone', 'escalationPriority', 'contactClass',
            'notificationCategories', 'notificationWindows', 'emailAllowed',
            'active', 'tags', 'linkedMembershipId', 'linkedUserId', 'version',
            'createdAt', 'updatedAt', 'archivedAt'
          ]
          or ${table.operation} like 'contact_group.%'
          and jsonb_array_length(jsonb_path_query_array(
            ${table.resultSnapshot} -> 'resource', '$.keyvalue().key'
          )) = 11
          and ${table.resultSnapshot} -> 'resource' ?& array[
            'key', 'version', 'name', 'description', 'mode',
            'ruleSchemaVersion', 'rule', 'memberIds', 'createdAt',
            'updatedAt', 'archivedAt'
          ]
          or ${table.operation} like 'ticket_contact.%'
          and jsonb_array_length(jsonb_path_query_array(
            ${table.resultSnapshot} -> 'resource', '$.keyvalue().key'
          )) = 10
          and ${table.resultSnapshot} -> 'resource' ?& array[
            'ticketKind', 'ticketId', 'contactId', 'role', 'origin',
            'sourceAlertId', 'sourceAlertVersion', 'version', 'createdAt',
            'archivedAt'
          ]
        )`,
    ),
    check(
      "customer_contact_commands_retention_check",
      sql`${table.expiresAt} > ${table.createdAt}
        and ${table.expiresAt} <= ${table.createdAt} + interval '7 days'`,
    ),
  ],
).enableRLS();
