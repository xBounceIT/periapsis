import { relations, sql } from "drizzle-orm";
import {
  check,
  foreignKey,
  index,
  integer,
  jsonb,
  pgTable,
  primaryKey,
  text,
  timestamp,
  unique,
  uuid,
} from "drizzle-orm/pg-core";

import { bytea } from "./binary.js";
import {
  notificationAudience,
  notificationEventType,
  notificationObjectType,
} from "./enums.js";
import { tenantMemberships, users } from "./identity.js";
import { outboxEvents } from "./outbox.js";
import { tenants } from "./tenancy.js";

export const tenantNotificationInboxStates = pgTable(
  "tenant_notification_inbox_states",
  {
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    userId: uuid("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "restrict" }),
    revision: integer("revision").notNull().default(0),
    updatedAt: timestamp("updated_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    primaryKey({
      name: "tenant_notification_inbox_states_pkey",
      columns: [table.tenantId, table.userId],
    }),
    foreignKey({
      name: "tenant_notification_inbox_states_membership_fk",
      columns: [table.tenantId, table.userId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.userId],
    }).onDelete("restrict"),
    check(
      "tenant_notification_inbox_states_revision_check",
      sql`${table.revision} between 0 and 2147483647`,
    ),
  ],
).enableRLS();

export const tenantNotificationInboxItems = pgTable(
  "tenant_notification_inbox_items",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    userId: uuid("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "restrict" }),
    eventId: uuid("event_id").notNull(),
    audience: notificationAudience("audience").notNull(),
    eventType: notificationEventType("event_type").notNull(),
    resourceKind: notificationObjectType("resource_kind").notNull(),
    resourceId: uuid("resource_id").notNull(),
    resourceVersion: integer("resource_version").notNull(),
    title: text("title").notNull(),
    summary: text("summary").notNull().default(""),
    occurredAt: timestamp("occurred_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    readAt: timestamp("read_at", { withTimezone: true, mode: "date" }),
    revision: integer("revision").notNull().default(1),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    unique("tenant_notification_inbox_items_tenant_id_id_key").on(
      table.tenantId,
      table.id,
    ),
    unique("tenant_notification_inbox_items_event_user_key").on(
      table.tenantId,
      table.eventId,
      table.userId,
    ),
    foreignKey({
      name: "tenant_notification_inbox_items_state_fk",
      columns: [table.tenantId, table.userId],
      foreignColumns: [
        tenantNotificationInboxStates.tenantId,
        tenantNotificationInboxStates.userId,
      ],
    }).onDelete("restrict"),
    foreignKey({
      name: "tenant_notification_inbox_items_event_fk",
      columns: [table.tenantId, table.eventId],
      foreignColumns: [outboxEvents.tenantId, outboxEvents.id],
    }).onDelete("restrict"),
    index("tenant_notification_inbox_items_personal_cursor_idx").on(
      table.tenantId,
      table.userId,
      table.audience,
      table.id.desc(),
    ),
    index("tenant_notification_inbox_items_personal_unread_cursor_idx")
      .on(table.tenantId, table.userId, table.audience, table.id.desc())
      .where(sql`${table.readAt} is null`),
    check(
      "tenant_notification_inbox_items_identity_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true
        and (uuid_extract_version(${table.eventId}) = 7) is true
        and (uuid_extract_version(${table.resourceId}) = 7) is true`,
    ),
    check(
      "tenant_notification_inbox_items_revision_check",
      sql`${table.resourceVersion} between 1 and 2147483647
        and ${table.revision} between 1 and 2147483647`,
    ),
    check(
      "tenant_notification_inbox_items_text_check",
      sql`btrim(${table.title}) <> ''
        and octet_length(${table.title}) <= 240
        and ${table.title} !~ '[[:cntrl:]]'
        and ${table.title} !~ U&'[\\202A-\\202E\\2066-\\2069\\200E\\200F\\061C]'
        and octet_length(${table.summary}) <= 2000
        and ${table.summary} !~ '[[:cntrl:]]'
        and ${table.summary} !~ U&'[\\202A-\\202E\\2066-\\2069\\200E\\200F\\061C]'`,
    ),
    check(
      "tenant_notification_inbox_items_time_check",
      sql`${table.occurredAt} <= ${table.createdAt}
        and ${table.updatedAt} >= ${table.createdAt}
        and (${table.readAt} is null or (
          ${table.readAt} >= ${table.occurredAt}
          and ${table.readAt} <= ${table.updatedAt}
        ))`,
    ),
    check(
      "tenant_notification_inbox_items_event_resource_check",
      sql`case
        when ${table.eventType} in (
          'alert.created', 'alert.assigned', 'alert.claimed',
          'alert.status_changed', 'alert.escalated', 'alert.watcher_added',
          'alert.watcher_removed'
        ) then ${table.resourceKind} = 'alert'
        when ${table.eventType} in (
          'case.created', 'case.assigned', 'case.claimed', 'case.transferred',
          'case.status_changed', 'case.watcher_added', 'case.watcher_removed'
        ) then ${table.resourceKind} = 'case'
        when ${table.eventType} in (
          'comment.public_added', 'comment.private_added',
          'sla.warning', 'sla.breached'
        ) then ${table.resourceKind} in ('alert', 'case')
        when ${table.eventType} = 'contact.changed'
          then ${table.resourceKind} = 'contact'
        when ${table.eventType} = 'task.assigned'
          then ${table.resourceKind} = 'task'
        when ${table.eventType} = 'evidence.added'
          then ${table.resourceKind} = 'evidence'
        when ${table.eventType} = 'webhook.custom' then true
        else false
      end`,
    ),
    check(
      "tenant_notification_inbox_items_customer_event_check",
      sql`${table.audience} <> 'customer' or ${table.eventType} not in (
        'alert.watcher_added', 'alert.watcher_removed',
        'case.watcher_added', 'case.watcher_removed',
        'comment.private_added'
      )`,
    ),
  ],
).enableRLS();

export const tenantNotificationInboxCommands = pgTable(
  "tenant_notification_inbox_commands",
  {
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    userId: uuid("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "restrict" }),
    operation: text("operation").notNull(),
    keyDigest: bytea("key_digest").notNull(),
    requestDigest: bytea("request_digest").notNull(),
    result: jsonb("result").$type<Record<string, unknown>>().notNull(),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    expiresAt: timestamp("expires_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
  },
  (table) => [
    primaryKey({
      name: "tenant_notification_inbox_commands_pkey",
      columns: [table.tenantId, table.userId, table.operation, table.keyDigest],
    }),
    foreignKey({
      name: "tenant_notification_inbox_commands_state_fk",
      columns: [table.tenantId, table.userId],
      foreignColumns: [
        tenantNotificationInboxStates.tenantId,
        tenantNotificationInboxStates.userId,
      ],
    }).onDelete("restrict"),
    index("tenant_notification_inbox_commands_expiry_idx").on(table.expiresAt),
    check(
      "tenant_notification_inbox_commands_operation_check",
      sql`${table.operation} in (
        'notification_inbox.set_read_state',
        'notification_inbox.mark_all_read'
      )`,
    ),
    check(
      "tenant_notification_inbox_commands_digest_check",
      sql`octet_length(${table.keyDigest}) = 32
        and octet_length(${table.requestDigest}) = 32`,
    ),
    check(
      "tenant_notification_inbox_commands_result_check",
      sql`jsonb_typeof(${table.result}) = 'object'
        and octet_length(${table.result}::text) <= 16384
        and ${table.expiresAt} > ${table.createdAt}`,
    ),
  ],
).enableRLS();

export const tenantNotificationInboxStatesRelations = relations(
  tenantNotificationInboxStates,
  ({ many, one }) => ({
    tenant: one(tenants, {
      fields: [tenantNotificationInboxStates.tenantId],
      references: [tenants.id],
    }),
    user: one(users, {
      fields: [tenantNotificationInboxStates.userId],
      references: [users.id],
    }),
    membership: one(tenantMemberships, {
      fields: [
        tenantNotificationInboxStates.tenantId,
        tenantNotificationInboxStates.userId,
      ],
      references: [tenantMemberships.tenantId, tenantMemberships.userId],
    }),
    items: many(tenantNotificationInboxItems),
    commands: many(tenantNotificationInboxCommands),
  }),
);

export const tenantNotificationInboxItemsRelations = relations(
  tenantNotificationInboxItems,
  ({ one }) => ({
    state: one(tenantNotificationInboxStates, {
      fields: [
        tenantNotificationInboxItems.tenantId,
        tenantNotificationInboxItems.userId,
      ],
      references: [
        tenantNotificationInboxStates.tenantId,
        tenantNotificationInboxStates.userId,
      ],
    }),
    event: one(outboxEvents, {
      fields: [
        tenantNotificationInboxItems.tenantId,
        tenantNotificationInboxItems.eventId,
      ],
      references: [outboxEvents.tenantId, outboxEvents.id],
    }),
  }),
);

export const tenantNotificationInboxCommandsRelations = relations(
  tenantNotificationInboxCommands,
  ({ one }) => ({
    state: one(tenantNotificationInboxStates, {
      fields: [
        tenantNotificationInboxCommands.tenantId,
        tenantNotificationInboxCommands.userId,
      ],
      references: [
        tenantNotificationInboxStates.tenantId,
        tenantNotificationInboxStates.userId,
      ],
    }),
  }),
);
