import { sql } from "drizzle-orm";
import {
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
import { tenantMemberships } from "./identity.js";
import { ticketRuntimeOwnerRole } from "./roles.js";
import { tenants } from "./tenancy.js";
import { cases } from "./ticketing.js";

const ownerPolicy = (name: string) =>
  pgPolicy(name, {
    as: "permissive",
    for: "all",
    to: ticketRuntimeOwnerRole,
    using: sql`true`,
    withCheck: sql`true`,
  });

/**
 * Immutable watcher relation events. The latest event for one tenant ticket
 * and target user is the current relation state; retaining both add and remove
 * events lets notification fanout evaluate the relation at event time without
 * rewriting history.
 */
export const ticketWatcherEvents = pgTable(
  "ticket_watcher_events",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    alertId: uuid("alert_id"),
    caseId: uuid("case_id"),
    targetUserId: uuid("target_user_id").notNull(),
    action: text("action").notNull(),
    displayNameSnapshot: text("display_name_snapshot").notNull(),
    ticketVersion: integer("ticket_version").notNull(),
    actorMembershipId: uuid("actor_membership_id").notNull(),
    actorUserId: uuid("actor_user_id").notNull(),
    occurredAt: timestamp("occurred_at", {
      withTimezone: true,
      mode: "date",
    })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    unique("ticket_watcher_events_tenant_id_key").on(table.tenantId, table.id),
    uniqueIndex("ticket_watcher_events_alert_version_key")
      .on(table.tenantId, table.alertId, table.ticketVersion)
      .where(sql`${table.alertId} is not null`),
    uniqueIndex("ticket_watcher_events_case_version_key")
      .on(table.tenantId, table.caseId, table.ticketVersion)
      .where(sql`${table.caseId} is not null`),
    foreignKey({
      name: "ticket_watcher_events_alert_fk",
      columns: [table.tenantId, table.alertId],
      foreignColumns: [alerts.tenantId, alerts.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "ticket_watcher_events_case_fk",
      columns: [table.tenantId, table.caseId],
      foreignColumns: [cases.tenantId, cases.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "ticket_watcher_events_target_membership_fk",
      columns: [table.tenantId, table.targetUserId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.userId],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "ticket_watcher_events_actor_fk",
      columns: [table.tenantId, table.actorMembershipId, table.actorUserId],
      foreignColumns: [
        tenantMemberships.tenantId,
        tenantMemberships.id,
        tenantMemberships.userId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    index("ticket_watcher_events_alert_target_history_idx").on(
      table.tenantId,
      table.alertId,
      table.targetUserId,
      table.ticketVersion,
    ),
    index("ticket_watcher_events_case_target_history_idx").on(
      table.tenantId,
      table.caseId,
      table.targetUserId,
      table.ticketVersion,
    ),
    check(
      "ticket_watcher_events_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "ticket_watcher_events_resource_check",
      sql`(${table.alertId} is null) <> (${table.caseId} is null)`,
    ),
    check(
      "ticket_watcher_events_action_check",
      sql`${table.action} in ('add','remove')`,
    ),
    check(
      "ticket_watcher_events_display_name_check",
      sql`app.private_ticket_watcher_display_name_valid_v1(${table.displayNameSnapshot})`,
    ),
    check(
      "ticket_watcher_events_version_check",
      sql`${table.ticketVersion} between 2 and 2147483647`,
    ),
    ownerPolicy("ticket_watcher_events_owner_access"),
  ],
).enableRLS();

/** Exact immutable command results retained for historical idempotent replay. */
export const ticketWatcherCommands = pgTable(
  "ticket_watcher_commands",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    alertId: uuid("alert_id"),
    caseId: uuid("case_id"),
    actorMembershipId: uuid("actor_membership_id").notNull(),
    actorUserId: uuid("actor_user_id").notNull(),
    targetUserId: uuid("target_user_id").notNull(),
    action: text("action").notNull(),
    keyDigest: bytea("key_digest").notNull(),
    requestDigest: bytea("request_digest").notNull(),
    resultVersion: integer("result_version").notNull(),
    resultUpdatedAt: timestamp("result_updated_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    resultProjection: jsonb("result_projection")
      .$type<Record<string, unknown>>()
      .notNull(),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    unique("ticket_watcher_commands_tenant_id_key").on(
      table.tenantId,
      table.id,
    ),
    unique("ticket_watcher_commands_replay_key").on(
      table.tenantId,
      table.actorMembershipId,
      table.keyDigest,
    ),
    foreignKey({
      name: "ticket_watcher_commands_alert_fk",
      columns: [table.tenantId, table.alertId],
      foreignColumns: [alerts.tenantId, alerts.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "ticket_watcher_commands_case_fk",
      columns: [table.tenantId, table.caseId],
      foreignColumns: [cases.tenantId, cases.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "ticket_watcher_commands_actor_fk",
      columns: [table.tenantId, table.actorMembershipId, table.actorUserId],
      foreignColumns: [
        tenantMemberships.tenantId,
        tenantMemberships.id,
        tenantMemberships.userId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "ticket_watcher_commands_target_membership_fk",
      columns: [table.tenantId, table.targetUserId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.userId],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    index("ticket_watcher_commands_ticket_idx").on(
      table.tenantId,
      table.alertId,
      table.caseId,
      table.createdAt,
      table.id,
    ),
    check(
      "ticket_watcher_commands_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "ticket_watcher_commands_resource_check",
      sql`(${table.alertId} is null) <> (${table.caseId} is null)`,
    ),
    check(
      "ticket_watcher_commands_action_check",
      sql`${table.action} in ('add','remove')`,
    ),
    check(
      "ticket_watcher_commands_digest_check",
      sql`octet_length(${table.keyDigest}) = 32
        and octet_length(${table.requestDigest}) = 32`,
    ),
    check(
      "ticket_watcher_commands_result_check",
      sql`${table.resultVersion} between 1 and 2147483647
        and ${table.resultUpdatedAt} <= ${table.createdAt}
        and jsonb_typeof(${table.resultProjection}) = 'object'
        and octet_length(${table.resultProjection}::text) <= 1048576`,
    ),
    ownerPolicy("ticket_watcher_commands_owner_access"),
  ],
).enableRLS();
