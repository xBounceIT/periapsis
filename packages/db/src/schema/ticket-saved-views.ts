import { sql } from "drizzle-orm";
import {
  check,
  customType,
  foreignKey,
  index,
  integer,
  pgPolicy,
  pgTable,
  primaryKey,
  text,
  timestamp,
  unique,
  uuid,
} from "drizzle-orm/pg-core";

import { bytea } from "./binary.js";
import { ticketAggregateKind } from "./enums.js";
import { tenantMemberships } from "./identity.js";
import { ticketSavedViewOwnerRole } from "./roles.js";
import { tenants } from "./tenancy.js";

// Saved-view canonical JSON is byte-addressed by SHA-256. Its collation is
// fixed explicitly so a database/cluster locale change cannot alter equality
// or uniqueness behavior around the persisted security document.
const canonicalText = customType<{ data: string; driverData: string }>({
  dataType() {
    return 'text COLLATE "C"';
  },
});

export const ticketSavedViews = pgTable(
  "ticket_saved_views",
  {
    id: uuid("id").notNull(),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    ownerMembershipId: uuid("owner_membership_id").notNull(),
    aggregateKind: ticketAggregateKind("aggregate_kind").notNull(),
    name: canonicalText("name").notNull(),
    specCanonical: canonicalText("spec_canonical").notNull(),
    specDigest: bytea("spec_digest").notNull(),
    status: text("status").notNull(),
    revision: integer("revision").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    archivedAt: timestamp("archived_at", { withTimezone: true, mode: "date" }),
  },
  (table) => [
    primaryKey({ name: "ticket_saved_views_pkey", columns: [table.id] }),
    unique("ticket_saved_views_tenant_id_id_key").on(table.tenantId, table.id),
    foreignKey({
      name: "ticket_saved_views_owner_fk",
      columns: [table.tenantId, table.ownerMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    index("ticket_saved_views_owner_list_idx").on(
      table.tenantId,
      table.ownerMembershipId,
      table.aggregateKind,
      table.id,
    ),
    check(
      "ticket_saved_views_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "ticket_saved_views_name_check",
      sql`btrim(${table.name}) <> ''
        and octet_length(${table.name}) <= 120
        and ${table.name} !~ '[[:cntrl:]\u200e\u200f\u202a-\u202e\u2066-\u2069]'`,
    ),
    check(
      "ticket_saved_views_spec_check",
      sql`octet_length(${table.specCanonical}) between 1 and 262144
        and octet_length(${table.specDigest}) = 32`,
    ),
    check(
      "ticket_saved_views_lifecycle_check",
      sql`${table.status} in ('active', 'archived')
        and ${table.revision} between 1 and 2147483647
        and ${table.updatedAt} >= ${table.createdAt}
        and (${table.status} = 'archived') = (${table.archivedAt} is not null)
        and (${table.archivedAt} is null
          or ${table.archivedAt} between ${table.createdAt} and ${table.updatedAt})`,
    ),
    pgPolicy("ticket_saved_views_owner_access", {
      as: "permissive",
      for: "all",
      to: ticketSavedViewOwnerRole,
      using: sql`true`,
      withCheck: sql`true`,
    }),
  ],
).enableRLS();

export const ticketSavedViewCommands = pgTable(
  "ticket_saved_view_commands",
  {
    id: uuid("id").notNull(),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    actorUserId: uuid("actor_user_id").notNull(),
    ownerMembershipId: uuid("owner_membership_id").notNull(),
    aggregateKind: ticketAggregateKind("aggregate_kind").notNull(),
    action: text("action").notNull(),
    idempotencyKeyDigest: bytea("idempotency_key_digest").notNull(),
    requestFingerprintDigest: bytea("request_fingerprint_digest").notNull(),
    expectedRevision: integer("expected_revision").notNull(),
    nextRevision: integer("next_revision").notNull(),
    resultViewId: uuid("result_view_id").notNull(),
    resultName: canonicalText("result_name").notNull(),
    resultSpecCanonical: canonicalText("result_spec_canonical").notNull(),
    resultSpecDigest: bytea("result_spec_digest").notNull(),
    resultStatus: text("result_status").notNull(),
    resultCreatedAt: timestamp("result_created_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    resultUpdatedAt: timestamp("result_updated_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    resultArchivedAt: timestamp("result_archived_at", {
      withTimezone: true,
      mode: "date",
    }),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    expiresAt: timestamp("expires_at", { withTimezone: true, mode: "date" })
      .notNull()
      .default(sql`now() + interval '30 days'`),
  },
  (table) => [
    primaryKey({
      name: "ticket_saved_view_commands_pkey",
      columns: [table.id],
    }),
    unique("ticket_saved_view_commands_tenant_id_id_key").on(
      table.tenantId,
      table.id,
    ),
    unique("ticket_saved_view_commands_replay_key").on(
      table.tenantId,
      table.actorUserId,
      table.ownerMembershipId,
      table.aggregateKind,
      table.action,
      table.idempotencyKeyDigest,
    ),
    foreignKey({
      name: "ticket_saved_view_commands_actor_owner_fk",
      columns: [table.tenantId, table.ownerMembershipId, table.actorUserId],
      foreignColumns: [
        tenantMemberships.tenantId,
        tenantMemberships.id,
        tenantMemberships.userId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "ticket_saved_view_commands_result_fk",
      columns: [table.tenantId, table.resultViewId],
      foreignColumns: [ticketSavedViews.tenantId, ticketSavedViews.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    index("ticket_saved_view_commands_expiry_idx").on(
      table.expiresAt,
      table.tenantId,
      table.id,
    ),
    check(
      "ticket_saved_view_commands_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "ticket_saved_view_commands_action_check",
      sql`${table.action} in ('create', 'replace', 'archive', 'restore')
        and ${table.expectedRevision} between 0 and 2147483646
        and ${table.nextRevision} = ${table.expectedRevision} + 1
        and (${table.action} = 'create') = (${table.expectedRevision} = 0)`,
    ),
    check(
      "ticket_saved_view_commands_digest_check",
      sql`octet_length(${table.idempotencyKeyDigest}) = 32
        and octet_length(${table.requestFingerprintDigest}) = 32
        and octet_length(${table.resultSpecDigest}) = 32`,
    ),
    check(
      "ticket_saved_view_commands_result_check",
      sql`(uuid_extract_version(${table.resultViewId}) = 7) is true
        and btrim(${table.resultName}) <> ''
        and octet_length(${table.resultName}) <= 120
        and ${table.resultName} !~ '[[:cntrl:]\u200e\u200f\u202a-\u202e\u2066-\u2069]'
        and octet_length(${table.resultSpecCanonical}) between 1 and 262144
        and ${table.resultStatus} in ('active', 'archived')
        and ${table.nextRevision} between 1 and 2147483647
        and ${table.resultUpdatedAt} >= ${table.resultCreatedAt}
        and (${table.resultStatus} = 'archived') = (${table.resultArchivedAt} is not null)
        and (${table.resultArchivedAt} is null
          or ${table.resultArchivedAt} between ${table.resultCreatedAt} and ${table.resultUpdatedAt})
        and (${table.action} = 'archive') = (${table.resultStatus} = 'archived')`,
    ),
    check(
      "ticket_saved_view_commands_retention_check",
      sql`${table.expiresAt} >= ${table.createdAt} + interval '24 hours'
        and ${table.expiresAt} <= ${table.createdAt} + interval '90 days'`,
    ),
    pgPolicy("ticket_saved_view_commands_owner_access", {
      as: "permissive",
      for: "all",
      to: ticketSavedViewOwnerRole,
      using: sql`true`,
      withCheck: sql`true`,
    }),
  ],
).enableRLS();
