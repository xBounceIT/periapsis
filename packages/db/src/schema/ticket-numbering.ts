import { relations, sql } from "drizzle-orm";
import {
  bigint,
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
import { ticketAggregateKind, ticketNumberingPeriod } from "./enums.js";
import { tenantMemberships, users } from "./identity.js";
import { tenants } from "./tenancy.js";

export const tenantTicketNumberingPolicyVersions = pgTable(
  "tenant_ticket_numbering_policy_versions",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    aggregateKind: ticketAggregateKind("aggregate_kind").notNull(),
    version: integer("version").notNull(),
    prefix: text("prefix").notNull(),
    separator: text("separator").notNull(),
    period: ticketNumberingPeriod("period").notNull(),
    width: integer("width").notNull(),
    start: bigint("start", { mode: "number" }).notNull(),
    namespaceDigest: bytea("namespace_digest").notNull(),
    // The system-created version 1 has no human publisher. Administrative
    // replacements always persist the live actor membership.
    publishedByMembershipId: uuid("published_by_membership_id"),
    publishedAt: timestamp("published_at", {
      withTimezone: true,
      mode: "date",
    })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    unique("tenant_ticket_numbering_policy_versions_coordinate_key").on(
      table.tenantId,
      table.aggregateKind,
      table.version,
    ),
    unique("tenant_ticket_numbering_policy_versions_identity_key").on(
      table.tenantId,
      table.aggregateKind,
      table.id,
      table.version,
    ),
    foreignKey({
      name: "tenant_ticket_numbering_policy_versions_publisher_fk",
      columns: [table.tenantId, table.publishedByMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    }).onDelete("restrict"),
    check(
      "tenant_ticket_numbering_policy_versions_identity_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true
        and ${table.version} between 1 and 2147483647
        and (${table.version} = 1 or ${table.publishedByMembershipId} is not null)`,
    ),
    check(
      "tenant_ticket_numbering_policy_versions_format_check",
      sql`${table.prefix} ~ '^[A-Z][A-Z0-9]{0,11}$'
        and ${table.separator} in ('-', '/', '.', '_')
        and ${table.width} between 4 and 12
        and ${table.start} between 1 and repeat('9', ${table.width})::bigint
        and octet_length(${table.namespaceDigest}) = 32`,
    ),
  ],
).enableRLS();

export const tenantTicketNumberingPolicies = pgTable(
  "tenant_ticket_numbering_policies",
  {
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    aggregateKind: ticketAggregateKind("aggregate_kind").notNull(),
    currentVersion: integer("current_version").notNull(),
    updatedAt: timestamp("updated_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    primaryKey({
      name: "tenant_ticket_numbering_policies_pkey",
      columns: [table.tenantId, table.aggregateKind],
    }),
    foreignKey({
      name: "tenant_ticket_numbering_policies_current_version_fk",
      columns: [table.tenantId, table.aggregateKind, table.currentVersion],
      foreignColumns: [
        tenantTicketNumberingPolicyVersions.tenantId,
        tenantTicketNumberingPolicyVersions.aggregateKind,
        tenantTicketNumberingPolicyVersions.version,
      ],
    }).onDelete("restrict"),
    check(
      "tenant_ticket_numbering_policies_revision_check",
      sql`${table.currentVersion} between 1 and 2147483647`,
    ),
  ],
).enableRLS();

export const tenantTicketNumberingReceipts = pgTable(
  "tenant_ticket_numbering_receipts",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    aggregateKind: ticketAggregateKind("aggregate_kind").notNull(),
    aggregateId: uuid("aggregate_id").notNull(),
    policyVersionId: uuid("policy_version_id").notNull(),
    policyVersion: integer("policy_version").notNull(),
    namespaceDigest: bytea("namespace_digest").notNull(),
    period: integer("period").notNull(),
    sequence: bigint("sequence", { mode: "number" }).notNull(),
    number: text("number").notNull(),
    allocatedAt: timestamp("allocated_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
  },
  (table) => [
    unique("tenant_ticket_numbering_receipts_aggregate_key").on(
      table.tenantId,
      table.aggregateKind,
      table.aggregateId,
    ),
    unique("tenant_ticket_numbering_receipts_number_key").on(
      table.tenantId,
      table.aggregateKind,
      table.number,
    ),
    unique("tenant_ticket_numbering_receipts_sequence_key").on(
      table.tenantId,
      table.aggregateKind,
      table.namespaceDigest,
      table.period,
      table.sequence,
    ),
    foreignKey({
      name: "tenant_ticket_numbering_receipts_policy_fk",
      columns: [
        table.tenantId,
        table.aggregateKind,
        table.policyVersionId,
        table.policyVersion,
      ],
      foreignColumns: [
        tenantTicketNumberingPolicyVersions.tenantId,
        tenantTicketNumberingPolicyVersions.aggregateKind,
        tenantTicketNumberingPolicyVersions.id,
        tenantTicketNumberingPolicyVersions.version,
      ],
    }).onDelete("restrict"),
    check(
      "tenant_ticket_numbering_receipts_identity_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true
        and (uuid_extract_version(${table.aggregateId}) = 7) is true
        and ${table.policyVersion} between 1 and 2147483647`,
    ),
    check(
      "tenant_ticket_numbering_receipts_value_check",
      sql`octet_length(${table.namespaceDigest}) = 32
        and (${table.period} = 0 or ${table.period} between 2000 and 9999)
        and ${table.sequence} between 1 and 999999999999
        and btrim(${table.number}) = ${table.number}
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
  ],
).enableRLS();

export const tenantTicketNumberingCommands = pgTable(
  "tenant_ticket_numbering_commands",
  {
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    userId: uuid("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "restrict" }),
    aggregateKind: ticketAggregateKind("aggregate_kind").notNull(),
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
      name: "tenant_ticket_numbering_commands_pkey",
      columns: [
        table.tenantId,
        table.userId,
        table.aggregateKind,
        table.operation,
        table.keyDigest,
      ],
    }),
    foreignKey({
      name: "tenant_ticket_numbering_commands_policy_fk",
      columns: [table.tenantId, table.aggregateKind],
      foreignColumns: [
        tenantTicketNumberingPolicies.tenantId,
        tenantTicketNumberingPolicies.aggregateKind,
      ],
    }).onDelete("restrict"),
    index("tenant_ticket_numbering_commands_expiry_idx").on(table.expiresAt),
    check(
      "tenant_ticket_numbering_commands_envelope_check",
      sql`${table.operation} = 'ticket_numbering.policy.replace'
        and octet_length(${table.keyDigest}) = 32
        and octet_length(${table.requestDigest}) = 32
        and jsonb_typeof(${table.result}) = 'object'
        and octet_length(${table.result}::text) <= 8192
        and ${table.expiresAt} > ${table.createdAt}`,
    ),
  ],
).enableRLS();

export const tenantTicketNumberingPolicyVersionsRelations = relations(
  tenantTicketNumberingPolicyVersions,
  ({ one }) => ({
    tenant: one(tenants, {
      fields: [tenantTicketNumberingPolicyVersions.tenantId],
      references: [tenants.id],
    }),
    publisher: one(tenantMemberships, {
      fields: [
        tenantTicketNumberingPolicyVersions.tenantId,
        tenantTicketNumberingPolicyVersions.publishedByMembershipId,
      ],
      references: [tenantMemberships.tenantId, tenantMemberships.id],
    }),
  }),
);

export const tenantTicketNumberingPoliciesRelations = relations(
  tenantTicketNumberingPolicies,
  ({ one }) => ({
    currentVersion: one(tenantTicketNumberingPolicyVersions, {
      fields: [
        tenantTicketNumberingPolicies.tenantId,
        tenantTicketNumberingPolicies.aggregateKind,
        tenantTicketNumberingPolicies.currentVersion,
      ],
      references: [
        tenantTicketNumberingPolicyVersions.tenantId,
        tenantTicketNumberingPolicyVersions.aggregateKind,
        tenantTicketNumberingPolicyVersions.version,
      ],
    }),
  }),
);

export const tenantTicketNumberingReceiptsRelations = relations(
  tenantTicketNumberingReceipts,
  ({ one }) => ({
    policyVersion: one(tenantTicketNumberingPolicyVersions, {
      fields: [
        tenantTicketNumberingReceipts.tenantId,
        tenantTicketNumberingReceipts.aggregateKind,
        tenantTicketNumberingReceipts.policyVersionId,
        tenantTicketNumberingReceipts.policyVersion,
      ],
      references: [
        tenantTicketNumberingPolicyVersions.tenantId,
        tenantTicketNumberingPolicyVersions.aggregateKind,
        tenantTicketNumberingPolicyVersions.id,
        tenantTicketNumberingPolicyVersions.version,
      ],
    }),
  }),
);
