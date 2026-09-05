import { sql } from "drizzle-orm";
import {
  check,
  foreignKey,
  index,
  integer,
  pgTable,
  text,
  timestamp,
  unique,
  uuid,
} from "drizzle-orm/pg-core";

import { bytea } from "./binary.js";
import { membershipStatus } from "./enums.js";
import { tenantMemberships } from "./identity.js";
import { tenants } from "./tenancy.js";

/**
 * Durable, payload-bound receipts for tenant membership suspend/reactivate
 * commands. Runtime roles have no direct policy on this ledger; the guarded
 * SECURITY DEFINER lifecycle ABI is its only write and replay boundary.
 */
export const tenantMembershipLifecycleCommands = pgTable(
  "tenant_membership_lifecycle_commands",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    actorMembershipId: uuid("actor_membership_id").notNull(),
    targetMembershipId: uuid("target_membership_id").notNull(),
    targetUserId: uuid("target_user_id").notNull(),
    operation: text("operation").notNull(),
    keyDigest: bytea("key_digest").notNull(),
    requestDigest: bytea("request_digest").notNull(),
    expectedRevision: integer("expected_revision").notNull(),
    previousStatus: membershipStatus("previous_status").notNull(),
    resultStatus: membershipStatus("result_status").notNull(),
    resultRevision: integer("result_revision").notNull(),
    resultUpdatedAt: timestamp("result_updated_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    revokedSessionCount: integer("revoked_session_count").notNull().default(0),
    revokedContinuationCount: integer("revoked_continuation_count")
      .notNull()
      .default(0),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    expiresAt: timestamp("expires_at", { withTimezone: true, mode: "date" })
      .notNull()
      .default(sql`now() + interval '24 hours'`),
  },
  (table) => [
    unique("tenant_membership_lifecycle_commands_tenant_id_key").on(
      table.tenantId,
      table.id,
    ),
    unique("tenant_membership_lifecycle_commands_replay_key").on(
      table.tenantId,
      table.actorMembershipId,
      table.keyDigest,
    ),
    foreignKey({
      name: "tenant_membership_lifecycle_commands_actor_fk",
      columns: [table.tenantId, table.actorMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_membership_lifecycle_commands_target_fk",
      columns: [table.tenantId, table.targetMembershipId, table.targetUserId],
      foreignColumns: [
        tenantMemberships.tenantId,
        tenantMemberships.id,
        tenantMemberships.userId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    index("tenant_membership_lifecycle_commands_expiry_idx").on(
      table.expiresAt,
    ),
    check(
      "tenant_membership_lifecycle_commands_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "tenant_membership_lifecycle_commands_digest_check",
      sql`octet_length(${table.keyDigest}) = 32
        and octet_length(${table.requestDigest}) = 32`,
    ),
    check(
      "tenant_membership_lifecycle_commands_transition_check",
      sql`(${table.operation} = 'tenant_membership.suspend'
          and ${table.previousStatus} = 'active'
          and ${table.resultStatus} = 'suspended')
        or (${table.operation} = 'tenant_membership.reactivate'
          and ${table.previousStatus} = 'suspended'
          and ${table.resultStatus} = 'active')`,
    ),
    check(
      "tenant_membership_lifecycle_commands_revision_check",
      sql`${table.expectedRevision} between 1 and 2147483646
        and ${table.resultRevision} = ${table.expectedRevision} + 1`,
    ),
    check(
      "tenant_membership_lifecycle_commands_consequence_check",
      sql`${table.revokedSessionCount} >= 0
        and ${table.revokedContinuationCount} >= 0
        and (${table.operation} = 'tenant_membership.suspend'
          or (${table.revokedSessionCount} = 0
            and ${table.revokedContinuationCount} = 0))`,
    ),
    check(
      "tenant_membership_lifecycle_commands_retention_check",
      sql`${table.resultUpdatedAt} >= ${table.createdAt}
        and ${table.expiresAt} > ${table.createdAt}
        and ${table.expiresAt} <= ${table.createdAt} + interval '7 days'`,
    ),
  ],
).enableRLS();
