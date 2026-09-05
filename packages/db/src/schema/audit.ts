import { sql } from "drizzle-orm";
import {
  bigint,
  char,
  check,
  foreignKey,
  index,
  inet,
  jsonb,
  pgPolicy,
  pgTable,
  text,
  timestamp,
  unique,
  uuid,
} from "drizzle-orm/pg-core";

import { auditActorType, auditOutcome } from "./enums.js";
import {
  activeActorMembershipFor,
  tenantMemberships,
  users,
} from "./identity.js";
import { currentTenantId } from "./context.js";
import {
  apiRole,
  auditReaderOwnerRole,
  auditorRole,
  migratorRole,
  notifierRole,
  workerRole,
} from "./roles.js";
import { tenantServiceAccounts } from "./service-accounts.js";
import { tenants } from "./tenancy.js";

export type AuditDiff = Record<string, unknown> | null;

export const auditEvents = pgTable(
  "audit_events",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    sequence: bigint("sequence", {
      mode: "bigint",
    }).notNull(),
    occurredAt: timestamp("occurred_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    actorType: auditActorType("actor_type").notNull(),
    actorUserId: uuid("actor_user_id").references(() => users.id, {
      onDelete: "restrict",
    }),
    actorServiceAccountId: uuid("actor_service_account_id"),
    impersonatedByUserId: uuid("impersonated_by_user_id").references(
      () => users.id,
      {
        onDelete: "restrict",
      },
    ),
    action: text("action").notNull(),
    resourceType: text("resource_type").notNull(),
    resourceId: uuid("resource_id"),
    requestId: uuid("request_id"),
    correlationId: uuid("correlation_id"),
    ipAddress: inet("ip_address"),
    userAgent: text("user_agent"),
    authenticationMethod: text("authentication_method"),
    outcome: auditOutcome("outcome").notNull(),
    reason: text("reason"),
    before: jsonb("before").$type<AuditDiff>(),
    after: jsonb("after").$type<AuditDiff>(),
    metadata: jsonb("metadata")
      .$type<Record<string, unknown>>()
      .notNull()
      .default({}),
    previousHash: char("previous_hash", { length: 64 })
      .notNull()
      .default(
        "0000000000000000000000000000000000000000000000000000000000000000",
      ),
    eventHash: char("event_hash", { length: 64 })
      .notNull()
      .default(
        "0000000000000000000000000000000000000000000000000000000000000000",
      ),
  },
  (table) => [
    unique("audit_events_tenant_sequence_key").on(
      table.tenantId,
      table.sequence,
    ),
    index("audit_events_tenant_time_idx").on(
      table.tenantId,
      table.occurredAt,
      table.id,
    ),
    index("audit_events_tenant_resource_idx").on(
      table.tenantId,
      table.resourceType,
      table.resourceId,
    ),
    index("audit_events_tenant_action_sequence_idx").on(
      table.tenantId,
      table.action,
      table.sequence,
    ),
    index("audit_events_tenant_outcome_sequence_idx").on(
      table.tenantId,
      table.outcome,
      table.sequence,
    ),
    index("audit_events_tenant_actor_user_sequence_idx").on(
      table.tenantId,
      table.actorUserId,
      table.sequence,
    ),
    index("audit_events_tenant_actor_service_sequence_idx").on(
      table.tenantId,
      table.actorServiceAccountId,
      table.sequence,
    ),
    foreignKey({
      name: "audit_events_actor_membership_fk",
      columns: [table.tenantId, table.actorUserId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.userId],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "audit_events_actor_service_account_fk",
      columns: [table.tenantId, table.actorServiceAccountId],
      foreignColumns: [
        tenantServiceAccounts.tenantId,
        tenantServiceAccounts.id,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "audit_events_impersonator_membership_fk",
      columns: [table.tenantId, table.impersonatedByUserId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.userId],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "audit_events_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "audit_events_action_not_blank_check",
      sql`btrim(${table.action}) <> ''`,
    ),
    check(
      "audit_events_resource_type_not_blank_check",
      sql`btrim(${table.resourceType}) <> ''`,
    ),
    check(
      "audit_events_actor_consistency_check",
      sql`(${table.actorType} = 'user'
          and ${table.actorUserId} is not null
          and ${table.actorServiceAccountId} is null)
        or (${table.actorType} = 'service_account'
          and ${table.actorUserId} is null
          and ${table.actorServiceAccountId} is not null
          and ${table.impersonatedByUserId} is null)
        or (${table.actorType} = 'system'
          and ${table.actorUserId} is null
          and ${table.actorServiceAccountId} is null
          and ${table.impersonatedByUserId} is null)`,
    ),
    check(
      "audit_events_previous_hash_format_check",
      sql`${table.previousHash} ~ '^[0-9a-f]{64}$'`,
    ),
    check(
      "audit_events_event_hash_format_check",
      sql`${table.eventHash} ~ '^[0-9a-f]{64}$'`,
    ),
    pgPolicy("audit_events_api_tenant", {
      as: "permissive",
      for: "all",
      to: apiRole,
      using: activeActorMembershipFor(table.tenantId),
      withCheck: activeActorMembershipFor(table.tenantId),
    }),
    pgPolicy("audit_events_worker_access", {
      as: "permissive",
      for: "all",
      to: workerRole,
      using: sql`${table.tenantId} = ${currentTenantId}`,
      withCheck: sql`${table.tenantId} = ${currentTenantId}`,
    }),
    pgPolicy("audit_events_notifier_access", {
      as: "permissive",
      for: "all",
      to: notifierRole,
      using: sql`${table.tenantId} = ${currentTenantId}`,
      withCheck: sql`${table.tenantId} = ${currentTenantId}`,
    }),
    pgPolicy("audit_events_auditor_select", {
      as: "permissive",
      for: "select",
      to: auditorRole,
      using: sql`${table.tenantId} = ${currentTenantId}`,
    }),
    pgPolicy("audit_events_reader_select", {
      as: "permissive",
      for: "select",
      to: auditReaderOwnerRole,
      using: sql`${table.tenantId} = ${currentTenantId}
        and app.current_tenant_human_has_exact_permission_v3('audit.read', 'tenant')`,
    }),
  ],
).enableRLS();

/**
 * Internal serialization point for audit chaining. Runtime roles never receive direct
 * privileges; the sealing trigger reaches it through its tightly scoped definer.
 */
export const auditChainHeads = pgTable(
  "audit_chain_heads",
  {
    tenantId: uuid("tenant_id")
      .primaryKey()
      .references(() => tenants.id, { onDelete: "restrict" }),
    lastSequence: bigint("last_sequence", { mode: "bigint" })
      .notNull()
      .default(sql`0`),
    lastEventHash: char("last_event_hash", { length: 64 })
      .notNull()
      .default(
        "0000000000000000000000000000000000000000000000000000000000000000",
      ),
    updatedAt: timestamp("updated_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    check(
      "audit_chain_heads_tenant_uuidv7_check",
      sql`(uuid_extract_version(${table.tenantId}) = 7) is true`,
    ),
    check(
      "audit_chain_heads_last_sequence_nonnegative_check",
      sql`${table.lastSequence} >= 0`,
    ),
    check(
      "audit_chain_heads_last_hash_format_check",
      sql`${table.lastEventHash} ~ '^[0-9a-f]{64}$'`,
    ),
    pgPolicy("audit_chain_heads_migrator_access", {
      as: "permissive",
      for: "all",
      to: migratorRole,
      using: sql`true`,
      withCheck: sql`true`,
    }),
    pgPolicy("audit_chain_heads_reader_select", {
      as: "permissive",
      for: "select",
      to: auditReaderOwnerRole,
      using: sql`${table.tenantId} = ${currentTenantId}
        and app.current_tenant_human_has_exact_permission_v3('audit.read', 'tenant')`,
    }),
  ],
).enableRLS();
