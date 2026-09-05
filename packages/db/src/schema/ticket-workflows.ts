import { sql } from "drizzle-orm";
import {
  bigint,
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
import { ticketAggregateKind } from "./enums.js";
import { activeActorMembershipFor, tenantMemberships } from "./identity.js";
import { apiRole } from "./roles.js";
import { tenants } from "./tenancy.js";

export type TicketWorkflowState = {
  key: string;
  initial: boolean;
  terminal: boolean;
  visibility: "internal" | "customer";
  actions: Array<{
    action: string;
    effects: string[];
  }>;
};

export type TicketWorkflowConditionValue =
  | { type: "text"; value: string }
  | { type: "number"; value: number }
  | { type: "boolean"; value: boolean }
  | { type: "instant"; value: string };

export type TicketWorkflowCondition =
  | {
      kind: "predicate";
      field: string;
      operator:
        | "equal"
        | "not_equal"
        | "in"
        | "not_in"
        | "less_than"
        | "less_than_or_equal"
        | "greater_than"
        | "greater_than_or_equal"
        | "exists"
        | "not_exists";
      values?: TicketWorkflowConditionValue[];
    }
  | {
      kind: "all" | "any";
      children: TicketWorkflowCondition[];
    }
  | {
      kind: "not";
      children: [TicketWorkflowCondition];
    };

export type TicketWorkflowTransition = {
  key: string;
  from: string;
  to: string;
  requiredComment: boolean;
  reopen: boolean;
  requiredRoles: string[];
  requiredPermissions: string[];
  requiredCustomFields: string[];
  condition?: TicketWorkflowCondition;
  effects: string[];
};

export type TicketWorkflowCommandResultSnapshot = {
  schemaVersion: 1;
  action:
    | "create"
    | "publish"
    | "update_metadata"
    | "set_default"
    | "archive"
    | "restore";
  workflowId: string;
  aggregateKind: "alert" | "case";
  key: string;
  displayName: string;
  description: string;
  isDefault: boolean;
  status: "active" | "archived";
  revision: number;
  currentVersion: number;
  states: TicketWorkflowState[];
  transitions: TicketWorkflowTransition[];
  createdAt: string;
  updatedAt: string;
  archivedAt: string | null;
};

export const ticketWorkflows = pgTable(
  "ticket_workflows",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    aggregateKind: ticketAggregateKind("aggregate_kind").notNull(),
    key: text("key").notNull(),
    displayName: text("display_name").notNull(),
    description: text("description").notNull().default(""),
    isDefault: boolean("is_default").notNull().default(false),
    revision: integer("revision").notNull().default(1),
    currentVersion: integer("current_version").notNull().default(1),
    archivedAt: timestamp("archived_at", { withTimezone: true, mode: "date" }),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    unique("ticket_workflows_tenant_id_key").on(table.tenantId, table.id),
    unique("ticket_workflows_tenant_kind_key_key").on(
      table.tenantId,
      table.aggregateKind,
      table.key,
    ),
    unique("ticket_workflows_exact_kind_key").on(
      table.tenantId,
      table.id,
      table.aggregateKind,
    ),
    uniqueIndex("ticket_workflows_one_default_key")
      .on(table.tenantId, table.aggregateKind)
      .where(sql`${table.isDefault} and ${table.archivedAt} is null`),
    index("ticket_workflows_tenant_kind_idx").on(
      table.tenantId,
      table.aggregateKind,
      table.id,
    ),
    check(
      "ticket_workflows_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "ticket_workflows_key_check",
      sql`${table.key} ~ '^[a-z][a-z0-9_]{2,63}$'`,
    ),
    check(
      "ticket_workflows_display_name_check",
      sql`btrim(${table.displayName}) <> '' and char_length(${table.displayName}) <= 120 and ${table.displayName} !~ '[[:cntrl:]]'`,
    ),
    check(
      "ticket_workflows_description_check",
      sql`char_length(${table.description}) <= 1000 and ${table.description} !~ '[[:cntrl:]]'`,
    ),
    check(
      "ticket_workflows_current_version_check",
      sql`${table.currentVersion} > 0`,
    ),
    check("ticket_workflows_revision_check", sql`${table.revision} > 0`),
    check(
      "ticket_workflows_timestamps_check",
      sql`${table.updatedAt} >= ${table.createdAt}
        and (${table.archivedAt} is null
          or (${table.archivedAt} >= ${table.createdAt}
            and ${table.archivedAt} <= ${table.updatedAt}
            and not ${table.isDefault}))`,
    ),
    pgPolicy("ticket_workflows_api_tenant", {
      as: "permissive",
      for: "select",
      to: apiRole,
      using: activeActorMembershipFor(table.tenantId),
    }),
  ],
).enableRLS();

export const ticketWorkflowCommands = pgTable(
  "ticket_workflow_commands",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    actorMembershipId: uuid("actor_membership_id").notNull(),
    actorUserId: uuid("actor_user_id").notNull(),
    action: text("action").notNull(),
    keyDigest: bytea("key_digest").notNull(),
    requestDigest: bytea("request_digest").notNull(),
    resultWorkflowId: uuid("result_workflow_id").notNull(),
    resultRevision: integer("result_revision").notNull(),
    resultSnapshot: jsonb("result_snapshot")
      .$type<TicketWorkflowCommandResultSnapshot>()
      .notNull(),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    expiresAt: timestamp("expires_at", { withTimezone: true, mode: "date" })
      .notNull()
      .default(sql`now() + interval '24 hours'`),
  },
  (table) => [
    unique("ticket_workflow_commands_tenant_id_key").on(
      table.tenantId,
      table.id,
    ),
    unique("ticket_workflow_commands_replay_key").on(
      table.tenantId,
      table.actorUserId,
      table.action,
      table.keyDigest,
    ),
    foreignKey({
      name: "ticket_workflow_commands_actor_fk",
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
      name: "ticket_workflow_commands_result_fk",
      columns: [table.tenantId, table.resultWorkflowId],
      foreignColumns: [ticketWorkflows.tenantId, ticketWorkflows.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    index("ticket_workflow_commands_expiry_idx").on(table.expiresAt),
    check(
      "ticket_workflow_commands_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "ticket_workflow_commands_action_check",
      sql`${table.action} in (
        'create', 'publish', 'update_metadata',
        'set_default', 'archive', 'restore'
      )`,
    ),
    check(
      "ticket_workflow_commands_digest_check",
      sql`octet_length(${table.keyDigest}) = 32
        and octet_length(${table.requestDigest}) = 32`,
    ),
    check(
      "ticket_workflow_commands_result_check",
      sql`${table.resultRevision} > 0
        and jsonb_typeof(${table.resultSnapshot}) = 'object'
        and pg_column_size(${table.resultSnapshot}) <= 524288
        and jsonb_array_length(jsonb_path_query_array(
          ${table.resultSnapshot}, '$.keyvalue().key'
        )) = 16
        and ${table.resultSnapshot} ?& array[
          'schemaVersion', 'action', 'workflowId', 'aggregateKind', 'key',
          'displayName', 'description', 'isDefault', 'status', 'revision',
          'currentVersion', 'states', 'transitions', 'createdAt',
          'updatedAt', 'archivedAt'
        ]
        and (${table.resultSnapshot} ->> 'schemaVersion')::integer = 1
        and ${table.resultSnapshot} ->> 'action' = ${table.action}
        and ${table.resultSnapshot} ->> 'workflowId' = ${table.resultWorkflowId}::text
        and (${table.resultSnapshot} ->> 'revision')::integer = ${table.resultRevision}
        and ${table.resultSnapshot} ->> 'aggregateKind' in ('alert', 'case')
        and ${table.resultSnapshot} ->> 'status' in ('active', 'archived')
        and jsonb_typeof(${table.resultSnapshot} -> 'states') = 'array'
        and jsonb_typeof(${table.resultSnapshot} -> 'transitions') = 'array'`,
    ),
    check(
      "ticket_workflow_commands_retention_check",
      sql`${table.expiresAt} > ${table.createdAt}
        and ${table.expiresAt} <= ${table.createdAt} + interval '7 days'`,
    ),
  ],
).enableRLS();

export const ticketWorkflowVersions = pgTable(
  "ticket_workflow_versions",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    workflowId: uuid("workflow_id").notNull(),
    aggregateKind: ticketAggregateKind("aggregate_kind").notNull(),
    version: integer("version").notNull(),
    states: jsonb("states").$type<TicketWorkflowState[]>().notNull(),
    transitions: jsonb("transitions")
      .$type<TicketWorkflowTransition[]>()
      .notNull(),
    publishedByMembershipId: uuid("published_by_membership_id"),
    publishedAt: timestamp("published_at", {
      withTimezone: true,
      mode: "date",
    })
      .notNull()
      .defaultNow(),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    unique("ticket_workflow_versions_tenant_id_key").on(
      table.tenantId,
      table.id,
    ),
    unique("ticket_workflow_versions_identity_key").on(
      table.tenantId,
      table.workflowId,
      table.version,
    ),
    unique("ticket_workflow_versions_exact_kind_key").on(
      table.tenantId,
      table.workflowId,
      table.aggregateKind,
      table.version,
    ),
    foreignKey({
      name: "ticket_workflow_versions_workflow_fk",
      columns: [table.tenantId, table.workflowId, table.aggregateKind],
      foreignColumns: [
        ticketWorkflows.tenantId,
        ticketWorkflows.id,
        ticketWorkflows.aggregateKind,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "ticket_workflow_versions_publisher_fk",
      columns: [table.tenantId, table.publishedByMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    index("ticket_workflow_versions_lookup_idx").on(
      table.tenantId,
      table.aggregateKind,
      table.workflowId,
      table.version,
    ),
    check(
      "ticket_workflow_versions_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check("ticket_workflow_versions_version_check", sql`${table.version} > 0`),
    check(
      "ticket_workflow_versions_states_check",
      sql`jsonb_typeof(${table.states}) = 'array' and jsonb_array_length(${table.states}) between 2 and 64`,
    ),
    check(
      "ticket_workflow_versions_transitions_check",
      sql`jsonb_typeof(${table.transitions}) = 'array' and jsonb_array_length(${table.transitions}) between 1 and 256`,
    ),
    check(
      "ticket_workflow_versions_timestamps_check",
      sql`${table.publishedAt} >= ${table.createdAt}`,
    ),
    pgPolicy("ticket_workflow_versions_api_tenant", {
      as: "permissive",
      for: "select",
      to: apiRole,
      using: activeActorMembershipFor(table.tenantId),
    }),
  ],
).enableRLS();

export const ticketNumberCounters = pgTable(
  "ticket_number_counters",
  {
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    aggregateKind: ticketAggregateKind("aggregate_kind").notNull(),
    namespaceDigest: bytea("namespace_digest").notNull(),
    period: integer("period").notNull(),
    nextValue: bigint("next_value", { mode: "number" }).notNull().default(1),
    updatedAt: timestamp("updated_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    unique("ticket_number_counters_key").on(
      table.tenantId,
      table.aggregateKind,
      table.namespaceDigest,
      table.period,
    ),
    check(
      "ticket_number_counters_period_check",
      sql`${table.period} = 0 or ${table.period} between 2000 and 9999`,
    ),
    check(
      "ticket_number_counters_next_value_check",
      sql`${table.nextValue} between 1 and 1000000000000
        and octet_length(${table.namespaceDigest}) = 32`,
    ),
  ],
).enableRLS();
