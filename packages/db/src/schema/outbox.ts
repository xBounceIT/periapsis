import { sql } from "drizzle-orm";
import {
  check,
  index,
  integer,
  jsonb,
  pgPolicy,
  pgTable,
  text,
  timestamp,
  unique,
  uuid,
} from "drizzle-orm/pg-core";

import { currentTenantId } from "./context.js";
import { notificationAudience, ticketPrincipalKind } from "./enums.js";
import { activeActorMembershipFor } from "./identity.js";
import {
  apiRole,
  notifierRole,
  slaWorkerOwnerRole,
  workerRole,
} from "./roles.js";
import { tenants } from "./tenancy.js";
import { bytea } from "./binary.js";

export const outboxEvents = pgTable(
  "outbox_events",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    aggregateType: text("aggregate_type").notNull(),
    aggregateId: uuid("aggregate_id").notNull(),
    aggregateVersion: integer("aggregate_version"),
    eventType: text("event_type").notNull(),
    schemaVersion: integer("schema_version").notNull().default(1),
    payload: jsonb("payload").$type<Record<string, unknown>>().notNull(),
    deduplicationKey: text("deduplication_key"),
    correlationId: uuid("correlation_id"),
    causationId: uuid("causation_id"),
    actorKind: ticketPrincipalKind("actor_kind"),
    actorId: uuid("actor_id"),
    producer: text("producer"),
    maximumAudience: notificationAudience("maximum_audience"),
    traceparent: text("traceparent"),
    tracestate: text("tracestate"),
    occurredAt: timestamp("occurred_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    availableAt: timestamp("available_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    attempts: integer("attempts").notNull().default(0),
    maxAttempts: integer("max_attempts").notNull().default(12),
    lockedAt: timestamp("locked_at", { withTimezone: true, mode: "date" }),
    lockedBy: text("locked_by"),
    leaseToken: uuid("lease_token"),
    leaseUntil: timestamp("lease_until", {
      withTimezone: true,
      mode: "date",
    }),
    processedAt: timestamp("processed_at", {
      withTimezone: true,
      mode: "date",
    }),
    lastError: text("last_error"),
    failureCategory: text("failure_category"),
    deadLetteredAt: timestamp("dead_lettered_at", {
      withTimezone: true,
      mode: "date",
    }),
    fanoutCommitDigest: bytea("fanout_commit_digest"),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    unique("outbox_events_tenant_id_id_key").on(table.tenantId, table.id),
    unique("outbox_events_tenant_deduplication_key").on(
      table.tenantId,
      table.deduplicationKey,
    ),
    index("outbox_events_dequeue_idx")
      .on(table.availableAt, table.occurredAt, table.id)
      .where(
        sql`${table.processedAt} is null and ${table.attempts} < ${table.maxAttempts}`,
      ),
    index("outbox_events_tenant_aggregate_idx").on(
      table.tenantId,
      table.aggregateType,
      table.aggregateId,
    ),
    check(
      "outbox_events_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "outbox_events_aggregate_type_not_blank_check",
      sql`btrim(${table.aggregateType}) <> ''`,
    ),
    check(
      "outbox_events_event_type_not_blank_check",
      sql`btrim(${table.eventType}) <> ''`,
    ),
    check(
      "outbox_events_schema_version_positive_check",
      sql`${table.schemaVersion} > 0`,
    ),
    check(
      "outbox_events_attempts_nonnegative_check",
      sql`${table.attempts} >= 0`,
    ),
    check(
      "outbox_events_max_attempts_positive_check",
      sql`${table.maxAttempts} > 0`,
    ),
    check(
      "outbox_events_lock_consistency_check",
      sql`(${table.lockedAt} is null) = (${table.lockedBy} is null)
        and (${table.leaseToken} is null) = (${table.leaseUntil} is null)`,
    ),
    check(
      "outbox_events_notification_v2_envelope_check",
      sql`not (${table.eventType} like 'notification.%' and ${table.schemaVersion} = 2)
        or (${table.aggregateVersion} between 1 and 2147483647
          and ${table.actorKind} is not null
          and (${table.actorKind} = 'system') = (${table.actorId} is null)
          and ${table.producer} ~ '^[a-z][a-z0-9_.-]{1,127}$'
          and ${table.maximumAudience} is not null
          and app.private_notification_trace_context_is_safe_v1(
            ${table.traceparent}, ${table.tracestate}
          )
          and jsonb_typeof(${table.payload}) = 'object'
          and ${table.payload} ? 'operatorContext'
          and jsonb_typeof(${table.payload} -> 'operatorContext') = 'object'
          and (${table.maximumAudience} = 'customer') = (${table.payload} ? 'customerContext')
          and (not (${table.payload} ? 'customerContext')
            or jsonb_typeof(${table.payload} -> 'customerContext') = 'object'))`,
    ),
    check(
      "outbox_events_fanout_bounds_check",
      sql`(${table.failureCategory} is null
          or (${table.failureCategory} ~ '^[a-z][a-z0-9_]{0,63}$'))
        and (${table.deadLetteredAt} is null or ${table.processedAt} is not null)
        and (${table.leaseUntil} is null or ${table.processedAt} is null)
        and (${table.fanoutCommitDigest} is null
          or (octet_length(${table.fanoutCommitDigest}) = 32
            and ${table.processedAt} is not null))`,
    ),
    pgPolicy("outbox_events_api_tenant", {
      as: "permissive",
      for: "all",
      to: apiRole,
      using: activeActorMembershipFor(table.tenantId),
      withCheck: activeActorMembershipFor(table.tenantId),
    }),
    pgPolicy("outbox_events_worker_access", {
      as: "permissive",
      for: "all",
      to: workerRole,
      using: sql`${table.tenantId} = ${currentTenantId}`,
      withCheck: sql`${table.tenantId} = ${currentTenantId}`,
    }),
    pgPolicy("outbox_events_notifier_access", {
      as: "permissive",
      for: "all",
      to: notifierRole,
      using: sql`${table.tenantId} = ${currentTenantId}
        and ${table.eventType} like 'notification.%'`,
      withCheck: sql`${table.tenantId} = ${currentTenantId}
        and ${table.eventType} like 'notification.%'`,
    }),
    pgPolicy("outbox_events_sla_event_owner_read_v1", {
      as: "permissive",
      for: "select",
      to: slaWorkerOwnerRole,
      using: sql`${table.tenantId} = ${currentTenantId}
        and ${table.eventType} in (
          'sla.alert.created', 'sla.case.created',
          'sla.alert.transitioned', 'sla.case.transitioned',
          'sla.alert.assigned', 'sla.case.assigned',
          'sla.alert.claimed', 'sla.case.claimed',
          'sla.alert.released', 'sla.case.released',
          'sla.alert.transferred', 'sla.case.transferred',
          'alert.commented', 'case.commented'
        )`,
    }),
  ],
).enableRLS();
