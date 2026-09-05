import { sql } from "drizzle-orm";
import {
  check,
  foreignKey,
  index,
  integer,
  pgPolicy,
  pgTable,
  text,
  timestamp,
  unique,
  uuid,
} from "drizzle-orm/pg-core";

import { alerts } from "./alerts.js";
import { activeActorMembershipFor, tenantMemberships } from "./identity.js";
import { apiRole } from "./roles.js";
import { tenants } from "./tenancy.js";

const tenantSelectPolicy = (tenantId: unknown) =>
  activeActorMembershipFor(tenantId);

/**
 * An explicit Alert-to-Alert classification. Both relation kinds are evidence,
 * never an instruction to merge or rewrite either Alert. canonicalFirstAlertId
 * and canonicalSecondAlertId make a pair unique independently of input order,
 * including for the symmetric correlation relation.
 */
export const alertRelations = pgTable(
  "alert_relations",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    sourceAlertId: uuid("source_alert_id").notNull(),
    targetAlertId: uuid("target_alert_id").notNull(),
    canonicalFirstAlertId: uuid("canonical_first_alert_id").notNull(),
    canonicalSecondAlertId: uuid("canonical_second_alert_id").notNull(),
    relationType: text("relation_type").notNull(),
    reason: text("reason").notNull(),
    linkedByMembershipId: uuid("linked_by_membership_id").notNull(),
    linkedByUserId: uuid("linked_by_user_id").notNull(),
    priorSourceVersion: integer("prior_source_version").notNull(),
    resultSourceVersion: integer("result_source_version").notNull(),
    priorTargetVersion: integer("prior_target_version").notNull(),
    resultTargetVersion: integer("result_target_version").notNull(),
    linkedAt: timestamp("linked_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    unique("alert_relations_tenant_id_key").on(table.tenantId, table.id),
    unique("alert_relations_identity_key").on(
      table.tenantId,
      table.id,
      table.sourceAlertId,
      table.targetAlertId,
    ),
    unique("alert_relations_pair_key").on(
      table.tenantId,
      table.canonicalFirstAlertId,
      table.canonicalSecondAlertId,
    ),
    foreignKey({
      name: "alert_relations_source_alert_fk",
      columns: [table.tenantId, table.sourceAlertId],
      foreignColumns: [alerts.tenantId, alerts.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "alert_relations_target_alert_fk",
      columns: [table.tenantId, table.targetAlertId],
      foreignColumns: [alerts.tenantId, alerts.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "alert_relations_actor_membership_fk",
      columns: [table.tenantId, table.linkedByMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "alert_relations_actor_user_fk",
      columns: [table.tenantId, table.linkedByUserId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.userId],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    index("alert_relations_source_idx").on(
      table.tenantId,
      table.sourceAlertId,
      table.id,
    ),
    index("alert_relations_target_idx").on(
      table.tenantId,
      table.targetAlertId,
      table.id,
    ),
    check(
      "alert_relations_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "alert_relations_pair_check",
      sql`${table.sourceAlertId} <> ${table.targetAlertId}
        and ${table.canonicalFirstAlertId} < ${table.canonicalSecondAlertId}
        and ${table.canonicalFirstAlertId} = least(${table.sourceAlertId}, ${table.targetAlertId})
        and ${table.canonicalSecondAlertId} = greatest(${table.sourceAlertId}, ${table.targetAlertId})`,
    ),
    check(
      "alert_relations_type_check",
      sql`${table.relationType} in ('duplicate_of', 'correlation')`,
    ),
    check(
      "alert_relations_reason_check",
      sql`btrim(${table.reason}) <> '' and octet_length(${table.reason}) <= 2000 and ${table.reason} !~ '[[:cntrl:]]'`,
    ),
    check(
      "alert_relations_version_check",
      sql`${table.priorSourceVersion} between 1 and 2147483646
        and ${table.resultSourceVersion} = ${table.priorSourceVersion} + 1
        and ${table.priorTargetVersion} between 1 and 2147483646
        and ${table.resultTargetVersion} = ${table.priorTargetVersion} + 1`,
    ),
    pgPolicy("alert_relations_api_tenant", {
      as: "permissive",
      for: "select",
      to: apiRole,
      using: tenantSelectPolicy(table.tenantId),
    }),
  ],
).enableRLS();

/** A terminal, immutable withdrawal of one historical relation. */
export const alertRelationRetractions = pgTable(
  "alert_relation_retractions",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    relationId: uuid("relation_id").notNull(),
    sourceAlertId: uuid("source_alert_id").notNull(),
    targetAlertId: uuid("target_alert_id").notNull(),
    retractedByMembershipId: uuid("retracted_by_membership_id").notNull(),
    retractedByUserId: uuid("retracted_by_user_id").notNull(),
    reason: text("reason").notNull(),
    priorSourceVersion: integer("prior_source_version").notNull(),
    resultSourceVersion: integer("result_source_version").notNull(),
    priorTargetVersion: integer("prior_target_version").notNull(),
    resultTargetVersion: integer("result_target_version").notNull(),
    retractedAt: timestamp("retracted_at", {
      withTimezone: true,
      mode: "date",
    })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    unique("alert_relation_retractions_tenant_id_key").on(
      table.tenantId,
      table.id,
    ),
    unique("alert_relation_retractions_relation_key").on(
      table.tenantId,
      table.relationId,
    ),
    foreignKey({
      name: "alert_relation_retractions_relation_identity_fk",
      columns: [
        table.tenantId,
        table.relationId,
        table.sourceAlertId,
        table.targetAlertId,
      ],
      foreignColumns: [
        alertRelations.tenantId,
        alertRelations.id,
        alertRelations.sourceAlertId,
        alertRelations.targetAlertId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "alert_relation_retractions_actor_membership_fk",
      columns: [table.tenantId, table.retractedByMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "alert_relation_retractions_actor_user_fk",
      columns: [table.tenantId, table.retractedByUserId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.userId],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    index("alert_relation_retractions_source_idx").on(
      table.tenantId,
      table.sourceAlertId,
      table.id,
    ),
    index("alert_relation_retractions_target_idx").on(
      table.tenantId,
      table.targetAlertId,
      table.id,
    ),
    check(
      "alert_relation_retractions_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "alert_relation_retractions_reason_check",
      sql`btrim(${table.reason}) <> '' and octet_length(${table.reason}) <= 2000 and ${table.reason} !~ '[[:cntrl:]]'`,
    ),
    check(
      "alert_relation_retractions_version_check",
      sql`${table.priorSourceVersion} between 1 and 2147483646
        and ${table.resultSourceVersion} = ${table.priorSourceVersion} + 1
        and ${table.priorTargetVersion} between 1 and 2147483646
        and ${table.resultTargetVersion} = ${table.priorTargetVersion} + 1`,
    ),
    pgPolicy("alert_relation_retractions_api_tenant", {
      as: "permissive",
      for: "select",
      to: apiRole,
      using: tenantSelectPolicy(table.tenantId),
    }),
  ],
).enableRLS();
