import { sql } from "drizzle-orm";
import {
  bigint,
  check,
  foreignKey,
  index,
  pgTable,
  text,
  timestamp,
  uuid,
} from "drizzle-orm/pg-core";

import { alerts } from "./alerts.js";
import { dfirAssets, dfirIOCs } from "./dfir.js";
import { tenantMemberships } from "./identity.js";
import { tenants } from "./tenancy.js";
import { cases } from "./ticketing.js";

/** Association history survives active-link removal and receipt expiration.
 * Application roles access it only through the closed shared-resource ABI. */
export const dfirSharedResourceLinkEvents = pgTable(
  "dfir_shared_resource_link_events",
  {
    id: uuid("id").primaryKey(),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    resourceKind: text("resource_kind").notNull(),
    iocId: uuid("ioc_id"),
    assetId: uuid("asset_id"),
    caseId: uuid("case_id"),
    alertId: uuid("alert_id"),
    linkId: uuid("link_id").notNull(),
    eventKind: text("event_kind").notNull(),
    priorVersion: bigint("prior_version", { mode: "bigint" }).notNull(),
    resultVersion: bigint("result_version", { mode: "bigint" }).notNull(),
    actorMembershipId: uuid("actor_membership_id").notNull(),
    occurredAt: timestamp("occurred_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    foreignKey({
      name: "dfir_shared_link_events_ioc_fk",
      columns: [table.tenantId, table.iocId],
      foreignColumns: [dfirIOCs.tenantId, dfirIOCs.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "dfir_shared_link_events_asset_fk",
      columns: [table.tenantId, table.assetId],
      foreignColumns: [dfirAssets.tenantId, dfirAssets.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "dfir_shared_link_events_case_fk",
      columns: [table.tenantId, table.caseId],
      foreignColumns: [cases.tenantId, cases.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "dfir_shared_link_events_alert_fk",
      columns: [table.tenantId, table.alertId],
      foreignColumns: [alerts.tenantId, alerts.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "dfir_shared_link_events_actor_fk",
      columns: [table.tenantId, table.actorMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    index("dfir_shared_link_events_ioc_idx").on(
      table.tenantId,
      table.iocId,
      table.occurredAt,
      table.id,
    ),
    index("dfir_shared_link_events_asset_idx").on(
      table.tenantId,
      table.assetId,
      table.occurredAt,
      table.id,
    ),
    check(
      "dfir_shared_link_events_shape_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true
      and (uuid_extract_version(${table.linkId}) = 7) is true
      and num_nonnulls(${table.caseId}, ${table.alertId}) = 1
      and ((${table.resourceKind} = 'ioc' and ${table.iocId} is not null and ${table.assetId} is null)
        or (${table.resourceKind} = 'asset' and ${table.assetId} is not null and ${table.iocId} is null))
      and ${table.eventKind} in ('linked','unlinked','imported')
      and ${table.priorVersion} between 0 and 9007199254740991
      and ${table.resultVersion} between 1 and 9007199254740991
      and ((${table.eventKind} = 'imported' and ${table.resultVersion} = ${table.priorVersion})
        or (${table.eventKind} <> 'imported' and ${table.resultVersion} = ${table.priorVersion} + 1))`,
    ),
  ],
).enableRLS();
