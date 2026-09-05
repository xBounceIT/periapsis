import { sql } from "drizzle-orm";
import {
  bigint,
  boolean,
  check,
  foreignKey,
  index,
  inet,
  integer,
  jsonb,
  macaddr,
  macaddr8,
  pgEnum,
  pgPolicy,
  pgTable,
  primaryKey,
  text,
  timestamp,
  unique,
  uniqueIndex,
  uuid,
} from "drizzle-orm/pg-core";

import { alerts } from "./alerts.js";
import { bytea } from "./binary.js";
import { currentTenantId } from "./context.js";
import { ticketPrincipalKind } from "./enums.js";
import { activeActorMembershipFor, tenantMemberships } from "./identity.js";
import { operatorTeamAssignmentEpochs } from "./operator-teams.js";
import { apiRole, workerRole } from "./roles.js";
import { tenantServiceAccounts } from "./service-accounts.js";
import { tenants } from "./tenancy.js";
import { alertCaseLinks, cases, ticketCommands } from "./ticketing.js";

export const dfirIndicatorType = pgEnum("dfir_indicator_type", [
  "ipv4",
  "ipv6",
  "domain",
  "hostname",
  "url",
  "email",
  "md5",
  "sha1",
  "sha256",
  "sha512",
  "filename",
  "registry_key",
  "process",
  "mutex",
  "cve",
  "custom",
]);

export const dfirTlp = pgEnum("dfir_tlp", ["red", "amber", "green", "clear"]);

export const dfirMaliciousState = pgEnum("dfir_malicious_state", [
  "unknown",
  "benign",
  "suspicious",
  "confirmed",
]);

export const dfirAssetCriticality = pgEnum("dfir_asset_criticality", [
  "low",
  "medium",
  "high",
  "critical",
]);

export const dfirEvidenceClassification = pgEnum(
  "dfir_evidence_classification",
  ["public", "internal", "confidential", "restricted"],
);

export const dfirScanState = pgEnum("dfir_scan_state", [
  "pending_upload",
  "uploaded",
  "verifying",
  "quarantined",
  "scanning",
  "available",
  "rejected",
  "scan_failed",
  "retained",
  "deleted",
]);

export const dfirCustodyAction = pgEnum("dfir_custody_action", [
  "collected",
  "accessed",
  "transferred",
  "sealed",
  "unsealed",
  "scan_state_changed",
  "retention_changed",
  "legal_hold_placed",
  "legal_hold_released",
  "destroyed",
]);

export const dfirTemporalPrecision = pgEnum("dfir_temporal_precision", [
  "year",
  "month",
  "day",
  "hour",
  "minute",
  "second",
  "millisecond",
  "microsecond",
]);

export const dfirTaskStatus = pgEnum("dfir_task_status", [
  "todo",
  "in_progress",
  "blocked",
  "done",
  "cancelled",
]);

export const dfirTaskPriority = pgEnum("dfir_task_priority", [
  "low",
  "medium",
  "high",
  "urgent",
]);

export const dfirMutationRootKind = pgEnum("dfir_mutation_root_kind", [
  "case",
  "alert",
]);

/**
 * Durable caller-owned identifier tombstones. Receipt payloads and replay keys
 * may expire, but an externally supplied DFIR identifier is never reusable.
 */
export const dfirMutationResourceIds = pgTable(
  "dfir_mutation_resource_ids",
  {
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    resourceKind: text("resource_kind").notNull(),
    resourceId: uuid("resource_id").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    primaryKey({
      name: "dfir_mutation_resource_ids_pkey",
      columns: [table.tenantId, table.resourceKind, table.resourceId],
    }),
    check(
      "dfir_mutation_resource_ids_shape_check",
      sql`${table.resourceKind} in ('ioc','asset','timeline_event','evidence','custody_event','relationship','relationship_retraction','task','checklist_item','storage_object','attachment','shared_link_event')
        and (uuid_extract_version(${table.resourceId}) = 7) is true`,
    ),
  ],
).enableRLS();

/**
 * Durable replay-key tombstones. Expiring the response snapshot never makes a
 * previously consumed idempotency key available for a different request.
 */
export const dfirMutationReplayKeys = pgTable(
  "dfir_mutation_replay_keys",
  {
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    actorUserId: uuid("actor_user_id").notNull(),
    actorMembershipId: uuid("actor_membership_id").notNull(),
    operation: text("operation").notNull(),
    keyDigest: bytea("key_digest").notNull(),
    firstUsedAt: timestamp("first_used_at", {
      withTimezone: true,
      mode: "date",
    })
      .notNull()
      .defaultNow(),
    receiptExpiresAt: timestamp("receipt_expires_at", {
      withTimezone: true,
      mode: "date",
    })
      .notNull()
      .default(sql`now() + interval '24 hours'`),
  },
  (table) => [
    primaryKey({
      name: "dfir_mutation_replay_keys_pkey",
      columns: [
        table.tenantId,
        table.actorUserId,
        table.operation,
        table.keyDigest,
      ],
    }),
    foreignKey({
      name: "dfir_mutation_replay_keys_actor_fk",
      columns: [table.tenantId, table.actorMembershipId, table.actorUserId],
      foreignColumns: [
        tenantMemberships.tenantId,
        tenantMemberships.id,
        tenantMemberships.userId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "dfir_mutation_replay_keys_shape_check",
      sql`(uuid_extract_version(${table.actorUserId}) = 7) is true
        and (uuid_extract_version(${table.actorMembershipId}) = 7) is true
        and ${table.operation} in (
          'dfir.ioc.create','dfir.ioc.replace','dfir.asset.create','dfir.asset.replace',
          'dfir.ioc.link','dfir.ioc.unlink','dfir.asset.link','dfir.asset.unlink',
          'dfir.timeline.create','dfir.evidence.create','dfir.evidence.custody.append',
          'dfir.relationship.create','dfir.relationship.retract','dfir.attachment.prepare',
          'case.dfir.task.create','case.dfir.task.transition','case.dfir.task.replace_details',
          'case.dfir.task.assign','case.dfir.task.reschedule','case.dfir.task.replace_checklist',
          'dfir.alert.evidence.create','dfir.alert.evidence.custody.append',
          'dfir.alert.task.create','dfir.alert.task.transition','dfir.alert.task.replace_details',
          'dfir.alert.task.assign','dfir.alert.task.reschedule','dfir.alert.task.checklist.replace',
          'case.dfir.task.comments.replace','dfir.alert.task.comments.replace',
          'dfir.alert.relationship.create','dfir.alert.relationship.retract'
        )
        and octet_length(${table.keyDigest}) = 32
        and ${table.receiptExpiresAt} >= ${table.firstUsedAt} + interval '24 hours'
        and ${table.receiptExpiresAt} <= ${table.firstUsedAt} + interval '7 days'`,
    ),
  ],
).enableRLS();

export const dfirVisibility = pgEnum("dfir_visibility", ["public", "private"]);

export const dfirEntityKind = pgEnum("dfir_entity_kind", [
  "alert",
  "case",
  "ioc",
  "asset",
  "evidence",
  "task",
  "attachment",
  "external",
]);

export const dfirIOCs = pgTable(
  "dfir_iocs",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    type: dfirIndicatorType("type").notNull(),
    value: text("value").notNull(),
    normalizedValue: text("normalized_value").notNull(),
    ipValue: inet("ip_value"),
    description: text("description").notNull().default(""),
    source: text("source").notNull(),
    confidence: integer("confidence").notNull(),
    tlp: dfirTlp("tlp").notNull(),
    firstSeen: timestamp("first_seen", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    lastSeen: timestamp("last_seen", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    maliciousState: dfirMaliciousState("malicious_state").notNull(),
    tags: text("tags")
      .array()
      .notNull()
      .default(sql`ARRAY[]::text[]`),
    enrichment: jsonb("enrichment").$type<Record<string, unknown>>(),
    createdByMembershipId: uuid("created_by_membership_id").notNull(),
    updatedByMembershipId: uuid("updated_by_membership_id").notNull(),
    version: bigint("version", { mode: "bigint" })
      .notNull()
      .default(sql`1`),
    archivedAt: timestamp("archived_at", { withTimezone: true, mode: "date" }),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    unique("dfir_iocs_tenant_id_key").on(table.tenantId, table.id),
    uniqueIndex("dfir_iocs_live_observable_key")
      .on(table.tenantId, table.type, table.normalizedValue)
      .where(sql`${table.archivedAt} is null`),
    index("dfir_iocs_inventory_idx").on(
      table.tenantId,
      table.archivedAt,
      table.type,
      table.updatedAt,
      table.id,
    ),
    index("dfir_iocs_ip_idx").on(table.tenantId, table.ipValue, table.id),
    foreignKey({
      name: "dfir_iocs_creator_fk",
      columns: [table.tenantId, table.createdByMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "dfir_iocs_updater_fk",
      columns: [table.tenantId, table.updatedByMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "dfir_iocs_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "dfir_iocs_value_check",
      sql`btrim(${table.value}) <> '' and octet_length(${table.value}) <= 8192
        and btrim(${table.normalizedValue}) <> '' and octet_length(${table.normalizedValue}) <= 8192
        and ${table.value} !~ '[[:cntrl:]]' and ${table.normalizedValue} !~ '[[:cntrl:]]'`,
    ),
    check(
      "dfir_iocs_ip_shape_check",
      sql`(${table.type} in ('ipv4','ipv6')) = (${table.ipValue} is not null)`,
    ),
    check(
      "dfir_iocs_metadata_check",
      sql`octet_length(${table.description}) <= 16384 and octet_length(${table.source}) between 1 and 512
        and ${table.confidence} between 0 and 100 and ${table.lastSeen} >= ${table.firstSeen}
        and cardinality(${table.tags}) <= 256
        and (${table.enrichment} is null or (jsonb_typeof(${table.enrichment}) = 'object' and pg_column_size(${table.enrichment}) <= 65536))`,
    ),
    check(
      "dfir_iocs_version_check",
      sql`${table.version} between 1 and 9007199254740991`,
    ),
    check(
      "dfir_iocs_timestamps_check",
      sql`${table.updatedAt} >= ${table.createdAt}`,
    ),
    pgPolicy("dfir_iocs_api_tenant", {
      as: "permissive",
      for: "all",
      to: apiRole,
      using: activeActorMembershipFor(table.tenantId),
      withCheck: activeActorMembershipFor(table.tenantId),
    }),
  ],
).enableRLS();

export type DfirOriginalAssetIdentifiers = {
  hostname?: string;
  fqdn?: string;
  ipAddresses: string[];
  macAddresses: string[];
};

export const dfirAssets = pgTable(
  "dfir_assets",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    hostname: text("hostname"),
    normalizedHostname: text("normalized_hostname"),
    fqdn: text("fqdn"),
    normalizedFqdn: text("normalized_fqdn"),
    ipAddresses: inet("ip_addresses")
      .array()
      .notNull()
      .default(sql`ARRAY[]::inet[]`),
    macAddresses: macaddr("mac_addresses")
      .array()
      .notNull()
      .default(sql`ARRAY[]::macaddr[]`),
    mac8Addresses: macaddr8("mac8_addresses")
      .array()
      .notNull()
      .default(sql`ARRAY[]::macaddr8[]`),
    originalIdentifiers: jsonb("original_identifiers")
      .$type<DfirOriginalAssetIdentifiers>()
      .notNull(),
    assetType: text("asset_type").notNull(),
    operatingSystem: text("operating_system").notNull().default(""),
    owner: text("owner").notNull().default(""),
    businessUnit: text("business_unit").notNull().default(""),
    criticality: dfirAssetCriticality("criticality").notNull(),
    environment: text("environment").notNull(),
    externalId: text("external_id"),
    tags: text("tags")
      .array()
      .notNull()
      .default(sql`ARRAY[]::text[]`),
    firstSeen: timestamp("first_seen", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    lastSeen: timestamp("last_seen", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    customAttributes:
      jsonb("custom_attributes").$type<Record<string, unknown>>(),
    createdByMembershipId: uuid("created_by_membership_id").notNull(),
    updatedByMembershipId: uuid("updated_by_membership_id").notNull(),
    version: bigint("version", { mode: "bigint" })
      .notNull()
      .default(sql`1`),
    archivedAt: timestamp("archived_at", { withTimezone: true, mode: "date" }),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    unique("dfir_assets_tenant_id_key").on(table.tenantId, table.id),
    uniqueIndex("dfir_assets_live_external_key")
      .on(table.tenantId, table.externalId)
      .where(
        sql`${table.externalId} is not null and ${table.archivedAt} is null`,
      ),
    index("dfir_assets_inventory_idx").on(
      table.tenantId,
      table.archivedAt,
      table.criticality,
      table.updatedAt,
      table.id,
    ),
    index("dfir_assets_hostname_idx").on(
      table.tenantId,
      table.normalizedHostname,
      table.id,
    ),
    index("dfir_assets_fqdn_idx").on(
      table.tenantId,
      table.normalizedFqdn,
      table.id,
    ),
    foreignKey({
      name: "dfir_assets_creator_fk",
      columns: [table.tenantId, table.createdByMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "dfir_assets_updater_fk",
      columns: [table.tenantId, table.updatedByMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "dfir_assets_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "dfir_assets_identifier_check",
      sql`${table.hostname} is not null or ${table.fqdn} is not null or cardinality(${table.ipAddresses}) > 0
        or cardinality(${table.macAddresses}) > 0 or cardinality(${table.mac8Addresses}) > 0
        or ${table.externalId} is not null`,
    ),
    check(
      "dfir_assets_hostname_shape_check",
      sql`(${table.hostname} is null) = (${table.normalizedHostname} is null)
        and (${table.fqdn} is null) = (${table.normalizedFqdn} is null)`,
    ),
    check(
      "dfir_assets_metadata_check",
      sql`${table.assetType} ~ '^[a-z][a-z0-9_.-]{0,63}$'
        and ${table.environment} ~ '^[a-z][a-z0-9_.-]{0,63}$'
        and octet_length(${table.operatingSystem}) <= 512
        and octet_length(${table.owner}) <= 512 and octet_length(${table.businessUnit}) <= 256
        and (${table.externalId} is null or octet_length(${table.externalId}) between 1 and 512)
        and cardinality(${table.ipAddresses}) + cardinality(${table.macAddresses}) + cardinality(${table.mac8Addresses}) <= 512
        and cardinality(${table.tags}) <= 256 and ${table.lastSeen} >= ${table.firstSeen}
        and jsonb_typeof(${table.originalIdentifiers}) = 'object'
        and pg_column_size(${table.originalIdentifiers}) <= 65536
        and (${table.customAttributes} is null or (jsonb_typeof(${table.customAttributes}) = 'object' and pg_column_size(${table.customAttributes}) <= 65536))`,
    ),
    check(
      "dfir_assets_version_check",
      sql`${table.version} between 1 and 9007199254740991`,
    ),
    check(
      "dfir_assets_timestamps_check",
      sql`${table.updatedAt} >= ${table.createdAt}`,
    ),
    pgPolicy("dfir_assets_api_tenant", {
      as: "permissive",
      for: "all",
      to: apiRole,
      using: activeActorMembershipFor(table.tenantId),
      withCheck: activeActorMembershipFor(table.tenantId),
    }),
  ],
).enableRLS();

export const dfirIOCLinks = pgTable(
  "dfir_ioc_links",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    iocId: uuid("ioc_id").notNull(),
    alertId: uuid("alert_id"),
    caseId: uuid("case_id"),
    createdByMembershipId: uuid("created_by_membership_id").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    unique("dfir_ioc_links_tenant_id_key").on(table.tenantId, table.id),
    uniqueIndex("dfir_ioc_links_alert_key")
      .on(table.tenantId, table.iocId, table.alertId)
      .where(sql`${table.alertId} is not null`),
    uniqueIndex("dfir_ioc_links_case_key")
      .on(table.tenantId, table.iocId, table.caseId)
      .where(sql`${table.caseId} is not null`),
    foreignKey({
      name: "dfir_ioc_links_ioc_fk",
      columns: [table.tenantId, table.iocId],
      foreignColumns: [dfirIOCs.tenantId, dfirIOCs.id],
    })
      .onUpdate("cascade")
      .onDelete("cascade"),
    foreignKey({
      name: "dfir_ioc_links_alert_fk",
      columns: [table.tenantId, table.alertId],
      foreignColumns: [alerts.tenantId, alerts.id],
    })
      .onUpdate("cascade")
      .onDelete("cascade"),
    foreignKey({
      name: "dfir_ioc_links_case_fk",
      columns: [table.tenantId, table.caseId],
      foreignColumns: [cases.tenantId, cases.id],
    })
      .onUpdate("cascade")
      .onDelete("cascade"),
    foreignKey({
      name: "dfir_ioc_links_creator_fk",
      columns: [table.tenantId, table.createdByMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "dfir_ioc_links_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "dfir_ioc_links_subject_check",
      sql`(${table.alertId} is null) <> (${table.caseId} is null)`,
    ),
    pgPolicy("dfir_ioc_links_api_tenant", {
      as: "permissive",
      for: "all",
      to: apiRole,
      using: activeActorMembershipFor(table.tenantId),
      withCheck: activeActorMembershipFor(table.tenantId),
    }),
  ],
).enableRLS();

export const dfirAssetLinks = pgTable(
  "dfir_asset_links",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    assetId: uuid("asset_id").notNull(),
    alertId: uuid("alert_id"),
    caseId: uuid("case_id"),
    createdByMembershipId: uuid("created_by_membership_id").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    unique("dfir_asset_links_tenant_id_key").on(table.tenantId, table.id),
    uniqueIndex("dfir_asset_links_alert_key")
      .on(table.tenantId, table.assetId, table.alertId)
      .where(sql`${table.alertId} is not null`),
    uniqueIndex("dfir_asset_links_case_key")
      .on(table.tenantId, table.assetId, table.caseId)
      .where(sql`${table.caseId} is not null`),
    foreignKey({
      name: "dfir_asset_links_asset_fk",
      columns: [table.tenantId, table.assetId],
      foreignColumns: [dfirAssets.tenantId, dfirAssets.id],
    })
      .onUpdate("cascade")
      .onDelete("cascade"),
    foreignKey({
      name: "dfir_asset_links_alert_fk",
      columns: [table.tenantId, table.alertId],
      foreignColumns: [alerts.tenantId, alerts.id],
    })
      .onUpdate("cascade")
      .onDelete("cascade"),
    foreignKey({
      name: "dfir_asset_links_case_fk",
      columns: [table.tenantId, table.caseId],
      foreignColumns: [cases.tenantId, cases.id],
    })
      .onUpdate("cascade")
      .onDelete("cascade"),
    foreignKey({
      name: "dfir_asset_links_creator_fk",
      columns: [table.tenantId, table.createdByMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "dfir_asset_links_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "dfir_asset_links_subject_check",
      sql`(${table.alertId} is null) <> (${table.caseId} is null)`,
    ),
    pgPolicy("dfir_asset_links_api_tenant", {
      as: "permissive",
      for: "all",
      to: apiRole,
      using: activeActorMembershipFor(table.tenantId),
      withCheck: activeActorMembershipFor(table.tenantId),
    }),
  ],
).enableRLS();

/**
 * Transaction-local idempotency reservations for Alert-scoped DFIR resource
 * mutations. The application role has no direct table privileges; the closed
 * ABI binds one human actor, operation and key digest to an exact result.
 */
export const alertDfirResourceCommands = pgTable(
  "alert_dfir_resource_commands",
  {
    commandId: uuid("command_id").primaryKey(),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    actorUserId: uuid("actor_user_id").notNull(),
    actorMembershipId: uuid("actor_membership_id").notNull(),
    alertId: uuid("alert_id").notNull(),
    operation: text("operation").notNull(),
    resourceId: uuid("resource_id").notNull(),
    resultVersion: bigint("result_version", { mode: "bigint" }).notNull(),
    keyDigest: bytea("key_digest").notNull(),
    requestDigest: bytea("request_digest").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    expiresAt: timestamp("expires_at", { withTimezone: true, mode: "date" })
      .notNull()
      .default(sql`now() + interval '24 hours'`),
  },
  (table) => [
    unique("alert_dfir_resource_commands_replay_key").on(
      table.tenantId,
      table.actorUserId,
      table.operation,
      table.keyDigest,
    ),
    unique("alert_dfir_resource_commands_result_key").on(
      table.tenantId,
      table.alertId,
      table.operation,
      table.resourceId,
      table.resultVersion,
    ),
    unique("alert_dfir_resource_commands_tenant_command_key").on(
      table.tenantId,
      table.commandId,
    ),
    unique("alert_dfir_resource_commands_result_coordinate_key").on(
      table.tenantId,
      table.commandId,
      table.alertId,
      table.operation,
      table.resourceId,
      table.resultVersion,
    ),
    index("alert_dfir_resource_commands_expiry_idx").on(
      table.expiresAt,
      table.tenantId,
      table.commandId,
    ),
    foreignKey({
      name: "alert_dfir_resource_commands_alert_fk",
      columns: [table.tenantId, table.alertId],
      foreignColumns: [alerts.tenantId, alerts.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "alert_dfir_resource_commands_actor_fk",
      columns: [table.tenantId, table.actorMembershipId, table.actorUserId],
      foreignColumns: [
        tenantMemberships.tenantId,
        tenantMemberships.id,
        tenantMemberships.userId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "alert_dfir_resource_commands_shape_check",
      sql`(uuid_extract_version(${table.commandId}) = 7) is true
        and (uuid_extract_version(${table.resourceId}) = 7) is true
        and ${table.operation} in (
          'dfir.ioc.create','dfir.ioc.replace','dfir.asset.create','dfir.asset.replace','dfir.timeline.create',
          'dfir.alert.evidence.create','dfir.alert.evidence.custody.append',
          'dfir.alert.task.create','dfir.alert.task.transition','dfir.alert.task.replace_details','dfir.alert.task.assign',
          'dfir.alert.task.reschedule','dfir.alert.task.checklist.replace','dfir.alert.task.comments.replace',
          'dfir.alert.relationship.create','dfir.alert.relationship.retract'
        )
        and ${table.resultVersion} between 1 and 9007199254740991
        and octet_length(${table.keyDigest}) = 32
        and octet_length(${table.requestDigest}) = 32
        and ${table.expiresAt} >= ${table.createdAt} + interval '24 hours'
        and ${table.expiresAt} <= ${table.createdAt} + interval '7 days'`,
    ),
  ],
).enableRLS();

/**
 * Immutable response projections for exact idempotent replay. Mutable DFIR
 * rows cannot represent an earlier task/checklist or relationship version, so
 * the receipt result is stored independently from the live aggregate.
 */
export const alertDfirResourceCommandResults = pgTable(
  "alert_dfir_resource_command_results",
  {
    commandId: uuid("command_id").primaryKey(),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    alertId: uuid("alert_id").notNull(),
    operation: text("operation").notNull(),
    resourceId: uuid("resource_id").notNull(),
    resultVersion: bigint("result_version", { mode: "bigint" }).notNull(),
    resultSnapshot: jsonb("result_snapshot")
      .$type<Record<string, unknown>>()
      .notNull(),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    unique("alert_dfir_resource_command_results_coordinate_key").on(
      table.tenantId,
      table.alertId,
      table.operation,
      table.resourceId,
      table.resultVersion,
    ),
    foreignKey({
      name: "alert_dfir_resource_command_results_command_fk",
      columns: [
        table.tenantId,
        table.commandId,
        table.alertId,
        table.operation,
        table.resourceId,
        table.resultVersion,
      ],
      foreignColumns: [
        alertDfirResourceCommands.tenantId,
        alertDfirResourceCommands.commandId,
        alertDfirResourceCommands.alertId,
        alertDfirResourceCommands.operation,
        alertDfirResourceCommands.resourceId,
        alertDfirResourceCommands.resultVersion,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "alert_dfir_resource_command_results_alert_fk",
      columns: [table.tenantId, table.alertId],
      foreignColumns: [alerts.tenantId, alerts.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "alert_dfir_resource_command_results_shape_check",
      sql`(uuid_extract_version(${table.commandId}) = 7) is true
        and (uuid_extract_version(${table.resourceId}) = 7) is true
        and ${table.resultVersion} between 1 and 9007199254740991
        and jsonb_typeof(${table.resultSnapshot}) = 'object'
        and octet_length(${table.resultSnapshot}::text) <= 16777216`,
    ),
  ],
).enableRLS();

/**
 * Bounded immutable reservations for DFIR mutations whose live resource may
 * advance after the first response. The application role has no direct table
 * privileges: the closed mutation ABI binds one actor and idempotency key to
 * the exact root, operation, caller-owned identifiers and JSON-safe version.
 */
export const dfirMutationCommands = pgTable(
  "dfir_mutation_commands",
  {
    commandId: uuid("command_id").primaryKey(),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    actorUserId: uuid("actor_user_id").notNull(),
    actorMembershipId: uuid("actor_membership_id").notNull(),
    rootKind: dfirMutationRootKind("root_kind").notNull(),
    rootId: uuid("root_id").notNull(),
    operation: text("operation").notNull(),
    resourceKind: text("resource_kind").notNull(),
    resourceId: uuid("resource_id").notNull(),
    secondaryResourceId: uuid("secondary_resource_id"),
    resultVersion: bigint("result_version", { mode: "bigint" }).notNull(),
    keyDigest: bytea("key_digest").notNull(),
    requestDigest: bytea("request_digest").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    expiresAt: timestamp("expires_at", { withTimezone: true, mode: "date" })
      .notNull()
      .default(sql`now() + interval '24 hours'`),
  },
  (table) => [
    unique("dfir_mutation_commands_replay_key").on(
      table.tenantId,
      table.actorUserId,
      table.operation,
      table.keyDigest,
    ),
    unique("dfir_mutation_commands_tenant_command_key").on(
      table.tenantId,
      table.commandId,
    ),
    unique("dfir_mutation_commands_result_coordinate_key").on(
      table.tenantId,
      table.commandId,
      table.rootKind,
      table.rootId,
      table.operation,
      table.resourceKind,
      table.resourceId,
      table.resultVersion,
    ),
    uniqueIndex("dfir_mutation_commands_create_resource_key")
      .on(table.tenantId, table.resourceKind, table.resourceId)
      .where(
        sql`${table.operation} in ('dfir.ioc.create','dfir.asset.create','dfir.timeline.create','dfir.evidence.create','dfir.relationship.create','dfir.attachment.prepare')`,
      ),
    uniqueIndex("dfir_mutation_commands_secondary_resource_key")
      .on(table.tenantId, table.secondaryResourceId)
      .where(sql`${table.secondaryResourceId} is not null`),
    index("dfir_mutation_commands_expiry_idx").on(
      table.expiresAt,
      table.tenantId,
      table.commandId,
    ),
    foreignKey({
      name: "dfir_mutation_commands_actor_fk",
      columns: [table.tenantId, table.actorMembershipId, table.actorUserId],
      foreignColumns: [
        tenantMemberships.tenantId,
        tenantMemberships.id,
        tenantMemberships.userId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "dfir_mutation_commands_shape_check",
      sql`(uuid_extract_version(${table.commandId}) = 7) is true
        and (uuid_extract_version(${table.rootId}) = 7) is true
        and (uuid_extract_version(${table.resourceId}) = 7) is true
        and (${table.secondaryResourceId} is null or (uuid_extract_version(${table.secondaryResourceId}) = 7) is true)
        and (
          (${table.operation} = 'dfir.ioc.create' and ${table.resourceKind} = 'ioc' and ${table.resultVersion} = 1 and ${table.secondaryResourceId} is null)
          or (${table.operation} = 'dfir.ioc.replace' and ${table.resourceKind} = 'ioc' and ${table.resultVersion} between 2 and 9007199254740991 and ${table.secondaryResourceId} is null)
          or (${table.operation} in ('dfir.ioc.link','dfir.ioc.unlink') and ${table.resourceKind} = 'ioc' and ${table.resultVersion} between 2 and 9007199254740991 and ${table.secondaryResourceId} is not null)
          or (${table.operation} = 'dfir.asset.create' and ${table.resourceKind} = 'asset' and ${table.resultVersion} = 1 and ${table.secondaryResourceId} is null)
          or (${table.operation} = 'dfir.asset.replace' and ${table.resourceKind} = 'asset' and ${table.resultVersion} between 2 and 9007199254740991 and ${table.secondaryResourceId} is null)
          or (${table.operation} in ('dfir.asset.link','dfir.asset.unlink') and ${table.resourceKind} = 'asset' and ${table.resultVersion} between 2 and 9007199254740991 and ${table.secondaryResourceId} is not null)
          or (${table.operation} = 'dfir.timeline.create' and ${table.resourceKind} = 'timeline_event' and ${table.resultVersion} = 1 and ${table.secondaryResourceId} is null)
          or (${table.operation} = 'dfir.evidence.create' and ${table.rootKind} = 'case' and ${table.resourceKind} = 'evidence' and ${table.resultVersion} = 1 and ${table.secondaryResourceId} is not null)
          or (${table.operation} = 'dfir.evidence.custody.append' and ${table.rootKind} = 'case' and ${table.resourceKind} = 'evidence' and ${table.resultVersion} between 2 and 1000 and ${table.secondaryResourceId} is not null)
          or (${table.operation} = 'dfir.relationship.create' and ${table.rootKind} = 'case' and ${table.resourceKind} = 'relationship' and ${table.resultVersion} = 1 and ${table.secondaryResourceId} is null)
          or (${table.operation} = 'dfir.relationship.retract' and ${table.rootKind} = 'case' and ${table.resourceKind} = 'relationship' and ${table.resultVersion} = 2 and ${table.secondaryResourceId} is not null)
          or (${table.operation} = 'dfir.attachment.prepare' and ${table.resourceKind} = 'storage_object' and ${table.resultVersion} = 1 and ${table.secondaryResourceId} is not null)
        )
        and octet_length(${table.keyDigest}) = 32
        and octet_length(${table.requestDigest}) = 32
        and ${table.expiresAt} >= ${table.createdAt} + interval '24 hours'
        and ${table.expiresAt} <= ${table.createdAt} + interval '7 days'`,
    ),
  ],
).enableRLS();

/** Exact typed response snapshots paired one-to-one with DFIR reservations. */
export const dfirMutationCommandResults = pgTable(
  "dfir_mutation_command_results",
  {
    commandId: uuid("command_id").primaryKey(),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    rootKind: dfirMutationRootKind("root_kind").notNull(),
    rootId: uuid("root_id").notNull(),
    operation: text("operation").notNull(),
    resourceKind: text("resource_kind").notNull(),
    resourceId: uuid("resource_id").notNull(),
    resultVersion: bigint("result_version", { mode: "bigint" }).notNull(),
    resultSnapshot: jsonb("result_snapshot")
      .$type<Record<string, unknown>>()
      .notNull(),
  },
  (table) => [
    unique("dfir_mutation_command_results_coordinate_key").on(
      table.tenantId,
      table.rootKind,
      table.rootId,
      table.operation,
      table.resourceKind,
      table.resourceId,
      table.resultVersion,
    ),
    foreignKey({
      name: "dfir_mutation_command_results_command_fk",
      columns: [
        table.tenantId,
        table.commandId,
        table.rootKind,
        table.rootId,
        table.operation,
        table.resourceKind,
        table.resourceId,
        table.resultVersion,
      ],
      foreignColumns: [
        dfirMutationCommands.tenantId,
        dfirMutationCommands.commandId,
        dfirMutationCommands.rootKind,
        dfirMutationCommands.rootId,
        dfirMutationCommands.operation,
        dfirMutationCommands.resourceKind,
        dfirMutationCommands.resourceId,
        dfirMutationCommands.resultVersion,
      ],
    })
      .onUpdate("cascade")
      .onDelete("cascade"),
    check(
      "dfir_mutation_command_results_shape_check",
      sql`(uuid_extract_version(${table.commandId}) = 7) is true
        and (uuid_extract_version(${table.rootId}) = 7) is true
        and (uuid_extract_version(${table.resourceId}) = 7) is true
        and ${table.resultVersion} between 1 and 9007199254740991
        and jsonb_typeof(${table.resultSnapshot}) is not distinct from 'object'
        and ${table.resultSnapshot} ?& array['schemaVersion','tenantId','rootKind','rootId','operation','resourceKind','resourceId','resultVersion','projection']
        and jsonb_typeof(${table.resultSnapshot}->'schemaVersion') is not distinct from 'number'
        and (${table.resultSnapshot}->>'schemaVersion') is not distinct from '1'
        and jsonb_typeof(${table.resultSnapshot}->'tenantId') is not distinct from 'string'
        and (${table.resultSnapshot}->>'tenantId')::uuid is not distinct from ${table.tenantId}
        and jsonb_typeof(${table.resultSnapshot}->'rootKind') is not distinct from 'string'
        and (${table.resultSnapshot}->>'rootKind') is not distinct from ${table.rootKind}::text
        and jsonb_typeof(${table.resultSnapshot}->'rootId') is not distinct from 'string'
        and (${table.resultSnapshot}->>'rootId')::uuid is not distinct from ${table.rootId}
        and jsonb_typeof(${table.resultSnapshot}->'operation') is not distinct from 'string'
        and (${table.resultSnapshot}->>'operation') is not distinct from ${table.operation}
        and jsonb_typeof(${table.resultSnapshot}->'resourceKind') is not distinct from 'string'
        and (${table.resultSnapshot}->>'resourceKind') is not distinct from ${table.resourceKind}
        and jsonb_typeof(${table.resultSnapshot}->'resourceId') is not distinct from 'string'
        and (${table.resultSnapshot}->>'resourceId')::uuid is not distinct from ${table.resourceId}
        and jsonb_typeof(${table.resultSnapshot}->'resultVersion') is not distinct from 'number'
        and (${table.resultSnapshot}->>'resultVersion')::numeric is not distinct from ${table.resultVersion}
        and jsonb_typeof(${table.resultSnapshot}->'projection') is not distinct from 'object'
        and octet_length(${table.resultSnapshot}::text) <= case ${table.resourceKind}
          when 'storage_object' then 16384
          when 'evidence' then 16777216
          else 262144
        end`,
    ),
  ],
).enableRLS();

/**
 * DFIR-only retention coordinate for task receipts stored in the shared
 * ticket command journal. Non-DFIR ticket commands never receive a row here
 * and therefore remain outside the DFIR receipt pruning boundary.
 */
export const dfirTicketCommandRetentions = pgTable(
  "dfir_ticket_command_retentions",
  {
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    commandId: uuid("command_id").notNull(),
    operation: text("operation").notNull(),
    commandCreatedAt: timestamp("command_created_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    expiresAt: timestamp("expires_at", { withTimezone: true, mode: "date" })
      .notNull()
      .default(sql`now() + interval '24 hours'`),
  },
  (table) => [
    primaryKey({
      name: "dfir_ticket_command_retentions_pkey",
      columns: [table.tenantId, table.commandId],
    }),
    foreignKey({
      name: "dfir_ticket_command_retentions_command_fk",
      columns: [
        table.tenantId,
        table.commandId,
        table.operation,
        table.commandCreatedAt,
      ],
      foreignColumns: [
        ticketCommands.tenantId,
        ticketCommands.id,
        ticketCommands.operation,
        ticketCommands.createdAt,
      ],
    })
      .onUpdate("cascade")
      .onDelete("cascade"),
    index("dfir_ticket_command_retentions_expiry_idx").on(
      table.expiresAt,
      table.tenantId,
      table.commandId,
    ),
    check(
      "dfir_ticket_command_retentions_shape_check",
      sql`(uuid_extract_version(${table.commandId}) = 7) is true
        and ${table.operation} in (
          'case.dfir.task.create','case.dfir.task.transition',
          'case.dfir.task.replace_details','case.dfir.task.assign',
          'case.dfir.task.reschedule','case.dfir.task.replace_checklist',
          'case.dfir.task.comments.replace'
        )
        and ${table.expiresAt} >= ${table.commandCreatedAt} + interval '24 hours'
        and ${table.expiresAt} <= ${table.commandCreatedAt} + interval '7 days'`,
    ),
  ],
).enableRLS();

export const dfirStorageObjects = pgTable(
  "dfir_storage_objects",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    bucket: text("bucket").notNull(),
    objectKey: text("object_key").notNull(),
    originalFilename: text("original_filename").notNull(),
    classification: dfirEvidenceClassification("classification").notNull(),
    state: dfirScanState("state").notNull().default("pending_upload"),
    expectedSizeBytes: bigint("expected_size_bytes", {
      mode: "bigint",
    }).notNull(),
    uploadExpiresAt: timestamp("upload_expires_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    contentSha256: bytea("content_sha256"),
    sizeBytes: bigint("size_bytes", { mode: "bigint" }),
    detectedMime: text("detected_mime"),
    verifiedAt: timestamp("verified_at", { withTimezone: true, mode: "date" }),
    retentionUntil: timestamp("retention_until", {
      withTimezone: true,
      mode: "date",
    }),
    legalHold: boolean("legal_hold").notNull().default(false),
    cleanupFence: bigint("cleanup_fence", { mode: "bigint" })
      .notNull()
      .default(sql`0`),
    cleanupClaimedAt: timestamp("cleanup_claimed_at", {
      withTimezone: true,
      mode: "date",
    }),
    cleanupLeaseExpiresAt: timestamp("cleanup_lease_expires_at", {
      withTimezone: true,
      mode: "date",
    }),
    cleanupAttemptCount: bigint("cleanup_attempt_count", { mode: "bigint" })
      .notNull()
      .default(sql`0`),
    cleanupLastFailureCode: text("cleanup_last_failure_code"),
    createdByMembershipId: uuid("created_by_membership_id").notNull(),
    version: bigint("version", { mode: "bigint" })
      .notNull()
      .default(sql`1`),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    unique("dfir_storage_objects_tenant_id_key").on(table.tenantId, table.id),
    unique("dfir_storage_objects_location_key").on(
      table.tenantId,
      table.bucket,
      table.objectKey,
    ),
    index("dfir_storage_objects_scan_queue_idx").on(
      table.tenantId,
      table.state,
      table.updatedAt,
      table.id,
    ),
    index("dfir_storage_objects_cleanup_queue_idx")
      .on(
        table.tenantId,
        table.uploadExpiresAt,
        table.cleanupLeaseExpiresAt,
        table.id,
      )
      .where(sql`${table.state} = 'pending_upload'`),
    foreignKey({
      name: "dfir_storage_objects_creator_fk",
      columns: [table.tenantId, table.createdByMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "dfir_storage_objects_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "dfir_storage_objects_bucket_check",
      sql`${table.bucket} ~ '^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$' and ${table.bucket} !~ '\\.\\.'`,
    ),
    check(
      "dfir_storage_objects_key_check",
      sql`octet_length(${table.objectKey}) between 38 and 1024 and ${table.objectKey} like ${table.tenantId}::text || '/%' and ${table.objectKey} !~ '(^|/)\\.\\.?(/|$)' and ${table.objectKey} !~ '[\\\\[:cntrl:]]'`,
    ),
    check(
      "dfir_storage_objects_filename_check",
      sql`octet_length(${table.originalFilename}) between 1 and 255 and ${table.originalFilename} !~ '[/\\\\[:cntrl:]]' and ${table.originalFilename} not in ('.','..')`,
    ),
    check(
      "dfir_storage_objects_content_shape_check",
      sql`((${table.expectedSizeBytes} = 0 and ${table.state} in ('pending_upload','rejected','deleted')
          and ${table.contentSha256} is null and ${table.sizeBytes} is null
          and ${table.detectedMime} is null and ${table.verifiedAt} is null)
        or (${table.expectedSizeBytes} between 1 and 5000000000
          and ((${table.contentSha256} is null and ${table.sizeBytes} is null and ${table.detectedMime} is null and ${table.verifiedAt} is null)
            or (octet_length(${table.contentSha256}) = 32 and ${table.sizeBytes} = ${table.expectedSizeBytes}
              and octet_length(${table.detectedMime}) between 3 and 512 and ${table.verifiedAt} is not null))))`,
    ),
    check(
      "dfir_storage_objects_upload_expiry_check",
      sql`${table.uploadExpiresAt} > ${table.createdAt}
        and ${table.uploadExpiresAt} <= ${table.createdAt} + interval '1 hour'`,
    ),
    check(
      "dfir_storage_objects_cleanup_check",
      sql`${table.cleanupFence} between 0 and 9223372036854775806
        and ${table.cleanupAttemptCount} = ${table.cleanupFence}
        and (${table.cleanupLastFailureCode} is null or ${table.cleanupLastFailureCode} ~ '^[a-z][a-z0-9_.-]{0,63}$')
        and ((${table.cleanupClaimedAt} is null and ${table.cleanupLeaseExpiresAt} is null)
          or (${table.state} = 'pending_upload' and ${table.cleanupClaimedAt} >= ${table.createdAt}
            and ${table.cleanupLeaseExpiresAt} > ${table.cleanupClaimedAt}
            and ${table.cleanupLeaseExpiresAt} <= ${table.cleanupClaimedAt} + interval '15 minutes'))
        and (${table.state} <> 'deleted' or (${table.cleanupClaimedAt} is null and ${table.cleanupLeaseExpiresAt} is null))`,
    ),
    check(
      "dfir_storage_objects_retention_check",
      sql`${table.retentionUntil} is null or ${table.retentionUntil} >= ${table.createdAt}`,
    ),
    check(
      "dfir_storage_objects_version_check",
      sql`${table.version} between 1 and 9007199254740991`,
    ),
    check(
      "dfir_storage_objects_timestamps_check",
      sql`${table.updatedAt} >= ${table.createdAt} and (${table.verifiedAt} is null or ${table.verifiedAt} between ${table.createdAt} and ${table.updatedAt})`,
    ),
    pgPolicy("dfir_storage_objects_api_tenant", {
      as: "permissive",
      for: "all",
      to: apiRole,
      using: activeActorMembershipFor(table.tenantId),
      withCheck: activeActorMembershipFor(table.tenantId),
    }),
    pgPolicy("dfir_storage_objects_worker_tenant", {
      as: "permissive",
      for: "all",
      to: workerRole,
      using: sql`${table.tenantId} = ${currentTenantId}`,
      withCheck: sql`${table.tenantId} = ${currentTenantId}`,
    }),
  ],
).enableRLS();

export const dfirEvidence = pgTable(
  "dfir_evidence",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    alertId: uuid("alert_id"),
    caseId: uuid("case_id"),
    storageObjectId: uuid("storage_object_id").notNull(),
    title: text("title").notNull(),
    description: text("description").notNull().default(""),
    evidenceType: text("evidence_type").notNull(),
    classification: dfirEvidenceClassification("classification").notNull(),
    contentSha256: bytea("content_sha256").notNull(),
    sizeBytes: bigint("size_bytes", { mode: "bigint" }).notNull(),
    detectedMime: text("detected_mime").notNull(),
    collectedAt: timestamp("collected_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    collectedByMembershipId: uuid("collected_by_membership_id").notNull(),
    source: text("source").notNull(),
    initialRetentionUntil: timestamp("initial_retention_until", {
      withTimezone: true,
      mode: "date",
    }),
    retentionUntil: timestamp("retention_until", {
      withTimezone: true,
      mode: "date",
    }),
    initialLegalHold: boolean("initial_legal_hold").notNull().default(false),
    legalHold: boolean("legal_hold").notNull().default(false),
    initialScanState: dfirScanState("initial_scan_state").notNull(),
    scanState: dfirScanState("scan_state").notNull(),
    sealed: boolean("sealed").notNull().default(false),
    destroyed: boolean("destroyed").notNull().default(false),
    anchorHash: bytea("anchor_hash").notNull(),
    custodyHeadHash: bytea("custody_head_hash").notNull(),
    custodyCount: bigint("custody_count", { mode: "bigint" })
      .notNull()
      .default(sql`1`),
    version: bigint("version", { mode: "bigint" })
      .notNull()
      .default(sql`1`),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    unique("dfir_evidence_tenant_id_key").on(table.tenantId, table.id),
    unique("dfir_evidence_storage_object_key").on(
      table.tenantId,
      table.storageObjectId,
    ),
    index("dfir_evidence_case_idx").on(
      table.tenantId,
      table.caseId,
      table.collectedAt,
      table.id,
    ),
    index("dfir_evidence_alert_idx").on(
      table.tenantId,
      table.alertId,
      table.collectedAt,
      table.id,
    ),
    foreignKey({
      name: "dfir_evidence_alert_fk",
      columns: [table.tenantId, table.alertId],
      foreignColumns: [alerts.tenantId, alerts.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "dfir_evidence_case_fk",
      columns: [table.tenantId, table.caseId],
      foreignColumns: [cases.tenantId, cases.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "dfir_evidence_storage_fk",
      columns: [table.tenantId, table.storageObjectId],
      foreignColumns: [dfirStorageObjects.tenantId, dfirStorageObjects.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "dfir_evidence_collector_fk",
      columns: [table.tenantId, table.collectedByMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "dfir_evidence_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "dfir_evidence_root_check",
      sql`num_nonnulls(${table.alertId}, ${table.caseId}) = 1`,
    ),
    check(
      "dfir_evidence_text_check",
      sql`btrim(${table.title}) <> '' and octet_length(${table.title}) <= 512 and octet_length(${table.description}) <= 16384 and ${table.evidenceType} ~ '^[a-z][a-z0-9_.-]{0,63}$' and octet_length(${table.source}) between 1 and 512`,
    ),
    check(
      "dfir_evidence_content_check",
      sql`octet_length(${table.contentSha256}) = 32 and ${table.sizeBytes} between 1 and 5000000000 and octet_length(${table.detectedMime}) between 3 and 512`,
    ),
    check(
      "dfir_evidence_hash_check",
      sql`octet_length(${table.anchorHash}) = 32 and octet_length(${table.custodyHeadHash}) = 32`,
    ),
    check(
      "dfir_evidence_retention_check",
      sql`(${table.initialRetentionUntil} is null or ${table.initialRetentionUntil} >= ${table.collectedAt}) and (${table.retentionUntil} is null or ${table.retentionUntil} >= ${table.collectedAt})`,
    ),
    check(
      "dfir_evidence_destroyed_check",
      sql`not ${table.destroyed} or ${table.scanState} = 'deleted'`,
    ),
    check(
      "dfir_evidence_version_check",
      sql`${table.version} = ${table.custodyCount} and ${table.version} between 1 and 1000`,
    ),
    check(
      "dfir_evidence_timestamps_check",
      sql`${table.updatedAt} >= ${table.createdAt}`,
    ),
    pgPolicy("dfir_evidence_api_tenant", {
      as: "permissive",
      for: "all",
      to: apiRole,
      using: activeActorMembershipFor(table.tenantId),
      withCheck: activeActorMembershipFor(table.tenantId),
    }),
    pgPolicy("dfir_evidence_worker_tenant", {
      as: "permissive",
      for: "all",
      to: workerRole,
      using: sql`${table.tenantId} = ${currentTenantId}`,
      withCheck: sql`${table.tenantId} = ${currentTenantId}`,
    }),
  ],
).enableRLS();

export const dfirCustodyEvents = pgTable(
  "dfir_custody_events",
  {
    id: uuid("id").primaryKey(),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    evidenceId: uuid("evidence_id").notNull(),
    sequence: bigint("sequence", { mode: "bigint" }).notNull(),
    action: dfirCustodyAction("action").notNull(),
    actorPrincipalKind: ticketPrincipalKind("actor_principal_kind").notNull(),
    actorId: uuid("actor_id").notNull(),
    actorMembershipId: uuid("actor_membership_id"),
    actorUserId: uuid("actor_user_id"),
    actorServiceAccountId: uuid("actor_service_account_id"),
    reason: text("reason").notNull(),
    stateValue: text("state_value").notNull().default(""),
    previousHash: bytea("previous_hash").notNull(),
    eventHash: bytea("event_hash").notNull(),
    occurredAt: timestamp("occurred_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
  },
  (table) => [
    unique("dfir_custody_events_tenant_id_key").on(table.tenantId, table.id),
    unique("dfir_custody_events_evidence_sequence_key").on(
      table.tenantId,
      table.evidenceId,
      table.sequence,
    ),
    foreignKey({
      name: "dfir_custody_events_evidence_fk",
      columns: [table.tenantId, table.evidenceId],
      foreignColumns: [dfirEvidence.tenantId, dfirEvidence.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "dfir_custody_events_membership_fk",
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
      name: "dfir_custody_events_service_account_fk",
      columns: [table.tenantId, table.actorServiceAccountId],
      foreignColumns: [
        tenantServiceAccounts.tenantId,
        tenantServiceAccounts.id,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    index("dfir_custody_events_evidence_idx").on(
      table.tenantId,
      table.evidenceId,
      table.sequence,
    ),
    check(
      "dfir_custody_events_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "dfir_custody_events_sequence_check",
      sql`${table.sequence} between 1 and 1000`,
    ),
    check(
      "dfir_custody_events_actor_check",
      sql`(${table.actorPrincipalKind} = 'human' and ${table.actorMembershipId} is not null and ${table.actorUserId} is not null and ${table.actorServiceAccountId} is null and ${table.actorId} = ${table.actorUserId}) or (${table.actorPrincipalKind} = 'service_account' and ${table.actorMembershipId} is null and ${table.actorUserId} is null and ${table.actorServiceAccountId} is not null and ${table.actorId} = ${table.actorServiceAccountId}) or (${table.actorPrincipalKind} = 'system' and ${table.actorMembershipId} is null and ${table.actorUserId} is null and ${table.actorServiceAccountId} is null)`,
    ),
    check(
      "dfir_custody_events_reason_check",
      sql`btrim(${table.reason}) <> '' and octet_length(${table.reason}) <= 2000 and ${table.reason} !~ '[[:cntrl:]]'`,
    ),
    check(
      "dfir_custody_events_state_check",
      sql`octet_length(${table.stateValue}) <= 512 and ${table.stateValue} !~ '[[:cntrl:]]'`,
    ),
    check(
      "dfir_custody_events_hash_check",
      sql`octet_length(${table.previousHash}) = 32 and octet_length(${table.eventHash}) = 32`,
    ),
    pgPolicy("dfir_custody_events_api_tenant", {
      as: "permissive",
      for: "select",
      to: apiRole,
      using: activeActorMembershipFor(table.tenantId),
    }),
    pgPolicy("dfir_custody_events_worker_tenant", {
      as: "permissive",
      for: "select",
      to: workerRole,
      using: sql`${table.tenantId} = ${currentTenantId}`,
    }),
  ],
).enableRLS();

export const dfirTimelineEvents = pgTable(
  "dfir_timeline_events",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    alertId: uuid("alert_id"),
    caseId: uuid("case_id"),
    eventTime: timestamp("event_time", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    ingestedAt: timestamp("ingested_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    originalTimezone: text("original_timezone").notNull(),
    precision: dfirTemporalPrecision("precision").notNull(),
    source: text("source").notNull(),
    category: text("category").notNull(),
    title: text("title").notNull(),
    description: text("description").notNull().default(""),
    actorUserId: uuid("actor_user_id"),
    tags: text("tags")
      .array()
      .notNull()
      .default(sql`ARRAY[]::text[]`),
    createdByMembershipId: uuid("created_by_membership_id").notNull(),
    version: bigint("version", { mode: "bigint" })
      .notNull()
      .default(sql`1`),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    unique("dfir_timeline_events_tenant_id_key").on(table.tenantId, table.id),
    foreignKey({
      name: "dfir_timeline_events_alert_fk",
      columns: [table.tenantId, table.alertId],
      foreignColumns: [alerts.tenantId, alerts.id],
    })
      .onUpdate("cascade")
      .onDelete("cascade"),
    foreignKey({
      name: "dfir_timeline_events_case_fk",
      columns: [table.tenantId, table.caseId],
      foreignColumns: [cases.tenantId, cases.id],
    })
      .onUpdate("cascade")
      .onDelete("cascade"),
    foreignKey({
      name: "dfir_timeline_events_actor_fk",
      columns: [table.tenantId, table.actorUserId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.userId],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "dfir_timeline_events_creator_fk",
      columns: [table.tenantId, table.createdByMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    index("dfir_timeline_events_case_time_idx").on(
      table.tenantId,
      table.caseId,
      table.eventTime,
      table.id,
    ),
    index("dfir_timeline_events_alert_time_idx").on(
      table.tenantId,
      table.alertId,
      table.eventTime,
      table.id,
    ),
    check(
      "dfir_timeline_events_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "dfir_timeline_events_subject_check",
      sql`num_nonnulls(${table.alertId}, ${table.caseId}) = 1`,
    ),
    check(
      "dfir_timeline_events_text_check",
      sql`octet_length(${table.originalTimezone}) between 1 and 128 and octet_length(${table.source}) between 1 and 512 and ${table.category} ~ '^[a-z][a-z0-9_.-]{0,63}$' and octet_length(${table.title}) between 1 and 512 and octet_length(${table.description}) <= 16384`,
    ),
    check(
      "dfir_timeline_events_tags_check",
      sql`cardinality(${table.tags}) <= 256`,
    ),
    check(
      "dfir_timeline_events_version_check",
      sql`${table.version} between 1 and 9007199254740991 and ${table.updatedAt} >= ${table.createdAt}`,
    ),
    pgPolicy("dfir_timeline_events_api_tenant", {
      as: "permissive",
      for: "all",
      to: apiRole,
      using: activeActorMembershipFor(table.tenantId),
      withCheck: activeActorMembershipFor(table.tenantId),
    }),
  ],
).enableRLS();

export const dfirTimelineIOCLinks = pgTable(
  "dfir_timeline_ioc_links",
  {
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    timelineEventId: uuid("timeline_event_id").notNull(),
    iocId: uuid("ioc_id").notNull(),
  },
  (table) => [
    unique("dfir_timeline_ioc_links_key").on(
      table.tenantId,
      table.timelineEventId,
      table.iocId,
    ),
    foreignKey({
      name: "dfir_timeline_ioc_links_event_fk",
      columns: [table.tenantId, table.timelineEventId],
      foreignColumns: [dfirTimelineEvents.tenantId, dfirTimelineEvents.id],
    })
      .onUpdate("cascade")
      .onDelete("cascade"),
    foreignKey({
      name: "dfir_timeline_ioc_links_ioc_fk",
      columns: [table.tenantId, table.iocId],
      foreignColumns: [dfirIOCs.tenantId, dfirIOCs.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    pgPolicy("dfir_timeline_ioc_links_api_tenant", {
      as: "permissive",
      for: "all",
      to: apiRole,
      using: activeActorMembershipFor(table.tenantId),
      withCheck: activeActorMembershipFor(table.tenantId),
    }),
  ],
).enableRLS();

export const dfirTimelineAssetLinks = pgTable(
  "dfir_timeline_asset_links",
  {
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    timelineEventId: uuid("timeline_event_id").notNull(),
    assetId: uuid("asset_id").notNull(),
  },
  (table) => [
    unique("dfir_timeline_asset_links_key").on(
      table.tenantId,
      table.timelineEventId,
      table.assetId,
    ),
    foreignKey({
      name: "dfir_timeline_asset_links_event_fk",
      columns: [table.tenantId, table.timelineEventId],
      foreignColumns: [dfirTimelineEvents.tenantId, dfirTimelineEvents.id],
    })
      .onUpdate("cascade")
      .onDelete("cascade"),
    foreignKey({
      name: "dfir_timeline_asset_links_asset_fk",
      columns: [table.tenantId, table.assetId],
      foreignColumns: [dfirAssets.tenantId, dfirAssets.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    pgPolicy("dfir_timeline_asset_links_api_tenant", {
      as: "permissive",
      for: "all",
      to: apiRole,
      using: activeActorMembershipFor(table.tenantId),
      withCheck: activeActorMembershipFor(table.tenantId),
    }),
  ],
).enableRLS();

export const dfirTimelineEvidenceLinks = pgTable(
  "dfir_timeline_evidence_links",
  {
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    timelineEventId: uuid("timeline_event_id").notNull(),
    evidenceId: uuid("evidence_id").notNull(),
  },
  (table) => [
    unique("dfir_timeline_evidence_links_key").on(
      table.tenantId,
      table.timelineEventId,
      table.evidenceId,
    ),
    foreignKey({
      name: "dfir_timeline_evidence_links_event_fk",
      columns: [table.tenantId, table.timelineEventId],
      foreignColumns: [dfirTimelineEvents.tenantId, dfirTimelineEvents.id],
    })
      .onUpdate("cascade")
      .onDelete("cascade"),
    foreignKey({
      name: "dfir_timeline_evidence_links_evidence_fk",
      columns: [table.tenantId, table.evidenceId],
      foreignColumns: [dfirEvidence.tenantId, dfirEvidence.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    pgPolicy("dfir_timeline_evidence_links_api_tenant", {
      as: "permissive",
      for: "all",
      to: apiRole,
      using: activeActorMembershipFor(table.tenantId),
      withCheck: activeActorMembershipFor(table.tenantId),
    }),
  ],
).enableRLS();

export type DfirChecklistItem = {
  id: string;
  title: string;
  completed: boolean;
  completedAt?: string;
  completedBy?: string;
};

export const dfirTasks = pgTable(
  "dfir_tasks",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    alertId: uuid("alert_id"),
    caseId: uuid("case_id"),
    title: text("title").notNull(),
    description: text("description").notNull().default(""),
    status: dfirTaskStatus("status").notNull().default("todo"),
    priority: dfirTaskPriority("priority").notNull().default("medium"),
    assigneeUserId: uuid("assignee_user_id"),
    operatorTeamId: uuid("operator_team_id"),
    operatorTeamEpochId: uuid("operator_team_epoch_id"),
    dueAt: timestamp("due_at", { withTimezone: true, mode: "date" }),
    checklist: jsonb("checklist")
      .$type<DfirChecklistItem[]>()
      .notNull()
      .default([]),
    completedAt: timestamp("completed_at", {
      withTimezone: true,
      mode: "date",
    }),
    completedByUserId: uuid("completed_by_user_id"),
    completionData: jsonb("completion_data").$type<Record<string, unknown>>(),
    commentIds: uuid("comment_ids")
      .array()
      .notNull()
      .default(sql`ARRAY[]::uuid[]`),
    slaInstanceId: uuid("sla_instance_id"),
    createdByMembershipId: uuid("created_by_membership_id"),
    createdByServiceAccountId: uuid("created_by_service_account_id"),
    updatedByMembershipId: uuid("updated_by_membership_id"),
    updatedByServiceAccountId: uuid("updated_by_service_account_id"),
    version: bigint("version", { mode: "bigint" })
      .notNull()
      .default(sql`1`),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    unique("dfir_tasks_tenant_id_key").on(table.tenantId, table.id),
    foreignKey({
      name: "dfir_tasks_alert_fk",
      columns: [table.tenantId, table.alertId],
      foreignColumns: [alerts.tenantId, alerts.id],
    })
      .onUpdate("cascade")
      .onDelete("cascade"),
    foreignKey({
      name: "dfir_tasks_case_fk",
      columns: [table.tenantId, table.caseId],
      foreignColumns: [cases.tenantId, cases.id],
    })
      .onUpdate("cascade")
      .onDelete("cascade"),
    foreignKey({
      name: "dfir_tasks_assignee_fk",
      columns: [table.tenantId, table.assigneeUserId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.userId],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "dfir_tasks_team_epoch_fk",
      columns: [
        table.tenantId,
        table.operatorTeamEpochId,
        table.operatorTeamId,
      ],
      foreignColumns: [
        operatorTeamAssignmentEpochs.tenantId,
        operatorTeamAssignmentEpochs.id,
        operatorTeamAssignmentEpochs.operatorTeamId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "dfir_tasks_completer_fk",
      columns: [table.tenantId, table.completedByUserId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.userId],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "dfir_tasks_creator_fk",
      columns: [table.tenantId, table.createdByMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "dfir_tasks_creator_service_account_fk",
      columns: [table.tenantId, table.createdByServiceAccountId],
      foreignColumns: [
        tenantServiceAccounts.tenantId,
        tenantServiceAccounts.id,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "dfir_tasks_updater_fk",
      columns: [table.tenantId, table.updatedByMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "dfir_tasks_updater_service_account_fk",
      columns: [table.tenantId, table.updatedByServiceAccountId],
      foreignColumns: [
        tenantServiceAccounts.tenantId,
        tenantServiceAccounts.id,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    index("dfir_tasks_case_status_idx").on(
      table.tenantId,
      table.caseId,
      table.status,
      table.dueAt,
      table.id,
    ),
    index("dfir_tasks_alert_status_idx").on(
      table.tenantId,
      table.alertId,
      table.status,
      table.dueAt,
      table.id,
    ),
    index("dfir_tasks_assignee_idx").on(
      table.tenantId,
      table.assigneeUserId,
      table.status,
      table.id,
    ),
    check(
      "dfir_tasks_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "dfir_tasks_root_check",
      sql`num_nonnulls(${table.alertId}, ${table.caseId}) = 1`,
    ),
    check(
      "dfir_tasks_text_check",
      sql`octet_length(${table.title}) between 1 and 512 and octet_length(${table.description}) <= 16384`,
    ),
    check(
      "dfir_tasks_assignment_check",
      sql`${table.assigneeUserId} is null or (${table.operatorTeamId} is not null and ${table.operatorTeamEpochId} is not null)`,
    ),
    check(
      "dfir_tasks_attribution_check",
      sql`(${table.createdByMembershipId} is null) <>
            (${table.createdByServiceAccountId} is null)
        and (${table.updatedByMembershipId} is null) <>
            (${table.updatedByServiceAccountId} is null)`,
    ),
    check(
      "dfir_tasks_team_check",
      sql`(${table.operatorTeamId} is null) = (${table.operatorTeamEpochId} is null)`,
    ),
    check(
      "dfir_tasks_completion_check",
      sql`(${table.status} in ('done','cancelled')) = (${table.completedAt} is not null and ${table.completedByUserId} is not null) and (${table.status} in ('done','cancelled') or ${table.completionData} is null)`,
    ),
    check(
      "dfir_tasks_collection_check",
      sql`jsonb_typeof(${table.checklist}) = 'array' and jsonb_array_length(${table.checklist}) <= 100 and pg_column_size(${table.checklist}) <= 65536 and cardinality(${table.commentIds}) <= 1000 and (${table.completionData} is null or (jsonb_typeof(${table.completionData}) = 'object' and pg_column_size(${table.completionData}) <= 65536))`,
    ),
    check(
      "dfir_tasks_version_check",
      sql`${table.version} between 1 and 9007199254740991`,
    ),
    check(
      "dfir_tasks_timestamps_check",
      sql`${table.updatedAt} >= ${table.createdAt} and (${table.completedAt} is null or ${table.completedAt} between ${table.createdAt} and ${table.updatedAt})`,
    ),
    pgPolicy("dfir_tasks_api_tenant", {
      as: "permissive",
      for: "all",
      to: apiRole,
      using: activeActorMembershipFor(table.tenantId),
      withCheck: activeActorMembershipFor(table.tenantId),
    }),
  ],
).enableRLS();

export const dfirAttachments = pgTable(
  "dfir_attachments",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    subjectKind: dfirEntityKind("subject_kind").notNull(),
    alertId: uuid("alert_id"),
    caseId: uuid("case_id"),
    iocId: uuid("ioc_id"),
    assetId: uuid("asset_id"),
    evidenceId: uuid("evidence_id"),
    taskId: uuid("task_id"),
    storageObjectId: uuid("storage_object_id").notNull(),
    originalFilename: text("original_filename").notNull(),
    visibility: dfirVisibility("visibility").notNull(),
    scanState: dfirScanState("scan_state").notNull(),
    uploadedByMembershipId: uuid("uploaded_by_membership_id").notNull(),
    uploadedAt: timestamp("uploaded_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    version: bigint("version", { mode: "bigint" })
      .notNull()
      .default(sql`1`),
  },
  (table) => [
    unique("dfir_attachments_tenant_id_key").on(table.tenantId, table.id),
    unique("dfir_attachments_storage_key").on(
      table.tenantId,
      table.storageObjectId,
    ),
    foreignKey({
      name: "dfir_attachments_alert_fk",
      columns: [table.tenantId, table.alertId],
      foreignColumns: [alerts.tenantId, alerts.id],
    })
      .onUpdate("cascade")
      .onDelete("cascade"),
    foreignKey({
      name: "dfir_attachments_case_fk",
      columns: [table.tenantId, table.caseId],
      foreignColumns: [cases.tenantId, cases.id],
    })
      .onUpdate("cascade")
      .onDelete("cascade"),
    foreignKey({
      name: "dfir_attachments_ioc_fk",
      columns: [table.tenantId, table.iocId],
      foreignColumns: [dfirIOCs.tenantId, dfirIOCs.id],
    })
      .onUpdate("cascade")
      .onDelete("cascade"),
    foreignKey({
      name: "dfir_attachments_asset_fk",
      columns: [table.tenantId, table.assetId],
      foreignColumns: [dfirAssets.tenantId, dfirAssets.id],
    })
      .onUpdate("cascade")
      .onDelete("cascade"),
    foreignKey({
      name: "dfir_attachments_evidence_fk",
      columns: [table.tenantId, table.evidenceId],
      foreignColumns: [dfirEvidence.tenantId, dfirEvidence.id],
    })
      .onUpdate("cascade")
      .onDelete("cascade"),
    foreignKey({
      name: "dfir_attachments_task_fk",
      columns: [table.tenantId, table.taskId],
      foreignColumns: [dfirTasks.tenantId, dfirTasks.id],
    })
      .onUpdate("cascade")
      .onDelete("cascade"),
    foreignKey({
      name: "dfir_attachments_storage_fk",
      columns: [table.tenantId, table.storageObjectId],
      foreignColumns: [dfirStorageObjects.tenantId, dfirStorageObjects.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "dfir_attachments_uploader_fk",
      columns: [table.tenantId, table.uploadedByMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    index("dfir_attachments_case_idx").on(
      table.tenantId,
      table.caseId,
      table.uploadedAt,
      table.id,
    ),
    index("dfir_attachments_alert_idx").on(
      table.tenantId,
      table.alertId,
      table.uploadedAt,
      table.id,
    ),
    check(
      "dfir_attachments_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "dfir_attachments_subject_check",
      sql`num_nonnulls(${table.alertId},${table.caseId},${table.iocId},${table.assetId},${table.evidenceId},${table.taskId}) = 1 and (${table.subjectKind} = 'alert') = (${table.alertId} is not null) and (${table.subjectKind} = 'case') = (${table.caseId} is not null) and (${table.subjectKind} = 'ioc') = (${table.iocId} is not null) and (${table.subjectKind} = 'asset') = (${table.assetId} is not null) and (${table.subjectKind} = 'evidence') = (${table.evidenceId} is not null) and (${table.subjectKind} = 'task') = (${table.taskId} is not null)`,
    ),
    check(
      "dfir_attachments_filename_check",
      sql`octet_length(${table.originalFilename}) between 1 and 255 and ${table.originalFilename} !~ '[/\\\\[:cntrl:]]' and ${table.originalFilename} not in ('.','..')`,
    ),
    check(
      "dfir_attachments_state_check",
      sql`${table.version} > 0 and (${table.scanState} <> 'deleted' or ${table.visibility} = 'private')`,
    ),
    pgPolicy("dfir_attachments_api_tenant", {
      as: "permissive",
      for: "all",
      to: apiRole,
      using: activeActorMembershipFor(table.tenantId),
      withCheck: activeActorMembershipFor(table.tenantId),
    }),
  ],
).enableRLS();

/**
 * Immutable provenance for attachments shared from an Alert into an
 * escalation Case. The source attachment remains physically attached to the
 * Alert; consumers resolve Case visibility through this tenant-bound ledger.
 */
export const dfirAttachmentCaseLinks = pgTable(
  "dfir_attachment_case_links",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    attachmentId: uuid("attachment_id").notNull(),
    caseId: uuid("case_id").notNull(),
    sourceAlertId: uuid("source_alert_id").notNull(),
    sourceAlertVersion: integer("source_alert_version").notNull(),
    escalationLinkId: uuid("escalation_link_id").notNull(),
    createdByMembershipId: uuid("created_by_membership_id").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    unique("dfir_attachment_case_links_tenant_id_key").on(
      table.tenantId,
      table.id,
    ),
    unique("dfir_attachment_case_links_exact_key").on(
      table.tenantId,
      table.attachmentId,
      table.caseId,
    ),
    index("dfir_attachment_case_links_case_idx").on(
      table.tenantId,
      table.caseId,
      table.createdAt,
      table.id,
    ),
    foreignKey({
      name: "dfir_attachment_case_links_attachment_fk",
      columns: [table.tenantId, table.attachmentId],
      foreignColumns: [dfirAttachments.tenantId, dfirAttachments.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "dfir_attachment_case_links_case_fk",
      columns: [table.tenantId, table.caseId],
      foreignColumns: [cases.tenantId, cases.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "dfir_attachment_case_links_source_alert_fk",
      columns: [table.tenantId, table.sourceAlertId],
      foreignColumns: [alerts.tenantId, alerts.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "dfir_attachment_case_links_escalation_fk",
      columns: [table.tenantId, table.escalationLinkId],
      foreignColumns: [alertCaseLinks.tenantId, alertCaseLinks.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "dfir_attachment_case_links_creator_fk",
      columns: [table.tenantId, table.createdByMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "dfir_attachment_case_links_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "dfir_attachment_case_links_source_version_check",
      sql`${table.sourceAlertVersion} > 0`,
    ),
    pgPolicy("dfir_attachment_case_links_api_tenant", {
      as: "permissive",
      for: "select",
      to: apiRole,
      using: activeActorMembershipFor(table.tenantId),
    }),
  ],
).enableRLS();

export const dfirRelationships = pgTable(
  "dfir_relationships",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    alertId: uuid("alert_id"),
    caseId: uuid("case_id"),
    sourceKind: dfirEntityKind("source_kind").notNull(),
    sourceId: uuid("source_id"),
    sourceExternalType: text("source_external_type"),
    sourceExternalId: text("source_external_id"),
    targetKind: dfirEntityKind("target_kind").notNull(),
    targetId: uuid("target_id"),
    targetExternalType: text("target_external_type"),
    targetExternalId: text("target_external_id"),
    relationshipType: text("relationship_type").notNull(),
    metadata: jsonb("metadata").$type<Record<string, unknown>>(),
    createdByMembershipId: uuid("created_by_membership_id").notNull(),
    version: bigint("version", { mode: "bigint" })
      .notNull()
      .default(sql`1`),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    unique("dfir_relationships_tenant_id_key").on(table.tenantId, table.id),
    unique("dfir_relationships_alert_root_key").on(
      table.tenantId,
      table.id,
      table.alertId,
    ),
    unique("dfir_relationships_case_root_key").on(
      table.tenantId,
      table.id,
      table.caseId,
    ),
    foreignKey({
      name: "dfir_relationships_alert_fk",
      columns: [table.tenantId, table.alertId],
      foreignColumns: [alerts.tenantId, alerts.id],
    })
      .onUpdate("cascade")
      .onDelete("cascade"),
    foreignKey({
      name: "dfir_relationships_case_fk",
      columns: [table.tenantId, table.caseId],
      foreignColumns: [cases.tenantId, cases.id],
    })
      .onUpdate("cascade")
      .onDelete("cascade"),
    foreignKey({
      name: "dfir_relationships_creator_fk",
      columns: [table.tenantId, table.createdByMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    index("dfir_relationships_source_idx").on(
      table.tenantId,
      table.sourceKind,
      table.sourceId,
      table.createdAt,
      table.id,
    ),
    index("dfir_relationships_alert_idx").on(
      table.tenantId,
      table.alertId,
      table.createdAt,
      table.id,
    ),
    index("dfir_relationships_case_idx").on(
      table.tenantId,
      table.caseId,
      table.createdAt,
      table.id,
    ),
    index("dfir_relationships_target_idx").on(
      table.tenantId,
      table.targetKind,
      table.targetId,
      table.createdAt,
      table.id,
    ),
    check(
      "dfir_relationships_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "dfir_relationships_root_check",
      sql`num_nonnulls(${table.alertId}, ${table.caseId}) = 1`,
    ),
    check(
      "dfir_relationships_source_check",
      sql`(${table.sourceKind} = 'external' and ${table.sourceId} is null and ${table.sourceExternalType} ~ '^[a-z][a-z0-9_.-]{0,63}$' and octet_length(${table.sourceExternalId}) between 1 and 2048) or (${table.sourceKind} <> 'external' and ${table.sourceId} is not null and ${table.sourceExternalType} is null and ${table.sourceExternalId} is null)`,
    ),
    check(
      "dfir_relationships_target_check",
      sql`(${table.targetKind} = 'external' and ${table.targetId} is null and ${table.targetExternalType} ~ '^[a-z][a-z0-9_.-]{0,63}$' and octet_length(${table.targetExternalId}) between 1 and 2048) or (${table.targetKind} <> 'external' and ${table.targetId} is not null and ${table.targetExternalType} is null and ${table.targetExternalId} is null)`,
    ),
    check(
      "dfir_relationships_distinct_check",
      sql`row(${table.sourceKind},${table.sourceId},${table.sourceExternalType},${table.sourceExternalId}) is distinct from row(${table.targetKind},${table.targetId},${table.targetExternalType},${table.targetExternalId})`,
    ),
    check(
      "dfir_relationships_type_check",
      sql`${table.relationshipType} ~ '^[a-z][a-z0-9_.-]{0,63}$'
        and not (${table.sourceKind} = 'alert' and ${table.targetKind} = 'alert'
          and ${table.relationshipType} in ('duplicate_of', 'correlation'))`,
    ),
    check(
      "dfir_relationships_metadata_check",
      sql`${table.metadata} is null or (jsonb_typeof(${table.metadata}) = 'object' and octet_length(${table.metadata}::text) <= 65536)`,
    ),
    check(
      "dfir_relationships_version_check",
      sql`${table.version} between 1 and 9007199254740991`,
    ),
    pgPolicy("dfir_relationships_api_tenant", {
      as: "permissive",
      for: "all",
      to: apiRole,
      using: activeActorMembershipFor(table.tenantId),
      withCheck: activeActorMembershipFor(table.tenantId),
    }),
  ],
).enableRLS();

/** Terminal append-only evidence for a retracted general DFIR relationship. */
export const dfirRelationshipRetractions = pgTable(
  "dfir_relationship_retractions",
  {
    id: uuid("id").primaryKey(),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    relationshipId: uuid("relationship_id").notNull(),
    alertId: uuid("alert_id"),
    caseId: uuid("case_id"),
    retractedByMembershipId: uuid("retracted_by_membership_id").notNull(),
    reason: text("reason").notNull(),
    priorVersion: bigint("prior_version", { mode: "bigint" }).notNull(),
    resultVersion: bigint("result_version", { mode: "bigint" }).notNull(),
    retractedAt: timestamp("retracted_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
  },
  (table) => [
    unique("dfir_relationship_retractions_tenant_id_key").on(
      table.tenantId,
      table.id,
    ),
    unique("dfir_relationship_retractions_relationship_key").on(
      table.tenantId,
      table.relationshipId,
    ),
    foreignKey({
      name: "dfir_relationship_retractions_relationship_fk",
      columns: [table.tenantId, table.relationshipId],
      foreignColumns: [dfirRelationships.tenantId, dfirRelationships.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "dfir_relationship_retractions_alert_root_fk",
      columns: [table.tenantId, table.relationshipId, table.alertId],
      foreignColumns: [
        dfirRelationships.tenantId,
        dfirRelationships.id,
        dfirRelationships.alertId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "dfir_relationship_retractions_case_root_fk",
      columns: [table.tenantId, table.relationshipId, table.caseId],
      foreignColumns: [
        dfirRelationships.tenantId,
        dfirRelationships.id,
        dfirRelationships.caseId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "dfir_relationship_retractions_alert_fk",
      columns: [table.tenantId, table.alertId],
      foreignColumns: [alerts.tenantId, alerts.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "dfir_relationship_retractions_case_fk",
      columns: [table.tenantId, table.caseId],
      foreignColumns: [cases.tenantId, cases.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "dfir_relationship_retractions_actor_fk",
      columns: [table.tenantId, table.retractedByMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    index("dfir_relationship_retractions_alert_idx").on(
      table.tenantId,
      table.alertId,
      table.retractedAt,
      table.id,
    ),
    index("dfir_relationship_retractions_case_idx").on(
      table.tenantId,
      table.caseId,
      table.retractedAt,
      table.id,
    ),
    check(
      "dfir_relationship_retractions_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "dfir_relationship_retractions_root_check",
      sql`num_nonnulls(${table.alertId}, ${table.caseId}) = 1`,
    ),
    check(
      "dfir_relationship_retractions_reason_check",
      sql`btrim(${table.reason}) <> '' and octet_length(${table.reason}) <= 2000
        and ${table.reason} !~ '[[:cntrl:]]'`,
    ),
    check(
      "dfir_relationship_retractions_version_check",
      sql`${table.priorVersion} between 1 and 9007199254740990
        and ${table.resultVersion} = ${table.priorVersion} + 1`,
    ),
    pgPolicy("dfir_relationship_retractions_api_tenant", {
      as: "permissive",
      for: "select",
      to: apiRole,
      using: activeActorMembershipFor(table.tenantId),
    }),
  ],
).enableRLS();

export const dfirActivities = pgTable(
  "dfir_activities",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    alertId: uuid("alert_id"),
    caseId: uuid("case_id"),
    resourceKind: dfirEntityKind("resource_kind").notNull(),
    resourceId: uuid("resource_id").notNull(),
    action: text("action").notNull(),
    summary: text("summary").notNull(),
    actorPrincipalKind: ticketPrincipalKind("actor_principal_kind").notNull(),
    actorMembershipId: uuid("actor_membership_id"),
    actorUserId: uuid("actor_user_id"),
    actorServiceAccountId: uuid("actor_service_account_id"),
    details: jsonb("details")
      .$type<Record<string, unknown>>()
      .notNull()
      .default({}),
    occurredAt: timestamp("occurred_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    unique("dfir_activities_tenant_id_key").on(table.tenantId, table.id),
    foreignKey({
      name: "dfir_activities_alert_fk",
      columns: [table.tenantId, table.alertId],
      foreignColumns: [alerts.tenantId, alerts.id],
    })
      .onUpdate("cascade")
      .onDelete("cascade"),
    foreignKey({
      name: "dfir_activities_case_fk",
      columns: [table.tenantId, table.caseId],
      foreignColumns: [cases.tenantId, cases.id],
    })
      .onUpdate("cascade")
      .onDelete("cascade"),
    foreignKey({
      name: "dfir_activities_membership_fk",
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
      name: "dfir_activities_service_account_fk",
      columns: [table.tenantId, table.actorServiceAccountId],
      foreignColumns: [
        tenantServiceAccounts.tenantId,
        tenantServiceAccounts.id,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    index("dfir_activities_case_idx").on(
      table.tenantId,
      table.caseId,
      table.occurredAt,
      table.id,
    ),
    index("dfir_activities_alert_idx").on(
      table.tenantId,
      table.alertId,
      table.occurredAt,
      table.id,
    ),
    check(
      "dfir_activities_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "dfir_activities_root_check",
      sql`num_nonnulls(${table.alertId}, ${table.caseId}) = 1`,
    ),
    check(
      "dfir_activities_resource_check",
      sql`${table.resourceKind} <> 'external'`,
    ),
    check(
      "dfir_activities_action_check",
      sql`${table.action} ~ '^dfir\\.[a-z][a-z0-9_.-]{1,63}$'`,
    ),
    check(
      "dfir_activities_summary_check",
      sql`octet_length(${table.summary}) between 1 and 512 and ${table.summary} !~ '[[:cntrl:]]'`,
    ),
    check(
      "dfir_activities_actor_check",
      sql`(${table.actorPrincipalKind} = 'human' and ${table.actorMembershipId} is not null and ${table.actorUserId} is not null and ${table.actorServiceAccountId} is null) or (${table.actorPrincipalKind} = 'service_account' and ${table.actorMembershipId} is null and ${table.actorUserId} is null and ${table.actorServiceAccountId} is not null) or (${table.actorPrincipalKind} = 'system' and ${table.actorMembershipId} is null and ${table.actorUserId} is null and ${table.actorServiceAccountId} is null)`,
    ),
    check(
      "dfir_activities_details_check",
      sql`jsonb_typeof(${table.details}) = 'object' and pg_column_size(${table.details}) <= 65536`,
    ),
    pgPolicy("dfir_activities_api_tenant", {
      as: "permissive",
      for: "select",
      to: apiRole,
      using: activeActorMembershipFor(table.tenantId),
    }),
    pgPolicy("dfir_activities_worker_tenant", {
      as: "permissive",
      for: "select",
      to: workerRole,
      using: sql`${table.tenantId} = ${currentTenantId}`,
    }),
  ],
).enableRLS();
