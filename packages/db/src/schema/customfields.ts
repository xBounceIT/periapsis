import { sql } from "drizzle-orm";
import {
  bigint,
  boolean,
  check,
  cidr,
  date,
  foreignKey,
  index,
  inet,
  integer,
  jsonb,
  numeric,
  pgEnum,
  pgPolicy,
  pgTable,
  text,
  timestamp,
  unique,
  uniqueIndex,
  uuid,
} from "drizzle-orm/pg-core";

import { alerts } from "./alerts.js";
import { activeActorMembershipFor, tenantMemberships } from "./identity.js";
import { apiRole } from "./roles.js";
import { tenants } from "./tenancy.js";
import { cases } from "./ticketing.js";

export const customFieldObjectType = pgEnum("custom_field_object_type", [
  "alert",
  "case",
]);

export const customFieldDataType = pgEnum("custom_field_data_type", [
  "short_text",
  "long_text",
  "integer",
  "decimal",
  "boolean",
  "date",
  "datetime",
  "duration",
  "single_select",
  "multi_select",
  "url",
  "email",
  "ip",
  "cidr",
  "user",
  "operator_team",
  "customer_contact",
  "asset_reference",
  "ioc_reference",
  "structured_json",
]);

export const customFieldAudience = pgEnum("custom_field_audience", [
  "customer",
  "operator",
]);

export const customFieldValuePresence = pgEnum("custom_field_value_presence", [
  "null",
  "present",
]);

export const customFieldMigrationKind = pgEnum("custom_field_migration_kind", [
  "data_type",
  "option_removal",
  "constraints",
]);

export const customFieldMigrationStatus = pgEnum(
  "custom_field_migration_status",
  ["planned", "running", "completed", "failed", "cancelled"],
);

export type CustomFieldDefinitionSnapshot = {
  key: string;
  label: string;
  description: string;
  dataType: string;
  required: boolean;
  nullable: boolean;
  defaultPresence: "missing" | "null" | "present";
  defaultValue?: unknown;
  constraints: Record<string, unknown>;
  options: Array<{
    id: string;
    key: string;
    label: string;
    position: number;
    archived: boolean;
  }>;
  permissions: Array<Record<string, unknown>>;
  placement: Record<string, boolean>;
  capabilities: Record<string, boolean>;
  requiredOnTransitions: string[];
};

export const customFieldDefinitions = pgTable(
  "custom_field_definitions",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    objectType: customFieldObjectType("object_type").notNull(),
    key: text("key").notNull(),
    label: text("label").notNull(),
    description: text("description").notNull().default(""),
    dataType: customFieldDataType("data_type").notNull(),
    required: boolean("required").notNull().default(false),
    nullable: boolean("nullable").notNull().default(false),
    hasDefault: boolean("has_default").notNull().default(false),
    defaultValue: jsonb("default_value").$type<unknown>(),
    minimumLength: integer("minimum_length"),
    maximumLength: integer("maximum_length"),
    minimumNumber: text("minimum_number"),
    maximumNumber: text("maximum_number"),
    validationPattern: text("validation_pattern"),
    showInCreate: boolean("show_in_create").notNull().default(true),
    showInDetail: boolean("show_in_detail").notNull().default(true),
    showInList: boolean("show_in_list").notNull().default(false),
    showInExport: boolean("show_in_export").notNull().default(false),
    requiredOnTransitions: text("required_on_transitions")
      .array()
      .notNull()
      .default(sql`ARRAY[]::text[]`),
    searchable: boolean("searchable").notNull().default(false),
    filterable: boolean("filterable").notNull().default(false),
    sortable: boolean("sortable").notNull().default(false),
    allowStructuredJson: boolean("allow_structured_json")
      .notNull()
      .default(false),
    schemaVersion: bigint("schema_version", { mode: "bigint" })
      .notNull()
      .default(sql`1`),
    createdByMembershipId: uuid("created_by_membership_id").notNull(),
    updatedByMembershipId: uuid("updated_by_membership_id").notNull(),
    archivedByMembershipId: uuid("archived_by_membership_id"),
    archivedAt: timestamp("archived_at", { withTimezone: true, mode: "date" }),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    unique("custom_field_definitions_tenant_id_key").on(
      table.tenantId,
      table.id,
    ),
    unique("custom_field_definitions_tenant_object_key_key").on(
      table.tenantId,
      table.objectType,
      table.key,
    ),
    index("custom_field_definitions_inventory_idx").on(
      table.tenantId,
      table.objectType,
      table.archivedAt,
      table.key,
      table.id,
    ),
    foreignKey({
      name: "custom_field_definitions_creator_fk",
      columns: [table.tenantId, table.createdByMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "custom_field_definitions_updater_fk",
      columns: [table.tenantId, table.updatedByMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "custom_field_definitions_archiver_fk",
      columns: [table.tenantId, table.archivedByMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "custom_field_definitions_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "custom_field_definitions_key_check",
      sql`${table.key} ~ '^[a-z][a-z0-9_.-]{0,63}$'`,
    ),
    check(
      "custom_field_definitions_text_check",
      sql`btrim(${table.label}) <> '' and octet_length(${table.label}) <= 256
        and ${table.label} !~ '[[:cntrl:]]'
        and octet_length(${table.description}) <= 8192
        and ${table.description} !~ '[[:cntrl:]\u202a-\u202e\u2066-\u2069]'`,
    ),
    check(
      "custom_field_definitions_default_check",
      sql`(${table.hasDefault} and ${table.defaultValue} is not null and pg_column_size(${table.defaultValue}) <= 65536)
        or (not ${table.hasDefault} and ${table.defaultValue} is null)`,
    ),
    check(
      "custom_field_definitions_length_check",
      sql`(${table.minimumLength} is null or ${table.minimumLength} between 0 and 65536)
        and (${table.maximumLength} is null or ${table.maximumLength} between 0 and 65536)
        and (${table.minimumLength} is null or ${table.maximumLength} is null or ${table.minimumLength} <= ${table.maximumLength})`,
    ),
    check(
      "custom_field_definitions_numeric_check",
      sql`(${table.minimumNumber} is null or ${table.minimumNumber} ~ '^-?(0|[1-9][0-9]*)(\\.[0-9]+)?$')
        and (${table.maximumNumber} is null or ${table.maximumNumber} ~ '^-?(0|[1-9][0-9]*)(\\.[0-9]+)?$')
        and (${table.minimumNumber} is null or octet_length(${table.minimumNumber}) <= 256)
        and (${table.maximumNumber} is null or octet_length(${table.maximumNumber}) <= 256)`,
    ),
    check(
      "custom_field_definitions_pattern_check",
      sql`${table.validationPattern} is null or octet_length(${table.validationPattern}) between 1 and 512`,
    ),
    check(
      "custom_field_definitions_transition_check",
      sql`cardinality(${table.requiredOnTransitions}) <= 128`,
    ),
    check(
      "custom_field_definitions_structured_json_check",
      sql`(${table.dataType} = 'structured_json') = ${table.allowStructuredJson}`,
    ),
    check(
      "custom_field_definitions_schema_version_check",
      sql`${table.schemaVersion} between 1 and 9223372036854775806`,
    ),
    check(
      "custom_field_definitions_archive_check",
      sql`(${table.archivedAt} is null) = (${table.archivedByMembershipId} is null)
        and (${table.archivedAt} is null or (not ${table.required} and not ${table.showInCreate}))`,
    ),
    check(
      "custom_field_definitions_timestamps_check",
      sql`${table.updatedAt} >= ${table.createdAt}
        and (${table.archivedAt} is null or ${table.archivedAt} >= ${table.createdAt})`,
    ),
    pgPolicy("custom_field_definitions_api_tenant", {
      as: "permissive",
      for: "all",
      to: apiRole,
      using: activeActorMembershipFor(table.tenantId),
      withCheck: activeActorMembershipFor(table.tenantId),
    }),
  ],
).enableRLS();

export const customFieldDefinitionRevisions = pgTable(
  "custom_field_definition_revisions",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    definitionId: uuid("definition_id").notNull(),
    objectType: customFieldObjectType("object_type").notNull(),
    schemaVersion: bigint("schema_version", { mode: "bigint" }).notNull(),
    snapshot: jsonb("snapshot")
      .$type<CustomFieldDefinitionSnapshot>()
      .notNull(),
    createdByMembershipId: uuid("created_by_membership_id").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    unique("custom_field_definition_revisions_tenant_id_key").on(
      table.tenantId,
      table.id,
    ),
    unique("custom_field_definition_revisions_version_key").on(
      table.tenantId,
      table.definitionId,
      table.schemaVersion,
    ),
    foreignKey({
      name: "custom_field_definition_revisions_definition_fk",
      columns: [table.tenantId, table.definitionId],
      foreignColumns: [
        customFieldDefinitions.tenantId,
        customFieldDefinitions.id,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "custom_field_definition_revisions_creator_fk",
      columns: [table.tenantId, table.createdByMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "custom_field_definition_revisions_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "custom_field_definition_revisions_version_check",
      sql`${table.schemaVersion} between 1 and 9223372036854775806`,
    ),
    check(
      "custom_field_definition_revisions_snapshot_check",
      sql`jsonb_typeof(${table.snapshot}) = 'object' and pg_column_size(${table.snapshot}) <= 262144`,
    ),
    pgPolicy("custom_field_definition_revisions_api_tenant", {
      as: "permissive",
      for: "all",
      to: apiRole,
      using: activeActorMembershipFor(table.tenantId),
      withCheck: activeActorMembershipFor(table.tenantId),
    }),
  ],
).enableRLS();

export const customFieldOptions = pgTable(
  "custom_field_options",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    definitionId: uuid("definition_id").notNull(),
    key: text("key").notNull(),
    label: text("label").notNull(),
    position: integer("position").notNull(),
    introducedInSchemaVersion: bigint("introduced_in_schema_version", {
      mode: "bigint",
    }).notNull(),
    archivedInSchemaVersion: bigint("archived_in_schema_version", {
      mode: "bigint",
    }),
    archivedAt: timestamp("archived_at", { withTimezone: true, mode: "date" }),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    unique("custom_field_options_tenant_id_key").on(table.tenantId, table.id),
    unique("custom_field_options_definition_key_key").on(
      table.tenantId,
      table.definitionId,
      table.key,
    ),
    unique("custom_field_options_definition_position_key").on(
      table.tenantId,
      table.definitionId,
      table.position,
    ),
    foreignKey({
      name: "custom_field_options_definition_fk",
      columns: [table.tenantId, table.definitionId],
      foreignColumns: [
        customFieldDefinitions.tenantId,
        customFieldDefinitions.id,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    index("custom_field_options_inventory_idx").on(
      table.tenantId,
      table.definitionId,
      table.position,
      table.id,
    ),
    check(
      "custom_field_options_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "custom_field_options_key_check",
      sql`${table.key} ~ '^[a-z][a-z0-9_.-]{0,63}$'`,
    ),
    check(
      "custom_field_options_label_check",
      sql`btrim(${table.label}) <> '' and octet_length(${table.label}) <= 256 and ${table.label} !~ '[[:cntrl:]]'`,
    ),
    check(
      "custom_field_options_position_check",
      sql`${table.position} between 0 and 65535`,
    ),
    check(
      "custom_field_options_version_check",
      sql`${table.introducedInSchemaVersion} > 0
        and (${table.archivedInSchemaVersion} is null or ${table.archivedInSchemaVersion} > ${table.introducedInSchemaVersion})
        and (${table.archivedInSchemaVersion} is null) = (${table.archivedAt} is null)`,
    ),
    pgPolicy("custom_field_options_api_tenant", {
      as: "permissive",
      for: "all",
      to: apiRole,
      using: activeActorMembershipFor(table.tenantId),
      withCheck: activeActorMembershipFor(table.tenantId),
    }),
  ],
).enableRLS();

export const customFieldPermissions = pgTable(
  "custom_field_permissions",
  {
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    definitionId: uuid("definition_id").notNull(),
    audience: customFieldAudience("audience").notNull(),
    canRead: boolean("can_read").notNull().default(false),
    canCreate: boolean("can_create").notNull().default(false),
    canUpdate: boolean("can_update").notNull().default(false),
    schemaVersion: bigint("schema_version", { mode: "bigint" }).notNull(),
    updatedAt: timestamp("updated_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    unique("custom_field_permissions_key").on(
      table.tenantId,
      table.definitionId,
      table.audience,
    ),
    foreignKey({
      name: "custom_field_permissions_definition_fk",
      columns: [table.tenantId, table.definitionId],
      foreignColumns: [
        customFieldDefinitions.tenantId,
        customFieldDefinitions.id,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "custom_field_permissions_write_requires_read_check",
      sql`(not ${table.canCreate} and not ${table.canUpdate}) or ${table.canRead}`,
    ),
    check(
      "custom_field_permissions_version_check",
      sql`${table.schemaVersion} between 1 and 9223372036854775806`,
    ),
    pgPolicy("custom_field_permissions_api_tenant", {
      as: "permissive",
      for: "all",
      to: apiRole,
      using: activeActorMembershipFor(table.tenantId),
      withCheck: activeActorMembershipFor(table.tenantId),
    }),
  ],
).enableRLS();

export type CustomFieldLayoutSection = {
  key: string;
  label: string;
  position: number;
  definitionIds: string[];
};

export const customFieldLayouts = pgTable(
  "custom_field_layouts",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    objectType: customFieldObjectType("object_type").notNull(),
    audience: customFieldAudience("audience").notNull(),
    schemaVersion: bigint("schema_version", { mode: "bigint" })
      .notNull()
      .default(sql`1`),
    sections: jsonb("sections").$type<CustomFieldLayoutSection[]>().notNull(),
    updatedByMembershipId: uuid("updated_by_membership_id").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    unique("custom_field_layouts_tenant_id_key").on(table.tenantId, table.id),
    unique("custom_field_layouts_tenant_object_audience_key").on(
      table.tenantId,
      table.objectType,
      table.audience,
    ),
    foreignKey({
      name: "custom_field_layouts_updater_fk",
      columns: [table.tenantId, table.updatedByMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "custom_field_layouts_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "custom_field_layouts_version_check",
      sql`${table.schemaVersion} between 1 and 9223372036854775806`,
    ),
    check(
      "custom_field_layouts_sections_check",
      sql`jsonb_typeof(${table.sections}) = 'array'
        and jsonb_array_length(${table.sections}) between 1 and 64
        and pg_column_size(${table.sections}) <= 262144`,
    ),
    check(
      "custom_field_layouts_timestamps_check",
      sql`${table.updatedAt} >= ${table.createdAt}`,
    ),
    pgPolicy("custom_field_layouts_api_tenant", {
      as: "permissive",
      for: "all",
      to: apiRole,
      using: activeActorMembershipFor(table.tenantId),
      withCheck: activeActorMembershipFor(table.tenantId),
    }),
  ],
).enableRLS();

export const customFieldMigrations = pgTable(
  "custom_field_migrations",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    definitionId: uuid("definition_id").notNull(),
    kind: customFieldMigrationKind("kind").notNull(),
    fromDataType: customFieldDataType("from_data_type").notNull(),
    toDataType: customFieldDataType("to_data_type").notNull(),
    fromSchemaVersion: bigint("from_schema_version", {
      mode: "bigint",
    }).notNull(),
    toSchemaVersion: bigint("to_schema_version", { mode: "bigint" }).notNull(),
    status: customFieldMigrationStatus("status").notNull().default("planned"),
    planDigest: text("plan_digest").notNull(),
    reason: text("reason").notNull(),
    affectedValues: bigint("affected_values", { mode: "bigint" }),
    completedAt: timestamp("completed_at", {
      withTimezone: true,
      mode: "date",
    }),
    createdByMembershipId: uuid("created_by_membership_id").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    unique("custom_field_migrations_tenant_id_key").on(
      table.tenantId,
      table.id,
    ),
    unique("custom_field_migrations_definition_version_key").on(
      table.tenantId,
      table.definitionId,
      table.toSchemaVersion,
    ),
    foreignKey({
      name: "custom_field_migrations_definition_fk",
      columns: [table.tenantId, table.definitionId],
      foreignColumns: [
        customFieldDefinitions.tenantId,
        customFieldDefinitions.id,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "custom_field_migrations_creator_fk",
      columns: [table.tenantId, table.createdByMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    index("custom_field_migrations_status_idx").on(
      table.tenantId,
      table.status,
      table.createdAt,
      table.id,
    ),
    check(
      "custom_field_migrations_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "custom_field_migrations_version_check",
      sql`${table.fromSchemaVersion} > 0 and ${table.toSchemaVersion} = ${table.fromSchemaVersion} + 1`,
    ),
    check(
      "custom_field_migrations_digest_check",
      sql`${table.planDigest} ~ '^[0-9a-f]{64}$'`,
    ),
    check(
      "custom_field_migrations_reason_check",
      sql`btrim(${table.reason}) <> '' and octet_length(${table.reason}) <= 2000 and ${table.reason} !~ '[[:cntrl:]]'`,
    ),
    check(
      "custom_field_migrations_completion_check",
      sql`(${table.status} = 'completed') = (${table.completedAt} is not null)
        and (${table.affectedValues} is null or ${table.affectedValues} >= 0)
        and ${table.updatedAt} >= ${table.createdAt}`,
    ),
    pgPolicy("custom_field_migrations_api_tenant", {
      as: "permissive",
      for: "all",
      to: apiRole,
      using: activeActorMembershipFor(table.tenantId),
      withCheck: activeActorMembershipFor(table.tenantId),
    }),
  ],
).enableRLS();

export const customFieldValues = pgTable(
  "custom_field_values",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    objectType: customFieldObjectType("object_type").notNull(),
    alertId: uuid("alert_id"),
    caseId: uuid("case_id"),
    definitionId: uuid("definition_id").notNull(),
    definitionSchemaVersion: bigint("definition_schema_version", {
      mode: "bigint",
    }).notNull(),
    dataType: customFieldDataType("data_type").notNull(),
    presence: customFieldValuePresence("presence").notNull(),
    canonicalValue: jsonb("canonical_value").$type<unknown>().notNull(),
    textValue: text("text_value"),
    integerValue: bigint("integer_value", { mode: "bigint" }),
    decimalValue: numeric("decimal_value"),
    booleanValue: boolean("boolean_value"),
    dateValue: date("date_value", { mode: "string" }),
    dateTimeValue: timestamp("date_time_value", {
      withTimezone: true,
      mode: "date",
    }),
    ipValue: inet("ip_value"),
    cidrValue: cidr("cidr_value"),
    referenceId: uuid("reference_id"),
    optionKeys: text("option_keys").array(),
    structuredValue: jsonb("structured_value").$type<Record<string, unknown>>(),
    createdByMembershipId: uuid("created_by_membership_id").notNull(),
    updatedByMembershipId: uuid("updated_by_membership_id").notNull(),
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
    unique("custom_field_values_tenant_id_key").on(table.tenantId, table.id),
    uniqueIndex("custom_field_values_alert_definition_key")
      .on(table.tenantId, table.alertId, table.definitionId)
      .where(sql`${table.alertId} is not null`),
    uniqueIndex("custom_field_values_case_definition_key")
      .on(table.tenantId, table.caseId, table.definitionId)
      .where(sql`${table.caseId} is not null`),
    foreignKey({
      name: "custom_field_values_definition_fk",
      columns: [table.tenantId, table.definitionId],
      foreignColumns: [
        customFieldDefinitions.tenantId,
        customFieldDefinitions.id,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "custom_field_values_definition_revision_fk",
      columns: [
        table.tenantId,
        table.definitionId,
        table.definitionSchemaVersion,
      ],
      foreignColumns: [
        customFieldDefinitionRevisions.tenantId,
        customFieldDefinitionRevisions.definitionId,
        customFieldDefinitionRevisions.schemaVersion,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "custom_field_values_alert_fk",
      columns: [table.tenantId, table.alertId],
      foreignColumns: [alerts.tenantId, alerts.id],
    })
      .onUpdate("cascade")
      .onDelete("cascade"),
    foreignKey({
      name: "custom_field_values_case_fk",
      columns: [table.tenantId, table.caseId],
      foreignColumns: [cases.tenantId, cases.id],
    })
      .onUpdate("cascade")
      .onDelete("cascade"),
    foreignKey({
      name: "custom_field_values_creator_fk",
      columns: [table.tenantId, table.createdByMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "custom_field_values_updater_fk",
      columns: [table.tenantId, table.updatedByMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    index("custom_field_values_definition_text_idx").on(
      table.tenantId,
      table.definitionId,
      table.textValue,
      table.id,
    ),
    index("custom_field_values_definition_integer_idx").on(
      table.tenantId,
      table.definitionId,
      table.integerValue,
      table.id,
    ),
    index("custom_field_values_definition_decimal_idx").on(
      table.tenantId,
      table.definitionId,
      table.decimalValue,
      table.id,
    ),
    index("custom_field_values_definition_datetime_idx").on(
      table.tenantId,
      table.definitionId,
      table.dateTimeValue,
      table.id,
    ),
    index("custom_field_values_saved_sort_boolean_idx").on(
      table.tenantId,
      table.objectType,
      table.definitionId,
      table.definitionSchemaVersion,
      table.booleanValue,
      table.alertId,
      table.caseId,
    ),
    index("custom_field_values_saved_sort_date_idx").on(
      table.tenantId,
      table.objectType,
      table.definitionId,
      table.definitionSchemaVersion,
      table.dateValue,
      table.alertId,
      table.caseId,
    ),
    index("custom_field_values_saved_sort_ip_idx").on(
      table.tenantId,
      table.objectType,
      table.definitionId,
      table.definitionSchemaVersion,
      table.ipValue,
      table.alertId,
      table.caseId,
    ),
    index("custom_field_values_saved_sort_cidr_idx").on(
      table.tenantId,
      table.objectType,
      table.definitionId,
      table.definitionSchemaVersion,
      table.cidrValue,
      table.alertId,
      table.caseId,
    ),
    index("custom_field_values_saved_sort_reference_idx").on(
      table.tenantId,
      table.objectType,
      table.definitionId,
      table.definitionSchemaVersion,
      table.referenceId,
      table.alertId,
      table.caseId,
    ),
    index("custom_field_values_saved_sort_single_select_idx").on(
      table.tenantId,
      table.objectType,
      table.definitionId,
      table.definitionSchemaVersion,
      sql`(${table.optionKeys}[1])`,
      table.alertId,
      table.caseId,
    ),
    check(
      "custom_field_values_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "custom_field_values_subject_check",
      sql`(${table.objectType} = 'alert' and ${table.alertId} is not null and ${table.caseId} is null)
        or (${table.objectType} = 'case' and ${table.caseId} is not null and ${table.alertId} is null)`,
    ),
    check(
      "custom_field_values_version_check",
      sql`${table.definitionSchemaVersion} > 0 and ${table.version} > 0`,
    ),
    check(
      "custom_field_values_size_check",
      sql`pg_column_size(${table.canonicalValue}) <= 65536
        and (${table.optionKeys} is null or cardinality(${table.optionKeys}) <= 512)
        and (${table.structuredValue} is null or (jsonb_typeof(${table.structuredValue}) = 'object' and pg_column_size(${table.structuredValue}) <= 65536))`,
    ),
    check(
      "custom_field_values_null_shape_check",
      sql`${table.presence} <> 'null' or (
        ${table.canonicalValue} = 'null'::jsonb
        and ${table.textValue} is null and ${table.integerValue} is null
        and ${table.decimalValue} is null and ${table.booleanValue} is null
        and ${table.dateValue} is null and ${table.dateTimeValue} is null
        and ${table.ipValue} is null and ${table.cidrValue} is null
        and ${table.referenceId} is null and ${table.optionKeys} is null
        and ${table.structuredValue} is null
      )`,
    ),
    check(
      "custom_field_values_present_shape_check",
      sql`${table.presence} <> 'present' or (
        case
          when ${table.dataType} in ('short_text','long_text','url','email') then ${table.textValue} is not null
          when ${table.dataType} in ('integer','duration') then ${table.integerValue} is not null
          when ${table.dataType} = 'decimal' then ${table.decimalValue} is not null
          when ${table.dataType} = 'boolean' then ${table.booleanValue} is not null
          when ${table.dataType} = 'date' then ${table.dateValue} is not null
          when ${table.dataType} = 'datetime' then ${table.dateTimeValue} is not null
          when ${table.dataType} = 'ip' then ${table.ipValue} is not null
          when ${table.dataType} = 'cidr' then ${table.cidrValue} is not null
          when ${table.dataType} in ('user','operator_team','customer_contact','asset_reference','ioc_reference') then ${table.referenceId} is not null
          when ${table.dataType} = 'single_select' then cardinality(${table.optionKeys}) = 1
          when ${table.dataType} = 'multi_select' then ${table.optionKeys} is not null
          when ${table.dataType} = 'structured_json' then ${table.structuredValue} is not null
          else false
        end
      )`,
    ),
    check(
      "custom_field_values_timestamps_check",
      sql`${table.updatedAt} >= ${table.createdAt}`,
    ),
    pgPolicy("custom_field_values_api_tenant", {
      as: "permissive",
      for: "all",
      to: apiRole,
      using: activeActorMembershipFor(table.tenantId),
      withCheck: activeActorMembershipFor(table.tenantId),
    }),
  ],
).enableRLS();
