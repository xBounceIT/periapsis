import { sql } from "drizzle-orm";
import {
  bigint,
  boolean,
  check,
  foreignKey,
  index,
  integer,
  pgTable,
  primaryKey,
  text,
  timestamp,
  unique,
  uuid,
} from "drizzle-orm/pg-core";

import { bytea } from "./binary.js";
import {
  authProviderKind,
  ldapDirectoryOperationKind,
  ldapProviderTestCategory,
  ldapProviderTestOutcome,
  ldapProviderTestStatus,
} from "./enums.js";
import {
  tenantAuthProviderBindings,
  tenantIdentityProviderAccessEpochs,
} from "./identity-access.js";
import {
  tenantLdapMappingRuleEpochs,
  tenantLdapMappingRules,
} from "./identity-mappings.js";
import {
  identityKeyringVersions,
  tenantAuthProviders,
} from "./identity-providers.js";
import { tenantMemberships } from "./identity.js";
import { tenants } from "./tenancy.js";

/**
 * One committed, bounded LDAP directory operation. The row stores only
 * revision pins and sanitized result metadata; network inputs and directory
 * values are deliberately absent. A non-null binding identifies a mapping
 * dry run whose complete rule selection is copied to the child table.
 */
export const tenantLdapDirectoryOperationRuns = pgTable(
  "tenant_ldap_directory_operation_runs",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    providerId: uuid("provider_id").notNull(),
    providerKind: authProviderKind("provider_kind").notNull().default("ldap"),
    operationKind: ldapDirectoryOperationKind("operation_kind").notNull(),
    bindingId: uuid("binding_id"),
    providerVersion: integer("provider_version").notNull(),
    configurationVersion: integer("configuration_version").notNull(),
    endpointSnapshotDigest: bytea("endpoint_snapshot_digest").notNull(),
    bindSecretId: uuid("bind_secret_id").notNull(),
    bindSecretVersion: integer("bind_secret_version").notNull(),
    bindSecretKeyVersion: integer("bind_secret_key_version")
      .notNull()
      .references(() => identityKeyringVersions.keyVersion, {
        onDelete: "restrict",
      }),
    bindSecretAlgorithm: text("bind_secret_algorithm").notNull(),
    bindingVersion: integer("binding_version"),
    bindingAuthRevision: integer("binding_auth_revision"),
    bindingAccessEpochId: uuid("binding_access_epoch_id"),
    ruleSetRevision: bigint("rule_set_revision", { mode: "bigint" }),
    authorizationRevision: bigint("authorization_revision", {
      mode: "bigint",
    }),
    status: ldapProviderTestStatus("status").notNull().default("started"),
    outcome: ldapProviderTestOutcome("outcome"),
    category: ldapProviderTestCategory("category"),
    endpointPriority: integer("endpoint_priority"),
    durationMs: integer("duration_ms"),
    matchedEntryCount: integer("matched_entry_count"),
    resultTruncated: boolean("result_truncated"),
    reason: text("reason").notNull(),
    startedByMembershipId: uuid("started_by_membership_id").notNull(),
    completedByMembershipId: uuid("completed_by_membership_id"),
    requestId: uuid("request_id").notNull(),
    correlationId: uuid("correlation_id").notNull(),
    startedAt: timestamp("started_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    expiresAt: timestamp("expires_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    completedAt: timestamp("completed_at", {
      withTimezone: true,
      mode: "date",
    }),
    version: integer("version").notNull().default(1),
  },
  (table) => [
    unique("tenant_ldap_directory_runs_tenant_id_key").on(
      table.tenantId,
      table.id,
    ),
    unique("tenant_ldap_directory_runs_exact_binding_key").on(
      table.tenantId,
      table.id,
      table.bindingId,
    ),
    index("tenant_ldap_directory_runs_provider_started_idx").on(
      table.tenantId,
      table.providerId,
      table.startedAt,
      table.id,
    ),
    index("tenant_ldap_directory_runs_actor_started_idx").on(
      table.tenantId,
      table.startedByMembershipId,
      table.startedAt,
      table.id,
    ),
    index("tenant_ldap_directory_runs_status_started_idx").on(
      table.tenantId,
      table.status,
      table.startedAt,
      table.id,
    ),
    index("tenant_ldap_directory_runs_key_version_idx").on(
      table.tenantId,
      table.bindSecretKeyVersion,
      table.status,
      table.expiresAt,
    ),
    foreignKey({
      name: "tenant_ldap_directory_runs_provider_fk",
      columns: [table.tenantId, table.providerId, table.providerKind],
      foreignColumns: [
        tenantAuthProviders.tenantId,
        tenantAuthProviders.id,
        tenantAuthProviders.kind,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_ldap_directory_runs_binding_fk",
      columns: [table.tenantId, table.bindingId, table.providerId],
      foreignColumns: [
        tenantAuthProviderBindings.tenantId,
        tenantAuthProviderBindings.id,
        tenantAuthProviderBindings.providerId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_ldap_directory_runs_access_epoch_fk",
      columns: [
        table.tenantId,
        table.bindingAccessEpochId,
        table.bindingId,
        table.providerId,
      ],
      foreignColumns: [
        tenantIdentityProviderAccessEpochs.tenantId,
        tenantIdentityProviderAccessEpochs.id,
        tenantIdentityProviderAccessEpochs.bindingId,
        tenantIdentityProviderAccessEpochs.providerId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_ldap_directory_runs_starter_fk",
      columns: [table.tenantId, table.startedByMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_ldap_directory_runs_completer_fk",
      columns: [table.tenantId, table.completedByMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "tenant_ldap_directory_runs_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "tenant_ldap_directory_runs_kind_check",
      sql`${table.providerKind} = 'ldap'`,
    ),
    check(
      "tenant_ldap_directory_runs_revision_check",
      sql`${table.providerVersion} > 0
        and ${table.configurationVersion} > 0
        and ${table.bindSecretVersion} > 0
        and ${table.bindSecretKeyVersion} > 0`,
    ),
    check(
      "tenant_ldap_directory_runs_secret_check",
      sql`(uuid_extract_version(${table.bindSecretId}) = 7) is true
        and octet_length(${table.endpointSnapshotDigest}) = 32
        and ${table.bindSecretAlgorithm} = 'aes-256-gcm'`,
    ),
    check(
      "tenant_ldap_directory_runs_planning_check",
      sql`(${table.bindingId} is null
          and ${table.bindingVersion} is null
          and ${table.bindingAuthRevision} is null
          and ${table.bindingAccessEpochId} is null
          and ${table.ruleSetRevision} is null
          and ${table.authorizationRevision} is null)
        or (${table.operationKind} = 'search_user'
          and ${table.bindingId} is not null
          and ${table.bindingVersion} > 0
          and ${table.bindingAuthRevision} > 0
          and ${table.bindingAccessEpochId} is not null
          and ${table.ruleSetRevision} > 0
          and ${table.authorizationRevision} > 0)`,
    ),
    check(
      "tenant_ldap_directory_runs_reason_check",
      sql`btrim(${table.reason}) <> ''
        and char_length(${table.reason}) <= 500
        and ${table.reason} !~ '[[:cntrl:]]'`,
    ),
    check(
      "tenant_ldap_directory_runs_result_bounds_check",
      sql`(${table.endpointPriority} is null
          or ${table.endpointPriority} between 1 and 8)
        and (${table.durationMs} is null
          or ${table.durationMs} between 0 and 120000)
        and (${table.matchedEntryCount} is null
          or ${table.matchedEntryCount} between 0 and 10)`,
    ),
    check(
      "tenant_ldap_directory_runs_lifetime_check",
      sql`${table.expiresAt} > ${table.startedAt}
        and ${table.expiresAt} <= ${table.startedAt} + interval '2 minutes'`,
    ),
    check(
      "tenant_ldap_directory_runs_lifecycle_check",
      sql`((${table.status} = 'started'
          and ${table.outcome} is null
          and ${table.category} is null
          and ${table.endpointPriority} is null
          and ${table.durationMs} is null
          and ${table.matchedEntryCount} is null
          and ${table.resultTruncated} is null
          and ${table.completedByMembershipId} is null
          and ${table.completedAt} is null
          and ${table.version} = 1)
        or (${table.status} = 'completed'
          and ${table.outcome} is not null
          and ${table.category} is not null
          and ${table.durationMs} is not null
          and ${table.matchedEntryCount} is not null
          and ${table.resultTruncated} is not null
          and ${table.completedByMembershipId} is not null
          and ${table.completedByMembershipId} = ${table.startedByMembershipId}
          and ${table.completedAt} >= ${table.startedAt}
          and ${table.version} = 2)) is true`,
    ),
  ],
).enableRLS();

/**
 * Immutable exact rule selection for one mapping dry run. Disabled rules use
 * isolated planning IDs that are never authorization sources or live epochs.
 */
export const tenantLdapDirectoryRunMappings = pgTable(
  "tenant_ldap_directory_run_mappings",
  {
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    operationRunId: uuid("operation_run_id").notNull(),
    bindingId: uuid("binding_id").notNull(),
    mappingRuleId: uuid("mapping_rule_id").notNull(),
    mappingVersion: integer("mapping_version").notNull(),
    configurationRevision: integer("configuration_revision").notNull(),
    sourceEpochId: uuid("source_epoch_id"),
    sourceEpochSequence: integer("source_epoch_sequence"),
    authorizationSourceId: uuid("authorization_source_id"),
    planningEpochId: uuid("planning_epoch_id").notNull(),
    planningSourceId: uuid("planning_source_id").notNull(),
    includedDisabled: boolean("included_disabled").notNull(),
    priority: integer("priority").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    primaryKey({
      name: "tenant_ldap_directory_run_mappings_pkey",
      columns: [table.tenantId, table.operationRunId, table.mappingRuleId],
    }),
    unique("tenant_ldap_directory_run_mappings_epoch_key").on(
      table.tenantId,
      table.operationRunId,
      table.planningEpochId,
    ),
    unique("tenant_ldap_directory_run_mappings_source_key").on(
      table.tenantId,
      table.operationRunId,
      table.planningSourceId,
    ),
    index("tenant_ldap_directory_run_mappings_order_idx").on(
      table.tenantId,
      table.operationRunId,
      table.priority,
      table.mappingRuleId,
    ),
    foreignKey({
      name: "tenant_ldap_directory_run_mappings_run_fk",
      columns: [table.tenantId, table.operationRunId, table.bindingId],
      foreignColumns: [
        tenantLdapDirectoryOperationRuns.tenantId,
        tenantLdapDirectoryOperationRuns.id,
        tenantLdapDirectoryOperationRuns.bindingId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_ldap_directory_run_mappings_rule_fk",
      columns: [table.tenantId, table.mappingRuleId, table.bindingId],
      foreignColumns: [
        tenantLdapMappingRules.tenantId,
        tenantLdapMappingRules.id,
        tenantLdapMappingRules.bindingId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_ldap_directory_run_mappings_epoch_fk",
      columns: [
        table.tenantId,
        table.sourceEpochId,
        table.mappingRuleId,
        table.bindingId,
        table.configurationRevision,
      ],
      foreignColumns: [
        tenantLdapMappingRuleEpochs.tenantId,
        tenantLdapMappingRuleEpochs.id,
        tenantLdapMappingRuleEpochs.mappingRuleId,
        tenantLdapMappingRuleEpochs.bindingId,
        tenantLdapMappingRuleEpochs.configurationRevision,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "tenant_ldap_directory_run_mappings_revision_check",
      sql`${table.mappingVersion} > 0
        and ${table.configurationRevision} > 0
        and ${table.priority} between 0 and 1000000`,
    ),
    check(
      "tenant_ldap_directory_run_mappings_planning_id_check",
      sql`${sql`(uuid_extract_version(${table.planningEpochId}) = 7) is true`}
        and ${sql`(uuid_extract_version(${table.planningSourceId}) = 7) is true`}`,
    ),
    check(
      "tenant_ldap_directory_run_mappings_source_check",
      sql`(not ${table.includedDisabled}
          and ${table.sourceEpochId} is not null
          and ${table.sourceEpochSequence} > 0
          and ${table.authorizationSourceId} is not null
          and ${table.planningEpochId} = ${table.sourceEpochId}
          and ${table.planningSourceId} = ${table.authorizationSourceId})
        or (${table.includedDisabled}
          and ${table.sourceEpochId} is null
          and ${table.sourceEpochSequence} is null
          and ${table.authorizationSourceId} is null)`,
    ),
  ],
).enableRLS();
