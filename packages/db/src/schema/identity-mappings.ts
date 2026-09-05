import { sql } from "drizzle-orm";
import {
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
  uniqueIndex,
  uuid,
} from "drizzle-orm/pg-core";
import type { PgTableExtraConfigValue } from "drizzle-orm/pg-core";

import {
  tenantAuthorizationSources,
  tenantRoles,
  tenantSecurityGroups,
} from "./authorization.js";
import {
  ldapMappingCaseMode,
  ldapMappingMatcherType,
  ldapMappingReconciliationMode,
  tenantPrincipalKind,
} from "./enums.js";
import { tenantAuthProviderBindings } from "./identity-access.js";
import { tenantMemberships } from "./identity.js";
import { operatorTeamAssignmentEpochs } from "./operator-teams.js";
import { tenants } from "./tenancy.js";

/**
 * The mutable administrative projection for one tenant LDAP mapping. Historical
 * authority is never interpreted through these current fields: every live
 * source epoch copies the complete scalar configuration and pins the immutable
 * role-target revision below.
 */
export const tenantLdapMappingRules = pgTable(
  "tenant_ldap_mapping_rules",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    bindingId: uuid("binding_id").notNull(),
    matcherType: ldapMappingMatcherType("matcher_type").notNull(),
    matcherValue: text("matcher_value").notNull(),
    caseMode: ldapMappingCaseMode("case_mode").notNull(),
    priority: integer("priority").notNull().default(100),
    tenantSecurityGroupId: uuid("tenant_security_group_id").notNull(),
    reconciliationMode: ldapMappingReconciliationMode(
      "reconciliation_mode",
    ).notNull(),
    operatorTeamId: uuid("operator_team_id"),
    operatorTeamAssignmentEpochId: uuid("operator_team_assignment_epoch_id"),
    configurationRevision: integer("configuration_revision")
      .notNull()
      .default(1),
    enabled: boolean("enabled").notNull().default(false),
    currentSourceEpochId: uuid("current_source_epoch_id"),
    notes: text("notes").notNull().default(""),
    lastMatchedAt: timestamp("last_matched_at", {
      withTimezone: true,
      mode: "date",
    }),
    createdByMembershipId: uuid("created_by_membership_id").notNull(),
    updatedByMembershipId: uuid("updated_by_membership_id").notNull(),
    archivedAt: timestamp("archived_at", {
      withTimezone: true,
      mode: "date",
    }),
    archivedByMembershipId: uuid("archived_by_membership_id"),
    archiveReason: text("archive_reason"),
    version: integer("version").notNull().default(1),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table): PgTableExtraConfigValue[] => [
    unique("tenant_ldap_mapping_rules_tenant_id_key").on(
      table.tenantId,
      table.id,
    ),
    unique("tenant_ldap_mapping_rules_exact_binding_key").on(
      table.tenantId,
      table.id,
      table.bindingId,
    ),
    index("tenant_ldap_mapping_rules_tenant_binding_order_idx").on(
      table.tenantId,
      table.bindingId,
      table.enabled,
      table.priority,
      table.id,
    ),
    index("tenant_ldap_mapping_rules_tenant_group_idx").on(
      table.tenantId,
      table.tenantSecurityGroupId,
      table.id,
    ),
    index("tenant_ldap_mapping_rules_tenant_team_idx").on(
      table.tenantId,
      table.operatorTeamAssignmentEpochId,
      table.id,
    ),
    foreignKey({
      name: "tenant_ldap_mapping_rules_binding_fk",
      columns: [table.tenantId, table.bindingId],
      foreignColumns: [
        tenantAuthProviderBindings.tenantId,
        tenantAuthProviderBindings.id,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_ldap_mapping_rules_group_fk",
      columns: [table.tenantId, table.tenantSecurityGroupId],
      foreignColumns: [tenantSecurityGroups.tenantId, tenantSecurityGroups.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_ldap_mapping_rules_team_assignment_fk",
      columns: [
        table.tenantId,
        table.operatorTeamAssignmentEpochId,
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
      name: "tenant_ldap_mapping_rules_creator_fk",
      columns: [table.tenantId, table.createdByMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_ldap_mapping_rules_updater_fk",
      columns: [table.tenantId, table.updatedByMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_ldap_mapping_rules_archiver_fk",
      columns: [table.tenantId, table.archivedByMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_ldap_mapping_rules_current_epoch_fk",
      columns: [
        table.tenantId,
        table.currentSourceEpochId,
        table.id,
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
      "tenant_ldap_mapping_rules_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "tenant_ldap_mapping_rules_matcher_check",
      sql`btrim(${table.matcherValue}) <> ''
        and ${table.matcherValue} !~ '[[:cntrl:]]'
        and ((${table.matcherType} = 'exact_dn'
            and char_length(${table.matcherValue}) <= 2048
            and octet_length(${table.matcherValue}) <= 8192)
          or (${table.matcherType} in ('exact_cn', 'regex')
            and char_length(${table.matcherValue}) <= 512))`,
    ),
    check(
      "tenant_ldap_mapping_rules_priority_check",
      sql`${table.priority} between 0 and 1000000`,
    ),
    check(
      "tenant_ldap_mapping_rules_configuration_check",
      sql`${table.configurationRevision} > 0 and ${table.version} > 0`,
    ),
    check(
      "tenant_ldap_mapping_rules_operator_target_check",
      sql`(${table.operatorTeamId} is null
          and ${table.operatorTeamAssignmentEpochId} is null)
        or (${table.operatorTeamId} is not null
          and ${table.operatorTeamAssignmentEpochId} is not null)`,
    ),
    check(
      "tenant_ldap_mapping_rules_enabled_epoch_check",
      sql`(${table.enabled} and ${table.archivedAt} is null
          and ${table.currentSourceEpochId} is not null)
        or (not ${table.enabled} and ${table.currentSourceEpochId} is null)`,
    ),
    check(
      "tenant_ldap_mapping_rules_notes_check",
      sql`char_length(${table.notes}) <= 2000
        and ${table.notes} !~ '[[:cntrl:]]'`,
    ),
    check(
      "tenant_ldap_mapping_rules_archive_check",
      sql`(${table.archivedAt} is null
          and ${table.archivedByMembershipId} is null
          and ${table.archiveReason} is null)
        or (${table.archivedAt} is not null
          and ${table.archivedByMembershipId} is not null
          and ${table.archiveReason} is not null
          and not ${table.enabled}
          and ${table.currentSourceEpochId} is null
          and ${table.archivedAt} >= ${table.createdAt}
          and btrim(${table.archiveReason}) <> ''
          and char_length(${table.archiveReason}) <= 500
          and ${table.archiveReason} !~ '[[:cntrl:]]')`,
    ),
    check(
      "tenant_ldap_mapping_rules_timestamps_check",
      sql`${table.updatedAt} >= ${table.createdAt}
        and (${table.lastMatchedAt} is null
          or ${table.lastMatchedAt} >= ${table.createdAt})
        and (${table.archivedAt} is null
          or ${table.updatedAt} >= ${table.archivedAt})`,
    ),
  ],
).enableRLS();

/** Immutable role targets, retained by semantic configuration revision. */
export const tenantLdapMappingRuleRoleTargets = pgTable(
  "tenant_ldap_mapping_rule_role_targets",
  {
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    mappingRuleId: uuid("mapping_rule_id").notNull(),
    configurationRevision: integer("configuration_revision").notNull(),
    roleId: uuid("role_id").notNull(),
    rolePrincipalKind: tenantPrincipalKind("role_principal_kind")
      .notNull()
      .default("human"),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    primaryKey({
      name: "tenant_ldap_mapping_rule_role_targets_pkey",
      columns: [
        table.tenantId,
        table.mappingRuleId,
        table.configurationRevision,
        table.roleId,
      ],
    }),
    index("tenant_ldap_mapping_rule_role_targets_role_idx").on(
      table.tenantId,
      table.roleId,
      table.mappingRuleId,
      table.configurationRevision,
    ),
    foreignKey({
      name: "tenant_ldap_mapping_rule_role_targets_rule_fk",
      columns: [table.tenantId, table.mappingRuleId],
      foreignColumns: [
        tenantLdapMappingRules.tenantId,
        tenantLdapMappingRules.id,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_ldap_mapping_rule_role_targets_role_fk",
      columns: [table.tenantId, table.roleId, table.rolePrincipalKind],
      foreignColumns: [
        tenantRoles.tenantId,
        tenantRoles.id,
        tenantRoles.principalKind,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "tenant_ldap_mapping_rule_role_targets_revision_check",
      sql`${table.configurationRevision} > 0`,
    ),
    check(
      "tenant_ldap_mapping_rule_role_targets_human_check",
      sql`${table.rolePrincipalKind} = 'human'`,
    ),
  ],
).enableRLS();

/**
 * One immutable identity_mapping source epoch. Scalar target and matcher fields
 * are copied here so later rule edits cannot reinterpret historical authority;
 * role IDs remain pinned by (mapping_rule_id, configuration_revision).
 */
export const tenantLdapMappingRuleEpochs = pgTable(
  "tenant_ldap_mapping_rule_epochs",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    mappingRuleId: uuid("mapping_rule_id").notNull(),
    bindingId: uuid("binding_id").notNull(),
    sourceId: uuid("source_id").notNull(),
    sequence: integer("sequence").notNull(),
    configurationRevision: integer("configuration_revision").notNull(),
    matcherType: ldapMappingMatcherType("matcher_type").notNull(),
    matcherValue: text("matcher_value").notNull(),
    caseMode: ldapMappingCaseMode("case_mode").notNull(),
    priority: integer("priority").notNull(),
    tenantSecurityGroupId: uuid("tenant_security_group_id").notNull(),
    reconciliationMode: ldapMappingReconciliationMode(
      "reconciliation_mode",
    ).notNull(),
    operatorTeamId: uuid("operator_team_id"),
    operatorTeamAssignmentEpochId: uuid("operator_team_assignment_epoch_id"),
    activatedByMembershipId: uuid("activated_by_membership_id").notNull(),
    activatedAt: timestamp("activated_at", {
      withTimezone: true,
      mode: "date",
    })
      .notNull()
      .defaultNow(),
    endedAt: timestamp("ended_at", { withTimezone: true, mode: "date" }),
    endedByMembershipId: uuid("ended_by_membership_id"),
    endReason: text("end_reason"),
    version: integer("version").notNull().default(1),
  },
  (table): PgTableExtraConfigValue[] => [
    unique("tenant_ldap_mapping_rule_epochs_tenant_id_key").on(
      table.tenantId,
      table.id,
    ),
    unique("tenant_ldap_mapping_rule_epochs_current_key").on(
      table.tenantId,
      table.id,
      table.mappingRuleId,
      table.bindingId,
      table.configurationRevision,
    ),
    unique("tenant_ldap_mapping_rule_epochs_exact_source_key").on(
      table.tenantId,
      table.id,
      table.mappingRuleId,
      table.bindingId,
      table.sourceId,
    ),
    unique("tenant_ldap_mapping_rule_epochs_rule_sequence_key").on(
      table.tenantId,
      table.mappingRuleId,
      table.sequence,
    ),
    unique("tenant_ldap_mapping_rule_epochs_source_key").on(
      table.tenantId,
      table.sourceId,
    ),
    uniqueIndex("tenant_ldap_mapping_rule_epochs_live_rule_key")
      .on(table.tenantId, table.mappingRuleId)
      .where(sql`${table.endedAt} is null`),
    index("tenant_ldap_mapping_rule_epochs_tenant_binding_idx").on(
      table.tenantId,
      table.bindingId,
      table.mappingRuleId,
      table.sequence,
    ),
    foreignKey({
      name: "tenant_ldap_mapping_rule_epochs_rule_fk",
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
      name: "tenant_ldap_mapping_rule_epochs_source_fk",
      columns: [table.tenantId, table.sourceId],
      foreignColumns: [
        tenantAuthorizationSources.tenantId,
        tenantAuthorizationSources.id,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_ldap_mapping_rule_epochs_group_fk",
      columns: [table.tenantId, table.tenantSecurityGroupId],
      foreignColumns: [tenantSecurityGroups.tenantId, tenantSecurityGroups.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_ldap_mapping_rule_epochs_team_assignment_fk",
      columns: [
        table.tenantId,
        table.operatorTeamAssignmentEpochId,
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
      name: "tenant_ldap_mapping_rule_epochs_activator_fk",
      columns: [table.tenantId, table.activatedByMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_ldap_mapping_rule_epochs_ender_fk",
      columns: [table.tenantId, table.endedByMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "tenant_ldap_mapping_rule_epochs_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "tenant_ldap_mapping_rule_epochs_sequence_check",
      sql`${table.sequence} > 0 and ${table.configurationRevision} > 0`,
    ),
    check(
      "tenant_ldap_mapping_rule_epochs_matcher_check",
      sql`btrim(${table.matcherValue}) <> ''
        and ${table.matcherValue} !~ '[[:cntrl:]]'
        and ((${table.matcherType} = 'exact_dn'
            and char_length(${table.matcherValue}) <= 2048
            and octet_length(${table.matcherValue}) <= 8192)
          or (${table.matcherType} in ('exact_cn', 'regex')
            and char_length(${table.matcherValue}) <= 512))`,
    ),
    check(
      "tenant_ldap_mapping_rule_epochs_priority_check",
      sql`${table.priority} between 0 and 1000000`,
    ),
    check(
      "tenant_ldap_mapping_rule_epochs_operator_target_check",
      sql`(${table.operatorTeamId} is null
          and ${table.operatorTeamAssignmentEpochId} is null)
        or (${table.operatorTeamId} is not null
          and ${table.operatorTeamAssignmentEpochId} is not null)`,
    ),
    check(
      "tenant_ldap_mapping_rule_epochs_lifecycle_check",
      sql`(${table.endedAt} is null
          and ${table.endedByMembershipId} is null
          and ${table.endReason} is null
          and ${table.version} = 1)
        or (${table.endedAt} is not null
          and ${table.endedByMembershipId} is not null
          and ${table.endReason} is not null
          and ${table.endedAt} >= ${table.activatedAt}
          and btrim(${table.endReason}) <> ''
          and char_length(${table.endReason}) <= 500
          and ${table.endReason} !~ '[[:cntrl:]]'
          and ${table.version} = 2)`,
    ),
  ],
).enableRLS();
