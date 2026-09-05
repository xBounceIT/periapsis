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
  uniqueIndex,
  uuid,
} from "drizzle-orm/pg-core";

import { bytea } from "./binary.js";
import {
  authProviderKind,
  ldapIdentityApplyDecision,
  ldapIdentityApplyMode,
  ldapSyncAbsenceStatus,
  ldapSyncRunStatus,
  ldapSyncTrigger,
} from "./enums.js";
import {
  tenantAuthProviderBindings,
  tenantIdentityProviderAccessEpochs,
  tenantLdapExternalIdentities,
  tenantLdapProviderAccessGrants,
} from "./identity-access.js";
import {
  tenantLdapMappingRuleEpochs,
  tenantLdapMappingRules,
} from "./identity-mappings.js";
import {
  identityKeyringVersions,
  tenantAuthProviders,
  tenantLdapProviderSecrets,
} from "./identity-providers.js";
import { tenantMemberships } from "./identity.js";
import { tenants } from "./tenancy.js";

/**
 * Durable synchronization state. Directory values, subjects, DNs, filters,
 * credentials and cursors are deliberately absent: only exact revision pins,
 * bounded counters and one-way digests cross the network/transaction split.
 */
export const tenantLdapSyncRuns = pgTable(
  "tenant_ldap_sync_runs",
  {
    id: uuid("id").primaryKey(),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    providerId: uuid("provider_id").notNull(),
    providerKind: authProviderKind("provider_kind").notNull().default("ldap"),
    bindingId: uuid("binding_id").notNull(),
    trigger: ldapSyncTrigger("trigger").notNull(),
    status: ldapSyncRunStatus("status").notNull().default("queued"),
    claimId: uuid("claim_id"),
    claimReceiptDigest: bytea("claim_receipt_digest"),
    claimFence: bigint("claim_fence", { mode: "bigint" })
      .notNull()
      .default(sql`0`),
    claimAcquiredAt: timestamp("claim_acquired_at", {
      withTimezone: true,
      mode: "date",
    }),
    claimExpiresAt: timestamp("claim_expires_at", {
      withTimezone: true,
      mode: "date",
    }),
    providerVersion: integer("provider_version").notNull(),
    configurationVersion: integer("configuration_version").notNull(),
    bindingVersion: integer("binding_version").notNull(),
    bindingAuthRevision: integer("binding_auth_revision").notNull(),
    bindingAccessEpochId: uuid("binding_access_epoch_id").notNull(),
    ruleSetRevision: bigint("rule_set_revision", { mode: "bigint" }).notNull(),
    authorizationRevision: bigint("authorization_revision", {
      mode: "bigint",
    }).notNull(),
    authorizationProgressRevision: bigint("authorization_progress_revision", {
      mode: "bigint",
    }).notNull(),
    bindSecretId: uuid("bind_secret_id").notNull(),
    bindSecretVersion: integer("bind_secret_version").notNull(),
    bindSecretKeyVersion: integer("bind_secret_key_version")
      .notNull()
      .references(() => identityKeyringVersions.keyVersion, {
        onDelete: "restrict",
      }),
    bindSecretAlgorithm: text("bind_secret_algorithm").notNull(),
    endpointSnapshotDigest: bytea("endpoint_snapshot_digest").notNull(),
    enumerationComplete: boolean("enumeration_complete"),
    resultTruncated: boolean("result_truncated"),
    cursorDigest: bytea("cursor_digest"),
    observedCount: integer("observed_count").notNull().default(0),
    appliedCount: integer("applied_count").notNull().default(0),
    revokedCount: integer("revoked_count").notNull().default(0),
    failureCategory: text("failure_category"),
    reason: text("reason").notNull(),
    startedByMembershipId: uuid("started_by_membership_id"),
    requestId: uuid("request_id").notNull(),
    correlationId: uuid("correlation_id").notNull(),
    queuedAt: timestamp("queued_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    enumerationStartedAt: timestamp("enumeration_started_at", {
      withTimezone: true,
      mode: "date",
    }),
    enumerationCompletedAt: timestamp("enumeration_completed_at", {
      withTimezone: true,
      mode: "date",
    }),
    completedAt: timestamp("completed_at", {
      withTimezone: true,
      mode: "date",
    }),
    version: integer("version").notNull().default(1),
  },
  (table) => [
    unique("tenant_ldap_sync_runs_tenant_id_key").on(table.tenantId, table.id),
    unique("tenant_ldap_sync_runs_exact_binding_key").on(
      table.tenantId,
      table.id,
      table.bindingId,
    ),
    uniqueIndex("tenant_ldap_sync_runs_live_binding_key")
      .on(table.tenantId, table.bindingId)
      .where(sql`${table.status} in ('queued', 'enumerating', 'applying')`),
    uniqueIndex("tenant_ldap_sync_runs_claim_id_key")
      .on(table.claimId)
      .where(sql`${table.claimId} is not null`),
    index("tenant_ldap_sync_runs_binding_queued_idx").on(
      table.tenantId,
      table.bindingId,
      table.queuedAt,
      table.id,
    ),
    index("tenant_ldap_sync_runs_status_queued_idx").on(
      table.tenantId,
      table.status,
      table.queuedAt,
      table.id,
    ),
    index("tenant_ldap_sync_runs_reclaim_idx").on(
      table.status,
      table.claimExpiresAt,
      table.queuedAt,
      table.id,
    ),
    foreignKey({
      name: "tenant_ldap_sync_runs_provider_fk",
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
      name: "tenant_ldap_sync_runs_binding_fk",
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
      name: "tenant_ldap_sync_runs_access_epoch_fk",
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
      name: "tenant_ldap_sync_runs_secret_id_fk",
      columns: [table.tenantId, table.bindSecretId],
      foreignColumns: [
        tenantLdapProviderSecrets.tenantId,
        tenantLdapProviderSecrets.id,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_ldap_sync_runs_secret_provider_fk",
      columns: [table.tenantId, table.providerId],
      foreignColumns: [
        tenantLdapProviderSecrets.tenantId,
        tenantLdapProviderSecrets.providerId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_ldap_sync_runs_starter_fk",
      columns: [table.tenantId, table.startedByMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "tenant_ldap_sync_runs_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "tenant_ldap_sync_runs_kind_check",
      sql`${table.providerKind} = 'ldap'`,
    ),
    check(
      "tenant_ldap_sync_runs_revision_check",
      sql`${table.providerVersion} > 0
        and ${table.configurationVersion} > 0
        and ${table.bindingVersion} > 0
        and ${table.bindingAuthRevision} > 0
        and ${table.ruleSetRevision} > 0
        and ${table.authorizationRevision} > 0
        and ${table.authorizationProgressRevision} >= ${table.authorizationRevision}
        and ${table.bindSecretVersion} > 0
        and ${table.bindSecretKeyVersion} > 0
        and ${table.claimFence} >= 0
        and ${table.version} between 1 and 5`,
    ),
    check(
      "tenant_ldap_sync_runs_claim_check",
      sql`(
          ${table.claimFence} = 0
          and ${table.claimId} is null
          and ${table.claimReceiptDigest} is null
          and ${table.claimAcquiredAt} is null
          and ${table.claimExpiresAt} is null
        ) or (
          ${table.claimFence} > 0
          and (uuid_extract_version(${table.claimId}) = 7) is true
          and octet_length(${table.claimReceiptDigest}) = 32
          and ${table.claimAcquiredAt} >= ${table.queuedAt}
          and ${table.claimExpiresAt} > ${table.claimAcquiredAt}
        )`,
    ),
    check(
      "tenant_ldap_sync_runs_digest_check",
      sql`(uuid_extract_version(${table.bindSecretId}) = 7) is true
        and ${table.bindSecretAlgorithm} = 'aes-256-gcm'
        and octet_length(${table.endpointSnapshotDigest}) = 32
        and (${table.cursorDigest} is null or octet_length(${table.cursorDigest}) = 32)`,
    ),
    check(
      "tenant_ldap_sync_runs_actor_check",
      sql`(${table.trigger} = 'scheduled' and ${table.startedByMembershipId} is null)
        or (${table.trigger} = 'manual' and ${table.startedByMembershipId} is not null)`,
    ),
    check(
      "tenant_ldap_sync_runs_reason_check",
      sql`btrim(${table.reason}) <> '' and char_length(${table.reason}) <= 500
        and ${table.reason} !~ '[[:cntrl:]]'`,
    ),
    check(
      "tenant_ldap_sync_runs_counts_check",
      sql`${table.observedCount} between 0 and 5000
        and ${table.appliedCount} between 0 and ${table.observedCount}
        and ${table.revokedCount} between 0 and 5000`,
    ),
    check(
      "tenant_ldap_sync_runs_failure_check",
      sql`${table.failureCategory} is null or (
        btrim(${table.failureCategory}) <> ''
        and char_length(${table.failureCategory}) <= 64
        and ${table.failureCategory} ~ '^[a-z][a-z0-9_]{1,63}$'
      )`,
    ),
    check(
      "tenant_ldap_sync_runs_lifecycle_check",
      sql`(
          ${table.status} = 'queued'
          and ${table.enumerationComplete} is null
          and ${table.resultTruncated} is null
          and ${table.enumerationStartedAt} is null
          and ${table.enumerationCompletedAt} is null
          and ${table.completedAt} is null
          and ${table.failureCategory} is null
          and ${table.claimFence} = 0
          and ${table.version} = 1
        ) or (
          ${table.status} = 'enumerating'
          and ${table.enumerationComplete} is null
          and ${table.resultTruncated} is null
          and ${table.enumerationStartedAt} >= ${table.queuedAt}
          and ${table.enumerationCompletedAt} is null
          and ${table.completedAt} is null
          and ${table.failureCategory} is null
          and ${table.claimFence} > 0
          and ${table.version} = 2
        ) or (
          ${table.status} = 'applying'
          and ${table.enumerationComplete} is true
          and ${table.resultTruncated} is false
          and ${table.enumerationStartedAt} >= ${table.queuedAt}
          and ${table.enumerationCompletedAt} >= ${table.enumerationStartedAt}
          and ${table.completedAt} is null
          and ${table.failureCategory} is null
          and ${table.claimFence} > 0
          and ${table.version} = 3
        ) or (
          ${table.status} = 'succeeded'
          and ${table.enumerationComplete} is true
          and ${table.resultTruncated} is false
          and ${table.enumerationCompletedAt} >= ${table.enumerationStartedAt}
          and ${table.completedAt} >= ${table.enumerationCompletedAt}
          and ${table.failureCategory} is null
          and ${table.appliedCount} = ${table.observedCount}
          and ${table.version} = 4
        ) or (
          ${table.status} in ('failed', 'cancelled', 'stale')
          and ${table.completedAt} >= coalesce(${table.enumerationStartedAt}, ${table.queuedAt})
          and ${table.failureCategory} is not null
          and ${table.version} between 2 and 5
        )`,
    ),
  ],
).enableRLS();

/** Immutable mapping/source pins selected when the sync run is queued. */
export const tenantLdapSyncRunMappings = pgTable(
  "tenant_ldap_sync_run_mappings",
  {
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    syncRunId: uuid("sync_run_id").notNull(),
    bindingId: uuid("binding_id").notNull(),
    mappingRuleId: uuid("mapping_rule_id").notNull(),
    mappingVersion: integer("mapping_version").notNull(),
    configurationRevision: integer("configuration_revision").notNull(),
    sourceEpochId: uuid("source_epoch_id").notNull(),
    sourceId: uuid("source_id").notNull(),
    priority: integer("priority").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    primaryKey({
      name: "tenant_ldap_sync_run_mappings_pkey",
      columns: [table.tenantId, table.syncRunId, table.mappingRuleId],
    }),
    unique("tenant_ldap_sync_run_mappings_epoch_key").on(
      table.tenantId,
      table.syncRunId,
      table.sourceEpochId,
    ),
    index("tenant_ldap_sync_run_mappings_order_idx").on(
      table.tenantId,
      table.syncRunId,
      table.priority,
      table.mappingRuleId,
    ),
    foreignKey({
      name: "tenant_ldap_sync_run_mappings_run_fk",
      columns: [table.tenantId, table.syncRunId, table.bindingId],
      foreignColumns: [
        tenantLdapSyncRuns.tenantId,
        tenantLdapSyncRuns.id,
        tenantLdapSyncRuns.bindingId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_ldap_sync_run_mappings_rule_fk",
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
      name: "tenant_ldap_sync_run_mappings_epoch_fk",
      columns: [
        table.tenantId,
        table.sourceEpochId,
        table.mappingRuleId,
        table.bindingId,
        table.sourceId,
      ],
      foreignColumns: [
        tenantLdapMappingRuleEpochs.tenantId,
        tenantLdapMappingRuleEpochs.id,
        tenantLdapMappingRuleEpochs.mappingRuleId,
        tenantLdapMappingRuleEpochs.bindingId,
        tenantLdapMappingRuleEpochs.sourceId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "tenant_ldap_sync_run_mappings_revision_check",
      sql`${table.mappingVersion} > 0 and ${table.configurationRevision} > 0
        and ${table.priority} between 0 and 1000000`,
    ),
  ],
).enableRLS();

/** Digest-only bounded staging; normalized LDAP values never enter this table. */
export const tenantLdapSyncStagedObservations = pgTable(
  "tenant_ldap_sync_staged_observations",
  {
    id: uuid("id").notNull(),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    syncRunId: uuid("sync_run_id").notNull(),
    providerId: uuid("provider_id").notNull(),
    ordinal: integer("ordinal").notNull(),
    digestKeyVersion: integer("digest_key_version").notNull(),
    subjectDigest: bytea("subject_digest").notNull(),
    observationDigest: bytea("observation_digest").notNull(),
    externalIdentityId: uuid("external_identity_id"),
    planningFence: bigint("planning_fence", { mode: "bigint" }),
    planningClaimedAt: timestamp("planning_claimed_at", {
      withTimezone: true,
      mode: "date",
    }),
    stagedAt: timestamp("staged_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    appliedAt: timestamp("applied_at", { withTimezone: true, mode: "date" }),
    applyAttempt: integer("apply_attempt").notNull().default(0),
  },
  (table) => [
    primaryKey({
      name: "tenant_ldap_sync_staged_observations_pkey",
      columns: [table.tenantId, table.syncRunId, table.id],
    }),
    unique("tenant_ldap_sync_staged_observations_ordinal_key").on(
      table.tenantId,
      table.syncRunId,
      table.ordinal,
    ),
    unique("tenant_ldap_sync_staged_observations_subject_key").on(
      table.tenantId,
      table.syncRunId,
      table.digestKeyVersion,
      table.subjectDigest,
    ),
    index("tenant_ldap_sync_staged_observations_apply_idx").on(
      table.tenantId,
      table.syncRunId,
      table.appliedAt,
      table.ordinal,
    ),
    foreignKey({
      name: "tenant_ldap_sync_staged_observations_run_fk",
      columns: [table.tenantId, table.syncRunId],
      foreignColumns: [tenantLdapSyncRuns.tenantId, tenantLdapSyncRuns.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_ldap_sync_staged_observations_identity_fk",
      columns: [table.tenantId, table.providerId, table.externalIdentityId],
      foreignColumns: [
        tenantLdapExternalIdentities.tenantId,
        tenantLdapExternalIdentities.providerId,
        tenantLdapExternalIdentities.id,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "tenant_ldap_sync_staged_observations_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "tenant_ldap_sync_staged_observations_bounds_check",
      sql`${table.ordinal} between 1 and 5000
        and ${table.digestKeyVersion} between 1 and 32767
        and octet_length(${table.subjectDigest}) = 32
        and octet_length(${table.observationDigest}) = 32
        and ${table.applyAttempt} between 0 and 10
        and ((${table.planningFence} is null and ${table.planningClaimedAt} is null)
          or (${table.planningFence} > 0
            and ${table.planningClaimedAt} >= ${table.stagedAt}))
        and (${table.appliedAt} is null or ${table.appliedAt} >= ${table.stagedAt})`,
    ),
  ],
).enableRLS();

/** Idempotent receipt for the exact plan consumed by JIT or sync. */
export const tenantLdapIdentityPlanApplications = pgTable(
  "tenant_ldap_identity_plan_applications",
  {
    id: uuid("id").primaryKey(),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    planDigest: bytea("plan_digest").notNull(),
    applyMode: ldapIdentityApplyMode("apply_mode").notNull(),
    decision: ldapIdentityApplyDecision("decision").notNull(),
    denialCategory: text("denial_category"),
    providerId: uuid("provider_id").notNull(),
    bindingId: uuid("binding_id").notNull(),
    syncRunId: uuid("sync_run_id"),
    syncObservationId: uuid("sync_observation_id"),
    providerVersion: integer("provider_version").notNull(),
    configurationVersion: integer("configuration_version").notNull(),
    bindingVersion: integer("binding_version").notNull(),
    bindingAuthRevision: integer("binding_auth_revision").notNull(),
    bindingAccessEpochId: uuid("binding_access_epoch_id").notNull(),
    ruleSetRevision: bigint("rule_set_revision", { mode: "bigint" }).notNull(),
    authorizationRevision: bigint("authorization_revision", {
      mode: "bigint",
    }).notNull(),
    externalIdentityId: uuid("external_identity_id"),
    userId: uuid("user_id"),
    membershipId: uuid("membership_id"),
    accessGrantId: uuid("access_grant_id"),
    ensuredEdgeCount: integer("ensured_edge_count").notNull().default(0),
    revokedEdgeCount: integer("revoked_edge_count").notNull().default(0),
    auditEventId: uuid("audit_event_id").notNull(),
    requestId: uuid("request_id").notNull(),
    correlationId: uuid("correlation_id").notNull(),
    observedAt: timestamp("observed_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    appliedAt: timestamp("applied_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    unique("tenant_ldap_identity_plan_applications_tenant_id_key").on(
      table.tenantId,
      table.id,
    ),
    unique("tenant_ldap_identity_plan_applications_audit_key").on(
      table.tenantId,
      table.auditEventId,
    ),
    index("tenant_ldap_identity_plan_applications_binding_idx").on(
      table.tenantId,
      table.bindingId,
      table.appliedAt,
      table.id,
    ),
    index("tenant_ldap_identity_plan_applications_identity_idx").on(
      table.tenantId,
      table.externalIdentityId,
      table.appliedAt,
      table.id,
    ),
    foreignKey({
      name: "tenant_ldap_identity_plan_applications_binding_fk",
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
      name: "tenant_ldap_identity_plan_applications_access_epoch_fk",
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
      name: "tenant_ldap_identity_plan_applications_sync_observation_fk",
      columns: [table.tenantId, table.syncRunId, table.syncObservationId],
      foreignColumns: [
        tenantLdapSyncStagedObservations.tenantId,
        tenantLdapSyncStagedObservations.syncRunId,
        tenantLdapSyncStagedObservations.id,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_ldap_identity_plan_applications_identity_fk",
      columns: [
        table.tenantId,
        table.providerId,
        table.externalIdentityId,
        table.userId,
      ],
      foreignColumns: [
        tenantLdapExternalIdentities.tenantId,
        tenantLdapExternalIdentities.providerId,
        tenantLdapExternalIdentities.id,
        tenantLdapExternalIdentities.userId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_ldap_identity_plan_applications_membership_fk",
      columns: [table.tenantId, table.membershipId, table.userId],
      foreignColumns: [
        tenantMemberships.tenantId,
        tenantMemberships.id,
        tenantMemberships.userId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_ldap_identity_plan_applications_access_grant_fk",
      columns: [table.tenantId, table.accessGrantId],
      foreignColumns: [
        tenantLdapProviderAccessGrants.tenantId,
        tenantLdapProviderAccessGrants.id,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "tenant_ldap_identity_plan_applications_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "tenant_ldap_identity_plan_applications_digest_check",
      sql`octet_length(${table.planDigest}) = 32`,
    ),
    check(
      "tenant_ldap_identity_plan_applications_revision_check",
      sql`${table.providerVersion} > 0 and ${table.configurationVersion} > 0
        and ${table.bindingVersion} > 0 and ${table.bindingAuthRevision} > 0
        and ${table.ruleSetRevision} > 0 and ${table.authorizationRevision} > 0`,
    ),
    check(
      "tenant_ldap_identity_plan_applications_mode_check",
      sql`(${table.applyMode} = 'jit'
          and ${table.syncRunId} is null and ${table.syncObservationId} is null)
        or (${table.applyMode} = 'sync'
          and ${table.syncRunId} is not null and ${table.syncObservationId} is not null)`,
    ),
    check(
      "tenant_ldap_identity_plan_applications_decision_check",
      sql`(${table.decision} = 'denied'
          and ${table.denialCategory} is not null
          and ${table.externalIdentityId} is null and ${table.userId} is null
          and ${table.membershipId} is null and ${table.accessGrantId} is null
          and ${table.ensuredEdgeCount} = 0)
        or (${table.decision} = 'admitted'
          and ${table.denialCategory} is null
          and ${table.externalIdentityId} is not null and ${table.userId} is not null
          and ${table.membershipId} is not null and ${table.accessGrantId} is not null)`,
    ),
    check(
      "tenant_ldap_identity_plan_applications_denial_check",
      sql`${table.denialCategory} is null or (
        btrim(${table.denialCategory}) <> ''
        and char_length(${table.denialCategory}) <= 64
        and ${table.denialCategory} ~ '^[a-z][a-z0-9_]{1,63}$'
      )`,
    ),
    check(
      "tenant_ldap_identity_plan_applications_counts_check",
      sql`${table.ensuredEdgeCount} between 0 and 10000
        and ${table.revokedEdgeCount} between 0 and 10000
        and ${table.appliedAt} >= ${table.observedAt}`,
    ),
  ],
).enableRLS();

/** Grace-period absence is explicit and source qualified, never inferred from a partial run. */
export const tenantLdapSyncAbsences = pgTable(
  "tenant_ldap_sync_absences",
  {
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    bindingId: uuid("binding_id").notNull(),
    externalIdentityId: uuid("external_identity_id").notNull(),
    membershipId: uuid("membership_id").notNull(),
    firstMissingRunId: uuid("first_missing_run_id").notNull(),
    latestMissingRunId: uuid("latest_missing_run_id").notNull(),
    status: ldapSyncAbsenceStatus("status").notNull().default("pending"),
    firstMissingAt: timestamp("first_missing_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    applyAfter: timestamp("apply_after", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    resolvedAt: timestamp("resolved_at", { withTimezone: true, mode: "date" }),
    version: integer("version").notNull().default(1),
  },
  (table) => [
    primaryKey({
      name: "tenant_ldap_sync_absences_pkey",
      columns: [table.tenantId, table.bindingId, table.externalIdentityId],
    }),
    index("tenant_ldap_sync_absences_due_idx").on(
      table.tenantId,
      table.status,
      table.applyAfter,
      table.bindingId,
    ),
    foreignKey({
      name: "tenant_ldap_sync_absences_binding_fk",
      columns: [table.tenantId, table.bindingId],
      foreignColumns: [
        tenantAuthProviderBindings.tenantId,
        tenantAuthProviderBindings.id,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_ldap_sync_absences_identity_fk",
      columns: [table.tenantId, table.externalIdentityId],
      foreignColumns: [
        tenantLdapExternalIdentities.tenantId,
        tenantLdapExternalIdentities.id,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_ldap_sync_absences_membership_fk",
      columns: [table.tenantId, table.membershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_ldap_sync_absences_first_run_fk",
      columns: [table.tenantId, table.firstMissingRunId, table.bindingId],
      foreignColumns: [
        tenantLdapSyncRuns.tenantId,
        tenantLdapSyncRuns.id,
        tenantLdapSyncRuns.bindingId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_ldap_sync_absences_latest_run_fk",
      columns: [table.tenantId, table.latestMissingRunId, table.bindingId],
      foreignColumns: [
        tenantLdapSyncRuns.tenantId,
        tenantLdapSyncRuns.id,
        tenantLdapSyncRuns.bindingId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "tenant_ldap_sync_absences_lifecycle_check",
      sql`${table.applyAfter} >= ${table.firstMissingAt}
        and ((${table.status} = 'pending' and ${table.resolvedAt} is null)
          or (${table.status} in ('cleared', 'applied')
            and ${table.resolvedAt} >= ${table.firstMissingAt}))
        and ${table.version} > 0`,
    ),
  ],
).enableRLS();
