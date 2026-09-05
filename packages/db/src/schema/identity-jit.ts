import { sql } from "drizzle-orm";
import {
  bigint,
  check,
  foreignKey,
  index,
  integer,
  jsonb,
  pgTable,
  primaryKey,
  text,
  timestamp,
  unique,
  uuid,
} from "drizzle-orm/pg-core";

import { bytea } from "./binary.js";
import { authProviderKind, ldapJitRunStatus } from "./enums.js";
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
  tenantLdapProviderSecrets,
} from "./identity-providers.js";
import { tenantLdapIdentityPlanApplications } from "./identity-sync.js";
import { tenants } from "./tenancy.js";

/**
 * A short-lived pre-authentication capability. The opaque receipt is never
 * stored, only its SHA-256 digest. Login names, passwords and LDAP values are
 * deliberately absent; all network and account meters are keyed digests.
 */
export const tenantLdapJitAuthenticationRuns = pgTable(
  "tenant_ldap_jit_authentication_runs",
  {
    id: uuid("id").primaryKey(),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    receiptDigest: bytea("receipt_digest").notNull(),
    providerId: uuid("provider_id").notNull(),
    providerKind: authProviderKind("provider_kind").notNull().default("ldap"),
    bindingId: uuid("binding_id").notNull(),
    providerVersion: integer("provider_version").notNull(),
    configurationVersion: integer("configuration_version").notNull(),
    bindSecretId: uuid("bind_secret_id").notNull(),
    bindSecretVersion: integer("bind_secret_version").notNull(),
    bindSecretKeyVersion: integer("bind_secret_key_version")
      .notNull()
      .references(() => identityKeyringVersions.keyVersion, {
        onDelete: "restrict",
      }),
    bindSecretAlgorithm: text("bind_secret_algorithm").notNull(),
    endpointSnapshotDigest: bytea("endpoint_snapshot_digest").notNull(),
    bindingVersion: integer("binding_version").notNull(),
    bindingAuthRevision: integer("binding_auth_revision").notNull(),
    bindingAccessEpochId: uuid("binding_access_epoch_id").notNull(),
    ruleSetRevision: bigint("rule_set_revision", { mode: "bigint" }).notNull(),
    authorizationRevision: bigint("authorization_revision", {
      mode: "bigint",
    }).notNull(),
    /**
     * Authorization revision after the admitted/denied mapping mutation.
     * The input revision above remains immutable; this result pin is written
     * exactly once by the planning -> terminal transition.
     */
    resultAuthorizationRevision: bigint("result_authorization_revision", {
      mode: "bigint",
    }),
    networkRateKeyDigest: bytea("network_rate_key_digest").notNull(),
    accountRateKeyDigest: bytea("account_rate_key_digest").notNull(),
    providerRateKeyDigest: bytea("provider_rate_key_digest").notNull(),
    status: ldapJitRunStatus("status").notNull().default("network_pending"),
    terminalCategory: text("terminal_category"),
    applicationId: uuid("application_id"),
    planDigest: bytea("plan_digest"),
    beginAuditEventId: uuid("begin_audit_event_id").notNull(),
    terminalAuditEventId: uuid("terminal_audit_event_id"),
    requestId: uuid("request_id").notNull(),
    correlationId: uuid("correlation_id").notNull(),
    startedAt: timestamp("started_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    expiresAt: timestamp("expires_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    claimedAt: timestamp("claimed_at", {
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
    unique("tenant_ldap_jit_runs_tenant_id_key").on(table.tenantId, table.id),
    unique("tenant_ldap_jit_runs_exact_binding_key").on(
      table.tenantId,
      table.id,
      table.bindingId,
    ),
    unique("tenant_ldap_jit_runs_receipt_key").on(table.receiptDigest),
    unique("tenant_ldap_jit_runs_begin_audit_key").on(
      table.tenantId,
      table.beginAuditEventId,
    ),
    unique("tenant_ldap_jit_runs_terminal_audit_key").on(
      table.tenantId,
      table.terminalAuditEventId,
    ),
    index("tenant_ldap_jit_runs_expiry_idx").on(
      table.status,
      table.expiresAt,
      table.id,
    ),
    index("tenant_ldap_jit_runs_binding_started_idx").on(
      table.tenantId,
      table.bindingId,
      table.startedAt,
      table.id,
    ),
    foreignKey({
      name: "tenant_ldap_jit_runs_provider_fk",
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
      name: "tenant_ldap_jit_runs_binding_fk",
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
      name: "tenant_ldap_jit_runs_secret_id_fk",
      columns: [table.tenantId, table.bindSecretId],
      foreignColumns: [
        tenantLdapProviderSecrets.tenantId,
        tenantLdapProviderSecrets.id,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_ldap_jit_runs_secret_provider_fk",
      columns: [table.tenantId, table.providerId],
      foreignColumns: [
        tenantLdapProviderSecrets.tenantId,
        tenantLdapProviderSecrets.providerId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_ldap_jit_runs_access_epoch_fk",
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
      name: "tenant_ldap_jit_runs_application_fk",
      columns: [table.tenantId, table.applicationId],
      foreignColumns: [
        tenantLdapIdentityPlanApplications.tenantId,
        tenantLdapIdentityPlanApplications.id,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "tenant_ldap_jit_runs_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "tenant_ldap_jit_runs_kind_check",
      sql`${table.providerKind} = 'ldap'`,
    ),
    check(
      "tenant_ldap_jit_runs_revision_check",
      sql`${table.providerVersion} > 0
        and ${table.configurationVersion} > 0
        and ${table.bindSecretVersion} > 0
        and ${table.bindSecretKeyVersion} > 0
        and ${table.bindingVersion} > 0
        and ${table.bindingAuthRevision} > 0
        and ${table.ruleSetRevision} > 0
        and ${table.authorizationRevision} > 0
        and ${table.version} between 1 and 3`,
    ),
    check(
      "tenant_ldap_jit_runs_result_authorization_revision_check",
      sql`((${table.status} in ('succeeded', 'denied')
          and ${table.resultAuthorizationRevision} > 0)
        or (${table.status} not in ('succeeded', 'denied')
          and ${table.resultAuthorizationRevision} is null))`,
    ),
    check(
      "tenant_ldap_jit_runs_digest_check",
      sql`octet_length(${table.receiptDigest}) = 32
        and octet_length(${table.endpointSnapshotDigest}) = 32
        and octet_length(${table.networkRateKeyDigest}) = 32
        and octet_length(${table.accountRateKeyDigest}) = 32
        and octet_length(${table.providerRateKeyDigest}) = 32
        and (${table.planDigest} is null or octet_length(${table.planDigest}) = 32)`,
    ),
    check(
      "tenant_ldap_jit_runs_secret_check",
      sql`(uuid_extract_version(${table.bindSecretId}) = 7) is true
        and ${table.bindSecretAlgorithm} = 'aes-256-gcm'`,
    ),
    check(
      "tenant_ldap_jit_runs_lifetime_check",
      sql`${table.expiresAt} > ${table.startedAt}
        and ${table.expiresAt} <= ${table.startedAt} + interval '2 minutes'`,
    ),
    check(
      "tenant_ldap_jit_runs_terminal_category_check",
      sql`${table.terminalCategory} is null or (
        char_length(${table.terminalCategory}) between 2 and 64
        and ${table.terminalCategory} ~ '^[a-z][a-z0-9_]{1,63}$'
      )`,
    ),
    check(
      "tenant_ldap_jit_runs_lifecycle_check",
      sql`(
          ${table.status} = 'network_pending'
          and ${table.terminalCategory} is null
          and ${table.applicationId} is null and ${table.planDigest} is null
          and ${table.terminalAuditEventId} is null
          and ${table.claimedAt} is null and ${table.completedAt} is null
          and ${table.version} = 1
        ) or (
          ${table.status} = 'planning'
          and ${table.terminalCategory} is null
          and ${table.applicationId} is null and ${table.planDigest} is null
          and ${table.terminalAuditEventId} is null
          and ${table.claimedAt} >= ${table.startedAt}
          and ${table.completedAt} is null and ${table.version} = 2
        ) or (
          ${table.status} in ('succeeded', 'denied')
          and ${table.terminalCategory} is null
          and ${table.applicationId} is not null and ${table.planDigest} is not null
          and ${table.terminalAuditEventId} is not null
          and ${table.claimedAt} >= ${table.startedAt}
          and ${table.completedAt} >= ${table.claimedAt}
          and ${table.version} = 3
        ) or (
          ${table.status} in ('failed', 'stale', 'expired')
          and ${table.terminalCategory} is not null
          and ${table.applicationId} is null and ${table.planDigest} is null
          and ${table.terminalAuditEventId} is not null
          and ${table.completedAt} >= coalesce(${table.claimedAt}, ${table.startedAt})
          and ((${table.version} = 2 and ${table.claimedAt} is null)
            or (${table.version} = 3 and ${table.claimedAt} is not null))
        )`,
    ),
  ],
).enableRLS();

/**
 * Immutable, exact request/result binding for the one authority issuance that
 * may follow an admitted LDAP JIT run. Runtime retries never rebuild a result
 * from caller supplied fields.
 */
export const tenantLdapJitAuthorityIssuanceReceipts = pgTable(
  "tenant_ldap_jit_authority_issuance_receipts",
  {
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    jitRunId: uuid("jit_run_id").notNull(),
    requestDigest: bytea("request_digest").notNull(),
    resultSnapshot: jsonb("result_snapshot").notNull(),
    createdAt: timestamp("created_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
  },
  (table) => [
    primaryKey({
      name: "tenant_ldap_jit_authority_issuance_receipts_pkey",
      columns: [table.tenantId, table.jitRunId],
    }),
    foreignKey({
      name: "tenant_ldap_jit_authority_issuance_receipts_run_fk",
      columns: [table.tenantId, table.jitRunId],
      foreignColumns: [
        tenantLdapJitAuthenticationRuns.tenantId,
        tenantLdapJitAuthenticationRuns.id,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "tenant_ldap_jit_authority_issuance_receipts_value_check",
      sql`octet_length(${table.requestDigest}) = 32
        and jsonb_typeof(${table.resultSnapshot}) = 'object'
        and pg_column_size(${table.resultSnapshot}) between 2 and 65536`,
    ),
  ],
).enableRLS();

/** Exact immutable mapping/source pins committed before the LDAP network hop. */
export const tenantLdapJitRunMappings = pgTable(
  "tenant_ldap_jit_run_mappings",
  {
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    jitRunId: uuid("jit_run_id").notNull(),
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
      name: "tenant_ldap_jit_run_mappings_pkey",
      columns: [table.tenantId, table.jitRunId, table.mappingRuleId],
    }),
    unique("tenant_ldap_jit_run_mappings_epoch_key").on(
      table.tenantId,
      table.jitRunId,
      table.sourceEpochId,
    ),
    index("tenant_ldap_jit_run_mappings_order_idx").on(
      table.tenantId,
      table.jitRunId,
      table.priority,
      table.mappingRuleId,
    ),
    foreignKey({
      name: "tenant_ldap_jit_run_mappings_run_fk",
      columns: [table.tenantId, table.jitRunId, table.bindingId],
      foreignColumns: [
        tenantLdapJitAuthenticationRuns.tenantId,
        tenantLdapJitAuthenticationRuns.id,
        tenantLdapJitAuthenticationRuns.bindingId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_ldap_jit_run_mappings_rule_fk",
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
      name: "tenant_ldap_jit_run_mappings_epoch_fk",
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
      "tenant_ldap_jit_run_mappings_revision_check",
      sql`${table.mappingVersion} > 0 and ${table.configurationRevision} > 0
        and ${table.priority} between 0 and 1000000`,
    ),
  ],
).enableRLS();
