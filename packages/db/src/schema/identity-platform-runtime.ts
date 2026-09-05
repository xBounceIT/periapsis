import { sql } from "drizzle-orm";
import {
  bigint,
  boolean,
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
  uniqueIndex,
  uuid,
} from "drizzle-orm/pg-core";

import { authSessions } from "./authentication.js";
import { tenantAuthorizationSources } from "./authorization.js";
import { bytea } from "./binary.js";
import { authProviderKind, identitySubjectFormat } from "./enums.js";
import {
  tenantPlatformAuthProviderBindings,
  tenantPlatformIdentityProviderAccessEpochs,
} from "./identity-platform-bindings.js";
import {
  platformAuthProviders,
  platformFederatedProviderPolicies,
  platformOidcProviderConfigurations,
} from "./identity-platform-federation.js";
import {
  authSessionMfaStates,
  tenantMfaAuthorityAnchors,
  tenantPostPrimaryContinuations,
} from "./identity-mfa.js";
import { identityKeyringVersions } from "./identity-providers.js";
import { tenantMemberships, users } from "./identity.js";
import { tenants } from "./tenancy.js";

/**
 * Provider-global immutable subject identity; tenant admission lives elsewhere.
 * Retirement actor/reason belong to the append-only platform audit stream, and
 * the protected retirement ABI invalidates dependent runtime paths atomically.
 */
export const platformFederatedExternalIdentities = pgTable(
  "platform_federated_external_identities",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    platformProviderId: uuid("platform_provider_id").notNull(),
    providerKind: authProviderKind("provider_kind").notNull().default("oidc"),
    userId: uuid("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "restrict" }),
    subjectFormat: identitySubjectFormat("subject_format").notNull(),
    subjectCiphertext: bytea("subject_ciphertext").notNull(),
    subjectNonce: bytea("subject_nonce").notNull(),
    keyVersion: integer("key_version").notNull(),
    admittedConfigurationRevision: bigint("admitted_configuration_revision", {
      mode: "bigint",
    }).notNull(),
    admittedSecurityRevision: bigint("admitted_security_revision", {
      mode: "bigint",
    }).notNull(),
    lastObservedAt: timestamp("last_observed_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    lastObservationState: text("last_observation_state")
      .notNull()
      .default("known"),
    retiredAt: timestamp("retired_at", { withTimezone: true, mode: "date" }),
    version: bigint("version", { mode: "bigint" })
      .notNull()
      .default(sql`1`),
    resourceVersion: bigint("resource_version", { mode: "bigint" })
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
    unique("platform_federated_external_identities_provider_key").on(
      table.platformProviderId,
      table.id,
    ),
    unique("platform_federated_external_identities_exact_key").on(
      table.platformProviderId,
      table.id,
      table.userId,
    ),
    uniqueIndex("platform_federated_external_identities_live_provider_user_key")
      .on(table.platformProviderId, table.userId)
      .where(sql`${table.retiredAt} is null`),
    index("platform_federated_external_identities_live_provider_cursor_idx")
      .on(table.platformProviderId, table.id)
      .where(sql`${table.retiredAt} is null`),
    foreignKey({
      name: "platform_federated_external_identities_provider_fk",
      columns: [table.platformProviderId, table.providerKind],
      foreignColumns: [platformAuthProviders.id, platformAuthProviders.kind],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "platform_federated_external_identities_policy_fk",
      columns: [table.platformProviderId, table.providerKind],
      foreignColumns: [
        platformFederatedProviderPolicies.providerId,
        platformFederatedProviderPolicies.providerKind,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "platform_federated_external_identities_keyring_fk",
      columns: [table.keyVersion],
      foreignColumns: [identityKeyringVersions.keyVersion],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "platform_federated_external_identities_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "platform_federated_external_identities_subject_check",
      sql`${table.providerKind} in ('oidc','saml')
        and ${table.subjectFormat} = 'utf8_exact'
        and octet_length(${table.subjectCiphertext}) between 17 and 4112
        and octet_length(${table.subjectNonce}) = 12
        and ${table.keyVersion} between 1 and 32767`,
    ),
    check(
      "platform_federated_external_identities_observation_state_check",
      sql`${table.lastObservationState} in ('known', 'legacy_unknown')
        and (${table.lastObservationState} = 'known' or (
          ${table.retiredAt} is not null
          and ${table.resourceVersion} = 1
          and ${table.lastObservedAt} = ${table.retiredAt}))`,
    ),
    check(
      "platform_federated_external_identities_lifecycle_check",
      sql`${table.admittedConfigurationRevision} between 1 and 9007199254740991
        and ${table.admittedSecurityRevision} between 1 and 9007199254740991
        and ${table.version} between 1 and 2147483647
        and ${table.resourceVersion} between 1 and 2147483647
        and ${table.lastObservedAt} >= ${table.createdAt}
        and ${table.updatedAt} >= ${table.createdAt}
        and (${table.retiredAt} is null or (
          ${table.retiredAt} >= ${table.createdAt}
          and ${table.updatedAt} >= ${table.retiredAt}))`,
    ),
  ],
).enableRLS();

export const platformFederatedExternalIdentityAliases = pgTable(
  "platform_federated_external_identity_aliases",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    platformProviderId: uuid("platform_provider_id").notNull(),
    externalIdentityId: uuid("external_identity_id").notNull(),
    keyVersion: integer("key_version").notNull(),
    subjectDigest: bytea("subject_digest").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    retiredAt: timestamp("retired_at", { withTimezone: true, mode: "date" }),
  },
  (table) => [
    unique("platform_federated_external_identity_aliases_digest_key").on(
      table.platformProviderId,
      table.keyVersion,
      table.subjectDigest,
    ),
    unique("platform_federated_external_identity_aliases_version_key").on(
      table.externalIdentityId,
      table.keyVersion,
    ),
    foreignKey({
      name: "platform_federated_external_identity_aliases_identity_fk",
      columns: [table.platformProviderId, table.externalIdentityId],
      foreignColumns: [
        platformFederatedExternalIdentities.platformProviderId,
        platformFederatedExternalIdentities.id,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "platform_federated_external_identity_aliases_keyring_fk",
      columns: [table.keyVersion],
      foreignColumns: [identityKeyringVersions.keyVersion],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "platform_federated_external_identity_aliases_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "platform_federated_external_identity_aliases_digest_check",
      sql`${table.keyVersion} between 1 and 32767
        and octet_length(${table.subjectDigest}) = 32`,
    ),
    check(
      "platform_federated_external_identity_aliases_lifecycle_check",
      sql`${table.retiredAt} is null or ${table.retiredAt} >= ${table.createdAt}`,
    ),
  ],
).enableRLS();

/**
 * Bounded exact-replay ledger for administrator-created provider account links.
 * The confidential subject is deliberately absent: replay equality is proven
 * against the provider-scoped alias tombstones while this row binds only the
 * normalized public request.
 */
export const platformIdentityAccountCommands = pgTable(
  "platform_identity_account_commands",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    actorUserId: uuid("actor_user_id")
      .notNull()
      .references(() => users.id, { onDelete: "restrict" }),
    operation: text("operation").notNull(),
    platformProviderId: uuid("platform_provider_id")
      .notNull()
      .references(() => platformAuthProviders.id, { onDelete: "restrict" }),
    keyDigest: bytea("key_digest").notNull(),
    publicRequestDigest: bytea("public_request_digest").notNull(),
    resultAccountId: uuid("result_account_id").notNull(),
    resultVersion: bigint("result_version", { mode: "bigint" }).notNull(),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    expiresAt: timestamp("expires_at", { withTimezone: true, mode: "date" })
      .notNull()
      .default(sql`now() + interval '24 hours'`),
  },
  (table) => [
    unique("platform_identity_account_commands_replay_key").on(
      table.actorUserId,
      table.operation,
      table.platformProviderId,
      table.keyDigest,
    ),
    index("platform_identity_account_commands_expiry_idx").on(table.expiresAt),
    index("platform_identity_account_commands_result_idx").on(
      table.platformProviderId,
      table.resultAccountId,
    ),
    foreignKey({
      name: "platform_identity_account_commands_result_fk",
      columns: [table.platformProviderId, table.resultAccountId],
      foreignColumns: [
        platformFederatedExternalIdentities.platformProviderId,
        platformFederatedExternalIdentities.id,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "platform_identity_account_commands_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "platform_identity_account_commands_operation_check",
      sql`${table.operation} = 'account.prelink'`,
    ),
    check(
      "platform_identity_account_commands_digest_check",
      sql`octet_length(${table.keyDigest}) = 32
        and octet_length(${table.publicRequestDigest}) = 32`,
    ),
    check(
      "platform_identity_account_commands_result_check",
      sql`${table.resultVersion} = 1`,
    ),
    check(
      "platform_identity_account_commands_retention_check",
      sql`${table.expiresAt} > ${table.createdAt}
        and ${table.expiresAt} <= ${table.createdAt} + interval '7 days'`,
    ),
  ],
).enableRLS();

/** Tenant-owned admission of one provider-global identity. */
export const tenantPlatformFederatedProviderAccessGrants = pgTable(
  "tenant_platform_federated_provider_access_grants",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    platformProviderId: uuid("platform_provider_id").notNull(),
    bindingId: uuid("binding_id").notNull(),
    accessEpochId: uuid("access_epoch_id").notNull(),
    sourceId: uuid("source_id").notNull(),
    externalIdentityId: uuid("external_identity_id").notNull(),
    membershipId: uuid("membership_id").notNull(),
    userId: uuid("user_id").notNull(),
    ownsMembership: boolean("owns_membership").notNull().default(false),
    startedAt: timestamp("started_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    lastObservedAt: timestamp("last_observed_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    endedAt: timestamp("ended_at", { withTimezone: true, mode: "date" }),
    version: bigint("version", { mode: "bigint" })
      .notNull()
      .default(sql`1`),
  },
  (table) => [
    unique("tenant_platform_federated_provider_access_grants_tenant_id_key").on(
      table.tenantId,
      table.id,
    ),
    unique("tenant_platform_federated_provider_access_grants_exact_key").on(
      table.tenantId,
      table.id,
      table.platformProviderId,
      table.bindingId,
      table.accessEpochId,
      table.sourceId,
      table.externalIdentityId,
      table.membershipId,
      table.userId,
    ),
    uniqueIndex(
      "tenant_platform_federated_provider_access_grants_live_binding_member_key",
    )
      .on(table.tenantId, table.bindingId, table.membershipId)
      .where(sql`${table.endedAt} is null`),
    foreignKey({
      name: "tenant_platform_federated_provider_access_grants_epoch_fk",
      columns: [
        table.tenantId,
        table.accessEpochId,
        table.bindingId,
        table.platformProviderId,
        table.sourceId,
      ],
      foreignColumns: [
        tenantPlatformIdentityProviderAccessEpochs.tenantId,
        tenantPlatformIdentityProviderAccessEpochs.id,
        tenantPlatformIdentityProviderAccessEpochs.bindingId,
        tenantPlatformIdentityProviderAccessEpochs.platformProviderId,
        tenantPlatformIdentityProviderAccessEpochs.sourceId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_platform_federated_provider_access_grants_identity_fk",
      columns: [
        table.platformProviderId,
        table.externalIdentityId,
        table.userId,
      ],
      foreignColumns: [
        platformFederatedExternalIdentities.platformProviderId,
        platformFederatedExternalIdentities.id,
        platformFederatedExternalIdentities.userId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_platform_federated_provider_access_grants_membership_fk",
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
      name: "tenant_platform_federated_provider_access_grants_source_fk",
      columns: [table.tenantId, table.sourceId],
      foreignColumns: [
        tenantAuthorizationSources.tenantId,
        tenantAuthorizationSources.id,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "tenant_platform_federated_provider_access_grants_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "tenant_platform_federated_provider_access_grants_lifecycle_check",
      sql`${table.version} between 1 and 2147483647
        and ${table.lastObservedAt} >= ${table.startedAt}
        and (${table.endedAt} is null or ${table.endedAt} >= ${table.startedAt})`,
    ),
  ],
).enableRLS();

export const tenantPlatformFederatedProviderProfileContributions = pgTable(
  "tenant_platform_federated_provider_profile_contributions",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id").notNull(),
    accessGrantId: uuid("access_grant_id").notNull(),
    displayName: text("display_name"),
    username: text("username"),
    email: text("email"),
    mappingRevision: bigint("mapping_revision", { mode: "bigint" }).notNull(),
    observedAt: timestamp("observed_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    retiredAt: timestamp("retired_at", { withTimezone: true, mode: "date" }),
    version: bigint("version", { mode: "bigint" })
      .notNull()
      .default(sql`1`),
  },
  (table) => [
    unique("tenant_platform_profile_contributions_tenant_id_key").on(
      table.tenantId,
      table.id,
    ),
    uniqueIndex(
      "tenant_platform_federated_provider_profile_contributions_live_grant_key",
    )
      .on(table.tenantId, table.accessGrantId)
      .where(sql`${table.retiredAt} is null`),
    foreignKey({
      name: "tenant_platform_federated_provider_profile_contributions_grant_fk",
      columns: [table.tenantId, table.accessGrantId],
      foreignColumns: [
        tenantPlatformFederatedProviderAccessGrants.tenantId,
        tenantPlatformFederatedProviderAccessGrants.id,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_platform_profile_contributions_tenant_fk",
      columns: [table.tenantId],
      foreignColumns: [tenants.id],
    }).onDelete("restrict"),
    check(
      "tenant_platform_federated_provider_profile_contributions_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "tenant_platform_federated_provider_profile_contributions_present_check",
      sql`${table.displayName} is not null
        or ${table.username} is not null or ${table.email} is not null`,
    ),
    check(
      "tenant_platform_federated_provider_profile_contributions_value_check",
      sql`${table.mappingRevision} between 1 and 9007199254740991
        and ${table.version} between 1 and 2147483647
        and (${table.displayName} is null or (
          btrim(${table.displayName}) <> '' and char_length(${table.displayName}) <= 160
          and ${table.displayName} !~ '[[:cntrl:]]'))
        and (${table.username} is null or (
          btrim(${table.username}) <> '' and char_length(${table.username}) <= 320
          and ${table.username} !~ '[[:cntrl:]]'))
        and (${table.email} is null or (
          ${table.email} = lower(btrim(${table.email}))
          and position('@' in ${table.email}) > 1
          and char_length(${table.email}) <= 320
          and ${table.email} !~ '[[:cntrl:]]'))`,
    ),
    check(
      "tenant_platform_federated_provider_profile_contributions_lifecycle_check",
      sql`${table.retiredAt} is null or ${table.retiredAt} >= ${table.observedAt}`,
    ),
  ],
).enableRLS();

/** One browser-bound OIDC flow through an explicit tenant/platform binding. */
export const tenantPlatformOidcAuthenticationTransactions = pgTable(
  "tenant_platform_oidc_authentication_transactions",
  {
    transactionId: bytea("transaction_id").notNull(),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    platformProviderId: uuid("platform_provider_id").notNull(),
    bindingId: uuid("binding_id").notNull(),
    providerKind: authProviderKind("provider_kind").notNull().default("oidc"),
    protocol: text("protocol").notNull().default("oidc"),
    accessEpochId: uuid("access_epoch_id").notNull(),
    accessSourceId: uuid("access_source_id").notNull(),
    operationRunId: uuid("operation_run_id").notNull(),
    operationDigest: bytea("operation_digest").notNull(),
    receiptDigest: bytea("receipt_digest").notNull(),
    networkDigest: bytea("network_digest").notNull(),
    accountDigest: bytea("account_digest").notNull(),
    providerDigest: bytea("provider_digest").notNull(),
    stateDigest: bytea("state_digest").notNull(),
    browserDigest: bytea("browser_digest").notNull(),
    nonceDigest: bytea("nonce_digest").notNull(),
    providerRevision: bigint("provider_revision", { mode: "bigint" }).notNull(),
    bindingRevision: bigint("binding_revision", { mode: "bigint" }).notNull(),
    configurationRevision: bigint("configuration_revision", {
      mode: "bigint",
    }).notNull(),
    securityRevision: bigint("security_revision", { mode: "bigint" }).notNull(),
    planRevision: bigint("plan_revision", { mode: "bigint" }).notNull(),
    mappingRevision: bigint("mapping_revision", { mode: "bigint" }).notNull(),
    authorizationRevision: bigint("authorization_revision", {
      mode: "bigint",
    }).notNull(),
    assurancePolicyRevision: bigint("assurance_policy_revision", {
      mode: "bigint",
    }).notNull(),
    clientSecretRevision: bigint("client_secret_revision", {
      mode: "bigint",
    }).notNull(),
    discoveryRevision: bigint("discovery_revision", {
      mode: "bigint",
    }).notNull(),
    discoveryDigest: bytea("discovery_digest").notNull(),
    jwksRevision: bigint("jwks_revision", { mode: "bigint" }).notNull(),
    jwksDigest: bytea("jwks_digest").notNull(),
    verifierKeyVersion: integer("verifier_key_version").notNull(),
    verifierCiphertext: bytea("verifier_ciphertext").notNull(),
    clientId: text("client_id").notNull(),
    tenantRedirectUri: text("tenant_redirect_uri").notNull(),
    postLogoutRedirectUri: text("post_logout_redirect_uri").notNull(),
    scopes: text("scopes").array().notNull(),
    allowRefreshToken: boolean("allow_refresh_token").notNull(),
    useUserInfo: boolean("use_user_info").notNull(),
    returnPath: text("return_path").notNull(),
    state: text("state").notNull().default("pending"),
    version: bigint("version", { mode: "bigint" })
      .notNull()
      .default(sql`1`),
    claimAttemptId: bytea("claim_attempt_id"),
    createdAt: timestamp("created_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    expiresAt: timestamp("expires_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    claimedAt: timestamp("claimed_at", { withTimezone: true, mode: "date" }),
    completedAt: timestamp("completed_at", {
      withTimezone: true,
      mode: "date",
    }),
    failureReason: text("failure_reason"),
  },
  (table) => [
    primaryKey({
      name: "tenant_platform_oidc_authentication_transactions_pkey",
      columns: [table.tenantId, table.transactionId],
    }),
    unique("tenant_platform_oidc_authentication_transactions_operation_key").on(
      table.operationRunId,
    ),
    unique("tenant_platform_oidc_authentication_transactions_receipt_key").on(
      table.receiptDigest,
    ),
    unique("tenant_platform_oidc_authentication_transactions_state_key").on(
      table.stateDigest,
    ),
    unique("tenant_platform_oidc_authentication_transactions_exact_key").on(
      table.tenantId,
      table.transactionId,
      table.platformProviderId,
      table.bindingId,
    ),
    uniqueIndex(
      "tenant_platform_oidc_authentication_transactions_live_browser_key",
    )
      .on(table.browserDigest)
      .where(sql`${table.state} in ('pending', 'claimed')`),
    index("tenant_platform_oidc_authentication_transactions_expiry_idx").on(
      table.state,
      table.expiresAt,
      table.transactionId,
    ),
    foreignKey({
      name: "tenant_platform_oidc_authentication_transactions_binding_fk",
      columns: [table.tenantId, table.bindingId, table.platformProviderId],
      foreignColumns: [
        tenantPlatformAuthProviderBindings.tenantId,
        tenantPlatformAuthProviderBindings.id,
        tenantPlatformAuthProviderBindings.platformProviderId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_platform_oidc_authentication_transactions_epoch_fk",
      columns: [
        table.tenantId,
        table.accessEpochId,
        table.bindingId,
        table.platformProviderId,
        table.accessSourceId,
      ],
      foreignColumns: [
        tenantPlatformIdentityProviderAccessEpochs.tenantId,
        tenantPlatformIdentityProviderAccessEpochs.id,
        tenantPlatformIdentityProviderAccessEpochs.bindingId,
        tenantPlatformIdentityProviderAccessEpochs.platformProviderId,
        tenantPlatformIdentityProviderAccessEpochs.sourceId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_platform_oidc_authentication_transactions_policy_fk",
      columns: [table.platformProviderId, table.providerKind],
      foreignColumns: [
        platformFederatedProviderPolicies.providerId,
        platformFederatedProviderPolicies.providerKind,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_platform_oidc_authentication_transactions_configuration_fk",
      columns: [table.platformProviderId],
      foreignColumns: [platformOidcProviderConfigurations.providerId],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_platform_oidc_authentication_transactions_keyring_fk",
      columns: [table.verifierKeyVersion],
      foreignColumns: [identityKeyringVersions.keyVersion],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "tenant_platform_oidc_authentication_transactions_id_check",
      sql`octet_length(${table.transactionId}) = 32
        and (uuid_extract_version(${table.operationRunId}) = 7) is true`,
    ),
    check(
      "tenant_platform_oidc_authentication_transactions_digest_check",
      sql`octet_length(${table.operationDigest}) = 32
        and octet_length(${table.receiptDigest}) = 32
        and octet_length(${table.networkDigest}) = 32
        and octet_length(${table.accountDigest}) = 32
        and octet_length(${table.providerDigest}) = 32
        and octet_length(${table.stateDigest}) = 32
        and octet_length(${table.browserDigest}) = 32
        and octet_length(${table.nonceDigest}) = 32
        and octet_length(${table.discoveryDigest}) = 32
        and octet_length(${table.jwksDigest}) = 32`,
    ),
    check(
      "tenant_platform_oidc_authentication_transactions_pin_check",
      sql`${table.providerKind} = 'oidc' and ${table.protocol} = 'oidc'
        and ${table.providerRevision} between 1 and 2147483647
        and ${table.bindingRevision} between 1 and 2147483647
        and ${table.configurationRevision} between 1 and 9007199254740991
        and ${table.securityRevision} between 1 and 9007199254740991
        and ${table.planRevision} between 1 and 9007199254740991
        and ${table.mappingRevision} between 1 and 9007199254740991
        and ${table.authorizationRevision} between 1 and 9007199254740991
        and ${table.assurancePolicyRevision} between 1 and 9007199254740991
        and ${table.clientSecretRevision} between 1 and 9007199254740991
        and ${table.discoveryRevision} between 1 and 9007199254740991
        and ${table.jwksRevision} between 1 and 9007199254740991
        and ${table.verifierKeyVersion} between 1 and 32767
        and octet_length(${table.verifierCiphertext}) between 16 and 4096
        and octet_length(convert_to(${table.clientId}, 'UTF8')) between 1 and 512
        and ${table.tenantRedirectUri} ~ '^https://[^/?#@]+/api/v1/auth/federated/oidc/callback$'
        and char_length(${table.tenantRedirectUri}) between 1 and 4096
        and char_length(${table.postLogoutRedirectUri}) between 1 and 4096
        and cardinality(${table.scopes}) between 1 and 64
        and array_position(${table.scopes}, null) is null
        and char_length(${table.returnPath}) between 1 and 2048
        and left(${table.returnPath}, 1) = '/'
        and ${table.clientId} !~ '[[:cntrl:]]'
        and ${table.tenantRedirectUri} !~ '[[:cntrl:]]'
        and ${table.postLogoutRedirectUri} !~ '[[:cntrl:]]'
        and ${table.returnPath} !~ '[[:cntrl:]]'`,
    ),
    check(
      "tenant_platform_oidc_authentication_transactions_lifecycle_check",
      sql`${table.version} between 1 and 2147483647
        and ${table.expiresAt} between ${table.createdAt} + interval '1 minute'
          and ${table.createdAt} + interval '15 minutes'
        and ((
          ${table.state} = 'pending' and ${table.claimAttemptId} is null
          and ${table.claimedAt} is null and ${table.completedAt} is null
          and ${table.failureReason} is null
        ) or (
          ${table.state} = 'claimed' and octet_length(${table.claimAttemptId}) = 32
          and ${table.claimedAt} is not null and ${table.completedAt} is null
          and ${table.failureReason} is null
        ) or (
          ${table.state} in ('completed', 'failed', 'expired')
          and ${table.completedAt} is not null
          and ${table.completedAt} >= ${table.createdAt}
          and (${table.claimAttemptId} is null) = (${table.claimedAt} is null)
          and (${table.state} <> 'completed'
            or (${table.claimAttemptId} is not null and ${table.failureReason} is null))
          and (${table.state} = 'completed') = (${table.failureReason} is null)
        ))`,
    ),
  ],
).enableRLS();

/** Immutable replay receipt and bounded result for one platform-binding apply. */
export const tenantPlatformOidcAuthenticationApplications = pgTable(
  "tenant_platform_oidc_authentication_applications",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    transactionId: bytea("transaction_id").notNull(),
    operationDigest: bytea("operation_digest").notNull(),
    platformProviderId: uuid("platform_provider_id").notNull(),
    bindingId: uuid("binding_id").notNull(),
    externalIdentityId: uuid("external_identity_id"),
    category: text("category").notNull(),
    primaryKind: text("primary_kind"),
    userId: uuid("user_id").references(() => users.id, {
      onDelete: "restrict",
    }),
    sessionId: uuid("session_id").references(() => authSessions.id, {
      onDelete: "restrict",
    }),
    continuationId: uuid("continuation_id"),
    requestSnapshot: jsonb("request_snapshot")
      .$type<Record<string, unknown>>()
      .notNull(),
    resultSnapshot: jsonb("result_snapshot")
      .$type<Record<string, unknown>>()
      .notNull(),
    appliedAt: timestamp("applied_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
  },
  (table) => [
    unique("tenant_platform_oidc_authentication_applications_operation_key").on(
      table.tenantId,
      table.operationDigest,
    ),
    unique(
      "tenant_platform_oidc_authentication_applications_transaction_key",
    ).on(table.tenantId, table.transactionId),
    foreignKey({
      name: "tenant_platform_oidc_authentication_applications_transaction_fk",
      columns: [
        table.tenantId,
        table.transactionId,
        table.platformProviderId,
        table.bindingId,
      ],
      foreignColumns: [
        tenantPlatformOidcAuthenticationTransactions.tenantId,
        tenantPlatformOidcAuthenticationTransactions.transactionId,
        tenantPlatformOidcAuthenticationTransactions.platformProviderId,
        tenantPlatformOidcAuthenticationTransactions.bindingId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_platform_oidc_authentication_applications_session_fk",
      columns: [
        table.tenantId,
        table.sessionId,
        table.primaryKind,
        table.userId,
      ],
      foreignColumns: [
        authSessionMfaStates.tenantId,
        authSessionMfaStates.sessionId,
        authSessionMfaStates.primaryKind,
        authSessionMfaStates.userId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_platform_oidc_authentication_applications_continuation_fk",
      columns: [table.tenantId, table.continuationId, table.userId],
      foreignColumns: [
        tenantPostPrimaryContinuations.tenantId,
        tenantPostPrimaryContinuations.id,
        tenantPostPrimaryContinuations.userId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_platform_oidc_authentication_applications_identity_fk",
      columns: [
        table.platformProviderId,
        table.externalIdentityId,
        table.userId,
      ],
      foreignColumns: [
        platformFederatedExternalIdentities.platformProviderId,
        platformFederatedExternalIdentities.id,
        platformFederatedExternalIdentities.userId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "tenant_platform_oidc_authentication_applications_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "tenant_platform_oidc_authentication_applications_digest_check",
      sql`octet_length(${table.transactionId}) = 32
        and octet_length(${table.operationDigest}) = 32`,
    ),
    check(
      "tenant_platform_oidc_authentication_applications_result_check",
      sql`${table.category} in ('success', 'identity_collision', 'stale', 'denied')
        and jsonb_typeof(${table.requestSnapshot}) = 'object'
        and pg_column_size(${table.requestSnapshot}) between 2 and 2097152
        and jsonb_typeof(${table.resultSnapshot}) = 'object'
        and pg_column_size(${table.resultSnapshot}) between 2 and 65536
        and ((${table.category} = 'success'
          and ${table.primaryKind} = 'tenant_platform_provider'
          and ${table.userId} is not null and ${table.externalIdentityId} is not null
          and ((${table.sessionId} is null) <> (${table.continuationId} is null)))
        or (${table.category} <> 'success'
          and ${table.primaryKind} is null and ${table.userId} is null
          and ${table.externalIdentityId} is null
          and ${table.sessionId} is null and ${table.continuationId} is null))`,
    ),
  ],
).enableRLS();

/** Exact tenant-to-platform-provider primary provenance for one usable session. */
export const authSessionTenantPlatformFederatedProvenance = pgTable(
  "auth_session_tenant_platform_federated_provenance",
  {
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    sessionId: uuid("session_id").notNull(),
    userId: uuid("user_id").notNull(),
    primaryKind: text("primary_kind")
      .notNull()
      .default("tenant_platform_provider"),
    authenticationMethod: text("authentication_method")
      .notNull()
      .default("oidc"),
    platformProviderId: uuid("platform_provider_id").notNull(),
    bindingId: uuid("binding_id").notNull(),
    accessEpochId: uuid("access_epoch_id").notNull(),
    accessSourceId: uuid("access_source_id").notNull(),
    accessGrantId: uuid("access_grant_id").notNull(),
    membershipId: uuid("membership_id").notNull(),
    externalIdentityId: uuid("external_identity_id").notNull(),
    externalIdentityRevision: bigint("external_identity_revision", {
      mode: "bigint",
    }).notNull(),
    providerRevision: bigint("provider_revision", { mode: "bigint" }).notNull(),
    bindingRevision: bigint("binding_revision", { mode: "bigint" }).notNull(),
    securityRevision: bigint("security_revision", { mode: "bigint" }).notNull(),
    mappingRevision: bigint("mapping_revision", { mode: "bigint" }).notNull(),
    authorizationRevision: bigint("authorization_revision", {
      mode: "bigint",
    }).notNull(),
    subjectAliasKeyVersion: integer("subject_alias_key_version").notNull(),
    trustRuleRevision: bigint("trust_rule_revision", {
      mode: "bigint",
    }).notNull(),
    authenticatedAt: timestamp("authenticated_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
  },
  (table) => [
    primaryKey({
      name: "auth_session_tenant_platform_federated_provenance_pkey",
      columns: [table.tenantId, table.sessionId],
    }),
    unique("auth_session_tenant_platform_federated_provenance_exact_key").on(
      table.tenantId,
      table.sessionId,
      table.userId,
      table.platformProviderId,
      table.bindingId,
      table.externalIdentityId,
    ),
    foreignKey({
      name: "auth_session_tenant_platform_federated_provenance_state_fk",
      columns: [
        table.tenantId,
        table.sessionId,
        table.primaryKind,
        table.userId,
      ],
      foreignColumns: [
        authSessionMfaStates.tenantId,
        authSessionMfaStates.sessionId,
        authSessionMfaStates.primaryKind,
        authSessionMfaStates.userId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "auth_session_tenant_platform_federated_provenance_identity_fk",
      columns: [
        table.platformProviderId,
        table.externalIdentityId,
        table.userId,
      ],
      foreignColumns: [
        platformFederatedExternalIdentities.platformProviderId,
        platformFederatedExternalIdentities.id,
        platformFederatedExternalIdentities.userId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "auth_session_tenant_platform_federated_provenance_binding_fk",
      columns: [table.tenantId, table.bindingId, table.platformProviderId],
      foreignColumns: [
        tenantPlatformAuthProviderBindings.tenantId,
        tenantPlatformAuthProviderBindings.id,
        tenantPlatformAuthProviderBindings.platformProviderId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "auth_session_tenant_platform_federated_provenance_access_grant_fk",
      columns: [
        table.tenantId,
        table.accessGrantId,
        table.platformProviderId,
        table.bindingId,
        table.accessEpochId,
        table.accessSourceId,
        table.externalIdentityId,
        table.membershipId,
        table.userId,
      ],
      foreignColumns: [
        tenantPlatformFederatedProviderAccessGrants.tenantId,
        tenantPlatformFederatedProviderAccessGrants.id,
        tenantPlatformFederatedProviderAccessGrants.platformProviderId,
        tenantPlatformFederatedProviderAccessGrants.bindingId,
        tenantPlatformFederatedProviderAccessGrants.accessEpochId,
        tenantPlatformFederatedProviderAccessGrants.sourceId,
        tenantPlatformFederatedProviderAccessGrants.externalIdentityId,
        tenantPlatformFederatedProviderAccessGrants.membershipId,
        tenantPlatformFederatedProviderAccessGrants.userId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "auth_session_tenant_platform_federated_provenance_value_check",
      sql`${table.primaryKind} = 'tenant_platform_provider'
        and ${table.authenticationMethod} in ('oidc','saml')
        and ${table.externalIdentityRevision} between 1 and 2147483647
        and ${table.providerRevision} between 1 and 2147483647
        and ${table.bindingRevision} between 1 and 2147483647
        and ${table.securityRevision} between 1 and 9007199254740991
        and ${table.mappingRevision} between 1 and 9007199254740991
        and ${table.authorizationRevision} between 1 and 9007199254740991
        and ${table.subjectAliasKeyVersion} between 1 and 32767
        and ${table.trustRuleRevision} between 1 and 9007199254740991`,
    ),
  ],
).enableRLS();

/** Provider assurance evidence cannot use tenant-provider foreign keys. */
export const authSessionTenantPlatformFederatedEvidence = pgTable(
  "auth_session_tenant_platform_federated_evidence",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id").notNull(),
    sessionId: uuid("session_id").notNull(),
    userId: uuid("user_id").notNull(),
    platformProviderId: uuid("platform_provider_id").notNull(),
    bindingId: uuid("binding_id").notNull(),
    externalIdentityId: uuid("external_identity_id").notNull(),
    level: text("level").notNull(),
    authenticatedAt: timestamp("authenticated_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    expiresAt: timestamp("expires_at", { withTimezone: true, mode: "date" }),
    trustRuleRevision: bigint("trust_rule_revision", {
      mode: "bigint",
    }).notNull(),
  },
  (table) => [
    unique("auth_session_tenant_platform_federated_evidence_exact_key").on(
      table.tenantId,
      table.sessionId,
      table.id,
    ),
    foreignKey({
      name: "auth_session_tenant_platform_federated_evidence_provenance_fk",
      columns: [
        table.tenantId,
        table.sessionId,
        table.userId,
        table.platformProviderId,
        table.bindingId,
        table.externalIdentityId,
      ],
      foreignColumns: [
        authSessionTenantPlatformFederatedProvenance.tenantId,
        authSessionTenantPlatformFederatedProvenance.sessionId,
        authSessionTenantPlatformFederatedProvenance.userId,
        authSessionTenantPlatformFederatedProvenance.platformProviderId,
        authSessionTenantPlatformFederatedProvenance.bindingId,
        authSessionTenantPlatformFederatedProvenance.externalIdentityId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "auth_session_tenant_platform_federated_evidence_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "auth_session_tenant_platform_federated_evidence_value_check",
      sql`${table.level} in ('primary','mfa','phishing_resistant')
        and ${table.trustRuleRevision} between 1 and 9007199254740991
        and (${table.expiresAt} is null or ${table.expiresAt} > ${table.authenticatedAt})`,
    ),
  ],
).enableRLS();

/** Immutable platform-provider baseline copied into an MFA authority anchor. */
export const tenantMfaAuthorityPlatformFederatedEvidence = pgTable(
  "tenant_mfa_authority_platform_federated_evidence",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id").notNull(),
    anchorId: uuid("anchor_id").notNull(),
    userId: uuid("user_id").notNull(),
    platformProviderId: uuid("platform_provider_id").notNull(),
    bindingId: uuid("binding_id").notNull(),
    externalIdentityId: uuid("external_identity_id").notNull(),
    level: text("level").notNull(),
    authenticatedAt: timestamp("authenticated_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    expiresAt: timestamp("expires_at", { withTimezone: true, mode: "date" }),
    trustRuleRevision: bigint("trust_rule_revision", {
      mode: "bigint",
    }).notNull(),
  },
  (table) => [
    unique("tenant_mfa_authority_platform_federated_evidence_exact_key").on(
      table.tenantId,
      table.anchorId,
      table.id,
    ),
    index("tenant_mfa_authority_platform_federated_evidence_anchor_idx").on(
      table.tenantId,
      table.anchorId,
      table.authenticatedAt,
      table.id,
    ),
    foreignKey({
      name: "tenant_mfa_authority_platform_federated_evidence_anchor_fk",
      columns: [table.tenantId, table.anchorId],
      foreignColumns: [
        tenantMfaAuthorityAnchors.tenantId,
        tenantMfaAuthorityAnchors.id,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_mfa_authority_platform_federated_evidence_identity_fk",
      columns: [
        table.platformProviderId,
        table.externalIdentityId,
        table.userId,
      ],
      foreignColumns: [
        platformFederatedExternalIdentities.platformProviderId,
        platformFederatedExternalIdentities.id,
        platformFederatedExternalIdentities.userId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_mfa_authority_platform_federated_evidence_binding_fk",
      columns: [table.tenantId, table.bindingId, table.platformProviderId],
      foreignColumns: [
        tenantPlatformAuthProviderBindings.tenantId,
        tenantPlatformAuthProviderBindings.id,
        tenantPlatformAuthProviderBindings.platformProviderId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "tenant_mfa_authority_platform_federated_evidence_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "tenant_mfa_authority_platform_federated_evidence_value_check",
      sql`${table.level} in ('primary','mfa','phishing_resistant')
        and ${table.trustRuleRevision} between 1 and 9007199254740991
        and (${table.expiresAt} is null or ${table.expiresAt} > ${table.authenticatedAt})`,
    ),
  ],
).enableRLS();

/** Platform-provider primary evidence retained while a step-up is pending. */
export const tenantPostPrimaryPlatformFederatedEvidence = pgTable(
  "tenant_post_primary_platform_federated_evidence",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id").notNull(),
    continuationId: uuid("continuation_id").notNull(),
    userId: uuid("user_id").notNull(),
    platformProviderId: uuid("platform_provider_id").notNull(),
    bindingId: uuid("binding_id").notNull(),
    externalIdentityId: uuid("external_identity_id").notNull(),
    level: text("level").notNull(),
    authenticatedAt: timestamp("authenticated_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    expiresAt: timestamp("expires_at", { withTimezone: true, mode: "date" }),
    trustRuleRevision: bigint("trust_rule_revision", {
      mode: "bigint",
    }).notNull(),
  },
  (table) => [
    unique("tenant_post_primary_platform_federated_evidence_exact_key").on(
      table.tenantId,
      table.continuationId,
      table.id,
    ),
    foreignKey({
      name: "tenant_post_primary_platform_federated_evidence_continuation_fk",
      columns: [table.tenantId, table.continuationId, table.userId],
      foreignColumns: [
        tenantPostPrimaryContinuations.tenantId,
        tenantPostPrimaryContinuations.id,
        tenantPostPrimaryContinuations.userId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_post_primary_platform_federated_evidence_identity_fk",
      columns: [
        table.platformProviderId,
        table.externalIdentityId,
        table.userId,
      ],
      foreignColumns: [
        platformFederatedExternalIdentities.platformProviderId,
        platformFederatedExternalIdentities.id,
        platformFederatedExternalIdentities.userId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "tenant_post_primary_platform_federated_evidence_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "tenant_post_primary_platform_federated_evidence_value_check",
      sql`${table.level} in ('primary','mfa','phishing_resistant')
        and ${table.trustRuleRevision} between 1 and 9007199254740991
        and (${table.expiresAt} is null or ${table.expiresAt} > ${table.authenticatedAt})`,
    ),
  ],
).enableRLS();

/**
 * Exact immutable authority carried by a platform-provider continuation.
 * Revalidation continuations additionally pin their source rotation state.
 */
export const tenantPostPrimaryPlatformFederatedProvenance = pgTable(
  "tenant_post_primary_platform_federated_provenance",
  {
    tenantId: uuid("tenant_id").notNull(),
    continuationId: uuid("continuation_id").notNull(),
    userId: uuid("user_id").notNull(),
    origin: text("origin").notNull(),
    platformProviderId: uuid("platform_provider_id").notNull(),
    bindingId: uuid("binding_id").notNull(),
    accessEpochId: uuid("access_epoch_id").notNull(),
    accessSourceId: uuid("access_source_id").notNull(),
    accessGrantId: uuid("access_grant_id").notNull(),
    membershipId: uuid("membership_id").notNull(),
    externalIdentityId: uuid("external_identity_id").notNull(),
    externalIdentityRevision: bigint("external_identity_revision", {
      mode: "bigint",
    }).notNull(),
    providerRevision: bigint("provider_revision", { mode: "bigint" }).notNull(),
    bindingRevision: bigint("binding_revision", { mode: "bigint" }).notNull(),
    securityRevision: bigint("security_revision", { mode: "bigint" }).notNull(),
    mappingRevision: bigint("mapping_revision", { mode: "bigint" }).notNull(),
    authorizationRevision: bigint("authorization_revision", {
      mode: "bigint",
    }).notNull(),
    subjectAliasKeyVersion: integer("subject_alias_key_version").notNull(),
    trustRuleRevision: bigint("trust_rule_revision", {
      mode: "bigint",
    }).notNull(),
    authenticatedAt: timestamp("authenticated_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    sourceSessionId: uuid("source_session_id").references(
      () => authSessions.id,
      {
        onDelete: "restrict",
      },
    ),
    sourceSessionFamilyId: uuid("source_session_family_id"),
    sourceSessionVersion: bigint("source_session_version", { mode: "bigint" }),
    sourceAbsoluteExpiresAt: timestamp("source_absolute_expires_at", {
      withTimezone: true,
      mode: "date",
    }),
  },
  (table) => [
    primaryKey({
      name: "tenant_post_primary_platform_federated_provenance_pkey",
      columns: [table.tenantId, table.continuationId],
    }),
    unique("tenant_post_primary_platform_federated_provenance_exact_key").on(
      table.tenantId,
      table.continuationId,
      table.userId,
      table.platformProviderId,
      table.bindingId,
      table.externalIdentityId,
    ),
    foreignKey({
      name: "tenant_post_primary_platform_federated_provenance_continuation_fk",
      columns: [
        table.tenantId,
        table.continuationId,
        table.userId,
        table.platformProviderId,
        table.bindingId,
        table.externalIdentityId,
      ],
      foreignColumns: [
        tenantPostPrimaryContinuations.tenantId,
        tenantPostPrimaryContinuations.id,
        tenantPostPrimaryContinuations.userId,
        tenantPostPrimaryContinuations.platformProviderId,
        tenantPostPrimaryContinuations.bindingId,
        tenantPostPrimaryContinuations.externalIdentityId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_post_primary_platform_federated_provenance_identity_fk",
      columns: [
        table.platformProviderId,
        table.externalIdentityId,
        table.userId,
      ],
      foreignColumns: [
        platformFederatedExternalIdentities.platformProviderId,
        platformFederatedExternalIdentities.id,
        platformFederatedExternalIdentities.userId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_post_primary_platform_federated_provenance_binding_fk",
      columns: [table.tenantId, table.bindingId, table.platformProviderId],
      foreignColumns: [
        tenantPlatformAuthProviderBindings.tenantId,
        tenantPlatformAuthProviderBindings.id,
        tenantPlatformAuthProviderBindings.platformProviderId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_post_primary_platform_federated_provenance_access_grant_fk",
      columns: [
        table.tenantId,
        table.accessGrantId,
        table.platformProviderId,
        table.bindingId,
        table.accessEpochId,
        table.accessSourceId,
        table.externalIdentityId,
        table.membershipId,
        table.userId,
      ],
      foreignColumns: [
        tenantPlatformFederatedProviderAccessGrants.tenantId,
        tenantPlatformFederatedProviderAccessGrants.id,
        tenantPlatformFederatedProviderAccessGrants.platformProviderId,
        tenantPlatformFederatedProviderAccessGrants.bindingId,
        tenantPlatformFederatedProviderAccessGrants.accessEpochId,
        tenantPlatformFederatedProviderAccessGrants.sourceId,
        tenantPlatformFederatedProviderAccessGrants.externalIdentityId,
        tenantPlatformFederatedProviderAccessGrants.membershipId,
        tenantPlatformFederatedProviderAccessGrants.userId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "tenant_post_primary_platform_federated_provenance_value_check",
      sql`${table.origin} in ('initial_login','session_revalidation')
        and ${table.externalIdentityRevision} between 1 and 2147483647
        and ${table.providerRevision} between 1 and 2147483647
        and ${table.bindingRevision} between 1 and 2147483647
        and ${table.securityRevision} between 1 and 9007199254740991
        and ${table.mappingRevision} between 1 and 9007199254740991
        and ${table.authorizationRevision} between 1 and 9007199254740991
        and ${table.subjectAliasKeyVersion} between 1 and 32767
        and ${table.trustRuleRevision} between 1 and 9007199254740991
        and ((${table.origin} = 'initial_login'
          and ${table.sourceSessionId} is null
          and ${table.sourceSessionFamilyId} is null
          and ${table.sourceSessionVersion} is null
          and ${table.sourceAbsoluteExpiresAt} is null)
        or (${table.origin} = 'session_revalidation'
          and ${table.sourceSessionId} is not null
          and ${table.sourceSessionFamilyId} is not null
          and (uuid_extract_version(${table.sourceSessionFamilyId}) = 7) is true
          and ${table.sourceSessionVersion} between 1 and 9007199254740991
          and ${table.sourceAbsoluteExpiresAt} > ${table.authenticatedAt}))`,
    ),
  ],
).enableRLS();

/** Exact CAS replay ledger for platform-binding session revalidation. */
export const tenantPlatformFederatedSessionRevalidationCommands = pgTable(
  "tenant_platform_federated_session_revalidation_commands",
  {
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    sessionId: uuid("session_id").notNull(),
    expectedVersion: bigint("expected_version", { mode: "bigint" }).notNull(),
    requestDigest: bytea("request_digest").notNull(),
    decision: text("decision").notNull(),
    resultSnapshot: jsonb("result_snapshot")
      .$type<Record<string, unknown>>()
      .notNull(),
    appliedAt: timestamp("applied_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
  },
  (table) => [
    primaryKey({
      name: "tenant_platform_federated_session_revalidation_commands_pkey",
      columns: [table.tenantId, table.sessionId, table.expectedVersion],
    }),
    foreignKey({
      name: "tenant_platform_federated_session_revalidation_commands_session_fk",
      columns: [table.tenantId, table.sessionId],
      foreignColumns: [
        authSessionTenantPlatformFederatedProvenance.tenantId,
        authSessionTenantPlatformFederatedProvenance.sessionId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "tenant_platform_federated_session_revalidation_commands_value_check",
      sql`${table.expectedVersion} between 1 and 2147483647
        and octet_length(${table.requestDigest}) = 32
        and ${table.decision} in ('usable', 'rotate', 'step_up', 'revoke', 'deny')
        and jsonb_typeof(${table.resultSnapshot}) = 'object'
        and pg_column_size(${table.resultSnapshot}) between 2 and 65536`,
    ),
  ],
).enableRLS();
