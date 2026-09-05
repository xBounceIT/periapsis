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

import { authSessions, totpCredentials } from "./authentication.js";
import { bytea } from "./binary.js";
import { authProviderKind } from "./enums.js";
import {
  platformAuthProviders,
  platformFederatedProviderPolicies,
  platformSamlProviderConfigurations,
} from "./identity-platform-federation.js";
import {
  platformFederatedExternalIdentities,
  platformFederatedExternalIdentityAliases,
} from "./identity-platform-runtime.js";
import { identityKeyringVersions } from "./identity-providers.js";
import { mfaPolicyRevisions } from "./identity-mfa.js";
import { users } from "./identity.js";
import { tenants } from "./tenancy.js";

/** Independent, prelinked-only direct platform SAML login lifecycle. */
export const platformSamlLoginPolicies = pgTable(
  "platform_saml_login_policies",
  {
    providerId: uuid("provider_id").primaryKey(),
    providerKind: authProviderKind("provider_kind").notNull().default("saml"),
    accountMode: text("account_mode").notNull().default("disabled"),
    enabled: boolean("enabled").notNull().default(false),
    revision: bigint("revision", { mode: "bigint" })
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
    unique("platform_saml_login_policies_kind_key").on(
      table.providerId,
      table.providerKind,
    ),
    foreignKey({
      name: "platform_saml_login_policies_provider_fk",
      columns: [table.providerId, table.providerKind],
      foreignColumns: [platformAuthProviders.id, platformAuthProviders.kind],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "platform_saml_login_policies_runtime_policy_fk",
      columns: [table.providerId, table.providerKind],
      foreignColumns: [
        platformFederatedProviderPolicies.providerId,
        platformFederatedProviderPolicies.providerKind,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "platform_saml_login_policies_configuration_fk",
      columns: [table.providerId],
      foreignColumns: [platformSamlProviderConfigurations.providerId],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "platform_saml_login_policies_value_check",
      sql`${table.providerKind} = 'saml'
        and ${table.accountMode} in ('disabled','existing_identity')
        and (not ${table.enabled} or ${table.accountMode} = 'existing_identity')
        and ${table.revision} between 1 and 9007199254740991
        and ${table.updatedAt} >= ${table.createdAt}`,
    ),
  ],
).enableRLS();

/** Browser-bound direct platform SAML transaction; never shared with OIDC. */
export const platformSamlAuthenticationTransactions = pgTable(
  "platform_saml_authentication_transactions",
  {
    transactionId: bytea("transaction_id").primaryKey(),
    platformProviderId: uuid("platform_provider_id").notNull(),
    providerKind: authProviderKind("provider_kind").notNull().default("saml"),
    protocol: text("protocol").notNull().default("saml"),
    operationRunId: uuid("operation_run_id").notNull(),
    operationDigest: bytea("operation_digest").notNull(),
    receiptDigest: bytea("receipt_digest").notNull(),
    networkDigest: bytea("network_digest").notNull(),
    accountDigest: bytea("account_digest").notNull(),
    providerDigest: bytea("provider_digest").notNull(),
    relayStateDigest: bytea("relay_state_digest").notNull(),
    browserDigest: bytea("browser_digest").notNull(),
    requestId: text("request_id").notNull(),
    providerRevision: bigint("provider_revision", { mode: "bigint" }).notNull(),
    loginPolicyRevision: bigint("login_policy_revision", {
      mode: "bigint",
    }).notNull(),
    configurationRevision: bigint("configuration_revision", {
      mode: "bigint",
    }).notNull(),
    securityRevision: bigint("security_revision", { mode: "bigint" }).notNull(),
    planRevision: bigint("plan_revision", { mode: "bigint" }).notNull(),
    assurancePolicyRevision: bigint("assurance_policy_revision", {
      mode: "bigint",
    }).notNull(),
    metadataRevision: bigint("metadata_revision", { mode: "bigint" }).notNull(),
    metadataDigest: bytea("metadata_digest").notNull(),
    spKeyRevision: bigint("sp_key_revision", { mode: "bigint" }).notNull(),
    configurationDigest: bytea("configuration_digest").notNull(),
    platformFloorPolicyId: uuid("platform_floor_policy_id").notNull(),
    platformFloorPolicyRevision: bigint("platform_floor_policy_revision", {
      mode: "bigint",
    }).notNull(),
    returnPath: text("return_path").notNull(),
    state: text("state").notNull().default("pending"),
    version: bigint("version", { mode: "bigint" })
      .notNull()
      .default(sql`1`),
    createdAt: timestamp("created_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    expiresAt: timestamp("expires_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    completedAt: timestamp("completed_at", {
      withTimezone: true,
      mode: "date",
    }),
    failureReason: text("failure_reason"),
  },
  (table) => [
    unique("platform_saml_auth_transactions_operation_key").on(
      table.operationRunId,
    ),
    unique("platform_saml_auth_transactions_receipt_key").on(
      table.receiptDigest,
    ),
    unique("platform_saml_auth_transactions_relay_key").on(
      table.relayStateDigest,
    ),
    unique("platform_saml_auth_transactions_request_key").on(
      table.platformProviderId,
      table.requestId,
    ),
    unique("platform_saml_auth_transactions_exact_key").on(
      table.transactionId,
      table.platformProviderId,
    ),
    uniqueIndex("platform_saml_auth_transactions_live_browser_key")
      .on(table.browserDigest)
      .where(sql`${table.state} = 'pending'`),
    index("platform_saml_auth_transactions_expiry_idx").on(
      table.state,
      table.expiresAt,
      table.transactionId,
    ),
    foreignKey({
      name: "platform_saml_auth_transactions_provider_fk",
      columns: [table.platformProviderId, table.providerKind],
      foreignColumns: [platformAuthProviders.id, platformAuthProviders.kind],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "platform_saml_auth_transactions_policy_fk",
      columns: [table.platformProviderId, table.providerKind],
      foreignColumns: [
        platformFederatedProviderPolicies.providerId,
        platformFederatedProviderPolicies.providerKind,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "platform_saml_auth_transactions_login_policy_fk",
      columns: [table.platformProviderId, table.providerKind],
      foreignColumns: [
        platformSamlLoginPolicies.providerId,
        platformSamlLoginPolicies.providerKind,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "platform_saml_auth_transactions_configuration_fk",
      columns: [table.platformProviderId],
      foreignColumns: [platformSamlProviderConfigurations.providerId],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "platform_saml_auth_transactions_platform_floor_fk",
      columns: [table.platformFloorPolicyId, table.platformFloorPolicyRevision],
      foreignColumns: [mfaPolicyRevisions.id, mfaPolicyRevisions.revision],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "platform_saml_auth_transactions_digest_check",
      sql`octet_length(${table.transactionId}) = 32
        and (uuid_extract_version(${table.operationRunId}) = 7) is true
        and octet_length(${table.operationDigest}) = 32
        and octet_length(${table.receiptDigest}) = 32
        and octet_length(${table.networkDigest}) = 32
        and octet_length(${table.accountDigest}) = 32
        and octet_length(${table.providerDigest}) = 32
        and octet_length(${table.relayStateDigest}) = 32
        and octet_length(${table.browserDigest}) = 32
        and octet_length(${table.metadataDigest}) = 32
        and octet_length(${table.configurationDigest}) = 32`,
    ),
    check(
      "platform_saml_auth_transactions_pin_check",
      sql`${table.providerKind} = 'saml' and ${table.protocol} = 'saml'
        and ${table.providerRevision} between 1 and 2147483647
        and ${table.loginPolicyRevision} between 1 and 9007199254740991
        and ${table.configurationRevision} between 1 and 9007199254740991
        and ${table.securityRevision} between 1 and 9007199254740991
        and ${table.planRevision} between 1 and 9007199254740991
        and ${table.assurancePolicyRevision} between 1 and 9007199254740991
        and ${table.metadataRevision} between 1 and 9007199254740991
        and ${table.spKeyRevision} between 1 and 9007199254740991
        and (uuid_extract_version(${table.platformFloorPolicyId}) = 7) is true
        and ${table.platformFloorPolicyRevision} between 1 and 9007199254740991
        and char_length(${table.requestId}) between 1 and 1024
        and ${table.requestId} !~ '[[:cntrl:]]'
        and ${table.returnPath} ~ '^/[^[:cntrl:]]*$'
        and left(${table.returnPath},2) <> '//'`,
    ),
    check(
      "platform_saml_auth_transactions_lifecycle_check",
      sql`${table.version} between 1 and 2147483647
        and ${table.expiresAt} between ${table.createdAt} + interval '1 minute'
          and ${table.createdAt} + interval '15 minutes'
        and ((${table.state} = 'pending' and ${table.version} = 1
          and ${table.completedAt} is null and ${table.failureReason} is null)
        or (${table.state} in ('completed','failed','expired')
          and ${table.version} >= 2 and ${table.completedAt} >= ${table.createdAt}
          and (${table.state} = 'completed') = (${table.failureReason} is null)))`,
    ),
  ],
).enableRLS();

/** One-use post-primary capability with an exact direct-platform-SAML authority. */
export const platformSamlPostPrimaryContinuations = pgTable(
  "platform_saml_post_primary_continuations",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    userId: uuid("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "restrict" }),
    receiptDigest: bytea("receipt_digest").notNull(),
    authority: text("authority").notNull().default("direct_platform_saml"),
    authenticationMethod: text("authentication_method")
      .notNull()
      .default("saml"),
    action: text("action").notNull(),
    audience: text("audience").notNull(),
    platformProviderId: uuid("platform_provider_id").notNull(),
    externalIdentityId: uuid("external_identity_id").notNull(),
    providerRevision: bigint("provider_revision", { mode: "bigint" }).notNull(),
    loginPolicyRevision: bigint("login_policy_revision", {
      mode: "bigint",
    }).notNull(),
    configurationRevision: bigint("configuration_revision", {
      mode: "bigint",
    }).notNull(),
    securityRevision: bigint("security_revision", { mode: "bigint" }).notNull(),
    planRevision: bigint("plan_revision", { mode: "bigint" }).notNull(),
    assurancePolicyRevision: bigint("assurance_policy_revision", {
      mode: "bigint",
    }).notNull(),
    metadataRevision: bigint("metadata_revision", { mode: "bigint" }).notNull(),
    metadataDigest: bytea("metadata_digest").notNull(),
    spKeyRevision: bigint("sp_key_revision", { mode: "bigint" }).notNull(),
    configurationDigest: bytea("configuration_digest").notNull(),
    userAuthenticationRevision: bigint("user_authentication_revision", {
      mode: "bigint",
    }).notNull(),
    identityVersion: bigint("identity_version", { mode: "bigint" }).notNull(),
    aliasKeyVersion: integer("alias_key_version").notNull(),
    platformAuthorityId: uuid("platform_authority_id").notNull(),
    platformAuthorityRevision: bigint("platform_authority_revision", {
      mode: "bigint",
    }).notNull(),
    platformFloorPolicyId: uuid("platform_floor_policy_id").notNull(),
    platformFloorPolicyRevision: bigint("platform_floor_policy_revision", {
      mode: "bigint",
    }).notNull(),
    selectedTotpCredentialId: uuid("selected_totp_credential_id").notNull(),
    selectedTotpSecurityRevision: bigint("selected_totp_security_revision", {
      mode: "bigint",
    }).notNull(),
    trustRuleId: uuid("trust_rule_id"),
    trustRuleRevision: bigint("trust_rule_revision", { mode: "bigint" }),
    origin: text("origin").notNull().default("initial_login"),
    sourceSessionId: uuid("source_session_id"),
    sourceSessionFamilyId: uuid("source_session_family_id"),
    sourceSessionVersion: bigint("source_session_version", { mode: "bigint" }),
    sourceAbsoluteExpiresAt: timestamp("source_absolute_expires_at", {
      withTimezone: true,
      mode: "date",
    }),
    state: text("state").notNull().default("pending"),
    version: bigint("version", { mode: "bigint" })
      .notNull()
      .default(sql`1`),
    createdAt: timestamp("created_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    expiresAt: timestamp("expires_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    consumedAt: timestamp("consumed_at", { withTimezone: true, mode: "date" }),
    revokedAt: timestamp("revoked_at", { withTimezone: true, mode: "date" }),
    revokeReason: text("revoke_reason"),
  },
  (table) => [
    unique("platform_saml_post_primary_continuations_receipt_key").on(
      table.receiptDigest,
    ),
    unique("platform_saml_post_primary_continuations_user_key").on(
      table.id,
      table.userId,
    ),
    unique("platform_saml_post_primary_continuations_exact_key").on(
      table.id,
      table.userId,
      table.platformProviderId,
      table.externalIdentityId,
    ),
    index("platform_saml_post_primary_continuations_pending_idx")
      .on(table.userId, table.expiresAt, table.id)
      .where(sql`${table.state} = 'pending'`),
    foreignKey({
      name: "platform_saml_post_primary_continuations_identity_fk",
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
      name: "platform_saml_post_primary_continuations_source_session_fk",
      columns: [table.sourceSessionId],
      foreignColumns: [authSessions.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "platform_saml_post_primary_continuations_floor_fk",
      columns: [table.platformFloorPolicyId, table.platformFloorPolicyRevision],
      foreignColumns: [mfaPolicyRevisions.id, mfaPolicyRevisions.revision],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "platform_saml_post_primary_continuations_totp_fk",
      columns: [table.selectedTotpCredentialId, table.userId],
      foreignColumns: [totpCredentials.id, totpCredentials.userId],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "platform_saml_post_primary_continuations_value_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true
        and octet_length(${table.receiptDigest}) = 32
        and ${table.authority} = 'direct_platform_saml'
        and ${table.authenticationMethod} = 'saml'
        and ${table.providerRevision} between 1 and 2147483647
        and ${table.loginPolicyRevision} between 1 and 9007199254740991
        and ${table.configurationRevision} between 1 and 9007199254740991
        and ${table.securityRevision} between 1 and 9007199254740991
        and ${table.planRevision} between 1 and 9007199254740991
        and ${table.assurancePolicyRevision} between 1 and 9007199254740991
        and ${table.metadataRevision} between 1 and 9007199254740991
        and octet_length(${table.metadataDigest}) = 32
        and ${table.spKeyRevision} between 1 and 9007199254740991
        and octet_length(${table.configurationDigest}) = 32
        and ${table.userAuthenticationRevision} between 1 and 9007199254740991
        and ${table.identityVersion} between 1 and 2147483647
        and ${table.aliasKeyVersion} between 1 and 32767
        and (uuid_extract_version(${table.platformAuthorityId}) = 7) is true
        and ${table.platformAuthorityRevision} between 1 and 9007199254740991
        and (uuid_extract_version(${table.platformFloorPolicyId}) = 7) is true
        and ${table.platformFloorPolicyRevision} between 1 and 9007199254740991
        and (uuid_extract_version(${table.selectedTotpCredentialId}) = 7) is true
        and ${table.selectedTotpSecurityRevision} between 1 and 9007199254740991
        and ((${table.trustRuleId} is null and ${table.trustRuleRevision} is null)
          or ((uuid_extract_version(${table.trustRuleId}) = 7) is true
            and ${table.trustRuleRevision} between 1 and 9007199254740991))
        and ((${table.origin} = 'initial_login'
          and ${table.sourceSessionId} is null and ${table.sourceSessionFamilyId} is null
          and ${table.sourceSessionVersion} is null and ${table.sourceAbsoluteExpiresAt} is null)
        or (${table.origin} = 'session_revalidation'
          and (uuid_extract_version(${table.sourceSessionId}) = 7) is true
          and (uuid_extract_version(${table.sourceSessionFamilyId}) = 7) is true
          and ${table.sourceSessionId} <> ${table.sourceSessionFamilyId}
          and ${table.sourceSessionVersion} between 1 and 2147483647
          and ${table.sourceAbsoluteExpiresAt} > ${table.createdAt}))
        and btrim(${table.action}) = ${table.action}
        and char_length(${table.action}) between 1 and 256
        and ${table.action} !~ '[[:cntrl:]]'
        and btrim(${table.audience}) = ${table.audience}
        and char_length(${table.audience}) between 1 and 256
        and ${table.audience} !~ '[[:cntrl:]]'`,
    ),
    check(
      "platform_saml_post_primary_continuations_lifecycle_check",
      sql`${table.expiresAt} > ${table.createdAt}
        and ((${table.state} = 'pending' and ${table.version} = 1
          and ${table.consumedAt} is null and ${table.revokedAt} is null and ${table.revokeReason} is null)
        or (${table.state} = 'consumed' and ${table.version} >= 2
          and ${table.consumedAt} between ${table.createdAt} and ${table.expiresAt}
          and ${table.revokedAt} is null and ${table.revokeReason} is null)
        or (${table.state} in ('revoked','expired') and ${table.version} >= 2
          and ${table.consumedAt} is null and ${table.revokedAt} >= ${table.createdAt}
          and btrim(${table.revokeReason}) <> '' and char_length(${table.revokeReason}) <= 500
          and ${table.revokeReason} !~ '[[:cntrl:]]'))`,
    ),
  ],
).enableRLS();

export const platformSamlPostPrimaryContinuationEvidence = pgTable(
  "platform_saml_post_primary_continuation_evidence",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    continuationId: uuid("continuation_id").notNull(),
    userId: uuid("user_id").notNull(),
    kind: text("kind").notNull(),
    level: text("level").notNull(),
    platformProviderId: uuid("platform_provider_id"),
    externalIdentityId: uuid("external_identity_id"),
    totpCredentialId: uuid("totp_credential_id"),
    factorRevision: bigint("factor_revision", { mode: "bigint" }),
    trustRuleId: uuid("trust_rule_id"),
    trustRuleRevision: bigint("trust_rule_revision", { mode: "bigint" }),
    authenticatedAt: timestamp("authenticated_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    expiresAt: timestamp("expires_at", { withTimezone: true, mode: "date" }),
  },
  (table) => [
    unique("platform_saml_post_primary_continuation_evidence_key").on(
      table.continuationId,
      table.id,
    ),
    foreignKey({
      name: "platform_saml_post_primary_continuation_evidence_parent_fk",
      columns: [table.continuationId, table.userId],
      foreignColumns: [
        platformSamlPostPrimaryContinuations.id,
        platformSamlPostPrimaryContinuations.userId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "platform_saml_post_primary_continuation_evidence_identity_fk",
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
      name: "platform_saml_post_primary_continuation_evidence_totp_fk",
      columns: [table.totpCredentialId, table.userId],
      foreignColumns: [totpCredentials.id, totpCredentials.userId],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "platform_saml_post_primary_continuation_evidence_value_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true
        and ${table.level} in ('primary','mfa','phishing_resistant')
        and (${table.expiresAt} is null or ${table.expiresAt} > ${table.authenticatedAt})
        and ((${table.kind} = 'platform_provider' and ${table.platformProviderId} is not null
          and ${table.externalIdentityId} is not null and ${table.totpCredentialId} is null
          and ${table.factorRevision} is null)
        or (${table.kind} = 'totp' and ${table.level} = 'mfa'
          and ${table.platformProviderId} is null and ${table.externalIdentityId} is null
          and ${table.totpCredentialId} is not null
          and ${table.factorRevision} between 1 and 9007199254740991
          and ${table.trustRuleId} is null and ${table.trustRuleRevision} is null))`,
    ),
  ],
).enableRLS();

export const platformSamlPostPrimaryContinuationPolicyPins = pgTable(
  "platform_saml_post_primary_continuation_policy_pins",
  {
    continuationId: uuid("continuation_id").notNull(),
    policyKind: text("policy_kind").notNull(),
    policyId: uuid("policy_id").notNull(),
    policyRevision: bigint("policy_revision", { mode: "bigint" }).notNull(),
  },
  (table) => [
    primaryKey({
      name: "platform_saml_post_primary_continuation_policy_pins_pkey",
      columns: [table.continuationId, table.policyKind, table.policyId],
    }),
    foreignKey({
      name: "platform_saml_post_primary_continuation_policy_pins_parent_fk",
      columns: [table.continuationId],
      foreignColumns: [platformSamlPostPrimaryContinuations.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "platform_saml_post_primary_continuation_policy_pins_value_check",
      sql`${table.policyKind} in ('login','assurance','platform_floor')
        and ${table.policyRevision} between 1 and 9007199254740991`,
    ),
  ],
).enableRLS();

export const platformSamlPostPrimaryTotpChallenges = pgTable(
  "platform_saml_post_primary_totp_challenges",
  {
    id: bytea("id").primaryKey(),
    continuationId: uuid("continuation_id").notNull(),
    userId: uuid("user_id").notNull(),
    totpCredentialId: uuid("totp_credential_id").notNull(),
    browserDigest: bytea("browser_digest").notNull(),
    expectedContinuationVersion: bigint("expected_continuation_version", {
      mode: "bigint",
    }).notNull(),
    userAuthenticationRevision: bigint("user_authentication_revision", {
      mode: "bigint",
    }).notNull(),
    totpSecurityRevision: bigint("totp_security_revision", {
      mode: "bigint",
    }).notNull(),
    failureCount: integer("failure_count").notNull().default(0),
    state: text("state").notNull().default("pending"),
    version: bigint("version", { mode: "bigint" })
      .notNull()
      .default(sql`1`),
    completionRequestDigest: bytea("completion_request_digest"),
    completionRequestSnapshot: jsonb("completion_request_snapshot").$type<
      Record<string, unknown>
    >(),
    resultSnapshot: jsonb("result_snapshot").$type<Record<string, unknown>>(),
    createdAt: timestamp("created_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    expiresAt: timestamp("expires_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    completedAt: timestamp("completed_at", {
      withTimezone: true,
      mode: "date",
    }),
    abandonedAt: timestamp("abandoned_at", {
      withTimezone: true,
      mode: "date",
    }),
    cleanupReason: text("cleanup_reason"),
    cleanedUpAt: timestamp("cleaned_up_at", {
      withTimezone: true,
      mode: "date",
    }),
  },
  (table) => [
    uniqueIndex(
      "platform_saml_post_primary_totp_challenges_live_continuation_key",
    )
      .on(table.continuationId)
      .where(sql`${table.state} = 'pending'`),
    index("platform_saml_post_primary_totp_challenges_expiry_idx")
      .on(table.expiresAt, table.id)
      .where(sql`${table.state} = 'pending'`),
    foreignKey({
      name: "platform_saml_post_primary_totp_challenges_parent_fk",
      columns: [table.continuationId, table.userId],
      foreignColumns: [
        platformSamlPostPrimaryContinuations.id,
        platformSamlPostPrimaryContinuations.userId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "platform_saml_post_primary_totp_challenges_factor_fk",
      columns: [table.totpCredentialId, table.userId],
      foreignColumns: [totpCredentials.id, totpCredentials.userId],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "platform_saml_post_primary_totp_challenges_value_check",
      sql`octet_length(${table.id}) = 32 and octet_length(${table.browserDigest}) = 32
        and ${table.expectedContinuationVersion} between 1 and 2147483647
        and ${table.userAuthenticationRevision} between 1 and 9007199254740991
        and ${table.totpSecurityRevision} between 1 and 9007199254740991
        and ${table.failureCount} between 0 and 5
        and ${table.version} between 1 and 2147483647
        and ${table.expiresAt} between ${table.createdAt} + interval '1 minute'
          and ${table.createdAt} + interval '10 minutes'
        and ((${table.state} = 'pending' and ${table.completedAt} is null
          and ${table.abandonedAt} is null and ${table.completionRequestDigest} is null
          and ${table.completionRequestSnapshot} is null
          and ${table.resultSnapshot} is null and ${table.cleanupReason} is null
          and ${table.cleanedUpAt} is null)
        or (${table.state} = 'completed' and ${table.completedAt} >= ${table.createdAt}
          and ${table.abandonedAt} is null and octet_length(${table.completionRequestDigest}) = 32
          and jsonb_typeof(${table.completionRequestSnapshot}) = 'object'
          and pg_column_size(${table.completionRequestSnapshot}) between 2 and 131072
          and jsonb_typeof(${table.resultSnapshot}) = 'object'
          and pg_column_size(${table.resultSnapshot}) between 2 and 65536
          and ((${table.cleanupReason} is null and ${table.cleanedUpAt} is null)
            or (${table.cleanupReason} = 'delivery_failed'
              and ${table.cleanedUpAt} >= ${table.completedAt})))
        or (${table.state} in ('abandoned','expired','failed') and ${table.completedAt} is null
          and ${table.abandonedAt} >= ${table.createdAt}
          and ${table.completionRequestDigest} is null
          and ${table.completionRequestSnapshot} is null and ${table.resultSnapshot} is null
          and ${table.cleanupReason} is null and ${table.cleanedUpAt} is null))`,
    ),
  ],
).enableRLS();

/** Tenantless session assurance state for direct platform SAML only. */
export const authSessionPlatformSamlStates = pgTable(
  "auth_session_platform_saml_states",
  {
    sessionId: uuid("session_id")
      .primaryKey()
      .references(() => authSessions.id, { onDelete: "restrict" }),
    userId: uuid("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "restrict" }),
    authority: text("authority").notNull().default("direct_platform_saml"),
    authenticationMethod: text("authentication_method")
      .notNull()
      .default("saml"),
    sessionVersion: bigint("session_version", { mode: "bigint" }).notNull(),
    userAuthenticationRevision: bigint("user_authentication_revision", {
      mode: "bigint",
    }).notNull(),
    recoveryRestricted: boolean("recovery_restricted").notNull(),
    audience: text("audience").notNull(),
    primaryKind: text("primary_kind").notNull().default("platform_provider"),
    issuedAt: timestamp("issued_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
  },
  (table) => [
    unique("auth_session_platform_saml_states_exact_key").on(
      table.sessionId,
      table.userId,
      table.authority,
      table.authenticationMethod,
      table.primaryKind,
    ),
    unique("auth_session_platform_saml_states_user_key").on(
      table.sessionId,
      table.userId,
    ),
    index("auth_session_platform_saml_states_user_idx").on(
      table.userId,
      table.issuedAt,
      table.sessionId,
    ),
    check(
      "auth_session_platform_saml_states_value_check",
      sql`${table.authority} = 'direct_platform_saml'
        and ${table.authenticationMethod} = 'saml'
        and ${table.sessionVersion} between 1 and 2147483647
        and ${table.userAuthenticationRevision} between 1 and 9007199254740991
        and ${table.primaryKind} = 'platform_provider'
        and btrim(${table.audience}) = ${table.audience}
        and char_length(${table.audience}) between 1 and 256
        and ${table.audience} !~ '[[:cntrl:]]'`,
    ),
  ],
).enableRLS();

export const authSessionPlatformSamlProvenance = pgTable(
  "auth_session_platform_saml_provenance",
  {
    sessionId: uuid("session_id").primaryKey(),
    userId: uuid("user_id").notNull(),
    authority: text("authority").notNull().default("direct_platform_saml"),
    authenticationMethod: text("authentication_method")
      .notNull()
      .default("saml"),
    primaryKind: text("primary_kind").notNull().default("platform_provider"),
    platformProviderId: uuid("platform_provider_id").notNull(),
    externalIdentityId: uuid("external_identity_id").notNull(),
    providerRevision: bigint("provider_revision", { mode: "bigint" }).notNull(),
    loginPolicyRevision: bigint("login_policy_revision", {
      mode: "bigint",
    }).notNull(),
    configurationRevision: bigint("configuration_revision", {
      mode: "bigint",
    }).notNull(),
    securityRevision: bigint("security_revision", { mode: "bigint" }).notNull(),
    planRevision: bigint("plan_revision", { mode: "bigint" }).notNull(),
    assurancePolicyRevision: bigint("assurance_policy_revision", {
      mode: "bigint",
    }).notNull(),
    metadataRevision: bigint("metadata_revision", { mode: "bigint" }).notNull(),
    metadataDigest: bytea("metadata_digest").notNull(),
    spKeyRevision: bigint("sp_key_revision", { mode: "bigint" }).notNull(),
    configurationDigest: bytea("configuration_digest").notNull(),
    userAuthenticationRevision: bigint("user_authentication_revision", {
      mode: "bigint",
    }).notNull(),
    identityVersion: bigint("identity_version", { mode: "bigint" }).notNull(),
    aliasKeyVersion: integer("alias_key_version").notNull(),
    platformAuthorityId: uuid("platform_authority_id").notNull(),
    platformAuthorityRevision: bigint("platform_authority_revision", {
      mode: "bigint",
    }).notNull(),
    platformFloorPolicyId: uuid("platform_floor_policy_id").notNull(),
    platformFloorPolicyRevision: bigint("platform_floor_policy_revision", {
      mode: "bigint",
    }).notNull(),
    trustRuleId: uuid("trust_rule_id"),
    trustRuleRevision: bigint("trust_rule_revision", { mode: "bigint" }),
    authenticatedAt: timestamp("authenticated_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
  },
  (table) => [
    unique("auth_session_platform_saml_provenance_exact_key").on(
      table.sessionId,
      table.userId,
      table.platformProviderId,
      table.externalIdentityId,
    ),
    foreignKey({
      name: "auth_session_platform_saml_provenance_state_fk",
      columns: [
        table.sessionId,
        table.userId,
        table.authority,
        table.authenticationMethod,
        table.primaryKind,
      ],
      foreignColumns: [
        authSessionPlatformSamlStates.sessionId,
        authSessionPlatformSamlStates.userId,
        authSessionPlatformSamlStates.authority,
        authSessionPlatformSamlStates.authenticationMethod,
        authSessionPlatformSamlStates.primaryKind,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "auth_session_platform_saml_provenance_identity_fk",
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
      name: "auth_session_platform_saml_provenance_floor_fk",
      columns: [table.platformFloorPolicyId, table.platformFloorPolicyRevision],
      foreignColumns: [mfaPolicyRevisions.id, mfaPolicyRevisions.revision],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "auth_session_platform_saml_provenance_value_check",
      sql`${table.authority} = 'direct_platform_saml'
        and ${table.authenticationMethod} = 'saml' and ${table.primaryKind} = 'platform_provider'
        and ${table.providerRevision} between 1 and 2147483647
        and ${table.loginPolicyRevision} between 1 and 9007199254740991
        and ${table.configurationRevision} between 1 and 9007199254740991
        and ${table.securityRevision} between 1 and 9007199254740991
        and ${table.planRevision} between 1 and 9007199254740991
        and ${table.assurancePolicyRevision} between 1 and 9007199254740991
        and ${table.metadataRevision} between 1 and 9007199254740991
        and octet_length(${table.metadataDigest}) = 32
        and ${table.spKeyRevision} between 1 and 9007199254740991
        and octet_length(${table.configurationDigest}) = 32
        and ${table.userAuthenticationRevision} between 1 and 9007199254740991
        and ${table.identityVersion} between 1 and 2147483647
        and ${table.aliasKeyVersion} between 1 and 32767
        and (uuid_extract_version(${table.platformAuthorityId}) = 7) is true
        and ${table.platformAuthorityRevision} between 1 and 9007199254740991
        and (uuid_extract_version(${table.platformFloorPolicyId}) = 7) is true
        and ${table.platformFloorPolicyRevision} between 1 and 9007199254740991
        and ((${table.trustRuleId} is null and ${table.trustRuleRevision} is null)
          or ((uuid_extract_version(${table.trustRuleId}) = 7) is true
            and ${table.trustRuleRevision} between 1 and 9007199254740991))`,
    ),
  ],
).enableRLS();

export const authSessionPlatformSamlEvidence = pgTable(
  "auth_session_platform_saml_evidence",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    sessionId: uuid("session_id").notNull(),
    userId: uuid("user_id").notNull(),
    kind: text("kind").notNull(),
    level: text("level").notNull(),
    platformProviderId: uuid("platform_provider_id"),
    externalIdentityId: uuid("external_identity_id"),
    totpCredentialId: uuid("totp_credential_id"),
    factorRevision: bigint("factor_revision", { mode: "bigint" }),
    trustRuleId: uuid("trust_rule_id"),
    trustRuleRevision: bigint("trust_rule_revision", { mode: "bigint" }),
    authenticatedAt: timestamp("authenticated_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    expiresAt: timestamp("expires_at", { withTimezone: true, mode: "date" }),
  },
  (table) => [
    unique("auth_session_platform_saml_evidence_key").on(
      table.sessionId,
      table.id,
    ),
    foreignKey({
      name: "auth_session_platform_saml_evidence_state_fk",
      columns: [table.sessionId, table.userId],
      foreignColumns: [
        authSessionPlatformSamlStates.sessionId,
        authSessionPlatformSamlStates.userId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "auth_session_platform_saml_evidence_identity_fk",
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
      name: "auth_session_platform_saml_evidence_totp_fk",
      columns: [table.totpCredentialId, table.userId],
      foreignColumns: [totpCredentials.id, totpCredentials.userId],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "auth_session_platform_saml_evidence_value_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true
        and ${table.level} in ('primary','mfa','phishing_resistant')
        and (${table.expiresAt} is null or ${table.expiresAt} > ${table.authenticatedAt})
        and ((${table.kind} = 'platform_provider' and ${table.platformProviderId} is not null
          and ${table.externalIdentityId} is not null and ${table.totpCredentialId} is null
          and ${table.factorRevision} is null)
        or (${table.kind} = 'totp' and ${table.level} = 'mfa'
          and ${table.platformProviderId} is null and ${table.externalIdentityId} is null
          and ${table.totpCredentialId} is not null
          and ${table.factorRevision} between 1 and 9007199254740991
          and ${table.trustRuleId} is null and ${table.trustRuleRevision} is null))`,
    ),
  ],
).enableRLS();

export const authSessionPlatformSamlPolicyPins = pgTable(
  "auth_session_platform_saml_policy_pins",
  {
    sessionId: uuid("session_id").notNull(),
    policyKind: text("policy_kind").notNull(),
    policyId: uuid("policy_id").notNull(),
    policyRevision: bigint("policy_revision", { mode: "bigint" }).notNull(),
  },
  (table) => [
    primaryKey({
      name: "auth_session_platform_saml_policy_pins_pkey",
      columns: [table.sessionId, table.policyKind, table.policyId],
    }),
    foreignKey({
      name: "auth_session_platform_saml_policy_pins_state_fk",
      columns: [table.sessionId],
      foreignColumns: [authSessionPlatformSamlStates.sessionId],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "auth_session_platform_saml_policy_pins_value_check",
      sql`${table.policyKind} in ('login','assurance','platform_floor')
        and ${table.policyRevision} between 1 and 9007199254740991`,
    ),
  ],
).enableRLS();

/** Encrypted direct-platform SAML NameID/session-index/logout material. */
export const platformSamlSessionMaterials = pgTable(
  "platform_saml_session_materials",
  {
    id: uuid("id").primaryKey(),
    sessionId: uuid("session_id"),
    continuationId: uuid("continuation_id"),
    userId: uuid("user_id").notNull(),
    platformProviderId: uuid("platform_provider_id").notNull(),
    externalIdentityId: uuid("external_identity_id").notNull(),
    loginPolicyRevision: bigint("login_policy_revision", {
      mode: "bigint",
    }).notNull(),
    sessionIndexDigest: bytea("session_index_digest"),
    keyVersion: integer("key_version"),
    nonce: bytea("nonce"),
    ciphertext: bytea("ciphertext"),
    /**
     * Bounded, public-only configuration pinned at authentication apply time.
     * Legacy rows may be null and therefore degrade to local-only logout.
     */
    logoutConfiguration: jsonb("logout_configuration"),
    logoutDisposition: text("logout_disposition")
      .notNull()
      .default("available"),
    logoutOperationRunId: uuid("logout_operation_run_id"),
    logoutClaimedAt: timestamp("logout_claimed_at", {
      withTimezone: true,
      mode: "date",
    }),
    scrubbedAt: timestamp("scrubbed_at", {
      withTimezone: true,
      mode: "date",
    }),
    scrubOperationRunId: uuid("scrub_operation_run_id"),
    createdAt: timestamp("created_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
  },
  (table) => [
    uniqueIndex("platform_saml_session_materials_session_key")
      .on(table.sessionId)
      .where(sql`${table.sessionId} is not null`),
    uniqueIndex("platform_saml_session_materials_continuation_key")
      .on(table.continuationId)
      .where(sql`${table.continuationId} is not null`),
    uniqueIndex("platform_saml_session_materials_session_index_key")
      .on(table.platformProviderId, table.sessionIndexDigest)
      .where(sql`${table.sessionIndexDigest} is not null`),
    index("platform_saml_session_materials_cleanup_idx")
      .on(table.createdAt, table.id)
      .where(sql`${table.scrubbedAt} is null`),
    foreignKey({
      name: "platform_saml_session_materials_keyring_fk",
      columns: [table.keyVersion],
      foreignColumns: [identityKeyringVersions.keyVersion],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "platform_saml_session_materials_session_fk",
      columns: [
        table.sessionId,
        table.userId,
        table.platformProviderId,
        table.externalIdentityId,
      ],
      foreignColumns: [
        authSessionPlatformSamlProvenance.sessionId,
        authSessionPlatformSamlProvenance.userId,
        authSessionPlatformSamlProvenance.platformProviderId,
        authSessionPlatformSamlProvenance.externalIdentityId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "platform_saml_session_materials_continuation_fk",
      columns: [
        table.continuationId,
        table.userId,
        table.platformProviderId,
        table.externalIdentityId,
      ],
      foreignColumns: [
        platformSamlPostPrimaryContinuations.id,
        platformSamlPostPrimaryContinuations.userId,
        platformSamlPostPrimaryContinuations.platformProviderId,
        platformSamlPostPrimaryContinuations.externalIdentityId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "platform_saml_session_materials_value_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true
        and ((${table.sessionId} is null) <> (${table.continuationId} is null))
        and ${table.id} <> coalesce(${table.sessionId},${table.continuationId})
        and ${table.loginPolicyRevision} between 1 and 9007199254740991
        and (${table.sessionIndexDigest} is null or octet_length(${table.sessionIndexDigest}) = 32)
        and (${table.logoutConfiguration} is null or (
          jsonb_typeof(${table.logoutConfiguration}) = 'object'
          and pg_column_size(${table.logoutConfiguration}) between 2 and 2097152))
        and ${table.logoutDisposition} in ('available','claimed','skipped')
        and ((${table.logoutDisposition} = 'available'
            and ${table.logoutOperationRunId} is null
            and ${table.logoutClaimedAt} is null)
          or (${table.logoutDisposition} in ('claimed','skipped')
            and (uuid_extract_version(${table.logoutOperationRunId}) = 7) is true
            and ${table.logoutOperationRunId} <> ${table.id}
            and ${table.logoutClaimedAt} >= ${table.createdAt}
            and date_trunc('microseconds', ${table.logoutClaimedAt})
              = ${table.logoutClaimedAt}))
        and ((${table.scrubbedAt} is null
            and ${table.scrubOperationRunId} is null
            and ${table.keyVersion} between 1 and 32767
            and octet_length(${table.nonce}) = 12
            and octet_length(${table.ciphertext}) between 17 and 16384)
          or (${table.scrubbedAt} >= ${table.createdAt}
            and date_trunc('microseconds', ${table.scrubbedAt}) = ${table.scrubbedAt}
            and (uuid_extract_version(${table.scrubOperationRunId}) = 7) is true
            and ${table.scrubOperationRunId} <> ${table.id}
            and ${table.keyVersion} is null and ${table.nonce} is null
            and ${table.ciphertext} is null
            and ${table.sessionIndexDigest} is null
            and ${table.logoutConfiguration} is null))`,
    ),
  ],
).enableRLS();

/** Exact apply/replay receipt for one direct-platform SAML transaction. */
export const platformSamlAuthenticationApplications = pgTable(
  "platform_saml_authentication_applications",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    transactionId: bytea("transaction_id").notNull(),
    proofDigest: bytea("proof_digest").notNull(),
    platformProviderId: uuid("platform_provider_id").notNull(),
    responseIdDigest: bytea("response_id_digest").notNull(),
    assertionIdDigest: bytea("assertion_id_digest").notNull(),
    sessionIndexDigest: bytea("session_index_digest"),
    category: text("category").notNull(),
    userId: uuid("user_id").references(() => users.id, {
      onDelete: "restrict",
    }),
    externalIdentityId: uuid("external_identity_id"),
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
    cleanupReason: text("cleanup_reason"),
    cleanedUpAt: timestamp("cleaned_up_at", {
      withTimezone: true,
      mode: "date",
    }),
  },
  (table) => [
    unique("platform_saml_auth_applications_proof_key").on(table.proofDigest),
    unique("platform_saml_auth_applications_transaction_key").on(
      table.transactionId,
    ),
    unique("platform_saml_auth_applications_response_key").on(
      table.platformProviderId,
      table.responseIdDigest,
    ),
    unique("platform_saml_auth_applications_assertion_key").on(
      table.platformProviderId,
      table.assertionIdDigest,
    ),
    uniqueIndex("platform_saml_auth_applications_session_index_key")
      .on(table.platformProviderId, table.sessionIndexDigest)
      .where(sql`${table.sessionIndexDigest} is not null`),
    foreignKey({
      name: "platform_saml_auth_applications_transaction_fk",
      columns: [table.transactionId, table.platformProviderId],
      foreignColumns: [
        platformSamlAuthenticationTransactions.transactionId,
        platformSamlAuthenticationTransactions.platformProviderId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "platform_saml_auth_applications_identity_fk",
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
      name: "platform_saml_auth_applications_continuation_fk",
      columns: [table.continuationId, table.userId],
      foreignColumns: [
        platformSamlPostPrimaryContinuations.id,
        platformSamlPostPrimaryContinuations.userId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "platform_saml_auth_applications_value_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true
        and octet_length(${table.transactionId}) = 32
        and octet_length(${table.proofDigest}) = 32
        and octet_length(${table.responseIdDigest}) = 32
        and octet_length(${table.assertionIdDigest}) = 32
        and (${table.sessionIndexDigest} is null or octet_length(${table.sessionIndexDigest}) = 32)
        and ${table.category} in ('success','identity_collision','stale','denied')
        and jsonb_typeof(${table.requestSnapshot}) = 'object'
        and pg_column_size(${table.requestSnapshot}) between 2 and 2097152
        and jsonb_typeof(${table.resultSnapshot}) = 'object'
        and pg_column_size(${table.resultSnapshot}) between 2 and 65536
        and ((${table.category} = 'success' and ${table.userId} is not null
          and ${table.externalIdentityId} is not null
          and ((${table.sessionId} is null) <> (${table.continuationId} is null)))
        or (${table.category} <> 'success' and ${table.userId} is null
          and ${table.externalIdentityId} is null and ${table.sessionId} is null
          and ${table.continuationId} is null))
        and ((${table.cleanupReason} is null and ${table.cleanedUpAt} is null)
          or (${table.category} = 'success'
            and ${table.cleanupReason} in ('credential_release_failed','protocol_failed','invalid_outcome','delivery_failed')
            and ${table.cleanedUpAt} >= ${table.appliedAt}))`,
    ),
  ],
).enableRLS();

/** Exact CAS replay ledger for future direct-platform SAML revalidation. */
export const platformSamlSessionRevalidationCommands = pgTable(
  "platform_saml_session_revalidation_commands",
  {
    sessionId: uuid("session_id").notNull(),
    expectedVersion: bigint("expected_version", { mode: "bigint" }).notNull(),
    requestDigest: bytea("request_digest").notNull(),
    decision: text("decision").notNull(),
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
    cleanupReason: text("cleanup_reason"),
    cleanedUpAt: timestamp("cleaned_up_at", {
      withTimezone: true,
      mode: "date",
    }),
  },
  (table) => [
    primaryKey({
      name: "platform_saml_session_revalidation_commands_pkey",
      columns: [table.sessionId, table.expectedVersion],
    }),
    foreignKey({
      name: "platform_saml_session_revalidation_commands_session_fk",
      columns: [table.sessionId],
      foreignColumns: [authSessionPlatformSamlStates.sessionId],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "platform_saml_session_revalidation_commands_value_check",
      sql`${table.expectedVersion} between 1 and 2147483647
        and octet_length(${table.requestDigest}) = 32
        and ${table.decision} in ('usable','rotate','step_up','revoke','deny')
        and jsonb_typeof(${table.requestSnapshot}) = 'object'
        and pg_column_size(${table.requestSnapshot}) between 2 and 131072
        and jsonb_typeof(${table.resultSnapshot}) = 'object'
        and pg_column_size(${table.resultSnapshot}) between 2 and 65536
        and ((${table.cleanupReason} is null and ${table.cleanedUpAt} is null)
          or (${table.cleanupReason} = 'delivery_failed' and ${table.cleanedUpAt} >= ${table.appliedAt}))`,
    ),
  ],
).enableRLS();

/** Physically separate source-SAML/target-tenant rotation replay ledger. */
export const platformSamlTenantSwitchCommands = pgTable(
  "platform_saml_tenant_switch_commands",
  {
    sourceSessionId: uuid("source_session_id").notNull(),
    expectedVersion: bigint("expected_version", { mode: "bigint" }).notNull(),
    authenticationMethod: text("authentication_method")
      .notNull()
      .default("saml"),
    targetTenantId: uuid("target_tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    targetTenantVersion: bigint("target_tenant_version", {
      mode: "bigint",
    }).notNull(),
    membershipId: uuid("membership_id").notNull(),
    bindingId: uuid("binding_id").notNull(),
    bindingVersion: bigint("binding_version", { mode: "bigint" }).notNull(),
    mappingRevision: bigint("mapping_revision", { mode: "bigint" }).notNull(),
    authorizationRevision: bigint("authorization_revision", {
      mode: "bigint",
    }).notNull(),
    accessEpochId: uuid("access_epoch_id").notNull(),
    accessEpochVersion: bigint("access_epoch_version", {
      mode: "bigint",
    }).notNull(),
    accessSourceId: uuid("access_source_id").notNull(),
    accessGrantId: uuid("access_grant_id").notNull(),
    accessGrantVersion: bigint("access_grant_version", {
      mode: "bigint",
    }).notNull(),
    requestDigest: bytea("request_digest").notNull(),
    requestSnapshot: jsonb("request_snapshot")
      .$type<Record<string, unknown>>()
      .notNull(),
    decision: text("decision").notNull(),
    rotatedSessionId: uuid("rotated_session_id").references(
      () => authSessions.id,
      {
        onDelete: "restrict",
      },
    ),
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
      name: "platform_saml_tenant_switch_commands_pkey",
      columns: [
        table.sourceSessionId,
        table.expectedVersion,
        table.targetTenantId,
      ],
    }),
    foreignKey({
      name: "platform_saml_tenant_switch_commands_source_fk",
      columns: [table.sourceSessionId],
      foreignColumns: [authSessionPlatformSamlStates.sessionId],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "platform_saml_tenant_switch_commands_value_check",
      sql`${table.expectedVersion} between 1 and 2147483647
        and ${table.authenticationMethod} = 'saml'
        and ${table.targetTenantVersion} between 1 and 2147483647
        and ${table.bindingVersion} between 1 and 2147483647
        and ${table.mappingRevision} between 1 and 9007199254740991
        and ${table.authorizationRevision} between 1 and 9007199254740991
        and ${table.accessEpochVersion} between 1 and 2147483647
        and ${table.accessGrantVersion} between 1 and 2147483647
        and octet_length(${table.requestDigest}) = 32
        and jsonb_typeof(${table.requestSnapshot}) = 'object'
        and pg_column_size(${table.requestSnapshot}) between 2 and 262144
        and ${table.decision} in ('rotated','stale','denied')
        and (${table.decision} = 'rotated') = (${table.rotatedSessionId} is not null)
        and jsonb_typeof(${table.resultSnapshot}) = 'object'
        and pg_column_size(${table.resultSnapshot}) between 2 and 65536`,
    ),
  ],
).enableRLS();

// Alias rows are part of the exact prelinked-only dependency surface.
void platformFederatedExternalIdentityAliases;
