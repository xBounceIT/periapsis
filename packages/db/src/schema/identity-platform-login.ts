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
  platformOidcProviderConfigurations,
} from "./identity-platform-federation.js";
import {
  platformFederatedExternalIdentities,
  platformFederatedExternalIdentityAliases,
} from "./identity-platform-runtime.js";
import { identityKeyringVersions } from "./identity-providers.js";
import { mfaPolicyRevisions } from "./identity-mfa.js";
import { users } from "./identity.js";
import { tenants } from "./tenancy.js";

/**
 * Direct platform login is an independently administered, prelinked-only
 * policy boundary. Tenant execution and the historical
 * platform_login_enabled sentinel never authorize or mutate this lifecycle.
 */
export const platformOidcLoginPolicies = pgTable(
  "platform_oidc_login_policies",
  {
    providerId: uuid("provider_id").primaryKey(),
    providerKind: authProviderKind("provider_kind").notNull().default("oidc"),
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
    unique("platform_oidc_login_policies_kind_key").on(
      table.providerId,
      table.providerKind,
    ),
    foreignKey({
      name: "platform_oidc_login_policies_provider_fk",
      columns: [table.providerId, table.providerKind],
      foreignColumns: [platformAuthProviders.id, platformAuthProviders.kind],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "platform_oidc_login_policies_runtime_policy_fk",
      columns: [table.providerId, table.providerKind],
      foreignColumns: [
        platformFederatedProviderPolicies.providerId,
        platformFederatedProviderPolicies.providerKind,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "platform_oidc_login_policies_configuration_fk",
      columns: [table.providerId],
      foreignColumns: [platformOidcProviderConfigurations.providerId],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "platform_oidc_login_policies_value_check",
      sql`${table.providerKind} = 'oidc'
        and ${table.accountMode} in ('disabled', 'existing_identity')
        and (not ${table.enabled} or ${table.accountMode} = 'existing_identity')
        and ${table.revision} between 1 and 9007199254740991
        and ${table.updatedAt} >= ${table.createdAt}`,
    ),
  ],
).enableRLS();

/** One browser-bound direct platform OIDC authorization-code transaction. */
export const platformOidcAuthenticationTransactions = pgTable(
  "platform_oidc_authentication_transactions",
  {
    transactionId: bytea("transaction_id").primaryKey(),
    platformProviderId: uuid("platform_provider_id").notNull(),
    providerKind: authProviderKind("provider_kind").notNull().default("oidc"),
    protocol: text("protocol").notNull().default("oidc"),
    operationRunId: uuid("operation_run_id").notNull(),
    operationDigest: bytea("operation_digest").notNull(),
    receiptDigest: bytea("receipt_digest").notNull(),
    networkDigest: bytea("network_digest").notNull(),
    accountDigest: bytea("account_digest").notNull(),
    providerDigest: bytea("provider_digest").notNull(),
    stateDigest: bytea("state_digest").notNull(),
    browserDigest: bytea("browser_digest").notNull(),
    browserCapabilityDigest: bytea("browser_capability_digest").notNull(),
    nonceDigest: bytea("nonce_digest").notNull(),
    authorizationCodeDigest: bytea("authorization_code_digest"),
    codeChallengeMethod: text("code_challenge_method")
      .notNull()
      .default("S256"),
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
    platformFloorPolicyId: uuid("platform_floor_policy_id").notNull(),
    platformFloorPolicyRevision: bigint("platform_floor_policy_revision", {
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
    redirectUri: text("redirect_uri").notNull(),
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
    unique("platform_oidc_auth_transactions_operation_key").on(
      table.operationRunId,
    ),
    unique("platform_oidc_auth_transactions_receipt_key").on(
      table.receiptDigest,
    ),
    unique("platform_oidc_auth_transactions_state_key").on(table.stateDigest),
    unique("platform_oidc_auth_transactions_exact_key").on(
      table.transactionId,
      table.platformProviderId,
    ),
    uniqueIndex("platform_oidc_auth_transactions_live_browser_key")
      .on(table.browserDigest)
      .where(sql`${table.state} in ('pending', 'claimed')`),
    index("platform_oidc_auth_transactions_expiry_idx").on(
      table.state,
      table.expiresAt,
      table.transactionId,
    ),
    foreignKey({
      name: "platform_oidc_auth_transactions_provider_fk",
      columns: [table.platformProviderId, table.providerKind],
      foreignColumns: [platformAuthProviders.id, platformAuthProviders.kind],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "platform_oidc_auth_transactions_policy_fk",
      columns: [table.platformProviderId, table.providerKind],
      foreignColumns: [
        platformFederatedProviderPolicies.providerId,
        platformFederatedProviderPolicies.providerKind,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "platform_oidc_auth_transactions_login_policy_fk",
      columns: [table.platformProviderId, table.providerKind],
      foreignColumns: [
        platformOidcLoginPolicies.providerId,
        platformOidcLoginPolicies.providerKind,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "platform_oidc_auth_transactions_configuration_fk",
      columns: [table.platformProviderId],
      foreignColumns: [platformOidcProviderConfigurations.providerId],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "platform_oidc_auth_transactions_keyring_fk",
      columns: [table.verifierKeyVersion],
      foreignColumns: [identityKeyringVersions.keyVersion],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "platform_oidc_auth_transactions_platform_floor_fk",
      columns: [table.platformFloorPolicyId, table.platformFloorPolicyRevision],
      foreignColumns: [mfaPolicyRevisions.id, mfaPolicyRevisions.revision],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "platform_oidc_auth_transactions_id_check",
      sql`octet_length(${table.transactionId}) = 32
        and (uuid_extract_version(${table.operationRunId}) = 7) is true`,
    ),
    check(
      "platform_oidc_auth_transactions_digest_check",
      sql`octet_length(${table.operationDigest}) = 32
        and octet_length(${table.receiptDigest}) = 32
        and octet_length(${table.networkDigest}) = 32
        and octet_length(${table.accountDigest}) = 32
        and octet_length(${table.providerDigest}) = 32
        and octet_length(${table.stateDigest}) = 32
        and octet_length(${table.browserDigest}) = 32
        and octet_length(${table.browserCapabilityDigest}) = 32
        and ${table.browserCapabilityDigest} <> ${table.browserDigest}
        and octet_length(${table.nonceDigest}) = 32
        and (${table.authorizationCodeDigest} is null
          or octet_length(${table.authorizationCodeDigest}) = 32)
        and octet_length(${table.discoveryDigest}) = 32
        and octet_length(${table.jwksDigest}) = 32`,
    ),
    check(
      "platform_oidc_auth_transactions_pin_check",
      sql`${table.providerKind} = 'oidc' and ${table.protocol} = 'oidc'
        and ${table.codeChallengeMethod} = 'S256'
        and ${table.providerRevision} between 1 and 2147483647
        and ${table.loginPolicyRevision} between 1 and 9007199254740991
        and ${table.configurationRevision} between 1 and 9007199254740991
        and ${table.securityRevision} between 1 and 9007199254740991
        and ${table.planRevision} between 1 and 9007199254740991
        and ${table.assurancePolicyRevision} between 1 and 9007199254740991
        and (uuid_extract_version(${table.platformFloorPolicyId}) = 7) is true
        and ${table.platformFloorPolicyRevision} between 1 and 9007199254740991
        and ${table.clientSecretRevision} between 1 and 9007199254740991
        and ${table.discoveryRevision} between 1 and 9007199254740991
        and ${table.jwksRevision} between 1 and 9007199254740991
        and ${table.verifierKeyVersion} between 1 and 32767
        and octet_length(${table.verifierCiphertext}) between 16 and 4096
        and octet_length(convert_to(${table.clientId}, 'UTF8')) between 1 and 512
        and ${table.redirectUri} ~ '^https://[^/?#@]+/api/v1/auth/platform/oidc/callback$'
        and char_length(${table.redirectUri}) between 1 and 4096
        and char_length(${table.postLogoutRedirectUri}) between 1 and 4096
        and cardinality(${table.scopes}) between 1 and 64
        and array_position(${table.scopes}, null) is null
        and char_length(${table.returnPath}) between 1 and 2048
        and left(${table.returnPath}, 1) = '/'
        and ${table.clientId} !~ '[[:cntrl:]]'
        and ${table.redirectUri} !~ '[[:cntrl:]]'
        and ${table.postLogoutRedirectUri} !~ '[[:cntrl:]]'
        and ${table.returnPath} !~ '[[:cntrl:]]'`,
    ),
    check(
      "platform_oidc_auth_transactions_lifecycle_check",
      sql`${table.version} between 1 and 2147483647
        and ${table.expiresAt} between ${table.createdAt} + interval '1 minute'
          and ${table.createdAt} + interval '15 minutes'
        and ((
          ${table.state} = 'pending' and ${table.version} = 1
          and ${table.claimAttemptId} is null
          and ${table.authorizationCodeDigest} is null
          and ${table.claimedAt} is null and ${table.completedAt} is null
          and ${table.failureReason} is null
        ) or (
          ${table.state} = 'claimed' and ${table.version} = 2
          and octet_length(${table.claimAttemptId}) = 32
          and ${table.authorizationCodeDigest} is not null
          and ${table.claimedAt} is not null and ${table.completedAt} is null
          and ${table.failureReason} is null
        ) or (
          ${table.state} in ('completed', 'failed', 'expired')
          and ${table.version} >= 2 and ${table.completedAt} is not null
          and ${table.completedAt} >= ${table.createdAt}
          and (${table.state} <> 'completed'
            or (${table.claimAttemptId} is not null
              and ${table.authorizationCodeDigest} is not null
              and ${table.failureReason} is null))
          and (${table.state} = 'completed') = (${table.failureReason} is null)
        ))`,
    ),
  ],
).enableRLS();

/** One-use direct post-primary capability, independent of tenant MFA rows. */
export const platformPostPrimaryContinuations = pgTable(
  "platform_post_primary_continuations",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    userId: uuid("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "restrict" }),
    receiptDigest: bytea("receipt_digest").notNull(),
    action: text("action").notNull(),
    audience: text("audience").notNull(),
    platformProviderId: uuid("platform_provider_id").notNull(),
    externalIdentityId: uuid("external_identity_id").notNull(),
    providerRevision: bigint("provider_revision", { mode: "bigint" }).notNull(),
    loginPolicyRevision: bigint("login_policy_revision", {
      mode: "bigint",
    }).notNull(),
    securityRevision: bigint("security_revision", { mode: "bigint" }).notNull(),
    userAuthenticationRevision: bigint("user_authentication_revision", {
      mode: "bigint",
    }).notNull(),
    identityVersion: bigint("identity_version", { mode: "bigint" }).notNull(),
    aliasKeyVersion: integer("alias_key_version").notNull(),
    assurancePolicyRevision: bigint("assurance_policy_revision", {
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
    sourceSessionId: uuid("source_session_id").references(
      () => authSessions.id,
      { onDelete: "restrict" },
    ),
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
    consumedAt: timestamp("consumed_at", {
      withTimezone: true,
      mode: "date",
    }),
    revokedAt: timestamp("revoked_at", { withTimezone: true, mode: "date" }),
    revokeReason: text("revoke_reason"),
  },
  (table) => [
    unique("platform_post_primary_continuations_receipt_key").on(
      table.receiptDigest,
    ),
    unique("platform_post_primary_continuations_user_key").on(
      table.id,
      table.userId,
    ),
    unique("platform_post_primary_continuations_exact_key").on(
      table.id,
      table.userId,
      table.platformProviderId,
      table.externalIdentityId,
    ),
    index("platform_post_primary_continuations_pending_idx")
      .on(table.userId, table.expiresAt, table.id)
      .where(sql`${table.state} = 'pending'`),
    foreignKey({
      name: "platform_post_primary_continuations_identity_fk",
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
      name: "platform_post_primary_continuations_platform_floor_fk",
      columns: [table.platformFloorPolicyId, table.platformFloorPolicyRevision],
      foreignColumns: [mfaPolicyRevisions.id, mfaPolicyRevisions.revision],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "platform_post_primary_continuations_selected_totp_fk",
      columns: [table.selectedTotpCredentialId, table.userId],
      foreignColumns: [totpCredentials.id, totpCredentials.userId],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "platform_post_primary_continuations_id_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true
        and octet_length(${table.receiptDigest}) = 32`,
    ),
    check(
      "platform_post_primary_continuations_pin_check",
      sql`${table.providerRevision} between 1 and 2147483647
        and ${table.loginPolicyRevision} between 1 and 9007199254740991
        and ${table.securityRevision} between 1 and 9007199254740991
        and ${table.userAuthenticationRevision} between 1 and 9007199254740991
        and ${table.identityVersion} between 1 and 2147483647
        and ${table.aliasKeyVersion} between 1 and 32767
        and ${table.assurancePolicyRevision} between 1 and 9007199254740991
        and (uuid_extract_version(${table.platformFloorPolicyId}) = 7) is true
        and ${table.platformFloorPolicyRevision} between 1 and 9007199254740991
        and (uuid_extract_version(${table.selectedTotpCredentialId}) = 7) is true
        and ${table.selectedTotpSecurityRevision} between 1 and 9007199254740991
        and ((${table.trustRuleId} is null and ${table.trustRuleRevision} is null)
          or ((uuid_extract_version(${table.trustRuleId}) = 7) is true
            and ${table.trustRuleRevision} between 1 and 9007199254740991))
        and ((${table.origin} = 'initial_login'
          and ${table.sourceSessionId} is null
          and ${table.sourceSessionFamilyId} is null
          and ${table.sourceSessionVersion} is null
          and ${table.sourceAbsoluteExpiresAt} is null)
        or (${table.origin} = 'session_revalidation'
          and ${table.sourceSessionId} is not null
          and (uuid_extract_version(${table.sourceSessionFamilyId}) = 7) is true
          and ${table.sourceSessionVersion} between 1 and 2147483647
          and ${table.sourceAbsoluteExpiresAt} > ${table.createdAt}))`,
    ),
    check(
      "platform_post_primary_continuations_text_check",
      sql`btrim(${table.action}) = ${table.action}
        and char_length(${table.action}) between 1 and 256
        and ${table.action} !~ '[[:cntrl:]]'
        and btrim(${table.audience}) = ${table.audience}
        and char_length(${table.audience}) between 1 and 256
        and ${table.audience} !~ '[[:cntrl:]]'`,
    ),
    check(
      "platform_post_primary_continuations_lifecycle_check",
      sql`${table.expiresAt} > ${table.createdAt}
        and (( ${table.state} = 'pending' and ${table.version} = 1
          and ${table.consumedAt} is null and ${table.revokedAt} is null
          and ${table.revokeReason} is null)
        or (${table.state} = 'consumed' and ${table.version} >= 2
          and ${table.consumedAt} between ${table.createdAt} and ${table.expiresAt}
          and ${table.revokedAt} is null and ${table.revokeReason} is null)
        or (${table.state} in ('revoked','expired') and ${table.version} >= 2
          and ${table.consumedAt} is null and ${table.revokedAt} >= ${table.createdAt}
          and btrim(${table.revokeReason}) <> ''
          and char_length(${table.revokeReason}) <= 500
          and ${table.revokeReason} !~ '[[:cntrl:]]'))`,
    ),
  ],
).enableRLS();

/** Immutable direct primary/factor assurance evidence retained by a capability. */
export const platformPostPrimaryContinuationEvidence = pgTable(
  "platform_post_primary_continuation_evidence",
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
    unique("platform_post_primary_continuation_evidence_key").on(
      table.continuationId,
      table.id,
    ),
    foreignKey({
      name: "platform_post_primary_continuation_evidence_parent_fk",
      columns: [table.continuationId, table.userId],
      foreignColumns: [
        platformPostPrimaryContinuations.id,
        platformPostPrimaryContinuations.userId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "platform_post_primary_continuation_evidence_identity_fk",
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
      name: "platform_post_primary_continuation_evidence_totp_fk",
      columns: [table.totpCredentialId, table.userId],
      foreignColumns: [totpCredentials.id, totpCredentials.userId],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "platform_post_primary_continuation_evidence_value_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true
        and ${table.level} in ('primary','mfa','phishing_resistant')
        and (${table.expiresAt} is null or ${table.expiresAt} > ${table.authenticatedAt})
        and ((${table.kind} = 'platform_provider'
          and ${table.platformProviderId} is not null
          and ${table.externalIdentityId} is not null
          and ${table.totpCredentialId} is null
          and ${table.factorRevision} is null
          and ((${table.level} = 'primary'
            and ${table.trustRuleId} is null
            and ${table.trustRuleRevision} is null)
          or (${table.level} in ('mfa','phishing_resistant')
            and (uuid_extract_version(${table.trustRuleId}) = 7) is true
            and ${table.trustRuleRevision} between 1 and 9007199254740991)))
        or (${table.kind} = 'totp' and ${table.level} = 'mfa'
          and ${table.platformProviderId} is null
          and ${table.externalIdentityId} is null
          and ${table.totpCredentialId} is not null
          and ${table.factorRevision} between 1 and 9007199254740991
          and ${table.trustRuleId} is null
          and ${table.trustRuleRevision} is null))`,
    ),
  ],
).enableRLS();

/** Exact ordered policy pins carried by a direct capability. */
export const platformPostPrimaryContinuationPolicyPins = pgTable(
  "platform_post_primary_continuation_policy_pins",
  {
    continuationId: uuid("continuation_id").notNull(),
    policyKind: text("policy_kind").notNull(),
    policyId: uuid("policy_id").notNull(),
    policyRevision: bigint("policy_revision", { mode: "bigint" }).notNull(),
  },
  (table) => [
    primaryKey({
      name: "platform_post_primary_continuation_policy_pins_pkey",
      columns: [table.continuationId, table.policyKind, table.policyId],
    }),
    foreignKey({
      name: "platform_post_primary_continuation_policy_pins_parent_fk",
      columns: [table.continuationId],
      foreignColumns: [platformPostPrimaryContinuations.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "platform_post_primary_continuation_policy_pins_value_check",
      sql`${table.policyKind} in ('login','assurance','platform_floor')
        and ${table.policyRevision} between 1 and 9007199254740991`,
    ),
  ],
).enableRLS();

/** Claimed one-use TOTP ceremony for a direct post-primary continuation. */
export const platformPostPrimaryTotpChallenges = pgTable(
  "platform_post_primary_totp_challenges",
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
  },
  (table) => [
    uniqueIndex("platform_post_primary_totp_challenges_live_continuation_key")
      .on(table.continuationId)
      .where(sql`${table.state} = 'pending'`),
    index("platform_post_primary_totp_challenges_expiry_idx")
      .on(table.expiresAt, table.id)
      .where(sql`${table.state} = 'pending'`),
    foreignKey({
      name: "platform_post_primary_totp_challenges_parent_fk",
      columns: [table.continuationId, table.userId],
      foreignColumns: [
        platformPostPrimaryContinuations.id,
        platformPostPrimaryContinuations.userId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "platform_post_primary_totp_challenges_factor_fk",
      columns: [table.totpCredentialId, table.userId],
      foreignColumns: [totpCredentials.id, totpCredentials.userId],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "platform_post_primary_totp_challenges_value_check",
      sql`octet_length(${table.id}) = 32
        and octet_length(${table.browserDigest}) = 32
        and ${table.expectedContinuationVersion} between 1 and 2147483647
        and ${table.userAuthenticationRevision} between 1 and 9007199254740991
        and ${table.totpSecurityRevision} between 1 and 9007199254740991
        and ${table.failureCount} between 0 and 5
        and ${table.version} between 1 and 2147483647
        and ${table.expiresAt} between ${table.createdAt} + interval '1 minute'
          and ${table.createdAt} + interval '10 minutes'
        and ((${table.state} = 'pending'
          and ${table.completedAt} is null and ${table.abandonedAt} is null
          and ${table.completionRequestDigest} is null
          and ${table.resultSnapshot} is null)
        or (${table.state} = 'completed'
          and ${table.completedAt} >= ${table.createdAt}
          and ${table.abandonedAt} is null
          and octet_length(${table.completionRequestDigest}) = 32
          and jsonb_typeof(${table.resultSnapshot}) = 'object'
          and pg_column_size(${table.resultSnapshot}) between 2 and 65536)
        or (${table.state} in ('abandoned','expired','failed')
          and ${table.completedAt} is null
          and ${table.abandonedAt} >= ${table.createdAt}
          and ${table.completionRequestDigest} is null
          and ${table.resultSnapshot} is null))`,
    ),
  ],
).enableRLS();

/** Direct session assurance state; active_tenant_id is guarded to NULL in SQL. */
export const authSessionPlatformOidcStates = pgTable(
  "auth_session_platform_oidc_states",
  {
    sessionId: uuid("session_id")
      .primaryKey()
      .references(() => authSessions.id, { onDelete: "restrict" }),
    userId: uuid("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "restrict" }),
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
    unique("auth_session_platform_oidc_states_exact_key").on(
      table.sessionId,
      table.userId,
      table.primaryKind,
    ),
    unique("auth_session_platform_oidc_states_user_key").on(
      table.sessionId,
      table.userId,
    ),
    index("auth_session_platform_oidc_states_user_idx").on(
      table.userId,
      table.issuedAt,
      table.sessionId,
    ),
    check(
      "auth_session_platform_oidc_states_value_check",
      sql`${table.sessionVersion} between 1 and 2147483647
        and ${table.userAuthenticationRevision} between 1 and 9007199254740991
        and ${table.primaryKind} = 'platform_provider'
        and btrim(${table.audience}) = ${table.audience}
        and char_length(${table.audience}) between 1 and 256
        and ${table.audience} !~ '[[:cntrl:]]'`,
    ),
  ],
).enableRLS();

/** Exact provider-global authority for one direct session. */
export const authSessionPlatformOidcProvenance = pgTable(
  "auth_session_platform_oidc_provenance",
  {
    sessionId: uuid("session_id").primaryKey(),
    userId: uuid("user_id").notNull(),
    primaryKind: text("primary_kind").notNull().default("platform_provider"),
    platformProviderId: uuid("platform_provider_id").notNull(),
    externalIdentityId: uuid("external_identity_id").notNull(),
    providerRevision: bigint("provider_revision", { mode: "bigint" }).notNull(),
    loginPolicyRevision: bigint("login_policy_revision", {
      mode: "bigint",
    }).notNull(),
    securityRevision: bigint("security_revision", { mode: "bigint" }).notNull(),
    userAuthenticationRevision: bigint("user_authentication_revision", {
      mode: "bigint",
    }).notNull(),
    identityVersion: bigint("identity_version", { mode: "bigint" }).notNull(),
    aliasKeyVersion: integer("alias_key_version").notNull(),
    assurancePolicyRevision: bigint("assurance_policy_revision", {
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
    unique("auth_session_platform_oidc_provenance_exact_key").on(
      table.sessionId,
      table.userId,
      table.platformProviderId,
      table.externalIdentityId,
    ),
    foreignKey({
      name: "auth_session_platform_oidc_provenance_state_fk",
      columns: [table.sessionId, table.userId, table.primaryKind],
      foreignColumns: [
        authSessionPlatformOidcStates.sessionId,
        authSessionPlatformOidcStates.userId,
        authSessionPlatformOidcStates.primaryKind,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "auth_session_platform_oidc_provenance_identity_fk",
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
      name: "auth_session_platform_oidc_provenance_platform_floor_fk",
      columns: [table.platformFloorPolicyId, table.platformFloorPolicyRevision],
      foreignColumns: [mfaPolicyRevisions.id, mfaPolicyRevisions.revision],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "auth_session_platform_oidc_provenance_value_check",
      sql`${table.primaryKind} = 'platform_provider'
        and ${table.providerRevision} between 1 and 2147483647
        and ${table.loginPolicyRevision} between 1 and 9007199254740991
        and ${table.securityRevision} between 1 and 9007199254740991
        and ${table.userAuthenticationRevision} between 1 and 9007199254740991
        and ${table.identityVersion} between 1 and 2147483647
        and ${table.aliasKeyVersion} between 1 and 32767
        and ${table.assurancePolicyRevision} between 1 and 9007199254740991
        and (uuid_extract_version(${table.platformFloorPolicyId}) = 7) is true
        and ${table.platformFloorPolicyRevision} between 1 and 9007199254740991
        and ((${table.trustRuleId} is null and ${table.trustRuleRevision} is null)
          or ((uuid_extract_version(${table.trustRuleId}) = 7) is true
            and ${table.trustRuleRevision} between 1 and 9007199254740991))`,
    ),
  ],
).enableRLS();

/** Immutable assurance evidence for a direct session. */
export const authSessionPlatformOidcEvidence = pgTable(
  "auth_session_platform_oidc_evidence",
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
    unique("auth_session_platform_oidc_evidence_key").on(
      table.sessionId,
      table.id,
    ),
    foreignKey({
      name: "auth_session_platform_oidc_evidence_state_fk",
      columns: [table.sessionId, table.userId],
      foreignColumns: [
        authSessionPlatformOidcStates.sessionId,
        authSessionPlatformOidcStates.userId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "auth_session_platform_oidc_evidence_identity_fk",
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
      name: "auth_session_platform_oidc_evidence_totp_fk",
      columns: [table.totpCredentialId, table.userId],
      foreignColumns: [totpCredentials.id, totpCredentials.userId],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "auth_session_platform_oidc_evidence_value_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true
        and ${table.level} in ('primary','mfa','phishing_resistant')
        and (${table.expiresAt} is null or ${table.expiresAt} > ${table.authenticatedAt})
        and ((${table.kind} = 'platform_provider'
          and ${table.platformProviderId} is not null
          and ${table.externalIdentityId} is not null
          and ${table.totpCredentialId} is null
          and ${table.factorRevision} is null
          and ((${table.level} = 'primary'
            and ${table.trustRuleId} is null
            and ${table.trustRuleRevision} is null)
          or (${table.level} in ('mfa','phishing_resistant')
            and (uuid_extract_version(${table.trustRuleId}) = 7) is true
            and ${table.trustRuleRevision} between 1 and 9007199254740991)))
        or (${table.kind} = 'totp' and ${table.level} = 'mfa'
          and ${table.platformProviderId} is null
          and ${table.externalIdentityId} is null
          and ${table.totpCredentialId} is not null
          and ${table.factorRevision} between 1 and 9007199254740991
          and ${table.trustRuleId} is null
          and ${table.trustRuleRevision} is null))`,
    ),
  ],
).enableRLS();

/** Exact policy pins for a direct session. */
export const authSessionPlatformOidcPolicyPins = pgTable(
  "auth_session_platform_oidc_policy_pins",
  {
    sessionId: uuid("session_id").notNull(),
    policyKind: text("policy_kind").notNull(),
    policyId: uuid("policy_id").notNull(),
    policyRevision: bigint("policy_revision", { mode: "bigint" }).notNull(),
  },
  (table) => [
    primaryKey({
      name: "auth_session_platform_oidc_policy_pins_pkey",
      columns: [table.sessionId, table.policyKind, table.policyId],
    }),
    foreignKey({
      name: "auth_session_platform_oidc_policy_pins_state_fk",
      columns: [table.sessionId],
      foreignColumns: [authSessionPlatformOidcStates.sessionId],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "auth_session_platform_oidc_policy_pins_value_check",
      sql`${table.policyKind} in ('login','assurance','platform_floor')
        and ${table.policyRevision} between 1 and 9007199254740991`,
    ),
  ],
).enableRLS();

/** Immutable replay receipt for a direct authentication apply. */
export const platformOidcAuthenticationApplications = pgTable(
  "platform_oidc_authentication_applications",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    transactionId: bytea("transaction_id").notNull(),
    operationDigest: bytea("operation_digest").notNull(),
    platformProviderId: uuid("platform_provider_id").notNull(),
    externalIdentityId: uuid("external_identity_id"),
    category: text("category").notNull(),
    primaryKind: text("primary_kind"),
    userId: uuid("user_id").references(() => users.id, {
      onDelete: "restrict",
    }),
    sessionId: uuid("session_id").references(() => authSessions.id, {
      onDelete: "restrict",
    }),
    continuationId: uuid("continuation_id").references(
      () => platformPostPrimaryContinuations.id,
      { onDelete: "restrict" },
    ),
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
    unique("platform_oidc_auth_applications_operation_key").on(
      table.operationDigest,
    ),
    unique("platform_oidc_auth_applications_transaction_key").on(
      table.transactionId,
    ),
    foreignKey({
      name: "platform_oidc_auth_applications_transaction_fk",
      columns: [table.transactionId, table.platformProviderId],
      foreignColumns: [
        platformOidcAuthenticationTransactions.transactionId,
        platformOidcAuthenticationTransactions.platformProviderId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "platform_oidc_auth_applications_identity_fk",
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
      "platform_oidc_auth_applications_value_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true
        and octet_length(${table.transactionId}) = 32
        and octet_length(${table.operationDigest}) = 32
        and ${table.category} in ('success','identity_collision','stale','denied')
        and jsonb_typeof(${table.requestSnapshot}) = 'object'
        and pg_column_size(${table.requestSnapshot}) between 2 and 2097152
        and jsonb_typeof(${table.resultSnapshot}) = 'object'
        and pg_column_size(${table.resultSnapshot}) between 2 and 65536
        and ((${table.category} = 'success'
          and ${table.primaryKind} = 'platform_provider'
          and ${table.userId} is not null
          and ${table.externalIdentityId} is not null
          and ((${table.sessionId} is null) <> (${table.continuationId} is null)))
        or (${table.category} <> 'success'
          and ${table.primaryKind} is null and ${table.userId} is null
          and ${table.externalIdentityId} is null
          and ${table.sessionId} is null and ${table.continuationId} is null))`,
    ),
  ],
).enableRLS();

/** Exact CAS replay ledger for direct-session revalidation. */
export const platformOidcSessionRevalidationCommands = pgTable(
  "platform_oidc_session_revalidation_commands",
  {
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
      name: "platform_oidc_session_revalidation_commands_pkey",
      columns: [table.sessionId, table.expectedVersion],
    }),
    foreignKey({
      name: "platform_oidc_session_revalidation_commands_session_fk",
      columns: [table.sessionId],
      foreignColumns: [authSessionPlatformOidcStates.sessionId],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "platform_oidc_session_revalidation_commands_value_check",
      sql`${table.expectedVersion} between 1 and 2147483647
        and octet_length(${table.requestDigest}) = 32
        and ${table.decision} in ('usable','rotate','step_up','revoke','deny')
        and jsonb_typeof(${table.resultSnapshot}) = 'object'
        and pg_column_size(${table.resultSnapshot}) between 2 and 65536`,
    ),
  ],
).enableRLS();

/** Source-direct/target-tenant graph rotation replay ledger. */
export const platformOidcTenantSwitchCommands = pgTable(
  "platform_oidc_tenant_switch_commands",
  {
    sourceSessionId: uuid("source_session_id").notNull(),
    expectedVersion: bigint("expected_version", { mode: "bigint" }).notNull(),
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
    decision: text("decision").notNull(),
    rotatedSessionId: uuid("rotated_session_id").references(
      () => authSessions.id,
      { onDelete: "restrict" },
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
      name: "platform_oidc_tenant_switch_commands_pkey",
      columns: [
        table.sourceSessionId,
        table.expectedVersion,
        table.targetTenantId,
      ],
    }),
    foreignKey({
      name: "platform_oidc_tenant_switch_commands_source_fk",
      columns: [table.sourceSessionId],
      foreignColumns: [authSessionPlatformOidcStates.sessionId],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "platform_oidc_tenant_switch_commands_value_check",
      sql`${table.expectedVersion} between 1 and 2147483647
        and ${table.targetTenantVersion} between 1 and 2147483647
        and ${table.bindingVersion} between 1 and 2147483647
        and ${table.mappingRevision} between 1 and 9007199254740991
        and ${table.authorizationRevision} between 1 and 9007199254740991
        and ${table.accessEpochVersion} between 1 and 2147483647
        and ${table.accessGrantVersion} between 1 and 2147483647
        and octet_length(${table.requestDigest}) = 32
        and ${table.decision} in ('rotated','stale','denied')
        and (${table.decision} = 'rotated') = (${table.rotatedSessionId} is not null)
        and jsonb_typeof(${table.resultSnapshot}) = 'object'
        and pg_column_size(${table.resultSnapshot}) between 2 and 65536`,
    ),
  ],
).enableRLS();

// Keep the alias table in this module's dependency surface so direct login
// readiness can prove exact-subject prelinking rather than user/profile lookup.
void platformFederatedExternalIdentityAliases;
