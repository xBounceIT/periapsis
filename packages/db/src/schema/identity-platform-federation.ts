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
import { authProviderKind } from "./enums.js";
import { identityKeyringVersions } from "./identity-providers.js";
import { users } from "./identity.js";

/**
 * Platform-managed identity providers are deliberately separate from the
 * tenant provider family. A nullable tenant discriminator would make a
 * missing predicate a cross-tenant authorization defect.
 */
export const platformAuthProviders = pgTable(
  "platform_auth_providers",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    key: text("key").notNull(),
    displayName: text("display_name").notNull(),
    description: text("description").notNull().default(""),
    kind: authProviderKind("kind").notNull(),
    enabled: boolean("enabled").notNull().default(false),
    createdByUserId: uuid("created_by_user_id")
      .notNull()
      .references(() => users.id, { onDelete: "restrict" }),
    updatedByUserId: uuid("updated_by_user_id")
      .notNull()
      .references(() => users.id, { onDelete: "restrict" }),
    archivedAt: timestamp("archived_at", {
      withTimezone: true,
      mode: "date",
    }),
    archivedByUserId: uuid("archived_by_user_id").references(() => users.id, {
      onDelete: "restrict",
    }),
    archiveReason: text("archive_reason"),
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
    unique("platform_auth_providers_id_kind_key").on(table.id, table.kind),
    unique("platform_auth_providers_key_key").on(table.key),
    index("platform_auth_providers_kind_idx").on(table.kind, table.id),
    uniqueIndex("platform_auth_providers_active_display_key")
      .on(table.displayName)
      .where(sql`${table.archivedAt} is null`),
    check(
      "platform_auth_providers_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "platform_auth_providers_kind_check",
      sql`${table.kind} in ('ldap', 'oidc', 'saml')`,
    ),
    check(
      "platform_auth_providers_key_check",
      sql`${table.key} = lower(btrim(${table.key}))
        and ${table.key} ~ '^[a-z][a-z0-9_-]{2,63}$'`,
    ),
    check(
      "platform_auth_providers_display_name_check",
      sql`${table.displayName} = btrim(${table.displayName})
        and ${table.displayName} <> ''
        and char_length(${table.displayName}) <= 120
        and ${table.displayName} !~ '[[:cntrl:]]'`,
    ),
    check(
      "platform_auth_providers_description_check",
      sql`${table.description} = btrim(${table.description})
        and char_length(${table.description}) <= 1000
        and ${table.description} !~ '[[:cntrl:]]'`,
    ),
    check(
      "platform_auth_providers_archive_check",
      sql`(${table.archivedAt} is null
          and ${table.archivedByUserId} is null
          and ${table.archiveReason} is null)
        or (${table.archivedAt} is not null
          and ${table.archivedByUserId} is not null
          and ${table.archiveReason} is not null
          and not ${table.enabled}
          and ${table.archivedAt} >= ${table.createdAt}
          and ${table.archiveReason} = btrim(${table.archiveReason})
          and ${table.archiveReason} <> ''
          and octet_length(convert_to(${table.archiveReason}, 'UTF8')) <= 2048
          and ${table.archiveReason} !~ '[[:cntrl:]]')`,
    ),
    check(
      "platform_auth_providers_lifecycle_check",
      sql`${table.version} between 1 and 2147483647
        and isfinite(${table.createdAt}) and isfinite(${table.updatedAt})
        and extract(year from ${table.createdAt} at time zone 'UTC') between 1970 and 9999
        and extract(year from ${table.updatedAt} at time zone 'UTC') between 1970 and 9999
        and ${table.updatedAt} >= ${table.createdAt}
        and (${table.archivedAt} is null or (
          isfinite(${table.archivedAt})
          and extract(year from ${table.archivedAt} at time zone 'UTC') between 1970 and 9999
          and ${table.updatedAt} >= ${table.archivedAt}))`,
    ),
  ],
).enableRLS();

/** Exact idempotency ledger for platform-provider create commands. */
export const platformIdentityProviderCommands = pgTable(
  "platform_identity_provider_commands",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    actorUserId: uuid("actor_user_id")
      .notNull()
      .references(() => users.id, { onDelete: "restrict" }),
    operation: text("operation").notNull(),
    keyDigest: bytea("key_digest").notNull(),
    requestDigest: bytea("request_digest").notNull(),
    resultProviderId: uuid("result_provider_id")
      .notNull()
      .references(() => platformAuthProviders.id, { onDelete: "restrict" }),
    resultVersion: bigint("result_version", { mode: "bigint" }).notNull(),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    expiresAt: timestamp("expires_at", { withTimezone: true, mode: "date" })
      .notNull()
      .default(sql`now() + interval '24 hours'`),
  },
  (table) => [
    unique("platform_identity_provider_commands_replay_key").on(
      table.actorUserId,
      table.operation,
      table.keyDigest,
    ),
    index("platform_identity_provider_commands_expiry_idx").on(table.expiresAt),
    check(
      "platform_identity_provider_commands_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "platform_identity_provider_commands_operation_check",
      sql`${table.operation} = 'provider.create'`,
    ),
    check(
      "platform_identity_provider_commands_digest_check",
      sql`octet_length(${table.keyDigest}) = 32
        and octet_length(${table.requestDigest}) = 32`,
    ),
    check(
      "platform_identity_provider_commands_result_check",
      sql`${table.resultVersion} = 1`,
    ),
    check(
      "platform_identity_provider_commands_retention_check",
      sql`${table.expiresAt} > ${table.createdAt}
        and ${table.expiresAt} <= ${table.createdAt} + interval '7 days'`,
    ),
  ],
).enableRLS();

/** Sanitized diagnostics only; upstream bodies and credentials never persist. */
export const platformIdentityProviderTestRuns = pgTable(
  "platform_identity_provider_test_runs",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    providerId: uuid("provider_id")
      .notNull()
      .references(() => platformAuthProviders.id, { onDelete: "restrict" }),
    actorUserId: uuid("actor_user_id")
      .notNull()
      .references(() => users.id, { onDelete: "restrict" }),
    providerVersion: bigint("provider_version", { mode: "bigint" }).notNull(),
    configurationRevision: bigint("configuration_revision", {
      mode: "bigint",
    }).notNull(),
    kind: text("kind").notNull(),
    status: text("status").notNull(),
    outcome: text("outcome"),
    category: text("category"),
    correlationId: uuid("correlation_id").notNull(),
    startedAt: timestamp("started_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    completedAt: timestamp("completed_at", {
      withTimezone: true,
      mode: "date",
    }),
  },
  (table) => [
    unique("platform_identity_provider_test_runs_correlation_key").on(
      table.correlationId,
    ),
    index("platform_identity_provider_test_runs_provider_idx").on(
      table.providerId,
      table.startedAt,
      table.id,
    ),
    check(
      "platform_identity_provider_test_runs_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "platform_identity_provider_test_runs_revision_check",
      sql`${table.providerVersion} between 1 and 2147483647
        and ${table.configurationRevision} between 1 and 9007199254740991`,
    ),
    check(
      "platform_identity_provider_test_runs_value_check",
      sql`(${table.kind} in ('configuration','connection','trust')
        and ${table.status} in ('running','completed')
        and ((${table.status} = 'running'
            and ${table.outcome} is null
            and ${table.category} is null
            and ${table.completedAt} is null)
          or (${table.status} = 'completed'
            and ${table.outcome} is not null
            and ${table.category} is not null
            and ${table.outcome} in ('success','failure','inconclusive')
            and ${table.category} in (
              'success','cancelled','configuration_invalid','destination_blocked',
              'dns_failed','connect_failed','connect_timeout','tls_failed',
              'discovery_unreachable','issuer_mismatch','jwks_invalid',
              'metadata_invalid','certificate_expired','stale_configuration',
              'protocol_failed')
            and ((${table.outcome} = 'success' and ${table.category} = 'success')
              or (${table.outcome} = 'inconclusive'
                and ${table.category} = 'stale_configuration')
              or (${table.outcome} = 'failure'
                and ${table.category} not in ('success','stale_configuration')))
            and ${table.completedAt} >= ${table.startedAt}))) is true`,
    ),
  ],
).enableRLS();

/**
 * Tenant-execution runtime pins for a platform provider. The historical
 * platformLoginEnabled sentinel is permanently false; direct platform login
 * is governed by the separate platformOidcLoginPolicies lifecycle.
 */
export const platformFederatedProviderPolicies = pgTable(
  "platform_federated_provider_policies",
  {
    providerId: uuid("provider_id").primaryKey(),
    providerKind: authProviderKind("provider_kind").notNull(),
    configurationRevision: bigint("configuration_revision", {
      mode: "bigint",
    }).notNull(),
    securityRevision: bigint("security_revision", {
      mode: "bigint",
    }).notNull(),
    planRevision: bigint("plan_revision", { mode: "bigint" }).notNull(),
    assurancePolicyRevision: bigint("assurance_policy_revision", {
      mode: "bigint",
    }).notNull(),
    accountMode: text("account_mode").notNull().default("disabled"),
    platformLoginEnabled: boolean("platform_login_enabled")
      .notNull()
      .default(false),
    enabled: boolean("enabled").notNull().default(false),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    unique("platform_federated_provider_policies_kind_key").on(
      table.providerId,
      table.providerKind,
    ),
    foreignKey({
      name: "platform_federated_provider_policies_provider_fk",
      columns: [table.providerId, table.providerKind],
      foreignColumns: [platformAuthProviders.id, platformAuthProviders.kind],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "platform_federated_provider_policies_kind_check",
      sql`${table.providerKind} in ('ldap', 'oidc', 'saml')`,
    ),
    check(
      "platform_federated_provider_policies_revision_check",
      sql`${table.configurationRevision} between 1 and 9007199254740991
        and ${table.securityRevision} between 1 and 9007199254740991
        and ${table.planRevision} between 1 and 9007199254740991
        and ${table.assurancePolicyRevision} between 1 and 9007199254740991`,
    ),
    check(
      "platform_federated_provider_policies_account_check",
      sql`${table.accountMode} in ('disabled', 'existing_identity', 'create')`,
    ),
    check(
      "platform_federated_provider_policies_login_check",
      sql`not ${table.platformLoginEnabled}`,
    ),
    check(
      "platform_federated_provider_policies_timestamp_check",
      sql`${table.updatedAt} >= ${table.createdAt}`,
    ),
  ],
).enableRLS();

export const platformOidcProviderConfigurations = pgTable(
  "platform_oidc_provider_configurations",
  {
    providerId: uuid("provider_id").primaryKey(),
    providerKind: authProviderKind("provider_kind").notNull().default("oidc"),
    issuer: text("issuer").notNull(),
    clientId: text("client_id").notNull(),
    redirectUri: text("redirect_uri").notNull(),
    tenantRedirectUri: text("tenant_redirect_uri").notNull(),
    postLogoutRedirectUri: text("post_logout_redirect_uri").notNull(),
    extraScopes: text("extra_scopes")
      .array()
      .notNull()
      .default(sql`ARRAY[]::text[]`),
    allowRefreshToken: boolean("allow_refresh_token").notNull().default(false),
    useUserInfo: boolean("use_user_info").notNull().default(false),
    clientSecretRevision: bigint("client_secret_revision", {
      mode: "bigint",
    }).notNull(),
    discoveryRevision: bigint("discovery_revision", {
      mode: "bigint",
    }).notNull(),
    jwksRevision: bigint("jwks_revision", { mode: "bigint" }).notNull(),
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
    foreignKey({
      name: "platform_oidc_provider_configurations_provider_fk",
      columns: [table.providerId, table.providerKind],
      foreignColumns: [platformAuthProviders.id, platformAuthProviders.kind],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "platform_oidc_provider_configurations_kind_check",
      sql`${table.providerKind} = 'oidc'`,
    ),
    check(
      "platform_oidc_provider_configurations_revision_check",
      sql`${table.clientSecretRevision} between 1 and 9007199254740991
        and ${table.discoveryRevision} between 1 and 9007199254740991
        and ${table.jwksRevision} between 1 and 9007199254740991
        and ${table.version} between 1 and 9007199254740991`,
    ),
    check(
      "platform_oidc_provider_configurations_text_check",
      sql`${table.issuer} = btrim(${table.issuer})
        and ${table.issuer} ~ '^https://[^/?#@]+[^#?]*$'
        and char_length(${table.issuer}) between 1 and 4096
        and octet_length(convert_to(${table.clientId}, 'UTF8')) between 1 and 512
        and ${table.clientId}
          !~ U&'[\\0001-\\0020\\007F-\\00A0\\1680\\2000-\\200A\\2028\\2029\\202F\\205F\\3000]'
        and ${table.redirectUri} ~ '^https://[^/?#@]+'
        and ${table.tenantRedirectUri} ~ '^https://[^/?#@]+/api/v1/auth/federated/oidc/callback$'
        and ${table.postLogoutRedirectUri} ~ '^https://[^/?#@]+'
        and char_length(${table.redirectUri}) between 1 and 4096
        and char_length(${table.tenantRedirectUri}) between 1 and 4096
        and char_length(${table.postLogoutRedirectUri}) between 1 and 4096
        and ${table.issuer} !~ '[[:cntrl:]]'
        and ${table.clientId} !~ '[[:cntrl:]]'
        and ${table.redirectUri} !~ '[[:cntrl:]]'
        and ${table.tenantRedirectUri} !~ '[[:cntrl:]]'
        and ${table.postLogoutRedirectUri} !~ '[[:cntrl:]]'`,
    ),
    check(
      "platform_oidc_provider_configurations_scope_check",
      sql`cardinality(${table.extraScopes}) <= 31
        and array_position(${table.extraScopes}, null) is null
        and array_position(${table.extraScopes}, 'openid') is null
        and (${table.allowRefreshToken} =
          (array_position(${table.extraScopes}, 'offline_access') is not null))
        and array_to_string(${table.extraScopes}, ' ') ~
          '^$|^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}( [A-Za-z0-9][A-Za-z0-9._:/-]{0,127})*$'`,
    ),
    check(
      "platform_oidc_provider_configurations_timestamp_check",
      sql`${table.updatedAt} >= ${table.createdAt}`,
    ),
  ],
).enableRLS();

export const platformOidcClaimRules = pgTable(
  "platform_oidc_claim_rules",
  {
    providerId: uuid("provider_id").notNull(),
    source: text("source").notNull(),
    sequence: integer("sequence").notNull(),
    kind: text("kind").notNull(),
    claimName: text("claim_name").notNull(),
    profileField: text("profile_field"),
    required: boolean("required").notNull().default(false),
  },
  (table) => [
    primaryKey({
      name: "platform_oidc_claim_rules_pkey",
      columns: [table.providerId, table.source, table.sequence],
    }),
    unique("platform_oidc_claim_rules_claim_key").on(
      table.providerId,
      table.source,
      table.claimName,
    ),
    foreignKey({
      name: "platform_oidc_claim_rules_configuration_fk",
      columns: [table.providerId],
      foreignColumns: [platformOidcProviderConfigurations.providerId],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "platform_oidc_claim_rules_value_check",
      sql`${table.source} in ('id_token', 'userinfo')
        and ${table.sequence} between 0 and 1023
        and ${table.kind} in ('scalar', 'profile', 'groups', 'acr', 'amr')
        and char_length(${table.claimName}) between 1 and 256
        and ${table.claimName} ~ '^[!-~]+$'
        and ${table.claimName} !~ '["\\\\]'
        and ((${table.kind} = 'profile'
            and ${table.profileField} is not null
            and ${table.profileField} in ('username', 'email', 'display_name'))
          or (${table.kind} <> 'profile' and ${table.profileField} is null))
        and (${table.kind} not in ('acr', 'amr')
          or (${table.claimName} = ${table.kind} and not ${table.required}))`,
    ),
  ],
).enableRLS();

export const platformOidcDiscoverySnapshots = pgTable(
  "platform_oidc_discovery_snapshots",
  {
    providerId: uuid("provider_id").notNull(),
    revision: bigint("revision", { mode: "bigint" }).notNull(),
    issuer: text("issuer").notNull(),
    document: bytea("document").notNull(),
    documentDigest: bytea("document_digest").notNull(),
    retrievedAt: timestamp("retrieved_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    freshUntil: timestamp("fresh_until", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    cacheable: boolean("cacheable").notNull(),
    mustRevalidate: boolean("must_revalidate").notNull(),
    clientAuthentication: text("client_authentication").notNull(),
    signingAlgorithms: text("signing_algorithms").array().notNull(),
  },
  (table) => [
    primaryKey({
      name: "platform_oidc_discovery_snapshots_pkey",
      columns: [table.providerId, table.revision],
    }),
    foreignKey({
      name: "platform_oidc_discovery_snapshots_configuration_fk",
      columns: [table.providerId],
      foreignColumns: [platformOidcProviderConfigurations.providerId],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "platform_oidc_discovery_snapshots_value_check",
      sql`${table.revision} between 1 and 9007199254740991
        and octet_length(${table.document}) between 2 and 1048576
        and octet_length(${table.documentDigest}) = 32
        and ${table.freshUntil} between ${table.retrievedAt} and ${table.retrievedAt} + interval '7 days'
        and (${table.cacheable} or (${table.mustRevalidate} and ${table.freshUntil} = ${table.retrievedAt}))
        and ${table.clientAuthentication} in ('client_secret_basic', 'client_secret_post')
        and cardinality(${table.signingAlgorithms}) between 1 and 16
        and array_position(${table.signingAlgorithms}, null) is null`,
    ),
  ],
).enableRLS();

export const platformOidcJwksSnapshots = pgTable(
  "platform_oidc_jwks_snapshots",
  {
    providerId: uuid("provider_id").notNull(),
    revision: bigint("revision", { mode: "bigint" }).notNull(),
    document: bytea("document").notNull(),
    documentDigest: bytea("document_digest").notNull(),
    retrievedAt: timestamp("retrieved_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    freshUntil: timestamp("fresh_until", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    cacheable: boolean("cacheable").notNull(),
    mustRevalidate: boolean("must_revalidate").notNull(),
  },
  (table) => [
    primaryKey({
      name: "platform_oidc_jwks_snapshots_pkey",
      columns: [table.providerId, table.revision],
    }),
    foreignKey({
      name: "platform_oidc_jwks_snapshots_configuration_fk",
      columns: [table.providerId],
      foreignColumns: [platformOidcProviderConfigurations.providerId],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "platform_oidc_jwks_snapshots_value_check",
      sql`${table.revision} between 1 and 9007199254740991
        and octet_length(${table.document}) between 2 and 1048576
        and octet_length(${table.documentDigest}) = 32
        and ${table.freshUntil} between ${table.retrievedAt} and ${table.retrievedAt} + interval '7 days'
        and (${table.cacheable} or (${table.mustRevalidate} and ${table.freshUntil} = ${table.retrievedAt}))`,
    ),
  ],
).enableRLS();

export const platformOidcClientSecrets = pgTable(
  "platform_oidc_client_secrets",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    providerId: uuid("provider_id").notNull(),
    revision: bigint("revision", { mode: "bigint" }).notNull(),
    keyVersion: integer("key_version").notNull(),
    nonce: bytea("nonce").notNull(),
    ciphertext: bytea("ciphertext").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    retiredAt: timestamp("retired_at", { withTimezone: true, mode: "date" }),
  },
  (table) => [
    unique("platform_oidc_client_secrets_revision_key").on(
      table.providerId,
      table.revision,
    ),
    foreignKey({
      name: "platform_oidc_client_secrets_configuration_fk",
      columns: [table.providerId],
      foreignColumns: [platformOidcProviderConfigurations.providerId],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "platform_oidc_client_secrets_keyring_fk",
      columns: [table.keyVersion],
      foreignColumns: [identityKeyringVersions.keyVersion],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "platform_oidc_client_secrets_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "platform_oidc_client_secrets_envelope_check",
      sql`${table.revision} between 1 and 9007199254740991
        and ${table.keyVersion} between 1 and 32767
        and octet_length(${table.nonce}) = 12
        and octet_length(${table.ciphertext}) between 17 and 8208`,
    ),
    check(
      "platform_oidc_client_secrets_retirement_check",
      sql`${table.retiredAt} is null or ${table.retiredAt} >= ${table.createdAt}`,
    ),
  ],
).enableRLS();

export const platformSamlProviderConfigurations = pgTable(
  "platform_saml_provider_configurations",
  {
    providerId: uuid("provider_id").primaryKey(),
    providerKind: authProviderKind("provider_kind").notNull().default("saml"),
    expectedEntityId: text("expected_entity_id").notNull(),
    spEntityId: text("sp_entity_id").notNull(),
    acsUrl: text("acs_url").notNull(),
    spKeyRevision: bigint("sp_key_revision", { mode: "bigint" }).notNull(),
    metadataRevision: bigint("metadata_revision", { mode: "bigint" }).notNull(),
    redirectSignatureAlgorithm: text("redirect_signature_algorithm").notNull(),
    signaturePolicy: text("signature_policy").notNull(),
    encryptionPolicy: text("encryption_policy").notNull(),
    decryptionKeyVersions: integer("decryption_key_versions").array().notNull(),
    requestedAuthnContexts: text("requested_authn_contexts").array().notNull(),
    subjectSource: text("subject_source").notNull(),
    subjectAttributeName: text("subject_attribute_name"),
    subjectAttributeNameFormat: text("subject_attribute_name_format"),
    clockSkewNanoseconds: bigint("clock_skew_nanoseconds", {
      mode: "bigint",
    }).notNull(),
    maxAuthenticationAgeNanoseconds: bigint(
      "max_authentication_age_nanoseconds",
      { mode: "bigint" },
    ).notNull(),
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
    foreignKey({
      name: "platform_saml_provider_configurations_provider_fk",
      columns: [table.providerId, table.providerKind],
      foreignColumns: [platformAuthProviders.id, platformAuthProviders.kind],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "platform_saml_provider_configurations_kind_check",
      sql`${table.providerKind} = 'saml'`,
    ),
    check(
      "platform_saml_provider_configurations_revision_check",
      sql`${table.spKeyRevision} between 1 and 9007199254740991
        and ${table.metadataRevision} between 1 and 9007199254740991
        and ${table.version} between 1 and 9007199254740991`,
    ),
    check(
      "platform_saml_provider_configurations_policy_check",
      sql`${table.redirectSignatureAlgorithm} in (
          'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
          'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384',
          'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512',
          'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256',
          'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384',
          'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512')
        and ${table.signaturePolicy} in ('signed_assertion','signed_response','both')
        and ${table.encryptionPolicy} = 'disabled'
        and cardinality(${table.decryptionKeyVersions}) = 0
        and array_position(${table.decryptionKeyVersions}, null) is null
        and cardinality(${table.requestedAuthnContexts}) between 1 and 32
        and array_position(${table.requestedAuthnContexts}, null) is null
        and array_to_string(${table.requestedAuthnContexts}, '')
          !~ U&'[\\0001-\\0008\\000B\\000C\\000E-\\001F\\FFFE\\FFFF]'
        and ${table.clockSkewNanoseconds} between 0 and 300000000000
        and ${table.maxAuthenticationAgeNanoseconds} between 60000000000 and 86400000000000`,
    ),
    check(
      "platform_saml_provider_configurations_subject_check",
      sql`(${table.subjectSource} = 'persistent_nameid'
          and ${table.subjectAttributeName} is null
          and ${table.subjectAttributeNameFormat} is null)
        or (${table.subjectSource} = 'immutable_attribute'
          and ${table.subjectAttributeName} is not null
          and ${table.subjectAttributeNameFormat} is not null
          and octet_length(convert_to(${table.subjectAttributeName}, 'UTF8')) between 1 and 512
          and octet_length(convert_to(${table.subjectAttributeNameFormat}, 'UTF8')) between 1 and 512)`,
    ),
    check(
      "platform_saml_provider_configurations_text_check",
      sql`${table.expectedEntityId} = btrim(${table.expectedEntityId})
        and ${table.expectedEntityId} <> ${table.spEntityId}
        and ${table.expectedEntityId} ~ '^[a-z][a-z0-9+.-]*:'
        and ${table.spEntityId} ~ '^https://[^/?#@]+'
        and ${table.acsUrl} ~ '^https://[^/?#@]+'
        and octet_length(convert_to(${table.expectedEntityId}, 'UTF8')) between 1 and 2048
        and octet_length(convert_to(${table.spEntityId}, 'UTF8')) between 1 and 2048
        and octet_length(convert_to(${table.acsUrl}, 'UTF8')) between 1 and 4096
        and ${table.expectedEntityId} !~ U&'[\\0001-\\0008\\000B\\000C\\000E-\\001F\\FFFE\\FFFF]'
        and ${table.spEntityId} !~ '[[:cntrl:]]'
        and ${table.acsUrl} !~ '[[:cntrl:]]'
        and coalesce(${table.subjectAttributeName}, '')
          !~ U&'[\\0001-\\0008\\000B\\000C\\000E-\\001F\\FFFE\\FFFF]'
        and coalesce(${table.subjectAttributeNameFormat}, '')
          !~ U&'[\\0001-\\0008\\000B\\000C\\000E-\\001F\\FFFE\\FFFF]'`,
    ),
    check(
      "platform_saml_provider_configurations_timestamp_check",
      sql`${table.updatedAt} >= ${table.createdAt}`,
    ),
  ],
).enableRLS();

export const platformSamlAttributeRules = pgTable(
  "platform_saml_attribute_rules",
  {
    providerId: uuid("provider_id").notNull(),
    sequence: integer("sequence").notNull(),
    kind: text("kind").notNull(),
    attributeName: text("attribute_name").notNull(),
    attributeNameFormat: text("attribute_name_format").notNull(),
    profileField: text("profile_field"),
    required: boolean("required").notNull().default(false),
  },
  (table) => [
    primaryKey({
      name: "platform_saml_attribute_rules_pkey",
      columns: [table.providerId, table.sequence],
    }),
    foreignKey({
      name: "platform_saml_attribute_rules_configuration_fk",
      columns: [table.providerId],
      foreignColumns: [platformSamlProviderConfigurations.providerId],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "platform_saml_attribute_rules_value_check",
      sql`${table.sequence} between 0 and 1023
        and ${table.kind} in ('scalar','profile','groups')
        and octet_length(convert_to(${table.attributeName}, 'UTF8')) between 1 and 512
        and octet_length(convert_to(${table.attributeNameFormat}, 'UTF8')) between 1 and 512
        and ${table.attributeName} !~ U&'[\\0001-\\0008\\000B\\000C\\000E-\\001F\\FFFE\\FFFF]'
        and ${table.attributeNameFormat} !~ U&'[\\0001-\\0008\\000B\\000C\\000E-\\001F\\FFFE\\FFFF]'
        and ((${table.kind} = 'profile'
            and ${table.profileField} is not null
            and ${table.profileField} in ('username','email','display_name'))
          or (${table.kind} <> 'profile' and ${table.profileField} is null))`,
    ),
  ],
).enableRLS();

export const platformSamlMetadataSnapshots = pgTable(
  "platform_saml_metadata_snapshots",
  {
    providerId: uuid("provider_id").notNull(),
    revision: bigint("revision", { mode: "bigint" }).notNull(),
    document: bytea("document").notNull(),
    documentDigest: bytea("document_digest").notNull(),
    retrievedAt: timestamp("retrieved_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    maximumValidUntil: timestamp("maximum_valid_until", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
  },
  (table) => [
    primaryKey({
      name: "platform_saml_metadata_snapshots_pkey",
      columns: [table.providerId, table.revision],
    }),
    foreignKey({
      name: "platform_saml_metadata_snapshots_configuration_fk",
      columns: [table.providerId],
      foreignColumns: [platformSamlProviderConfigurations.providerId],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "platform_saml_metadata_snapshots_value_check",
      sql`${table.revision} between 1 and 9007199254740991
        and octet_length(${table.document}) between 1 and 524288
        and octet_length(${table.documentDigest}) = 32
        and ${table.maximumValidUntil} > ${table.retrievedAt}`,
    ),
  ],
).enableRLS();

export const platformSamlSpKeys = pgTable(
  "platform_saml_sp_keys",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    providerId: uuid("provider_id").notNull(),
    revision: bigint("revision", { mode: "bigint" }).notNull(),
    keyVersion: integer("key_version").notNull(),
    nonce: bytea("nonce").notNull(),
    ciphertext: bytea("ciphertext").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    retiredAt: timestamp("retired_at", { withTimezone: true, mode: "date" }),
  },
  (table) => [
    unique("platform_saml_sp_keys_revision_key").on(
      table.providerId,
      table.revision,
    ),
    foreignKey({
      name: "platform_saml_sp_keys_configuration_fk",
      columns: [table.providerId],
      foreignColumns: [platformSamlProviderConfigurations.providerId],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "platform_saml_sp_keys_keyring_fk",
      columns: [table.keyVersion],
      foreignColumns: [identityKeyringVersions.keyVersion],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "platform_saml_sp_keys_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "platform_saml_sp_keys_envelope_check",
      sql`${table.revision} between 1 and 9007199254740991
        and ${table.keyVersion} between 1 and 32767
        and octet_length(${table.nonce}) = 12
        and octet_length(${table.ciphertext}) between 17 and 131072`,
    ),
    check(
      "platform_saml_sp_keys_retirement_check",
      sql`${table.retiredAt} is null or ${table.retiredAt} >= ${table.createdAt}`,
    ),
  ],
).enableRLS();

export const platformSamlSpCertificates = pgTable(
  "platform_saml_sp_certificates",
  {
    keyId: uuid("key_id").notNull(),
    sequence: integer("sequence").notNull(),
    certificateDer: bytea("certificate_der").notNull(),
    notBefore: timestamp("not_before", { withTimezone: true, mode: "date" }),
    notAfter: timestamp("not_after", { withTimezone: true, mode: "date" }),
  },
  (table) => [
    primaryKey({
      name: "platform_saml_sp_certificates_pkey",
      columns: [table.keyId, table.sequence],
    }),
    unique("platform_saml_sp_certificates_value_key").on(
      table.keyId,
      table.certificateDer,
    ),
    foreignKey({
      name: "platform_saml_sp_certificates_key_fk",
      columns: [table.keyId],
      foreignColumns: [platformSamlSpKeys.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "platform_saml_sp_certificates_value_check",
      sql`${table.sequence} between 0 and 7
        and octet_length(${table.certificateDer}) between 1 and 65536
        and ((${table.notBefore} is null and ${table.notAfter} is null)
          or (${table.notBefore} is not null and ${table.notAfter} is not null
            and ${table.notBefore} < ${table.notAfter}))`,
    ),
  ],
).enableRLS();

/** Exact assurance translations for platform login; claims never grant roles. */
export const platformFederatedTrustRules = pgTable(
  "platform_federated_trust_rules",
  {
    id: uuid("id")
      .notNull()
      .default(sql`uuidv7()`),
    providerId: uuid("provider_id").notNull(),
    providerKind: authProviderKind("provider_kind").notNull(),
    revision: bigint("revision", { mode: "bigint" }).notNull(),
    enabled: boolean("enabled").notNull().default(false),
    level: text("level").notNull(),
    exactValue: text("exact_value"),
    requiredValues: text("required_values")
      .array()
      .notNull()
      .default(sql`ARRAY[]::text[]`),
    maximumAuthenticationAgeSeconds: integer(
      "maximum_authentication_age_seconds",
    ).notNull(),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    retiredAt: timestamp("retired_at", { withTimezone: true, mode: "date" }),
  },
  (table) => [
    primaryKey({
      name: "platform_federated_trust_rules_pkey",
      columns: [table.id, table.revision],
    }),
    uniqueIndex("platform_federated_trust_rules_live_key")
      .on(table.id)
      .where(sql`${table.retiredAt} is null`),
    uniqueIndex("platform_federated_trust_rules_live_saml_exact_key")
      .on(table.providerId, table.exactValue)
      .where(
        sql`${table.providerKind} = 'saml' and ${table.retiredAt} is null`,
      ),
    index("platform_federated_trust_rules_provider_idx").on(
      table.providerId,
      table.id,
    ),
    foreignKey({
      name: "platform_federated_trust_rules_policy_fk",
      columns: [table.providerId, table.providerKind],
      foreignColumns: [
        platformFederatedProviderPolicies.providerId,
        platformFederatedProviderPolicies.providerKind,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "platform_federated_trust_rules_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "platform_federated_trust_rules_value_check",
      sql`${table.providerKind} in ('oidc','saml')
        and ${table.revision} between 1 and 9007199254740991
        and ${table.level} in ('mfa','phishing_resistant')
        and ${table.maximumAuthenticationAgeSeconds} between 60 and 2592000
        and cardinality(${table.requiredValues}) <= 128
        and array_position(${table.requiredValues}, null) is null
        and (${table.exactValue} is null or (
          char_length(${table.exactValue}) between 1 and 4096
          and octet_length(convert_to(${table.exactValue}, 'UTF8')) <= 4096
          and ${table.exactValue}
            !~ U&'[\\0001-\\001F\\007F-\\009F\\200E\\200F\\202A-\\202E\\2066-\\2069]'))
        and array_to_string(${table.requiredValues}, '')
          !~ U&'[\\0001-\\001F\\007F-\\009F\\200E\\200F\\202A-\\202E\\2066-\\2069]'
        and ((${table.providerKind} = 'oidc'
            and (${table.exactValue} is not null or cardinality(${table.requiredValues}) > 0))
          or (${table.providerKind} = 'saml'
            and ${table.exactValue} is not null
            and cardinality(${table.requiredValues}) = 0))`,
    ),
    check(
      "platform_federated_trust_rules_retirement_check",
      sql`${table.retiredAt} is null or ${table.retiredAt} >= ${table.createdAt}`,
    ),
  ],
).enableRLS();
