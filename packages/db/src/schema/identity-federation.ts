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
import {
  tenantAuthorizationSources,
  tenantRoles,
  tenantSecurityGroups,
} from "./authorization.js";
import { bytea } from "./binary.js";
import {
  authProviderKind,
  identitySubjectFormat,
  tenantPrincipalKind,
} from "./enums.js";
import {
  tenantAuthProviderBindings,
  tenantIdentityProviderAccessEpochs,
} from "./identity-access.js";
import {
  authSessionMfaStates,
  tenantMfaSubjects,
  tenantPostPrimaryContinuations,
} from "./identity-mfa.js";
import {
  identityKeyringVersions,
  tenantAuthProviders,
} from "./identity-providers.js";
import { tenantMemberships, users } from "./identity.js";
import { operatorTeamAssignmentEpochs } from "./operator-teams.js";
import { tenants } from "./tenancy.js";

/**
 * Live, typed runtime pins shared by one tenant-owned OIDC or SAML provider.
 * Protocol documents and secrets remain in discriminator-specific children.
 */
export const tenantFederatedProviderPolicies = pgTable(
  "tenant_federated_provider_policies",
  {
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    providerId: uuid("provider_id").notNull(),
    bindingId: uuid("binding_id").notNull(),
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
    jitMode: text("jit_mode").notNull().default("disabled"),
    noMatchPolicy: text("no_match_policy").notNull().default("deny"),
    enabled: boolean("enabled").notNull().default(false),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    primaryKey({
      name: "tenant_federated_provider_policies_pkey",
      columns: [table.tenantId, table.providerId],
    }),
    unique("tenant_federated_provider_policies_binding_key").on(
      table.tenantId,
      table.bindingId,
      table.providerId,
    ),
    unique("tenant_federated_provider_policies_kind_key").on(
      table.tenantId,
      table.bindingId,
      table.providerId,
      table.providerKind,
    ),
    foreignKey({
      name: "tenant_federated_provider_policies_provider_fk",
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
      name: "tenant_federated_provider_policies_binding_fk",
      columns: [table.tenantId, table.bindingId, table.providerId],
      foreignColumns: [
        tenantAuthProviderBindings.tenantId,
        tenantAuthProviderBindings.id,
        tenantAuthProviderBindings.providerId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "tenant_federated_provider_policies_kind_check",
      sql`${table.providerKind} in ('oidc', 'saml')`,
    ),
    check(
      "tenant_federated_provider_policies_revision_check",
      sql`${table.configurationRevision} > 0
        and ${table.securityRevision} > 0
        and ${table.planRevision} > 0
        and ${table.assurancePolicyRevision} > 0`,
    ),
    check(
      "tenant_federated_provider_policies_admission_check",
      sql`${table.jitMode} in ('disabled', 'create')
        and ${table.noMatchPolicy} in ('deny', 'provider_access_only')`,
    ),
    check(
      "tenant_federated_provider_policies_timestamp_check",
      sql`${table.updatedAt} >= ${table.createdAt}`,
    ),
  ],
).enableRLS();

export const tenantOidcProviderConfigurations = pgTable(
  "tenant_oidc_provider_configurations",
  {
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    providerId: uuid("provider_id").notNull(),
    providerKind: authProviderKind("provider_kind").notNull().default("oidc"),
    issuer: text("issuer").notNull(),
    clientId: text("client_id"),
    redirectUri: text("redirect_uri").notNull(),
    postLogoutRedirectUri: text("post_logout_redirect_uri"),
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
    primaryKey({
      name: "tenant_oidc_provider_configurations_pkey",
      columns: [table.tenantId, table.providerId],
    }),
    foreignKey({
      name: "tenant_oidc_provider_configurations_policy_fk",
      columns: [table.tenantId, table.providerId, table.providerKind],
      foreignColumns: [
        tenantAuthProviders.tenantId,
        tenantAuthProviders.id,
        tenantAuthProviders.kind,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "tenant_oidc_provider_configurations_kind_check",
      sql`${table.providerKind} = 'oidc'`,
    ),
    check(
      "tenant_oidc_provider_configurations_revision_check",
      sql`${table.clientSecretRevision} between 1 and 9007199254740991
        and ${table.discoveryRevision} between 1 and 9007199254740991
        and ${table.jwksRevision} between 1 and 9007199254740991
        and ${table.version} between 1 and 9007199254740991`,
    ),
    check(
      "tenant_oidc_provider_configurations_text_check",
      sql`char_length(${table.issuer}) between 1 and 4096
        and octet_length(convert_to(${table.clientId}, 'UTF8')) between 1 and 512
        and char_length(${table.redirectUri}) between 1 and 4096
        and char_length(${table.postLogoutRedirectUri}) between 1 and 4096
        and ${table.issuer} !~ '[[:cntrl:]]'
        and ${table.clientId} !~ U&'[\\0001-\\0020\\007F-\\00A0\\1680\\2000-\\200A\\2028\\2029\\202F\\205F\\3000]'
        and ${table.redirectUri} !~ '[[:cntrl:]]'
        and ${table.postLogoutRedirectUri} !~ '[[:cntrl:]]'`,
    ),
    check(
      "tenant_oidc_provider_configurations_scope_check",
      sql`cardinality(${table.extraScopes}) <= 31
        and array_position(${table.extraScopes}, null) is null
        and array_position(${table.extraScopes}, 'openid') is null
        and (${table.allowRefreshToken} =
          (array_position(${table.extraScopes}, 'offline_access') is not null))`,
    ),
    check(
      "tenant_oidc_provider_configurations_timestamp_check",
      sql`${table.updatedAt} >= ${table.createdAt}`,
    ),
  ],
).enableRLS();

/** Exact, ordered OIDC claim extraction rules; claim values never persist. */
export const tenantOidcClaimRules = pgTable(
  "tenant_oidc_claim_rules",
  {
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
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
      name: "tenant_oidc_claim_rules_pkey",
      columns: [table.tenantId, table.providerId, table.source, table.sequence],
    }),
    unique("tenant_oidc_claim_rules_claim_key").on(
      table.tenantId,
      table.providerId,
      table.source,
      table.claimName,
    ),
    foreignKey({
      name: "tenant_oidc_claim_rules_configuration_fk",
      columns: [table.tenantId, table.providerId],
      foreignColumns: [
        tenantOidcProviderConfigurations.tenantId,
        tenantOidcProviderConfigurations.providerId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "tenant_oidc_claim_rules_value_check",
      sql`${table.source} in ('id_token', 'userinfo')
        and ${table.sequence} between 0 and 1023
        and ${table.kind} in ('scalar', 'profile', 'groups', 'acr', 'amr')
        and char_length(${table.claimName}) between 1 and 256
        and ${table.claimName} ~ '^[!-~]+$'
        and ${table.claimName} !~ '["\\\\]'
        and ((${table.kind} = 'profile'
            and ${table.profileField} in ('username', 'email', 'display_name'))
          or (${table.kind} <> 'profile' and ${table.profileField} is null))
        and (${table.kind} not in ('acr', 'amr')
          or (${table.claimName} = ${table.kind} and not ${table.required}))`,
    ),
  ],
).enableRLS();

export const tenantOidcDiscoverySnapshots = pgTable(
  "tenant_oidc_discovery_snapshots",
  {
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
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
      name: "tenant_oidc_discovery_snapshots_pkey",
      columns: [table.tenantId, table.providerId, table.revision],
    }),
    foreignKey({
      name: "tenant_oidc_discovery_snapshots_configuration_fk",
      columns: [table.tenantId, table.providerId],
      foreignColumns: [
        tenantOidcProviderConfigurations.tenantId,
        tenantOidcProviderConfigurations.providerId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "tenant_oidc_discovery_snapshots_revision_check",
      sql`${table.revision} > 0`,
    ),
    check(
      "tenant_oidc_discovery_snapshots_document_check",
      sql`octet_length(${table.document}) between 2 and 1048576
        and octet_length(${table.documentDigest}) = 32`,
    ),
    check(
      "tenant_oidc_discovery_snapshots_cache_check",
      sql`${table.freshUntil} between ${table.retrievedAt} and ${table.retrievedAt} + interval '7 days'
        and (${table.cacheable} or (${table.mustRevalidate} and ${table.freshUntil} = ${table.retrievedAt}))`,
    ),
    check(
      "tenant_oidc_discovery_snapshots_policy_check",
      sql`${table.clientAuthentication} in ('client_secret_basic', 'client_secret_post')
        and cardinality(${table.signingAlgorithms}) between 1 and 16`,
    ),
  ],
).enableRLS();

export const tenantOidcJwksSnapshots = pgTable(
  "tenant_oidc_jwks_snapshots",
  {
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
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
      name: "tenant_oidc_jwks_snapshots_pkey",
      columns: [table.tenantId, table.providerId, table.revision],
    }),
    foreignKey({
      name: "tenant_oidc_jwks_snapshots_configuration_fk",
      columns: [table.tenantId, table.providerId],
      foreignColumns: [
        tenantOidcProviderConfigurations.tenantId,
        tenantOidcProviderConfigurations.providerId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "tenant_oidc_jwks_snapshots_revision_check",
      sql`${table.revision} > 0`,
    ),
    check(
      "tenant_oidc_jwks_snapshots_document_check",
      sql`octet_length(${table.document}) between 2 and 1048576
        and octet_length(${table.documentDigest}) = 32`,
    ),
    check(
      "tenant_oidc_jwks_snapshots_cache_check",
      sql`${table.freshUntil} between ${table.retrievedAt} and ${table.retrievedAt} + interval '7 days'
        and (${table.cacheable} or (${table.mustRevalidate} and ${table.freshUntil} = ${table.retrievedAt}))`,
    ),
  ],
).enableRLS();

export const tenantOidcClientSecrets = pgTable(
  "tenant_oidc_client_secrets",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
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
    unique("tenant_oidc_client_secrets_revision_key").on(
      table.tenantId,
      table.providerId,
      table.revision,
    ),
    foreignKey({
      name: "tenant_oidc_client_secrets_configuration_fk",
      columns: [table.tenantId, table.providerId],
      foreignColumns: [
        tenantOidcProviderConfigurations.tenantId,
        tenantOidcProviderConfigurations.providerId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_oidc_client_secrets_keyring_fk",
      columns: [table.keyVersion],
      foreignColumns: [identityKeyringVersions.keyVersion],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "tenant_oidc_client_secrets_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "tenant_oidc_client_secrets_envelope_check",
      sql`${table.revision} > 0 and ${table.keyVersion} between 1 and 32767
        and octet_length(${table.nonce}) = 12
        and octet_length(${table.ciphertext}) between 17 and 8208`,
    ),
    check(
      "tenant_oidc_client_secrets_retirement_check",
      sql`${table.retiredAt} is null or ${table.retiredAt} >= ${table.createdAt}`,
    ),
  ],
).enableRLS();

export const tenantSamlProviderConfigurations = pgTable(
  "tenant_saml_provider_configurations",
  {
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    providerId: uuid("provider_id").notNull(),
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
      {
        mode: "bigint",
      },
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
    primaryKey({
      name: "tenant_saml_provider_configurations_pkey",
      columns: [table.tenantId, table.providerId],
    }),
    foreignKey({
      name: "tenant_saml_provider_configurations_provider_fk",
      columns: [table.tenantId, table.providerId, table.providerKind],
      foreignColumns: [
        tenantAuthProviders.tenantId,
        tenantAuthProviders.id,
        tenantAuthProviders.kind,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "tenant_saml_provider_configurations_kind_check",
      sql`${table.providerKind} = 'saml'`,
    ),
    check(
      "tenant_saml_provider_configurations_revision_check",
      sql`${table.spKeyRevision} between 1 and 9007199254740991
        and ${table.metadataRevision} between 1 and 9007199254740991
        and ${table.version} between 1 and 9007199254740991`,
    ),
    check(
      "tenant_saml_provider_configurations_policy_check",
      sql`${table.redirectSignatureAlgorithm} in (
          'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
          'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384',
          'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512',
          'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256',
          'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384',
          'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512')
        and ${table.signaturePolicy} in ('signed_assertion','signed_response','both')
        and ${table.encryptionPolicy} in ('disabled','optional','required')
        and ((${table.encryptionPolicy} = 'disabled'
            and cardinality(${table.decryptionKeyVersions}) = 0)
          or (${table.encryptionPolicy} in ('optional','required')
            and cardinality(${table.decryptionKeyVersions}) between 1 and 8))
        and array_position(${table.decryptionKeyVersions}, null) is null
        and cardinality(${table.requestedAuthnContexts}) between 1 and 32
        and array_position(${table.requestedAuthnContexts}, null) is null
        and array_to_string(${table.requestedAuthnContexts}, '')
          !~ U&'[\\0001-\\0008\\000B\\000C\\000E-\\001F\\FFFE\\FFFF]'
        and ${table.clockSkewNanoseconds} between 0 and 300000000000
        and ${table.maxAuthenticationAgeNanoseconds} between 60000000000 and 86400000000000`,
    ),
    check(
      "tenant_saml_provider_configurations_subject_check",
      sql`(${table.subjectSource} = 'persistent_nameid'
          and ${table.subjectAttributeName} is null
          and ${table.subjectAttributeNameFormat} is null)
        or (${table.subjectSource} = 'immutable_attribute'
          and octet_length(convert_to(${table.subjectAttributeName}, 'UTF8')) between 1 and 512
          and octet_length(convert_to(${table.subjectAttributeNameFormat}, 'UTF8')) between 1 and 512)`,
    ),
    check(
      "tenant_saml_provider_configurations_text_check",
      sql`${table.expectedEntityId} <> ${table.spEntityId}
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
      "tenant_saml_provider_configurations_timestamp_check",
      sql`${table.updatedAt} >= ${table.createdAt}`,
    ),
  ],
).enableRLS();

export const tenantSamlAttributeRules = pgTable(
  "tenant_saml_attribute_rules",
  {
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
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
      name: "tenant_saml_attribute_rules_pkey",
      columns: [table.tenantId, table.providerId, table.sequence],
    }),
    foreignKey({
      name: "tenant_saml_attribute_rules_configuration_fk",
      columns: [table.tenantId, table.providerId],
      foreignColumns: [
        tenantSamlProviderConfigurations.tenantId,
        tenantSamlProviderConfigurations.providerId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "tenant_saml_attribute_rules_value_check",
      sql`${table.sequence} between 0 and 1023
        and ${table.kind} in ('scalar','profile','groups')
        and octet_length(convert_to(${table.attributeName}, 'UTF8')) between 1 and 512
        and octet_length(convert_to(${table.attributeNameFormat}, 'UTF8')) between 1 and 512
        and ${table.attributeName} !~ U&'[\\0001-\\0008\\000B\\000C\\000E-\\001F\\FFFE\\FFFF]'
        and ${table.attributeNameFormat} !~ U&'[\\0001-\\0008\\000B\\000C\\000E-\\001F\\FFFE\\FFFF]'
        and ((${table.kind} = 'profile'
            and ${table.profileField} in ('username','email','display_name'))
          or (${table.kind} <> 'profile' and ${table.profileField} is null))`,
    ),
  ],
).enableRLS();

export const tenantSamlMetadataSnapshots = pgTable(
  "tenant_saml_metadata_snapshots",
  {
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
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
      name: "tenant_saml_metadata_snapshots_pkey",
      columns: [table.tenantId, table.providerId, table.revision],
    }),
    foreignKey({
      name: "tenant_saml_metadata_snapshots_configuration_fk",
      columns: [table.tenantId, table.providerId],
      foreignColumns: [
        tenantSamlProviderConfigurations.tenantId,
        tenantSamlProviderConfigurations.providerId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "tenant_saml_metadata_snapshots_revision_check",
      sql`${table.revision} > 0`,
    ),
    check(
      "tenant_saml_metadata_snapshots_document_check",
      sql`octet_length(${table.document}) between 1 and 524288
        and octet_length(${table.documentDigest}) = 32
        and ${table.maximumValidUntil} > ${table.retrievedAt}`,
    ),
  ],
).enableRLS();

export const tenantSamlSpKeys = pgTable(
  "tenant_saml_sp_keys",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    providerId: uuid("provider_id").notNull(),
    revision: bigint("revision", { mode: "bigint" }).notNull(),
    keyVersion: integer("key_version").notNull(),
    ciphertext: bytea("ciphertext").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    retiredAt: timestamp("retired_at", { withTimezone: true, mode: "date" }),
  },
  (table) => [
    unique("tenant_saml_sp_keys_tenant_id_key").on(table.tenantId, table.id),
    unique("tenant_saml_sp_keys_revision_key").on(
      table.tenantId,
      table.providerId,
      table.revision,
    ),
    foreignKey({
      name: "tenant_saml_sp_keys_configuration_fk",
      columns: [table.tenantId, table.providerId],
      foreignColumns: [
        tenantSamlProviderConfigurations.tenantId,
        tenantSamlProviderConfigurations.providerId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_saml_sp_keys_keyring_fk",
      columns: [table.keyVersion],
      foreignColumns: [identityKeyringVersions.keyVersion],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "tenant_saml_sp_keys_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "tenant_saml_sp_keys_envelope_check",
      sql`${table.revision} > 0 and ${table.keyVersion} between 1 and 32767
        and octet_length(${table.ciphertext}) between 17 and 131072`,
    ),
    check(
      "tenant_saml_sp_keys_retirement_check",
      sql`${table.retiredAt} is null or ${table.retiredAt} >= ${table.createdAt}`,
    ),
  ],
).enableRLS();

export const tenantSamlSpCertificates = pgTable(
  "tenant_saml_sp_certificates",
  {
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    keyId: uuid("key_id").notNull(),
    sequence: integer("sequence").notNull(),
    certificateDer: bytea("certificate_der").notNull(),
    notBefore: timestamp("not_before", { withTimezone: true, mode: "date" }),
    notAfter: timestamp("not_after", { withTimezone: true, mode: "date" }),
  },
  (table) => [
    primaryKey({
      name: "tenant_saml_sp_certificates_pkey",
      columns: [table.tenantId, table.keyId, table.sequence],
    }),
    unique("tenant_saml_sp_certificates_value_key").on(
      table.tenantId,
      table.keyId,
      table.certificateDer,
    ),
    foreignKey({
      name: "tenant_saml_sp_certificates_key_fk",
      columns: [table.tenantId, table.keyId],
      foreignColumns: [tenantSamlSpKeys.tenantId, tenantSamlSpKeys.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "tenant_saml_sp_certificates_value_check",
      sql`${table.sequence} between 0 and 7
        and octet_length(${table.certificateDer}) between 1 and 65536
        and ((${table.notBefore} is null and ${table.notAfter} is null)
          or (${table.notBefore} is not null and ${table.notAfter} is not null
            and ${table.notBefore} < ${table.notAfter}))`,
    ),
  ],
).enableRLS();

/** Exact provider assurance translations; mutable display labels are absent. */
export const tenantFederatedTrustRules = pgTable(
  "tenant_federated_trust_rules",
  {
    id: uuid("id")
      .notNull()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    providerId: uuid("provider_id").notNull(),
    bindingId: uuid("binding_id").notNull(),
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
      name: "tenant_federated_trust_rules_pkey",
      columns: [table.tenantId, table.id, table.revision],
    }),
    uniqueIndex("tenant_federated_trust_rules_live_key")
      .on(table.tenantId, table.id)
      .where(sql`${table.retiredAt} is null`),
    uniqueIndex("tenant_federated_trust_rules_live_saml_exact_key")
      .on(table.tenantId, table.providerId, table.exactValue)
      .where(
        sql`${table.providerKind} = 'saml' and ${table.retiredAt} is null`,
      ),
    index("tenant_federated_trust_rules_provider_idx").on(
      table.tenantId,
      table.providerId,
      table.bindingId,
      table.id,
    ),
    foreignKey({
      name: "tenant_federated_trust_rules_policy_fk",
      columns: [
        table.tenantId,
        table.bindingId,
        table.providerId,
        table.providerKind,
      ],
      foreignColumns: [
        tenantFederatedProviderPolicies.tenantId,
        tenantFederatedProviderPolicies.bindingId,
        tenantFederatedProviderPolicies.providerId,
        tenantFederatedProviderPolicies.providerKind,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "tenant_federated_trust_rules_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "tenant_federated_trust_rules_value_check",
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
      "tenant_federated_trust_rules_retirement_check",
      sql`${table.retiredAt} is null or ${table.retiredAt} >= ${table.createdAt}`,
    ),
  ],
).enableRLS();

/** Provider-qualified immutable tenant identities; email never links accounts. */
export const tenantFederatedExternalIdentities = pgTable(
  "tenant_federated_external_identities",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    providerId: uuid("provider_id").notNull(),
    bindingId: uuid("binding_id").notNull(),
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
    lastObservedAt: timestamp("last_observed_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    retiredAt: timestamp("retired_at", { withTimezone: true, mode: "date" }),
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
    unique("tenant_federated_external_identities_tenant_id_key").on(
      table.tenantId,
      table.id,
    ),
    unique("tenant_federated_external_identities_provider_key").on(
      table.tenantId,
      table.providerId,
      table.id,
    ),
    unique("tenant_federated_external_identities_exact_key").on(
      table.tenantId,
      table.providerId,
      table.id,
      table.userId,
    ),
    uniqueIndex("tenant_federated_external_identities_live_provider_user_key")
      .on(table.tenantId, table.providerId, table.userId)
      .where(sql`${table.retiredAt} is null`),
    foreignKey({
      name: "tenant_federated_external_identities_policy_fk",
      columns: [table.tenantId, table.bindingId, table.providerId],
      foreignColumns: [
        tenantFederatedProviderPolicies.tenantId,
        tenantFederatedProviderPolicies.bindingId,
        tenantFederatedProviderPolicies.providerId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_federated_external_identities_keyring_fk",
      columns: [table.keyVersion],
      foreignColumns: [identityKeyringVersions.keyVersion],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_federated_external_identities_subject_fk",
      columns: [table.tenantId, table.userId],
      foreignColumns: [tenantMfaSubjects.tenantId, tenantMfaSubjects.userId],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "tenant_federated_external_identities_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "tenant_federated_external_identities_subject_check",
      sql`${table.subjectFormat} = 'utf8_exact'
        and octet_length(${table.subjectCiphertext}) between 17 and 4112
        and octet_length(${table.subjectNonce}) = 12
        and ${table.keyVersion} between 1 and 32767`,
    ),
    check(
      "tenant_federated_external_identities_lifecycle_check",
      sql`${table.admittedConfigurationRevision} > 0 and ${table.version} > 0
        and ${table.lastObservedAt} >= ${table.createdAt}
        and ${table.updatedAt} >= ${table.createdAt}
        and (${table.retiredAt} is null or (${table.retiredAt} >= ${table.createdAt}
          and ${table.updatedAt} >= ${table.retiredAt}))`,
    ),
  ],
).enableRLS();

export const tenantFederatedExternalIdentityAliases = pgTable(
  "tenant_federated_external_identity_aliases",
  {
    id: uuid("id")
      .notNull()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    providerId: uuid("provider_id").notNull(),
    externalIdentityId: uuid("external_identity_id").notNull(),
    keyVersion: integer("key_version").notNull(),
    subjectDigest: bytea("subject_digest").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    retiredAt: timestamp("retired_at", { withTimezone: true, mode: "date" }),
  },
  (table) => [
    primaryKey({
      name: "tenant_federated_external_identity_aliases_pkey",
      columns: [table.tenantId, table.id],
    }),
    unique("tenant_federated_external_identity_aliases_digest_key").on(
      table.tenantId,
      table.providerId,
      table.keyVersion,
      table.subjectDigest,
    ),
    unique("tenant_federated_external_identity_aliases_version_key").on(
      table.tenantId,
      table.externalIdentityId,
      table.keyVersion,
    ),
    foreignKey({
      name: "tenant_federated_external_identity_aliases_identity_fk",
      columns: [table.tenantId, table.providerId, table.externalIdentityId],
      foreignColumns: [
        tenantFederatedExternalIdentities.tenantId,
        tenantFederatedExternalIdentities.providerId,
        tenantFederatedExternalIdentities.id,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_federated_external_identity_aliases_keyring_fk",
      columns: [table.keyVersion],
      foreignColumns: [identityKeyringVersions.keyVersion],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "tenant_federated_external_identity_aliases_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "tenant_federated_external_identity_aliases_digest_check",
      sql`${table.keyVersion} between 1 and 32767 and octet_length(${table.subjectDigest}) = 32`,
    ),
    check(
      "tenant_federated_external_identity_aliases_lifecycle_check",
      sql`${table.retiredAt} is null or ${table.retiredAt} >= ${table.createdAt}`,
    ),
  ],
).enableRLS();

/**
 * Immutable mapping authority for OIDC/SAML. Claim values observed at login are
 * never persisted; only administrator-authored exact matchers live here.
 */
export const tenantFederatedMappingRuleEpochs = pgTable(
  "tenant_federated_mapping_rule_epochs",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    ruleId: uuid("rule_id").notNull(),
    providerId: uuid("provider_id").notNull(),
    bindingId: uuid("binding_id").notNull(),
    providerKind: authProviderKind("provider_kind").notNull(),
    sourceId: uuid("source_id").notNull(),
    sequence: integer("sequence").notNull(),
    revision: bigint("revision", { mode: "bigint" }).notNull(),
    mappingRevision: bigint("mapping_revision", { mode: "bigint" }).notNull(),
    priority: integer("priority").notNull(),
    matcherKind: text("matcher_kind").notNull(),
    claimName: text("claim_name"),
    matcherValue: text("matcher_value").notNull(),
    reconciliationMode: text("reconciliation_mode").notNull(),
    tenantSecurityGroupId: uuid("tenant_security_group_id").notNull(),
    operatorTeamId: uuid("operator_team_id"),
    operatorTeamAssignmentEpochId: uuid("operator_team_assignment_epoch_id"),
    enabled: boolean("enabled").notNull().default(false),
    activatedAt: timestamp("activated_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    endedAt: timestamp("ended_at", { withTimezone: true, mode: "date" }),
  },
  (table) => [
    unique("tenant_federated_mapping_rule_epochs_tenant_id_key").on(
      table.tenantId,
      table.id,
    ),
    unique("tenant_federated_mapping_rule_epochs_exact_key").on(
      table.tenantId,
      table.id,
      table.ruleId,
      table.bindingId,
      table.sourceId,
    ),
    unique("tenant_federated_mapping_rule_epochs_source_key").on(
      table.tenantId,
      table.sourceId,
    ),
    unique("tenant_federated_mapping_rule_epochs_sequence_key").on(
      table.tenantId,
      table.bindingId,
      table.mappingRevision,
      table.sequence,
    ),
    uniqueIndex("tenant_federated_mapping_rule_epochs_live_rule_key")
      .on(table.tenantId, table.ruleId)
      .where(sql`${table.endedAt} is null`),
    index("tenant_federated_mapping_rule_epochs_planning_idx").on(
      table.tenantId,
      table.bindingId,
      table.mappingRevision,
      table.enabled,
      table.priority,
      table.ruleId,
    ),
    foreignKey({
      name: "tenant_federated_mapping_rule_epochs_policy_fk",
      columns: [
        table.tenantId,
        table.bindingId,
        table.providerId,
        table.providerKind,
      ],
      foreignColumns: [
        tenantFederatedProviderPolicies.tenantId,
        tenantFederatedProviderPolicies.bindingId,
        tenantFederatedProviderPolicies.providerId,
        tenantFederatedProviderPolicies.providerKind,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_federated_mapping_rule_epochs_source_fk",
      columns: [table.tenantId, table.sourceId],
      foreignColumns: [
        tenantAuthorizationSources.tenantId,
        tenantAuthorizationSources.id,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_federated_mapping_rule_epochs_group_fk",
      columns: [table.tenantId, table.tenantSecurityGroupId],
      foreignColumns: [tenantSecurityGroups.tenantId, tenantSecurityGroups.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_federated_mapping_rule_epochs_team_fk",
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
    check(
      "tenant_federated_mapping_rule_epochs_id_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true
        and (uuid_extract_version(${table.ruleId}) = 7) is true`,
    ),
    check(
      "tenant_federated_mapping_rule_epochs_matcher_check",
      sql`(${table.matcherKind} = 'group_equals'
          and ${table.claimName} is null)
        or (${table.matcherKind} = 'scalar_equals'
          and btrim(${table.claimName}) = ${table.claimName}
          and char_length(${table.claimName}) between 1 and 256
          and ${table.claimName} ~ '^[!-~]+$'
          and ${table.claimName} !~ '["\\\\]')`,
    ),
    check(
      "tenant_federated_mapping_rule_epochs_value_check",
      sql`${table.sequence} between 1 and 2000
        and ${table.revision} > 0 and ${table.mappingRevision} > 0
        and ${table.priority} between 0 and 1000000
        and ${table.reconciliationMode} in ('additive','authoritative')
        and btrim(${table.matcherValue}) <> ''
        and char_length(${table.matcherValue}) <= 1024
        and octet_length(${table.matcherValue}) <= 4096
        and ${table.matcherValue}
          !~ U&'[\\0001-\\001F\\007F-\\009F\\200E\\200F\\202A-\\202E\\2066-\\2069]'`,
    ),
    check(
      "tenant_federated_mapping_rule_epochs_team_check",
      sql`(${table.operatorTeamId} is null) = (${table.operatorTeamAssignmentEpochId} is null)`,
    ),
    check(
      "tenant_federated_mapping_rule_epochs_lifecycle_check",
      sql`(${table.enabled} and ${table.endedAt} is null)
        or (not ${table.enabled} and (${table.endedAt} is null or ${table.endedAt} >= ${table.activatedAt}))`,
    ),
  ],
).enableRLS();

export const tenantFederatedMappingRuleRoleTargets = pgTable(
  "tenant_federated_mapping_rule_role_targets",
  {
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    ruleEpochId: uuid("rule_epoch_id").notNull(),
    roleId: uuid("role_id").notNull(),
    rolePrincipalKind: tenantPrincipalKind("role_principal_kind")
      .notNull()
      .default("human"),
  },
  (table) => [
    primaryKey({
      name: "tenant_federated_mapping_rule_role_targets_pkey",
      columns: [table.tenantId, table.ruleEpochId, table.roleId],
    }),
    foreignKey({
      name: "tenant_federated_mapping_rule_role_targets_epoch_fk",
      columns: [table.tenantId, table.ruleEpochId],
      foreignColumns: [
        tenantFederatedMappingRuleEpochs.tenantId,
        tenantFederatedMappingRuleEpochs.id,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_federated_mapping_rule_role_targets_role_fk",
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
      "tenant_federated_mapping_rule_role_targets_human_check",
      sql`${table.rolePrincipalKind} = 'human'`,
    ),
  ],
).enableRLS();

/** Bounded one-flow OIDC/SAML browser transaction. */
export const tenantFederatedAuthenticationTransactions = pgTable(
  "tenant_federated_authentication_transactions",
  {
    transactionId: bytea("transaction_id").notNull(),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    providerId: uuid("provider_id").notNull(),
    bindingId: uuid("binding_id").notNull(),
    providerKind: authProviderKind("provider_kind").notNull(),
    protocol: text("protocol").notNull(),
    operationRunId: uuid("operation_run_id").notNull(),
    operationDigest: bytea("operation_digest").notNull(),
    receiptDigest: bytea("receipt_digest").notNull(),
    networkDigest: bytea("network_digest").notNull(),
    accountDigest: bytea("account_digest").notNull(),
    providerDigest: bytea("provider_digest").notNull(),
    stateDigest: bytea("state_digest"),
    relayStateDigest: bytea("relay_state_digest"),
    browserDigest: bytea("browser_digest").notNull(),
    nonceDigest: bytea("nonce_digest"),
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
    clientSecretRevision: bigint("client_secret_revision", { mode: "bigint" }),
    discoveryRevision: bigint("discovery_revision", { mode: "bigint" }),
    discoveryDigest: bytea("discovery_digest"),
    jwksRevision: bigint("jwks_revision", { mode: "bigint" }),
    jwksDigest: bytea("jwks_digest"),
    verifierKeyVersion: integer("verifier_key_version"),
    verifierCiphertext: bytea("verifier_ciphertext"),
    clientId: text("client_id"),
    redirectUri: text("redirect_uri"),
    postLogoutRedirectUri: text("post_logout_redirect_uri"),
    scopes: text("scopes").array(),
    allowRefreshToken: boolean("allow_refresh_token"),
    useUserInfo: boolean("use_user_info"),
    metadataRevision: bigint("metadata_revision", { mode: "bigint" }),
    metadataDigest: bytea("metadata_digest"),
    spKeyRevision: bigint("sp_key_revision", { mode: "bigint" }),
    configurationDigest: bytea("configuration_digest"),
    requestId: text("request_id"),
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
      name: "tenant_federated_authentication_transactions_pkey",
      columns: [table.tenantId, table.transactionId],
    }),
    unique("tenant_federated_authentication_transactions_operation_key").on(
      table.protocol,
      table.operationRunId,
    ),
    unique(
      "tenant_federated_authentication_transactions_tenant_operation_key",
    ).on(table.tenantId, table.operationRunId),
    unique("tenant_federated_authentication_transactions_receipt_key").on(
      table.receiptDigest,
    ),
    unique("tenant_federated_authentication_transactions_exact_key").on(
      table.tenantId,
      table.protocol,
      table.transactionId,
      table.providerId,
      table.bindingId,
      table.providerKind,
    ),
    uniqueIndex("tenant_federated_authentication_transactions_oidc_state_key")
      .on(table.stateDigest)
      .where(sql`${table.protocol} = 'oidc'`),
    uniqueIndex("tenant_federated_authentication_transactions_saml_relay_key")
      .on(table.relayStateDigest)
      .where(sql`${table.protocol} = 'saml'`),
    uniqueIndex("tenant_federated_authentication_transactions_live_browser_key")
      .on(table.protocol, table.browserDigest)
      .where(sql`${table.state} in ('pending', 'claimed')`),
    index("tenant_federated_authentication_transactions_expiry_idx").on(
      table.state,
      table.expiresAt,
      table.transactionId,
    ),
    foreignKey({
      name: "tenant_federated_authentication_transactions_policy_fk",
      columns: [
        table.tenantId,
        table.bindingId,
        table.providerId,
        table.providerKind,
      ],
      foreignColumns: [
        tenantFederatedProviderPolicies.tenantId,
        tenantFederatedProviderPolicies.bindingId,
        tenantFederatedProviderPolicies.providerId,
        tenantFederatedProviderPolicies.providerKind,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_federated_authentication_transactions_verifier_keyring_fk",
      columns: [table.verifierKeyVersion],
      foreignColumns: [identityKeyringVersions.keyVersion],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "tenant_federated_authentication_transactions_id_check",
      sql`octet_length(${table.transactionId}) = 32
        and (uuid_extract_version(${table.operationRunId}) = 7) is true`,
    ),
    check(
      "tenant_federated_authentication_transactions_digest_check",
      sql`octet_length(${table.operationDigest}) = 32
        and octet_length(${table.receiptDigest}) = 32
        and octet_length(${table.networkDigest}) = 32
        and octet_length(${table.accountDigest}) = 32
        and octet_length(${table.providerDigest}) = 32
        and octet_length(${table.browserDigest}) = 32`,
    ),
    check(
      "tenant_federated_authentication_transactions_protocol_check",
      sql`((${table.protocol} = 'oidc'
          and ${table.providerKind} = 'oidc'
          and octet_length(${table.stateDigest}) = 32
          and octet_length(${table.nonceDigest}) = 32
          and ${table.relayStateDigest} is null
          and ${table.clientSecretRevision} > 0
          and ${table.discoveryRevision} > 0 and octet_length(${table.discoveryDigest}) = 32
          and ${table.jwksRevision} > 0 and octet_length(${table.jwksDigest}) = 32
          and ${table.verifierKeyVersion} between 1 and 2147483647
          and octet_length(${table.verifierCiphertext}) between 16 and 4096
          and octet_length(convert_to(${table.clientId}, 'UTF8')) between 1 and 512
          and char_length(${table.redirectUri}) between 1 and 4096
          and char_length(${table.postLogoutRedirectUri}) between 1 and 4096
          and cardinality(${table.scopes}) between 1 and 64
          and array_position(${table.scopes}, null) is null
          and ${table.allowRefreshToken} is not null and ${table.useUserInfo} is not null
          and ${table.metadataRevision} is null and ${table.metadataDigest} is null
          and ${table.spKeyRevision} is null and ${table.configurationDigest} is null
          and ${table.requestId} is null)
        or (${table.protocol} = 'saml'
          and ${table.providerKind} = 'saml'
          and octet_length(${table.relayStateDigest}) = 32
          and ${table.stateDigest} is null
          and ${table.nonceDigest} is null
          and ${table.clientSecretRevision} is null
          and ${table.discoveryRevision} is null and ${table.discoveryDigest} is null
          and ${table.jwksRevision} is null and ${table.jwksDigest} is null
          and ${table.verifierKeyVersion} is null and ${table.verifierCiphertext} is null
          and ${table.clientId} is null and ${table.redirectUri} is null
          and ${table.postLogoutRedirectUri} is null and ${table.scopes} is null
          and ${table.allowRefreshToken} is null and ${table.useUserInfo} is null
          and ${table.metadataRevision} > 0 and octet_length(${table.metadataDigest}) = 32
          and ${table.spKeyRevision} > 0 and octet_length(${table.configurationDigest}) = 32
          and char_length(${table.requestId}) between 1 and 1024)) is true`,
    ),
    check(
      "tenant_federated_authentication_transactions_pin_check",
      sql`${table.providerRevision} > 0 and ${table.bindingRevision} > 0
        and ${table.configurationRevision} > 0 and ${table.securityRevision} > 0
        and ${table.mappingRevision} > 0 and ${table.authorizationRevision} > 0
        and ${table.assurancePolicyRevision} > 0
        and char_length(${table.returnPath}) between 1 and 2048
        and left(${table.returnPath}, 1) = '/'
        and ${table.returnPath} !~ '[[:cntrl:]]'
        and (${table.clientId} is null or ${table.clientId} !~ '[[:cntrl:]]')
        and (${table.redirectUri} is null or ${table.redirectUri} !~ '[[:cntrl:]]')
        and (${table.postLogoutRedirectUri} is null or ${table.postLogoutRedirectUri} !~ '[[:cntrl:]]')
        and (${table.requestId} is null or ${table.requestId} !~ '[[:cntrl:]]')`,
    ),
    check(
      "tenant_federated_authentication_transactions_lifecycle_check",
      sql`(${table.version} > 0
        and ${table.expiresAt} between ${table.createdAt} + interval '1 minute'
          and ${table.createdAt} + interval '15 minutes'
        and ((${table.state} = 'pending'
            and ${table.claimAttemptId} is null and ${table.claimedAt} is null
            and ${table.completedAt} is null and ${table.failureReason} is null)
          or (${table.protocol} = 'oidc' and ${table.state} = 'claimed'
            and octet_length(${table.claimAttemptId}) = 32 and ${table.claimedAt} is not null
            and ${table.completedAt} is null and ${table.failureReason} is null)
          or (${table.state} in ('completed','failed','expired')
            and ${table.completedAt} is not null
            and ${table.completedAt} >= ${table.createdAt}
            and (${table.claimAttemptId} is null) = (${table.claimedAt} is null)
            and (${table.protocol} <> 'saml'
              or (${table.claimAttemptId} is null and ${table.claimedAt} is null))
            and (${table.state} <> 'completed' or ${table.protocol} <> 'oidc'
              or (${table.claimAttemptId} is not null and ${table.claimedAt} is not null))
            and (${table.state} = 'completed') = (${table.failureReason} is null)))) is true`,
    ),
  ],
).enableRLS();

/** Immutable operation digest and bounded result snapshot for exact apply replay. */
export const tenantFederatedAuthenticationApplications = pgTable(
  "tenant_federated_authentication_applications",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    protocol: text("protocol").notNull(),
    transactionId: bytea("transaction_id"),
    operationDigest: bytea("operation_digest").notNull(),
    providerId: uuid("provider_id"),
    bindingId: uuid("binding_id"),
    providerKind: authProviderKind("provider_kind"),
    responseIdDigest: bytea("response_id_digest"),
    assertionIdDigest: bytea("assertion_id_digest"),
    sessionIndexDigest: bytea("session_index_digest"),
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
    unique("tenant_federated_authentication_applications_operation_key").on(
      table.tenantId,
      table.operationDigest,
    ),
    uniqueIndex("tenant_federated_authentication_applications_transaction_key")
      .on(table.tenantId, table.protocol, table.transactionId)
      .where(sql`${table.transactionId} is not null`),
    uniqueIndex(
      "tenant_federated_authentication_applications_saml_response_key",
    )
      .on(table.tenantId, table.providerId, table.responseIdDigest)
      .where(sql`${table.protocol} = 'saml'`),
    uniqueIndex(
      "tenant_federated_authentication_applications_saml_assertion_key",
    )
      .on(table.tenantId, table.providerId, table.assertionIdDigest)
      .where(sql`${table.protocol} = 'saml'`),
    uniqueIndex(
      "tenant_federated_authentication_applications_saml_session_index_key",
    )
      .on(table.tenantId, table.providerId, table.sessionIndexDigest)
      .where(sql`${table.sessionIndexDigest} is not null`),
    foreignKey({
      name: "tenant_federated_authentication_applications_policy_fk",
      columns: [
        table.tenantId,
        table.bindingId,
        table.providerId,
        table.providerKind,
      ],
      foreignColumns: [
        tenantFederatedProviderPolicies.tenantId,
        tenantFederatedProviderPolicies.bindingId,
        tenantFederatedProviderPolicies.providerId,
        tenantFederatedProviderPolicies.providerKind,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_federated_authentication_applications_transaction_fk",
      columns: [
        table.tenantId,
        table.protocol,
        table.transactionId,
        table.providerId,
        table.bindingId,
        table.providerKind,
      ],
      foreignColumns: [
        tenantFederatedAuthenticationTransactions.tenantId,
        tenantFederatedAuthenticationTransactions.protocol,
        tenantFederatedAuthenticationTransactions.transactionId,
        tenantFederatedAuthenticationTransactions.providerId,
        tenantFederatedAuthenticationTransactions.bindingId,
        tenantFederatedAuthenticationTransactions.providerKind,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_federated_authentication_applications_session_fk",
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
      name: "tenant_federated_authentication_applications_continuation_fk",
      columns: [table.tenantId, table.continuationId, table.userId],
      foreignColumns: [
        tenantPostPrimaryContinuations.tenantId,
        tenantPostPrimaryContinuations.id,
        tenantPostPrimaryContinuations.userId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "tenant_federated_authentication_applications_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "tenant_federated_authentication_applications_digest_check",
      sql`octet_length(${table.operationDigest}) = 32
        and (${table.transactionId} is null or octet_length(${table.transactionId}) = 32)`,
    ),
    check(
      "tenant_federated_authentication_applications_protocol_check",
      sql`((${table.protocol} = 'passkey'
          and ${table.transactionId} is null and ${table.providerId} is null and ${table.bindingId} is null
          and ${table.providerKind} is null
          and ${table.responseIdDigest} is null and ${table.assertionIdDigest} is null
          and ${table.sessionIndexDigest} is null)
        or (${table.protocol} = 'oidc'
          and octet_length(${table.transactionId}) = 32
          and ${table.providerId} is not null and ${table.bindingId} is not null
          and ${table.providerKind} = 'oidc'
          and ${table.responseIdDigest} is null and ${table.assertionIdDigest} is null
          and ${table.sessionIndexDigest} is null)
        or (${table.protocol} = 'saml'
          and octet_length(${table.transactionId}) = 32
          and ${table.providerId} is not null and ${table.bindingId} is not null
          and ${table.providerKind} = 'saml'
          and octet_length(${table.responseIdDigest}) = 32
          and octet_length(${table.assertionIdDigest}) = 32
          and (${table.sessionIndexDigest} is null
            or octet_length(${table.sessionIndexDigest}) = 32))) is true`,
    ),
    check(
      "tenant_federated_authentication_applications_result_check",
      sql`${table.category} in ('success','identity_collision','stale','denied')
        and jsonb_typeof(${table.requestSnapshot}) = 'object'
        and pg_column_size(${table.requestSnapshot}) between 2 and 2097152
        and jsonb_typeof(${table.resultSnapshot}) = 'object'
        and pg_column_size(${table.resultSnapshot}) between 2 and 65536
        and ((${table.category} = 'success'
            and ${table.userId} is not null
            and ((${table.protocol} = 'passkey' and ${table.primaryKind} = 'passkey')
              or (${table.protocol} in ('oidc','saml') and ${table.primaryKind} = 'tenant_provider'))
            and ((${table.sessionId} is null) <> (${table.continuationId} is null)))
          or (${table.category} <> 'success'
            and ${table.primaryKind} is null
            and ${table.userId} is null and ${table.sessionId} is null and ${table.continuationId} is null))`,
    ),
  ],
).enableRLS();

/** Exact typed tenant-provider primary provenance for one session. */
export const authSessionFederatedProvenance = pgTable(
  "auth_session_federated_provenance",
  {
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    sessionId: uuid("session_id").notNull(),
    userId: uuid("user_id").notNull(),
    primaryKind: text("primary_kind").notNull().default("tenant_provider"),
    authenticationMethod: text("authentication_method").notNull(),
    providerId: uuid("provider_id").notNull(),
    bindingId: uuid("binding_id").notNull(),
    providerKind: authProviderKind("provider_kind").notNull(),
    externalIdentityId: uuid("external_identity_id").notNull(),
    externalIdentityRevision: bigint("external_identity_revision", {
      mode: "bigint",
    }).notNull(),
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
      name: "auth_session_federated_provenance_pkey",
      columns: [table.tenantId, table.sessionId],
    }),
    unique("auth_session_federated_provenance_provider_key").on(
      table.tenantId,
      table.sessionId,
      table.providerId,
      table.bindingId,
    ),
    unique("auth_session_federated_provenance_exact_key").on(
      table.tenantId,
      table.sessionId,
      table.userId,
      table.providerId,
      table.bindingId,
      table.providerKind,
      table.externalIdentityId,
    ),
    foreignKey({
      name: "auth_session_federated_provenance_state_fk",
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
      name: "auth_session_federated_provenance_identity_fk",
      columns: [
        table.tenantId,
        table.providerId,
        table.externalIdentityId,
        table.userId,
      ],
      foreignColumns: [
        tenantFederatedExternalIdentities.tenantId,
        tenantFederatedExternalIdentities.providerId,
        tenantFederatedExternalIdentities.id,
        tenantFederatedExternalIdentities.userId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "auth_session_federated_provenance_policy_fk",
      columns: [
        table.tenantId,
        table.bindingId,
        table.providerId,
        table.providerKind,
      ],
      foreignColumns: [
        tenantFederatedProviderPolicies.tenantId,
        tenantFederatedProviderPolicies.bindingId,
        tenantFederatedProviderPolicies.providerId,
        tenantFederatedProviderPolicies.providerKind,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "auth_session_federated_provenance_value_check",
      sql`${table.primaryKind} = 'tenant_provider'
        and ${table.authenticationMethod} in ('oidc','saml')
        and ${table.providerKind}::text = ${table.authenticationMethod}
        and ${table.externalIdentityRevision} > 0 and ${table.trustRuleRevision} > 0`,
    ),
  ],
).enableRLS();

/** Immutable SAML material identity with an optional encrypted logout envelope. */
export const tenantSamlSessionMaterials = pgTable(
  "tenant_saml_session_materials",
  {
    id: uuid("id").primaryKey(),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    sessionId: uuid("session_id"),
    continuationId: uuid("continuation_id"),
    userId: uuid("user_id").notNull(),
    providerId: uuid("provider_id").notNull(),
    bindingId: uuid("binding_id").notNull(),
    providerKind: authProviderKind("provider_kind").notNull().default("saml"),
    externalIdentityId: uuid("external_identity_id").notNull(),
    sessionIndexDigest: bytea("session_index_digest"),
    aadVersion: integer("aad_version").notNull(),
    keyVersion: integer("key_version"),
    ciphertext: bytea("ciphertext"),
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
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    unique("tenant_saml_session_materials_tenant_id_key").on(
      table.tenantId,
      table.id,
    ),
    uniqueIndex("tenant_saml_session_materials_session_key")
      .on(table.tenantId, table.sessionId)
      .where(sql`${table.sessionId} is not null`),
    uniqueIndex("tenant_saml_session_materials_continuation_key")
      .on(table.tenantId, table.continuationId)
      .where(sql`${table.continuationId} is not null`),
    uniqueIndex("tenant_saml_session_materials_session_index_key")
      .on(table.tenantId, table.providerId, table.sessionIndexDigest)
      .where(sql`${table.sessionIndexDigest} is not null`),
    index("tenant_saml_session_materials_cleanup_idx")
      .on(table.createdAt, table.id)
      .where(sql`${table.scrubbedAt} is null`),
    foreignKey({
      name: "tenant_saml_session_materials_policy_fk",
      columns: [
        table.tenantId,
        table.bindingId,
        table.providerId,
        table.providerKind,
      ],
      foreignColumns: [
        tenantFederatedProviderPolicies.tenantId,
        tenantFederatedProviderPolicies.bindingId,
        tenantFederatedProviderPolicies.providerId,
        tenantFederatedProviderPolicies.providerKind,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_saml_session_materials_keyring_fk",
      columns: [table.keyVersion],
      foreignColumns: [identityKeyringVersions.keyVersion],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_saml_session_materials_session_fk",
      columns: [
        table.tenantId,
        table.sessionId,
        table.userId,
        table.providerId,
        table.bindingId,
        table.providerKind,
        table.externalIdentityId,
      ],
      foreignColumns: [
        authSessionFederatedProvenance.tenantId,
        authSessionFederatedProvenance.sessionId,
        authSessionFederatedProvenance.userId,
        authSessionFederatedProvenance.providerId,
        authSessionFederatedProvenance.bindingId,
        authSessionFederatedProvenance.providerKind,
        authSessionFederatedProvenance.externalIdentityId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_saml_session_materials_continuation_fk",
      columns: [
        table.tenantId,
        table.continuationId,
        table.userId,
        table.providerId,
        table.bindingId,
        table.providerKind,
        table.externalIdentityId,
      ],
      foreignColumns: [
        tenantPostPrimaryContinuations.tenantId,
        tenantPostPrimaryContinuations.id,
        tenantPostPrimaryContinuations.userId,
        tenantPostPrimaryContinuations.providerId,
        tenantPostPrimaryContinuations.bindingId,
        tenantPostPrimaryContinuations.providerKind,
        tenantPostPrimaryContinuations.externalIdentityId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "tenant_saml_session_materials_value_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true
        and ((${table.sessionId} is null) <> (${table.continuationId} is null))
        and ${table.id} <> coalesce(${table.sessionId}, ${table.continuationId})
        and ${table.providerKind} = 'saml'
        and (${table.sessionIndexDigest} is null or octet_length(${table.sessionIndexDigest}) = 32)
        and ${table.aadVersion} in (1, 2)
        and (${table.keyVersion} is null) = (${table.ciphertext} is null)
        and (${table.logoutConfiguration} is null
          or (jsonb_typeof(${table.logoutConfiguration}) = 'object'
            and pg_column_size(${table.logoutConfiguration}) between 2 and 6291456))
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
            and (${table.keyVersion} is null
              or (${table.keyVersion} between 1 and 32767
                and octet_length(${table.ciphertext}) between 16 and 16384)))
          or (${table.scrubbedAt} >= ${table.createdAt}
            and date_trunc('microseconds', ${table.scrubbedAt}) = ${table.scrubbedAt}
            and (uuid_extract_version(${table.scrubOperationRunId}) = 7) is true
            and ${table.scrubOperationRunId} <> ${table.id}
            and ${table.keyVersion} is null and ${table.ciphertext} is null
            and ${table.sessionIndexDigest} is null
            and ${table.logoutConfiguration} is null))`,
    ),
  ],
).enableRLS();

/**
 * Immutable OIDC login material identity. Token envelopes are purpose- and
 * row-bound by the identity keyring; an access token is intentionally absent.
 */
export const tenantOidcSessionMaterials = pgTable(
  "tenant_oidc_session_materials",
  {
    id: uuid("id").primaryKey(),
    tenantId: uuid("tenant_id").references(() => tenants.id, {
      onDelete: "restrict",
    }),
    authority: text("authority").notNull(),
    sessionId: uuid("session_id"),
    continuationId: uuid("continuation_id"),
    rotationFamilyId: uuid("rotation_family_id"),
    userId: uuid("user_id").notNull(),
    providerId: uuid("provider_id").notNull(),
    bindingId: uuid("binding_id"),
    providerKind: authProviderKind("provider_kind").notNull().default("oidc"),
    externalIdentityId: uuid("external_identity_id").notNull(),
    aadVersion: integer("aad_version").notNull(),
    idTokenKeyVersion: integer("id_token_key_version"),
    idTokenCiphertext: bytea("id_token_ciphertext"),
    idTokenDigest: bytea("id_token_digest"),
    refreshTokenKeyVersion: integer("refresh_token_key_version"),
    refreshTokenCiphertext: bytea("refresh_token_ciphertext"),
    refreshTokenDigest: bytea("refresh_token_digest"),
    refreshGeneration: bigint("refresh_generation", { mode: "bigint" })
      .notNull()
      .default(sql`0`),
    refreshState: text("refresh_state").notNull().default("unavailable"),
    refreshClaimedAt: timestamp("refresh_claimed_at", {
      withTimezone: true,
      mode: "date",
    }),
    refreshClaimExpiresAt: timestamp("refresh_claim_expires_at", {
      withTimezone: true,
      mode: "date",
    }),
    refreshVersion: bigint("refresh_version", { mode: "bigint" })
      .notNull()
      .default(sql`1`),
    /** Consecutive safe-to-retry completions for the current token generation. */
    refreshRetryAttempt: integer("refresh_retry_attempt").notNull().default(0),
    accessExpiresAt: timestamp("access_expires_at", {
      withTimezone: true,
      mode: "date",
    }),
    expiresAt: timestamp("expires_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    scrubbedAt: timestamp("scrubbed_at", {
      withTimezone: true,
      mode: "date",
    }),
    scrubOperationRunId: uuid("scrub_operation_run_id"),
    clientSecretRevision: bigint("client_secret_revision", {
      mode: "bigint",
    }),
    clientAuthentication: text("client_authentication"),
    clientId: text("client_id"),
    tokenEndpoint: text("token_endpoint"),
    revocationEndpoint: text("revocation_endpoint"),
    endSessionEndpoint: text("end_session_endpoint"),
    postLogoutRedirectUri: text("post_logout_redirect_uri"),
    logoutDisposition: text("logout_disposition")
      .notNull()
      .default("available"),
    logoutOperationRunId: uuid("logout_operation_run_id"),
    logoutClaimedAt: timestamp("logout_claimed_at", {
      withTimezone: true,
      mode: "date",
    }),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    unique("tenant_oidc_session_materials_tenant_id_key").on(
      table.tenantId,
      table.id,
    ),
    uniqueIndex("tenant_oidc_session_materials_session_key")
      .on(table.authority, table.sessionId)
      .where(sql`${table.sessionId} is not null`),
    uniqueIndex("tenant_oidc_session_materials_continuation_key")
      .on(table.authority, table.continuationId)
      .where(sql`${table.continuationId} is not null`),
    uniqueIndex("tenant_oidc_session_materials_family_key")
      .on(table.authority, table.rotationFamilyId)
      .where(sql`${table.rotationFamilyId} is not null`),
    foreignKey({
      name: "tenant_oidc_session_materials_id_token_keyring_fk",
      columns: [table.idTokenKeyVersion],
      foreignColumns: [identityKeyringVersions.keyVersion],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_oidc_session_materials_refresh_keyring_fk",
      columns: [table.refreshTokenKeyVersion],
      foreignColumns: [identityKeyringVersions.keyVersion],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "tenant_oidc_session_materials_identity_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true
        and ((${table.sessionId} is null) <> (${table.continuationId} is null))
        and ${table.id} <> coalesce(${table.sessionId}, ${table.continuationId})
        and ${table.providerKind} = 'oidc'
        and ((${table.authority} in ('tenant_provider','tenant_platform_provider')
            and ${table.tenantId} is not null and ${table.bindingId} is not null)
          or (${table.authority} = 'platform_provider'
            and ${table.tenantId} is null and ${table.bindingId} is null))
        and ((${table.sessionId} is null and ${table.rotationFamilyId} is null)
          or (${table.sessionId} is not null
            and (uuid_extract_version(${table.rotationFamilyId}) = 7) is true
            and ${table.rotationFamilyId} <> ${table.sessionId}
            and ${table.rotationFamilyId} <> ${table.id}))`,
    ),
    check(
      "tenant_oidc_session_materials_token_check",
      sql`${table.aadVersion} = 1
        and ((${table.scrubbedAt} is null
          and (${table.idTokenKeyVersion} is null)
          = (${table.idTokenCiphertext} is null)
        and (${table.idTokenKeyVersion} is null)
          = (${table.idTokenDigest} is null)
        and (${table.idTokenKeyVersion} is null
          or (${table.idTokenKeyVersion} between 1 and 32767
            and octet_length(${table.idTokenCiphertext}) between 29 and 262172
            and octet_length(${table.idTokenDigest}) = 32
            and encode(${table.idTokenDigest}, 'hex') <> repeat('00', 32)))
        and ${table.refreshVersion} between 1 and 8999999999999999
          and ${table.refreshRetryAttempt} between 0 and 5
          and ((${table.refreshState} = 'unavailable'
            and ${table.refreshGeneration} = 0
            and ${table.refreshRetryAttempt} = 0
            and ${table.refreshClaimedAt} is null
            and ${table.refreshClaimExpiresAt} is null
            and ${table.refreshTokenKeyVersion} is null
            and ${table.refreshTokenCiphertext} is null
            and ${table.refreshTokenDigest} is null
            and ${table.accessExpiresAt} is null)
          or (${table.refreshState} in ('ready','claimed','revoked')
            and ${table.refreshGeneration} between 1 and 8999999999999999
            and ${table.refreshTokenKeyVersion} between 1 and 32767
            and octet_length(${table.refreshTokenCiphertext}) between 29 and 262172
            and octet_length(${table.refreshTokenDigest}) = 32
            and ${table.accessExpiresAt} > ${table.createdAt}
            and ${table.accessExpiresAt} <= ${table.expiresAt}
            and ((${table.refreshState} = 'ready'
                and ${table.refreshClaimedAt} is null
                and ${table.refreshClaimExpiresAt} is null)
              or (${table.refreshState} = 'claimed'
                and ${table.refreshClaimedAt} >= ${table.createdAt}
                and ${table.refreshClaimExpiresAt} > ${table.refreshClaimedAt}
                and ${table.refreshClaimExpiresAt} <= ${table.expiresAt}
                and ${table.refreshClaimExpiresAt}
                  <= ${table.refreshClaimedAt} + interval '2 minutes')
              or (${table.refreshState} = 'revoked'
                and ${table.refreshClaimedAt} is null
                and ${table.refreshClaimExpiresAt} is null)))))
          or (${table.scrubbedAt} >= ${table.createdAt}
            and ${table.refreshState} = 'scrubbed'
            and ${table.refreshRetryAttempt} = 0
            and ${table.refreshClaimedAt} is null
            and ${table.refreshClaimExpiresAt} is null
            and ${table.idTokenKeyVersion} is null
            and ${table.idTokenCiphertext} is null
            and ${table.idTokenDigest} is null
            and ${table.refreshTokenKeyVersion} is null
            and ${table.refreshTokenCiphertext} is null
            and ${table.refreshTokenDigest} is null
            and ${table.accessExpiresAt} is null))`,
    ),
    check(
      "tenant_oidc_session_materials_protocol_check",
      sql`((${table.refreshState} = 'scrubbed'
            and ${table.clientSecretRevision} is null
            and ${table.clientAuthentication} is null
            and ${table.clientId} is null
            and ${table.tokenEndpoint} is null
            and ${table.revocationEndpoint} is null
            and ${table.endSessionEndpoint} is null
            and ${table.postLogoutRedirectUri} is null)
          or (${table.refreshState} <> 'scrubbed'
            and ${table.clientId} is not null
            and ${table.postLogoutRedirectUri} is not null
            and ((${table.refreshState} in ('ready','claimed','revoked'))
              = (${table.clientSecretRevision} is not null
                and ${table.clientAuthentication} is not null
                and ${table.tokenEndpoint} is not null))))
        and (${table.clientSecretRevision} is null
          or ${table.clientSecretRevision} > 0)
        and (${table.clientAuthentication} is null
          or ${table.clientAuthentication} in ('client_secret_basic','client_secret_post'))
        and (${table.clientId} is null or (
          octet_length(convert_to(${table.clientId}, 'UTF8')) between 1 and 512
          and ${table.clientId} !~ '[[:cntrl:]]'))
        and (${table.tokenEndpoint} is null
          or (char_length(${table.tokenEndpoint}) between 9 and 4096
            and ${table.tokenEndpoint} ~ '^https://[^[:space:]#]+$'))
        and (${table.revocationEndpoint} is null
          or (char_length(${table.revocationEndpoint}) between 9 and 4096
            and ${table.revocationEndpoint} ~ '^https://[^[:space:]#]+$'))
        and (${table.endSessionEndpoint} is null
          or (char_length(${table.endSessionEndpoint}) between 9 and 4096
            and ${table.endSessionEndpoint} ~ '^https://[^[:space:]#]+$'))
        and (${table.scrubbedAt} is not null
          or (${table.endSessionEndpoint} is null)
            = (${table.idTokenKeyVersion} is null))
        and (${table.postLogoutRedirectUri} is null or (
          char_length(${table.postLogoutRedirectUri}) between 9 and 4096
          and ${table.postLogoutRedirectUri} ~ '^https://[^[:space:]#]+$'))
        and ${table.expiresAt} > ${table.createdAt}
        and date_trunc('microseconds', ${table.expiresAt}) = ${table.expiresAt}`,
    ),
    check(
      "tenant_oidc_session_materials_logout_check",
      sql`${table.logoutDisposition} in ('available','not_configured','claimed','skipped')
        and ((${table.logoutDisposition} in ('available','not_configured')
            and ${table.logoutOperationRunId} is null
            and ${table.logoutClaimedAt} is null)
          or (${table.logoutDisposition} in ('claimed','skipped')
            and (uuid_extract_version(${table.logoutOperationRunId}) = 7) is true
            and ${table.logoutOperationRunId} <> ${table.id}
            and ${table.logoutClaimedAt} >= ${table.createdAt}))
        and ((${table.endSessionEndpoint} is null)
          = (${table.logoutDisposition} = 'not_configured')
          or ${table.logoutDisposition} in ('claimed','skipped'))
        and ((${table.scrubbedAt} is null
            and ${table.scrubOperationRunId} is null)
          or (${table.scrubbedAt} is not null
            and (uuid_extract_version(${table.scrubOperationRunId}) = 7) is true
            and ${table.scrubOperationRunId} <> ${table.id}))
        and ${table.updatedAt} >= ${table.createdAt}`,
    ),
  ],
).enableRLS();

/** Hash-only replay ledger retained no longer than the session-family limit. */
export const tenantOidcConsumedRefreshTokens = pgTable(
  "tenant_oidc_consumed_refresh_tokens",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id").references(() => tenants.id, {
      onDelete: "restrict",
    }),
    authority: text("authority").notNull(),
    materialId: uuid("material_id").notNull(),
    sessionFamilyId: uuid("session_family_id").notNull(),
    generation: bigint("generation", { mode: "bigint" }).notNull(),
    tokenDigest: bytea("token_digest").notNull(),
    consumedAt: timestamp("consumed_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    retainUntil: timestamp("retain_until", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
  },
  (table) => [
    unique("tenant_oidc_consumed_refresh_tokens_generation_key").on(
      table.authority,
      table.materialId,
      table.generation,
    ),
    unique("tenant_oidc_consumed_refresh_tokens_digest_key").on(
      table.authority,
      table.materialId,
      table.tokenDigest,
    ),
    index("tenant_oidc_consumed_refresh_tokens_expiry_idx").on(
      table.retainUntil,
      table.tenantId,
      table.materialId,
    ),
    foreignKey({
      name: "tenant_oidc_consumed_refresh_tokens_material_fk",
      columns: [table.materialId],
      foreignColumns: [tenantOidcSessionMaterials.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "tenant_oidc_consumed_refresh_tokens_value_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true
        and (uuid_extract_version(${table.sessionFamilyId}) = 7) is true
        and ((${table.authority} in ('tenant_provider','tenant_platform_provider')
            and ${table.tenantId} is not null)
          or (${table.authority} = 'platform_provider'
            and ${table.tenantId} is null))
        and ${table.generation} between 1 and 8999999999999999
        and octet_length(${table.tokenDigest}) = 32
        and encode(${table.tokenDigest}, 'hex') <> repeat('00', 32)
        and date_trunc('microseconds', ${table.consumedAt}) = ${table.consumedAt}
        and ${table.retainUntil} > ${table.consumedAt}`,
    ),
  ],
).enableRLS();

/** Immutable replay ledger for local-first OIDC logout. */
export const tenantOidcLogoutCommands = pgTable(
  "tenant_oidc_logout_commands",
  {
    tenantId: uuid("tenant_id").references(() => tenants.id, {
      onDelete: "restrict",
    }),
    authority: text("authority").notNull(),
    operationRunId: uuid("operation_run_id").notNull(),
    sessionId: uuid("session_id").notNull(),
    expectedVersion: bigint("expected_version", { mode: "bigint" }).notNull(),
    requestUpstream: boolean("request_upstream").notNull(),
    materialId: uuid("material_id"),
    requestDigest: bytea("request_digest").notNull(),
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
    primaryKey({
      name: "tenant_oidc_logout_commands_pkey",
      columns: [table.operationRunId],
    }),
    foreignKey({
      name: "tenant_oidc_logout_commands_material_fk",
      columns: [table.materialId],
      foreignColumns: [tenantOidcSessionMaterials.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "tenant_oidc_logout_commands_identity_check",
      sql`(uuid_extract_version(${table.operationRunId}) = 7) is true
        and ${table.operationRunId} <> ${table.sessionId}
        and ((${table.authority} in ('tenant_provider','tenant_platform_provider','tenant_session')
            and ${table.tenantId} is not null)
          or (${table.authority} in ('platform_provider','platform_session')
            and ${table.tenantId} is null))
        and (${table.materialId} is null or (
          ${table.operationRunId} <> ${table.materialId}
          and ${table.sessionId} <> ${table.materialId}))`,
    ),
    check(
      "tenant_oidc_logout_commands_value_check",
      sql`${table.expectedVersion} > 0
        and octet_length(${table.requestDigest}) = 32
        and encode(${table.requestDigest}, 'hex') <> repeat('00', 32)
        and jsonb_typeof(${table.requestSnapshot}) = 'object'
        and pg_column_size(${table.requestSnapshot}) between 2 and 16384
        and ${table.requestSnapshot}::text
          !~* '"(tokenDigest|csrfDigest|ciphertext|keyVersion|idToken|refreshToken|secret)"[[:space:]]*:'
        and jsonb_typeof(${table.resultSnapshot}) = 'object'
        and pg_column_size(${table.resultSnapshot}) between 2 and 65536
        and ${table.resultSnapshot} ? 'category'
        and ${table.resultSnapshot}::text
          !~* '"(tokenDigest|csrfDigest|ciphertext|keyVersion|idToken|refreshToken|secret|endpoint)"[[:space:]]*:'
        and date_trunc('microseconds', ${table.appliedAt}) = ${table.appliedAt}`,
    ),
  ],
).enableRLS();

/** Bounded server-side retry queue; token bytes remain in the material row. */
export const tenantOidcLogoutRetryJobs = pgTable(
  "tenant_oidc_logout_retry_jobs",
  {
    id: uuid("id").primaryKey(),
    tenantId: uuid("tenant_id").references(() => tenants.id, {
      onDelete: "restrict",
    }),
    authority: text("authority").notNull(),
    operationRunId: uuid("operation_run_id").notNull(),
    materialId: uuid("material_id").notNull(),
    sessionFamilyId: uuid("session_family_id").notNull(),
    state: text("state").notNull().default("pending"),
    attempt: integer("attempt").notNull().default(0),
    maximumAttempts: integer("maximum_attempts").notNull().default(8),
    notBefore: timestamp("not_before", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    claimedAt: timestamp("claimed_at", { withTimezone: true, mode: "date" }),
    claimExpiresAt: timestamp("claim_expires_at", {
      withTimezone: true,
      mode: "date",
    }),
    completedAt: timestamp("completed_at", {
      withTimezone: true,
      mode: "date",
    }),
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
    unique("tenant_oidc_logout_retry_jobs_material_key").on(table.materialId),
    index("tenant_oidc_logout_retry_jobs_claim_idx").on(
      table.state,
      table.notBefore,
      table.id,
    ),
    foreignKey({
      name: "tenant_oidc_logout_retry_jobs_command_fk",
      columns: [table.operationRunId],
      foreignColumns: [tenantOidcLogoutCommands.operationRunId],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_oidc_logout_retry_jobs_material_fk",
      columns: [table.materialId],
      foreignColumns: [tenantOidcSessionMaterials.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "tenant_oidc_logout_retry_jobs_identity_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true
        and (uuid_extract_version(${table.sessionFamilyId}) = 7) is true
        and ((${table.authority} in ('tenant_provider','tenant_platform_provider')
            and ${table.tenantId} is not null)
          or (${table.authority} = 'platform_provider'
            and ${table.tenantId} is null))
        and ${table.id} <> ${table.operationRunId}
        and ${table.id} <> ${table.materialId}
        and ${table.id} <> ${table.sessionFamilyId}`,
    ),
    check(
      "tenant_oidc_logout_retry_jobs_state_check",
      sql`${table.state} in ('pending','claimed','complete','dead_letter')
        and ${table.attempt} between 0 and ${table.maximumAttempts}
        and ${table.maximumAttempts} between 1 and 16
        and ${table.version} between 1 and 8999999999999999
        and ${table.notBefore} >= ${table.createdAt}
        and ((${table.state} = 'pending'
            and ${table.claimedAt} is null and ${table.claimExpiresAt} is null
            and ${table.completedAt} is null)
          or (${table.state} = 'claimed'
            and ${table.attempt} > 0 and ${table.claimedAt} is not null
            and ${table.claimExpiresAt} > ${table.claimedAt}
            and ${table.completedAt} is null)
          or (${table.state} in ('complete','dead_letter')
            and ${table.attempt} > 0 and ${table.claimedAt} is not null
            and ${table.claimExpiresAt} is not null
            and ${table.completedAt} >= ${table.claimedAt}))
        and ${table.updatedAt} >= ${table.createdAt}`,
    ),
  ],
).enableRLS();

/**
 * Same-origin, one-time logout handoff. Only the digest of the opaque browser
 * proof is retained; encrypted protocol material stays in its source vault.
 */
export const sessionLogoutContinuations = pgTable(
  "session_logout_continuations",
  {
    id: uuid("id").primaryKey(),
    tokenDigest: bytea("token_digest").notNull(),
    operationRunId: uuid("operation_run_id").notNull(),
    sessionId: uuid("session_id").notNull(),
    userId: uuid("user_id").notNull(),
    tenantId: uuid("tenant_id").references(() => tenants.id, {
      onDelete: "restrict",
    }),
    authority: text("authority").notNull(),
    protocol: text("protocol").notNull(),
    oidcMaterialId: uuid("oidc_material_id"),
    tenantSamlMaterialId: uuid("tenant_saml_material_id"),
    platformSamlMaterialId: uuid("platform_saml_material_id"),
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
  },
  (table) => [
    unique("session_logout_continuations_token_key").on(table.tokenDigest),
    unique("session_logout_continuations_operation_key").on(
      table.operationRunId,
    ),
    uniqueIndex("session_logout_continuations_oidc_material_key")
      .on(table.oidcMaterialId)
      .where(sql`${table.oidcMaterialId} is not null`),
    uniqueIndex("session_logout_continuations_tenant_saml_material_key")
      .on(table.tenantId, table.tenantSamlMaterialId)
      .where(sql`${table.tenantSamlMaterialId} is not null`),
    uniqueIndex("session_logout_continuations_platform_saml_material_key")
      .on(table.platformSamlMaterialId)
      .where(sql`${table.platformSamlMaterialId} is not null`),
    index("session_logout_continuations_expiry_idx").on(
      table.expiresAt,
      table.id,
    ),
    foreignKey({
      name: "session_logout_continuations_command_fk",
      columns: [table.operationRunId],
      foreignColumns: [tenantOidcLogoutCommands.operationRunId],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "session_logout_continuations_oidc_material_fk",
      columns: [table.oidcMaterialId],
      foreignColumns: [tenantOidcSessionMaterials.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "session_logout_continuations_tenant_saml_material_fk",
      columns: [table.tenantId, table.tenantSamlMaterialId],
      foreignColumns: [
        tenantSamlSessionMaterials.tenantId,
        tenantSamlSessionMaterials.id,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "session_logout_continuations_identity_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true
        and ${table.id} <> ${table.operationRunId}
        and ${table.id} <> ${table.sessionId}
        and ${table.id} <> ${table.userId}
        and octet_length(${table.tokenDigest}) = 32
        and encode(${table.tokenDigest}, 'hex') <> repeat('00', 32)
        and ((${table.protocol} = 'oidc'
            and ${table.oidcMaterialId} is not null
            and ${table.tenantSamlMaterialId} is null
            and ${table.platformSamlMaterialId} is null
            and ((${table.authority} in ('tenant_provider','tenant_platform_provider')
                and ${table.tenantId} is not null)
              or (${table.authority} = 'platform_provider'
                and ${table.tenantId} is null)))
          or (${table.protocol} = 'saml'
            and ${table.oidcMaterialId} is null
            and ((${table.authority} = 'tenant_provider'
                and ${table.tenantId} is not null
                and ${table.tenantSamlMaterialId} is not null
                and ${table.platformSamlMaterialId} is null)
              or (${table.authority} = 'platform_provider'
                and ${table.tenantId} is null
                and ${table.tenantSamlMaterialId} is null
                and ${table.platformSamlMaterialId} is not null)
              or (${table.authority} = 'tenant_platform_provider'
                and ${table.tenantId} is not null
                and ${table.tenantSamlMaterialId} is null
                and ${table.platformSamlMaterialId} is not null))))`,
    ),
    check(
      "session_logout_continuations_lifecycle_check",
      sql`date_trunc('microseconds', ${table.createdAt}) = ${table.createdAt}
        and date_trunc('microseconds', ${table.expiresAt}) = ${table.expiresAt}
        and ${table.expiresAt} > ${table.createdAt}
        and ${table.expiresAt} <= ${table.createdAt} + interval '2 minutes'
        and (${table.consumedAt} is null or (
          date_trunc('microseconds', ${table.consumedAt}) = ${table.consumedAt}
          and ${table.consumedAt} >= ${table.createdAt}
          and ${table.consumedAt} < ${table.expiresAt}))`,
    ),
  ],
).enableRLS();

/** Immutable, bounded replay ledger for local-first SAML logout. */
export const tenantSamlLogoutCommands = pgTable(
  "tenant_saml_logout_commands",
  {
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    operationRunId: uuid("operation_run_id").notNull(),
    sessionId: uuid("session_id").notNull(),
    expectedVersion: bigint("expected_version", { mode: "bigint" }).notNull(),
    requestUpstream: boolean("request_upstream").notNull(),
    materialId: uuid("material_id").notNull(),
    requestDigest: bytea("request_digest").notNull(),
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
    primaryKey({
      name: "tenant_saml_logout_commands_pkey",
      columns: [table.tenantId, table.operationRunId],
    }),
    unique("tenant_saml_logout_commands_operation_key").on(
      table.operationRunId,
    ),
    foreignKey({
      name: "tenant_saml_logout_commands_session_fk",
      columns: [table.tenantId, table.sessionId],
      foreignColumns: [
        authSessionMfaStates.tenantId,
        authSessionMfaStates.sessionId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_saml_logout_commands_material_transaction_fk",
      columns: [table.tenantId, table.materialId],
      foreignColumns: [
        tenantFederatedAuthenticationTransactions.tenantId,
        tenantFederatedAuthenticationTransactions.operationRunId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_saml_logout_commands_material_fk",
      columns: [table.tenantId, table.materialId],
      foreignColumns: [
        tenantSamlSessionMaterials.tenantId,
        tenantSamlSessionMaterials.id,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "tenant_saml_logout_commands_identity_check",
      sql`(uuid_extract_version(${table.operationRunId}) = 7) is true
        and ${table.operationRunId} <> ${table.sessionId}
        and ${table.operationRunId} <> ${table.materialId}
        and ${table.sessionId} <> ${table.materialId}`,
    ),
    check(
      "tenant_saml_logout_commands_value_check",
      sql`${table.expectedVersion} > 0
        and octet_length(${table.requestDigest}) = 32
        and jsonb_typeof(${table.requestSnapshot}) = 'object'
        and pg_column_size(${table.requestSnapshot}) between 2 and 16384
        and jsonb_typeof(${table.resultSnapshot}) = 'object'
        and pg_column_size(${table.resultSnapshot}) between 2 and 6291456
        and date_trunc('microseconds', ${table.appliedAt}) = ${table.appliedAt}`,
    ),
  ],
).enableRLS();

/** Exact CAS replay ledger; diagnostics contain only closed decision metadata. */
export const tenantFederatedSessionRevalidationCommands = pgTable(
  "tenant_federated_session_revalidation_commands",
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
      name: "tenant_federated_session_revalidation_commands_pkey",
      columns: [table.tenantId, table.sessionId, table.expectedVersion],
    }),
    foreignKey({
      name: "tenant_federated_session_revalidation_commands_session_fk",
      columns: [table.tenantId, table.sessionId],
      foreignColumns: [
        authSessionMfaStates.tenantId,
        authSessionMfaStates.sessionId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "tenant_federated_session_revalidation_commands_value_check",
      sql`${table.expectedVersion} > 0
        and octet_length(${table.requestDigest}) = 32
        and ${table.decision} in ('usable','rotate','step_up','revoke','deny')
        and jsonb_typeof(${table.resultSnapshot}) = 'object'
        and pg_column_size(${table.resultSnapshot}) between 2 and 65536`,
    ),
  ],
).enableRLS();

/** Live provider admission is pinned to the same access epoch as mappings. */
export const tenantFederatedProviderAccessGrants = pgTable(
  "tenant_federated_provider_access_grants",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    providerId: uuid("provider_id").notNull(),
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
    unique("tenant_federated_provider_access_grants_tenant_id_key").on(
      table.tenantId,
      table.id,
    ),
    uniqueIndex(
      "tenant_federated_provider_access_grants_live_binding_member_key",
    )
      .on(table.tenantId, table.bindingId, table.membershipId)
      .where(sql`${table.endedAt} is null`),
    foreignKey({
      name: "tenant_federated_provider_access_grants_epoch_fk",
      columns: [
        table.tenantId,
        table.accessEpochId,
        table.bindingId,
        table.providerId,
        table.sourceId,
      ],
      foreignColumns: [
        tenantIdentityProviderAccessEpochs.tenantId,
        tenantIdentityProviderAccessEpochs.id,
        tenantIdentityProviderAccessEpochs.bindingId,
        tenantIdentityProviderAccessEpochs.providerId,
        tenantIdentityProviderAccessEpochs.sourceId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_federated_provider_access_grants_identity_fk",
      columns: [
        table.tenantId,
        table.providerId,
        table.externalIdentityId,
        table.userId,
      ],
      foreignColumns: [
        tenantFederatedExternalIdentities.tenantId,
        tenantFederatedExternalIdentities.providerId,
        tenantFederatedExternalIdentities.id,
        tenantFederatedExternalIdentities.userId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_federated_provider_access_grants_membership_fk",
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
      name: "tenant_federated_provider_access_grants_source_fk",
      columns: [table.tenantId, table.sourceId],
      foreignColumns: [
        tenantAuthorizationSources.tenantId,
        tenantAuthorizationSources.id,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "tenant_federated_provider_access_grants_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "tenant_federated_provider_access_grants_lifecycle_check",
      sql`${table.version} > 0 and ${table.lastObservedAt} >= ${table.startedAt}
        and (${table.endedAt} is null or ${table.endedAt} >= ${table.startedAt})`,
    ),
  ],
).enableRLS();

/**
 * Immutable access authority captured when a tenant-owned federated login
 * issues a post-primary continuation.  The parent continuation intentionally
 * carries only the protocol primary; this child pins the exact tenant access
 * epoch/source/grant and configuration revisions so a later deactivate / reactivate
 * cycle cannot revive the old continuation.
 */
export const tenantPostPrimaryFederatedProvenance = pgTable(
  "tenant_post_primary_federated_provenance",
  {
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    continuationId: uuid("continuation_id").notNull(),
    userId: uuid("user_id").notNull(),
    origin: text("origin").notNull(),
    primaryKind: text("primary_kind").notNull().default("tenant_provider"),
    authenticationMethod: text("authentication_method").notNull(),
    providerId: uuid("provider_id").notNull(),
    bindingId: uuid("binding_id").notNull(),
    providerKind: authProviderKind("provider_kind").notNull(),
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
      name: "tenant_post_primary_federated_provenance_pkey",
      columns: [table.tenantId, table.continuationId],
    }),
    unique("tenant_post_primary_federated_provenance_exact_key").on(
      table.tenantId,
      table.continuationId,
      table.userId,
      table.providerId,
      table.bindingId,
      table.providerKind,
      table.externalIdentityId,
    ),
    foreignKey({
      name: "tenant_post_primary_federated_provenance_continuation_fk",
      columns: [
        table.tenantId,
        table.continuationId,
        table.userId,
        table.providerId,
        table.bindingId,
        table.providerKind,
        table.externalIdentityId,
      ],
      foreignColumns: [
        tenantPostPrimaryContinuations.tenantId,
        tenantPostPrimaryContinuations.id,
        tenantPostPrimaryContinuations.userId,
        tenantPostPrimaryContinuations.providerId,
        tenantPostPrimaryContinuations.bindingId,
        tenantPostPrimaryContinuations.providerKind,
        tenantPostPrimaryContinuations.externalIdentityId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_post_primary_federated_provenance_identity_fk",
      columns: [
        table.tenantId,
        table.providerId,
        table.externalIdentityId,
        table.userId,
      ],
      foreignColumns: [
        tenantFederatedExternalIdentities.tenantId,
        tenantFederatedExternalIdentities.providerId,
        tenantFederatedExternalIdentities.id,
        tenantFederatedExternalIdentities.userId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_post_primary_federated_provenance_binding_fk",
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
      name: "tenant_post_primary_federated_provenance_access_grant_fk",
      columns: [table.tenantId, table.accessGrantId],
      foreignColumns: [
        tenantFederatedProviderAccessGrants.tenantId,
        tenantFederatedProviderAccessGrants.id,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_post_primary_federated_provenance_membership_fk",
      columns: [table.tenantId, table.membershipId, table.userId],
      foreignColumns: [
        tenantMemberships.tenantId,
        tenantMemberships.id,
        tenantMemberships.userId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "tenant_post_primary_federated_provenance_value_check",
      sql`${table.origin} in ('initial_login','session_revalidation')
        and ${table.primaryKind} = 'tenant_provider'
        and ${table.authenticationMethod} in ('oidc','saml')
        and ${table.providerKind}::text = ${table.authenticationMethod}
        and ${table.externalIdentityRevision} between 1 and 9007199254740991
        and ${table.providerRevision} between 1 and 9007199254740991
        and ${table.bindingRevision} between 1 and 9007199254740991
        and ${table.configurationRevision} between 1 and 9007199254740991
        and ${table.securityRevision} between 1 and 9007199254740991
        and ${table.planRevision} between 1 and 9007199254740991
        and ${table.mappingRevision} between 1 and 9007199254740991
        and ${table.authorizationRevision} between 1 and 9007199254740991
        and ${table.assurancePolicyRevision} between 1 and 9007199254740991
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

/** Source-owned profile projection; raw protocol claims never persist. */
export const tenantFederatedProviderProfileContributions = pgTable(
  "tenant_federated_provider_profile_contributions",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
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
    unique("tenant_federated_provider_profile_contributions_tenant_id_key").on(
      table.tenantId,
      table.id,
    ),
    uniqueIndex(
      "tenant_federated_provider_profile_contributions_live_grant_key",
    )
      .on(table.tenantId, table.accessGrantId)
      .where(sql`${table.retiredAt} is null`),
    foreignKey({
      name: "tenant_federated_provider_profile_contributions_grant_fk",
      columns: [table.tenantId, table.accessGrantId],
      foreignColumns: [
        tenantFederatedProviderAccessGrants.tenantId,
        tenantFederatedProviderAccessGrants.id,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "tenant_federated_provider_profile_contributions_id_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "tenant_federated_provider_profile_contributions_present_check",
      sql`${table.displayName} is not null or ${table.username} is not null or ${table.email} is not null`,
    ),
    check(
      "tenant_federated_provider_profile_contributions_value_check",
      sql`${table.mappingRevision} > 0 and ${table.version} > 0
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
      "tenant_federated_provider_profile_contributions_lifecycle_check",
      sql`${table.retiredAt} is null or ${table.retiredAt} >= ${table.observedAt}`,
    ),
  ],
).enableRLS();
