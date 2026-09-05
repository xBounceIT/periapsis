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
  text,
  timestamp,
  unique,
  uniqueIndex,
  uuid,
} from "drizzle-orm/pg-core";

import { authSessions, totpCredentials } from "./authentication.js";
import { bytea } from "./binary.js";
import {
  authProviderKind,
  identityDeprovisionMode,
  identityJitMode,
  identityNoMatchPolicy,
  identitySubjectFormat,
  ldapAccountStatusMode,
  ldapNestedGroupMode,
  ldapProviderTemplate,
  ldapReferralMode,
  ldapTransport,
} from "./enums.js";
import {
  platformAuthProviders,
  platformFederatedProviderPolicies,
} from "./identity-platform-federation.js";
import { identityKeyringVersions } from "./identity-providers.js";
import { users } from "./identity.js";
import { platformRoles, userPlatformRoles } from "./platform.js";

/**
 * Platform LDAP is a provider-global trust boundary. None of these tables has
 * a nullable or synthetic tenant discriminator; tenant admission remains in
 * the independent platform-provider binding family.
 */
export const platformLdapProviderConfigurations = pgTable(
  "platform_ldap_provider_configurations",
  {
    providerId: uuid("provider_id").primaryKey(),
    providerKind: authProviderKind("provider_kind").notNull().default("ldap"),
    template: ldapProviderTemplate("template").notNull(),
    verifyCertificate: boolean("verify_certificate").notNull().default(true),
    customCaPem: text("custom_ca_pem"),
    connectTimeoutMs: integer("connect_timeout_ms").notNull().default(3000),
    operationTimeoutMs: integer("operation_timeout_ms")
      .notNull()
      .default(10000),
    bindDn: text("bind_dn").notNull(),
    userBaseDn: text("user_base_dn").notNull(),
    groupBaseDn: text("group_base_dn"),
    userSearchFilter: text("user_search_filter").notNull(),
    groupSearchFilter: text("group_search_filter"),
    userDnTemplate: text("user_dn_template"),
    pageSize: integer("page_size").notNull().default(200),
    maxPages: integer("max_pages").notNull().default(100),
    maxEntries: integer("max_entries").notNull().default(5000),
    maxResponseBytes: integer("max_response_bytes")
      .notNull()
      .default(10_485_760),
    referralMode: ldapReferralMode("referral_mode")
      .notNull()
      .default("disabled"),
    maxReferralHops: integer("max_referral_hops").notNull().default(0),
    nestedGroupMode: ldapNestedGroupMode("nested_group_mode")
      .notNull()
      .default("disabled"),
    maxNestedGroupDepth: integer("max_nested_group_depth").notNull().default(0),
    maxGroups: integer("max_groups").notNull().default(1000),
    firstNameAttribute: text("first_name_attribute").notNull(),
    lastNameAttribute: text("last_name_attribute").notNull(),
    displayNameAttribute: text("display_name_attribute").notNull(),
    usernameAttribute: text("username_attribute").notNull(),
    alternateUsernameAttribute: text("alternate_username_attribute"),
    emailAttribute: text("email_attribute"),
    immutableSubjectAttribute: text("immutable_subject_attribute").notNull(),
    immutableSubjectFormat: identitySubjectFormat(
      "immutable_subject_format",
    ).notNull(),
    groupMembershipAttribute: text("group_membership_attribute"),
    posixMemberUidAttribute: text("posix_member_uid_attribute"),
    posixGidNumberAttribute: text("posix_gid_number_attribute"),
    accountStatusMode: ldapAccountStatusMode("account_status_mode")
      .notNull()
      .default("none"),
    accountStatusAttribute: text("account_status_attribute"),
    accountDisabledValue: text("account_disabled_value"),
    jitMode: identityJitMode("jit_mode").notNull().default("existing_identity"),
    noMatchPolicy: identityNoMatchPolicy("no_match_policy")
      .notNull()
      .default("deny"),
    deprovisionMode: identityDeprovisionMode("deprovision_mode")
      .notNull()
      .default("immediate"),
    deprovisionGraceSeconds: integer("deprovision_grace_seconds")
      .notNull()
      .default(0),
    syncIntervalSeconds: integer("sync_interval_seconds"),
    configurationRevision: bigint("configuration_revision", {
      mode: "bigint",
    })
      .notNull()
      .default(sql`1`),
    securityRevision: bigint("security_revision", { mode: "bigint" })
      .notNull()
      .default(sql`1`),
    mappingRevision: bigint("mapping_revision", { mode: "bigint" })
      .notNull()
      .default(sql`1`),
    updatedByUserId: uuid("updated_by_user_id")
      .notNull()
      .references(() => users.id, { onDelete: "restrict" }),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    unique("platform_ldap_provider_configurations_kind_key").on(
      table.providerId,
      table.providerKind,
    ),
    foreignKey({
      name: "platform_ldap_provider_configurations_provider_fk",
      columns: [table.providerId, table.providerKind],
      foreignColumns: [platformAuthProviders.id, platformAuthProviders.kind],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "platform_ldap_provider_configurations_policy_fk",
      columns: [table.providerId, table.providerKind],
      foreignColumns: [
        platformFederatedProviderPolicies.providerId,
        platformFederatedProviderPolicies.providerKind,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "platform_ldap_provider_configurations_kind_check",
      sql`${table.providerKind} = 'ldap'`,
    ),
    check(
      "platform_ldap_provider_configurations_ca_check",
      sql`${table.customCaPem} is null
        or char_length(${table.customCaPem}) between 1 and 131072`,
    ),
    check(
      "platform_ldap_provider_configurations_timeout_check",
      sql`${table.connectTimeoutMs} between 100 and 30000
        and ${table.operationTimeoutMs} between 100 and 60000
        and ${table.connectTimeoutMs} <= ${table.operationTimeoutMs}`,
    ),
    check(
      "platform_ldap_provider_configurations_dn_check",
      sql`${table.bindDn} = btrim(${table.bindDn})
        and char_length(${table.bindDn}) between 1 and 2048
        and ${table.userBaseDn} = btrim(${table.userBaseDn})
        and char_length(${table.userBaseDn}) between 1 and 2048
        and (${table.groupBaseDn} is null or (
          ${table.groupBaseDn} = btrim(${table.groupBaseDn})
          and char_length(${table.groupBaseDn}) between 1 and 2048))`,
    ),
    check(
      "platform_ldap_provider_configurations_filter_check",
      sql`${table.userSearchFilter} = btrim(${table.userSearchFilter})
        and char_length(${table.userSearchFilter}) between 1 and 4096
        and (${table.groupSearchFilter} is null or (
          ${table.groupSearchFilter} = btrim(${table.groupSearchFilter})
          and char_length(${table.groupSearchFilter}) between 1 and 4096))
        and (${table.userDnTemplate} is null or (
          ${table.userDnTemplate} = btrim(${table.userDnTemplate})
          and char_length(${table.userDnTemplate}) between 1 and 2048))`,
    ),
    check(
      "platform_ldap_provider_configurations_budget_check",
      sql`${table.pageSize} between 1 and 1000
        and ${table.maxPages} between 1 and 1000
        and ${table.maxEntries} between 1 and 100000
        and ${table.maxResponseBytes} between 1024 and 52428800
        and ${table.maxGroups} between 1 and 10000`,
    ),
    check(
      "platform_ldap_provider_configurations_referral_check",
      sql`(${table.referralMode} = 'disabled' and ${table.maxReferralHops} = 0)
        or (${table.referralMode} = 'configured_endpoints'
          and ${table.maxReferralHops} between 1 and 3)`,
    ),
    check(
      "platform_ldap_provider_configurations_nested_group_check",
      sql`(${table.nestedGroupMode} = 'disabled' and ${table.maxNestedGroupDepth} = 0)
        or (${table.nestedGroupMode} <> 'disabled'
          and ${table.maxNestedGroupDepth} between 1 and 20)`,
    ),
    check(
      "platform_ldap_provider_configurations_attribute_check",
      sql`${table.firstNameAttribute} = btrim(${table.firstNameAttribute})
        and char_length(${table.firstNameAttribute}) between 1 and 128
        and ${table.lastNameAttribute} = btrim(${table.lastNameAttribute})
        and char_length(${table.lastNameAttribute}) between 1 and 128
        and ${table.displayNameAttribute} = btrim(${table.displayNameAttribute})
        and char_length(${table.displayNameAttribute}) between 1 and 128
        and ${table.usernameAttribute} = btrim(${table.usernameAttribute})
        and char_length(${table.usernameAttribute}) between 1 and 128
        and ${table.immutableSubjectAttribute} = btrim(${table.immutableSubjectAttribute})
        and char_length(${table.immutableSubjectAttribute}) between 1 and 128
        and (${table.alternateUsernameAttribute} is null or char_length(btrim(${table.alternateUsernameAttribute})) between 1 and 128)
        and (${table.emailAttribute} is null or char_length(btrim(${table.emailAttribute})) between 1 and 128)
        and (${table.groupMembershipAttribute} is null or char_length(btrim(${table.groupMembershipAttribute})) between 1 and 128)
        and (${table.posixMemberUidAttribute} is null or char_length(btrim(${table.posixMemberUidAttribute})) between 1 and 128)
        and (${table.posixGidNumberAttribute} is null or char_length(btrim(${table.posixGidNumberAttribute})) between 1 and 128)`,
    ),
    check(
      "platform_ldap_provider_configurations_status_check",
      sql`(${table.accountStatusMode} = 'none'
          and ${table.accountStatusAttribute} is null
          and ${table.accountDisabledValue} is null)
        or (${table.accountStatusMode} = 'active_directory_uac'
          and char_length(btrim(${table.accountStatusAttribute})) between 1 and 128
          and ${table.accountDisabledValue} is null)
        or (${table.accountStatusMode} = 'attribute_equals'
          and char_length(btrim(${table.accountStatusAttribute})) between 1 and 128
          and char_length(btrim(${table.accountDisabledValue})) between 1 and 256)`,
    ),
    check(
      "platform_ldap_provider_configurations_policy_check",
      sql`${table.jitMode} in ('disabled','existing_identity')
        and ${table.noMatchPolicy} = 'deny'
        and ((${table.deprovisionMode} <> 'grace' and ${table.deprovisionGraceSeconds} = 0)
          or (${table.deprovisionMode} = 'grace'
            and ${table.deprovisionGraceSeconds} between 60 and 2592000))
        and (${table.syncIntervalSeconds} is null
          or ${table.syncIntervalSeconds} between 300 and 2592000)`,
    ),
    check(
      "platform_ldap_provider_configurations_revision_check",
      sql`${table.configurationRevision} between 1 and 9007199254740991
        and ${table.securityRevision} between 1 and 9007199254740991
        and ${table.mappingRevision} between 1 and 9007199254740991
        and ${table.updatedAt} >= ${table.createdAt}`,
    ),
  ],
).enableRLS();

export const platformLdapProviderEndpoints = pgTable(
  "platform_ldap_provider_endpoints",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    providerId: uuid("provider_id").notNull(),
    providerKind: authProviderKind("provider_kind").notNull().default("ldap"),
    priority: integer("priority").notNull(),
    host: text("host").notNull(),
    port: integer("port").notNull(),
    transport: ldapTransport("transport").notNull(),
    tlsServerName: text("tls_server_name").notNull(),
    referralAllowed: boolean("referral_allowed").notNull().default(false),
    enabled: boolean("enabled").notNull().default(true),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    unique("platform_ldap_provider_endpoints_provider_priority_key").on(
      table.providerId,
      table.priority,
    ),
    unique("platform_ldap_provider_endpoints_provider_endpoint_key").on(
      table.providerId,
      table.transport,
      table.host,
      table.port,
    ),
    index("platform_ldap_provider_endpoints_live_idx").on(
      table.providerId,
      table.enabled,
      table.priority,
    ),
    foreignKey({
      name: "platform_ldap_provider_endpoints_provider_fk",
      columns: [table.providerId, table.providerKind],
      foreignColumns: [
        platformLdapProviderConfigurations.providerId,
        platformLdapProviderConfigurations.providerKind,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "platform_ldap_provider_endpoints_value_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true
        and ${table.providerKind} = 'ldap'
        and ${table.priority} between 1 and 8
        and ${table.host} = lower(btrim(${table.host}))
        and char_length(${table.host}) between 1 and 253
        and ${table.host} !~ '[[:space:][:cntrl:]/@?#]'
        and ${table.port} between 1 and 65535
        and ${table.tlsServerName} = lower(btrim(${table.tlsServerName}))
        and char_length(${table.tlsServerName}) between 1 and 253
        and ${table.tlsServerName} !~ '[[:space:][:cntrl:]/@?#]'
        and ${table.updatedAt} >= ${table.createdAt}`,
    ),
  ],
).enableRLS();

/** Encrypted, write-only bind material; no projection exposes this row. */
export const platformLdapBindSecrets = pgTable(
  "platform_ldap_bind_secrets",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    providerId: uuid("provider_id").notNull(),
    providerKind: authProviderKind("provider_kind").notNull().default("ldap"),
    revision: bigint("revision", { mode: "bigint" }).notNull(),
    keyVersion: integer("key_version")
      .notNull()
      .references(() => identityKeyringVersions.keyVersion, {
        onDelete: "restrict",
      }),
    nonce: bytea("nonce").notNull(),
    ciphertext: bytea("ciphertext").notNull(),
    rotatedByUserId: uuid("rotated_by_user_id")
      .notNull()
      .references(() => users.id, { onDelete: "restrict" }),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    retiredAt: timestamp("retired_at", { withTimezone: true, mode: "date" }),
  },
  (table) => [
    unique("platform_ldap_bind_secrets_provider_revision_key").on(
      table.providerId,
      table.revision,
    ),
    uniqueIndex("platform_ldap_bind_secrets_live_key")
      .on(table.providerId)
      .where(sql`${table.retiredAt} is null`),
    foreignKey({
      name: "platform_ldap_bind_secrets_provider_fk",
      columns: [table.providerId, table.providerKind],
      foreignColumns: [
        platformLdapProviderConfigurations.providerId,
        platformLdapProviderConfigurations.providerKind,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "platform_ldap_bind_secrets_value_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true
        and ${table.providerKind} = 'ldap'
        and ${table.revision} between 1 and 9007199254740991
        and ${table.keyVersion} between 1 and 32767
        and octet_length(${table.nonce}) = 12
        and octet_length(${table.ciphertext}) between 17 and 8192
        and (${table.retiredAt} is null or ${table.retiredAt} >= ${table.createdAt})`,
    ),
  ],
).enableRLS();

/** LDAP group matching never targets users or permissions directly. */
export const platformLdapMappingRules = pgTable(
  "platform_ldap_mapping_rules",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    providerId: uuid("provider_id").notNull(),
    matcherType: text("matcher_type").notNull(),
    matcherValue: text("matcher_value").notNull(),
    caseSensitive: boolean("case_sensitive").notNull().default(false),
    priority: integer("priority").notNull(),
    platformRoleId: uuid("platform_role_id")
      .notNull()
      .references(() => platformRoles.id, { onDelete: "restrict" }),
    reconciliationMode: text("reconciliation_mode").notNull(),
    enabled: boolean("enabled").notNull().default(false),
    notes: text("notes").notNull().default(""),
    lastMatchedAt: timestamp("last_matched_at", {
      withTimezone: true,
      mode: "date",
    }),
    version: bigint("version", { mode: "bigint" })
      .notNull()
      .default(sql`1`),
    createdByUserId: uuid("created_by_user_id")
      .notNull()
      .references(() => users.id, { onDelete: "restrict" }),
    updatedByUserId: uuid("updated_by_user_id")
      .notNull()
      .references(() => users.id, { onDelete: "restrict" }),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    archivedAt: timestamp("archived_at", { withTimezone: true, mode: "date" }),
  },
  (table) => [
    unique("platform_ldap_mapping_rules_provider_priority_key").on(
      table.providerId,
      table.priority,
    ),
    index("platform_ldap_mapping_rules_provider_live_idx")
      .on(table.providerId, table.enabled, table.priority, table.id)
      .where(sql`${table.archivedAt} is null`),
    foreignKey({
      name: "platform_ldap_mapping_rules_provider_fk",
      columns: [table.providerId],
      foreignColumns: [platformLdapProviderConfigurations.providerId],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "platform_ldap_mapping_rules_value_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true
        and ${table.matcherType} in ('exact_dn','exact_cn','regex')
        and ${table.matcherValue} = btrim(${table.matcherValue})
        and octet_length(convert_to(${table.matcherValue}, 'UTF8')) between 1 and 2048
        and ${table.matcherValue} !~ '[[:cntrl:]]'
        and ${table.priority} between 0 and 1000000
        and ${table.reconciliationMode} in ('additive','authoritative')
        and ${table.notes} = btrim(${table.notes})
        and octet_length(convert_to(${table.notes}, 'UTF8')) <= 2048
        and ${table.notes} !~ '[[:cntrl:]]'
        and ${table.version} between 1 and 2147483647
        and ${table.updatedAt} >= ${table.createdAt}
        and (${table.lastMatchedAt} is null or ${table.lastMatchedAt} >= ${table.createdAt})
        and (${table.archivedAt} is null or (
          not ${table.enabled} and ${table.archivedAt} >= ${table.createdAt}))`,
    ),
  ],
).enableRLS();

/** Provider-global subject identity, protected independently from tenant LDAP. */
export const platformLdapExternalIdentities = pgTable(
  "platform_ldap_external_identities",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    providerId: uuid("provider_id").notNull(),
    userId: uuid("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "restrict" }),
    subjectFormat: identitySubjectFormat("subject_format").notNull(),
    subjectCiphertext: bytea("subject_ciphertext").notNull(),
    subjectNonce: bytea("subject_nonce").notNull(),
    keyVersion: integer("key_version")
      .notNull()
      .references(() => identityKeyringVersions.keyVersion, {
        onDelete: "restrict",
      }),
    username: text("username").notNull(),
    email: text("email"),
    displayName: text("display_name").notNull(),
    firstName: text("first_name"),
    lastName: text("last_name"),
    groupsDigest: bytea("groups_digest").notNull(),
    configurationRevision: bigint("configuration_revision", {
      mode: "bigint",
    }).notNull(),
    securityRevision: bigint("security_revision", { mode: "bigint" }).notNull(),
    mappingRevision: bigint("mapping_revision", { mode: "bigint" }).notNull(),
    lastObservedAt: timestamp("last_observed_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    disabledAt: timestamp("disabled_at", { withTimezone: true, mode: "date" }),
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
    unique("platform_ldap_external_identities_provider_key").on(
      table.providerId,
      table.id,
    ),
    uniqueIndex("platform_ldap_external_identities_live_user_key")
      .on(table.providerId, table.userId)
      .where(sql`${table.retiredAt} is null`),
    foreignKey({
      name: "platform_ldap_external_identities_provider_fk",
      columns: [table.providerId],
      foreignColumns: [platformLdapProviderConfigurations.providerId],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "platform_ldap_external_identities_value_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true
        and octet_length(${table.subjectCiphertext}) between 17 and 4112
        and octet_length(${table.subjectNonce}) = 12
        and ${table.keyVersion} between 1 and 32767
        and ${table.username} = btrim(${table.username})
        and octet_length(convert_to(${table.username}, 'UTF8')) between 1 and 1280
        and (${table.email} is null or (
          ${table.email} = lower(btrim(${table.email}))
          and position('@' in ${table.email}) > 1
          and char_length(${table.email}) <= 320))
        and ${table.displayName} = btrim(${table.displayName})
        and char_length(${table.displayName}) between 1 and 160
        and octet_length(${table.groupsDigest}) = 32
        and ${table.configurationRevision} between 1 and 9007199254740991
        and ${table.securityRevision} between 1 and 9007199254740991
        and ${table.mappingRevision} between 1 and 9007199254740991
        and ${table.version} between 1 and 2147483647
        and ${table.lastObservedAt} >= ${table.createdAt}
        and ${table.updatedAt} >= ${table.createdAt}
        and (${table.disabledAt} is null or ${table.disabledAt} >= ${table.createdAt})
        and (${table.retiredAt} is null or ${table.retiredAt} >= ${table.createdAt})`,
    ),
  ],
).enableRLS();

export const platformLdapExternalIdentityAliases = pgTable(
  "platform_ldap_external_identity_aliases",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
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
    unique("platform_ldap_external_identity_aliases_digest_key").on(
      table.providerId,
      table.keyVersion,
      table.subjectDigest,
    ),
    unique("platform_ldap_external_identity_aliases_version_key").on(
      table.externalIdentityId,
      table.keyVersion,
    ),
    foreignKey({
      name: "platform_ldap_external_identity_aliases_identity_fk",
      columns: [table.providerId, table.externalIdentityId],
      foreignColumns: [
        platformLdapExternalIdentities.providerId,
        platformLdapExternalIdentities.id,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "platform_ldap_external_identity_aliases_value_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true
        and ${table.keyVersion} between 1 and 32767
        and octet_length(${table.subjectDigest}) = 32
        and (${table.retiredAt} is null or ${table.retiredAt} >= ${table.createdAt})`,
    ),
  ],
).enableRLS();

/** Source ownership prevents LDAP reconciliation from revoking manual grants. */
export const platformLdapRoleGrants = pgTable(
  "platform_ldap_role_grants",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    providerId: uuid("provider_id").notNull(),
    externalIdentityId: uuid("external_identity_id").notNull(),
    mappingRuleId: uuid("mapping_rule_id").notNull(),
    userId: uuid("user_id").notNull(),
    platformRoleId: uuid("platform_role_id").notNull(),
    userPlatformRoleId: uuid("user_platform_role_id").notNull(),
    sourceMappingRevision: bigint("source_mapping_revision", {
      mode: "bigint",
    }).notNull(),
    grantedAt: timestamp("granted_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    refreshedAt: timestamp("refreshed_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    revokedAt: timestamp("revoked_at", { withTimezone: true, mode: "date" }),
  },
  (table) => [
    uniqueIndex("platform_ldap_role_grants_live_key")
      .on(
        table.providerId,
        table.externalIdentityId,
        table.mappingRuleId,
        table.platformRoleId,
      )
      .where(sql`${table.revokedAt} is null`),
    foreignKey({
      name: "platform_ldap_role_grants_identity_fk",
      columns: [table.providerId, table.externalIdentityId],
      foreignColumns: [
        platformLdapExternalIdentities.providerId,
        platformLdapExternalIdentities.id,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "platform_ldap_role_grants_mapping_fk",
      columns: [table.mappingRuleId],
      foreignColumns: [platformLdapMappingRules.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "platform_ldap_role_grants_user_role_fk",
      columns: [table.userPlatformRoleId],
      foreignColumns: [userPlatformRoles.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "platform_ldap_role_grants_value_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true
        and ${table.sourceMappingRevision} between 1 and 9007199254740991
        and ${table.refreshedAt} >= ${table.grantedAt}
        and (${table.revokedAt} is null or ${table.revokedAt} >= ${table.grantedAt})`,
    ),
  ],
).enableRLS();

/** Bounded, non-oracular login receipt; passwords and raw attributes never persist. */
export const platformLdapAuthenticationRuns = pgTable(
  "platform_ldap_authentication_runs",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    providerId: uuid("provider_id").notNull(),
    receiptDigest: bytea("receipt_digest").notNull(),
    networkRateDigest: bytea("network_rate_digest").notNull(),
    accountRateDigest: bytea("account_rate_digest").notNull(),
    providerRateDigest: bytea("provider_rate_digest").notNull(),
    providerVersion: bigint("provider_version", { mode: "bigint" }).notNull(),
    configurationRevision: bigint("configuration_revision", {
      mode: "bigint",
    }).notNull(),
    securityRevision: bigint("security_revision", { mode: "bigint" }).notNull(),
    mappingRevision: bigint("mapping_revision", { mode: "bigint" }).notNull(),
    state: text("state").notNull().default("pending"),
    failureCategory: text("failure_category"),
    externalIdentityId: uuid("external_identity_id"),
    userId: uuid("user_id"),
    sessionId: uuid("session_id"),
    resultDigest: bytea("result_digest"),
    startedAt: timestamp("started_at", {
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
  },
  (table) => [
    unique("platform_ldap_authentication_runs_receipt_key").on(
      table.receiptDigest,
    ),
    index("platform_ldap_authentication_runs_expiry_idx").on(
      table.state,
      table.expiresAt,
      table.id,
    ),
    foreignKey({
      name: "platform_ldap_authentication_runs_provider_fk",
      columns: [table.providerId],
      foreignColumns: [platformLdapProviderConfigurations.providerId],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "platform_ldap_authentication_runs_value_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true
        and octet_length(${table.receiptDigest}) = 32
        and octet_length(${table.networkRateDigest}) = 32
        and octet_length(${table.accountRateDigest}) = 32
        and octet_length(${table.providerRateDigest}) = 32
        and ${table.providerVersion} between 1 and 2147483647
        and ${table.configurationRevision} between 1 and 9007199254740991
        and ${table.securityRevision} between 1 and 9007199254740991
        and ${table.mappingRevision} between 1 and 9007199254740991
        and ${table.expiresAt} between ${table.startedAt} + interval '30 seconds'
          and ${table.startedAt} + interval '5 minutes'
        and ((${table.state} = 'pending'
          and ${table.failureCategory} is null
          and ${table.externalIdentityId} is null
          and ${table.userId} is null and ${table.sessionId} is null
          and ${table.resultDigest} is null and ${table.completedAt} is null)
        or (${table.state} = 'succeeded'
          and ${table.failureCategory} is null
          and ${table.externalIdentityId} is not null
          and ${table.userId} is not null and ${table.sessionId} is not null
          and octet_length(${table.resultDigest}) = 32
          and ${table.completedAt} between ${table.startedAt} and ${table.expiresAt})
        or (${table.state} in ('denied','failed','stale')
          and ${table.failureCategory} is not null
          and ${table.externalIdentityId} is null
          and ${table.userId} is null and ${table.sessionId} is null
          and ${table.resultDigest} is null
          and ${table.completedAt} between ${table.startedAt} and ${table.expiresAt}))`,
    ),
  ],
).enableRLS();

/** Exact provider, identity, factor, and mapping pins for a tenantless session. */
export const platformLdapSessionProvenance = pgTable(
  "platform_ldap_session_provenance",
  {
    sessionId: uuid("session_id").primaryKey(),
    userId: uuid("user_id").notNull(),
    providerId: uuid("provider_id").notNull(),
    externalIdentityId: uuid("external_identity_id").notNull(),
    authenticationRunId: uuid("authentication_run_id").notNull(),
    providerVersion: bigint("provider_version", { mode: "bigint" }).notNull(),
    configurationRevision: bigint("configuration_revision", {
      mode: "bigint",
    }).notNull(),
    securityRevision: bigint("security_revision", { mode: "bigint" }).notNull(),
    mappingRevision: bigint("mapping_revision", { mode: "bigint" }).notNull(),
    identityVersion: bigint("identity_version", { mode: "bigint" }).notNull(),
    totpCredentialId: uuid("totp_credential_id").notNull(),
    totpSecurityRevision: bigint("totp_security_revision", {
      mode: "bigint",
    }).notNull(),
    authenticatedAt: timestamp("authenticated_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
  },
  (table) => [
    unique("platform_ldap_session_provenance_exact_key").on(
      table.sessionId,
      table.userId,
      table.providerId,
      table.externalIdentityId,
    ),
    foreignKey({
      name: "platform_ldap_session_provenance_session_fk",
      columns: [table.sessionId],
      foreignColumns: [authSessions.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "platform_ldap_session_provenance_identity_fk",
      columns: [table.providerId, table.externalIdentityId],
      foreignColumns: [
        platformLdapExternalIdentities.providerId,
        platformLdapExternalIdentities.id,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "platform_ldap_session_provenance_run_fk",
      columns: [table.authenticationRunId],
      foreignColumns: [platformLdapAuthenticationRuns.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "platform_ldap_session_provenance_totp_fk",
      columns: [table.totpCredentialId, table.userId],
      foreignColumns: [totpCredentials.id, totpCredentials.userId],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "platform_ldap_session_provenance_value_check",
      sql`${table.providerVersion} between 1 and 2147483647
        and ${table.configurationRevision} between 1 and 9007199254740991
        and ${table.securityRevision} between 1 and 9007199254740991
        and ${table.mappingRevision} between 1 and 9007199254740991
        and ${table.identityVersion} between 1 and 2147483647
        and ${table.totpSecurityRevision} between 1 and 9007199254740991`,
    ),
  ],
).enableRLS();

/** Sanitized, bounded evidence for connection/bind/search/mapping tests. */
export const platformLdapTestRuns = pgTable(
  "platform_ldap_test_runs",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    providerId: uuid("provider_id").notNull(),
    actorUserId: uuid("actor_user_id")
      .notNull()
      .references(() => users.id, { onDelete: "restrict" }),
    kind: text("kind").notNull(),
    state: text("state").notNull().default("pending"),
    outcome: text("outcome"),
    category: text("category"),
    endpointPriority: integer("endpoint_priority"),
    durationMs: integer("duration_ms"),
    matchedEntryCount: integer("matched_entry_count"),
    attributes: jsonb("attributes"),
    providerVersion: bigint("provider_version", { mode: "bigint" }).notNull(),
    configurationRevision: bigint("configuration_revision", {
      mode: "bigint",
    }).notNull(),
    mappingRevision: bigint("mapping_revision", { mode: "bigint" }).notNull(),
    secretRevision: bigint("secret_revision", { mode: "bigint" }),
    requestId: uuid("request_id").notNull(),
    correlationId: uuid("correlation_id").notNull(),
    startedAt: timestamp("started_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    completedAt: timestamp("completed_at", {
      withTimezone: true,
      mode: "date",
    }),
  },
  (table) => [
    index("platform_ldap_test_runs_provider_idx").on(
      table.providerId,
      table.startedAt,
      table.id,
    ),
    foreignKey({
      name: "platform_ldap_test_runs_provider_fk",
      columns: [table.providerId],
      foreignColumns: [platformLdapProviderConfigurations.providerId],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "platform_ldap_test_runs_value_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true
        and ${table.kind} in ('connection','bind','search_user','filter','mapping_dry_run')
        and ${table.state} in ('pending','completed')
        and ${table.providerVersion} between 1 and 2147483647
        and ${table.configurationRevision} between 1 and 9007199254740991
        and ${table.mappingRevision} between 1 and 9007199254740991
        and (${table.secretRevision} is null
          or ${table.secretRevision} between 1 and 9007199254740991)
        and ((${table.state} = 'pending'
          and ${table.outcome} is null and ${table.category} is null
          and ${table.endpointPriority} is null and ${table.durationMs} is null
          and ${table.matchedEntryCount} is null and ${table.attributes} is null
          and ${table.completedAt} is null)
        or (${table.state} = 'completed'
          and ${table.outcome} in ('success','failure','inconclusive')
          and ${table.category} in (
            'success','cancelled','configuration_invalid','destination_blocked',
            'dns_failed','connect_failed','connect_timeout','tls_failed',
            'certificate_rejected','bind_rejected','user_not_found',
            'user_ambiguous','mapping_denied','stale_configuration','protocol_failed')
          and ${table.durationMs} between 0 and 120000
          and (${table.matchedEntryCount} is null
            or ${table.matchedEntryCount} between 0 and 1000)
          and (${table.attributes} is null or (
            jsonb_typeof(${table.attributes}) = 'array'
            and pg_column_size(${table.attributes}) between 2 and 32768))
          and ${table.completedAt} >= ${table.startedAt}))`,
    ),
  ],
).enableRLS();
