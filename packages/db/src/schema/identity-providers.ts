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
  ldapProviderTestCategory,
  ldapProviderTestKind,
  ldapProviderTestOutcome,
  ldapProviderTestStatus,
  ldapReferralMode,
  ldapTransport,
} from "./enums.js";
import { tenantMemberships } from "./identity.js";
import { tenants } from "./tenancy.js";

export const identityKeyringVersions = pgTable(
  "identity_keyring_versions",
  {
    keyVersion: integer("key_version").primaryKey(),
    verifier: bytea("verifier").notNull(),
    isActive: boolean("is_active").notNull().default(false),
    boundAt: timestamp("bound_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    retiredAt: timestamp("retired_at", {
      withTimezone: true,
      mode: "date",
    }),
  },
  (table) => [
    unique("identity_keyring_versions_verifier_key").on(table.verifier),
    uniqueIndex("identity_keyring_versions_single_active_key")
      .on(table.isActive)
      .where(sql`${table.isActive}`),
    check(
      "identity_keyring_versions_version_check",
      sql`${table.keyVersion} between 1 and 32767`,
    ),
    check(
      "identity_keyring_versions_verifier_check",
      sql`octet_length(${table.verifier}) = 32`,
    ),
    check(
      "identity_keyring_versions_retirement_check",
      sql`(${table.retiredAt} is null or ${table.retiredAt} >= ${table.boundAt})
        and (not ${table.isActive} or ${table.retiredAt} is null)`,
    ),
  ],
).enableRLS();

export const tenantAuthProviders = pgTable(
  "tenant_auth_providers",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    key: text("key").notNull(),
    displayName: text("display_name").notNull(),
    description: text("description").notNull().default(""),
    kind: authProviderKind("kind").notNull(),
    enabled: boolean("enabled").notNull().default(false),
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
  (table) => [
    unique("tenant_auth_providers_tenant_id_key").on(table.tenantId, table.id),
    unique("tenant_auth_providers_tenant_id_kind_key").on(
      table.tenantId,
      table.id,
      table.kind,
    ),
    unique("tenant_auth_providers_tenant_key_key").on(
      table.tenantId,
      table.key,
    ),
    index("tenant_auth_providers_tenant_kind_idx").on(
      table.tenantId,
      table.kind,
      table.id,
    ),
    uniqueIndex("tenant_auth_providers_tenant_active_display_key")
      .on(table.tenantId, table.displayName)
      .where(sql`${table.archivedAt} is null`),
    foreignKey({
      name: "tenant_auth_providers_creator_membership_fk",
      columns: [table.tenantId, table.createdByMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_auth_providers_updater_membership_fk",
      columns: [table.tenantId, table.updatedByMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_auth_providers_archiver_membership_fk",
      columns: [table.tenantId, table.archivedByMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "tenant_auth_providers_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "tenant_auth_providers_implemented_kind_check",
      sql`${table.kind} in ('ldap', 'oidc', 'saml')`,
    ),
    check(
      "tenant_auth_providers_key_check",
      sql`${table.key} ~ '^[a-z][a-z0-9_-]{2,63}$'`,
    ),
    check(
      "tenant_auth_providers_display_name_check",
      sql`btrim(${table.displayName}) <> ''
        and char_length(${table.displayName}) <= 120
        and ${table.displayName} !~ '[[:cntrl:]]'`,
    ),
    check(
      "tenant_auth_providers_description_check",
      sql`char_length(${table.description}) <= 1000
        and ${table.description} !~ '[[:cntrl:]]'`,
    ),
    check(
      "tenant_auth_providers_archive_check",
      sql`(${table.archivedAt} is null
          and ${table.archivedByMembershipId} is null
          and ${table.archiveReason} is null)
        or (${table.archivedAt} is not null
          and ${table.archivedByMembershipId} is not null
          and ${table.archiveReason} is not null
          and ${table.enabled} is false
          and ${table.archivedAt} >= ${table.createdAt}
          and btrim(${table.archiveReason}) <> ''
          and char_length(${table.archiveReason}) <= 500
          and ${table.archiveReason} !~ '[[:cntrl:]]')`,
    ),
    check("tenant_auth_providers_version_check", sql`${table.version} > 0`),
    check(
      "tenant_auth_providers_updated_check",
      sql`${table.updatedAt} >= ${table.createdAt}
        and (${table.archivedAt} is null or ${table.updatedAt} >= ${table.archivedAt})`,
    ),
  ],
).enableRLS();

export const tenantLdapProviderConfigs = pgTable(
  "tenant_ldap_provider_configs",
  {
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    providerId: uuid("provider_id").notNull(),
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
    jitMode: identityJitMode("jit_mode").notNull().default("disabled"),
    noMatchPolicy: identityNoMatchPolicy("no_match_policy")
      .notNull()
      .default("deny"),
    deprovisionMode: identityDeprovisionMode("deprovision_mode")
      .notNull()
      .default("retain"),
    deprovisionGraceSeconds: integer("deprovision_grace_seconds")
      .notNull()
      .default(0),
    syncIntervalSeconds: integer("sync_interval_seconds"),
    updatedByMembershipId: uuid("updated_by_membership_id").notNull(),
    version: integer("version").notNull().default(1),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    primaryKey({
      name: "tenant_ldap_provider_configs_pkey",
      columns: [table.tenantId, table.providerId],
    }),
    foreignKey({
      name: "tenant_ldap_provider_configs_provider_fk",
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
      name: "tenant_ldap_provider_configs_updater_fk",
      columns: [table.tenantId, table.updatedByMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "tenant_ldap_provider_configs_kind_check",
      sql`${table.providerKind} = 'ldap'`,
    ),
    check(
      "tenant_ldap_provider_configs_ca_check",
      sql`${table.customCaPem} is null
        or char_length(${table.customCaPem}) between 1 and 131072`,
    ),
    check(
      "tenant_ldap_provider_configs_timeout_check",
      sql`${table.connectTimeoutMs} between 100 and 30000
        and ${table.operationTimeoutMs} between 100 and 60000
        and ${table.connectTimeoutMs} <= ${table.operationTimeoutMs}`,
    ),
    check(
      "tenant_ldap_provider_configs_dn_check",
      sql`btrim(${table.bindDn}) <> ''
        and char_length(${table.bindDn}) <= 2048
        and btrim(${table.userBaseDn}) <> ''
        and char_length(${table.userBaseDn}) <= 2048
        and (${table.groupBaseDn} is null or (
          btrim(${table.groupBaseDn}) <> ''
          and char_length(${table.groupBaseDn}) <= 2048
        ))`,
    ),
    check(
      "tenant_ldap_provider_configs_filter_check",
      sql`btrim(${table.userSearchFilter}) <> ''
        and char_length(${table.userSearchFilter}) <= 4096
        and (${table.groupSearchFilter} is null or (
          btrim(${table.groupSearchFilter}) <> ''
          and char_length(${table.groupSearchFilter}) <= 4096
        ))
        and (${table.userDnTemplate} is null or (
          btrim(${table.userDnTemplate}) <> ''
          and char_length(${table.userDnTemplate}) <= 2048
        ))`,
    ),
    check(
      "tenant_ldap_provider_configs_budget_check",
      sql`${table.pageSize} between 1 and 1000
        and ${table.maxPages} between 1 and 1000
        and ${table.maxEntries} between 1 and 100000
        and ${table.maxResponseBytes} between 1024 and 52428800
        and ${table.maxGroups} between 1 and 10000`,
    ),
    check(
      "tenant_ldap_provider_configs_referral_check",
      sql`(${table.referralMode} = 'disabled' and ${table.maxReferralHops} = 0)
        or (${table.referralMode} = 'configured_endpoints'
          and ${table.maxReferralHops} between 1 and 3)`,
    ),
    check(
      "tenant_ldap_provider_configs_nested_group_check",
      sql`(${table.nestedGroupMode} = 'disabled' and ${table.maxNestedGroupDepth} = 0)
        or (${table.nestedGroupMode} <> 'disabled'
          and ${table.maxNestedGroupDepth} between 1 and 20)`,
    ),
    check(
      "tenant_ldap_provider_configs_attribute_check",
      sql`btrim(${table.firstNameAttribute}) <> ''
        and btrim(${table.lastNameAttribute}) <> ''
        and btrim(${table.displayNameAttribute}) <> ''
        and btrim(${table.usernameAttribute}) <> ''
        and btrim(${table.immutableSubjectAttribute}) <> ''
        and char_length(${table.firstNameAttribute}) <= 128
        and char_length(${table.lastNameAttribute}) <= 128
        and char_length(${table.displayNameAttribute}) <= 128
        and char_length(${table.usernameAttribute}) <= 128
        and char_length(${table.immutableSubjectAttribute}) <= 128
        and (${table.alternateUsernameAttribute} is null or (
          btrim(${table.alternateUsernameAttribute}) <> ''
          and char_length(${table.alternateUsernameAttribute}) <= 128
        ))
        and (${table.emailAttribute} is null or (
          btrim(${table.emailAttribute}) <> ''
          and char_length(${table.emailAttribute}) <= 128
        ))
        and (${table.groupMembershipAttribute} is null or (
          btrim(${table.groupMembershipAttribute}) <> ''
          and char_length(${table.groupMembershipAttribute}) <= 128
        ))
        and (${table.posixMemberUidAttribute} is null or (
          btrim(${table.posixMemberUidAttribute}) <> ''
          and char_length(${table.posixMemberUidAttribute}) <= 128
        ))
        and (${table.posixGidNumberAttribute} is null or (
          btrim(${table.posixGidNumberAttribute}) <> ''
          and char_length(${table.posixGidNumberAttribute}) <= 128
        ))`,
    ),
    check(
      "tenant_ldap_provider_configs_status_attribute_check",
      sql`(${table.accountStatusMode} = 'none'
          and ${table.accountStatusAttribute} is null
          and ${table.accountDisabledValue} is null)
        or (${table.accountStatusMode} = 'active_directory_uac'
          and ${table.accountStatusAttribute} is not null
          and btrim(${table.accountStatusAttribute}) <> ''
          and char_length(${table.accountStatusAttribute}) <= 128
          and ${table.accountDisabledValue} is null)
        or (${table.accountStatusMode} = 'attribute_equals'
          and ${table.accountStatusAttribute} is not null
          and btrim(${table.accountStatusAttribute}) <> ''
          and char_length(${table.accountStatusAttribute}) <= 128
          and ${table.accountDisabledValue} is not null
          and btrim(${table.accountDisabledValue}) <> ''
          and char_length(${table.accountDisabledValue}) <= 256)`,
    ),
    check(
      "tenant_ldap_provider_configs_deprovision_check",
      sql`(${table.deprovisionMode} <> 'grace' and ${table.deprovisionGraceSeconds} = 0)
        or (${table.deprovisionMode} = 'grace'
          and ${table.deprovisionGraceSeconds} between 60 and 2592000)`,
    ),
    check(
      "tenant_ldap_provider_configs_sync_check",
      sql`${table.syncIntervalSeconds} is null
        or ${table.syncIntervalSeconds} between 300 and 2592000`,
    ),
    check(
      "tenant_ldap_provider_configs_version_check",
      sql`${table.version} > 0`,
    ),
    check(
      "tenant_ldap_provider_configs_updated_check",
      sql`${table.updatedAt} >= ${table.createdAt}`,
    ),
  ],
).enableRLS();

export const tenantLdapProviderUrls = pgTable(
  "tenant_ldap_provider_urls",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
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
    unique("tenant_ldap_provider_urls_tenant_id_key").on(
      table.tenantId,
      table.id,
    ),
    unique("tenant_ldap_provider_urls_provider_priority_key").on(
      table.tenantId,
      table.providerId,
      table.priority,
    ),
    unique("tenant_ldap_provider_urls_provider_endpoint_key").on(
      table.tenantId,
      table.providerId,
      table.transport,
      table.host,
      table.port,
    ),
    index("tenant_ldap_provider_urls_provider_enabled_idx").on(
      table.tenantId,
      table.providerId,
      table.enabled,
      table.priority,
    ),
    foreignKey({
      name: "tenant_ldap_provider_urls_provider_fk",
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
      "tenant_ldap_provider_urls_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "tenant_ldap_provider_urls_kind_check",
      sql`${table.providerKind} = 'ldap'`,
    ),
    check(
      "tenant_ldap_provider_urls_priority_check",
      sql`${table.priority} between 1 and 8`,
    ),
    check(
      "tenant_ldap_provider_urls_host_check",
      sql`btrim(${table.host}) <> ''
        and ${table.host} = lower(${table.host})
        and char_length(${table.host}) <= 253
        and ${table.host} !~ '[[:space:][:cntrl:]/@?#]'`,
    ),
    check(
      "tenant_ldap_provider_urls_port_check",
      sql`${table.port} between 1 and 65535`,
    ),
    check(
      "tenant_ldap_provider_urls_tls_name_check",
      sql`btrim(${table.tlsServerName}) <> ''
        and ${table.tlsServerName} = lower(${table.tlsServerName})
        and char_length(${table.tlsServerName}) <= 253
        and ${table.tlsServerName} !~ '[[:space:][:cntrl:]/@?#]'`,
    ),
    check(
      "tenant_ldap_provider_urls_updated_check",
      sql`${table.updatedAt} >= ${table.createdAt}`,
    ),
  ],
).enableRLS();

export const tenantLdapProviderSecrets = pgTable(
  "tenant_ldap_provider_secrets",
  {
    id: uuid("id")
      .notNull()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    providerId: uuid("provider_id").notNull(),
    providerKind: authProviderKind("provider_kind").notNull().default("ldap"),
    secretCiphertext: bytea("secret_ciphertext").notNull(),
    secretNonce: bytea("secret_nonce").notNull(),
    keyVersion: integer("key_version")
      .notNull()
      .references(() => identityKeyringVersions.keyVersion, {
        onDelete: "restrict",
      }),
    encryptionAlgorithm: text("encryption_algorithm")
      .notNull()
      .default("aes-256-gcm"),
    rotatedByMembershipId: uuid("rotated_by_membership_id").notNull(),
    rotatedAt: timestamp("rotated_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    version: integer("version").notNull().default(1),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    primaryKey({
      name: "tenant_ldap_provider_secrets_pkey",
      columns: [table.tenantId, table.providerId],
    }),
    unique("tenant_ldap_provider_secrets_tenant_id_id_unique").on(
      table.tenantId,
      table.id,
    ),
    index("tenant_ldap_provider_secrets_live_key_version_idx").on(
      table.keyVersion,
      table.tenantId,
      table.providerId,
    ),
    foreignKey({
      name: "tenant_ldap_provider_secrets_provider_fk",
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
      name: "tenant_ldap_provider_secrets_rotator_fk",
      columns: [table.tenantId, table.rotatedByMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "tenant_ldap_provider_secrets_kind_check",
      sql`${table.providerKind} = 'ldap'`,
    ),
    check(
      "tenant_ldap_provider_secrets_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "tenant_ldap_provider_secrets_ciphertext_check",
      sql`octet_length(${table.secretCiphertext}) between 17 and 8192
        and octet_length(${table.secretNonce}) = 12`,
    ),
    check(
      "tenant_ldap_provider_secrets_algorithm_check",
      sql`${table.encryptionAlgorithm} = 'aes-256-gcm'`,
    ),
    check(
      "tenant_ldap_provider_secrets_version_check",
      sql`${table.version} > 0`,
    ),
    check(
      "tenant_ldap_provider_secrets_updated_check",
      sql`${table.rotatedAt} >= ${table.createdAt}
        and ${table.updatedAt} >= ${table.rotatedAt}`,
    ),
  ],
).enableRLS();

export const tenantLdapProviderTestRuns = pgTable(
  "tenant_ldap_provider_test_runs",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    providerId: uuid("provider_id").notNull(),
    providerKind: authProviderKind("provider_kind").notNull().default("ldap"),
    testKind: ldapProviderTestKind("test_kind").notNull(),
    status: ldapProviderTestStatus("status").notNull().default("started"),
    outcome: ldapProviderTestOutcome("outcome"),
    category: ldapProviderTestCategory("category"),
    endpointPriority: integer("endpoint_priority"),
    durationMs: integer("duration_ms"),
    providerVersion: integer("provider_version").notNull(),
    configurationVersion: integer("configuration_version").notNull(),
    secretVersion: integer("secret_version"),
    startedByMembershipId: uuid("started_by_membership_id").notNull(),
    completedByMembershipId: uuid("completed_by_membership_id"),
    requestId: uuid("request_id").notNull(),
    correlationId: uuid("correlation_id").notNull(),
    startedAt: timestamp("started_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    completedAt: timestamp("completed_at", {
      withTimezone: true,
      mode: "date",
    }),
    version: integer("version").notNull().default(1),
  },
  (table) => [
    index("tenant_ldap_provider_test_runs_provider_started_idx").on(
      table.tenantId,
      table.providerId,
      table.startedAt,
      table.id,
    ),
    index("tenant_ldap_provider_test_runs_actor_started_idx").on(
      table.tenantId,
      table.startedByMembershipId,
      table.startedAt,
      table.id,
    ),
    index("tenant_ldap_provider_test_runs_status_started_idx").on(
      table.tenantId,
      table.status,
      table.startedAt,
      table.id,
    ),
    foreignKey({
      name: "tenant_ldap_provider_test_runs_provider_fk",
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
      name: "tenant_ldap_provider_test_runs_starter_fk",
      columns: [table.tenantId, table.startedByMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_ldap_provider_test_runs_completer_fk",
      columns: [table.tenantId, table.completedByMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "tenant_ldap_provider_test_runs_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "tenant_ldap_provider_test_runs_kind_check",
      sql`${table.providerKind} = 'ldap'`,
    ),
    check(
      "tenant_ldap_provider_test_runs_revision_check",
      sql`${table.providerVersion} > 0
        and ${table.configurationVersion} > 0
        and (${table.secretVersion} is null or ${table.secretVersion} > 0)`,
    ),
    check(
      "tenant_ldap_provider_test_runs_secret_check",
      sql`((${table.testKind} = 'connection' and ${table.secretVersion} is null)
        or (${table.testKind} = 'bind' and ${table.secretVersion} is not null)) is true`,
    ),
    check(
      "tenant_ldap_provider_test_runs_result_bounds_check",
      sql`(${table.endpointPriority} is null or ${table.endpointPriority} between 1 and 8)
        and (${table.durationMs} is null or ${table.durationMs} between 0 and 120000)`,
    ),
    check(
      "tenant_ldap_provider_test_runs_result_semantics_check",
      sql`((${table.outcome} is null and ${table.category} is null)
        or (${table.outcome} = 'success'
          and ${table.category} = 'success'
          and ${table.endpointPriority} is not null)
        or (${table.outcome} = 'inconclusive' and ${table.category} = 'stale_configuration')
        or (${table.outcome} = 'failure'
          and ${table.category} not in ('success', 'stale_configuration')
          and (${table.category} = 'cancelled' or ${table.endpointPriority} is not null)
          and (${table.testKind} = 'bind' or ${table.category} <> 'bind_rejected'))) is true`,
    ),
    check(
      "tenant_ldap_provider_test_runs_lifecycle_check",
      sql`((${table.status} = 'started'
          and ${table.outcome} is null
          and ${table.category} is null
          and ${table.endpointPriority} is null
          and ${table.durationMs} is null
          and ${table.completedByMembershipId} is null
          and ${table.completedAt} is null
          and ${table.version} = 1)
        or (${table.status} = 'completed'
          and ${table.outcome} is not null
          and ${table.category} is not null
          and ${table.durationMs} is not null
          and ${table.completedByMembershipId} is not null
          and ${table.completedByMembershipId} = ${table.startedByMembershipId}
          and ${table.completedAt} >= ${table.startedAt}
          and ${table.version} = 2)) is true`,
    ),
  ],
).enableRLS();
