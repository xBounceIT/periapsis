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
import type { PgTableExtraConfigValue } from "drizzle-orm/pg-core";

import { tenantAuthorizationSources } from "./authorization.js";
import { bytea } from "./binary.js";
import { identitySubjectFormat } from "./enums.js";
import {
  identityKeyringVersions,
  tenantAuthProviders,
} from "./identity-providers.js";
import { tenantMemberships, users } from "./identity.js";
import { tenantAuthProviderLoginKeys } from "./identity-platform-bindings.js";
import { tenants } from "./tenancy.js";

/**
 * A tenant login code is deliberately separate from provider ownership. The
 * first LDAP slice binds only tenant-owned providers; a future platform
 * provider binding uses its own physical table family rather than a nullable
 * provider scope on this table.
 */
export const tenantAuthProviderBindings = pgTable(
  "tenant_auth_provider_bindings",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    bindingFamily: text("binding_family").notNull().default("tenant_provider"),
    providerId: uuid("provider_id").notNull(),
    key: text("key").notNull(),
    enabled: boolean("enabled").notNull().default(false),
    profilePriority: integer("profile_priority").notNull().default(100),
    authRevision: integer("auth_revision").notNull().default(1),
    mappingRevision: bigint("mapping_revision", { mode: "bigint" })
      .notNull()
      .default(sql`1`),
    currentAccessEpochId: uuid("current_access_epoch_id"),
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
    unique("tenant_auth_provider_bindings_tenant_id_key").on(
      table.tenantId,
      table.id,
    ),
    unique("tenant_auth_provider_bindings_tenant_id_provider_id_key").on(
      table.tenantId,
      table.id,
      table.providerId,
    ),
    unique("tenant_auth_provider_bindings_login_claim_key").on(
      table.tenantId,
      table.bindingFamily,
      table.id,
      table.key,
    ),
    unique("tenant_auth_provider_bindings_tenant_provider_key").on(
      table.tenantId,
      table.providerId,
    ),
    unique("tenant_auth_provider_bindings_tenant_login_key").on(
      table.tenantId,
      table.key,
    ),
    index("tenant_auth_provider_bindings_tenant_enabled_idx").on(
      table.tenantId,
      table.enabled,
      table.key,
      table.id,
    ),
    index("tenant_auth_provider_bindings_tenant_profile_priority_idx").on(
      table.tenantId,
      table.profilePriority,
      table.id,
    ),
    foreignKey({
      name: "tenant_auth_provider_bindings_login_claim_fk",
      columns: [table.tenantId, table.bindingFamily, table.id, table.key],
      foreignColumns: [
        tenantAuthProviderLoginKeys.tenantId,
        tenantAuthProviderLoginKeys.bindingFamily,
        tenantAuthProviderLoginKeys.bindingId,
        tenantAuthProviderLoginKeys.key,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_auth_provider_bindings_provider_fk",
      columns: [table.tenantId, table.providerId],
      foreignColumns: [tenantAuthProviders.tenantId, tenantAuthProviders.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_auth_provider_bindings_creator_fk",
      columns: [table.tenantId, table.createdByMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_auth_provider_bindings_updater_fk",
      columns: [table.tenantId, table.updatedByMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_auth_provider_bindings_archiver_fk",
      columns: [table.tenantId, table.archivedByMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_auth_provider_bindings_current_epoch_fk",
      columns: [
        table.tenantId,
        table.currentAccessEpochId,
        table.id,
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
    check(
      "tenant_auth_provider_bindings_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "tenant_auth_provider_bindings_key_check",
      sql`${table.key} = lower(btrim(${table.key}))
        and ${table.key} ~ '^[a-z][a-z0-9_-]{2,63}$'`,
    ),
    check(
      "tenant_auth_provider_bindings_family_check",
      sql`${table.bindingFamily} = 'tenant_provider'`,
    ),
    check(
      "tenant_auth_provider_bindings_priority_check",
      sql`${table.profilePriority} between 0 and 1000000`,
    ),
    check(
      "tenant_auth_provider_bindings_revision_check",
      sql`${table.authRevision} > 0
        and ${table.mappingRevision} > 0
        and ${table.version} > 0`,
    ),
    check(
      "tenant_auth_provider_bindings_live_epoch_check",
      sql`(${table.enabled} and ${table.archivedAt} is null
          and ${table.currentAccessEpochId} is not null)
        or (not ${table.enabled} and ${table.currentAccessEpochId} is null)`,
    ),
    check(
      "tenant_auth_provider_bindings_archive_check",
      sql`(${table.archivedAt} is null
          and ${table.archivedByMembershipId} is null
          and ${table.archiveReason} is null)
        or (${table.archivedAt} is not null
          and ${table.archivedByMembershipId} is not null
          and ${table.archiveReason} is not null
          and not ${table.enabled}
          and ${table.currentAccessEpochId} is null
          and ${table.archivedAt} >= ${table.createdAt}
          and btrim(${table.archiveReason}) <> ''
          and char_length(${table.archiveReason}) <= 500
          and ${table.archiveReason} !~ '[[:cntrl:]]')`,
    ),
    check(
      "tenant_auth_provider_bindings_updated_check",
      sql`${table.updatedAt} >= ${table.createdAt}
        and (${table.archivedAt} is null or ${table.updatedAt} >= ${table.archivedAt})`,
    ),
  ],
).enableRLS();

/** One immutable provider-access source epoch. A terminal close never reopens. */
export const tenantIdentityProviderAccessEpochs = pgTable(
  "tenant_identity_provider_access_epochs",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    bindingId: uuid("binding_id").notNull(),
    providerId: uuid("provider_id").notNull(),
    sourceId: uuid("source_id").notNull(),
    sequence: integer("sequence").notNull(),
    startedByMembershipId: uuid("started_by_membership_id").notNull(),
    startedAt: timestamp("started_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    endedAt: timestamp("ended_at", { withTimezone: true, mode: "date" }),
    endedByMembershipId: uuid("ended_by_membership_id"),
    endReason: text("end_reason"),
    version: integer("version").notNull().default(1),
  },
  (table): PgTableExtraConfigValue[] => [
    unique("tenant_identity_provider_access_epochs_tenant_id_key").on(
      table.tenantId,
      table.id,
    ),
    unique("tenant_identity_provider_access_epochs_exact_key").on(
      table.tenantId,
      table.id,
      table.bindingId,
      table.providerId,
      table.sourceId,
    ),
    unique("tenant_identity_provider_access_epochs_current_key").on(
      table.tenantId,
      table.id,
      table.bindingId,
      table.providerId,
    ),
    unique("tenant_identity_provider_access_epochs_binding_sequence_key").on(
      table.tenantId,
      table.bindingId,
      table.sequence,
    ),
    unique("tenant_identity_provider_access_epochs_source_key").on(
      table.tenantId,
      table.sourceId,
    ),
    uniqueIndex("tenant_identity_provider_access_epochs_live_binding_key")
      .on(table.tenantId, table.bindingId)
      .where(sql`${table.endedAt} is null`),
    index("tenant_identity_provider_access_epochs_tenant_provider_idx").on(
      table.tenantId,
      table.providerId,
      table.bindingId,
      table.sequence,
    ),
    foreignKey({
      name: "tenant_identity_provider_access_epochs_binding_fk",
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
      name: "tenant_identity_provider_access_epochs_source_fk",
      columns: [table.tenantId, table.sourceId],
      foreignColumns: [
        tenantAuthorizationSources.tenantId,
        tenantAuthorizationSources.id,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_identity_provider_access_epochs_starter_fk",
      columns: [table.tenantId, table.startedByMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_identity_provider_access_epochs_ender_fk",
      columns: [table.tenantId, table.endedByMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "tenant_identity_provider_access_epochs_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "tenant_identity_provider_access_epochs_sequence_check",
      sql`${table.sequence} > 0`,
    ),
    check(
      "tenant_identity_provider_access_epochs_lifecycle_check",
      sql`(${table.endedAt} is null
          and ${table.endedByMembershipId} is null
          and ${table.endReason} is null
          and ${table.version} = 1)
        or (${table.endedAt} is not null
          and ${table.endedByMembershipId} is not null
          and ${table.endReason} is not null
          and ${table.endedAt} >= ${table.startedAt}
          and btrim(${table.endReason}) <> ''
          and char_length(${table.endReason}) <= 500
          and ${table.endReason} !~ '[[:cntrl:]]'
          and ${table.version} = 2)`,
    ),
  ],
).enableRLS();

/** Provider-qualified immutable subjects; email, username, and DN never link. */
export const tenantLdapExternalIdentities = pgTable(
  "tenant_ldap_external_identities",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
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
    encryptionAlgorithm: text("encryption_algorithm")
      .notNull()
      .default("aes-256-gcm"),
    admittedConfigurationVersion: integer(
      "admitted_configuration_version",
    ).notNull(),
    admittedAt: timestamp("admitted_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    lastObservedAt: timestamp("last_observed_at", {
      withTimezone: true,
      mode: "date",
    })
      .notNull()
      .defaultNow(),
    retiredAt: timestamp("retired_at", { withTimezone: true, mode: "date" }),
    retiredByMembershipId: uuid("retired_by_membership_id"),
    retireReason: text("retire_reason"),
    version: integer("version").notNull().default(1),
    updatedAt: timestamp("updated_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    unique("tenant_ldap_external_identities_tenant_id_key").on(
      table.tenantId,
      table.id,
    ),
    unique("tenant_ldap_external_identities_exact_key").on(
      table.tenantId,
      table.providerId,
      table.id,
      table.userId,
    ),
    unique("tenant_ldap_external_identities_provider_id_key").on(
      table.tenantId,
      table.providerId,
      table.id,
    ),
    uniqueIndex("tenant_ldap_external_identities_live_provider_user_key")
      .on(table.tenantId, table.providerId, table.userId)
      .where(sql`${table.retiredAt} is null`),
    index("tenant_ldap_external_identities_tenant_user_idx").on(
      table.tenantId,
      table.userId,
      table.providerId,
      table.id,
    ),
    index("tenant_ldap_external_identities_tenant_key_version_idx").on(
      table.tenantId,
      table.keyVersion,
      table.providerId,
      table.id,
    ),
    foreignKey({
      name: "tenant_ldap_external_identities_provider_fk",
      columns: [table.tenantId, table.providerId],
      foreignColumns: [tenantAuthProviders.tenantId, tenantAuthProviders.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_ldap_external_identities_retired_by_fk",
      columns: [table.tenantId, table.retiredByMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "tenant_ldap_external_identities_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "tenant_ldap_external_identities_ciphertext_check",
      sql`octet_length(${table.subjectCiphertext}) between 17 and 4112
        and octet_length(${table.subjectNonce}) = 12`,
    ),
    check(
      "tenant_ldap_external_identities_algorithm_check",
      sql`${table.encryptionAlgorithm} = 'aes-256-gcm'`,
    ),
    check(
      "tenant_ldap_external_identities_revision_check",
      sql`${table.admittedConfigurationVersion} > 0 and ${table.version} > 0`,
    ),
    check(
      "tenant_ldap_external_identities_lifecycle_check",
      sql`${table.lastObservedAt} >= ${table.admittedAt}
        and ${table.updatedAt} >= ${table.admittedAt}
        and ((${table.retiredAt} is null
            and ${table.retiredByMembershipId} is null
            and ${table.retireReason} is null)
          or (${table.retiredAt} is not null
            and ${table.retireReason} is not null
            and ${table.retiredAt} >= ${table.admittedAt}
            and ${table.updatedAt} >= ${table.retiredAt}
            and btrim(${table.retireReason}) <> ''
            and char_length(${table.retireReason}) <= 500
            and ${table.retireReason} !~ '[[:cntrl:]]'))`,
    ),
  ],
).enableRLS();

export const tenantLdapExternalIdentitySubjectAliases = pgTable(
  "tenant_ldap_external_identity_subject_aliases",
  {
    id: uuid("id")
      .notNull()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    providerId: uuid("provider_id").notNull(),
    externalIdentityId: uuid("external_identity_id").notNull(),
    digestKeyVersion: integer("digest_key_version")
      .notNull()
      .references(() => identityKeyringVersions.keyVersion, {
        onDelete: "restrict",
      }),
    subjectDigest: bytea("subject_digest").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    retiredAt: timestamp("retired_at", { withTimezone: true, mode: "date" }),
    retireReason: text("retire_reason"),
  },
  (table) => [
    primaryKey({
      name: "tenant_ldap_external_identity_subject_aliases_pkey",
      columns: [table.tenantId, table.id],
    }),
    uniqueIndex("tenant_ldap_external_identity_subject_aliases_live_digest_key")
      .on(
        table.tenantId,
        table.providerId,
        table.digestKeyVersion,
        table.subjectDigest,
      )
      .where(sql`${table.retiredAt} is null`),
    uniqueIndex(
      "tenant_ldap_external_identity_subject_aliases_live_version_key",
    )
      .on(table.tenantId, table.externalIdentityId, table.digestKeyVersion)
      .where(sql`${table.retiredAt} is null`),
    index("tenant_ldap_external_identity_subject_aliases_identity_idx").on(
      table.tenantId,
      table.externalIdentityId,
      table.digestKeyVersion,
      table.id,
    ),
    index("tenant_ldap_external_identity_subject_aliases_key_version_idx").on(
      table.tenantId,
      table.digestKeyVersion,
      table.providerId,
      table.id,
    ),
    foreignKey({
      name: "tenant_ldap_external_identity_subject_aliases_identity_fk",
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
      "tenant_ldap_external_identity_subject_aliases_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "tenant_ldap_external_identity_subject_aliases_digest_check",
      sql`octet_length(${table.subjectDigest}) = 32`,
    ),
    check(
      "tenant_ldap_external_identity_subject_aliases_lifecycle_check",
      sql`(${table.retiredAt} is null and ${table.retireReason} is null)
        or (${table.retiredAt} is not null
          and ${table.retireReason} is not null
          and ${table.retiredAt} >= ${table.createdAt}
          and btrim(${table.retireReason}) <> ''
          and char_length(${table.retireReason}) <= 500
          and ${table.retireReason} !~ '[[:cntrl:]]')`,
    ),
  ],
).enableRLS();

export const tenantLdapProviderAccessGrants = pgTable(
  "tenant_ldap_provider_access_grants",
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
    configurationVersion: integer("configuration_version").notNull(),
    ownsMembership: boolean("owns_membership").notNull().default(false),
    startedAt: timestamp("started_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    lastObservedAt: timestamp("last_observed_at", {
      withTimezone: true,
      mode: "date",
    })
      .notNull()
      .defaultNow(),
    endedAt: timestamp("ended_at", { withTimezone: true, mode: "date" }),
    endReason: text("end_reason"),
    version: integer("version").notNull().default(1),
    updatedAt: timestamp("updated_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    unique("tenant_ldap_provider_access_grants_tenant_id_key").on(
      table.tenantId,
      table.id,
    ),
    uniqueIndex("tenant_ldap_provider_access_grants_live_binding_member_key")
      .on(table.tenantId, table.bindingId, table.membershipId)
      .where(sql`${table.endedAt} is null`),
    uniqueIndex("tenant_ldap_provider_access_grants_live_epoch_identity_key")
      .on(table.tenantId, table.accessEpochId, table.externalIdentityId)
      .where(sql`${table.endedAt} is null`),
    index("tenant_ldap_provider_access_grants_tenant_membership_idx").on(
      table.tenantId,
      table.membershipId,
      table.bindingId,
      table.id,
    ),
    index("tenant_ldap_provider_access_grants_tenant_source_idx").on(
      table.tenantId,
      table.sourceId,
      table.membershipId,
      table.id,
    ),
    foreignKey({
      name: "tenant_ldap_provider_access_grants_epoch_source_fk",
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
      name: "tenant_ldap_provider_access_grants_identity_user_fk",
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
      name: "tenant_ldap_provider_access_grants_membership_user_fk",
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
      "tenant_ldap_provider_access_grants_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "tenant_ldap_provider_access_grants_revision_check",
      sql`${table.configurationVersion} > 0 and ${table.version} > 0`,
    ),
    check(
      "tenant_ldap_provider_access_grants_lifecycle_check",
      sql`${table.lastObservedAt} >= ${table.startedAt}
        and ${table.updatedAt} >= ${table.startedAt}
        and ((${table.endedAt} is null and ${table.endReason} is null)
          or (${table.endedAt} is not null
            and ${table.endReason} is not null
            and ${table.endedAt} >= ${table.startedAt}
            and ${table.updatedAt} >= ${table.endedAt}
            and btrim(${table.endReason}) <> ''
            and char_length(${table.endReason}) <= 500
            and ${table.endReason} !~ '[[:cntrl:]]'))`,
    ),
  ],
).enableRLS();

export const tenantLdapProviderProfileContributions = pgTable(
  "tenant_ldap_provider_profile_contributions",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    accessGrantId: uuid("access_grant_id").notNull(),
    displayName: text("display_name"),
    firstName: text("first_name"),
    lastName: text("last_name"),
    username: text("username"),
    email: text("email"),
    configurationVersion: integer("configuration_version").notNull(),
    observedAt: timestamp("observed_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    retiredAt: timestamp("retired_at", { withTimezone: true, mode: "date" }),
    retireReason: text("retire_reason"),
    version: integer("version").notNull().default(1),
    updatedAt: timestamp("updated_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    unique("tenant_ldap_provider_profile_contributions_tenant_id_key").on(
      table.tenantId,
      table.id,
    ),
    uniqueIndex("tenant_ldap_provider_profile_contributions_live_grant_key")
      .on(table.tenantId, table.accessGrantId)
      .where(sql`${table.retiredAt} is null`),
    index("tenant_ldap_provider_profile_contributions_tenant_observed_idx").on(
      table.tenantId,
      table.observedAt,
      table.id,
    ),
    foreignKey({
      name: "tenant_ldap_provider_profile_contributions_grant_fk",
      columns: [table.tenantId, table.accessGrantId],
      foreignColumns: [
        tenantLdapProviderAccessGrants.tenantId,
        tenantLdapProviderAccessGrants.id,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "tenant_ldap_provider_profile_contributions_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "tenant_ldap_provider_profile_contributions_present_check",
      sql`${table.displayName} is not null
        or ${table.firstName} is not null
        or ${table.lastName} is not null
        or ${table.username} is not null
        or ${table.email} is not null`,
    ),
    check(
      "tenant_ldap_provider_profile_contributions_name_check",
      sql`(${table.displayName} is null or (
          btrim(${table.displayName}) <> ''
          and char_length(${table.displayName}) <= 160
          and ${table.displayName} !~ '[[:cntrl:]]'
        )) and (${table.firstName} is null or (
          btrim(${table.firstName}) <> ''
          and char_length(${table.firstName}) <= 160
          and ${table.firstName} !~ '[[:cntrl:]]'
        )) and (${table.lastName} is null or (
          btrim(${table.lastName}) <> ''
          and char_length(${table.lastName}) <= 160
          and ${table.lastName} !~ '[[:cntrl:]]'
        ))`,
    ),
    check(
      "tenant_ldap_provider_profile_contributions_username_check",
      sql`${table.username} is null or (
        btrim(${table.username}) <> ''
        and char_length(${table.username}) <= 320
        and ${table.username} !~ '[[:cntrl:]]'
      )`,
    ),
    check(
      "tenant_ldap_provider_profile_contributions_email_check",
      sql`${table.email} is null or (
        ${table.email} = lower(btrim(${table.email}))
        and position('@' in ${table.email}) > 1
        and char_length(${table.email}) <= 320
        and ${table.email} !~ '[[:cntrl:]]'
      )`,
    ),
    check(
      "tenant_ldap_provider_profile_contributions_lifecycle_check",
      sql`${table.configurationVersion} > 0
        and ${table.version} > 0
        and ${table.updatedAt} >= ${table.observedAt}
        and ((${table.retiredAt} is null and ${table.retireReason} is null)
          or (${table.retiredAt} is not null
            and ${table.retireReason} is not null
            and ${table.retiredAt} >= ${table.observedAt}
            and ${table.updatedAt} >= ${table.retiredAt}
            and btrim(${table.retireReason}) <> ''
            and char_length(${table.retireReason}) <= 500
            and ${table.retireReason} !~ '[[:cntrl:]]'))`,
    ),
  ],
).enableRLS();

/** Non-null fields win independently over every live provider contribution. */
export const tenantUserManualProfileOverrides = pgTable(
  "tenant_user_manual_profile_overrides",
  {
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    membershipId: uuid("membership_id").notNull(),
    userId: uuid("user_id").notNull(),
    displayName: text("display_name"),
    firstName: text("first_name"),
    lastName: text("last_name"),
    username: text("username"),
    email: text("email"),
    reason: text("reason").notNull(),
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
      name: "tenant_user_manual_profile_overrides_pkey",
      columns: [table.tenantId, table.membershipId],
    }),
    unique("tenant_user_manual_profile_overrides_tenant_user_key").on(
      table.tenantId,
      table.userId,
    ),
    index("tenant_user_manual_profile_overrides_tenant_updater_idx").on(
      table.tenantId,
      table.updatedByMembershipId,
      table.membershipId,
    ),
    foreignKey({
      name: "tenant_user_manual_profile_overrides_membership_user_fk",
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
      name: "tenant_user_manual_profile_overrides_updater_fk",
      columns: [table.tenantId, table.updatedByMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "tenant_user_manual_profile_overrides_present_check",
      sql`${table.displayName} is not null
        or ${table.firstName} is not null
        or ${table.lastName} is not null
        or ${table.username} is not null
        or ${table.email} is not null`,
    ),
    check(
      "tenant_user_manual_profile_overrides_name_check",
      sql`(${table.displayName} is null or (
          btrim(${table.displayName}) <> ''
          and char_length(${table.displayName}) <= 160
          and ${table.displayName} !~ '[[:cntrl:]]'
        )) and (${table.firstName} is null or (
          btrim(${table.firstName}) <> ''
          and char_length(${table.firstName}) <= 160
          and ${table.firstName} !~ '[[:cntrl:]]'
        )) and (${table.lastName} is null or (
          btrim(${table.lastName}) <> ''
          and char_length(${table.lastName}) <= 160
          and ${table.lastName} !~ '[[:cntrl:]]'
        ))`,
    ),
    check(
      "tenant_user_manual_profile_overrides_username_check",
      sql`${table.username} is null or (
        btrim(${table.username}) <> ''
        and char_length(${table.username}) <= 320
        and ${table.username} !~ '[[:cntrl:]]'
      )`,
    ),
    check(
      "tenant_user_manual_profile_overrides_email_check",
      sql`${table.email} is null or (
        ${table.email} = lower(btrim(${table.email}))
        and position('@' in ${table.email}) > 1
        and char_length(${table.email}) <= 320
        and ${table.email} !~ '[[:cntrl:]]'
      )`,
    ),
    check(
      "tenant_user_manual_profile_overrides_reason_check",
      sql`btrim(${table.reason}) <> ''
        and char_length(${table.reason}) <= 500
        and ${table.reason} !~ '[[:cntrl:]]'`,
    ),
    check(
      "tenant_user_manual_profile_overrides_version_check",
      sql`${table.version} > 0 and ${table.updatedAt} >= ${table.createdAt}`,
    ),
  ],
).enableRLS();
