import { sql } from "drizzle-orm";
import {
  boolean,
  check,
  cidr,
  foreignKey,
  index,
  inet,
  integer,
  pgPolicy,
  pgTable,
  primaryKey,
  text,
  timestamp,
  unique,
  uniqueIndex,
  uuid,
} from "drizzle-orm/pg-core";

import {
  tenantAuthorizationSources,
  tenantPermissions,
  tenantPermissionScopes,
  tenantRoles,
} from "./authorization.js";
import { bytea } from "./binary.js";
import { authorizationScope, tenantPrincipalKind } from "./enums.js";
import { tenantMemberships } from "./identity.js";
import { ticketAttributionOwnerRole } from "./roles.js";
import { tenants } from "./tenancy.js";

export const tenantServiceAccounts = pgTable(
  "tenant_service_accounts",
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
    createdByMembershipId: uuid("created_by_membership_id"),
    systemOwned: boolean("system_owned").notNull().default(false),
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
    unique("tenant_service_accounts_tenant_id_key").on(
      table.tenantId,
      table.id,
    ),
    unique("tenant_service_accounts_tenant_key_key").on(
      table.tenantId,
      table.key,
    ),
    index("tenant_service_accounts_tenant_active_idx")
      .on(table.tenantId, table.id)
      .where(sql`${table.archivedAt} is null`),
    foreignKey({
      name: "tenant_service_accounts_creator_membership_fk",
      columns: [table.tenantId, table.createdByMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_service_accounts_archiver_membership_fk",
      columns: [table.tenantId, table.archivedByMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "tenant_service_accounts_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "tenant_service_accounts_key_check",
      sql`${table.key} ~ '^[a-z][a-z0-9_]{2,63}$'`,
    ),
    check(
      "tenant_service_accounts_display_name_check",
      sql`btrim(${table.displayName}) <> '' and char_length(${table.displayName}) <= 120 and ${table.displayName} !~ '[[:cntrl:]]'`,
    ),
    check(
      "tenant_service_accounts_description_check",
      sql`char_length(${table.description}) <= 500 and ${table.description} !~ '[[:cntrl:]]'`,
    ),
    check(
      "tenant_service_accounts_ownership_check",
      sql`(${table.systemOwned}
          and ${table.key} = 'sla_action_runtime'
          and ${table.createdByMembershipId} is null)
        or (not ${table.systemOwned}
          and ${table.key} <> 'sla_action_runtime'
          and ${table.createdByMembershipId} is not null)`,
    ),
    check(
      "tenant_service_accounts_archive_check",
      sql`(${table.systemOwned}
          and ${table.archivedAt} is null
          and ${table.archivedByMembershipId} is null
          and ${table.archiveReason} is null)
        or (not ${table.systemOwned} and
          ((${table.archivedAt} is null and ${table.archivedByMembershipId} is null and ${table.archiveReason} is null)
        or (${table.archivedAt} is not null
          and ${table.archivedByMembershipId} is not null
          and ${table.archiveReason} is not null
          and ${table.archivedAt} >= ${table.createdAt}
          and btrim(${table.archiveReason}) <> ''
          and char_length(${table.archiveReason}) <= 500
          and ${table.archiveReason} !~ '[[:cntrl:]]')))`,
    ),
    check("tenant_service_accounts_version_check", sql`${table.version} > 0`),
    check(
      "tenant_service_accounts_updated_check",
      sql`${table.updatedAt} >= ${table.createdAt} and (${table.archivedAt} is null or ${table.updatedAt} >= ${table.archivedAt})`,
    ),
    pgPolicy("tenant_service_accounts_ticket_attribution", {
      as: "permissive",
      for: "select",
      to: ticketAttributionOwnerRole,
      using: sql`${table.tenantId} = app.context_tenant_id()
        and app.current_tenant_membership_id() is not null`,
    }),
  ],
).enableRLS();

export const tenantServiceAccountRoleGrants = pgTable(
  "tenant_service_account_role_grants",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    serviceAccountId: uuid("service_account_id").notNull(),
    roleId: uuid("role_id").notNull(),
    rolePrincipalKind: tenantPrincipalKind("role_principal_kind")
      .notNull()
      .default("service_account"),
    sourceId: uuid("source_id").notNull(),
    grantedByMembershipId: uuid("granted_by_membership_id").notNull(),
    grantReason: text("grant_reason").notNull(),
    grantedAt: timestamp("granted_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    expiresAt: timestamp("expires_at", {
      withTimezone: true,
      mode: "date",
    }),
    revokedAt: timestamp("revoked_at", {
      withTimezone: true,
      mode: "date",
    }),
    revokedByMembershipId: uuid("revoked_by_membership_id"),
    revokeReason: text("revoke_reason"),
    version: integer("version").notNull().default(1),
    updatedAt: timestamp("updated_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    unique("tenant_service_account_role_grants_tenant_id_key").on(
      table.tenantId,
      table.id,
    ),
    uniqueIndex("tenant_service_account_role_grants_active_key")
      .on(table.tenantId, table.serviceAccountId, table.roleId, table.sourceId)
      .where(sql`${table.revokedAt} is null`),
    index("tenant_service_account_role_grants_effective_idx")
      .on(table.tenantId, table.serviceAccountId, table.roleId, table.expiresAt)
      .where(sql`${table.revokedAt} is null`),
    index("tenant_service_account_role_grants_role_idx").on(
      table.tenantId,
      table.roleId,
      table.id,
    ),
    foreignKey({
      name: "tenant_service_account_role_grants_account_fk",
      columns: [table.tenantId, table.serviceAccountId],
      foreignColumns: [
        tenantServiceAccounts.tenantId,
        tenantServiceAccounts.id,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_service_account_role_grants_role_principal_fk",
      columns: [table.tenantId, table.roleId, table.rolePrincipalKind],
      foreignColumns: [
        tenantRoles.tenantId,
        tenantRoles.id,
        tenantRoles.principalKind,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_service_account_role_grants_source_fk",
      columns: [table.tenantId, table.sourceId],
      foreignColumns: [
        tenantAuthorizationSources.tenantId,
        tenantAuthorizationSources.id,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_service_account_role_grants_grantor_fk",
      columns: [table.tenantId, table.grantedByMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_service_account_role_grants_revoker_fk",
      columns: [table.tenantId, table.revokedByMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "tenant_service_account_role_grants_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "tenant_service_account_role_grants_role_kind_check",
      sql`${table.rolePrincipalKind} = 'service_account'`,
    ),
    check(
      "tenant_service_account_role_grants_expiry_check",
      sql`${table.expiresAt} is null or ${table.expiresAt} > ${table.grantedAt}`,
    ),
    check(
      "tenant_service_account_role_grants_reason_check",
      sql`btrim(${table.grantReason}) <> '' and char_length(${table.grantReason}) <= 500 and ${table.grantReason} !~ '[[:cntrl:]]'`,
    ),
    check(
      "tenant_service_account_role_grants_revocation_check",
      sql`(${table.revokedAt} is null and ${table.revokedByMembershipId} is null and ${table.revokeReason} is null)
        or (${table.revokedAt} is not null
          and ${table.revokedByMembershipId} is not null
          and ${table.revokeReason} is not null
          and ${table.revokedAt} >= ${table.grantedAt}
          and btrim(${table.revokeReason}) <> ''
          and char_length(${table.revokeReason}) <= 500
          and ${table.revokeReason} !~ '[[:cntrl:]]')`,
    ),
    check(
      "tenant_service_account_role_grants_version_check",
      sql`${table.version} > 0`,
    ),
    check(
      "tenant_service_account_role_grants_updated_check",
      sql`${table.updatedAt} >= ${table.grantedAt} and (${table.revokedAt} is null or ${table.updatedAt} >= ${table.revokedAt})`,
    ),
  ],
).enableRLS();

export const tenantApiCredentials = pgTable(
  "tenant_api_credentials",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    serviceAccountId: uuid("service_account_id").notNull(),
    label: text("label").notNull(),
    formatVersion: integer("format_version").notNull().default(1),
    locator: bytea("locator").notNull(),
    keyVersion: integer("key_version").notNull(),
    secretDigest: bytea("secret_digest").notNull(),
    issuedByMembershipId: uuid("issued_by_membership_id").notNull(),
    issuedAt: timestamp("issued_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    expiresAt: timestamp("expires_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    rotatedFromCredentialId: uuid("rotated_from_credential_id"),
    revokedAt: timestamp("revoked_at", {
      withTimezone: true,
      mode: "date",
    }),
    revokedByMembershipId: uuid("revoked_by_membership_id"),
    revokeReason: text("revoke_reason"),
    lastUsedAt: timestamp("last_used_at", {
      withTimezone: true,
      mode: "date",
    }),
    lastUsedIp: inet("last_used_ip"),
    version: integer("version").notNull().default(1),
    updatedAt: timestamp("updated_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    unique("tenant_api_credentials_tenant_id_key").on(table.tenantId, table.id),
    unique("tenant_api_credentials_account_id_key").on(
      table.tenantId,
      table.serviceAccountId,
      table.id,
    ),
    unique("tenant_api_credentials_locator_key").on(table.locator),
    unique("tenant_api_credentials_rotated_from_key").on(
      table.tenantId,
      table.serviceAccountId,
      table.rotatedFromCredentialId,
    ),
    index("tenant_api_credentials_account_active_idx")
      .on(table.tenantId, table.serviceAccountId, table.expiresAt, table.id)
      .where(sql`${table.revokedAt} is null`),
    index("tenant_api_credentials_live_key_version_idx")
      .on(table.keyVersion, table.expiresAt, table.id)
      .where(sql`${table.revokedAt} is null`),
    foreignKey({
      name: "tenant_api_credentials_account_fk",
      columns: [table.tenantId, table.serviceAccountId],
      foreignColumns: [
        tenantServiceAccounts.tenantId,
        tenantServiceAccounts.id,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_api_credentials_issuer_fk",
      columns: [table.tenantId, table.issuedByMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_api_credentials_revoker_fk",
      columns: [table.tenantId, table.revokedByMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_api_credentials_rotated_from_fk",
      columns: [
        table.tenantId,
        table.serviceAccountId,
        table.rotatedFromCredentialId,
      ],
      foreignColumns: [table.tenantId, table.serviceAccountId, table.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "tenant_api_credentials_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "tenant_api_credentials_label_check",
      sql`btrim(${table.label}) <> '' and char_length(${table.label}) <= 120 and ${table.label} !~ '[[:cntrl:]]'`,
    ),
    check(
      "tenant_api_credentials_format_version_check",
      sql`${table.formatVersion} > 0`,
    ),
    check(
      "tenant_api_credentials_key_version_check",
      sql`${table.keyVersion} > 0`,
    ),
    check(
      "tenant_api_credentials_secret_material_check",
      sql`octet_length(${table.locator}) = 16 and octet_length(${table.secretDigest}) = 32`,
    ),
    check(
      "tenant_api_credentials_expiry_check",
      sql`${table.expiresAt} > ${table.issuedAt} and ${table.expiresAt} <= ${table.issuedAt} + interval '90 days'`,
    ),
    check(
      "tenant_api_credentials_rotation_check",
      sql`${table.rotatedFromCredentialId} is null or ${table.rotatedFromCredentialId} <> ${table.id}`,
    ),
    check(
      "tenant_api_credentials_revocation_check",
      sql`(${table.revokedAt} is null and ${table.revokedByMembershipId} is null and ${table.revokeReason} is null)
        or (${table.revokedAt} is not null
          and ${table.revokedByMembershipId} is not null
          and ${table.revokeReason} is not null
          and ${table.revokedAt} >= ${table.issuedAt}
          and btrim(${table.revokeReason}) <> ''
          and char_length(${table.revokeReason}) <= 500
          and ${table.revokeReason} !~ '[[:cntrl:]]')`,
    ),
    check(
      "tenant_api_credentials_last_used_check",
      sql`(${table.lastUsedAt} is null and ${table.lastUsedIp} is null)
        or (${table.lastUsedAt} is not null and ${table.lastUsedIp} is not null and ${table.lastUsedAt} >= ${table.issuedAt})`,
    ),
    check("tenant_api_credentials_version_check", sql`${table.version} > 0`),
    check(
      "tenant_api_credentials_updated_check",
      sql`${table.updatedAt} >= ${table.issuedAt}
        and (${table.revokedAt} is null or ${table.updatedAt} >= ${table.revokedAt})
        and (${table.lastUsedAt} is null or ${table.updatedAt} >= ${table.lastUsedAt})`,
    ),
  ],
).enableRLS();

export const tenantApiCredentialPermissions = pgTable(
  "tenant_api_credential_permissions",
  {
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    credentialId: uuid("credential_id").notNull(),
    permissionId: uuid("permission_id").notNull(),
    permissionServiceAccountAllowed: boolean(
      "permission_service_account_allowed",
    )
      .notNull()
      .default(true),
    scope: authorizationScope("scope").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    primaryKey({
      name: "tenant_api_credential_permissions_pkey",
      columns: [
        table.tenantId,
        table.credentialId,
        table.permissionId,
        table.scope,
      ],
    }),
    index("tenant_api_credential_permissions_authority_idx").on(
      table.tenantId,
      table.permissionId,
      table.scope,
      table.credentialId,
    ),
    foreignKey({
      name: "tenant_api_credential_permissions_credential_fk",
      columns: [table.tenantId, table.credentialId],
      foreignColumns: [tenantApiCredentials.tenantId, tenantApiCredentials.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_api_credential_permissions_catalog_fk",
      columns: [table.permissionId, table.permissionServiceAccountAllowed],
      foreignColumns: [
        tenantPermissions.id,
        tenantPermissions.serviceAccountAllowed,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_api_credential_permissions_scope_fk",
      columns: [table.permissionId, table.scope],
      foreignColumns: [
        tenantPermissionScopes.permissionId,
        tenantPermissionScopes.scope,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "tenant_api_credential_permissions_allowed_check",
      sql`${table.permissionServiceAccountAllowed} is true`,
    ),
    check(
      "tenant_api_credential_permissions_not_platform_check",
      sql`${table.scope} <> 'platform'`,
    ),
  ],
).enableRLS();

export const tenantApiCredentialNetworks = pgTable(
  "tenant_api_credential_networks",
  {
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    credentialId: uuid("credential_id").notNull(),
    network: cidr("network").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    primaryKey({
      name: "tenant_api_credential_networks_pkey",
      columns: [table.tenantId, table.credentialId, table.network],
    }),
    foreignKey({
      name: "tenant_api_credential_networks_credential_fk",
      columns: [table.tenantId, table.credentialId],
      foreignColumns: [tenantApiCredentials.tenantId, tenantApiCredentials.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
  ],
).enableRLS();

export const tenantApiCredentialCommands = pgTable(
  "tenant_api_credential_commands",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    serviceAccountId: uuid("service_account_id").notNull(),
    actorMembershipId: uuid("actor_membership_id").notNull(),
    operation: text("operation").notNull(),
    keyDigest: bytea("key_digest").notNull(),
    requestDigest: bytea("request_digest").notNull(),
    resultCredentialId: uuid("result_credential_id").notNull(),
    resultVersion: integer("result_version").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    unique("tenant_api_credential_commands_tenant_id_key").on(
      table.tenantId,
      table.id,
    ),
    unique("tenant_api_credential_commands_replay_key").on(
      table.tenantId,
      table.actorMembershipId,
      table.serviceAccountId,
      table.operation,
      table.keyDigest,
    ),
    foreignKey({
      name: "tenant_api_credential_commands_account_fk",
      columns: [table.tenantId, table.serviceAccountId],
      foreignColumns: [
        tenantServiceAccounts.tenantId,
        tenantServiceAccounts.id,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_api_credential_commands_actor_fk",
      columns: [table.tenantId, table.actorMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_api_credential_commands_result_fk",
      columns: [
        table.tenantId,
        table.serviceAccountId,
        table.resultCredentialId,
      ],
      foreignColumns: [
        tenantApiCredentials.tenantId,
        tenantApiCredentials.serviceAccountId,
        tenantApiCredentials.id,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "tenant_api_credential_commands_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "tenant_api_credential_commands_operation_check",
      sql`${table.operation} in ('service_account.credential.issue', 'service_account.credential.rotate')`,
    ),
    check(
      "tenant_api_credential_commands_digest_check",
      sql`octet_length(${table.keyDigest}) = 32 and octet_length(${table.requestDigest}) = 32`,
    ),
    check(
      "tenant_api_credential_commands_result_version_check",
      sql`${table.resultVersion} > 0`,
    ),
  ],
).enableRLS();
