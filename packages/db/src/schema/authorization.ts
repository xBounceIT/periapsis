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

import {
  authorizationScope,
  authorizationSourceKind,
  tenantPrincipalKind,
} from "./enums.js";
import { bytea } from "./binary.js";
import { tenantMemberships } from "./identity.js";
import { tenants } from "./tenancy.js";

export const tenantPermissions = pgTable(
  "tenant_permissions",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    key: text("key").notNull(),
    displayName: text("display_name").notNull(),
    description: text("description").notNull(),
    serviceAccountAllowed: boolean("service_account_allowed")
      .notNull()
      .default(false),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    unique("tenant_permissions_key_key").on(table.key),
    unique("tenant_permissions_id_service_account_allowed_key").on(
      table.id,
      table.serviceAccountAllowed,
    ),
    check(
      "tenant_permissions_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "tenant_permissions_key_canonical_check",
      sql`${table.key} ~ '^[a-z][a-z0-9_]*(\\.[a-z][a-z0-9_]*)+$'`,
    ),
    check(
      "tenant_permissions_display_name_check",
      sql`btrim(${table.displayName}) <> '' and char_length(${table.displayName}) <= 120 and ${table.displayName} !~ '[[:cntrl:]]'`,
    ),
    check(
      "tenant_permissions_description_check",
      sql`btrim(${table.description}) <> '' and char_length(${table.description}) <= 500 and ${table.description} !~ '[[:cntrl:]]'`,
    ),
  ],
).enableRLS();

export const tenantPermissionScopes = pgTable(
  "tenant_permission_scopes",
  {
    permissionId: uuid("permission_id")
      .notNull()
      .references(() => tenantPermissions.id, { onDelete: "restrict" }),
    scope: authorizationScope("scope").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    primaryKey({
      name: "tenant_permission_scopes_pkey",
      columns: [table.permissionId, table.scope],
    }),
    check(
      "tenant_permission_scopes_not_platform_check",
      sql`${table.scope} <> 'platform'`,
    ),
  ],
).enableRLS();

export const tenantAuthorizationSources = pgTable(
  "tenant_authorization_sources",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    kind: authorizationSourceKind("kind").notNull(),
    key: text("key").notNull(),
    authoritative: boolean("authoritative").notNull().default(false),
    protected: boolean("protected").notNull().default(false),
    retiredAt: timestamp("retired_at", {
      withTimezone: true,
      mode: "date",
    }),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    unique("tenant_authorization_sources_tenant_id_key").on(
      table.tenantId,
      table.id,
    ),
    unique("tenant_authorization_sources_tenant_key_key").on(
      table.tenantId,
      table.key,
    ),
    index("tenant_authorization_sources_tenant_kind_idx").on(
      table.tenantId,
      table.kind,
      table.id,
    ),
    check(
      "tenant_authorization_sources_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "tenant_authorization_sources_key_check",
      sql`${table.key} ~ '^[a-z][a-z0-9_.:-]{0,126}[a-z0-9]$'`,
    ),
    check(
      "tenant_authorization_sources_retirement_check",
      sql`${table.retiredAt} is null or (${table.protected} is false and ${table.retiredAt} >= ${table.createdAt})`,
    ),
  ],
).enableRLS();

export const tenantAuthorizationStates = pgTable(
  "tenant_authorization_states",
  {
    tenantId: uuid("tenant_id")
      .primaryKey()
      .references(() => tenants.id, { onDelete: "restrict" }),
    initializedAt: timestamp("initialized_at", {
      withTimezone: true,
      mode: "date",
    }),
    revision: bigint("revision", { mode: "bigint" })
      .notNull()
      .default(sql`0`),
    updatedAt: timestamp("updated_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    check(
      "tenant_authorization_states_revision_check",
      sql`${table.revision} >= 0`,
    ),
    check(
      "tenant_authorization_states_initialized_check",
      sql`${table.initializedAt} is null or ${table.updatedAt} >= ${table.initializedAt}`,
    ),
  ],
).enableRLS();

export const tenantAuthorizationCommands = pgTable(
  "tenant_authorization_commands",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    actorMembershipId: uuid("actor_membership_id").notNull(),
    operation: text("operation").notNull(),
    keyDigest: bytea("key_digest").notNull(),
    requestDigest: bytea("request_digest").notNull(),
    resultResourceId: uuid("result_resource_id").notNull(),
    resultVersion: integer("result_version").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    expiresAt: timestamp("expires_at", { withTimezone: true, mode: "date" })
      .notNull()
      .default(sql`now() + interval '24 hours'`),
  },
  (table) => [
    unique("tenant_authorization_commands_tenant_id_key").on(
      table.tenantId,
      table.id,
    ),
    unique("tenant_authorization_commands_replay_key").on(
      table.tenantId,
      table.actorMembershipId,
      table.operation,
      table.keyDigest,
    ),
    index("tenant_authorization_commands_expiry_idx").on(table.expiresAt),
    foreignKey({
      name: "tenant_authorization_commands_actor_fk",
      columns: [table.tenantId, table.actorMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "tenant_authorization_commands_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "tenant_authorization_commands_operation_check",
      sql`${table.operation} in (
        'tenant_role.create',
        'tenant_role_grant.create',
        'tenant_security_group.create',
        'tenant_security_group_membership.create',
        'tenant_security_group_role_grant.create',
        'operator_team_assignment.create',
        'operator_team_roster_entry.create',
        'identity_provider.create',
        'identity_provider_binding.create',
        'identity_mapping.create',
        'identity_sync.run',
        'dfir.attachment.prepare'
      )`,
    ),
    check(
      "tenant_authorization_commands_digest_check",
      sql`octet_length(${table.keyDigest}) = 32 and octet_length(${table.requestDigest}) = 32`,
    ),
    check(
      "tenant_authorization_commands_result_version_check",
      sql`${table.resultVersion} > 0`,
    ),
    check(
      "tenant_authorization_commands_retention_check",
      sql`${table.expiresAt} > ${table.createdAt} and ${table.expiresAt} <= ${table.createdAt} + interval '7 days'`,
    ),
  ],
).enableRLS();

export const tenantRoles = pgTable(
  "tenant_roles",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    key: text("key").notNull(),
    displayName: text("display_name").notNull(),
    description: text("description").notNull(),
    systemRole: boolean("system_role").notNull().default(false),
    protectedRole: boolean("protected_role").notNull().default(false),
    principalKind: tenantPrincipalKind("principal_kind")
      .notNull()
      .default("human"),
    version: integer("version").notNull().default(1),
    createdByMembershipId: uuid("created_by_membership_id"),
    archivedAt: timestamp("archived_at", {
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
    unique("tenant_roles_tenant_id_key").on(table.tenantId, table.id),
    unique("tenant_roles_tenant_id_principal_kind_key").on(
      table.tenantId,
      table.id,
      table.principalKind,
    ),
    unique("tenant_roles_tenant_key_key").on(table.tenantId, table.key),
    index("tenant_roles_tenant_active_idx")
      .on(table.tenantId, table.id)
      .where(sql`${table.archivedAt} is null`),
    foreignKey({
      name: "tenant_roles_creator_membership_fk",
      columns: [table.tenantId, table.createdByMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "tenant_roles_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "tenant_roles_key_canonical_check",
      sql`${table.key} ~ '^[a-z][a-z0-9_]{2,63}$'`,
    ),
    check(
      "tenant_roles_display_name_check",
      sql`btrim(${table.displayName}) <> '' and char_length(${table.displayName}) <= 120 and ${table.displayName} !~ '[[:cntrl:]]'`,
    ),
    check(
      "tenant_roles_description_check",
      sql`char_length(${table.description}) <= 500 and ${table.description} !~ '[[:cntrl:]]'`,
    ),
    check(
      "tenant_roles_protected_check",
      sql`${table.protectedRole} is false or ${table.systemRole} is true`,
    ),
    check(
      "tenant_roles_protected_principal_kind_check",
      sql`${table.protectedRole} is false or ${table.principalKind} = 'human'`,
    ),
    check("tenant_roles_version_check", sql`${table.version} > 0`),
    check(
      "tenant_roles_timestamps_check",
      sql`${table.updatedAt} >= ${table.createdAt} and (${table.archivedAt} is null or ${table.archivedAt} >= ${table.createdAt})`,
    ),
  ],
).enableRLS();

export const tenantRolePermissions = pgTable(
  "tenant_role_permissions",
  {
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    roleId: uuid("role_id").notNull(),
    permissionId: uuid("permission_id").notNull(),
    scope: authorizationScope("scope").notNull(),
    createdByMembershipId: uuid("created_by_membership_id"),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    primaryKey({
      name: "tenant_role_permissions_pkey",
      columns: [table.tenantId, table.roleId, table.permissionId, table.scope],
    }),
    index("tenant_role_permissions_catalog_idx").on(
      table.permissionId,
      table.scope,
      table.tenantId,
      table.roleId,
    ),
    foreignKey({
      name: "tenant_role_permissions_role_fk",
      columns: [table.tenantId, table.roleId],
      foreignColumns: [tenantRoles.tenantId, tenantRoles.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_role_permissions_scope_fk",
      columns: [table.permissionId, table.scope],
      foreignColumns: [
        tenantPermissionScopes.permissionId,
        tenantPermissionScopes.scope,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_role_permissions_creator_fk",
      columns: [table.tenantId, table.createdByMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "tenant_role_permissions_not_platform_check",
      sql`${table.scope} <> 'platform'`,
    ),
  ],
).enableRLS();

export const tenantRoleDelegationCeilings = pgTable(
  "tenant_role_delegation_ceilings",
  {
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    roleId: uuid("role_id").notNull(),
    permissionId: uuid("permission_id").notNull(),
    scope: authorizationScope("scope").notNull(),
    createdByMembershipId: uuid("created_by_membership_id"),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    primaryKey({
      name: "tenant_role_delegation_ceilings_pkey",
      columns: [table.tenantId, table.roleId, table.permissionId, table.scope],
    }),
    foreignKey({
      name: "tenant_role_delegation_permission_fk",
      columns: [table.tenantId, table.roleId, table.permissionId, table.scope],
      foreignColumns: [
        tenantRolePermissions.tenantId,
        tenantRolePermissions.roleId,
        tenantRolePermissions.permissionId,
        tenantRolePermissions.scope,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_role_delegation_creator_fk",
      columns: [table.tenantId, table.createdByMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "tenant_role_delegation_not_platform_check",
      sql`${table.scope} <> 'platform'`,
    ),
  ],
).enableRLS();

export const tenantMembershipRoleGrants = pgTable(
  "tenant_membership_role_grants",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    membershipId: uuid("membership_id").notNull(),
    roleId: uuid("role_id").notNull(),
    sourceId: uuid("source_id").notNull(),
    grantedByMembershipId: uuid("granted_by_membership_id"),
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
    unique("tenant_membership_role_grants_tenant_id_key").on(
      table.tenantId,
      table.id,
    ),
    uniqueIndex("tenant_membership_role_grants_active_key")
      .on(table.tenantId, table.membershipId, table.roleId, table.sourceId)
      .where(sql`${table.revokedAt} is null`),
    index("tenant_membership_role_grants_effective_idx")
      .on(table.tenantId, table.membershipId, table.roleId, table.expiresAt)
      .where(sql`${table.revokedAt} is null`),
    index("tenant_membership_role_grants_role_idx").on(
      table.tenantId,
      table.roleId,
      table.id,
    ),
    foreignKey({
      name: "tenant_membership_role_grants_membership_fk",
      columns: [table.tenantId, table.membershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_membership_role_grants_role_fk",
      columns: [table.tenantId, table.roleId],
      foreignColumns: [tenantRoles.tenantId, tenantRoles.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_membership_role_grants_grantor_fk",
      columns: [table.tenantId, table.grantedByMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_membership_role_grants_revoker_fk",
      columns: [table.tenantId, table.revokedByMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_membership_role_grants_source_fk",
      columns: [table.tenantId, table.sourceId],
      foreignColumns: [
        tenantAuthorizationSources.tenantId,
        tenantAuthorizationSources.id,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "tenant_membership_role_grants_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "tenant_membership_role_grants_expiry_check",
      sql`${table.expiresAt} is null or ${table.expiresAt} > ${table.grantedAt}`,
    ),
    check(
      "tenant_membership_role_grants_reason_check",
      sql`btrim(${table.grantReason}) <> '' and char_length(${table.grantReason}) <= 500 and ${table.grantReason} !~ '[[:cntrl:]]'`,
    ),
    check(
      "tenant_membership_role_grants_revocation_check",
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
      "tenant_membership_role_grants_version_check",
      sql`${table.version} > 0`,
    ),
    check(
      "tenant_membership_role_grants_updated_check",
      sql`${table.updatedAt} >= ${table.grantedAt} and (${table.revokedAt} is null or ${table.updatedAt} >= ${table.revokedAt})`,
    ),
  ],
).enableRLS();

export const tenantSecurityGroups = pgTable(
  "tenant_security_groups",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    key: text("key").notNull(),
    displayName: text("display_name").notNull(),
    description: text("description").notNull(),
    version: integer("version").notNull().default(1),
    createdByMembershipId: uuid("created_by_membership_id"),
    archivedAt: timestamp("archived_at", {
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
    unique("tenant_security_groups_tenant_id_key").on(table.tenantId, table.id),
    unique("tenant_security_groups_tenant_key_key").on(
      table.tenantId,
      table.key,
    ),
    index("tenant_security_groups_tenant_active_idx")
      .on(table.tenantId, table.id)
      .where(sql`${table.archivedAt} is null`),
    foreignKey({
      name: "tenant_security_groups_creator_membership_fk",
      columns: [table.tenantId, table.createdByMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "tenant_security_groups_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "tenant_security_groups_key_canonical_check",
      sql`${table.key} ~ '^[a-z][a-z0-9_]{2,63}$'`,
    ),
    check(
      "tenant_security_groups_display_name_check",
      sql`btrim(${table.displayName}) <> '' and char_length(${table.displayName}) <= 120 and ${table.displayName} !~ '[[:cntrl:]]'`,
    ),
    check(
      "tenant_security_groups_description_check",
      sql`char_length(${table.description}) <= 500 and ${table.description} !~ '[[:cntrl:]]'`,
    ),
    check("tenant_security_groups_version_check", sql`${table.version} > 0`),
    check(
      "tenant_security_groups_timestamps_check",
      sql`${table.updatedAt} >= ${table.createdAt} and (${table.archivedAt} is null or ${table.archivedAt} >= ${table.createdAt})`,
    ),
  ],
).enableRLS();

export const tenantSecurityGroupMemberships = pgTable(
  "tenant_security_group_memberships",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    groupId: uuid("group_id").notNull(),
    membershipId: uuid("membership_id").notNull(),
    sourceId: uuid("source_id").notNull(),
    grantedByMembershipId: uuid("granted_by_membership_id"),
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
    unique("tenant_security_group_memberships_tenant_id_key").on(
      table.tenantId,
      table.id,
    ),
    uniqueIndex("tenant_security_group_memberships_active_key")
      .on(table.tenantId, table.groupId, table.membershipId, table.sourceId)
      .where(sql`${table.revokedAt} is null`),
    index("tenant_security_group_memberships_effective_idx")
      .on(table.tenantId, table.membershipId, table.groupId, table.expiresAt)
      .where(sql`${table.revokedAt} is null`),
    index("tenant_security_group_memberships_group_idx").on(
      table.tenantId,
      table.groupId,
      table.id,
    ),
    foreignKey({
      name: "tenant_security_group_memberships_group_fk",
      columns: [table.tenantId, table.groupId],
      foreignColumns: [tenantSecurityGroups.tenantId, tenantSecurityGroups.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_security_group_memberships_membership_fk",
      columns: [table.tenantId, table.membershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_security_group_memberships_source_fk",
      columns: [table.tenantId, table.sourceId],
      foreignColumns: [
        tenantAuthorizationSources.tenantId,
        tenantAuthorizationSources.id,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_security_group_memberships_grantor_fk",
      columns: [table.tenantId, table.grantedByMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_security_group_memberships_revoker_fk",
      columns: [table.tenantId, table.revokedByMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "tenant_security_group_memberships_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "tenant_security_group_memberships_expiry_check",
      sql`${table.expiresAt} is null or ${table.expiresAt} > ${table.grantedAt}`,
    ),
    check(
      "tenant_security_group_memberships_reason_check",
      sql`btrim(${table.grantReason}) <> '' and char_length(${table.grantReason}) <= 500 and ${table.grantReason} !~ '[[:cntrl:]]'`,
    ),
    check(
      "tenant_security_group_memberships_revocation_check",
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
      "tenant_security_group_memberships_version_check",
      sql`${table.version} > 0`,
    ),
    check(
      "tenant_security_group_memberships_updated_check",
      sql`${table.updatedAt} >= ${table.grantedAt} and (${table.revokedAt} is null or ${table.updatedAt} >= ${table.revokedAt})`,
    ),
  ],
).enableRLS();

export const tenantSecurityGroupRoleGrants = pgTable(
  "tenant_security_group_role_grants",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    groupId: uuid("group_id").notNull(),
    roleId: uuid("role_id").notNull(),
    sourceId: uuid("source_id").notNull(),
    grantedByMembershipId: uuid("granted_by_membership_id"),
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
    unique("tenant_security_group_role_grants_tenant_id_key").on(
      table.tenantId,
      table.id,
    ),
    uniqueIndex("tenant_security_group_role_grants_active_key")
      .on(table.tenantId, table.groupId, table.roleId, table.sourceId)
      .where(sql`${table.revokedAt} is null`),
    index("tenant_security_group_role_grants_effective_idx")
      .on(table.tenantId, table.groupId, table.roleId, table.expiresAt)
      .where(sql`${table.revokedAt} is null`),
    index("tenant_security_group_role_grants_role_idx").on(
      table.tenantId,
      table.roleId,
      table.id,
    ),
    foreignKey({
      name: "tenant_security_group_role_grants_group_fk",
      columns: [table.tenantId, table.groupId],
      foreignColumns: [tenantSecurityGroups.tenantId, tenantSecurityGroups.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_security_group_role_grants_role_fk",
      columns: [table.tenantId, table.roleId],
      foreignColumns: [tenantRoles.tenantId, tenantRoles.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_security_group_role_grants_source_fk",
      columns: [table.tenantId, table.sourceId],
      foreignColumns: [
        tenantAuthorizationSources.tenantId,
        tenantAuthorizationSources.id,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_security_group_role_grants_grantor_fk",
      columns: [table.tenantId, table.grantedByMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_security_group_role_grants_revoker_fk",
      columns: [table.tenantId, table.revokedByMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "tenant_security_group_role_grants_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "tenant_security_group_role_grants_expiry_check",
      sql`${table.expiresAt} is null or ${table.expiresAt} > ${table.grantedAt}`,
    ),
    check(
      "tenant_security_group_role_grants_reason_check",
      sql`btrim(${table.grantReason}) <> '' and char_length(${table.grantReason}) <= 500 and ${table.grantReason} !~ '[[:cntrl:]]'`,
    ),
    check(
      "tenant_security_group_role_grants_revocation_check",
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
      "tenant_security_group_role_grants_version_check",
      sql`${table.version} > 0`,
    ),
    check(
      "tenant_security_group_role_grants_updated_check",
      sql`${table.updatedAt} >= ${table.grantedAt} and (${table.revokedAt} is null or ${table.updatedAt} >= ${table.revokedAt})`,
    ),
  ],
).enableRLS();
