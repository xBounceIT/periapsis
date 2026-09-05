import { sql } from "drizzle-orm";
import {
  bigint,
  boolean,
  check,
  foreignKey,
  index,
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

import { currentTenantId, currentUserId } from "./context.js";
import {
  loginIdentifierKind,
  membershipRole,
  membershipStatus,
} from "./enums.js";
import { apiRole } from "./roles.js";
import { tenants } from "./tenancy.js";

export const users = pgTable(
  "users",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    email: text("email"),
    displayName: text("display_name").notNull(),
    firstName: text("first_name"),
    lastName: text("last_name"),
    active: boolean("active").notNull().default(true),
    version: bigint("version", { mode: "bigint" })
      .notNull()
      .default(sql`1`),
    authenticationRevision: bigint("authentication_revision", {
      mode: "bigint",
    })
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
    unique("users_email_key").on(table.email),
    index("users_active_idx").on(table.active),
    check(
      "users_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "users_email_canonical_check",
      sql`${table.email} is null or ${table.email} = lower(btrim(${table.email}))`,
    ),
    check(
      "users_email_shape_check",
      sql`${table.email} is null or (
        position('@' in ${table.email}) > 1
        and char_length(${table.email}) <= 320
        and ${table.email} !~ '[[:cntrl:]]'
      )`,
    ),
    check(
      "users_display_name_not_blank_check",
      sql`btrim(${table.displayName}) <> ''
        and char_length(${table.displayName}) <= 160
        and ${table.displayName} !~ '[[:cntrl:]]'`,
    ),
    check(
      "users_updated_after_created_check",
      sql`${table.updatedAt} >= ${table.createdAt}`,
    ),
    check(
      "users_version_check",
      sql`${table.version} between 1 and 2147483647`,
    ),
    check(
      "users_authentication_revision_check",
      sql`${table.authenticationRevision} between 1 and 9007199254740991`,
    ),
  ],
).enableRLS();

export const userLoginIdentifiers = pgTable(
  "user_login_identifiers",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    userId: uuid("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "restrict" }),
    kind: loginIdentifierKind("kind").notNull(),
    canonicalValue: text("canonical_value").notNull(),
    verifiedAt: timestamp("verified_at", {
      withTimezone: true,
      mode: "date",
    }),
    retiredAt: timestamp("retired_at", {
      withTimezone: true,
      mode: "date",
    }),
    retireReason: text("retire_reason"),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    unique("user_login_identifiers_id_user_key").on(table.id, table.userId),
    unique("user_login_identifiers_kind_value_key").on(
      table.kind,
      table.canonicalValue,
    ),
    uniqueIndex("user_login_identifiers_user_active_kind_key")
      .on(table.userId, table.kind)
      .where(sql`${table.retiredAt} is null`),
    index("user_login_identifiers_user_idx").on(table.userId, table.id),
    check(
      "user_login_identifiers_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "user_login_identifiers_local_email_check",
      sql`${table.kind} <> 'local_email' or (
        ${table.canonicalValue} = lower(btrim(${table.canonicalValue}))
        and position('@' in ${table.canonicalValue}) > 1
        and char_length(${table.canonicalValue}) <= 320
        and ${table.canonicalValue} !~ '[[:cntrl:]]'
      )`,
    ),
    check(
      "user_login_identifiers_retirement_check",
      sql`(${table.retiredAt} is null and ${table.retireReason} is null)
        or (${table.retiredAt} is not null
          and ${table.retireReason} is not null
          and ${table.retiredAt} >= ${table.createdAt}
          and btrim(${table.retireReason}) <> ''
          and char_length(${table.retireReason}) <= 500
          and ${table.retireReason} !~ '[[:cntrl:]]')`,
    ),
    check(
      "user_login_identifiers_timestamps_check",
      sql`${table.updatedAt} >= ${table.createdAt}
        and (${table.verifiedAt} is null or ${table.verifiedAt} >= ${table.createdAt})
        and (${table.retiredAt} is null or ${table.updatedAt} >= ${table.retiredAt})`,
    ),
  ],
).enableRLS();

export const tenantMemberships = pgTable(
  "tenant_memberships",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    userId: uuid("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "restrict" }),
    role: membershipRole("role").notNull(),
    status: membershipStatus("status").notNull().default("active"),
    lifecycleRevision: integer("lifecycle_revision").notNull().default(1),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    unique("tenant_memberships_tenant_user_key").on(
      table.tenantId,
      table.userId,
    ),
    unique("tenant_memberships_tenant_id_key").on(table.tenantId, table.id),
    unique("tenant_memberships_tenant_id_user_id_key").on(
      table.tenantId,
      table.id,
      table.userId,
    ),
    index("tenant_memberships_user_tenant_idx").on(
      table.userId,
      table.tenantId,
    ),
    index("tenant_memberships_tenant_role_idx").on(table.tenantId, table.role),
    check(
      "tenant_memberships_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "tenant_memberships_updated_after_created_check",
      sql`${table.updatedAt} >= ${table.createdAt}`,
    ),
    check(
      "tenant_memberships_lifecycle_revision_check",
      sql`${table.lifecycleRevision} between 1 and 2147483647`,
    ),
    pgPolicy("tenant_memberships_api_self", {
      as: "permissive",
      for: "select",
      to: apiRole,
      using: sql`${table.tenantId} = ${currentTenantId}
        and ${table.userId} = ${currentUserId}
        and ${table.status} = 'active'`,
    }),
  ],
).enableRLS();

export const tenantUserProfiles = pgTable(
  "tenant_user_profiles",
  {
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    membershipId: uuid("membership_id").notNull(),
    userId: uuid("user_id").notNull(),
    displayName: text("display_name").notNull(),
    firstName: text("first_name"),
    lastName: text("last_name"),
    username: text("username"),
    email: text("email"),
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
      name: "tenant_user_profiles_pkey",
      columns: [table.tenantId, table.membershipId],
    }),
    unique("tenant_user_profiles_tenant_user_key").on(
      table.tenantId,
      table.userId,
    ),
    index("tenant_user_profiles_tenant_display_idx").on(
      table.tenantId,
      table.displayName,
      table.membershipId,
    ),
    index("tenant_user_profiles_tenant_username_idx").on(
      table.tenantId,
      table.username,
      table.membershipId,
    ),
    foreignKey({
      name: "tenant_user_profiles_membership_fk",
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
      "tenant_user_profiles_display_name_check",
      sql`btrim(${table.displayName}) <> ''
        and char_length(${table.displayName}) <= 160
        and ${table.displayName} !~ '[[:cntrl:]]'`,
    ),
    check(
      "tenant_user_profiles_name_check",
      sql`(${table.firstName} is null or (
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
      "tenant_user_profiles_username_check",
      sql`${table.username} is null or (
        btrim(${table.username}) <> ''
        and char_length(${table.username}) <= 320
        and ${table.username} !~ '[[:cntrl:]]'
      )`,
    ),
    check(
      "tenant_user_profiles_email_check",
      sql`${table.email} is null or (
        ${table.email} = lower(btrim(${table.email}))
        and position('@' in ${table.email}) > 1
        and char_length(${table.email}) <= 320
        and ${table.email} !~ '[[:cntrl:]]'
      )`,
    ),
    check("tenant_user_profiles_version_check", sql`${table.version} > 0`),
    check(
      "tenant_user_profiles_updated_check",
      sql`${table.updatedAt} >= ${table.createdAt}`,
    ),
  ],
).enableRLS();

export const activeActorMembershipFor = (tenantId: unknown) => sql`
  ${tenantId} = ${currentTenantId}
  and app.tenant_is_active_v1(${tenantId})
  and exists (
    select 1
    from ${tenantMemberships}
    where ${tenantMemberships.tenantId} = ${tenantId}
      and ${tenantMemberships.userId} = ${currentUserId}
      and ${tenantMemberships.status} = 'active'
  )
`;

export const usersApiTenantSelectPolicy = pgPolicy("users_api_tenant_select", {
  as: "permissive",
  for: "select",
  to: apiRole,
  using: sql`app.tenant_is_active_v1(${currentTenantId})
  and exists (
    select 1
    from ${tenantMemberships}
    where ${tenantMemberships.userId} = ${users.id}
      and ${tenantMemberships.tenantId} = ${currentTenantId}
      and ${tenantMemberships.status} = 'active'
  )`,
}).link(users);

export const tenantsApiCurrentSelectPolicy = pgPolicy(
  "tenants_api_select_current",
  {
    as: "permissive",
    for: "select",
    to: apiRole,
    using: activeActorMembershipFor(tenants.id),
  },
).link(tenants);
