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
  uuid,
} from "drizzle-orm/pg-core";
import type { PgTableExtraConfigValue } from "drizzle-orm/pg-core";

import { tenantAuthorizationSources } from "./authorization.js";
import { bytea } from "./binary.js";
import { platformAuthProviders } from "./identity-platform-federation.js";
import { users } from "./identity.js";
import { tenants } from "./tenancy.js";

/**
 * One tenant-wide login-code namespace shared by tenant-owned and explicit
 * platform-provider bindings. The family and binding identity are immutable;
 * the key can move only through the protected rename workflow.
 */
export const tenantAuthProviderLoginKeys = pgTable(
  "tenant_auth_provider_login_keys",
  {
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    bindingFamily: text("binding_family").notNull(),
    bindingId: uuid("binding_id").notNull(),
    key: text("key").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    primaryKey({
      name: "tenant_auth_provider_login_keys_pkey",
      columns: [table.tenantId, table.key],
    }),
    unique("tenant_auth_provider_login_keys_binding_key").on(
      table.tenantId,
      table.bindingFamily,
      table.bindingId,
    ),
    unique("tenant_auth_provider_login_keys_exact_key").on(
      table.tenantId,
      table.bindingFamily,
      table.bindingId,
      table.key,
    ),
    index("tenant_auth_provider_login_keys_binding_idx").on(
      table.tenantId,
      table.bindingFamily,
      table.bindingId,
    ),
    check(
      "tenant_auth_provider_login_keys_family_check",
      sql`${table.bindingFamily} in ('tenant_provider', 'platform_provider')`,
    ),
    check(
      "tenant_auth_provider_login_keys_binding_uuidv7_check",
      sql`(uuid_extract_version(${table.bindingId}) = 7) is true`,
    ),
    check(
      "tenant_auth_provider_login_keys_key_check",
      sql`${table.key} = lower(btrim(${table.key}))
        and ${table.key} ~ '^[a-z][a-z0-9_-]{2,63}$'`,
    ),
    check(
      "tenant_auth_provider_login_keys_timestamp_check",
      sql`${table.updatedAt} >= ${table.createdAt}`,
    ),
  ],
).enableRLS();

/**
 * Explicit tenant admission policy for one platform provider. Lifecycle
 * writers couple an enabled binding to its current access epoch and reset the
 * admission modes when that epoch is retired.
 */
export const tenantPlatformAuthProviderBindings = pgTable(
  "tenant_platform_auth_provider_bindings",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    bindingFamily: text("binding_family")
      .notNull()
      .default("platform_provider"),
    platformProviderId: uuid("platform_provider_id").notNull(),
    key: text("key").notNull(),
    enabled: boolean("enabled").notNull().default(false),
    jitMode: text("jit_mode").notNull().default("disabled"),
    noMatchPolicy: text("no_match_policy").notNull().default("deny"),
    profilePriority: integer("profile_priority").notNull().default(100),
    authRevision: bigint("auth_revision", { mode: "bigint" })
      .notNull()
      .default(sql`1`),
    mappingRevision: bigint("mapping_revision", { mode: "bigint" })
      .notNull()
      .default(sql`1`),
    currentAccessEpochId: uuid("current_access_epoch_id"),
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
  (table): PgTableExtraConfigValue[] => [
    unique("tenant_platform_auth_provider_bindings_tenant_id_key").on(
      table.tenantId,
      table.id,
    ),
    unique("tenant_platform_auth_provider_bindings_exact_key").on(
      table.tenantId,
      table.id,
      table.platformProviderId,
    ),
    unique("tenant_platform_auth_provider_bindings_provider_key").on(
      table.tenantId,
      table.platformProviderId,
    ),
    unique("tenant_platform_auth_provider_bindings_login_key").on(
      table.tenantId,
      table.key,
    ),
    unique("tenant_platform_auth_provider_bindings_login_claim_key").on(
      table.tenantId,
      table.bindingFamily,
      table.id,
      table.key,
    ),
    index("tenant_platform_auth_provider_bindings_provider_idx").on(
      table.platformProviderId,
      table.archivedAt,
      table.id,
    ),
    index("tenant_platform_auth_provider_bindings_tenant_idx").on(
      table.tenantId,
      table.archivedAt,
      table.id,
    ),
    foreignKey({
      name: "tenant_platform_auth_provider_bindings_login_claim_fk",
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
      name: "tenant_platform_auth_provider_bindings_provider_fk",
      columns: [table.platformProviderId],
      foreignColumns: [platformAuthProviders.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_platform_auth_provider_bindings_current_epoch_fk",
      columns: [
        table.tenantId,
        table.currentAccessEpochId,
        table.id,
        table.platformProviderId,
      ],
      foreignColumns: [
        tenantPlatformIdentityProviderAccessEpochs.tenantId,
        tenantPlatformIdentityProviderAccessEpochs.id,
        tenantPlatformIdentityProviderAccessEpochs.bindingId,
        tenantPlatformIdentityProviderAccessEpochs.platformProviderId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "tenant_platform_auth_provider_bindings_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "tenant_platform_auth_provider_bindings_family_check",
      sql`${table.bindingFamily} = 'platform_provider'`,
    ),
    check(
      "tenant_platform_auth_provider_bindings_key_check",
      sql`${table.key} = lower(btrim(${table.key}))
        and ${table.key} ~ '^[a-z][a-z0-9_-]{2,63}$'`,
    ),
    check(
      "tenant_platform_auth_provider_bindings_priority_check",
      sql`${table.profilePriority} between 0 and 1000000`,
    ),
    check(
      "tenant_platform_auth_provider_bindings_revision_check",
      sql`${table.authRevision} between 1 and 9007199254740991
        and ${table.mappingRevision} between 1 and 9007199254740991
        and ${table.version} between 1 and 2147483647`,
    ),
    check(
      "tenant_platform_auth_provider_bindings_admission_check",
      sql`${table.jitMode} in ('disabled', 'create')
        and ${table.noMatchPolicy} in ('deny', 'provider_access_only')`,
    ),
    check(
      "tenant_platform_auth_provider_bindings_activation_check",
      sql`${table.enabled} = (${table.currentAccessEpochId} is not null)`,
    ),
    check(
      "tenant_platform_auth_provider_bindings_archive_check",
      sql`(${table.archivedAt} is null
          and ${table.archivedByUserId} is null
          and ${table.archiveReason} is null)
        or (${table.archivedAt} is not null
          and ${table.archivedByUserId} is not null
          and ${table.archiveReason} is not null
          and not ${table.enabled}
          and ${table.currentAccessEpochId} is null
          and ${table.archivedAt} >= ${table.createdAt}
          and ${table.archiveReason} = btrim(${table.archiveReason})
          and ${table.archiveReason} <> ''
          and octet_length(convert_to(${table.archiveReason}, 'UTF8')) <= 2048
          and ${table.archiveReason} !~ '[[:cntrl:]]')`,
    ),
    check(
      "tenant_platform_auth_provider_bindings_lifecycle_check",
      sql`isfinite(${table.createdAt}) and isfinite(${table.updatedAt})
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

/**
 * Physically separate access epochs for tenant admission through a platform
 * provider. Each live epoch owns the canonical authoritative authorization
 * source that bounds provider-derived tenant access.
 */
export const tenantPlatformIdentityProviderAccessEpochs = pgTable(
  "tenant_platform_identity_provider_access_epochs",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    bindingId: uuid("binding_id").notNull(),
    platformProviderId: uuid("platform_provider_id").notNull(),
    sourceId: uuid("source_id").notNull(),
    sequence: integer("sequence").notNull(),
    startedByUserId: uuid("started_by_user_id")
      .notNull()
      .references(() => users.id, { onDelete: "restrict" }),
    startedAt: timestamp("started_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    endedAt: timestamp("ended_at", { withTimezone: true, mode: "date" }),
    endedByUserId: uuid("ended_by_user_id").references(() => users.id, {
      onDelete: "restrict",
    }),
    endReason: text("end_reason"),
    version: bigint("version", { mode: "bigint" })
      .notNull()
      .default(sql`1`),
  },
  (table) => [
    unique("tenant_platform_identity_provider_access_epochs_tenant_id_key").on(
      table.tenantId,
      table.id,
    ),
    unique("tenant_platform_identity_provider_access_epochs_exact_key").on(
      table.tenantId,
      table.id,
      table.bindingId,
      table.platformProviderId,
      table.sourceId,
    ),
    unique("tenant_platform_identity_provider_access_epochs_current_key").on(
      table.tenantId,
      table.id,
      table.bindingId,
      table.platformProviderId,
    ),
    unique("tenant_platform_identity_provider_access_epochs_sequence_key").on(
      table.tenantId,
      table.bindingId,
      table.sequence,
    ),
    unique("tenant_platform_identity_provider_access_epochs_source_key").on(
      table.tenantId,
      table.sourceId,
    ),
    index("tenant_platform_identity_provider_access_epochs_provider_idx").on(
      table.platformProviderId,
      table.tenantId,
      table.bindingId,
      table.sequence,
    ),
    foreignKey({
      name: "tenant_platform_identity_provider_access_epochs_binding_fk",
      columns: [table.tenantId, table.bindingId, table.platformProviderId],
      foreignColumns: [
        tenantPlatformAuthProviderBindings.tenantId,
        tenantPlatformAuthProviderBindings.id,
        tenantPlatformAuthProviderBindings.platformProviderId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_platform_identity_provider_access_epochs_source_fk",
      columns: [table.tenantId, table.sourceId],
      foreignColumns: [
        tenantAuthorizationSources.tenantId,
        tenantAuthorizationSources.id,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "tenant_platform_identity_provider_access_epochs_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "tenant_platform_identity_provider_access_epochs_sequence_check",
      sql`${table.sequence} > 0`,
    ),
    check(
      "tenant_platform_identity_provider_access_epochs_lifecycle_check",
      sql`(${table.endedAt} is null
          and ${table.endedByUserId} is null
          and ${table.endReason} is null
          and ${table.version} = 1)
        or (${table.endedAt} is not null
          and ${table.endedByUserId} is not null
          and ${table.endReason} is not null
          and ${table.endedAt} >= ${table.startedAt}
          and ${table.endReason} = btrim(${table.endReason})
          and ${table.endReason} <> ''
          and octet_length(convert_to(${table.endReason}, 'UTF8')) <= 2048
          and ${table.endReason} !~ '[[:cntrl:]]'
          and ${table.version} = 2)`,
    ),
  ],
).enableRLS();

/** Platform-actor-scoped idempotency ledger with tenant-qualified provenance. */
export const tenantPlatformIdentityBindingCommands = pgTable(
  "tenant_platform_identity_binding_commands",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    actorUserId: uuid("actor_user_id")
      .notNull()
      .references(() => users.id, { onDelete: "restrict" }),
    operation: text("operation").notNull(),
    keyDigest: bytea("key_digest").notNull(),
    requestDigest: bytea("request_digest").notNull(),
    resultBindingId: uuid("result_binding_id").notNull(),
    resultVersion: bigint("result_version", { mode: "bigint" }).notNull(),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    expiresAt: timestamp("expires_at", { withTimezone: true, mode: "date" })
      .notNull()
      .default(sql`now() + interval '24 hours'`),
  },
  (table) => [
    unique("tenant_platform_identity_binding_commands_replay_key").on(
      table.actorUserId,
      table.operation,
      table.keyDigest,
    ),
    index("tenant_platform_identity_binding_commands_expiry_idx").on(
      table.expiresAt,
    ),
    foreignKey({
      name: "tenant_platform_identity_binding_commands_result_fk",
      columns: [table.tenantId, table.resultBindingId],
      foreignColumns: [
        tenantPlatformAuthProviderBindings.tenantId,
        tenantPlatformAuthProviderBindings.id,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "tenant_platform_identity_binding_commands_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "tenant_platform_identity_binding_commands_operation_check",
      sql`${table.operation} = 'binding.create'`,
    ),
    check(
      "tenant_platform_identity_binding_commands_digest_check",
      sql`octet_length(${table.keyDigest}) = 32
        and octet_length(${table.requestDigest}) = 32`,
    ),
    check(
      "tenant_platform_identity_binding_commands_result_check",
      sql`${table.resultVersion} = 1`,
    ),
    check(
      "tenant_platform_identity_binding_commands_retention_check",
      sql`${table.expiresAt} > ${table.createdAt}
        and ${table.expiresAt} <= ${table.createdAt} + interval '7 days'`,
    ),
  ],
).enableRLS();
