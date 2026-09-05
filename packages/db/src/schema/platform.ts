import { sql } from "drizzle-orm";
import {
  bigint,
  boolean,
  char,
  check,
  index,
  inet,
  integer,
  jsonb,
  pgPolicy,
  pgTable,
  primaryKey,
  text,
  timestamp,
  unique,
  uniqueIndex,
  uuid,
} from "drizzle-orm/pg-core";

import { bytea } from "./binary.js";
import { auditActorType, auditOutcome } from "./enums.js";
import { users } from "./identity.js";
import { auditReaderOwnerRole } from "./roles.js";

export const platformPermissions = pgTable(
  "platform_permissions",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    key: text("key").notNull(),
    description: text("description").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    unique("platform_permissions_key_key").on(table.key),
    check(
      "platform_permissions_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "platform_permissions_key_canonical_check",
      sql`${table.key} ~ '^[a-z][a-z0-9_]*(\\.[a-z][a-z0-9_]*)+$'`,
    ),
    check(
      "platform_permissions_description_check",
      sql`btrim(${table.description}) <> ''`,
    ),
  ],
).enableRLS();

export const platformRoles = pgTable(
  "platform_roles",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    key: text("key").notNull(),
    displayName: text("display_name").notNull(),
    system: boolean("system").notNull().default(true),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    unique("platform_roles_key_key").on(table.key),
    check(
      "platform_roles_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "platform_roles_key_canonical_check",
      sql`${table.key} ~ '^[a-z][a-z0-9_]*$'`,
    ),
    check(
      "platform_roles_display_name_check",
      sql`btrim(${table.displayName}) <> ''`,
    ),
  ],
).enableRLS();

export const platformRolePermissions = pgTable(
  "platform_role_permissions",
  {
    roleId: uuid("role_id")
      .notNull()
      .references(() => platformRoles.id, { onDelete: "restrict" }),
    permissionId: uuid("permission_id")
      .notNull()
      .references(() => platformPermissions.id, { onDelete: "restrict" }),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    primaryKey({
      name: "platform_role_permissions_pkey",
      columns: [table.roleId, table.permissionId],
    }),
  ],
).enableRLS();

export const userPlatformRoles = pgTable(
  "user_platform_roles",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    userId: uuid("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "restrict" }),
    roleId: uuid("role_id")
      .notNull()
      .references(() => platformRoles.id, { onDelete: "restrict" }),
    grantedByUserId: uuid("granted_by_user_id").references(() => users.id, {
      onDelete: "restrict",
    }),
    grantedAt: timestamp("granted_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    revokedAt: timestamp("revoked_at", { withTimezone: true, mode: "date" }),
    revokedByUserId: uuid("revoked_by_user_id").references(() => users.id, {
      onDelete: "restrict",
    }),
  },
  (table) => [
    uniqueIndex("user_platform_roles_active_key")
      .on(table.userId, table.roleId)
      .where(sql`${table.revokedAt} is null`),
    index("user_platform_roles_user_active_idx")
      .on(table.userId, table.roleId)
      .where(sql`${table.revokedAt} is null`),
    check(
      "user_platform_roles_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "user_platform_roles_revocation_check",
      sql`(${table.revokedAt} is null and ${table.revokedByUserId} is null)
        or (${table.revokedAt} >= ${table.grantedAt} and ${table.revokedByUserId} is not null)`,
    ),
  ],
).enableRLS();

export const platformBootstrapEnrollments = pgTable(
  "platform_bootstrap_enrollments",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    singletonSlot: boolean("singleton_slot").notNull().default(true),
    canonicalEmail: text("canonical_email").notNull(),
    tokenDigest: bytea("token_digest").notNull(),
    enrollmentRateKeyDigest: bytea("enrollment_rate_key_digest").notNull(),
    totpSecretCiphertext: bytea("totp_secret_ciphertext").notNull(),
    totpSecretNonce: bytea("totp_secret_nonce").notNull(),
    totpSecretAad: bytea("totp_secret_aad").notNull(),
    totpKeyVersion: integer("totp_key_version").notNull(),
    attempts: integer("attempts").notNull().default(0),
    maxAttempts: integer("max_attempts").notNull().default(5),
    lastAttemptAt: timestamp("last_attempt_at", {
      withTimezone: true,
      mode: "date",
    }),
    expiresAt: timestamp("expires_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    consumedAt: timestamp("consumed_at", { withTimezone: true, mode: "date" }),
    invalidatedAt: timestamp("invalidated_at", {
      withTimezone: true,
      mode: "date",
    }),
    consumedByUserId: uuid("consumed_by_user_id").references(() => users.id, {
      onDelete: "restrict",
    }),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    unique("platform_bootstrap_enrollments_token_key").on(table.tokenDigest),
    uniqueIndex("platform_bootstrap_enrollments_active_slot_key")
      .on(table.singletonSlot)
      .where(
        sql`${table.consumedAt} is null and ${table.invalidatedAt} is null`,
      ),
    check(
      "platform_bootstrap_enrollments_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "platform_bootstrap_enrollments_slot_check",
      sql`${table.singletonSlot} is true`,
    ),
    check(
      "platform_bootstrap_enrollments_email_check",
      sql`${table.canonicalEmail} = lower(btrim(${table.canonicalEmail})) and position('@' in ${table.canonicalEmail}) > 1`,
    ),
    check(
      "platform_bootstrap_enrollments_token_check",
      sql`octet_length(${table.tokenDigest}) = 32`,
    ),
    check(
      "platform_bootstrap_enrollments_rate_digest_check",
      sql`octet_length(${table.enrollmentRateKeyDigest}) = 32`,
    ),
    check(
      "platform_bootstrap_enrollments_ciphertext_check",
      sql`octet_length(${table.totpSecretCiphertext}) > 16`,
    ),
    check(
      "platform_bootstrap_enrollments_nonce_check",
      sql`octet_length(${table.totpSecretNonce}) >= 12`,
    ),
    check(
      "platform_bootstrap_enrollments_aad_check",
      sql`octet_length(${table.totpSecretAad}) > 0`,
    ),
    check(
      "platform_bootstrap_enrollments_key_version_check",
      sql`${table.totpKeyVersion} > 0`,
    ),
    check(
      "platform_bootstrap_enrollments_attempts_check",
      sql`${table.attempts} >= 0 and ${table.maxAttempts} between 1 and 10 and ${table.attempts} <= ${table.maxAttempts}`,
    ),
    check(
      "platform_bootstrap_enrollments_expiry_check",
      sql`${table.expiresAt} > ${table.createdAt} and ${table.expiresAt} <= ${table.createdAt} + interval '15 minutes'`,
    ),
    check(
      "platform_bootstrap_enrollments_consumption_check",
      sql`(${table.consumedAt} is null and ${table.consumedByUserId} is null)
        or (${table.consumedAt} >= ${table.createdAt} and ${table.consumedByUserId} is not null and ${table.invalidatedAt} is null)`,
    ),
    check(
      "platform_bootstrap_enrollments_invalidation_check",
      sql`${table.invalidatedAt} is null
        or (${table.invalidatedAt} >= ${table.createdAt} and ${table.consumedAt} is null)`,
    ),
  ],
).enableRLS();

export const platformBootstrapState = pgTable(
  "platform_bootstrap_state",
  {
    singleton: boolean("singleton").primaryKey().default(true),
    authorityTokenDigest: bytea("authority_token_digest"),
    authorityConfiguredAt: timestamp("authority_configured_at", {
      withTimezone: true,
      mode: "date",
    }),
    masterKeyVerifier: bytea("master_key_verifier"),
    masterKeyVerifierBoundAt: timestamp("master_key_verifier_bound_at", {
      withTimezone: true,
      mode: "date",
    }),
    completedAt: timestamp("completed_at", {
      withTimezone: true,
      mode: "date",
    }),
    completedByUserId: uuid("completed_by_user_id").references(() => users.id, {
      onDelete: "restrict",
    }),
    enrollmentId: uuid("enrollment_id").references(
      () => platformBootstrapEnrollments.id,
      { onDelete: "restrict" },
    ),
  },
  (table) => [
    check(
      "platform_bootstrap_state_singleton_check",
      sql`${table.singleton} is true`,
    ),
    check(
      "platform_bootstrap_state_authority_check",
      sql`(${table.authorityTokenDigest} is null and ${table.authorityConfiguredAt} is null)
        or (octet_length(${table.authorityTokenDigest}) = 32 and ${table.authorityConfiguredAt} is not null)`,
    ),
    check(
      "platform_bootstrap_state_master_key_verifier_check",
      sql`(${table.masterKeyVerifier} is null and ${table.masterKeyVerifierBoundAt} is null)
        or (octet_length(${table.masterKeyVerifier}) = 32 and ${table.masterKeyVerifierBoundAt} is not null)`,
    ),
    check(
      "platform_bootstrap_state_protected_configuration_check",
      sql`(${table.authorityTokenDigest} is null
          and ${table.authorityConfiguredAt} is null
          and ${table.masterKeyVerifier} is null
          and ${table.masterKeyVerifierBoundAt} is null)
        or (${table.authorityTokenDigest} is not null
          and ${table.authorityConfiguredAt} is not null
          and ${table.masterKeyVerifier} is not null
          and ${table.masterKeyVerifierBoundAt} is not null)`,
    ),
    check(
      "platform_bootstrap_state_completion_check",
      sql`(${table.completedAt} is null and ${table.completedByUserId} is null and ${table.enrollmentId} is null)
        or (${table.completedAt} is not null
          and ${table.completedByUserId} is not null
          and ${table.enrollmentId} is not null
          and ${table.masterKeyVerifier} is not null
          and ${table.masterKeyVerifierBoundAt} <= ${table.completedAt})`,
    ),
  ],
).enableRLS();

export type PlatformAuditDiff = Record<string, unknown> | null;

export const platformAuditEvents = pgTable(
  "platform_audit_events",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    sequence: bigint("sequence", { mode: "bigint" }).notNull(),
    occurredAt: timestamp("occurred_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    actorType: auditActorType("actor_type").notNull(),
    actorUserId: uuid("actor_user_id").references(() => users.id, {
      onDelete: "restrict",
    }),
    action: text("action").notNull(),
    resourceType: text("resource_type").notNull(),
    resourceId: uuid("resource_id"),
    requestId: uuid("request_id"),
    correlationId: uuid("correlation_id"),
    ipAddress: inet("ip_address"),
    userAgent: text("user_agent"),
    authenticationMethod: text("authentication_method"),
    outcome: auditOutcome("outcome").notNull(),
    reason: text("reason"),
    before: jsonb("before").$type<PlatformAuditDiff>(),
    after: jsonb("after").$type<PlatformAuditDiff>(),
    metadata: jsonb("metadata")
      .$type<Record<string, unknown>>()
      .notNull()
      .default({}),
    previousHash: char("previous_hash", { length: 64 })
      .notNull()
      .default(
        "0000000000000000000000000000000000000000000000000000000000000000",
      ),
    eventHash: char("event_hash", { length: 64 })
      .notNull()
      .default(
        "0000000000000000000000000000000000000000000000000000000000000000",
      ),
  },
  (table) => [
    unique("platform_audit_events_sequence_key").on(table.sequence),
    index("platform_audit_events_time_idx").on(table.occurredAt, table.id),
    index("platform_audit_events_resource_idx").on(
      table.resourceType,
      table.resourceId,
    ),
    index("platform_audit_events_action_sequence_idx").on(
      table.action,
      table.sequence,
    ),
    index("platform_audit_events_outcome_sequence_idx").on(
      table.outcome,
      table.sequence,
    ),
    index("platform_audit_events_actor_user_sequence_idx").on(
      table.actorUserId,
      table.sequence,
    ),
    check(
      "platform_audit_events_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check("platform_audit_events_sequence_check", sql`${table.sequence} > 0`),
    check(
      "platform_audit_events_action_check",
      sql`btrim(${table.action}) <> ''`,
    ),
    check(
      "platform_audit_events_resource_type_check",
      sql`btrim(${table.resourceType}) <> ''`,
    ),
    check(
      "platform_audit_events_user_agent_check",
      sql`${table.userAgent} is null or length(${table.userAgent}) between 1 and 1024`,
    ),
    check(
      "platform_audit_events_authentication_method_check",
      sql`${table.authenticationMethod} is null or length(${table.authenticationMethod}) between 1 and 64`,
    ),
    check(
      "platform_audit_events_reason_check",
      sql`${table.reason} is null or octet_length(${table.reason}) between 1 and 2048`,
    ),
    check(
      "platform_audit_events_actor_check",
      sql`(${table.actorType} = 'user' and ${table.actorUserId} is not null)
        or (${table.actorType} in ('system', 'service_account') and ${table.actorUserId} is null)`,
    ),
    check(
      "platform_audit_events_previous_hash_check",
      sql`${table.previousHash} ~ '^[0-9a-f]{64}$'`,
    ),
    check(
      "platform_audit_events_event_hash_check",
      sql`${table.eventHash} ~ '^[0-9a-f]{64}$'`,
    ),
    pgPolicy("platform_audit_events_reader_select", {
      as: "permissive",
      for: "select",
      to: auditReaderOwnerRole,
      using: sql`app.platform_user_has_permission(app.context_user_id(), 'platform.audit.read')`,
    }),
  ],
).enableRLS();

export const platformAuditChainHead = pgTable(
  "platform_audit_chain_head",
  {
    singleton: boolean("singleton").primaryKey().default(true),
    lastSequence: bigint("last_sequence", { mode: "bigint" })
      .notNull()
      .default(sql`0`),
    lastEventHash: char("last_event_hash", { length: 64 })
      .notNull()
      .default(
        "0000000000000000000000000000000000000000000000000000000000000000",
      ),
    updatedAt: timestamp("updated_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    check(
      "platform_audit_chain_head_singleton_check",
      sql`${table.singleton} is true`,
    ),
    check(
      "platform_audit_chain_head_sequence_check",
      sql`${table.lastSequence} >= 0`,
    ),
    check(
      "platform_audit_chain_head_hash_check",
      sql`${table.lastEventHash} ~ '^[0-9a-f]{64}$'`,
    ),
    pgPolicy("platform_audit_chain_head_reader_select", {
      as: "permissive",
      for: "select",
      to: auditReaderOwnerRole,
      using: sql`app.platform_user_has_permission(app.context_user_id(), 'platform.audit.read')`,
    }),
  ],
).enableRLS();
