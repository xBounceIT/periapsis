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
import { bytea } from "./binary.js";
import { userLoginIdentifiers, users } from "./identity.js";

const safeRevision = (value: unknown) =>
  sql`${value} between 1 and 9007199254740991`;

/** Safe lifecycle shell; all credential and ceremony material is separate. */
export const platformLocalAccounts = pgTable(
  "platform_local_accounts",
  {
    id: uuid("id").primaryKey(),
    userId: uuid("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "restrict" }),
    loginIdentifierId: uuid("login_identifier_id").notNull(),
    status: text("status").notNull().default("invited"),
    protectedRecoveryPrincipal: boolean("protected_recovery_principal")
      .notNull()
      .default(false),
    revision: bigint("revision", { mode: "bigint" })
      .notNull()
      .default(sql`1`),
    identityEpoch: bigint("identity_epoch", { mode: "bigint" })
      .notNull()
      .default(sql`1`),
    invitedAt: timestamp("invited_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    activatedAt: timestamp("activated_at", {
      withTimezone: true,
      mode: "date",
    }),
    disabledAt: timestamp("disabled_at", {
      withTimezone: true,
      mode: "date",
    }),
    recoveryStartedAt: timestamp("recovery_started_at", {
      withTimezone: true,
      mode: "date",
    }),
    updatedAt: timestamp("updated_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
  },
  (table) => [
    unique("platform_local_accounts_user_key").on(table.userId),
    unique("platform_local_accounts_identifier_key").on(
      table.loginIdentifierId,
    ),
    unique("platform_local_accounts_id_user_key").on(table.id, table.userId),
    foreignKey({
      name: "platform_local_accounts_identifier_fk",
      columns: [table.loginIdentifierId, table.userId],
      foreignColumns: [userLoginIdentifiers.id, userLoginIdentifiers.userId],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    index("platform_local_accounts_inventory_idx").on(table.status, table.id),
    check(
      "platform_local_accounts_id_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "platform_local_accounts_status_check",
      sql`${table.status} in ('invited','active','disabled','recovery_restricted')`,
    ),
    check(
      "platform_local_accounts_revision_check",
      sql`${safeRevision(table.revision)} and ${safeRevision(table.identityEpoch)}`,
    ),
    check(
      "platform_local_accounts_lifecycle_check",
      sql`(${table.status} = 'invited'
          and ${table.activatedAt} is null
          and ${table.disabledAt} is null
          and ${table.recoveryStartedAt} is null)
        or (${table.status} = 'active'
          and ${table.activatedAt} is not null
          and ${table.disabledAt} is null
          and ${table.recoveryStartedAt} is null)
        or (${table.status} = 'disabled'
          and ${table.activatedAt} is not null
          and ${table.disabledAt} is not null)
        or (${table.status} = 'recovery_restricted'
          and ${table.activatedAt} is not null
          and ${table.disabledAt} is null
          and ${table.recoveryStartedAt} is not null)`,
    ),
    check(
      "platform_local_accounts_timestamps_check",
      sql`date_trunc('milliseconds', ${table.invitedAt}) = ${table.invitedAt}
        and date_trunc('milliseconds', ${table.updatedAt}) = ${table.updatedAt}
        and ${table.updatedAt} >= ${table.invitedAt}
        and (${table.activatedAt} is null
          or (date_trunc('milliseconds', ${table.activatedAt}) = ${table.activatedAt}
            and ${table.activatedAt} between ${table.invitedAt} and ${table.updatedAt}))
        and (${table.disabledAt} is null
          or (date_trunc('milliseconds', ${table.disabledAt}) = ${table.disabledAt}
            and ${table.disabledAt} between ${table.invitedAt} and ${table.updatedAt}))
        and (${table.recoveryStartedAt} is null
          or (date_trunc('milliseconds', ${table.recoveryStartedAt}) = ${table.recoveryStartedAt}
            and ${table.recoveryStartedAt} between ${table.invitedAt} and ${table.updatedAt}))`,
    ),
  ],
).enableRLS();

/** Encrypted pending TOTP enrollment; never exposed by a public projection. */
export const platformLocalAccountCeremonies = pgTable(
  "platform_local_account_ceremonies",
  {
    factorId: uuid("factor_id").primaryKey(),
    accountId: uuid("account_id").notNull(),
    userId: uuid("user_id").notNull(),
    purpose: text("purpose").notNull(),
    version: bigint("version", { mode: "bigint" }).notNull(),
    factorRevision: bigint("factor_revision", { mode: "bigint" }).notNull(),
    ceremonyTokenDigest: bytea("ceremony_token_digest").notNull(),
    secretCiphertext: bytea("secret_ciphertext").notNull(),
    secretNonce: bytea("secret_nonce").notNull(),
    secretAad: bytea("secret_aad").notNull(),
    keyVersion: integer("key_version").notNull(),
    state: text("state").notNull().default("pending"),
    attempts: integer("attempts").notNull().default(0),
    maximumAttempts: integer("maximum_attempts").notNull().default(5),
    expiresAt: timestamp("expires_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    confirmedAt: timestamp("confirmed_at", {
      withTimezone: true,
      mode: "date",
    }),
    retiredAt: timestamp("retired_at", {
      withTimezone: true,
      mode: "date",
    }),
    failureReason: text("failure_reason"),
    createdAt: timestamp("created_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    updatedAt: timestamp("updated_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
  },
  (table) => [
    foreignKey({
      name: "platform_local_account_ceremonies_account_fk",
      columns: [table.accountId, table.userId],
      foreignColumns: [platformLocalAccounts.id, platformLocalAccounts.userId],
    }).onDelete("restrict"),
    unique("platform_local_account_ceremonies_token_key").on(
      table.ceremonyTokenDigest,
    ),
    uniqueIndex("platform_local_account_ceremonies_pending_key")
      .on(table.accountId)
      .where(sql`${table.state} = 'pending'`),
    index("platform_local_account_ceremonies_expiry_idx").on(
      table.state,
      table.expiresAt,
      table.factorId,
    ),
    check(
      "platform_local_account_ceremonies_identity_check",
      sql`(uuid_extract_version(${table.factorId}) = 7) is true
        and ${table.purpose} in ('invite','recover')
        and ${table.version} = 1
        and ${table.factorRevision} = 1
        and octet_length(${table.ceremonyTokenDigest}) = 32`,
    ),
    check(
      "platform_local_account_ceremonies_envelope_check",
      sql`octet_length(${table.secretCiphertext}) between 17 and 8192
        and octet_length(${table.secretNonce}) = 12
        and octet_length(${table.secretAad}) between 1 and 1024
        and ${table.keyVersion} > 0`,
    ),
    check(
      "platform_local_account_ceremonies_attempt_check",
      sql`${table.attempts} between 0 and ${table.maximumAttempts}
        and ${table.maximumAttempts} between 1 and 20`,
    ),
    check(
      "platform_local_account_ceremonies_state_check",
      sql`(${table.state} = 'pending'
          and ${table.confirmedAt} is null and ${table.retiredAt} is null
          and ${table.failureReason} is null)
        or (${table.state} = 'confirmed'
          and ${table.confirmedAt} is not null and ${table.retiredAt} is null
          and ${table.failureReason} is null)
        or (${table.state} in ('retired','failed')
          and ${table.confirmedAt} is null and ${table.retiredAt} is not null
          and (${table.state} = 'retired') = (${table.failureReason} is null))`,
    ),
    check(
      "platform_local_account_ceremonies_timestamp_check",
      sql`date_trunc('milliseconds', ${table.createdAt}) = ${table.createdAt}
        and date_trunc('milliseconds', ${table.updatedAt}) = ${table.updatedAt}
        and date_trunc('milliseconds', ${table.expiresAt}) = ${table.expiresAt}
        and ${table.expiresAt} > ${table.createdAt}
        and ${table.updatedAt} >= ${table.createdAt}
        and (${table.confirmedAt} is null
          or ${table.confirmedAt} between ${table.createdAt} and ${table.updatedAt})
        and (${table.retiredAt} is null
          or ${table.retiredAt} between ${table.createdAt} and ${table.updatedAt})`,
    ),
  ],
).enableRLS();

/** Payload-bound replay receipt. The result snapshot is always safe JSON. */
export const platformLocalAccountCommandReceipts = pgTable(
  "platform_local_account_command_receipts",
  {
    commandId: uuid("command_id").primaryKey(),
    actorUserId: uuid("actor_user_id")
      .notNull()
      .references(() => users.id, { onDelete: "restrict" }),
    actorSessionId: uuid("actor_session_id")
      .notNull()
      .references(() => authSessions.id, { onDelete: "restrict" }),
    accountId: uuid("account_id")
      .notNull()
      .references(() => platformLocalAccounts.id, { onDelete: "restrict" }),
    action: text("action").notNull(),
    expectedRevision: bigint("expected_revision", { mode: "bigint" }).notNull(),
    idempotencyKeyDigest: bytea("idempotency_key_digest").notNull(),
    publicRequestDigest: bytea("public_request_digest").notNull(),
    resultSnapshot: jsonb("result_snapshot")
      .$type<Record<string, unknown>>()
      .notNull(),
    artifactIssued: boolean("artifact_issued").notNull(),
    createdAt: timestamp("created_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
  },
  (table) => [
    unique("platform_local_account_command_receipts_replay_key").on(
      table.actorUserId,
      table.idempotencyKeyDigest,
    ),
    index("platform_local_account_command_receipts_account_idx").on(
      table.accountId,
      table.createdAt,
      table.commandId,
    ),
    check(
      "platform_local_account_command_receipts_identity_check",
      sql`(uuid_extract_version(${table.commandId}) = 7) is true
        and ${table.action} in ('invite','activate','disable','recover','enable','rotate_password')
        and ${table.expectedRevision} between 0 and 9007199254740990
        and octet_length(${table.idempotencyKeyDigest}) = 32
        and octet_length(${table.publicRequestDigest}) = 32
        and jsonb_typeof(${table.resultSnapshot}) = 'object'
        and pg_column_size(${table.resultSnapshot}) <= 16384
        and date_trunc('milliseconds', ${table.createdAt}) = ${table.createdAt}`,
    ),
  ],
).enableRLS();

/** Bounded immutable PHC history, never selected by a public ABI. */
export const platformLocalPasswordHistory = pgTable(
  "platform_local_password_history",
  {
    accountId: uuid("account_id")
      .notNull()
      .references(() => platformLocalAccounts.id, { onDelete: "restrict" }),
    credentialVersion: bigint("credential_version", {
      mode: "bigint",
    }).notNull(),
    passwordPhc: text("password_phc").notNull(),
    changedAt: timestamp("changed_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
  },
  (table) => [
    primaryKey({
      name: "platform_local_password_history_pkey",
      columns: [table.accountId, table.credentialVersion],
    }),
    index("platform_local_password_history_recent_idx").on(
      table.accountId,
      table.credentialVersion,
    ),
    check(
      "platform_local_password_history_value_check",
      sql`${safeRevision(table.credentialVersion)}
        and ${table.passwordPhc} like '$argon2id$%'
        and octet_length(${table.passwordPhc}) between 32 and 1024
        and date_trunc('milliseconds', ${table.changedAt}) = ${table.changedAt}`,
    ),
  ],
).enableRLS();
