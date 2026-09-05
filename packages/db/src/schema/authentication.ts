import { sql } from "drizzle-orm";
import {
  bigint,
  boolean,
  check,
  foreignKey,
  index,
  integer,
  pgTable,
  text,
  timestamp,
  unique,
  uniqueIndex,
  uuid,
} from "drizzle-orm/pg-core";

import { authChallengePurpose, authRateLimitScope } from "./enums.js";
import { userLoginIdentifiers, users } from "./identity.js";
import { bytea } from "./binary.js";
import { tenants } from "./tenancy.js";

export const localBreakGlassCredentials = pgTable(
  "local_break_glass_credentials",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    userId: uuid("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "restrict" }),
    loginIdentifierId: uuid("login_identifier_id").notNull(),
    passwordPhc: text("password_phc").notNull(),
    passwordAlgorithm: text("password_algorithm").notNull().default("argon2id"),
    passwordVersion: integer("password_version").notNull().default(1),
    mustRotate: boolean("must_rotate").notNull().default(false),
    changedAt: timestamp("changed_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    disabledAt: timestamp("disabled_at", { withTimezone: true, mode: "date" }),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    unique("local_break_glass_credentials_user_key").on(table.userId),
    unique("local_break_glass_credentials_login_identifier_key").on(
      table.loginIdentifierId,
    ),
    foreignKey({
      name: "local_break_glass_credentials_login_identifier_fk",
      columns: [table.loginIdentifierId, table.userId],
      foreignColumns: [userLoginIdentifiers.id, userLoginIdentifiers.userId],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "local_break_glass_credentials_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "local_break_glass_credentials_algorithm_check",
      sql`${table.passwordAlgorithm} = 'argon2id'`,
    ),
    check(
      "local_break_glass_credentials_phc_check",
      sql`${table.passwordPhc} like '$argon2id$%' and length(${table.passwordPhc}) between 32 and 1024`,
    ),
    check(
      "local_break_glass_credentials_version_check",
      sql`${table.passwordVersion} > 0`,
    ),
    check(
      "local_break_glass_credentials_updated_check",
      sql`${table.updatedAt} >= ${table.createdAt} and ${table.changedAt} >= ${table.createdAt}`,
    ),
  ],
).enableRLS();

export const totpCredentials = pgTable(
  "totp_credentials",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    userId: uuid("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "restrict" }),
    secretCiphertext: bytea("secret_ciphertext").notNull(),
    secretNonce: bytea("secret_nonce").notNull(),
    secretAad: bytea("secret_aad").notNull(),
    keyVersion: integer("key_version").notNull(),
    encryptionAlgorithm: text("encryption_algorithm")
      .notNull()
      .default("aes-256-gcm"),
    otpAlgorithm: text("otp_algorithm").notNull().default("SHA1"),
    digits: integer("digits").notNull().default(6),
    periodSeconds: integer("period_seconds").notNull().default(30),
    confirmedAt: timestamp("confirmed_at", {
      withTimezone: true,
      mode: "date",
    }),
    lastAcceptedCounter: bigint("last_accepted_counter", { mode: "bigint" }),
    securityRevision: bigint("security_revision", { mode: "bigint" })
      .notNull()
      .default(sql`1`),
    disabledAt: timestamp("disabled_at", { withTimezone: true, mode: "date" }),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    uniqueIndex("totp_credentials_user_live_key")
      .on(table.userId)
      .where(sql`${table.disabledAt} is null`),
    unique("totp_credentials_id_user_key").on(table.id, table.userId),
    check(
      "totp_credentials_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "totp_credentials_ciphertext_check",
      sql`octet_length(${table.secretCiphertext}) > 16`,
    ),
    check(
      "totp_credentials_nonce_check",
      sql`octet_length(${table.secretNonce}) >= 12`,
    ),
    check(
      "totp_credentials_aad_check",
      sql`octet_length(${table.secretAad}) > 0`,
    ),
    check("totp_credentials_key_version_check", sql`${table.keyVersion} > 0`),
    check(
      "totp_credentials_encryption_algorithm_check",
      sql`${table.encryptionAlgorithm} in ('aes-256-gcm', 'xchacha20-poly1305')`,
    ),
    check(
      "totp_credentials_otp_algorithm_check",
      sql`${table.otpAlgorithm} in ('SHA1', 'SHA256', 'SHA512')`,
    ),
    check("totp_credentials_digits_check", sql`${table.digits} in (6, 8)`),
    check(
      "totp_credentials_period_check",
      sql`${table.periodSeconds} between 15 and 120`,
    ),
    check(
      "totp_credentials_counter_check",
      sql`${table.lastAcceptedCounter} is null or ${table.lastAcceptedCounter} >= 0`,
    ),
    check(
      "totp_credentials_security_revision_check",
      sql`${table.securityRevision} between 1 and 9007199254740991`,
    ),
    check(
      "totp_credentials_updated_check",
      sql`${table.updatedAt} >= ${table.createdAt}`,
    ),
  ],
).enableRLS();

export const recoveryCodes = pgTable(
  "recovery_codes",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    userId: uuid("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "restrict" }),
    totpCredentialId: uuid("totp_credential_id").notNull(),
    codeDigest: bytea("code_digest").notNull(),
    keyVersion: integer("key_version").notNull(),
    consumedAt: timestamp("consumed_at", { withTimezone: true, mode: "date" }),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    foreignKey({
      name: "recovery_codes_credential_user_fk",
      columns: [table.totpCredentialId, table.userId],
      foreignColumns: [totpCredentials.id, totpCredentials.userId],
    }).onDelete("restrict"),
    unique("recovery_codes_credential_digest_key").on(
      table.totpCredentialId,
      table.codeDigest,
    ),
    index("recovery_codes_user_available_idx")
      .on(table.userId, table.createdAt)
      .where(sql`${table.consumedAt} is null`),
    check(
      "recovery_codes_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "recovery_codes_digest_check",
      sql`octet_length(${table.codeDigest}) = 32`,
    ),
    check("recovery_codes_key_version_check", sql`${table.keyVersion} > 0`),
    check(
      "recovery_codes_consumed_after_created_check",
      sql`${table.consumedAt} is null or ${table.consumedAt} >= ${table.createdAt}`,
    ),
  ],
).enableRLS();

export const authChallenges = pgTable(
  "auth_challenges",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    userId: uuid("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "restrict" }),
    challengeRateKeyDigest: bytea("challenge_rate_key_digest").notNull(),
    mfaRateKeyDigest: bytea("mfa_rate_key_digest").notNull(),
    loginAccountRateKeyDigest: bytea("login_account_rate_key_digest").notNull(),
    tokenDigest: bytea("token_digest").notNull(),
    purpose: authChallengePurpose("purpose").notNull(),
    attempts: integer("attempts").notNull().default(0),
    maxAttempts: integer("max_attempts").notNull().default(5),
    expiresAt: timestamp("expires_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    consumedAt: timestamp("consumed_at", { withTimezone: true, mode: "date" }),
    lastAttemptAt: timestamp("last_attempt_at", {
      withTimezone: true,
      mode: "date",
    }),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    unique("auth_challenges_token_digest_key").on(table.tokenDigest),
    uniqueIndex("auth_challenges_user_unconsumed_key")
      .on(table.userId, table.purpose)
      .where(sql`${table.consumedAt} is null`),
    check(
      "auth_challenges_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "auth_challenges_digest_check",
      sql`octet_length(${table.tokenDigest}) = 32`,
    ),
    check(
      "auth_challenges_challenge_rate_digest_check",
      sql`octet_length(${table.challengeRateKeyDigest}) = 32`,
    ),
    check(
      "auth_challenges_mfa_rate_digest_check",
      sql`octet_length(${table.mfaRateKeyDigest}) = 32`,
    ),
    check(
      "auth_challenges_login_account_rate_digest_check",
      sql`octet_length(${table.loginAccountRateKeyDigest}) = 32`,
    ),
    check(
      "auth_challenges_attempts_check",
      sql`${table.attempts} >= 0 and ${table.maxAttempts} between 1 and 20 and ${table.attempts} <= ${table.maxAttempts}`,
    ),
    check(
      "auth_challenges_expiry_check",
      sql`${table.expiresAt} > ${table.createdAt}`,
    ),
    check(
      "auth_challenges_consumed_check",
      sql`${table.consumedAt} is null or ${table.consumedAt} >= ${table.createdAt}`,
    ),
  ],
).enableRLS();

export const authSessions = pgTable(
  "auth_sessions",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    userId: uuid("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "restrict" }),
    rotationFamilyId: uuid("rotation_family_id").notNull(),
    activeTenantId: uuid("active_tenant_id").references(() => tenants.id, {
      onDelete: "restrict",
    }),
    tokenDigest: bytea("token_digest").notNull(),
    csrfSecretDigest: bytea("csrf_secret_digest").notNull(),
    authenticationMethod: text("authentication_method").notNull(),
    mfaSatisfiedAt: timestamp("mfa_satisfied_at", {
      withTimezone: true,
      mode: "date",
    }),
    lastSeenAt: timestamp("last_seen_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    idleExpiresAt: timestamp("idle_expires_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    absoluteExpiresAt: timestamp("absolute_expires_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    revokedAt: timestamp("revoked_at", { withTimezone: true, mode: "date" }),
    revokeReason: text("revoke_reason"),
    rotatedFromSessionId: uuid("rotated_from_session_id"),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    foreignKey({
      name: "auth_sessions_rotated_from_fk",
      columns: [table.rotatedFromSessionId],
      foreignColumns: [table.id],
    }).onDelete("set null"),
    unique("auth_sessions_token_digest_key").on(table.tokenDigest),
    unique("auth_sessions_rotated_from_key").on(table.rotatedFromSessionId),
    index("auth_sessions_user_active_idx")
      .on(table.userId, table.absoluteExpiresAt)
      .where(sql`${table.revokedAt} is null`),
    index("auth_sessions_user_family_idx").on(
      table.userId,
      table.rotationFamilyId,
      table.createdAt,
    ),
    check(
      "auth_sessions_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "auth_sessions_rotation_family_uuidv7_check",
      sql`(uuid_extract_version(${table.rotationFamilyId}) = 7) is true`,
    ),
    check(
      "auth_sessions_token_digest_check",
      sql`octet_length(${table.tokenDigest}) = 32`,
    ),
    check(
      "auth_sessions_csrf_digest_check",
      sql`octet_length(${table.csrfSecretDigest}) = 32`,
    ),
    check(
      "auth_sessions_method_check",
      sql`${table.authenticationMethod} in ('bootstrap_totp', 'passkey', 'totp', 'recovery_code', 'oidc', 'saml', 'ldap')`,
    ),
    check(
      "auth_sessions_expiry_check",
      sql`${table.lastSeenAt} >= ${table.createdAt}
        and ${table.idleExpiresAt} > ${table.createdAt}
        and ${table.absoluteExpiresAt} > ${table.createdAt}
        and ${table.idleExpiresAt} <= ${table.absoluteExpiresAt}`,
    ),
    check(
      "auth_sessions_live_expiry_precision_check",
      sql`${table.revokedAt} is not null
        or (date_trunc('milliseconds', ${table.idleExpiresAt}) = ${table.idleExpiresAt}
          and date_trunc('milliseconds', ${table.absoluteExpiresAt}) = ${table.absoluteExpiresAt})`,
    ),
    check(
      "auth_sessions_revoke_check",
      sql`(${table.revokedAt} is null and ${table.revokeReason} is null)
        or (${table.revokedAt} >= ${table.createdAt} and btrim(${table.revokeReason}) <> '')`,
    ),
  ],
).enableRLS();

export const authRateLimits = pgTable(
  "auth_rate_limits",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    scope: authRateLimitScope("scope").notNull(),
    keyDigest: bytea("key_digest").notNull(),
    attemptCount: integer("attempt_count").notNull().default(0),
    windowStartedAt: timestamp("window_started_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    windowExpiresAt: timestamp("window_expires_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    blockedUntil: timestamp("blocked_until", {
      withTimezone: true,
      mode: "date",
    }),
    updatedAt: timestamp("updated_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    unique("auth_rate_limits_scope_key_key").on(table.scope, table.keyDigest),
    index("auth_rate_limits_expiry_idx").on(table.windowExpiresAt),
    check(
      "auth_rate_limits_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "auth_rate_limits_digest_check",
      sql`octet_length(${table.keyDigest}) = 32`,
    ),
    check(
      "auth_rate_limits_attempt_count_check",
      sql`${table.attemptCount} >= 0`,
    ),
    check(
      "auth_rate_limits_window_check",
      sql`${table.windowExpiresAt} > ${table.windowStartedAt}`,
    ),
  ],
).enableRLS();
