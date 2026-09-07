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

import { tenantRoles, tenantSecurityGroups } from "./authorization.js";
import { authSessions, localBreakGlassCredentials } from "./authentication.js";
import { bytea } from "./binary.js";
import { authProviderKind } from "./enums.js";
import { tenantAuthProviderBindings } from "./identity-access.js";
import { tenantPlatformAuthProviderBindings } from "./identity-platform-bindings.js";
import { tenantMemberships, users } from "./identity.js";
import { tenants } from "./tenancy.js";

// Migration 0238 is the PostgreSQL adapter for policy administration using an
// exact recent local break-glass TOTP after tenant selection. It creates no
// implicit policy or factor and never substitutes for an existing tenant MFA state.

/**
 * Stable, tenant-qualified MFA identity facts. The WebAuthn user handle is
 * random protocol material and is never derived from an email or user UUID.
 */
export const tenantMfaSubjects = pgTable(
  "tenant_mfa_subjects",
  {
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    userId: uuid("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "restrict" }),
    webauthnUserHandle: bytea("webauthn_user_handle").notNull(),
    identityEpoch: bigint("identity_epoch", { mode: "bigint" })
      .notNull()
      .default(sql`1`),
    sessionInvalidationEpoch: bigint("session_invalidation_epoch", {
      mode: "bigint",
    })
      .notNull()
      .default(sql`1`),
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
    primaryKey({
      name: "tenant_mfa_subjects_pkey",
      columns: [table.tenantId, table.userId],
    }),
    unique("tenant_mfa_subjects_user_handle_key").on(table.webauthnUserHandle),
    foreignKey({
      name: "tenant_mfa_subjects_membership_fk",
      columns: [table.tenantId, table.userId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.userId],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "tenant_mfa_subjects_user_handle_check",
      sql`octet_length(${table.webauthnUserHandle}) = 32
        and encode(${table.webauthnUserHandle}, 'hex') <> repeat('00', 32)`,
    ),
    check(
      "tenant_mfa_subjects_epoch_check",
      sql`${table.identityEpoch} > 0
        and ${table.sessionInvalidationEpoch} > 0
        and ${table.version} > 0`,
    ),
    check(
      "tenant_mfa_subjects_updated_check",
      sql`${table.updatedAt} >= ${table.createdAt}`,
    ),
  ],
).enableRLS();

/** One tenant-owned TOTP factor. Secret bytes are an opaque keyring envelope. */
export const tenantTotpFactors = pgTable(
  "tenant_totp_factors",
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
    secretEnvelope: bytea("secret_envelope").notNull(),
    keyVersion: integer("key_version").notNull(),
    otpAlgorithm: text("otp_algorithm").notNull().default("SHA1"),
    digits: integer("digits").notNull().default(6),
    periodSeconds: integer("period_seconds").notNull().default(30),
    lastAcceptedCounter: bigint("last_accepted_counter", { mode: "bigint" })
      .notNull()
      .default(sql`-1`),
    recordVersion: bigint("record_version", { mode: "bigint" })
      .notNull()
      .default(sql`1`),
    securityRevision: bigint("security_revision", { mode: "bigint" })
      .notNull()
      .default(sql`1`),
    status: text("status").notNull().default("active"),
    confirmedAt: timestamp("confirmed_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    revokedAt: timestamp("revoked_at", { withTimezone: true, mode: "date" }),
    revokeReason: text("revoke_reason"),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    unique("tenant_totp_factors_tenant_id_key").on(table.tenantId, table.id),
    unique("tenant_totp_factors_tenant_user_id_key").on(
      table.tenantId,
      table.userId,
      table.id,
    ),
    index("tenant_totp_factors_user_active_idx")
      .on(table.tenantId, table.userId, table.id)
      .where(sql`${table.status} = 'active'`),
    foreignKey({
      name: "tenant_totp_factors_subject_fk",
      columns: [table.tenantId, table.userId],
      foreignColumns: [tenantMfaSubjects.tenantId, tenantMfaSubjects.userId],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "tenant_totp_factors_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "tenant_totp_factors_envelope_check",
      sql`octet_length(${table.secretEnvelope}) between 17 and 16384`,
    ),
    check(
      "tenant_totp_factors_key_version_check",
      sql`${table.keyVersion} between 1 and 32767`,
    ),
    check(
      "tenant_totp_factors_parameters_check",
      sql`${table.otpAlgorithm} in ('SHA1', 'SHA256', 'SHA512')
        and ${table.digits} in (6, 8)
        and ${table.periodSeconds} between 15 and 120`,
    ),
    check(
      "tenant_totp_factors_revision_check",
      sql`${table.lastAcceptedCounter} >= -1
        and ${table.recordVersion} > 0
        and ${table.securityRevision} > 0`,
    ),
    check(
      "tenant_totp_factors_lifecycle_check",
      sql`(${table.status} = 'active'
          and ${table.revokedAt} is null
          and ${table.revokeReason} is null)
        or (${table.status} = 'revoked'
          and ${table.revokedAt} is not null
          and ${table.revokeReason} is not null
          and ${table.revokedAt} >= ${table.confirmedAt}
          and btrim(${table.revokeReason}) <> ''
          and char_length(${table.revokeReason}) <= 500
          and ${table.revokeReason} !~ '[[:cntrl:]]')`,
    ),
    check(
      "tenant_totp_factors_timestamps_check",
      sql`${table.confirmedAt} >= ${table.createdAt}
        and ${table.updatedAt} >= ${table.createdAt}
        and (${table.revokedAt} is null or ${table.updatedAt} >= ${table.revokedAt})`,
    ),
  ],
).enableRLS();

export const tenantRecoveryCodeSets = pgTable(
  "tenant_recovery_code_sets",
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
    digestKeyVersion: integer("digest_key_version").notNull(),
    recordVersion: bigint("record_version", { mode: "bigint" })
      .notNull()
      .default(sql`1`),
    securityRevision: bigint("security_revision", { mode: "bigint" })
      .notNull()
      .default(sql`1`),
    completionRequestDigest: bytea("completion_request_digest").notNull(),
    resultSnapshot: jsonb("result_snapshot")
      .$type<Record<string, unknown>>()
      .notNull(),
    status: text("status").notNull().default("active"),
    generatedAt: timestamp("generated_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    revokedAt: timestamp("revoked_at", { withTimezone: true, mode: "date" }),
    revokeReason: text("revoke_reason"),
    updatedAt: timestamp("updated_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    unique("tenant_recovery_code_sets_tenant_id_key").on(
      table.tenantId,
      table.id,
    ),
    unique("tenant_recovery_code_sets_tenant_user_id_key").on(
      table.tenantId,
      table.userId,
      table.id,
    ),
    uniqueIndex("tenant_recovery_code_sets_user_active_key")
      .on(table.tenantId, table.userId)
      .where(sql`${table.status} = 'active'`),
    foreignKey({
      name: "tenant_recovery_code_sets_subject_fk",
      columns: [table.tenantId, table.userId],
      foreignColumns: [tenantMfaSubjects.tenantId, tenantMfaSubjects.userId],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "tenant_recovery_code_sets_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "tenant_recovery_code_sets_revision_check",
      sql`${table.digestKeyVersion} between 1 and 32767
        and ${table.recordVersion} > 0
        and ${table.securityRevision} > 0`,
    ),
    check(
      "tenant_recovery_code_sets_replay_check",
      sql`octet_length(${table.completionRequestDigest}) = 32
        and jsonb_typeof(${table.resultSnapshot}) = 'object'
        and pg_column_size(${table.resultSnapshot}) between 2 and 2097152`,
    ),
    check(
      "tenant_recovery_code_sets_lifecycle_check",
      sql`(${table.status} = 'active'
          and ${table.revokedAt} is null
          and ${table.revokeReason} is null)
        or (${table.status} = 'revoked'
          and ${table.revokedAt} is not null
          and ${table.revokeReason} is not null
          and ${table.revokedAt} >= ${table.generatedAt}
          and btrim(${table.revokeReason}) <> ''
          and char_length(${table.revokeReason}) <= 500
          and ${table.revokeReason} !~ '[[:cntrl:]]')`,
    ),
    check(
      "tenant_recovery_code_sets_updated_check",
      sql`${table.updatedAt} >= ${table.generatedAt}
        and (${table.revokedAt} is null or ${table.updatedAt} >= ${table.revokedAt})`,
    ),
  ],
).enableRLS();

export const tenantRecoveryCodes = pgTable(
  "tenant_recovery_codes",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    setId: uuid("set_id").notNull(),
    codeDigest: bytea("code_digest").notNull(),
    consumedAt: timestamp("consumed_at", {
      withTimezone: true,
      mode: "date",
    }),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    foreignKey({
      name: "tenant_recovery_codes_set_fk",
      columns: [table.tenantId, table.setId],
      foreignColumns: [
        tenantRecoveryCodeSets.tenantId,
        tenantRecoveryCodeSets.id,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    unique("tenant_recovery_codes_set_digest_key").on(
      table.tenantId,
      table.setId,
      table.codeDigest,
    ),
    index("tenant_recovery_codes_available_idx")
      .on(table.tenantId, table.setId, table.createdAt, table.id)
      .where(sql`${table.consumedAt} is null`),
    check(
      "tenant_recovery_codes_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "tenant_recovery_codes_digest_check",
      sql`octet_length(${table.codeDigest}) = 32`,
    ),
    check(
      "tenant_recovery_codes_consumed_check",
      sql`${table.consumedAt} is null or ${table.consumedAt} >= ${table.createdAt}`,
    ),
  ],
).enableRLS();

/** One-use post-primary capability. Only its browser receipt digest persists. */
export const tenantPostPrimaryContinuations = pgTable(
  "tenant_post_primary_continuations",
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
    receiptDigest: bytea("receipt_digest").notNull(),
    identityEpoch: bigint("identity_epoch", { mode: "bigint" }).notNull(),
    action: text("action").notNull(),
    audience: text("audience").notNull(),
    primaryKind: text("primary_kind").notNull(),
    localCredentialId: uuid("local_credential_id"),
    passkeyCredentialId: uuid("passkey_credential_id"),
    providerId: uuid("provider_id"),
    platformProviderId: uuid("platform_provider_id"),
    bindingId: uuid("binding_id"),
    providerKind: authProviderKind("provider_kind"),
    externalIdentityId: uuid("external_identity_id"),
    primaryRevision: bigint("primary_revision", { mode: "bigint" }).notNull(),
    sessionInvalidationEpoch: bigint("session_invalidation_epoch", {
      mode: "bigint",
    }).notNull(),
    state: text("state").notNull().default("pending"),
    version: bigint("version", { mode: "bigint" })
      .notNull()
      .default(sql`1`),
    createdAt: timestamp("created_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    expiresAt: timestamp("expires_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    consumedAt: timestamp("consumed_at", {
      withTimezone: true,
      mode: "date",
    }),
    revokedAt: timestamp("revoked_at", { withTimezone: true, mode: "date" }),
    revokeReason: text("revoke_reason"),
  },
  (table) => [
    unique("tenant_post_primary_continuations_tenant_id_key").on(
      table.tenantId,
      table.id,
    ),
    unique("tenant_post_primary_continuations_exact_user_key").on(
      table.tenantId,
      table.id,
      table.userId,
    ),
    unique("tenant_post_primary_continuations_exact_passkey_key").on(
      table.tenantId,
      table.id,
      table.userId,
      table.passkeyCredentialId,
    ),
    unique("tenant_post_primary_continuations_exact_provider_key").on(
      table.tenantId,
      table.id,
      table.userId,
      table.providerId,
      table.bindingId,
      table.providerKind,
      table.externalIdentityId,
    ),
    unique("tenant_post_primary_continuations_exact_platform_provider_key").on(
      table.tenantId,
      table.id,
      table.userId,
      table.platformProviderId,
      table.bindingId,
      table.externalIdentityId,
    ),
    unique("tenant_post_primary_continuations_receipt_key").on(
      table.receiptDigest,
    ),
    index("tenant_post_primary_continuations_subject_pending_idx")
      .on(table.tenantId, table.userId, table.expiresAt, table.id)
      .where(sql`${table.state} = 'pending'`),
    foreignKey({
      name: "tenant_post_primary_continuations_subject_fk",
      columns: [table.tenantId, table.userId],
      foreignColumns: [tenantMfaSubjects.tenantId, tenantMfaSubjects.userId],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_post_primary_continuations_local_credential_fk",
      columns: [table.localCredentialId],
      foreignColumns: [localBreakGlassCredentials.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_post_primary_continuations_passkey_fk",
      columns: [table.tenantId, table.userId, table.passkeyCredentialId],
      foreignColumns: [
        tenantWebauthnCredentials.tenantId,
        tenantWebauthnCredentials.userId,
        tenantWebauthnCredentials.id,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_post_primary_continuations_provider_binding_fk",
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
      name: "tenant_post_primary_continuations_platform_binding_fk",
      columns: [table.tenantId, table.bindingId, table.platformProviderId],
      foreignColumns: [
        tenantPlatformAuthProviderBindings.tenantId,
        tenantPlatformAuthProviderBindings.id,
        tenantPlatformAuthProviderBindings.platformProviderId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "tenant_post_primary_continuations_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "tenant_post_primary_continuations_receipt_check",
      sql`octet_length(${table.receiptDigest}) = 32`,
    ),
    check(
      "tenant_post_primary_continuations_version_check",
      sql`${table.identityEpoch} > 0
        and ${table.primaryRevision} > 0
        and ${table.sessionInvalidationEpoch} > 0
        and ${table.version} > 0`,
    ),
    check(
      "tenant_post_primary_continuations_text_check",
      sql`btrim(${table.action}) = ${table.action}
        and char_length(${table.action}) between 1 and 256
        and ${table.action} !~ '[[:cntrl:]]'
        and btrim(${table.audience}) = ${table.audience}
        and char_length(${table.audience}) between 1 and 256
        and ${table.audience} !~ '[[:cntrl:]]'`,
    ),
    check(
      "tenant_post_primary_continuations_primary_check",
      sql`(${table.primaryKind} = 'local_credential'
          and ${table.localCredentialId} is not null
          and ${table.passkeyCredentialId} is null
          and ${table.providerId} is null and ${table.platformProviderId} is null
          and ${table.bindingId} is null
          and ${table.providerKind} is null
          and ${table.externalIdentityId} is null)
        or (${table.primaryKind} = 'passkey'
          and ${table.localCredentialId} is null
          and ${table.passkeyCredentialId} is not null
          and ${table.providerId} is null and ${table.platformProviderId} is null
          and ${table.bindingId} is null
          and ${table.providerKind} is null
          and ${table.externalIdentityId} is null)
        or (${table.primaryKind} = 'tenant_provider'
          and ${table.localCredentialId} is null
          and ${table.passkeyCredentialId} is null
          and ${table.providerId} is not null and ${table.platformProviderId} is null
          and ${table.bindingId} is not null
          and ${table.providerKind} in ('oidc', 'saml', 'ldap')
          and ${table.externalIdentityId} is not null)
        or (${table.primaryKind} = 'tenant_platform_provider'
          and ${table.localCredentialId} is null
          and ${table.passkeyCredentialId} is null
          and ${table.providerId} is null and ${table.platformProviderId} is not null
          and ${table.bindingId} is not null
          and ${table.providerKind} = 'oidc'
          and ${table.externalIdentityId} is not null)`,
    ),
    check(
      "tenant_post_primary_continuations_lifecycle_check",
      sql`((${table.state} = 'pending'
          and ${table.version} >= 1
          and ${table.consumedAt} is null
          and ${table.revokedAt} is null
          and ${table.revokeReason} is null)
        or (${table.state} = 'consumed'
          and ${table.version} >= 2
          and ${table.consumedAt} is not null
          and ${table.revokedAt} is null
          and ${table.revokeReason} is null)
        or (${table.state} in ('revoked', 'expired')
          and ${table.version} >= 2
          and ${table.consumedAt} is null
          and ${table.revokedAt} is not null
          and ${table.revokeReason} is not null
          and btrim(${table.revokeReason}) <> ''
          and char_length(${table.revokeReason}) <= 500
          and ${table.revokeReason} !~ '[[:cntrl:]]'))`,
    ),
    check(
      "tenant_post_primary_continuations_timestamps_check",
      sql`${table.expiresAt} > ${table.createdAt}
        and (${table.consumedAt} is null
          or ${table.consumedAt} between ${table.createdAt} and ${table.expiresAt})
        and (${table.revokedAt} is null or ${table.revokedAt} >= ${table.createdAt})`,
    ),
    check(
      "tenant_post_primary_continuations_pending_expiry_precision_check",
      sql`${table.state} <> 'pending'
        or date_trunc('milliseconds', ${table.expiresAt}) = ${table.expiresAt}`,
    ),
  ],
).enableRLS();

export const tenantPostPrimaryContinuationEvidence = pgTable(
  "tenant_post_primary_continuation_evidence",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    continuationId: uuid("continuation_id").notNull(),
    localCredentialId: uuid("local_credential_id"),
    totpFactorId: uuid("totp_factor_id"),
    webauthnCredentialId: uuid("webauthn_credential_id"),
    recoveryCodeSetId: uuid("recovery_code_set_id"),
    level: text("level").notNull(),
    kind: text("kind").notNull(),
    providerId: uuid("provider_id"),
    bindingId: uuid("binding_id"),
    authenticatedAt: timestamp("authenticated_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    expiresAt: timestamp("expires_at", { withTimezone: true, mode: "date" }),
    factorRevision: bigint("factor_revision", { mode: "bigint" }),
    trustRuleRevision: bigint("trust_rule_revision", { mode: "bigint" }),
  },
  (table) => [
    unique("tenant_post_primary_continuation_evidence_key").on(
      table.tenantId,
      table.continuationId,
      table.id,
    ),
    foreignKey({
      name: "tenant_post_primary_continuation_evidence_continuation_fk",
      columns: [table.tenantId, table.continuationId],
      foreignColumns: [
        tenantPostPrimaryContinuations.tenantId,
        tenantPostPrimaryContinuations.id,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_post_primary_continuation_evidence_local_credential_fk",
      columns: [table.localCredentialId],
      foreignColumns: [localBreakGlassCredentials.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_post_primary_continuation_evidence_totp_fk",
      columns: [table.tenantId, table.totpFactorId],
      foreignColumns: [tenantTotpFactors.tenantId, tenantTotpFactors.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_post_primary_continuation_evidence_webauthn_fk",
      columns: [table.tenantId, table.webauthnCredentialId],
      foreignColumns: [
        tenantWebauthnCredentials.tenantId,
        tenantWebauthnCredentials.id,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_post_primary_continuation_evidence_recovery_fk",
      columns: [table.tenantId, table.recoveryCodeSetId],
      foreignColumns: [
        tenantRecoveryCodeSets.tenantId,
        tenantRecoveryCodeSets.id,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_post_primary_continuation_evidence_provider_binding_fk",
      columns: [table.tenantId, table.bindingId, table.providerId],
      foreignColumns: [
        tenantAuthProviderBindings.tenantId,
        tenantAuthProviderBindings.id,
        tenantAuthProviderBindings.providerId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "tenant_post_primary_continuation_evidence_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "tenant_post_primary_continuation_evidence_value_check",
      sql`${table.level} in ('primary', 'mfa', 'phishing_resistant')
        and ((${table.kind} = 'local_credential'
            and ${table.level} = 'primary'
            and ${table.localCredentialId} is not null
            and ${table.totpFactorId} is null
            and ${table.webauthnCredentialId} is null
            and ${table.recoveryCodeSetId} is null
            and ${table.providerId} is null
            and ${table.bindingId} is null
            and ${table.factorRevision} > 0
            and ${table.trustRuleRevision} is null)
          or (${table.kind} = 'totp'
            and ${table.level} = 'mfa'
            and ${table.localCredentialId} is null
            and ${table.totpFactorId} is not null
            and ${table.webauthnCredentialId} is null
            and ${table.recoveryCodeSetId} is null
            and ${table.providerId} is null
            and ${table.bindingId} is null
            and ${table.factorRevision} > 0
            and ${table.trustRuleRevision} is null)
          or (${table.kind} = 'webauthn'
            and ${table.localCredentialId} is null
            and ${table.totpFactorId} is null
            and ${table.webauthnCredentialId} is not null
            and ${table.recoveryCodeSetId} is null
            and ${table.providerId} is null
            and ${table.bindingId} is null
            and ${table.factorRevision} > 0
            and ${table.trustRuleRevision} is null)
          or (${table.kind} = 'recovery'
            and ${table.level} = 'mfa'
            and ${table.localCredentialId} is null
            and ${table.totpFactorId} is null
            and ${table.webauthnCredentialId} is null
            and ${table.recoveryCodeSetId} is not null
            and ${table.providerId} is null
            and ${table.bindingId} is null
            and ${table.factorRevision} > 0
            and ${table.trustRuleRevision} is null)
          or (${table.kind} = 'provider'
            and ${table.localCredentialId} is null
            and ${table.totpFactorId} is null
            and ${table.webauthnCredentialId} is null
            and ${table.recoveryCodeSetId} is null
            and ${table.providerId} is not null
            and ${table.bindingId} is not null
            and ${table.factorRevision} is null
            and ${table.trustRuleRevision} > 0))`,
    ),
    check(
      "tenant_post_primary_continuation_evidence_expiry_check",
      sql`${table.expiresAt} is null or ${table.expiresAt} > ${table.authenticatedAt}`,
    ),
  ],
).enableRLS();

export const tenantPostPrimaryContinuationPolicyPins = pgTable(
  "tenant_post_primary_continuation_policy_pins",
  {
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    continuationId: uuid("continuation_id").notNull(),
    policyId: uuid("policy_id").notNull(),
    policyRevision: bigint("policy_revision", { mode: "bigint" }).notNull(),
  },
  (table) => [
    primaryKey({
      name: "tenant_post_primary_continuation_policy_pins_pkey",
      columns: [table.tenantId, table.continuationId, table.policyId],
    }),
    foreignKey({
      name: "tenant_post_primary_continuation_policy_pins_continuation_fk",
      columns: [table.tenantId, table.continuationId],
      foreignColumns: [
        tenantPostPrimaryContinuations.tenantId,
        tenantPostPrimaryContinuations.id,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "tenant_post_primary_continuation_policy_pins_revision_check",
      sql`${table.policyRevision} > 0`,
    ),
  ],
).enableRLS();

/**
 * A normalized authorization snapshot pinned by a one-time ceremony. Primary
 * discoverable authentication deliberately has no user or live anchor yet.
 */
export const tenantMfaAuthorityAnchors = pgTable(
  "tenant_mfa_authority_anchors",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    userId: uuid("user_id").references(() => users.id, {
      onDelete: "restrict",
    }),
    flow: text("flow").notNull(),
    identityEpoch: bigint("identity_epoch", { mode: "bigint" }),
    sessionId: uuid("session_id").references(() => authSessions.id, {
      onDelete: "restrict",
    }),
    sessionFamilyId: uuid("session_family_id"),
    continuationId: uuid("continuation_id"),
    anchorVersion: bigint("anchor_version", { mode: "bigint" }),
    anchorExpiresAt: timestamp("anchor_expires_at", {
      withTimezone: true,
      mode: "date",
    }),
    recoveryRestricted: boolean("recovery_restricted").notNull().default(false),
    action: text("action").notNull(),
    audience: text("audience").notNull(),
    requirementLevel: text("requirement_level").notNull(),
    localRequired: boolean("local_required").notNull().default(false),
    freshnessNanoseconds: bigint("freshness_nanoseconds", { mode: "bigint" })
      .notNull()
      .default(sql`0`),
    enrollmentDeadline: timestamp("enrollment_deadline", {
      withTimezone: true,
      mode: "date",
    }),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    unique("tenant_mfa_authority_anchors_tenant_id_key").on(
      table.tenantId,
      table.id,
    ),
    index("tenant_mfa_authority_anchors_session_idx").on(
      table.tenantId,
      table.sessionId,
      table.id,
    ),
    index("tenant_mfa_authority_anchors_continuation_idx").on(
      table.tenantId,
      table.continuationId,
      table.id,
    ),
    foreignKey({
      name: "tenant_mfa_authority_anchors_subject_fk",
      columns: [table.tenantId, table.userId],
      foreignColumns: [tenantMfaSubjects.tenantId, tenantMfaSubjects.userId],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_mfa_authority_anchors_continuation_fk",
      columns: [table.tenantId, table.continuationId],
      foreignColumns: [
        tenantPostPrimaryContinuations.tenantId,
        tenantPostPrimaryContinuations.id,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "tenant_mfa_authority_anchors_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "tenant_mfa_authority_anchors_user_epoch_check",
      sql`(${table.userId} is null and ${table.identityEpoch} is null)
        or (${table.userId} is not null and ${table.identityEpoch} > 0)`,
    ),
    check(
      "tenant_mfa_authority_anchors_flow_check",
      sql`(${table.flow} = 'primary'
          and ${table.sessionId} is null
          and ${table.sessionFamilyId} is null
          and ${table.continuationId} is null
          and ${table.anchorVersion} is null
          and ${table.anchorExpiresAt} is null
          and not ${table.recoveryRestricted})
        or (${table.flow} = 'continuation'
          and ${table.userId} is not null
          and ${table.sessionId} is null
          and ${table.sessionFamilyId} is null
          and ${table.continuationId} is not null
          and ${table.anchorVersion} > 0
          and ${table.anchorExpiresAt} > ${table.createdAt}
          and not ${table.recoveryRestricted})
        or (${table.flow} = 'session'
          and ${table.userId} is not null
          and ${table.sessionId} is not null
          and ${table.sessionFamilyId} is not null
          and ${table.continuationId} is null
          and ${table.anchorVersion} > 0
          and ${table.anchorExpiresAt} > ${table.createdAt})`,
    ),
    check(
      "tenant_mfa_authority_anchors_action_check",
      sql`btrim(${table.action}) = ${table.action}
        and char_length(${table.action}) between 1 and 256
        and ${table.action} !~ '[[:cntrl:]]'`,
    ),
    check(
      "tenant_mfa_authority_anchors_audience_check",
      sql`btrim(${table.audience}) = ${table.audience}
        and char_length(${table.audience}) between 1 and 256
        and ${table.audience} !~ '[[:cntrl:]]'`,
    ),
    check(
      "tenant_mfa_authority_anchors_requirement_check",
      sql`${table.requirementLevel} in ('primary', 'mfa', 'phishing_resistant')
        and ${table.freshnessNanoseconds} between 0 and 31536000000000000
        and (${table.enrollmentDeadline} is null
          or ${table.enrollmentDeadline} > ${table.createdAt})`,
    ),
  ],
).enableRLS();

export const tenantMfaAuthorityPolicyPins = pgTable(
  "tenant_mfa_authority_policy_pins",
  {
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    anchorId: uuid("anchor_id").notNull(),
    policyId: uuid("policy_id").notNull(),
    policyRevision: bigint("policy_revision", { mode: "bigint" }).notNull(),
    scope: text("scope").notNull(),
    roleId: uuid("role_id"),
    securityGroupId: uuid("security_group_id"),
    action: text("action"),
  },
  (table) => [
    primaryKey({
      name: "tenant_mfa_authority_policy_pins_pkey",
      columns: [table.tenantId, table.anchorId, table.scope, table.policyId],
    }),
    foreignKey({
      name: "tenant_mfa_authority_policy_pins_anchor_fk",
      columns: [table.tenantId, table.anchorId],
      foreignColumns: [
        tenantMfaAuthorityAnchors.tenantId,
        tenantMfaAuthorityAnchors.id,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_mfa_authority_policy_pins_role_fk",
      columns: [table.tenantId, table.roleId],
      foreignColumns: [tenantRoles.tenantId, tenantRoles.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_mfa_authority_policy_pins_security_group_fk",
      columns: [table.tenantId, table.securityGroupId],
      foreignColumns: [tenantSecurityGroups.tenantId, tenantSecurityGroups.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "tenant_mfa_authority_policy_pins_revision_check",
      sql`${table.policyRevision} > 0`,
    ),
    check(
      "tenant_mfa_authority_policy_pins_scope_check",
      sql`(${table.scope} in ('platform_floor', 'tenant_baseline')
          and ${table.roleId} is null
          and ${table.securityGroupId} is null
          and ${table.action} is null)
        or (${table.scope} = 'role'
          and ${table.roleId} is not null
          and ${table.securityGroupId} is null
          and ${table.action} is null)
        or (${table.scope} = 'security_group'
          and ${table.roleId} is null
          and ${table.securityGroupId} is not null
          and ${table.action} is null)
        or (${table.scope} = 'action'
          and ${table.roleId} is null
          and ${table.securityGroupId} is null
          and ${table.action} is not null
          and btrim(${table.action}) = ${table.action}
          and char_length(${table.action}) between 1 and 256
          and ${table.action} !~ '[[:cntrl:]]')`,
    ),
  ],
).enableRLS();

export const tenantMfaAuthorityEvidence = pgTable(
  "tenant_mfa_authority_evidence",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    anchorId: uuid("anchor_id").notNull(),
    localCredentialId: uuid("local_credential_id"),
    totpFactorId: uuid("totp_factor_id"),
    webauthnCredentialId: uuid("webauthn_credential_id"),
    recoveryCodeSetId: uuid("recovery_code_set_id"),
    level: text("level").notNull(),
    kind: text("kind").notNull(),
    providerId: uuid("provider_id"),
    bindingId: uuid("binding_id"),
    authenticatedAt: timestamp("authenticated_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    expiresAt: timestamp("expires_at", { withTimezone: true, mode: "date" }),
    factorRevision: bigint("factor_revision", { mode: "bigint" }),
    trustRuleRevision: bigint("trust_rule_revision", { mode: "bigint" }),
  },
  (table) => [
    unique("tenant_mfa_authority_evidence_anchor_id_key").on(
      table.tenantId,
      table.anchorId,
      table.id,
    ),
    index("tenant_mfa_authority_evidence_anchor_idx").on(
      table.tenantId,
      table.anchorId,
      table.authenticatedAt,
      table.id,
    ),
    foreignKey({
      name: "tenant_mfa_authority_evidence_anchor_fk",
      columns: [table.tenantId, table.anchorId],
      foreignColumns: [
        tenantMfaAuthorityAnchors.tenantId,
        tenantMfaAuthorityAnchors.id,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_mfa_authority_evidence_local_credential_fk",
      columns: [table.localCredentialId],
      foreignColumns: [localBreakGlassCredentials.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_mfa_authority_evidence_totp_fk",
      columns: [table.tenantId, table.totpFactorId],
      foreignColumns: [tenantTotpFactors.tenantId, tenantTotpFactors.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_mfa_authority_evidence_webauthn_fk",
      columns: [table.tenantId, table.webauthnCredentialId],
      foreignColumns: [
        tenantWebauthnCredentials.tenantId,
        tenantWebauthnCredentials.id,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_mfa_authority_evidence_recovery_fk",
      columns: [table.tenantId, table.recoveryCodeSetId],
      foreignColumns: [
        tenantRecoveryCodeSets.tenantId,
        tenantRecoveryCodeSets.id,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_mfa_authority_evidence_provider_binding_fk",
      columns: [table.tenantId, table.bindingId, table.providerId],
      foreignColumns: [
        tenantAuthProviderBindings.tenantId,
        tenantAuthProviderBindings.id,
        tenantAuthProviderBindings.providerId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "tenant_mfa_authority_evidence_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "tenant_mfa_authority_evidence_level_kind_check",
      sql`${table.level} in ('primary', 'mfa', 'phishing_resistant')
        and ((${table.kind} = 'local_credential'
          and ${table.level} = 'primary'
          and ${table.localCredentialId} is not null
          and ${table.totpFactorId} is null
          and ${table.webauthnCredentialId} is null
          and ${table.recoveryCodeSetId} is null
          and ${table.providerId} is null
          and ${table.bindingId} is null
          and ${table.factorRevision} > 0
          and ${table.trustRuleRevision} is null)
        or (${table.kind} = 'totp'
          and ${table.level} = 'mfa'
          and ${table.localCredentialId} is null
          and ${table.totpFactorId} is not null
          and ${table.webauthnCredentialId} is null
          and ${table.recoveryCodeSetId} is null
          and ${table.providerId} is null
          and ${table.bindingId} is null
          and ${table.factorRevision} > 0
          and ${table.trustRuleRevision} is null)
        or (${table.kind} = 'webauthn'
          and ${table.localCredentialId} is null
          and ${table.totpFactorId} is null
          and ${table.webauthnCredentialId} is not null
          and ${table.recoveryCodeSetId} is null
          and ${table.providerId} is null
          and ${table.bindingId} is null
          and ${table.factorRevision} > 0
          and ${table.trustRuleRevision} is null)
        or (${table.kind} = 'recovery'
          and ${table.level} = 'mfa'
          and ${table.localCredentialId} is null
          and ${table.totpFactorId} is null
          and ${table.webauthnCredentialId} is null
          and ${table.recoveryCodeSetId} is not null
          and ${table.providerId} is null
          and ${table.bindingId} is null
          and ${table.factorRevision} > 0
          and ${table.trustRuleRevision} is null)
        or (${table.kind} = 'provider'
          and ${table.localCredentialId} is null
          and ${table.totpFactorId} is null
          and ${table.webauthnCredentialId} is null
          and ${table.recoveryCodeSetId} is null
          and ${table.providerId} is not null
          and ${table.bindingId} is not null
          and ${table.factorRevision} is null
          and ${table.trustRuleRevision} > 0))`,
    ),
    check(
      "tenant_mfa_authority_evidence_expiry_check",
      sql`${table.expiresAt} is null or ${table.expiresAt} > ${table.authenticatedAt}`,
    ),
  ],
).enableRLS();

export const tenantMfaStepUpChallenges = pgTable(
  "tenant_mfa_step_up_challenges",
  {
    id: bytea("id").primaryKey(),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    authorityAnchorId: uuid("authority_anchor_id").notNull(),
    browserDigest: bytea("browser_digest").notNull(),
    allowedFactors: text("allowed_factors").array().notNull(),
    claimedFactorKind: text("claimed_factor_kind"),
    state: text("state").notNull().default("pending"),
    failureReason: text("failure_reason"),
    completionRequestDigest: bytea("completion_request_digest"),
    resultSnapshot: jsonb("result_snapshot").$type<Record<string, unknown>>(),
    version: bigint("version", { mode: "bigint" })
      .notNull()
      .default(sql`1`),
    createdAt: timestamp("created_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    expiresAt: timestamp("expires_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    claimedAt: timestamp("claimed_at", { withTimezone: true, mode: "date" }),
    completedAt: timestamp("completed_at", {
      withTimezone: true,
      mode: "date",
    }),
    failedAt: timestamp("failed_at", { withTimezone: true, mode: "date" }),
  },
  (table) => [
    unique("tenant_mfa_step_up_challenges_tenant_id_key").on(
      table.tenantId,
      table.id,
    ),
    index("tenant_mfa_step_up_challenges_expiry_idx")
      .on(table.expiresAt, table.tenantId, table.id)
      .where(sql`${table.state} in ('pending', 'claimed')`),
    foreignKey({
      name: "tenant_mfa_step_up_challenges_anchor_fk",
      columns: [table.tenantId, table.authorityAnchorId],
      foreignColumns: [
        tenantMfaAuthorityAnchors.tenantId,
        tenantMfaAuthorityAnchors.id,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "tenant_mfa_step_up_challenges_id_check",
      sql`octet_length(${table.id}) = 32`,
    ),
    check(
      "tenant_mfa_step_up_challenges_browser_check",
      sql`octet_length(${table.browserDigest}) = 32`,
    ),
    check(
      "tenant_mfa_step_up_challenges_factors_check",
      sql`${table.allowedFactors} = array['totp']::text[]
        or ${table.allowedFactors} = array['recovery_code']::text[]
        or ${table.allowedFactors} = array['totp', 'recovery_code']::text[]`,
    ),
    check(
      "tenant_mfa_step_up_challenges_claimed_factor_check",
      sql`${table.claimedFactorKind} is null
        or (${table.claimedFactorKind} in ('totp', 'recovery_code')
          and ${table.claimedFactorKind} = any(${table.allowedFactors}))`,
    ),
    check(
      "tenant_mfa_step_up_challenges_claimed_factor_live_check",
      sql`${table.state} <> 'claimed' or ${table.claimedFactorKind} is not null`,
    ),
    check(
      "tenant_mfa_step_up_challenges_version_check",
      sql`${table.version} > 0`,
    ),
    check(
      "tenant_mfa_step_up_challenges_replay_check",
      sql`(${table.completionRequestDigest} is null and ${table.resultSnapshot} is null)
        or (octet_length(${table.completionRequestDigest}) = 32
          and jsonb_typeof(${table.resultSnapshot}) = 'object'
          and pg_column_size(${table.resultSnapshot}) between 2 and 2097152)`,
    ),
    check(
      "tenant_mfa_step_up_challenges_lifecycle_check",
      sql`((${table.state} = 'pending'
          and ${table.version} = 1
          and ${table.claimedFactorKind} is null
          and ${table.claimedAt} is null
          and ${table.completedAt} is null
          and ${table.failedAt} is null
          and ${table.failureReason} is null
          and ${table.completionRequestDigest} is null
          and ${table.resultSnapshot} is null)
        or (${table.state} = 'claimed'
          and ${table.version} >= 2
          and ${table.claimedAt} is not null
          and ${table.completedAt} is null
          and ${table.failedAt} is null
          and ${table.failureReason} is null
          and ${table.completionRequestDigest} is null
          and ${table.resultSnapshot} is null)
        or (${table.state} = 'completed'
          and ${table.version} >= 3
          and ${table.claimedAt} is not null
          and ${table.completedAt} is not null
          and ${table.failedAt} is null
          and ${table.failureReason} is null
          and ${table.completionRequestDigest} is not null
          and ${table.resultSnapshot} is not null)
        or (${table.state} in ('failed', 'expired')
          and ${table.version} >= 3
          and ${table.claimedAt} is not null
          and ${table.completedAt} is null
          and ${table.failedAt} is not null
          and ${table.failureReason} in (
            'factor_rejected', 'expired', 'factor_selector_unavailable'
          )
          and ${table.completionRequestDigest} is null
          and ${table.resultSnapshot} is null))`,
    ),
    check(
      "tenant_mfa_step_up_challenges_timestamps_check",
      sql`${table.expiresAt} > ${table.createdAt}
        and (${table.claimedAt} is null or ${table.claimedAt} >= ${table.createdAt})
        and (${table.completedAt} is null or ${table.completedAt} >= ${table.claimedAt})
        and (${table.failedAt} is null or ${table.failedAt} >= ${table.claimedAt})`,
    ),
  ],
).enableRLS();

export const tenantTotpEnrollments = pgTable(
  "tenant_totp_enrollments",
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
    authorityAnchorId: uuid("authority_anchor_id").notNull(),
    factorId: uuid("factor_id").notNull(),
    browserDigest: bytea("browser_digest").notNull(),
    secretEnvelope: bytea("secret_envelope").notNull(),
    keyVersion: integer("key_version").notNull(),
    state: text("state").notNull().default("pending"),
    completionRequestDigest: bytea("completion_request_digest"),
    resultSnapshot: jsonb("result_snapshot").$type<Record<string, unknown>>(),
    version: bigint("version", { mode: "bigint" })
      .notNull()
      .default(sql`1`),
    createdAt: timestamp("created_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    expiresAt: timestamp("expires_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    claimedAt: timestamp("claimed_at", { withTimezone: true, mode: "date" }),
    completedAt: timestamp("completed_at", {
      withTimezone: true,
      mode: "date",
    }),
    failedAt: timestamp("failed_at", { withTimezone: true, mode: "date" }),
  },
  (table) => [
    unique("tenant_totp_enrollments_tenant_id_key").on(
      table.tenantId,
      table.id,
    ),
    unique("tenant_totp_enrollments_factor_key").on(
      table.tenantId,
      table.factorId,
    ),
    uniqueIndex("tenant_totp_enrollments_user_pending_key")
      .on(table.tenantId, table.userId)
      .where(sql`${table.state} in ('pending', 'claimed')`),
    index("tenant_totp_enrollments_expiry_idx")
      .on(table.expiresAt, table.tenantId, table.id)
      .where(sql`${table.state} in ('pending', 'claimed')`),
    foreignKey({
      name: "tenant_totp_enrollments_subject_fk",
      columns: [table.tenantId, table.userId],
      foreignColumns: [tenantMfaSubjects.tenantId, tenantMfaSubjects.userId],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_totp_enrollments_anchor_fk",
      columns: [table.tenantId, table.authorityAnchorId],
      foreignColumns: [
        tenantMfaAuthorityAnchors.tenantId,
        tenantMfaAuthorityAnchors.id,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "tenant_totp_enrollments_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "tenant_totp_enrollments_factor_uuidv7_check",
      sql`(uuid_extract_version(${table.factorId}) = 7) is true`,
    ),
    check(
      "tenant_totp_enrollments_material_check",
      sql`octet_length(${table.browserDigest}) = 32
        and octet_length(${table.secretEnvelope}) between 17 and 16384
        and ${table.keyVersion} between 1 and 32767`,
    ),
    check(
      "tenant_totp_enrollments_replay_check",
      sql`(${table.completionRequestDigest} is null and ${table.resultSnapshot} is null)
        or (octet_length(${table.completionRequestDigest}) = 32
          and jsonb_typeof(${table.resultSnapshot}) = 'object'
          and pg_column_size(${table.resultSnapshot}) between 2 and 2097152)`,
    ),
    check(
      "tenant_totp_enrollments_lifecycle_check",
      sql`((${table.state} = 'pending'
          and ${table.version} = 1
          and ${table.claimedAt} is null
          and ${table.completedAt} is null
          and ${table.failedAt} is null
          and ${table.completionRequestDigest} is null
          and ${table.resultSnapshot} is null)
        or (${table.state} = 'claimed'
          and ${table.version} >= 2
          and ${table.claimedAt} is not null
          and ${table.completedAt} is null
          and ${table.failedAt} is null
          and ${table.completionRequestDigest} is null
          and ${table.resultSnapshot} is null)
        or (${table.state} = 'completed'
          and ${table.version} >= 3
          and ${table.claimedAt} is not null
          and ${table.completedAt} is not null
          and ${table.failedAt} is null
          and ${table.completionRequestDigest} is not null
          and ${table.resultSnapshot} is not null)
        or (${table.state} = 'failed'
          and ${table.version} >= 3
          and ${table.claimedAt} is not null
          and ${table.completedAt} is null
          and ${table.failedAt} is not null
          and ${table.completionRequestDigest} is null
          and ${table.resultSnapshot} is null))`,
    ),
    check(
      "tenant_totp_enrollments_timestamps_check",
      sql`${table.expiresAt} > ${table.createdAt}
        and (${table.claimedAt} is null or ${table.claimedAt} >= ${table.createdAt})
        and (${table.completedAt} is null or ${table.completedAt} >= ${table.claimedAt})
        and (${table.failedAt} is null or ${table.failedAt} >= ${table.claimedAt})`,
    ),
  ],
).enableRLS();

export const tenantWebauthnCeremonies = pgTable(
  "tenant_webauthn_ceremonies",
  {
    id: bytea("id").primaryKey(),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    authorityAnchorId: uuid("authority_anchor_id").notNull(),
    challengeDigest: bytea("challenge_digest").notNull(),
    browserDigest: bytea("browser_digest").notNull(),
    rpId: text("rp_id").notNull(),
    rpRevision: bigint("rp_revision", { mode: "bigint" }).notNull(),
    allowedOrigins: text("allowed_origins").array().notNull(),
    purpose: text("purpose").notNull(),
    mode: text("mode"),
    userHandleDigest: bytea("user_handle_digest"),
    requireUserPresence: boolean("require_user_presence").notNull(),
    userVerification: text("user_verification").notNull(),
    residentKey: text("resident_key").notNull(),
    attestation: text("attestation").notNull(),
    metadataRevision: bigint("metadata_revision", { mode: "bigint" })
      .notNull()
      .default(sql`0`),
    state: text("state").notNull().default("pending"),
    failureReason: text("failure_reason"),
    completionRequestDigest: bytea("completion_request_digest"),
    resultSnapshot: jsonb("result_snapshot").$type<Record<string, unknown>>(),
    version: bigint("version", { mode: "bigint" })
      .notNull()
      .default(sql`1`),
    createdAt: timestamp("created_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    expiresAt: timestamp("expires_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    claimedAt: timestamp("claimed_at", { withTimezone: true, mode: "date" }),
    completedAt: timestamp("completed_at", {
      withTimezone: true,
      mode: "date",
    }),
    failedAt: timestamp("failed_at", { withTimezone: true, mode: "date" }),
  },
  (table) => [
    unique("tenant_webauthn_ceremonies_tenant_id_key").on(
      table.tenantId,
      table.id,
    ),
    index("tenant_webauthn_ceremonies_expiry_idx")
      .on(table.expiresAt, table.tenantId, table.id)
      .where(sql`${table.state} in ('pending', 'claimed')`),
    foreignKey({
      name: "tenant_webauthn_ceremonies_anchor_fk",
      columns: [table.tenantId, table.authorityAnchorId],
      foreignColumns: [
        tenantMfaAuthorityAnchors.tenantId,
        tenantMfaAuthorityAnchors.id,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "tenant_webauthn_ceremonies_artifact_check",
      sql`octet_length(${table.id}) = 32
        and octet_length(${table.challengeDigest}) = 32
        and octet_length(${table.browserDigest}) = 32
        and (${table.userHandleDigest} is null
          or octet_length(${table.userHandleDigest}) = 32)`,
    ),
    check(
      "tenant_webauthn_ceremonies_rp_check",
      sql`btrim(${table.rpId}) = ${table.rpId}
        and char_length(${table.rpId}) between 1 and 253
        and ${table.rpRevision} > 0
        and cardinality(${table.allowedOrigins}) between 1 and 16`,
    ),
    check(
      "tenant_webauthn_ceremonies_purpose_check",
      sql`(${table.purpose} = 'registration'
          and ${table.mode} is null
          and ${table.userHandleDigest} is not null)
        or (${table.purpose} in ('primary_authentication', 'continuation_authentication', 'step_up_authentication')
          and ${table.mode} in ('known_user', 'discoverable')
          and (${table.mode} = 'discoverable' or ${table.userHandleDigest} is not null))`,
    ),
    check(
      "tenant_webauthn_ceremonies_policy_check",
      sql`${table.requireUserPresence}
        and ${table.userVerification} in ('preferred', 'required')
        and ${table.residentKey} in ('preferred', 'required')
        and ${table.attestation} in ('none', 'direct', 'enterprise')
        and ((${table.attestation} = 'none' and ${table.metadataRevision} = 0)
          or (${table.attestation} <> 'none' and ${table.metadataRevision} > 0))`,
    ),
    check(
      "tenant_webauthn_ceremonies_replay_check",
      sql`(${table.completionRequestDigest} is null and ${table.resultSnapshot} is null)
        or (octet_length(${table.completionRequestDigest}) = 32
          and jsonb_typeof(${table.resultSnapshot}) = 'object'
          and pg_column_size(${table.resultSnapshot}) between 2 and 2097152)`,
    ),
    check(
      "tenant_webauthn_ceremonies_lifecycle_check",
      sql`((${table.state} = 'pending'
          and ${table.version} = 1
          and ${table.claimedAt} is null
          and ${table.completedAt} is null
          and ${table.failedAt} is null
          and ${table.failureReason} is null
          and ${table.completionRequestDigest} is null
          and ${table.resultSnapshot} is null)
        or (${table.state} = 'claimed'
          and ${table.version} >= 2
          and ${table.claimedAt} is not null
          and ${table.completedAt} is null
          and ${table.failedAt} is null
          and ${table.failureReason} is null
          and ${table.completionRequestDigest} is null
          and ${table.resultSnapshot} is null)
        or (${table.state} = 'completed'
          and ${table.version} >= 3
          and ${table.claimedAt} is not null
          and ${table.completedAt} is not null
          and ${table.failedAt} is null
          and ${table.failureReason} is null
          and ${table.completionRequestDigest} is not null
          and ${table.resultSnapshot} is not null)
        or (${table.state} in ('failed', 'expired')
          and ${table.version} >= 3
          and ${table.claimedAt} is not null
          and ${table.completedAt} is null
          and ${table.failedAt} is not null
          and ${table.failureReason} in ('expired', 'malformed_response', 'verification_rejected', 'credential_rejected')
          and ${table.completionRequestDigest} is null
          and ${table.resultSnapshot} is null))`,
    ),
    check(
      "tenant_webauthn_ceremonies_timestamps_check",
      sql`${table.version} > 0
        and ${table.expiresAt} > ${table.createdAt}
        and (${table.claimedAt} is null or ${table.claimedAt} >= ${table.createdAt})
        and (${table.completedAt} is null or ${table.completedAt} >= ${table.claimedAt})
        and (${table.failedAt} is null or ${table.failedAt} >= ${table.claimedAt})`,
    ),
  ],
).enableRLS();

/** Ordered, bounded allow/exclude list; raw IDs never enter logs or audit. */
export const tenantWebauthnCeremonyCredentials = pgTable(
  "tenant_webauthn_ceremony_credentials",
  {
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    ceremonyId: bytea("ceremony_id").notNull(),
    ordinal: integer("ordinal").notNull(),
    credentialId: bytea("credential_id").notNull(),
  },
  (table) => [
    primaryKey({
      name: "tenant_webauthn_ceremony_credentials_pkey",
      columns: [table.tenantId, table.ceremonyId, table.ordinal],
    }),
    unique("tenant_webauthn_ceremony_credentials_id_key").on(
      table.tenantId,
      table.ceremonyId,
      table.credentialId,
    ),
    foreignKey({
      name: "tenant_webauthn_ceremony_credentials_ceremony_fk",
      columns: [table.tenantId, table.ceremonyId],
      foreignColumns: [
        tenantWebauthnCeremonies.tenantId,
        tenantWebauthnCeremonies.id,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "tenant_webauthn_ceremony_credentials_value_check",
      sql`${table.ordinal} between 0 and 127
        and octet_length(${table.credentialId}) between 1 and 4096`,
    ),
  ],
).enableRLS();

export const tenantWebauthnCredentials = pgTable(
  "tenant_webauthn_credentials",
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
    credentialId: bytea("credential_id").notNull(),
    publicKey: bytea("public_key").notNull(),
    displayName: text("display_name").notNull(),
    userHandleDigest: bytea("user_handle_digest").notNull(),
    rpId: text("rp_id").notNull(),
    rpRevision: bigint("rp_revision", { mode: "bigint" }).notNull(),
    signCount: bigint("sign_count", { mode: "bigint" })
      .notNull()
      .default(sql`0`),
    discoverable: boolean("discoverable").notNull(),
    userVerification: boolean("user_verification").notNull(),
    backupEligible: boolean("backup_eligible").notNull(),
    backedUp: boolean("backed_up").notNull(),
    aaguid: bytea("aaguid").notNull(),
    attestationFormat: text("attestation_format").notNull(),
    attestationType: text("attestation_type").notNull(),
    attestationTrusted: boolean("attestation_trusted").notNull(),
    metadataRevision: bigint("metadata_revision", { mode: "bigint" })
      .notNull()
      .default(sql`0`),
    status: text("status").notNull().default("active"),
    version: bigint("version", { mode: "bigint" })
      .notNull()
      .default(sql`1`),
    securityRevision: bigint("security_revision", { mode: "bigint" })
      .notNull()
      .default(sql`1`),
    createdAt: timestamp("created_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    lastUsedAt: timestamp("last_used_at", {
      withTimezone: true,
      mode: "date",
    }),
    revokedAt: timestamp("revoked_at", { withTimezone: true, mode: "date" }),
    revokeReason: text("revoke_reason"),
    updatedAt: timestamp("updated_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
  },
  (table) => [
    unique("tenant_webauthn_credentials_tenant_id_key").on(
      table.tenantId,
      table.id,
    ),
    unique("tenant_webauthn_credentials_tenant_user_id_key").on(
      table.tenantId,
      table.userId,
      table.id,
    ),
    unique("tenant_webauthn_credentials_credential_id_key").on(
      table.credentialId,
    ),
    index("tenant_webauthn_credentials_user_active_idx")
      .on(table.tenantId, table.userId, table.id)
      .where(sql`${table.status} = 'active'`),
    foreignKey({
      name: "tenant_webauthn_credentials_subject_fk",
      columns: [table.tenantId, table.userId],
      foreignColumns: [tenantMfaSubjects.tenantId, tenantMfaSubjects.userId],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "tenant_webauthn_credentials_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "tenant_webauthn_credentials_material_check",
      sql`octet_length(${table.credentialId}) between 1 and 4096
        and octet_length(${table.publicKey}) between 32 and 65536
        and octet_length(${table.userHandleDigest}) = 32
        and octet_length(${table.aaguid}) = 16`,
    ),
    check(
      "tenant_webauthn_credentials_display_name_check",
      sql`btrim(${table.displayName}) = ${table.displayName}
        and char_length(${table.displayName}) between 1 and 120
        and ${table.displayName} !~ '[[:cntrl:]]'`,
    ),
    check(
      "tenant_webauthn_credentials_rp_counter_check",
      sql`btrim(${table.rpId}) = ${table.rpId}
        and char_length(${table.rpId}) between 1 and 253
        and ${table.rpRevision} > 0
        and ${table.signCount} between 0 and 4294967295`,
    ),
    check(
      "tenant_webauthn_credentials_backup_check",
      sql`not ${table.backedUp} or ${table.backupEligible}`,
    ),
    check(
      "tenant_webauthn_credentials_attestation_check",
      sql`btrim(${table.attestationFormat}) = ${table.attestationFormat}
        and char_length(${table.attestationFormat}) between 1 and 64
        and ${table.attestationFormat} !~ '[[:cntrl:]]'
        and ${table.attestationType} in ('none', 'self', 'basic', 'enterprise')
        and ${table.metadataRevision} >= 0`,
    ),
    check(
      "tenant_webauthn_credentials_lifecycle_check",
      sql`(${table.status} = 'active'
          and ${table.revokedAt} is null
          and ${table.revokeReason} is null)
        or (${table.status} in ('revoked', 'clone_suspected')
          and ${table.revokedAt} is not null
          and ${table.revokeReason} is not null
          and ${table.revokedAt} >= ${table.createdAt}
          and btrim(${table.revokeReason}) <> ''
          and char_length(${table.revokeReason}) <= 500
          and ${table.revokeReason} !~ '[[:cntrl:]]')`,
    ),
    check(
      "tenant_webauthn_credentials_timestamps_check",
      sql`${table.version} between 1 and 9007199254740991
        and ${table.securityRevision} between 1 and 9007199254740991
        and ${table.securityRevision} <= ${table.version}
        and ${table.updatedAt} >= ${table.createdAt}
        and (${table.lastUsedAt} is null
          or (${table.lastUsedAt} >= ${table.createdAt}
            and ${table.updatedAt} >= ${table.lastUsedAt}))
        and (${table.revokedAt} is null or ${table.updatedAt} >= ${table.revokedAt})`,
    ),
  ],
).enableRLS();

/**
 * Immutable passkey authority captured before an MFA continuation becomes
 * usable. Revalidation rows pin the exact source rotation state; initial-login
 * rows deliberately carry no source-session substitute.
 */
export const tenantPostPrimaryPasskeyProvenance = pgTable(
  "tenant_post_primary_passkey_provenance",
  {
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    continuationId: uuid("continuation_id").notNull(),
    userId: uuid("user_id").notNull(),
    origin: text("origin").notNull(),
    primaryKind: text("primary_kind").notNull().default("passkey"),
    authenticationMethod: text("authentication_method")
      .notNull()
      .default("passkey"),
    credentialId: uuid("credential_id").notNull(),
    credentialRevision: bigint("credential_revision", {
      mode: "bigint",
    }).notNull(),
    authenticatedAt: timestamp("authenticated_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    sourceSessionId: uuid("source_session_id").references(
      () => authSessions.id,
      { onDelete: "restrict" },
    ),
    sourceSessionFamilyId: uuid("source_session_family_id"),
    sourceSessionVersion: bigint("source_session_version", {
      mode: "bigint",
    }),
    sourceAbsoluteExpiresAt: timestamp("source_absolute_expires_at", {
      withTimezone: true,
      mode: "date",
    }),
  },
  (table) => [
    primaryKey({
      name: "tenant_post_primary_passkey_provenance_pkey",
      columns: [table.tenantId, table.continuationId],
    }),
    index("tenant_post_primary_passkey_provenance_credential_idx").on(
      table.tenantId,
      table.userId,
      table.credentialId,
      table.continuationId,
    ),
    index("tenant_post_primary_passkey_provenance_source_session_idx")
      .on(table.tenantId, table.sourceSessionId, table.continuationId)
      .where(sql`${table.origin} = 'session_revalidation'`),
    foreignKey({
      name: "tenant_post_primary_passkey_provenance_continuation_fk",
      columns: [
        table.tenantId,
        table.continuationId,
        table.userId,
        table.credentialId,
      ],
      foreignColumns: [
        tenantPostPrimaryContinuations.tenantId,
        tenantPostPrimaryContinuations.id,
        tenantPostPrimaryContinuations.userId,
        tenantPostPrimaryContinuations.passkeyCredentialId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_post_primary_passkey_provenance_credential_fk",
      columns: [table.tenantId, table.userId, table.credentialId],
      foreignColumns: [
        tenantWebauthnCredentials.tenantId,
        tenantWebauthnCredentials.userId,
        tenantWebauthnCredentials.id,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "tenant_post_primary_passkey_provenance_value_check",
      sql`${table.primaryKind} = 'passkey'
        and ${table.authenticationMethod} = 'passkey'
        and ${table.credentialRevision} between 1 and 9007199254740991
        and ((${table.origin} = 'initial_login'
          and ${table.sourceSessionId} is null
          and ${table.sourceSessionFamilyId} is null
          and ${table.sourceSessionVersion} is null
          and ${table.sourceAbsoluteExpiresAt} is null)
        or (${table.origin} = 'session_revalidation'
          and ${table.sourceSessionId} is not null
          and ${table.sourceSessionFamilyId} is not null
          and (uuid_extract_version(${table.sourceSessionFamilyId}) = 7) is true
          and ${table.sourceSessionVersion} between 1 and 9007199254740991
          and ${table.sourceAbsoluteExpiresAt} > ${table.authenticatedAt}
          and date_trunc('milliseconds', ${table.sourceAbsoluteExpiresAt}) =
            ${table.sourceAbsoluteExpiresAt}))`,
    ),
  ],
).enableRLS();

export const tenantWebauthnCredentialTransports = pgTable(
  "tenant_webauthn_credential_transports",
  {
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    credentialId: uuid("credential_id").notNull(),
    transport: text("transport").notNull(),
  },
  (table) => [
    primaryKey({
      name: "tenant_webauthn_credential_transports_pkey",
      columns: [table.tenantId, table.credentialId, table.transport],
    }),
    foreignKey({
      name: "tenant_webauthn_credential_transports_credential_fk",
      columns: [table.tenantId, table.credentialId],
      foreignColumns: [
        tenantWebauthnCredentials.tenantId,
        tenantWebauthnCredentials.id,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "tenant_webauthn_credential_transports_value_check",
      sql`${table.transport} in ('usb', 'nfc', 'ble', 'internal', 'hybrid', 'smart_card')`,
    ),
  ],
).enableRLS();

/**
 * Session assurance state is deliberately not primary provenance. The exact
 * primary source lives in one discriminator-bound child table below.
 */
export const authSessionMfaStates = pgTable(
  "auth_session_mfa_states",
  {
    sessionId: uuid("session_id")
      .primaryKey()
      .references(() => authSessions.id, { onDelete: "restrict" }),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    userId: uuid("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "restrict" }),
    sessionVersion: bigint("session_version", { mode: "bigint" }).notNull(),
    identityEpoch: bigint("identity_epoch", { mode: "bigint" }).notNull(),
    recoveryRestricted: boolean("recovery_restricted").notNull(),
    audience: text("audience").notNull(),
    primaryKind: text("primary_kind").notNull(),
    sessionInvalidationEpoch: bigint("session_invalidation_epoch", {
      mode: "bigint",
    }).notNull(),
    issuedAt: timestamp("issued_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
  },
  (table) => [
    unique("auth_session_mfa_states_tenant_session_key").on(
      table.tenantId,
      table.sessionId,
    ),
    unique("auth_session_mfa_states_exact_user_key").on(
      table.tenantId,
      table.sessionId,
      table.userId,
    ),
    unique("auth_session_mfa_states_primary_subject_key").on(
      table.tenantId,
      table.sessionId,
      table.primaryKind,
      table.userId,
    ),
    index("auth_session_mfa_states_subject_idx").on(
      table.tenantId,
      table.userId,
      table.issuedAt,
      table.sessionId,
    ),
    foreignKey({
      name: "auth_session_mfa_states_subject_fk",
      columns: [table.tenantId, table.userId],
      foreignColumns: [tenantMfaSubjects.tenantId, tenantMfaSubjects.userId],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "auth_session_mfa_states_version_check",
      sql`${table.sessionVersion} > 0
        and ${table.identityEpoch} > 0
        and ${table.sessionInvalidationEpoch} > 0`,
    ),
    check(
      "auth_session_mfa_states_audience_check",
      sql`btrim(${table.audience}) = ${table.audience}
        and char_length(${table.audience}) between 1 and 256
        and ${table.audience} !~ '[[:cntrl:]]'`,
    ),
    check(
      "auth_session_mfa_states_primary_kind_check",
      sql`${table.primaryKind} in (
        'local_credential', 'passkey', 'tenant_provider', 'tenant_platform_provider'
      )`,
    ),
  ],
).enableRLS();

export const authSessionLocalCredentialProvenance = pgTable(
  "auth_session_local_credential_provenance",
  {
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    sessionId: uuid("session_id").notNull(),
    userId: uuid("user_id").notNull(),
    primaryKind: text("primary_kind").notNull().default("local_credential"),
    credentialId: uuid("credential_id").notNull(),
    credentialRevision: bigint("credential_revision", {
      mode: "bigint",
    }).notNull(),
    authenticatedAt: timestamp("authenticated_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
  },
  (table) => [
    primaryKey({
      name: "auth_session_local_credential_provenance_pkey",
      columns: [table.tenantId, table.sessionId],
    }),
    foreignKey({
      name: "auth_session_local_credential_provenance_state_fk",
      columns: [
        table.tenantId,
        table.sessionId,
        table.primaryKind,
        table.userId,
      ],
      foreignColumns: [
        authSessionMfaStates.tenantId,
        authSessionMfaStates.sessionId,
        authSessionMfaStates.primaryKind,
        authSessionMfaStates.userId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "auth_session_local_credential_provenance_credential_fk",
      columns: [table.credentialId],
      foreignColumns: [localBreakGlassCredentials.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "auth_session_local_credential_provenance_kind_check",
      sql`${table.primaryKind} = 'local_credential'`,
    ),
    check(
      "auth_session_local_credential_provenance_revision_check",
      sql`${table.credentialRevision} > 0`,
    ),
  ],
).enableRLS();

export const authSessionPasskeyProvenance = pgTable(
  "auth_session_passkey_provenance",
  {
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    sessionId: uuid("session_id").notNull(),
    userId: uuid("user_id").notNull(),
    primaryKind: text("primary_kind").notNull().default("passkey"),
    credentialId: uuid("credential_id").notNull(),
    credentialRevision: bigint("credential_revision", {
      mode: "bigint",
    }).notNull(),
    authenticatedAt: timestamp("authenticated_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
  },
  (table) => [
    primaryKey({
      name: "auth_session_passkey_provenance_pkey",
      columns: [table.tenantId, table.sessionId],
    }),
    foreignKey({
      name: "auth_session_passkey_provenance_state_fk",
      columns: [
        table.tenantId,
        table.sessionId,
        table.primaryKind,
        table.userId,
      ],
      foreignColumns: [
        authSessionMfaStates.tenantId,
        authSessionMfaStates.sessionId,
        authSessionMfaStates.primaryKind,
        authSessionMfaStates.userId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "auth_session_passkey_provenance_credential_fk",
      columns: [table.tenantId, table.userId, table.credentialId],
      foreignColumns: [
        tenantWebauthnCredentials.tenantId,
        tenantWebauthnCredentials.userId,
        tenantWebauthnCredentials.id,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "auth_session_passkey_provenance_kind_check",
      sql`${table.primaryKind} = 'passkey'`,
    ),
    check(
      "auth_session_passkey_provenance_revision_check",
      sql`${table.credentialRevision} > 0`,
    ),
  ],
).enableRLS();

export const authSessionMfaEvidence = pgTable(
  "auth_session_mfa_evidence",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    sessionId: uuid("session_id").notNull(),
    localCredentialId: uuid("local_credential_id"),
    totpFactorId: uuid("totp_factor_id"),
    webauthnCredentialId: uuid("webauthn_credential_id"),
    recoveryCodeSetId: uuid("recovery_code_set_id"),
    level: text("level").notNull(),
    kind: text("kind").notNull(),
    providerId: uuid("provider_id"),
    bindingId: uuid("binding_id"),
    authenticatedAt: timestamp("authenticated_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    expiresAt: timestamp("expires_at", { withTimezone: true, mode: "date" }),
    factorRevision: bigint("factor_revision", { mode: "bigint" }),
    trustRuleRevision: bigint("trust_rule_revision", { mode: "bigint" }),
  },
  (table) => [
    unique("auth_session_mfa_evidence_session_id_key").on(
      table.tenantId,
      table.sessionId,
      table.id,
    ),
    index("auth_session_mfa_evidence_session_idx").on(
      table.tenantId,
      table.sessionId,
      table.authenticatedAt,
      table.id,
    ),
    foreignKey({
      name: "auth_session_mfa_evidence_session_fk",
      columns: [table.tenantId, table.sessionId],
      foreignColumns: [
        authSessionMfaStates.tenantId,
        authSessionMfaStates.sessionId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "auth_session_mfa_evidence_local_credential_fk",
      columns: [table.localCredentialId],
      foreignColumns: [localBreakGlassCredentials.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "auth_session_mfa_evidence_totp_fk",
      columns: [table.tenantId, table.totpFactorId],
      foreignColumns: [tenantTotpFactors.tenantId, tenantTotpFactors.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "auth_session_mfa_evidence_webauthn_fk",
      columns: [table.tenantId, table.webauthnCredentialId],
      foreignColumns: [
        tenantWebauthnCredentials.tenantId,
        tenantWebauthnCredentials.id,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "auth_session_mfa_evidence_recovery_fk",
      columns: [table.tenantId, table.recoveryCodeSetId],
      foreignColumns: [
        tenantRecoveryCodeSets.tenantId,
        tenantRecoveryCodeSets.id,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "auth_session_mfa_evidence_provider_binding_fk",
      columns: [table.tenantId, table.bindingId, table.providerId],
      foreignColumns: [
        tenantAuthProviderBindings.tenantId,
        tenantAuthProviderBindings.id,
        tenantAuthProviderBindings.providerId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "auth_session_mfa_evidence_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "auth_session_mfa_evidence_typed_source_check",
      sql`${table.level} in ('primary', 'mfa', 'phishing_resistant')
        and ((${table.kind} = 'local_credential'
          and ${table.level} = 'primary'
          and ${table.localCredentialId} is not null
          and ${table.totpFactorId} is null
          and ${table.webauthnCredentialId} is null
          and ${table.recoveryCodeSetId} is null
          and ${table.providerId} is null
          and ${table.bindingId} is null
          and ${table.factorRevision} > 0
          and ${table.trustRuleRevision} is null)
        or (${table.kind} = 'totp'
          and ${table.level} = 'mfa'
          and ${table.localCredentialId} is null
          and ${table.totpFactorId} is not null
          and ${table.webauthnCredentialId} is null
          and ${table.recoveryCodeSetId} is null
          and ${table.providerId} is null
          and ${table.bindingId} is null
          and ${table.factorRevision} > 0
          and ${table.trustRuleRevision} is null)
        or (${table.kind} = 'webauthn'
          and ${table.localCredentialId} is null
          and ${table.totpFactorId} is null
          and ${table.webauthnCredentialId} is not null
          and ${table.recoveryCodeSetId} is null
          and ${table.providerId} is null
          and ${table.bindingId} is null
          and ${table.factorRevision} > 0
          and ${table.trustRuleRevision} is null)
        or (${table.kind} = 'recovery'
          and ${table.level} = 'mfa'
          and ${table.localCredentialId} is null
          and ${table.totpFactorId} is null
          and ${table.webauthnCredentialId} is null
          and ${table.recoveryCodeSetId} is not null
          and ${table.providerId} is null
          and ${table.bindingId} is null
          and ${table.factorRevision} > 0
          and ${table.trustRuleRevision} is null)
        or (${table.kind} = 'provider'
          and ${table.localCredentialId} is null
          and ${table.totpFactorId} is null
          and ${table.webauthnCredentialId} is null
          and ${table.recoveryCodeSetId} is null
          and ${table.providerId} is not null
          and ${table.bindingId} is not null
          and ${table.factorRevision} is null
          and ${table.trustRuleRevision} > 0))`,
    ),
    check(
      "auth_session_mfa_evidence_expiry_check",
      sql`${table.expiresAt} is null or ${table.expiresAt} > ${table.authenticatedAt}`,
    ),
  ],
).enableRLS();

/**
 * Owner-only, transaction-scoped authority for replacing one copied WebAuthn
 * evidence row while an authentication completion rotates a session. A
 * deferred runtime guard requires every row to be consumed and deleted before
 * commit; application roles never receive direct table privileges.
 */
export const tenantMfaWebauthnEvidenceCopyCapabilities = pgTable(
  "tenant_mfa_webauthn_evidence_copy_capabilities",
  {
    tenantId: uuid("tenant_id").notNull(),
    sourceAnchorId: uuid("source_anchor_id").notNull(),
    sourceEvidenceId: uuid("source_evidence_id").notNull(),
    destinationSessionId: uuid("destination_session_id").notNull(),
    backendPid: integer("backend_pid").notNull(),
    transactionId: bigint("transaction_id", { mode: "bigint" }).notNull(),
    userId: uuid("user_id").notNull(),
    factorKind: text("factor_kind").notNull().default("webauthn"),
    credentialId: uuid("credential_id").notNull(),
    sourceRevision: bigint("source_revision", { mode: "bigint" }).notNull(),
    targetRevision: bigint("target_revision", { mode: "bigint" }).notNull(),
    sourceLevel: text("source_level").notNull(),
    targetLevel: text("target_level").notNull(),
    sourceAuthenticatedAt: timestamp("source_authenticated_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    sourceExpiresAt: timestamp("source_expires_at", {
      withTimezone: true,
      mode: "date",
    }),
    targetAuthenticatedAt: timestamp("target_authenticated_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    consumedEvidenceId: uuid("consumed_evidence_id"),
    consumedAt: timestamp("consumed_at", {
      withTimezone: true,
      mode: "date",
    }),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    primaryKey({
      name: "tenant_mfa_webauthn_evidence_copy_capabilities_pkey",
      columns: [
        table.tenantId,
        table.sourceAnchorId,
        table.destinationSessionId,
        table.backendPid,
        table.transactionId,
      ],
    }),
    unique("tenant_mfa_webauthn_evidence_copy_capabilities_destination_key").on(
      table.backendPid,
      table.transactionId,
      table.tenantId,
      table.destinationSessionId,
      table.credentialId,
    ),
    foreignKey({
      name: "tenant_mfa_webauthn_evidence_copy_capabilities_tenant_fk",
      columns: [table.tenantId],
      foreignColumns: [tenants.id],
    })
      .onUpdate("no action")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_mfa_webauthn_evidence_copy_capabilities_source_fk",
      columns: [table.tenantId, table.sourceAnchorId, table.sourceEvidenceId],
      foreignColumns: [
        tenantMfaAuthorityEvidence.tenantId,
        tenantMfaAuthorityEvidence.anchorId,
        tenantMfaAuthorityEvidence.id,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_mfa_webauthn_evidence_copy_capabilities_credential_fk",
      columns: [table.tenantId, table.userId, table.credentialId],
      foreignColumns: [
        tenantWebauthnCredentials.tenantId,
        tenantWebauthnCredentials.userId,
        tenantWebauthnCredentials.id,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "tenant_mfa_webauthn_evidence_copy_capabilities_value_check",
      sql`${table.backendPid} > 0
        and ${table.transactionId} > 0
        and (uuid_extract_version(${table.destinationSessionId}) = 7) is true
        and ${table.factorKind} = 'webauthn'
        and ${table.sourceRevision} between 1 and 9007199254740991
        and ${table.targetRevision} between ${table.sourceRevision}
          and least(${table.sourceRevision} + 1, 9007199254740991)
        and ${table.sourceLevel} in ('primary', 'mfa', 'phishing_resistant')
        and ${table.targetLevel} in ('primary', 'mfa', 'phishing_resistant')
        and ${table.targetAuthenticatedAt} >= ${table.sourceAuthenticatedAt}
        and (${table.sourceExpiresAt} is null
          or ${table.sourceExpiresAt} > ${table.sourceAuthenticatedAt})
        and ((${table.consumedEvidenceId} is null and ${table.consumedAt} is null)
          or (${table.consumedEvidenceId} is not null
            and (uuid_extract_version(${table.consumedEvidenceId}) = 7) is true
            and ${table.consumedAt} is not null
            and ${table.consumedAt} >= ${table.createdAt}))`,
    ),
  ],
).enableRLS();

/**
 * Owner-only, transaction-scoped proof that recovery-code replacement retired
 * one exact recovery evidence row before rotating a session. LDAP and frozen
 * non-LDAP writers consume the row in the creating transaction; no runtime
 * role can mint it or retain it after the public replacement ABI returns.
 */
export const tenantMfaLdapRecoveryReplacementCapabilities = pgTable(
  "tenant_mfa_ldap_recovery_replacement_capabilities",
  {
    tenantId: uuid("tenant_id").notNull(),
    sourceAnchorId: uuid("source_anchor_id").notNull(),
    sourceEvidenceId: uuid("source_evidence_id").notNull(),
    replacedRecoverySetId: uuid("replaced_recovery_set_id").notNull(),
    destinationSessionId: uuid("destination_session_id").notNull(),
    backendPid: integer("backend_pid").notNull(),
    transactionId: bigint("transaction_id", { mode: "bigint" }).notNull(),
    completedAt: timestamp("completed_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    createdAt: timestamp("created_at", {
      withTimezone: true,
      mode: "date",
    })
      .notNull()
      .default(sql`transaction_timestamp()`),
  },
  (table) => [
    primaryKey({
      name: "tenant_mfa_ldap_recovery_replacement_capabilities_pkey",
      columns: [
        table.backendPid,
        table.transactionId,
        table.tenantId,
        table.sourceAnchorId,
        table.replacedRecoverySetId,
      ],
    }),
    unique(
      "tenant_mfa_ldap_recovery_replacement_capabilities_destination_key",
    ).on(
      table.backendPid,
      table.transactionId,
      table.tenantId,
      table.destinationSessionId,
    ),
    foreignKey({
      name: "tenant_mfa_ldap_recovery_replacement_capabilities_tenant_fk",
      columns: [table.tenantId],
      foreignColumns: [tenants.id],
    })
      .onUpdate("no action")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_mfa_ldap_recovery_replacement_capabilities_source_fk",
      columns: [table.tenantId, table.sourceAnchorId, table.sourceEvidenceId],
      foreignColumns: [
        tenantMfaAuthorityEvidence.tenantId,
        tenantMfaAuthorityEvidence.anchorId,
        tenantMfaAuthorityEvidence.id,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "tenant_mfa_ldap_recovery_replacement_capabilities_set_fk",
      columns: [table.tenantId, table.replacedRecoverySetId],
      foreignColumns: [
        tenantRecoveryCodeSets.tenantId,
        tenantRecoveryCodeSets.id,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "tenant_mfa_ldap_recovery_replacement_capabilities_value_check",
      sql`${table.backendPid} > 0
        and ${table.transactionId} > 0
        and (uuid_extract_version(${table.destinationSessionId}) = 7) is true
        and abs(extract(epoch from (${table.createdAt} - ${table.completedAt}))) <= 300`,
    ),
  ],
).enableRLS();

export const authSessionMfaPolicyPins = pgTable(
  "auth_session_mfa_policy_pins",
  {
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    sessionId: uuid("session_id").notNull(),
    policyId: uuid("policy_id").notNull(),
    policyRevision: bigint("policy_revision", { mode: "bigint" }).notNull(),
  },
  (table) => [
    primaryKey({
      name: "auth_session_mfa_policy_pins_pkey",
      columns: [table.tenantId, table.sessionId, table.policyId],
    }),
    foreignKey({
      name: "auth_session_mfa_policy_pins_session_fk",
      columns: [table.tenantId, table.sessionId],
      foreignColumns: [
        authSessionMfaStates.tenantId,
        authSessionMfaStates.sessionId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "auth_session_mfa_policy_pins_revision_check",
      sql`${table.policyRevision} > 0`,
    ),
  ],
).enableRLS();

/**
 * Immutable monotonic assurance policy revisions. Nullable tenant_id is legal
 * only for the platform floor, which is platform-owned rather than customer
 * data. Protected writers retire a revision instead of updating its meaning.
 */
export const mfaPolicyRevisions = pgTable(
  "mfa_policy_revisions",
  {
    id: uuid("id").notNull(),
    revision: bigint("revision", { mode: "bigint" }).notNull(),
    tenantId: uuid("tenant_id").references(() => tenants.id, {
      onDelete: "restrict",
    }),
    scope: text("scope").notNull(),
    roleId: uuid("role_id"),
    securityGroupId: uuid("security_group_id"),
    action: text("action"),
    level: text("level").notNull(),
    localRequired: boolean("local_required").notNull().default(false),
    freshnessNanoseconds: bigint("freshness_nanoseconds", { mode: "bigint" })
      .notNull()
      .default(sql`0`),
    enrollmentDeadline: timestamp("enrollment_deadline", {
      withTimezone: true,
      mode: "date",
    }),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    retiredAt: timestamp("retired_at", { withTimezone: true, mode: "date" }),
  },
  (table) => [
    primaryKey({
      name: "mfa_policy_revisions_pkey",
      columns: [table.id, table.revision],
    }),
    unique("mfa_policy_revisions_tenant_id_key").on(
      table.tenantId,
      table.id,
      table.revision,
    ),
    uniqueIndex("mfa_policy_revisions_platform_live_key")
      .on(table.scope)
      .where(
        sql`${table.scope} = 'platform_floor' and ${table.retiredAt} is null`,
      ),
    uniqueIndex("mfa_policy_revisions_tenant_live_key")
      .on(table.tenantId, table.scope)
      .where(
        sql`${table.scope} = 'tenant_baseline' and ${table.retiredAt} is null`,
      ),
    uniqueIndex("mfa_policy_revisions_role_live_key")
      .on(table.tenantId, table.roleId)
      .where(sql`${table.scope} = 'role' and ${table.retiredAt} is null`),
    uniqueIndex("mfa_policy_revisions_security_group_live_key")
      .on(table.tenantId, table.securityGroupId)
      .where(
        sql`${table.scope} = 'security_group' and ${table.retiredAt} is null`,
      ),
    uniqueIndex("mfa_policy_revisions_action_live_key")
      .on(table.tenantId, table.action)
      .where(sql`${table.scope} = 'action' and ${table.retiredAt} is null`),
    index("mfa_policy_revisions_tenant_history_idx").on(
      table.tenantId,
      table.scope,
      table.id,
      table.revision,
    ),
    foreignKey({
      name: "mfa_policy_revisions_role_fk",
      columns: [table.tenantId, table.roleId],
      foreignColumns: [tenantRoles.tenantId, tenantRoles.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "mfa_policy_revisions_security_group_fk",
      columns: [table.tenantId, table.securityGroupId],
      foreignColumns: [tenantSecurityGroups.tenantId, tenantSecurityGroups.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "mfa_policy_revisions_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "mfa_policy_revisions_revision_check",
      sql`${table.revision} between 1 and 9007199254740991`,
    ),
    check(
      "mfa_policy_revisions_scope_check",
      sql`(${table.scope} = 'platform_floor'
          and ${table.tenantId} is null
          and ${table.roleId} is null
          and ${table.securityGroupId} is null
          and ${table.action} is null)
        or (${table.scope} = 'tenant_baseline'
          and ${table.tenantId} is not null
          and ${table.roleId} is null
          and ${table.securityGroupId} is null
          and ${table.action} is null)
        or (${table.scope} = 'role'
          and ${table.tenantId} is not null
          and ${table.roleId} is not null
          and ${table.securityGroupId} is null
          and ${table.action} is null)
        or (${table.scope} = 'security_group'
          and ${table.tenantId} is not null
          and ${table.roleId} is null
          and ${table.securityGroupId} is not null
          and ${table.action} is null)
        or (${table.scope} = 'action'
          and ${table.tenantId} is not null
          and ${table.roleId} is null
          and ${table.securityGroupId} is null
          and ${table.action} is not null
          and btrim(${table.action}) = ${table.action}
          and char_length(${table.action}) between 1 and 256
          and ${table.action} !~ '[[:cntrl:]]')`,
    ),
    check(
      "mfa_policy_revisions_requirement_check",
      sql`${table.level} in ('primary', 'mfa', 'phishing_resistant')
        and ${table.freshnessNanoseconds} between 0 and 31536000000000000
        and mod(${table.freshnessNanoseconds}, 1000000000) = 0
        and (${table.enrollmentDeadline} is null
          or ${table.enrollmentDeadline} > ${table.createdAt})`,
    ),
    check(
      "mfa_policy_revisions_retired_check",
      sql`${table.retiredAt} is null or ${table.retiredAt} >= ${table.createdAt}`,
    ),
  ],
).enableRLS();

/**
 * Payload-bound idempotency receipts for protected MFA-policy mutations.
 * The result snapshot is the exact post-mutation document returned on replay;
 * callers never receive a projection rebuilt from later mutable state.
 */
export const mfaPolicyCommands = pgTable(
  "mfa_policy_commands",
  {
    id: uuid("id").primaryKey(),
    tenantId: uuid("tenant_id").references(() => tenants.id, {
      onDelete: "restrict",
    }),
    actorUserId: uuid("actor_user_id")
      .notNull()
      .references(() => users.id, { onDelete: "restrict" }),
    operation: text("operation").notNull(),
    requestDigest: bytea("request_digest").notNull(),
    resultPolicyId: uuid("result_policy_id").notNull(),
    resultPolicyRevision: bigint("result_policy_revision", {
      mode: "bigint",
    }).notNull(),
    resultSnapshot: jsonb("result_snapshot")
      .$type<Record<string, unknown>>()
      .notNull(),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    index("mfa_policy_commands_result_idx").on(
      table.resultPolicyId,
      table.resultPolicyRevision,
      table.id,
    ),
    index("mfa_policy_commands_tenant_created_idx").on(
      table.tenantId,
      table.createdAt,
      table.id,
    ),
    foreignKey({
      name: "mfa_policy_commands_result_fk",
      columns: [table.resultPolicyId, table.resultPolicyRevision],
      foreignColumns: [mfaPolicyRevisions.id, mfaPolicyRevisions.revision],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "mfa_policy_commands_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "mfa_policy_commands_operation_check",
      sql`${table.operation} in ('platform.publish', 'platform.retire', 'tenant.publish', 'tenant.retire')`,
    ),
    check(
      "mfa_policy_commands_digest_check",
      sql`octet_length(${table.requestDigest}) = 32
        and encode(${table.requestDigest}, 'hex') <> repeat('00', 32)`,
    ),
    check(
      "mfa_policy_commands_result_check",
      sql`${table.resultPolicyRevision} between 1 and 9007199254740991
        and jsonb_typeof(${table.resultSnapshot}) = 'object'
        and pg_column_size(${table.resultSnapshot}) between 2 and 65536`,
    ),
  ],
).enableRLS();
