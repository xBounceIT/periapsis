import { sql } from "drizzle-orm";
import {
  bigint,
  boolean,
  char,
  check,
  foreignKey,
  index,
  integer,
  jsonb,
  pgPolicy,
  pgTable,
  primaryKey,
  smallint,
  text,
  timestamp,
  unique,
  uniqueIndex,
  uuid,
} from "drizzle-orm/pg-core";

import { authSessions } from "./authentication.js";
import { bytea } from "./binary.js";
import { tenantMemberships, users } from "./identity.js";
import { auditOperationsOwnerRole } from "./roles.js";
import { tenants } from "./tenancy.js";

const zeroAuditHash =
  "0000000000000000000000000000000000000000000000000000000000000000";

/**
 * Monotonic authorization generation for platform users. Tenant export jobs
 * pin tenant_authorization_states.revision; platform jobs pin this independent
 * generation, which is advanced by both user-role and shared role-permission
 * changes in the guarded migration ABI.
 */
export const platformUserAuthorizationEpochs = pgTable(
  "platform_user_authorization_epochs",
  {
    userId: uuid("user_id")
      .primaryKey()
      .references(() => users.id, { onDelete: "restrict" }),
    permissionEpoch: bigint("permission_epoch", { mode: "bigint" })
      .notNull()
      .default(sql`1`),
    updatedAt: timestamp("updated_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    check(
      "platform_user_authorization_epochs_value_check",
      sql`${table.permissionEpoch} between 1 and 9007199254740991`,
    ),
    pgPolicy("platform_user_authorization_epochs_owner_access", {
      as: "permissive",
      for: "all",
      to: auditOperationsOwnerRole,
      using: sql`true`,
      withCheck: sql`true`,
    }),
  ],
).enableRLS();

export const tenantAuditExportJobs = pgTable(
  "tenant_audit_export_jobs",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    requesterUserId: uuid("requester_user_id")
      .notNull()
      .references(() => users.id, { onDelete: "restrict" }),
    requesterMembershipId: uuid("requester_membership_id").notNull(),
    requesterSessionId: uuid("requester_session_id")
      .notNull()
      .references(() => authSessions.id, { onDelete: "restrict" }),
    membershipLifecycleRevision: bigint("membership_lifecycle_revision", {
      mode: "bigint",
    }).notNull(),
    permissionEpoch: bigint("permission_epoch", { mode: "bigint" }).notNull(),
    normalizedFilter: jsonb("normalized_filter")
      .$type<Record<string, unknown>>()
      .notNull(),
    filterDigest: bytea("filter_digest").notNull(),
    projectionVersion: integer("projection_version").notNull().default(1),
    format: text("format").notNull().default("jsonl"),
    state: text("state").notNull().default("pending"),
    revision: bigint("revision", { mode: "bigint" })
      .notNull()
      .default(sql`1`),
    attempts: smallint("attempts").notNull().default(0),
    maximumAttempts: smallint("maximum_attempts").notNull().default(5),
    failureCode: text("failure_code").notNull().default("none"),
    requestedAt: timestamp("requested_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    availableAt: timestamp("available_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    expiresAt: timestamp("expires_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    leaseWorkerId: uuid("lease_worker_id"),
    leaseFence: bytea("lease_fence"),
    leaseClaimedAt: timestamp("lease_claimed_at", {
      withTimezone: true,
      mode: "date",
    }),
    leaseExpiresAt: timestamp("lease_expires_at", {
      withTimezone: true,
      mode: "date",
    }),
    artifactId: uuid("artifact_id"),
    objectKey: text("object_key"),
    artifactDigest: bytea("artifact_digest"),
    artifactRows: bigint("artifact_rows", { mode: "bigint" }),
    artifactBytes: bigint("artifact_bytes", { mode: "bigint" }),
    artifactExpiresAt: timestamp("artifact_expires_at", {
      withTimezone: true,
      mode: "date",
    }),
    terminalAt: timestamp("terminal_at", { withTimezone: true, mode: "date" }),
  },
  (table) => [
    unique("tenant_audit_export_jobs_tenant_id_key").on(
      table.tenantId,
      table.id,
    ),
    foreignKey({
      name: "tenant_audit_export_jobs_requester_membership_fk",
      columns: [
        table.tenantId,
        table.requesterMembershipId,
        table.requesterUserId,
      ],
      foreignColumns: [
        tenantMemberships.tenantId,
        tenantMemberships.id,
        tenantMemberships.userId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    index("tenant_audit_export_jobs_queue_idx").on(
      table.state,
      table.availableAt,
      table.tenantId,
      table.id,
    ),
    index("tenant_audit_export_jobs_requester_idx").on(
      table.tenantId,
      table.requesterMembershipId,
      table.requestedAt,
      table.id,
    ),
    check(
      "tenant_audit_export_jobs_shape_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true
        and ${table.membershipLifecycleRevision} between 1 and 9007199254740991
        and ${table.permissionEpoch} between 1 and 9007199254740991
        and octet_length(${table.filterDigest}) = 32
        and jsonb_typeof(${table.normalizedFilter}) = 'object'
        and pg_column_size(${table.normalizedFilter}) <= 65536
        and ${table.projectionVersion} = 1 and ${table.format} = 'jsonl'
        and ${table.revision} between 1 and 9007199254740991
        and ${table.attempts} between 0 and ${table.maximumAttempts}
        and ${table.maximumAttempts} between 1 and 10
        and ${table.updatedAt} >= ${table.requestedAt}
        and ${table.availableAt} >= ${table.requestedAt}
        and ${table.expiresAt} > ${table.requestedAt}
        and ${table.expiresAt} <= ${table.requestedAt} + interval '7 days'
        and ${table.state} in ('pending','running','cancellation_requested','succeeded','failed','cancelled','authorization_revoked','expired')
        and ${table.failureCode} in ('none','transient_storage','transient_database','authorization_revoked','output_limit','lease_expired','expired','internal')
        and ((${table.leaseWorkerId} is null and ${table.leaseFence} is null and ${table.leaseClaimedAt} is null and ${table.leaseExpiresAt} is null)
          or (${table.state} in ('running','cancellation_requested') and ${table.leaseWorkerId} is not null
            and octet_length(${table.leaseFence}) = 32 and ${table.leaseExpiresAt} > ${table.leaseClaimedAt}))
        and ((${table.artifactId} is null and ${table.objectKey} is null and ${table.artifactDigest} is null
              and ${table.artifactRows} is null and ${table.artifactBytes} is null and ${table.artifactExpiresAt} is null)
          or (${table.state} = 'succeeded' and (uuid_extract_version(${table.artifactId}) = 7) is true
              and ${table.objectKey} ~ '^tenants/[0-9a-f-]{36}/audit/exports/[0-9a-f-]{36}/v1\\.jsonl$'
              and octet_length(${table.artifactDigest}) = 32 and ${table.artifactRows} >= 0
              and ${table.artifactBytes} >= 0 and ${table.artifactExpiresAt} = ${table.expiresAt}))`,
    ),
    pgPolicy("tenant_audit_export_jobs_owner_access", {
      as: "permissive",
      for: "all",
      to: auditOperationsOwnerRole,
      using: sql`true`,
      withCheck: sql`true`,
    }),
  ],
).enableRLS();

export const tenantAuditOperationReceipts = pgTable(
  "tenant_audit_operation_receipts",
  {
    tenantId: uuid("tenant_id").notNull(),
    actorUserId: uuid("actor_user_id").notNull(),
    membershipId: uuid("membership_id").notNull(),
    action: text("action").notNull(),
    idempotencyKeyDigest: bytea("idempotency_key_digest").notNull(),
    payloadDigest: bytea("payload_digest").notNull(),
    response: jsonb("response").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    expiresAt: timestamp("expires_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
  },
  (table) => [
    primaryKey({
      name: "tenant_audit_operation_receipts_pkey",
      columns: [
        table.tenantId,
        table.actorUserId,
        table.membershipId,
        table.action,
        table.idempotencyKeyDigest,
      ],
    }),
    index("tenant_audit_operation_receipts_expiry_idx").on(
      table.expiresAt,
      table.tenantId,
      table.actorUserId,
    ),
    foreignKey({
      name: "tenant_audit_operation_receipts_membership_fk",
      columns: [table.tenantId, table.membershipId, table.actorUserId],
      foreignColumns: [
        tenantMemberships.tenantId,
        tenantMemberships.id,
        tenantMemberships.userId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "tenant_audit_operation_receipts_shape_check",
      sql`${table.action} in ('export.create','export.cancel','retention.change','legal_hold.place','legal_hold.release')
        and octet_length(${table.idempotencyKeyDigest}) = 32
        and octet_length(${table.payloadDigest}) = 32
        and jsonb_typeof(${table.response}) = 'object'
        and pg_column_size(${table.response}) <= 65536
        and ${table.expiresAt} > ${table.createdAt}
        and ${table.expiresAt} <= ${table.createdAt} + interval '7 days'`,
    ),
    pgPolicy("tenant_audit_operation_receipts_owner_access", {
      as: "permissive",
      for: "all",
      to: auditOperationsOwnerRole,
      using: sql`true`,
      withCheck: sql`true`,
    }),
  ],
).enableRLS();

export const tenantAuditExportManifests = pgTable(
  "tenant_audit_export_manifests",
  {
    tenantId: uuid("tenant_id").notNull(),
    jobId: uuid("job_id").notNull(),
    artifactId: uuid("artifact_id").notNull(),
    jobRevision: bigint("job_revision", { mode: "bigint" }).notNull(),
    projectionVersion: integer("projection_version").notNull(),
    format: text("format").notNull(),
    objectKey: text("object_key").notNull(),
    digest: bytea("digest").notNull(),
    rows: bigint("rows", { mode: "bigint" }).notNull(),
    bytes: bigint("bytes", { mode: "bigint" }).notNull(),
    publishedAt: timestamp("published_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    expiresAt: timestamp("expires_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
  },
  (table) => [
    primaryKey({
      name: "tenant_audit_export_manifests_pkey",
      columns: [table.tenantId, table.jobId, table.artifactId],
    }),
    unique("tenant_audit_export_manifests_artifact_key").on(table.artifactId),
    foreignKey({
      name: "tenant_audit_export_manifests_job_fk",
      columns: [table.tenantId, table.jobId],
      foreignColumns: [
        tenantAuditExportJobs.tenantId,
        tenantAuditExportJobs.id,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "tenant_audit_export_manifests_shape_check",
      sql`(uuid_extract_version(${table.artifactId}) = 7) is true
        and ${table.jobRevision} between 1 and 9007199254740991
        and ${table.projectionVersion} = 1 and ${table.format} = 'jsonl'
        and ${table.objectKey} ~ '^tenants/[0-9a-f-]{36}/audit/exports/[0-9a-f-]{36}/v1\\.jsonl$'
        and octet_length(${table.digest}) = 32 and ${table.rows} >= 0 and ${table.bytes} >= 0
        and ${table.expiresAt} > ${table.publishedAt}`,
    ),
    pgPolicy("tenant_audit_export_manifests_owner_access", {
      as: "permissive",
      for: "all",
      to: auditOperationsOwnerRole,
      using: sql`true`,
      withCheck: sql`true`,
    }),
  ],
).enableRLS();

export const platformAuditExportJobs = pgTable(
  "platform_audit_export_jobs",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    requesterUserId: uuid("requester_user_id")
      .notNull()
      .references(() => users.id, { onDelete: "restrict" }),
    requesterSessionId: uuid("requester_session_id")
      .notNull()
      .references(() => authSessions.id, { onDelete: "restrict" }),
    permissionEpoch: bigint("permission_epoch", { mode: "bigint" }).notNull(),
    normalizedFilter: jsonb("normalized_filter")
      .$type<Record<string, unknown>>()
      .notNull(),
    filterDigest: bytea("filter_digest").notNull(),
    projectionVersion: integer("projection_version").notNull().default(1),
    format: text("format").notNull().default("jsonl"),
    state: text("state").notNull().default("pending"),
    revision: bigint("revision", { mode: "bigint" })
      .notNull()
      .default(sql`1`),
    attempts: smallint("attempts").notNull().default(0),
    maximumAttempts: smallint("maximum_attempts").notNull().default(5),
    failureCode: text("failure_code").notNull().default("none"),
    requestedAt: timestamp("requested_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    availableAt: timestamp("available_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    expiresAt: timestamp("expires_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    leaseWorkerId: uuid("lease_worker_id"),
    leaseFence: bytea("lease_fence"),
    leaseClaimedAt: timestamp("lease_claimed_at", {
      withTimezone: true,
      mode: "date",
    }),
    leaseExpiresAt: timestamp("lease_expires_at", {
      withTimezone: true,
      mode: "date",
    }),
    artifactId: uuid("artifact_id"),
    objectKey: text("object_key"),
    artifactDigest: bytea("artifact_digest"),
    artifactRows: bigint("artifact_rows", { mode: "bigint" }),
    artifactBytes: bigint("artifact_bytes", { mode: "bigint" }),
    artifactExpiresAt: timestamp("artifact_expires_at", {
      withTimezone: true,
      mode: "date",
    }),
    terminalAt: timestamp("terminal_at", { withTimezone: true, mode: "date" }),
  },
  (table) => [
    index("platform_audit_export_jobs_queue_idx").on(
      table.state,
      table.availableAt,
      table.id,
    ),
    index("platform_audit_export_jobs_requester_idx").on(
      table.requesterUserId,
      table.requestedAt,
      table.id,
    ),
    check(
      "platform_audit_export_jobs_shape_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true
        and ${table.permissionEpoch} between 1 and 9007199254740991
        and octet_length(${table.filterDigest}) = 32
        and jsonb_typeof(${table.normalizedFilter}) = 'object' and pg_column_size(${table.normalizedFilter}) <= 65536
        and ${table.projectionVersion} = 1 and ${table.format} = 'jsonl'
        and ${table.revision} between 1 and 9007199254740991
        and ${table.attempts} between 0 and ${table.maximumAttempts} and ${table.maximumAttempts} between 1 and 10
        and ${table.updatedAt} >= ${table.requestedAt} and ${table.availableAt} >= ${table.requestedAt}
        and ${table.expiresAt} > ${table.requestedAt} and ${table.expiresAt} <= ${table.requestedAt} + interval '7 days'
        and ${table.state} in ('pending','running','cancellation_requested','succeeded','failed','cancelled','authorization_revoked','expired')
        and ${table.failureCode} in ('none','transient_storage','transient_database','authorization_revoked','output_limit','lease_expired','expired','internal')
        and ((${table.leaseWorkerId} is null and ${table.leaseFence} is null and ${table.leaseClaimedAt} is null and ${table.leaseExpiresAt} is null)
          or (${table.state} in ('running','cancellation_requested') and ${table.leaseWorkerId} is not null
            and octet_length(${table.leaseFence}) = 32 and ${table.leaseExpiresAt} > ${table.leaseClaimedAt}))
        and ((${table.artifactId} is null and ${table.objectKey} is null and ${table.artifactDigest} is null
              and ${table.artifactRows} is null and ${table.artifactBytes} is null and ${table.artifactExpiresAt} is null)
          or (${table.state} = 'succeeded' and (uuid_extract_version(${table.artifactId}) = 7) is true
              and ${table.objectKey} ~ '^platform/audit/exports/[0-9a-f-]{36}/v1\\.jsonl$'
              and octet_length(${table.artifactDigest}) = 32 and ${table.artifactRows} >= 0
              and ${table.artifactBytes} >= 0 and ${table.artifactExpiresAt} = ${table.expiresAt}))`,
    ),
    pgPolicy("platform_audit_export_jobs_owner_access", {
      as: "permissive",
      for: "all",
      to: auditOperationsOwnerRole,
      using: sql`true`,
      withCheck: sql`true`,
    }),
  ],
).enableRLS();

export const platformAuditOperationReceipts = pgTable(
  "platform_audit_operation_receipts",
  {
    actorUserId: uuid("actor_user_id")
      .notNull()
      .references(() => users.id, { onDelete: "restrict" }),
    action: text("action").notNull(),
    idempotencyKeyDigest: bytea("idempotency_key_digest").notNull(),
    payloadDigest: bytea("payload_digest").notNull(),
    response: jsonb("response").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    expiresAt: timestamp("expires_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
  },
  (table) => [
    primaryKey({
      name: "platform_audit_operation_receipts_pkey",
      columns: [table.actorUserId, table.action, table.idempotencyKeyDigest],
    }),
    index("platform_audit_operation_receipts_expiry_idx").on(
      table.expiresAt,
      table.actorUserId,
    ),
    check(
      "platform_audit_operation_receipts_shape_check",
      sql`${table.action} in ('export.create','export.cancel','retention.change','legal_hold.place','legal_hold.release')
        and octet_length(${table.idempotencyKeyDigest}) = 32 and octet_length(${table.payloadDigest}) = 32
        and jsonb_typeof(${table.response}) = 'object' and pg_column_size(${table.response}) <= 65536
        and ${table.expiresAt} > ${table.createdAt} and ${table.expiresAt} <= ${table.createdAt} + interval '7 days'`,
    ),
    pgPolicy("platform_audit_operation_receipts_owner_access", {
      as: "permissive",
      for: "all",
      to: auditOperationsOwnerRole,
      using: sql`true`,
      withCheck: sql`true`,
    }),
  ],
).enableRLS();

export const platformAuditExportManifests = pgTable(
  "platform_audit_export_manifests",
  {
    jobId: uuid("job_id").notNull(),
    artifactId: uuid("artifact_id").notNull(),
    jobRevision: bigint("job_revision", { mode: "bigint" }).notNull(),
    projectionVersion: integer("projection_version").notNull(),
    format: text("format").notNull(),
    objectKey: text("object_key").notNull(),
    digest: bytea("digest").notNull(),
    rows: bigint("rows", { mode: "bigint" }).notNull(),
    bytes: bigint("bytes", { mode: "bigint" }).notNull(),
    publishedAt: timestamp("published_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    expiresAt: timestamp("expires_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
  },
  (table) => [
    primaryKey({
      name: "platform_audit_export_manifests_pkey",
      columns: [table.jobId, table.artifactId],
    }),
    unique("platform_audit_export_manifests_artifact_key").on(table.artifactId),
    foreignKey({
      name: "platform_audit_export_manifests_job_fk",
      columns: [table.jobId],
      foreignColumns: [platformAuditExportJobs.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "platform_audit_export_manifests_shape_check",
      sql`(uuid_extract_version(${table.artifactId}) = 7) is true
        and ${table.jobRevision} between 1 and 9007199254740991
        and ${table.projectionVersion} = 1 and ${table.format} = 'jsonl'
        and ${table.objectKey} ~ '^platform/audit/exports/[0-9a-f-]{36}/v1\\.jsonl$'
        and octet_length(${table.digest}) = 32 and ${table.rows} >= 0 and ${table.bytes} >= 0
        and ${table.expiresAt} > ${table.publishedAt}`,
    ),
    pgPolicy("platform_audit_export_manifests_owner_access", {
      as: "permissive",
      for: "all",
      to: auditOperationsOwnerRole,
      using: sql`true`,
      withCheck: sql`true`,
    }),
  ],
).enableRLS();

export const tenantAuditRetentionPolicies = pgTable(
  "tenant_audit_retention_policies",
  {
    tenantId: uuid("tenant_id")
      .primaryKey()
      .references(() => tenants.id, { onDelete: "restrict" }),
    retentionDays: integer("retention_days").notNull().default(365),
    revision: bigint("revision", { mode: "bigint" })
      .notNull()
      .default(sql`1`),
    updatedByUserId: uuid("updated_by_user_id").references(() => users.id, {
      onDelete: "restrict",
    }),
    reason: text("reason").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    check(
      "tenant_audit_retention_policies_shape_check",
      sql`${table.retentionDays} between 30 and 3650
        and ${table.revision} between 1 and 9007199254740991
        and ${table.updatedAt} >= ${table.createdAt}
        and ${table.reason} = btrim(${table.reason}) and octet_length(${table.reason}) between 1 and 2048
        and ${table.reason} !~ '[[:cntrl:]]'`,
    ),
    pgPolicy("tenant_audit_retention_policies_owner_access", {
      as: "permissive",
      for: "all",
      to: auditOperationsOwnerRole,
      using: sql`true`,
      withCheck: sql`true`,
    }),
  ],
).enableRLS();

export const platformAuditRetentionPolicy = pgTable(
  "platform_audit_retention_policy",
  {
    singleton: boolean("singleton").primaryKey().default(true),
    retentionDays: integer("retention_days").notNull().default(730),
    revision: bigint("revision", { mode: "bigint" })
      .notNull()
      .default(sql`1`),
    updatedByUserId: uuid("updated_by_user_id").references(() => users.id, {
      onDelete: "restrict",
    }),
    reason: text("reason").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    check(
      "platform_audit_retention_policy_singleton_check",
      sql`${table.singleton} is true`,
    ),
    check(
      "platform_audit_retention_policy_shape_check",
      sql`${table.retentionDays} between 30 and 3650
        and ${table.revision} between 1 and 9007199254740991
        and ${table.updatedAt} >= ${table.createdAt}
        and ${table.reason} = btrim(${table.reason}) and octet_length(${table.reason}) between 1 and 2048
        and ${table.reason} !~ '[[:cntrl:]]'`,
    ),
    pgPolicy("platform_audit_retention_policy_owner_access", {
      as: "permissive",
      for: "all",
      to: auditOperationsOwnerRole,
      using: sql`true`,
      withCheck: sql`true`,
    }),
  ],
).enableRLS();

export const tenantAuditLegalHolds = pgTable(
  "tenant_audit_legal_holds",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    state: text("state").notNull().default("active"),
    revision: bigint("revision", { mode: "bigint" })
      .notNull()
      .default(sql`1`),
    placedByUserId: uuid("placed_by_user_id")
      .notNull()
      .references(() => users.id, { onDelete: "restrict" }),
    placedAt: timestamp("placed_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    placementReason: text("placement_reason").notNull(),
    releasedByUserId: uuid("released_by_user_id").references(() => users.id, {
      onDelete: "restrict",
    }),
    releasedAt: timestamp("released_at", { withTimezone: true, mode: "date" }),
    releaseReason: text("release_reason"),
  },
  (table) => [
    unique("tenant_audit_legal_holds_tenant_id_key").on(
      table.tenantId,
      table.id,
    ),
    uniqueIndex("tenant_audit_legal_holds_active_key")
      .on(table.tenantId)
      .where(sql`${table.state} = 'active'`),
    check(
      "tenant_audit_legal_holds_shape_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true
        and ${table.revision} between 1 and 9007199254740991
        and ${table.placementReason} = btrim(${table.placementReason})
        and octet_length(${table.placementReason}) between 1 and 2048 and ${table.placementReason} !~ '[[:cntrl:]]'
        and ((${table.state} = 'active' and ${table.revision} = 1 and ${table.releasedByUserId} is null
              and ${table.releasedAt} is null and ${table.releaseReason} is null)
          or (${table.state} = 'released' and ${table.revision} = 2 and ${table.releasedByUserId} is not null
              and ${table.releasedAt} >= ${table.placedAt} and ${table.releaseReason} = btrim(${table.releaseReason})
              and octet_length(${table.releaseReason}) between 1 and 2048 and ${table.releaseReason} !~ '[[:cntrl:]]'))`,
    ),
    pgPolicy("tenant_audit_legal_holds_owner_access", {
      as: "permissive",
      for: "all",
      to: auditOperationsOwnerRole,
      using: sql`true`,
      withCheck: sql`true`,
    }),
  ],
).enableRLS();

export const platformAuditLegalHolds = pgTable(
  "platform_audit_legal_holds",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    state: text("state").notNull().default("active"),
    revision: bigint("revision", { mode: "bigint" })
      .notNull()
      .default(sql`1`),
    placedByUserId: uuid("placed_by_user_id")
      .notNull()
      .references(() => users.id, { onDelete: "restrict" }),
    placedAt: timestamp("placed_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    placementReason: text("placement_reason").notNull(),
    releasedByUserId: uuid("released_by_user_id").references(() => users.id, {
      onDelete: "restrict",
    }),
    releasedAt: timestamp("released_at", { withTimezone: true, mode: "date" }),
    releaseReason: text("release_reason"),
  },
  (table) => [
    uniqueIndex("platform_audit_legal_holds_active_key")
      .on(table.state)
      .where(sql`${table.state} = 'active'`),
    check(
      "platform_audit_legal_holds_shape_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true
        and ${table.revision} between 1 and 9007199254740991
        and ${table.placementReason} = btrim(${table.placementReason})
        and octet_length(${table.placementReason}) between 1 and 2048 and ${table.placementReason} !~ '[[:cntrl:]]'
        and ((${table.state} = 'active' and ${table.revision} = 1 and ${table.releasedByUserId} is null
              and ${table.releasedAt} is null and ${table.releaseReason} is null)
          or (${table.state} = 'released' and ${table.revision} = 2 and ${table.releasedByUserId} is not null
              and ${table.releasedAt} >= ${table.placedAt} and ${table.releaseReason} = btrim(${table.releaseReason})
              and octet_length(${table.releaseReason}) between 1 and 2048 and ${table.releaseReason} !~ '[[:cntrl:]]'))`,
    ),
    pgPolicy("platform_audit_legal_holds_owner_access", {
      as: "permissive",
      for: "all",
      to: auditOperationsOwnerRole,
      using: sql`true`,
      withCheck: sql`true`,
    }),
  ],
).enableRLS();

export const tenantAuditSegments = pgTable(
  "tenant_audit_segments",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    startSequence: bigint("start_sequence", { mode: "bigint" }).notNull(),
    endSequence: bigint("end_sequence", { mode: "bigint" }).notNull(),
    previousHash: char("previous_hash", { length: 64 }).notNull(),
    endHash: char("end_hash", { length: 64 }).notNull(),
    eventCount: bigint("event_count", { mode: "bigint" }).notNull(),
    cutoffAt: timestamp("cutoff_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    state: text("state").notNull().default("closed"),
    revision: bigint("revision", { mode: "bigint" })
      .notNull()
      .default(sql`1`),
    reason: text("reason").notNull(),
    objectKey: text("object_key").notNull(),
    digest: bytea("digest"),
    bytes: bigint("bytes", { mode: "bigint" }),
    signingKeyId: text("signing_key_id"),
    signature: bytea("signature"),
    closedAt: timestamp("closed_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    preservedAt: timestamp("preserved_at", {
      withTimezone: true,
      mode: "date",
    }),
    prunedAt: timestamp("pruned_at", { withTimezone: true, mode: "date" }),
  },
  (table) => [
    unique("tenant_audit_segments_tenant_id_key").on(table.tenantId, table.id),
    unique("tenant_audit_segments_tenant_range_key").on(
      table.tenantId,
      table.startSequence,
    ),
    unique("tenant_audit_segments_tenant_end_key").on(
      table.tenantId,
      table.endSequence,
    ),
    index("tenant_audit_segments_state_idx").on(
      table.state,
      table.closedAt,
      table.tenantId,
      table.id,
    ),
    check(
      "tenant_audit_segments_shape_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true
        and ${table.startSequence} > 0 and ${table.endSequence} >= ${table.startSequence}
        and ${table.eventCount} = ${table.endSequence} - ${table.startSequence} + 1
        and ${table.previousHash} ~ '^[0-9a-f]{64}$' and ${table.endHash} ~ '^[0-9a-f]{64}$'
        and ${table.revision} between 1 and 3
        and ${table.reason} = btrim(${table.reason}) and octet_length(${table.reason}) between 1 and 2048
        and ${table.reason} !~ '[[:cntrl:]]'
        and ${table.objectKey} = ('tenants/' || ${table.tenantId}::text || '/audit/segments/'
          || ${table.startSequence}::text || '-' || ${table.endSequence}::text || '/'
          || ${table.id}::text || '.jsonl')
        and ((${table.state} = 'closed' and ${table.revision} = 1 and ${table.digest} is null and ${table.bytes} is null
              and ${table.signingKeyId} is null and ${table.signature} is null and ${table.preservedAt} is null and ${table.prunedAt} is null)
          or (${table.state} = 'preserved' and ${table.revision} = 2 and octet_length(${table.digest}) = 32 and ${table.bytes} > 0
              and ${table.signingKeyId} ~ '^[a-z0-9][a-z0-9_.:-]{0,127}$' and octet_length(${table.signature}) = 64
              and ${table.preservedAt} >= ${table.closedAt} and ${table.prunedAt} is null)
          or (${table.state} = 'pruned' and ${table.revision} = 3 and octet_length(${table.digest}) = 32 and ${table.bytes} > 0
              and ${table.signingKeyId} ~ '^[a-z0-9][a-z0-9_.:-]{0,127}$' and octet_length(${table.signature}) = 64
              and ${table.preservedAt} >= ${table.closedAt} and ${table.prunedAt} >= ${table.preservedAt}))`,
    ),
    pgPolicy("tenant_audit_segments_owner_access", {
      as: "permissive",
      for: "all",
      to: auditOperationsOwnerRole,
      using: sql`true`,
      withCheck: sql`true`,
    }),
  ],
).enableRLS();

export const platformAuditSegments = pgTable(
  "platform_audit_segments",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    startSequence: bigint("start_sequence", { mode: "bigint" }).notNull(),
    endSequence: bigint("end_sequence", { mode: "bigint" }).notNull(),
    previousHash: char("previous_hash", { length: 64 }).notNull(),
    endHash: char("end_hash", { length: 64 }).notNull(),
    eventCount: bigint("event_count", { mode: "bigint" }).notNull(),
    cutoffAt: timestamp("cutoff_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    state: text("state").notNull().default("closed"),
    revision: bigint("revision", { mode: "bigint" })
      .notNull()
      .default(sql`1`),
    reason: text("reason").notNull(),
    objectKey: text("object_key").notNull(),
    digest: bytea("digest"),
    bytes: bigint("bytes", { mode: "bigint" }),
    signingKeyId: text("signing_key_id"),
    signature: bytea("signature"),
    closedAt: timestamp("closed_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    preservedAt: timestamp("preserved_at", {
      withTimezone: true,
      mode: "date",
    }),
    prunedAt: timestamp("pruned_at", { withTimezone: true, mode: "date" }),
  },
  (table) => [
    unique("platform_audit_segments_start_key").on(table.startSequence),
    unique("platform_audit_segments_end_key").on(table.endSequence),
    index("platform_audit_segments_state_idx").on(
      table.state,
      table.closedAt,
      table.id,
    ),
    check(
      "platform_audit_segments_shape_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true
        and ${table.startSequence} > 0 and ${table.endSequence} >= ${table.startSequence}
        and ${table.eventCount} = ${table.endSequence} - ${table.startSequence} + 1
        and ${table.previousHash} ~ '^[0-9a-f]{64}$' and ${table.endHash} ~ '^[0-9a-f]{64}$'
        and ${table.revision} between 1 and 3
        and ${table.reason} = btrim(${table.reason}) and octet_length(${table.reason}) between 1 and 2048 and ${table.reason} !~ '[[:cntrl:]]'
        and ${table.objectKey} = ('platform/audit/segments/' || ${table.startSequence}::text
          || '-' || ${table.endSequence}::text || '/' || ${table.id}::text || '.jsonl')
        and ((${table.state} = 'closed' and ${table.revision} = 1 and ${table.digest} is null and ${table.bytes} is null
              and ${table.signingKeyId} is null and ${table.signature} is null and ${table.preservedAt} is null and ${table.prunedAt} is null)
          or (${table.state} = 'preserved' and ${table.revision} = 2 and octet_length(${table.digest}) = 32 and ${table.bytes} > 0
              and ${table.signingKeyId} ~ '^[a-z0-9][a-z0-9_.:-]{0,127}$' and octet_length(${table.signature}) = 64
              and ${table.preservedAt} >= ${table.closedAt} and ${table.prunedAt} is null)
          or (${table.state} = 'pruned' and ${table.revision} = 3 and octet_length(${table.digest}) = 32 and ${table.bytes} > 0
              and ${table.signingKeyId} ~ '^[a-z0-9][a-z0-9_.:-]{0,127}$' and octet_length(${table.signature}) = 64
              and ${table.preservedAt} >= ${table.closedAt} and ${table.prunedAt} >= ${table.preservedAt}))`,
    ),
    pgPolicy("platform_audit_segments_owner_access", {
      as: "permissive",
      for: "all",
      to: auditOperationsOwnerRole,
      using: sql`true`,
      withCheck: sql`true`,
    }),
  ],
).enableRLS();

export const tenantAuditRetentionAnchors = pgTable(
  "tenant_audit_retention_anchors",
  {
    tenantId: uuid("tenant_id")
      .primaryKey()
      .references(() => tenants.id, { onDelete: "restrict" }),
    retainedThroughSequence: bigint("retained_through_sequence", {
      mode: "bigint",
    })
      .notNull()
      .default(sql`0`),
    retainedThroughHash: char("retained_through_hash", { length: 64 })
      .notNull()
      .default(zeroAuditHash),
    lastSegmentId: uuid("last_segment_id"),
    segmentDigest: bytea("segment_digest"),
    signingKeyId: text("signing_key_id"),
    signature: bytea("signature"),
    revision: bigint("revision", { mode: "bigint" })
      .notNull()
      .default(sql`1`),
    reason: text("reason").notNull().default("initial retention anchor"),
    updatedAt: timestamp("updated_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    foreignKey({
      name: "tenant_audit_retention_anchors_segment_fk",
      columns: [table.tenantId, table.lastSegmentId],
      foreignColumns: [tenantAuditSegments.tenantId, tenantAuditSegments.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "tenant_audit_retention_anchors_shape_check",
      sql`${table.retainedThroughSequence} >= 0 and ${table.retainedThroughHash} ~ '^[0-9a-f]{64}$'
        and ${table.revision} between 1 and 9007199254740991
        and ${table.reason} = btrim(${table.reason}) and octet_length(${table.reason}) between 1 and 2048 and ${table.reason} !~ '[[:cntrl:]]'
        and ((${table.retainedThroughSequence} = 0 and ${table.retainedThroughHash} = ${zeroAuditHash}
              and ${table.lastSegmentId} is null and ${table.segmentDigest} is null and ${table.signingKeyId} is null and ${table.signature} is null)
          or (${table.retainedThroughSequence} > 0 and ${table.lastSegmentId} is not null and octet_length(${table.segmentDigest}) = 32
              and ${table.signingKeyId} ~ '^[a-z0-9][a-z0-9_.:-]{0,127}$' and octet_length(${table.signature}) = 64))`,
    ),
    pgPolicy("tenant_audit_retention_anchors_owner_access", {
      as: "permissive",
      for: "all",
      to: auditOperationsOwnerRole,
      using: sql`true`,
      withCheck: sql`true`,
    }),
  ],
).enableRLS();

/**
 * Transaction-local proof consumed by immutable LDAP JIT guards during a
 * verified retention prune. No runtime role receives relation access; the
 * row exists only inside the owner ABI transaction and is removed before
 * commit.
 */
export const tenantAuditRetentionPruneCapabilities = pgTable(
  "tenant_audit_retention_prune_capabilities",
  {
    backendPid: integer("backend_pid").notNull(),
    transactionId: bigint("transaction_id", { mode: "bigint" }).notNull(),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    segmentId: uuid("segment_id").notNull(),
    startSequence: bigint("start_sequence", { mode: "bigint" }).notNull(),
    endSequence: bigint("end_sequence", { mode: "bigint" }).notNull(),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    primaryKey({
      name: "tenant_audit_retention_prune_capabilities_pkey",
      columns: [table.backendPid, table.transactionId],
    }),
    foreignKey({
      name: "tenant_audit_retention_prune_capabilities_segment_fk",
      columns: [table.tenantId, table.segmentId],
      foreignColumns: [tenantAuditSegments.tenantId, tenantAuditSegments.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "tenant_audit_retention_prune_capabilities_shape_check",
      sql`${table.backendPid} > 0 and ${table.transactionId} > 0
        and ${table.startSequence} > 0 and ${table.endSequence} >= ${table.startSequence}`,
    ),
    pgPolicy("tenant_audit_retention_prune_capabilities_owner_all_v1", {
      as: "permissive",
      for: "all",
      to: auditOperationsOwnerRole,
      using: sql`true`,
      withCheck: sql`true`,
    }),
  ],
).enableRLS();

export const platformAuditRetentionAnchor = pgTable(
  "platform_audit_retention_anchor",
  {
    singleton: boolean("singleton").primaryKey().default(true),
    retainedThroughSequence: bigint("retained_through_sequence", {
      mode: "bigint",
    })
      .notNull()
      .default(sql`0`),
    retainedThroughHash: char("retained_through_hash", { length: 64 })
      .notNull()
      .default(zeroAuditHash),
    lastSegmentId: uuid("last_segment_id").references(
      () => platformAuditSegments.id,
      {
        onDelete: "restrict",
      },
    ),
    segmentDigest: bytea("segment_digest"),
    signingKeyId: text("signing_key_id"),
    signature: bytea("signature"),
    revision: bigint("revision", { mode: "bigint" })
      .notNull()
      .default(sql`1`),
    reason: text("reason").notNull().default("initial retention anchor"),
    updatedAt: timestamp("updated_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    check(
      "platform_audit_retention_anchor_singleton_check",
      sql`${table.singleton} is true`,
    ),
    check(
      "platform_audit_retention_anchor_shape_check",
      sql`${table.retainedThroughSequence} >= 0 and ${table.retainedThroughHash} ~ '^[0-9a-f]{64}$'
        and ${table.revision} between 1 and 9007199254740991
        and ${table.reason} = btrim(${table.reason}) and octet_length(${table.reason}) between 1 and 2048 and ${table.reason} !~ '[[:cntrl:]]'
        and ((${table.retainedThroughSequence} = 0 and ${table.retainedThroughHash} = ${zeroAuditHash}
              and ${table.lastSegmentId} is null and ${table.segmentDigest} is null and ${table.signingKeyId} is null and ${table.signature} is null)
          or (${table.retainedThroughSequence} > 0 and ${table.lastSegmentId} is not null and octet_length(${table.segmentDigest}) = 32
              and ${table.signingKeyId} ~ '^[a-z0-9][a-z0-9_.:-]{0,127}$' and octet_length(${table.signature}) = 64))`,
    ),
    pgPolicy("platform_audit_retention_anchor_owner_access", {
      as: "permissive",
      for: "all",
      to: auditOperationsOwnerRole,
      using: sql`true`,
      withCheck: sql`true`,
    }),
  ],
).enableRLS();
