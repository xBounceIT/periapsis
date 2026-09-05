import { sql } from "drizzle-orm";
import {
  bigint,
  boolean,
  check,
  customType,
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
  uuid,
} from "drizzle-orm/pg-core";

import { bytea } from "./binary.js";
import { ticketAggregateKind } from "./enums.js";
import { tenantMemberships } from "./identity.js";
import { ticketRuntimeOwnerRole } from "./roles.js";
import { tenants } from "./tenancy.js";

const canonicalText = customType<{ data: string; driverData: string }>({
  dataType() {
    return 'text COLLATE "C"';
  },
});

const ownerPolicy = (name: string) =>
  pgPolicy(name, {
    as: "permissive",
    for: "all",
    to: ticketRuntimeOwnerRole,
    using: sql`true`,
    withCheck: sql`true`,
  });

/** Global, non-customer worker identities admitted by the closed ticket ABI. */
export const ticketRuntimeServicePrincipals = pgTable(
  "ticket_runtime_service_principals",
  {
    id: uuid("id").primaryKey(),
    key: text("key").notNull(),
    enabled: boolean("enabled").notNull().default(true),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    unique("ticket_runtime_service_principals_key_key").on(table.key),
    check(
      "ticket_runtime_service_principals_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "ticket_runtime_service_principals_key_check",
      sql`${table.key} = 'ticket_runtime'`,
    ),
  ],
);

export const ticketBulkJobs = pgTable(
  "ticket_bulk_jobs",
  {
    id: uuid("id").primaryKey(),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    requesterUserId: uuid("requester_user_id").notNull(),
    ownerMembershipId: uuid("owner_membership_id").notNull(),
    kind: ticketAggregateKind("kind").notNull(),
    selectionSource: text("selection_source").notNull(),
    mutation: jsonb("mutation").$type<Record<string, unknown>>().notNull(),
    targetSetDigest: bytea("target_set_digest").notNull(),
    queryDigest: bytea("query_digest"),
    catalogDigest: bytea("catalog_digest"),
    savedViewId: uuid("saved_view_id"),
    savedViewRevision: bigint("saved_view_revision", { mode: "number" }),
    savedViewDigest: bytea("saved_view_digest"),
    projectionVersion: bigint("projection_version", { mode: "number" })
      .notNull()
      .default(1),
    maximumAttempts: smallint("maximum_attempts").notNull(),
    state: text("state").notNull(),
    revision: bigint("revision", { mode: "number" }).notNull(),
    total: integer("total").notNull(),
    succeeded: integer("succeeded").notNull().default(0),
    noChange: integer("no_change").notNull().default(0),
    versionConflict: integer("version_conflict").notNull().default(0),
    notFoundOrHidden: integer("not_found_or_hidden").notNull().default(0),
    authorizationDenied: integer("authorization_denied").notNull().default(0),
    rejected: integer("rejected").notNull().default(0),
    cancelled: integer("cancelled").notNull().default(0),
    authorizationRevoked: integer("authorization_revoked").notNull().default(0),
    internalFailure: integer("internal_failure").notNull().default(0),
    requestedAt: timestamp("requested_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    updatedAt: timestamp("updated_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    availableAt: timestamp("available_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    expiresAt: timestamp("expires_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    activeBatch: boolean("active_batch").notNull().default(false),
    terminalAt: timestamp("terminal_at", { withTimezone: true, mode: "date" }),
  },
  (table) => [
    unique("ticket_bulk_jobs_tenant_id_id_key").on(table.tenantId, table.id),
    foreignKey({
      name: "ticket_bulk_jobs_owner_fk",
      columns: [table.tenantId, table.ownerMembershipId, table.requesterUserId],
      foreignColumns: [
        tenantMemberships.tenantId,
        tenantMemberships.id,
        tenantMemberships.userId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    index("ticket_bulk_jobs_claim_idx").on(
      table.tenantId,
      table.kind,
      table.state,
      table.availableAt,
      table.id,
    ),
    index("ticket_bulk_jobs_owner_idx").on(
      table.tenantId,
      table.ownerMembershipId,
      table.requestedAt,
      table.id,
    ),
    check(
      "ticket_bulk_jobs_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "ticket_bulk_jobs_definition_check",
      sql`${table.selectionSource} in ('explicit', 'query')
        and jsonb_typeof(${table.mutation}) = 'object'
        and octet_length(${table.targetSetDigest}) = 32
        and ${table.projectionVersion} = 1
        and ${table.maximumAttempts} between 1 and 100
        and ((${table.selectionSource} = 'explicit'
              and ${table.queryDigest} is null
              and ${table.catalogDigest} is null
              and ${table.savedViewId} is null
              and ${table.savedViewRevision} is null
              and ${table.savedViewDigest} is null)
          or (${table.selectionSource} = 'query'
              and octet_length(${table.queryDigest}) = 32
              and octet_length(${table.catalogDigest}) = 32
              and ((${table.savedViewId} is null
                    and ${table.savedViewRevision} is null
                    and ${table.savedViewDigest} is null)
                or (${table.savedViewId} is not null
                    and ${table.savedViewRevision} between 1 and 9007199254740991
                    and octet_length(${table.savedViewDigest}) = 32))))`,
    ),
    check(
      "ticket_bulk_jobs_state_check",
      sql`${table.state} in ('pending','running','cancellation_requested','completed','failed','cancelled','authorization_revoked')
        and ${table.revision} between 1 and 9007199254740991
        and ${table.total} between 1 and 100000
        and ${table.succeeded} >= 0 and ${table.noChange} >= 0
        and ${table.versionConflict} >= 0 and ${table.notFoundOrHidden} >= 0
        and ${table.authorizationDenied} >= 0 and ${table.rejected} >= 0
        and ${table.cancelled} >= 0 and ${table.authorizationRevoked} >= 0
        and ${table.internalFailure} >= 0
        and (${table.succeeded} + ${table.noChange} + ${table.versionConflict}
          + ${table.notFoundOrHidden} + ${table.authorizationDenied}
          + ${table.rejected} + ${table.cancelled}
          + ${table.authorizationRevoked} + ${table.internalFailure}) <= ${table.total}
        and ${table.updatedAt} >= ${table.requestedAt}
        and ${table.availableAt} >= ${table.requestedAt}
        and ${table.expiresAt} > ${table.requestedAt}
        and (${table.terminalAt} is null) = (${table.state} not in ('completed','failed','cancelled','authorization_revoked'))`,
    ),
    ownerPolicy("ticket_bulk_jobs_owner_access"),
  ],
).enableRLS();

export const ticketBulkQuerySnapshots = pgTable(
  "ticket_bulk_query_snapshots",
  {
    tenantId: uuid("tenant_id").notNull(),
    jobId: uuid("job_id").notNull(),
    source: text("source").notNull(),
    specCanonical: canonicalText("spec_canonical").notNull(),
    queryDigest: bytea("query_digest").notNull(),
    catalogDigest: bytea("catalog_digest").notNull(),
    savedViewId: uuid("saved_view_id"),
    savedViewOwnerId: uuid("saved_view_owner_id"),
    savedViewRevision: bigint("saved_view_revision", { mode: "number" }),
    savedViewDigest: bytea("saved_view_digest"),
  },
  (table) => [
    primaryKey({
      name: "ticket_bulk_query_snapshots_pkey",
      columns: [table.jobId],
    }),
    foreignKey({
      name: "ticket_bulk_query_snapshots_job_fk",
      columns: [table.tenantId, table.jobId],
      foreignColumns: [ticketBulkJobs.tenantId, ticketBulkJobs.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "ticket_bulk_query_snapshots_shape_check",
      sql`${table.source} in ('inline','saved_view')
        and octet_length(${table.specCanonical}) between 1 and 262144
        and octet_length(${table.queryDigest}) = 32
        and octet_length(${table.catalogDigest}) = 32
        and ((${table.source} = 'inline'
              and ${table.savedViewId} is null
              and ${table.savedViewOwnerId} is null
              and ${table.savedViewRevision} is null
              and ${table.savedViewDigest} is null)
          or (${table.source} = 'saved_view'
              and ${table.savedViewId} is not null
              and ${table.savedViewOwnerId} is not null
              and ${table.savedViewRevision} between 1 and 9007199254740991
              and octet_length(${table.savedViewDigest}) = 32))`,
    ),
    ownerPolicy("ticket_bulk_query_snapshots_owner_access"),
  ],
).enableRLS();

export const ticketBulkTargets = pgTable(
  "ticket_bulk_targets",
  {
    tenantId: uuid("tenant_id").notNull(),
    jobId: uuid("job_id").notNull(),
    sequence: integer("sequence").notNull(),
    targetId: uuid("target_id").notNull(),
    targetVersion: bigint("target_version", { mode: "number" }).notNull(),
    result: text("result"),
    recordedAt: timestamp("recorded_at", { withTimezone: true, mode: "date" }),
  },
  (table) => [
    primaryKey({
      name: "ticket_bulk_targets_pkey",
      columns: [table.tenantId, table.jobId, table.sequence],
    }),
    unique("ticket_bulk_targets_job_target_key").on(
      table.tenantId,
      table.jobId,
      table.targetId,
    ),
    foreignKey({
      name: "ticket_bulk_targets_job_fk",
      columns: [table.tenantId, table.jobId],
      foreignColumns: [ticketBulkJobs.tenantId, ticketBulkJobs.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    index("ticket_bulk_targets_pending_idx").on(
      table.tenantId,
      table.jobId,
      table.result,
      table.sequence,
    ),
    check(
      "ticket_bulk_targets_shape_check",
      sql`${table.sequence} between 1 and 100000
        and ${table.targetVersion} between 1 and 9007199254740991
        and (${table.result} is null) = (${table.recordedAt} is null)
        and (${table.result} is null or ${table.result} in ('succeeded','no_change','version_conflict','not_found_or_hidden','authorization_denied','rejected','cancelled','authorization_revoked','internal_failure'))`,
    ),
    ownerPolicy("ticket_bulk_targets_owner_access"),
  ],
).enableRLS();

export const ticketBulkBatches = pgTable(
  "ticket_bulk_batches",
  {
    id: uuid("id").primaryKey(),
    tenantId: uuid("tenant_id").notNull(),
    jobId: uuid("job_id").notNull(),
    kind: ticketAggregateKind("kind").notNull(),
    workerId: uuid("worker_id").notNull(),
    revision: bigint("revision", { mode: "number" }).notNull(),
    attempt: smallint("attempt").notNull(),
    fenceDigest: bytea("fence_digest").notNull(),
    targetSetDigest: bytea("target_set_digest").notNull(),
    projectionVersion: bigint("projection_version", {
      mode: "number",
    }).notNull(),
    claimedAt: timestamp("claimed_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    leaseExpiresAt: timestamp("lease_expires_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    jobExpiresAt: timestamp("job_expires_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    state: text("state").notNull(),
    processed: integer("processed").notNull().default(0),
    receiptDigest: bytea("receipt_digest"),
    failureCode: text("failure_code"),
    retryAt: timestamp("retry_at", { withTimezone: true, mode: "date" }),
    completedAt: timestamp("completed_at", {
      withTimezone: true,
      mode: "date",
    }),
  },
  (table) => [
    unique("ticket_bulk_batches_tenant_job_id_key").on(
      table.tenantId,
      table.jobId,
      table.id,
    ),
    foreignKey({
      name: "ticket_bulk_batches_job_fk",
      columns: [table.tenantId, table.jobId],
      foreignColumns: [ticketBulkJobs.tenantId, ticketBulkJobs.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    index("ticket_bulk_batches_lease_idx").on(
      table.tenantId,
      table.kind,
      table.state,
      table.leaseExpiresAt,
      table.id,
    ),
    check(
      "ticket_bulk_batches_shape_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true
        and (uuid_extract_version(${table.workerId}) = 7) is true
        and ${table.revision} between 1 and 9007199254740991
        and ${table.attempt} between 1 and 100
        and octet_length(${table.fenceDigest}) = 32
        and octet_length(${table.targetSetDigest}) = 32
        and ${table.projectionVersion} = 1
        and ${table.leaseExpiresAt} > ${table.claimedAt}
        and ${table.jobExpiresAt} >= ${table.leaseExpiresAt}
        and ${table.state} in ('active','released','retry_scheduled','terminal')
        and ${table.processed} between 0 and 100`,
    ),
    ownerPolicy("ticket_bulk_batches_owner_access"),
  ],
).enableRLS();

export const ticketBulkCommandReceipts = pgTable(
  "ticket_bulk_command_receipts",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id").notNull(),
    jobId: uuid("job_id").notNull(),
    actorUserId: uuid("actor_user_id").notNull(),
    ownerMembershipId: uuid("owner_membership_id").notNull(),
    kind: ticketAggregateKind("kind").notNull(),
    action: text("action").notNull(),
    idempotencyKeyDigest: bytea("idempotency_key_digest").notNull(),
    requestFingerprintDigest: bytea("request_fingerprint_digest").notNull(),
    resultSnapshot: jsonb("result_snapshot")
      .$type<Record<string, unknown>>()
      .notNull(),
    createdAt: timestamp("created_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    expiresAt: timestamp("expires_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
  },
  (table) => [
    unique("ticket_bulk_command_receipts_replay_key").on(
      table.tenantId,
      table.actorUserId,
      table.ownerMembershipId,
      table.kind,
      table.action,
      table.idempotencyKeyDigest,
    ),
    foreignKey({
      name: "ticket_bulk_command_receipts_job_fk",
      columns: [table.tenantId, table.jobId],
      foreignColumns: [ticketBulkJobs.tenantId, ticketBulkJobs.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    index("ticket_bulk_command_receipts_expiry_idx").on(
      table.expiresAt,
      table.tenantId,
      table.id,
    ),
    check(
      "ticket_bulk_command_receipts_shape_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true
        and octet_length(${table.idempotencyKeyDigest}) = 32
        and octet_length(${table.requestFingerprintDigest}) = 32
        and jsonb_typeof(${table.resultSnapshot}) = 'object'
        and octet_length(${table.resultSnapshot}::text) <= 1048576
        and ${table.expiresAt} > ${table.createdAt}`,
    ),
    ownerPolicy("ticket_bulk_command_receipts_owner_access"),
  ],
).enableRLS();

export const ticketExportJobs = pgTable(
  "ticket_export_jobs",
  {
    id: uuid("id").primaryKey(),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    requesterUserId: uuid("requester_user_id").notNull(),
    ownerMembershipId: uuid("owner_membership_id").notNull(),
    customerContactId: uuid("customer_contact_id"),
    kind: ticketAggregateKind("kind").notNull(),
    audience: text("audience").notNull(),
    commentScope: text("comment_scope").notNull(),
    querySource: text("query_source").notNull(),
    savedViewId: uuid("saved_view_id"),
    savedViewOwnerId: uuid("saved_view_owner_id"),
    savedViewRevision: bigint("saved_view_revision", { mode: "number" }),
    savedViewDigest: bytea("saved_view_digest"),
    queryDigest: bytea("query_digest").notNull(),
    catalogDigest: bytea("catalog_digest").notNull(),
    projectionVersion: bigint("projection_version", {
      mode: "number",
    }).notNull(),
    format: text("format").notNull(),
    maximumRows: integer("maximum_rows").notNull(),
    maximumBytes: bigint("maximum_bytes", { mode: "number" }).notNull(),
    maximumAttempts: smallint("maximum_attempts").notNull(),
    state: text("state").notNull(),
    revision: bigint("revision", { mode: "number" }).notNull(),
    attempts: smallint("attempts").notNull(),
    failureCode: text("failure_code").notNull(),
    requestedAt: timestamp("requested_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    updatedAt: timestamp("updated_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    availableAt: timestamp("available_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    expiresAt: timestamp("expires_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    leaseWorkerId: uuid("lease_worker_id"),
    leaseFenceDigest: bytea("lease_fence_digest"),
    leaseClaimedAt: timestamp("lease_claimed_at", {
      withTimezone: true,
      mode: "date",
    }),
    leaseExpiresAt: timestamp("lease_expires_at", {
      withTimezone: true,
      mode: "date",
    }),
    artifactId: uuid("artifact_id"),
    artifactDigest: bytea("artifact_digest"),
    artifactRows: integer("artifact_rows"),
    artifactBytes: bigint("artifact_bytes", { mode: "number" }),
    artifactExpiresAt: timestamp("artifact_expires_at", {
      withTimezone: true,
      mode: "date",
    }),
    terminalAt: timestamp("terminal_at", { withTimezone: true, mode: "date" }),
  },
  (table) => [
    unique("ticket_export_jobs_tenant_id_id_key").on(table.tenantId, table.id),
    foreignKey({
      name: "ticket_export_jobs_owner_fk",
      columns: [table.tenantId, table.ownerMembershipId, table.requesterUserId],
      foreignColumns: [
        tenantMemberships.tenantId,
        tenantMemberships.id,
        tenantMemberships.userId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    index("ticket_export_jobs_claim_idx").on(
      table.tenantId,
      table.kind,
      table.audience,
      table.state,
      table.availableAt,
      table.id,
    ),
    index("ticket_export_jobs_owner_idx").on(
      table.tenantId,
      table.ownerMembershipId,
      table.requestedAt,
      table.id,
    ),
    check(
      "ticket_export_jobs_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "ticket_export_jobs_definition_check",
      sql`${table.audience} in ('operator','customer')
        and ${table.commentScope} in ('none','public','public_and_private')
        and (${table.audience} = 'operator' or ${table.commentScope} <> 'public_and_private')
        and ${table.querySource} in ('inline','saved_view')
        and ((${table.querySource} = 'inline'
              and ${table.savedViewId} is null
              and ${table.savedViewOwnerId} is null
              and ${table.savedViewRevision} is null
              and ${table.savedViewDigest} is null)
          or (${table.querySource} = 'saved_view'
              and ${table.savedViewId} is not null
              and ${table.savedViewOwnerId} is not null
              and ${table.savedViewRevision} between 1 and 9007199254740991
              and octet_length(${table.savedViewDigest}) = 32))
        and octet_length(${table.queryDigest}) = 32
        and octet_length(${table.catalogDigest}) = 32
        and ${table.projectionVersion} = 1
        and ${table.format} = 'csv'
        and ${table.maximumRows} between 1 and 1000000
        and ${table.maximumBytes} between 1 and 1073741824
        and ${table.maximumAttempts} between 1 and 100`,
    ),
    check(
      "ticket_export_jobs_state_check",
      sql`${table.state} in ('pending','running','cancellation_requested','succeeded','failed','cancelled')
        and ${table.revision} between 1 and 9007199254740991
        and ${table.attempts} between 0 and ${table.maximumAttempts}
        and ${table.failureCode} in ('none','transient_storage','transient_database','authorization_revoked','snapshot_stale','output_limit','lease_expired','expired','internal')
        and ${table.updatedAt} >= ${table.requestedAt}
        and ${table.availableAt} >= ${table.requestedAt}
        and ${table.expiresAt} > ${table.requestedAt}
        and ((${table.leaseWorkerId} is null and ${table.leaseFenceDigest} is null
              and ${table.leaseClaimedAt} is null and ${table.leaseExpiresAt} is null)
          or (${table.leaseWorkerId} is not null
              and octet_length(${table.leaseFenceDigest}) = 32
              and ${table.leaseExpiresAt} > ${table.leaseClaimedAt}))
        and ((${table.artifactId} is null and ${table.artifactDigest} is null
              and ${table.artifactRows} is null and ${table.artifactBytes} is null
              and ${table.artifactExpiresAt} is null)
          or (${table.artifactId} is not null
              and octet_length(${table.artifactDigest}) = 32
              and ${table.artifactRows} >= 0 and ${table.artifactBytes} > 0
              and ${table.artifactExpiresAt} > ${table.requestedAt}))
        and (${table.terminalAt} is null) = (${table.state} not in ('succeeded','failed','cancelled'))`,
    ),
    ownerPolicy("ticket_export_jobs_owner_access"),
  ],
).enableRLS();

export const ticketExportQuerySnapshots = pgTable(
  "ticket_export_query_snapshots",
  {
    tenantId: uuid("tenant_id").notNull(),
    jobId: uuid("job_id").notNull(),
    specCanonical: canonicalText("spec_canonical").notNull(),
    queryDigest: bytea("query_digest").notNull(),
    catalogDigest: bytea("catalog_digest").notNull(),
  },
  (table) => [
    primaryKey({
      name: "ticket_export_query_snapshots_pkey",
      columns: [table.jobId],
    }),
    foreignKey({
      name: "ticket_export_query_snapshots_job_fk",
      columns: [table.tenantId, table.jobId],
      foreignColumns: [ticketExportJobs.tenantId, ticketExportJobs.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "ticket_export_query_snapshots_shape_check",
      sql`octet_length(${table.specCanonical}) between 1 and 262144
        and octet_length(${table.queryDigest}) = 32
        and octet_length(${table.catalogDigest}) = 32`,
    ),
    ownerPolicy("ticket_export_query_snapshots_owner_access"),
  ],
).enableRLS();

export const ticketExportManifests = pgTable(
  "ticket_export_manifests",
  {
    tenantId: uuid("tenant_id").notNull(),
    jobId: uuid("job_id").notNull(),
    artifactId: uuid("artifact_id").notNull(),
    jobRevision: bigint("job_revision", { mode: "number" }).notNull(),
    attempt: smallint("attempt").notNull(),
    projectionVersion: bigint("projection_version", {
      mode: "number",
    }).notNull(),
    digest: bytea("digest").notNull(),
    rows: integer("rows").notNull(),
    bytes: bigint("bytes", { mode: "number" }).notNull(),
    recordedAt: timestamp("recorded_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    expiresAt: timestamp("expires_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    publishedAt: timestamp("published_at", {
      withTimezone: true,
      mode: "date",
    }),
  },
  (table) => [
    primaryKey({
      name: "ticket_export_manifests_pkey",
      columns: [table.tenantId, table.jobId, table.artifactId],
    }),
    unique("ticket_export_manifests_artifact_id_key").on(table.artifactId),
    unique("ticket_export_manifests_job_attempt_key").on(
      table.tenantId,
      table.jobId,
      table.attempt,
    ),
    foreignKey({
      name: "ticket_export_manifests_job_fk",
      columns: [table.tenantId, table.jobId],
      foreignColumns: [ticketExportJobs.tenantId, ticketExportJobs.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    index("ticket_export_manifests_expiry_idx").on(
      table.tenantId,
      table.expiresAt,
      table.artifactId,
    ),
    check(
      "ticket_export_manifests_shape_check",
      sql`(uuid_extract_version(${table.artifactId}) = 7) is true
        and ${table.jobRevision} between 1 and 9007199254740991
        and ${table.attempt} between 1 and 100
        and ${table.projectionVersion} = 1
        and octet_length(${table.digest}) = 32
        and ${table.rows} >= 0 and ${table.bytes} > 0
        and ${table.expiresAt} > ${table.recordedAt}
        and (${table.publishedAt} is null or ${table.publishedAt} >= ${table.recordedAt})`,
    ),
    ownerPolicy("ticket_export_manifests_owner_access"),
  ],
).enableRLS();

export const ticketExportCommandReceipts = pgTable(
  "ticket_export_command_receipts",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id").notNull(),
    jobId: uuid("job_id").notNull(),
    actorUserId: uuid("actor_user_id").notNull(),
    ownerMembershipId: uuid("owner_membership_id").notNull(),
    kind: ticketAggregateKind("kind").notNull(),
    audience: text("audience").notNull(),
    action: text("action").notNull(),
    idempotencyKeyDigest: bytea("idempotency_key_digest").notNull(),
    requestFingerprintDigest: bytea("request_fingerprint_digest").notNull(),
    resultSnapshot: jsonb("result_snapshot")
      .$type<Record<string, unknown>>()
      .notNull(),
    createdAt: timestamp("created_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    expiresAt: timestamp("expires_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
  },
  (table) => [
    unique("ticket_export_command_receipts_replay_key").on(
      table.tenantId,
      table.actorUserId,
      table.ownerMembershipId,
      table.kind,
      table.audience,
      table.action,
      table.idempotencyKeyDigest,
    ),
    foreignKey({
      name: "ticket_export_command_receipts_job_fk",
      columns: [table.tenantId, table.jobId],
      foreignColumns: [ticketExportJobs.tenantId, ticketExportJobs.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    index("ticket_export_command_receipts_expiry_idx").on(
      table.expiresAt,
      table.tenantId,
      table.id,
    ),
    check(
      "ticket_export_command_receipts_shape_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true
        and ${table.audience} in ('operator','customer')
        and octet_length(${table.idempotencyKeyDigest}) = 32
        and octet_length(${table.requestFingerprintDigest}) = 32
        and jsonb_typeof(${table.resultSnapshot}) = 'object'
        and octet_length(${table.resultSnapshot}::text) <= 1048576
        and ${table.expiresAt} > ${table.createdAt}`,
    ),
    ownerPolicy("ticket_export_command_receipts_owner_access"),
  ],
).enableRLS();

export const ticketExportArtifactCleanups = pgTable(
  "ticket_export_artifact_cleanups",
  {
    tenantId: uuid("tenant_id").notNull(),
    jobId: uuid("job_id").notNull(),
    artifactId: uuid("artifact_id").notNull(),
    kind: ticketAggregateKind("kind").notNull(),
    audience: text("audience").notNull(),
    reason: text("reason").notNull(),
    jobRevision: bigint("job_revision", { mode: "number" }).notNull(),
    cleanupRevision: bigint("cleanup_revision", { mode: "number" }).notNull(),
    cleanupAttempt: smallint("cleanup_attempt").notNull(),
    state: text("state").notNull(),
    eligibleAt: timestamp("eligible_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    workerId: uuid("worker_id"),
    cleanupFence: bytea("cleanup_fence"),
    claimedAt: timestamp("claimed_at", { withTimezone: true, mode: "date" }),
    leaseExpiresAt: timestamp("lease_expires_at", {
      withTimezone: true,
      mode: "date",
    }),
    failureCode: text("failure_code"),
    retryAt: timestamp("retry_at", { withTimezone: true, mode: "date" }),
    completedAt: timestamp("completed_at", {
      withTimezone: true,
      mode: "date",
    }),
    updatedAt: timestamp("updated_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
  },
  (table) => [
    primaryKey({
      name: "ticket_export_artifact_cleanups_pkey",
      columns: [table.tenantId, table.artifactId],
    }),
    foreignKey({
      name: "ticket_export_artifact_cleanups_manifest_fk",
      columns: [table.tenantId, table.jobId, table.artifactId],
      foreignColumns: [
        ticketExportManifests.tenantId,
        ticketExportManifests.jobId,
        ticketExportManifests.artifactId,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    index("ticket_export_artifact_cleanups_queue_idx").on(
      table.tenantId,
      table.kind,
      table.audience,
      table.state,
      table.eligibleAt,
      table.artifactId,
    ),
    index("ticket_export_artifact_cleanups_lease_idx").on(
      table.state,
      table.leaseExpiresAt,
      table.artifactId,
    ),
    check(
      "ticket_export_artifact_cleanups_shape_check",
      sql`${table.audience} in ('operator','customer')
        and ${table.reason} in ('expired','orphaned')
        and ${table.jobRevision} between 1 and 9007199254740991
        and ${table.cleanupRevision} between 1 and 9007199254740991
        and ${table.cleanupAttempt} between 0 and 100
        and ${table.state} in ('pending','leased','retry_scheduled','dead_lettered','completed')
        and ((${table.state} = 'leased'
              and ${table.workerId} is not null
              and octet_length(${table.cleanupFence}) = 32
              and ${table.claimedAt} is not null
              and ${table.leaseExpiresAt} > ${table.claimedAt})
          or (${table.state} <> 'leased'
              and ${table.workerId} is null
              and ${table.cleanupFence} is null
              and ${table.claimedAt} is null
              and ${table.leaseExpiresAt} is null))
        and (${table.state} = 'completed') = (${table.completedAt} is not null)
        and (${table.state} = 'retry_scheduled') = (${table.retryAt} is not null)
        and ${table.updatedAt} >= ${table.eligibleAt}`,
    ),
    ownerPolicy("ticket_export_artifact_cleanups_owner_access"),
  ],
).enableRLS();
