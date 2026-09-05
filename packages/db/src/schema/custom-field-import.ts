import { sql } from "drizzle-orm";
import {
  bigint,
  check,
  foreignKey,
  index,
  inet,
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
import { currentTenantId } from "./context.js";
import { customFieldObjectType } from "./customfields.js";
import { tenantMemberships } from "./identity.js";
import { customFieldImportOwnerRole } from "./roles.js";
import { tenants } from "./tenancy.js";

const ownerPolicy = (name: string, tenantId: unknown) =>
  pgPolicy(name, {
    as: "permissive",
    for: "all",
    to: customFieldImportOwnerRole,
    using: sql`${tenantId} = ${currentTenantId}`,
    withCheck: sql`${tenantId} = ${currentTenantId}`,
  });

export const customFieldImportJobs = pgTable(
  "custom_field_import_jobs",
  {
    id: uuid("id").primaryKey(),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, {
        onDelete: "restrict",
        onUpdate: "restrict",
      }),
    requesterUserId: uuid("requester_user_id").notNull(),
    ownerMembershipId: uuid("owner_membership_id").notNull(),
    objectType: customFieldObjectType("object_type").notNull(),
    mode: text("mode").notNull(),
    manifestSnapshot: jsonb("manifest_snapshot")
      .$type<Record<string, unknown>>()
      .notNull(),
    requestDigest: bytea("request_digest").notNull(),
    projectionVersion: bigint("projection_version", {
      mode: "number",
    }).notNull(),
    maximumAttempts: smallint("maximum_attempts").notNull(),
    state: text("state").notNull(),
    revision: bigint("revision", { mode: "number" }).notNull(),
    attempts: smallint("attempts").notNull().default(0),
    total: integer("total").notNull(),
    dryRunValid: integer("dry_run_valid").notNull().default(0),
    committed: integer("committed").notNull().default(0),
    noChange: integer("no_change").notNull().default(0),
    validationFailed: integer("validation_failed").notNull().default(0),
    definitionChanged: integer("definition_changed").notNull().default(0),
    versionConflict: integer("version_conflict").notNull().default(0),
    notFoundOrHidden: integer("not_found_or_hidden").notNull().default(0),
    authorizationDenied: integer("authorization_denied").notNull().default(0),
    cancelled: integer("cancelled").notNull().default(0),
    authorizationRevoked: integer("authorization_revoked").notNull().default(0),
    expired: integer("expired").notNull().default(0),
    internalFailure: integer("internal_failure").notNull().default(0),
    requestId: uuid("request_id").notNull(),
    correlationId: uuid("correlation_id").notNull(),
    ipAddress: inet("ip_address").notNull(),
    userAgent: text("user_agent").notNull(),
    authenticationMethod: text("authentication_method").notNull(),
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
    fenceId: uuid("fence_id"),
    leaseUntil: timestamp("lease_until", {
      withTimezone: true,
      mode: "date",
    }),
    terminalAt: timestamp("terminal_at", {
      withTimezone: true,
      mode: "date",
    }),
  },
  (table) => [
    unique("custom_field_import_jobs_tenant_id_id_key").on(
      table.tenantId,
      table.id,
    ),
    unique("custom_field_import_jobs_exact_coordinate_key").on(
      table.tenantId,
      table.id,
      table.requesterUserId,
      table.ownerMembershipId,
      table.objectType,
    ),
    foreignKey({
      name: "custom_field_import_jobs_owner_fk",
      columns: [table.tenantId, table.ownerMembershipId, table.requesterUserId],
      foreignColumns: [
        tenantMemberships.tenantId,
        tenantMemberships.id,
        tenantMemberships.userId,
      ],
    })
      .onUpdate("restrict")
      .onDelete("restrict"),
    index("custom_field_import_jobs_claim_idx").on(
      table.tenantId,
      table.objectType,
      table.state,
      table.availableAt,
      table.id,
    ),
    index("custom_field_import_jobs_queue_idx").on(
      table.state,
      table.availableAt,
      table.tenantId,
      table.id,
    ),
    index("custom_field_import_jobs_owner_idx").on(
      table.tenantId,
      table.ownerMembershipId,
      table.requestedAt,
      table.id,
    ),
    check(
      "custom_field_import_jobs_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "custom_field_import_jobs_definition_check",
      sql`${table.mode} in ('dry_run','commit')
        and jsonb_typeof(${table.manifestSnapshot}) = 'object'
        and octet_length(${table.manifestSnapshot}::text) <= 34603008
        and octet_length(${table.requestDigest}) = 32
        and ${table.projectionVersion} = 1
        and ${table.maximumAttempts} between 1 and 5`,
    ),
    check(
      "custom_field_import_jobs_state_check",
      sql`${table.state} in ('pending','running','cancellation_requested','completed','failed','cancelled','authorization_revoked','expired')
        and ${table.revision} between 1 and 2147483646
        and ${table.attempts} between 0 and ${table.maximumAttempts}
        and ${table.total} between 1 and 10000
        and ${table.dryRunValid} >= 0 and ${table.committed} >= 0
        and ${table.noChange} >= 0 and ${table.validationFailed} >= 0
        and ${table.definitionChanged} >= 0 and ${table.versionConflict} >= 0
        and ${table.notFoundOrHidden} >= 0 and ${table.authorizationDenied} >= 0
        and ${table.cancelled} >= 0 and ${table.authorizationRevoked} >= 0
        and ${table.expired} >= 0 and ${table.internalFailure} >= 0
        and (${table.dryRunValid} + ${table.committed} + ${table.noChange}
          + ${table.validationFailed} + ${table.definitionChanged}
          + ${table.versionConflict} + ${table.notFoundOrHidden}
          + ${table.authorizationDenied} + ${table.cancelled}
          + ${table.authorizationRevoked} + ${table.expired}
          + ${table.internalFailure}) <= ${table.total}
        and ${table.updatedAt} >= ${table.requestedAt}
        and ${table.availableAt} >= ${table.requestedAt}
        and ${table.availableAt} <= ${table.expiresAt}
        and ${table.expiresAt} > ${table.requestedAt}
        and ((${table.fenceId} is null and ${table.leaseUntil} is null)
          or (${table.fenceId} is not null and ${table.leaseUntil} is not null))
        and (${table.terminalAt} is null) = (${table.state} not in ('completed','failed','cancelled','authorization_revoked','expired'))
        and (${table.leaseUntil} is null or (
          (uuid_extract_version(${table.fenceId}) = 7) is true
          and ${table.leaseUntil} > ${table.updatedAt}
          and ${table.leaseUntil} <= ${table.expiresAt}
          and ${table.leaseUntil} <= ${table.updatedAt} + interval '5 minutes'
        ))
        and (${table.terminalAt} is null or (
          ${table.terminalAt} = ${table.updatedAt}
          and ${table.terminalAt} >= ${table.requestedAt}
          and (${table.terminalAt} <= ${table.expiresAt}
            or ${table.state} in ('expired','cancelled'))
        ))
        and case ${table.state}
          when 'pending' then
            ${table.revision} = 1
            and ${table.attempts} = 0
            and ${table.fenceId} is null
            and ${table.terminalAt} is null
            and (${table.dryRunValid} + ${table.committed} + ${table.noChange}
              + ${table.validationFailed} + ${table.definitionChanged}
              + ${table.versionConflict} + ${table.notFoundOrHidden}
              + ${table.authorizationDenied} + ${table.cancelled}
              + ${table.authorizationRevoked} + ${table.expired}
              + ${table.internalFailure}) < ${table.total}
            and ${table.updatedAt} <= ${table.expiresAt}
            and ${table.availableAt} >= ${table.updatedAt}
          when 'running' then
            ${table.attempts} > 0
            and ${table.fenceId} is not null
            and ${table.terminalAt} is null
            and (${table.dryRunValid} + ${table.committed} + ${table.noChange}
              + ${table.validationFailed} + ${table.definitionChanged}
              + ${table.versionConflict} + ${table.notFoundOrHidden}
              + ${table.authorizationDenied} + ${table.cancelled}
              + ${table.authorizationRevoked} + ${table.expired}
              + ${table.internalFailure}) < ${table.total}
            and (${table.cancelled} + ${table.authorizationRevoked}
              + ${table.expired} + ${table.internalFailure}) = 0
            and ${table.updatedAt} <= ${table.expiresAt}
            and ${table.availableAt} <= ${table.updatedAt}
          when 'cancellation_requested' then
            ${table.attempts} > 0
            and ${table.fenceId} is not null
            and ${table.terminalAt} is null
            and (${table.dryRunValid} + ${table.committed} + ${table.noChange}
              + ${table.validationFailed} + ${table.definitionChanged}
              + ${table.versionConflict} + ${table.notFoundOrHidden}
              + ${table.authorizationDenied} + ${table.cancelled}
              + ${table.authorizationRevoked} + ${table.expired}
              + ${table.internalFailure}) < ${table.total}
            and (${table.cancelled} + ${table.authorizationRevoked}
              + ${table.expired} + ${table.internalFailure}) = 0
            and ${table.updatedAt} <= ${table.expiresAt}
          when 'completed' then
            ${table.fenceId} is null
            and ${table.terminalAt} is not null
            and (${table.dryRunValid} + ${table.committed} + ${table.noChange}
              + ${table.validationFailed} + ${table.definitionChanged}
              + ${table.versionConflict} + ${table.notFoundOrHidden}
              + ${table.authorizationDenied} + ${table.cancelled}
              + ${table.authorizationRevoked} + ${table.expired}
              + ${table.internalFailure}) = ${table.total}
            and (${table.cancelled} + ${table.authorizationRevoked}
              + ${table.expired} + ${table.internalFailure}) = 0
          when 'failed' then
            ${table.fenceId} is null
            and ${table.terminalAt} is not null
            and (${table.dryRunValid} + ${table.committed} + ${table.noChange}
              + ${table.validationFailed} + ${table.definitionChanged}
              + ${table.versionConflict} + ${table.notFoundOrHidden}
              + ${table.authorizationDenied} + ${table.cancelled}
              + ${table.authorizationRevoked} + ${table.expired}
              + ${table.internalFailure}) = ${table.total}
            and ${table.internalFailure} > 0
            and ${table.cancelled} = 0
            and ${table.authorizationRevoked} = 0
          when 'cancelled' then
            ${table.fenceId} is null
            and ${table.terminalAt} is not null
            and (${table.dryRunValid} + ${table.committed} + ${table.noChange}
              + ${table.validationFailed} + ${table.definitionChanged}
              + ${table.versionConflict} + ${table.notFoundOrHidden}
              + ${table.authorizationDenied} + ${table.cancelled}
              + ${table.authorizationRevoked} + ${table.expired}
              + ${table.internalFailure}) = ${table.total}
            and ${table.cancelled} > 0
            and ${table.authorizationRevoked} = 0
            and ${table.internalFailure} = 0
          when 'authorization_revoked' then
            ${table.fenceId} is null
            and ${table.terminalAt} is not null
            and (${table.dryRunValid} + ${table.committed} + ${table.noChange}
              + ${table.validationFailed} + ${table.definitionChanged}
              + ${table.versionConflict} + ${table.notFoundOrHidden}
              + ${table.authorizationDenied} + ${table.cancelled}
              + ${table.authorizationRevoked} + ${table.expired}
              + ${table.internalFailure}) = ${table.total}
            and ${table.authorizationRevoked} > 0
            and ${table.cancelled} = 0
            and ${table.expired} = 0
            and ${table.internalFailure} = 0
          when 'expired' then
            ${table.fenceId} is null
            and ${table.terminalAt} is not null
            and (${table.dryRunValid} + ${table.committed} + ${table.noChange}
              + ${table.validationFailed} + ${table.definitionChanged}
              + ${table.versionConflict} + ${table.notFoundOrHidden}
              + ${table.authorizationDenied} + ${table.cancelled}
              + ${table.authorizationRevoked} + ${table.expired}
              + ${table.internalFailure}) = ${table.total}
            and ${table.expired} > 0
            and ${table.cancelled} = 0
            and ${table.authorizationRevoked} = 0
            and ${table.internalFailure} = 0
          else false
        end`,
    ),
    check(
      "custom_field_import_jobs_audit_check",
      sql`octet_length(${table.userAgent}) <= 1024
        and ${table.userAgent} !~ '[[:cntrl:]]'
        and ${table.authenticationMethod} ~ '^[A-Za-z0-9][A-Za-z0-9._/-]{0,63}$'`,
    ),
    ownerPolicy("custom_field_import_jobs_owner_access", table.tenantId),
  ],
).enableRLS();

export const customFieldImportRows = pgTable(
  "custom_field_import_rows",
  {
    tenantId: uuid("tenant_id").notNull(),
    jobId: uuid("job_id").notNull(),
    sequence: integer("sequence").notNull(),
    targetId: uuid("target_id").notNull(),
    expectedVersion: bigint("expected_version", { mode: "number" }).notNull(),
    cellsSnapshot: jsonb("cells_snapshot").$type<unknown[]>().notNull(),
    cellsDigest: bytea("cells_digest").notNull(),
  },
  (table) => [
    primaryKey({
      name: "custom_field_import_rows_pkey",
      columns: [table.tenantId, table.jobId, table.sequence],
    }),
    unique("custom_field_import_rows_job_target_key").on(
      table.tenantId,
      table.jobId,
      table.targetId,
    ),
    unique("custom_field_import_rows_exact_coordinate_key").on(
      table.tenantId,
      table.jobId,
      table.sequence,
      table.targetId,
      table.expectedVersion,
    ),
    foreignKey({
      name: "custom_field_import_rows_job_fk",
      columns: [table.tenantId, table.jobId],
      foreignColumns: [
        customFieldImportJobs.tenantId,
        customFieldImportJobs.id,
      ],
    })
      .onUpdate("restrict")
      .onDelete("restrict"),
    index("custom_field_import_rows_sequence_idx").on(
      table.tenantId,
      table.jobId,
      table.sequence,
    ),
    check(
      "custom_field_import_rows_shape_check",
      sql`${table.sequence} between 1 and 10000
        and ${table.expectedVersion} between 1 and 9007199254740990
        and jsonb_typeof(${table.cellsSnapshot}) = 'array'
        and jsonb_array_length(${table.cellsSnapshot}) between 0 and 512
        and octet_length(${table.cellsSnapshot}::text) <= 33554432
        and octet_length(${table.cellsDigest}) = 32`,
    ),
    ownerPolicy("custom_field_import_rows_owner_access", table.tenantId),
  ],
).enableRLS();

export const customFieldImportResults = pgTable(
  "custom_field_import_results",
  {
    tenantId: uuid("tenant_id").notNull(),
    jobId: uuid("job_id").notNull(),
    sequence: integer("sequence").notNull(),
    outcome: text("outcome").notNull(),
    resultingVersion: bigint("resulting_version", { mode: "number" }).notNull(),
    fieldErrors: jsonb("field_errors").$type<unknown[]>().notNull(),
    commandKeyDigest: bytea("command_key_digest").notNull(),
    requestFingerprintDigest: bytea("request_fingerprint_digest").notNull(),
    recordedAt: timestamp("recorded_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
  },
  (table) => [
    primaryKey({
      name: "custom_field_import_results_pkey",
      columns: [table.tenantId, table.jobId, table.sequence],
    }),
    foreignKey({
      name: "custom_field_import_results_row_fk",
      columns: [table.tenantId, table.jobId, table.sequence],
      foreignColumns: [
        customFieldImportRows.tenantId,
        customFieldImportRows.jobId,
        customFieldImportRows.sequence,
      ],
    })
      .onUpdate("restrict")
      .onDelete("restrict"),
    index("custom_field_import_results_page_idx").on(
      table.tenantId,
      table.jobId,
      table.sequence,
    ),
    check(
      "custom_field_import_results_shape_check",
      sql`${table.sequence} between 1 and 10000
        and ${table.outcome} in ('dry_run_valid','committed','no_change','validation_failed','definition_changed','version_conflict','not_found_or_hidden','authorization_denied','cancelled','authorization_revoked','expired','internal_failure')
        and ${table.resultingVersion} between 0 and 9007199254740991
        and jsonb_typeof(${table.fieldErrors}) = 'array'
        and jsonb_array_length(${table.fieldErrors}) <= 512
        and octet_length(${table.fieldErrors}::text) <= 1048576
        and octet_length(${table.commandKeyDigest}) = 32
        and octet_length(${table.requestFingerprintDigest}) = 32`,
    ),
    ownerPolicy("custom_field_import_results_owner_access", table.tenantId),
  ],
).enableRLS();

export const customFieldImportCommandReceipts = pgTable(
  "custom_field_import_command_receipts",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id").notNull(),
    jobId: uuid("job_id").notNull(),
    actorUserId: uuid("actor_user_id").notNull(),
    ownerMembershipId: uuid("owner_membership_id").notNull(),
    objectType: customFieldObjectType("object_type").notNull(),
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
    unique("custom_field_import_command_receipts_replay_key").on(
      table.tenantId,
      table.actorUserId,
      table.ownerMembershipId,
      table.objectType,
      table.action,
      table.idempotencyKeyDigest,
    ),
    foreignKey({
      name: "custom_field_import_command_receipts_job_coordinate_fk",
      columns: [
        table.tenantId,
        table.jobId,
        table.actorUserId,
        table.ownerMembershipId,
        table.objectType,
      ],
      foreignColumns: [
        customFieldImportJobs.tenantId,
        customFieldImportJobs.id,
        customFieldImportJobs.requesterUserId,
        customFieldImportJobs.ownerMembershipId,
        customFieldImportJobs.objectType,
      ],
    })
      .onUpdate("restrict")
      .onDelete("restrict"),
    index("custom_field_import_command_receipts_expiry_idx").on(
      table.expiresAt,
      table.tenantId,
      table.id,
    ),
    check(
      "custom_field_import_command_receipts_shape_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true
        and ${table.action} in ('request','cancel')
        and octet_length(${table.idempotencyKeyDigest}) = 32
        and octet_length(${table.requestFingerprintDigest}) = 32
        and jsonb_typeof(${table.resultSnapshot}) = 'object'
        and octet_length(${table.resultSnapshot}::text) <= 34603008
        and ${table.expiresAt} > ${table.createdAt}`,
    ),
    ownerPolicy(
      "custom_field_import_command_receipts_owner_access",
      table.tenantId,
    ),
  ],
).enableRLS();
