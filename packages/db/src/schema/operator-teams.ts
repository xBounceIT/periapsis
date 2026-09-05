import { sql } from "drizzle-orm";
import {
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

import { tenantAuthorizationSources } from "./authorization.js";
import { bytea } from "./binary.js";
import { tenantMemberships, users } from "./identity.js";
import { tenants } from "./tenancy.js";

export const operatorTeams = pgTable(
  "operator_teams",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    key: text("key").notNull(),
    displayName: text("display_name").notNull(),
    description: text("description").notNull(),
    version: integer("version").notNull().default(1),
    createdByUserId: uuid("created_by_user_id").references(() => users.id, {
      onDelete: "restrict",
    }),
    archivedAt: timestamp("archived_at", {
      withTimezone: true,
      mode: "date",
    }),
    archivedByUserId: uuid("archived_by_user_id").references(() => users.id, {
      onDelete: "restrict",
    }),
    archiveReason: text("archive_reason"),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    unique("operator_teams_key_key").on(table.key),
    index("operator_teams_active_idx")
      .on(table.id)
      .where(sql`${table.archivedAt} is null`),
    check(
      "operator_teams_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "operator_teams_key_canonical_check",
      sql`${table.key} ~ '^[a-z][a-z0-9_]{2,63}$'`,
    ),
    check(
      "operator_teams_display_name_check",
      sql`btrim(${table.displayName}) <> '' and char_length(${table.displayName}) <= 120 and ${table.displayName} !~ '[[:cntrl:]]'`,
    ),
    check(
      "operator_teams_description_check",
      sql`char_length(${table.description}) <= 500 and ${table.description} !~ '[[:cntrl:]]'`,
    ),
    check("operator_teams_version_check", sql`${table.version} > 0`),
    check(
      "operator_teams_archive_check",
      sql`(${table.archivedAt} is null and ${table.archivedByUserId} is null and ${table.archiveReason} is null)
        or (${table.archivedAt} is not null
          and ${table.archivedByUserId} is not null
          and ${table.archiveReason} is not null
          and ${table.archivedAt} >= ${table.createdAt}
          and btrim(${table.archiveReason}) <> ''
          and char_length(${table.archiveReason}) <= 500
          and ${table.archiveReason} !~ '[[:cntrl:]]')`,
    ),
    check(
      "operator_teams_timestamps_check",
      sql`${table.updatedAt} >= ${table.createdAt} and (${table.archivedAt} is null or ${table.updatedAt} >= ${table.archivedAt})`,
    ),
  ],
).enableRLS();

export const platformCommands = pgTable(
  "platform_commands",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    actorUserId: uuid("actor_user_id")
      .notNull()
      .references(() => users.id, { onDelete: "restrict" }),
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
    unique("platform_commands_replay_key").on(
      table.actorUserId,
      table.operation,
      table.keyDigest,
    ),
    index("platform_commands_expiry_idx").on(table.expiresAt),
    check(
      "platform_commands_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "platform_commands_operation_check",
      sql`${table.operation} in ('operator_team.create', 'platform.tenant_access.authorize')`,
    ),
    check(
      "platform_commands_digest_check",
      sql`octet_length(${table.keyDigest}) = 32 and octet_length(${table.requestDigest}) = 32`,
    ),
    check(
      "platform_commands_result_version_check",
      sql`${table.resultVersion} > 0`,
    ),
    check(
      "platform_commands_retention_check",
      sql`${table.expiresAt} > ${table.createdAt} and ${table.expiresAt} <= ${table.createdAt} + interval '7 days'`,
    ),
  ],
).enableRLS();

export const operatorTeamAssignmentEpochs = pgTable(
  "operator_team_assignment_epochs",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    operatorTeamId: uuid("operator_team_id")
      .notNull()
      .references(() => operatorTeams.id, { onDelete: "restrict" }),
    assignedByMembershipId: uuid("assigned_by_membership_id").notNull(),
    assignmentReason: text("assignment_reason").notNull(),
    assignedAt: timestamp("assigned_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    endedAt: timestamp("ended_at", { withTimezone: true, mode: "date" }),
    endedByMembershipId: uuid("ended_by_membership_id"),
    endReason: text("end_reason"),
    version: integer("version").notNull().default(1),
    updatedAt: timestamp("updated_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    unique("operator_team_assignment_epochs_tenant_id_key").on(
      table.tenantId,
      table.id,
    ),
    unique("operator_team_assignment_epochs_exact_team_key").on(
      table.tenantId,
      table.id,
      table.operatorTeamId,
    ),
    uniqueIndex("operator_team_assignment_epochs_active_key")
      .on(table.tenantId, table.operatorTeamId)
      .where(sql`${table.endedAt} is null`),
    index("operator_team_assignment_epochs_active_team_idx")
      .on(table.operatorTeamId)
      .where(sql`${table.endedAt} is null`),
    index("operator_team_assignment_epochs_tenant_team_idx").on(
      table.tenantId,
      table.operatorTeamId,
      table.assignedAt,
      table.id,
    ),
    foreignKey({
      name: "operator_team_assignment_epochs_assigner_fk",
      columns: [table.tenantId, table.assignedByMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "operator_team_assignment_epochs_ender_fk",
      columns: [table.tenantId, table.endedByMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "operator_team_assignment_epochs_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "operator_team_assignment_epochs_assignment_reason_check",
      sql`btrim(${table.assignmentReason}) <> '' and char_length(${table.assignmentReason}) <= 500 and ${table.assignmentReason} !~ '[[:cntrl:]]'`,
    ),
    check(
      "operator_team_assignment_epochs_end_check",
      sql`(${table.endedAt} is null and ${table.endedByMembershipId} is null and ${table.endReason} is null)
        or (${table.endedAt} is not null
          and ${table.endedByMembershipId} is not null
          and ${table.endReason} is not null
          and ${table.endedAt} >= ${table.assignedAt}
          and btrim(${table.endReason}) <> ''
          and char_length(${table.endReason}) <= 500
          and ${table.endReason} !~ '[[:cntrl:]]')`,
    ),
    check(
      "operator_team_assignment_epochs_version_check",
      sql`${table.version} > 0`,
    ),
    check(
      "operator_team_assignment_epochs_updated_check",
      sql`${table.updatedAt} >= ${table.assignedAt} and (${table.endedAt} is null or ${table.updatedAt} >= ${table.endedAt})`,
    ),
  ],
).enableRLS();

export const operatorTeamRosterEntries = pgTable(
  "operator_team_roster_entries",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    assignmentEpochId: uuid("assignment_epoch_id").notNull(),
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
    unique("operator_team_roster_entries_tenant_id_key").on(
      table.tenantId,
      table.id,
    ),
    uniqueIndex("operator_team_roster_entries_active_key")
      .on(
        table.tenantId,
        table.assignmentEpochId,
        table.membershipId,
        table.sourceId,
      )
      .where(sql`${table.revokedAt} is null`),
    index("operator_team_roster_entries_effective_idx")
      .on(
        table.tenantId,
        table.membershipId,
        table.assignmentEpochId,
        table.expiresAt,
      )
      .where(sql`${table.revokedAt} is null`),
    index("operator_team_roster_entries_epoch_idx").on(
      table.tenantId,
      table.assignmentEpochId,
      table.id,
    ),
    index("operator_team_roster_entries_source_idx").on(
      table.tenantId,
      table.sourceId,
      table.assignmentEpochId,
      table.id,
    ),
    foreignKey({
      name: "operator_team_roster_entries_epoch_fk",
      columns: [table.tenantId, table.assignmentEpochId],
      foreignColumns: [
        operatorTeamAssignmentEpochs.tenantId,
        operatorTeamAssignmentEpochs.id,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "operator_team_roster_entries_membership_fk",
      columns: [table.tenantId, table.membershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "operator_team_roster_entries_source_fk",
      columns: [table.tenantId, table.sourceId],
      foreignColumns: [
        tenantAuthorizationSources.tenantId,
        tenantAuthorizationSources.id,
      ],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "operator_team_roster_entries_grantor_fk",
      columns: [table.tenantId, table.grantedByMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    foreignKey({
      name: "operator_team_roster_entries_revoker_fk",
      columns: [table.tenantId, table.revokedByMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    })
      .onUpdate("cascade")
      .onDelete("restrict"),
    check(
      "operator_team_roster_entries_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "operator_team_roster_entries_expiry_check",
      sql`${table.expiresAt} is null or ${table.expiresAt} > ${table.grantedAt}`,
    ),
    check(
      "operator_team_roster_entries_reason_check",
      sql`btrim(${table.grantReason}) <> '' and char_length(${table.grantReason}) <= 500 and ${table.grantReason} !~ '[[:cntrl:]]'`,
    ),
    check(
      "operator_team_roster_entries_revocation_check",
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
      "operator_team_roster_entries_version_check",
      sql`${table.version} > 0`,
    ),
    check(
      "operator_team_roster_entries_updated_check",
      sql`${table.updatedAt} >= ${table.grantedAt} and (${table.revokedAt} is null or ${table.updatedAt} >= ${table.revokedAt})`,
    ),
  ],
).enableRLS();
