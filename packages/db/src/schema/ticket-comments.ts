import { sql } from "drizzle-orm";
import {
  boolean,
  check,
  foreignKey,
  index,
  integer,
  pgPolicy,
  pgTable,
  text,
  timestamp,
  unique,
  uuid,
} from "drizzle-orm/pg-core";

import { alerts } from "./alerts.js";
import { bytea } from "./binary.js";
import { dfirAttachments } from "./dfir.js";
import { ticketCommentVisibility } from "./enums.js";
import { tenantMemberships } from "./identity.js";
import { ticketRuntimeOwnerRole } from "./roles.js";
import { tenants } from "./tenancy.js";
import { cases, ticketComments } from "./ticketing.js";

const ownerPolicy = (name: string) =>
  pgPolicy(name, {
    as: "permissive",
    for: "all",
    to: ticketRuntimeOwnerRole,
    using: sql`true`,
    withCheck: sql`true`,
  });

/** Immutable body and relation-set revision of one ticket comment. */
export const ticketCommentRevisions = pgTable(
  "ticket_comment_revisions",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    commentId: uuid("comment_id").notNull(),
    revision: integer("revision").notNull(),
    bodyMarkdown: text("body_markdown").notNull(),
    bodyHtml: text("body_html").notNull(),
    reason: text("reason").notNull(),
    editedByMembershipId: uuid("edited_by_membership_id").notNull(),
    editedByUserId: uuid("edited_by_user_id").notNull(),
    editedAt: timestamp("edited_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
  },
  (table) => [
    unique("ticket_comment_revisions_tenant_id_key").on(
      table.tenantId,
      table.id,
    ),
    unique("ticket_comment_revisions_comment_revision_key").on(
      table.tenantId,
      table.commentId,
      table.revision,
    ),
    foreignKey({
      name: "ticket_comment_revisions_comment_fk",
      columns: [table.tenantId, table.commentId],
      foreignColumns: [ticketComments.tenantId, ticketComments.id],
    })
      .onUpdate("restrict")
      .onDelete("restrict"),
    foreignKey({
      name: "ticket_comment_revisions_editor_fk",
      columns: [
        table.tenantId,
        table.editedByMembershipId,
        table.editedByUserId,
      ],
      foreignColumns: [
        tenantMemberships.tenantId,
        tenantMemberships.id,
        tenantMemberships.userId,
      ],
    })
      .onUpdate("restrict")
      .onDelete("restrict"),
    index("ticket_comment_revisions_history_idx").on(
      table.tenantId,
      table.commentId,
      table.revision,
    ),
    check(
      "ticket_comment_revisions_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "ticket_comment_revisions_revision_check",
      sql`${table.revision} between 1 and 2147483647`,
    ),
    check(
      "ticket_comment_revisions_body_check",
      sql`app.private_ticket_comment_markdown_valid_v1(${table.bodyMarkdown})
        and app.private_ticket_comment_html_valid_v1(${table.bodyHtml})`,
    ),
    check(
      "ticket_comment_revisions_reason_check",
      sql`(${table.revision} = 1 and ${table.reason} = 'original_comment')
        or (${table.revision} > 1
          and app.private_ticket_comment_edit_reason_valid_v1(${table.reason}))`,
    ),
    check(
      "ticket_comment_revisions_timestamp_check",
      sql`app.private_ticket_comment_timestamp_valid_v1(${table.editedAt})`,
    ),
    ownerPolicy("ticket_comment_revisions_owner_access"),
  ],
).enableRLS();

/** Frozen attachment labels for one exact comment revision. */
export const ticketCommentRevisionAttachments = pgTable(
  "ticket_comment_revision_attachments",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    revisionId: uuid("revision_id").notNull(),
    attachmentId: uuid("attachment_id").notNull(),
    originalFilename: text("original_filename").notNull(),
    visibility: ticketCommentVisibility("visibility").notNull(),
  },
  (table) => [
    unique("ticket_comment_revision_attachments_tenant_id_key").on(
      table.tenantId,
      table.id,
    ),
    unique("ticket_comment_revision_attachments_revision_key").on(
      table.tenantId,
      table.revisionId,
      table.attachmentId,
    ),
    foreignKey({
      name: "ticket_comment_revision_attachments_revision_fk",
      columns: [table.tenantId, table.revisionId],
      foreignColumns: [
        ticketCommentRevisions.tenantId,
        ticketCommentRevisions.id,
      ],
    })
      .onUpdate("restrict")
      .onDelete("restrict"),
    foreignKey({
      name: "ticket_comment_revision_attachments_attachment_fk",
      columns: [table.tenantId, table.attachmentId],
      foreignColumns: [dfirAttachments.tenantId, dfirAttachments.id],
    })
      .onUpdate("restrict")
      .onDelete("restrict"),
    check(
      "ticket_comment_revision_attachments_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "ticket_comment_revision_attachments_filename_check",
      sql`app.private_ticket_comment_filename_valid_v1(${table.originalFilename})`,
    ),
    ownerPolicy("ticket_comment_revision_attachments_owner_access"),
  ],
).enableRLS();

/** Frozen active-operator mentions for one exact comment revision. */
export const ticketCommentRevisionMentions = pgTable(
  "ticket_comment_revision_mentions",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    revisionId: uuid("revision_id").notNull(),
    mentionedMembershipId: uuid("mentioned_membership_id").notNull(),
    mentionedUserId: uuid("mentioned_user_id").notNull(),
    displayName: text("display_name").notNull(),
  },
  (table) => [
    unique("ticket_comment_revision_mentions_tenant_id_key").on(
      table.tenantId,
      table.id,
    ),
    unique("ticket_comment_revision_mentions_revision_key").on(
      table.tenantId,
      table.revisionId,
      table.mentionedMembershipId,
    ),
    foreignKey({
      name: "ticket_comment_revision_mentions_revision_fk",
      columns: [table.tenantId, table.revisionId],
      foreignColumns: [
        ticketCommentRevisions.tenantId,
        ticketCommentRevisions.id,
      ],
    })
      .onUpdate("restrict")
      .onDelete("restrict"),
    foreignKey({
      name: "ticket_comment_revision_mentions_membership_fk",
      columns: [
        table.tenantId,
        table.mentionedMembershipId,
        table.mentionedUserId,
      ],
      foreignColumns: [
        tenantMemberships.tenantId,
        tenantMemberships.id,
        tenantMemberships.userId,
      ],
    })
      .onUpdate("restrict")
      .onDelete("restrict"),
    check(
      "ticket_comment_revision_mentions_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "ticket_comment_revision_mentions_display_name_check",
      sql`app.private_ticket_comment_display_name_valid_v1(${table.displayName})`,
    ),
    ownerPolicy("ticket_comment_revision_mentions_owner_access"),
  ],
).enableRLS();

/**
 * Global reservation for one tenant actor and raw idempotency-key digest.
 * Legacy keys that name more than one predecessor command are retained as an
 * explicit ambiguous tombstone and can never be replayed or rebound.
 */
export const ticketCommentIdempotencyKeys = pgTable(
  "ticket_comment_idempotency_keys",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    actorMembershipId: uuid("actor_membership_id").notNull(),
    actorUserId: uuid("actor_user_id").notNull(),
    keyDigest: bytea("key_digest").notNull(),
    sourceKind: text("source_kind").notNull(),
    operation: text("operation").notNull(),
    requestDigest: bytea("request_digest"),
    resultCommentId: uuid("result_comment_id"),
    resultRevision: integer("result_revision"),
    legacyAmbiguous: boolean("legacy_ambiguous").notNull().default(false),
    createdAt: timestamp("created_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
  },
  (table) => [
    unique("ticket_comment_idempotency_keys_tenant_id_key").on(
      table.tenantId,
      table.id,
    ),
    unique("ticket_comment_idempotency_keys_replay_key").on(
      table.tenantId,
      table.actorMembershipId,
      table.keyDigest,
    ),
    foreignKey({
      name: "ticket_comment_idempotency_keys_actor_fk",
      columns: [table.tenantId, table.actorMembershipId, table.actorUserId],
      foreignColumns: [
        tenantMemberships.tenantId,
        tenantMemberships.id,
        tenantMemberships.userId,
      ],
    })
      .onUpdate("restrict")
      .onDelete("restrict"),
    foreignKey({
      name: "ticket_comment_idempotency_keys_result_fk",
      columns: [table.tenantId, table.resultCommentId, table.resultRevision],
      foreignColumns: [
        ticketCommentRevisions.tenantId,
        ticketCommentRevisions.commentId,
        ticketCommentRevisions.revision,
      ],
    })
      .onUpdate("restrict")
      .onDelete("restrict"),
    index("ticket_comment_idempotency_keys_result_idx").on(
      table.tenantId,
      table.resultCommentId,
      table.resultRevision,
    ),
    check(
      "ticket_comment_idempotency_keys_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "ticket_comment_idempotency_keys_digest_check",
      sql`octet_length(${table.keyDigest}) = 32
        and ${table.keyDigest} <> decode(repeat('00',32),'hex')
        and (${table.requestDigest} is null
          or octet_length(${table.requestDigest}) = 32
            and ${table.requestDigest} <> decode(repeat('00',32),'hex'))`,
    ),
    check(
      "ticket_comment_idempotency_keys_shape_check",
      sql`(${table.legacyAmbiguous}
          and ${table.sourceKind} = 'ambiguous'
          and ${table.operation} = 'legacy_ambiguous'
          and ${table.requestDigest} is null
          and ${table.resultCommentId} is null
          and ${table.resultRevision} is null)
        or (not ${table.legacyAmbiguous}
          and ${table.sourceKind} in ('comment','ticket_action','watcher')
          and ${table.operation} ~ '^(alert|case|ticket)\\.[a-z][a-z0-9_.-]{1,63}$'
          and ${table.requestDigest} is not null
          and ((${table.sourceKind} = 'comment'
              and ${table.resultCommentId} is not null
              and ${table.resultRevision} between 1 and 2147483647)
            or (${table.sourceKind} <> 'comment'
              and ${table.resultCommentId} is null
              and ${table.resultRevision} is null)))`,
    ),
    check(
      "ticket_comment_idempotency_keys_timestamp_check",
      sql`app.private_ticket_comment_timestamp_valid_v1(${table.createdAt})`,
    ),
    ownerPolicy("ticket_comment_idempotency_keys_owner_access"),
  ],
).enableRLS();

/** Exact source aggregate and revision used for each escalation-copy comment. */
export const ticketCommentEscalationSources = pgTable(
  "ticket_comment_escalation_sources",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    copiedCommentId: uuid("copied_comment_id").notNull(),
    sourceCommentId: uuid("source_comment_id"),
    sourceRevision: integer("source_revision"),
    sourceAlertId: uuid("source_alert_id"),
    destinationCaseId: uuid("destination_case_id").notNull(),
    legacyUnresolved: boolean("legacy_unresolved").notNull().default(false),
    createdAt: timestamp("created_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
  },
  (table) => [
    unique("ticket_comment_escalation_sources_tenant_id_key").on(
      table.tenantId,
      table.id,
    ),
    unique("ticket_comment_escalation_sources_copy_key").on(
      table.tenantId,
      table.copiedCommentId,
    ),
    foreignKey({
      name: "ticket_comment_escalation_sources_copy_fk",
      columns: [table.tenantId, table.copiedCommentId],
      foreignColumns: [ticketComments.tenantId, ticketComments.id],
    })
      .onUpdate("restrict")
      .onDelete("restrict"),
    foreignKey({
      name: "ticket_comment_escalation_sources_source_revision_fk",
      columns: [table.tenantId, table.sourceCommentId, table.sourceRevision],
      foreignColumns: [
        ticketCommentRevisions.tenantId,
        ticketCommentRevisions.commentId,
        ticketCommentRevisions.revision,
      ],
    })
      .onUpdate("restrict")
      .onDelete("restrict"),
    foreignKey({
      name: "ticket_comment_escalation_sources_alert_fk",
      columns: [table.tenantId, table.sourceAlertId],
      foreignColumns: [alerts.tenantId, alerts.id],
    })
      .onUpdate("restrict")
      .onDelete("restrict"),
    foreignKey({
      name: "ticket_comment_escalation_sources_case_fk",
      columns: [table.tenantId, table.destinationCaseId],
      foreignColumns: [cases.tenantId, cases.id],
    })
      .onUpdate("restrict")
      .onDelete("restrict"),
    index("ticket_comment_escalation_sources_source_idx").on(
      table.tenantId,
      table.sourceCommentId,
      table.sourceRevision,
    ),
    check(
      "ticket_comment_escalation_sources_id_uuidv7_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true`,
    ),
    check(
      "ticket_comment_escalation_sources_shape_check",
      sql`(${table.legacyUnresolved}
          and ${table.sourceCommentId} is null
          and ${table.sourceRevision} is null
          and ${table.sourceAlertId} is null)
        or (not ${table.legacyUnresolved}
          and ${table.sourceCommentId} is not null
          and ${table.sourceRevision} between 1 and 2147483647
          and ${table.sourceAlertId} is not null)`,
    ),
    check(
      "ticket_comment_escalation_sources_timestamp_check",
      sql`app.private_ticket_comment_timestamp_valid_v1(${table.createdAt})`,
    ),
    ownerPolicy("ticket_comment_escalation_sources_owner_access"),
  ],
).enableRLS();
