import { relations, sql } from "drizzle-orm";
import {
  check,
  boolean,
  foreignKey,
  index,
  integer,
  jsonb,
  pgPolicy,
  pgTable,
  primaryKey,
  text,
  timestamp,
  unique,
  uuid,
} from "drizzle-orm/pg-core";

import { bytea } from "./binary.js";
import { currentTenantId } from "./context.js";
import { tenantMemberships, users } from "./identity.js";
import {
  apiRole,
  notificationDispatchOwnerRole,
  notifierRole,
  webhookURLPolicyOwnerRole,
} from "./roles.js";
import { tenants } from "./tenancy.js";

const webhookURLPolicyOwnerTenantPolicy = (name: string, tenantId: unknown) =>
  pgPolicy(name, {
    as: "permissive",
    for: "all",
    to: webhookURLPolicyOwnerRole,
    using: sql`${tenantId} = ${currentTenantId}`,
    withCheck: sql`${tenantId} = ${currentTenantId}`,
  });

export type WebhookURLPolicyRuleDocument = Readonly<{
  effect: "allow" | "deny";
  match: "exact" | "subdomains";
  hostname: string;
  port: number;
}>;

export const tenantWebhookURLPolicyVersions = pgTable(
  "tenant_webhook_url_policy_versions",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    policyId: uuid("policy_id").notNull(),
    version: integer("version").notNull(),
    rules: jsonb("rules").$type<WebhookURLPolicyRuleDocument[]>().notNull(),
    semanticDigest: bytea("semantic_digest").notNull(),
    policyDigest: bytea("policy_digest").notNull(),
    publishedByMembershipId: uuid("published_by_membership_id").notNull(),
    publishedAt: timestamp("published_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
  },
  (table) => [
    unique("tenant_webhook_url_policy_versions_coordinate_key").on(
      table.tenantId,
      table.policyId,
      table.version,
    ),
    unique("tenant_webhook_url_policy_versions_identity_key").on(
      table.tenantId,
      table.policyId,
      table.id,
      table.version,
    ),
    foreignKey({
      name: "tenant_webhook_url_policy_versions_publisher_fk",
      columns: [table.tenantId, table.publishedByMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    }).onDelete("restrict"),
    check(
      "tenant_webhook_url_policy_versions_identity_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true
        and (uuid_extract_version(${table.policyId}) = 7) is true
        and ${table.id} <> ${table.policyId}
        and ${table.version} between 1 and 2147483647
        and date_trunc('milliseconds', ${table.publishedAt}) = ${table.publishedAt}
        and extract(year from ${table.publishedAt} at time zone 'UTC') between 2000 and 9999`,
    ),
    check(
      "tenant_webhook_url_policy_versions_document_check",
      sql`jsonb_typeof(${table.rules}) = 'array'
        and jsonb_array_length(${table.rules}) <= 256
        and octet_length(${table.rules}::text) <= 131072
        and octet_length(${table.semanticDigest}) = 32
        and octet_length(${table.policyDigest}) = 32`,
    ),
    webhookURLPolicyOwnerTenantPolicy(
      "tenant_webhook_url_policy_versions_owner_tenant",
      table.tenantId,
    ),
    pgPolicy("tenant_webhook_url_policy_versions_dispatch_select", {
      as: "permissive",
      for: "select",
      to: notificationDispatchOwnerRole,
      using: sql`true`,
    }),
  ],
).enableRLS();

export const tenantWebhookURLPolicies = pgTable(
  "tenant_webhook_url_policies",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    currentVersion: integer("current_version").notNull(),
    createdAt: timestamp("created_at", {
      withTimezone: true,
      mode: "date",
    })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp("updated_at", {
      withTimezone: true,
      mode: "date",
    })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    unique("tenant_webhook_url_policies_tenant_key").on(table.tenantId),
    unique("tenant_webhook_url_policies_tenant_identity_key").on(
      table.tenantId,
      table.id,
    ),
    foreignKey({
      name: "tenant_webhook_url_policies_current_version_fk",
      columns: [table.tenantId, table.id, table.currentVersion],
      foreignColumns: [
        tenantWebhookURLPolicyVersions.tenantId,
        tenantWebhookURLPolicyVersions.policyId,
        tenantWebhookURLPolicyVersions.version,
      ],
    }).onDelete("restrict"),
    check(
      "tenant_webhook_url_policies_identity_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true
        and ${table.currentVersion} between 1 and 2147483647
        and ${table.updatedAt} >= ${table.createdAt}`,
    ),
    webhookURLPolicyOwnerTenantPolicy(
      "tenant_webhook_url_policies_owner_tenant",
      table.tenantId,
    ),
    pgPolicy("tenant_webhook_url_policies_dispatch_select", {
      as: "permissive",
      for: "select",
      to: notificationDispatchOwnerRole,
      using: sql`true`,
    }),
  ],
).enableRLS();

export const tenantWebhookURLPolicyCommands = pgTable(
  "tenant_webhook_url_policy_commands",
  {
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    actorUserId: uuid("actor_user_id")
      .notNull()
      .references(() => users.id, { onDelete: "restrict" }),
    actorMembershipId: uuid("actor_membership_id").notNull(),
    operation: text("operation").notNull(),
    keyDigest: bytea("key_digest").notNull(),
    requestDigest: bytea("request_digest").notNull(),
    resultPolicyId: uuid("result_policy_id").notNull(),
    resultVersionId: uuid("result_version_id").notNull(),
    resultVersion: integer("result_version").notNull(),
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
      name: "tenant_webhook_url_policy_commands_pkey",
      columns: [
        table.tenantId,
        table.actorUserId,
        table.operation,
        table.keyDigest,
      ],
    }),
    foreignKey({
      name: "tenant_webhook_url_policy_commands_membership_fk",
      columns: [table.tenantId, table.actorMembershipId, table.actorUserId],
      foreignColumns: [
        tenantMemberships.tenantId,
        tenantMemberships.id,
        tenantMemberships.userId,
      ],
    }).onDelete("restrict"),
    foreignKey({
      name: "tenant_webhook_url_policy_commands_result_fk",
      columns: [
        table.tenantId,
        table.resultPolicyId,
        table.resultVersionId,
        table.resultVersion,
      ],
      foreignColumns: [
        tenantWebhookURLPolicyVersions.tenantId,
        tenantWebhookURLPolicyVersions.policyId,
        tenantWebhookURLPolicyVersions.id,
        tenantWebhookURLPolicyVersions.version,
      ],
    }).onDelete("restrict"),
    index("tenant_webhook_url_policy_commands_expiry_idx").on(table.expiresAt),
    check(
      "tenant_webhook_url_policy_commands_envelope_check",
      sql`${table.operation} = 'webhook_url_policy.publish'
        and octet_length(${table.keyDigest}) = 32
        and octet_length(${table.requestDigest}) = 32
        and ${table.resultVersion} between 1 and 2147483647
        and ${table.expiresAt} > ${table.createdAt}`,
    ),
    webhookURLPolicyOwnerTenantPolicy(
      "tenant_webhook_url_policy_commands_owner_tenant",
      table.tenantId,
    ),
  ],
).enableRLS();

/**
 * Deployment-owned, non-tenant, non-secret opt-in. A runtime can only read
 * the row named by its immutable session login and never receives DML.
 */
export const webhookPlainLocalRuntimeRoleOptIns = pgTable(
  "webhook_plain_local_runtime_role_opt_ins",
  {
    roleName: text("role_name").primaryKey(),
    enabled: boolean("enabled").notNull().default(false),
    updatedAt: timestamp("updated_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    check(
      "webhook_plain_local_runtime_role_opt_ins_role_check",
      sql`${table.roleName} in ('periapsis_api_login', 'periapsis_notifier_login')`,
    ),
    pgPolicy("webhook_plain_local_runtime_role_opt_ins_api_self", {
      as: "permissive",
      for: "select",
      to: apiRole,
      using: sql`${table.roleName} = session_user::text`,
    }),
    pgPolicy("webhook_plain_local_runtime_role_opt_ins_notifier_self", {
      as: "permissive",
      for: "select",
      to: notifierRole,
      using: sql`${table.roleName} = session_user::text`,
    }),
    pgPolicy("webhook_plain_local_runtime_role_opt_ins_owner_self", {
      as: "permissive",
      for: "select",
      to: webhookURLPolicyOwnerRole,
      using: sql`${table.roleName} = session_user::text`,
    }),
  ],
).enableRLS();

export const tenantWebhookURLPolicyVersionsRelations = relations(
  tenantWebhookURLPolicyVersions,
  ({ one }) => ({
    tenant: one(tenants, {
      fields: [tenantWebhookURLPolicyVersions.tenantId],
      references: [tenants.id],
    }),
    publisher: one(tenantMemberships, {
      fields: [
        tenantWebhookURLPolicyVersions.tenantId,
        tenantWebhookURLPolicyVersions.publishedByMembershipId,
      ],
      references: [tenantMemberships.tenantId, tenantMemberships.id],
    }),
  }),
);

export const tenantWebhookURLPoliciesRelations = relations(
  tenantWebhookURLPolicies,
  ({ one }) => ({
    currentVersion: one(tenantWebhookURLPolicyVersions, {
      fields: [
        tenantWebhookURLPolicies.tenantId,
        tenantWebhookURLPolicies.id,
        tenantWebhookURLPolicies.currentVersion,
      ],
      references: [
        tenantWebhookURLPolicyVersions.tenantId,
        tenantWebhookURLPolicyVersions.policyId,
        tenantWebhookURLPolicyVersions.version,
      ],
    }),
  }),
);
