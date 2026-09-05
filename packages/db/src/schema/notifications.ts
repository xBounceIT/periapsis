import { sql } from "drizzle-orm";
import {
  bigint,
  boolean,
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
  uuid,
} from "drizzle-orm/pg-core";

import { bytea } from "./binary.js";
import { currentTenantId } from "./context.js";
import {
  notificationAudience,
  notificationChannel,
  notificationDeliveryStatus,
  notificationEventType,
  notificationFailureClass,
  notificationObjectType,
  notificationSecretKind,
  notificationSmtpSecurity,
} from "./enums.js";
import {
  activeActorMembershipFor,
  tenantMemberships,
  users,
} from "./identity.js";
import { outboxEvents } from "./outbox.js";
import { apiRole, notifierRole } from "./roles.js";
import { tenants } from "./tenancy.js";
import { tenantWebhookURLPolicyVersions } from "./webhook-url-policy.js";

type NotificationCondition = Record<string, unknown>;
type NotificationRecipient = Record<string, unknown>;
type NotificationContext = Record<string, unknown>;
type NotificationRetry = Record<string, unknown>;

const tenantPolicy = (name: string, tenantId: unknown) =>
  pgPolicy(name, {
    as: "permissive",
    for: "all",
    to: apiRole,
    using: activeActorMembershipFor(tenantId),
    withCheck: activeActorMembershipFor(tenantId),
  });

const notifierPolicy = (name: string, tenantId: unknown) =>
  pgPolicy(name, {
    as: "permissive",
    for: "all",
    to: notifierRole,
    using: sql`${tenantId} = ${currentTenantId}
      and app.tenant_is_active_v1(${tenantId})`,
    withCheck: sql`${tenantId} = ${currentTenantId}
      and app.tenant_is_active_v1(${tenantId})`,
  });

export const tenantNotificationTemplates = pgTable(
  "tenant_notification_templates",
  {
    id: uuid("id").primaryKey(),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    key: text("key").notNull(),
    currentVersion: integer("current_version").notNull().default(1),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    createdByMembershipId: uuid("created_by_membership_id").notNull(),
    createdByUserId: uuid("created_by_user_id")
      .notNull()
      .references(() => users.id, { onDelete: "restrict" }),
    updatedAt: timestamp("updated_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    unique("tenant_notification_templates_tenant_id_id_key").on(
      table.tenantId,
      table.id,
    ),
    unique("tenant_notification_templates_tenant_id_key_key").on(
      table.tenantId,
      table.key,
    ),
    foreignKey({
      name: "tenant_notification_templates_creator_membership_fk",
      columns: [table.tenantId, table.createdByMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    }).onDelete("restrict"),
    check(
      "tenant_notification_templates_identity_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true
        and ${table.key} ~ '^[a-z][a-z0-9_.-]{1,126}[a-z0-9]$'
        and ${table.currentVersion} between 1 and 2147483647
        and ${table.updatedAt} >= ${table.createdAt}`,
    ),
    tenantPolicy("tenant_notification_templates_api_tenant", table.tenantId),
  ],
).enableRLS();

export const tenantNotificationTemplateVersions = pgTable(
  "tenant_notification_template_versions",
  {
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    templateId: uuid("template_id").notNull(),
    version: integer("version").notNull(),
    key: text("key").notNull(),
    name: text("name").notNull(),
    language: text("language").notNull(),
    subject: text("subject").notNull(),
    html: text("html").notNull(),
    plainText: text("plain_text"),
    css: text("css"),
    sampleData: jsonb("sample_data")
      .$type<NotificationContext>()
      .notNull()
      .default(sql`'{}'::jsonb`),
    placeholders: text("placeholders").array().notNull(),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    createdByMembershipId: uuid("created_by_membership_id").notNull(),
    createdByUserId: uuid("created_by_user_id")
      .notNull()
      .references(() => users.id, { onDelete: "restrict" }),
  },
  (table) => [
    primaryKey({
      name: "tenant_notification_template_versions_pkey",
      columns: [table.tenantId, table.templateId, table.version],
    }),
    foreignKey({
      name: "tenant_notification_template_versions_template_fk",
      columns: [table.tenantId, table.templateId],
      foreignColumns: [
        tenantNotificationTemplates.tenantId,
        tenantNotificationTemplates.id,
      ],
    }).onDelete("restrict"),
    foreignKey({
      name: "tenant_notification_template_versions_creator_membership_fk",
      columns: [table.tenantId, table.createdByMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    }).onDelete("restrict"),
    check(
      "tenant_notification_template_versions_bounds_check",
      sql`${table.version} between 1 and 2147483647
        and ${table.key} ~ '^[a-z][a-z0-9_.-]{1,126}[a-z0-9]$'
        and btrim(${table.name}) <> '' and char_length(${table.name}) <= 160
        and ${table.language} ~ '^[a-z]{2,3}(-[A-Z]{2})?$'
        and char_length(${table.subject}) between 1 and 998
        and char_length(${table.html}) between 1 and 200000
        and (${table.plainText} is null or char_length(${table.plainText}) <= 200000)
        and (${table.css} is null or char_length(${table.css}) <= 50000)
        and jsonb_typeof(${table.sampleData}) = 'object'
        and octet_length(${table.sampleData}::text) <= 65536
        and cardinality(${table.placeholders}) <= 256`,
    ),
    tenantPolicy(
      "tenant_notification_template_versions_api_tenant",
      table.tenantId,
    ),
  ],
).enableRLS();

export const tenantNotificationRules = pgTable(
  "tenant_notification_rules",
  {
    id: uuid("id").primaryKey(),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    currentVersion: integer("current_version").notNull().default(1),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    createdByMembershipId: uuid("created_by_membership_id").notNull(),
    createdByUserId: uuid("created_by_user_id")
      .notNull()
      .references(() => users.id, { onDelete: "restrict" }),
    updatedAt: timestamp("updated_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    unique("tenant_notification_rules_tenant_id_id_key").on(
      table.tenantId,
      table.id,
    ),
    foreignKey({
      name: "tenant_notification_rules_creator_membership_fk",
      columns: [table.tenantId, table.createdByMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    }).onDelete("restrict"),
    check(
      "tenant_notification_rules_identity_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true
        and ${table.currentVersion} between 1 and 2147483647
        and ${table.updatedAt} >= ${table.createdAt}`,
    ),
    tenantPolicy("tenant_notification_rules_api_tenant", table.tenantId),
  ],
).enableRLS();

export const tenantNotificationRuleVersions = pgTable(
  "tenant_notification_rule_versions",
  {
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    ruleId: uuid("rule_id").notNull(),
    version: integer("version").notNull(),
    name: text("name").notNull(),
    description: text("description").notNull().default(""),
    eventType: notificationEventType("event_type").notNull(),
    objectType: notificationObjectType("object_type").notNull(),
    condition: jsonb("condition").$type<NotificationCondition>().notNull(),
    recipients: jsonb("recipients").$type<NotificationRecipient[]>().notNull(),
    templateId: uuid("template_id").notNull(),
    templateVersion: integer("template_version").notNull(),
    channel: notificationChannel("channel").notNull(),
    priority: integer("priority").notNull(),
    delayMs: bigint("delay_ms", { mode: "number" }).notNull(),
    quietHours: jsonb("quiet_hours").$type<NotificationContext>(),
    deduplicationWindowMs: bigint("deduplication_window_ms", {
      mode: "number",
    }).notNull(),
    grouping: jsonb("grouping").$type<NotificationContext>().notNull(),
    retry: jsonb("retry").$type<NotificationRetry>().notNull(),
    enabled: boolean("enabled").notNull(),
    effectiveFrom: timestamp("effective_from", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
    effectiveUntil: timestamp("effective_until", {
      withTimezone: true,
      mode: "date",
    }),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    createdByMembershipId: uuid("created_by_membership_id").notNull(),
    createdByUserId: uuid("created_by_user_id")
      .notNull()
      .references(() => users.id, { onDelete: "restrict" }),
  },
  (table) => [
    primaryKey({
      name: "tenant_notification_rule_versions_pkey",
      columns: [table.tenantId, table.ruleId, table.version],
    }),
    foreignKey({
      name: "tenant_notification_rule_versions_rule_fk",
      columns: [table.tenantId, table.ruleId],
      foreignColumns: [
        tenantNotificationRules.tenantId,
        tenantNotificationRules.id,
      ],
    }).onDelete("restrict"),
    foreignKey({
      name: "tenant_notification_rule_versions_template_fk",
      columns: [table.tenantId, table.templateId, table.templateVersion],
      foreignColumns: [
        tenantNotificationTemplateVersions.tenantId,
        tenantNotificationTemplateVersions.templateId,
        tenantNotificationTemplateVersions.version,
      ],
    }).onDelete("restrict"),
    foreignKey({
      name: "tenant_notification_rule_versions_creator_membership_fk",
      columns: [table.tenantId, table.createdByMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    }).onDelete("restrict"),
    index("tenant_notification_rule_versions_fanout_idx").on(
      table.tenantId,
      table.eventType,
      table.objectType,
      table.enabled,
      table.effectiveFrom,
    ),
    check(
      "tenant_notification_rule_versions_bounds_check",
      sql`${table.version} between 1 and 2147483647
        and btrim(${table.name}) <> '' and char_length(${table.name}) <= 160
        and char_length(${table.description}) <= 2048
        and jsonb_typeof(${table.condition}) = 'object'
        and octet_length(${table.condition}::text) <= 65536
        and jsonb_typeof(${table.recipients}) = 'array'
        and jsonb_array_length(${table.recipients}) between 1 and 256
        and octet_length(${table.recipients}::text) <= 65536
        and ${table.templateVersion} between 1 and 2147483647
        and ${table.priority} between 0 and 100
        and ${table.delayMs} between 0 and 2592000000
        and ${table.deduplicationWindowMs} between 0 and 2592000000
        and (${table.quietHours} is null or jsonb_typeof(${table.quietHours}) = 'object')
        and jsonb_typeof(${table.grouping}) = 'object'
        and jsonb_typeof(${table.retry}) = 'object'
        and (${table.effectiveUntil} is null or ${table.effectiveUntil} > ${table.effectiveFrom})`,
    ),
    tenantPolicy(
      "tenant_notification_rule_versions_api_tenant",
      table.tenantId,
    ),
  ],
).enableRLS();

export const tenantNotificationSecretVersions = pgTable(
  "tenant_notification_secret_versions",
  {
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    secretId: uuid("secret_id").notNull(),
    version: integer("version").notNull(),
    kind: notificationSecretKind("kind").notNull(),
    keyVersion: smallint("key_version").notNull(),
    nonce: bytea("nonce").notNull(),
    ciphertext: bytea("ciphertext").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    createdByMembershipId: uuid("created_by_membership_id").notNull(),
    createdByUserId: uuid("created_by_user_id")
      .notNull()
      .references(() => users.id, { onDelete: "restrict" }),
  },
  (table) => [
    primaryKey({
      name: "tenant_notification_secret_versions_pkey",
      columns: [table.tenantId, table.secretId, table.version],
    }),
    foreignKey({
      name: "tenant_notification_secret_versions_creator_membership_fk",
      columns: [table.tenantId, table.createdByMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    }).onDelete("restrict"),
    check(
      "tenant_notification_secret_versions_envelope_check",
      sql`(uuid_extract_version(${table.secretId}) = 7) is true
        and ${table.version} between 1 and 2147483647
        and ${table.keyVersion} between 1 and 32767
        and octet_length(${table.nonce}) = 12
        and octet_length(${table.ciphertext}) between 17 and 65552`,
    ),
    tenantPolicy(
      "tenant_notification_secret_versions_api_tenant",
      table.tenantId,
    ),
  ],
).enableRLS();

export const platformNotificationSecretVersions = pgTable(
  "platform_notification_secret_versions",
  {
    secretId: uuid("secret_id").notNull(),
    version: integer("version").notNull(),
    kind: notificationSecretKind("kind").notNull(),
    keyVersion: smallint("key_version").notNull(),
    nonce: bytea("nonce").notNull(),
    ciphertext: bytea("ciphertext").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    createdByUserId: uuid("created_by_user_id")
      .notNull()
      .references(() => users.id, { onDelete: "restrict" }),
  },
  (table) => [
    primaryKey({
      name: "platform_notification_secret_versions_pkey",
      columns: [table.secretId, table.version],
    }),
    check(
      "platform_notification_secret_versions_envelope_check",
      sql`(uuid_extract_version(${table.secretId}) = 7) is true
        and ${table.version} between 1 and 2147483647
        and ${table.keyVersion} between 1 and 32767
        and octet_length(${table.nonce}) = 12
        and octet_length(${table.ciphertext}) between 17 and 65552`,
    ),
  ],
);

export const tenantNotificationSmtpConfigurations = pgTable(
  "tenant_notification_smtp_configurations",
  {
    id: uuid("id").primaryKey(),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    currentVersion: integer("current_version").notNull().default(1),
    revokedAt: timestamp("revoked_at", { withTimezone: true, mode: "date" }),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    createdByMembershipId: uuid("created_by_membership_id").notNull(),
    createdByUserId: uuid("created_by_user_id")
      .notNull()
      .references(() => users.id, { onDelete: "restrict" }),
    updatedAt: timestamp("updated_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    unique("tenant_notification_smtp_configurations_tenant_id_id_key").on(
      table.tenantId,
      table.id,
    ),
    unique("tenant_notification_smtp_configurations_one_per_tenant").on(
      table.tenantId,
    ),
    foreignKey({
      name: "tenant_notification_smtp_configurations_creator_membership_fk",
      columns: [table.tenantId, table.createdByMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    }).onDelete("restrict"),
    check(
      "tenant_notification_smtp_configurations_identity_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true
        and ${table.currentVersion} between 1 and 2147483647
        and ${table.updatedAt} >= ${table.createdAt}
        and (${table.revokedAt} is null or ${table.revokedAt} >= ${table.createdAt})`,
    ),
    tenantPolicy(
      "tenant_notification_smtp_configurations_api_tenant",
      table.tenantId,
    ),
  ],
).enableRLS();

export const tenantNotificationSmtpConfigurationVersions = pgTable(
  "tenant_notification_smtp_configuration_versions",
  {
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    configurationId: uuid("configuration_id").notNull(),
    version: integer("version").notNull(),
    name: text("name").notNull(),
    host: text("host").notNull(),
    port: integer("port").notNull(),
    security: notificationSmtpSecurity("security").notNull(),
    username: text("username"),
    passwordSecretId: uuid("password_secret_id"),
    passwordSecretVersion: integer("password_secret_version"),
    fromName: text("from_name").notNull(),
    fromEmail: text("from_email").notNull(),
    replyToEmail: text("reply_to_email"),
    timeoutMs: integer("timeout_ms").notNull(),
    maximumConnections: integer("maximum_connections").notNull(),
    maximumMessagesPerConnection: integer(
      "maximum_messages_per_connection",
    ).notNull(),
    rateLimitPerSecond: integer("rate_limit_per_second").notNull(),
    dkimDomainName: text("dkim_domain_name"),
    dkimSelector: text("dkim_selector"),
    dkimSecretId: uuid("dkim_secret_id"),
    dkimSecretVersion: integer("dkim_secret_version"),
    enabled: boolean("enabled").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    createdByMembershipId: uuid("created_by_membership_id").notNull(),
    createdByUserId: uuid("created_by_user_id")
      .notNull()
      .references(() => users.id, { onDelete: "restrict" }),
  },
  (table) => [
    primaryKey({
      name: "tenant_notification_smtp_configuration_versions_pkey",
      columns: [table.tenantId, table.configurationId, table.version],
    }),
    foreignKey({
      name: "tenant_notification_smtp_configuration_versions_config_fk",
      columns: [table.tenantId, table.configurationId],
      foreignColumns: [
        tenantNotificationSmtpConfigurations.tenantId,
        tenantNotificationSmtpConfigurations.id,
      ],
    }).onDelete("restrict"),
    foreignKey({
      name: "tenant_notification_smtp_password_secret_fk",
      columns: [
        table.tenantId,
        table.passwordSecretId,
        table.passwordSecretVersion,
      ],
      foreignColumns: [
        tenantNotificationSecretVersions.tenantId,
        tenantNotificationSecretVersions.secretId,
        tenantNotificationSecretVersions.version,
      ],
    }).onDelete("restrict"),
    foreignKey({
      name: "tenant_notification_smtp_dkim_secret_fk",
      columns: [table.tenantId, table.dkimSecretId, table.dkimSecretVersion],
      foreignColumns: [
        tenantNotificationSecretVersions.tenantId,
        tenantNotificationSecretVersions.secretId,
        tenantNotificationSecretVersions.version,
      ],
    }).onDelete("restrict"),
    foreignKey({
      name: "tenant_notification_smtp_versions_creator_membership_fk",
      columns: [table.tenantId, table.createdByMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    }).onDelete("restrict"),
    check(
      "tenant_notification_smtp_versions_bounds_check",
      sql`${table.version} between 1 and 2147483647
        and btrim(${table.name}) <> '' and char_length(${table.name}) <= 160
        and ${table.host} ~ '^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$'
        and ${table.port} between 1 and 65535
        and (${table.username} is null) = (${table.passwordSecretId} is null)
        and (${table.passwordSecretId} is null) = (${table.passwordSecretVersion} is null)
        and (${table.dkimDomainName} is null) = (${table.dkimSelector} is null)
        and (${table.dkimSelector} is null) = (${table.dkimSecretId} is null)
        and (${table.dkimSecretId} is null) = (${table.dkimSecretVersion} is null)
        and char_length(${table.fromName}) between 1 and 160
        and char_length(${table.fromEmail}) between 3 and 320
        and (${table.replyToEmail} is null or char_length(${table.replyToEmail}) between 3 and 320)
        and ${table.timeoutMs} between 1000 and 120000
        and ${table.maximumConnections} between 1 and 100
        and ${table.maximumMessagesPerConnection} between 1 and 10000
        and ${table.rateLimitPerSecond} between 1 and 10000`,
    ),
    tenantPolicy(
      "tenant_notification_smtp_configuration_versions_api_tenant",
      table.tenantId,
    ),
  ],
).enableRLS();

export const platformNotificationSmtpConfigurations = pgTable(
  "platform_notification_smtp_configurations",
  {
    id: uuid("id").primaryKey(),
    currentVersion: integer("current_version").notNull().default(1),
    revokedAt: timestamp("revoked_at", { withTimezone: true, mode: "date" }),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    createdByUserId: uuid("created_by_user_id")
      .notNull()
      .references(() => users.id, { onDelete: "restrict" }),
    updatedAt: timestamp("updated_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    check(
      "platform_notification_smtp_configurations_identity_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true
        and ${table.currentVersion} between 1 and 2147483647
        and ${table.updatedAt} >= ${table.createdAt}`,
    ),
  ],
);

export const platformNotificationSmtpConfigurationVersions = pgTable(
  "platform_notification_smtp_configuration_versions",
  {
    configurationId: uuid("configuration_id").notNull(),
    version: integer("version").notNull(),
    name: text("name").notNull(),
    host: text("host").notNull(),
    port: integer("port").notNull(),
    security: notificationSmtpSecurity("security").notNull(),
    username: text("username"),
    passwordSecretId: uuid("password_secret_id"),
    passwordSecretVersion: integer("password_secret_version"),
    fromName: text("from_name").notNull(),
    fromEmail: text("from_email").notNull(),
    replyToEmail: text("reply_to_email"),
    timeoutMs: integer("timeout_ms").notNull(),
    maximumConnections: integer("maximum_connections").notNull(),
    maximumMessagesPerConnection: integer(
      "maximum_messages_per_connection",
    ).notNull(),
    rateLimitPerSecond: integer("rate_limit_per_second").notNull(),
    dkimDomainName: text("dkim_domain_name"),
    dkimSelector: text("dkim_selector"),
    dkimSecretId: uuid("dkim_secret_id"),
    dkimSecretVersion: integer("dkim_secret_version"),
    enabled: boolean("enabled").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    createdByUserId: uuid("created_by_user_id")
      .notNull()
      .references(() => users.id, { onDelete: "restrict" }),
  },
  (table) => [
    primaryKey({
      name: "platform_notification_smtp_configuration_versions_pkey",
      columns: [table.configurationId, table.version],
    }),
    foreignKey({
      name: "platform_notification_smtp_configuration_versions_config_fk",
      columns: [table.configurationId],
      foreignColumns: [platformNotificationSmtpConfigurations.id],
    }).onDelete("restrict"),
    foreignKey({
      name: "platform_notification_smtp_password_secret_fk",
      columns: [table.passwordSecretId, table.passwordSecretVersion],
      foreignColumns: [
        platformNotificationSecretVersions.secretId,
        platformNotificationSecretVersions.version,
      ],
    }).onDelete("restrict"),
    foreignKey({
      name: "platform_notification_smtp_dkim_secret_fk",
      columns: [table.dkimSecretId, table.dkimSecretVersion],
      foreignColumns: [
        platformNotificationSecretVersions.secretId,
        platformNotificationSecretVersions.version,
      ],
    }).onDelete("restrict"),
    check(
      "platform_notification_smtp_versions_bounds_check",
      sql`${table.version} between 1 and 2147483647
        and btrim(${table.name}) <> '' and char_length(${table.name}) <= 160
        and ${table.host} ~ '^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$'
        and ${table.port} between 1 and 65535
        and (${table.username} is null) = (${table.passwordSecretId} is null)
        and (${table.passwordSecretId} is null) = (${table.passwordSecretVersion} is null)
        and (${table.dkimDomainName} is null) = (${table.dkimSelector} is null)
        and (${table.dkimSelector} is null) = (${table.dkimSecretId} is null)
        and (${table.dkimSecretId} is null) = (${table.dkimSecretVersion} is null)
        and char_length(${table.fromName}) between 1 and 160
        and char_length(${table.fromEmail}) between 3 and 320
        and ${table.timeoutMs} between 1000 and 120000
        and ${table.maximumConnections} between 1 and 100
        and ${table.maximumMessagesPerConnection} between 1 and 10000
        and ${table.rateLimitPerSecond} between 1 and 10000`,
    ),
  ],
);

export const tenantNotificationWebhookConfigurations = pgTable(
  "tenant_notification_webhook_configurations",
  {
    id: uuid("id").primaryKey(),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    currentVersion: integer("current_version").notNull().default(1),
    revokedAt: timestamp("revoked_at", { withTimezone: true, mode: "date" }),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    createdByMembershipId: uuid("created_by_membership_id").notNull(),
    createdByUserId: uuid("created_by_user_id")
      .notNull()
      .references(() => users.id, { onDelete: "restrict" }),
    updatedAt: timestamp("updated_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    unique("tenant_notification_webhooks_tenant_id_id_key").on(
      table.tenantId,
      table.id,
    ),
    foreignKey({
      name: "tenant_notification_webhooks_creator_membership_fk",
      columns: [table.tenantId, table.createdByMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    }).onDelete("restrict"),
    check(
      "tenant_notification_webhooks_identity_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true
        and ${table.currentVersion} between 1 and 2147483647
        and ${table.updatedAt} >= ${table.createdAt}`,
    ),
    tenantPolicy("tenant_notification_webhooks_api_tenant", table.tenantId),
  ],
).enableRLS();

export const tenantNotificationWebhookConfigurationVersions = pgTable(
  "tenant_notification_webhook_configuration_versions",
  {
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    configurationId: uuid("configuration_id").notNull(),
    version: integer("version").notNull(),
    name: text("name").notNull(),
    endpointUrl: text("endpoint_url").notNull(),
    endpointCanonicalUrl: text("endpoint_canonical_url").notNull(),
    endpointDigest: bytea("endpoint_digest").notNull(),
    webhookURLPolicyId: uuid("webhook_url_policy_id"),
    webhookURLPolicyVersionId: uuid("webhook_url_policy_version_id"),
    webhookURLPolicyVersion: integer("webhook_url_policy_version"),
    webhookURLPolicyDigest: bytea("webhook_url_policy_digest"),
    localDevelopmentExemption: boolean("local_development_exemption")
      .notNull()
      .default(false),
    eventTypes: notificationEventType("event_types").array().notNull(),
    audience: notificationAudience("audience").notNull(),
    signingSecretId: uuid("signing_secret_id").notNull(),
    signingSecretVersion: integer("signing_secret_version").notNull(),
    timeoutMs: integer("timeout_ms").notNull(),
    enabled: boolean("enabled").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    createdByMembershipId: uuid("created_by_membership_id").notNull(),
    createdByUserId: uuid("created_by_user_id")
      .notNull()
      .references(() => users.id, { onDelete: "restrict" }),
  },
  (table) => [
    primaryKey({
      name: "tenant_notification_webhook_configuration_versions_pkey",
      columns: [table.tenantId, table.configurationId, table.version],
    }),
    foreignKey({
      name: "tenant_notification_webhook_versions_config_fk",
      columns: [table.tenantId, table.configurationId],
      foreignColumns: [
        tenantNotificationWebhookConfigurations.tenantId,
        tenantNotificationWebhookConfigurations.id,
      ],
    }).onDelete("restrict"),
    foreignKey({
      name: "tenant_notification_webhook_versions_url_policy_fk",
      columns: [
        table.tenantId,
        table.webhookURLPolicyId,
        table.webhookURLPolicyVersionId,
        table.webhookURLPolicyVersion,
      ],
      foreignColumns: [
        tenantWebhookURLPolicyVersions.tenantId,
        tenantWebhookURLPolicyVersions.policyId,
        tenantWebhookURLPolicyVersions.id,
        tenantWebhookURLPolicyVersions.version,
      ],
    }).onDelete("restrict"),
    foreignKey({
      name: "tenant_notification_webhook_signing_secret_fk",
      columns: [
        table.tenantId,
        table.signingSecretId,
        table.signingSecretVersion,
      ],
      foreignColumns: [
        tenantNotificationSecretVersions.tenantId,
        tenantNotificationSecretVersions.secretId,
        tenantNotificationSecretVersions.version,
      ],
    }).onDelete("restrict"),
    foreignKey({
      name: "tenant_notification_webhook_versions_creator_membership_fk",
      columns: [table.tenantId, table.createdByMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    }).onDelete("restrict"),
    check(
      "tenant_notification_webhook_versions_bounds_check",
      sql`${table.version} between 1 and 2147483647
        and btrim(${table.name}) <> '' and char_length(${table.name}) <= 160
        and octet_length(${table.endpointUrl}) between 8 and 2048
        and octet_length(${table.endpointCanonicalUrl}) between 8 and 2048
        and ${table.endpointUrl} = ${table.endpointCanonicalUrl}
        and octet_length(${table.endpointDigest}) = 32
        and (
          not ${table.localDevelopmentExemption}
          and ${table.endpointCanonicalUrl} like 'https://%'
          and ${table.webhookURLPolicyId} is not null
          and ${table.webhookURLPolicyVersionId} is not null
          and ${table.webhookURLPolicyVersion} between 1 and 2147483647
          and octet_length(${table.webhookURLPolicyDigest}) = 32
          or ${table.localDevelopmentExemption}
          and ${table.endpointCanonicalUrl} like 'http://%'
          and ${table.webhookURLPolicyId} is null
          and ${table.webhookURLPolicyVersionId} is null
          and ${table.webhookURLPolicyVersion} is null
          and ${table.webhookURLPolicyDigest} is null
        )
        and cardinality(${table.eventTypes}) between 1 and 64
        and ${table.signingSecretVersion} between 1 and 2147483647
        and ${table.timeoutMs} between 1000 and 120000`,
    ),
    tenantPolicy(
      "tenant_notification_webhook_versions_api_tenant",
      table.tenantId,
    ),
  ],
).enableRLS();

// A fanout snapshot freezes the immutable rule/template and SMTP pins selected
// for an event without persisting recipient addresses or other live directory
// material. Crashed workers reuse this snapshot; only the eventual delivery
// rows contain recipient-specific projections.
export const tenantNotificationFanoutSnapshots = pgTable(
  "tenant_notification_fanout_snapshots",
  {
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    eventId: uuid("event_id")
      .notNull()
      .references(() => outboxEvents.id, { onDelete: "restrict" }),
    rulePins: jsonb("rule_pins")
      .$type<Array<{ ruleId: string; version: number }>>()
      .notNull(),
    webhookConfigurationPins: jsonb("webhook_configuration_pins")
      .$type<Array<{ configurationId: string; version: number }>>()
      .notNull()
      .default(sql`'[]'::jsonb`),
    smtpConfigurationScope: text("smtp_configuration_scope"),
    smtpConfigurationId: uuid("smtp_configuration_id"),
    smtpConfigurationVersion: integer("smtp_configuration_version"),
    snapshotDigest: bytea("snapshot_digest").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    primaryKey({
      name: "tenant_notification_fanout_snapshots_pkey",
      columns: [table.tenantId, table.eventId],
    }),
    check(
      "tenant_notification_fanout_snapshots_bounds_check",
      sql`jsonb_typeof(${table.rulePins}) = 'array'
        and jsonb_array_length(${table.rulePins}) <= 1000
        and octet_length(${table.rulePins}::text) <= 131072
        and jsonb_typeof(${table.webhookConfigurationPins}) = 'array'
        and jsonb_array_length(${table.webhookConfigurationPins}) <= 1000
        and octet_length(${table.webhookConfigurationPins}::text) <= 131072
        and (${table.smtpConfigurationScope} is null)
          = (${table.smtpConfigurationId} is null)
        and (${table.smtpConfigurationId} is null)
          = (${table.smtpConfigurationVersion} is null)
        and (${table.smtpConfigurationScope} is null
          or ${table.smtpConfigurationScope} in ('tenant', 'platform'))
        and (${table.smtpConfigurationVersion} is null
          or ${table.smtpConfigurationVersion} between 1 and 2147483647)
        and octet_length(${table.snapshotDigest}) = 32`,
    ),
    tenantPolicy(
      "tenant_notification_fanout_snapshots_api_tenant",
      table.tenantId,
    ),
    notifierPolicy(
      "tenant_notification_fanout_snapshots_notifier_tenant",
      table.tenantId,
    ),
  ],
).enableRLS();

export const tenantNotificationDeliveries = pgTable(
  "tenant_notification_deliveries",
  {
    id: uuid("id").primaryKey(),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    eventId: uuid("event_id")
      .notNull()
      .references(() => outboxEvents.id, { onDelete: "restrict" }),
    parentDeliveryId: uuid("parent_delivery_id"),
    deliveryKey: text("delivery_key").notNull(),
    ruleId: uuid("rule_id"),
    ruleVersion: integer("rule_version"),
    templateId: uuid("template_id"),
    templateVersion: integer("template_version"),
    templateSnapshot: jsonb("template_snapshot").$type<NotificationContext>(),
    smtpConfigurationScope: text("smtp_configuration_scope"),
    smtpConfigurationId: uuid("smtp_configuration_id"),
    smtpConfigurationVersion: integer("smtp_configuration_version"),
    webhookConfigurationId: uuid("webhook_configuration_id"),
    webhookConfigurationVersion: integer("webhook_configuration_version"),
    webhookSigningSecretId: uuid("webhook_signing_secret_id"),
    webhookSigningSecretVersion: integer("webhook_signing_secret_version"),
    webhookSigningKeyVersion: integer("webhook_signing_key_version"),
    webhookPayloadVersion: integer("webhook_payload_version"),
    webhookPayload: jsonb("webhook_payload").$type<NotificationContext>(),
    channel: notificationChannel("channel").notNull(),
    audience: notificationAudience("audience").notNull(),
    recipient: text("recipient").notNull(),
    destinationRedacted: text("destination_redacted").notNull(),
    context: jsonb("context").$type<NotificationContext>().notNull(),
    priority: integer("priority").notNull(),
    deduplicationKey: text("deduplication_key").notNull(),
    groupingKey: text("grouping_key"),
    groupingWindowMs: bigint("grouping_window_ms", { mode: "number" })
      .notNull()
      .default(0),
    groupingMaximumItems: integer("grouping_maximum_items")
      .notNull()
      .default(1),
    retry: jsonb("retry").$type<NotificationRetry>().notNull(),
    status: notificationDeliveryStatus("status").notNull().default("queued"),
    attemptCount: integer("attempt_count").notNull().default(0),
    maximumAttempts: integer("maximum_attempts").notNull(),
    nextAttemptAt: timestamp("next_attempt_at", {
      withTimezone: true,
      mode: "date",
    }),
    leaseOwner: text("lease_owner"),
    fenceToken: uuid("fence_token"),
    leaseUntil: timestamp("lease_until", {
      withTimezone: true,
      mode: "date",
    }),
    stableMessageId: text("stable_message_id"),
    reservedAt: timestamp("reserved_at", { withTimezone: true, mode: "date" }),
    deliveredAt: timestamp("delivered_at", {
      withTimezone: true,
      mode: "date",
    }),
    failureAt: timestamp("failure_at", { withTimezone: true, mode: "date" }),
    failureClass: notificationFailureClass("failure_class"),
    failureCode: text("failure_code"),
    providerReceipt: jsonb("provider_receipt").$type<NotificationContext>(),
    createdAt: timestamp("created_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    unique("tenant_notification_deliveries_tenant_id_id_key").on(
      table.tenantId,
      table.id,
    ),
    unique("tenant_notification_deliveries_tenant_delivery_key_key").on(
      table.tenantId,
      table.deliveryKey,
    ),
    foreignKey({
      name: "tenant_notification_deliveries_parent_fk",
      columns: [table.tenantId, table.parentDeliveryId],
      foreignColumns: [table.tenantId, table.id],
    }).onDelete("restrict"),
    foreignKey({
      name: "tenant_notification_deliveries_rule_fk",
      columns: [table.tenantId, table.ruleId, table.ruleVersion],
      foreignColumns: [
        tenantNotificationRuleVersions.tenantId,
        tenantNotificationRuleVersions.ruleId,
        tenantNotificationRuleVersions.version,
      ],
    }).onDelete("restrict"),
    foreignKey({
      name: "tenant_notification_deliveries_template_fk",
      columns: [table.tenantId, table.templateId, table.templateVersion],
      foreignColumns: [
        tenantNotificationTemplateVersions.tenantId,
        tenantNotificationTemplateVersions.templateId,
        tenantNotificationTemplateVersions.version,
      ],
    }).onDelete("restrict"),
    foreignKey({
      name: "tenant_notification_deliveries_webhook_fk",
      columns: [
        table.tenantId,
        table.webhookConfigurationId,
        table.webhookConfigurationVersion,
      ],
      foreignColumns: [
        tenantNotificationWebhookConfigurationVersions.tenantId,
        tenantNotificationWebhookConfigurationVersions.configurationId,
        tenantNotificationWebhookConfigurationVersions.version,
      ],
    }).onDelete("restrict"),
    foreignKey({
      name: "tenant_notification_deliveries_webhook_secret_fk",
      columns: [
        table.tenantId,
        table.webhookSigningSecretId,
        table.webhookSigningSecretVersion,
      ],
      foreignColumns: [
        tenantNotificationSecretVersions.tenantId,
        tenantNotificationSecretVersions.secretId,
        tenantNotificationSecretVersions.version,
      ],
    }).onDelete("restrict"),
    index("tenant_notification_deliveries_claim_idx")
      .on(table.nextAttemptAt, table.priority, table.createdAt, table.id)
      .where(
        sql`${table.status} in ('queued', 'retry_scheduled', 'leased', 'reserved')`,
      ),
    index("tenant_notification_deliveries_tenant_created_idx").on(
      table.tenantId,
      table.createdAt,
      table.id,
    ),
    check(
      "tenant_notification_deliveries_bounds_check",
      sql`(uuid_extract_version(${table.id}) = 7) is true
        and ${table.deliveryKey} ~ '^[0-9a-f]{64}$'
        and char_length(${table.recipient}) between 3 and 320
        and char_length(${table.destinationRedacted}) between 3 and 320
        and jsonb_typeof(${table.context}) = 'object'
        and octet_length(${table.context}::text) <= 65536
        and ${table.priority} between 0 and 100
        and char_length(${table.deduplicationKey}) between 1 and 240
        and (${table.groupingKey} is null or char_length(${table.groupingKey}) <= 240)
        and ${table.groupingWindowMs} between 0 and 2592000000
        and ${table.groupingMaximumItems} between 1 and 10000
        and jsonb_typeof(${table.retry}) = 'object'
        and ${table.attemptCount} between 0 and 100
        and ${table.maximumAttempts} between 1 and 100
        and ${table.attemptCount} <= ${table.maximumAttempts}
        and (${table.leaseOwner} is null) = (${table.fenceToken} is null)
        and (${table.fenceToken} is null) = (${table.leaseUntil} is null)
        and (${table.stableMessageId} is null) = (${table.reservedAt} is null)
        and (${table.failureCode} is null or ${table.failureCode} ~ '^[a-z][a-z0-9_]{0,63}$')
        and (${table.providerReceipt} is null or jsonb_typeof(${table.providerReceipt}) = 'object')
        and (${table.ruleId} is null) = (${table.ruleVersion} is null)
        and (${table.templateId} is null) = (${table.templateVersion} is null)
        and (${table.templateSnapshot} is null or ${table.templateSnapshot} =
          '{"key":"system.smtp-test","name":"Periapsis SMTP test","language":"en","version":1,"subject":"Periapsis SMTP test","html":"<p>This message verifies your Periapsis SMTP configuration.</p>","plainText":"This message verifies your Periapsis SMTP configuration.","css":""}'::jsonb)
        and ((${table.channel} = 'email'
          and ((${table.templateId} is not null) <> (${table.templateSnapshot} is not null))
          and ${table.smtpConfigurationScope} in ('tenant', 'platform')
          and ${table.smtpConfigurationId} is not null
          and ${table.smtpConfigurationVersion} is not null
          and ${table.webhookConfigurationId} is null
          and ${table.webhookConfigurationVersion} is null
          and ${table.webhookSigningSecretId} is null
          and ${table.webhookSigningSecretVersion} is null
          and ${table.webhookSigningKeyVersion} is null
          and ${table.webhookPayloadVersion} is null
          and ${table.webhookPayload} is null)
          or (${table.channel} = 'webhook'
            and ${table.templateSnapshot} is null
            and ${table.smtpConfigurationScope} is null
            and ${table.smtpConfigurationId} is null
            and ${table.smtpConfigurationVersion} is null
            and ${table.webhookConfigurationId} is not null
            and ${table.webhookConfigurationVersion} is not null
            and ${table.webhookSigningSecretId} is not null
            and ${table.webhookSigningSecretVersion} between 1 and 2147483647
            and ${table.webhookSigningKeyVersion} between 1 and 32767
            and ${table.webhookPayloadVersion} = 1
            and jsonb_typeof(${table.webhookPayload}) = 'object'
            and octet_length(${table.webhookPayload}::text) <= 262144))`,
    ),
    tenantPolicy("tenant_notification_deliveries_api_tenant", table.tenantId),
    notifierPolicy(
      "tenant_notification_deliveries_notifier_tenant",
      table.tenantId,
    ),
  ],
).enableRLS();

export const tenantNotificationDeliveryAttempts = pgTable(
  "tenant_notification_delivery_attempts",
  {
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    deliveryId: uuid("delivery_id").notNull(),
    attempt: integer("attempt").notNull(),
    fenceToken: uuid("fence_token").notNull(),
    startedAt: timestamp("started_at", { withTimezone: true, mode: "date" })
      .notNull()
      .defaultNow(),
    completedAt: timestamp("completed_at", {
      withTimezone: true,
      mode: "date",
    }),
    outcome: text("outcome"),
    failureClass: notificationFailureClass("failure_class"),
    providerReceipt: jsonb("provider_receipt").$type<NotificationContext>(),
  },
  (table) => [
    primaryKey({
      name: "tenant_notification_delivery_attempts_pkey",
      columns: [table.tenantId, table.deliveryId, table.attempt],
    }),
    foreignKey({
      name: "tenant_notification_delivery_attempts_delivery_fk",
      columns: [table.tenantId, table.deliveryId],
      foreignColumns: [
        tenantNotificationDeliveries.tenantId,
        tenantNotificationDeliveries.id,
      ],
    }).onDelete("restrict"),
    check(
      "tenant_notification_delivery_attempts_lifecycle_check",
      sql`${table.attempt} between 1 and 100
        and (uuid_extract_version(${table.fenceToken}) = 7) is true
        and (${table.completedAt} is null) = (${table.outcome} is null)
        and (${table.outcome} is null or ${table.outcome} in (
          'delivered', 'replayed', 'retried', 'dead_lettered',
          'uncertain', 'fenced'
        ))
        and (${table.providerReceipt} is null or jsonb_typeof(${table.providerReceipt}) = 'object')`,
    ),
    tenantPolicy(
      "tenant_notification_delivery_attempts_api_tenant",
      table.tenantId,
    ),
    notifierPolicy(
      "tenant_notification_delivery_attempts_notifier_tenant",
      table.tenantId,
    ),
  ],
).enableRLS();

export const tenantNotificationCommands = pgTable(
  "tenant_notification_commands",
  {
    id: uuid("id")
      .primaryKey()
      .default(sql`uuidv7()`),
    tenantId: uuid("tenant_id")
      .notNull()
      .references(() => tenants.id, { onDelete: "restrict" }),
    actorMembershipId: uuid("actor_membership_id").notNull(),
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
      .default(sql`transaction_timestamp() + interval '24 hours'`),
  },
  (table) => [
    unique("tenant_notification_commands_replay_key").on(
      table.tenantId,
      table.actorMembershipId,
      table.operation,
      table.keyDigest,
    ),
    foreignKey({
      name: "tenant_notification_commands_actor_membership_fk",
      columns: [table.tenantId, table.actorMembershipId],
      foreignColumns: [tenantMemberships.tenantId, tenantMemberships.id],
    }).onDelete("restrict"),
    check(
      "tenant_notification_commands_bounds_check",
      sql`${table.operation} in (
          'rule.create', 'rule.version', 'template.create',
          'template.version', 'template.duplicate', 'template.rollback',
          'template.test', 'smtp.version', 'smtp.test',
          'delivery.retry', 'webhook.create', 'webhook.version',
          'webhook.test'
        )
        and octet_length(${table.keyDigest}) = 32
        and octet_length(${table.requestDigest}) = 32
        and ${table.resultVersion} between 1 and 2147483647
        and ${table.expiresAt} > ${table.createdAt}`,
    ),
    tenantPolicy("tenant_notification_commands_api_tenant", table.tenantId),
  ],
).enableRLS();

export const platformNotificationCommands = pgTable(
  "platform_notification_commands",
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
      .default(sql`transaction_timestamp() + interval '24 hours'`),
  },
  (table) => [
    unique("platform_notification_commands_replay_key").on(
      table.actorUserId,
      table.operation,
      table.keyDigest,
    ),
    check(
      "platform_notification_commands_bounds_check",
      sql`${table.operation} in ('smtp.version', 'smtp.test')
        and octet_length(${table.keyDigest}) = 32
        and octet_length(${table.requestDigest}) = 32
        and ${table.resultVersion} between 1 and 2147483647
        and ${table.expiresAt} > ${table.createdAt}`,
    ),
  ],
);
