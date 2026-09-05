import type {
  NotificationDelivery,
  NotificationDeliveryDetail,
  NotificationRule,
  NotificationTemplate,
  SmtpConfiguration,
  WebhookConfiguration,
  WebhookUrlPolicy,
} from "@periapsis/contracts";

import type { NotificationAdminApi } from "./notification-api";

export const fixtureTenantId = "01991c20-7d5f-7000-8000-000000000001";
export const fixtureInstant = "2026-08-25T10:00:00Z";

export const notificationRuleFixture: NotificationRule = {
  id: "01991c20-7d5f-7000-8000-000000000010",
  tenantId: fixtureTenantId,
  version: 1,
  name: "Critical alert dispatch",
  description: "Routes critical alerts to the assigned operator.",
  eventType: "alert.created",
  objectType: "alert",
  condition: { kind: "all", children: [] },
  recipients: [{ kind: "assignee", audience: "operator" }],
  templateId: "01991c20-7d5f-7000-8000-000000000020",
  templateVersion: 1,
  channel: "email",
  priority: 100,
  delayMs: 0,
  deduplicationWindowMs: 60_000,
  grouping: { mode: "object", windowMs: 60_000, maximumItems: 25 },
  retry: {
    maximumAttempts: 5,
    initialDelayMs: 30_000,
    maximumDelayMs: 3_600_000,
    multiplier: 2,
    jitterPercent: 10,
  },
  enabled: true,
  effectiveFrom: fixtureInstant,
  createdAt: fixtureInstant,
  createdBy: "membership-1",
};

export const notificationTemplateFixture: NotificationTemplate = {
  id: "01991c20-7d5f-7000-8000-000000000020",
  tenantId: fixtureTenantId,
  version: 1,
  key: "critical-alert",
  name: "Critical alert",
  language: "en",
  subject: "Critical alert {{alert.number}}",
  html: "<p>Critical alert</p>",
  plainText: "Critical alert",
  sampleData: {},
  placeholders: ["alert.number"],
  createdAt: fixtureInstant,
  createdBy: "membership-1",
};

export const smtpFixture: SmtpConfiguration = {
  id: "01991c20-7d5f-7000-8000-000000000030",
  tenantId: fixtureTenantId,
  inheritedFromGlobal: false,
  name: "Tenant relay",
  host: "smtp.example.test",
  port: 587,
  security: "starttls",
  username: "mailer",
  passwordConfigured: true,
  fromName: "Periapsis SOC",
  fromEmail: "soc@example.test",
  replyToEmail: null,
  timeoutMs: 10_000,
  maximumConnections: 4,
  maximumMessagesPerConnection: 100,
  rateLimitPerSecond: 10,
  dkim: {
    domainName: "example.test",
    selector: "periapsis",
    privateKeyConfigured: true,
  },
  enabled: true,
  version: 1,
  createdAt: fixtureInstant,
  createdBy: "membership-1",
};

export const deliveryFixture: NotificationDelivery = {
  id: "01991c20-7d5f-7000-8000-000000000040",
  tenantId: fixtureTenantId,
  eventId: "01991c20-7d5f-7000-8000-000000000041",
  channel: "email",
  audience: "operator",
  status: "dead_lettered",
  destinationRedacted: "s***@example.test",
  attemptCount: 2,
  maximumAttempts: 2,
  failureAt: fixtureInstant,
  failureClass: "submission_uncertain",
  createdAt: fixtureInstant,
};

export const deliveryDetailFixture: NotificationDeliveryDetail = {
  ...deliveryFixture,
  attempts: [
    {
      number: 1,
      startedAt: fixtureInstant,
      completedAt: fixtureInstant,
      outcome: "retried",
      failureClass: "timeout",
    },
    {
      number: 2,
      startedAt: fixtureInstant,
      completedAt: fixtureInstant,
      outcome: "uncertain",
      failureClass: "submission_uncertain",
    },
  ],
};

export const webhookFixture: WebhookConfiguration = {
  id: "01991c20-7d5f-7000-8000-000000000050",
  tenantId: fixtureTenantId,
  name: "SIEM bridge",
  endpointUrl: "https://hooks.example.test/periapsis",
  eventTypes: ["alert.created"],
  audience: "operator",
  signingKeyConfigured: true,
  signingKeyVersion: 1,
  timeoutMs: 10_000,
  enabled: true,
  version: 1,
  createdAt: fixtureInstant,
  createdBy: "membership-1",
};

export const webhookUrlPolicyFixture: WebhookUrlPolicy = {
  id: "01991c20-7d5f-7000-8000-000000000060",
  versionId: "01991c20-7d5f-7000-8000-000000000061",
  tenantId: fixtureTenantId,
  version: 1,
  scheme: "https",
  defaultAction: "deny",
  rules: [
    {
      effect: "allow",
      match: "exact",
      hostname: "hooks.example.test",
      port: 443,
    },
  ],
  publishedByMembershipId: "01991c20-7d5f-7000-8000-000000000062",
  publishedAt: fixtureInstant,
};

export function createNotificationApiMock(
  overrides: Partial<NotificationAdminApi> = {},
): NotificationAdminApi {
  const defaults: NotificationAdminApi = {
    listRules: async () => ({ items: [notificationRuleFixture] }),
    getRule: async () => ({ etag: '"v1"', value: notificationRuleFixture }),
    createRule: async () => ({ etag: '"v1"', value: notificationRuleFixture }),
    versionRule: async () => ({
      etag: '"v2"',
      value: { ...notificationRuleFixture, version: 2 },
    }),
    listTemplates: async () => ({ items: [notificationTemplateFixture] }),
    getTemplate: async () => ({
      etag: '"v1"',
      value: notificationTemplateFixture,
    }),
    createTemplate: async () => ({
      etag: '"v1"',
      value: notificationTemplateFixture,
    }),
    versionTemplate: async () => ({
      etag: '"v2"',
      value: { ...notificationTemplateFixture, version: 2 },
    }),
    previewTemplate: async () => ({
      subject: "Preview",
      html: "<p>Preview</p>",
      plainText: "Preview",
    }),
    duplicateTemplate: async () => ({
      etag: '"v1"',
      value: {
        ...notificationTemplateFixture,
        id: `${notificationTemplateFixture.id}-copy`,
        key: "critical-alert-copy",
        name: "Critical alert copy",
      },
    }),
    rollbackTemplate: async () => ({
      etag: '"v2"',
      value: { ...notificationTemplateFixture, version: 2 },
    }),
    testTemplate: async () => deliveryFixture,
    getTenantSmtp: async () => ({ etag: '"v1"', value: smtpFixture }),
    putTenantSmtp: async () => ({
      etag: '"v2"',
      value: { ...smtpFixture, version: 2 },
    }),
    testTenantSmtp: async () => ({
      configurationId: smtpFixture.id,
      configurationVersion: 1,
      healthy: true,
      checkedAt: fixtureInstant,
      checks: [{ kind: "dns", outcome: "passed" }],
    }),
    listDeliveries: async () => ({ items: [deliveryFixture] }),
    getDelivery: async () => deliveryDetailFixture,
    retryDelivery: async () => {
      const {
        failureAt: _failureAt,
        failureClass: _failureClass,
        ...original
      } = deliveryFixture;
      return {
        ...original,
        id: `${deliveryFixture.id}-retry`,
        parentDeliveryId: deliveryFixture.id,
        status: "queued",
        attemptCount: 0,
      };
    },
    listWebhooks: async () => ({ items: [webhookFixture] }),
    getWebhook: async () => ({ etag: '"v1"', value: webhookFixture }),
    createWebhook: async () => ({ etag: '"v1"', value: webhookFixture }),
    versionWebhook: async () => ({
      etag: '"v2"',
      value: { ...webhookFixture, version: 2 },
    }),
    testWebhook: async () => ({ ...deliveryFixture, channel: "webhook" }),
    getWebhookUrlPolicy: async () => ({
      etag: '"v1"',
      value: webhookUrlPolicyFixture,
    }),
    publishWebhookUrlPolicy: async () => ({
      etag: '"v2"',
      value: { ...webhookUrlPolicyFixture, version: 2 },
      replayed: false,
    }),
    getPlatformSmtp: async () => ({
      etag: '"v1"',
      value: { ...smtpFixture, tenantId: null, inheritedFromGlobal: false },
    }),
    putPlatformSmtp: async () => ({
      etag: '"v2"',
      value: {
        ...smtpFixture,
        tenantId: null,
        inheritedFromGlobal: false,
        version: 2,
      },
    }),
    testPlatformSmtp: async () => ({
      configurationId: smtpFixture.id,
      configurationVersion: 1,
      healthy: true,
      checkedAt: fixtureInstant,
      checks: [{ kind: "connect", outcome: "passed" }],
    }),
  };
  return { ...defaults, ...overrides };
}
