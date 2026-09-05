import {
  createTenantNotificationRule,
  createTenantNotificationTemplate,
  createTenantWebhookConfiguration,
  duplicateTenantNotificationTemplate,
  getPlatformSmtpConfiguration,
  getTenantNotificationDelivery,
  getTenantNotificationRule,
  getTenantNotificationTemplate,
  getTenantSmtpConfiguration,
  getTenantWebhookConfiguration,
  getTenantWebhookUrlPolicy,
  listTenantNotificationDeliveries,
  listTenantNotificationRules,
  listTenantNotificationTemplates,
  listTenantWebhookConfigurations,
  previewTenantNotificationTemplate,
  publishTenantWebhookUrlPolicy,
  retryTenantNotificationDelivery,
  rollbackTenantNotificationTemplate,
  testPlatformSmtpConfiguration,
  testSendTenantNotificationTemplate,
  testTenantSmtpConfiguration,
  testTenantWebhookConfiguration,
  versionPlatformSmtpConfiguration,
  versionTenantNotificationRule,
  versionTenantNotificationTemplate,
  versionTenantSmtpConfiguration,
  versionTenantWebhookConfiguration,
  type NotificationDelivery,
  type NotificationDeliveryDetail,
  type NotificationDeliveryStatus,
  type NotificationManualRetryRequest,
  type NotificationRule,
  type NotificationRuleWrite,
  type NotificationTemplate,
  type NotificationTemplateDuplicateRequest,
  type NotificationTemplatePreview,
  type NotificationTemplatePreviewRequest,
  type NotificationTemplateRollbackRequest,
  type NotificationTemplateTestSendRequest,
  type NotificationTemplateWrite,
  type PlatformSmtpConfigurationHealth,
  type PlatformSmtpConfigurationTestRequest,
  type SmtpConfiguration,
  type SmtpConfigurationHealth,
  type SmtpConfigurationTestRequest,
  type SmtpConfigurationWriteWritable,
  type WebhookConfiguration,
  type WebhookConfigurationTestRequest,
  type WebhookConfigurationWriteWritable,
  type WebhookUrlPolicy,
  type WebhookUrlPolicyPublishRequest,
} from "@periapsis/contracts";

import { sessionAwareFetch } from "../lib/session-transition-transport";

export interface CursorPage<T> {
  items: T[];
  nextCursor?: string;
}

export interface Versioned<T> {
  etag: string;
  value: T;
}

export interface ReplayedVersioned<T> extends Versioned<T> {
  replayed: boolean;
}

export interface NotificationMutationContext {
  csrfToken: string;
  idempotencyKey: string;
}

interface TenantMutationContext extends NotificationMutationContext {
  tenantId: string;
}

interface TenantVersionMutationContext extends TenantMutationContext {
  etag: string;
}

export interface NotificationAdminApi {
  listRules(input: {
    after?: string;
    signal?: AbortSignal;
    tenantId: string;
  }): Promise<CursorPage<NotificationRule>>;
  getRule(input: {
    id: string;
    signal?: AbortSignal;
    tenantId: string;
  }): Promise<Versioned<NotificationRule>>;
  createRule(
    input: TenantMutationContext & { body: NotificationRuleWrite },
  ): Promise<Versioned<NotificationRule>>;
  versionRule(
    input: TenantVersionMutationContext & {
      body: NotificationRuleWrite;
      id: string;
    },
  ): Promise<Versioned<NotificationRule>>;

  listTemplates(input: {
    after?: string;
    signal?: AbortSignal;
    tenantId: string;
  }): Promise<CursorPage<NotificationTemplate>>;
  getTemplate(input: {
    id: string;
    signal?: AbortSignal;
    tenantId: string;
  }): Promise<Versioned<NotificationTemplate>>;
  createTemplate(
    input: TenantMutationContext & { body: NotificationTemplateWrite },
  ): Promise<Versioned<NotificationTemplate>>;
  versionTemplate(
    input: TenantVersionMutationContext & {
      body: NotificationTemplateWrite;
      id: string;
    },
  ): Promise<Versioned<NotificationTemplate>>;
  previewTemplate(input: {
    body: NotificationTemplatePreviewRequest;
    csrfToken: string;
    tenantId: string;
  }): Promise<NotificationTemplatePreview>;
  duplicateTemplate(
    input: TenantMutationContext & {
      body: NotificationTemplateDuplicateRequest;
      id: string;
    },
  ): Promise<Versioned<NotificationTemplate>>;
  rollbackTemplate(
    input: TenantVersionMutationContext & {
      body: NotificationTemplateRollbackRequest;
      id: string;
    },
  ): Promise<Versioned<NotificationTemplate>>;
  testTemplate(
    input: TenantMutationContext & {
      body: NotificationTemplateTestSendRequest;
      id: string;
    },
  ): Promise<NotificationDelivery>;

  getTenantSmtp(input: {
    signal?: AbortSignal;
    tenantId: string;
  }): Promise<Versioned<SmtpConfiguration>>;
  putTenantSmtp(
    input: TenantMutationContext & {
      body: SmtpConfigurationWriteWritable;
      etag?: string;
    },
  ): Promise<Versioned<SmtpConfiguration>>;
  testTenantSmtp(
    input: TenantMutationContext & { body: SmtpConfigurationTestRequest },
  ): Promise<SmtpConfigurationHealth>;

  listDeliveries(input: {
    after?: string;
    signal?: AbortSignal;
    status?: NotificationDeliveryStatus[];
    tenantId: string;
  }): Promise<CursorPage<NotificationDelivery>>;
  getDelivery(input: {
    id: string;
    signal?: AbortSignal;
    tenantId: string;
  }): Promise<NotificationDeliveryDetail>;
  retryDelivery(
    input: TenantMutationContext & {
      body: NotificationManualRetryRequest;
      id: string;
    },
  ): Promise<NotificationDelivery>;

  listWebhooks(input: {
    after?: string;
    signal?: AbortSignal;
    tenantId: string;
  }): Promise<CursorPage<WebhookConfiguration>>;
  getWebhook(input: {
    id: string;
    signal?: AbortSignal;
    tenantId: string;
  }): Promise<Versioned<WebhookConfiguration>>;
  createWebhook(
    input: TenantMutationContext & {
      body: WebhookConfigurationWriteWritable;
    },
  ): Promise<Versioned<WebhookConfiguration>>;
  versionWebhook(
    input: TenantVersionMutationContext & {
      body: WebhookConfigurationWriteWritable;
      id: string;
    },
  ): Promise<Versioned<WebhookConfiguration>>;
  testWebhook(
    input: TenantMutationContext & {
      body: WebhookConfigurationTestRequest;
      id: string;
    },
  ): Promise<NotificationDelivery>;

  getWebhookUrlPolicy(input: {
    signal?: AbortSignal;
    tenantId: string;
  }): Promise<Versioned<WebhookUrlPolicy> | null>;
  publishWebhookUrlPolicy(
    input: TenantVersionMutationContext & {
      auditReason: string;
      body: WebhookUrlPolicyPublishRequest;
    },
  ): Promise<ReplayedVersioned<WebhookUrlPolicy>>;

  getPlatformSmtp(input?: {
    signal?: AbortSignal;
  }): Promise<Versioned<SmtpConfiguration>>;
  putPlatformSmtp(
    input: NotificationMutationContext & {
      body: SmtpConfigurationWriteWritable;
      etag?: string;
    },
  ): Promise<Versioned<SmtpConfiguration>>;
  testPlatformSmtp(
    input: NotificationMutationContext & {
      body: PlatformSmtpConfigurationTestRequest;
    },
  ): Promise<PlatformSmtpConfigurationHealth>;
}

interface GeneratedResult<T> {
  data: T | undefined;
  error: unknown;
  response?: Response | undefined;
}

const sameOrigin = {
  baseUrl: globalThis.location.origin,
  credentials: "same-origin" as const,
  fetch: sessionAwareFetch,
};
const strongEntityTagPattern = /^"v([1-9]\d{0,9})"$/u;
const uuidV7Pattern =
  /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const canonicalPolicyHostnamePattern =
  /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/u;
const webhookURLPolicyKeys = new Set([
  "id",
  "versionId",
  "tenantId",
  "version",
  "scheme",
  "defaultAction",
  "rules",
  "publishedByMembershipId",
  "publishedAt",
]);
const webhookURLPolicyRuleKeys = new Set([
  "effect",
  "match",
  "hostname",
  "port",
]);
const forbiddenResponseKeys = new Set([
  "password",
  "passwordCiphertext",
  "privateKey",
  "privateKeyCiphertext",
  "providerResponse",
  "secret",
  "secretRef",
  "secretReference",
  "signingKey",
  "signingKeyCiphertext",
]);
const deliveryForbiddenResponseKeys = new Set([
  ...forbiddenResponseKeys,
  "destination",
  "messageBody",
  "recipient",
  "renderedBody",
]);

export const notificationAdminApi: NotificationAdminApi = {
  async listRules({ after, signal, tenantId }) {
    requireTenant(tenantId);
    const value = unwrap(
      await listTenantNotificationRules({
        ...sameOrigin,
        path: { tenantId },
        query: { limit: 50, ...(after ? { after } : {}) },
        ...(signal ? { signal } : {}),
      }),
    );
    return projectPage(value, tenantId, projectRule);
  },

  async getRule({ id, signal, tenantId }) {
    requireResourceId(id);
    requireTenant(tenantId);
    const result = await getTenantNotificationRule({
      ...sameOrigin,
      path: { notificationRuleId: id, tenantId },
      ...(signal ? { signal } : {}),
    });
    return projectVersioned(result, tenantId, projectRule);
  },

  async createRule(input) {
    requireMutation(input);
    const result = await createTenantNotificationRule({
      ...sameOrigin,
      body: input.body,
      headers: mutationHeaders(input),
      path: { tenantId: input.tenantId },
    });
    return projectVersioned(result, input.tenantId, projectRule);
  },

  async versionRule(input) {
    requireVersionMutation(input);
    requireResourceId(input.id);
    const result = await versionTenantNotificationRule({
      ...sameOrigin,
      body: input.body,
      headers: versionHeaders(input),
      path: { notificationRuleId: input.id, tenantId: input.tenantId },
    });
    return projectVersioned(result, input.tenantId, projectRule);
  },

  async listTemplates({ after, signal, tenantId }) {
    requireTenant(tenantId);
    const value = unwrap(
      await listTenantNotificationTemplates({
        ...sameOrigin,
        path: { tenantId },
        query: { limit: 50, ...(after ? { after } : {}) },
        ...(signal ? { signal } : {}),
      }),
    );
    return projectPage(value, tenantId, projectTemplate);
  },

  async getTemplate({ id, signal, tenantId }) {
    requireResourceId(id);
    requireTenant(tenantId);
    const result = await getTenantNotificationTemplate({
      ...sameOrigin,
      path: { notificationTemplateId: id, tenantId },
      ...(signal ? { signal } : {}),
    });
    return projectVersioned(result, tenantId, projectTemplate);
  },

  async createTemplate(input) {
    requireMutation(input);
    const result = await createTenantNotificationTemplate({
      ...sameOrigin,
      body: input.body,
      headers: mutationHeaders(input),
      path: { tenantId: input.tenantId },
    });
    return projectVersioned(result, input.tenantId, projectTemplate);
  },

  async versionTemplate(input) {
    requireVersionMutation(input);
    requireResourceId(input.id);
    const result = await versionTenantNotificationTemplate({
      ...sameOrigin,
      body: input.body,
      headers: versionHeaders(input),
      path: { notificationTemplateId: input.id, tenantId: input.tenantId },
    });
    return projectVersioned(result, input.tenantId, projectTemplate);
  },

  async previewTemplate({ body, csrfToken, tenantId }) {
    requireCsrf(csrfToken);
    requireTenant(tenantId);
    return projectPreview(
      unwrap(
        await previewTenantNotificationTemplate({
          ...sameOrigin,
          body,
          headers: { "X-CSRF-Token": csrfToken },
          path: { tenantId },
        }),
      ),
    );
  },

  async duplicateTemplate(input) {
    requireMutation(input);
    requireResourceId(input.id);
    const result = await duplicateTenantNotificationTemplate({
      ...sameOrigin,
      body: input.body,
      headers: mutationHeaders(input),
      path: { notificationTemplateId: input.id, tenantId: input.tenantId },
    });
    return projectVersioned(result, input.tenantId, projectTemplate);
  },

  async rollbackTemplate(input) {
    requireVersionMutation(input);
    requireResourceId(input.id);
    const result = await rollbackTenantNotificationTemplate({
      ...sameOrigin,
      body: input.body,
      headers: versionHeaders(input),
      path: { notificationTemplateId: input.id, tenantId: input.tenantId },
    });
    return projectVersioned(result, input.tenantId, projectTemplate);
  },

  async testTemplate(input) {
    requireMutation(input);
    requireResourceId(input.id);
    return projectDelivery(
      unwrap(
        await testSendTenantNotificationTemplate({
          ...sameOrigin,
          body: input.body,
          headers: mutationHeaders(input),
          path: {
            notificationTemplateId: input.id,
            tenantId: input.tenantId,
          },
        }),
      ),
      input.tenantId,
    );
  },

  async getTenantSmtp({ signal, tenantId }) {
    requireTenant(tenantId);
    const result = await getTenantSmtpConfiguration({
      ...sameOrigin,
      path: { tenantId },
      ...(signal ? { signal } : {}),
    });
    return projectVersioned(result, tenantId, projectTenantSmtp);
  },

  async putTenantSmtp(input) {
    requireMutation(input);
    if (input.etag) requireEtag(input.etag);
    const result = await versionTenantSmtpConfiguration({
      ...sameOrigin,
      body: input.body,
      headers: optionalVersionHeaders(input),
      path: { tenantId: input.tenantId },
    });
    return projectVersioned(result, input.tenantId, projectTenantSmtp);
  },

  async testTenantSmtp(input) {
    requireMutation(input);
    return projectSmtpHealth(
      unwrap(
        await testTenantSmtpConfiguration({
          ...sameOrigin,
          body: input.body,
          headers: mutationHeaders(input),
          path: { tenantId: input.tenantId },
        }),
      ),
    );
  },

  async listDeliveries({ after, signal, status, tenantId }) {
    requireTenant(tenantId);
    const value = unwrap(
      await listTenantNotificationDeliveries({
        ...sameOrigin,
        path: { tenantId },
        query: {
          limit: 50,
          ...(after ? { after } : {}),
          ...(status?.length ? { status } : {}),
        },
        ...(signal ? { signal } : {}),
      }),
    );
    return projectPage(value, tenantId, projectDelivery);
  },

  async getDelivery({ id, signal, tenantId }) {
    requireResourceId(id);
    requireTenant(tenantId);
    return projectDeliveryDetail(
      unwrap(
        await getTenantNotificationDelivery({
          ...sameOrigin,
          path: { notificationDeliveryId: id, tenantId },
          ...(signal ? { signal } : {}),
        }),
      ),
      tenantId,
    );
  },

  async retryDelivery(input) {
    requireMutation(input);
    requireResourceId(input.id);
    return projectDelivery(
      unwrap(
        await retryTenantNotificationDelivery({
          ...sameOrigin,
          body: input.body,
          headers: mutationHeaders(input),
          path: { notificationDeliveryId: input.id, tenantId: input.tenantId },
        }),
      ),
      input.tenantId,
    );
  },

  async listWebhooks({ after, signal, tenantId }) {
    requireTenant(tenantId);
    const value = unwrap(
      await listTenantWebhookConfigurations({
        ...sameOrigin,
        path: { tenantId },
        query: { limit: 50, ...(after ? { after } : {}) },
        ...(signal ? { signal } : {}),
      }),
    );
    return projectPage(value, tenantId, projectWebhook);
  },

  async getWebhook({ id, signal, tenantId }) {
    requireResourceId(id);
    requireTenant(tenantId);
    const result = await getTenantWebhookConfiguration({
      ...sameOrigin,
      path: { tenantId, webhookConfigurationId: id },
      ...(signal ? { signal } : {}),
    });
    return projectVersioned(result, tenantId, projectWebhook);
  },

  async createWebhook(input) {
    requireMutation(input);
    const result = await createTenantWebhookConfiguration({
      ...sameOrigin,
      body: input.body,
      headers: mutationHeaders(input),
      path: { tenantId: input.tenantId },
    });
    return projectVersioned(result, input.tenantId, projectWebhook);
  },

  async versionWebhook(input) {
    requireVersionMutation(input);
    requireResourceId(input.id);
    const result = await versionTenantWebhookConfiguration({
      ...sameOrigin,
      body: input.body,
      headers: versionHeaders(input),
      path: { tenantId: input.tenantId, webhookConfigurationId: input.id },
    });
    return projectVersioned(result, input.tenantId, projectWebhook);
  },

  async testWebhook(input) {
    requireMutation(input);
    requireResourceId(input.id);
    return projectDelivery(
      unwrap(
        await testTenantWebhookConfiguration({
          ...sameOrigin,
          body: input.body,
          headers: mutationHeaders(input),
          path: { tenantId: input.tenantId, webhookConfigurationId: input.id },
        }),
      ),
      input.tenantId,
    );
  },

  async getWebhookUrlPolicy({ signal, tenantId }) {
    requireTenant(tenantId);
    const result = await getTenantWebhookUrlPolicy({
      ...sameOrigin,
      path: { tenantId },
      ...(signal ? { signal } : {}),
    });
    if (result.data === undefined && result.response?.status === 404) {
      return null;
    }
    return projectVersioned(result, tenantId, projectWebhookUrlPolicy);
  },

  async publishWebhookUrlPolicy(input) {
    requireMutation(input);
    requireWebhookUrlPolicyEtag(input.etag);
    requireAuditReason(input.auditReason);
    if (
      input.body.expectedVersion !== webhookURLPolicyETagVersion(input.etag)
    ) {
      throw new NotificationApiError(
        "The webhook policy version does not match its precondition.",
      );
    }
    const result = await publishTenantWebhookUrlPolicy({
      ...sameOrigin,
      body: input.body,
      headers: {
        ...mutationHeaders(input),
        "If-Match": input.etag,
        "X-Audit-Reason": input.auditReason,
      },
      path: { tenantId: input.tenantId },
    });
    const body = unwrap(result);
    if (!isRecord(body) || typeof body.replayed !== "boolean") {
      throw projectionMismatch();
    }
    const replayHeader = result.response?.headers.get("X-Idempotent-Replay");
    if (replayHeader !== String(body.replayed)) {
      throw projectionMismatch(
        "The API returned an inconsistent webhook policy replay receipt.",
      );
    }
    const versioned = projectVersioned(
      { ...result, data: body.policy },
      input.tenantId,
      projectWebhookUrlPolicy,
    );
    return { ...versioned, replayed: body.replayed };
  },

  async getPlatformSmtp(input) {
    const result = await getPlatformSmtpConfiguration({
      ...sameOrigin,
      ...(input?.signal ? { signal: input.signal } : {}),
    });
    return projectVersioned(result, null, projectPlatformSmtp);
  },

  async putPlatformSmtp(input) {
    requireMutation(input);
    if (input.etag) requireEtag(input.etag);
    const result = await versionPlatformSmtpConfiguration({
      ...sameOrigin,
      body: input.body,
      headers: optionalVersionHeaders(input),
    });
    return projectVersioned(result, null, projectPlatformSmtp);
  },

  async testPlatformSmtp(input) {
    requireMutation(input);
    return projectPlatformSmtpHealth(
      unwrap(
        await testPlatformSmtpConfiguration({
          ...sameOrigin,
          body: input.body,
          headers: mutationHeaders(input),
        }),
      ),
    );
  },
};

function mutationHeaders(input: NotificationMutationContext) {
  return {
    "Idempotency-Key": input.idempotencyKey,
    "X-CSRF-Token": input.csrfToken,
  };
}

function versionHeaders(input: NotificationMutationContext & { etag: string }) {
  return { ...mutationHeaders(input), "If-Match": input.etag };
}

function optionalVersionHeaders(
  input: NotificationMutationContext & { etag?: string },
) {
  return {
    ...mutationHeaders(input),
    ...(input.etag ? { "If-Match": input.etag } : {}),
  };
}

function requireMutation(
  input: NotificationMutationContext & { tenantId?: string },
) {
  requireCsrf(input.csrfToken);
  requireIdempotencyKey(input.idempotencyKey);
  if (input.tenantId !== undefined) requireTenant(input.tenantId);
}

function requireVersionMutation(input: TenantVersionMutationContext): void {
  requireMutation(input);
  requireEtag(input.etag);
}

function requireTenant(tenantId: string): void {
  if (!tenantId.trim() || tenantId.length > 160) {
    throw new NotificationApiError("A valid tenant context is required.");
  }
}

function requireResourceId(id: string): void {
  if (!id.trim() || id.length > 160) {
    throw new NotificationApiError("A valid resource identifier is required.");
  }
}

function requireCsrf(value: string): void {
  if (!value.trim() || value.length > 4096) {
    throw new NotificationApiError("Request integrity context is unavailable.");
  }
}

function requireIdempotencyKey(value: string): void {
  if (!value.trim() || value.length > 128 || value.includes(",")) {
    throw new NotificationApiError("A valid retry key is required.");
  }
}

function requireEtag(value: string): void {
  if (!strongEntityTagPattern.test(value)) {
    throw new NotificationApiError("A current strong entity tag is required.");
  }
}

const webhookURLPolicyEntityTagPattern = /^"v(0|[1-9]\d{0,9})"$/u;

function webhookURLPolicyETagVersion(value: string): number {
  const match = webhookURLPolicyEntityTagPattern.exec(value);
  const version = match ? Number(match[1]) : Number.NaN;
  if (
    !Number.isSafeInteger(version) ||
    version < 0 ||
    version >= 2_147_483_647
  ) {
    throw new NotificationApiError(
      "A current strong webhook policy entity tag is required.",
    );
  }
  return version;
}

function requireWebhookUrlPolicyEtag(value: string): void {
  webhookURLPolicyETagVersion(value);
}

function requireAuditReason(value: string): void {
  if (
    value.length === 0 ||
    value.length > 2048 ||
    value !== value.trim() ||
    value.includes(",") ||
    !isVisibleASCII(value)
  ) {
    throw new NotificationApiError("A valid audited reason is required.");
  }
}

function isVisibleASCII(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code < 0x20 || code > 0x7e) return false;
  }
  return true;
}

function unwrap<T>(result: GeneratedResult<T>): T {
  if (result.data !== undefined) return result.data;
  throw toNotificationApiError(result.response);
}

function projectVersioned<T>(
  result: GeneratedResult<T>,
  tenantId: string | null,
  project: (value: T, tenantId: string | null) => T,
): Versioned<T> {
  const value = project(unwrap(result), tenantId);
  const version = versionOf(value);
  const etag = result.response?.headers.get("ETag");
  const match = etag ? strongEntityTagPattern.exec(etag) : null;
  if (!etag || !match || Number(match[1]) !== version) {
    throw projectionMismatch(
      "The API omitted the current notification version.",
    );
  }
  return { etag, value };
}

function projectPage<T>(
  value: { items: T[]; nextCursor?: string },
  tenantId: string,
  project: (item: T, tenantId: string) => T,
): CursorPage<T> {
  assertStructurallyRedacted(value);
  if (
    !isRecord(value) ||
    !Array.isArray(value.items) ||
    value.items.length > 100
  ) {
    throw projectionMismatch();
  }
  if (
    value.nextCursor !== undefined &&
    (typeof value.nextCursor !== "string" || value.nextCursor.length === 0)
  ) {
    throw projectionMismatch();
  }
  return {
    items: value.items.map((item) => project(item, tenantId)),
    ...(value.nextCursor ? { nextCursor: value.nextCursor } : {}),
  };
}

function projectRule(value: NotificationRule, tenantId: string | null) {
  if (!isRecord(value)) throw projectionMismatch();
  assertTenantProjection(value, tenantId);
  assertResourceVersion(value.version);
  if (
    typeof value.name !== "string" ||
    typeof value.templateId !== "string" ||
    !value.name.trim() ||
    !value.templateId.trim()
  )
    throw projectionMismatch();
  return value;
}

function projectTemplate(value: NotificationTemplate, tenantId: string | null) {
  if (!isRecord(value)) throw projectionMismatch();
  assertTenantProjection(value, tenantId);
  assertResourceVersion(value.version);
  if (
    typeof value.key !== "string" ||
    typeof value.name !== "string" ||
    !value.key.trim() ||
    !value.name.trim()
  ) {
    throw projectionMismatch();
  }
  return value;
}

function projectDelivery(value: NotificationDelivery, tenantId: string | null) {
  if (!isRecord(value)) throw projectionMismatch();
  assertTenantProjection(value, tenantId);
  assertNoForbiddenKeys(value, deliveryForbiddenResponseKeys);
  if (
    typeof value.id !== "string" ||
    typeof value.destinationRedacted !== "string" ||
    !value.id.trim() ||
    !value.destinationRedacted.trim()
  ) {
    throw projectionMismatch();
  }
  return value;
}

function projectDeliveryDetail(
  value: NotificationDeliveryDetail,
  tenantId: string,
) {
  if (!isRecord(value)) throw projectionMismatch();
  projectDelivery(value, tenantId);
  if (!Array.isArray(value.attempts) || value.attempts.length > 100) {
    throw projectionMismatch();
  }
  return value;
}

function projectWebhook(value: WebhookConfiguration, tenantId: string | null) {
  if (!isRecord(value)) throw projectionMismatch();
  assertTenantProjection(value, tenantId);
  assertResourceVersion(value.version);
  assertResourceVersion(value.signingKeyVersion);
  return value;
}

function projectWebhookUrlPolicy(
  value: WebhookUrlPolicy,
  tenantId: string | null,
) {
  if (!isRecord(value) || tenantId === null) throw projectionMismatch();
  assertStructurallyRedacted(value);
  if (Object.keys(value).some((key) => !webhookURLPolicyKeys.has(key))) {
    throw projectionMismatch();
  }
  assertTenantProjection(value, tenantId);
  assertResourceVersion(value.version);
  if (
    value.scheme !== "https" ||
    value.defaultAction !== "deny" ||
    !uuidV7Pattern.test(value.id) ||
    !uuidV7Pattern.test(value.versionId) ||
    !uuidV7Pattern.test(value.publishedByMembershipId) ||
    value.id === value.versionId ||
    typeof value.publishedAt !== "string" ||
    !Number.isFinite(Date.parse(value.publishedAt)) ||
    !Array.isArray(value.rules) ||
    value.rules.length > 256
  ) {
    throw projectionMismatch();
  }
  const projectedRules = value.rules.map((rule) => {
    if (
      !isRecord(rule) ||
      Object.keys(rule).some((key) => !webhookURLPolicyRuleKeys.has(key)) ||
      (rule.effect !== "allow" && rule.effect !== "deny") ||
      (rule.match !== "exact" && rule.match !== "subdomains") ||
      typeof rule.hostname !== "string" ||
      !canonicalPolicyHostnamePattern.test(rule.hostname) ||
      !Number.isInteger(rule.port) ||
      rule.port < 1 ||
      rule.port > 65_535
    ) {
      throw projectionMismatch();
    }
    return {
      effect: rule.effect,
      match: rule.match,
      hostname: rule.hostname,
      port: rule.port,
    };
  });
  const records = projectedRules.map(
    (rule) =>
      `${rule.effect}\0${rule.match}\0${rule.hostname}\0${String(rule.port)}`,
  );
  if (
    records.some((record, index) => index > 0 && records[index - 1]! >= record)
  ) {
    throw projectionMismatch(
      "The webhook URL policy rules were not canonical or unique.",
    );
  }
  return {
    id: value.id,
    versionId: value.versionId,
    tenantId: value.tenantId,
    version: value.version,
    scheme: value.scheme,
    defaultAction: value.defaultAction,
    rules: projectedRules,
    publishedByMembershipId: value.publishedByMembershipId,
    publishedAt: value.publishedAt,
  };
}

function projectTenantSmtp(value: SmtpConfiguration, tenantId: string | null) {
  if (!isRecord(value)) throw projectionMismatch();
  assertStructurallyRedacted(value);
  assertResourceVersion(value.version);
  if (
    tenantId === null ||
    (value.tenantId !== tenantId &&
      !(value.inheritedFromGlobal && value.tenantId === null))
  ) {
    throw projectionMismatch();
  }
  return value;
}

function projectPlatformSmtp(
  value: SmtpConfiguration,
  tenantId: string | null,
) {
  if (!isRecord(value)) throw projectionMismatch();
  assertStructurallyRedacted(value);
  assertResourceVersion(value.version);
  if (
    tenantId !== null ||
    value.tenantId !== null ||
    value.inheritedFromGlobal
  ) {
    throw projectionMismatch();
  }
  return value;
}

function projectPreview(value: NotificationTemplatePreview) {
  if (!isRecord(value)) throw projectionMismatch();
  assertStructurallyRedacted(value);
  if (
    typeof value.subject !== "string" ||
    typeof value.html !== "string" ||
    typeof value.plainText !== "string"
  ) {
    throw projectionMismatch();
  }
  return value;
}

function projectSmtpHealth(value: SmtpConfigurationHealth) {
  if (!isRecord(value)) throw projectionMismatch();
  assertStructurallyRedacted(value);
  assertResourceVersion(value.configurationVersion);
  if (!Array.isArray(value.checks) || value.checks.length > 20) {
    throw projectionMismatch();
  }
  return value;
}

function projectPlatformSmtpHealth(value: PlatformSmtpConfigurationHealth) {
  if (!isRecord(value)) throw projectionMismatch();
  const allowedKeys = new Set([
    "configurationId",
    "configurationVersion",
    "healthy",
    "checkedAt",
    "checks",
  ]);
  if (Object.keys(value).some((key) => !allowedKeys.has(key))) {
    throw projectionMismatch();
  }
  assertStructurallyRedacted(value);
  assertResourceVersion(value.configurationVersion);
  if (
    !Array.isArray(value.checks) ||
    value.checks.length < 1 ||
    value.checks.length > 4
  ) {
    throw projectionMismatch();
  }
  return value;
}

function assertTenantProjection(
  value: { tenantId: string },
  tenantId: string | null,
): void {
  if (!isRecord(value) || typeof value.tenantId !== "string") {
    throw projectionMismatch();
  }
  assertStructurallyRedacted(value);
  if (tenantId === null || value.tenantId !== tenantId) {
    throw projectionMismatch();
  }
}

function versionOf(value: unknown): number {
  if (!isRecord(value)) throw projectionMismatch();
  const version = value["version"];
  assertResourceVersion(version);
  return version;
}

function assertResourceVersion(value: unknown): asserts value is number {
  if (!Number.isSafeInteger(value) || Number(value) < 1) {
    throw projectionMismatch();
  }
}

export function assertStructurallyRedacted(value: unknown, depth = 0): void {
  assertNoForbiddenKeys(value, forbiddenResponseKeys, depth);
}

function assertNoForbiddenKeys(
  value: unknown,
  forbiddenKeys: ReadonlySet<string>,
  depth = 0,
): void {
  if (depth > 12) throw projectionMismatch();
  if (Array.isArray(value)) {
    if (value.length > 500) throw projectionMismatch();
    for (const item of value) {
      assertNoForbiddenKeys(item, forbiddenKeys, depth + 1);
    }
    return;
  }
  if (!isRecord(value)) return;
  const entries = Object.entries(value);
  if (entries.length > 200) throw projectionMismatch();
  for (const [key, item] of entries) {
    if (forbiddenKeys.has(key)) throw projectionMismatch();
    assertNoForbiddenKeys(item, forbiddenKeys, depth + 1);
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function projectionMismatch(
  message = "The notification projection was not safe to display.",
) {
  return new NotificationApiError(message, undefined, "projection_mismatch");
}

function toNotificationApiError(response?: Response) {
  const status = response?.status;
  return new NotificationApiError(fallbackForStatus(status), status);
}

function fallbackForStatus(status: number | undefined): string {
  switch (status) {
    case 400:
      return "The notification request was not accepted.";
    case 401:
      return "The current session was not accepted.";
    case 403:
      return "The server denied this notification operation.";
    case 404:
      return "The notification resource is not available in this projection.";
    case 409:
      return "This attempt conflicts with current notification state.";
    case 412:
      return "This configuration changed. Reload it before creating another version.";
    case 428:
      return "The current configuration version is required.";
    case 429:
      return "The notification operation is temporarily rate limited.";
    case 503:
      return "A required notification dependency is unavailable.";
    default:
      return "The notification request could not be completed.";
  }
}

export class NotificationApiError extends Error {
  constructor(
    message: string,
    readonly status?: number,
    readonly code?: string,
  ) {
    super(message);
    this.name = "NotificationApiError";
  }
}
