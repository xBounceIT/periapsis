import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const repositoryRoot = resolve(import.meta.dirname, "../../..");
const document = JSON.parse(
  readFileSync(
    resolve(repositoryRoot, "services/api/internal/contract/openapi.json"),
    "utf8",
  ),
);

const fail = (message) => {
  throw new Error(`Notification contract invariant failed: ${message}`);
};

const assert = (condition, message) => {
  if (!condition) fail(message);
};

const exact = (actual, expected, message) => {
  assert(
    JSON.stringify(actual) === JSON.stringify(expected),
    `${message}: received ${JSON.stringify(actual)}`,
  );
};

const operation = (path, method) => {
  const value = document.paths?.[path]?.[method];
  assert(value !== undefined, `${method.toUpperCase()} ${path} is missing`);
  return value;
};

const parameterRefs = (path, value) =>
  new Set(
    [
      ...(document.paths[path]?.parameters ?? []),
      ...(value.parameters ?? []),
    ].flatMap((parameter) =>
      parameter.$ref === undefined ? [] : [parameter.$ref],
    ),
  );

const requestSchemaRef = (value) =>
  value.requestBody?.content?.["application/json"]?.schema?.$ref;

const responseSchemaRef = (value, status) =>
  value.responses?.[status]?.content?.["application/json"]?.schema?.$ref;

const resolvedResponse = (response) => {
  if (response?.$ref === undefined) return response;
  const prefix = "#/components/responses/";
  assert(
    response.$ref.startsWith(prefix),
    `unsupported response reference ${response.$ref}`,
  );
  return document.components.responses[response.$ref.slice(prefix.length)];
};

const problemRefs = (response) => {
  const schema =
    resolvedResponse(response)?.content?.["application/problem+json"]?.schema;
  if (schema?.$ref !== undefined) return [schema.$ref];
  return [...(schema?.oneOf ?? []), ...(schema?.anyOf ?? [])].flatMap(
    (branch) => (branch.$ref === undefined ? [] : [branch.$ref]),
  );
};

const tenantBase = "/api/v1/tenants/{tenantId}";
const ruleBase = `${tenantBase}/notification-rules`;
const ruleItem = `${ruleBase}/{notificationRuleId}`;
const templateBase = `${tenantBase}/notification-templates`;
const templateItem = `${templateBase}/{notificationTemplateId}`;
const smtpBase = `${tenantBase}/smtp-configuration`;
const deliveryBase = `${tenantBase}/notification-deliveries`;
const deliveryItem = `${deliveryBase}/{notificationDeliveryId}`;
const webhookBase = `${tenantBase}/webhooks`;
const webhookItem = `${webhookBase}/{webhookConfigurationId}`;
const webhookUrlPolicy = `${tenantBase}/notification-webhook-url-policy`;
const platformSmtpBase = "/api/v1/platform/smtp-configuration";

const tenantOperations = [
  [ruleBase, "get"],
  [ruleBase, "post"],
  [ruleItem, "get"],
  [ruleItem, "put"],
  [templateBase, "get"],
  [templateBase, "post"],
  [`${templateBase}/preview`, "post"],
  [templateItem, "get"],
  [templateItem, "put"],
  [`${templateItem}/duplicate`, "post"],
  [`${templateItem}/rollback`, "post"],
  [`${templateItem}/test-send`, "post"],
  [smtpBase, "get"],
  [smtpBase, "put"],
  [`${smtpBase}/test`, "post"],
  [deliveryBase, "get"],
  [deliveryItem, "get"],
  [`${deliveryItem}/retry`, "post"],
  [webhookBase, "get"],
  [webhookBase, "post"],
  [webhookItem, "get"],
  [webhookItem, "put"],
  [`${webhookItem}/test`, "post"],
  [webhookUrlPolicy, "get"],
  [webhookUrlPolicy, "put"],
];

const platformOperations = [
  [platformSmtpBase, "get"],
  [platformSmtpBase, "put"],
  [`${platformSmtpBase}/test`, "post"],
];

assert(
  document.paths[`${tenantBase}/webhook-configurations`] === undefined,
  "the roadmap endpoint must remain /webhooks, without a shadow alias",
);

for (const [path, method] of tenantOperations) {
  const value = operation(path, method);
  const authorization = value["x-periapsis-authorization"];
  assert(
    authorization?.tenantContext === "path" &&
      authorization.activeMembership === true &&
      authorization.permission === "notification.manage",
    `${value.operationId} must enforce tenant notification administration authority`,
  );
  exact(
    authorization.scopes,
    ["tenant"],
    `${value.operationId} scopes must be exact`,
  );
  exact(
    authorization.principalTypes,
    ["human"],
    `${value.operationId} must remain human-only`,
  );
  assert(
    value.security?.some(
      (alternative) => alternative.sessionCookie !== undefined,
    ),
    `${value.operationId} must require a live browser session`,
  );
  if (!["get", "head", "options"].includes(method)) {
    assert(
      value.security?.some(
        (alternative) =>
          alternative.sessionCookie !== undefined &&
          alternative.csrfToken !== undefined,
      ),
      `${value.operationId} mutation must require CSRF with its cookie`,
    );
  }
  for (const [status, response] of Object.entries(value.responses ?? {})) {
    if (Number(status) < 400) continue;
    exact(
      problemRefs(response),
      ["#/components/schemas/Problem"],
      `${value.operationId} ${status} must use RFC 9457 Problem Details`,
    );
  }
}

for (const [path, method] of platformOperations) {
  const value = operation(path, method);
  const authorization = value["x-periapsis-authorization"];
  assert(
    authorization?.activeSession === true &&
      authorization.activeMembership === undefined &&
      authorization.tenantContext === undefined &&
      authorization.permission === "platform.notification.manage",
    `${value.operationId} must enforce platform-only notification authority`,
  );
  exact(
    authorization.scopes,
    ["platform"],
    `${value.operationId} platform scope must be exact`,
  );
  exact(
    authorization.principalTypes,
    ["human"],
    `${value.operationId} must remain human-only`,
  );
  if (method !== "get") {
    assert(
      value.security?.some(
        (alternative) =>
          alternative.sessionCookie !== undefined &&
          alternative.csrfToken !== undefined,
      ),
      `${value.operationId} mutation must require CSRF`,
    );
  }
  for (const [status, response] of Object.entries(value.responses ?? {})) {
    if (Number(status) < 400) continue;
    exact(
      problemRefs(response),
      ["#/components/schemas/Problem"],
      `${value.operationId} ${status} must use RFC 9457 Problem Details`,
    );
  }
}

const idempotentMutations = [
  [ruleBase, "post"],
  [ruleItem, "put"],
  [templateBase, "post"],
  [templateItem, "put"],
  [`${templateItem}/duplicate`, "post"],
  [`${templateItem}/rollback`, "post"],
  [`${templateItem}/test-send`, "post"],
  [smtpBase, "put"],
  [`${smtpBase}/test`, "post"],
  [`${deliveryItem}/retry`, "post"],
  [webhookBase, "post"],
  [webhookItem, "put"],
  [`${webhookItem}/test`, "post"],
  [webhookUrlPolicy, "put"],
  [platformSmtpBase, "put"],
  [`${platformSmtpBase}/test`, "post"],
];
for (const [path, method] of idempotentMutations) {
  assert(
    parameterRefs(path, operation(path, method)).has(
      "#/components/parameters/IdempotencyKey",
    ),
    `${method.toUpperCase()} ${path} must bind an idempotency key`,
  );
}

for (const [path, method] of [
  [ruleItem, "put"],
  [templateItem, "put"],
  [`${templateItem}/rollback`, "post"],
  [webhookItem, "put"],
]) {
  const value = operation(path, method);
  assert(
    parameterRefs(path, value).has("#/components/parameters/IfMatch") &&
      value.responses["412"] !== undefined &&
      value.responses["428"] !== undefined,
    `${value.operationId} must require strong optimistic concurrency`,
  );
}

const webhookUrlPolicyRead = operation(webhookUrlPolicy, "get");
const webhookUrlPolicyPublish = operation(webhookUrlPolicy, "put");
assert(
  parameterRefs(webhookUrlPolicy, webhookUrlPolicyPublish).has(
    "#/components/parameters/WebhookUrlPolicyIfMatch",
  ) &&
    parameterRefs(webhookUrlPolicy, webhookUrlPolicyPublish).has(
      "#/components/parameters/WebhookUrlPolicyAuditReason",
    ) &&
    webhookUrlPolicyPublish.responses["412"] !== undefined &&
    webhookUrlPolicyPublish.responses["428"] !== undefined,
  "webhook URL policy publication must bind bootstrap-capable strong CAS and a dedicated audit reason",
);
assert(
  requestSchemaRef(webhookUrlPolicyPublish) ===
    "#/components/schemas/WebhookUrlPolicyPublishRequest" &&
    responseSchemaRef(webhookUrlPolicyPublish, "200") ===
      "#/components/schemas/WebhookUrlPolicyMutationResult" &&
    responseSchemaRef(webhookUrlPolicyRead, "200") ===
      "#/components/schemas/WebhookUrlPolicy",
  "webhook URL policy request and response projections must remain exact",
);
const webhookUrlPolicyTag =
  document.components.schemas.WebhookUrlPolicyStrongEntityTag;
assert(
  webhookUrlPolicyTag.minLength === 4 &&
    webhookUrlPolicyTag.maxLength === 13 &&
    webhookUrlPolicyTag.pattern.includes("(?:0|") &&
    webhookUrlPolicyTag.pattern.startsWith('^"v') &&
    webhookUrlPolicyTag.pattern.endsWith('"$'),
  "webhook URL policy CAS must admit only canonical strong v0..v2147483646 tags",
);
const webhookUrlPolicySchema = document.components.schemas.WebhookUrlPolicy;
const webhookUrlPolicyWrite =
  document.components.schemas.WebhookUrlPolicyPublishRequest;
assert(
  webhookUrlPolicySchema.additionalProperties === false &&
    webhookUrlPolicySchema.properties.scheme.const === "https" &&
    webhookUrlPolicySchema.properties.defaultAction.const === "deny" &&
    webhookUrlPolicySchema.properties.rules.maxItems === 256 &&
    webhookUrlPolicyWrite.additionalProperties === false &&
    webhookUrlPolicyWrite.properties.rules.maxItems === 256 &&
    webhookUrlPolicyWrite.properties.expectedVersion.minimum === 0 &&
    webhookUrlPolicyWrite.properties.expectedVersion.maximum === 2147483646 &&
    document.components.schemas.WebhookUrlPolicyRuleWrite
      .additionalProperties === false,
  "webhook URL policies must remain closed, bounded, HTTPS-only, and default-deny",
);
assert(
  webhookUrlPolicyRead["x-periapsis-authorization"].permission ===
    "notification.manage" &&
    webhookUrlPolicyPublish["x-periapsis-authorization"].permission ===
      "notification.manage",
  "sensitive egress policy administration must not inherit generic settings authority",
);

for (const path of [smtpBase, platformSmtpBase]) {
  const value = operation(path, "put");
  assert(
    parameterRefs(path, value).has("#/components/parameters/IfMatchOptional") &&
      value.responses["200"] !== undefined &&
      value.responses["201"] !== undefined &&
      value.responses["412"] !== undefined &&
      value.responses["428"] !== undefined,
    `${value.operationId} must distinguish singleton create from version append`,
  );
}

for (const [path, schemaRef] of [
  [ruleBase, "#/components/schemas/NotificationRuleList"],
  [templateBase, "#/components/schemas/NotificationTemplateList"],
  [deliveryBase, "#/components/schemas/NotificationDeliveryList"],
  [webhookBase, "#/components/schemas/WebhookConfigurationList"],
]) {
  const value = operation(path, "get");
  assert(
    parameterRefs(path, value).has(
      "#/components/parameters/NotificationAfterCursor",
    ) &&
      parameterRefs(path, value).has("#/components/parameters/PageSize") &&
      responseSchemaRef(value, "200") === schemaRef,
    `${value.operationId} must use bounded opaque cursor pagination`,
  );
}
assert(
  document.components.schemas.NotificationCursor.maxLength === 512 &&
    document.components.schemas.NotificationCursor.pattern?.startsWith(
      "^n1\\.",
    ),
  "notification cursors must remain versioned, opaque, and bounded",
);

for (const [path, method, schema] of [
  [ruleBase, "post", "NotificationRuleWrite"],
  [ruleItem, "put", "NotificationRuleWrite"],
  [templateBase, "post", "NotificationTemplateWrite"],
  [templateItem, "put", "NotificationTemplateWrite"],
  [`${templateBase}/preview`, "post", "NotificationTemplatePreviewRequest"],
  [`${templateItem}/duplicate`, "post", "NotificationTemplateDuplicateRequest"],
  [`${templateItem}/rollback`, "post", "NotificationTemplateRollbackRequest"],
  [`${templateItem}/test-send`, "post", "NotificationTemplateTestSendRequest"],
  [smtpBase, "put", "SmtpConfigurationWrite"],
  [`${smtpBase}/test`, "post", "SmtpConfigurationTestRequest"],
  [`${deliveryItem}/retry`, "post", "NotificationManualRetryRequest"],
  [webhookBase, "post", "WebhookConfigurationWrite"],
  [webhookItem, "put", "WebhookConfigurationWrite"],
  [`${webhookItem}/test`, "post", "WebhookConfigurationTestRequest"],
  [platformSmtpBase, "put", "SmtpConfigurationWrite"],
  [`${platformSmtpBase}/test`, "post", "PlatformSmtpConfigurationTestRequest"],
]) {
  const value = operation(path, method);
  assert(
    requestSchemaRef(value) === `#/components/schemas/${schema}`,
    `${value.operationId} request projection drifted`,
  );
}

const platformSmtpTest = operation(`${platformSmtpBase}/test`, "post");
assert(
  requestSchemaRef(platformSmtpTest) ===
    "#/components/schemas/PlatformSmtpConfigurationTestRequest" &&
    platformSmtpTest.responses["200"] !== undefined &&
    platformSmtpTest.responses["202"] === undefined &&
    document.components.schemas.PlatformSmtpConfigurationTestRequest
      .additionalProperties === false &&
    document.components.schemas.PlatformSmtpConfigurationTestRequest.properties
      .recipient === undefined,
  "platform SMTP test must remain health-only without tenant delivery input",
);
assert(
  responseSchemaRef(platformSmtpTest, "200") ===
    "#/components/schemas/PlatformSmtpConfigurationHealth" &&
    document.components.schemas.PlatformSmtpConfigurationHealth
      .additionalProperties === false &&
    document.components.schemas.PlatformSmtpConfigurationHealth.properties
      .queuedDeliveryId === undefined,
  "platform SMTP health response must structurally omit tenant delivery identifiers",
);

const eventTypes = [
  "alert.created",
  "alert.assigned",
  "alert.claimed",
  "alert.status_changed",
  "alert.escalated",
  "alert.watcher_added",
  "alert.watcher_removed",
  "case.created",
  "case.assigned",
  "case.claimed",
  "case.transferred",
  "case.status_changed",
  "case.watcher_added",
  "case.watcher_removed",
  "comment.public_added",
  "comment.private_added",
  "contact.changed",
  "sla.warning",
  "sla.breached",
  "task.assigned",
  "evidence.added",
  "webhook.custom",
];
exact(
  document.components.schemas.NotificationEventType.enum,
  eventTypes,
  "initial notification event taxonomy must remain exact",
);
const recipientSelector =
  document.components.schemas.NotificationRecipientSelector;
exact(
  recipientSelector.properties.kind.enum,
  [
    "assignee",
    "previous_assignee",
    "operator_team",
    "watcher",
    "mentioned",
    "actor",
    "tenant_admin",
    "platform_group",
    "customer_contacts",
    "contact_group",
    "contact_tag",
    "explicit_email",
    "custom_email_field",
  ],
  "recipient selector taxonomy must remain exact",
);
exact(
  recipientSelector.required,
  ["kind", "audience"],
  "recipient selectors must always carry an explicit audience",
);
assert(
  recipientSelector.properties.value.minLength === 1 &&
    recipientSelector.properties.value.maxLength === 320 &&
    recipientSelector.properties.value.pattern.includes("\\u007F-\\u009F"),
  "recipient selector values must remain nonblank, control-free, and bounded",
);

const selectorBranch = (kinds) =>
  recipientSelector.allOf.find((branch) => {
    const condition = branch.if?.properties?.kind;
    const actual =
      condition?.enum ??
      (condition?.const === undefined ? undefined : [condition.const]);
    return JSON.stringify(actual) === JSON.stringify(kinds);
  });
const isNever = (value) =>
  JSON.stringify(value) === JSON.stringify({ not: {} });
const assertClosedBranch = ({
  audience,
  kinds,
  required,
  valueRequired,
  explicitEmail = false,
}) => {
  const branch = selectorBranch(kinds);
  exact(
    branch?.then?.required,
    required,
    `${kinds.join("/")} required fields must remain exact`,
  );
  if (audience !== undefined) {
    assert(
      branch.then.properties.audience?.const === audience,
      `${kinds.join("/")} audience must remain ${audience}`,
    );
  }
  assert(
    valueRequired
      ? branch.then.properties.value?.minLength >= 1 &&
          branch.then.properties.value?.maxLength === 320
      : isNever(branch.then.properties.value),
    `${kinds.join("/")} value presence must remain closed by kind`,
  );
  assert(
    explicitEmail
      ? branch.then.properties.authorized?.const === true &&
          branch.then.properties.value?.format === "email"
      : isNever(branch.then.properties.authorized),
    `${kinds.join("/")} authorization flag must remain closed by kind`,
  );
};

assertClosedBranch({
  audience: "operator",
  kinds: [
    "assignee",
    "previous_assignee",
    "watcher",
    "mentioned",
    "tenant_admin",
  ],
  required: ["audience"],
  valueRequired: false,
});
assertClosedBranch({
  audience: "operator",
  kinds: ["operator_team", "platform_group"],
  required: ["audience", "value"],
  valueRequired: true,
});
assertClosedBranch({
  audience: "customer",
  kinds: ["customer_contacts"],
  required: ["audience"],
  valueRequired: false,
});
assertClosedBranch({
  audience: "customer",
  kinds: ["contact_group", "contact_tag"],
  required: ["audience", "value"],
  valueRequired: true,
});
assertClosedBranch({
  kinds: ["actor"],
  required: ["audience"],
  valueRequired: false,
});
assertClosedBranch({
  kinds: ["custom_email_field"],
  required: ["audience", "value"],
  valueRequired: true,
});
assertClosedBranch({
  explicitEmail: true,
  kinds: ["explicit_email"],
  required: ["audience", "value", "authorized"],
  valueRequired: true,
});
assert(
  document.components.schemas.NotificationRuleWrite.unevaluatedProperties ===
    false &&
    document.components.schemas.NotificationRule.unevaluatedProperties ===
      false &&
    document.components.schemas.NotificationRuleFields.properties.recipients
      .maxItems === 100 &&
    document.components.schemas.NotificationPredicateCondition.properties.path
      .maxLength === 511 &&
    document.components.schemas.NotificationAllCondition.properties.children
      .maxItems === 64,
  "rules must remain mass-assignment closed and structurally bounded",
);

const templateFields = document.components.schemas.NotificationTemplateFields;
assert(
  document.components.schemas.NotificationTemplateWrite
    .unevaluatedProperties === false &&
    document.components.schemas.NotificationTemplate.unevaluatedProperties ===
      false &&
    templateFields.properties.subject.maxLength === 998 &&
    templateFields.properties.html.maxLength === 262144 &&
    templateFields.properties.css.maxLength === 65536 &&
    document.components.schemas.NotificationSampleData.maxProperties === 100,
  "template inputs must remain closed and bounded",
);
assert(
  operation(`${templateBase}/preview`, "post")["x-periapsis-authorization"]
    .customerProjection === "fail_closed" &&
    document.components.schemas.NotificationTemplatePreview.properties.html
      .maxLength === 1048576,
  "preview must use the production fail-closed projection with bounded output",
);

const smtpWrite = document.components.schemas.SmtpConfigurationWrite;
const smtpProjection = document.components.schemas.SmtpConfiguration;
assert(
  smtpWrite.additionalProperties === false &&
    smtpWrite.properties.password.writeOnly === true &&
    smtpWrite.required.includes("clearPassword") &&
    smtpWrite.required.includes("clearDkim") &&
    document.components.schemas.SmtpDkimWrite.properties.privateKey
      .writeOnly === true &&
    smtpProjection.additionalProperties === false,
  "SMTP commands must be closed and secret inputs must be write-only",
);
for (const forbidden of [
  "password",
  "passwordSecretReference",
  "privateKey",
  "privateKeySecretReference",
]) {
  assert(
    smtpProjection.properties[forbidden] === undefined,
    `SMTP projection must structurally omit ${forbidden}`,
  );
}
assert(
  smtpProjection.required.includes("tenantId") &&
    smtpProjection.required.includes("inheritedFromGlobal") &&
    smtpProjection.required.includes("passwordConfigured") &&
    document.components.schemas.SmtpConfigurationHealth.description.includes(
      "no SMTP banner",
    ),
  "SMTP projections must expose inheritance and health without secret/provider text",
);

const webhookWrite = document.components.schemas.WebhookConfigurationWrite;
const webhookProjection = document.components.schemas.WebhookConfiguration;
assert(
  webhookWrite.additionalProperties === false &&
    webhookWrite.properties.signingKey.writeOnly === true &&
    webhookWrite.properties.eventTypes.maxItems === eventTypes.length &&
    webhookProjection.properties.signingKey === undefined &&
    webhookProjection.properties.signingKeyReference === undefined &&
    webhookProjection.required.includes("signingKeyVersion"),
  "webhook configuration must pin and redact signing material",
);

const delivery = document.components.schemas.NotificationDeliveryFields;
for (const forbidden of [
  "recipient",
  "endpointUrl",
  "subject",
  "html",
  "plainText",
  "body",
  "providerResponse",
]) {
  assert(
    delivery.properties[forbidden] === undefined,
    `delivery projection must structurally omit ${forbidden}`,
  );
}
assert(
  (document.components.schemas.NotificationDelivery.unevaluatedProperties ===
    false ||
    document.components.schemas.NotificationDelivery.additionalProperties ===
      false) &&
    (document.components.schemas.NotificationDeliveryDetail
      .unevaluatedProperties === false ||
      document.components.schemas.NotificationDeliveryDetail
        .additionalProperties === false) &&
    delivery.required.includes("tenantId") &&
    delivery.properties.destinationRedacted.description.includes(
      "complete email address or endpoint URL is never returned",
    ) &&
    document.components.schemas.NotificationDeliveryAttempt
      .additionalProperties === false,
  "delivery history must remain tenant-owned, closed, append-only, and redacted",
);
assert(
  operation(`${deliveryItem}/retry`, "post").description.includes(
    "never silently resent",
  ) &&
    document.components.schemas.NotificationManualRetryRequest.required.includes(
      "acknowledgeUncertainSubmission",
    ) &&
    document.components.schemas.NotificationManualRetryRequest.properties.reason
      .maxLength === 1000,
  "manual retry must preserve immutable history and require uncertain-send acknowledgement",
);

for (const [path, method, status, schemaRef] of [
  [ruleBase, "post", "201", "#/components/schemas/NotificationRule"],
  [ruleItem, "put", "200", "#/components/schemas/NotificationRule"],
  [templateBase, "post", "201", "#/components/schemas/NotificationTemplate"],
  [templateItem, "put", "200", "#/components/schemas/NotificationTemplate"],
  [
    `${templateItem}/test-send`,
    "post",
    "202",
    "#/components/schemas/NotificationDelivery",
  ],
  [
    `${deliveryItem}/retry`,
    "post",
    "201",
    "#/components/schemas/NotificationDelivery",
  ],
  [webhookBase, "post", "201", "#/components/schemas/WebhookConfiguration"],
  [webhookItem, "put", "200", "#/components/schemas/WebhookConfiguration"],
  [
    `${webhookItem}/test`,
    "post",
    "202",
    "#/components/schemas/NotificationDelivery",
  ],
]) {
  const value = operation(path, method);
  assert(
    responseSchemaRef(value, status) === schemaRef,
    `${value.operationId} success projection drifted`,
  );
}
