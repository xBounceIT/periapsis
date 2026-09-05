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
  throw new Error(`Contact/portal contract invariant failed: ${message}`);
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

const tenantBase = "/api/v1/tenants/{tenantId}";
const contactBase = `${tenantBase}/contacts`;
const contactItem = `${contactBase}/{contactId}`;
const groupBase = `${tenantBase}/contact-groups`;
const groupItem = `${groupBase}/{contactGroupId}`;
const alertContactLinks = `${tenantBase}/alerts/{alertId}/contacts`;
const caseContactLinks = `${tenantBase}/cases/{caseId}/contacts`;

for (const path of [alertContactLinks, caseContactLinks]) {
  const value = operation(path, "get");
  const refs = parameterRefs(path, value);
  assert(
    refs.has("#/components/parameters/ContactAfterCursor") &&
      refs.has("#/components/parameters/PageSize"),
    `${value.operationId} must expose the cursor and page-size inputs required to reach every returned page`,
  );
}

for (const [path, method, permission] of [
  [contactBase, "get", "contact.read"],
  [contactBase, "post", "contact.manage"],
  [contactItem, "get", "contact.read"],
  [contactItem, "put", "contact.manage"],
  [contactItem, "delete", "contact.manage"],
  [groupBase, "get", "contact_group.read"],
  [groupBase, "post", "contact_group.manage"],
  [groupItem, "get", "contact_group.read"],
  [groupItem, "put", "contact_group.manage"],
]) {
  const value = operation(path, method);
  const authorization = value["x-periapsis-authorization"];
  assert(
    authorization.permission === permission &&
      authorization.activeMembership === true &&
      authorization.tenantContext === "path",
    `${value.operationId} operator permission drifted`,
  );
  exact(
    authorization.actorKinds,
    ["operator"],
    `${value.operationId} must remain operator-only`,
  );
  exact(
    authorization.principalTypes,
    ["human"],
    `${value.operationId} must remain an interactive human operation`,
  );
}

for (const [path, method] of [
  [contactBase, "post"],
  [contactItem, "put"],
  [contactItem, "delete"],
  [groupBase, "post"],
  [groupItem, "put"],
]) {
  const refs = parameterRefs(path, operation(path, method));
  assert(
    refs.has("#/components/parameters/IdempotencyKey"),
    `${method.toUpperCase()} ${path} must be idempotent`,
  );
  if (path === contactItem || path === groupItem) {
    assert(
      refs.has("#/components/parameters/IfMatch"),
      `${method.toUpperCase()} ${path} must require a strong expected version`,
    );
  }
}

const portalOperations = [
  [
    `${tenantBase}/portal/me/contact`,
    "get",
    "portal.contact.preference.manage",
    "required",
  ],
  [
    `${tenantBase}/portal/me/contact`,
    "put",
    "portal.contact.preference.manage",
    "required",
  ],
  [
    `${tenantBase}/portal/alerts`,
    "get",
    "portal.alert.read",
    "required_before_pagination",
  ],
  [
    `${tenantBase}/portal/alerts/{alertId}`,
    "get",
    "portal.alert.read",
    "required",
  ],
  [
    `${tenantBase}/portal/alerts/{alertId}/sla`,
    "get",
    "portal.alert.read",
    "required",
  ],
  [
    `${tenantBase}/portal/alerts/{alertId}/export`,
    "get",
    "portal.alert.read",
    "required",
  ],
  [
    `${tenantBase}/portal/cases`,
    "get",
    "portal.case.read",
    "required_before_pagination",
  ],
  [
    `${tenantBase}/portal/cases/{caseId}`,
    "get",
    "portal.case.read",
    "required",
  ],
  [
    `${tenantBase}/portal/cases/{caseId}/sla`,
    "get",
    "portal.case.read",
    "required",
  ],
  [
    `${tenantBase}/portal/cases/{caseId}/export`,
    "get",
    "portal.case.read",
    "required",
  ],
  [
    `${tenantBase}/portal/alerts/{alertId}/dfir/attachments`,
    "get",
    "portal.attachment.read",
    "required_before_pagination",
  ],
  [
    `${tenantBase}/portal/alerts/{alertId}/dfir/attachments/{attachmentId}/prepare-download`,
    "post",
    "portal.attachment.read",
    "required_at_prepare",
  ],
  [
    `${tenantBase}/portal/cases/{caseId}/dfir/attachments`,
    "get",
    "portal.attachment.read",
    "required_before_pagination",
  ],
  [
    `${tenantBase}/portal/cases/{caseId}/dfir/attachments/{attachmentId}/prepare-download`,
    "post",
    "portal.attachment.read",
    "required_at_prepare",
  ],
  [
    `${tenantBase}/portal/alerts/{alertId}/comments`,
    "get",
    "portal.comment.public",
    "required_before_pagination",
  ],
  [
    `${tenantBase}/portal/alerts/{alertId}/comments`,
    "post",
    "portal.comment.public",
    "required_at_commit",
  ],
  [
    `${tenantBase}/portal/cases/{caseId}/comments`,
    "get",
    "portal.comment.public",
    "required_before_pagination",
  ],
  [
    `${tenantBase}/portal/cases/{caseId}/comments`,
    "post",
    "portal.comment.public",
    "required_at_commit",
  ],
  [
    `${tenantBase}/portal/alerts/{alertId}/activities`,
    "get",
    "portal.alert.read",
    "required_before_pagination",
  ],
  [
    `${tenantBase}/portal/cases/{caseId}/activities`,
    "get",
    "portal.case.read",
    "required_before_pagination",
  ],
];
for (const [path, method, permission, exactContactLink] of portalOperations) {
  const value = operation(path, method);
  const authorization = value["x-periapsis-authorization"];
  assert(
    authorization.permission === permission &&
      authorization.exactContactLink === exactContactLink,
    `${value.operationId} must require the exact contact relationship`,
  );
  exact(authorization.scopes, ["own"], `${value.operationId} scope drifted`);
  exact(
    authorization.actorKinds,
    ["customer"],
    `${value.operationId} must remain customer-only`,
  );
  exact(
    authorization.principalTypes,
    ["human"],
    `${value.operationId} must reject service principals`,
  );
}

for (const [operatorPath, portalPath] of [
  [
    `${tenantBase}/alerts/{alertId}/sla`,
    `${tenantBase}/portal/alerts/{alertId}/sla`,
  ],
  [
    `${tenantBase}/cases/{caseId}/sla`,
    `${tenantBase}/portal/cases/{caseId}/sla`,
  ],
]) {
  const operator = operation(operatorPath, "get");
  const operatorAuthorization = operator["x-periapsis-authorization"];
  exact(
    operatorAuthorization.actorKinds,
    ["operator"],
    `${operator.operationId} must remain operator-only`,
  );
  assert(
    operatorAuthorization.customerPermission === undefined &&
      operatorAuthorization.customerScopes === undefined &&
      operatorAuthorization.projection === "operator" &&
      operator.responses["200"]?.content?.["application/json"]?.schema?.$ref ===
        "#/components/schemas/SLAOperatorObjectProjection",
    `${operator.operationId} must not retain a customer fallback`,
  );

  const portal = operation(portalPath, "get");
  const portalAuthorization = portal["x-periapsis-authorization"];
  assert(
    portalAuthorization.projection === "customer_safe" &&
      portal.responses["200"]?.content?.["application/json"]?.schema?.$ref ===
        "#/components/schemas/SLACustomerObjectProjection" &&
      portal.responses["200"]?.headers?.["Cache-Control"]?.$ref ===
        "#/components/headers/NoStore",
    `${portal.operationId} must expose only the no-store customer SLA projection`,
  );
  for (const status of ["400", "401", "403", "404", "503"]) {
    assert(
      portal.responses[status]?.$ref?.includes("/NoStore"),
      `${portal.operationId} ${status} must remain no-store`,
    );
  }
}
assert(
  document.components.schemas.SLAObjectProjection === undefined,
  "the retired dual-audience SLA projection must not be reintroduced",
);

for (const [path, filename] of [
  [
    `${tenantBase}/portal/alerts/{alertId}/export`,
    "periapsis-customer-alert.csv",
  ],
  [`${tenantBase}/portal/cases/{caseId}/export`, "periapsis-customer-case.csv"],
]) {
  const value = operation(path, "get");
  const authorization = value["x-periapsis-authorization"];
  const description = value.description.replace(/\s+/gu, " ");
  exact(
    authorization.requiredPermissions,
    ["portal.comment.public"],
    `${value.operationId} must resolve its compound authority atomically`,
  );
  assert(
    authorization.permissionResolution === "same_live_authority_snapshot" &&
      authorization.projection === "customer_safe_export_allowlist" &&
      description.includes("at most 200 public comments") &&
      description.includes("capped at 2 MiB") &&
      description.includes("neutralizes spreadsheet formulas") &&
      description.includes("never loads private comments"),
    `${value.operationId} customer export boundary drifted`,
  );
  const response = value.responses["200"];
  const csv = response.content?.["text/csv"]?.schema;
  assert(
    csv?.type === "string" &&
      csv.format === "binary" &&
      csv.maxLength === 2097152,
    `${value.operationId} must return only a bounded binary CSV`,
  );
  assert(
    response.headers?.["Cache-Control"]?.$ref ===
      "#/components/headers/NoStore" &&
      response.headers?.["Content-Disposition"]?.schema?.const ===
        `attachment; filename="${filename}"` &&
      response.headers?.["X-Content-Type-Options"]?.schema?.const === "nosniff",
    `${value.operationId} download headers drifted`,
  );
  assert(
    value.responses["413"]?.$ref ===
      "#/components/responses/NoStorePayloadTooLarge",
    `${value.operationId} must expose the bounded synchronous limit`,
  );
}

for (const [
  kind,
  identifier,
  ticketPermission,
  listOperationId,
  downloadOperationId,
] of [
  [
    "alerts",
    "alertId",
    "portal.alert.read",
    "listCustomerPortalAlertDfirAttachments",
    "prepareCustomerPortalAlertDfirAttachmentDownload",
  ],
  [
    "cases",
    "caseId",
    "portal.case.read",
    "listCustomerPortalCaseDfirAttachments",
    "prepareCustomerPortalCaseDfirAttachmentDownload",
  ],
]) {
  const base = `${tenantBase}/portal/${kind}/{${identifier}}/dfir/attachments`;
  const list = operation(base, "get");
  const listAuthorization = list["x-periapsis-authorization"];
  exact(
    listAuthorization.requiredPermissions,
    [ticketPermission],
    `${list.operationId} must require the root-ticket read permission`,
  );
  exact(listAuthorization.scopes, ["own"], `${list.operationId} scope drifted`);
  exact(
    listAuthorization.principalTypes,
    ["human"],
    `${list.operationId} principal type drifted`,
  );
  exact(
    listAuthorization.actorKinds,
    ["customer"],
    `${list.operationId} actor kind drifted`,
  );
  assert(
    list.operationId === listOperationId &&
      JSON.stringify(list.security) ===
        JSON.stringify([{ sessionCookie: [] }]) &&
      listAuthorization.tenantContext === "path" &&
      listAuthorization.activeMembership === true &&
      listAuthorization.permission === "portal.attachment.read" &&
      listAuthorization.permissionResolution ===
        "same_live_authority_snapshot" &&
      listAuthorization.exactContactLink === "required_before_pagination" &&
      listAuthorization.visibility === "public_available_only_fail_closed" &&
      listAuthorization.projection === "customer_safe_attachment_allowlist" &&
      listAuthorization.uiVisibilityIsNotAuthorization === true,
    `${list.operationId} customer attachment boundary drifted`,
  );
  const listRefs = parameterRefs(base, list);
  assert(
    listRefs.has(
      "#/components/parameters/CustomerPortalAttachmentAfterCursor",
    ) && listRefs.has("#/components/parameters/PageSize"),
    `${list.operationId} must remain bounded and cursor-paginated`,
  );
  assert(
    list.responses["200"]?.headers?.["Cache-Control"]?.$ref ===
      "#/components/headers/NoStore" &&
      list.responses["200"]?.content?.["application/json"]?.schema?.$ref ===
        "#/components/schemas/CustomerPortalAttachmentList",
    `${list.operationId} must return only the no-store customer attachment page`,
  );

  const downloadPath = `${base}/{attachmentId}/prepare-download`;
  const download = operation(downloadPath, "post");
  const downloadAuthorization = download["x-periapsis-authorization"];
  exact(
    downloadAuthorization.requiredPermissions,
    [ticketPermission],
    `${download.operationId} must require the root-ticket read permission`,
  );
  exact(
    downloadAuthorization.scopes,
    ["own"],
    `${download.operationId} scope drifted`,
  );
  exact(
    downloadAuthorization.principalTypes,
    ["human"],
    `${download.operationId} principal type drifted`,
  );
  exact(
    downloadAuthorization.actorKinds,
    ["customer"],
    `${download.operationId} actor kind drifted`,
  );
  assert(
    download.operationId === downloadOperationId &&
      download.requestBody === undefined &&
      downloadAuthorization.tenantContext === "path" &&
      downloadAuthorization.activeMembership === true &&
      downloadAuthorization.permission === "portal.attachment.read" &&
      downloadAuthorization.permissionResolution ===
        "same_live_authority_snapshot" &&
      downloadAuthorization.exactContactLink === "required_at_prepare" &&
      downloadAuthorization.visibility ===
        "public_available_only_fail_closed" &&
      downloadAuthorization.projection ===
        "customer_safe_attachment_allowlist" &&
      downloadAuthorization.uiVisibilityIsNotAuthorization === true &&
      JSON.stringify(download.security) ===
        JSON.stringify([{ sessionCookie: [], csrfToken: [] }]),
    `${download.operationId} must derive every lookup from the path and require CSRF`,
  );
  assert(
    download.responses["200"]?.headers?.["Cache-Control"]?.$ref ===
      "#/components/headers/NoStore" &&
      download.responses["200"]?.headers?.["Referrer-Policy"]?.$ref ===
        "#/components/headers/NoReferrer" &&
      download.responses["200"]?.content?.["application/json"]?.schema?.$ref ===
        "#/components/schemas/CustomerPortalPreparedAttachmentDownload",
    `${download.operationId} must return only a no-store, no-referrer customer capability`,
  );

  for (const value of [list, download]) {
    for (const status of [
      "400",
      "401",
      "403",
      "404",
      ...(value === download ? ["409"] : []),
      "503",
    ]) {
      assert(
        value.responses[status]?.$ref?.includes("/NoStore"),
        `${value.operationId} ${status} must remain no-store`,
      );
    }
  }
}

const portalAttachment = document.components.schemas.CustomerPortalAttachment;
exact(
  portalAttachment.required,
  [
    "projection",
    "id",
    "resourceKind",
    "resourceId",
    "originalFilename",
    "uploadedAt",
    "downloadable",
  ],
  "customer attachment required fields drifted",
);
assert(
  portalAttachment.additionalProperties === false &&
    portalAttachment.properties.projection.const === "customer" &&
    portalAttachment.properties.downloadable.const === true &&
    portalAttachment.properties.originalFilename.minLength === 1 &&
    portalAttachment.properties.originalFilename.maxLength === 1024 &&
    portalAttachment.properties.originalFilename.pattern !== undefined,
  "customer attachment projection must remain closed and downloadable-only",
);
for (const property of [
  "tenantId",
  "subject",
  "storageObjectId",
  "uploadedBy",
  "classification",
  "visibility",
  "scanState",
]) {
  assert(
    portalAttachment.properties[property] === undefined,
    `customer attachment projection must omit ${property}`,
  );
}
assert(
  document.components.schemas.CustomerPortalAttachmentCursor.minLength === 16 &&
    document.components.schemas.CustomerPortalAttachmentCursor.maxLength ===
      512 &&
    document.components.schemas.CustomerPortalAttachmentCursor.pattern ===
      "^[A-Za-z0-9_-]+$" &&
    document.components.schemas.CustomerPortalAttachmentList
      .additionalProperties === false &&
    document.components.schemas.CustomerPortalAttachmentList.properties.items
      .maxItems === 100 &&
    document.components.schemas.CustomerPortalPreparedAttachmentDownload
      .additionalProperties === false &&
    document.components.schemas.CustomerPortalPreparedAttachmentDownload
      .properties.attachment.$ref ===
      "#/components/schemas/CustomerPortalAttachment" &&
    document.components.schemas.CustomerPortalPreparedAttachmentDownload
      .properties.downloadUrl.maxLength === 8192,
  "customer attachment list and prepared-download projections must remain closed and bounded",
);

for (const path of [
  `${tenantBase}/portal/me/contact`,
  `${tenantBase}/portal/alerts/{alertId}/comments`,
  `${tenantBase}/portal/cases/{caseId}/comments`,
]) {
  const value = operation(
    path,
    "post" in (document.paths[path] ?? {}) ? "post" : "put",
  );
  const refs = parameterRefs(path, value);
  assert(
    refs.has("#/components/parameters/IdempotencyKey"),
    `${value.operationId} must be idempotent`,
  );
}
assert(
  parameterRefs(
    `${tenantBase}/portal/me/contact`,
    operation(`${tenantBase}/portal/me/contact`, "put"),
  ).has("#/components/parameters/IfMatch"),
  "portal preference replacement must require If-Match",
);

const linkedAccount = document.components.schemas.ContactLinkedAccount;
exact(
  linkedAccount.required,
  ["membershipId", "userId"],
  "linked membership and user identity must be atomic",
);
assert(
  linkedAccount.additionalProperties === false,
  "linked identity must remain closed",
);

const window = document.components.schemas.ContactNotificationWindow;
assert(
  window.additionalProperties === false &&
    window.properties.isoWeekday.minimum === 1 &&
    window.properties.isoWeekday.maximum === 7 &&
    window.properties.startMinute.maximum === 1439 &&
    window.properties.endMinute.maximum === 1440,
  "notification windows must remain bounded ISO-weekday half-open intervals",
);

const contactFields = document.components.schemas.CustomerContactFields;
assert(
  contactFields.properties.email.description.includes("Shared mailboxes") &&
    contactFields.properties.notificationWindows.maxItems === 64 &&
    contactFields.properties.tags.uniqueItems === true,
  "contact routing fields must preserve shared mailbox and collection bounds",
);

const portalContact = document.components.schemas.CustomerPortalContact;
assert(
  portalContact.additionalProperties === false &&
    portalContact.properties.active.const === true,
  "portal contact projection must remain closed and active-only",
);
for (const property of [
  "tenantId",
  "contactClass",
  "escalationPriority",
  "tags",
  "linkedAccount",
  "archivedAt",
  "createdAt",
  "updatedAt",
]) {
  assert(
    portalContact.properties[property] === undefined,
    `portal contact projection must omit ${property}`,
  );
}

const rule = document.components.schemas.ContactRecipientRuleNode;
exact(
  rule.properties.kind.enum,
  ["all", "any", "not", "predicate"],
  "recipient rule node kinds drifted",
);
assert(
  rule.additionalProperties === false &&
    rule.properties.children.maxItems === 64 &&
    rule.properties.values.maxItems === 64 &&
    rule.description.includes("maximum depth 8") &&
    rule.description.includes("maximum 128 nodes"),
  "recipient rule AST must remain closed and bounded",
);

const link = document.components.schemas.TicketCustomerContactLink;
for (const property of [
  "email",
  "phone",
  "firstName",
  "lastName",
  "linkedAccount",
]) {
  assert(
    link.properties[property] === undefined,
    `ticket contact links must not embed ${property}`,
  );
}
assert(
  link.properties.escalationProvenance !== undefined,
  "ticket contact links must preserve immutable escalation provenance",
);

assert(
  document.components.schemas.EscalationCopySelection.properties.contactIds !==
    undefined,
  "Alert-to-Case escalation must expose explicit contact copy selection",
);
assert(
  document.components.schemas.CustomerPortalCommentCreate
    .additionalProperties === false &&
    document.components.schemas.CustomerPortalCommentCreate.properties
      .bodyMarkdown.maxLength === 20000,
  "portal comments must remain public Markdown-only bounded input",
);
