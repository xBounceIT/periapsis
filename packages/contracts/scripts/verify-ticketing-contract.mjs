import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const repositoryRoot = resolve(import.meta.dirname, "../../..");
const document = JSON.parse(
  readFileSync(
    resolve(repositoryRoot, "services/api/internal/contract/openapi.json"),
    "utf8",
  ),
);
const generatedSdk = readFileSync(
  resolve(repositoryRoot, "packages/contracts/generated/typescript/sdk.gen.ts"),
  "utf8",
);
const generatedTypes = readFileSync(
  resolve(
    repositoryRoot,
    "packages/contracts/generated/typescript/types.gen.ts",
  ),
  "utf8",
);
const generatedGo = readFileSync(
  resolve(repositoryRoot, "services/api/internal/contract/api.gen.go"),
  "utf8",
);

const fail = (message) => {
  throw new Error(`Ticketing contract invariant failed: ${message}`);
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

const parameterRefs = (value) =>
  new Set((value.parameters ?? []).map((parameter) => parameter.$ref));

const parameterNames = (value) =>
  new Set((value.parameters ?? []).map((parameter) => parameter.name));

const securityAlternatives = (value) => value.security ?? [];

const requestSchema = (value) =>
  value.requestBody?.content?.["application/json"]?.schema;

const responseSchema = (value, status) =>
  value.responses?.[status]?.content?.["application/json"]?.schema;

const problemRefs = (response) => {
  if (response?.$ref !== undefined) {
    const name = response.$ref.replace("#/components/responses/", "");
    return problemRefs(document.components.responses[name]);
  }
  const schema = response?.content?.["application/problem+json"]?.schema;
  if (schema?.$ref !== undefined) return [schema.$ref];
  return [...(schema?.oneOf ?? []), ...(schema?.anyOf ?? [])].flatMap(
    (branch) => (branch.$ref === undefined ? [] : [branch.$ref]),
  );
};

const alertBase = "/api/v1/tenants/{tenantId}/alerts";
const alertItem = `${alertBase}/{alertId}`;
const caseBase = "/api/v1/tenants/{tenantId}/cases";
const caseItem = `${caseBase}/{caseId}`;
const alertActivityFeed = "/api/v1/tenants/{tenantId}/activities/alerts";
const caseActivityFeed = "/api/v1/tenants/{tenantId}/activities/cases";
const liveScopes = ["own", "assigned", "operator_team", "tenant"];

const phaseThreeOperations = [
  [alertBase, "get", "alert.read"],
  [alertItem, "get", "alert.read"],
  [alertItem, "delete", "alert.delete"],
  [`${alertItem}/transition`, "post", "alert.update"],
  [`${alertItem}/close`, "post", "alert.update"],
  [`${alertItem}/reopen`, "post", "alert.update"],
  [`${alertItem}/assign`, "post", "alert.assign"],
  [`${alertItem}/claim`, "post", "alert.claim"],
  [`${alertItem}/release`, "post", "alert.claim"],
  [`${alertItem}/transfer`, "post", "alert.assign"],
  [`${alertItem}/escalate`, "post", "alert.escalate"],
  [`${alertItem}/link`, "post", "alert.escalate"],
  [`${alertItem}/unlink`, "post", "alert.escalate"],
  [`${alertItem}/comments`, "get", "alert.comment.read"],
  [`${alertItem}/comments`, "post", "alert.comment.public"],
  [`${alertItem}/activities`, "get", "alert.read"],
  [`${alertItem}/linked-cases`, "get", "alert.read"],
  [caseBase, "get", "case.read"],
  [caseBase, "post", "case.create"],
  [caseItem, "get", "case.read"],
  [`${caseItem}/transition`, "post", "case.transition"],
  [`${caseItem}/close`, "post", "case.transition"],
  [`${caseItem}/reopen`, "post", "case.transition"],
  [`${caseItem}/assign`, "post", "case.transfer"],
  [`${caseItem}/claim`, "post", "case.claim"],
  [`${caseItem}/release`, "post", "case.claim"],
  [`${caseItem}/transfer`, "post", "case.transfer"],
  [`${caseItem}/comments`, "get", "case.comment.read"],
  [`${caseItem}/comments`, "post", "case.comment.public"],
  [`${caseItem}/activities`, "get", "case.read"],
  [`${caseItem}/linked-alerts`, "get", "case.read"],
];

for (const [path, method, permission] of phaseThreeOperations) {
  const value = operation(path, method);
  assert(
    securityAlternatives(value).some(
      (alternative) => alternative.sessionCookie !== undefined,
    ),
    `${value.operationId} must authenticate a live human session`,
  );
  const authorization = value["x-periapsis-authorization"];
  assert(
    authorization?.tenantContext === "path" &&
      authorization.activeMembership === true &&
      authorization.permission === permission,
    `${value.operationId} tenant authority metadata drifted`,
  );
  exact(
    authorization.principalTypes,
    ["human"],
    `${value.operationId} must remain human-only`,
  );
  exact(
    authorization.scopes,
    permission === "case.create" ? ["tenant"] : liveScopes,
    `${value.operationId} must declare exact live authorization scopes`,
  );
  if (!["get", "head", "options"].includes(method)) {
    assert(
      securityAlternatives(value).some(
        (alternative) => alternative.csrfToken !== undefined,
      ),
      `${value.operationId} must require CSRF for cookie mutations`,
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

for (const feed of [
  {
    path: alertActivityFeed,
    permission: "alert.activity.read",
    liveTicketReadPermission: "alert.read",
    operationId: "listTenantAlertActivityFeed",
    typeName: "ListTenantAlertActivityFeed",
  },
  {
    path: caseActivityFeed,
    permission: "case.activity.read",
    liveTicketReadPermission: "case.read",
    operationId: "listTenantCaseActivityFeed",
    typeName: "ListTenantCaseActivityFeed",
  },
]) {
  const value = operation(feed.path, "get");
  const authorization = value["x-periapsis-authorization"];
  exact(
    securityAlternatives(value),
    [{ sessionCookie: [] }],
    `${feed.operationId} must authenticate only a live human session`,
  );
  assert(
    value.operationId === feed.operationId &&
      authorization?.tenantContext === "path" &&
      authorization.activeMembership === true &&
      authorization.permission === feed.permission &&
      authorization.liveTicketReadPermission ===
        feed.liveTicketReadPermission &&
      authorization.permissionResolution === "same_live_authority_snapshot" &&
      authorization.projection === "operator_safe_fail_closed",
    `${feed.operationId} compound live authorization metadata drifted`,
  );
  exact(
    authorization.scopes,
    liveScopes,
    `${feed.operationId} live scopes drifted`,
  );
  exact(
    authorization.principalTypes,
    ["human"],
    `${feed.operationId} must remain human-only`,
  );
  exact(
    authorization.actorKinds,
    ["operator"],
    `${feed.operationId} must remain operator-only`,
  );
  assert(
    parameterRefs(value).has("#/components/parameters/AfterCursor") &&
      parameterRefs(value).has("#/components/parameters/PageSize") &&
      responseSchema(value, "200")?.$ref ===
        "#/components/schemas/OperatorActivityList" &&
      value.responses["200"].headers?.["Cache-Control"]?.$ref ===
        "#/components/headers/NoStore" &&
      value.description.includes("not the immutable security audit log") &&
      value.description.includes("removed before pagination"),
    `${feed.operationId} bounded operator projection or audit separation drifted`,
  );
  for (const [status, response] of Object.entries(value.responses ?? {})) {
    if (Number(status) < 400) continue;
    exact(
      problemRefs(response),
      ["#/components/schemas/Problem"],
      `${feed.operationId} ${status} must use RFC 9457 Problem Details`,
    );
  }
  assert(
    generatedSdk.includes(`export const ${feed.operationId} =`) &&
      generatedTypes.includes(`export type ${feed.typeName}Data =`) &&
      generatedGo.includes(`\t${feed.typeName}(w http.ResponseWriter`) &&
      generatedGo.includes(`http.MethodGet+" "+options.BaseURL+"${feed.path}"`),
    `${feed.operationId} generated TypeScript and Go surfaces drifted`,
  );
}

assert(
  document.components.schemas.OperatorActivityList.additionalProperties ===
    false &&
    document.components.schemas.OperatorActivityList.properties.items
      .maxItems === 100 &&
    document.components.schemas.OperatorActivityList.properties.items.items
      .$ref === "#/components/schemas/OperatorActivity" &&
    document.components.schemas.OperatorActivityList.properties.nextCursor
      .format === "uuid",
  "tenant activity feed must remain closed, bounded, operator-only, and UUID-cursor paginated",
);

for (const [path, listSchema] of [
  [alertBase, "#/components/schemas/AlertList"],
  [caseBase, "#/components/schemas/CaseList"],
]) {
  const value = operation(path, "get");
  assert(
    parameterRefs(value).has("#/components/parameters/TicketAfterCursor") &&
      parameterRefs(value).has("#/components/parameters/PageSize"),
    `${value.operationId} must use bounded opaque cursor pagination`,
  );
  const filters = parameterNames(value);
  for (const name of [
    "status",
    "severity",
    "priority",
    "assignedTeamId",
    "assigneeUserId",
    "claimedBy",
    "queue",
    "customerVisible",
    "search",
    "customFieldKey",
    "customFieldValue",
    "sort",
  ]) {
    assert(filters.has(name), `${value.operationId} lacks ${name} filtering`);
  }
  assert(
    responseSchema(value, "200")?.$ref === listSchema,
    `${value.operationId} response projection drifted`,
  );
}
assert(
  document.components.schemas.TicketCursor.maxLength === 512 &&
    document.components.schemas.TicketCursor.pattern !== undefined &&
    document.components.schemas.TicketSort.description.includes(
      "deterministic tie-breaker",
    ),
  "ticket cursors and sort orders must remain bounded and deterministic",
);

const alertCreate = operation(alertBase, "post");
exact(
  alertCreate.security,
  [{ sessionCookie: [], csrfToken: [] }, { serviceAccountBearer: [] }],
  "existing alert.create service-principal compatibility must remain exact",
);
assert(
  parameterRefs(alertCreate).has("#/components/parameters/IdempotencyKey") &&
    requestSchema(alertCreate)?.$ref ===
      "#/components/schemas/AlertCreateRequest",
  "Alert create must preserve its idempotent compatible command",
);
for (const property of ["rawPayload", "tags", "customFields"]) {
  assert(
    document.components.schemas.AlertCreateRequest.properties[property] !==
      undefined,
    `Alert create must accept ${property}`,
  );
}
const caseCreate = operation(caseBase, "post");
assert(
  parameterRefs(caseCreate).has("#/components/parameters/IdempotencyKey") &&
    requestSchema(caseCreate)?.$ref ===
      "#/components/schemas/CaseCreateRequest" &&
    responseSchema(caseCreate, "201")?.$ref ===
      "#/components/schemas/CaseOperatorProjection",
  "Case create must be bounded and idempotent",
);

const optimisticActions = [
  [`${alertItem}/transition`, "#/components/schemas/TicketTransitionRequest"],
  [`${alertItem}/close`, "#/components/schemas/TicketTransitionRequest"],
  [`${alertItem}/reopen`, "#/components/schemas/TicketTransitionRequest"],
  [`${alertItem}/assign`, "#/components/schemas/TicketAssignmentRequest"],
  [`${alertItem}/claim`, "#/components/schemas/TicketClaimRequest"],
  [`${alertItem}/release`, "#/components/schemas/TicketReleaseRequest"],
  [`${alertItem}/transfer`, "#/components/schemas/TicketTransferRequest"],
  [`${caseItem}/transition`, "#/components/schemas/TicketTransitionRequest"],
  [`${caseItem}/close`, "#/components/schemas/TicketTransitionRequest"],
  [`${caseItem}/reopen`, "#/components/schemas/TicketTransitionRequest"],
  [`${caseItem}/assign`, "#/components/schemas/TicketAssignmentRequest"],
  [`${caseItem}/claim`, "#/components/schemas/TicketClaimRequest"],
  [`${caseItem}/release`, "#/components/schemas/TicketReleaseRequest"],
  [`${caseItem}/transfer`, "#/components/schemas/TicketTransferRequest"],
];
for (const [path, schemaRef] of optimisticActions) {
  const value = operation(path, "post");
  exact(
    value["x-periapsis-authorization"].actorKinds,
    ["operator"],
    `${value.operationId} must reject customer actors even if the UI is stale`,
  );
  assert(
    parameterRefs(value).has("#/components/parameters/IfMatch") &&
      value.responses["412"] !== undefined &&
      value.responses["428"] !== undefined,
    `${value.operationId} must require strong optimistic concurrency`,
  );
  assert(
    requestSchema(value)?.$ref === schemaRef,
    `${value.operationId} request schema drifted`,
  );
  const name = schemaRef.replace("#/components/schemas/", "");
  assert(
    document.components.schemas[name].required.includes("expectedVersion"),
    `${name} must bind the numeric expected version`,
  );
}
const alertDelete = operation(alertItem, "delete");
assert(
  parameterRefs(alertDelete).has("#/components/parameters/IfMatch") &&
    parameterRefs(alertDelete).has("#/components/parameters/IdempotencyKey") &&
    requestSchema(alertDelete)?.$ref ===
      "#/components/schemas/AlertDeleteRequest" &&
    responseSchema(alertDelete, "200")?.$ref ===
      "#/components/schemas/AlertDeleteReceipt" &&
    alertDelete.responses["412"] !== undefined &&
    alertDelete.responses["428"] !== undefined,
  "Alert delete must be optimistic, idempotent, and receipt-bearing",
);
exact(
  alertDelete["x-periapsis-authorization"].actorKinds,
  ["operator"],
  "Alert delete must remain human-operator-only",
);
assert(
  document.components.schemas.AlertDeleteRequest.required.includes(
    "expectedVersion",
  ) &&
    document.components.schemas.AlertDeleteRequest.required.includes(
      "reason",
    ) &&
    document.components.schemas.AlertDeleteRequest.additionalProperties ===
      false &&
    document.components.schemas.AlertDeleteReceipt.additionalProperties ===
      false &&
    document.components.schemas.AlertDeleteReceipt.properties.replayed.type ===
      "boolean",
  "Alert delete request and receipt must stay closed and version-bound",
);
for (const path of [
  caseBase,
  `${alertItem}/escalate`,
  `${alertItem}/link`,
  `${alertItem}/unlink`,
]) {
  const value = operation(path, "post");
  exact(
    value["x-periapsis-authorization"].actorKinds,
    ["operator"],
    `${value.operationId} must remain operator-only`,
  );
}

const explicitLink = operation(`${alertItem}/link`, "post");
const explicitUnlink = operation(`${alertItem}/unlink`, "post");
for (const value of [explicitLink, explicitUnlink]) {
  assert(
    parameterRefs(value).has("#/components/parameters/IfMatch") &&
      parameterRefs(value).has("#/components/parameters/IdempotencyKey") &&
      value.responses["409"] !== undefined &&
      value.responses["412"] !== undefined &&
      value.responses["428"] !== undefined,
    `${value.operationId} must remain optimistic, payload-bound, and idempotent`,
  );
  assert(
    value["x-periapsis-authorization"].permissionResolution ===
      "same_live_authority_snapshot",
    `${value.operationId} must reauthorize both aggregates without case.create`,
  );
}
assert(
  explicitLink["x-periapsis-authorization"].conditionalPermissions
    .existing_case === "case.update" &&
    explicitUnlink["x-periapsis-authorization"].conditionalPermissions
      .linked_case === "case.update",
  "explicit link/unlink must pair alert.escalate with case.update",
);
assert(
  requestSchema(explicitLink)?.$ref ===
    "#/components/schemas/AlertCaseLinkRequest" &&
    document.components.schemas.AlertCaseLinkRequest.properties.target.$ref ===
      "#/components/schemas/ExistingCaseEscalationTarget" &&
    !JSON.stringify(document.components.schemas.AlertCaseLinkRequest).includes(
      "NewCaseEscalationTarget",
    ) &&
    responseSchema(explicitLink, "200")?.$ref ===
      "#/components/schemas/AlertCaseEscalationResult",
  "explicit link must structurally accept only an existing Case and reuse the escalation receipt",
);
assert(
  requestSchema(explicitUnlink)?.$ref ===
    "#/components/schemas/AlertCaseUnlinkRequest" &&
    responseSchema(explicitUnlink, "200")?.$ref ===
      "#/components/schemas/AlertCaseUnlinkReceipt" &&
    document.components.schemas.AlertCaseUnlinkRequest.additionalProperties ===
      false &&
    document.components.schemas.AlertCaseUnlinkReceipt.additionalProperties ===
      false &&
    ["expectedVersion", "caseId", "expectedCaseVersion", "reason"].every(
      (field) =>
        document.components.schemas.AlertCaseUnlinkRequest.required.includes(
          field,
        ),
    ),
  "explicit unlink must bind both aggregate versions and return a closed receipt",
);
assert(
  explicitLink.description.includes("terminal") &&
    explicitUnlink.description.includes("cannot be linked again"),
  "terminal Alert/Case pair semantics must stay documented",
);
assert(
  generatedSdk.includes("export const linkTenantAlertToExistingCase =") &&
    generatedSdk.includes("export const unlinkTenantAlertFromCase =") &&
    generatedTypes.includes(
      "export type LinkTenantAlertToExistingCaseData =",
    ) &&
    generatedTypes.includes("export type UnlinkTenantAlertFromCaseData =") &&
    generatedGo.includes(
      "\tLinkTenantAlertToExistingCase(w http.ResponseWriter",
    ) &&
    generatedGo.includes("\tUnlinkTenantAlertFromCase(w http.ResponseWriter") &&
    generatedGo.includes(
      `http.MethodPost+" "+options.BaseURL+"${alertItem}/link"`,
    ) &&
    generatedGo.includes(
      `http.MethodPost+" "+options.BaseURL+"${alertItem}/unlink"`,
    ),
  "explicit link/unlink generated TypeScript and Go surfaces drifted",
);
for (const path of [
  `${alertItem}/transition`,
  `${alertItem}/close`,
  `${alertItem}/reopen`,
  `${caseItem}/transition`,
  `${caseItem}/close`,
  `${caseItem}/reopen`,
]) {
  assert(
    parameterRefs(operation(path, "post")).has(
      "#/components/parameters/IdempotencyKey",
    ),
    `${path} must be idempotent`,
  );
}

const explicitTransitionOperations = [
  {
    canonical: `${alertItem}/transition`,
    explicit: `${alertItem}/close`,
    operationId: "closeTenantAlert",
    typeName: "CloseTenantAlert",
    intentText: ["non-terminal", "terminal"],
  },
  {
    canonical: `${alertItem}/transition`,
    explicit: `${alertItem}/reopen`,
    operationId: "reopenTenantAlert",
    typeName: "ReopenTenantAlert",
    intentText: ["terminal current state", "declared as reopen"],
  },
  {
    canonical: `${caseItem}/transition`,
    explicit: `${caseItem}/close`,
    operationId: "closeTenantCase",
    typeName: "CloseTenantCase",
    intentText: ["non-terminal", "terminal"],
  },
  {
    canonical: `${caseItem}/transition`,
    explicit: `${caseItem}/reopen`,
    operationId: "reopenTenantCase",
    typeName: "ReopenTenantCase",
    intentText: ["terminal current state", "declared as reopen"],
  },
];
const transitionShape = (path) => {
  const value = operation(path, "post");
  return {
    pathParameters: document.paths[path].parameters,
    tags: value.tags,
    security: value.security,
    authorization: value["x-periapsis-authorization"],
    parameters: value.parameters,
    requestBody: value.requestBody,
    successHeaders: value.responses["200"].headers,
    successContent: value.responses["200"].content,
    errors: Object.fromEntries(
      ["400", "401", "403", "404", "409", "412", "428", "503"].map((status) => [
        status,
        value.responses[status],
      ]),
    ),
  };
};
for (const explicit of explicitTransitionOperations) {
  const value = operation(explicit.explicit, "post");
  exact(
    transitionShape(explicit.explicit),
    transitionShape(explicit.canonical),
    `${explicit.operationId} must preserve the canonical transition transport and authorization contract`,
  );
  assert(
    explicit.intentText.every((text) => value.description.includes(text)),
    `${explicit.operationId} must document its server-bound workflow intent`,
  );
  assert(
    generatedSdk.includes(`export const ${explicit.operationId} =`) &&
      generatedTypes.includes(`export type ${explicit.typeName}Data =`) &&
      generatedGo.includes(`\t${explicit.typeName}(w http.ResponseWriter`) &&
      generatedGo.includes(
        `http.MethodPost+" "+options.BaseURL+"${explicit.explicit}"`,
      ),
    `${explicit.operationId} generated TypeScript/Go surface drifted`,
  );
}

for (const [path, resultRef] of [
  [`${alertItem}/claim`, "#/components/schemas/AlertClaimResult"],
  [`${caseItem}/claim`, "#/components/schemas/CaseClaimResult"],
]) {
  const value = operation(path, "post");
  assert(
    responseSchema(value, "200")?.$ref === resultRef &&
      value.responses["409"] !== undefined &&
      value["x-periapsis-authorization"].atomicClaimWinner ===
        "persisted_compare_and_swap",
    `${value.operationId} must expose one persisted winner and a conflict loser`,
  );
}
assert(
  document.components.schemas.AlertClaimResult.properties.alert.$ref ===
    "#/components/schemas/AlertOperatorProjection" &&
    document.components.schemas.CaseClaimResult.properties.case.$ref ===
      "#/components/schemas/CaseOperatorProjection",
  "operator-only claim commands must not return an ambiguous customer branch",
);
exact(
  document.components.schemas.TicketSideEffectKind.enum,
  ["activity", "audit", "sla", "notification"],
  "mutation side effects must remain a closed plan",
);
assert(
  document.components.schemas.TicketSideEffectPlan.minItems === 2 &&
    document.components.schemas.TicketSideEffectPlan.maxItems === 4 &&
    document.components.schemas.TicketSideEffectPlan.allOf[0].contains.const ===
      "activity" &&
    document.components.schemas.TicketSideEffectPlan.allOf[1].contains.const ===
      "audit",
  "activity and audit must remain mandatory while SLA and notification stay declarative",
);

const escalation = operation(`${alertItem}/escalate`, "post");
assert(
  parameterRefs(escalation).has("#/components/parameters/IfMatch") &&
    parameterRefs(escalation).has("#/components/parameters/IdempotencyKey") &&
    requestSchema(escalation)?.$ref ===
      "#/components/schemas/AlertCaseEscalationRequest",
  "Alert escalation must be optimistic and idempotent",
);
exact(
  escalation["x-periapsis-authorization"].conditionalPermissions,
  { create_case: "case.create", existing_case: "case.update" },
  "Alert escalation target permissions drifted",
);
const escalationRequest =
  document.components.schemas.AlertCaseEscalationRequest;
assert(
  escalationRequest.properties.sources.minItems === 1 &&
    escalationRequest.properties.sources.maxItems === 100 &&
    escalationRequest.required.includes("expectedVersion"),
  "Alert escalation sources must be bounded and versioned",
);
for (const property of [
  "linkedAt",
  "linkedBy",
  "relationType",
  "escalationReason",
  "copiedFieldSnapshot",
  "sourceAlertVersion",
]) {
  assert(
    document.components.schemas.AlertCaseLink.required.includes(property),
    `Alert/Case link must preserve ${property}`,
  );
}
exact(
  document.components.schemas.AlertCaseRelationType.enum,
  ["escalation", "correlation"],
  "Alert/Case relation types must match the deterministic kernel",
);
assert(
  document.components.schemas.EscalationCopySelection.properties
    .publicCommentIds !== undefined &&
    document.components.schemas.EscalationCopySelection.properties
      .privateCommentIds === undefined &&
    document.components.schemas.EscalationCopySelection.minProperties ===
      undefined,
  "escalation must have no private-comment channel and must permit link-only copies",
);

for (const [path, publicPermission, privatePermission] of [
  [`${alertItem}/comments`, "alert.comment.public", "alert.comment.private"],
  [`${caseItem}/comments`, "case.comment.public", "case.comment.private"],
]) {
  const value = operation(path, "post");
  assert(
    parameterRefs(value).has("#/components/parameters/IdempotencyKey") &&
      value["x-periapsis-authorization"].permission === publicPermission &&
      value["x-periapsis-authorization"].conditionalPermissions.private ===
        privatePermission,
    `${value.operationId} comment permissions drifted`,
  );
  exact(
    value["x-periapsis-authorization"].actorKinds,
    ["operator"],
    `${value.operationId} must remain operator-only; customers use the exact-contact portal operation`,
  );
}
for (const [path, permission] of [
  [
    "/api/v1/tenants/{tenantId}/portal/alerts/{alertId}/comments",
    "portal.comment.public",
  ],
  [
    "/api/v1/tenants/{tenantId}/portal/cases/{caseId}/comments",
    "portal.comment.public",
  ],
]) {
  for (const method of ["get", "post"]) {
    const value = operation(path, method);
    assert(
      value["x-periapsis-authorization"].permission === permission,
      `${value.operationId} portal comment permission drifted`,
    );
    exact(
      value["x-periapsis-authorization"].actorKinds,
      ["customer"],
      `${value.operationId} must remain customer-only`,
    );
  }
}
exact(
  document.components.schemas.CommentVisibility.enum,
  ["public", "private"],
  "comment visibility must remain closed",
);
assert(
  document.components.schemas.CommentCreateRequest.properties.bodyMarkdown
    .maxLength === 20000 &&
    document.components.schemas.CommentCreateRequest.properties.attachmentIds
      .maxItems === 20 &&
    document.components.schemas.CommentCreateRequest.properties
      .mentionedMembershipIds.maxItems === 50,
  "comment write bounds must match the application boundary",
);
assert(
  document.components.schemas.CustomerComment.properties.visibility.const ===
    "public",
  "customer comments must be structurally public-only",
);
for (const property of [
  "rawPayload",
  "classification",
  "assignment",
  "creator",
  "availableTransitions",
]) {
  assert(
    document.components.schemas.AlertCustomerProjection.properties[property] ===
      undefined,
    `customer Alert projection must omit ${property}`,
  );
  assert(
    document.components.schemas.CaseCustomerProjection.properties[property] ===
      undefined,
    `customer Case projection must omit ${property}`,
  );
}
assert(
  !document.components.schemas.CustomerActivityKind.enum.some((kind) =>
    kind.includes("private"),
  ) &&
    document.components.schemas.CustomerActivity.properties.details ===
      undefined,
  "customer activity must structurally exclude private and arbitrary details",
);
exact(
  document.components.schemas.OperatorActivityActor.oneOf.map(
    (branch) => branch.$ref,
  ),
  [
    "#/components/schemas/OperatorCommentAuthor",
    "#/components/schemas/ServiceAccountActivityActor",
    "#/components/schemas/SystemActivityActor",
  ],
  "operator activity actors must remain a closed structurally discriminated union",
);
assert(
  document.components.schemas.OperatorCommentAuthor.required.includes(
    "membershipId",
  ) &&
    document.components.schemas.ServiceAccountActivityActor.required.includes(
      "serviceAccountId",
    ) &&
    document.components.schemas.ServiceAccountActivityActor.properties
      .principalType.const === "service_account" &&
    document.components.schemas.SystemActivityActor.properties.principalType
      .const === "system" &&
    document.components.schemas.ServiceAccountActivityActor
      .additionalProperties === false &&
    document.components.schemas.SystemActivityActor.additionalProperties ===
      false,
  "activity actor identities must reject missing and mixed principal data",
);

assert(
  document.components.schemas.AlertWorkflowState.allOf[1].properties.kind
    .const === "alert" &&
    document.components.schemas.CaseWorkflowState.allOf[1].properties.kind
      .const === "case",
  "Alert and Case workflow versions must remain separate",
);
assert(
  document.components.schemas.AlertCustomerProjection.properties.workflow
    .$ref === "#/components/schemas/AlertCustomerWorkflowState" &&
    document.components.schemas.CaseCustomerProjection.properties.workflow
      .$ref === "#/components/schemas/CaseCustomerWorkflowState" &&
    document.components.schemas.AlertCustomerWorkflowState.allOf[1].properties
      .customerVisible.const === true &&
    document.components.schemas.CaseCustomerWorkflowState.allOf[1].properties
      .customerVisible.const === true,
  "customer projections must expose customer-visible workflow states only",
);
assert(
  document.components.schemas.AlertCaseCopiedFieldSnapshot
    .additionalProperties === false &&
    document.components.schemas.ActivityDetails.additionalProperties.$ref ===
      "#/components/schemas/CustomFieldValue",
  "copied snapshots and activity details must remain bounded",
);
for (const schemaName of [
  "TicketTransitionRequest",
  "TicketAssignmentRequest",
  "TicketClaimRequest",
  "TicketReleaseRequest",
  "AlertDeleteRequest",
  "AlertDeleteReceipt",
  "TicketTransferRequest",
  "AlertCaseEscalationRequest",
  "CommentCreateRequest",
  "AlertOperatorProjection",
  "AlertCustomerProjection",
  "CaseOperatorProjection",
  "CaseCustomerProjection",
  "OperatorComment",
  "CustomerComment",
  "OperatorActivity",
  "CustomerActivity",
]) {
  assert(
    document.components.schemas[schemaName].additionalProperties === false,
    `${schemaName} must reject unknown fields`,
  );
}

const exportCollection = "/api/v1/tenants/{tenantId}/ticket-exports";
const exportItem = `${exportCollection}/{jobId}`;
const exportDownload = `${exportItem}/prepare-download`;
const exportOperations = [
  [exportCollection, "post"],
  [exportItem, "get"],
  [exportDownload, "post"],
  [`${exportItem}/cancel`, "post"],
];
for (const [path, method] of exportOperations) {
  const value = operation(path, method);
  const authorization = value["x-periapsis-authorization"];
  exact(
    securityAlternatives(value),
    method === "post"
      ? [{ sessionCookie: [], csrfToken: [] }]
      : [{ sessionCookie: [] }],
    `${value.operationId} authentication or CSRF requirements drifted`,
  );
  assert(
    authorization.tenantContext === "path" &&
      authorization.activeMembership === true &&
      authorization.ownership === "exact_membership" &&
      authorization.uiVisibilityIsNotAuthorization === true,
    `${value.operationId} must re-resolve exact live tenant membership`,
  );
  exact(
    authorization.actorKinds,
    ["operator"],
    `${value.operationId} must remain operator-only`,
  );
  exact(
    authorization.principalTypes,
    ["human"],
    `${value.operationId} must remain exact-membership human-only`,
  );
  exact(
    authorization.scopes,
    liveScopes,
    `${value.operationId} live scopes drifted`,
  );
  exact(
    authorization.permissionsByKind,
    { alert: "alert.read", case: "case.read" },
    `${value.operationId} must repeat live ticket-read authority`,
  );
  if (method === "post" && path !== exportDownload) {
    assert(
      parameterRefs(value).has("#/components/parameters/IdempotencyKey"),
      `${value.operationId} must bind one idempotent attempt`,
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

const exportRequest = operation(exportCollection, "post");
const exportDownloadOperation = operation(exportDownload, "post");
exact(
  exportRequest["x-periapsis-authorization"].privateCommentPermissionsByKind,
  { alert: "alert.comment.private", case: "case.comment.private" },
  "private-comment exports must declare their additional live permissions",
);
assert(
  requestSchema(exportRequest)?.$ref ===
    "#/components/schemas/TicketExportJobRequest" &&
    responseSchema(exportRequest, "202")?.$ref ===
      "#/components/schemas/TicketExportJobMutationResult" &&
    responseSchema(operation(exportItem, "get"), "200")?.$ref ===
      "#/components/schemas/TicketExportJob" &&
    responseSchema(exportDownloadOperation, "200")?.$ref ===
      "#/components/schemas/TicketExportPreparedDownload" &&
    exportDownloadOperation["x-periapsis-authorization"].liveReauthorization ===
      "every_grant" &&
    exportDownloadOperation.responses["409"] !== undefined &&
    requestSchema(operation(`${exportItem}/cancel`, "post"))?.$ref ===
      "#/components/schemas/TicketExportJobCancelRequest" &&
    operation(`${exportItem}/cancel`, "post").responses["412"] !== undefined,
  "ticket-export request, read, download, or cancellation contract drifted",
);

const exportSchemas = document.components.schemas;
exact(
  Object.keys(exportSchemas.TicketExportJobRequest.properties).sort(),
  [
    "comments",
    "kind",
    "maximumBytes",
    "maximumRows",
    "retentionSeconds",
    "source",
  ],
  "ticket-export request must not accept audience, format, or delivery controls",
);
exact(
  [...exportSchemas.TicketExportJobRequest.required].sort(),
  ["comments", "kind", "source"],
  "ticket-export request required members drifted",
);
exact(
  [...exportSchemas.TicketExportSourceRequest.required].sort(),
  ["source"],
  "ticket-export source discriminator must be required",
);
assert(
  exportSchemas.TicketExportSourceRequest.allOf?.length === 2 &&
    exportSchemas.TicketExportQuerySnapshot.allOf?.length === 2 &&
    exportSchemas.TicketExportJob.allOf?.length === 4,
  "ticket-export source, snapshot, or terminal-state conditionals drifted",
);
exact(
  [...exportSchemas.TicketExportQuerySnapshot.required].sort(),
  ["catalogSha256", "effectiveSpec", "querySha256", "source"],
  "ticket-export query receipt must retain its immutable snapshot proof",
);
assert(
  exportSchemas.TicketExportJobRequest.properties.maximumRows.maximum ===
    100000 &&
    exportSchemas.TicketExportJobRequest.properties.maximumBytes.maximum ===
      536870912 &&
    exportSchemas.TicketExportJobRequest.properties.retentionSeconds.minimum ===
      900 &&
    exportSchemas.TicketExportJobRequest.properties.retentionSeconds.maximum ===
      604800 &&
    exportSchemas.TicketExportJobCancelRequest.properties.expectedRevision
      .maximum === 2147483646 &&
    exportSchemas.TicketExportArtifact.properties.rows.minimum === 0,
  "ticket-export limits, empty exports, retention, or cancellation CAS drifted",
);
exact(
  exportSchemas.TicketExportCommentScope.enum,
  ["none", "public", "public_and_private"],
  "ticket-export comment scope must remain closed",
);
exact(
  exportSchemas.TicketExportState.enum,
  [
    "pending",
    "running",
    "cancellation_requested",
    "succeeded",
    "failed",
    "cancelled",
  ],
  "ticket-export state vocabulary drifted",
);
exact(
  exportSchemas.TicketExportFailureCode.enum,
  [
    "none",
    "transient_storage",
    "transient_database",
    "authorization_revoked",
    "snapshot_stale",
    "output_limit",
    "lease_expired",
    "expired",
    "internal",
  ],
  "ticket-export failure taxonomy must remain bounded and redacted",
);
exact(
  Object.keys(exportSchemas.TicketExportArtifact.properties).sort(),
  ["bytes", "expiresAt", "id", "rows", "sha256"],
  "artifact projection must not expose object keys or delivery URLs",
);
assert(
  exportSchemas.TicketExportJob.properties.lease === undefined &&
    exportSchemas.TicketExportJob.properties.fence === undefined &&
    exportSchemas.TicketExportArtifact.properties.downloadUrl === undefined &&
    exportSchemas.TicketExportPreparedDownload.properties.downloadUrl
      .maxLength === 8192,
  "owner projection or short-lived download boundary drifted",
);
exact(
  Object.keys(exportSchemas.TicketExportPreparedDownload.properties).sort(),
  ["artifact", "downloadUrl", "expiresAt"],
  "prepared download must expose only the verified artifact and short-lived capability",
);
for (const schemaName of [
  "TicketExportSavedViewSourceRequest",
  "TicketExportSourceRequest",
  "TicketExportJobRequest",
  "TicketExportJobCancelRequest",
  "TicketExportSavedViewPin",
  "TicketExportQuerySnapshot",
  "TicketExportArtifact",
  "TicketExportPreparedDownload",
  "TicketExportJob",
  "TicketExportJobMutationResult",
]) {
  assert(
    exportSchemas[schemaName].additionalProperties === false,
    `${schemaName} must reject unknown fields`,
  );
}

const savedViewCollection = "/api/v1/tenants/{tenantId}/ticket-views";
const savedViewItem = `${savedViewCollection}/{viewId}`;
const savedViewOperations = [
  [savedViewCollection, "get"],
  [savedViewCollection, "post"],
  [savedViewItem, "get"],
  [savedViewItem, "put"],
  [`${savedViewItem}/archive`, "post"],
  [`${savedViewItem}/restore`, "post"],
];
for (const [path, method] of savedViewOperations) {
  const value = operation(path, method);
  const authorization = value["x-periapsis-authorization"];
  exact(
    authorization.permissionsByKind,
    { alert: "alert.read", case: "case.read" },
    `${value.operationId} must reuse live ticket-read authority by kind`,
  );
  exact(
    authorization.actorKinds,
    ["operator"],
    `${value.operationId} must remain operator-only`,
  );
  exact(
    authorization.principalTypes,
    ["human"],
    `${value.operationId} must remain exact-membership human-only`,
  );
  exact(
    authorization.scopes,
    liveScopes,
    `${value.operationId} live scopes drifted`,
  );
  if (!["get", "head", "options"].includes(method)) {
    assert(
      parameterRefs(value).has("#/components/parameters/IdempotencyKey") &&
        securityAlternatives(value).some(
          (alternative) => alternative.csrfToken !== undefined,
        ),
      `${value.operationId} must bind CSRF and one idempotent attempt`,
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

const savedViewList = operation(savedViewCollection, "get");
assert(
  parameterRefs(savedViewList).has(
    "#/components/parameters/SavedViewAfterCursor",
  ) &&
    parameterRefs(savedViewList).has("#/components/parameters/SavedViewKind") &&
    parameterRefs(savedViewList).has(
      "#/components/parameters/IncludeArchived",
    ) &&
    responseSchema(savedViewList, "200")?.$ref ===
      "#/components/schemas/SavedTicketViewPage",
  "saved-view inventory must be kind-scoped, cursor-paginated, and lifecycle-aware",
);
assert(
  parameterRefs(operation(alertBase, "get")).has(
    "#/components/parameters/TicketSavedViewId",
  ) &&
    parameterRefs(operation(caseBase, "get")).has(
      "#/components/parameters/TicketSavedViewId",
    ),
  "Alert and Case lists must expose one private saved-view execution parameter",
);

const savedViewCreate = operation(savedViewCollection, "post");
const savedViewReplace = operation(savedViewItem, "put");
assert(
  requestSchema(savedViewCreate)?.$ref ===
    "#/components/schemas/SavedTicketViewCreateRequest" &&
    responseSchema(savedViewCreate, "201")?.$ref ===
      "#/components/schemas/SavedTicketViewMutationResult" &&
    requestSchema(savedViewReplace)?.$ref ===
      "#/components/schemas/SavedTicketViewReplaceRequest",
  "saved-view create and replace command schemas drifted",
);
for (const value of [
  savedViewReplace,
  operation(`${savedViewItem}/archive`, "post"),
  operation(`${savedViewItem}/restore`, "post"),
]) {
  assert(
    parameterRefs(value).has("#/components/parameters/SavedViewIfMatch") &&
      value.responses["412"] !== undefined &&
      value.responses["428"] !== undefined,
    `${value.operationId} must require representation-bound optimistic concurrency`,
  );
}

const savedViewSchemas = document.components.schemas;
assert(
  savedViewSchemas.SavedTicketViewFiltersInput.properties.custom.maxItems ===
    8 &&
    savedViewSchemas.SavedTicketViewSpecInput.properties.columns.maxItems ===
      64 &&
    savedViewSchemas.SavedTicketViewColumnInput.properties.width.minimum ===
      80 &&
    savedViewSchemas.SavedTicketViewColumnInput.properties.width.maximum ===
      1200 &&
    savedViewSchemas.SavedTicketViewCustomFilterInput.properties.operator
      .const === "equal" &&
    savedViewSchemas.SavedTicketViewCustomFilter.properties.operator.const ===
      "equal",
  "saved-view filters, columns, widths, and equality vocabulary must remain closed and bounded",
);
for (const schemaName of [
  "AppliedSavedTicketView",
  "SavedTicketViewCreateRequest",
  "SavedTicketViewReplaceRequest",
  "SavedTicketViewLifecycleRequest",
  "SavedTicketViewSpecInput",
  "SavedTicketViewFiltersInput",
  "SavedTicketViewColumnInput",
  "SavedTicketViewSortInput",
  "SavedTicketView",
  "SavedTicketViewSpec",
  "SavedTicketViewDefinitionPin",
  "SavedTicketViewColumn",
  "SavedTicketViewSort",
  "TicketCustomDynamicColumnValue",
  "TicketSLADynamicColumnValue",
]) {
  assert(
    savedViewSchemas[schemaName].additionalProperties === false,
    `${schemaName} must reject unknown projection fields`,
  );
}
assert(
  savedViewSchemas.AlertOperatorProjection.properties.dynamicColumns !==
    undefined &&
    savedViewSchemas.CaseOperatorProjection.properties.dynamicColumns !==
      undefined &&
    savedViewSchemas.AlertCustomerProjection.properties.dynamicColumns ===
      undefined &&
    savedViewSchemas.CaseCustomerProjection.properties.dynamicColumns ===
      undefined &&
    savedViewSchemas.AlertList.properties.appliedView.$ref ===
      "#/components/schemas/AppliedSavedTicketView" &&
    savedViewSchemas.CaseList.properties.appliedView.$ref ===
      "#/components/schemas/AppliedSavedTicketView",
  "dynamic saved-view values must remain operator-only with an exact applied-view proof",
);

const bulkCollection = "/api/v1/tenants/{tenantId}/ticket-bulk-jobs";
const bulkItem = `${bulkCollection}/{jobId}`;
const bulkOperations = [
  [bulkCollection, "post"],
  [bulkItem, "get"],
  [`${bulkItem}/cancel`, "post"],
  [`${bulkItem}/results`, "get"],
];
for (const [path, method] of bulkOperations) {
  const value = operation(path, method);
  const authorization = value["x-periapsis-authorization"];
  exact(
    authorization.actorKinds,
    ["operator"],
    `${value.operationId} must remain operator-only`,
  );
  exact(
    authorization.principalTypes,
    ["human"],
    `${value.operationId} must remain exact-membership human-only`,
  );
  exact(
    authorization.scopes,
    liveScopes,
    `${value.operationId} live scopes drifted`,
  );
  if (method === "post") {
    assert(
      parameterRefs(value).has("#/components/parameters/IdempotencyKey") &&
        securityAlternatives(value).some(
          (alternative) => alternative.csrfToken !== undefined,
        ),
      `${value.operationId} must bind CSRF and one idempotent attempt`,
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

const bulkRequest = operation(bulkCollection, "post");
exact(
  bulkRequest["x-periapsis-authorization"].permissionsByKindAndAction,
  {
    alert: {
      transition: "alert.update",
      assign: "alert.assign",
      transfer: "alert.assign",
      claim: "alert.claim",
      release: "alert.claim",
    },
    case: {
      transition: "case.transition",
      assign: "case.transfer",
      transfer: "case.transfer",
      claim: "case.claim",
      release: "case.claim",
    },
  },
  "bulk creation must declare the exact direct-path permission matrix",
);
assert(
  requestSchema(bulkRequest)?.$ref ===
    "#/components/schemas/TicketBulkJobRequest" &&
    responseSchema(bulkRequest, "202")?.$ref ===
      "#/components/schemas/TicketBulkJobMutationResult",
  "bulk creation command and receipt schemas drifted",
);
for (const value of [
  operation(bulkItem, "get"),
  operation(`${bulkItem}/cancel`, "post"),
  operation(`${bulkItem}/results`, "get"),
]) {
  exact(
    value["x-periapsis-authorization"].permissionsByKind,
    { alert: "alert.read", case: "case.read" },
    `${value.operationId} must repeat owner-scoped live ticket-read authority`,
  );
}
assert(
  requestSchema(operation(`${bulkItem}/cancel`, "post"))?.$ref ===
    "#/components/schemas/TicketBulkJobCancelRequest" &&
    operation(`${bulkItem}/cancel`, "post").responses["412"] !== undefined &&
    responseSchema(operation(`${bulkItem}/results`, "get"), "200")?.$ref ===
      "#/components/schemas/TicketBulkTargetResultPage",
  "bulk cancellation CAS or bounded result paging drifted",
);

const bulkSchemas = document.components.schemas;
assert(
  bulkSchemas.TicketBulkSelectionRequest.properties.targets.maxItems === 1000 &&
    bulkSchemas.TicketBulkSelection.properties.targetCount.maximum === 100000 &&
    bulkSchemas.TicketBulkJobRequest.properties.retentionSeconds.minimum ===
      300 &&
    bulkSchemas.TicketBulkJobRequest.properties.retentionSeconds.maximum ===
      2592000 &&
    bulkSchemas.TicketBulkTargetResultPage.properties.items.maxItems === 100 &&
    bulkSchemas.TicketBulkTargetResultPage.properties.nextCursor.maxLength ===
      512,
  "bulk selections, retention, and result pages must remain bounded",
);
exact(
  bulkSchemas.TicketBulkMutationRequest.properties.action.enum,
  ["transition", "assign", "transfer", "claim", "release"],
  "bulk mutations must remain a closed direct-path vocabulary",
);
exact(
  bulkSchemas.TicketBulkTargetResultCode.enum,
  [
    "succeeded",
    "no_change",
    "version_conflict",
    "not_found_or_hidden",
    "authorization_denied",
    "rejected",
    "cancelled",
    "authorization_revoked",
    "internal_failure",
  ],
  "bulk result codes must remain bounded and non-oracular",
);
for (const schemaName of [
  "TicketBulkTargetPin",
  "TicketBulkSavedViewSourceRequest",
  "TicketBulkQuerySourceRequest",
  "TicketBulkSelectionRequest",
  "TicketBulkMutationRequest",
  "TicketBulkJobRequest",
  "TicketBulkJobCancelRequest",
  "TicketBulkSavedViewPin",
  "TicketBulkSelection",
  "TicketBulkProgress",
  "TicketBulkJob",
  "TicketBulkJobMutationResult",
  "TicketBulkTargetResult",
  "TicketBulkTargetResultPage",
]) {
  assert(
    bulkSchemas[schemaName].additionalProperties === false,
    `${schemaName} must reject unknown fields`,
  );
}
