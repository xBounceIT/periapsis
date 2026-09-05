import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const root = resolve(import.meta.dirname, "../../..");
const document = JSON.parse(
  readFileSync(
    resolve(root, "services/api/internal/contract/openapi.json"),
    "utf8",
  ),
);
const generatedSdk = readFileSync(
  resolve(root, "packages/contracts/generated/typescript/sdk.gen.ts"),
  "utf8",
);
const generatedTypes = readFileSync(
  resolve(root, "packages/contracts/generated/typescript/types.gen.ts"),
  "utf8",
);
const generatedGo = readFileSync(
  resolve(root, "services/api/internal/contract/api.gen.go"),
  "utf8",
);

const fail = (message) => {
  throw new Error("Alert-relation contract invariant failed: " + message);
};
const assert = (condition, message) => {
  if (!condition) fail(message);
};
const exact = (actual, expected, message) => {
  assert(
    JSON.stringify(actual) === JSON.stringify(expected),
    message + ": received " + JSON.stringify(actual),
  );
};

const collectionPath =
  "/api/v1/tenants/{tenantId}/alerts/{alertId}/related-alerts";
const retractionPath = collectionPath + "/{relationId}/retract";
const collection = document.paths?.[collectionPath];
const retraction = document.paths?.[retractionPath];
exact(
  collection?.parameters?.map((parameter) => parameter.$ref),
  ["#/components/parameters/TenantId", "#/components/parameters/AlertId"],
  "collection path coordinates drifted",
);
exact(
  retraction?.parameters?.map((parameter) => parameter.$ref),
  [
    "#/components/parameters/TenantId",
    "#/components/parameters/AlertId",
    "#/components/parameters/AlertRelationId",
  ],
  "retraction path coordinates drifted",
);

const operations = [
  {
    value: collection?.get,
    id: "listTenantAlertRelations",
    security: [{ sessionCookie: [] }],
    parameters: [
      "#/components/parameters/AfterCursor",
      "#/components/parameters/PageSize",
    ],
    statuses: ["200", "400", "401", "403", "404", "503"],
    response: "#/components/schemas/AlertRelationList",
    mutation: false,
  },
  {
    value: collection?.post,
    id: "createTenantAlertRelation",
    security: [{ sessionCookie: [], csrfToken: [] }],
    parameters: [
      "#/components/parameters/IfMatch",
      "#/components/parameters/IdempotencyKey",
    ],
    statuses: ["200", "400", "401", "403", "404", "409", "412", "428", "503"],
    request: "#/components/schemas/AlertRelationCreateRequest",
    response: "#/components/schemas/AlertRelationMutationReceipt",
    mutation: true,
  },
  {
    value: retraction?.post,
    id: "retractTenantAlertRelation",
    security: [{ sessionCookie: [], csrfToken: [] }],
    parameters: [
      "#/components/parameters/IfMatch",
      "#/components/parameters/IdempotencyKey",
    ],
    statuses: ["200", "400", "401", "403", "404", "409", "412", "428", "503"],
    request: "#/components/schemas/AlertRelationRetractionRequest",
    response: "#/components/schemas/AlertRelationMutationReceipt",
    mutation: true,
  },
];

for (const expected of operations) {
  const operation = expected.value;
  assert(operation !== undefined, expected.id + " is missing");
  assert(
    operation.operationId === expected.id,
    expected.id + " operationId drifted",
  );
  exact(
    operation.security,
    expected.security,
    expected.id + " session or CSRF drifted",
  );
  exact(
    operation.parameters?.map((parameter) => parameter.$ref),
    expected.parameters,
    expected.id + " parameters drifted",
  );
  exact(
    Object.keys(operation.responses ?? {}),
    expected.statuses,
    expected.id + " outcomes drifted",
  );
  const authorization = operation["x-periapsis-authorization"];
  assert(
    authorization?.tenantContext === "path" &&
      authorization.activeMembership === true &&
      authorization.permission === "alert.update" &&
      authorization.permissionResolution ===
        "same_live_authority_snapshot_and_common_scope" &&
      authorization.uiVisibilityIsNotAuthorization === true,
    expected.id + " live compound authority drifted",
  );
  exact(
    authorization.requiredPermissions,
    ["alert.read", "alert.update"],
    expected.id + " permission intersection drifted",
  );
  exact(
    authorization.scopes,
    ["own", "assigned", "operator_team", "tenant"],
    expected.id + " scopes drifted",
  );
  exact(
    authorization.principalTypes,
    ["human"],
    expected.id + " principals drifted",
  );
  exact(
    authorization.actorKinds,
    ["operator"],
    expected.id + " actors drifted",
  );
  if (!expected.mutation) {
    assert(operation.requestBody === undefined, "list must not accept a body");
  } else {
    assert(
      operation.requestBody?.required === true &&
        operation.requestBody.content?.["application/json"]?.schema?.$ref ===
          expected.request,
      expected.id + " closed request drifted",
    );
  }
  const success = operation.responses["200"];
  assert(
    success?.headers?.["Cache-Control"]?.$ref ===
      "#/components/headers/NoStore" &&
      success.content?.["application/json"]?.schema?.$ref === expected.response,
    expected.id + " success projection or cache policy drifted",
  );
  if (expected.mutation) {
    assert(
      success.headers?.ETag?.$ref === "#/components/headers/StrongETag" &&
        success.headers?.["X-Idempotent-Replay"]?.$ref ===
          "#/components/headers/IdempotentReplay",
      expected.id + " CAS or replay receipt headers drifted",
    );
  }
  for (const status of expected.statuses.filter(
    (value) => Number(value) >= 400,
  )) {
    const reference = operation.responses[status]?.$ref;
    assert(
      reference?.startsWith("#/components/responses/NoStore") === true,
      expected.id + " " + status + " must be no-store RFC 9457",
    );
    const component =
      document.components.responses[
        reference.slice("#/components/responses/".length)
      ];
    assert(
      component?.headers?.["Cache-Control"]?.$ref ===
        "#/components/headers/NoStore" &&
        component.content?.["application/problem+json"]?.schema?.$ref ===
          "#/components/schemas/Problem",
      expected.id + " " + status + " Problem Details drifted",
    );
  }
}

const schemas = document.components.schemas;
const uuidV7Pattern =
  "^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}(?![\\s\\S])";
assert(
  schemas.AlertRelationUUIDv7.type === "string" &&
    schemas.AlertRelationUUIDv7.format === "uuid" &&
    schemas.AlertRelationUUIDv7.minLength === 36 &&
    schemas.AlertRelationUUIDv7.maxLength === 36 &&
    schemas.AlertRelationUUIDv7.pattern === uuidV7Pattern,
  "relation coordinates must remain canonical UUIDv7",
);
exact(
  schemas.AlertRelationType.enum,
  ["duplicate_of", "correlation"],
  "relation types drifted",
);
exact(
  schemas.AlertRelationDirection.enum,
  ["outgoing", "incoming", "symmetric"],
  "direction semantics drifted",
);
exact(
  schemas.AlertRelationStatus.enum,
  ["active", "retracted"],
  "status semantics drifted",
);

for (const name of [
  "RelatedAlertSummary",
  "AlertRelationRetraction",
  "AlertRelation",
  "AlertRelationList",
  "AlertRelationCreateRequest",
  "AlertRelationRetractionRequest",
  "AlertRelationMutationReceipt",
]) {
  assert(
    schemas[name]?.additionalProperties === false,
    name + " must remain closed",
  );
}
exact(
  Object.keys(schemas.RelatedAlertSummary.properties),
  ["id", "number", "title", "severity", "stateKey", "version", "updatedAt"],
  "related Alert allowlist drifted",
);
for (const forbidden of [
  "rawPayload",
  "description",
  "customFields",
  "assignment",
  "creator",
  "deduplicationKey",
]) {
  assert(
    schemas.RelatedAlertSummary.properties[forbidden] === undefined,
    "related Alert leaked " + forbidden,
  );
}
assert(
  schemas.AlertRelationList.properties.items.maxItems === 100 &&
    schemas.AlertRelationList.properties.items.items.$ref ===
      "#/components/schemas/AlertRelation" &&
    schemas.AlertRelationList.properties.nextCursor.$ref ===
      "#/components/schemas/AlertRelationUUIDv7",
  "bounded UUIDv7 relation page drifted",
);
assert(
  schemas.AlertRelation.properties.retraction.$ref ===
    "#/components/schemas/AlertRelationRetraction" &&
    !schemas.AlertRelation.required.includes("retraction"),
  "append-only optional retraction shape drifted",
);
exact(
  schemas.AlertRelationCreateRequest.required,
  [
    "targetAlertId",
    "relationType",
    "expectedVersion",
    "expectedTargetVersion",
    "reason",
  ],
  "create request pins drifted",
);
exact(
  schemas.AlertRelationRetractionRequest.required,
  [
    "relatedAlertId",
    "expectedVersion",
    "expectedRelatedAlertVersion",
    "reason",
  ],
  "retraction request pins drifted",
);
for (const field of [
  "previousAlertVersion",
  "alertVersion",
  "previousRelatedAlertVersion",
  "relatedAlertVersion",
]) {
  assert(
    schemas.AlertRelationMutationReceipt.required.includes(field),
    "receipt lost " + field,
  );
}

const operatorActivity = schemas.OperatorActivityKind.enum;
assert(
  operatorActivity.includes("relation_added") &&
    operatorActivity.includes("relation_retracted"),
  "operator activity evidence is missing",
);
const customerActivity = schemas.CustomerActivityKind.enum;
assert(
  !customerActivity.includes("relation_added") &&
    !customerActivity.includes("relation_retracted"),
  "customer activity leaked private relation evidence",
);

for (const operationId of [
  "listTenantAlertRelations",
  "createTenantAlertRelation",
  "retractTenantAlertRelation",
]) {
  assert(
    generatedSdk.includes("export const " + operationId + " ="),
    "generated TypeScript SDK is missing " + operationId,
  );
}
for (const symbol of [
  "AlertRelation",
  "AlertRelationRetraction",
  "AlertRelationList",
  "AlertRelationCreateRequest",
  "AlertRelationRetractionRequest",
  "AlertRelationMutationReceipt",
  "RelatedAlertSummary",
]) {
  assert(
    generatedTypes.includes("export type " + symbol + " ="),
    "generated TypeScript type is missing " + symbol,
  );
  assert(
    generatedGo.includes("type " + symbol + " struct {"),
    "generated Go type is missing " + symbol,
  );
}
for (const signature of [
  "ListTenantAlertRelations(w http.ResponseWriter, r *http.Request, tenantId TenantId, alertId AlertId, params ListTenantAlertRelationsParams)",
  "CreateTenantAlertRelation(w http.ResponseWriter, r *http.Request, tenantId TenantId, alertId AlertId, params CreateTenantAlertRelationParams)",
  "RetractTenantAlertRelation(w http.ResponseWriter, r *http.Request, tenantId TenantId, alertId AlertId, relationId AlertRelationId, params RetractTenantAlertRelationParams)",
]) {
  assert(
    generatedGo.includes(signature),
    "generated Go handler signature drifted: " + signature,
  );
}

process.stdout.write("Alert-relation contract invariants verified.\n");
