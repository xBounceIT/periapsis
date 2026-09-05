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
  throw new Error(`Custom-field contract invariant failed: ${message}`);
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

const definitionCollection =
  "/api/v1/tenants/{tenantId}/custom-field-definitions";
const compatibilityCollection = "/api/v1/tenants/{tenantId}/custom-fields";
const definitionItem = `${definitionCollection}/{definitionId}`;
const objectValues =
  "/api/v1/tenants/{tenantId}/objects/{objectType}/{objectId}/custom-fields";
const tenantScopes = ["tenant"];
const objectScopes = ["own", "assigned", "operator_team", "tenant"];

const operations = [
  {
    path: compatibilityCollection,
    method: "get",
    operationId: "listTenantCustomFields",
    permission: "custom_field.read",
    scopes: tenantScopes,
    etag: false,
  },
  {
    path: compatibilityCollection,
    method: "post",
    operationId: "createTenantCustomField",
    permission: "custom_field.manage",
    scopes: tenantScopes,
    mutation: true,
    idempotent: true,
    etag: true,
    operatorOnly: true,
  },
  {
    path: definitionCollection,
    method: "get",
    operationId: "listTenantCustomFieldDefinitions",
    permission: "custom_field.read",
    scopes: tenantScopes,
    etag: false,
  },
  {
    path: definitionCollection,
    method: "post",
    operationId: "createTenantCustomFieldDefinition",
    permission: "custom_field.manage",
    scopes: tenantScopes,
    mutation: true,
    idempotent: true,
    etag: true,
    operatorOnly: true,
  },
  {
    path: definitionItem,
    method: "get",
    operationId: "getTenantCustomFieldDefinition",
    permission: "custom_field.read",
    scopes: tenantScopes,
    etag: true,
  },
  {
    path: definitionItem,
    method: "put",
    operationId: "replaceTenantCustomFieldDefinition",
    permission: "custom_field.manage",
    scopes: tenantScopes,
    mutation: true,
    idempotent: true,
    optimistic: true,
    etag: true,
    operatorOnly: true,
  },
  {
    path: definitionItem,
    method: "delete",
    operationId: "archiveTenantCustomFieldDefinition",
    permission: "custom_field.manage",
    scopes: tenantScopes,
    mutation: true,
    idempotent: true,
    optimistic: true,
    etag: true,
    operatorOnly: true,
  },
  {
    path: objectValues,
    method: "get",
    operationId: "getTenantObjectCustomFields",
    permission: "custom_field.read",
    scopes: objectScopes,
    etag: true,
  },
  {
    path: objectValues,
    method: "put",
    operationId: "replaceTenantObjectCustomFields",
    permission: "custom_field.manage",
    scopes: objectScopes,
    mutation: true,
    idempotent: true,
    optimistic: true,
    etag: true,
  },
];

exact(
  document.paths[compatibilityCollection].parameters,
  document.paths[definitionCollection].parameters,
  "compatibility and canonical collections must bind the same tenant path",
);
for (const method of ["get", "post"]) {
  const compatibility = operation(compatibilityCollection, method);
  const canonical = operation(definitionCollection, method);
  for (const property of [
    "security",
    "x-periapsis-authorization",
    "parameters",
    "requestBody",
    "responses",
  ]) {
    exact(
      compatibility[property],
      canonical[property],
      `${method.toUpperCase()} compatibility ${property} drifted from canonical`,
    );
  }
}

for (const expected of operations) {
  const value = operation(expected.path, expected.method);
  const authorization = value["x-periapsis-authorization"];
  exact(
    value.operationId,
    expected.operationId,
    `${expected.method.toUpperCase()} ${expected.path} operationId drifted`,
  );
  exact(
    value.security,
    expected.mutation
      ? [{ sessionCookie: [], csrfToken: [] }]
      : [{ sessionCookie: [] }],
    `${expected.operationId} authentication or CSRF requirements drifted`,
  );
  assert(
    authorization?.tenantContext === "path" &&
      authorization.activeMembership === true &&
      authorization.permission === expected.permission,
    `${expected.operationId} tenant authority metadata drifted`,
  );
  exact(
    authorization.principalTypes,
    ["human"],
    `${expected.operationId} principal types drifted`,
  );
  exact(
    authorization.scopes,
    expected.scopes,
    `${expected.operationId} scopes drifted`,
  );
  if (expected.operatorOnly) {
    exact(
      authorization.actorKinds,
      ["operator"],
      `${expected.operationId} must remain operator-only`,
    );
  } else if (expected.path === objectValues) {
    assert(
      authorization.actorKinds === undefined,
      `${expected.operationId} must preserve policy-filtered operator/customer projections`,
    );
  }

  const refs = parameterRefs(value);
  assert(
    refs.has("#/components/parameters/IdempotencyKey") ===
      Boolean(expected.idempotent),
    `${expected.operationId} idempotency requirement drifted`,
  );
  assert(
    refs.has("#/components/parameters/IfMatch") ===
      Boolean(expected.optimistic),
    `${expected.operationId} optimistic-concurrency requirement drifted`,
  );
  if (expected.optimistic) {
    assert(
      value.responses?.["412"] !== undefined &&
        value.responses?.["428"] !== undefined,
      `${expected.operationId} must expose stale and missing precondition outcomes`,
    );
  }

  for (const [status, response] of Object.entries(value.responses ?? {})) {
    if (Number(status) >= 400) {
      assert(
        response.$ref?.startsWith("#/components/responses/NoStore") === true,
        `${expected.operationId} ${status} must use a no-store problem response`,
      );
      continue;
    }
    assert(
      response.headers?.["Cache-Control"]?.$ref ===
        "#/components/headers/NoStore",
      `${expected.operationId} ${status} must be no-store`,
    );
    assert(
      (response.headers?.ETag?.$ref === "#/components/headers/StrongETag") ===
        expected.etag,
      `${expected.operationId} ${status} ETag contract drifted`,
    );
  }
}

assert(
  parameterNames(operation(definitionCollection, "get")).has("objectType") &&
    parameterRefs(operation(definitionCollection, "get")).has(
      "#/components/parameters/PageSize",
    ) &&
    parameterNames(operation(definitionCollection, "get")).has("after"),
  "definition inventory must remain object-scoped and cursor-paginated",
);
assert(
  parameterNames(operation(definitionItem, "get")).has("objectType"),
  "definition lookup must bind the object type",
);
assert(
  parameterNames(operation(objectValues, "get")).has("surface") &&
    parameterNames(operation(objectValues, "put")).has("surface") === false,
  "reads must select a projection surface while replacement phase determines the write surface",
);

const schemas = document.components.schemas;
exact(
  schemas.CustomFieldDataType.enum,
  [
    "short_text",
    "long_text",
    "integer",
    "decimal",
    "boolean",
    "date",
    "datetime",
    "duration",
    "single_select",
    "multi_select",
    "url",
    "email",
    "ip",
    "cidr",
    "user",
    "operator_team",
    "customer_contact",
    "asset_reference",
    "ioc_reference",
    "structured_json",
  ],
  "custom-field type vocabulary must remain the exact 20 supported types",
);
exact(
  schemas.CustomFieldVisibility.required,
  ["customer", "operator"],
  "visibility metadata requirements drifted",
);
exact(
  Object.keys(schemas.CustomFieldVisibility.properties),
  ["customer", "operator"],
  "visibility metadata fields drifted",
);
exact(
  schemas.CustomFieldEditPolicy.required,
  ["customerCreate", "customerUpdate", "operatorCreate", "operatorUpdate"],
  "edit-policy metadata requirements drifted",
);
exact(
  schemas.CustomFieldPlacement.required,
  ["showInCreate", "showInDetail", "showInList", "showInExport"],
  "placement metadata requirements drifted",
);
for (const schemaName of [
  "CustomFieldVisibility",
  "CustomFieldEditPolicy",
  "CustomFieldPlacement",
  "CustomFieldDefinitionSpec",
  "CustomFieldDefinitionCreateRequest",
  "CustomFieldDefinitionReplaceRequest",
  "CustomFieldDefinitionArchiveRequest",
  "CustomFieldDefinition",
  "CustomFieldProjection",
  "CustomFieldValuesReplaceRequest",
  "CustomFieldProjectedValue",
  "CustomFieldValuesResult",
]) {
  assert(
    schemas[schemaName].additionalProperties === false,
    `${schemaName} must reject unknown fields`,
  );
}
for (const property of ["visibility", "editPolicy", "placement"]) {
  assert(
    schemas.CustomFieldDefinitionSpec.required.includes(property) &&
      schemas.CustomFieldDefinitionSpec.properties[property].$ref ===
        `#/components/schemas/CustomField${
          property === "visibility"
            ? "Visibility"
            : property === "editPolicy"
              ? "EditPolicy"
              : "Placement"
        }`,
    `definition ${property} metadata must remain required and typed`,
  );
}

const replacement = schemas.CustomFieldValuesReplaceRequest;
assert(
  replacement.required.includes("phase") &&
    replacement.required.includes("values") &&
    replacement.required.includes("expectedVersion") &&
    replacement.properties.surface === undefined &&
    replacement.description.includes("phase update") &&
    replacement.description.includes("Omitting one of those keys") &&
    replacement.description.includes("present null stores explicit null") &&
    replacement.description.includes("hidden, non-detail, and read-only") &&
    schemas.CustomFieldWritePhase.enum.includes("update"),
  "detail-update omission, removal, explicit-null, or preservation semantics drifted",
);
assert(
  schemas.CustomFieldValues.additionalProperties.$ref ===
    "#/components/schemas/CustomFieldValue" &&
    schemas.CustomFieldValue.anyOf.some((branch) => branch.type === "null") &&
    schemas.CustomFieldProjectedValue.required.includes("presence") &&
    !schemas.CustomFieldProjectedValue.required.includes("value"),
  "missing, explicit null, and present custom-field values must remain distinguishable",
);
exact(
  schemas.CustomFieldProjectedValue.properties.presence.enum,
  ["missing", "null", "present"],
  "projected value presence vocabulary drifted",
);

for (const symbol of operations.map((value) => value.operationId)) {
  assert(
    generatedSdk.includes(`export const ${symbol} =`),
    `generated TypeScript client is missing ${symbol}`,
  );
}
for (const symbol of [
  "CustomFieldDataType",
  "CustomFieldVisibility",
  "CustomFieldEditPolicy",
  "CustomFieldPlacement",
  "CustomFieldDefinitionSpec",
  "CustomFieldValuesReplaceRequest",
  "CustomFieldProjection",
  "ListTenantCustomFieldDefinitionsData",
  "CreateTenantCustomFieldDefinitionData",
  "ListTenantCustomFieldsData",
  "CreateTenantCustomFieldData",
  "GetTenantCustomFieldDefinitionData",
  "ReplaceTenantCustomFieldDefinitionData",
  "ArchiveTenantCustomFieldDefinitionData",
  "GetTenantObjectCustomFieldsData",
  "ReplaceTenantObjectCustomFieldsData",
]) {
  assert(
    generatedTypes.includes(`export type ${symbol} =`),
    `generated TypeScript types are missing ${symbol}`,
  );
}
for (const [signature, route] of [
  [
    "ListTenantCustomFields(w http.ResponseWriter, r *http.Request, tenantId TenantId, params ListTenantCustomFieldsParams)",
    'm.HandleFunc(http.MethodGet+" "+options.BaseURL+"/api/v1/tenants/{tenantId}/custom-fields", wrapper.ListTenantCustomFields)',
  ],
  [
    "CreateTenantCustomField(w http.ResponseWriter, r *http.Request, tenantId TenantId, params CreateTenantCustomFieldParams)",
    'm.HandleFunc(http.MethodPost+" "+options.BaseURL+"/api/v1/tenants/{tenantId}/custom-fields", wrapper.CreateTenantCustomField)',
  ],
]) {
  assert(
    generatedGo.includes(signature) && generatedGo.includes(route),
    `generated Go server is missing exact compatibility binding ${signature}`,
  );
}

process.stdout.write("Custom-field contract invariants verified.\n");
