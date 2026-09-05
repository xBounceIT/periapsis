import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const repositoryRoot = resolve(import.meta.dirname, "../../..");
const document = JSON.parse(
  readFileSync(
    resolve(repositoryRoot, "services/api/internal/contract/openapi.json"),
    "utf8",
  ),
);
const sdk = readFileSync(
  resolve(repositoryRoot, "packages/contracts/generated/typescript/sdk.gen.ts"),
  "utf8",
);

const fail = (message) => {
  throw new Error(
    `Platform tenant lifecycle contract invariant failed: ${message}`,
  );
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

const lifecycleOperations = [
  ["suspend", "suspendPlatformTenant", "suspendPlatformTenant"],
  ["reactivate", "reactivatePlatformTenant", "reactivatePlatformTenant"],
];

for (const [action, operationId, generatedName] of lifecycleOperations) {
  const path = `/api/v1/platform/tenants/{tenantId}/${action}`;
  const operation = document.paths?.[path]?.post;
  assert(operation?.operationId === operationId, `${operationId} is missing`);
  exact(
    document.paths[path].parameters.map((parameter) => parameter.$ref),
    ["#/components/parameters/TenantId"],
    `${operationId} must bind one explicit tenant identity`,
  );
  assert(
    operation.security?.length === 1 &&
      operation.security[0].sessionCookie !== undefined &&
      operation.security[0].csrfToken !== undefined,
    `${operationId} must require the session and CSRF pair`,
  );
  const authorization = operation["x-periapsis-authorization"];
  assert(
    authorization?.activeSession === true &&
      authorization.permission === "platform.tenant.manage" &&
      authorization.uiVisibilityIsNotAuthorization === true,
    `${operationId} lost deny-by-default platform lifecycle authority`,
  );
  exact(
    authorization.scopes,
    ["platform"],
    `${operationId} must remain platform scoped`,
  );
  exact(
    authorization.principalTypes,
    ["human"],
    `${operationId} must remain human-only`,
  );
  assert(
    operation.parameters?.some(
      (parameter) => parameter.$ref === "#/components/parameters/IfMatch",
    ) &&
      operation.requestBody?.required === true &&
      operation.requestBody.content?.["application/json"]?.schema?.$ref ===
        "#/components/schemas/TenantLifecycleChangeRequest",
    `${operationId} must bind one strong precondition to the closed command`,
  );
  exact(
    Object.keys(operation.responses).sort(),
    ["200", "400", "401", "403", "404", "412", "428", "503"],
    `${operationId} response vocabulary drifted`,
  );
  assert(
    operation.responses["200"]?.headers?.["Cache-Control"]?.$ref ===
      "#/components/headers/NoStore" &&
      operation.responses["200"]?.headers?.ETag?.$ref ===
        "#/components/headers/StrongETag" &&
      operation.responses["200"]?.content?.["application/json"]?.schema
        ?.$ref === "#/components/schemas/TenantLifecycleReceipt",
    `${operationId} success must return a version-bound sanitized receipt`,
  );
  for (const status of ["400", "401", "403", "404", "412", "428", "503"]) {
    const response = operation.responses[status];
    assert(
      response?.$ref?.startsWith("#/components/responses/NoStore"),
      `${operationId} ${status} must prevent authority-response storage`,
    );
    const name = response?.$ref?.slice("#/components/responses/".length);
    const schema =
      document.components.responses?.[name]?.content?.[
        "application/problem+json"
      ]?.schema;
    assert(
      schema?.$ref === "#/components/schemas/Problem",
      `${operationId} ${status} must remain RFC 9457 Problem Details`,
    );
  }
  assert(
    sdk.includes(`export const ${generatedName} =`),
    `${operationId} generated client declaration is missing`,
  );
}

const command = document.components.schemas.TenantLifecycleChangeRequest;
exact(
  command.required,
  ["expectedVersion", "reason"],
  "lifecycle command required fields drifted",
);
assert(
  command.additionalProperties === false &&
    command.properties.expectedVersion.$ref ===
      "#/components/schemas/TenantLifecycleExpectedVersion" &&
    command.properties.reason.minLength === 1 &&
    command.properties.reason.maxLength === 2048 &&
    command.properties.reason.pattern ===
      "^(?!\\s)(?![\\s\\S]*\\s$)(?![\\s\\S]*[\\p{Cc}\\p{Cf}])[\\s\\S]+$",
  "lifecycle command must remain closed, versioned, and bounded",
);
const expectedVersion =
  document.components.schemas.TenantLifecycleExpectedVersion;
assert(
  expectedVersion.type === "integer" &&
    expectedVersion.minimum === 1 &&
    expectedVersion.maximum === 2147483646,
  "lifecycle expected version must reserve one int32 revision for the transition",
);

const receipt = document.components.schemas.TenantLifecycleReceipt;
assert(
  receipt.additionalProperties === false &&
    receipt.required.includes("tenantId") &&
    receipt.required.includes("previousStatus") &&
    receipt.required.includes("status") &&
    receipt.required.includes("version") &&
    receipt.properties.reason === undefined,
  "lifecycle receipt must bind identity and transition while omitting the reason",
);
assert(
  document.components.schemas.TenantSummary.properties.version.$ref ===
    "#/components/schemas/ResourceVersion" &&
    !document.components.schemas.TenantSummary.required.includes("version"),
  "tenant inventory lifecycle version must remain rolling-compatible and fail-closed",
);
assert(
  document.components.schemas.PlatformPermission.enum.includes(
    "platform.tenant.manage",
  ),
  "session permission vocabulary must expose lifecycle authority",
);
