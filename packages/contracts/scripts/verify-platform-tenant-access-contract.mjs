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
    `Platform tenant-access contract invariant failed: ${message}`,
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

const path = "/api/v1/platform/tenants/{tenantId}/access";
const operation = document.paths?.[path]?.post;
assert(
  operation?.operationId === "authorizePlatformTenantAccess",
  "explicit access operation is missing",
);
exact(
  document.paths[path].parameters.map((parameter) => parameter.$ref),
  ["#/components/parameters/TenantId"],
  "operation must bind exactly one target tenant",
);
assert(
  operation.security?.length === 1 &&
    operation.security[0].sessionCookie !== undefined &&
    operation.security[0].csrfToken !== undefined,
  "operation must require session and CSRF",
);
const authorization = operation["x-periapsis-authorization"];
assert(
  authorization?.activeSession === true &&
    authorization.permission === "platform.tenant.access" &&
    authorization.freshMfaSeconds === 900 &&
    authorization.uiVisibilityIsNotAuthorization === true,
  "operation lost dedicated live authority or fresh-MFA metadata",
);
exact(
  authorization.scopes,
  ["platform"],
  "operation must remain platform scoped",
);
exact(
  authorization.principalTypes,
  ["human"],
  "operation must remain human only",
);
exact(
  operation.parameters.map((parameter) => parameter.$ref),
  ["#/components/parameters/IfMatch", "#/components/parameters/IdempotencyKey"],
  "operation must require exact version and retry identity",
);
assert(
  operation.requestBody?.required === true &&
    operation.requestBody.content?.["application/json"]?.schema?.$ref ===
      "#/components/schemas/PlatformTenantAccessRequest",
  "operation must consume the closed explicit-access command",
);
exact(
  Object.keys(operation.responses).sort(),
  ["200", "201", "400", "401", "403", "404", "409", "412", "428", "503"],
  "response vocabulary drifted",
);
for (const status of ["200", "201"]) {
  const response = operation.responses[status];
  assert(
    response?.headers?.["Cache-Control"]?.$ref ===
      "#/components/headers/NoStore" &&
      response?.headers?.ETag?.$ref === "#/components/headers/StrongETag" &&
      response?.content?.["application/json"]?.schema?.$ref ===
        "#/components/schemas/PlatformTenantAccessReceipt",
    `${status} must return a no-store, target-version-bound receipt`,
  );
}
for (const status of ["400", "401", "403", "404", "409", "412", "428", "503"]) {
  const reference = operation.responses[status]?.$ref;
  assert(
    reference?.startsWith("#/components/responses/NoStore"),
    `${status} must prevent authority-response storage`,
  );
}

const request = document.components.schemas.PlatformTenantAccessRequest;
exact(
  request.required,
  ["expectedVersion", "reason"],
  "request required fields drifted",
);
assert(
  request.additionalProperties === false &&
    request.properties.expectedVersion.$ref ===
      "#/components/schemas/TenantLifecycleExpectedVersion" &&
    request.properties.reason.minLength === 1 &&
    request.properties.reason.maxLength === 2048 &&
    request.properties.reason.pattern ===
      "^(?!\\s)(?![\\s\\S]*\\s$)(?![\\s\\S]*[\\p{Cc}\\p{Cf}])[\\s\\S]+$",
  "request must remain closed, versioned, and audit-safe",
);

const receipt = document.components.schemas.PlatformTenantAccessReceipt;
exact(
  receipt.required,
  [
    "tenantId",
    "membershipId",
    "userId",
    "tenantVersion",
    "membershipRevision",
    "authorizationRevision",
    "authorizedAt",
    "replayed",
  ],
  "receipt required fields drifted",
);
assert(
  receipt.additionalProperties === false &&
    receipt.properties.tenantVersion.$ref ===
      "#/components/schemas/ResourceVersion" &&
    receipt.properties.membershipRevision.$ref ===
      "#/components/schemas/ResourceVersion" &&
    receipt.properties.authorizationRevision.type === "string" &&
    receipt.properties.authorizationRevision.pattern === "^[1-9][0-9]{0,18}$" &&
    receipt.properties.reason === undefined &&
    receipt.properties.idempotencyKey === undefined,
  "receipt must bind ordinary authority revisions without reflecting operator metadata",
);
assert(
  document.components.schemas.PlatformPermission.enum.includes(
    "platform.tenant.access",
  ),
  "session permission vocabulary must expose only the dedicated access authority",
);
assert(
  sdk.includes("export const authorizePlatformTenantAccess ="),
  "generated client declaration is missing",
);
