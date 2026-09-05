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
const types = readFileSync(
  resolve(
    repositoryRoot,
    "packages/contracts/generated/typescript/types.gen.ts",
  ),
  "utf8",
);
const go = readFileSync(
  resolve(repositoryRoot, "services/api/internal/contract/api.gen.go"),
  "utf8",
);

const fail = (message) => {
  throw new Error(`Tenant settings contract invariant failed: ${message}`);
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

const compatibilityPath = document.paths?.["/api/v1/tenants/{tenantId}"];
const path = document.paths?.["/api/v1/tenants/{tenantId}/settings"];
assert(path, "the explicit tenant path is missing");
assert(compatibilityPath, "the tenant compatibility path is missing");
exact(
  path.parameters?.map((parameter) => parameter.$ref),
  ["#/components/parameters/TenantId"],
  "the settings path must bind exactly one tenant identity",
);
exact(
  compatibilityPath.parameters,
  path.parameters,
  "the compatibility path must bind the canonical tenant identity",
);

const read = path.get;
assert(
  read?.operationId === "getTenantSettings",
  "safe settings read is missing",
);
const compatibilityRead = compatibilityPath.get;
assert(
  compatibilityRead?.operationId === "getTenant",
  "safe tenant compatibility read is missing",
);
for (const property of [
  "security",
  "x-periapsis-authorization",
  "parameters",
  "requestBody",
  "responses",
]) {
  exact(
    compatibilityRead[property],
    read[property],
    `tenant compatibility ${property} drifted from settings read`,
  );
}
assert(
  read.security?.length === 1 &&
    read.security[0].sessionCookie !== undefined &&
    read.security[0].csrfToken === undefined,
  "settings read must require only the live session cookie",
);
assert(
  read["x-periapsis-authorization"]?.tenantContext === "path" &&
    read["x-periapsis-authorization"].activeMembership === true &&
    read["x-periapsis-authorization"].permission === "settings.read" &&
    read["x-periapsis-authorization"].uiVisibilityIsNotAuthorization === true,
  "settings read lost deny-by-default tenant authority",
);
exact(
  read["x-periapsis-authorization"].scopes,
  ["tenant"],
  "settings read must remain tenant scoped",
);

const update = path.put;
assert(
  update?.operationId === "updateTenantSettings",
  "settings replacement is missing",
);
assert(
  update.security?.length === 1 &&
    update.security[0].sessionCookie !== undefined &&
    update.security[0].csrfToken !== undefined,
  "settings replacement must require the session and CSRF pair",
);
exact(
  update["x-periapsis-authorization"]?.permissions,
  ["settings.read", "settings.manage"],
  "settings replacement must require both safe read and manage authority",
);
assert(
  update["x-periapsis-authorization"]?.tenantContext === "path" &&
    update["x-periapsis-authorization"].activeMembership === true &&
    update["x-periapsis-authorization"].uiVisibilityIsNotAuthorization === true,
  "settings replacement lost tenant and membership enforcement",
);
exact(
  update.parameters?.map((parameter) => parameter.$ref),
  [
    "#/components/parameters/IfMatch",
    "#/components/parameters/TenantSettingsAuditReason",
  ],
  "settings replacement must bind one strong CAS and one safe reason",
);
assert(
  update.requestBody?.required === true &&
    update.requestBody.content?.["application/json"]?.schema?.$ref ===
      "#/components/schemas/TenantSettingsUpdateRequest",
  "settings replacement must use one closed full representation",
);
exact(
  Object.keys(update.responses).toSorted(),
  ["200", "400", "401", "403", "404", "412", "428", "503"],
  "settings response vocabulary drifted",
);

for (const operation of [read, update]) {
  const response = operation.responses["200"];
  assert(
    response?.headers?.["Cache-Control"]?.$ref ===
      "#/components/headers/PrivateNoStore" &&
      response.headers?.ETag?.$ref === "#/components/headers/StrongETag" &&
      response.content?.["application/json"]?.schema?.$ref ===
        "#/components/schemas/TenantSettings",
    `${operation.operationId} must return the version-bound private projection`,
  );
}

for (const status of ["400", "401", "403", "404", "412", "428", "503"]) {
  const response = update.responses[status];
  assert(
    response?.$ref?.startsWith("#/components/responses/NoStore"),
    `settings replacement ${status} must prevent response storage`,
  );
}

const settings = document.components.schemas.TenantSettings;
const updateRequest = document.components.schemas.TenantSettingsUpdateRequest;
const publicFields = [
  "tenantId",
  "brandName",
  "brandMark",
  "primaryColor",
  "accentColor",
  "timezone",
  "locale",
  "version",
  "updatedAt",
];
assert(
  settings.additionalProperties === false,
  "settings projection must be closed",
);
exact(settings.required, publicFields, "settings projection fields drifted");
for (const forbidden of [
  "logoUrl",
  "logoUri",
  "imageUrl",
  "storageKey",
  "updatedByMembershipId",
  "reason",
]) {
  assert(
    settings.properties[forbidden] === undefined &&
      updateRequest.properties[forbidden] === undefined,
    `settings contract exposed forbidden field ${forbidden}`,
  );
}
assert(
  settings.properties.brandMark.pattern === "^[A-Z0-9]{1,4}$" &&
    settings.properties.primaryColor.pattern === "^#[0-9a-f]{6}$" &&
    settings.properties.accentColor.pattern === "^#[0-9a-f]{6}$" &&
    settings.properties.timezone.pattern.startsWith("^(?!Local$)") &&
    settings.properties.locale.pattern.startsWith("^(?!und"),
  "safe branding and regional formats drifted",
);
assert(
  updateRequest.additionalProperties === false &&
    updateRequest.required.includes("expectedVersion") &&
    updateRequest.properties.expectedVersion.minimum === 1 &&
    updateRequest.properties.expectedVersion.maximum === 2147483646,
  "settings replacement must reserve one int32 CAS revision",
);

const reason = document.components.parameters.TenantSettingsAuditReason;
assert(
  reason.required === true &&
    reason.schema?.minLength === 1 &&
    reason.schema?.maxLength === 500 &&
    reason.schema?.pattern ===
      "^[\\x21-\\x2B\\x2D-\\x7E]([\\x20-\\x2B\\x2D-\\x7E]*[\\x21-\\x2B\\x2D-\\x7E])?$",
  "settings mutation reason must stay mandatory, bounded, and header-safe",
);
for (const permission of ["settings.read", "settings.manage"]) {
  assert(
    document.components.schemas.TenantPermissionKey.enum.includes(permission),
    `tenant permission vocabulary is missing ${permission}`,
  );
}

for (const symbol of [
  "getTenant",
  "getTenantSettings",
  "updateTenantSettings",
]) {
  assert(
    sdk.includes(`export const ${symbol} =`),
    `${symbol} generated TypeScript client is missing`,
  );
}
for (const symbol of [
  "GetTenantData",
  "GetTenantSettingsData",
  "UpdateTenantSettingsData",
]) {
  assert(
    types.includes(`export type ${symbol} =`),
    `${symbol} generated TypeScript type is missing`,
  );
}
for (const signature of [
  "GetTenant(w http.ResponseWriter, r *http.Request, tenantId TenantId)",
  "GetTenantSettings(w http.ResponseWriter, r *http.Request, tenantId TenantId)",
  "UpdateTenantSettings(w http.ResponseWriter, r *http.Request, tenantId TenantId, params UpdateTenantSettingsParams)",
]) {
  assert(
    go.includes(signature),
    `${signature} generated Go contract is missing`,
  );
}
assert(
  go.includes(
    'm.HandleFunc(http.MethodGet+" "+options.BaseURL+"/api/v1/tenants/{tenantId}", wrapper.GetTenant)',
  ),
  "generated Go router is missing the exact tenant compatibility binding",
);

process.stdout.write("Tenant settings contract invariants verified.\n");
