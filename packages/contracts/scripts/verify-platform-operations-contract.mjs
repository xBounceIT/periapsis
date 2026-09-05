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
const go = readFileSync(
  resolve(repositoryRoot, "services/api/internal/contract/api.gen.go"),
  "utf8",
);

const fail = (message) => {
  throw new Error(`Platform operations contract invariant failed: ${message}`);
};
const assert = (condition, message) => {
  if (!condition) fail(message);
};

const operations = [
  [
    "/api/v1/platform/users",
    "get",
    "listPlatformUsers",
    "platform.user.read",
    false,
  ],
  [
    "/api/v1/platform/settings",
    "get",
    "getPlatformGlobalSettings",
    "platform.settings.read",
    false,
  ],
  [
    "/api/v1/platform/settings",
    "put",
    "updatePlatformGlobalSettings",
    "platform.settings.read",
    true,
  ],
  [
    "/api/v1/platform/operations/health",
    "get",
    "getPlatformOperationsHealth",
    "platform.operations.read",
    false,
  ],
  [
    "/api/v1/platform/operations/queues",
    "get",
    "listPlatformOperationQueues",
    "platform.operations.read",
    false,
  ],
  [
    "/api/v1/platform/operations/failed-notifications",
    "get",
    "listPlatformFailedNotifications",
    "platform.operations.read",
    false,
  ],
  [
    "/api/v1/platform/feature-flags",
    "get",
    "listPlatformFeatureFlags",
    "platform.feature_flag.read",
    false,
  ],
  [
    "/api/v1/platform/feature-flags/{flagKey}",
    "put",
    "updatePlatformFeatureFlag",
    "platform.feature_flag.read",
    true,
  ],
];

for (const [path, method, operationID, permission, mutation] of operations) {
  const operation = document.paths[path]?.[method];
  assert(
    operation?.operationId === operationID,
    `${method.toUpperCase()} ${path} is missing`,
  );
  const authorization = operation["x-periapsis-authorization"];
  const permissionIsExact = mutation
    ? authorization?.permissions?.length === 2 &&
      authorization.permissions[0] === permission &&
      authorization.permissions[1] === permission.replace(/\.read$/u, ".manage")
    : authorization?.permission === permission;
  assert(
    authorization?.activeSession === true &&
      permissionIsExact &&
      authorization.scopes?.length === 1 &&
      authorization.scopes[0] === "platform" &&
      authorization.principalTypes?.length === 1 &&
      authorization.principalTypes[0] === "human" &&
      authorization.uiVisibilityIsNotAuthorization === true,
    `${operationID} must preserve exact tenantless human authority`,
  );
  assert(
    operation.security?.[0]?.sessionCookie !== undefined &&
      (!mutation || operation.security[0].csrfToken !== undefined),
    `${operationID} must require the expected session/CSRF pair`,
  );
  assert(
    operation.responses?.["200"]?.headers?.["Cache-Control"],
    `${operationID} success must be no-store`,
  );
  if (mutation) {
    assert(
      authorization.recentLocalAssuranceSeconds === 900,
      `${operationID} must require manage authority and fresh local MFA`,
    );
    const parameters = operation.parameters ?? [];
    assert(
      parameters.some(
        ({ $ref }) => $ref === "#/components/parameters/IfMatch",
      ) &&
        parameters.some(
          ({ $ref }) =>
            $ref === "#/components/parameters/PlatformOperationsAuditReason",
        ),
      `${operationID} must bind If-Match and a safe audit reason`,
    );
  }

  const goName = operationID[0].toUpperCase() + operationID.slice(1);
  assert(
    sdk.includes(`export const ${operationID} =`),
    `${operationID} TypeScript SDK is missing`,
  );
  assert(go.includes(goName), `${goName} Go contract is missing`);
}

for (const schemaName of [
  "PlatformUserInventoryItem",
  "PlatformOperationQueueSource",
  "PlatformFailedNotification",
  "PlatformGlobalSettings",
  "PlatformFeatureFlag",
]) {
  assert(
    document.components.schemas[schemaName]?.additionalProperties === false,
    `${schemaName} must remain a closed projection`,
  );
}

const users = document.components.schemas.PlatformUserInventoryItem;
for (const forbidden of [
  "password",
  "credential",
  "assertion",
  "attributes",
  "sessionIds",
  "tenantIds",
]) {
  assert(
    users.properties[forbidden] === undefined,
    `user inventory leaked ${forbidden}`,
  );
}
assert(
  users.properties.activeTenantMembershipCount &&
    users.properties.totalTenantMembershipCount &&
    users.properties.liveSessionsByAuthenticationMethod,
  "user inventory must distinguish effective memberships and live session summaries",
);

const failed = document.components.schemas.PlatformFailedNotification;
for (const forbidden of [
  "recipient",
  "body",
  "renderedContent",
  "providerReceipt",
  "lastError",
]) {
  assert(
    failed.properties[forbidden] === undefined,
    `failed notification leaked ${forbidden}`,
  );
}

const settings = document.components.schemas.PlatformGlobalSettings;
assert(
  Object.keys(settings.properties).sort().join(",") ===
    "defaultLocale,defaultTimezone,platformName,supportUrl,updatedAt,version",
  "global settings must remain typed and secret-free",
);
assert(
  document.components.schemas.PlatformFeatureFlagKey.enum.join(",") ===
    "platform_failed_notifications_view",
  "feature flags must remain allowlisted",
);

console.log("Platform operations contract invariants verified.");
