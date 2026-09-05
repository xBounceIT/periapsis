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
  throw new Error(`MFA policy contract invariant failed: ${message}`);
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

const platformBase = "/api/v1/platform/mfa-policies";
const tenantBase = "/api/v1/tenants/{tenantId}/mfa-policies";
const operations = [
  [platformBase, "get", "listPlatformMfaPolicies", "read", false],
  [platformBase, "post", "publishPlatformMfaPolicy", "manage", true],
  [
    `${platformBase}/{policyId}/revisions/{revision}`,
    "get",
    "getPlatformMfaPolicyRevision",
    "read",
    false,
  ],
  [
    `${platformBase}/simulate`,
    "post",
    "simulatePlatformMfaPolicyChange",
    "read",
    true,
  ],
  [
    `${platformBase}/{policyId}`,
    "put",
    "replacePlatformMfaPolicy",
    "manage",
    true,
  ],
  [
    `${platformBase}/{policyId}/retire`,
    "post",
    "retirePlatformMfaPolicy",
    "manage",
    true,
  ],
  [tenantBase, "get", "listTenantMfaPolicies", "read", false],
  [tenantBase, "post", "publishTenantMfaPolicy", "manage", true],
  [
    `${tenantBase}/{policyId}/revisions/{revision}`,
    "get",
    "getTenantMfaPolicyRevision",
    "read",
    false,
  ],
  [
    `${tenantBase}/simulate`,
    "post",
    "simulateTenantMfaPolicyChange",
    "read",
    true,
  ],
  [`${tenantBase}/{policyId}`, "put", "replaceTenantMfaPolicy", "manage", true],
  [
    `${tenantBase}/{policyId}/retire`,
    "post",
    "retireTenantMfaPolicy",
    "manage",
    true,
  ],
];

for (const [path, method, operationId, permission, csrf] of operations) {
  const operation = document.paths?.[path]?.[method];
  assert(operation?.operationId === operationId, `${operationId} is missing`);
  const security = operation.security?.[0] ?? {};
  assert(
    security.sessionCookie !== undefined,
    `${operationId} lost session auth`,
  );
  assert(
    !csrf || security.csrfToken !== undefined,
    `${operationId} lost CSRF protection`,
  );
  const authorization = operation["x-periapsis-authorization"] ?? {};
  const tenant = path.startsWith(tenantBase);
  if (tenant) {
    assert(
      authorization.tenantContext === "path" &&
        authorization.activeMembership === true,
      `${operationId} lost active-tenant binding`,
    );
    exact(
      permission === "manage"
        ? authorization.permissions
        : [authorization.permission],
      permission === "manage"
        ? ["identity_policy.read", "identity_policy.manage"]
        : ["identity_policy.read"],
      `${operationId} tenant permissions drifted`,
    );
  } else {
    assert(
      authorization.tenantContext === "forbidden" &&
        authorization.activeSession === true,
      `${operationId} must require a live platform session and reject tenant context`,
    );
    exact(
      authorization.scopes,
      ["platform"],
      `${operationId} platform scope drifted`,
    );
    exact(
      permission === "manage"
        ? authorization.permissions
        : [authorization.permission],
      permission === "manage"
        ? ["platform.identity_policy.read", "platform.identity_policy.manage"]
        : ["platform.identity_policy.read"],
      `${operationId} platform permissions drifted`,
    );
  }
  exact(
    authorization.principalTypes,
    ["human"],
    `${operationId} principal boundary drifted`,
  );
  assert(
    authorization.uiVisibilityIsNotAuthorization === true,
    `${operationId} lost deny-by-default UI warning`,
  );
  if (permission === "manage") {
    assert(
      authorization.recentLocalAssuranceSeconds === 300,
      `${operationId} lost recent local assurance`,
    );
  }
  for (const [status, response] of Object.entries(operation.responses ?? {})) {
    if (status.startsWith("2")) {
      assert(
        response.headers?.["Cache-Control"]?.$ref ===
          "#/components/headers/NoStore" ||
          response.$ref === "#/components/responses/MfaPolicyMutationSucceeded",
        `${operationId} ${status} must be no-store`,
      );
    } else {
      assert(
        response.$ref?.startsWith("#/components/responses/NoStore"),
        `${operationId} ${status} must use no-store Problem Details`,
      );
    }
  }
  assert(
    sdk.includes(`export const ${operationId} =`),
    `${operationId} generated client is missing`,
  );
}

const schemas = document.components?.schemas ?? {};
const exactAudiencePattern =
  "^(?!\\s)(?![\\s\\S]*\\s$)(?![\\s\\S]*[\\p{Cc}\\p{Cf}])[\\s\\S]+$";
const exactInstantPattern =
  "^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:[0-5]\\d(?:\\.\\d{3})?Z$";
assert(
  schemas.MfaPolicyRevision?.maximum === 9007199254740991,
  "revision must remain JavaScript exact",
);
exact(
  schemas.MfaPolicyScope?.enum,
  ["platform_floor", "tenant_baseline", "security_group", "role", "action"],
  "runtime scope precedence drifted",
);
assert(
  schemas.PlatformMfaPolicyTargetInput?.additionalProperties === false &&
    schemas.TenantMfaPolicyTargetInput?.additionalProperties === false &&
    schemas.TenantMfaPolicyTargetInput?.properties?.tenantId === undefined,
  "tenant identity must come only from the path",
);
for (const schema of [
  schemas.TenantMfaPolicyTargetInput,
  schemas.MfaPolicyTarget,
  schemas.MfaPolicySimulationContext,
]) {
  assert(
    schema?.properties?.action?.pattern === exactAudiencePattern,
    "actions must remain exact trimmed non-control text",
  );
}
for (const field of ["roleIds", "securityGroupIds"]) {
  const schema = schemas.MfaPolicySimulationContext?.properties?.[field];
  assert(
    schema?.maxItems === 512 && schema.uniqueItems === true,
    `${field} must remain bounded and deduplicated`,
  );
}
assert(
  schemas.MfaPolicySimulationSource?.required?.includes("requirement"),
  "every simulation source must carry its requirement",
);
assert(
  schemas.MfaPolicySimulationResult?.required?.includes("context"),
  "simulation must echo normalized context (null for platform)",
);
assert(
  schemas.MfaPolicyRecoverySafety?.properties?.reasonCodes?.maxItems === 3,
  "recovery reasons must remain bounded",
);
exact(
  schemas.MfaPolicyRecoveryReason?.enum,
  [
    "no_eligible_direct_administrator",
    "no_ready_local_primary",
    "no_ready_local_mfa",
    "no_ready_local_phishing_resistant",
  ],
  "recovery reason allowlist drifted",
);
assert(
  schemas.MfaPolicyRequirement?.properties?.freshnessSeconds?.maximum ===
    31536000,
  "freshness bound drifted",
);
for (const [field, schema] of [
  [
    "enrollmentDeadline",
    schemas.MfaPolicyRequirement?.properties?.enrollmentDeadline,
  ],
  ["createdAt", schemas.MfaPolicyDocument?.properties?.createdAt],
  ["retiredAt", schemas.MfaPolicyDocument?.properties?.retiredAt],
]) {
  assert(
    schema?.format === "date-time" && schema.pattern === exactInstantPattern,
    `${field} must remain a UTC RFC3339 instant with at most millisecond precision`,
  );
}

const parameters = document.components?.parameters ?? {};
assert(
  parameters.MfaPolicyCommandId?.schema?.format === "uuid",
  "command ID must be UUID shaped",
);
assert(
  parameters.MfaPolicyAuditReason?.schema?.maxLength === 2048,
  "audit reason bound drifted",
);

console.log("MFA policy contract invariants verified");
