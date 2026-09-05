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
    `Platform identity-account contract invariant failed: ${message}`,
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

const schemas = document.components?.schemas;
assert(
  schemas && typeof schemas === "object",
  "OpenAPI component schemas are missing",
);

const providerPath = "/api/v1/platform/auth-providers/{providerId}";
const collectionPath = `${providerPath}/accounts`;
const itemPath = `${collectionPath}/{accountId}`;
const operations = [
  [
    collectionPath,
    "get",
    "listPlatformAuthProviderAccounts",
    "read",
    false,
    "listPlatformAuthProviderAccounts",
  ],
  [
    collectionPath,
    "post",
    "prelinkPlatformAuthProviderAccount",
    "manage",
    true,
    "prelinkPlatformAuthProviderAccount",
  ],
  [
    itemPath,
    "get",
    "getPlatformAuthProviderAccount",
    "read",
    false,
    "getPlatformAuthProviderAccount",
  ],
  [
    itemPath,
    "delete",
    "retirePlatformAuthProviderAccount",
    "manage",
    true,
    "retirePlatformAuthProviderAccount",
  ],
];

for (const [
  path,
  method,
  operationId,
  permission,
  mutation,
  sdkName,
] of operations) {
  const operation = document.paths?.[path]?.[method];
  assert(operation?.operationId === operationId, `${operationId} is missing`);
  const security = operation.security?.[0] ?? {};
  assert(
    security.sessionCookie !== undefined &&
      (!mutation || security.csrfToken !== undefined),
    `${operationId} lost its session${mutation ? "/CSRF" : ""} boundary`,
  );
  const authorization = operation["x-periapsis-authorization"];
  assert(
    authorization?.activeSession === true &&
      authorization.permission === `platform.identity_account.${permission}` &&
      authorization.uiVisibilityIsNotAuthorization === true,
    `${operationId} lost deny-by-default account authority`,
  );
  exact(authorization.scopes, ["platform"], `${operationId} scope drifted`);
  exact(
    authorization.principalTypes,
    ["human"],
    `${operationId} principal drifted`,
  );
  if (mutation) {
    assert(
      authorization.conditionalPermissions?.response_projection ===
        "platform.identity_account.read",
      `${operationId} must preflight live safe-projection authority`,
    );
  }
  for (const [status, response] of Object.entries(operation.responses ?? {})) {
    if (status.startsWith("2")) {
      assert(
        response.headers?.["Cache-Control"]?.$ref ===
          "#/components/headers/NoStore",
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
    sdk.includes(`export const ${sdkName} =`),
    `${operationId} generated client is missing`,
  );
}

exact(
  document.paths[collectionPath].parameters,
  [{ $ref: "#/components/parameters/PlatformAuthProviderId" }],
  "account collection provider parameter drifted",
);
exact(
  document.paths[itemPath].parameters,
  [
    { $ref: "#/components/parameters/PlatformAuthProviderId" },
    { $ref: "#/components/parameters/PlatformAuthProviderAccountId" },
  ],
  "account item path parameters drifted",
);

const prelink = document.paths[collectionPath].post;
const prelinkReferences = new Set(
  prelink.parameters.map((parameter) => parameter.$ref),
);
assert(
  prelinkReferences.has("#/components/parameters/IdempotencyKey") &&
    prelinkReferences.has(
      "#/components/parameters/PlatformIdentityProviderAuditReason",
    ) &&
    prelink["x-periapsis-idempotency-retention-seconds"] === 86400 &&
    /guaranteed 24-hour command window/u.test(prelink.description),
  "prelink must bind a 24-hour retry key and one audit reason",
);
assert(
  prelink.responses["201"]?.headers?.Location?.$ref ===
    "#/components/headers/ResourceLocation" &&
    prelink.responses["201"]?.headers?.ETag?.$ref ===
      "#/components/headers/PlatformAuthProviderAccountStrongETag" &&
    prelink.responses["201"]?.content?.["application/json"]?.schema?.$ref ===
      "#/components/schemas/PlatformAuthProviderAccount",
  "prelink must return the current safe resource, Location, and strong ETag",
);

const retire = document.paths[itemPath].delete;
const retireReferences = new Set(
  retire.parameters.map((parameter) => parameter.$ref),
);
assert(
  retireReferences.has(
    "#/components/parameters/PlatformAuthProviderAccountIfMatch",
  ) &&
    retireReferences.has(
      "#/components/parameters/PlatformIdentityProviderAuditReason",
    ) &&
    retire.responses["412"] !== undefined &&
    retire.responses["428"] !== undefined &&
    retire.responses["200"]?.headers?.ETag?.$ref ===
      "#/components/headers/PlatformAuthProviderAccountStrongETag" &&
    retire.responses["200"]?.content?.["application/json"]?.schema?.$ref ===
      "#/components/schemas/PlatformAuthProviderAccount",
  "retire must bind strong CAS and return the current safe retired resource",
);
assert(
  document.paths[itemPath].get.responses["200"]?.headers?.ETag?.$ref ===
    "#/components/headers/PlatformAuthProviderAccountStrongETag",
  "account detail reads must return a strong ETag",
);

const accountEntityTag = schemas.PlatformAuthProviderAccountStrongEntityTag;
assert(
  accountEntityTag?.type === "string" &&
    accountEntityTag.minLength === 7 &&
    accountEntityTag.maxLength === 25 &&
    accountEntityTag.pattern?.includes("-u") &&
    accountEntityTag.example === '"v3-u11"',
  "account ETag must bind exact account and embedded user revisions",
);

const account = schemas.PlatformAuthProviderAccount;
assert(
  account?.additionalProperties === false,
  "account projection must remain closed",
);
exact(
  account.required,
  [
    "id",
    "providerId",
    "user",
    "state",
    "admittedConfigurationRevision",
    "admittedSecurityRevision",
    "lastObservationState",
    "lastObservedAt",
    "retiredAt",
    "version",
    "createdAt",
    "updatedAt",
  ],
  "account projection required fields drifted",
);
exact(
  Object.keys(account.properties ?? {}),
  account.required,
  "account safe projection drifted",
);
const observationState =
  schemas.PlatformAuthProviderAccountLastObservationState;
exact(
  observationState?.enum,
  ["known", "legacy_unknown"],
  "account observation-state vocabulary drifted",
);
assert(
  JSON.stringify(account.properties.lastObservedAt?.type) ===
    JSON.stringify(["string", "null"]) &&
    account.properties.lastObservedAt?.format === "date-time" &&
    account["x-periapsis-observation-state-invariant"] ===
      "known_requires_timestamp_and_legacy_unknown_requires_retired_null_v1" &&
    account.allOf?.[0]?.if?.properties?.lastObservationState?.const ===
      "known" &&
    account.allOf?.[0]?.then?.properties?.lastObservedAt?.type === "string" &&
    account.allOf?.[1]?.if?.properties?.lastObservationState?.const ===
      "legacy_unknown" &&
    account.allOf?.[1]?.then?.properties?.state?.const === "retired" &&
    account.allOf?.[1]?.then?.properties?.lastObservedAt?.type === "null" &&
    account.allOf?.[1]?.then?.properties?.version?.const === 1,
  "account observation timestamp must be conditionally truthful",
);

const user = schemas.PlatformAuthProviderAccountUser;
assert(
  user?.additionalProperties === false,
  "account user projection must remain closed",
);
exact(
  user.required,
  ["id", "displayName", "email", "active", "version"],
  "account user requirements drifted",
);
exact(
  Object.keys(user.properties ?? {}),
  user.required,
  "account user safe projection drifted",
);

for (const [name, schema] of [
  ["PlatformAuthProviderAccount", account],
  ["PlatformAuthProviderAccountUser", user],
  ["PlatformAuthProviderAccountList", schemas.PlatformAuthProviderAccountList],
]) {
  const serialized = JSON.stringify(schema).toLowerCase();
  for (const forbidden of [
    '"issuer"',
    '"subject"',
    '"aliases"',
    '"ciphertext"',
    '"nonce"',
    '"claims"',
    '"roles"',
    '"permissions"',
    '"memberships"',
    '"accesstoken"',
    '"refreshtoken"',
  ]) {
    assert(
      !serialized.includes(forbidden),
      `${name} exposes forbidden material ${forbidden}`,
    );
  }
}

const prelinkRequest = schemas.PlatformAuthProviderAccountPrelinkRequest;
assert(
  prelinkRequest?.additionalProperties === false,
  "prelink request must remain closed",
);
exact(
  prelinkRequest.required,
  ["userId", "issuer", "subject"],
  "prelink request requirements drifted",
);
exact(
  Object.keys(prelinkRequest.properties ?? {}),
  prelinkRequest.required,
  "prelink accepted fields drifted",
);
assert(
  prelinkRequest.properties.issuer?.writeOnly === true &&
    prelinkRequest.properties.issuer?.maxLength === 2048 &&
    prelinkRequest.properties.issuer?.["x-periapsis-max-utf8-bytes"] === 2048 &&
    prelinkRequest.properties.subject?.writeOnly === true &&
    prelinkRequest.properties.subject?.maxLength === 1024 &&
    prelinkRequest.properties.subject?.["x-periapsis-max-utf8-bytes"] === 1024,
  "issuer and subject must remain write-only and byte-bounded",
);

const retireRequest = schemas.PlatformAuthProviderAccountRetireRequest;
assert(
  retireRequest?.additionalProperties === false,
  "retire request must remain closed",
);
exact(
  retireRequest.required,
  ["expectedVersion"],
  "retire requirements drifted",
);
exact(
  Object.keys(retireRequest.properties ?? {}),
  ["expectedVersion"],
  "retire accepted fields drifted",
);
assert(
  retireRequest.properties.expectedVersion?.minimum === 1 &&
    retireRequest.properties.expectedVersion?.maximum === 2147483646,
  "retire version must remain safely incrementable",
);
