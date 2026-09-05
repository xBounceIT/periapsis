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
    `Platform local-account contract invariant failed: ${message}`,
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
const parameters = document.components?.parameters;
assert(schemas && parameters, "OpenAPI components are missing");

const resolveSchema = (candidate, message) => {
  const reference = candidate?.$ref;
  assert(
    typeof reference === "string" &&
      reference.startsWith("#/components/schemas/"),
    `${message} must be a local component-schema reference`,
  );
  const name = reference.slice("#/components/schemas/".length);
  const schema = schemas[name];
  assert(schema && typeof schema === "object", `${message} references ${name}`);
  return schema;
};
const parameterName = (candidate) => {
  if (candidate?.$ref?.startsWith("#/components/parameters/")) {
    return parameters[candidate.$ref.slice("#/components/parameters/".length)]
      ?.name;
  }
  return candidate?.name;
};
const responseSchema = (operation, status) =>
  resolveSchema(
    operation.responses?.[status]?.content?.["application/json"]?.schema,
    `${operation.operationId} ${status} response`,
  );
const requestSchema = (operation) =>
  resolveSchema(
    operation.requestBody?.content?.["application/json"]?.schema,
    `${operation.operationId} request`,
  );

const base = "/api/v1/platform/local-accounts";
const item = `${base}/{localAccountId}`;
const operationSpecs = [
  [base, "get", "listPlatformLocalAccounts", "read", false, "200"],
  [base, "post", "invitePlatformLocalAccount", "manage", true, "201"],
  [item, "get", "getPlatformLocalAccount", "read", false, "200"],
  [
    `${item}/activate`,
    "post",
    "activatePlatformLocalAccount",
    "manage",
    true,
    "200",
  ],
  [
    `${item}/disable`,
    "post",
    "disablePlatformLocalAccount",
    "manage",
    true,
    "200",
  ],
  [
    `${item}/enable`,
    "post",
    "enablePlatformLocalAccount",
    "manage",
    true,
    "200",
  ],
  [
    `${item}/recover`,
    "post",
    "recoverPlatformLocalAccount",
    "manage",
    true,
    "200",
  ],
  [
    `${item}/password`,
    "put",
    "rotatePlatformLocalAccountPassword",
    "manage",
    true,
    "200",
  ],
];

for (const [
  path,
  method,
  operationId,
  permission,
  mutation,
  success,
] of operationSpecs) {
  const operation = document.paths?.[path]?.[method];
  assert(
    operation?.operationId === operationId,
    `${method.toUpperCase()} ${path} is missing`,
  );
  exact(
    operation.tags,
    ["Platform local accounts"],
    `${operationId} tag drifted`,
  );
  const expectedSecurity = mutation
    ? [{ sessionCookie: [], csrfToken: [] }]
    : [{ sessionCookie: [] }];
  exact(
    operation.security,
    expectedSecurity,
    `${operationId} security drifted`,
  );
  const authorization = operation["x-periapsis-authorization"];
  assert(
    authorization?.activeSession === true &&
      authorization.permission === `platform.identity_account.${permission}` &&
      authorization.scopes?.length === 1 &&
      authorization.scopes[0] === "platform" &&
      authorization.principalTypes?.length === 1 &&
      authorization.principalTypes[0] === "human" &&
      authorization.uiVisibilityIsNotAuthorization === true,
    `${operationId} platform authorization drifted`,
  );
  if (mutation) {
    assert(
      authorization.freshLocalMfa === true,
      `${operationId} must require fresh local MFA`,
    );
    assert(
      authorization.conditionalPermissions?.response_projection ===
        "platform.identity_account.read",
      `${operationId} must require read permission for its response projection`,
    );
    assert(
      operation["x-periapsis-idempotency-retention-seconds"] === 86400,
      `${operationId} idempotency window drifted`,
    );
    const names = operation.parameters?.map(parameterName) ?? [];
    assert(
      names.includes("Idempotency-Key"),
      `${operationId} lacks Idempotency-Key`,
    );
    assert(
      names.includes("X-Audit-Reason"),
      `${operationId} lacks X-Audit-Reason`,
    );
    if (operationId !== "invitePlatformLocalAccount") {
      assert(names.includes("If-Match"), `${operationId} lacks If-Match`);
      assert(operation.responses?.["412"], `${operationId} lacks 412`);
      assert(operation.responses?.["428"], `${operationId} lacks 428`);
    }
    assert(operation.responses?.["409"], `${operationId} lacks 409`);
  }
  assert(
    operation.responses?.[success],
    `${operationId} lacks success response`,
  );
  assert(operation.responses?.["401"], `${operationId} lacks 401`);
  assert(operation.responses?.["403"], `${operationId} lacks 403`);
  assert(operation.responses?.["503"], `${operationId} lacks 503`);
}

const account = schemas.PlatformLocalAccount;
assert(
  account?.type === "object" && account.additionalProperties === false,
  "safe account must remain closed",
);
const forbiddenReadProperties = [
  "password",
  "passwordPhc",
  "ceremonyToken",
  "ceremonyTokenDigest",
  "factorProof",
  "factorSecret",
  "totpEnrollment",
  "recoveryCode",
  "sessionProvenance",
  "roles",
  "permissions",
  "tenantMemberships",
];
for (const property of forbiddenReadProperties) {
  assert(
    !(property in (account.properties ?? {})),
    `safe account exposes ${property}`,
  );
}
exact(
  account.required,
  Object.keys(account.properties ?? {}),
  "safe account must require its exact bounded projection",
);
assert(
  account.properties?.revision?.$ref ===
    "#/components/schemas/PlatformLocalAccountRevision",
  "safe account revision must use the canonical revision schema",
);

const list = schemas.PlatformLocalAccountList;
assert(
  list?.additionalProperties === false &&
    list.properties?.items?.maxItems === 100 &&
    list.properties.items.items?.$ref ===
      "#/components/schemas/PlatformLocalAccount",
  "safe list must remain closed and bounded",
);

const transition = schemas.PlatformLocalAccountTransitionRequest;
assert(
  transition?.additionalProperties === false &&
    transition.properties?.expectedRevision?.minimum === 1 &&
    transition.properties?.expectedRevision?.maximum === 9007199254740990,
  "transition CAS body must remain positive and incrementable",
);

const activation = schemas.PlatformLocalAccountActivateRequest;
const rotation = schemas.PlatformLocalAccountPasswordRotationRequest;
const canonicalCeremonyTokenPattern =
  "^(?!A{43}$)[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$";
for (const [name, schema] of [
  ["activation", activation],
  ["password rotation", rotation],
]) {
  assert(
    schema?.additionalProperties === false,
    `${name} request must remain closed`,
  );
  const password = schema.properties?.newPassword;
  assert(
    password?.writeOnly === true &&
      password.minLength === 14 &&
      password.maxLength === 1024 &&
      password["x-periapsis-max-utf8-bytes"] === 1024 &&
      password["x-periapsis-sensitive"] === true,
    `${name} password must remain write-only and byte-bounded`,
  );
}
assert(
  activation.properties?.ceremonyToken?.writeOnly === true &&
    activation.properties.ceremonyToken.minLength === 43 &&
    activation.properties.ceremonyToken.maxLength === 43 &&
    activation.properties.ceremonyToken.pattern ===
      canonicalCeremonyTokenPattern &&
    activation.properties?.factorProof?.writeOnly === true &&
    activation.properties.factorProof.maxLength === 8,
  "activation secrets must remain write-only and bounded",
);

const result = responseSchema(document.paths[base].post, "201");
const totpEnrollment = schemas.PlatformLocalAccountTOTPEnrollment;
assert(
  result === schemas.PlatformLocalAccountMutationResult &&
    result.additionalProperties === false &&
    !result.required.includes("ceremonyToken") &&
    !result.required.includes("totpEnrollment") &&
    result.properties?.ceremonyToken?.minLength === 43 &&
    result.properties.ceremonyToken.maxLength === 43 &&
    result.properties.ceremonyToken.pattern === canonicalCeremonyTokenPattern &&
    result.properties.ceremonyToken["x-periapsis-sensitive"] === true &&
    result.properties?.totpEnrollment?.$ref ===
      "#/components/schemas/PlatformLocalAccountTOTPEnrollment" &&
    result.dependentRequired?.ceremonyToken?.[0] === "totpEnrollment" &&
    result.dependentRequired?.totpEnrollment?.[0] === "ceremonyToken",
  "one-time result enrollment semantics drifted",
);
assert(
  totpEnrollment?.additionalProperties === false &&
    JSON.stringify(totpEnrollment.required) ===
      JSON.stringify(["secret", "provisioningUri"]) &&
    totpEnrollment.properties?.secret?.pattern === "^[A-Z2-7]{16,256}$" &&
    totpEnrollment.properties.secret.maxLength === 256 &&
    totpEnrollment.properties.secret["x-periapsis-sensitive"] === true &&
    totpEnrollment.properties?.provisioningUri?.pattern ===
      "^otpauth://totp/" &&
    totpEnrollment.properties.provisioningUri.maxLength === 2048 &&
    totpEnrollment.properties.provisioningUri["x-periapsis-sensitive"] === true,
  "one-time TOTP enrollment must remain canonical, sensitive, and bounded",
);
assert(
  responseSchema(document.paths[item].get, "200") === account,
  "item read must return only the safe projection",
);
assert(
  responseSchema(document.paths[base].get, "200") === list,
  "list read must return only the safe projection",
);
assert(
  requestSchema(document.paths[`${item}/activate`].post) === activation &&
    requestSchema(document.paths[`${item}/password`].put) === rotation,
  "secret mutation request references drifted",
);

const reason = parameters.PlatformLocalAccountAuditReason?.schema;
assert(
  reason?.minLength === 1 &&
    reason.maxLength === 500 &&
    reason["x-periapsis-max-utf8-bytes"] === 500,
  "audit reason must remain strictly bounded",
);
const etag = schemas.PlatformLocalAccountStrongEntityTag;
assert(
  etag?.minLength === 4 &&
    etag.maxLength === 19 &&
    etag["x-periapsis-revision-maximum"] === 9007199254740991,
  "strong ETag must remain bounded to JSON-safe revisions",
);

for (const sdkName of [
  "listPlatformLocalAccounts",
  "invitePlatformLocalAccount",
  "getPlatformLocalAccount",
  "activatePlatformLocalAccount",
  "disablePlatformLocalAccount",
  "enablePlatformLocalAccount",
  "recoverPlatformLocalAccount",
  "rotatePlatformLocalAccountPassword",
]) {
  assert(
    sdk.includes(`const ${sdkName}`) || sdk.includes(`function ${sdkName}`),
    `${sdkName} SDK operation is missing`,
  );
}

console.log("Platform local-account contract invariants verified.");
