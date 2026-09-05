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
    `Platform identity-provider contract invariant failed: ${message}`,
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
const resolveSchemaReference = (candidate, message) => {
  const reference = candidate?.$ref;
  assert(
    typeof reference === "string" &&
      reference.startsWith("#/components/schemas/"),
    `${message} must be a local component-schema reference`,
  );
  const name = reference.slice("#/components/schemas/".length);
  const schema = schemas[name];
  assert(
    schema && typeof schema === "object",
    `${message} references missing schema ${name}`,
  );
  return schema;
};
const resolveClosedSamlVariant = (name, expectedCommonReference) => {
  const schema = schemas[name];
  assert(schema && typeof schema === "object", `${name} is missing`);
  assert(schema.unevaluatedProperties === false, `${name} must remain closed`);
  assert(
    Array.isArray(schema.allOf) && schema.allOf.length === 2,
    `${name} must compose exactly one common and one variant schema`,
  );
  assert(
    schema.allOf[0]?.$ref === expectedCommonReference,
    `${name} common schema reference drifted`,
  );
  resolveSchemaReference(schema.allOf[0], `${name} common schema`);
  const variant = schema.allOf[1];
  assert(
    variant?.type === "object" &&
      variant.properties &&
      typeof variant.properties === "object" &&
      Array.isArray(variant.required),
    `${name} variant object is malformed`,
  );
  return variant;
};

const basePath = "/api/v1/platform/auth-providers";
const itemPath = `${basePath}/{providerId}`;
const secretPath = `${itemPath}/oidc-client-secret`;
const samlMetadataPath = `${itemPath}/saml/metadata`;
const samlSPKeyPath = `${itemPath}/saml/sp-key`;
const bindingBasePath = `${itemPath}/tenant-bindings`;
const bindingItemPath = `${bindingBasePath}/{bindingId}`;
const activatePath = `${itemPath}/activate`;
const deactivatePath = `${itemPath}/deactivate`;
const directLoginActivatePath = `${itemPath}/direct-login/activate`;
const directLoginDeactivatePath = `${itemPath}/direct-login/deactivate`;
const bindingActivatePath = `${bindingItemPath}/activate`;
const bindingDeactivatePath = `${bindingItemPath}/deactivate`;
const operations = [
  [
    basePath,
    "get",
    "listPlatformAuthProviders",
    "read",
    false,
    "listPlatformAuthProviders",
  ],
  [
    basePath,
    "post",
    "createPlatformAuthProvider",
    "manage",
    true,
    "createPlatformAuthProvider",
  ],
  [
    itemPath,
    "get",
    "getPlatformAuthProvider",
    "read",
    false,
    "getPlatformAuthProvider",
  ],
  [
    itemPath,
    "put",
    "updatePlatformAuthProvider",
    "manage",
    true,
    "updatePlatformAuthProvider",
  ],
  [
    itemPath,
    "delete",
    "archivePlatformAuthProvider",
    "manage",
    true,
    "archivePlatformAuthProvider",
  ],
  [
    secretPath,
    "put",
    "replacePlatformOIDCAuthProviderClientSecret",
    "manage",
    true,
    "replacePlatformOidcAuthProviderClientSecret",
  ],
  [
    samlMetadataPath,
    "put",
    "replacePlatformSAMLAuthProviderMetadata",
    "manage",
    true,
    "replacePlatformSamlAuthProviderMetadata",
  ],
  [
    samlSPKeyPath,
    "put",
    "replacePlatformSAMLAuthProviderSPKey",
    "manage",
    true,
    "replacePlatformSamlAuthProviderSpKey",
  ],
  [
    samlSPKeyPath,
    "delete",
    "clearPlatformSAMLAuthProviderSPKey",
    "manage",
    true,
    "clearPlatformSamlAuthProviderSpKey",
  ],
  [
    activatePath,
    "post",
    "activatePlatformAuthProviderTenantExecution",
    "manage",
    true,
    "activatePlatformAuthProviderTenantExecution",
  ],
  [
    deactivatePath,
    "post",
    "deactivatePlatformAuthProviderTenantExecution",
    "manage",
    true,
    "deactivatePlatformAuthProviderTenantExecution",
  ],
  [
    directLoginActivatePath,
    "post",
    "activatePlatformOIDCDirectLogin",
    "manage",
    true,
    "activatePlatformOidcDirectLogin",
  ],
  [
    directLoginDeactivatePath,
    "post",
    "deactivatePlatformOIDCDirectLogin",
    "manage",
    true,
    "deactivatePlatformOidcDirectLogin",
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
      authorization.permission === `platform.identity_provider.${permission}` &&
      authorization.uiVisibilityIsNotAuthorization === true,
    `${operationId} lost deny-by-default authority`,
  );
  exact(authorization.scopes, ["platform"], `${operationId} scope drifted`);
  exact(
    authorization.principalTypes,
    ["human"],
    `${operationId} principal drifted`,
  );
  for (const [status, response] of Object.entries(operation.responses)) {
    if (status === "204") {
      assert(
        response.headers?.["Cache-Control"]?.$ref ===
          "#/components/headers/NoStore",
        `${operationId} ${status} must be no-store`,
      );
      continue;
    }
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

for (const path of [directLoginActivatePath, directLoginDeactivatePath]) {
  assert(
    document.paths[path].post["x-periapsis-authorization"]
      .conditionalPermissions?.response_projection ===
      "platform.identity_provider.read",
    `${document.paths[path].post.operationId} must preflight live response-projection authority`,
  );
}

const bindingOperations = [
  [
    bindingBasePath,
    "get",
    "listPlatformAuthProviderTenantBindings",
    "read",
    false,
    "listPlatformAuthProviderTenantBindings",
  ],
  [
    bindingBasePath,
    "post",
    "createPlatformAuthProviderTenantBinding",
    "manage",
    true,
    "createPlatformAuthProviderTenantBinding",
  ],
  [
    bindingItemPath,
    "get",
    "getPlatformAuthProviderTenantBinding",
    "read",
    false,
    "getPlatformAuthProviderTenantBinding",
  ],
  [
    bindingItemPath,
    "patch",
    "updatePlatformAuthProviderTenantBinding",
    "manage",
    true,
    "updatePlatformAuthProviderTenantBinding",
  ],
  [
    bindingItemPath,
    "delete",
    "archivePlatformAuthProviderTenantBinding",
    "manage",
    true,
    "archivePlatformAuthProviderTenantBinding",
  ],
  [
    bindingActivatePath,
    "post",
    "activatePlatformAuthProviderTenantBinding",
    "manage",
    true,
    "activatePlatformAuthProviderTenantBinding",
  ],
  [
    bindingDeactivatePath,
    "post",
    "deactivatePlatformAuthProviderTenantBinding",
    "manage",
    true,
    "deactivatePlatformAuthProviderTenantBinding",
  ],
];

for (const [
  path,
  method,
  operationId,
  permission,
  mutation,
  sdkName,
] of bindingOperations) {
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
      authorization.permission === `platform.identity_binding.${permission}` &&
      authorization.uiVisibilityIsNotAuthorization === true,
    `${operationId} lost deny-by-default binding authority`,
  );
  exact(authorization.scopes, ["platform"], `${operationId} scope drifted`);
  exact(
    authorization.principalTypes,
    ["human"],
    `${operationId} principal drifted`,
  );
  for (const [status, response] of Object.entries(operation.responses)) {
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

for (const operationId of [
  "updatePlatformAuthProviderTenantBinding",
  "archivePlatformAuthProviderTenantBinding",
  "activatePlatformAuthProviderTenantBinding",
  "deactivatePlatformAuthProviderTenantBinding",
]) {
  const operation = bindingOperations
    .map(([path, method]) => document.paths[path][method])
    .find((candidate) => candidate.operationId === operationId);
  const references = new Set(
    operation.parameters.map((parameter) => parameter.$ref),
  );
  assert(
    references.has(
      "#/components/parameters/PlatformAuthProviderTenantBindingIfMatch",
    ) &&
      references.has(
        "#/components/parameters/PlatformIdentityProviderAuditReason",
      ),
    `${operationId} must bind strong CAS and one audit reason`,
  );
  assert(
    operation.responses["412"] !== undefined &&
      operation.responses["428"] !== undefined,
    `${operationId} must expose 412 and 428`,
  );
}

const createBinding = document.paths[bindingBasePath].post;
exact(
  document.paths[bindingBasePath].get.parameters.map(
    (parameter) => parameter.$ref,
  ),
  [
    "#/components/parameters/AfterCursor",
    "#/components/parameters/PageSize",
    "#/components/parameters/IncludeArchived",
  ],
  "binding list pagination parameters drifted",
);
assert(
  createBinding.parameters.some(
    (parameter) => parameter.$ref === "#/components/parameters/IdempotencyKey",
  ) &&
    createBinding.parameters.some(
      (parameter) =>
        parameter.$ref ===
        "#/components/parameters/PlatformIdentityProviderAuditReason",
    ) &&
    createBinding["x-periapsis-authorization"].conditionalPermissions
      ?.response_projection === "platform.identity_binding.read" &&
    document.paths[bindingItemPath].patch["x-periapsis-authorization"]
      .conditionalPermissions?.response_projection ===
      "platform.identity_binding.read",
  "binding create/update must bind retry, audit, and live projection authority",
);
assert(
  createBinding["x-periapsis-idempotency-retention-seconds"] === 86400 &&
    /guaranteed\s+for 24 hours/.test(createBinding.description) &&
    /permanent\s+provider\/tenant reservation/.test(
      createBinding.description,
    ) &&
    createBinding.responses["201"].description.includes(
      "exact 24-hour retention window",
    ) &&
    createBinding.responses["201"].description.includes(
      "rejects the retry as a conflict",
    ),
  "binding create must document bounded replay and post-expiry duplicate safety",
);
const genericIdempotencyDescription =
  document.components.parameters.IdempotencyKey?.description ?? "";
const normalizedGenericIdempotencyDescription =
  genericIdempotencyDescription.replace(/\s+/gu, " ");
assert(
  normalizedGenericIdempotencyDescription.includes(
    "guaranteed only for the retention window documented by that operation",
  ) &&
    normalizedGenericIdempotencyDescription.includes(
      "does not promise indefinite replay",
    ) &&
    normalizedGenericIdempotencyDescription.includes(
      "uniqueness and conflict safeguards",
    ),
  "generic idempotency wording must remain retention-bounded",
);
assert(
  createBinding.responses["201"].headers?.Location?.$ref ===
    "#/components/headers/ResourceLocation" &&
    createBinding.responses["201"].headers?.ETag?.$ref ===
      "#/components/headers/PlatformAuthProviderTenantBindingStrongETag",
  "binding create must return Location and its composite strong ETag",
);
assert(
  document.paths[bindingItemPath].get.responses["200"].headers?.ETag?.$ref ===
    "#/components/headers/PlatformAuthProviderTenantBindingStrongETag" &&
    document.paths[bindingItemPath].patch.responses["200"].headers?.ETag
      ?.$ref ===
      "#/components/headers/PlatformAuthProviderTenantBindingStrongETag" &&
    document.paths[bindingItemPath].delete.responses["204"].headers?.ETag
      ?.$ref ===
      "#/components/headers/PlatformAuthProviderTenantBindingStrongETag",
  "binding item reads and CAS mutations must return composite strong ETags",
);

const bindingEntityTag =
  schemas.PlatformAuthProviderTenantBindingStrongEntityTag;
assert(
  bindingEntityTag?.type === "string" &&
    bindingEntityTag.minLength === 7 &&
    bindingEntityTag.maxLength === 25 &&
    bindingEntityTag.example === '"v3-t11"' &&
    new RegExp(bindingEntityTag.pattern).test('"v2147483647-t2147483647"') &&
    !new RegExp(bindingEntityTag.pattern).test('W/"v3-t11"') &&
    !new RegExp(bindingEntityTag.pattern).test('"v03-t11"') &&
    !new RegExp(bindingEntityTag.pattern).test('"v3-t011"') &&
    !new RegExp(bindingEntityTag.pattern).test('"v3-t11","v4-t11"') &&
    !new RegExp(bindingEntityTag.pattern).test('"v2147483648-t11"') &&
    !new RegExp(bindingEntityTag.pattern).test('"v3-t2147483648"'),
  "binding composite strong ETag grammar drifted",
);
assert(
  document.components.headers.PlatformAuthProviderTenantBindingStrongETag
    ?.schema?.$ref ===
    "#/components/schemas/PlatformAuthProviderTenantBindingStrongEntityTag" &&
    document.components.parameters.PlatformAuthProviderTenantBindingIfMatch
      ?.schema?.$ref ===
      "#/components/schemas/PlatformAuthProviderTenantBindingStrongEntityTag",
  "binding header and precondition must use the composite strong ETag",
);

const binding = schemas.PlatformAuthProviderTenantBinding;
assert(
  binding?.additionalProperties === false &&
    binding.properties?.origin?.const === "platform" &&
    binding.properties?.enabled?.type === "boolean" &&
    binding.properties?.activationAvailable?.type === "boolean" &&
    binding.properties?.currentAccessEpochId?.format === "uuid" &&
    binding.properties?.currentAccessEpochId?.type?.includes("null"),
  "binding projection must remain platform-origin and expose bounded lifecycle state",
);
exact(
  binding.required,
  [
    "id",
    "providerId",
    "tenant",
    "origin",
    "loginKey",
    "profilePriority",
    "jitMode",
    "noMatchPolicy",
    "enabled",
    "activationAvailable",
    "authRevision",
    "mappingRevision",
    "currentAccessEpochId",
    "archivedAt",
    "version",
    "createdAt",
    "updatedAt",
  ],
  "binding projection required fields drifted",
);
const bindingTenant = schemas.PlatformAuthProviderTenantBindingTenant;
assert(
  bindingTenant?.additionalProperties === false,
  "binding tenant projection must remain closed",
);
exact(
  bindingTenant.required,
  ["id", "slug", "name", "status", "version"],
  "binding tenant required fields drifted",
);
exact(
  Object.keys(bindingTenant.properties ?? {}),
  ["id", "slug", "name", "status", "version"],
  "binding tenant safe projection drifted",
);
assert(
  bindingTenant.properties.version?.$ref ===
    "#/components/schemas/ResourceVersion",
  "binding tenant projection must expose its live version",
);
const bindingRequestRequirements = {
  PlatformAuthProviderTenantBindingCreateRequest: [
    "tenantId",
    "loginKey",
    "profilePriority",
  ],
  PlatformAuthProviderTenantBindingPatchRequest: [
    "expectedVersion",
    "expectedTenantVersion",
    "loginKey",
    "profilePriority",
  ],
  PlatformAuthProviderTenantBindingArchiveRequest: [
    "expectedVersion",
    "expectedTenantVersion",
  ],
  PlatformAuthProviderTenantBindingActivationRequest: [
    "expectedVersion",
    "expectedTenantVersion",
    "jitMode",
    "noMatchPolicy",
  ],
  PlatformAuthProviderTenantBindingDeactivationRequest: [
    "expectedVersion",
    "expectedTenantVersion",
  ],
};
for (const name of [
  "PlatformAuthProviderTenantBindingCreateRequest",
  "PlatformAuthProviderTenantBindingPatchRequest",
  "PlatformAuthProviderTenantBindingArchiveRequest",
  "PlatformAuthProviderTenantBindingActivationRequest",
  "PlatformAuthProviderTenantBindingDeactivationRequest",
]) {
  const schema = schemas[name];
  assert(schema?.additionalProperties === false, `${name} must remain closed`);
  exact(
    schema.required,
    bindingRequestRequirements[name],
    `${name} requirements drifted`,
  );
  exact(
    Object.keys(schema.properties ?? {}),
    bindingRequestRequirements[name],
    `${name} accepted fields drifted`,
  );
  for (const forbidden of [
    "enabled",
    "activationAvailable",
    "currentAccessEpochId",
    "authRevision",
    "mappingRevision",
    "origin",
    "platformRoleId",
    "roleId",
  ]) {
    assert(
      schema.properties?.[forbidden] === undefined,
      `${name} must not accept ${forbidden}`,
    );
  }

  if (name !== "PlatformAuthProviderTenantBindingCreateRequest") {
    assert(
      schema.properties.expectedTenantVersion?.minimum === 1 &&
        schema.properties.expectedTenantVersion?.maximum === 2147483647,
      `${name} must bind the complete live tenant-version range`,
    );
  }
}

for (const operationId of [
  "updatePlatformAuthProvider",
  "archivePlatformAuthProvider",
  "replacePlatformOIDCAuthProviderClientSecret",
  "replacePlatformSAMLAuthProviderMetadata",
  "replacePlatformSAMLAuthProviderSPKey",
  "clearPlatformSAMLAuthProviderSPKey",
  "activatePlatformAuthProviderTenantExecution",
  "deactivatePlatformAuthProviderTenantExecution",
  "activatePlatformOIDCDirectLogin",
  "deactivatePlatformOIDCDirectLogin",
]) {
  const operation = operations
    .map(([path, method]) => document.paths[path][method])
    .find((candidate) => candidate.operationId === operationId);
  const references = new Set(
    operation.parameters.map((parameter) => parameter.$ref),
  );
  assert(
    references.has("#/components/parameters/IfMatch") &&
      references.has(
        "#/components/parameters/PlatformIdentityProviderAuditReason",
      ),
    `${operationId} must bind strong CAS and one audit reason`,
  );
  assert(
    operation.responses["412"] !== undefined &&
      operation.responses["428"] !== undefined,
    `${operationId} must expose 412 and 428`,
  );
}

const create = document.paths[basePath].post;
assert(
  create.parameters.some(
    (parameter) => parameter.$ref === "#/components/parameters/IdempotencyKey",
  ) &&
    create.parameters.some(
      (parameter) =>
        parameter.$ref ===
        "#/components/parameters/PlatformIdentityProviderAuditReason",
    ) &&
    create["x-periapsis-authorization"].conditionalPermissions
      ?.response_projection === "platform.identity_provider.read",
  "create must bind idempotency, audit, and live response-projection authority",
);
assert(
  document.paths[itemPath].put["x-periapsis-authorization"]
    .conditionalPermissions?.response_projection ===
    "platform.identity_provider.read",
  "update must preflight live response-projection authority",
);

const createUnion =
  document.components.schemas.PlatformAuthProviderCreateRequest;
exact(
  createUnion.oneOf.map((arm) => arm.$ref),
  [
    "#/components/schemas/PlatformLDAPAuthProviderCreateRequest",
    "#/components/schemas/PlatformOIDCAuthProviderCreateRequest",
    "#/components/schemas/PlatformSAMLAuthProviderCreateRequest",
  ],
  "create union drifted",
);
exact(
  createUnion.discriminator.mapping,
  {
    ldap: "#/components/schemas/PlatformLDAPAuthProviderCreateRequest",
    oidc: "#/components/schemas/PlatformOIDCAuthProviderCreateRequest",
    saml: "#/components/schemas/PlatformSAMLAuthProviderCreateRequest",
  },
  "create discriminator drifted",
);

for (const name of [
  "PlatformLDAPAuthProviderCreateRequest",
  "PlatformOIDCAuthProviderCreateRequest",
  "PlatformSAMLAuthProviderCreateRequest",
  "PlatformAuthProviderUpdateRequest",
  "PlatformAuthProviderArchiveRequest",
  "PlatformOIDCClientSecretReplaceRequest",
  "PlatformSAMLMetadataURLReplaceRequest",
  "PlatformSAMLMetadataXMLReplaceRequest",
  "PlatformSAMLSPKeyReplaceRequest",
  "PlatformSAMLSPKeyClearRequest",
  "PlatformAuthProviderActivationRequest",
  "PlatformAuthProviderDeactivationRequest",
  "PlatformOIDCDirectLoginCommandRequest",
]) {
  assert(
    document.components.schemas[name].additionalProperties === false,
    `${name} must remain closed`,
  );
}

const samlMetadataRequest = schemas.PlatformSAMLMetadataReplaceRequest;
exact(
  samlMetadataRequest.oneOf?.map((arm) => arm.$ref),
  [
    "#/components/schemas/PlatformSAMLMetadataURLReplaceRequest",
    "#/components/schemas/PlatformSAMLMetadataXMLReplaceRequest",
  ],
  "SAML metadata source union drifted",
);
exact(
  samlMetadataRequest.discriminator,
  {
    propertyName: "source",
    mapping: {
      url: "#/components/schemas/PlatformSAMLMetadataURLReplaceRequest",
      xml: "#/components/schemas/PlatformSAMLMetadataXMLReplaceRequest",
    },
  },
  "SAML metadata source discriminator drifted",
);
for (const [name, materialField] of [
  ["PlatformSAMLMetadataURLReplaceRequest", "metadataUrl"],
  ["PlatformSAMLMetadataXMLReplaceRequest", "metadataXml"],
]) {
  const schema = schemas[name];
  exact(
    schema.required,
    ["source", "expectedVersion", materialField, "approveTrustReset"],
    `${name} required fields drifted`,
  );
  exact(
    Object.keys(schema.properties ?? {}),
    ["source", "expectedVersion", materialField, "approveTrustReset"],
    `${name} accepted fields drifted`,
  );
}
assert(
  schemas.PlatformSAMLMetadataXMLReplaceRequest.properties.metadataXml
    ?.writeOnly === true &&
    schemas.PlatformSAMLMetadataXMLReplaceRequest.properties.metadataXml
      ?.maxLength === 524288,
  "SAML XML metadata must remain write-only and bounded",
);
assert(
  schemas.PlatformSAMLMetadataURLReplaceRequest.properties.metadataUrl
    ?.pattern === "^https://[^\\s#]+$" &&
    schemas.PlatformSAMLMetadataURLReplaceRequest.properties.metadataUrl
      ?.maxLength === 4096,
  "SAML metadata URL must remain HTTPS-only and bounded",
);
const samlSPKeyRequest = schemas.PlatformSAMLSPKeyReplaceRequest;
exact(
  samlSPKeyRequest.required,
  ["expectedVersion", "privateKeyPkcs8", "certificates"],
  "SAML SP-key requirements drifted",
);
assert(
  samlSPKeyRequest.properties.privateKeyPkcs8?.writeOnly === true &&
    samlSPKeyRequest.properties.privateKeyPkcs8?.format === "byte" &&
    samlSPKeyRequest.properties.privateKeyPkcs8?.maxLength === 174744 &&
    typeof samlSPKeyRequest.properties.privateKeyPkcs8?.pattern === "string" &&
    samlSPKeyRequest.properties.certificates?.writeOnly === true &&
    samlSPKeyRequest.properties.certificates?.minItems === 1 &&
    samlSPKeyRequest.properties.certificates?.maxItems === 8 &&
    samlSPKeyRequest.properties.certificates?.items?.format === "byte" &&
    samlSPKeyRequest.properties.certificates?.items?.maxLength === 87384 &&
    samlSPKeyRequest.properties.certificates?.items?.pattern ===
      samlSPKeyRequest.properties.privateKeyPkcs8.pattern,
  "SAML SP-key material must remain write-only and byte-bounded",
);
for (const [path, method] of [
  [samlMetadataPath, "put"],
  [samlSPKeyPath, "put"],
  [samlSPKeyPath, "delete"],
]) {
  const operation = document.paths[path][method];
  const response = operation.responses["204"];
  assert(
    response.headers?.ETag?.$ref === "#/components/headers/StrongETag" &&
      response.headers?.["X-Periapsis-SAML-Material-Revision"]?.$ref ===
        "#/components/headers/PlatformSAMLMaterialRevision",
    `${operation.operationId} must return exact provider and material revisions`,
  );
}
assert(
  document.paths[samlMetadataPath].put.responses["409"]?.$ref ===
    "#/components/responses/NoStoreSAMLTrustApprovalRequired",
  "SAML metadata trust reset must expose its stable protected-approval conflict",
);
assert(
  document.components.responses.NoStoreSAMLTrustApprovalRequired?.content?.[
    "application/problem+json"
  ]?.schema?.$ref === "#/components/schemas/SAMLTrustApprovalRequiredProblem",
  "SAML trust-reset conflict must use its typed Problem Details schema",
);
const samlTrustApprovalProblem = schemas.SAMLTrustApprovalRequiredProblem;
assert(
  samlTrustApprovalProblem?.allOf?.[0]?.$ref ===
    "#/components/schemas/Problem" &&
    samlTrustApprovalProblem.allOf[1]?.properties?.status?.const === 409 &&
    samlTrustApprovalProblem.allOf[1]?.properties?.code?.const ===
      "saml_trust_approval_required",
  "SAML trust-reset Problem Details status or stable code drifted",
);

const directLoginCommand = schemas.PlatformOIDCDirectLoginCommandRequest;
exact(
  directLoginCommand.required,
  ["expectedVersion"],
  "direct-login command requirements drifted",
);
exact(
  Object.keys(directLoginCommand.properties ?? {}),
  ["expectedVersion"],
  "direct-login command must accept only expectedVersion",
);
assert(
  directLoginCommand.properties.expectedVersion?.minimum === 1 &&
    directLoginCommand.properties.expectedVersion?.maximum === 2147483646,
  "direct-login command version bounds drifted",
);

const samlCreate = schemas.PlatformSAMLAuthProviderCreateConfiguration;
assert(
  samlCreate && typeof samlCreate === "object",
  "SAML create configuration union is missing",
);
const persistentSamlReference =
  "#/components/schemas/PlatformSAMLPersistentNameIDAuthProviderCreateConfiguration";
const immutableSamlReference =
  "#/components/schemas/PlatformSAMLImmutableAttributeAuthProviderCreateConfiguration";
exact(
  samlCreate.oneOf?.map((arm) => arm.$ref),
  [persistentSamlReference, immutableSamlReference],
  "SAML create configuration union drifted",
);
exact(
  samlCreate.discriminator,
  {
    propertyName: "subjectSource",
    mapping: {
      persistent_nameid: persistentSamlReference,
      immutable_attribute: immutableSamlReference,
    },
  },
  "SAML create configuration discriminator drifted",
);
for (const [index, message] of [
  "persistent NameID SAML create branch",
  "immutable-attribute SAML create branch",
].entries()) {
  resolveSchemaReference(samlCreate.oneOf[index], message);
}

const samlCommonReference =
  "#/components/schemas/PlatformSAMLAuthProviderCreateConfigurationCommon";
const samlCommon = schemas.PlatformSAMLAuthProviderCreateConfigurationCommon;
assert(
  samlCommon?.type === "object" &&
    samlCommon.properties &&
    typeof samlCommon.properties === "object",
  "SAML create common configuration is malformed",
);
assert(
  samlCommon.properties.encryptionPolicy?.const === "disabled" &&
    samlCommon.properties.decryptionKeyVersions === undefined,
  "SAML create encryption must stay disabled while protected key staging remains a dedicated command",
);
assert(
  samlCommon.properties.subjectAttributeName === undefined &&
    samlCommon.properties.subjectAttributeNameFormat === undefined,
  "SAML create common configuration must not weaken subject-source discrimination",
);

const persistentSaml = resolveClosedSamlVariant(
  "PlatformSAMLPersistentNameIDAuthProviderCreateConfiguration",
  samlCommonReference,
);
exact(
  persistentSaml.required,
  ["subjectSource"],
  "persistent NameID SAML requirements drifted",
);
exact(
  Object.keys(persistentSaml.properties),
  ["subjectSource"],
  "persistent NameID SAML must prohibit subject attributes",
);
assert(
  persistentSaml.properties.subjectSource?.const === "persistent_nameid",
  "persistent NameID SAML discriminator value drifted",
);

const immutableSaml = resolveClosedSamlVariant(
  "PlatformSAMLImmutableAttributeAuthProviderCreateConfiguration",
  samlCommonReference,
);
exact(
  immutableSaml.required,
  ["subjectSource", "subjectAttributeName", "subjectAttributeNameFormat"],
  "immutable-attribute SAML requirements drifted",
);

const samlProjectionCommon =
  schemas.PlatformSAMLAuthProviderConfigurationCommon;
assert(
  samlProjectionCommon?.type === "object" &&
    samlProjectionCommon.properties &&
    typeof samlProjectionCommon.properties === "object",
  "SAML safe projection common configuration is malformed",
);
exact(
  Object.keys(samlProjectionCommon.properties ?? {}),
  [
    "expectedEntityId",
    "spEntityId",
    "acsUrl",
    "spKeyRevision",
    "spKeyPresent",
    "metadataRevision",
    "redirectSignatureAlgorithm",
    "signaturePolicy",
    "encryptionPolicy",
    "requestedAuthnContexts",
    "clockSkewNanoseconds",
    "maxAuthenticationAgeNanoseconds",
  ],
  "SAML safe projection exposed raw metadata, certificate, or key material",
);
const samlProjection = schemas.PlatformSAMLAuthProviderConfiguration;
const persistentSamlProjectionReference =
  "#/components/schemas/PlatformSAMLPersistentNameIDAuthProviderConfiguration";
const immutableSamlProjectionReference =
  "#/components/schemas/PlatformSAMLImmutableAttributeAuthProviderConfiguration";
exact(
  samlProjection.oneOf?.map((arm) => arm.$ref),
  [persistentSamlProjectionReference, immutableSamlProjectionReference],
  "SAML safe projection union drifted",
);
const persistentSamlProjection = resolveClosedSamlVariant(
  "PlatformSAMLPersistentNameIDAuthProviderConfiguration",
  "#/components/schemas/PlatformSAMLAuthProviderConfigurationCommon",
);
const immutableSamlProjection = resolveClosedSamlVariant(
  "PlatformSAMLImmutableAttributeAuthProviderConfiguration",
  "#/components/schemas/PlatformSAMLAuthProviderConfigurationCommon",
);
exact(
  Object.keys(persistentSamlProjection.properties),
  ["subjectSource"],
  "persistent NameID SAML safe projection exposed extra material",
);
exact(
  Object.keys(immutableSamlProjection.properties),
  ["subjectSource", "subjectAttributeName", "subjectAttributeNameFormat"],
  "immutable-attribute SAML safe projection exposed extra material",
);
exact(
  Object.keys(immutableSaml.properties),
  ["subjectSource", "subjectAttributeName", "subjectAttributeNameFormat"],
  "immutable-attribute SAML fields drifted",
);
assert(
  immutableSaml.properties.subjectSource?.const === "immutable_attribute" &&
    immutableSaml.properties.subjectAttributeName?.type === "string" &&
    immutableSaml.properties.subjectAttributeNameFormat?.format === "uri",
  "immutable-attribute SAML subject contract drifted",
);

const oidcCreate = schemas.PlatformOIDCAuthProviderCreateConfiguration;
const oidcProjection = schemas.PlatformOIDCAuthProviderConfiguration;
for (const [name, schema] of [
  ["OIDC create", oidcCreate],
  ["OIDC projection", oidcProjection],
]) {
  assert(schema && typeof schema === "object", `${name} schema is missing`);
  assert(
    schema.properties.issuer?.maxLength === 2048 &&
      schema.properties.issuer?.["x-periapsis-max-utf8-bytes"] === 2048,
    `${name} issuer must remain bounded to exactly 2048 UTF-8 bytes`,
  );
  for (const field of [
    "redirectUri",
    "tenantRedirectUri",
    "postLogoutRedirectUri",
  ]) {
    assert(
      schema.properties[field]?.maxLength === 4096 &&
        schema.properties[field]?.["x-periapsis-max-utf8-bytes"] === 4096,
      `${name} ${field} must remain bounded to exactly 4096 UTF-8 bytes`,
    );
  }
}
exact(
  [
    oidcCreate.properties.redirectUri["x-periapsis-derived-path"],
    oidcCreate.properties.tenantRedirectUri["x-periapsis-derived-path"],
    oidcCreate.properties.postLogoutRedirectUri["x-periapsis-derived-path"],
    samlCommon.properties.spEntityId["x-periapsis-derived-path"],
    samlCommon.properties.acsUrl["x-periapsis-derived-path"],
  ],
  [
    "/api/v1/auth/platform/oidc/callback",
    "/api/v1/auth/federated/oidc/callback",
    "/signed-out",
    "/api/v1/auth/platform/saml/{providerKey}/metadata",
    "/api/v1/auth/platform/saml/acs",
  ],
  "deployment-owned federation endpoint paths drifted",
);

for (const name of [
  "PlatformAuthProviderSummary",
  "PlatformOIDCAuthProvider",
  "PlatformSAMLAuthProvider",
  "PlatformOIDCAuthProviderConfiguration",
  "PlatformSAMLAuthProviderConfiguration",
]) {
  const properties = Object.keys(
    document.components.schemas[name].properties ?? {},
  );
  for (const forbidden of [
    "clientSecret",
    "ciphertext",
    "nonce",
    "privateKey",
    "assertion",
    "accessToken",
    "refreshToken",
  ]) {
    assert(
      !properties.includes(forbidden),
      `${name} exposes forbidden material ${forbidden}`,
    );
  }
}

for (const name of [
  "PlatformAuthProviderSummary",
  "PlatformOIDCAuthProvider",
  "PlatformSAMLAuthProvider",
]) {
  assert(
    document.components.schemas[name].required.includes(
      "platformLoginActivationAvailable",
    ),
    `${name} must require direct-login activation availability`,
  );
}

assert(
  document.components.schemas.PlatformOIDCAuthProvider.properties.enabled
    .type === "boolean" &&
    document.components.schemas.PlatformOIDCAuthProvider.properties
      .activationAvailable.type === "boolean" &&
    document.components.schemas.PlatformOIDCAuthProvider.properties
      .platformLoginEnabled.type === "boolean" &&
    document.components.schemas.PlatformOIDCAuthProvider.properties
      .platformLoginEnabled.const === undefined &&
    document.components.schemas.PlatformOIDCAuthProvider.properties
      .platformLoginActivationAvailable.type === "boolean" &&
    document.components.schemas.PlatformOIDCAuthProvider.properties
      .platformLoginActivationAvailable.const === undefined &&
    document.components.schemas.PlatformAuthProviderSummary.properties
      .platformLoginEnabled.type === "boolean" &&
    document.components.schemas.PlatformAuthProviderSummary.properties
      .platformLoginEnabled.const === undefined &&
    document.components.schemas.PlatformAuthProviderSummary.properties
      .platformLoginActivationAvailable.type === "boolean" &&
    document.components.schemas.PlatformAuthProviderSummary.properties
      .platformLoginActivationAvailable.const === undefined &&
    document.components.schemas.PlatformSAMLAuthProvider.properties.enabled
      .type === "boolean" &&
    document.components.schemas.PlatformSAMLAuthProvider.properties
      .platformLoginEnabled.type === "boolean" &&
    document.components.schemas.PlatformSAMLAuthProvider.properties
      .platformLoginActivationAvailable.type === "boolean" &&
    document.components.schemas.PlatformSAMLAuthProvider.properties
      .activationAvailable.type === "boolean" &&
    document.components.schemas.PlatformSAMLAuthProvider.properties
      .secretPresent.type === "boolean" &&
    document.components.schemas.PlatformSAMLAuthProvider.properties
      .platformLoginEnabled.const === undefined &&
    document.components.schemas.PlatformSAMLAuthProvider.properties
      .platformLoginActivationAvailable.const === undefined &&
    document.components.schemas.PlatformSAMLAuthProvider.properties
      .activationAvailable.const === undefined &&
    JSON.stringify(
      document.components.schemas.PlatformOIDCAuthProvider.properties
        .accountMode.enum,
    ) === JSON.stringify(["disabled", "existing_identity", "create"]) &&
    JSON.stringify(
      document.components.schemas.PlatformSAMLAuthProvider.properties
        .accountMode.enum,
    ) === JSON.stringify(["disabled", "existing_identity", "create"]),
  "OIDC and SAML tenant execution and direct login must remain independent real projections",
);

assert(
  /immutable/i.test(
    document.components.schemas.PlatformSAMLAuthProviderCreateRequest.properties
      .key.description,
  ) &&
    document.components.schemas.PlatformSAMLAuthProvider.properties.key[
      "x-periapsis-immutable"
    ] === true &&
    /immutable/i.test(
      document.components.schemas.PlatformSAMLAuthProvider.properties.key
        .description,
    ),
  "SAML provider key must remain an immutable public locator across write and read contracts",
);

const permissions = document.components.schemas.PlatformPermission.enum;
for (const permission of [
  "platform.identity_provider.read",
  "platform.identity_provider.manage",
  "platform.identity_provider.test",
  "platform.identity_binding.read",
  "platform.identity_binding.manage",
  "platform.identity_policy.read",
  "platform.identity_policy.manage",
  "platform.identity_account.read",
  "platform.identity_account.manage",
]) {
  assert(
    permissions.includes(permission),
    `missing platform permission ${permission}`,
  );
}
