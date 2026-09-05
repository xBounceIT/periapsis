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
  throw new Error(`Federated-auth contract invariant failed: ${message}`);
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
const operation = (path, method, operationId) => {
  const value = document.paths?.[path]?.[method];
  assert(
    value?.operationId === operationId,
    `${method.toUpperCase()} ${path} is missing`,
  );
  exact(
    value.security,
    [],
    `${operationId} must reject ambient generated auth`,
  );
  exact(
    Object.keys(value.responses ?? {}).toSorted(),
    ["303", "401", "503"],
    `${operationId} response vocabulary drifted`,
  );
  for (const status of ["303", "401", "503"]) {
    const response = value.responses[status];
    assert(response !== undefined, `${operationId} lacks ${status}`);
  }
  return value;
};

const oidcStartPath =
  "/api/v1/auth/federated/oidc/{tenantSlug}/{loginKey}/start";
const samlStartPath =
  "/api/v1/auth/federated/saml/{tenantSlug}/{loginKey}/start";
const oidcCallbackPath = "/api/v1/auth/federated/oidc/callback";
const samlACSPath = "/api/v1/auth/federated/saml/acs";
const platformOIDCStartPath = "/api/v1/auth/platform/oidc/{providerKey}/start";
const platformOIDCCallbackPath = "/api/v1/auth/platform/oidc/callback";
const platformSAMLStartPath = "/api/v1/auth/platform/saml/{providerKey}/start";
const platformSAMLACSPath = "/api/v1/auth/platform/saml/acs";
const platformSAMLMetadataPath =
  "/api/v1/auth/platform/saml/{providerKey}/metadata";
const ldapLoginPath = "/api/v1/auth/ldap/{tenantSlug}/{loginKey}";
const logoutPath = "/api/v1/auth/session";
const logoutContinuationPath =
  "/api/v1/auth/logout/continuations/{continuationId}";

const logout = document.paths?.[logoutPath]?.delete;
const logoutContinuation = document.paths?.[logoutContinuationPath]?.get;
assert(logout?.operationId === "logoutCurrentSession", "logout is missing");
exact(
  Object.keys(logout.responses ?? {}).toSorted(),
  ["200", "204", "400", "401", "403", "503"],
  "logout response vocabulary drifted",
);
exact(
  logout.security,
  [{ sessionCookie: [], csrfToken: [] }],
  "logout must bind the session and CSRF proofs",
);
assert(
  logout["x-periapsis-authorization"]?.liveUserRequired === false &&
    logout["x-periapsis-authorization"]?.liveTenantRequired === false &&
    logout["x-periapsis-authorization"]?.liveMembershipRequired === false &&
    logout["x-periapsis-authorization"]?.liveProviderRequired === false,
  "logout must survive live identity and provider invalidation",
);
assert(
  logout.responses["200"].content?.["application/json"]?.schema?.$ref ===
    "#/components/schemas/LogoutResult" &&
    logout.responses["200"].headers?.["Cache-Control"]?.$ref ===
      "#/components/headers/NoStore" &&
    logout.responses["200"].headers?.["Referrer-Policy"]?.$ref ===
      "#/components/headers/NoReferrer" &&
    logout.responses["200"].headers?.["Set-Cookie"]?.$ref ===
      "#/components/headers/SessionAndLogoutContinuationCookies" &&
    logout.responses["204"].headers?.["Set-Cookie"]?.$ref ===
      "#/components/headers/ClearedSessionCookie",
  "logout must expose only the opaque continuation after local revocation",
);

assert(
  logoutContinuation?.operationId === "continueLogout",
  "logout continuation is missing",
);
exact(
  logoutContinuation.security,
  [{ logoutContinuationCookie: [] }],
  "logout continuation must declare only its path-scoped proof cookie",
);
exact(
  Object.keys(logoutContinuation.responses ?? {}),
  ["303"],
  "logout continuation must remain non-oracular",
);
assert(
  logoutContinuation["x-periapsis-generated-auth"] === "browser-cookie",
  "logout continuation must suppress generated access to its HttpOnly proof",
);
const logoutContinuationParameter =
  document.components.parameters.LogoutContinuationId;
assert(
  logoutContinuationParameter?.schema?.type === "string" &&
    logoutContinuationParameter.schema.format === undefined &&
    logoutContinuationParameter.schema.minLength === 36 &&
    logoutContinuationParameter.schema.maxLength === 36 &&
    logoutContinuationParameter.schema.pattern ===
      "^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}(?![\\s\\S])",
  "logout locator must stay a canonical UUIDv7 string so malformed paths reach the uniform 303 handler",
);
const logoutRedirect = logoutContinuation.responses["303"];
assert(
  logoutRedirect.headers?.["Cache-Control"]?.$ref ===
    "#/components/headers/NoStore" &&
    logoutRedirect.headers?.["Referrer-Policy"]?.$ref ===
      "#/components/headers/NoReferrer" &&
    logoutRedirect.headers?.Location?.$ref ===
      "#/components/headers/LogoutContinuationRedirect" &&
    logoutRedirect.headers?.["Set-Cookie"]?.$ref ===
      "#/components/headers/ClearedLogoutContinuationCookie" &&
    document.components.headers.ClearedLogoutContinuationCookie.required ===
      true &&
    logoutRedirect.content === undefined,
  "logout continuation must be a bodyless no-store no-referrer 303",
);
const logoutResult = document.components.schemas.LogoutResult;
exact(
  logoutResult.required,
  ["continuationUrl"],
  "logout result required fields drifted",
);
assert(
  logoutResult.additionalProperties === false &&
    logoutResult.properties.continuationUrl.minLength === 70 &&
    logoutResult.properties.continuationUrl.maxLength === 70 &&
    logoutResult.properties.continuationUrl.pattern ===
      "^/api/v1/auth/logout/continuations/[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}(?![\\s\\S])" &&
    document.components.securitySchemes.logoutContinuationCookie.name ===
      "__Secure-periapsis_logout_continuation",
  "logout result or proof-cookie boundary drifted",
);
const generatedLogoutContinuationStart = sdk.indexOf(
  "export const continueLogout =",
);
const generatedLogoutContinuationEnd = sdk.indexOf(
  "\n});",
  generatedLogoutContinuationStart,
);
assert(
  generatedLogoutContinuationStart >= 0 &&
    generatedLogoutContinuationEnd > generatedLogoutContinuationStart &&
    !sdk
      .slice(generatedLogoutContinuationStart, generatedLogoutContinuationEnd)
      .includes("security:"),
  "generated logout continuation must not expose its HttpOnly proof as an SDK argument",
);

const tenantOIDCCreateConfiguration =
  document.components.schemas.TenantFederationOIDCCreateConfiguration;
const tenantSAMLCreateConfiguration =
  document.components.schemas.TenantFederationSAMLCreateConfiguration;
const tenantSAMLMetadataURLReplaceRequest =
  document.components.schemas.TenantSAMLMetadataURLReplaceRequest;
const platformOIDCCreateConfiguration =
  document.components.schemas.PlatformOIDCAuthProviderCreateConfiguration;
const platformOIDCConfiguration =
  document.components.schemas.PlatformOIDCAuthProviderConfiguration;

const hasRefreshScopeCoupling = (schema) => {
  const relation = schema.allOf?.find(
    (candidate) => candidate.if?.properties?.allowRefreshToken?.const === true,
  );
  return (
    relation?.then?.properties?.extraScopes?.contains?.const ===
      "offline_access" &&
    relation.then.properties.extraScopes.minContains === 1 &&
    relation.then.properties.extraScopes.maxContains === 1 &&
    relation?.else?.properties?.extraScopes?.not?.contains?.const ===
      "offline_access"
  );
};

assert(
  document.components.schemas.TenantFederationBinding.properties.version
    ?.$ref === "#/components/schemas/ResourceVersion",
  "tenant federation binding CAS version must remain int32-bounded",
);
for (const schemaName of [
  "TenantFederationOIDCMappingPolicy",
  "TenantFederationSAMLMappingPolicy",
  "TenantFederationOIDCAssurancePolicy",
  "TenantFederationSAMLAssurancePolicy",
]) {
  assert(
    document.components.schemas[schemaName].properties.providerVersion?.$ref ===
      "#/components/schemas/ResourceVersion",
    `${schemaName} provider CAS version must remain int32-bounded`,
  );
}

assert(
  tenantOIDCCreateConfiguration.properties.postLogoutRedirectUri?.[
    "x-periapsis-derived-path"
  ] === "/signed-out" &&
    tenantOIDCCreateConfiguration.properties.postLogoutRedirectUri?.pattern ===
      "^https://[^\\s?#]+$" &&
    /PublicOrigin plus `\/signed-out`/.test(
      tenantOIDCCreateConfiguration.properties.postLogoutRedirectUri
        ?.description ?? "",
    ),
  "tenant OIDC post-logout redirect must remain deployment-derived",
);
assert(
  tenantSAMLMetadataURLReplaceRequest.properties.metadataUrl?.pattern ===
    "^https://[^\\s?#]+$" &&
    tenantSAMLMetadataURLReplaceRequest.properties.metadataUrl?.[
      "x-periapsis-max-utf8-bytes"
    ] === 4096,
  "tenant SAML metadata URL must reject query and fragment input",
);
assert(
  tenantSAMLCreateConfiguration.properties.expectedEntityId?.[
    "x-periapsis-max-utf8-bytes"
  ] === 2048 &&
    tenantSAMLCreateConfiguration.properties.requestedAuthnContexts?.items?.[
      "x-periapsis-max-utf8-bytes"
    ] === 2048 &&
    tenantSAMLCreateConfiguration.properties.subjectAttributeName?.[
      "x-periapsis-max-utf8-bytes"
    ] === 512 &&
    tenantSAMLCreateConfiguration.properties.subjectAttributeNameFormat?.[
      "x-periapsis-max-utf8-bytes"
    ] === 512,
  "tenant SAML text limits must declare the exact runtime UTF-8 byte bounds",
);
for (const [name, schema] of [
  ["tenant", tenantOIDCCreateConfiguration],
  ["platform create", platformOIDCCreateConfiguration],
  ["platform projection", platformOIDCConfiguration],
]) {
  assert(
    schema.properties.extraScopes.maxItems === 31 &&
      hasRefreshScopeCoupling(schema) &&
      schema.properties.clientId["x-periapsis-max-utf8-bytes"] === 512 &&
      schema.properties.clientId.pattern.includes("\\u00A0") &&
      schema.properties.clientId.pattern.includes("\\u2000"),
    `${name} OIDC configuration lost its refresh-scope or Unicode client-id boundary`,
  );
}

assert(
  /at least one UserInfo extraction rule/.test(
    tenantOIDCCreateConfiguration.properties.useUserInfo.description ?? "",
  ) &&
    /canonical HTTPS UserInfo endpoint/.test(
      document.components.schemas.TenantOIDCTrustDocumentsRefreshRequest
        .description ?? "",
    ),
  "tenant OIDC UserInfo mapping and discovery coupling drifted",
);
assert(
  document.components.schemas.TenantFederationOIDCMappingPolicyReplaceRequest[
    "x-periapsis-userinfo-coupling"
  ] ===
    "provider.configuration.useUserInfo == exists(oidcClaimRules[source == userinfo])" &&
    document.components.schemas.TenantFederationOIDCMappingPolicy[
      "x-periapsis-userinfo-coupling"
    ] === undefined,
  "OIDC mapping replacement must enforce UserInfo coupling while staged readback remains repairable",
);

const platformSAMLCreate =
  document.components.schemas.PlatformSAMLAuthProviderCreateConfigurationCommon;
const platformSAMLProjection =
  document.components.schemas.PlatformSAMLAuthProviderConfigurationCommon;
assert(
  tenantSAMLCreateConfiguration[
    "x-periapsis-distinct-from-derived-sp-entity-id"
  ] === "expectedEntityId" &&
    /must differ/.test(
      tenantSAMLCreateConfiguration.properties.expectedEntityId.description ??
        "",
    ) &&
    JSON.stringify(platformSAMLCreate["x-periapsis-distinct-fields"]) ===
      JSON.stringify(["expectedEntityId", "spEntityId"]) &&
    JSON.stringify(platformSAMLProjection["x-periapsis-distinct-fields"]) ===
      JSON.stringify(["expectedEntityId", "spEntityId"]),
  "tenant or platform SAML IdP and SP entity IDs must remain distinct",
);
assert(
  /Direct-platform login activation remains unavailable/.test(
    platformOIDCCreateConfiguration.properties.useUserInfo.description ?? "",
  ) &&
    /Direct-platform login activation is unavailable/.test(
      platformOIDCConfiguration.properties.useUserInfo.description ?? "",
    ),
  "platform UserInfo must remain incompatible with direct-platform activation",
);

const oidcClaimRule = document.components.schemas.TenantFederationOIDCClaimRule;
exact(
  oidcClaimRule["x-periapsis-reserved-security-claims"],
  [
    "iss",
    "sub",
    "aud",
    "azp",
    "exp",
    "iat",
    "nbf",
    "auth_time",
    "nonce",
    "at_hash",
    "acr",
    "amr",
  ],
  "OIDC extraction reserved security claims drifted",
);
for (const schemaName of [
  "TenantFederationOIDCMappingPolicyReplaceRequest",
  "TenantFederationOIDCMappingPolicy",
]) {
  const rules =
    document.components.schemas[schemaName].properties.oidcClaimRules;
  exact(
    rules["x-periapsis-max-items-by-kind-and-source"],
    { scalar: 16, profile: 8, groups: 1, acr: 1, amr: 1 },
    `${schemaName} extraction cardinality drifted`,
  );
  assert(
    rules["x-periapsis-unique-profile-field-per-source"] === true,
    `${schemaName} profile-field uniqueness drifted`,
  );
}
for (const schemaName of [
  "TenantFederationSAMLMappingPolicyReplaceRequest",
  "TenantFederationSAMLMappingPolicy",
]) {
  const rules =
    document.components.schemas[schemaName].properties.samlAttributeRules;
  exact(
    rules["x-periapsis-max-items-by-kind"],
    { scalar: 32, profile: 16, groups: 1 },
    `${schemaName} extraction cardinality drifted`,
  );
  assert(
    rules["x-periapsis-unique-profile-field"] === true,
    `${schemaName} profile-field uniqueness drifted`,
  );
}

const mappingEvidence =
  document.components.schemas.TenantFederationMappingRule.properties
    .matcherValue;
const oidcAssurance =
  document.components.schemas.TenantFederationOIDCAssuranceRule.properties;
const samlAssurance =
  document.components.schemas.TenantFederationSAMLAssuranceRule.properties;
assert(
  mappingEvidence["x-periapsis-max-utf8-bytes"] === 4096 &&
    mappingEvidence.pattern.includes("\\u202A") &&
    oidcAssurance.exactValue["x-periapsis-max-utf8-bytes"] === 4096 &&
    oidcAssurance.requiredValues.items["x-periapsis-max-utf8-bytes"] === 4096 &&
    samlAssurance.exactValue["x-periapsis-max-utf8-bytes"] === 4096 &&
    samlAssurance.exactValue["x-periapsis-xml-1-0-text"] === true,
  "mapping or assurance evidence lost its byte, directional-control, or XML boundary",
);
for (const schemaName of [
  "TenantFederationSAMLAssurancePolicyReplaceRequest",
  "TenantFederationSAMLAssurancePolicy",
]) {
  const rules = document.components.schemas[schemaName].properties.rules;
  assert(
    rules.maxItems === 64 && rules["x-periapsis-unique-exact-value"] === true,
    `${schemaName} cardinality or exact-value uniqueness drifted`,
  );
}
for (const schema of [
  tenantSAMLCreateConfiguration,
  document.components.schemas.PlatformSAMLAuthProviderCreateConfigurationCommon,
  document.components.schemas.PlatformSAMLAuthProviderConfigurationCommon,
]) {
  assert(
    schema.properties.expectedEntityId["x-periapsis-xml-1-0-text"] === true &&
      schema.properties.requestedAuthnContexts.items[
        "x-periapsis-xml-1-0-text"
      ] === true,
    "SAML provider text lost its XML 1.0 boundary",
  );
}

const ldapLogin = document.paths?.[ldapLoginPath]?.post;
assert(ldapLogin?.operationId === "loginTenantLDAP", "LDAP login is missing");
exact(ldapLogin.security, [], "LDAP login must reject ambient generated auth");
exact(
  document.paths[ldapLoginPath].parameters.map((parameter) => parameter.$ref),
  [
    "#/components/parameters/FederatedTenantSlug",
    "#/components/parameters/FederatedLoginKey",
  ],
  "LDAP login must use only canonical public locators",
);
exact(
  Object.keys(ldapLogin.responses ?? {}).toSorted(),
  ["303", "401", "429", "503"],
  "LDAP login response vocabulary drifted",
);
assert(
  ldapLogin.requestBody?.required === true &&
    Object.keys(ldapLogin.requestBody.content ?? {}).length === 1 &&
    ldapLogin.requestBody.content?.["application/x-www-form-urlencoded"]?.schema
      ?.$ref === "#/components/schemas/LDAPLoginRequest" &&
    /pre-existing bearer/.test(ldapLogin.description) &&
    /session, MFA, federation-transaction, and continuation authority/.test(
      ldapLogin.description,
    ) &&
    /never logged or persisted/.test(ldapLogin.description) &&
    /non-enumerating response/.test(ldapLogin.description),
  "LDAP login lost its form-only, authority-free, redacted, or enumeration boundary",
);
const ldapPassword =
  document.components.schemas.LDAPLoginRequest.properties.password;
assert(
  document.components.schemas.LDAPLoginRequest.additionalProperties === false &&
    ldapPassword.writeOnly === true &&
    ldapPassword.format === "password" &&
    ldapPassword.minLength === 1 &&
    ldapPassword.maxLength === 1024 &&
    ldapLogin.responses["303"].headers?.["Set-Cookie"]?.$ref ===
      "#/components/headers/LDAPCompletionCookies" &&
    document.components.schemas.SessionAuthenticationMethod.enum.includes(
      "ldap",
    ) &&
    sdk.includes("export const loginTenantLdap"),
  "LDAP password, completion cookie, session method, or generated SDK contract drifted",
);

const oidcStart = operation(
  oidcStartPath,
  "post",
  "startTenantOIDCFederatedLogin",
);
const samlStart = operation(
  samlStartPath,
  "post",
  "startTenantSAMLFederatedLogin",
);
const oidcCallback = operation(
  oidcCallbackPath,
  "get",
  "completeOIDCFederatedCallback",
);
const samlACS = operation(samlACSPath, "post", "completeSAMLFederatedACS");
const platformOIDCStart = operation(
  platformOIDCStartPath,
  "post",
  "startPlatformOIDCLogin",
);
const platformOIDCCallback = operation(
  platformOIDCCallbackPath,
  "get",
  "completePlatformOIDCCallback",
);
const platformSAMLStart = operation(
  platformSAMLStartPath,
  "post",
  "startPlatformSAMLLogin",
);
const platformSAMLACS = operation(
  platformSAMLACSPath,
  "post",
  "completePlatformSAMLACS",
);

for (const value of [
  oidcStart,
  samlStart,
  oidcCallback,
  samlACS,
  platformOIDCStart,
  platformOIDCCallback,
  platformSAMLStart,
  platformSAMLACS,
]) {
  assert(
    /Authorization(?:\s+and\s+bearer)?\s+headers/.test(value.description) &&
      /existing\s+session\s+authority/.test(value.description) &&
      /existing\s+(?:federated\s+)?MFA-continuation\s+authority/.test(
        value.description,
      ),
    `${value.operationId} must document rejection of prior MFA authority`,
  );
}

exact(
  document.paths[platformSAMLStartPath].parameters.map(
    (parameter) => parameter.$ref,
  ),
  ["#/components/parameters/PlatformSAMLProviderKey"],
  "platform SAML start must use only the canonical public provider locator",
);
assert(
  platformSAMLStart.requestBody?.required === true &&
    platformSAMLStart.requestBody?.content?.["application/json"]?.schema
      ?.$ref === "#/components/schemas/FederatedLoginStartRequest" &&
    platformSAMLStart.requestBody?.content?.[
      "application/x-www-form-urlencoded"
    ]?.schema?.$ref === "#/components/schemas/FederatedLoginStartRequest" &&
    /exact same-origin Origin or Referer/.test(platformSAMLStart.description) &&
    /IdP-initiated login is unsupported/.test(platformSAMLStart.description) &&
    /exact\s+live\s+pre-linked\s+provider\s+account/.test(
      platformSAMLStart.description,
    ),
  "platform SAML start lost its closed body, same-origin, SP-initiated, or pre-linked-only boundary",
);
assert(
  platformSAMLStart.responses["303"].headers?.Location?.$ref ===
    "#/components/headers/FederatedIdPRedirect" &&
    platformSAMLStart.responses["303"].headers?.["Set-Cookie"]?.$ref ===
      "#/components/headers/PlatformSAMLTransactionCookie" &&
    platformSAMLStart.responses["303"].headers?.["Cache-Control"]?.$ref ===
      "#/components/headers/NoStore" &&
    platformSAMLStart.responses["303"].headers?.["Referrer-Policy"]?.$ref ===
      "#/components/headers/NoReferrer",
  "platform SAML start lost pinned redirect, distinct cookie, no-store, or no-referrer semantics",
);

for (const [name, value, path] of [
  ["OIDC", oidcStart, oidcStartPath],
  ["SAML", samlStart, samlStartPath],
]) {
  exact(
    document.paths[path].parameters.map((parameter) => parameter.$ref),
    [
      "#/components/parameters/FederatedTenantSlug",
      "#/components/parameters/FederatedLoginKey",
    ],
    `${name} start must use only canonical public locators`,
  );
  assert(
    value.requestBody?.required === true &&
      value.requestBody?.content?.["application/json"]?.schema?.$ref ===
        "#/components/schemas/FederatedLoginStartRequest",
    `${name} start must use the bounded local return-path command`,
  );
  assert(
    value.responses["303"].headers?.Location?.$ref ===
      "#/components/headers/FederatedIdPRedirect" &&
      value.responses["303"].headers?.["Set-Cookie"]?.$ref ===
        "#/components/headers/FederatedTransactionCookie" &&
      value.responses["303"].headers?.["Cache-Control"]?.$ref ===
        "#/components/headers/NoStore",
    `${name} start lost pinned redirect or one-use cookie semantics`,
  );
}

exact(
  document.paths[platformOIDCStartPath].parameters.map(
    (parameter) => parameter.$ref,
  ),
  ["#/components/parameters/PlatformOIDCProviderKey"],
  "platform OIDC start must use only the canonical public provider locator",
);
assert(
  platformOIDCStart.requestBody?.required === true &&
    platformOIDCStart.requestBody?.content?.["application/json"]?.schema
      ?.$ref === "#/components/schemas/FederatedLoginStartRequest" &&
    platformOIDCStart.requestBody?.content?.[
      "application/x-www-form-urlencoded"
    ]?.schema?.$ref === "#/components/schemas/FederatedLoginStartRequest",
  "platform OIDC start must reuse the closed bounded return-path command",
);
assert(
  /exact same-origin Origin or Referer/.test(platformOIDCStart.description) &&
    /not a CORS surface/.test(platformOIDCStart.description) &&
    /exact live pre-linked provider account/.test(
      platformOIDCStart.description,
    ),
  "platform OIDC start lost its same-origin or pre-linked-only boundary",
);
assert(
  platformOIDCStart.responses["303"].headers?.Location?.$ref ===
    "#/components/headers/FederatedIdPRedirect" &&
    platformOIDCStart.responses["303"].headers?.["Set-Cookie"]?.$ref ===
      "#/components/headers/PlatformOIDCTransactionCookie" &&
    platformOIDCStart.responses["303"].headers?.["Cache-Control"]?.$ref ===
      "#/components/headers/NoStore",
  "platform OIDC start lost pinned redirect, distinct cookie, or no-store semantics",
);

const platformProviderKey =
  document.components.parameters.PlatformOIDCProviderKey;
assert(
  platformProviderKey.name === "providerKey" &&
    platformProviderKey.in === "path" &&
    platformProviderKey.required === true &&
    platformProviderKey.schema?.minLength === 3 &&
    platformProviderKey.schema?.maxLength === 64 &&
    platformProviderKey.schema?.pattern === "^[a-z][a-z0-9_-]{2,63}$",
  "platform OIDC provider locator lost its canonical closed bounds",
);

const platformSAMLProviderKey =
  document.components.parameters.PlatformSAMLProviderKey;
assert(
  platformSAMLProviderKey.name === "providerKey" &&
    platformSAMLProviderKey.in === "path" &&
    platformSAMLProviderKey.required === true &&
    platformSAMLProviderKey.schema?.minLength === 3 &&
    platformSAMLProviderKey.schema?.maxLength === 64 &&
    platformSAMLProviderKey.schema?.pattern === "^[a-z][a-z0-9_-]{2,63}$" &&
    /immutable/.test(platformSAMLProviderKey.description),
  "platform SAML provider locator lost its canonical immutable closed bounds",
);

const directPlatformDescriptions = `${platformOIDCStart.summary}\n${platformOIDCStart.description}\n${platformOIDCCallback.summary}\n${platformOIDCCallback.description}`;
for (const unsupportedAdvertisement of [
  "jit",
  "create",
  "recovery",
  "webauthn",
  "passkey",
]) {
  assert(
    !directPlatformDescriptions
      .toLowerCase()
      .includes(unsupportedAdvertisement),
    `direct-platform OIDC must not advertise ${unsupportedAdvertisement}`,
  );
}

assert(
  (oidcCallback.parameters ?? []).length === 0 &&
    oidcCallback.requestBody === undefined,
  "OIDC callback query must remain opaque to generated parameter binding",
);
assert(
  (platformOIDCCallback.parameters ?? []).length === 0 &&
    platformOIDCCallback.requestBody === undefined &&
    platformOIDCCallback["x-periapsis-maximum-raw-query-bytes"] === 65536 &&
    /exact raw query string is delivered unchanged/.test(
      platformOIDCCallback.description,
    ) &&
    /oversized artifacts fail closed/.test(platformOIDCCallback.description),
  "platform OIDC callback must preserve the exact bounded raw-query boundary",
);
assert(
  samlACS.requestBody?.required === true &&
    samlACS.requestBody?.content?.["application/x-www-form-urlencoded"] !==
      undefined &&
    samlACS.parameters === undefined,
  "SAML ACS must preserve the raw bounded form boundary",
);
assert(
  platformSAMLACS.requestBody?.required === true &&
    platformSAMLACS.requestBody?.content?.[
      "application/x-www-form-urlencoded"
    ] !== undefined &&
    platformSAMLACS.parameters === undefined &&
    platformSAMLACS["x-periapsis-maximum-raw-body-bytes"] === 3145882 &&
    /byte-for-byte/.test(platformSAMLACS.description) &&
    /worst-case three-byte percent encoding/.test(
      platformSAMLACS.description,
    ) &&
    /cleared on every attempt/.test(platformSAMLACS.description) &&
    /compensation/.test(platformSAMLACS.description),
  "platform SAML ACS must preserve exact raw bytes, the kernel cap, unconditional clearing, and delivery compensation",
);
const platformSAMLForm =
  platformSAMLACS.requestBody.content["application/x-www-form-urlencoded"]
    .schema;
exact(
  platformSAMLForm.required,
  ["SAMLResponse", "RelayState"],
  "platform SAML ACS required artifacts drifted",
);
assert(
  platformSAMLForm.additionalProperties === false &&
    platformSAMLForm.properties.SAMLResponse.maxLength === 1048576 &&
    platformSAMLForm.properties.RelayState.minLength === 43 &&
    platformSAMLForm.properties.RelayState.maxLength === 43 &&
    platformSAMLForm.properties.RelayState.pattern ===
      "^(?!A{43}$)[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$",
  "platform SAML ACS exact raw artifact bounds drifted",
);
const samlForm =
  samlACS.requestBody.content["application/x-www-form-urlencoded"].schema;
exact(
  samlForm.required,
  ["SAMLResponse", "RelayState"],
  "SAML ACS required artifacts drifted",
);
assert(
  samlForm.additionalProperties === false &&
    samlForm.properties.SAMLResponse.maxLength === 1048576 &&
    samlForm.properties.RelayState.maxLength === 80,
  "SAML ACS raw artifact bounds drifted",
);

for (const [name, value] of [
  ["OIDC callback", oidcCallback],
  ["SAML ACS", samlACS],
]) {
  assert(
    value.responses["303"].headers?.Location?.$ref ===
      "#/components/headers/LocalFederatedRedirect" &&
      value.responses["303"].headers?.["Set-Cookie"]?.$ref ===
        "#/components/headers/FederatedCompletionCookies" &&
      value.responses["303"].headers?.["Cache-Control"]?.$ref ===
        "#/components/headers/NoStore",
    `${name} lost local redirect, cookie clearing, or no-store semantics`,
  );
  for (const status of ["401", "503"]) {
    const response =
      document.components.responses[
        status === "401"
          ? "FederatedCallbackUnauthorized"
          : "FederatedCallbackServiceUnavailable"
      ];
    assert(
      value.responses[status].$ref ===
        `#/components/responses/${
          status === "401"
            ? "FederatedCallbackUnauthorized"
            : "FederatedCallbackServiceUnavailable"
        }` &&
        response.headers?.["Set-Cookie"]?.$ref ===
          "#/components/headers/ClearedFederatedTransactionCookie",
      `${name} ${status} must clear its one-use transaction cookie`,
    );
  }
}

assert(
  platformOIDCCallback.responses["303"].headers?.Location?.$ref ===
    "#/components/headers/LocalFederatedRedirect" &&
    platformOIDCCallback.responses["303"].headers?.["Set-Cookie"]?.$ref ===
      "#/components/headers/PlatformOIDCCompletionCookies" &&
    platformOIDCCallback.responses["303"].headers?.["Cache-Control"]?.$ref ===
      "#/components/headers/NoStore",
  "platform OIDC callback lost local redirect, distinct cookie clearing, or no-store semantics",
);

assert(
  platformSAMLACS.responses["303"].headers?.Location?.$ref ===
    "#/components/headers/LocalFederatedRedirect" &&
    platformSAMLACS.responses["303"].headers?.["Set-Cookie"]?.$ref ===
      "#/components/headers/PlatformSAMLCompletionCookies" &&
    platformSAMLACS.responses["303"].headers?.["Cache-Control"]?.$ref ===
      "#/components/headers/NoStore" &&
    platformSAMLACS.responses["303"].headers?.["Referrer-Policy"]?.$ref ===
      "#/components/headers/NoReferrer",
  "platform SAML ACS lost local redirect, distinct cookie clearing, no-store, or no-referrer semantics",
);
for (const [status, responseName] of [
  ["401", "PlatformSAMLCallbackUnauthorized"],
  ["503", "PlatformSAMLCallbackServiceUnavailable"],
]) {
  const response = document.components.responses[responseName];
  assert(
    platformSAMLACS.responses[status].$ref ===
      `#/components/responses/${responseName}` &&
      response.headers?.["Cache-Control"]?.$ref ===
        "#/components/headers/NoStore" &&
      response.headers?.["Referrer-Policy"]?.$ref ===
        "#/components/headers/NoReferrer" &&
      response.headers?.["Set-Cookie"]?.$ref ===
        "#/components/headers/ClearedPlatformSAMLTransactionCookie" &&
      response.content?.["application/problem+json"]?.schema?.$ref ===
        "#/components/schemas/Problem",
    `platform SAML ACS ${status} must fail generically and clear only its transaction cookie`,
  );
}

const platformSAMLMetadata = document.paths?.[platformSAMLMetadataPath]?.get;
assert(
  platformSAMLMetadata?.operationId === "getPlatformSAMLMetadata" &&
    JSON.stringify(platformSAMLMetadata.security) === "[]" &&
    platformSAMLMetadata.requestBody === undefined,
  "platform SAML metadata must remain public, bodyless, and provider-qualified",
);
exact(
  Object.keys(platformSAMLMetadata.responses ?? {}).toSorted(),
  ["200", "400", "404", "503"],
  "platform SAML metadata response vocabulary drifted",
);
assert(
  document.paths[platformSAMLMetadataPath].parameters?.[0]?.$ref ===
    "#/components/parameters/PlatformSAMLProviderKey" &&
    platformSAMLMetadata.responses["200"]?.content?.[
      "application/samlmetadata+xml"
    ]?.schema?.maxLength === 524288 &&
    platformSAMLMetadata.responses["200"]?.headers?.["Cache-Control"]?.$ref ===
      "#/components/headers/NoStore" &&
    platformSAMLMetadata.responses["200"]?.headers?.["Referrer-Policy"]
      ?.$ref === "#/components/headers/NoReferrer" &&
    /unknown, disabled,\s+or unready provider returns the same generic 404/.test(
      platformSAMLMetadata.description,
    ),
  "platform SAML metadata lost provider binding, exact content, privacy headers, or non-oracular 404 semantics",
);
for (const [status, responseName] of [
  ["401", "PlatformOIDCCallbackUnauthorized"],
  ["503", "PlatformOIDCCallbackServiceUnavailable"],
]) {
  const response = document.components.responses[responseName];
  assert(
    platformOIDCCallback.responses[status].$ref ===
      `#/components/responses/${responseName}` &&
      response.headers?.["Cache-Control"]?.$ref ===
        "#/components/headers/NoStore" &&
      response.headers?.["Set-Cookie"]?.$ref ===
        "#/components/headers/ClearedPlatformOIDCTransactionCookie" &&
      response.content?.["application/problem+json"]?.schema?.$ref ===
        "#/components/schemas/Problem",
    `platform OIDC callback ${status} must fail generically and clear only its transaction cookie`,
  );
}
assert(
  /common federated MFA continuation/.test(platformOIDCCallback.description) &&
    /no active tenant/.test(platformOIDCCallback.description) &&
    /requires live admission through an exact binding/.test(
      platformOIDCCallback.description,
    ) &&
    /rotates both session credential and primary provenance/.test(
      platformOIDCCallback.description,
    ),
  "platform OIDC callback must document direct-session and tenant-switch boundaries",
);

const platformOIDCCookieNames = [
  "periapsis_platform_oidc_transaction",
  "__Host-periapsis_platform_oidc_transaction",
];
for (const headerName of [
  "PlatformOIDCTransactionCookie",
  "ClearedPlatformOIDCTransactionCookie",
  "PlatformOIDCCompletionCookies",
]) {
  const header = document.components.headers[headerName];
  assert(
    header?.required === true &&
      header.schema?.type === "string" &&
      platformOIDCCookieNames.every((cookieName) =>
        header.description.includes(cookieName),
      ) &&
      /HttpOnly/.test(header.description) &&
      /Secure/.test(header.description) &&
      /SameSite=Lax/.test(header.description) &&
      /Path=\//.test(header.description),
    `${headerName} lost the distinct direct-platform OIDC cookie contract`,
  );
}
const platformSAMLCookieNames = [
  "periapsis_platform_saml_transaction",
  "__Host-periapsis_platform_saml_transaction",
];
for (const headerName of [
  "PlatformSAMLTransactionCookie",
  "ClearedPlatformSAMLTransactionCookie",
  "PlatformSAMLCompletionCookies",
]) {
  const header = document.components.headers[headerName];
  assert(
    header?.required === true &&
      header.schema?.type === "string" &&
      platformSAMLCookieNames.every((cookieName) =>
        header.description.includes(cookieName),
      ) &&
      /HttpOnly/.test(header.description) &&
      /Secure/.test(header.description) &&
      /SameSite=None/.test(header.description) &&
      /Path=\//.test(header.description),
    `${headerName} lost the distinct direct-platform SAML cookie contract`,
  );
}
assert(
  document.components.headers.ClearedFederatedBrowserCookies.description.includes(
    "direct-platform OIDC/SAML",
  ),
  "common federated abandonment must clear direct-platform OIDC and SAML browser state",
);

const session = document.components.schemas.Session;
assert(
  document.components.schemas.SessionAuthenticationMethod.enum.includes(
    "oidc",
  ) &&
    !session.required.includes("activeTenantId") &&
    session.properties.activeTenantId.type === "string" &&
    session.properties.activeTenantId.format === "uuid",
  "direct platform login must preserve oidc sessions with an optional active tenant",
);

const startRequest = document.components.schemas.FederatedLoginStartRequest;
assert(
  startRequest.additionalProperties === false &&
    JSON.stringify(startRequest.required) === JSON.stringify(["returnPath"]) &&
    startRequest.properties.returnPath.minLength === 1 &&
    startRequest.properties.returnPath.maxLength === 2048,
  "federated start request must remain a closed bounded return-path command",
);
assert(
  document.components.parameters.FederatedTenantSlug.schema.maxLength === 63 &&
    document.components.parameters.FederatedLoginKey.schema.maxLength === 64 &&
    document.components.headers.FederatedTransactionCookie.description.includes(
      "SameSite=None",
    ) &&
    document.components.headers.FederatedCompletionCookies.description
      .toLowerCase()
      .includes("expired"),
  "public locator or transaction-cookie invariants drifted",
);

const federatedMfaDefinitions = [
  [
    "/api/v1/auth/federated/mfa/step-up",
    "post",
    "startFederatedMfaStepUp",
    "startFederatedMfaStepUp",
    "200",
    ["200", "400", "401", "403", "429", "503"],
    "MfaCeremonyCookie",
    false,
  ],
  [
    "/api/v1/auth/federated/mfa/ceremony",
    "delete",
    "cancelFederatedMfaCeremony",
    "cancelFederatedMfaCeremony",
    "204",
    ["204", "400", "401", "429", "503"],
    "ClearedMfaCookie",
    false,
  ],
  [
    "/api/v1/auth/federated/mfa/step-up/{challengeId}/totp",
    "post",
    "completeFederatedMfaTotpStepUp",
    "completeFederatedMfaTotpStepUp",
    "200",
    ["200", "400", "401", "403", "409", "429", "503"],
    "SessionAndClearedFederatedMfaCookies",
    true,
  ],
  [
    "/api/v1/auth/federated/mfa/step-up/{challengeId}/recovery",
    "post",
    "completeFederatedMfaRecoveryStepUp",
    "completeFederatedMfaRecoveryStepUp",
    "200",
    ["200", "400", "401", "403", "409", "429", "503"],
    "SessionAndClearedFederatedMfaCookies",
    true,
  ],
  [
    "/api/v1/auth/federated/mfa/passkeys/options",
    "post",
    "startFederatedPasskeyStepUp",
    "startFederatedPasskeyStepUp",
    "200",
    ["200", "400", "401", "403", "429", "503"],
    "MfaCeremonyCookie",
    false,
  ],
  [
    "/api/v1/auth/federated/mfa/passkeys/verify",
    "post",
    "completeFederatedPasskeyStepUp",
    "completeFederatedPasskeyStepUp",
    "200",
    ["200", "400", "401", "403", "409", "429", "503"],
    "SessionAndClearedFederatedMfaCookies",
    true,
  ],
  [
    "/api/v1/auth/federated/mfa/totp/enrollments",
    "post",
    "startFederatedTotpEnrollment",
    "startFederatedTotpEnrollment",
    "201",
    ["201", "400", "401", "403", "409", "429", "503"],
    "MfaCeremonyCookie",
    false,
  ],
  [
    "/api/v1/auth/federated/mfa/totp/enrollments/{enrollmentId}",
    "post",
    "completeFederatedTotpEnrollment",
    "completeFederatedTotpEnrollment",
    "200",
    ["200", "400", "401", "403", "409", "429", "503"],
    "ClearedMfaCookie",
    true,
  ],
];

for (const [
  path,
  method,
  operationId,
  generatedName,
  successStatus,
  statuses,
  cookieHeader,
  acceptsBody,
] of federatedMfaDefinitions) {
  const value = document.paths?.[path]?.[method];
  assert(value?.operationId === operationId, `${operationId} is missing`);
  exact(
    value.security,
    [{ federatedContinuationCookie: [] }],
    `${operationId} must declare only the continuation cookie`,
  );
  assert(
    value["x-periapsis-generated-auth"] === "browser-cookie",
    `${operationId} must suppress generated access to its HttpOnly cookie`,
  );
  exact(
    Object.keys(value.responses ?? {}).toSorted(),
    statuses.toSorted(),
    `${operationId} response vocabulary drifted`,
  );
  assert(
    value.responses[successStatus]?.headers?.["Cache-Control"]?.$ref ===
      "#/components/headers/NoStore" &&
      value.responses[successStatus]?.headers?.["Set-Cookie"]?.$ref ===
        `#/components/headers/${cookieHeader}`,
    `${operationId} lost no-store or exact cookie transition semantics`,
  );
  assert(
    acceptsBody
      ? value.requestBody?.required === true
      : value.requestBody === undefined,
    `${operationId} request-body boundary drifted`,
  );

  const start = sdk.indexOf(`export const ${generatedName} =`);
  const next = sdk.indexOf("\nexport const ", start + 1);
  const end = next < 0 ? sdk.length : next;
  assert(start >= 0 && end > start, `generated ${operationId} is missing`);
  assert(
    !sdk.slice(start, end).includes("security:"),
    `generated ${operationId} must rely only on the browser-managed HttpOnly cookie`,
  );
}

const abandonMfa =
  document.paths?.["/api/v1/auth/federated/mfa/continuation"]?.delete;
assert(
  abandonMfa?.operationId === "abandonFederatedMfaContinuation" &&
    abandonMfa.requestBody === undefined,
  "federated MFA abandonment must remain a bodyless recovery operation",
);
exact(
  abandonMfa.security,
  [],
  "federated MFA abandonment must grant no generated authority",
);
exact(
  Object.keys(abandonMfa.responses ?? {}).toSorted(),
  ["204", "400", "401", "503"],
  "federated MFA abandonment response vocabulary drifted",
);
assert(
  abandonMfa.responses["204"]?.headers?.["Cache-Control"]?.$ref ===
    "#/components/headers/NoStore" &&
    abandonMfa.responses["204"]?.headers?.["Set-Cookie"]?.$ref ===
      "#/components/headers/ClearedFederatedBrowserCookies",
  "federated MFA abandonment must clear all anonymous browser capabilities",
);

const stepUpChallenge = document.components.schemas.MfaStepUpChallenge;
exact(
  stepUpChallenge.required,
  ["challengeId", "expiresAt", "methods", "totpFactorIds"],
  "federated local challenge selectors must be mandatory",
);
assert(
  stepUpChallenge.additionalProperties === false &&
    stepUpChallenge.properties.methods.minItems === 1 &&
    stepUpChallenge.properties.methods.maxItems === 2 &&
    stepUpChallenge.properties.methods.uniqueItems === true &&
    stepUpChallenge.properties.totpFactorIds.maxItems === 16 &&
    stepUpChallenge.properties.totpFactorIds.uniqueItems === true &&
    stepUpChallenge.properties.totpFactorIds.items.format === "uuid" &&
    stepUpChallenge.properties.totpFactorIds.description.includes(
      "non-empty exactly when",
    ),
  "federated TOTP selectors lost their closed bounded challenge relationship",
);
const continuationScheme =
  document.components.securitySchemes.federatedContinuationCookie;
assert(
  continuationScheme?.type === "apiKey" &&
    continuationScheme?.in === "cookie" &&
    continuationScheme?.name === "__Host-periapsis_federated_continuation",
  "federated continuation must remain a dedicated host-only browser cookie",
);

const abandonStart = sdk.indexOf(
  "export const abandonFederatedMfaContinuation =",
);
const abandonEnd = sdk.indexOf("\nexport const ", abandonStart + 1);
assert(
  abandonStart >= 0 &&
    abandonEnd > abandonStart &&
    !sdk.slice(abandonStart, abandonEnd).includes("security:"),
  "generated federated MFA abandonment must remain authority-free",
);

for (const [operationId, generatedName] of [
  ["startTenantOIDCFederatedLogin", "startTenantOidcFederatedLogin"],
  ["completeOIDCFederatedCallback", "completeOidcFederatedCallback"],
  ["startPlatformOIDCLogin", "startPlatformOidcLogin"],
  ["completePlatformOIDCCallback", "completePlatformOidcCallback"],
  ["startPlatformSAMLLogin", "startPlatformSamlLogin"],
  ["completePlatformSAMLACS", "completePlatformSamlacs"],
  ["getPlatformSAMLMetadata", "getPlatformSamlMetadata"],
  ["startTenantSAMLFederatedLogin", "startTenantSamlFederatedLogin"],
  ["completeSAMLFederatedACS", "completeSamlFederatedAcs"],
]) {
  const start = sdk.indexOf(`export const ${generatedName} =`);
  const next = sdk.indexOf("\nexport const ", start + 1);
  const end = next < 0 ? sdk.length : next;
  assert(
    start >= 0 && end > start,
    `generated ${operationId} declaration is missing`,
  );
  assert(
    !sdk.slice(start, end).includes("security:"),
    `generated ${operationId} must not synthesize ambient auth`,
  );
}
