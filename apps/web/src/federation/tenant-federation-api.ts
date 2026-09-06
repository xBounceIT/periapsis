import {
  archiveTenantFederatedAuthProvider,
  clearTenantOidcAuthProviderClientSecret,
  clearTenantSamlAuthProviderSpCredential,
  createTenantFederatedAuthProvider,
  getTenantFederatedAuthProvider,
  getTenantFederatedAuthProviderAssurancePolicy,
  getTenantFederatedAuthProviderMappingPolicy,
  listTenantFederatedAuthProviders,
  refreshTenantOidcAuthProviderTrustDocuments,
  replaceTenantFederatedAuthProviderAssurancePolicy,
  replaceTenantFederatedAuthProviderMappingPolicy,
  replaceTenantOidcAuthProviderClientSecret,
  replaceTenantSamlAuthProviderMetadata,
  replaceTenantSamlAuthProviderSpCredential,
  updateTenantFederatedAuthProvider,
  type TenantFederationAssurancePolicy,
  type TenantFederationAssurancePolicyReplaceRequest,
  type TenantFederationAuthProvider,
  type TenantFederationAuthProviderCreateRequest,
  type TenantFederationAuthProviderSummary,
  type TenantFederationAuthProviderUpdateRequest,
  type TenantFederationMappingPolicy,
  type TenantFederationMappingPolicyReplaceRequest,
  type TenantOidcTrustDocumentsRefreshRequest,
  type TenantSamlMetadataReplaceRequestWritable,
} from "@periapsis/contracts";

import { PhaseTwoApiError } from "../lib/phase-two-types";
import { parseRfc3339Instant } from "../lib/rfc3339-instant";
import { sessionAwareFetch } from "../lib/session-transition-transport";

export interface TenantFederationProviderPage {
  items: readonly TenantFederationAuthProviderSummary[];
  nextCursor?: string;
}

export interface TenantFederationProviderVersioned {
  etag: string;
  value: TenantFederationAuthProvider;
}

export interface TenantFederationSecretMutation {
  etag: string;
  secretRevision: number;
}

export interface TenantFederationSAMLMaterialMutation {
  etag: string;
  materialRevision: number;
}

export interface TenantFederationMappingPolicyVersioned {
  etag: string;
  mappingRevision: number;
  value: TenantFederationMappingPolicy;
}

export interface TenantFederationAssurancePolicyVersioned {
  assurancePolicyRevision: number;
  etag: string;
  value: TenantFederationAssurancePolicy;
}

export interface TenantFederationPolicyMutation {
  etag: string;
  revision: number;
}

export interface TenantFederationOIDCTrustMutation {
  discoveryRevision: number;
  etag: string;
  jwksKeyCount: number;
  jwksRevision: number;
}

export type TenantFederationMappingPolicyContext =
  { kind: "oidc"; useUserInfo: boolean } | { kind: "saml" };

export interface TenantFederationApi {
  list(
    tenantId: string,
    options?: {
      after?: string;
      includeArchived?: boolean;
      signal?: AbortSignal;
    },
  ): Promise<TenantFederationProviderPage>;
  get(
    tenantId: string,
    providerId: string,
    signal?: AbortSignal,
  ): Promise<TenantFederationProviderVersioned>;
  create(
    csrfToken: string,
    tenantId: string,
    idempotencyKey: string,
    input: TenantFederationAuthProviderCreateRequest,
  ): Promise<TenantFederationProviderVersioned & { location: string }>;
  update(
    csrfToken: string,
    tenantId: string,
    providerId: string,
    etag: string,
    input: TenantFederationAuthProviderUpdateRequest,
  ): Promise<TenantFederationProviderVersioned>;
  archive(
    csrfToken: string,
    tenantId: string,
    providerId: string,
    etag: string,
    reason: string,
  ): Promise<string>;
  replaceOidcClientSecret(
    csrfToken: string,
    tenantId: string,
    providerId: string,
    etag: string,
    clientSecret: string,
    reason: string,
  ): Promise<TenantFederationSecretMutation>;
  clearOidcClientSecret(
    csrfToken: string,
    tenantId: string,
    providerId: string,
    etag: string,
    reason: string,
  ): Promise<TenantFederationSecretMutation>;
  refreshOidcTrustDocuments(
    csrfToken: string,
    tenantId: string,
    providerId: string,
    etag: string,
    input: TenantOidcTrustDocumentsRefreshRequest,
  ): Promise<TenantFederationOIDCTrustMutation>;
  getMappingPolicy(
    tenantId: string,
    providerId: string,
    context: TenantFederationMappingPolicyContext,
    signal?: AbortSignal,
  ): Promise<TenantFederationMappingPolicyVersioned>;
  replaceMappingPolicy(
    csrfToken: string,
    tenantId: string,
    providerId: string,
    etag: string,
    input: TenantFederationMappingPolicyReplaceRequest,
    context: TenantFederationMappingPolicyContext,
  ): Promise<TenantFederationPolicyMutation>;
  getAssurancePolicy(
    tenantId: string,
    providerId: string,
    signal?: AbortSignal,
  ): Promise<TenantFederationAssurancePolicyVersioned>;
  replaceAssurancePolicy(
    csrfToken: string,
    tenantId: string,
    providerId: string,
    etag: string,
    input: TenantFederationAssurancePolicyReplaceRequest,
  ): Promise<TenantFederationPolicyMutation>;
  replaceSamlMetadata(
    csrfToken: string,
    tenantId: string,
    providerId: string,
    etag: string,
    input: TenantSamlMetadataReplaceRequestWritable,
  ): Promise<TenantFederationSAMLMaterialMutation>;
  replaceSamlSpCredential(
    csrfToken: string,
    tenantId: string,
    providerId: string,
    etag: string,
    reason: string,
  ): Promise<TenantFederationSAMLMaterialMutation>;
  clearSamlSpCredential(
    csrfToken: string,
    tenantId: string,
    providerId: string,
    etag: string,
    reason: string,
  ): Promise<TenantFederationSAMLMaterialMutation>;
}

const sameOrigin = {
  baseUrl: globalThis.location.origin,
  credentials: "same-origin" as const,
  fetch: sessionAwareFetch,
};

const uuidV7Pattern =
  /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const etagPattern = /^"v([1-9]\d{0,9})"$/;
const forbiddenFederatedEvidenceDirectionalControl =
  /[\u200E\u200F\u202A-\u202E\u2066-\u2069]/u;
const reservedOIDCSecurityClaims = new Set([
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
]);
const forbiddenProjectionKeys = new Set([
  "assertion",
  "certificate",
  "ciphertext",
  "claims",
  "clientsecret",
  "discoverydocument",
  "jwksdocument",
  "keymaterial",
  "metadata",
  "privatekey",
  "rawmetadata",
  "refreshtoken",
  "secret",
  "signingkey",
  "token",
]);

export const tenantFederationApi: TenantFederationApi = {
  async list(tenantId, options) {
    assertUuid(tenantId);
    const result = await listTenantFederatedAuthProviders({
      ...sameOrigin,
      cache: "no-store",
      path: { tenantId },
      query: {
        limit: 50,
        ...(options?.after ? { after: options.after } : {}),
        ...(options?.includeArchived === undefined
          ? {}
          : { includeArchived: options.includeArchived }),
      },
      ...(options?.signal ? { signal: options.signal } : {}),
    });
    const page = unwrapData(result, 200, "list");
    if (!Array.isArray(page.items) || page.items.length > 100) {
      throw projectionError();
    }
    page.items.forEach((provider) =>
      assertSummaryProjection(provider, tenantId),
    );
    if (page.nextCursor !== undefined) assertUuid(page.nextCursor);
    return {
      items: page.items.map((provider) => cloneSummary(provider)),
      ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}),
    };
  },

  async get(tenantId, providerId, signal) {
    assertUuid(tenantId);
    assertUuid(providerId);
    const result = await getTenantFederatedAuthProvider({
      ...sameOrigin,
      cache: "no-store",
      path: { tenantId, providerId },
      ...(signal ? { signal } : {}),
    });
    return unwrapProvider(result, 200, tenantId, providerId, "detail");
  },

  async create(csrfToken, tenantId, idempotencyKey, input) {
    assertMutationHeaders(csrfToken, idempotencyKey);
    assertUuid(tenantId);
    assertFederationConfiguration(input);
    const result = await createTenantFederatedAuthProvider({
      ...sameOrigin,
      body: input,
      cache: "no-store",
      headers: {
        "Idempotency-Key": idempotencyKey,
        "X-CSRF-Token": csrfToken,
      },
      path: { tenantId },
    });
    const created = unwrapProvider(result, 201, tenantId, undefined, "create");
    const location = assertLocation(
      result.response?.headers.get("Location") ?? null,
      tenantId,
      created.value.id,
    );
    return { ...created, location };
  },

  async update(csrfToken, tenantId, providerId, etag, input) {
    assertMutationHeaders(csrfToken);
    const previousVersion = assertEtag(etag);
    assertUuid(tenantId);
    assertUuid(providerId);
    assertFederationConfiguration(input);
    const result = await updateTenantFederatedAuthProvider({
      ...sameOrigin,
      body: input,
      cache: "no-store",
      headers: { "If-Match": etag, "X-CSRF-Token": csrfToken },
      path: { tenantId, providerId },
    });
    const updated = unwrapProvider(result, 200, tenantId, providerId, "update");
    if (updated.value.version !== previousVersion + 1) throw projectionError();
    return updated;
  },

  async archive(csrfToken, tenantId, providerId, etag, reason) {
    assertMutationHeaders(csrfToken);
    const previousVersion = assertEtag(etag);
    assertReason(reason);
    assertUuid(tenantId);
    assertUuid(providerId);
    const result = await archiveTenantFederatedAuthProvider({
      ...sameOrigin,
      body: { reason },
      cache: "no-store",
      headers: { "If-Match": etag, "X-CSRF-Token": csrfToken },
      path: { tenantId, providerId },
    });
    return unwrapBodyless(result, previousVersion, "archive").etag;
  },

  async replaceOidcClientSecret(
    csrfToken,
    tenantId,
    providerId,
    etag,
    clientSecret,
    reason,
  ) {
    assertMutationHeaders(csrfToken);
    const previousVersion = assertEtag(etag);
    assertReason(reason);
    const secretLength = utf8Length(clientSecret);
    if (secretLength < 1 || secretLength > 8192) {
      throw new PhaseTwoApiError(
        "The OIDC client secret is outside the bounded transfer size.",
      );
    }
    assertUuid(tenantId);
    assertUuid(providerId);
    const result = await replaceTenantOidcAuthProviderClientSecret({
      ...sameOrigin,
      body: { clientSecret, reason },
      cache: "no-store",
      headers: { "If-Match": etag, "X-CSRF-Token": csrfToken },
      path: { tenantId, providerId },
    });
    return unwrapBodyless(result, previousVersion, "secret rotation", true);
  },

  async clearOidcClientSecret(csrfToken, tenantId, providerId, etag, reason) {
    assertMutationHeaders(csrfToken);
    const previousVersion = assertEtag(etag);
    assertReason(reason);
    assertUuid(tenantId);
    assertUuid(providerId);
    const result = await clearTenantOidcAuthProviderClientSecret({
      ...sameOrigin,
      body: { reason },
      cache: "no-store",
      headers: { "If-Match": etag, "X-CSRF-Token": csrfToken },
      path: { tenantId, providerId },
    });
    return unwrapBodyless(result, previousVersion, "secret retirement", true);
  },

  async refreshOidcTrustDocuments(
    csrfToken,
    tenantId,
    providerId,
    etag,
    input,
  ) {
    assertMutationHeaders(csrfToken);
    const previousVersion = assertEtag(etag);
    assertUuid(tenantId);
    assertUuid(providerId);
    assertOidcTrustInput(input);
    const result = await refreshTenantOidcAuthProviderTrustDocuments({
      ...sameOrigin,
      body: input,
      cache: "no-store",
      headers: { "If-Match": etag, "X-CSRF-Token": csrfToken },
      path: { tenantId, providerId },
    });
    return unwrapOIDCTrustBodyless(result, previousVersion);
  },

  async getMappingPolicy(tenantId, providerId, context, signal) {
    assertUuid(tenantId);
    assertUuid(providerId);
    const result = await getTenantFederatedAuthProviderMappingPolicy({
      ...sameOrigin,
      cache: "no-store",
      path: { tenantId, providerId },
      ...(signal ? { signal } : {}),
    });
    const value = unwrapData(result, 200, "mapping policy read");
    assertPolicyProjection(value, tenantId, providerId, "mappingRevision");
    if (value.kind !== context.kind) throw projectionError();
    const etag = result.response?.headers.get("ETag") ?? "";
    if (assertEtag(etag) !== value.providerVersion) throw projectionError();
    const mappingRevision = requiredRevisionHeader(
      result.response,
      "X-Periapsis-Mapping-Revision",
    );
    if (mappingRevision !== value.mappingRevision) throw projectionError();
    return { etag, mappingRevision, value: cloneMappingPolicy(value) };
  },

  async replaceMappingPolicy(
    csrfToken,
    tenantId,
    providerId,
    etag,
    input,
    context,
  ) {
    assertMutationHeaders(csrfToken);
    const previousVersion = assertEtag(etag);
    assertUuid(tenantId);
    assertUuid(providerId);
    assertTenantFederationMappingPolicyReplacement(input, context);
    const result = await replaceTenantFederatedAuthProviderMappingPolicy({
      ...sameOrigin,
      body: input,
      cache: "no-store",
      headers: { "If-Match": etag, "X-CSRF-Token": csrfToken },
      path: { tenantId, providerId },
    });
    return unwrapPolicyBodyless(
      result,
      previousVersion,
      "X-Periapsis-Mapping-Revision",
      "mapping policy replacement",
    );
  },

  async getAssurancePolicy(tenantId, providerId, signal) {
    assertUuid(tenantId);
    assertUuid(providerId);
    const result = await getTenantFederatedAuthProviderAssurancePolicy({
      ...sameOrigin,
      cache: "no-store",
      path: { tenantId, providerId },
      ...(signal ? { signal } : {}),
    });
    const value = unwrapData(result, 200, "assurance policy read");
    assertPolicyProjection(
      value,
      tenantId,
      providerId,
      "assurancePolicyRevision",
    );
    const etag = result.response?.headers.get("ETag") ?? "";
    if (assertEtag(etag) !== value.providerVersion) throw projectionError();
    const assurancePolicyRevision = requiredRevisionHeader(
      result.response,
      "X-Periapsis-Assurance-Policy-Revision",
    );
    if (assurancePolicyRevision !== value.assurancePolicyRevision) {
      throw projectionError();
    }
    return {
      assurancePolicyRevision,
      etag,
      value: cloneAssurancePolicy(value),
    };
  },

  async replaceAssurancePolicy(csrfToken, tenantId, providerId, etag, input) {
    assertMutationHeaders(csrfToken);
    const previousVersion = assertEtag(etag);
    assertUuid(tenantId);
    assertUuid(providerId);
    assertTenantFederationAssurancePolicyReplacement(input);
    const result = await replaceTenantFederatedAuthProviderAssurancePolicy({
      ...sameOrigin,
      body: input,
      cache: "no-store",
      headers: { "If-Match": etag, "X-CSRF-Token": csrfToken },
      path: { tenantId, providerId },
    });
    return unwrapPolicyBodyless(
      result,
      previousVersion,
      "X-Periapsis-Assurance-Policy-Revision",
      "assurance policy replacement",
    );
  },

  async replaceSamlMetadata(csrfToken, tenantId, providerId, etag, input) {
    assertMutationHeaders(csrfToken);
    const previousVersion = assertEtag(etag);
    assertUuid(tenantId);
    assertUuid(providerId);
    assertTenantSAMLMetadataInput(input);
    const result = await replaceTenantSamlAuthProviderMetadata({
      ...sameOrigin,
      body: input,
      cache: "no-store",
      headers: { "If-Match": etag, "X-CSRF-Token": csrfToken },
      path: { tenantId, providerId },
    });
    return unwrapSAMLBodyless(result, previousVersion, "metadata replacement");
  },

  async replaceSamlSpCredential(csrfToken, tenantId, providerId, etag, reason) {
    assertMutationHeaders(csrfToken);
    const previousVersion = assertEtag(etag);
    assertReason(reason);
    assertUuid(tenantId);
    assertUuid(providerId);
    const result = await replaceTenantSamlAuthProviderSpCredential({
      ...sameOrigin,
      body: { reason },
      cache: "no-store",
      headers: { "If-Match": etag, "X-CSRF-Token": csrfToken },
      path: { tenantId, providerId },
    });
    return unwrapSAMLBodyless(
      result,
      previousVersion,
      "SP credential rotation",
    );
  },

  async clearSamlSpCredential(csrfToken, tenantId, providerId, etag, reason) {
    assertMutationHeaders(csrfToken);
    const previousVersion = assertEtag(etag);
    assertReason(reason);
    assertUuid(tenantId);
    assertUuid(providerId);
    const result = await clearTenantSamlAuthProviderSpCredential({
      ...sameOrigin,
      body: { reason },
      cache: "no-store",
      headers: { "If-Match": etag, "X-CSRF-Token": csrfToken },
      path: { tenantId, providerId },
    });
    return unwrapSAMLBodyless(
      result,
      previousVersion,
      "SP credential retirement",
    );
  },
};

interface GeneratedResult<T> {
  data: T | undefined;
  error: unknown;
  response?: Response | undefined;
}

function unwrapData<T>(
  result: GeneratedResult<T>,
  expectedStatus: number,
  operation: string,
): T {
  const response = result.response;
  if (!response?.ok) throw apiError(result.error, response);
  if (response.status !== expectedStatus) {
    throw new PhaseTwoApiError(
      `The tenant federation ${operation} endpoint returned an unexpected success status.`,
      response.status,
    );
  }
  assertNoStore(response);
  if (result.data === undefined) throw projectionError();
  return result.data;
}

function unwrapProvider(
  result: GeneratedResult<TenantFederationAuthProvider>,
  expectedStatus: number,
  tenantId: string,
  providerId: string | undefined,
  operation: string,
): TenantFederationProviderVersioned {
  const provider = unwrapData(result, expectedStatus, operation);
  assertProviderProjection(provider, tenantId, providerId);
  const etag = result.response?.headers.get("ETag") ?? "";
  if (assertEtag(etag) !== provider.version) throw projectionError();
  return { etag, value: cloneProvider(provider) };
}

function unwrapBodyless(
  result: GeneratedResult<void>,
  previousVersion: number,
  operation: string,
  requireSecretRevision = false,
): TenantFederationSecretMutation {
  const response = result.response;
  if (!response?.ok) throw apiError(result.error, response);
  if (
    response.status !== 204 ||
    (result.data !== undefined && result.data !== null)
  ) {
    throw new PhaseTwoApiError(
      `The tenant federation ${operation} endpoint returned payload data or an unexpected status.`,
      response.status,
    );
  }
  assertNoStore(response);
  const etag = response.headers.get("ETag") ?? "";
  if (assertEtag(etag) !== previousVersion + 1) throw projectionError();
  const rawRevision = response.headers.get("X-Periapsis-Secret-Revision");
  if (!requireSecretRevision) return { etag, secretRevision: 0 };
  const secretRevision = Number(rawRevision);
  if (
    rawRevision === null ||
    !/^[1-9]\d{0,15}$/.test(rawRevision) ||
    !Number.isSafeInteger(secretRevision)
  ) {
    throw projectionError();
  }
  return { etag, secretRevision };
}

function unwrapSAMLBodyless(
  result: GeneratedResult<void>,
  previousVersion: number,
  operation: string,
): TenantFederationSAMLMaterialMutation {
  const response = result.response;
  if (!response?.ok) throw apiError(result.error, response);
  if (
    response.status !== 204 ||
    (result.data !== undefined && result.data !== null)
  ) {
    throw new PhaseTwoApiError(
      `The tenant federation ${operation} endpoint returned payload data or an unexpected status.`,
      response.status,
    );
  }
  assertNoStore(response);
  const etag = response.headers.get("ETag") ?? "";
  if (assertEtag(etag) !== previousVersion + 1) throw projectionError();
  const rawRevision = response.headers.get(
    "X-Periapsis-SAML-Material-Revision",
  );
  const materialRevision = Number(rawRevision);
  if (
    rawRevision === null ||
    !/^[1-9]\d{0,9}$/.test(rawRevision) ||
    !Number.isSafeInteger(materialRevision) ||
    materialRevision < 2 ||
    materialRevision > 2_147_483_647
  ) {
    throw projectionError();
  }
  return { etag, materialRevision };
}

function unwrapPolicyBodyless(
  result: GeneratedResult<void>,
  previousVersion: number,
  revisionHeader: string,
  operation: string,
): TenantFederationPolicyMutation {
  const response = result.response;
  if (!response?.ok) throw apiError(result.error, response);
  if (
    response.status !== 204 ||
    (result.data !== undefined && result.data !== null)
  ) {
    throw new PhaseTwoApiError(
      `The tenant federation ${operation} endpoint returned payload data or an unexpected status.`,
      response.status,
    );
  }
  assertNoStore(response);
  const etag = response.headers.get("ETag") ?? "";
  if (assertEtag(etag) !== previousVersion + 1) throw projectionError();
  return {
    etag,
    revision: requiredRevisionHeader(response, revisionHeader, 2),
  };
}

function unwrapOIDCTrustBodyless(
  result: GeneratedResult<void>,
  previousVersion: number,
): TenantFederationOIDCTrustMutation {
  const response = result.response;
  if (!response?.ok) throw apiError(result.error, response);
  if (
    response.status !== 204 ||
    (result.data !== undefined && result.data !== null)
  ) {
    throw new PhaseTwoApiError(
      "The tenant OIDC trust refresh endpoint returned payload data or an unexpected status.",
      response.status,
    );
  }
  assertNoStore(response);
  const etag = response.headers.get("ETag") ?? "";
  if (assertEtag(etag) !== previousVersion + 1) throw projectionError();
  const discoveryRevision = requiredRevisionHeader(
    response,
    "X-Periapsis-OIDC-Discovery-Revision",
    2,
  );
  const jwksRevision = requiredRevisionHeader(
    response,
    "X-Periapsis-OIDC-JWKS-Revision",
    2,
  );
  const jwksKeyCount = requiredRevisionHeader(
    response,
    "X-Periapsis-OIDC-JWKS-Key-Count",
    1,
    32,
  );
  return { discoveryRevision, etag, jwksKeyCount, jwksRevision };
}

function requiredRevisionHeader(
  response: Response | undefined,
  name: string,
  minimum = 1,
  maximum = Number.MAX_SAFE_INTEGER,
): number {
  const raw = response?.headers.get(name) ?? null;
  const value = Number(raw);
  if (
    raw === null ||
    !/^[1-9]\d{0,15}$/.test(raw) ||
    !Number.isSafeInteger(value) ||
    value < minimum ||
    value > maximum
  ) {
    throw projectionError();
  }
  return value;
}

const oidcSigningAlgorithms = new Set<string>([
  "RS256",
  "RS384",
  "RS512",
  "PS256",
  "PS384",
  "PS512",
  "ES256",
  "ES384",
  "ES512",
  "EdDSA",
]);

function assertOidcTrustInput(
  input: TenantOidcTrustDocumentsRefreshRequest,
): void {
  assertReason(input.reason);
  if (
    Object.keys(input).toSorted().join(",") !==
      "clientAuthentication,reason,signingAlgorithms" ||
    !["client_secret_basic", "client_secret_post"].includes(
      input.clientAuthentication,
    ) ||
    !Array.isArray(input.signingAlgorithms) ||
    input.signingAlgorithms.length < 1 ||
    input.signingAlgorithms.length > 10 ||
    new Set(input.signingAlgorithms).size !== input.signingAlgorithms.length ||
    input.signingAlgorithms.some(
      (algorithm) => !oidcSigningAlgorithms.has(algorithm),
    )
  ) {
    throw new PhaseTwoApiError("The OIDC trust refresh policy is invalid.");
  }
}

function assertPolicyProjection(
  value: TenantFederationMappingPolicy | TenantFederationAssurancePolicy,
  tenantId: string,
  providerId: string,
  revisionKey: "mappingRevision" | "assurancePolicyRevision",
): void {
  assertNoRawMaterial(value);
  if (!isRecord(value)) throw projectionError();
  assertUuid(value.tenantId);
  assertUuid(value.providerId);
  const revision =
    revisionKey === "mappingRevision" && "mappingRevision" in value
      ? value.mappingRevision
      : revisionKey === "assurancePolicyRevision" &&
          "assurancePolicyRevision" in value
        ? value.assurancePolicyRevision
        : 0;
  if (
    value.tenantId !== tenantId ||
    value.providerId !== providerId ||
    (value.kind !== "oidc" && value.kind !== "saml") ||
    !Number.isSafeInteger(value.providerVersion) ||
    value.providerVersion < 1 ||
    !Number.isSafeInteger(revision) ||
    revision < 1 ||
    !Array.isArray(value.rules)
  ) {
    throw projectionError();
  }
  const valid =
    revisionKey === "mappingRevision"
      ? validMappingPolicy(value, true)
      : validAssurancePolicy(value, true);
  if (!valid) {
    throw projectionError();
  }
}

export function assertTenantFederationMappingPolicyReplacement(
  input: unknown,
  context?: TenantFederationMappingPolicyContext,
): asserts input is TenantFederationMappingPolicyReplaceRequest {
  assertNoRawMaterial(input);
  if (!isRecord(input) || typeof input.reason !== "string") {
    throw new PhaseTwoApiError("The federation policy request is invalid.");
  }
  assertReason(input.reason);
  if (!validMappingPolicy(input, false)) {
    throw new PhaseTwoApiError("The mapping policy is invalid.");
  }
  if (context && !validMappingPolicyContext(input, context)) {
    throw new PhaseTwoApiError(
      "OIDC UserInfo must be enabled exactly when the mapping policy contains at least one UserInfo extraction rule.",
    );
  }
}

function validMappingPolicyContext(
  value: TenantFederationMappingPolicyReplaceRequest,
  context: TenantFederationMappingPolicyContext,
): boolean {
  if (value.kind !== context.kind) return false;
  if (value.kind === "saml" || context.kind === "saml") return true;
  const hasUserInfoRule = value.oidcClaimRules.some(
    (rule) => rule.source === "userinfo",
  );
  return context.useUserInfo === hasUserInfoRule;
}

export function assertTenantFederationAssurancePolicyReplacement(
  input: unknown,
): asserts input is TenantFederationAssurancePolicyReplaceRequest {
  assertNoRawMaterial(input);
  if (!isRecord(input) || typeof input.reason !== "string") {
    throw new PhaseTwoApiError("The federation policy request is invalid.");
  }
  assertReason(input.reason);
  if (!validAssurancePolicy(input, false)) {
    throw new PhaseTwoApiError("The assurance policy is invalid.");
  }
}

function validMappingPolicy(
  value: Record<string, unknown>,
  projection: false,
): value is TenantFederationMappingPolicyReplaceRequest;
function validMappingPolicy(
  value: Record<string, unknown>,
  projection: true,
): value is TenantFederationMappingPolicy;
function validMappingPolicy(
  value: Record<string, unknown>,
  projection: boolean,
): boolean {
  if (value.kind !== "oidc" && value.kind !== "saml") return false;
  const required = projection
    ? [
        "tenantId",
        "providerId",
        "kind",
        "providerVersion",
        "mappingRevision",
        value.kind === "oidc" ? "oidcClaimRules" : "samlAttributeRules",
        "rules",
      ]
    : [
        "kind",
        value.kind === "oidc" ? "oidcClaimRules" : "samlAttributeRules",
        "rules",
        "reason",
      ];
  if (!hasExactKeys(value, required)) return false;
  const extraction =
    value.kind === "oidc" ? value.oidcClaimRules : value.samlAttributeRules;
  return (
    Array.isArray(extraction) &&
    (value.kind === "oidc"
      ? validOIDCClaimRules(extraction)
      : validSAMLAttributeRules(extraction)) &&
    Array.isArray(value.rules) &&
    value.rules.length <= 2_000 &&
    validMappingRules(value.rules)
  );
}

function validMappingRules(rules: readonly unknown[]): boolean {
  const ruleIDs = new Set<string>();
  return rules.every((candidate) => {
    if (
      !isRecord(candidate) ||
      !hasExactKeys(
        candidate,
        [
          "ruleId",
          "priority",
          "matcherKind",
          "matcherValue",
          "reconciliationMode",
          "tenantSecurityGroupId",
          "roleIds",
          "enabled",
        ],
        ["claimName", "operatorTeamId", "operatorTeamAssignmentEpochId"],
      ) ||
      typeof candidate.ruleId !== "string" ||
      !isUuidV7(candidate.ruleId) ||
      ruleIDs.has(candidate.ruleId) ||
      typeof candidate.priority !== "number" ||
      !Number.isInteger(candidate.priority) ||
      candidate.priority < 0 ||
      candidate.priority > 1_000_000 ||
      (candidate.matcherKind !== "scalar_equals" &&
        candidate.matcherKind !== "group_equals") ||
      !validFederatedEvidenceText(candidate.matcherValue, 1, 1_024) ||
      (candidate.reconciliationMode !== "additive" &&
        candidate.reconciliationMode !== "authoritative") ||
      typeof candidate.tenantSecurityGroupId !== "string" ||
      !isUuidV7(candidate.tenantSecurityGroupId) ||
      !Array.isArray(candidate.roleIds) ||
      candidate.roleIds.length < 1 ||
      candidate.roleIds.length > 32 ||
      typeof candidate.enabled !== "boolean"
    ) {
      return false;
    }
    ruleIDs.add(candidate.ruleId);
    const roleIDs = candidate.roleIds;
    if (
      roleIDs.some(
        (roleID) => typeof roleID !== "string" || !isUuidV7(roleID),
      ) ||
      new Set(roleIDs).size !== roleIDs.length
    ) {
      return false;
    }
    if (
      candidate.matcherKind === "scalar_equals"
        ? !validClaimName(candidate.claimName)
        : candidate.claimName !== undefined && candidate.claimName !== null
    ) {
      return false;
    }
    const operatorTeamID = candidate.operatorTeamId;
    const assignmentEpochID = candidate.operatorTeamAssignmentEpochId;
    const hasTeam = operatorTeamID !== undefined && operatorTeamID !== null;
    const hasEpoch =
      assignmentEpochID !== undefined && assignmentEpochID !== null;
    return (
      hasTeam === hasEpoch &&
      (!hasTeam ||
        (typeof operatorTeamID === "string" &&
          isUuidV7(operatorTeamID) &&
          typeof assignmentEpochID === "string" &&
          isUuidV7(assignmentEpochID)))
    );
  });
}

function validOIDCClaimRules(rules: readonly unknown[]): boolean {
  if (rules.length < 1 || rules.length > 64) return false;
  const claims = new Set<string>();
  const profiles = new Set<string>();
  const singletonKinds = new Set<string>();
  const scalarCounts = { id_token: 0, userinfo: 0 };
  const profileCounts = { id_token: 0, userinfo: 0 };
  let hasUsername = false;
  let hasAMR = false;
  for (const candidate of rules) {
    if (
      !isRecord(candidate) ||
      !hasExactKeys(
        candidate,
        ["source", "kind", "claimName", "required"],
        ["profileField"],
      ) ||
      (candidate.source !== "id_token" && candidate.source !== "userinfo") ||
      !["scalar", "profile", "groups", "acr", "amr"].includes(
        String(candidate.kind),
      ) ||
      !validClaimName(candidate.claimName) ||
      typeof candidate.required !== "boolean"
    ) {
      return false;
    }
    if (
      (candidate.kind === "scalar" ||
        candidate.kind === "profile" ||
        candidate.kind === "groups") &&
      reservedOIDCSecurityClaims.has(candidate.claimName)
    ) {
      return false;
    }
    const claimKey = `${candidate.source}\u0000${candidate.claimName}`;
    if (claims.has(claimKey)) return false;
    claims.add(claimKey);
    if (candidate.kind === "profile") {
      if (!isProfileField(candidate.profileField)) return false;
      profileCounts[candidate.source] += 1;
      if (profileCounts[candidate.source] > 8) return false;
      const profileKey = `${candidate.source}\u0000${candidate.profileField}`;
      if (profiles.has(profileKey)) return false;
      profiles.add(profileKey);
      hasUsername ||= candidate.profileField === "username";
    } else if (candidate.kind === "scalar" || candidate.kind === "groups") {
      if (
        candidate.profileField !== undefined &&
        candidate.profileField !== null
      )
        return false;
      if (candidate.kind === "scalar") {
        scalarCounts[candidate.source] += 1;
        if (scalarCounts[candidate.source] > 16) return false;
      } else {
        const singletonKey = `${candidate.source}\u0000groups`;
        if (singletonKinds.has(singletonKey)) return false;
        singletonKinds.add(singletonKey);
      }
    } else if (
      candidate.source !== "id_token" ||
      candidate.claimName !== candidate.kind ||
      candidate.required ||
      (candidate.profileField !== undefined && candidate.profileField !== null)
    ) {
      return false;
    } else {
      const singletonKey = `${candidate.source}\u0000${candidate.kind}`;
      if (singletonKinds.has(singletonKey)) return false;
      singletonKinds.add(singletonKey);
      hasAMR ||= candidate.kind === "amr";
    }
  }
  return hasUsername && hasAMR;
}

function validSAMLAttributeRules(rules: readonly unknown[]): boolean {
  if (rules.length < 1 || rules.length > 64) return false;
  const scalarNames = new Set<string>();
  const profiles = new Set<string>();
  let hasUsername = false;
  let hasGroups = false;
  let scalarCount = 0;
  let profileCount = 0;
  for (const candidate of rules) {
    if (
      !isRecord(candidate) ||
      !hasExactKeys(
        candidate,
        ["kind", "attributeName", "attributeNameFormat", "required"],
        ["profileField"],
      ) ||
      !["scalar", "profile", "groups"].includes(String(candidate.kind)) ||
      !validUTF8Text(candidate.attributeName, 1, 512) ||
      !validUTF8Text(candidate.attributeNameFormat, 1, 512) ||
      !validXMLText(candidate.attributeName) ||
      !validXMLText(candidate.attributeNameFormat) ||
      typeof candidate.required !== "boolean"
    ) {
      return false;
    }
    if (candidate.kind === "profile") {
      profileCount += 1;
      if (profileCount > 16) return false;
      if (
        !isProfileField(candidate.profileField) ||
        profiles.has(candidate.profileField)
      )
        return false;
      profiles.add(candidate.profileField);
      hasUsername ||= candidate.profileField === "username";
    } else if (
      candidate.profileField !== undefined &&
      candidate.profileField !== null
    ) {
      return false;
    } else if (candidate.kind === "scalar") {
      scalarCount += 1;
      if (scalarCount > 32) return false;
      if (scalarNames.has(candidate.attributeName)) return false;
      scalarNames.add(candidate.attributeName);
    } else {
      if (hasGroups) return false;
      hasGroups = true;
    }
  }
  return hasUsername;
}

function validAssurancePolicy(
  value: Record<string, unknown>,
  projection: boolean,
): boolean {
  if (value.kind !== "oidc" && value.kind !== "saml") return false;
  const required = projection
    ? [
        "tenantId",
        "providerId",
        "kind",
        "providerVersion",
        "assurancePolicyRevision",
        "rules",
      ]
    : ["kind", "rules", "reason"];
  if (
    !hasExactKeys(value, required) ||
    !Array.isArray(value.rules) ||
    value.rules.length > (value.kind === "saml" ? 64 : 128)
  ) {
    return false;
  }
  const ids = new Set<string>();
  const samlExactValues = new Set<string>();
  return value.rules.every((candidate) => {
    const requiredKeys =
      value.kind === "oidc"
        ? [
            "ruleId",
            "enabled",
            "level",
            "exactValue",
            "requiredValues",
            "maximumAuthenticationAgeSeconds",
          ]
        : [
            "ruleId",
            "enabled",
            "level",
            "exactValue",
            "maximumAuthenticationAgeSeconds",
          ];
    if (
      !isRecord(candidate) ||
      !hasExactKeys(candidate, requiredKeys) ||
      typeof candidate.ruleId !== "string" ||
      !isUuidV7(candidate.ruleId) ||
      ids.has(candidate.ruleId) ||
      typeof candidate.enabled !== "boolean" ||
      (candidate.level !== "mfa" && candidate.level !== "phishing_resistant") ||
      typeof candidate.maximumAuthenticationAgeSeconds !== "number" ||
      !Number.isInteger(candidate.maximumAuthenticationAgeSeconds) ||
      candidate.maximumAuthenticationAgeSeconds < 60 ||
      candidate.maximumAuthenticationAgeSeconds > 2_592_000
    ) {
      return false;
    }
    ids.add(candidate.ruleId);
    if (value.kind === "saml") {
      if (
        !validFederatedEvidenceText(candidate.exactValue, 1, 4_096) ||
        !validXMLText(candidate.exactValue) ||
        samlExactValues.has(candidate.exactValue)
      ) {
        return false;
      }
      samlExactValues.add(candidate.exactValue);
      return true;
    }
    if (
      candidate.exactValue !== null &&
      !validFederatedEvidenceText(candidate.exactValue, 1, 4_096)
    ) {
      return false;
    }
    if (
      !Array.isArray(candidate.requiredValues) ||
      candidate.requiredValues.length > 128 ||
      candidate.requiredValues.some(
        (entry) => !validFederatedEvidenceText(entry, 1, 4_096),
      ) ||
      new Set(candidate.requiredValues).size !== candidate.requiredValues.length
    ) {
      return false;
    }
    return candidate.exactValue !== null || candidate.requiredValues.length > 0;
  });
}

function hasExactKeys(
  value: Record<string, unknown>,
  required: readonly string[],
  optional: readonly string[] = [],
): boolean {
  const keys = Object.keys(value);
  const allowed = new Set([...required, ...optional]);
  return (
    required.every((key) => Object.hasOwn(value, key)) &&
    keys.every((key) => allowed.has(key))
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isUuidV7(value: string): boolean {
  return uuidV7Pattern.test(value);
}

function validClaimName(value: unknown): value is string {
  return (
    typeof value === "string" &&
    /^[\x21-\x25\x27-\x5b\x5d-\x7e]+$/.test(value) &&
    value.length <= 256
  );
}

function validTextWithLength(
  value: unknown,
  minimum: number,
  maximum: number,
  length: (value: string) => number,
): value is string {
  return (
    typeof value === "string" &&
    value.trim() === value &&
    length(value) >= minimum &&
    length(value) <= maximum &&
    !Array.from(value).some((character) => {
      const codePoint = character.codePointAt(0) ?? 0;
      return codePoint <= 0x1f || (codePoint >= 0x7f && codePoint <= 0x9f);
    })
  );
}

function validCodePointText(
  value: unknown,
  minimum: number,
  maximum: number,
): value is string {
  return validTextWithLength(
    value,
    minimum,
    maximum,
    (candidate) => Array.from(candidate).length,
  );
}

function validFederatedEvidenceText(
  value: unknown,
  minimumCodePoints: number,
  maximumCodePoints: number,
): value is string {
  return (
    validCodePointText(value, minimumCodePoints, maximumCodePoints) &&
    utf8Length(value) <= 4_096 &&
    !forbiddenFederatedEvidenceDirectionalControl.test(value)
  );
}

function validUTF8Text(
  value: unknown,
  minimum: number,
  maximum: number,
): value is string {
  return validTextWithLength(value, minimum, maximum, utf8Length);
}

function validOIDCClientID(value: unknown): value is string {
  return (
    validUTF8Text(value, 1, 512) && !/[\p{Cc}\p{White_Space}]/u.test(value)
  );
}

function assertFederationConfiguration(
  input:
    | TenantFederationAuthProviderCreateRequest
    | TenantFederationAuthProviderUpdateRequest,
): void {
  if (input.kind === "oidc") {
    if (!validOIDCClientID(input.configuration.clientId)) {
      throw new PhaseTwoApiError(
        "The OIDC client ID must stay within 512 UTF-8 bytes and contain no whitespace or control characters.",
      );
    }
    if (
      !validOIDCExtraScopes(
        input.configuration.extraScopes,
        input.configuration.allowRefreshToken,
      )
    ) {
      throw new PhaseTwoApiError(
        "OIDC allows at most 31 exact extra scopes and requires offline_access exactly when refresh rotation is enabled.",
      );
    }
    return;
  }
  const configuration = input.configuration;
  if (
    !validXMLText(configuration.expectedEntityId) ||
    !Array.isArray(configuration.requestedAuthnContexts) ||
    configuration.requestedAuthnContexts.some(
      (value) => !validXMLText(value),
    ) ||
    (configuration.subjectAttributeName !== null &&
      !validXMLText(configuration.subjectAttributeName)) ||
    (configuration.subjectAttributeNameFormat !== null &&
      !validXMLText(configuration.subjectAttributeNameFormat))
  ) {
    throw new PhaseTwoApiError(
      "The SAML configuration contains text that XML 1.0 cannot represent.",
    );
  }
}

function validOIDCExtraScopes(
  value: unknown,
  allowRefreshToken: unknown,
): value is string[] {
  if (
    !Array.isArray(value) ||
    value.length > 31 ||
    typeof allowRefreshToken !== "boolean"
  ) {
    return false;
  }
  const scopes = new Set<string>();
  for (const scope of value) {
    if (
      typeof scope !== "string" ||
      scope === "openid" ||
      !/^[\x21\x23-\x5b\x5d-\x7e]{1,128}$/u.test(scope) ||
      scopes.has(scope)
    ) {
      return false;
    }
    scopes.add(scope);
  }
  return scopes.has("offline_access") === allowRefreshToken;
}

function validXMLText(value: unknown): value is string {
  return (
    typeof value === "string" &&
    Array.from(value).every((character) => {
      const codePoint = character.codePointAt(0) ?? 0;
      return (
        codePoint === 0x09 ||
        codePoint === 0x0a ||
        codePoint === 0x0d ||
        (codePoint >= 0x20 && codePoint <= 0xd7ff) ||
        (codePoint >= 0xe000 && codePoint <= 0xfffd) ||
        (codePoint >= 0x10000 && codePoint <= 0x10ffff)
      );
    })
  );
}

function isProfileField(
  value: unknown,
): value is "username" | "email" | "display_name" {
  return value === "username" || value === "email" || value === "display_name";
}

function cloneMappingPolicy(
  value: TenantFederationMappingPolicy,
): TenantFederationMappingPolicy {
  const rules = value.rules.map((rule) => ({
    ...rule,
    roleIds: [...rule.roleIds],
  }));
  return value.kind === "oidc"
    ? {
        ...value,
        oidcClaimRules: value.oidcClaimRules.map((rule) => ({ ...rule })),
        rules,
      }
    : {
        ...value,
        rules,
        samlAttributeRules: value.samlAttributeRules.map((rule) => ({
          ...rule,
        })),
      };
}

function cloneAssurancePolicy(
  value: TenantFederationAssurancePolicy,
): TenantFederationAssurancePolicy {
  return value.kind === "oidc"
    ? {
        ...value,
        rules: value.rules.map((rule) => ({
          ...rule,
          requiredValues: [...rule.requiredValues],
        })),
      }
    : { ...value, rules: value.rules.map((rule) => ({ ...rule })) };
}

function assertTenantSAMLMetadataInput(
  input: TenantSamlMetadataReplaceRequestWritable,
): void {
  assertReason(input.reason);
  const keys = Object.keys(input).toSorted().join(",");
  if (input.source === "url") {
    if (
      keys !== "approveTrustReset,metadataUrl,reason,source" ||
      typeof input.approveTrustReset !== "boolean" ||
      !isHttpsFetchUrl(input.metadataUrl) ||
      utf8Length(input.metadataUrl) > 4096
    ) {
      throw new PhaseTwoApiError("The SAML metadata request is invalid.");
    }
    return;
  }
  if (
    input.source !== "xml" ||
    keys !== "approveTrustReset,metadataXml,reason,source" ||
    typeof input.approveTrustReset !== "boolean" ||
    utf8Length(input.metadataXml) < 1 ||
    utf8Length(input.metadataXml) > 524_288
  ) {
    throw new PhaseTwoApiError("The SAML metadata request is invalid.");
  }
}

function assertProviderProjection(
  provider: TenantFederationAuthProvider,
  tenantId: string,
  providerId?: string,
): void {
  assertNoRawMaterial(provider);
  assertSummaryProjection(provider, tenantId);
  if (providerId !== undefined && provider.id !== providerId) {
    throw projectionError();
  }
  for (const revision of [
    provider.configurationRevision,
    provider.securityRevision,
    provider.planRevision,
    provider.assurancePolicyRevision,
  ]) {
    if (!Number.isSafeInteger(revision) || revision < 1)
      throw projectionError();
  }
  if (provider.kind === "oidc") {
    if (
      !isHttpsUrl(provider.configuration.issuer) ||
      !isHttpsUrl(provider.configuration.redirectUri) ||
      !isHttpsUrl(provider.configuration.postLogoutRedirectUri) ||
      !validOIDCClientID(provider.configuration.clientId) ||
      !validOIDCExtraScopes(
        provider.configuration.extraScopes,
        provider.configuration.allowRefreshToken,
      ) ||
      !Number.isSafeInteger(provider.configuration.clientSecretRevision) ||
      provider.configuration.clientSecretRevision < 1 ||
      (provider.configuration.clientSecretPresent &&
        provider.configuration.clientSecretRevision < 2)
    ) {
      throw projectionError();
    }
  } else if (
    provider.kind !== "saml" ||
    !isHttpsUrl(provider.configuration.spEntityId) ||
    !isHttpsUrl(provider.configuration.acsUrl) ||
    !validXMLText(provider.configuration.expectedEntityId) ||
    provider.configuration.expectedEntityId ===
      provider.configuration.spEntityId ||
    provider.configuration.requestedAuthnContexts.some(
      (value) => !validXMLText(value),
    ) ||
    typeof provider.configuration.singleLogoutConfigured !== "boolean" ||
    typeof provider.configuration.spKeyPresent !== "boolean" ||
    !Number.isSafeInteger(provider.configuration.spKeyRevision) ||
    provider.configuration.spKeyRevision < 1 ||
    (provider.configuration.spKeyPresent &&
      provider.configuration.spKeyRevision < 2) ||
    !Number.isSafeInteger(provider.configuration.metadataRevision) ||
    provider.configuration.metadataRevision < 1
  ) {
    throw projectionError();
  }
}

function assertSummaryProjection(
  provider: TenantFederationAuthProviderSummary,
  tenantId: string,
): void {
  assertNoRawMaterial(provider);
  assertUuid(provider.id);
  assertUuid(provider.tenantId);
  assertUuid(provider.binding.id);
  if (
    provider.tenantId !== tenantId ||
    !["oidc", "saml"].includes(provider.kind) ||
    !Number.isInteger(provider.version) ||
    provider.version < 1 ||
    !Number.isSafeInteger(provider.binding.version) ||
    provider.binding.version < 1 ||
    typeof provider.enabled !== "boolean" ||
    provider.enabled !== provider.binding.enabled ||
    typeof provider.configured !== "boolean" ||
    typeof provider.key !== "string" ||
    typeof provider.displayName !== "string" ||
    !validInstant(provider.createdAt) ||
    !validInstant(provider.updatedAt) ||
    (provider.archivedAt !== null && !validInstant(provider.archivedAt))
  ) {
    throw projectionError();
  }
}

function assertNoRawMaterial(value: unknown): void {
  if (Array.isArray(value)) {
    value.forEach(assertNoRawMaterial);
    return;
  }
  if (typeof value !== "object" || value === null) return;
  for (const [key, child] of Object.entries(value)) {
    const normalizedKey = key.replaceAll(/[^A-Za-z0-9]/g, "").toLowerCase();
    if (forbiddenProjectionKeys.has(normalizedKey)) throw projectionError();
    assertNoRawMaterial(child);
  }
}

function cloneSummary(
  provider: TenantFederationAuthProviderSummary,
): TenantFederationAuthProviderSummary {
  return { ...provider, binding: { ...provider.binding } };
}

function cloneProvider(
  provider: TenantFederationAuthProvider,
): TenantFederationAuthProvider {
  if (provider.kind === "oidc") {
    return {
      ...provider,
      binding: { ...provider.binding },
      configuration: {
        ...provider.configuration,
        extraScopes: [...provider.configuration.extraScopes],
      },
    };
  }
  return {
    ...provider,
    binding: { ...provider.binding },
    configuration: {
      ...provider.configuration,
      requestedAuthnContexts: [
        ...provider.configuration.requestedAuthnContexts,
      ],
    },
  };
}

function assertNoStore(response: Response): void {
  if (response.headers.get("Cache-Control") !== "no-store") {
    throw new PhaseTwoApiError(
      "The tenant federation response was not marked no-store.",
      response.status,
    );
  }
}

function assertLocation(
  location: string | null,
  tenantId: string,
  providerId: string,
): string {
  if (!location) throw projectionError();
  let parsed: URL;
  try {
    parsed = new URL(location, globalThis.location.origin);
  } catch {
    throw projectionError();
  }
  if (
    parsed.origin !== globalThis.location.origin ||
    parsed.search !== "" ||
    parsed.hash !== "" ||
    parsed.pathname !==
      `/api/v1/tenants/${tenantId}/federated-auth-providers/${providerId}`
  ) {
    throw projectionError();
  }
  return location;
}

function assertMutationHeaders(
  csrfToken: string,
  idempotencyKey?: string,
): void {
  if (!csrfToken || csrfToken.length > 128 || csrfToken.includes(",")) {
    throw new PhaseTwoApiError("The session mutation proof is invalid.");
  }
  if (
    idempotencyKey !== undefined &&
    (!/^[A-Za-z0-9._~-]{16,128}$/.test(idempotencyKey) ||
      idempotencyKey.includes(","))
  ) {
    throw new PhaseTwoApiError("The idempotency key is invalid.");
  }
}

function assertReason(reason: string): void {
  const characters = Array.from(reason);
  if (
    reason.trim() !== reason ||
    characters.length < 1 ||
    characters.length > 500 ||
    characters.some((character) => {
      const codePoint = character.codePointAt(0) ?? 0;
      return codePoint <= 0x1f || (codePoint >= 0x7f && codePoint <= 0x9f);
    })
  ) {
    throw new PhaseTwoApiError("A bounded audit reason is required.");
  }
}

function assertEtag(etag: string): number {
  const match = etagPattern.exec(etag);
  const value = match ? Number(match[1]) : Number.NaN;
  if (!Number.isInteger(value) || value < 1 || value > 2_147_483_647) {
    throw projectionError();
  }
  return value;
}

function assertUuid(value: string): void {
  if (!uuidV7Pattern.test(value)) throw projectionError();
}

function isHttpsUrl(value: string): boolean {
  if (value.length < 1 || value.length > 4096 || value.trim() !== value) {
    return false;
  }
  try {
    const parsed = new URL(value);
    return (
      parsed.protocol === "https:" &&
      parsed.username === "" &&
      parsed.password === "" &&
      parsed.hash === ""
    );
  } catch {
    return false;
  }
}

function isHttpsFetchUrl(value: string): boolean {
  if (!isHttpsUrl(value)) return false;
  const parsed = new URL(value);
  return parsed.search === "";
}

function validInstant(value: string): boolean {
  return parseRfc3339Instant(value) !== undefined;
}

function utf8Length(value: string): number {
  return new TextEncoder().encode(value).length;
}

function projectionError(): PhaseTwoApiError {
  return new PhaseTwoApiError(
    "The API response did not match the requested tenant federation projection.",
  );
}

function apiError(error: unknown, response?: Response): PhaseTwoApiError {
  const problem =
    typeof error === "object" && error !== null
      ? (error as { detail?: unknown; title?: unknown })
      : undefined;
  const message =
    typeof problem?.detail === "string"
      ? problem.detail
      : typeof problem?.title === "string"
        ? problem.title
        : "The tenant federation request failed.";
  return new PhaseTwoApiError(message.slice(0, 320), response?.status);
}
