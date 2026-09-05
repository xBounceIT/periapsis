import { afterEach, describe, expect, it, vi } from "vitest";

import type {
  TenantFederationAuthProvider,
  TenantFederationAuthProviderCreateRequest,
  TenantFederationAuthProviderUpdateRequest,
  TenantFederationAssurancePolicy,
  TenantFederationAssurancePolicyReplaceRequest,
  TenantFederationMappingPolicy,
  TenantFederationMappingPolicyReplaceRequest,
  TenantSamlMetadataReplaceRequestWritable,
} from "@periapsis/contracts";

import {
  assertTenantFederationAssurancePolicyReplacement,
  assertTenantFederationMappingPolicyReplacement,
  tenantFederationApi,
} from "./tenant-federation-api";

const tenantId = "0198c97d-cf4f-7000-8000-000000000010";
const providerId = "0198c97d-cf4f-7000-8000-000000000088";
const bindingId = "0198c97d-cf4f-7000-8000-000000000089";
const mappingRuleId = "0198c97d-cf4f-7000-8000-000000000090";
const assuranceRuleId = "0198c97d-cf4f-7000-8000-000000000091";
const securityGroupId = "0198c97d-cf4f-7000-8000-000000000092";
const roleId = "0198c97d-cf4f-7000-8000-000000000093";

function createInput(): TenantFederationAuthProviderCreateRequest {
  return {
    kind: "oidc",
    key: "corporate_oidc",
    loginKey: "corporate_oidc",
    displayName: "Corporate OIDC",
    description: "",
    jitMode: "disabled",
    noMatchPolicy: "deny",
    reason: "approved provider",
    configuration: {
      issuer: "https://idp.example.test",
      clientId: "periapsis",
      postLogoutRedirectUri: `${globalThis.location.origin}/signed-out`,
      extraScopes: [],
      allowRefreshToken: false,
      useUserInfo: false,
    },
  };
}

afterEach(() => vi.restoreAllMocks());

describe("tenant federation OIDC input boundaries", () => {
  it("rejects an OIDC client ID above 512 UTF-8 bytes before transport", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    const create = createInput();
    if (create.kind !== "oidc") throw new Error("expected OIDC fixture");
    create.configuration.clientId = "é".repeat(257);
    const update: TenantFederationAuthProviderUpdateRequest = {
      kind: "oidc",
      displayName: "Updated Corporate OIDC",
      description: create.description,
      enabled: false,
      jitMode: create.jitMode,
      noMatchPolicy: create.noMatchPolicy,
      reason: create.reason,
      configuration: { ...create.configuration },
    };

    await expect(
      tenantFederationApi.create(
        "csrf-memory-only",
        tenantId,
        "federation-create-0001",
        create,
      ),
    ).rejects.toThrow(/512 UTF-8 bytes/u);
    await expect(
      tenantFederationApi.update(
        "csrf-memory-only",
        tenantId,
        providerId,
        '"v4"',
        update,
      ),
    ).rejects.toThrow(/512 UTF-8 bytes/u);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it.each(["acme\u00a0prod", "acme\u2003prod"])(
    "rejects Unicode whitespace in an OIDC client ID before transport",
    async (clientId) => {
      const fetchMock = vi.fn();
      vi.stubGlobal("fetch", fetchMock);
      const create = createInput();
      if (create.kind !== "oidc") throw new Error("expected OIDC fixture");
      create.configuration.clientId = clientId;

      await expect(
        tenantFederationApi.create(
          "csrf-memory-only",
          tenantId,
          "federation-create-0001",
          create,
        ),
      ).rejects.toThrow(/512 UTF-8 bytes/u);
      expect(fetchMock).not.toHaveBeenCalled();
    },
  );

  it.each([
    {
      label: "refresh without offline_access",
      allowRefreshToken: true,
      extraScopes: ["email"],
    },
    {
      label: "offline_access without refresh",
      allowRefreshToken: false,
      extraScopes: ["offline_access"],
    },
    {
      label: "32 extra scopes",
      allowRefreshToken: false,
      extraScopes: Array.from({ length: 32 }, (_, index) => `scope_${index}`),
    },
  ])(
    "rejects $label before transport",
    async ({ allowRefreshToken, extraScopes }) => {
      const fetchMock = vi.fn();
      vi.stubGlobal("fetch", fetchMock);
      const create = createInput();
      if (create.kind !== "oidc") throw new Error("expected OIDC fixture");
      create.configuration.allowRefreshToken = allowRefreshToken;
      create.configuration.extraScopes = extraScopes;

      await expect(
        tenantFederationApi.create(
          "csrf-memory-only",
          tenantId,
          "federation-create-0001",
          create,
        ),
      ).rejects.toThrow(/offline_access|31 exact extra scopes/u);
      expect(fetchMock).not.toHaveBeenCalled();
    },
  );

  it("rejects XML 1.0 noncharacters in SAML configuration before transport", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    const create: TenantFederationAuthProviderCreateRequest = {
      kind: "saml",
      key: "corporate_saml",
      loginKey: "corporate_saml",
      displayName: "Corporate SAML",
      description: "",
      jitMode: "disabled",
      noMatchPolicy: "deny",
      reason: "approved provider",
      configuration: {
        expectedEntityId: "https://idp.example.test/entity\ufffe",
        redirectSignatureAlgorithm:
          "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
        signaturePolicy: "signed_assertion",
        encryptionPolicy: "disabled",
        requestedAuthnContexts: [
          "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
        ],
        subjectSource: "persistent_nameid",
        subjectAttributeName: null,
        subjectAttributeNameFormat: null,
        clockSkewSeconds: 120,
        maxAuthenticationAgeSeconds: 3_600,
      },
    };

    await expect(
      tenantFederationApi.create(
        "csrf-memory-only",
        tenantId,
        "federation-create-0001",
        create,
      ),
    ).rejects.toThrow(/XML 1\.0/u);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("rejects a SAML projection whose IdP entity ID equals the derived SP entity ID", async () => {
    const provider = tenantSamlProviderFixture();
    provider.configuration.expectedEntityId = provider.configuration.spEntityId;
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(JSON.stringify(provider), {
          status: 200,
          headers: {
            "Cache-Control": "no-store",
            "Content-Type": "application/json",
            ETag: '"v4"',
          },
        }),
      ),
    );

    await expect(tenantFederationApi.get(tenantId, providerId)).rejects.toThrow(
      /projection/i,
    );
  });
});

describe("tenant federation SAML material API", () => {
  it("counts audit-reason Unicode code points instead of UTF-16 code units", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValue(samlMutationResponse('"v5"', "3"));
    vi.stubGlobal("fetch", fetchMock);
    const call = (reason: string) =>
      tenantFederationApi.replaceSamlMetadata(
        "csrf-memory-only",
        tenantId,
        providerId,
        '"v4"',
        {
          source: "url",
          metadataUrl: "https://idp.example.test/metadata",
          approveTrustReset: false,
          reason,
        },
      );

    await expect(call("😀".repeat(500))).resolves.toEqual({
      etag: '"v5"',
      materialRevision: 3,
    });
    await expect(call("😀".repeat(501))).rejects.toThrow(
      /bounded audit reason/u,
    );
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("sends exact write-only metadata choice and validates the bodyless receipt", async () => {
    const requests: Request[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (input instanceof Request) requests.push(input);
        return samlMutationResponse('"v5"', "3");
      }),
    );

    await expect(
      tenantFederationApi.replaceSamlMetadata(
        "csrf-memory-only",
        tenantId,
        providerId,
        '"v4"',
        {
          source: "url",
          metadataUrl: "https://idp.example.test/metadata",
          approveTrustReset: true,
          reason: "verified out of band",
        },
      ),
    ).resolves.toEqual({ etag: '"v5"', materialRevision: 3 });
    const request = requests[0];
    if (!request) throw new Error("generated client did not issue a request");
    expect(request.method).toBe("PUT");
    expect(request.cache).toBe("no-store");
    expect(new URL(request.url).pathname).toBe(
      `/api/v1/tenants/${tenantId}/federated-auth-providers/${providerId}/saml/metadata`,
    );
    expect(request.headers.get("If-Match")).toBe('"v4"');
    expect(request.headers.get("X-CSRF-Token")).toBe("csrf-memory-only");
    expect(await request.json()).toEqual({
      source: "url",
      metadataUrl: "https://idp.example.test/metadata",
      approveTrustReset: true,
      reason: "verified out of band",
    });
  });

  it("requests server generation and clearing with reason only", async () => {
    const requests: Request[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (input instanceof Request) requests.push(input);
        return samlMutationResponse('"v5"', "2");
      }),
    );
    await tenantFederationApi.replaceSamlSpCredential(
      "csrf-memory-only",
      tenantId,
      providerId,
      '"v4"',
      "generate approved credential",
    );
    await tenantFederationApi.clearSamlSpCredential(
      "csrf-memory-only",
      tenantId,
      providerId,
      '"v4"',
      "retire approved credential",
    );

    expect(requests).toHaveLength(2);
    expect(requests.map((request) => request.method)).toEqual([
      "PUT",
      "DELETE",
    ]);
    expect(await requests[0]!.json()).toEqual({
      reason: "generate approved credential",
    });
    expect(await requests[1]!.json()).toEqual({
      reason: "retire approved credential",
    });
  });

  it("rejects overlapping or injected metadata material before transport", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    const valid: TenantSamlMetadataReplaceRequestWritable = {
      source: "xml",
      metadataXml: "<EntityDescriptor/>",
      approveTrustReset: false,
      reason: "ambiguous",
    };
    const injected = {
      ...valid,
      metadataUrl: "https://idp.example.test/metadata",
    };
    await expect(
      tenantFederationApi.replaceSamlMetadata(
        "csrf-memory-only",
        tenantId,
        providerId,
        '"v4"',
        injected,
      ),
    ).rejects.toBeInstanceOf(Error);
    await expect(
      tenantFederationApi.replaceSamlMetadata(
        "csrf-memory-only",
        tenantId,
        providerId,
        '"v4"',
        {
          source: "url",
          metadataUrl: "https://idp.example.test/metadata?tenant=acme",
          approveTrustReset: false,
          reason: "query URL must fail before transport",
        },
      ),
    ).rejects.toBeInstanceOf(Error);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it.each([
    { etag: '"v4"', revision: "2", label: "stale ETag" },
    { etag: '"v5"', revision: "02", label: "noncanonical revision" },
    { etag: '"v5"', revision: "2147483648", label: "oversize revision" },
    { etag: '"v5"', revision: null, label: "missing revision" },
  ])("fails closed on $label", async ({ etag, revision }) => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(samlMutationResponse(etag, revision)),
    );
    await expect(
      tenantFederationApi.replaceSamlSpCredential(
        "csrf-memory-only",
        tenantId,
        providerId,
        '"v4"',
        "generate approved credential",
      ),
    ).rejects.toBeInstanceOf(Error);
  });
});

describe("tenant federation policy API", () => {
  it("accepts and clones an exact OIDC mapping readback", async () => {
    const projection = oidcMappingPolicy();
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValue(
          policyResponse(projection, "X-Periapsis-Mapping-Revision", "2"),
        ),
    );

    const result = await tenantFederationApi.getMappingPolicy(
      tenantId,
      providerId,
      { kind: "oidc", useUserInfo: false },
    );
    expect(result).toEqual({
      etag: '"v4"',
      mappingRevision: 2,
      value: projection,
    });
    result.value.rules[0]?.roleIds.push("0198c97d-cf4f-7000-8000-000000000094");
    expect(projection.rules[0]?.roleIds).toEqual([roleId]);
  });

  it("accepts astral mapping and assurance values at the 4096-byte boundary", async () => {
    const mapping = oidcMappingPolicy();
    mapping.rules[0]!.matcherValue = "😀".repeat(1_024);
    const samlAssurance = samlAssurancePolicy();
    samlAssurance.rules[0]!.exactValue = "🚀".repeat(1_024);
    const oidcAssurance = oidcAssurancePolicy();
    oidcAssurance.rules[0]!.exactValue = "🛡️";
    oidcAssurance.rules[0]!.requiredValues = ["🔐".repeat(1_024)];
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValueOnce(
          policyResponse(mapping, "X-Periapsis-Mapping-Revision", "2"),
        )
        .mockResolvedValueOnce(
          policyResponse(
            samlAssurance,
            "X-Periapsis-Assurance-Policy-Revision",
            "3",
          ),
        )
        .mockResolvedValueOnce(
          policyResponse(
            oidcAssurance,
            "X-Periapsis-Assurance-Policy-Revision",
            "3",
          ),
        ),
    );

    await expect(
      tenantFederationApi.getMappingPolicy(tenantId, providerId, {
        kind: "oidc",
        useUserInfo: false,
      }),
    ).resolves.toMatchObject({ value: mapping });
    await expect(
      tenantFederationApi.getAssurancePolicy(tenantId, providerId),
    ).resolves.toMatchObject({ value: samlAssurance });
    await expect(
      tenantFederationApi.getAssurancePolicy(tenantId, providerId),
    ).resolves.toMatchObject({ value: oidcAssurance });
  });

  it("rejects mapping and assurance values above their code-point or UTF-8 bounds", async () => {
    const mapping = oidcMappingPolicy();
    mapping.rules[0]!.matcherValue = "😀".repeat(1_025);
    const assurance = samlAssurancePolicy();
    assurance.rules[0]!.exactValue = "🚀".repeat(1_025);
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValueOnce(
          policyResponse(mapping, "X-Periapsis-Mapping-Revision", "2"),
        )
        .mockResolvedValueOnce(
          policyResponse(
            assurance,
            "X-Periapsis-Assurance-Policy-Revision",
            "3",
          ),
        ),
    );

    await expect(
      tenantFederationApi.getMappingPolicy(tenantId, providerId, {
        kind: "oidc",
        useUserInfo: false,
      }),
    ).rejects.toBeInstanceOf(Error);
    await expect(
      tenantFederationApi.getAssurancePolicy(tenantId, providerId),
    ).rejects.toBeInstanceOf(Error);
  });

  it.each([
    {
      label: "unknown top-level material",
      mutate: (value: TenantFederationMappingPolicy) => {
        Reflect.set(value, "rawMetadata", "<EntityDescriptor/>");
      },
    },
    {
      label: "non-UUIDv7 role target",
      mutate: (value: TenantFederationMappingPolicy) => {
        Reflect.set(value.rules[0]!, "roleIds", [
          "0198c97d-cf4f-4000-8000-000000000093",
        ]);
      },
    },
    {
      label: "non-boolean mapping state",
      mutate: (value: TenantFederationMappingPolicy) => {
        Reflect.set(value.rules[0]!, "enabled", "true");
      },
    },
  ])("rejects hostile mapping readback with $label", async ({ mutate }) => {
    const projection = oidcMappingPolicy();
    mutate(projection);
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValue(
          policyResponse(projection, "X-Periapsis-Mapping-Revision", "2"),
        ),
    );

    await expect(
      tenantFederationApi.getMappingPolicy(tenantId, providerId, {
        kind: "oidc",
        useUserInfo: false,
      }),
    ).rejects.toBeInstanceOf(Error);
  });

  it("rejects kind-drifted assurance readback", async () => {
    const projection = samlAssurancePolicy();
    Reflect.set(projection.rules[0]!, "requiredValues", ["otp"]);
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValue(
          policyResponse(
            projection,
            "X-Periapsis-Assurance-Policy-Revision",
            "3",
          ),
        ),
    );

    await expect(
      tenantFederationApi.getAssurancePolicy(tenantId, providerId),
    ).rejects.toBeInstanceOf(Error);
  });

  it("does not send malformed editor mapping state", async () => {
    const input = oidcMappingReplacement();
    Reflect.set(input.rules[0]!, "enabled", "true");
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    await expect(
      tenantFederationApi.replaceMappingPolicy(
        "csrf-memory-only",
        tenantId,
        providerId,
        '"v4"',
        input,
        { kind: "oidc", useUserInfo: false },
      ),
    ).rejects.toBeInstanceOf(Error);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("couples UserInfo enablement exactly to UserInfo extraction before transport", async () => {
    const input = oidcMappingReplacement();
    if (input.kind !== "oidc") throw new Error("expected OIDC policy");
    expect(() =>
      assertTenantFederationMappingPolicyReplacement(input, {
        kind: "oidc",
        useUserInfo: false,
      }),
    ).not.toThrow();
    expect(() =>
      assertTenantFederationMappingPolicyReplacement(input, {
        kind: "oidc",
        useUserInfo: true,
      }),
    ).toThrow(/UserInfo must be enabled exactly/u);

    input.oidcClaimRules.push({
      source: "userinfo",
      kind: "scalar",
      claimName: "department",
      profileField: null,
      required: false,
    });
    expect(() =>
      assertTenantFederationMappingPolicyReplacement(input, {
        kind: "oidc",
        useUserInfo: true,
      }),
    ).not.toThrow();
    expect(() =>
      assertTenantFederationMappingPolicyReplacement(input, {
        kind: "oidc",
        useUserInfo: false,
      }),
    ).toThrow(/UserInfo must be enabled exactly/u);

    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    await expect(
      tenantFederationApi.replaceMappingPolicy(
        "csrf-memory-only",
        tenantId,
        providerId,
        '"v4"',
        input,
        { kind: "oidc", useUserInfo: false },
      ),
    ).rejects.toThrow(/UserInfo must be enabled exactly/u);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("enforces the OIDC scalar extraction limit per source", () => {
    const input = oidcMappingReplacement();
    if (input.kind !== "oidc") throw new Error("expected OIDC policy");
    input.oidcClaimRules = [
      {
        source: "id_token",
        kind: "profile",
        claimName: "preferred_username",
        profileField: "username",
        required: true,
      },
      {
        source: "id_token",
        kind: "amr",
        claimName: "amr",
        profileField: null,
        required: false,
      },
      ...Array.from({ length: 16 }, (_, index) => ({
        source: "id_token" as const,
        kind: "scalar" as const,
        claimName: `claim_${index}`,
        profileField: null,
        required: false,
      })),
    ];
    expect(() =>
      assertTenantFederationMappingPolicyReplacement(input),
    ).not.toThrow();
    input.oidcClaimRules.push({
      source: "id_token",
      kind: "scalar",
      claimName: "claim_16",
      profileField: null,
      required: false,
    });
    expect(() => assertTenantFederationMappingPolicyReplacement(input)).toThrow(
      /mapping policy/u,
    );
  });

  it("allows at most one OIDC groups extractor per source", () => {
    const input = oidcMappingReplacement();
    if (input.kind !== "oidc") throw new Error("expected OIDC policy");
    input.oidcClaimRules.push({
      source: "id_token",
      kind: "groups",
      claimName: "groups",
      profileField: null,
      required: false,
    });
    expect(() =>
      assertTenantFederationMappingPolicyReplacement(input),
    ).not.toThrow();

    input.oidcClaimRules.push({
      source: "id_token",
      kind: "groups",
      claimName: "roles",
      profileField: null,
      required: false,
    });
    expect(() => assertTenantFederationMappingPolicyReplacement(input)).toThrow(
      /mapping policy/u,
    );
  });

  it.each([
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
  ])(
    "rejects reserved OIDC security claim %s as profile evidence",
    (claimName) => {
      const input = oidcMappingReplacement();
      if (input.kind !== "oidc") throw new Error("expected OIDC policy");
      input.oidcClaimRules[0]!.claimName = claimName;
      expect(() =>
        assertTenantFederationMappingPolicyReplacement(input),
      ).toThrow(/mapping policy/u);
    },
  );

  it("enforces SAML scalar extraction and XML 1.0 boundaries", () => {
    const input = samlMappingReplacement(32);
    expect(() =>
      assertTenantFederationMappingPolicyReplacement(input),
    ).not.toThrow();
    input.samlAttributeRules.push({
      kind: "scalar",
      attributeName: "attribute_32",
      attributeNameFormat: "urn:example:format",
      profileField: null,
      required: false,
    });
    expect(() => assertTenantFederationMappingPolicyReplacement(input)).toThrow(
      /mapping policy/u,
    );

    const invalidXML = samlMappingReplacement(1);
    invalidXML.samlAttributeRules[0]!.attributeName += "\uffff";
    expect(() =>
      assertTenantFederationMappingPolicyReplacement(invalidXML),
    ).toThrow(/mapping policy/u);
  });

  it("accepts 64 SAML assurance rules and rejects 65 or XML noncharacters", () => {
    const input = samlAssuranceReplacement(64);
    expect(() =>
      assertTenantFederationAssurancePolicyReplacement(input),
    ).not.toThrow();
    input.rules.push(samlAssuranceRule(64));
    expect(() =>
      assertTenantFederationAssurancePolicyReplacement(input),
    ).toThrow(/assurance policy/u);

    const invalidXML = samlAssuranceReplacement(1);
    invalidXML.rules[0]!.exactValue += "\ufffe";
    expect(() =>
      assertTenantFederationAssurancePolicyReplacement(invalidXML),
    ).toThrow(/assurance policy/u);

    const duplicate = samlAssuranceReplacement(2);
    duplicate.rules[1]!.exactValue = duplicate.rules[0]!.exactValue;
    duplicate.rules[1]!.enabled = false;
    expect(() =>
      assertTenantFederationAssurancePolicyReplacement(duplicate),
    ).toThrow(/assurance policy/u);
  });

  it("rejects directional controls from mapping and assurance evidence", () => {
    const mapping = oidcMappingReplacement();
    mapping.rules[0]!.matcherValue = "incident\u202emanager";
    expect(() =>
      assertTenantFederationMappingPolicyReplacement(mapping),
    ).toThrow(/mapping policy/u);

    const oidcAssurance = oidcAssuranceReplacement();
    oidcAssurance.rules[0]!.requiredValues = ["otp\u2066override"];
    expect(() =>
      assertTenantFederationAssurancePolicyReplacement(oidcAssurance),
    ).toThrow(/assurance policy/u);

    const samlAssurance = samlAssuranceReplacement(1);
    samlAssurance.rules[0]!.exactValue += "\u200f";
    expect(() =>
      assertTenantFederationAssurancePolicyReplacement(samlAssurance),
    ).toThrow(/assurance policy/u);
  });
});

function samlMutationResponse(etag: string, revision: string | null): Response {
  const headers: Record<string, string> = {
    "Cache-Control": "no-store",
    ETag: etag,
  };
  if (revision !== null) {
    headers["X-Periapsis-SAML-Material-Revision"] = revision;
  }
  return new Response(null, { status: 204, headers });
}

function tenantSamlProviderFixture(): Extract<
  TenantFederationAuthProvider,
  { kind: "saml" }
> {
  return {
    archivedAt: null,
    assurancePolicyRevision: 1,
    binding: {
      enabled: false,
      id: bindingId,
      loginKey: "workforce",
      updatedAt: "2026-08-30T19:00:00Z",
      version: 4,
    },
    configuration: {
      acsUrl: "https://soc.example.com/api/v1/auth/federated/saml/acs",
      clockSkewSeconds: 120,
      encryptionPolicy: "disabled",
      expectedEntityId: "https://id.example.com/saml/metadata",
      maxAuthenticationAgeSeconds: 28_800,
      metadataRevision: 2,
      redirectSignatureAlgorithm:
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
      requestedAuthnContexts: [
        "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
      ],
      signaturePolicy: "both",
      singleLogoutConfigured: false,
      spEntityId:
        "https://soc.example.com/api/v1/auth/federated/saml/acme/workforce/metadata",
      spKeyPresent: true,
      spKeyRevision: 2,
      subjectAttributeName: null,
      subjectAttributeNameFormat: null,
      subjectSource: "persistent_nameid",
    },
    configurationRevision: 2,
    configured: true,
    createdAt: "2026-08-30T18:00:00Z",
    description: "Tenant workforce SAML",
    displayName: "Workforce SAML",
    enabled: false,
    id: providerId,
    jitMode: "disabled",
    key: "workforce_saml",
    kind: "saml",
    noMatchPolicy: "deny",
    planRevision: 1,
    securityRevision: 2,
    tenantId,
    updatedAt: "2026-08-30T19:00:00Z",
    version: 4,
  };
}

function policyResponse(
  body: unknown,
  revisionHeader: string,
  revision: string,
): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: {
      "Cache-Control": "no-store",
      "Content-Type": "application/json",
      ETag: '"v4"',
      [revisionHeader]: revision,
    },
  });
}

function oidcMappingPolicy(): Extract<
  TenantFederationMappingPolicy,
  { kind: "oidc" }
> {
  return {
    tenantId,
    providerId,
    kind: "oidc",
    providerVersion: 4,
    mappingRevision: 2,
    oidcClaimRules: [
      {
        source: "id_token",
        kind: "profile",
        claimName: "preferred_username",
        profileField: "username",
        required: true,
      },
      {
        source: "id_token",
        kind: "amr",
        claimName: "amr",
        profileField: null,
        required: false,
      },
    ],
    rules: [
      {
        ruleId: mappingRuleId,
        priority: 10,
        matcherKind: "scalar_equals",
        claimName: "roles",
        matcherValue: "incident_manager",
        reconciliationMode: "authoritative",
        tenantSecurityGroupId: securityGroupId,
        roleIds: [roleId],
        operatorTeamId: null,
        operatorTeamAssignmentEpochId: null,
        enabled: true,
      },
    ],
  };
}

function oidcMappingReplacement(): TenantFederationMappingPolicyReplaceRequest {
  const projection = oidcMappingPolicy();
  return {
    kind: "oidc",
    oidcClaimRules: projection.oidcClaimRules,
    rules: projection.rules,
    reason: "replace exact tenant mapping policy",
  };
}

function samlAssurancePolicy(): Extract<
  TenantFederationAssurancePolicy,
  { kind: "saml" }
> {
  return {
    tenantId,
    providerId,
    kind: "saml",
    providerVersion: 4,
    assurancePolicyRevision: 3,
    rules: [
      {
        ruleId: assuranceRuleId,
        enabled: true,
        level: "mfa",
        exactValue: "urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken",
        maximumAuthenticationAgeSeconds: 900,
      },
    ],
  };
}

function oidcAssurancePolicy(): Extract<
  TenantFederationAssurancePolicy,
  { kind: "oidc" }
> {
  return {
    tenantId,
    providerId,
    kind: "oidc",
    providerVersion: 4,
    assurancePolicyRevision: 3,
    rules: [
      {
        ruleId: assuranceRuleId,
        enabled: true,
        level: "mfa",
        exactValue: "urn:example:acr:mfa",
        requiredValues: ["otp"],
        maximumAuthenticationAgeSeconds: 900,
      },
    ],
  };
}

function oidcAssuranceReplacement(): Extract<
  TenantFederationAssurancePolicyReplaceRequest,
  { kind: "oidc" }
> {
  return {
    kind: "oidc",
    reason: "Replace exact upstream assurance evidence",
    rules: [
      {
        ruleId: assuranceRuleId,
        enabled: true,
        level: "mfa",
        exactValue: "urn:example:acr:mfa",
        requiredValues: ["otp"],
        maximumAuthenticationAgeSeconds: 900,
      },
    ],
  };
}

function samlMappingReplacement(
  scalarCount: number,
): Extract<TenantFederationMappingPolicyReplaceRequest, { kind: "saml" }> {
  return {
    kind: "saml",
    samlAttributeRules: [
      {
        kind: "profile",
        attributeName: "uid",
        attributeNameFormat: "urn:example:format",
        profileField: "username",
        required: true,
      },
      ...Array.from({ length: scalarCount }, (_, index) => ({
        kind: "scalar" as const,
        attributeName: `attribute_${index}`,
        attributeNameFormat: "urn:example:format",
        profileField: null,
        required: false,
      })),
    ],
    rules: [],
    reason: "replace exact tenant mapping policy",
  };
}

function samlAssuranceRule(index: number) {
  return {
    ruleId: indexedUuid(index + 0x100),
    enabled: true,
    level: "mfa" as const,
    exactValue: `urn:example:authn:${index}`,
    maximumAuthenticationAgeSeconds: 900,
  };
}

function samlAssuranceReplacement(
  ruleCount: number,
): Extract<TenantFederationAssurancePolicyReplaceRequest, { kind: "saml" }> {
  return {
    kind: "saml",
    rules: Array.from({ length: ruleCount }, (_, index) =>
      samlAssuranceRule(index),
    ),
    reason: "replace exact tenant assurance policy",
  };
}

function indexedUuid(index: number): string {
  return `0198c97d-cf4f-7000-8000-${index.toString(16).padStart(12, "0")}`;
}
