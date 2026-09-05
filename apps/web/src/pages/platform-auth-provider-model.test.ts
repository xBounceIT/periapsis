import { describe, expect, it } from "vitest";

import {
  createPlatformAuthProviderDraft,
  derivePlatformAuthProviderDeploymentEndpoints,
  toPlatformAuthProviderCreateInput,
  validatePlatformAuthProviderAuditReason,
  validatePlatformAuthProviderDraft,
  validatePlatformOidcClientSecret,
  withPlatformOidcRefreshToken,
} from "./platform-auth-provider-model";
import {
  isPlatformAbsoluteUri,
  isPlatformHttpsUri,
  platformUtf8ByteLength,
} from "../lib/platform-auth-provider-validation";

const publicOrigin = "https://soc.example.com";
const deploymentEndpoints = derivePlatformAuthProviderDeploymentEndpoints(
  publicOrigin,
  "workforce_saml",
);
const issuerPrefix = "https://identity.example.com/";

function asciiIssuerWithByteLength(byteLength: number): string {
  return issuerPrefix + "a".repeat(byteLength - issuerPrefix.length);
}

function multibyteIssuerOver2048Bytes(): string {
  return (
    issuerPrefix + "é".repeat(Math.floor((2048 - issuerPrefix.length) / 2) + 1)
  );
}

if (deploymentEndpoints === null) {
  throw new Error("Expected canonical deployment endpoints.");
}

describe("platform identity-provider form model", () => {
  it("matches the protected canonical URI authority grammar", () => {
    for (const value of [
      "https://idp.example.test/issuer",
      "https://127.0.0.1:8443/issuer?tenant=one",
      "https://[2001:db8::1]/issuer",
    ]) {
      expect(isPlatformHttpsUri(value, true)).toBe(true);
    }
    for (const value of [
      "https://IDP.example.test/issuer",
      "https://idp.example.test:0443/issuer",
      "https://127.000.0.1/issuer",
      "https://[2001:0db8:0:0:0:0:0:1]/issuer",
      "https://idp_example.test/issuer",
    ]) {
      expect(isPlatformHttpsUri(value, true)).toBe(false);
    }
    expect(
      isPlatformAbsoluteUri(
        "urn:oasis:names:tc:SAML:2.0:ac:classes:Password",
        2048,
      ),
    ).toBe(true);
    expect(isPlatformAbsoluteUri("URN:example:test", 2048)).toBe(false);
    expect(isPlatformAbsoluteUri("urn:example:bad\\value", 2048)).toBe(false);
  });

  it("builds a typed non-secret OIDC create command", () => {
    const base = createPlatformAuthProviderDraft("oidc");
    if (base.kind !== "oidc") throw new Error("Expected OIDC draft.");
    const draft = {
      ...base,
      auditReason: "Stage the workforce federation coordinates",
      clientId: "periapsis-platform",
      displayName: "Workforce OIDC",
      extraScopes: "profile email",
      issuer: "https://identity.example.com",
      key: "workforce_oidc",
    };

    expect(
      validatePlatformAuthProviderDraft(draft, deploymentEndpoints),
    ).toEqual([]);
    const input = toPlatformAuthProviderCreateInput(draft, deploymentEndpoints);
    expect(input).toMatchObject({
      configuration: {
        extraScopes: ["profile", "email"],
        issuer: "https://identity.example.com",
        postLogoutRedirectUri: "https://soc.example.com/signed-out",
        redirectUri:
          "https://soc.example.com/api/v1/auth/platform/oidc/callback",
        tenantRedirectUri:
          "https://soc.example.com/api/v1/auth/federated/oidc/callback",
      },
      kind: "oidc",
    });
    expect(input).not.toHaveProperty("clientSecret");
    expect(input.configuration).not.toHaveProperty("clientSecret");
    expect(input).not.toHaveProperty("enabled");
    expect(input).not.toHaveProperty("platformLoginEnabled");
  });

  it("couples the bounded OIDC scope set to refresh-token handling", () => {
    const base = createPlatformAuthProviderDraft("oidc");
    if (base.kind !== "oidc") throw new Error("Expected OIDC draft.");
    const valid = {
      ...base,
      auditReason: "Stage bounded refresh-token handling",
      clientId: "periapsis-platform",
      displayName: "Workforce OIDC",
      extraScopes: "profile email",
      issuer: "https://identity.example.com",
      key: "workforce_oidc",
    };

    const enabled = withPlatformOidcRefreshToken(valid, true);
    expect(enabled.extraScopes).toBe("profile email offline_access");
    expect(
      validatePlatformAuthProviderDraft(enabled, deploymentEndpoints),
    ).toEqual([]);

    const disabled = withPlatformOidcRefreshToken(enabled, false);
    expect(disabled.extraScopes).toBe("profile email");
    expect(
      validatePlatformAuthProviderDraft(disabled, deploymentEndpoints),
    ).toEqual([]);

    expect(
      validatePlatformAuthProviderDraft(
        { ...valid, allowRefreshToken: true },
        deploymentEndpoints,
      ),
    ).toEqual(
      expect.arrayContaining([expect.stringMatching(/offline_access/i)]),
    );
    expect(
      validatePlatformAuthProviderDraft(
        {
          ...valid,
          extraScopes: Array.from(
            { length: 32 },
            (_, index) => `scope_${index}`,
          ).join(" "),
        },
        deploymentEndpoints,
      ),
    ).toEqual(expect.arrayContaining([expect.stringMatching(/at most 31/i)]));
  });

  it("rejects Unicode whitespace in OIDC client IDs and XML 1.0 noncharacters in SAML", () => {
    const oidc = createPlatformAuthProviderDraft("oidc");
    if (oidc.kind !== "oidc") throw new Error("Expected OIDC draft.");
    for (const clientId of ["client\u00a0id", "client\u2003id"]) {
      expect(
        validatePlatformAuthProviderDraft(
          {
            ...oidc,
            auditReason: "Stage strict OIDC identifiers",
            clientId,
            displayName: "Workforce OIDC",
            issuer: "https://identity.example.com",
            key: "workforce_oidc",
          },
          deploymentEndpoints,
        ),
      ).toEqual(expect.arrayContaining([expect.stringMatching(/Client ID/i)]));
    }

    const saml = createPlatformAuthProviderDraft("saml");
    if (saml.kind !== "saml") throw new Error("Expected SAML draft.");
    expect(
      validatePlatformAuthProviderDraft(
        {
          ...saml,
          auditReason: "Stage XML-safe SAML coordinates",
          displayName: "Workforce SAML",
          expectedEntityId: "https://idp.example.com/entity\uffff",
          key: "workforce_saml",
          requestedAuthnContexts:
            "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
        },
        deploymentEndpoints,
      ),
    ).toEqual(expect.arrayContaining([expect.stringMatching(/XML 1\.0/i)]));
  });

  it("fixes SAML create encryption to disabled and excludes SP key material", () => {
    const base = createPlatformAuthProviderDraft("saml");
    if (base.kind !== "saml") throw new Error("Expected SAML draft.");
    const draft = {
      ...base,
      auditReason: "Stage the upstream SAML trust coordinates",
      displayName: "Workforce SAML",
      expectedEntityId: "https://idp.example.com/entity",
      key: "workforce_saml",
      requestedAuthnContexts:
        "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
    };

    expect(
      validatePlatformAuthProviderDraft(draft, deploymentEndpoints),
    ).toEqual([]);
    expect(
      validatePlatformAuthProviderDraft(
        {
          ...draft,
          expectedEntityId: deploymentEndpoints.samlSpEntityId,
        },
        deploymentEndpoints,
      ),
    ).toEqual(
      expect.arrayContaining([expect.stringMatching(/differ.*SP entity/i)]),
    );
    const input = toPlatformAuthProviderCreateInput(draft, deploymentEndpoints);
    expect(input.kind).toBe("saml");
    if (input.kind !== "saml") throw new Error("Expected SAML input.");
    expect(input.configuration.encryptionPolicy).toBe("disabled");
    expect(input.configuration.spEntityId).toBe(
      "https://soc.example.com/api/v1/auth/platform/saml/workforce_saml/metadata",
    );
    expect(input.configuration.acsUrl).toBe(
      "https://soc.example.com/api/v1/auth/platform/saml/acs",
    );
    expect(input.configuration).not.toHaveProperty("spKey");
    expect(input.configuration).not.toHaveProperty("privateKey");
  });

  it("rejects header-unsafe audit reasons and invalid write-only secrets", () => {
    expect(validatePlatformAuthProviderAuditReason(" padded ")).toMatch(
      /whitespace/i,
    );
    expect(validatePlatformAuthProviderAuditReason("one,two")).toMatch(
      /comma/i,
    );
    expect(
      validatePlatformAuthProviderAuditReason("Motivazione approvata — SSO"),
    ).toMatch(/ASCII/i);
    expect(validatePlatformOidcClientSecret("")).toMatch(/enter/i);
    expect(validatePlatformOidcClientSecret("unsafe\u0000secret")).toMatch(
      /NUL/i,
    );
    expect(validatePlatformOidcClientSecret("broken-\ud800-secret")).toMatch(
      /UTF-8/i,
    );
  });

  it("rejects non-canonical and UTF-8-oversized create values before transport", () => {
    const oidc = createPlatformAuthProviderDraft("oidc");
    if (oidc.kind !== "oidc") throw new Error("Expected OIDC draft.");
    const oidcErrors = validatePlatformAuthProviderDraft(
      {
        ...oidc,
        auditReason: "Stage bounded OIDC coordinates",
        clientId: "é".repeat(257),
        displayName: "Workforce OIDC",
        issuer: " https://identity.example.com",
        key: "workforce_oidc",
      },
      deploymentEndpoints,
    );
    expect(oidcErrors).toEqual(
      expect.arrayContaining([
        expect.stringMatching(/Issuer.*HTTPS URI/i),
        expect.stringMatching(/Client ID.*UTF-8/i),
      ]),
    );

    const saml = createPlatformAuthProviderDraft("saml");
    if (saml.kind !== "saml") throw new Error("Expected SAML draft.");
    const samlErrors = validatePlatformAuthProviderDraft(
      {
        ...saml,
        auditReason: "Stage bounded SAML coordinates",
        displayName: "Workforce SAML",
        expectedEntityId: `urn:periapsis:${"a".repeat(2048)}`,
        key: "workforce_saml",
        requestedAuthnContexts: `urn:periapsis:${"b".repeat(2048)}`,
      },
      deploymentEndpoints,
    );
    expect(samlErrors).toEqual(
      expect.arrayContaining([
        expect.stringMatching(/Expected IdP entity ID.*2048 UTF-8 bytes/i),
        expect.stringMatching(/AuthnContext URIs/i),
      ]),
    );
  });

  it("enforces the issuer's 2048 UTF-8 byte limit independently of endpoint limits", () => {
    const base = createPlatformAuthProviderDraft("oidc");
    if (base.kind !== "oidc") throw new Error("Expected OIDC draft.");
    const draft = {
      ...base,
      auditReason: "Stage bounded OIDC coordinates",
      clientId: "periapsis-platform",
      displayName: "Workforce OIDC",
      key: "workforce_oidc",
    };
    const issuerAtLimit = asciiIssuerWithByteLength(2048);
    const issuerOverLimit = asciiIssuerWithByteLength(2049);
    const multibyteIssuer = multibyteIssuerOver2048Bytes();

    expect(platformUtf8ByteLength(issuerAtLimit)).toBe(2048);
    expect(platformUtf8ByteLength(issuerOverLimit)).toBe(2049);
    expect(platformUtf8ByteLength(multibyteIssuer)).toBeGreaterThan(2048);
    expect(Array.from(multibyteIssuer).length).toBeLessThan(2048);
    expect(isPlatformHttpsUri(issuerOverLimit, false, 4096)).toBe(true);
    expect(isPlatformHttpsUri(multibyteIssuer, false, 4096)).toBe(true);
    expect(
      validatePlatformAuthProviderDraft(
        { ...draft, issuer: issuerAtLimit },
        deploymentEndpoints,
      ),
    ).toEqual([]);
    for (const issuer of [issuerOverLimit, multibyteIssuer]) {
      expect(
        validatePlatformAuthProviderDraft(
          { ...draft, issuer },
          deploymentEndpoints,
        ),
      ).toEqual(
        expect.arrayContaining([
          expect.stringMatching(/Issuer.*2048 UTF-8 bytes/i),
        ]),
      );
    }
  });

  it("derives the exact platform registration endpoints from one canonical origin", () => {
    expect(deploymentEndpoints).toEqual({
      oidcPostLogoutRedirectUri: "https://soc.example.com/signed-out",
      oidcRedirectUri:
        "https://soc.example.com/api/v1/auth/platform/oidc/callback",
      oidcTenantRedirectUri:
        "https://soc.example.com/api/v1/auth/federated/oidc/callback",
      samlAcsUrl: "https://soc.example.com/api/v1/auth/platform/saml/acs",
      samlSpEntityId:
        "https://soc.example.com/api/v1/auth/platform/saml/workforce_saml/metadata",
    });
    expect(
      derivePlatformAuthProviderDeploymentEndpoints(
        "https://soc.example.com/path",
      ),
    ).toBeNull();
    expect(
      derivePlatformAuthProviderDeploymentEndpoints(
        "https://localhost:8443",
        "workforce_saml",
      ),
    ).toEqual({
      oidcPostLogoutRedirectUri: "https://localhost:8443/signed-out",
      oidcRedirectUri:
        "https://localhost:8443/api/v1/auth/platform/oidc/callback",
      oidcTenantRedirectUri:
        "https://localhost:8443/api/v1/auth/federated/oidc/callback",
      samlAcsUrl: "https://localhost:8443/api/v1/auth/platform/saml/acs",
      samlSpEntityId:
        "https://localhost:8443/api/v1/auth/platform/saml/workforce_saml/metadata",
    });
    expect(derivePlatformAuthProviderDeploymentEndpoints(undefined)).toBeNull();
  });

  it("fails closed when deployment-managed endpoints are unavailable or insecure", () => {
    const oidc = createPlatformAuthProviderDraft("oidc");
    if (oidc.kind !== "oidc") throw new Error("Expected OIDC draft.");
    const validDraft = {
      ...oidc,
      auditReason: "Stage the workforce federation coordinates",
      clientId: "periapsis-platform",
      displayName: "Workforce OIDC",
      issuer: "https://identity.example.com",
      key: "workforce_oidc",
    };

    expect(validatePlatformAuthProviderDraft(validDraft, null)).toEqual(
      expect.arrayContaining([
        expect.stringMatching(/endpoints are unavailable/i),
      ]),
    );
    const insecureEndpoints = derivePlatformAuthProviderDeploymentEndpoints(
      "http://localhost:5173",
    );
    expect(insecureEndpoints).toBeNull();
    expect(
      validatePlatformAuthProviderDraft(validDraft, insecureEndpoints),
    ).toEqual(
      expect.arrayContaining([
        expect.stringMatching(/endpoints are unavailable/i),
      ]),
    );
  });
});
