import type {
  PlatformAuthProviderCreateInput,
  PlatformAuthProviderUpdateInput,
  PlatformAuthProviderView,
} from "../lib/phase-two-types";
import {
  isPlatformAuditReasonHeader,
  isCanonicalPlatformText,
  isPlatformAbsoluteUri,
  isPlatformHttpsUri,
  isPlatformOidcClientId,
  isPlatformOidcExtraScopes,
  isPlatformProviderKey,
  isPlatformUnicodeScalarText,
  isPlatformXml10Text,
  platformUtf8ByteLength,
  type PlatformAuthProviderDeploymentEndpoints,
} from "../lib/platform-auth-provider-validation";
import {
  createLdapProviderDraft,
  validateLdapProviderDraft,
  type LdapProviderDraft,
} from "./ldap-provider-model";

export {
  derivePlatformAuthProviderDeploymentEndpoints,
  type PlatformAuthProviderDeploymentEndpoints,
} from "../lib/platform-auth-provider-validation";

export const platformAuthProviderRouteDescriptor = {
  label: "Platform IdPs",
  path: "/platform/identity-providers",
  permissions: [
    "platform.identity_provider.read",
    "platform.identity_binding.read",
    "platform.identity_account.read",
  ] as const,
};

type OidcCreateInput = Extract<
  PlatformAuthProviderCreateInput,
  { kind: "oidc" }
>;
type SamlCreateInput = Extract<
  PlatformAuthProviderCreateInput,
  { kind: "saml" }
>;
type LdapCreateInput = Extract<
  PlatformAuthProviderCreateInput,
  { kind: "ldap" }
>;

export type PlatformAuthProviderKind = PlatformAuthProviderCreateInput["kind"];
export type PlatformSamlSignatureAlgorithm =
  SamlCreateInput["configuration"]["redirectSignatureAlgorithm"];
export type PlatformSamlSignaturePolicy =
  SamlCreateInput["configuration"]["signaturePolicy"];
export type PlatformSamlSubjectSource =
  SamlCreateInput["configuration"]["subjectSource"];

interface CommonProviderDraft {
  auditReason: string;
  description: string;
  displayName: string;
  key: string;
}

export interface PlatformOidcProviderDraft extends CommonProviderDraft {
  allowRefreshToken: boolean;
  clientId: string;
  extraScopes: string;
  issuer: string;
  kind: "oidc";
  useUserInfo: boolean;
}

export interface PlatformSamlProviderDraft extends CommonProviderDraft {
  clockSkewSeconds: string;
  expectedEntityId: string;
  kind: "saml";
  maxAuthenticationAgeSeconds: string;
  redirectSignatureAlgorithm: PlatformSamlSignatureAlgorithm;
  requestedAuthnContexts: string;
  signaturePolicy: PlatformSamlSignaturePolicy;
  subjectAttributeName: string;
  subjectAttributeNameFormat: string;
  subjectSource: PlatformSamlSubjectSource;
}

export interface PlatformLdapProviderDraft extends LdapProviderDraft {
  auditReason: string;
  kind: "ldap";
}

export type PlatformAuthProviderDraft =
  | PlatformLdapProviderDraft
  | PlatformOidcProviderDraft
  | PlatformSamlProviderDraft;

export interface PlatformAuthProviderMetadataDraft {
  auditReason: string;
  description: string;
  displayName: string;
  key: string;
}

export const platformSamlSignatureAlgorithms: readonly {
  label: string;
  value: PlatformSamlSignatureAlgorithm;
}[] = [
  {
    label: "RSA SHA-256",
    value: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
  },
  {
    label: "RSA SHA-384",
    value: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384",
  },
  {
    label: "RSA SHA-512",
    value: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
  },
  {
    label: "ECDSA SHA-256",
    value: "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
  },
  {
    label: "ECDSA SHA-384",
    value: "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384",
  },
  {
    label: "ECDSA SHA-512",
    value: "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512",
  },
];

export function createPlatformAuthProviderDraft(
  kind: PlatformAuthProviderKind,
): PlatformAuthProviderDraft {
  const common = {
    auditReason: "",
    description: "",
    displayName: "",
    key: "",
  };
  if (kind === "oidc") {
    return {
      ...common,
      allowRefreshToken: false,
      clientId: "",
      extraScopes: "",
      issuer: "",
      kind: "oidc",
      useUserInfo: false,
    };
  }
  if (kind === "ldap") {
    const ldap = createLdapProviderDraft("active_directory");
    return {
      ...ldap,
      auditReason: "",
      configuration: {
        ...ldap.configuration,
        jitMode: "existing_identity",
      },
      kind: "ldap",
    };
  }
  return {
    ...common,
    clockSkewSeconds: "120",
    expectedEntityId: "",
    kind: "saml",
    maxAuthenticationAgeSeconds: "28800",
    redirectSignatureAlgorithm:
      "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
    requestedAuthnContexts: "",
    signaturePolicy: "signed_assertion",
    subjectAttributeName: "",
    subjectAttributeNameFormat: "",
    subjectSource: "persistent_nameid",
  };
}

export function validatePlatformAuthProviderDraft(
  draft: PlatformAuthProviderDraft,
  deploymentEndpoints: PlatformAuthProviderDeploymentEndpoints | null,
): readonly string[] {
  if (draft.kind === "ldap") {
    const errors = [...validateLdapProviderDraft(draft, "platform_global")];
    const reasonError = validatePlatformAuthProviderAuditReason(
      draft.auditReason,
    );
    if (reasonError) errors.push(reasonError);
    return errors;
  }
  const errors: string[] = [];
  validateMetadata(errors, draft);
  const reasonError = validatePlatformAuthProviderAuditReason(
    draft.auditReason,
  );
  if (reasonError) errors.push(reasonError);
  validateDeploymentEndpoints(errors, draft.kind, deploymentEndpoints);

  if (draft.kind === "oidc") {
    validateHttpsUri(errors, draft.issuer, "Issuer", false, 2048);
    if (!isPlatformOidcClientId(draft.clientId)) {
      errors.push(
        "Client ID must contain 1–512 canonical characters, stay within 512 UTF-8 bytes, and contain no whitespace or control characters.",
      );
    }
    const scopes = parseSpaceSeparatedValues(draft.extraScopes);
    if (!isPlatformOidcExtraScopes(scopes, draft.allowRefreshToken)) {
      errors.push(
        "Additional scopes must be unique valid scope names, exclude openid, total at most 31, and include offline_access exactly when refresh-token handling is enabled.",
      );
    }
    return errors;
  }

  validateUri(errors, draft.expectedEntityId, "Expected IdP entity ID", 2048);
  if (
    deploymentEndpoints !== null &&
    draft.expectedEntityId === deploymentEndpoints.samlSpEntityId
  ) {
    errors.push(
      "Expected IdP entity ID must differ from the deployment-managed SP entity ID.",
    );
  }
  const contexts = parseLineSeparatedValues(draft.requestedAuthnContexts);
  if (
    contexts.length < 1 ||
    contexts.length > 32 ||
    new Set(contexts).size !== contexts.length ||
    contexts.some((context) => !isPlatformAbsoluteUri(context, 2048))
  ) {
    errors.push("Enter 1–32 unique AuthnContext URIs, one per line.");
  }
  const clockSkew = parseBoundedInteger(draft.clockSkewSeconds, 0, 300);
  if (clockSkew === null) {
    errors.push("Clock skew must be a whole number from 0 to 300 seconds.");
  }
  const maximumAge = parseBoundedInteger(
    draft.maxAuthenticationAgeSeconds,
    60,
    86_400,
  );
  if (maximumAge === null) {
    errors.push(
      "Maximum authentication age must be a whole number from 60 to 86400 seconds.",
    );
  }
  if (draft.subjectSource === "immutable_attribute") {
    validateText(
      errors,
      draft.subjectAttributeName,
      "Subject attribute name",
      1,
      512,
      512,
    );
    validateUri(
      errors,
      draft.subjectAttributeNameFormat,
      "Subject attribute name format",
      512,
    );
  }
  const xmlValues = [draft.expectedEntityId, ...contexts];
  if (draft.subjectSource === "immutable_attribute") {
    xmlValues.push(
      draft.subjectAttributeName,
      draft.subjectAttributeNameFormat,
    );
  }
  if (xmlValues.some((value) => !isPlatformXml10Text(value))) {
    errors.push("SAML text must contain only XML 1.0 characters.");
  }
  return errors;
}

export function withPlatformOidcRefreshToken(
  draft: PlatformOidcProviderDraft,
  allowRefreshToken: boolean,
): PlatformOidcProviderDraft {
  const extraScopes = parseSpaceSeparatedValues(draft.extraScopes).filter(
    (scope) => scope !== "offline_access",
  );
  if (allowRefreshToken) extraScopes.push("offline_access");
  return {
    ...draft,
    allowRefreshToken,
    extraScopes: extraScopes.join(" "),
  };
}

export function toPlatformAuthProviderCreateInput(
  draft: PlatformAuthProviderDraft,
  deploymentEndpoints: PlatformAuthProviderDeploymentEndpoints | null,
): PlatformAuthProviderCreateInput {
  if (draft.kind === "ldap") {
    const input: LdapCreateInput = {
      configuration: {
        ...draft.configuration,
        jitMode: "existing_identity",
        noMatchPolicy: "deny",
      },
      description: draft.description,
      displayName: draft.displayName,
      endpoints: draft.endpoints.map((endpoint) => ({ ...endpoint })),
      key: draft.key,
      kind: "ldap",
    };
    return input;
  }
  if (deploymentEndpoints === null) {
    throw new Error("Deployment-managed provider endpoints are unavailable.");
  }
  if (draft.kind === "oidc") {
    const input: OidcCreateInput = {
      configuration: {
        allowRefreshToken: draft.allowRefreshToken,
        clientId: draft.clientId,
        extraScopes: parseSpaceSeparatedValues(draft.extraScopes),
        issuer: draft.issuer,
        postLogoutRedirectUri: deploymentEndpoints.oidcPostLogoutRedirectUri,
        redirectUri: deploymentEndpoints.oidcRedirectUri,
        tenantRedirectUri: deploymentEndpoints.oidcTenantRedirectUri,
        useUserInfo: draft.useUserInfo,
      },
      description: draft.description,
      displayName: draft.displayName,
      key: draft.key,
      kind: "oidc",
    };
    return input;
  }

  const commonConfiguration = {
    acsUrl: deploymentEndpoints.samlAcsUrl,
    clockSkewNanoseconds: Number(draft.clockSkewSeconds) * 1_000_000_000,
    encryptionPolicy: "disabled" as const,
    expectedEntityId: draft.expectedEntityId,
    maxAuthenticationAgeNanoseconds:
      Number(draft.maxAuthenticationAgeSeconds) * 1_000_000_000,
    redirectSignatureAlgorithm: draft.redirectSignatureAlgorithm,
    requestedAuthnContexts: parseLineSeparatedValues(
      draft.requestedAuthnContexts,
    ),
    signaturePolicy: draft.signaturePolicy,
    spEntityId: deploymentEndpoints.samlSpEntityId,
  };
  const input: SamlCreateInput = {
    configuration:
      draft.subjectSource === "immutable_attribute"
        ? {
            ...commonConfiguration,
            subjectAttributeName: draft.subjectAttributeName,
            subjectAttributeNameFormat: draft.subjectAttributeNameFormat,
            subjectSource: "immutable_attribute",
          }
        : {
            ...commonConfiguration,
            subjectSource: "persistent_nameid",
          },
    description: draft.description,
    displayName: draft.displayName,
    key: draft.key,
    kind: "saml",
  };
  return input;
}

function validateDeploymentEndpoints(
  errors: string[],
  kind: PlatformAuthProviderKind,
  deploymentEndpoints: PlatformAuthProviderDeploymentEndpoints | null,
): void {
  if (deploymentEndpoints === null) {
    errors.push(
      "Deployment-managed identity-provider endpoints are unavailable. Reload this page from the configured public app origin.",
    );
    return;
  }
  const valid =
    kind === "oidc"
      ? isPlatformHttpsUri(deploymentEndpoints.oidcRedirectUri, false) &&
        isPlatformHttpsUri(deploymentEndpoints.oidcTenantRedirectUri, false) &&
        isPlatformHttpsUri(deploymentEndpoints.oidcPostLogoutRedirectUri, false)
      : isPlatformHttpsUri(deploymentEndpoints.samlSpEntityId, false) &&
        isPlatformHttpsUri(deploymentEndpoints.samlAcsUrl, false);
  if (!valid) {
    errors.push(
      "Platform identity providers require deployment-managed endpoints on the configured HTTPS public app origin.",
    );
  }
}

export function metadataDraftFromProvider(
  provider: PlatformAuthProviderView,
): PlatformAuthProviderMetadataDraft {
  return {
    auditReason: "",
    description: provider.description,
    displayName: provider.displayName,
    key: provider.key,
  };
}

export function validatePlatformAuthProviderMetadataDraft(
  draft: PlatformAuthProviderMetadataDraft,
): readonly string[] {
  const errors: string[] = [];
  validateMetadata(errors, draft);
  const reasonError = validatePlatformAuthProviderAuditReason(
    draft.auditReason,
  );
  if (reasonError) errors.push(reasonError);
  return errors;
}

export function toPlatformAuthProviderUpdateInput(
  draft: PlatformAuthProviderMetadataDraft,
  expectedVersion: number,
): PlatformAuthProviderUpdateInput {
  return {
    description: draft.description,
    displayName: draft.displayName,
    expectedVersion,
    key: draft.key,
  };
}

export function validatePlatformAuthProviderAuditReason(
  reason: string,
): string | null {
  if (reason.trim() === "") return "Enter a non-secret audit reason.";
  if (reason.trim() !== reason) {
    return "Remove leading or trailing whitespace from the audit reason.";
  }
  if (!isPlatformAuditReasonHeader(reason)) {
    return "Use visible ASCII characters only and remove comma-folding characters from the audit reason.";
  }
  if (platformUtf8ByteLength(reason) > 2048) {
    return "Keep the audit reason within 2048 UTF-8 bytes.";
  }
  return null;
}

export function validatePlatformOidcClientSecret(
  secret: string,
): string | null {
  if (secret.length === 0) return "Enter the replacement client secret.";
  if (
    !isPlatformUnicodeScalarText(secret) ||
    secret.includes(String.fromCharCode(0))
  ) {
    return "The client secret must be valid UTF-8 text without NUL bytes.";
  }
  if (platformUtf8ByteLength(secret) > 8192) {
    return "Keep the client secret within 8192 UTF-8 bytes.";
  }
  return null;
}

function validateMetadata(
  errors: string[],
  draft: Pick<
    PlatformAuthProviderMetadataDraft,
    "description" | "displayName" | "key"
  >,
): void {
  if (!isPlatformProviderKey(draft.key)) {
    errors.push(
      "Key must be 3–64 lowercase characters and start with a letter.",
    );
  }
  validateText(errors, draft.displayName, "Display name", 1, 120);
  validateText(errors, draft.description, "Description", 0, 1000);
}

function validateText(
  errors: string[],
  value: string,
  label: string,
  minimumLength: number,
  maximumLength: number,
  maximumUtf8Bytes?: number,
): void {
  if (
    !isCanonicalPlatformText(
      value,
      minimumLength,
      maximumLength,
      maximumUtf8Bytes,
    )
  ) {
    errors.push(
      `${label} must be ${minimumLength}–${maximumLength} characters, use canonical text without control characters, and stay within its UTF-8 limit.`,
    );
  }
}

function validateHttpsUri(
  errors: string[],
  value: string,
  label: string,
  allowQuery: boolean,
  maximumUtf8Bytes = 4096,
): void {
  if (!isPlatformHttpsUri(value, allowQuery, maximumUtf8Bytes)) {
    errors.push(
      `${label} must be an absolute HTTPS URI without credentials or a fragment and stay within ${maximumUtf8Bytes} UTF-8 bytes.`,
    );
  }
}

function validateUri(
  errors: string[],
  value: string,
  label: string,
  maximumUtf8Bytes: number,
): void {
  if (!isPlatformAbsoluteUri(value, maximumUtf8Bytes)) {
    errors.push(
      `${label} must be a canonical absolute URI within ${maximumUtf8Bytes} UTF-8 bytes.`,
    );
  }
}

function parseSpaceSeparatedValues(value: string): string[] {
  return value.trim() === "" ? [] : value.trim().split(/\s+/u);
}

function parseLineSeparatedValues(value: string): string[] {
  return value
    .split(/\r?\n/u)
    .map((item) => item.trim())
    .filter((item) => item !== "");
}

function parseBoundedInteger(
  value: string,
  minimum: number,
  maximum: number,
): number | null {
  if (!/^(?:0|[1-9]\d*)$/u.test(value)) return null;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed >= minimum && parsed <= maximum
    ? parsed
    : null;
}
