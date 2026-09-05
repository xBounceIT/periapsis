const forbiddenPlatformTextCodePoint = /[\p{Cc}\p{Cf}]/u;
const forbiddenPlatformOidcClientIdCodePoint = /[\p{Cc}\p{Cf}\p{White_Space}]/u;
const platformUriWhitespace = /\s/u;
const platformOAuthScopePattern = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/;
const platformProviderKeyPattern = /^[a-z][a-z0-9_-]{2,63}$/;
const malformedPercentEscape = /%(?![0-9A-Fa-f]{2})/u;
const absoluteUriSchemePattern = /^[a-z][a-z0-9+.-]*:/;
const canonicalDnsHostPattern =
  /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/;
const canonicalPortPattern = /^[1-9][0-9]{0,4}$/;
const numericIpv4HostPattern = /^[0-9.]+$/;
const utf8 = new TextEncoder();

export interface PlatformAuthProviderDeploymentEndpoints {
  readonly oidcPostLogoutRedirectUri: string;
  readonly oidcRedirectUri: string;
  readonly oidcTenantRedirectUri: string;
  readonly samlAcsUrl: string;
  readonly samlSpEntityId: string;
}

const platformOidcCallbackPath = "/api/v1/auth/platform/oidc/callback";
const tenantOidcCallbackPath = "/api/v1/auth/federated/oidc/callback";
const platformOidcPostLogoutPath = "/signed-out";
const platformSamlAcsPath = "/api/v1/auth/platform/saml/acs";

export function derivePlatformAuthProviderDeploymentEndpoints(
  publicOrigin: string | null | undefined,
  providerKey?: string,
): PlatformAuthProviderDeploymentEndpoints | null {
  if (!publicOrigin) return null;
  try {
    const parsed = new URL(publicOrigin);
    if (
      parsed.protocol !== "https:" ||
      parsed.origin !== publicOrigin ||
      parsed.username !== "" ||
      parsed.password !== "" ||
      parsed.pathname !== "/" ||
      parsed.search !== "" ||
      parsed.hash !== ""
    ) {
      return null;
    }
    return {
      oidcPostLogoutRedirectUri: `${publicOrigin}${platformOidcPostLogoutPath}`,
      oidcRedirectUri: `${publicOrigin}${platformOidcCallbackPath}`,
      oidcTenantRedirectUri: `${publicOrigin}${tenantOidcCallbackPath}`,
      samlAcsUrl: `${publicOrigin}${platformSamlAcsPath}`,
      samlSpEntityId: platformProviderKeyPattern.test(providerKey ?? "")
        ? `${publicOrigin}/api/v1/auth/platform/saml/${providerKey}/metadata`
        : "",
    };
  } catch {
    return null;
  }
}

export function isCanonicalPlatformText(
  value: unknown,
  minimumCodePoints: number,
  maximumCodePoints: number,
  maximumUtf8Bytes?: number,
): value is string {
  if (
    typeof value !== "string" ||
    value.trim() !== value ||
    !isPlatformUnicodeScalarText(value) ||
    forbiddenPlatformTextCodePoint.test(value)
  ) {
    return false;
  }
  const codePoints = boundedCodePointLength(value, maximumCodePoints);
  return (
    codePoints >= minimumCodePoints &&
    (minimumCodePoints === 0 || /\S/u.test(value)) &&
    (maximumUtf8Bytes === undefined ||
      (value.length <= maximumUtf8Bytes &&
        platformUtf8ByteLength(value) <= maximumUtf8Bytes))
  );
}

export function isPlatformAbsoluteUri(
  value: unknown,
  maximumUtf8Bytes: number,
): value is string {
  if (
    typeof value !== "string" ||
    value === "" ||
    value.trim() !== value ||
    value.length > maximumUtf8Bytes ||
    !isPlatformUnicodeScalarText(value) ||
    platformUtf8ByteLength(value) > maximumUtf8Bytes ||
    forbiddenPlatformTextCodePoint.test(value) ||
    platformUriWhitespace.test(value) ||
    value.includes("\\") ||
    malformedPercentEscape.test(value) ||
    !absoluteUriSchemePattern.test(value)
  ) {
    return false;
  }
  try {
    const parsed = new URL(value);
    return parsed.protocol !== "";
  } catch {
    return false;
  }
}

export function isPlatformHttpsUri(
  value: unknown,
  allowQuery: boolean,
  maximumUtf8Bytes = 4096,
): value is string {
  if (
    typeof value !== "string" ||
    value.length < 9 ||
    value.length > maximumUtf8Bytes ||
    !value.startsWith("https://") ||
    value.trim() !== value ||
    !isPlatformUnicodeScalarText(value) ||
    platformUtf8ByteLength(value) > maximumUtf8Bytes ||
    forbiddenPlatformTextCodePoint.test(value) ||
    platformUriWhitespace.test(value) ||
    value.includes("\\") ||
    malformedPercentEscape.test(value) ||
    value.includes("#") ||
    (!allowQuery && value.includes("?"))
  ) {
    return false;
  }
  try {
    const parsed = new URL(value);
    return (
      parsed.protocol === "https:" &&
      parsed.host !== "" &&
      parsed.username === "" &&
      parsed.password === "" &&
      parsed.hash === "" &&
      (allowQuery || parsed.search === "") &&
      isCanonicalHttpsAuthority(value, parsed)
    );
  } catch {
    return false;
  }
}

function isCanonicalHttpsAuthority(value: string, parsed: URL): boolean {
  const authority = /^https:\/\/([^/?#]+)/.exec(value)?.[1];
  if (!authority || authority.includes("@")) return false;

  let hostValue: string;
  let portValue: string | undefined;
  if (authority.startsWith("[")) {
    const match = /^\[([0-9a-f:.]+)\](?::([1-9][0-9]{0,4}))?$/.exec(authority);
    if (!match) return false;
    hostValue = match[1] ?? "";
    portValue = match[2];
    if (`[${hostValue}]` !== parsed.hostname) return false;
  } else {
    const separator = authority.lastIndexOf(":");
    if (separator >= 0) {
      if (authority.indexOf(":") !== separator) return false;
      hostValue = authority.slice(0, separator);
      portValue = authority.slice(separator + 1);
    } else {
      hostValue = authority;
    }
    if (
      hostValue !== hostValue.toLowerCase() ||
      hostValue.length > 253 ||
      parsed.hostname !== hostValue
    ) {
      return false;
    }
    if (numericIpv4HostPattern.test(hostValue)) {
      if (!/^([0-9]{1,3}\.){3}[0-9]{1,3}$/.test(hostValue)) return false;
      if (
        hostValue
          .split(".")
          .some(
            (octet) => Number(octet) > 255 || String(Number(octet)) !== octet,
          )
      ) {
        return false;
      }
    } else if (!canonicalDnsHostPattern.test(hostValue)) {
      return false;
    }
  }

  if (portValue === undefined) return true;
  return canonicalPortPattern.test(portValue) && Number(portValue) <= 65_535;
}

export function isPlatformOAuthScope(value: unknown): value is string {
  return typeof value === "string" && platformOAuthScopePattern.test(value);
}

export function isPlatformOidcClientId(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= 512 &&
    isPlatformUnicodeScalarText(value) &&
    platformUtf8ByteLength(value) <= 512 &&
    !forbiddenPlatformOidcClientIdCodePoint.test(value)
  );
}

export function isPlatformOidcExtraScopes(
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
      !isPlatformOAuthScope(scope) ||
      scope === "openid" ||
      scopes.has(scope)
    ) {
      return false;
    }
    scopes.add(scope);
  }
  return scopes.has("offline_access") === allowRefreshToken;
}

export function isPlatformXml10Text(value: unknown): value is string {
  if (typeof value !== "string" || !isPlatformUnicodeScalarText(value)) {
    return false;
  }
  for (const character of value) {
    const codePoint = character.codePointAt(0) ?? 0;
    if (
      codePoint !== 0x09 &&
      codePoint !== 0x0a &&
      codePoint !== 0x0d &&
      !(codePoint >= 0x20 && codePoint <= 0xd7ff) &&
      !(codePoint >= 0xe000 && codePoint <= 0xfffd) &&
      !(codePoint >= 0x10000 && codePoint <= 0x10ffff)
    ) {
      return false;
    }
  }
  return true;
}

export function isPlatformProviderKey(value: unknown): value is string {
  return typeof value === "string" && platformProviderKeyPattern.test(value);
}

export function isPlatformAuditReasonHeader(value: unknown): value is string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > 2048 ||
    value.trim() !== value
  ) {
    return false;
  }
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit < 0x20 || codeUnit > 0x7e || codeUnit === 0x2c) return false;
  }
  return true;
}

export function platformUtf8ByteLength(value: string): number {
  return utf8.encode(value).byteLength;
}

export function hasForbiddenPlatformTextCodePoint(value: string): boolean {
  return forbiddenPlatformTextCodePoint.test(value);
}

export function isPlatformUnicodeScalarText(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (next < 0xdc00 || next > 0xdfff) return false;
      index += 1;
    } else if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) {
      return false;
    }
  }
  return true;
}

function boundedCodePointLength(value: string, maximum: number): number {
  let length = 0;
  const codePoints = value[Symbol.iterator]();
  while (!codePoints.next().done) {
    length += 1;
    if (length > maximum) return length;
  }
  return length;
}
