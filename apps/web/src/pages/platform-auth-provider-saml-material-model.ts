import {
  isPlatformHttpsUri,
  isPlatformUnicodeScalarText,
  platformUtf8ByteLength,
} from "../lib/platform-auth-provider-validation";

const maximumMetadataXmlBytes = 512 * 1024;
const maximumPrivateKeyDerBytes = 128 * 1024 - 16;
const maximumCertificateDerBytes = 64 * 1024;
const maximumCertificateCount = 8;
const canonicalBase64Pattern =
  /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u;

export type PlatformSamlMetadataSource = "url" | "xml";

export interface PlatformSamlSpKeyMaterial {
  certificates: string[];
  privateKeyPkcs8: string;
}

export type PlatformSamlSpKeyParseResult =
  | { errors: readonly string[]; material: null }
  | { errors: readonly []; material: PlatformSamlSpKeyMaterial };

export function validatePlatformSamlMetadataMaterial(
  source: PlatformSamlMetadataSource,
  value: string,
): string | null {
  if (source === "url") {
    return isPlatformHttpsUri(value, true, 4096)
      ? null
      : "Enter a canonical HTTPS metadata URL without credentials or a fragment.";
  }
  if (value.trim() === "") return "Enter the IdP metadata XML document.";
  if (
    !isPlatformUnicodeScalarText(value) ||
    value.includes(String.fromCharCode(0))
  ) {
    return "Metadata XML must be valid UTF-8 text without NUL bytes.";
  }
  if (
    value.length > maximumMetadataXmlBytes ||
    platformUtf8ByteLength(value) > maximumMetadataXmlBytes
  ) {
    return "Keep metadata XML within 512 KiB of UTF-8 text.";
  }
  return null;
}

export function parsePlatformSamlSpKeyMaterial(
  privateKeyPem: string,
  certificateBundlePem: string,
): PlatformSamlSpKeyParseResult {
  const errors: string[] = [];
  const privateKeyPkcs8 = parsePrivateKeyPem(privateKeyPem);
  if (privateKeyPkcs8 === null) {
    errors.push(
      "Enter exactly one unencrypted PKCS#8 PEM block labeled PRIVATE KEY, within 131056 DER bytes.",
    );
  }

  const certificates = parseCertificateBundle(certificateBundlePem);
  if (certificates === null) {
    errors.push(
      "Enter one to eight distinct X.509 PEM blocks labeled CERTIFICATE, each within 64 KiB of DER.",
    );
  }

  if (privateKeyPkcs8 === null || certificates === null) {
    return { errors, material: null };
  }
  return {
    errors: [],
    material: { certificates, privateKeyPkcs8 },
  };
}

function parseCertificateBundle(value: string): string[] | null {
  const normalized = normalizePem(value);
  if (normalized === "") return null;
  const blockPattern =
    /-----BEGIN CERTIFICATE-----\n([A-Za-z0-9+/=\n]+)\n-----END CERTIFICATE-----/gu;
  const certificates: string[] = [];
  let consumed = 0;
  for (const match of normalized.matchAll(blockPattern)) {
    const index = match.index;
    if (normalized.slice(consumed, index).trim() !== "") return null;
    const body = match[1];
    if (body === undefined) return null;
    const certificate = parseCanonicalBase64(body, maximumCertificateDerBytes);
    if (certificate === null) return null;
    certificates.push(certificate);
    if (certificates.length > maximumCertificateCount) return null;
    consumed = index + match[0].length;
  }
  if (
    certificates.length === 0 ||
    normalized.slice(consumed).trim() !== "" ||
    new Set(certificates).size !== certificates.length
  ) {
    return null;
  }
  return certificates;
}

function parsePrivateKeyPem(value: string): string | null {
  const normalized = normalizePem(value);
  const match =
    /^-----BEGIN PRIVATE KEY-----\n([A-Za-z0-9+/=\n]+)\n-----END PRIVATE KEY-----$/u.exec(
      normalized,
    );
  return match?.[1]
    ? parseCanonicalBase64(match[1], maximumPrivateKeyDerBytes)
    : null;
}

function parseCanonicalBase64(
  value: string,
  maximumDecodedBytes: number,
): string | null {
  const compact = value.replaceAll("\n", "");
  const maximumEncodedLength = Math.ceil(maximumDecodedBytes / 3) * 4;
  if (
    compact === "" ||
    compact.length > maximumEncodedLength ||
    !canonicalBase64Pattern.test(compact)
  ) {
    return null;
  }
  try {
    const binary = atob(compact);
    return binary.length <= maximumDecodedBytes && btoa(binary) === compact
      ? compact
      : null;
  } catch {
    return null;
  }
}

function normalizePem(value: string): string {
  return value.replaceAll("\r\n", "\n").replaceAll("\r", "\n").trim();
}
