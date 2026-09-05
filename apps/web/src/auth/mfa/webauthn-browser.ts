import type {
  WebAuthnAuthenticationOptions,
  WebAuthnAuthenticationResponse,
  WebAuthnCredentialTransport,
  WebAuthnRegistrationOptions,
  WebAuthnRegistrationResponse,
} from "@periapsis/contracts";

const maximumCredentialIdBytes = 1024;
const maximumResponseBytes = 256 * 1024;
const maximumExtensionBytes = 8 * 1024;

export interface BrowserCredentials {
  create(options?: CredentialCreationOptions): Promise<Credential | null>;
  get(options?: CredentialRequestOptions): Promise<Credential | null>;
}

export async function createPasskeyResponse(
  options: WebAuthnRegistrationOptions,
  displayName: string,
  credentials: BrowserCredentials = navigator.credentials,
): Promise<WebAuthnRegistrationResponse> {
  const name = displayName.trim();
  if (name.length < 1 || name.length > 120 || /[<>\p{Cc}]/u.test(name)) {
    throw new WebAuthnBrowserError("Choose a valid passkey name.");
  }
  const publicKey = registrationOptions(options);
  const credential = await credentials.create({ publicKey });
  const response = registrationCredential(credential);
  const extensions = response.credential.getClientExtensionResults();
  let safeExtensions: unknown;
  let serializedExtensions: string;
  try {
    serializedExtensions = JSON.stringify(extensions);
    safeExtensions = JSON.parse(serializedExtensions);
  } catch {
    throw new WebAuthnBrowserError(
      "The authenticator extension result is invalid.",
    );
  }
  if (serializedExtensions.length > maximumExtensionBytes) {
    throw new WebAuthnBrowserError(
      "The authenticator extension result is too large.",
    );
  }
  if (!isRecord(safeExtensions)) {
    throw new WebAuthnBrowserError(
      "The authenticator extension result is invalid.",
    );
  }
  if (
    response.credential.rawId.byteLength +
      response.attestation.attestationObject.byteLength +
      response.attestation.clientDataJSON.byteLength +
      serializedExtensions.length >
    maximumResponseBytes
  ) {
    throw new WebAuthnBrowserError(
      "The authenticator response is outside safe bounds.",
    );
  }
  return {
    ceremonyId: options.ceremonyId,
    displayName: name,
    credential: {
      clientExtensionResults: safeExtensions,
      id: encodeBinary(response.credential.rawId, maximumCredentialIdBytes),
      response: {
        attestationObject: encodeBinary(
          response.attestation.attestationObject,
          maximumResponseBytes,
        ),
        clientDataJSON: encodeBinary(
          response.attestation.clientDataJSON,
          maximumResponseBytes,
        ),
        transports: mapBrowserTransports(
          response.attestation.getTransports?.() ?? [],
        ),
      },
      type: "public-key",
    },
  };
}

export async function getPasskeyResponse(
  options: WebAuthnAuthenticationOptions,
  credentials: BrowserCredentials = navigator.credentials,
): Promise<WebAuthnAuthenticationResponse> {
  const publicKey = authenticationOptions(options);
  const credential = await credentials.get({ publicKey });
  const response = authenticationCredential(credential);
  if (
    response.credential.rawId.byteLength +
      response.assertion.authenticatorData.byteLength +
      response.assertion.clientDataJSON.byteLength +
      response.assertion.signature.byteLength +
      (response.assertion.userHandle?.byteLength ?? 0) >
    maximumResponseBytes
  ) {
    throw new WebAuthnBrowserError(
      "The authenticator response is outside safe bounds.",
    );
  }
  return {
    ceremonyId: options.ceremonyId,
    credential: {
      id: encodeBinary(response.credential.rawId, maximumCredentialIdBytes),
      response: {
        authenticatorData: encodeBinary(
          response.assertion.authenticatorData,
          maximumResponseBytes,
        ),
        clientDataJSON: encodeBinary(
          response.assertion.clientDataJSON,
          maximumResponseBytes,
        ),
        signature: encodeBinary(
          response.assertion.signature,
          maximumResponseBytes,
        ),
        ...(response.assertion.userHandle
          ? {
              userHandle: encodeBinary(
                response.assertion.userHandle,
                maximumCredentialIdBytes,
              ),
            }
          : {}),
      },
      type: "public-key",
    },
  };
}

function registrationOptions(
  options: WebAuthnRegistrationOptions,
): PublicKeyCredentialCreationOptions {
  const value = options.publicKey;
  if (
    !hasExactKeys(value, [
      "attestation",
      "authenticatorSelection",
      "challenge",
      "excludeCredentials",
      "pubKeyCredParams",
      "rp",
      "timeout",
      "user",
    ]) ||
    !hasExactKeys(value.rp, ["id", "name"]) ||
    !validRelyingPartyID(value.rp.id) ||
    value.rp.name !== "Periapsis" ||
    !hasExactKeys(value.user, ["displayName", "id", "name"]) ||
    !validDisplayText(value.user.name, 320) ||
    !validDisplayText(value.user.displayName, 160) ||
    !Array.isArray(value.pubKeyCredParams) ||
    value.pubKeyCredParams.length !== 2 ||
    new Set(value.pubKeyCredParams.map((parameter) => parameter.alg)).size !==
      2 ||
    value.pubKeyCredParams.some(
      (parameter) =>
        !hasExactKeys(parameter, ["alg", "type"]) ||
        parameter.type !== "public-key" ||
        (parameter.alg !== -7 && parameter.alg !== -257),
    ) ||
    !validTimeout(value.timeout) ||
    !Array.isArray(value.excludeCredentials) ||
    value.excludeCredentials.length > 64 ||
    value.excludeCredentials.some(
      (descriptor) => !validDescriptor(descriptor),
    ) ||
    !hasExactKeys(value.authenticatorSelection, [
      "requireResidentKey",
      "residentKey",
      "userVerification",
    ]) ||
    value.authenticatorSelection.userVerification !== "required" ||
    (value.authenticatorSelection.residentKey !== "preferred" &&
      value.authenticatorSelection.residentKey !== "required") ||
    (value.authenticatorSelection.residentKey === "required" &&
      !value.authenticatorSelection.requireResidentKey) ||
    !["direct", "enterprise", "none"].includes(value.attestation)
  ) {
    throw new WebAuthnBrowserError(
      "The server returned unsafe registration options.",
    );
  }
  return {
    attestation: value.attestation,
    authenticatorSelection: value.authenticatorSelection,
    challenge: decodeOpaque32(value.challenge),
    excludeCredentials: toBrowserDescriptors(value.excludeCredentials),
    pubKeyCredParams: value.pubKeyCredParams,
    rp: value.rp,
    timeout: value.timeout,
    user: {
      ...value.user,
      id: decodeOpaque32(value.user.id),
    },
  };
}

function authenticationOptions(
  options: WebAuthnAuthenticationOptions,
): PublicKeyCredentialRequestOptions {
  const value = options.publicKey;
  if (
    !hasExactKeys(value, [
      "allowCredentials",
      "challenge",
      "rpId",
      "timeout",
      "userVerification",
    ]) ||
    !validRelyingPartyID(value.rpId) ||
    !validTimeout(value.timeout) ||
    value.userVerification !== "required" ||
    !Array.isArray(value.allowCredentials) ||
    value.allowCredentials.length > 64 ||
    value.allowCredentials.some((descriptor) => !validDescriptor(descriptor))
  ) {
    throw new WebAuthnBrowserError(
      "The server returned unsafe authentication options.",
    );
  }
  return {
    allowCredentials: toBrowserDescriptors(value.allowCredentials),
    challenge: decodeOpaque32(value.challenge),
    rpId: value.rpId,
    timeout: value.timeout,
    userVerification: value.userVerification,
  };
}

function registrationCredential(value: Credential | null): {
  attestation: AuthenticatorAttestationResponse;
  credential: PublicKeyCredential;
} {
  if (!isRegistrationCredential(value)) {
    throw new WebAuthnBrowserError(
      "The authenticator returned an invalid registration response.",
    );
  }
  return {
    attestation: value.response,
    credential: value,
  };
}

function authenticationCredential(value: Credential | null): {
  assertion: AuthenticatorAssertionResponse;
  credential: PublicKeyCredential;
} {
  if (!isAuthenticationCredential(value)) {
    throw new WebAuthnBrowserError(
      "The authenticator returned an invalid assertion response.",
    );
  }
  return {
    assertion: value.response,
    credential: value,
  };
}

function decodeBinary(
  value: string,
  minimumBytes: number,
  maximumBytes: number,
): Uint8Array<ArrayBuffer> {
  if (!/^[A-Za-z0-9_-]+$/u.test(value)) {
    throw new WebAuthnBrowserError(
      "The server returned invalid WebAuthn bytes.",
    );
  }
  let binary: string;
  try {
    const standard = value.replaceAll("-", "+").replaceAll("_", "/");
    binary = atob(standard.padEnd(Math.ceil(standard.length / 4) * 4, "="));
  } catch {
    throw new WebAuthnBrowserError(
      "The server returned invalid WebAuthn bytes.",
    );
  }
  if (binary.length < minimumBytes || binary.length > maximumBytes) {
    throw new WebAuthnBrowserError(
      "The WebAuthn value is outside safe bounds.",
    );
  }
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  if (encodeBinary(bytes, maximumBytes) !== value) {
    throw new WebAuthnBrowserError(
      "The server returned non-canonical WebAuthn bytes.",
    );
  }
  return bytes;
}

function decodeOpaque32(value: string): Uint8Array<ArrayBuffer> {
  const bytes = decodeBinary(value, 32, 32);
  if (bytes.every((item) => item === 0)) {
    throw new WebAuthnBrowserError(
      "The server returned invalid WebAuthn bytes.",
    );
  }
  return bytes;
}

function encodeBinary(
  value: ArrayBuffer | ArrayBufferView<ArrayBuffer>,
  maximumBytes: number,
): string {
  const bytes =
    value instanceof ArrayBuffer
      ? new Uint8Array(value)
      : new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  if (bytes.length < 1 || bytes.length > maximumBytes) {
    throw new WebAuthnBrowserError(
      "The authenticator response is outside safe bounds.",
    );
  }
  let binary = "";
  for (let offset = 0; offset < bytes.length; offset += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
  }
  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/u, "");
}

function toBrowserTransports(
  values: readonly WebAuthnCredentialTransport[],
): AuthenticatorTransport[] {
  return values.flatMap((value) => (value === "smart_card" ? [] : [value]));
}

function toBrowserDescriptors(
  values: readonly {
    id: string;
    transports?: WebAuthnCredentialTransport[];
    type: "public-key";
  }[],
): PublicKeyCredentialDescriptor[] {
  return values.map((descriptor) => ({
    id: decodeBinary(descriptor.id, 1, maximumCredentialIdBytes),
    ...(descriptor.transports
      ? { transports: toBrowserTransports(descriptor.transports) }
      : {}),
    type: "public-key",
  }));
}

function mapBrowserTransports(
  values: readonly string[],
): WebAuthnCredentialTransport[] {
  if (values.length > 6) {
    throw new WebAuthnBrowserError(
      "The authenticator returned an unsupported transport.",
    );
  }
  const mapped = new Set<WebAuthnCredentialTransport>();
  for (const value of values) {
    const wireValue = value === "smart-card" ? "smart_card" : value;
    if (!isWireTransport(wireValue)) {
      throw new WebAuthnBrowserError(
        "The authenticator returned an unsupported transport.",
      );
    }
    mapped.add(wireValue);
  }
  return [...mapped].toSorted();
}

function isWireTransport(value: string): value is WebAuthnCredentialTransport {
  return ["ble", "hybrid", "internal", "nfc", "smart_card", "usb"].includes(
    value,
  );
}

function validDescriptor(value: {
  id: string;
  transports?: WebAuthnCredentialTransport[];
  type: "public-key";
}): boolean {
  if (
    !hasExactKeys(
      value,
      ["id", "transports", "type"],
      value.transports === undefined ? ["id", "type"] : undefined,
    ) ||
    value.type !== "public-key"
  ) {
    return false;
  }
  try {
    decodeBinary(value.id, 1, maximumCredentialIdBytes);
  } catch {
    return false;
  }
  return (
    value.transports === undefined ||
    (Array.isArray(value.transports) &&
      value.transports.length <= 6 &&
      new Set(value.transports).size === value.transports.length &&
      value.transports.every(isWireTransport))
  );
}

function validTimeout(value: number): boolean {
  return Number.isSafeInteger(value) && value >= 1000 && value <= 600_000;
}

function validDisplayText(value: string, maximum: number): boolean {
  return (
    value.length >= 1 &&
    value.length <= maximum &&
    value.trim() === value &&
    !/[<>\p{Cc}]/u.test(value)
  );
}

function validRelyingPartyID(value: string): boolean {
  if (
    value.length < 3 ||
    value.length > 253 ||
    value !== value.toLowerCase() ||
    value.startsWith(".") ||
    value.endsWith(".")
  ) {
    return false;
  }
  return value
    .split(".")
    .every(
      (label) =>
        label.length >= 1 &&
        label.length <= 63 &&
        /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/u.test(label),
    );
}

function hasExactKeys(
  value: object,
  allowed: readonly string[],
  required: readonly string[] = allowed,
): boolean {
  const keys = Object.keys(value);
  return (
    keys.every((key) => allowed.includes(key)) &&
    required.every((key) => Object.hasOwn(value, key))
  );
}

function isRegistrationCredential(
  value: Credential | null,
): value is PublicKeyCredential & {
  response: AuthenticatorAttestationResponse;
} {
  if (
    value === null ||
    value.type !== "public-key" ||
    !("rawId" in value) ||
    !("response" in value) ||
    !("getClientExtensionResults" in value) ||
    !(value.rawId instanceof ArrayBuffer) ||
    typeof value.getClientExtensionResults !== "function" ||
    !isRecord(value.response)
  ) {
    return false;
  }
  return (
    value.response.attestationObject instanceof ArrayBuffer &&
    value.response.clientDataJSON instanceof ArrayBuffer
  );
}

function isAuthenticationCredential(
  value: Credential | null,
): value is PublicKeyCredential & { response: AuthenticatorAssertionResponse } {
  if (
    value === null ||
    value.type !== "public-key" ||
    !("rawId" in value) ||
    !("response" in value) ||
    !("getClientExtensionResults" in value) ||
    !(value.rawId instanceof ArrayBuffer) ||
    typeof value.getClientExtensionResults !== "function" ||
    !isRecord(value.response)
  ) {
    return false;
  }
  return (
    value.response.authenticatorData instanceof ArrayBuffer &&
    value.response.clientDataJSON instanceof ArrayBuffer &&
    value.response.signature instanceof ArrayBuffer &&
    (value.response.userHandle === null ||
      value.response.userHandle === undefined ||
      value.response.userHandle instanceof ArrayBuffer)
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

export class WebAuthnBrowserError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "WebAuthnBrowserError";
  }
}
