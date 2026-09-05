import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const packageRoot = resolve(import.meta.dirname, "..");
const contract = JSON.parse(
  readFileSync(
    resolve(packageRoot, "../../services/api/internal/contract/openapi.json"),
    "utf8",
  ),
);
const alertCreate = contract.paths?.["/api/v1/tenants/{tenantId}/alerts"]?.post;
if (alertCreate?.["x-periapsis-generated-auth"] !== "explicit") {
  throw new Error("Alert create must require explicit generated-client auth");
}
const sdk = readFileSync(
  resolve(packageRoot, "generated/typescript/sdk.gen.ts"),
  "utf8",
);
const declarationStart = sdk.indexOf("export const createTenantAlert =");
const declarationEnd = sdk.indexOf("\n});", declarationStart);
if (declarationStart < 0 || declarationEnd < 0) {
  throw new Error("generated Alert create declaration is missing");
}
if (sdk.slice(declarationStart, declarationEnd).includes("security:")) {
  throw new Error("generated Alert create must not auto-apply mixed auth");
}

const logoutContinuation =
  contract.paths?.["/api/v1/auth/logout/continuations/{continuationId}"]?.get;
if (
  logoutContinuation?.operationId !== "continueLogout" ||
  logoutContinuation?.["x-periapsis-generated-auth"] !== "browser-cookie" ||
  JSON.stringify(logoutContinuation.security) !==
    JSON.stringify([{ logoutContinuationCookie: [] }])
) {
  throw new Error(
    "Logout continuation must require only its path-scoped browser cookie",
  );
}
const continueLogoutStart = sdk.indexOf("export const continueLogout =");
const continueLogoutEnd = sdk.indexOf("\n});", continueLogoutStart);
if (continueLogoutStart < 0 || continueLogoutEnd < 0) {
  throw new Error("generated logout continuation declaration is missing");
}
if (sdk.slice(continueLogoutStart, continueLogoutEnd).includes("security:")) {
  throw new Error(
    "generated logout continuation must rely on its HttpOnly browser cookie",
  );
}

const deviceList = contract.paths?.["/api/v1/auth/mfa/devices"]?.get;
const deviceRename =
  contract.paths?.["/api/v1/auth/mfa/devices/{deviceId}"]?.patch;
const deviceRevoke =
  contract.paths?.["/api/v1/auth/mfa/devices/{deviceId}/revoke"]?.post;
const tenantBoundMfaOperations = [
  contract.paths?.["/api/v1/auth/mfa/step-up"]?.post,
  contract.paths?.["/api/v1/auth/mfa/step-up/{challengeId}/totp"]?.post,
  contract.paths?.["/api/v1/auth/mfa/step-up/{challengeId}/recovery"]?.post,
  contract.paths?.["/api/v1/auth/mfa/totp/enrollments"]?.post,
  contract.paths?.["/api/v1/auth/mfa/totp/enrollments/{enrollmentId}"]?.post,
  contract.paths?.["/api/v1/auth/mfa/recovery-codes"]?.post,
  contract.paths?.["/api/v1/auth/mfa/passkeys/registration/options"]?.post,
  contract.paths?.["/api/v1/auth/mfa/passkeys/registration/verify"]?.post,
  contract.paths?.["/api/v1/auth/mfa/passkeys/authentication/options"]?.post,
  contract.paths?.["/api/v1/auth/mfa/passkeys/authentication/verify"]?.post,
];
if (
  tenantBoundMfaOperations.some(
    (operation) =>
      operation?.["x-periapsis-authorization"]?.activeTenant !== true ||
      operation?.["x-periapsis-authorization"]?.ownerOnly !== true,
  )
) {
  throw new Error(
    "Tenant-bound MFA enrollment and step-up must require an active tenant owner",
  );
}
const sessionMethods =
  contract.components?.schemas?.SessionAuthenticationMethod?.enum;
if (
  !Array.isArray(sessionMethods) ||
  JSON.stringify([...new Set(sessionMethods)].sort()) !==
    JSON.stringify(
      [
        "bootstrap_totp",
        "ldap",
        "oidc",
        "passkey",
        "recovery_code",
        "saml",
        "totp",
      ].sort(),
    )
) {
  throw new Error(
    "Session authentication methods lost their closed persisted set",
  );
}
const opaqueId = contract.components?.schemas?.MfaOpaqueId;
const credentialId = contract.components?.schemas?.WebAuthnCredentialId;
const deviceCursor = contract.components?.schemas?.MfaDeviceCursor;
if (
  opaqueId?.minLength !== 43 ||
  opaqueId?.maxLength !== 43 ||
  !String(opaqueId?.pattern).includes("(?!A{43}$)") ||
  credentialId?.minLength !== 2 ||
  credentialId?.maxLength !== 1366 ||
  deviceCursor?.minLength !== 24 ||
  deviceCursor?.maxLength !== 24
) {
  throw new Error("MFA opaque identifiers and cursors lost canonical bounds");
}
for (const [name, operation] of [
  ["listMfaDevices", deviceList],
  ["renameMfaPasskey", deviceRename],
  ["revokeMfaDevice", deviceRevoke],
]) {
  if (operation?.operationId !== name) {
    throw new Error(`${name} operation is missing from the canonical contract`);
  }
}
if (
  JSON.stringify(deviceList?.security) !==
    JSON.stringify([{ sessionCookie: [] }]) ||
  deviceList?.["x-periapsis-authorization"]?.activeTenant !== true ||
  deviceList?.["x-periapsis-authorization"]?.ownerOnly !== true
) {
  throw new Error(
    "MFA device inventory must require a tenant-bound live owner session",
  );
}
for (const operation of [deviceRename, deviceRevoke]) {
  const authorization = operation?.["x-periapsis-authorization"];
  const parameters = operation?.parameters ?? [];
  if (
    JSON.stringify(operation?.security) !==
      JSON.stringify([{ sessionCookie: [], csrfToken: [] }]) ||
    authorization?.activeTenant !== true ||
    authorization?.freshLocalMfa !== true ||
    authorization?.ownerOnly !== true ||
    JSON.stringify(authorization?.principalTypes) !==
      JSON.stringify(["human"]) ||
    !parameters.some(
      (parameter) =>
        parameter?.$ref === "#/components/parameters/IfMatch" ||
        (parameter?.name === "If-Match" && parameter?.required === true),
    ) ||
    !operation?.responses?.["412"] ||
    !operation?.responses?.["428"]
  ) {
    throw new Error(
      "MFA device mutation lost CSRF, owner, fresh-MFA, or CAS authority",
    );
  }
}

const device = contract.components?.schemas?.MfaDevice;
const allowedDeviceProperties = [
  "backedUp",
  "backupEligible",
  "createdAt",
  "discoverable",
  "displayName",
  "id",
  "kind",
  "lastUsedAt",
  "revokedAt",
  "status",
  "transports",
  "version",
].sort();
if (
  device?.additionalProperties !== false ||
  JSON.stringify(Object.keys(device?.properties ?? {}).sort()) !==
    JSON.stringify(allowedDeviceProperties)
) {
  throw new Error("MFA device projection must remain structurally redacted");
}
for (const operationName of [
  "listMfaDevices",
  "renameMfaPasskey",
  "revokeMfaDevice",
]) {
  const start = sdk.indexOf(`export const ${operationName} =`);
  const end = sdk.indexOf("\n});", start);
  if (start < 0 || end < 0) {
    throw new Error(`generated ${operationName} declaration is missing`);
  }
  if (!sdk.slice(start, end).includes("security:")) {
    throw new Error(
      `generated ${operationName} lost its declared security scheme`,
    );
  }
}
