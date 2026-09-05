import {
  abandonFederatedMfaContinuation,
  cancelFederatedMfaCeremony,
  completeFederatedMfaRecoveryStepUp,
  completeFederatedMfaTotpStepUp,
  completeFederatedPasskeyStepUp,
  completeFederatedTotpEnrollment,
  completePasskeyLogin,
  completeLocalMfaRecoveryStepUp,
  completeLocalMfaTotpStepUp,
  completePasskeyRegistration,
  completePasskeyStepUp,
  completeTotpEnrollment,
  listMfaDevices,
  regenerateMfaRecoveryCodes,
  renameMfaPasskey,
  revokeMfaDevice,
  startPasskeyLogin,
  startFederatedMfaStepUp,
  startFederatedPasskeyStepUp,
  startFederatedTotpEnrollment,
  startLocalMfaStepUp,
  startPasskeyRegistration,
  startPasskeyStepUp,
  startTotpEnrollment,
  type FederatedMfaEnrollmentResult,
  type MfaDevice,
  type MfaDeviceList,
  type MfaDeviceMutationResult,
  type MfaRecoveryCodesResult,
  type MfaStepUpChallenge,
  type PasskeyRegistrationResult,
  type Session,
  type TotpEnrollment,
  type WebAuthnAuthenticationOptions,
  type WebAuthnAuthenticationResponse,
  type WebAuthnRegistrationOptions,
  type WebAuthnRegistrationResponse,
} from "@periapsis/contracts";

import { platformPermissionKeys } from "../../lib/phase-two-types";
import { parseRfc3339Instant } from "../../lib/rfc3339-instant";
import { sessionAwareFetch } from "../../lib/session-transition-transport";
import {
  mfaDeviceEtag,
  type MfaDeviceMutationView,
  type MfaDevicePageView,
  type MfaDeviceView,
} from "./model";

const sessionAuthenticationMethods: ReadonlySet<string> = new Set<
  Session["authenticationMethod"]
>(["bootstrap_totp", "oidc", "passkey", "recovery_code", "saml", "totp"]);
const platformPermissionSet: ReadonlySet<string> = new Set(
  platformPermissionKeys,
);

interface GeneratedResult<T> {
  data: T | undefined;
  error: unknown;
  response?: Response;
}

export interface MfaTransport {
  completePasskeyLogin(input: {
    body: WebAuthnAuthenticationResponse;
  }): Promise<GeneratedResult<Session>>;
  completePasskeyRegistration(input: {
    body: WebAuthnRegistrationResponse;
    csrfToken: string;
  }): Promise<GeneratedResult<PasskeyRegistrationResult>>;
  completePasskeyStepUp(input: {
    body: WebAuthnAuthenticationResponse;
    csrfToken: string;
  }): Promise<GeneratedResult<Session>>;
  completeRecoveryStepUp(input: {
    challengeId: string;
    code: string;
    csrfToken: string;
  }): Promise<GeneratedResult<Session>>;
  completeTotpEnrollment(input: {
    code: string;
    csrfToken: string;
    enrollmentId: string;
  }): Promise<GeneratedResult<unknown>>;
  completeTotpStepUp(input: {
    challengeId: string;
    code: string;
    csrfToken: string;
    factorId: string;
  }): Promise<GeneratedResult<Session>>;
  listDevices(input: {
    after?: string;
    includeRevoked: boolean;
    signal?: AbortSignal;
  }): Promise<GeneratedResult<MfaDeviceList>>;
  regenerateRecoveryCodes(input: {
    csrfToken: string;
  }): Promise<GeneratedResult<MfaRecoveryCodesResult>>;
  renamePasskey(input: {
    body: { displayName: string; expectedVersion: number };
    csrfToken: string;
    deviceId: string;
    etag: string;
  }): Promise<GeneratedResult<MfaDeviceMutationResult>>;
  revokeDevice(input: {
    body: { expectedVersion: number; kind: "passkey" | "totp" };
    csrfToken: string;
    deviceId: string;
    etag: string;
  }): Promise<GeneratedResult<MfaDeviceMutationResult>>;
  startLocalStepUp(input: {
    action: string;
    csrfToken: string;
  }): Promise<GeneratedResult<MfaStepUpChallenge>>;
  startPasskeyLogin(input: {
    tenantId: string;
  }): Promise<GeneratedResult<WebAuthnAuthenticationOptions>>;
  startPasskeyRegistration(input: {
    csrfToken: string;
  }): Promise<GeneratedResult<WebAuthnRegistrationOptions>>;
  startPasskeyStepUp(input: {
    action: string;
    csrfToken: string;
  }): Promise<GeneratedResult<WebAuthnAuthenticationOptions>>;
  startTotpEnrollment(input: {
    csrfToken: string;
  }): Promise<GeneratedResult<TotpEnrollment>>;
}

export interface FederatedMfaTransport {
  abandonContinuation(): Promise<GeneratedResult<unknown>>;
  cancelCeremony(): Promise<GeneratedResult<unknown>>;
  completePasskeyStepUp(input: {
    body: WebAuthnAuthenticationResponse;
  }): Promise<GeneratedResult<Session>>;
  completeRecoveryStepUp(input: {
    challengeId: string;
    code: string;
  }): Promise<GeneratedResult<Session>>;
  completeTotpEnrollment(input: {
    code: string;
    enrollmentId: string;
  }): Promise<GeneratedResult<FederatedMfaEnrollmentResult>>;
  completeTotpStepUp(input: {
    challengeId: string;
    code: string;
    factorId: string;
  }): Promise<GeneratedResult<Session>>;
  startLocalStepUp(): Promise<GeneratedResult<MfaStepUpChallenge>>;
  startPasskeyStepUp(): Promise<GeneratedResult<WebAuthnAuthenticationOptions>>;
  startTotpEnrollment(): Promise<GeneratedResult<TotpEnrollment>>;
}

export interface MfaApi {
  completePasskeyLogin(body: WebAuthnAuthenticationResponse): Promise<Session>;
  completePasskeyRegistration(
    csrfToken: string,
    body: WebAuthnRegistrationResponse,
  ): Promise<void>;
  completePasskeyStepUp(
    csrfToken: string,
    body: WebAuthnAuthenticationResponse,
  ): Promise<void>;
  completeRecoveryStepUp(
    csrfToken: string,
    challengeId: string,
    code: string,
  ): Promise<void>;
  completeTotpEnrollment(
    csrfToken: string,
    enrollmentId: string,
    code: string,
  ): Promise<void>;
  completeTotpStepUp(
    csrfToken: string,
    challengeId: string,
    factorId: string,
    code: string,
  ): Promise<void>;
  listDevices(input?: {
    after?: string;
    includeRevoked?: boolean;
    signal?: AbortSignal;
  }): Promise<MfaDevicePageView>;
  regenerateRecoveryCodes(csrfToken: string): Promise<readonly string[]>;
  renamePasskey(
    csrfToken: string,
    device: MfaDeviceView,
    displayName: string,
  ): Promise<MfaDeviceMutationView>;
  revokeDevice(
    csrfToken: string,
    device: MfaDeviceView,
  ): Promise<MfaDeviceMutationView>;
  startLocalStepUp(
    csrfToken: string,
    action: string,
  ): Promise<MfaStepUpChallenge>;
  startPasskeyLogin(tenantId: string): Promise<WebAuthnAuthenticationOptions>;
  startPasskeyRegistration(
    csrfToken: string,
  ): Promise<WebAuthnRegistrationOptions>;
  startPasskeyStepUp(
    csrfToken: string,
    action: string,
  ): Promise<WebAuthnAuthenticationOptions>;
  startTotpEnrollment(csrfToken: string): Promise<TotpEnrollment>;
}

export interface FederatedMfaApi {
  abandonContinuation(): Promise<void>;
  cancelCeremony(): Promise<void>;
  completePasskeyStepUp(body: WebAuthnAuthenticationResponse): Promise<Session>;
  completeRecoveryStepUp(challengeId: string, code: string): Promise<Session>;
  completeTotpEnrollment(
    enrollmentId: string,
    code: string,
  ): Promise<FederatedMfaEnrollmentResult>;
  completeTotpStepUp(
    challengeId: string,
    factorId: string,
    code: string,
  ): Promise<Session>;
  startLocalStepUp(): Promise<MfaStepUpChallenge>;
  startPasskeyStepUp(): Promise<WebAuthnAuthenticationOptions>;
  startTotpEnrollment(): Promise<TotpEnrollment>;
}

const sameOrigin = {
  baseUrl: globalThis.location.origin,
  credentials: "same-origin" as const,
  fetch: sessionAwareFetch,
};

const generatedMfaTransport: MfaTransport = {
  completePasskeyLogin: ({ body }) =>
    completePasskeyLogin({
      ...sameOrigin,
      body,
    }),
  completePasskeyRegistration: ({ body, csrfToken }) =>
    completePasskeyRegistration({
      ...sameOrigin,
      body,
      headers: { "X-CSRF-Token": csrfToken },
    }),
  completePasskeyStepUp: ({ body, csrfToken }) =>
    completePasskeyStepUp({
      ...sameOrigin,
      body,
      headers: { "X-CSRF-Token": csrfToken },
    }),
  completeRecoveryStepUp: ({ challengeId, code, csrfToken }) =>
    completeLocalMfaRecoveryStepUp({
      ...sameOrigin,
      body: { code },
      headers: { "X-CSRF-Token": csrfToken },
      path: { challengeId },
    }),
  completeTotpEnrollment: ({ code, csrfToken, enrollmentId }) =>
    completeTotpEnrollment({
      ...sameOrigin,
      body: { code },
      headers: { "X-CSRF-Token": csrfToken },
      path: { enrollmentId },
    }),
  completeTotpStepUp: ({ challengeId, code, csrfToken, factorId }) =>
    completeLocalMfaTotpStepUp({
      ...sameOrigin,
      body: { code, factorId },
      headers: { "X-CSRF-Token": csrfToken },
      path: { challengeId },
    }),
  listDevices: ({ after, includeRevoked, signal }) =>
    listMfaDevices({
      ...sameOrigin,
      query: { includeRevoked, limit: 50, ...(after ? { after } : {}) },
      ...(signal ? { signal } : {}),
    }),
  regenerateRecoveryCodes: ({ csrfToken }) =>
    regenerateMfaRecoveryCodes({
      ...sameOrigin,
      headers: { "X-CSRF-Token": csrfToken },
    }),
  renamePasskey: ({ body, csrfToken, deviceId, etag }) =>
    renameMfaPasskey({
      ...sameOrigin,
      body,
      headers: { "If-Match": etag, "X-CSRF-Token": csrfToken },
      path: { deviceId },
    }),
  revokeDevice: ({ body, csrfToken, deviceId, etag }) =>
    revokeMfaDevice({
      ...sameOrigin,
      body,
      headers: { "If-Match": etag, "X-CSRF-Token": csrfToken },
      path: { deviceId },
    }),
  startLocalStepUp: ({ action, csrfToken }) =>
    startLocalMfaStepUp({
      ...sameOrigin,
      body: { action },
      headers: { "X-CSRF-Token": csrfToken },
    }),
  startPasskeyLogin: ({ tenantId }) =>
    startPasskeyLogin({
      ...sameOrigin,
      body: { tenantId },
    }),
  startPasskeyRegistration: ({ csrfToken }) =>
    startPasskeyRegistration({
      ...sameOrigin,
      headers: { "X-CSRF-Token": csrfToken },
    }),
  startPasskeyStepUp: ({ action, csrfToken }) =>
    startPasskeyStepUp({
      ...sameOrigin,
      body: { action },
      headers: { "X-CSRF-Token": csrfToken },
    }),
  startTotpEnrollment: ({ csrfToken }) =>
    startTotpEnrollment({
      ...sameOrigin,
      headers: { "X-CSRF-Token": csrfToken },
    }),
};

const generatedFederatedMfaTransport: FederatedMfaTransport = {
  abandonContinuation: () => abandonFederatedMfaContinuation(sameOrigin),
  cancelCeremony: () => cancelFederatedMfaCeremony(sameOrigin),
  completePasskeyStepUp: ({ body }) =>
    completeFederatedPasskeyStepUp({
      ...sameOrigin,
      body,
    }),
  completeRecoveryStepUp: ({ challengeId, code }) =>
    completeFederatedMfaRecoveryStepUp({
      ...sameOrigin,
      body: { code },
      path: { challengeId },
    }),
  completeTotpEnrollment: ({ code, enrollmentId }) =>
    completeFederatedTotpEnrollment({
      ...sameOrigin,
      body: { code },
      path: { enrollmentId },
    }),
  completeTotpStepUp: ({ challengeId, code, factorId }) =>
    completeFederatedMfaTotpStepUp({
      ...sameOrigin,
      body: { code, factorId },
      path: { challengeId },
    }),
  startLocalStepUp: () => startFederatedMfaStepUp(sameOrigin),
  startPasskeyStepUp: () => startFederatedPasskeyStepUp(sameOrigin),
  startTotpEnrollment: () => startFederatedTotpEnrollment(sameOrigin),
};

export function createMfaApi(transport: MfaTransport): MfaApi {
  return {
    async completePasskeyLogin(body) {
      const session = unwrap(await transport.completePasskeyLogin({ body }));
      requireSessionProjection(session);
      return session;
    },
    async completePasskeyRegistration(csrfToken, body) {
      requireCsrf(csrfToken);
      requirePasskeyRegistrationMutation(
        unwrap(
          await transport.completePasskeyRegistration({ body, csrfToken }),
        ),
      );
    },
    async completePasskeyStepUp(csrfToken, body) {
      requireCsrf(csrfToken);
      requireSessionProjection(
        unwrap(await transport.completePasskeyStepUp({ body, csrfToken })),
      );
    },
    async completeRecoveryStepUp(csrfToken, challengeId, code) {
      requireCsrf(csrfToken);
      requireOpaqueId(challengeId);
      requireText(code, 16, 128);
      requireSessionProjection(
        unwrap(
          await transport.completeRecoveryStepUp({
            challengeId,
            code,
            csrfToken,
          }),
        ),
      );
    },
    async completeTotpEnrollment(csrfToken, enrollmentId, code) {
      requireCsrf(csrfToken);
      requireUuid(enrollmentId);
      requireTotp(code);
      requireFactorMutation(
        unwrap(
          await transport.completeTotpEnrollment({
            code,
            csrfToken,
            enrollmentId,
          }),
        ),
      );
    },
    async completeTotpStepUp(csrfToken, challengeId, factorId, code) {
      requireCsrf(csrfToken);
      requireOpaqueId(challengeId);
      requireUuid(factorId);
      requireTotp(code);
      requireSessionProjection(
        unwrap(
          await transport.completeTotpStepUp({
            challengeId,
            code,
            csrfToken,
            factorId,
          }),
        ),
      );
    },
    async listDevices(input = {}) {
      if (input.after !== undefined) requireCursor(input.after);
      return projectDevicePage(
        unwrap(
          await transport.listDevices({
            includeRevoked: input.includeRevoked ?? false,
            ...(input.after ? { after: input.after } : {}),
            ...(input.signal ? { signal: input.signal } : {}),
          }),
        ),
      );
    },
    async regenerateRecoveryCodes(csrfToken) {
      requireCsrf(csrfToken);
      const result = unwrap(
        await transport.regenerateRecoveryCodes({ csrfToken }),
      );
      requireRecoveryMutation(result);
      if (
        !Array.isArray(result.recoveryCodes) ||
        result.recoveryCodes.length < 8 ||
        result.recoveryCodes.length > 16 ||
        new Set(result.recoveryCodes).size !== result.recoveryCodes.length ||
        result.recoveryCodes.some(
          (code) =>
            typeof code !== "string" ||
            code.length < 52 ||
            code.length > 128 ||
            !/^[A-Z2-7-]+$/u.test(code),
        )
      ) {
        throw projectionError();
      }
      return [...result.recoveryCodes];
    },
    async renamePasskey(csrfToken, device, displayName) {
      requireCsrf(csrfToken);
      const canonicalName = displayName.trim();
      requireText(canonicalName, 1, 120);
      if (/[<>\p{Cc}]/u.test(canonicalName) || device.kind !== "passkey") {
        throw new MfaApiError("The passkey name is invalid.");
      }
      return projectMutation(
        await transport.renamePasskey({
          body: { displayName: canonicalName, expectedVersion: device.version },
          csrfToken,
          deviceId: device.id,
          etag: mfaDeviceEtag(device),
        }),
      );
    },
    async revokeDevice(csrfToken, device) {
      requireCsrf(csrfToken);
      return projectMutation(
        await transport.revokeDevice({
          body: { expectedVersion: device.version, kind: device.kind },
          csrfToken,
          deviceId: device.id,
          etag: mfaDeviceEtag(device),
        }),
      );
    },
    async startLocalStepUp(csrfToken, action) {
      requireCsrf(csrfToken);
      requireAction(action);
      return projectStepUpChallenge(
        unwrap(await transport.startLocalStepUp({ action, csrfToken })),
      );
    },
    async startPasskeyLogin(tenantId) {
      requireUuid(tenantId);
      return requireWebAuthnOptions(
        unwrap(await transport.startPasskeyLogin({ tenantId })),
      );
    },
    async startPasskeyRegistration(csrfToken) {
      requireCsrf(csrfToken);
      return requireWebAuthnOptions(
        unwrap(await transport.startPasskeyRegistration({ csrfToken })),
      );
    },
    async startPasskeyStepUp(csrfToken, action) {
      requireCsrf(csrfToken);
      requireAction(action);
      return requireWebAuthnOptions(
        unwrap(await transport.startPasskeyStepUp({ action, csrfToken })),
      );
    },
    async startTotpEnrollment(csrfToken) {
      requireCsrf(csrfToken);
      return projectTotpEnrollment(
        unwrap(await transport.startTotpEnrollment({ csrfToken })),
      );
    },
  };
}

export function createFederatedMfaApi(
  transport: FederatedMfaTransport,
): FederatedMfaApi {
  return {
    async abandonContinuation() {
      requireNoContent(await transport.abandonContinuation());
    },
    async cancelCeremony() {
      requireNoContent(await transport.cancelCeremony());
    },
    async completePasskeyStepUp(body) {
      const session = unwrap(await transport.completePasskeyStepUp({ body }));
      requireSessionProjection(session);
      return session;
    },
    async completeRecoveryStepUp(challengeId, code) {
      requireOpaqueId(challengeId);
      requireText(code, 16, 128);
      const session = unwrap(
        await transport.completeRecoveryStepUp({ challengeId, code }),
      );
      requireSessionProjection(session);
      return session;
    },
    async completeTotpEnrollment(enrollmentId, code) {
      requireUuid(enrollmentId);
      requireTotp(code);
      return projectFederatedEnrollment(
        unwrap(await transport.completeTotpEnrollment({ code, enrollmentId })),
      );
    },
    async completeTotpStepUp(challengeId, factorId, code) {
      requireOpaqueId(challengeId);
      requireUuid(factorId);
      requireTotp(code);
      const session = unwrap(
        await transport.completeTotpStepUp({
          challengeId,
          code,
          factorId,
        }),
      );
      requireSessionProjection(session);
      return session;
    },
    async startLocalStepUp() {
      return projectStepUpChallenge(unwrap(await transport.startLocalStepUp()));
    },
    async startPasskeyStepUp() {
      return requireWebAuthnOptions(
        unwrap(await transport.startPasskeyStepUp()),
      );
    },
    async startTotpEnrollment() {
      return projectTotpEnrollment(
        unwrap(await transport.startTotpEnrollment()),
      );
    },
  };
}

export const mfaApi = createMfaApi(generatedMfaTransport);
export const federatedMfaApi = createFederatedMfaApi(
  generatedFederatedMfaTransport,
);

export class MfaApiError extends Error {
  readonly status: number | undefined;

  constructor(message: string, status?: number) {
    super(message);
    this.name = "MfaApiError";
    this.status = status;
  }
}

function projectStepUpChallenge(
  challenge: MfaStepUpChallenge,
): MfaStepUpChallenge {
  if (
    !isRecord(challenge) ||
    !isExactObject(challenge, [
      "challengeId",
      "expiresAt",
      "methods",
      "totpFactorIds",
    ]) ||
    !isOpaqueId(challenge.challengeId) ||
    parseRfc3339Instant(challenge.expiresAt) === undefined ||
    !Array.isArray(challenge.methods) ||
    challenge.methods.length < 1 ||
    challenge.methods.length > 2 ||
    challenge.methods.some(
      (method) => method !== "totp" && method !== "recovery_code",
    ) ||
    new Set(challenge.methods).size !== challenge.methods.length ||
    !Array.isArray(challenge.totpFactorIds) ||
    challenge.totpFactorIds.length > 16 ||
    challenge.totpFactorIds.some((factorId) => !isUuid(factorId)) ||
    new Set(challenge.totpFactorIds).size !== challenge.totpFactorIds.length ||
    challenge.methods.includes("totp") !== challenge.totpFactorIds.length > 0
  ) {
    throw projectionError();
  }
  return {
    challengeId: challenge.challengeId,
    expiresAt: challenge.expiresAt,
    methods: [...challenge.methods],
    totpFactorIds: [...challenge.totpFactorIds],
  };
}

function projectTotpEnrollment(enrollment: TotpEnrollment): TotpEnrollment {
  if (
    !isRecord(enrollment) ||
    !isExactObject(enrollment, [
      "enrollmentId",
      "expiresAt",
      "provisioningUri",
      "secret",
    ]) ||
    !isUuid(enrollment.enrollmentId) ||
    parseRfc3339Instant(enrollment.expiresAt) === undefined ||
    typeof enrollment.secret !== "string" ||
    !/^[A-Z2-7]{16,256}$/u.test(enrollment.secret) ||
    typeof enrollment.provisioningUri !== "string" ||
    enrollment.provisioningUri.length > 4096 ||
    !enrollment.provisioningUri.startsWith("otpauth://")
  ) {
    throw projectionError();
  }
  return enrollment;
}

function projectFederatedEnrollment(
  result: FederatedMfaEnrollmentResult,
): FederatedMfaEnrollmentResult {
  if (
    !isRecord(result) ||
    !isExactObject(result, ["factorId", "next"]) ||
    !isUuid(result.factorId) ||
    result.next !== "step_up"
  ) {
    throw projectionError();
  }
  return result;
}

function projectMutation(
  result: GeneratedResult<MfaDeviceMutationResult>,
): MfaDeviceMutationView {
  const value = unwrap(result);
  if (
    !isRecord(value) ||
    !isExactObject(value, ["currentSessionRevoked", "device"]) ||
    typeof value.currentSessionRevoked !== "boolean"
  ) {
    throw projectionError();
  }
  const device = projectDevice(value.device);
  const etag = result.response?.headers.get("ETag");
  if (etag !== mfaDeviceEtag(device)) throw projectionError();
  return { currentSessionRevoked: value.currentSessionRevoked, device };
}

function projectDevicePage(value: MfaDeviceList): MfaDevicePageView {
  if (
    !isRecord(value) ||
    !isExactObject(value, ["items", "nextCursor"], ["items"]) ||
    !Array.isArray(value.items) ||
    value.items.length > 100
  ) {
    throw projectionError();
  }
  const items = value.items.map(projectDevice);
  if (value.nextCursor !== undefined) requireCursor(value.nextCursor);
  return {
    items,
    ...(value.nextCursor ? { nextCursor: value.nextCursor } : {}),
  };
}

function projectDevice(value: MfaDevice): MfaDeviceView {
  const allowed = [
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
  ];
  const required = allowed.filter(
    (key) => key !== "lastUsedAt" && key !== "revokedAt",
  );
  if (
    !isRecord(value) ||
    !isExactObject(value, allowed, required) ||
    !isUuid(value.id) ||
    (value.kind !== "passkey" && value.kind !== "totp") ||
    typeof value.status !== "string" ||
    !["active", "clone_suspected", "revoked"].includes(value.status) ||
    typeof value.displayName !== "string" ||
    value.displayName.length > 120 ||
    !Number.isSafeInteger(value.version) ||
    value.version < 1 ||
    value.version > 2_147_483_647 ||
    typeof value.discoverable !== "boolean" ||
    typeof value.backupEligible !== "boolean" ||
    typeof value.backedUp !== "boolean" ||
    !Array.isArray(value.transports) ||
    value.transports.length > 6 ||
    new Set(value.transports).size !== value.transports.length ||
    value.transports.some(
      (transport) =>
        !["ble", "hybrid", "internal", "nfc", "smart_card", "usb"].includes(
          transport,
        ),
    ) ||
    parseRfc3339Instant(value.createdAt) === undefined ||
    (value.lastUsedAt !== undefined &&
      parseRfc3339Instant(value.lastUsedAt) === undefined) ||
    (value.revokedAt !== undefined &&
      parseRfc3339Instant(value.revokedAt) === undefined)
  ) {
    throw projectionError();
  }
  if (
    value.kind === "totp" &&
    (value.displayName !== "" ||
      value.discoverable ||
      value.backupEligible ||
      value.backedUp ||
      value.transports.length > 0 ||
      value.lastUsedAt !== undefined)
  ) {
    throw projectionError();
  }
  if (
    value.kind === "passkey" &&
    (value.displayName.trim() !== value.displayName ||
      value.displayName.length === 0 ||
      (value.backedUp && !value.backupEligible))
  ) {
    throw projectionError();
  }
  if (
    value.status === "active" ? value.revokedAt !== undefined : !value.revokedAt
  ) {
    throw projectionError();
  }
  return {
    backedUp: value.backedUp,
    backupEligible: value.backupEligible,
    createdAt: value.createdAt,
    discoverable: value.discoverable,
    displayName: value.displayName,
    id: value.id,
    kind: value.kind,
    ...(value.lastUsedAt ? { lastUsedAt: value.lastUsedAt } : {}),
    ...(value.revokedAt ? { revokedAt: value.revokedAt } : {}),
    status: value.status,
    transports: value.transports.toSorted(),
    version: value.version,
  };
}

function requireFactorMutation(value: unknown): void {
  if (
    !isRecord(value) ||
    !isExactObject(value, ["factorId", "session"]) ||
    !isUuid(value.factorId) ||
    !isRecord(value.session)
  ) {
    throw projectionError();
  }
  requireSessionProjection(value.session);
}

function requirePasskeyRegistrationMutation(value: unknown): void {
  if (
    !isRecord(value) ||
    !isExactObject(value, ["credential", "session"]) ||
    !isRecord(value.credential) ||
    !isExactObject(value.credential, [
      "backedUp",
      "backupEligible",
      "discoverable",
      "id",
      "transports",
    ]) ||
    typeof value.credential.id !== "string" ||
    !/^[A-Za-z0-9_-]{2,1366}$/u.test(value.credential.id) ||
    typeof value.credential.discoverable !== "boolean" ||
    typeof value.credential.backupEligible !== "boolean" ||
    typeof value.credential.backedUp !== "boolean" ||
    (value.credential.backedUp && !value.credential.backupEligible) ||
    !Array.isArray(value.credential.transports) ||
    value.credential.transports.length > 6 ||
    new Set(value.credential.transports).size !==
      value.credential.transports.length ||
    value.credential.transports.some(
      (transport) =>
        typeof transport !== "string" ||
        !["ble", "hybrid", "internal", "nfc", "smart_card", "usb"].includes(
          transport,
        ),
    ) ||
    !isRecord(value.session)
  ) {
    throw projectionError();
  }
  requireSessionProjection(value.session);
}

function requireRecoveryMutation(value: unknown): void {
  if (
    !isRecord(value) ||
    !isExactObject(value, ["recoveryCodes", "session"]) ||
    !isRecord(value.session)
  ) {
    throw projectionError();
  }
  requireSessionProjection(value.session);
}

function requireSessionProjection(value: unknown): void {
  if (
    !isRecord(value) ||
    !isExactObject(
      value,
      [
        "absoluteExpiresAt",
        "activeTenantId",
        "authenticationMethod",
        "createdAt",
        "csrfToken",
        "id",
        "idleExpiresAt",
        "lastSeenAt",
        "permissions",
        "user",
      ],
      [
        "absoluteExpiresAt",
        "authenticationMethod",
        "createdAt",
        "csrfToken",
        "id",
        "idleExpiresAt",
        "lastSeenAt",
        "permissions",
        "user",
      ],
    ) ||
    !isUuid(value.id) ||
    typeof value.csrfToken !== "string" ||
    !/^[A-Za-z0-9_-]{43,64}$/u.test(value.csrfToken) ||
    !isRecord(value.user) ||
    !isExactObject(
      value.user,
      ["displayName", "email", "id"],
      ["displayName", "id"],
    ) ||
    !isUuid(value.user.id) ||
    typeof value.user.displayName !== "string" ||
    value.user.displayName.length < 1 ||
    value.user.displayName.length > 160 ||
    value.user.displayName.trim() !== value.user.displayName ||
    /[<>\p{Cc}]/u.test(value.user.displayName) ||
    (value.user.email !== undefined &&
      (typeof value.user.email !== "string" ||
        value.user.email.length > 320 ||
        value.user.email.trim() !== value.user.email ||
        !/^[^\s<>@]+@[^\s<>@]+$/u.test(value.user.email))) ||
    !Array.isArray(value.permissions) ||
    value.permissions.length > 256 ||
    value.permissions.some(
      (permission) =>
        typeof permission !== "string" ||
        !platformPermissionSet.has(permission),
    ) ||
    new Set(value.permissions).size !== value.permissions.length ||
    typeof value.authenticationMethod !== "string" ||
    !sessionAuthenticationMethods.has(value.authenticationMethod) ||
    (value.activeTenantId !== undefined && !isUuid(value.activeTenantId)) ||
    value.id === value.user.id ||
    (value.activeTenantId !== undefined &&
      (value.activeTenantId === value.id ||
        value.activeTenantId === value.user.id)) ||
    !validSessionTimeline(value)
  ) {
    throw projectionError();
  }
}

function validSessionTimeline(value: Record<string, unknown>): boolean {
  const createdAt = parseRfc3339Instant(value.createdAt);
  const lastSeenAt = parseRfc3339Instant(value.lastSeenAt);
  const idleExpiresAt = parseRfc3339Instant(value.idleExpiresAt);
  const absoluteExpiresAt = parseRfc3339Instant(value.absoluteExpiresAt);
  return (
    createdAt !== undefined &&
    lastSeenAt !== undefined &&
    idleExpiresAt !== undefined &&
    absoluteExpiresAt !== undefined &&
    createdAt <= lastSeenAt &&
    lastSeenAt < idleExpiresAt &&
    idleExpiresAt <= absoluteExpiresAt
  );
}

function requireWebAuthnOptions<
  T extends WebAuthnAuthenticationOptions | WebAuthnRegistrationOptions,
>(value: T): T {
  if (
    !isRecord(value) ||
    !isExactObject(value, ["ceremonyId", "expiresAt", "publicKey"]) ||
    !isOpaqueId(value.ceremonyId) ||
    parseRfc3339Instant(value.expiresAt) === undefined ||
    !isRecord(value.publicKey)
  ) {
    throw projectionError();
  }
  return value;
}

function unwrap<T>(result: GeneratedResult<T>): T {
  if (
    result.data !== undefined &&
    result.error === undefined &&
    result.response?.ok === true
  ) {
    return result.data;
  }
  throw new MfaApiError(
    result.response?.status === 401
      ? "The security session expired."
      : result.response?.status === 403
        ? "Fresh local verification or tenant authority is required."
        : result.response?.status === 412
          ? "This device changed. Reload its current version."
          : result.response?.status === 429
            ? "Too many security attempts. Wait before retrying."
            : "The security operation could not be completed.",
    result.response?.status,
  );
}

function requireNoContent(result: GeneratedResult<unknown>): void {
  if (
    result.data !== undefined ||
    result.error !== undefined ||
    result.response?.ok !== true ||
    result.response.status !== 204
  ) {
    throw new MfaApiError(
      result.response?.status === 401
        ? "The security session expired."
        : "The security operation could not be completed.",
      result.response?.status,
    );
  }
}

function requireCsrf(value: string): void {
  requireText(value, 1, 128);
  if (value.includes(","))
    throw new MfaApiError("Session integrity is unavailable.");
}

function requireAction(value: string): void {
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(value)) {
    throw new MfaApiError("The step-up action is invalid.");
  }
}

function requireTotp(value: string): void {
  if (!/^[0-9]{6}$/u.test(value)) {
    throw new MfaApiError("Enter a six-digit authenticator code.");
  }
}

function requireText(value: string, minimum: number, maximum: number): void {
  if (value.length < minimum || value.length > maximum) {
    throw new MfaApiError("A bounded security value is required.");
  }
}

function requireCursor(value: string): void {
  if (!/^[A-Za-z0-9_-]{24}$/u.test(value)) {
    throw new MfaApiError("The device cursor is invalid.");
  }
}

function requireOpaqueId(value: string): void {
  if (!isOpaqueId(value))
    throw new MfaApiError("The MFA challenge is invalid.");
}

function requireUuid(value: string): void {
  if (!isUuid(value)) throw new MfaApiError("The MFA resource is invalid.");
}

function isOpaqueId(value: unknown): value is string {
  return (
    typeof value === "string" &&
    /^(?!A{43}$)[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/u.test(value)
  );
}

function isUuid(value: unknown): value is string {
  return (
    typeof value === "string" &&
    /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(
      value,
    )
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isExactObject(
  value: Record<string, unknown>,
  allowed: readonly string[],
  required: readonly string[] = allowed,
): boolean {
  const keys = Object.keys(value);
  return (
    keys.every((key) => allowed.includes(key)) &&
    required.every((key) => Object.hasOwn(value, key))
  );
}

function projectionError(): MfaApiError {
  return new MfaApiError(
    "The server returned an unsafe security projection. Access was stopped.",
  );
}
