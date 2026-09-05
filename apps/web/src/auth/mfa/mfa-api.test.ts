import { describe, expect, it, vi } from "vitest";

import type {
  FederatedMfaEnrollmentResult,
  MfaDevice,
  MfaDeviceList,
  MfaDeviceMutationResult,
  Session,
  WebAuthnAuthenticationOptions,
} from "@periapsis/contracts";

import {
  createFederatedMfaApi,
  createMfaApi,
  MfaApiError,
  type FederatedMfaTransport,
  type MfaTransport,
} from "./mfa-api";

const deviceId = "01991f20-0000-7000-8000-000000000001";
const opaqueId = "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

const passkey: MfaDevice = {
  backedUp: false,
  backupEligible: true,
  createdAt: "2026-08-26T10:00:00Z",
  discoverable: true,
  displayName: "Work laptop",
  id: deviceId,
  kind: "passkey",
  lastUsedAt: "2026-08-26T10:30:00Z",
  status: "active",
  transports: ["internal"],
  version: 3,
};

describe("MFA API projection", () => {
  it("validates tenant discovery and structurally projects a passkey session", async () => {
    const startPasskeyLogin = vi.fn<MfaTransport["startPasskeyLogin"]>(
      async () => ok(authenticationOptions()),
    );
    const completePasskeyLogin = vi.fn<MfaTransport["completePasskeyLogin"]>(
      async () => ok(sessionResult()),
    );
    const api = createMfaApi(
      createTransport({ completePasskeyLogin, startPasskeyLogin }),
    );

    await expect(api.startPasskeyLogin("not-a-tenant")).rejects.toThrow(
      "MFA resource is invalid",
    );
    expect(startPasskeyLogin).not.toHaveBeenCalled();

    await expect(
      api.startPasskeyLogin("01991f20-0000-7000-8000-000000000020"),
    ).resolves.toEqual(authenticationOptions());
    await expect(
      api.completePasskeyLogin({
        ceremonyId: opaqueId,
        credential: {
          id: "AQ",
          response: {
            authenticatorData: "Ag",
            clientDataJSON: "Aw",
            signature: "BA",
          },
          type: "public-key",
        },
      }),
    ).resolves.toEqual(sessionResult());

    const unsafe = createMfaApi(
      createTransport({
        startPasskeyLogin: async () =>
          ok({ ...authenticationOptions(), ceremonyId: "A".repeat(43) }),
      }),
    );
    await expect(
      unsafe.startPasskeyLogin("01991f20-0000-7000-8000-000000000020"),
    ).rejects.toThrow("unsafe security projection");

    const leaked = createMfaApi(
      createTransport({
        startPasskeyLogin: async () =>
          ok({
            ...authenticationOptions(),
            verifierSecret: "must-not-project",
          }),
      }),
    );
    await expect(
      leaked.startPasskeyLogin("01991f20-0000-7000-8000-000000000020"),
    ).rejects.toThrow("unsafe security projection");
  });

  it("projects a bounded device page and forwards its opaque cursor", async () => {
    const nextCursor = "AQGZmR8gAABwAIAAAAAAAAAA";
    const listDevices = vi.fn<MfaTransport["listDevices"]>(async () =>
      ok<MfaDeviceList>({ items: [passkey], nextCursor }),
    );
    const api = createMfaApi(createTransport({ listDevices }));

    await expect(api.listDevices({ includeRevoked: true })).resolves.toEqual({
      items: [passkey],
      nextCursor,
    });
    expect(listDevices).toHaveBeenCalledWith({ includeRevoked: true });
  });

  it("denies unknown or inconsistent device projections", async () => {
    const unsafe = { ...passkey, credentialPublicKey: "must-not-project" };
    const api = createMfaApi(
      createTransport({
        listDevices: async () => ok<MfaDeviceList>({ items: [unsafe] }),
      }),
    );

    await expect(api.listDevices()).rejects.toThrow(
      "unsafe security projection",
    );

    const invalidTotp = {
      ...passkey,
      displayName: "unexpected",
      kind: "totp" as const,
    };
    const invalidApi = createMfaApi(
      createTransport({
        listDevices: async () => ok({ items: [invalidTotp] }),
      }),
    );
    await expect(invalidApi.listDevices()).rejects.toBeInstanceOf(MfaApiError);
  });

  it("binds rename and revoke to CSRF, kind, body version, and a strong ETag", async () => {
    const renamed = { ...passkey, displayName: "Security key", version: 4 };
    const renamePasskey = vi.fn<MfaTransport["renamePasskey"]>(async () =>
      ok<MfaDeviceMutationResult>(
        { currentSessionRevoked: false, device: renamed },
        { ETag: '"v4"' },
      ),
    );
    const revokeDevice = vi.fn<MfaTransport["revokeDevice"]>(async () =>
      ok<MfaDeviceMutationResult>(
        {
          currentSessionRevoked: true,
          device: {
            ...renamed,
            revokedAt: "2026-08-26T11:00:00Z",
            status: "revoked",
            version: 5,
          },
        },
        { ETag: '"v5"' },
      ),
    );
    const api = createMfaApi(createTransport({ renamePasskey, revokeDevice }));

    await expect(
      api.renamePasskey("csrf-value", passkey, "  Security key  "),
    ).resolves.toMatchObject({ device: renamed });
    expect(renamePasskey).toHaveBeenCalledWith({
      body: { displayName: "Security key", expectedVersion: 3 },
      csrfToken: "csrf-value",
      deviceId,
      etag: '"v3"',
    });

    await expect(
      api.revokeDevice("csrf-value", renamed),
    ).resolves.toMatchObject({ currentSessionRevoked: true });
    expect(revokeDevice).toHaveBeenCalledWith({
      body: { expectedVersion: 4, kind: "passkey" },
      csrfToken: "csrf-value",
      deviceId,
      etag: '"v4"',
    });
  });

  it("rejects a successful mutation without the matching response ETag", async () => {
    const api = createMfaApi(
      createTransport({
        renamePasskey: async () =>
          ok(
            {
              currentSessionRevoked: false,
              device: { ...passkey, displayName: "Renamed", version: 4 },
            },
            { ETag: '"v3"' },
          ),
      }),
    );

    await expect(
      api.renamePasskey("csrf-value", passkey, "Renamed"),
    ).rejects.toThrow("unsafe security projection");
  });

  it("maps authentication and precondition failures without consuming unsafe bodies", async () => {
    const unauthorized = createMfaApi(
      createTransport({
        listDevices: async () => failure(401),
      }),
    );
    await expect(unauthorized.listDevices()).rejects.toMatchObject({
      message: "The security session expired.",
      status: 401,
    });

    const stale = createMfaApi(
      createTransport({
        revokeDevice: async () => failure(412),
      }),
    );
    await expect(
      stale.revokeDevice("csrf-value", passkey),
    ).rejects.toMatchObject({ status: 412 });

    const ambiguous = createMfaApi(
      createTransport({
        listDevices: async () => ({
          data: { items: [passkey] },
          error: { title: "conflicting transport state" },
          response: new Response(null, { status: 200 }),
        }),
      }),
    );
    await expect(ambiguous.listDevices()).rejects.toBeInstanceOf(MfaApiError);
  });
});

describe("federated MFA continuation API", () => {
  it("accepts only exact no-content browser-state recovery responses", async () => {
    const abandonContinuation = vi.fn<
      FederatedMfaTransport["abandonContinuation"]
    >(async () => noContent());
    const cancelCeremony = vi.fn<FederatedMfaTransport["cancelCeremony"]>(
      async () => noContent(),
    );
    const api = createFederatedMfaApi(
      createFederatedTransport({ abandonContinuation, cancelCeremony }),
    );

    await expect(api.cancelCeremony()).resolves.toBeUndefined();
    await expect(api.abandonContinuation()).resolves.toBeUndefined();
    expect(cancelCeremony).toHaveBeenCalledWith();
    expect(abandonContinuation).toHaveBeenCalledWith();

    const ambiguous = createFederatedMfaApi(
      createFederatedTransport({
        cancelCeremony: async () => ok({ leaked: true }),
      }),
    );
    await expect(ambiguous.cancelCeremony()).rejects.toBeInstanceOf(
      MfaApiError,
    );
  });

  it("projects exact TOTP selectors and sends no session or CSRF authority", async () => {
    const factorId = "01991f20-0000-7000-8000-000000000031";
    const startLocalStepUp = vi.fn<FederatedMfaTransport["startLocalStepUp"]>(
      async () =>
        ok({
          challengeId: opaqueId,
          expiresAt: "2026-08-26T12:00:00Z",
          methods: ["totp", "recovery_code"],
          totpFactorIds: [factorId],
        }),
    );
    const completeTotpStepUp = vi.fn<
      FederatedMfaTransport["completeTotpStepUp"]
    >(async () => ok(sessionResult()));
    const api = createFederatedMfaApi(
      createFederatedTransport({ completeTotpStepUp, startLocalStepUp }),
    );

    await expect(api.startLocalStepUp()).resolves.toMatchObject({
      methods: ["totp", "recovery_code"],
      totpFactorIds: [factorId],
    });
    await expect(
      api.completeTotpStepUp(opaqueId, factorId, "123456"),
    ).resolves.toEqual(sessionResult());
    expect(completeTotpStepUp).toHaveBeenCalledWith({
      challengeId: opaqueId,
      code: "123456",
      factorId,
    });
  });

  it("rejects missing, duplicate, or method-inconsistent TOTP selectors", async () => {
    const factorId = "01991f20-0000-7000-8000-000000000031";
    const unsafeChallenges = [
      {
        challengeId: opaqueId,
        expiresAt: "2026-08-26T12:00:00Z",
        methods: ["totp"] as Array<"recovery_code" | "totp">,
        totpFactorIds: [] as string[],
      },
      {
        challengeId: opaqueId,
        expiresAt: "2026-08-26T12:00:00Z",
        methods: ["recovery_code"] as Array<"recovery_code" | "totp">,
        totpFactorIds: [factorId],
      },
      {
        challengeId: opaqueId,
        expiresAt: "2026-08-26T12:00:00Z",
        methods: ["totp"] as Array<"recovery_code" | "totp">,
        totpFactorIds: [factorId, factorId],
      },
    ];
    await Promise.all(
      unsafeChallenges.map(async (challenge) => {
        const api = createFederatedMfaApi(
          createFederatedTransport({
            startLocalStepUp: async () => ok(challenge),
          }),
        );
        await expect(api.startLocalStepUp()).rejects.toThrow(
          "unsafe security projection",
        );
      }),
    );
  });

  it("retains only the typed enrollment continuation result", async () => {
    const factorId = "01991f20-0000-7000-8000-000000000031";
    const completeTotpEnrollment = vi.fn<
      FederatedMfaTransport["completeTotpEnrollment"]
    >(async () =>
      ok<FederatedMfaEnrollmentResult>({ factorId, next: "step_up" }),
    );
    const api = createFederatedMfaApi(
      createFederatedTransport({ completeTotpEnrollment }),
    );

    await expect(
      api.completeTotpEnrollment(
        "01991f20-0000-7000-8000-000000000030",
        "654321",
      ),
    ).resolves.toEqual({ factorId, next: "step_up" });
    expect(completeTotpEnrollment).toHaveBeenCalledWith({
      code: "654321",
      enrollmentId: "01991f20-0000-7000-8000-000000000030",
    });
  });
});

function createTransport(overrides: Partial<MfaTransport> = {}): MfaTransport {
  const unavailable = async () => failure(500);
  return {
    completePasskeyLogin: unavailable,
    completePasskeyRegistration: unavailable,
    completePasskeyStepUp: unavailable,
    completeRecoveryStepUp: unavailable,
    completeTotpEnrollment: unavailable,
    completeTotpStepUp: unavailable,
    listDevices: unavailable,
    regenerateRecoveryCodes: unavailable,
    renamePasskey: unavailable,
    revokeDevice: unavailable,
    startLocalStepUp: unavailable,
    startPasskeyLogin: unavailable,
    startPasskeyRegistration: unavailable,
    startPasskeyStepUp: unavailable,
    startTotpEnrollment: unavailable,
    ...overrides,
  };
}

function createFederatedTransport(
  overrides: Partial<FederatedMfaTransport> = {},
): FederatedMfaTransport {
  const unavailable = async () => failure(500);
  return {
    abandonContinuation: unavailable,
    cancelCeremony: unavailable,
    completePasskeyStepUp: unavailable,
    completeRecoveryStepUp: unavailable,
    completeTotpEnrollment: unavailable,
    completeTotpStepUp: unavailable,
    startLocalStepUp: unavailable,
    startPasskeyStepUp: unavailable,
    startTotpEnrollment: unavailable,
    ...overrides,
  };
}

function noContent(): {
  data: undefined;
  error: undefined;
  response: Response;
} {
  return {
    data: undefined,
    error: undefined,
    response: new Response(null, { status: 204 }),
  };
}

function ok<T>(
  data: T,
  headers: HeadersInit = {},
): {
  data: T;
  error: undefined;
  response: Response;
} {
  return {
    data,
    error: undefined,
    response: new Response(null, { headers, status: 200 }),
  };
}

function failure(status: number): {
  data: undefined;
  error: { title: string };
  response: Response;
} {
  return {
    data: undefined,
    error: { title: "redacted" },
    response: new Response(null, { status }),
  };
}

function authenticationOptions(): WebAuthnAuthenticationOptions {
  return {
    ceremonyId: opaqueId,
    expiresAt: "2026-08-26T12:00:00Z",
    publicKey: {
      allowCredentials: [],
      challenge: opaqueId,
      rpId: "console.example.invalid",
      timeout: 60_000,
      userVerification: "required",
    },
  };
}

function sessionResult(): Session {
  return {
    absoluteExpiresAt: "2026-08-27T10:00:00Z",
    activeTenantId: "01991f20-0000-7000-8000-000000000020",
    authenticationMethod: "passkey",
    createdAt: "2026-08-26T10:00:00Z",
    csrfToken: "C".repeat(43),
    id: "01991f20-0000-7000-8000-000000000021",
    idleExpiresAt: "2026-08-26T11:00:00Z",
    lastSeenAt: "2026-08-26T10:00:00Z",
    permissions: ["platform.audit.read"],
    user: {
      displayName: "Ada Lovelace",
      id: "01991f20-0000-7000-8000-000000000022",
    },
  };
}
