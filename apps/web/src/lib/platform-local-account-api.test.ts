import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { phaseTwoApi } from "./phase-two-api";
import type {
  PlatformLocalAccountView,
  VersionedView,
} from "./phase-two-types";

const accountId = "0198c97d-cf4f-7000-8000-000000000081";
const userId = "0198c97d-cf4f-7000-8000-000000000082";
const otherAccountId = "0198c97d-cf4f-7000-8000-000000000083";
const publicOrigin = "https://soc.example.com";
const enrollmentSecret = "JBSWY3DPEHPK3PXP";
const ceremonyToken = `${"B".repeat(42)}A`;
const enrollmentUri =
  `otpauth://totp/Periapsis:${accountId}` +
  `?algorithm=SHA1&digits=6&issuer=Periapsis&period=30&secret=${enrollmentSecret}`;

beforeEach(() => {
  vi.stubGlobal("location", { origin: publicOrigin });
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("phaseTwoApi protected platform local-account administration", () => {
  it("sends the exact invitation headers and accepts the enrollment bundle only once", async () => {
    const requests: Request[] = [];
    let call = 0;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (!(input instanceof Request)) throw new Error("Expected Request");
        requests.push(input);
        call += 1;
        return mutationResponse(
          {
            account: invitedAccount(),
            ...(call === 1
              ? {
                  ceremonyToken,
                  totpEnrollment: {
                    provisioningUri: enrollmentUri,
                    secret: enrollmentSecret,
                  },
                }
              : {}),
            replayed: call > 1,
          },
          201,
          '"v1"',
          `/api/v1/platform/local-accounts/${accountId}`,
        );
      }),
    );

    const input = {
      displayName: "Emergency Operator",
      loginIdentifier: "emergency@example.test",
      protectedRecoveryPrincipal: true,
    };
    const first = await phaseTwoApi.invitePlatformLocalAccount(
      "csrf-memory-only",
      "local-account-invite-0001",
      "Provision reviewed recovery operator",
      input,
    );
    expect(first).toMatchObject({
      ceremonyToken,
      location: `/api/v1/platform/local-accounts/${accountId}`,
      replayed: false,
      totpEnrollment: {
        provisioningUri: enrollmentUri,
        secret: enrollmentSecret,
      },
    });

    const request = requests[0];
    if (!request) throw new Error("Generated client did not call fetch.");
    expect(request.method).toBe("POST");
    expect(request.cache).toBe("no-store");
    expect(request.headers.get("Idempotency-Key")).toBe(
      "local-account-invite-0001",
    );
    expect(request.headers.get("X-Audit-Reason")).toBe(
      "Provision reviewed recovery operator",
    );
    expect(await request.json()).toEqual(input);

    const replay = await phaseTwoApi.invitePlatformLocalAccount(
      "csrf-memory-only",
      "local-account-invite-0001",
      "Provision reviewed recovery operator",
      input,
    );
    expect(replay).toEqual({
      account: { etag: '"v1"', value: invitedAccount() },
      location: `/api/v1/platform/local-accounts/${accountId}`,
      replayed: true,
    });
  });

  it.each([
    {
      label: "token without enrollment",
      payload: {
        account: invitedAccount(),
        ceremonyToken,
        replayed: false,
      },
    },
    {
      label: "customer-bearing enrollment label",
      payload: {
        account: invitedAccount(),
        ceremonyToken,
        replayed: false,
        totpEnrollment: {
          provisioningUri:
            "otpauth://totp/Periapsis:customer@example.test" +
            `?issuer=Periapsis&secret=${enrollmentSecret}`,
          secret: enrollmentSecret,
        },
      },
    },
    {
      label: "cross-account enrollment label",
      payload: {
        account: invitedAccount(),
        ceremonyToken,
        replayed: false,
        totpEnrollment: {
          provisioningUri:
            `otpauth://totp/Periapsis:${otherAccountId}` +
            `?issuer=Periapsis&secret=${enrollmentSecret}`,
          secret: enrollmentSecret,
        },
      },
    },
    {
      label: "zero enrollment secret",
      payload: {
        account: invitedAccount(),
        ceremonyToken,
        replayed: false,
        totpEnrollment: {
          provisioningUri:
            `otpauth://totp/Periapsis:${accountId}` +
            `?issuer=Periapsis&secret=${"A".repeat(16)}`,
          secret: "A".repeat(16),
        },
      },
    },
    {
      label: "artifact on replay",
      payload: {
        account: invitedAccount(),
        ceremonyToken,
        replayed: true,
        totpEnrollment: {
          provisioningUri: enrollmentUri,
          secret: enrollmentSecret,
        },
      },
    },
  ])("rejects $label", async ({ payload }) => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValue(
          mutationResponse(
            payload,
            201,
            '"v1"',
            `/api/v1/platform/local-accounts/${accountId}`,
          ),
        ),
    );

    await expect(
      phaseTwoApi.invitePlatformLocalAccount(
        "csrf-memory-only",
        "local-account-invite-0001",
        "Provision reviewed recovery operator",
        {
          displayName: "Emergency Operator",
          loginIdentifier: "emergency@example.test",
          protectedRecoveryPrincipal: true,
        },
      ),
    ).rejects.toMatchObject({ code: "tenant_projection_mismatch" });
  });

  it("binds activation body and CAS headers to the current safe projection", async () => {
    const requests: Request[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (input instanceof Request) requests.push(input);
        return mutationResponse(
          { account: activeAccount(), replayed: false },
          200,
          '"v2"',
        );
      }),
    );
    const current: VersionedView<PlatformLocalAccountView> = {
      etag: '"v1"',
      value: invitedAccount(),
    };

    await expect(
      phaseTwoApi.activatePlatformLocalAccount(
        "csrf-memory-only",
        accountId,
        current,
        "local-activate-0001",
        "Complete reviewed recovery enrollment",
        {
          ceremonyToken,
          factorProof: "123456",
          newPassword: "correct horse battery staple",
        },
      ),
    ).resolves.toMatchObject({
      account: { etag: '"v2"', value: { revision: 2, status: "active" } },
      replayed: false,
    });

    const request = requests[0];
    if (!request) throw new Error("Generated client did not call fetch.");
    expect(request.headers.get("If-Match")).toBe('"v1"');
    expect(request.headers.get("Idempotency-Key")).toBe("local-activate-0001");
    expect(await request.json()).toEqual({
      ceremonyToken,
      expectedRevision: 1,
      factorProof: "123456",
      newPassword: "correct horse battery staple",
    });
  });

  it("rejects unsafe read projections and readback enrollment fields", async () => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValue(
          mutationResponse(
            { ...activeAccount(), passwordHash: "must-not-cross" },
            200,
            '"v2"',
          ),
        ),
    );

    await expect(
      phaseTwoApi.getPlatformLocalAccount(accountId),
    ).rejects.toMatchObject({ code: "tenant_projection_mismatch" });
  });

  it("fails before transport for malformed activation material", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    await expect(
      phaseTwoApi.activatePlatformLocalAccount(
        "csrf-memory-only",
        accountId,
        { etag: '"v1"', value: invitedAccount() },
        "local-activate-0001",
        "Complete reviewed recovery enrollment",
        {
          ceremonyToken: "short",
          factorProof: "123456",
          newPassword: "correct horse battery staple",
        },
      ),
    ).rejects.toBeInstanceOf(Error);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it.each(["A".repeat(43), `${"B".repeat(42)}B`])(
    "fails before transport for noncanonical token %s",
    async (token) => {
      const fetchMock = vi.fn();
      vi.stubGlobal("fetch", fetchMock);

      await expect(
        phaseTwoApi.activatePlatformLocalAccount(
          "csrf-memory-only",
          accountId,
          { etag: '"v1"', value: invitedAccount() },
          "local-activate-0001",
          "Complete reviewed recovery enrollment",
          {
            ceremonyToken: token,
            factorProof: "123456",
            newPassword: "correct horse battery staple",
          },
        ),
      ).rejects.toBeInstanceOf(Error);
      expect(fetchMock).not.toHaveBeenCalled();
    },
  );
});

function mutationResponse(
  body: unknown,
  status: number,
  etag: string,
  location?: string,
): Response {
  return new Response(JSON.stringify(body), {
    headers: {
      "Cache-Control": "no-store",
      "Content-Type": "application/json",
      ETag: etag,
      ...(location === undefined ? {} : { Location: location }),
    },
    status,
  });
}

function invitedAccount(): PlatformLocalAccountView {
  return {
    activatedAt: null,
    confirmedAcceptableFactors: 0,
    credentialStatus: "pending",
    credentialVersion: 0,
    disabledAt: null,
    displayName: "Emergency Operator",
    id: accountId,
    identityEpoch: 1,
    invitedAt: "2026-08-30T12:00:00Z",
    loginIdentifier: "emergency@example.test",
    loginIdentifierStatus: "pending",
    protectedRecoveryPrincipal: true,
    recoveryStartedAt: null,
    revision: 1,
    status: "invited",
    updatedAt: "2026-08-30T12:00:00Z",
    userId,
  };
}

function activeAccount(): PlatformLocalAccountView {
  return {
    ...invitedAccount(),
    activatedAt: "2026-08-30T12:01:00Z",
    confirmedAcceptableFactors: 1,
    credentialStatus: "active",
    credentialVersion: 1,
    identityEpoch: 2,
    loginIdentifierStatus: "verified",
    revision: 2,
    status: "active",
    updatedAt: "2026-08-30T12:01:00Z",
  };
}
