import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { WebAuthnRegistrationOptions } from "@periapsis/contracts";

import { SessionContext } from "../session-context";
import type { SessionView } from "../../lib/phase-two-types";
import {
  createPhaseTwoApi,
  sessionFixture,
} from "../../test/phase-two-fixtures";
import type { MfaApi } from "./mfa-api";
import { MfaSecurityWorkspace } from "./mfa-workspace";
import type { MfaDeviceView } from "./model";
import type { BrowserCredentials } from "./webauthn-browser";

const opaqueId = "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

afterEach(cleanup);

const tenantId = "01991f20-0000-7000-8000-000000000010";
const passkey: MfaDeviceView = {
  backedUp: false,
  backupEligible: true,
  createdAt: "2026-08-26T10:00:00Z",
  discoverable: true,
  displayName: "Work laptop",
  id: "01991f20-0000-7000-8000-000000000011",
  kind: "passkey",
  status: "active",
  transports: ["internal"],
  version: 1,
};

describe("MFA security workspace", () => {
  it("fails closed on a deep link without an active tenant", () => {
    const listDevices = vi.fn<MfaApi["listDevices"]>();
    renderWorkspace({
      activeTenantId: null,
      mfaApi: createMfaApiMock({ listDevices }),
    });

    expect(screen.getByText("Tenant context required")).toBeVisible();
    expect(listDevices).not.toHaveBeenCalled();
  });

  it("does not let an aborted inventory response overwrite a newer filter", async () => {
    const first = createDeferred<{ items: readonly MfaDeviceView[] }>();
    const listDevices = vi
      .fn<MfaApi["listDevices"]>()
      .mockImplementationOnce(async () => first.promise)
      .mockResolvedValueOnce({ items: [passkey] });
    renderWorkspace({ mfaApi: createMfaApiMock({ listDevices }) });

    fireEvent.click(screen.getByRole("checkbox", { name: "Show revoked" }));
    expect(await screen.findByText("Work laptop")).toBeVisible();

    first.resolve({ items: [] });
    await first.promise;
    expect(screen.getByText("Work laptop")).toBeVisible();
    expect(listDevices).toHaveBeenCalledTimes(2);
  });

  it("renders bounded empty inventory and starts local TOTP verification", async () => {
    const totp: MfaDeviceView = {
      ...passkey,
      backedUp: false,
      backupEligible: false,
      discoverable: false,
      displayName: "",
      id: "01991f20-0000-7000-8000-000000000012",
      kind: "totp",
      transports: [],
    };
    const completeTotpStepUp = vi.fn<MfaApi["completeTotpStepUp"]>(
      async () => undefined,
    );
    const updateSession = vi.fn();
    renderWorkspace({
      mfaApi: createMfaApiMock({
        completeTotpStepUp,
        listDevices: async () => ({ items: [totp] }),
        startLocalStepUp: async () => ({
          challengeId: opaqueId,
          expiresAt: "2026-08-26T12:00:00Z",
          methods: ["totp"],
          totpFactorIds: [totp.id],
        }),
      }),
      updateSession,
    });

    expect(await screen.findByText("Authenticator app")).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "Verify code" }));
    fireEvent.change(await screen.findByLabelText("Authenticator code"), {
      target: { value: "123456" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Verify locally" }));

    await waitFor(() =>
      expect(completeTotpStepUp).toHaveBeenCalledWith(
        sessionFixture.csrfToken,
        opaqueId,
        totp.id,
        "123456",
      ),
    );
    expect(updateSession).toHaveBeenCalledWith(
      sessionFixture.id,
      expect.objectContaining({ id: sessionFixture.id }),
    );
  });

  it("completes browser passkey registration and revalidates the rotated session", async () => {
    const completePasskeyRegistration = vi.fn<
      MfaApi["completePasskeyRegistration"]
    >(async () => undefined);
    const updateSession = vi.fn();
    renderWorkspace({
      credentials: {
        create: async () => new FakeRegistrationCredential(),
        get: async () => null,
      },
      mfaApi: createMfaApiMock({
        completePasskeyRegistration,
        listDevices: async () => ({ items: [] }),
        startPasskeyRegistration: async () => registrationOptions(),
      }),
      updateSession,
    });

    await screen.findByText("No MFA devices returned");
    fireEvent.change(screen.getByLabelText("Passkey name"), {
      target: { value: "Work laptop" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Register passkey" }));

    await waitFor(() => expect(completePasskeyRegistration).toHaveBeenCalled());
    expect(completePasskeyRegistration.mock.calls[0]?.[0]).toBe(
      sessionFixture.csrfToken,
    );
    expect(completePasskeyRegistration.mock.calls[0]?.[1]).toMatchObject({
      displayName: "Work laptop",
    });
    expect(updateSession).toHaveBeenCalled();
    expect(
      await screen.findByText(
        /Passkey registered and the browser session rotated/u,
      ),
    ).toBeVisible();
  });

  it("clears local authority when device revocation ends the current session family", async () => {
    const clearSession = vi.fn();
    const getSession = vi.fn();
    const revokeDevice = vi.fn<MfaApi["revokeDevice"]>(async () => ({
      currentSessionRevoked: true,
      device: {
        ...passkey,
        revokedAt: "2026-08-26T11:00:00Z",
        status: "revoked",
        version: 2,
      },
    }));
    renderWorkspace({
      clearSession,
      getSession,
      mfaApi: createMfaApiMock({
        listDevices: async () => ({ items: [passkey] }),
        revokeDevice,
      }),
    });

    fireEvent.click(await screen.findByRole("button", { name: "Revoke" }));
    fireEvent.click(screen.getByRole("button", { name: "Confirm revoke" }));

    await waitFor(() => expect(revokeDevice).toHaveBeenCalled());
    expect(clearSession).toHaveBeenCalledWith(sessionFixture.id);
    expect(getSession).not.toHaveBeenCalled();
  });
});

interface RenderOptions {
  activeTenantId?: string | null;
  clearSession?: (expectedSessionId: string) => void;
  credentials?: BrowserCredentials;
  getSession?: () => Promise<SessionView | null>;
  mfaApi: MfaApi;
  updateSession?: (expectedSessionId: string, session: SessionView) => void;
}

function renderWorkspace(options: RenderOptions): void {
  const session = futureSession({
    ...sessionFixture,
    ...(options.activeTenantId === null
      ? {}
      : { activeTenantId: options.activeTenantId ?? tenantId }),
  });
  const api = createPhaseTwoApi({
    getSession: options.getSession ?? (async () => session),
  });
  render(
    <MemoryRouter initialEntries={["/account/security"]}>
      <SessionContext.Provider
        value={{
          api,
          clearSession: options.clearSession ?? vi.fn(),
          membershipRevision: 0,
          refreshMemberships: vi.fn(),
          session,
          updateSession: options.updateSession ?? vi.fn(),
        }}
      >
        <MfaSecurityWorkspace
          api={options.mfaApi}
          {...(options.credentials ? { credentials: options.credentials } : {})}
        />
      </SessionContext.Provider>
    </MemoryRouter>,
  );
}

function createMfaApiMock(overrides: Partial<MfaApi> = {}): MfaApi {
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

async function unavailable(): Promise<never> {
  throw new Error("Unexpected MFA API call");
}

function registrationOptions(): WebAuthnRegistrationOptions {
  return {
    ceremonyId: opaqueId,
    expiresAt: "2026-08-26T12:00:00Z",
    publicKey: {
      attestation: "none",
      authenticatorSelection: {
        requireResidentKey: true,
        residentKey: "required",
        userVerification: "required",
      },
      challenge: opaqueId,
      excludeCredentials: [],
      pubKeyCredParams: [
        { alg: -7, type: "public-key" },
        { alg: -257, type: "public-key" },
      ],
      rp: { id: "console.example.invalid", name: "Periapsis" },
      timeout: 60_000,
      user: {
        displayName: "Ada Lovelace",
        id: opaqueId,
        name: "ada@example.invalid",
      },
    },
  };
}

class FakeRegistrationCredential implements Credential {
  readonly id = "registration";
  readonly type = "public-key";
  readonly rawId = Uint8Array.from([3]).buffer;
  readonly response = {
    attestationObject: Uint8Array.from([5]).buffer,
    clientDataJSON: Uint8Array.from([4]).buffer,
    getTransports: () => ["internal"],
  };

  getClientExtensionResults(): AuthenticationExtensionsClientOutputs {
    return {};
  }
}

function futureSession(session: SessionView): SessionView {
  return {
    ...session,
    absoluteExpiresAt: "2099-08-26T12:00:00Z",
    idleExpiresAt: "2099-08-26T11:00:00Z",
  };
}

function createDeferred<T>(): {
  promise: Promise<T>;
  resolve: (value: T) => void;
} {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((promiseResolve) => {
    resolve = promiseResolve;
  });
  return { promise, resolve };
}
