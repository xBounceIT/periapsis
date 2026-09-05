import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { SessionContext } from "../auth/session-context";
import type {
  PhaseTwoApi,
  PlatformLocalAccountView,
  SessionView,
} from "../lib/phase-two-types";
import { createPhaseTwoApi, sessionFixture } from "../test/phase-two-fixtures";
import { PlatformLocalAccountsPage } from "./platform-local-accounts";

const accountId = "0198c97d-cf4f-7000-8000-000000000081";
const userId = "0198c97d-cf4f-7000-8000-000000000082";
const sessionId = "0198c97d-cf4f-7000-8000-000000000091";
const enrollmentSecret = "JBSWY3DPEHPK3PXP";
const ceremonyToken = `${"B".repeat(42)}A`;
const enrollmentUri =
  `otpauth://totp/Periapsis:${accountId}` +
  `?issuer=Periapsis&secret=${enrollmentSecret}`;

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe("PlatformLocalAccountsPage", () => {
  it("keeps controls hidden for a read-only platform session", async () => {
    const list = vi.fn<PhaseTwoApi["listPlatformLocalAccounts"]>(async () => ({
      items: [activeAccount()],
    }));
    const get = vi.fn<PhaseTwoApi["getPlatformLocalAccount"]>(async () => ({
      etag: '"v2"',
      value: activeAccount(),
    }));
    renderPage(
      { getPlatformLocalAccount: get, listPlatformLocalAccounts: list },
      ["platform.identity_account.read"],
    );

    const row = await findAccountRow();
    expect(within(row).getByRole("button", { name: /Inspect/ })).toBeVisible();
    expect(
      screen.queryByRole("button", { name: "Invite recovery account" }),
    ).not.toBeInTheDocument();
    fireEvent.click(within(row).getByRole("button", { name: /Inspect/ }));
    expect(await screen.findByText("Read-only platform access")).toBeVisible();
    expect(get).toHaveBeenCalledWith(accountId);
    expect(
      screen.queryByRole("button", { name: "Disable and revoke sessions" }),
    ).not.toBeInTheDocument();
  });

  it("shows the token, secret, and canonical URI once after invitation", async () => {
    vi.spyOn(globalThis.crypto, "randomUUID").mockReturnValue(
      "0198c97d-cf4f-7000-8000-000000000099",
    );
    const invite = vi.fn<PhaseTwoApi["invitePlatformLocalAccount"]>(
      async () => ({
        account: { etag: '"v1"', value: invitedAccount() },
        ceremonyToken,
        location: `/api/v1/platform/local-accounts/${accountId}`,
        replayed: false,
        totpEnrollment: {
          provisioningUri: enrollmentUri,
          secret: enrollmentSecret,
        },
      }),
    );
    renderPage({ invitePlatformLocalAccount: invite });

    fireEvent.click(
      await screen.findByRole("button", { name: "Invite recovery account" }),
    );
    const form = screen.getByRole("form", {
      name: "Invite local recovery account",
    });
    fireEvent.change(within(form).getByLabelText("Display name"), {
      target: { value: "Emergency Operator" },
    });
    fireEvent.change(within(form).getByLabelText("Login email"), {
      target: { value: "EMERGENCY@EXAMPLE.TEST" },
    });
    fireEvent.change(within(form).getByLabelText("Audit reason"), {
      target: { value: "Provision reviewed recovery operator" },
    });
    fireEvent.click(
      within(form).getByRole("button", { name: "Invite account" }),
    );

    await waitFor(() =>
      expect(invite).toHaveBeenCalledWith(
        sessionFixture.csrfToken,
        "0198c97d-cf4f-7000-8000-000000000099",
        "Provision reviewed recovery operator",
        {
          displayName: "Emergency Operator",
          loginIdentifier: "emergency@example.test",
          protectedRecoveryPrincipal: true,
        },
      ),
    );
    expect(screen.getByText(ceremonyToken)).toBeVisible();
    expect(screen.getByText(enrollmentSecret)).toBeVisible();
    expect(screen.getByText(enrollmentUri)).toBeVisible();
    expect(
      screen.getByText(/None of this material can be read again/i),
    ).toBeVisible();

    fireEvent.click(
      screen.getByRole("button", {
        name: "I have stored the enrollment material",
      }),
    );
    expect(screen.queryByText(enrollmentSecret)).not.toBeInTheDocument();
    expect(screen.queryByText(enrollmentUri)).not.toBeInTheDocument();
    expect(screen.queryByText(ceremonyToken)).not.toBeInTheDocument();
  });

  it("binds activation to the fetched revision and clears the sensitive draft", async () => {
    vi.spyOn(globalThis.crypto, "randomUUID").mockReturnValue(
      "0198c97d-cf4f-7000-8000-000000000099",
    );
    const activate = vi.fn<PhaseTwoApi["activatePlatformLocalAccount"]>(
      async () => ({
        account: { etag: '"v2"', value: activeAccount() },
        replayed: false,
      }),
    );
    const list = vi.fn<PhaseTwoApi["listPlatformLocalAccounts"]>(async () => ({
      items: [invitedAccount()],
    }));
    renderPage({
      activatePlatformLocalAccount: activate,
      getPlatformLocalAccount: async () => ({
        etag: '"v1"',
        value: invitedAccount(),
      }),
      listPlatformLocalAccounts: list,
    });

    await waitFor(() => expect(list).toHaveBeenCalled());
    fireEvent.click(within(await findAccountRow()).getByRole("button"));
    expect(await screen.findByText("Activation ceremony")).toBeVisible();
    fireEvent.change(screen.getByLabelText("Audit reason"), {
      target: { value: "Complete reviewed recovery enrollment" },
    });
    fireEvent.change(screen.getByLabelText("One-time token"), {
      target: { value: ceremonyToken },
    });
    fireEvent.change(screen.getByLabelText("New password"), {
      target: { value: "correct horse battery staple" },
    });
    fireEvent.change(screen.getByLabelText("Local factor proof"), {
      target: { value: "123456" },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Complete activation" }),
    );

    await waitFor(() =>
      expect(activate).toHaveBeenCalledWith(
        sessionFixture.csrfToken,
        accountId,
        { etag: '"v1"', value: invitedAccount() },
        "0198c97d-cf4f-7000-8000-000000000099",
        "Complete reviewed recovery enrollment",
        {
          ceremonyToken,
          factorProof: "123456",
          newPassword: "correct horse battery staple",
        },
      ),
    );
    expect(screen.queryByLabelText("One-time token")).not.toBeInTheDocument();
    expect(
      screen.queryByDisplayValue("correct horse battery staple"),
    ).not.toBeInTheDocument();
    expect(screen.queryByDisplayValue("123456")).not.toBeInTheDocument();
  });

  it("rejects a noncanonical or zero ceremony token before dispatch", async () => {
    const activate = vi.fn<PhaseTwoApi["activatePlatformLocalAccount"]>();
    renderPage({
      activatePlatformLocalAccount: activate,
      getPlatformLocalAccount: async () => ({
        etag: '"v1"',
        value: invitedAccount(),
      }),
      listPlatformLocalAccounts: async () => ({ items: [invitedAccount()] }),
    });

    fireEvent.click(within(await findAccountRow()).getByRole("button"));
    expect(await screen.findByText("Activation ceremony")).toBeVisible();
    fireEvent.change(screen.getByLabelText("Audit reason"), {
      target: { value: "Complete reviewed recovery enrollment" },
    });
    fireEvent.change(screen.getByLabelText("One-time token"), {
      target: { value: "A".repeat(43) },
    });
    fireEvent.change(screen.getByLabelText("New password"), {
      target: { value: "correct horse battery staple" },
    });
    fireEvent.change(screen.getByLabelText("Local factor proof"), {
      target: { value: "123456" },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Complete activation" }),
    );

    expect(activate).not.toHaveBeenCalled();
    expect(screen.getByText(/canonical 43-character token/i)).toBeVisible();
  });
});

function renderPage(
  overrides: Partial<PhaseTwoApi> = {},
  permissions: SessionView["permissions"] = [
    "platform.identity_account.read",
    "platform.identity_account.manage",
  ],
): void {
  const api = createPhaseTwoApi({
    listPlatformLocalAccounts: async () => ({ items: [] }),
    ...overrides,
  });
  const session: SessionView = {
    ...sessionFixture,
    id: sessionId,
    permissions,
  };
  render(
    <SessionContext.Provider
      value={{
        api,
        clearSession: vi.fn(),
        membershipRevision: 0,
        refreshMemberships: vi.fn(),
        session,
        updateSession: vi.fn(),
      }}
    >
      <PlatformLocalAccountsPage />
    </SessionContext.Provider>,
  );
}

async function findAccountRow(): Promise<HTMLElement> {
  const matches = await screen.findAllByText("Emergency Operator");
  const identity = matches.find((element) => element.tagName === "STRONG");
  const row = identity?.closest("tr");
  if (!row) throw new Error("Local account row is missing");
  return row;
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
