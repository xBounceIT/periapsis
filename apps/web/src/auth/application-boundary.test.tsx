import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { describe, expect, it, vi } from "vitest";

import { createPhaseTwoApi, sessionFixture } from "../test/phase-two-fixtures";
import { ApplicationBoundary } from "./application-boundary";
import type { FederatedMfaApi } from "./mfa/mfa-api";

describe("ApplicationBoundary", () => {
  it("keeps bootstrap secrets in the live flow and binds confirmation to the reserved email", async () => {
    const setItem = vi.spyOn(Storage.prototype, "setItem");
    const enrollBootstrap = vi.fn(async () => ({
      enrollmentToken: "e".repeat(43),
      expiresAt: "2026-08-23T11:30:00Z",
      totpSecret: "A".repeat(32),
      totpUri: "otpauth://totp/Periapsis:admin%40example.invalid?secret=AAAA",
    }));
    const confirmBootstrap = vi.fn(async () => ({
      recoveryCodes: Array.from(
        { length: 10 },
        (_, index) =>
          `recovery-${String(index).padStart(2, "0")}-${"x".repeat(24)}`,
      ),
      session: sessionFixture,
    }));
    const api = createPhaseTwoApi({
      confirmBootstrap,
      enrollBootstrap,
      getBootstrapStatus: async () => ({ available: true }),
    });

    render(
      <MemoryRouter>
        <ApplicationBoundary api={api} />
      </MemoryRouter>,
    );

    fireEvent.change(
      await screen.findByLabelText("Deployment bootstrap token"),
      { target: { value: "deployment-secret" } },
    );
    fireEvent.change(screen.getByLabelText("Administrator email"), {
      target: { value: "ADMIN@example.invalid " },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Generate TOTP enrollment" }),
    );

    expect(await screen.findByText("Manual enrollment")).toBeVisible();
    expect(enrollBootstrap).toHaveBeenCalledWith({
      bootstrapToken: "deployment-secret",
      email: "admin@example.invalid",
    });

    const reservedEmail = screen.getByLabelText("Reserved email");
    expect(reservedEmail).toHaveValue("admin@example.invalid");
    expect(reservedEmail).toHaveAttribute("readonly");

    fireEvent.change(screen.getByLabelText("Deployment bootstrap token"), {
      target: { value: "deployment-secret" },
    });
    fireEvent.change(screen.getByLabelText("Display name"), {
      target: { value: "Break Glass Admin" },
    });
    fireEvent.change(screen.getByLabelText("Authenticator code"), {
      target: { value: "123456" },
    });
    fireEvent.change(screen.getByLabelText("Password"), {
      target: { value: "correct-horse-battery-staple" },
    });
    fireEvent.change(screen.getByLabelText("Confirm password"), {
      target: { value: "correct-horse-battery-staple" },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Create break-glass administrator" }),
    );

    expect(await screen.findByText("Recovery codes")).toBeVisible();
    expect(confirmBootstrap).toHaveBeenCalledWith({
      bootstrapToken: "deployment-secret",
      code: "123456",
      displayName: "Break Glass Admin",
      email: "admin@example.invalid",
      enrollmentToken: "e".repeat(43),
      password: "correct-horse-battery-staple",
    });
    expect(setItem).not.toHaveBeenCalled();
    setItem.mockRestore();
  });

  it("completes a recovery-code MFA challenge before creating client session state", async () => {
    const completeMfa = vi.fn(async () => sessionFixture);
    const api = createPhaseTwoApi({
      completeMfa,
      getBootstrapStatus: async () => ({ available: false }),
      getSession: async () => null,
      login: async () => ({
        challengeToken: "c".repeat(43),
        expiresAt: "2026-08-23T11:30:00Z",
        methods: ["totp", "recovery_code"],
      }),
    });

    render(
      <MemoryRouter>
        <ApplicationBoundary api={api} />
      </MemoryRouter>,
    );

    fireEvent.change(await screen.findByLabelText("Email"), {
      target: { value: "ada@example.invalid" },
    });
    fireEvent.change(screen.getByLabelText("Password"), {
      target: { value: "not-kept-after-submit" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Continue to MFA" }));

    fireEvent.click(
      await screen.findByRole("button", { name: "Recovery code" }),
    );
    fireEvent.change(screen.getByLabelText("Recovery code"), {
      target: { value: "r".repeat(32) },
    });
    fireEvent.click(screen.getByRole("button", { name: "Verify and sign in" }));

    await waitFor(() =>
      expect(completeMfa).toHaveBeenCalledWith({
        challengeToken: "c".repeat(43),
        code: "r".repeat(32),
        method: "recovery_code",
      }),
    );
  });

  it("enters the exact federated continuation marker without probing session authority", async () => {
    const getBootstrapStatus = vi.fn(async () => ({ available: false }));
    const getSession = vi.fn(async () => null);
    const api = createPhaseTwoApi({ getBootstrapStatus, getSession });

    render(
      <MemoryRouter initialEntries={["/?auth=federated-mfa"]}>
        <ApplicationBoundary
          api={api}
          federatedMfaApi={createFederatedMfaApiMock()}
        />
      </MemoryRouter>,
    );

    expect(await screen.findByText("Complete local MFA.")).toBeVisible();
    expect(getBootstrapStatus).not.toHaveBeenCalled();
    expect(getSession).not.toHaveBeenCalled();
  });
});

function createFederatedMfaApiMock(): FederatedMfaApi {
  return {
    abandonContinuation: unavailableFederatedMfaOperation,
    cancelCeremony: unavailableFederatedMfaOperation,
    completePasskeyStepUp: unavailableFederatedMfaOperation,
    completeRecoveryStepUp: unavailableFederatedMfaOperation,
    completeTotpEnrollment: unavailableFederatedMfaOperation,
    completeTotpStepUp: unavailableFederatedMfaOperation,
    startLocalStepUp: unavailableFederatedMfaOperation,
    startPasskeyStepUp: unavailableFederatedMfaOperation,
    startTotpEnrollment: unavailableFederatedMfaOperation,
  };
}

async function unavailableFederatedMfaOperation(): Promise<never> {
  throw new Error("unavailable");
}
