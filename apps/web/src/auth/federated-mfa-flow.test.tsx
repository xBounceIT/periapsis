import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { Session } from "@periapsis/contracts";

import { sessionFixture } from "../test/phase-two-fixtures";
import { FederatedMfaFlow } from "./federated-mfa-flow";
import type { FederatedMfaApi } from "./mfa/mfa-api";
import type { BrowserCredentials } from "./mfa/webauthn-browser";

const challengeId = "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const factorId = "01991f20-0000-7000-8000-000000000031";

afterEach(cleanup);

describe("federated MFA continuation flow", () => {
  it("uses the exact server-projected TOTP selector to create the first session", async () => {
    const authenticatedSession: Session = {
      ...sessionFixture,
      authenticationMethod: "totp" as const,
      createdAt: "2026-08-26T10:00:00Z",
      lastSeenAt: "2026-08-26T10:00:00Z",
      permissions: [],
    };
    const completeTotpStepUp = vi.fn<FederatedMfaApi["completeTotpStepUp"]>(
      async () => authenticatedSession,
    );
    const onAuthenticated = vi.fn();
    render(
      <FederatedMfaFlow
        api={createApi({
          completeTotpStepUp,
          startLocalStepUp: async () => ({
            challengeId,
            expiresAt: "2026-08-26T12:00:00Z",
            methods: ["totp", "recovery_code"],
            totpFactorIds: [factorId],
          }),
        })}
        onAuthenticated={onAuthenticated}
        onRestart={vi.fn()}
      />,
    );

    fireEvent.click(
      screen.getByRole("button", { name: "Use local verification" }),
    );
    fireEvent.change(await screen.findByLabelText("Authenticator code"), {
      target: { value: "123456" },
    });
    expect(screen.queryByText(factorId)).not.toBeInTheDocument();
    fireEvent.click(
      screen.getByRole("button", { name: "Verify and create session" }),
    );

    await waitFor(() =>
      expect(completeTotpStepUp).toHaveBeenCalledWith(
        challengeId,
        factorId,
        "123456",
      ),
    );
    expect(onAuthenticated).toHaveBeenCalledWith(authenticatedSession);
  });

  it("keeps enrollment separate and requires a subsequent step-up", async () => {
    const completeTotpEnrollment = vi.fn<
      FederatedMfaApi["completeTotpEnrollment"]
    >(async () => ({ factorId, next: "step_up" }));
    const onAuthenticated = vi.fn();
    render(
      <FederatedMfaFlow
        api={createApi({
          completeTotpEnrollment,
          startTotpEnrollment: async () => ({
            enrollmentId: "01991f20-0000-7000-8000-000000000030",
            expiresAt: "2026-08-26T12:00:00Z",
            provisioningUri:
              "otpauth://totp/Periapsis:Ada?secret=AAAAAAAAAAAAAAAA",
            secret: "AAAAAAAAAAAAAAAA",
          }),
        })}
        onAuthenticated={onAuthenticated}
        onRestart={vi.fn()}
      />,
    );

    fireEvent.click(
      screen.getByRole("button", { name: "Set up an authenticator" }),
    );
    expect(await screen.findByText("AAAAAAAAAAAAAAAA")).toBeVisible();
    fireEvent.change(screen.getByLabelText("Current six-digit code"), {
      target: { value: "654321" },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Confirm authenticator" }),
    );

    expect(
      await screen.findByText(/Now start a separate local proof/u),
    ).toBeVisible();
    expect(completeTotpEnrollment).toHaveBeenCalledWith(
      "01991f20-0000-7000-8000-000000000030",
      "654321",
    );
    expect(onAuthenticated).not.toHaveBeenCalled();
    expect(
      screen.getByRole("button", { name: "Use local verification" }),
    ).toBeEnabled();
  });

  it("returns to method choice after a consumed failed challenge", async () => {
    render(
      <FederatedMfaFlow
        api={createApi({
          completeRecoveryStepUp: async () => {
            throw new Error("denied");
          },
          startLocalStepUp: async () => ({
            challengeId,
            expiresAt: "2026-08-26T12:00:00Z",
            methods: ["recovery_code"],
            totpFactorIds: [],
          }),
        })}
        onAuthenticated={vi.fn()}
        onRestart={vi.fn()}
      />,
    );

    fireEvent.click(
      screen.getByRole("button", { name: "Use local verification" }),
    );
    fireEvent.change(await screen.findByLabelText("Recovery code"), {
      target: { value: "R".repeat(32) },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Verify and create session" }),
    );

    expect(
      await screen.findByText(/Start a new one-use challenge/u),
    ).toBeVisible();
    expect(
      screen.getByRole("button", { name: "Use local verification" }),
    ).toBeEnabled();
  });

  it("discards the exact ceremony before offering a different proof", async () => {
    const cancelCeremony = vi.fn<FederatedMfaApi["cancelCeremony"]>(
      async () => undefined,
    );
    render(
      <FederatedMfaFlow
        api={createApi({
          cancelCeremony,
          startLocalStepUp: async () => ({
            challengeId,
            expiresAt: "2026-08-26T12:00:00Z",
            methods: ["totp"],
            totpFactorIds: [factorId],
          }),
        })}
        onAuthenticated={vi.fn()}
        onRestart={vi.fn()}
      />,
    );

    fireEvent.click(
      screen.getByRole("button", { name: "Use local verification" }),
    );
    fireEvent.click(
      await screen.findByRole("button", { name: "Choose another method" }),
    );

    await waitFor(() => expect(cancelCeremony).toHaveBeenCalledOnce());
    expect(
      screen.getByRole("button", { name: "Use local verification" }),
    ).toBeEnabled();
  });

  it("cancels a browser-aborted passkey ceremony", async () => {
    const cancelCeremony = vi.fn<FederatedMfaApi["cancelCeremony"]>(
      async () => undefined,
    );
    const credentials: BrowserCredentials = {
      create: async () => null,
      get: async () => null,
    };
    render(
      <FederatedMfaFlow
        api={createApi({
          cancelCeremony,
          startPasskeyStepUp: async () => ({
            ceremonyId: challengeId,
            expiresAt: "2026-08-26T12:00:00Z",
            publicKey: {
              allowCredentials: [],
              challenge: challengeId,
              rpId: "console.example.invalid",
              timeout: 60_000,
              userVerification: "required",
            },
          }),
        })}
        credentials={credentials}
        onAuthenticated={vi.fn()}
        onRestart={vi.fn()}
      />,
    );

    fireEvent.click(
      screen.getByRole("button", { name: "Verify with passkey" }),
    );

    await waitFor(() => expect(cancelCeremony).toHaveBeenCalledOnce());
    expect(
      await screen.findByText(/passkey proof was cancelled/u),
    ).toBeVisible();
  });

  it("clears all anonymous federated state before restarting sign in", async () => {
    const abandonContinuation = vi.fn<FederatedMfaApi["abandonContinuation"]>(
      async () => undefined,
    );
    const onRestart = vi.fn();
    render(
      <FederatedMfaFlow
        api={createApi({ abandonContinuation })}
        onAuthenticated={vi.fn()}
        onRestart={onRestart}
      />,
    );

    fireEvent.click(
      screen.getByRole("button", { name: "Restart organization sign in" }),
    );

    await waitFor(() => expect(abandonContinuation).toHaveBeenCalledOnce());
    expect(onRestart).toHaveBeenCalledOnce();
  });
});

function createApi(overrides: Partial<FederatedMfaApi> = {}): FederatedMfaApi {
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
    ...overrides,
  };
}

async function unavailableFederatedMfaOperation(): Promise<never> {
  throw new Error("unavailable");
}
