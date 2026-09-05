import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import type {
  Session,
  WebAuthnAuthenticationOptions,
} from "@periapsis/contracts";

import { createPhaseTwoApi } from "../test/phase-two-fixtures";
import { LoginFlow } from "./login-flow";
import type { MfaApi } from "./mfa/mfa-api";
import type { BrowserCredentials } from "./mfa/webauthn-browser";

afterEach(cleanup);

const tenantId = "01991f20-0000-7000-8000-000000000020";
const ceremonyId = "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

describe("organization SSO", () => {
  it("mounts physically separate tenant and platform SSO starts beside emergency login", () => {
    render(<LoginFlow api={createPhaseTwoApi()} onAuthenticated={vi.fn()} />);

    expect(screen.getByText("Organization SSO")).toBeVisible();
    expect(screen.getByText("Organization directory")).toBeVisible();
    expect(screen.getByText("Platform SSO")).toBeVisible();
    expect(screen.getByText("Emergency local sign-in")).toBeVisible();
    fireEvent.change(screen.getByLabelText("Tenant slug"), {
      target: { value: "acme-soc" },
    });
    fireEvent.change(screen.getByLabelText("Provider login key"), {
      target: { value: "primary_oidc" },
    });

    expect(
      screen.getByRole("button", { name: "Continue with OIDC" }),
    ).toHaveAttribute(
      "formaction",
      "/api/v1/auth/federated/oidc/acme-soc/primary_oidc/start",
    );
    expect(
      screen.getByRole("button", { name: "Continue with SAML" }),
    ).toHaveAttribute(
      "formaction",
      "/api/v1/auth/federated/saml/acme-soc/primary_oidc/start",
    );

    fireEvent.change(screen.getByLabelText("Directory tenant slug"), {
      target: { value: "acme-soc" },
    });
    fireEvent.change(screen.getByLabelText("Directory login key"), {
      target: { value: "employees_ad" },
    });
    expect(
      screen.getByRole("button", { name: "Continue with directory" }),
    ).toHaveAttribute("type", "submit");
    expect(screen.getByLabelText("Directory password")).toHaveAttribute(
      "name",
      "password",
    );

    fireEvent.change(screen.getByLabelText("Platform provider key"), {
      target: { value: "workforce_oidc" },
    });
    expect(
      screen.getByRole("button", { name: "Continue with platform OIDC" }),
    ).toHaveAttribute(
      "formaction",
      "/api/v1/auth/platform/oidc/workforce_oidc/start",
    );
    expect(
      screen.getByRole("button", { name: "Continue with platform SAML" }),
    ).toHaveAttribute(
      "formaction",
      "/api/v1/auth/platform/saml/workforce_oidc/start",
    );
    fireEvent.change(screen.getByLabelText("Platform LDAP provider key"), {
      target: { value: "workforce_ldap" },
    });
    expect(
      screen.getByRole("button", { name: "Continue with platform LDAP" }),
    ).toHaveAttribute(
      "formaction",
      "/api/v1/auth/platform/ldap/workforce_ldap",
    );
  });
});

describe("passkey login", () => {
  it("keeps tenant discovery explicit and authenticates from the browser assertion", async () => {
    const startPasskeyLogin = vi.fn<
      Pick<MfaApi, "startPasskeyLogin">["startPasskeyLogin"]
    >(async () => authenticationOptions());
    const completePasskeyLogin = vi.fn<
      Pick<MfaApi, "completePasskeyLogin">["completePasskeyLogin"]
    >(async () => sessionResult());
    const onAuthenticated = vi.fn();

    render(
      <LoginFlow
        api={createPhaseTwoApi()}
        credentials={credentials()}
        mfaApi={{ completePasskeyLogin, startPasskeyLogin }}
        onAuthenticated={onAuthenticated}
      />,
    );

    fireEvent.change(screen.getByLabelText("Tenant ID"), {
      target: { value: tenantId },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Sign in with passkey" }),
    );

    await waitFor(() =>
      expect(startPasskeyLogin).toHaveBeenCalledWith(tenantId),
    );
    expect(completePasskeyLogin).toHaveBeenCalledWith({
      ceremonyId,
      credential: {
        id: "AQI",
        response: {
          authenticatorData: "BA",
          clientDataJSON: "Aw",
          signature: "BQ",
        },
        type: "public-key",
      },
    });
    expect(onAuthenticated).toHaveBeenCalledWith(sessionResult());
  });

  it("does not fall back to password when the browser rejects the passkey ceremony", async () => {
    const completePasskeyLogin =
      vi.fn<Pick<MfaApi, "completePasskeyLogin">["completePasskeyLogin"]>();
    const onAuthenticated = vi.fn();
    render(
      <LoginFlow
        api={createPhaseTwoApi()}
        credentials={{ create: async () => null, get: async () => null }}
        mfaApi={{
          completePasskeyLogin,
          startPasskeyLogin: async () => authenticationOptions(),
        }}
        onAuthenticated={onAuthenticated}
      />,
    );

    fireEvent.change(screen.getByLabelText("Tenant ID"), {
      target: { value: tenantId },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Sign in with passkey" }),
    );

    expect(
      await screen.findByText(/passkey proof was not accepted/u),
    ).toBeVisible();
    expect(completePasskeyLogin).not.toHaveBeenCalled();
    expect(onAuthenticated).not.toHaveBeenCalled();
  });

  it("starts only one passkey ceremony for rapid duplicate submissions", async () => {
    let resolveOptions:
      ((value: WebAuthnAuthenticationOptions) => void) | undefined;
    const pendingOptions = new Promise<WebAuthnAuthenticationOptions>(
      (resolve) => {
        resolveOptions = resolve;
      },
    );
    const startPasskeyLogin = vi.fn(async () => pendingOptions);
    const completePasskeyLogin = vi.fn(async () => sessionResult());
    render(
      <LoginFlow
        api={createPhaseTwoApi()}
        credentials={credentials()}
        mfaApi={{ completePasskeyLogin, startPasskeyLogin }}
        onAuthenticated={vi.fn()}
      />,
    );
    const tenant = screen.getByLabelText("Tenant ID");
    fireEvent.change(tenant, { target: { value: tenantId } });
    const form = tenant.closest("form");
    if (!form) throw new Error("passkey form is missing");

    fireEvent.submit(form);
    fireEvent.submit(form);

    expect(startPasskeyLogin).toHaveBeenCalledTimes(1);
    resolveOptions?.(authenticationOptions());
    await waitFor(() => expect(completePasskeyLogin).toHaveBeenCalledOnce());
  });
});

function authenticationOptions(): WebAuthnAuthenticationOptions {
  return {
    ceremonyId,
    expiresAt: "2026-08-26T12:00:00Z",
    publicKey: {
      allowCredentials: [],
      challenge: ceremonyId,
      rpId: "console.example.invalid",
      timeout: 60_000,
      userVerification: "required",
    },
  };
}

function sessionResult(): Session {
  return {
    absoluteExpiresAt: "2026-08-27T10:00:00Z",
    activeTenantId: tenantId,
    authenticationMethod: "passkey",
    createdAt: "2026-08-26T10:00:00Z",
    csrfToken: "C".repeat(43),
    id: "01991f20-0000-7000-8000-000000000021",
    idleExpiresAt: "2026-08-26T11:00:00Z",
    lastSeenAt: "2026-08-26T10:00:00Z",
    permissions: [],
    user: {
      displayName: "Ada Lovelace",
      id: "01991f20-0000-7000-8000-000000000022",
    },
  };
}

function credentials(): BrowserCredentials {
  return {
    create: async () => null,
    get: async () => new FakeAuthenticationCredential(),
  };
}

class FakeAuthenticationCredential implements Credential {
  readonly id = "authentication";
  readonly type = "public-key";
  readonly rawId = Uint8Array.from([1, 2]).buffer;
  readonly response = {
    authenticatorData: Uint8Array.from([4]).buffer,
    clientDataJSON: Uint8Array.from([3]).buffer,
    signature: Uint8Array.from([5]).buffer,
    userHandle: null,
  };

  getClientExtensionResults(): AuthenticationExtensionsClientOutputs {
    return {};
  }
}
