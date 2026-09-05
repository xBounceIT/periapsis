import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import { PlatformOIDCLoginForm } from "./platform-oidc-login-form";

afterEach(cleanup);

describe("platform SSO login form", () => {
  it("uses physically separate native OIDC and SAML direct-login actions", () => {
    const { container } = render(<PlatformOIDCLoginForm />);
    const submit = screen.getByRole("button", {
      name: "Continue with platform OIDC",
    });

    expect(submit).toBeDisabled();
    fireEvent.change(screen.getByLabelText("Platform provider key"), {
      target: { value: "workforce_oidc" },
    });

    expect(submit).toBeEnabled();
    const form = container.querySelector("form");
    expect(form).toHaveAttribute(
      "action",
      "/api/v1/auth/platform/oidc/workforce_oidc/start",
    );
    expect(
      screen.getByRole("button", { name: "Continue with platform SAML" }),
    ).toHaveAttribute(
      "formaction",
      "/api/v1/auth/platform/saml/workforce_oidc/start",
    );
    expect(form).toHaveAttribute("method", "post");
    expect(form).toHaveAttribute(
      "enctype",
      "application/x-www-form-urlencoded",
    );
  });

  it("keeps the provider locator out of the strict body", () => {
    const { container } = render(<PlatformOIDCLoginForm />);
    fireEvent.change(screen.getByLabelText("Platform provider key"), {
      target: { value: "workforce_oidc" },
    });
    const form = container.querySelector("form");
    if (!(form instanceof HTMLFormElement)) {
      throw new Error("platform OIDC form is missing");
    }

    expect([...new FormData(form).entries()]).toEqual([["returnPath", "/"]]);
    expect(screen.getByLabelText("Platform provider key")).not.toHaveAttribute(
      "name",
    );
  });

  it("starts the canonical workforce_saml provider without putting it in the body", () => {
    const { container } = render(<PlatformOIDCLoginForm />);
    fireEvent.change(screen.getByLabelText("Platform provider key"), {
      target: { value: "workforce_saml" },
    });

    expect(
      screen.getByRole("button", { name: "Continue with platform SAML" }),
    ).toHaveAttribute(
      "formaction",
      "/api/v1/auth/platform/saml/workforce_saml/start",
    );
    const form = container.querySelector("form");
    if (!(form instanceof HTMLFormElement)) {
      throw new Error("platform SSO form is missing");
    }
    expect([...new FormData(form).entries()]).toEqual([["returnPath", "/"]]);
  });

  it("fails closed for noncanonical provider keys and disabled state", () => {
    const { rerender } = render(<PlatformOIDCLoginForm />);
    const input = screen.getByLabelText("Platform provider key");
    fireEvent.change(input, { target: { value: "Workforce OIDC" } });
    expect(
      screen.getByRole("button", { name: "Continue with platform OIDC" }),
    ).toBeDisabled();
    expect(
      screen.getByRole("button", { name: "Continue with platform SAML" }),
    ).toBeDisabled();

    rerender(<PlatformOIDCLoginForm disabled />);
    fireEvent.change(screen.getByLabelText("Platform provider key"), {
      target: { value: "workforce_oidc" },
    });
    expect(
      screen.getByRole("button", { name: "Continue with platform OIDC" }),
    ).toBeDisabled();
    expect(
      screen.getByRole("button", { name: "Continue with platform SAML" }),
    ).toBeDisabled();
  });
});
