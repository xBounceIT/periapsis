import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import { FederatedLoginForm } from "./federated-login-form";

afterEach(cleanup);

describe("federated login form", () => {
  it("uses native protocol-specific top-level POST actions", () => {
    const { container } = render(<FederatedLoginForm />);
    const oidc = screen.getByRole("button", { name: "Continue with OIDC" });
    const saml = screen.getByRole("button", { name: "Continue with SAML" });

    expect(oidc).toBeDisabled();
    expect(saml).toBeDisabled();
    fireEvent.change(screen.getByLabelText("Tenant slug"), {
      target: { value: "acme-soc" },
    });
    fireEvent.change(screen.getByLabelText("Provider login key"), {
      target: { value: "employees_eu" },
    });

    expect(oidc).toBeEnabled();
    expect(saml).toBeEnabled();
    expect(oidc).toHaveAttribute(
      "formaction",
      "/api/v1/auth/federated/oidc/acme-soc/employees_eu/start",
    );
    expect(saml).toHaveAttribute(
      "formaction",
      "/api/v1/auth/federated/saml/acme-soc/employees_eu/start",
    );
    const form = container.querySelector("form");
    expect(form).toHaveAttribute("method", "post");
    expect(form).toHaveAttribute(
      "enctype",
      "application/x-www-form-urlencoded",
    );
  });

  it("submits only the canonical local return path in the strict form body", () => {
    const { container } = render(<FederatedLoginForm />);
    fireEvent.change(screen.getByLabelText("Tenant slug"), {
      target: { value: "acme-soc" },
    });
    fireEvent.change(screen.getByLabelText("Provider login key"), {
      target: { value: "primary_oidc" },
    });
    const form = container.querySelector("form");
    if (!(form instanceof HTMLFormElement)) {
      throw new Error("federated form is missing");
    }

    expect([...new FormData(form).entries()]).toEqual([["returnPath", "/"]]);
    expect(screen.getByLabelText("Tenant slug")).not.toHaveAttribute("name");
    expect(screen.getByLabelText("Provider login key")).not.toHaveAttribute(
      "name",
    );
  });

  it("fails closed for noncanonical public locators", () => {
    render(<FederatedLoginForm />);
    fireEvent.change(screen.getByLabelText("Tenant slug"), {
      target: { value: "Acme" },
    });
    fireEvent.change(screen.getByLabelText("Provider login key"), {
      target: { value: "employees eu" },
    });

    expect(
      screen.getByRole("button", { name: "Continue with OIDC" }),
    ).toBeDisabled();
    expect(
      screen.getByRole("button", { name: "Continue with SAML" }),
    ).toBeDisabled();
  });
});
