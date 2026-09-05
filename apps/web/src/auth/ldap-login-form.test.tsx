import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import { LDAPLoginForm } from "./ldap-login-form";

afterEach(cleanup);

describe("LDAP login form", () => {
  it("uses a strict native tenant-bound POST action", () => {
    const { container } = render(<LDAPLoginForm />);
    const submit = screen.getByRole("button", {
      name: "Continue with directory",
    });
    expect(submit).toBeDisabled();

    fireEvent.change(screen.getByLabelText("Directory tenant slug"), {
      target: { value: "acme-soc" },
    });
    fireEvent.change(screen.getByLabelText("Directory login key"), {
      target: { value: "employees_ad" },
    });

    expect(submit).toBeEnabled();
    const form = container.querySelector("form");
    expect(form).toHaveAttribute("method", "post");
    expect(form).toHaveAttribute(
      "action",
      "/api/v1/auth/ldap/acme-soc/employees_ad",
    );
    expect(form).toHaveAttribute(
      "enctype",
      "application/x-www-form-urlencoded",
    );
  });

  it("keeps locators out of the body and the password out of SSO forms", () => {
    const { container } = render(<LDAPLoginForm />);
    fireEvent.change(screen.getByLabelText("Directory tenant slug"), {
      target: { value: "acme-soc" },
    });
    fireEvent.change(screen.getByLabelText("Directory login key"), {
      target: { value: "employees_ad" },
    });
    fireEvent.change(screen.getByLabelText("Directory username"), {
      target: { value: "operator@example.test" },
    });
    fireEvent.change(screen.getByLabelText("Directory password"), {
      target: { value: "directory-secret" },
    });

    const form = container.querySelector("form");
    if (!(form instanceof HTMLFormElement))
      throw new Error("LDAP form missing");
    expect([...new FormData(form).entries()]).toEqual([
      ["username", "operator@example.test"],
      ["password", "directory-secret"],
      ["returnPath", "/"],
    ]);
    expect(screen.getByLabelText("Directory tenant slug")).not.toHaveAttribute(
      "name",
    );
    expect(screen.getByLabelText("Directory login key")).not.toHaveAttribute(
      "name",
    );
    expect(form.action).not.toContain("oidc");
    expect(form.action).not.toContain("saml");
  });
});
