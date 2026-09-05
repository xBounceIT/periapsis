import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import { PlatformLDAPLoginForm } from "./platform-ldap-login-form";

afterEach(cleanup);

describe("platform LDAP login form", () => {
  it("posts only credentials, mandatory TOTP, and return path to the tenantless route", () => {
    const { container } = render(<PlatformLDAPLoginForm />);
    const submit = screen.getByRole("button", {
      name: "Continue with platform LDAP",
    });
    expect(submit).toBeDisabled();

    fireEvent.change(screen.getByLabelText("Platform LDAP provider key"), {
      target: { value: "workforce_ldap" },
    });
    fireEvent.change(screen.getByLabelText("Platform directory username"), {
      target: { value: "operator@example.test" },
    });
    fireEvent.change(screen.getByLabelText("Platform directory password"), {
      target: { value: "directory-secret" },
    });
    fireEvent.change(screen.getByLabelText("Local authenticator code"), {
      target: { value: "123456" },
    });

    const form = container.querySelector("form");
    if (!(form instanceof HTMLFormElement))
      throw new Error("LDAP form missing");
    expect(submit).toBeEnabled();
    expect(form).toHaveAttribute(
      "action",
      "/api/v1/auth/platform/ldap/workforce_ldap",
    );
    expect([...new FormData(form).entries()]).toEqual([
      ["username", "operator@example.test"],
      ["password", "directory-secret"],
      ["totpCode", "123456"],
      ["returnPath", "/"],
    ]);
    expect(
      screen.getByLabelText("Platform LDAP provider key"),
    ).not.toHaveAttribute("name");
  });
});
