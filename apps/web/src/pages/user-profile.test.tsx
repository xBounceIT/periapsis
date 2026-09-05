import { cleanup, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { afterEach, describe, expect, it, vi } from "vitest";

import { SessionContext } from "../auth/session-context";
import type { SessionView } from "../lib/phase-two-types";
import { createPhaseTwoApi, sessionFixture } from "../test/phase-two-fixtures";
import { UserProfilePage } from "./user-profile";

afterEach(cleanup);

describe("UserProfilePage", () => {
  it("shows only server-held identity context and links to security controls", () => {
    renderProfile({ ...sessionFixture, activeTenantId: "tenant-selected" });

    expect(
      screen.getByRole("heading", { level: 1, name: "User profile" }),
    ).toBeVisible();
    expect(screen.getByText("Ada Analyst")).toBeVisible();
    expect(screen.getByText("ada@example.invalid")).toBeVisible();
    expect(screen.getByText(sessionFixture.user.id)).toBeVisible();
    expect(screen.getByText("Tenant context")).toBeVisible();
    expect(
      screen.getByRole("link", { name: "Manage sessions" }),
    ).toHaveAttribute("href", "/sessions");
    expect(
      screen.getByRole("link", { name: "Manage MFA devices" }),
    ).toHaveAttribute("href", "/account/security");
    expect(screen.queryByRole("textbox")).not.toBeInTheDocument();
  });

  it("keeps tenant-only MFA controls hidden in platform context", () => {
    renderProfile({
      ...sessionFixture,
      permissions: ["platform.tenant.read"],
      user: {
        displayName: sessionFixture.user.displayName,
        id: sessionFixture.user.id,
      },
    });

    expect(screen.getByText("Platform context")).toBeVisible();
    expect(screen.getByText("1 platform permission")).toBeVisible();
    expect(
      screen.getByText("Not supplied by the identity provider"),
    ).toBeVisible();
    expect(
      screen.queryByRole("link", { name: "Manage MFA devices" }),
    ).not.toBeInTheDocument();
  });

  it("fails closed when session expiry values are malformed", () => {
    renderProfile({
      ...sessionFixture,
      absoluteExpiresAt: "not-a-time",
      idleExpiresAt: "also-not-a-time",
    });

    expect(screen.getAllByText("Unavailable")).toHaveLength(2);
  });
});

function renderProfile(session: SessionView): void {
  render(
    <MemoryRouter>
      <SessionContext.Provider
        value={{
          api: createPhaseTwoApi(),
          clearSession: vi.fn(),
          membershipRevision: 0,
          refreshMemberships: vi.fn(),
          session,
          updateSession: vi.fn(),
        }}
      >
        <UserProfilePage />
      </SessionContext.Provider>
    </MemoryRouter>,
  );
}
