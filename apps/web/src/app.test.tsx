import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router";
import { afterEach, describe, expect, it, vi } from "vitest";

import { AppShell, appRouteTitle } from "./app";
import { ApplicationBoundary } from "./auth/application-boundary";
import { useSession } from "./auth/session-context";
import type { SessionView } from "./lib/phase-two-types";
import { createPhaseTwoApi, sessionFixture } from "./test/phase-two-fixtures";

afterEach(() => {
  cleanup();
  document.title = "";
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("AppShell session generation", () => {
  it("provides a skip target and moves route focus to the labelled main landmark", async () => {
    const session = futureSession(sessionFixture);
    const api = createPhaseTwoApi({
      getBootstrapStatus: async () => ({ available: false }),
      getSession: async () => session,
      listMemberships: async () => ({ items: [] }),
    });

    render(
      <MemoryRouter initialEntries={["/profile"]}>
        <Routes>
          <Route element={<ApplicationBoundary api={api} />}>
            <Route element={<AppShell />}>
              <Route path="profile" element={<h1>User profile</h1>} />
            </Route>
          </Route>
        </Routes>
      </MemoryRouter>,
    );

    expect(
      await screen.findByRole("heading", { name: "User profile" }),
    ).toBeVisible();
    const main = screen.getByRole("main", { name: "Main content" });
    await waitFor(() => expect(main).toHaveFocus());
    expect(main).toHaveAttribute("id", "main-content");
    expect(main).toHaveAttribute("tabindex", "-1");
    const skipLink = screen.getByRole("link", {
      name: "Skip to main content",
    });
    expect(skipLink).toHaveAttribute("href", "#main-content");
    main.blur();
    fireEvent.click(skipLink);
    expect(main).toHaveFocus();
    expect(document.title).toBe("User profile · Periapsis");
  });

  it("assigns stable route titles without exposing record identifiers", () => {
    expect(appRouteTitle("/notifications")).toBe("Notification center");
    expect(appRouteTitle("/tenant/custom-field-imports")).toBe(
      "Custom-field imports",
    );
    expect(appRouteTitle("/alerts/new")).toBe("Create Alert");
    expect(appRouteTitle("/alerts/0198c97d-cf4f-7000-8000-000000000001")).toBe(
      "Alert detail",
    );
    expect(appRouteTitle("/unexpected/customer-material")).toBe("Workspace");
  });

  it("links the platform IdP area for independent binding-read authority", async () => {
    const session: SessionView = {
      ...futureSession(sessionFixture),
      permissions: ["platform.identity_binding.read"],
    };
    const api = createPhaseTwoApi({
      getBootstrapStatus: async () => ({ available: false }),
      getSession: async () => session,
      listMemberships: async () => ({ items: [] }),
    });

    render(
      <MemoryRouter>
        <Routes>
          <Route element={<ApplicationBoundary api={api} />}>
            <Route element={<AppShell />}>
              <Route index element={<div>Workspace</div>} />
            </Route>
          </Route>
        </Routes>
      </MemoryRouter>,
    );

    expect(
      await screen.findByRole("link", { name: "Platform IdPs" }),
    ).toBeVisible();
  });

  it("links the platform IdP area for independent account-read authority", async () => {
    const session: SessionView = {
      ...futureSession(sessionFixture),
      permissions: ["platform.identity_account.read"],
    };
    const api = createPhaseTwoApi({
      getBootstrapStatus: async () => ({ available: false }),
      getSession: async () => session,
      listMemberships: async () => ({ items: [] }),
    });

    render(
      <MemoryRouter>
        <Routes>
          <Route element={<ApplicationBoundary api={api} />}>
            <Route element={<AppShell />}>
              <Route index element={<div>Workspace</div>} />
            </Route>
          </Route>
        </Routes>
      </MemoryRouter>,
    );

    expect(
      await screen.findByRole("link", { name: "Platform IdPs" }),
    ).toBeVisible();
    expect(screen.getByRole("link", { name: "Local recovery" })).toBeVisible();
  });

  it("uses live typed platform settings for the tenantless shell and safe support link", async () => {
    const session: SessionView = {
      ...futureSession(sessionFixture),
      permissions: ["platform.operations.read", "platform.settings.read"],
    };
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({
            defaultLocale: "it-IT",
            defaultTimezone: "Europe/Rome",
            platformName: "Periapsis SOC",
            supportUrl: "https://support.example.test/help",
            updatedAt: "2026-09-01T10:00:00Z",
            version: 2,
          }),
          {
            headers: {
              "Cache-Control": "private, no-store",
              "Content-Type": "application/json",
              ETag: '"v2"',
            },
            status: 200,
          },
        ),
      ),
    );
    const api = createPhaseTwoApi({
      getBootstrapStatus: async () => ({ available: false }),
      getSession: async () => session,
      listMemberships: async () => ({ items: [] }),
    });

    render(
      <MemoryRouter initialEntries={["/platform/operations"]}>
        <Routes>
          <Route element={<ApplicationBoundary api={api} />}>
            <Route element={<AppShell />}>
              <Route
                path="platform/operations"
                element={<div>Operations</div>}
              />
            </Route>
          </Route>
        </Routes>
      </MemoryRouter>,
    );

    expect(
      await screen.findByRole("link", { name: "Periapsis SOC home" }),
    ).toBeVisible();
    expect(
      screen.getByRole("link", { name: "Platform operations" }),
    ).toHaveAttribute("href", "/platform/operations");
    const support = screen.getByRole("link", { name: "Support" });
    expect(support).toHaveAttribute(
      "href",
      "https://support.example.test/help",
    );
    expect(support).toHaveAttribute("rel", "noopener noreferrer");
    await waitFor(() =>
      expect(document.title).toBe("Platform operations · Periapsis SOC"),
    );
  });

  it("uses the display name when a federated identity has no email", async () => {
    const session: SessionView = {
      ...futureSession(sessionFixture),
      user: {
        displayName: "Federated Responder",
        id: sessionFixture.user.id,
      },
    };
    const api = createPhaseTwoApi({
      getBootstrapStatus: async () => ({ available: false }),
      getSession: async () => session,
      listMemberships: async () => ({ items: [] }),
    });

    render(
      <MemoryRouter>
        <Routes>
          <Route element={<ApplicationBoundary api={api} />}>
            <Route element={<AppShell />}>
              <Route index element={<div>Workspace</div>} />
            </Route>
          </Route>
        </Routes>
      </MemoryRouter>,
    );

    expect(await screen.findByText("Federated Responder")).toBeVisible();
  });

  it("clears local session state and follows only the opaque logout continuation", async () => {
    const session = futureSession(sessionFixture);
    const continuationUrl =
      "/api/v1/auth/logout/continuations/0198c97d-cf4f-7000-8000-000000000071";
    const logout = vi.fn(async () => ({ continuationUrl }));
    const navigateLogoutContinuation = vi.fn<(url: string) => void>();
    const api = createPhaseTwoApi({
      getBootstrapStatus: async () => ({ available: false }),
      getSession: async () => session,
      listMemberships: async () => ({ items: [] }),
      logout,
    });

    render(
      <MemoryRouter>
        <Routes>
          <Route element={<ApplicationBoundary api={api} />}>
            <Route
              element={
                <AppShell
                  navigateLogoutContinuation={navigateLogoutContinuation}
                />
              }
            >
              <Route index element={<div>Workspace</div>} />
            </Route>
          </Route>
        </Routes>
      </MemoryRouter>,
    );

    fireEvent.click(await screen.findByRole("button", { name: "Sign out" }));

    await waitFor(() => expect(logout).toHaveBeenCalledWith(session.csrfToken));
    expect(navigateLogoutContinuation).toHaveBeenCalledOnce();
    expect(navigateLogoutContinuation).toHaveBeenCalledWith(continuationUrl);
    await waitFor(() =>
      expect(
        screen.queryByRole("button", { name: "Sign out" }),
      ).not.toBeInTheDocument(),
    );
  });

  it.each([
    ["late 200", "session"],
    ["late 401", "missing"],
  ] as const)(
    "does not let a %s refresh overwrite or clear a rotated session",
    async (_name, responseKind) => {
      const original = futureSession(sessionFixture);
      const replacement = {
        ...original,
        csrfToken: "replacement-csrf-memory-value-000000000000000000",
        id: "0198c97d-cf4f-7000-8000-000000000099",
      };
      let resolveRefresh: ((session: SessionView | null) => void) | undefined;
      const refresh = new Promise<SessionView | null>((resolve) => {
        resolveRefresh = resolve;
      });
      const getSession = vi
        .fn<() => Promise<SessionView | null>>()
        .mockResolvedValueOnce(original)
        .mockImplementationOnce(() => refresh);
      const api = createPhaseTwoApi({
        getBootstrapStatus: async () => ({ available: false }),
        getSession,
        listMemberships: async () => ({ items: [] }),
      });

      render(
        <MemoryRouter>
          <Routes>
            <Route element={<ApplicationBoundary api={api} />}>
              <Route element={<AppShell />}>
                <Route
                  index
                  element={<SessionGenerationProbe replacement={replacement} />}
                />
              </Route>
            </Route>
          </Routes>
        </MemoryRouter>,
      );

      expect(await screen.findByTestId("session-generation")).toHaveTextContent(
        original.id,
      );
      await screen.findByText("No assigned tenant");
      await act(async () => {
        await Promise.resolve();
        window.dispatchEvent(new Event("focus"));
      });
      await waitFor(() => expect(getSession).toHaveBeenCalledTimes(2));
      fireEvent.click(screen.getByRole("button", { name: "Install S2" }));
      expect(screen.getByTestId("session-generation")).toHaveTextContent(
        replacement.id,
      );

      await act(async () => {
        resolveRefresh?.(responseKind === "session" ? original : null);
        await refresh;
      });

      expect(screen.getByTestId("session-generation")).toHaveTextContent(
        replacement.id,
      );
    },
  );
});

function SessionGenerationProbe({
  replacement,
}: {
  replacement: SessionView;
}): React.JSX.Element {
  const { session, updateSession } = useSession();
  return (
    <div>
      <output data-testid="session-generation">{session.id}</output>
      <button
        type="button"
        onClick={() => updateSession(sessionFixture.id, replacement)}
      >
        Install S2
      </button>
    </div>
  );
}

function futureSession(session: SessionView): SessionView {
  return {
    ...session,
    absoluteExpiresAt: "2099-08-24T12:00:00Z",
    idleExpiresAt: "2099-08-23T12:00:00Z",
  };
}
