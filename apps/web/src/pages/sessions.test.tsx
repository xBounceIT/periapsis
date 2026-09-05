import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { afterEach, describe, expect, it, vi } from "vitest";

import { SessionContext } from "../auth/session-context";
import { PhaseTwoApiError } from "../lib/phase-two-types";
import { createPhaseTwoApi, sessionFixture } from "../test/phase-two-fixtures";
import { SessionsPage } from "./sessions";

afterEach(cleanup);

const sessionSummary = (id: string) => ({
  absoluteExpiresAt: "2099-08-24T12:00:00Z",
  authenticationMethod: "totp" as const,
  createdAt: "2026-08-23T10:00:00Z",
  current: true,
  id,
  idleExpiresAt: "2099-08-23T12:00:00Z",
  lastSeenAt: "2026-08-23T10:30:00Z",
});

describe("SessionsPage", () => {
  it("labels every federated and passkey session method explicitly", async () => {
    const methods = [
      ["passkey", "Passkey", "0198c97d-cf4f-7000-8000-000000000121"],
      ["oidc", "OpenID Connect", "0198c97d-cf4f-7000-8000-000000000122"],
      ["saml", "SAML 2.0", "0198c97d-cf4f-7000-8000-000000000123"],
    ] as const;
    const api = createPhaseTwoApi({
      listSessions: async () => ({
        items: methods.map(([authenticationMethod, , id]) => ({
          ...sessionSummary(id),
          authenticationMethod,
          current: false,
        })),
      }),
    });

    render(
      <MemoryRouter>
        <SessionContext.Provider
          value={{
            api,
            clearSession: vi.fn(),
            membershipRevision: 0,
            refreshMemberships: vi.fn(),
            session: sessionFixture,
            updateSession: vi.fn(),
          }}
        >
          <SessionsPage />
        </SessionContext.Provider>
      </MemoryRouter>,
    );

    const labels = await Promise.all(
      methods.map(([, label]) => screen.findByText(label)),
    );
    for (const label of labels) expect(label).toBeVisible();
  });

  it("requires confirmation and clears client session state after current-session revocation", async () => {
    const revokeSession = vi.fn(async () => undefined);
    const api = createPhaseTwoApi({
      listSessions: async () => ({
        items: [
          {
            absoluteExpiresAt: "2099-08-24T12:00:00Z",
            authenticationMethod: "bootstrap_totp",
            createdAt: "2026-08-23T10:00:00Z",
            current: true,
            id: sessionFixture.id,
            idleExpiresAt: "2099-08-23T12:00:00Z",
            lastSeenAt: "2026-08-23T10:30:00Z",
          },
        ],
      }),
      revokeSession,
    });
    const clearSession = vi.fn();

    render(
      <MemoryRouter>
        <SessionContext.Provider
          value={{
            api,
            clearSession,
            membershipRevision: 0,
            refreshMemberships: vi.fn(),
            session: sessionFixture,
            updateSession: vi.fn(),
          }}
        >
          <SessionsPage />
        </SessionContext.Provider>
      </MemoryRouter>,
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Revoke and sign out" }),
    );
    expect(revokeSession).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "Confirm revoke" }));

    await waitFor(() =>
      expect(revokeSession).toHaveBeenCalledWith(
        sessionFixture.csrfToken,
        sessionFixture.id,
      ),
    );
    expect(clearSession).toHaveBeenCalledOnce();
  });

  it("does not offer revocation actions for historical revoked or expired sessions", async () => {
    const api = createPhaseTwoApi({
      listSessions: async () => ({
        items: [
          {
            absoluteExpiresAt: "2099-08-24T12:00:00Z",
            authenticationMethod: "totp",
            createdAt: "2026-08-20T10:00:00Z",
            current: false,
            id: "0198c97d-cf4f-7000-8000-000000000101",
            idleExpiresAt: "2099-08-23T12:00:00Z",
            lastSeenAt: "2026-08-20T10:30:00Z",
            revokedAt: "2026-08-20T11:00:00Z",
          },
          {
            absoluteExpiresAt: "2000-08-24T12:00:00Z",
            authenticationMethod: "recovery_code",
            createdAt: "2000-08-20T10:00:00Z",
            current: false,
            id: "0198c97d-cf4f-7000-8000-000000000102",
            idleExpiresAt: "2000-08-23T12:00:00Z",
            lastSeenAt: "2000-08-20T10:30:00Z",
          },
        ],
      }),
    });

    render(
      <MemoryRouter>
        <SessionContext.Provider
          value={{
            api,
            clearSession: vi.fn(),
            membershipRevision: 0,
            refreshMemberships: vi.fn(),
            session: sessionFixture,
            updateSession: vi.fn(),
          }}
        >
          <SessionsPage />
        </SessionContext.Provider>
      </MemoryRouter>,
    );

    expect(
      await screen.findByText("Revoked", { selector: "[data-slot='badge']" }),
    ).toBeVisible();
    expect(screen.getByText("Expired")).toBeVisible();
    expect(
      screen.queryByRole("button", { name: "Revoke session" }),
    ).not.toBeInTheDocument();
  });

  it("loads later pages once, shows loading state, and de-duplicates overlapping sessions", async () => {
    const cursor = "0198c97d-cf4f-7000-8000-000000000110";
    const first = {
      absoluteExpiresAt: "2099-08-24T12:00:00Z",
      authenticationMethod: "totp" as const,
      createdAt: "2026-08-23T10:00:00Z",
      current: true,
      id: sessionFixture.id,
      idleExpiresAt: "2099-08-23T12:00:00Z",
      lastSeenAt: "2026-08-23T10:30:00Z",
    };
    const later = {
      ...first,
      createdAt: "2026-08-22T10:00:00Z",
      current: false,
      id: "0198c97d-cf4f-7000-8000-000000000112",
    };
    let resolveLater:
      ((value: { items: Array<typeof first> }) => void) | undefined;
    const laterPage = new Promise<{ items: Array<typeof first> }>((resolve) => {
      resolveLater = resolve;
    });
    const listSessions = vi.fn((after?: string) =>
      after
        ? laterPage
        : Promise.resolve({ items: [first], nextCursor: cursor }),
    );
    const api = createPhaseTwoApi({ listSessions });

    const { container } = render(
      <MemoryRouter>
        <SessionContext.Provider
          value={{
            api,
            clearSession: vi.fn(),
            membershipRevision: 0,
            refreshMemberships: vi.fn(),
            session: sessionFixture,
            updateSession: vi.fn(),
          }}
        >
          <SessionsPage />
        </SessionContext.Provider>
      </MemoryRouter>,
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Load more sessions" }),
    );
    expect(
      screen.getByRole("button", { name: "Loading more sessions…" }),
    ).toBeDisabled();
    resolveLater?.({ items: [first, later] });

    await waitFor(() =>
      expect(container.querySelectorAll(".session-card")).toHaveLength(2),
    );
    expect(listSessions).toHaveBeenLastCalledWith(cursor);
  });

  it("refetches after rotation and does not clear a replacement session for a stale revoke", async () => {
    const replacementSession = {
      ...sessionFixture,
      id: "0198c97d-cf4f-7000-8000-000000000120",
    };
    const listSessions = vi
      .fn()
      .mockResolvedValueOnce({ items: [sessionSummary(sessionFixture.id)] })
      .mockResolvedValue({ items: [sessionSummary(replacementSession.id)] });
    let finishRevoke: (() => void) | undefined;
    let pendingRevoke: Promise<void> | undefined;
    const revokeSession = vi.fn(() => {
      pendingRevoke = new Promise<void>((resolve) => {
        finishRevoke = resolve;
      });
      return pendingRevoke;
    });
    const api = createPhaseTwoApi({ listSessions, revokeSession });
    const clearSession = vi.fn();
    const context = (session: typeof sessionFixture) => ({
      api,
      clearSession,
      membershipRevision: 0,
      refreshMemberships: vi.fn(),
      session,
      updateSession: vi.fn(),
    });
    const { rerender } = render(
      <MemoryRouter>
        <SessionContext.Provider value={context(sessionFixture)}>
          <SessionsPage />
        </SessionContext.Provider>
      </MemoryRouter>,
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Revoke and sign out" }),
    );
    fireEvent.click(screen.getByRole("button", { name: "Confirm revoke" }));
    await waitFor(() => expect(revokeSession).toHaveBeenCalledOnce());

    rerender(
      <MemoryRouter>
        <SessionContext.Provider value={context(replacementSession)}>
          <SessionsPage />
        </SessionContext.Provider>
      </MemoryRouter>,
    );
    await waitFor(() => expect(listSessions).toHaveBeenCalledTimes(2));
    finishRevoke?.();
    await pendingRevoke;

    expect(clearSession).not.toHaveBeenCalled();
    expect(
      screen.getByRole("button", { name: "Revoke and sign out" }),
    ).toBeVisible();
  });

  it("ignores a late stale-session 401 after the current session rotates", async () => {
    const replacementSession = {
      ...sessionFixture,
      id: "0198c97d-cf4f-7000-8000-000000000130",
    };
    const listSessions = vi
      .fn()
      .mockResolvedValueOnce({ items: [sessionSummary(sessionFixture.id)] })
      .mockResolvedValue({ items: [sessionSummary(replacementSession.id)] });
    let rejectRevoke: ((reason: unknown) => void) | undefined;
    const pendingRevoke = new Promise<never>((_resolve, reject) => {
      rejectRevoke = reject;
    });
    const revokeSession = vi.fn(() => pendingRevoke);
    const api = createPhaseTwoApi({ listSessions, revokeSession });
    const clearSession = vi.fn();
    const context = (session: typeof sessionFixture) => ({
      api,
      clearSession,
      membershipRevision: 0,
      refreshMemberships: vi.fn(),
      session,
      updateSession: vi.fn(),
    });
    const { rerender } = render(
      <MemoryRouter>
        <SessionContext.Provider value={context(sessionFixture)}>
          <SessionsPage />
        </SessionContext.Provider>
      </MemoryRouter>,
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Revoke and sign out" }),
    );
    fireEvent.click(screen.getByRole("button", { name: "Confirm revoke" }));
    await waitFor(() => expect(revokeSession).toHaveBeenCalledOnce());
    rerender(
      <MemoryRouter>
        <SessionContext.Provider value={context(replacementSession)}>
          <SessionsPage />
        </SessionContext.Provider>
      </MemoryRouter>,
    );
    await waitFor(() => expect(listSessions).toHaveBeenCalledTimes(2));
    rejectRevoke?.(new PhaseTwoApiError("old session", 401));
    await pendingRevoke.catch(() => undefined);

    expect(clearSession).not.toHaveBeenCalled();
    expect(
      screen.getByRole("button", { name: "Revoke and sign out" }),
    ).toBeVisible();
  });
});
