import { act, cleanup, render, screen, waitFor } from "@testing-library/react";
import { useState } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  PhaseTwoApiError,
  type SessionView,
  type TenantAuthorityView,
} from "../lib/phase-two-types";
import { createPhaseTwoApi, sessionFixture } from "../test/phase-two-fixtures";
import { SessionContext } from "./session-context";
import {
  TenantAuthorityProvider,
  useTenantAuthority,
} from "./tenant-authority-context";

afterEach(cleanup);

describe("TenantAuthorityProvider request generation", () => {
  it("keys authority by session and tenant and suppresses a late old-tenant success", async () => {
    const requests: Array<{
      deferred: Deferred<TenantAuthorityView>;
      signal?: AbortSignal;
      tenantId: string;
    }> = [];
    const api = createPhaseTwoApi({
      getTenantAuthority: (tenantId, signal) => {
        const deferred = createDeferred<TenantAuthorityView>();
        requests.push({ deferred, tenantId, ...(signal ? { signal } : {}) });
        return deferred.promise;
      },
    });

    render(<AuthorityHarness api={api} />);
    await waitFor(() => expect(requests).toHaveLength(1));
    expect(requests[0]?.tenantId).toBe("0198c97d-cf4f-7000-8000-000000000010");

    act(() => screen.getByRole("button", { name: "Switch tenant" }).click());
    await waitFor(() => expect(requests).toHaveLength(2));
    expect(requests[0]?.signal?.aborted).toBe(true);
    expect(screen.getByTestId("authority-status")).toHaveTextContent("loading");
    expect(screen.queryByText("old tenant authority")).not.toBeInTheDocument();

    await act(async () => {
      requests[0]?.deferred.resolve(
        authorityFixture(
          "0198c97d-cf4f-7000-8000-000000000010",
          "old tenant authority",
        ),
      );
      await Promise.resolve();
    });
    expect(screen.getByTestId("authority-status")).toHaveTextContent("loading");

    await act(async () => {
      requests[1]?.deferred.resolve(
        authorityFixture(
          "0198c97d-cf4f-7000-8000-000000000011",
          "new tenant authority",
        ),
      );
      await requests[1]?.deferred.promise;
    });
    expect(screen.getByTestId("authority-status")).toHaveTextContent("ready");
    expect(screen.getByTestId("authority-marker")).toHaveTextContent(
      "new tenant authority",
    );
  });

  it.each([
    ["401", new PhaseTwoApiError("old unauthorized", 401)],
    ["error", new Error("old network failure")],
  ])(
    "suppresses a late old-session %s after rotation",
    async (_label, lateError) => {
      const requests: Array<Deferred<TenantAuthorityView>> = [];
      const clearSession = vi.fn();
      const api = createPhaseTwoApi({
        getTenantAuthority: () => {
          const deferred = createDeferred<TenantAuthorityView>();
          requests.push(deferred);
          return deferred.promise;
        },
      });

      render(<AuthorityHarness api={api} clearSession={clearSession} />);
      await waitFor(() => expect(requests).toHaveLength(1));
      act(() => screen.getByRole("button", { name: "Rotate session" }).click());
      await waitFor(() => expect(requests).toHaveLength(2));

      await act(async () => {
        requests[0]?.reject(lateError);
        await Promise.resolve();
      });
      expect(clearSession).not.toHaveBeenCalled();
      expect(screen.getByTestId("authority-status")).toHaveTextContent(
        "loading",
      );

      await act(async () => {
        requests[1]?.resolve(
          authorityFixture(
            "0198c97d-cf4f-7000-8000-000000000010",
            "rotated session authority",
          ),
        );
        await requests[1]?.promise;
      });
      expect(screen.getByTestId("authority-marker")).toHaveTextContent(
        "rotated session authority",
      );
    },
  );

  it("fails closed immediately and suppresses the superseded same-pair reload", async () => {
    const requests: Array<{
      deferred: Deferred<TenantAuthorityView>;
      signal?: AbortSignal;
    }> = [];
    const api = createPhaseTwoApi({
      getTenantAuthority: (_tenantId, signal) => {
        const deferred = createDeferred<TenantAuthorityView>();
        requests.push({ deferred, ...(signal ? { signal } : {}) });
        return deferred.promise;
      },
    });

    render(<AuthorityHarness api={api} />);
    await waitFor(() => expect(requests).toHaveLength(1));
    fireReload();
    await waitFor(() => expect(requests).toHaveLength(2));
    expect(requests[0]?.signal?.aborted).toBe(true);
    expect(screen.getByTestId("authority-status")).toHaveTextContent("loading");

    await act(async () => {
      requests[0]?.deferred.resolve(
        authorityFixture(
          "0198c97d-cf4f-7000-8000-000000000010",
          "superseded same-pair authority",
        ),
      );
      await Promise.resolve();
    });
    expect(screen.getByTestId("authority-status")).toHaveTextContent("loading");
    expect(
      screen.queryByText("superseded same-pair authority"),
    ).not.toBeInTheDocument();

    await act(async () => {
      requests[1]?.deferred.resolve(
        authorityFixture(
          "0198c97d-cf4f-7000-8000-000000000010",
          "reloaded authority",
        ),
      );
      await requests[1]?.deferred.promise;
    });
    expect(screen.getByTestId("authority-marker")).toHaveTextContent(
      "reloaded authority",
    );
  });
});

function fireReload(): void {
  act(() => screen.getByRole("button", { name: "Reload authority" }).click());
}

function AuthorityHarness({
  api,
  clearSession = vi.fn(),
}: {
  api: ReturnType<typeof createPhaseTwoApi>;
  clearSession?: (expectedSessionId: string) => void;
}): React.JSX.Element {
  const [session, setSession] = useState<SessionView>({
    ...sessionFixture,
    activeTenantId: "0198c97d-cf4f-7000-8000-000000000010",
  });
  return (
    <SessionContext.Provider
      value={{
        api,
        clearSession,
        membershipRevision: 0,
        refreshMemberships: vi.fn(),
        session,
        updateSession: vi.fn(),
      }}
    >
      <TenantAuthorityProvider>
        <AuthorityProbe />
        <button
          type="button"
          onClick={() =>
            setSession((current) => ({
              ...current,
              activeTenantId: "0198c97d-cf4f-7000-8000-000000000011",
            }))
          }
        >
          Switch tenant
        </button>
        <button
          type="button"
          onClick={() =>
            setSession((current) => ({
              ...current,
              id: "0198c97d-cf4f-7000-8000-000000000099",
            }))
          }
        >
          Rotate session
        </button>
      </TenantAuthorityProvider>
    </SessionContext.Provider>
  );
}

function AuthorityProbe(): React.JSX.Element {
  const authority = useTenantAuthority();
  return (
    <div>
      <output data-testid="authority-status">{authority.status}</output>
      <output data-testid="authority-marker">
        {authority.authority?.roleGrants[0]?.provenance.reason ?? "none"}
      </output>
      <button type="button" onClick={authority.reload}>
        Reload authority
      </button>
    </div>
  );
}

function authorityFixture(
  tenantId: string,
  marker: string,
): TenantAuthorityView {
  return {
    delegationCeiling: [],
    evaluatedAt: "2026-08-23T10:00:00Z",
    legacyMembershipRole: "tenant_admin",
    membershipId: "0198c97d-cf4f-7000-8000-000000000020",
    membershipStatus: "active",
    operatorTeamRelationships: [],
    permissions: [],
    roleGrants: [
      {
        grantId: "0198c97d-cf4f-7000-8000-000000000030",
        provenance: {
          authoritative: false,
          grantedAt: "2026-08-23T10:00:00Z",
          reason: marker,
          sourceId: "0198c97d-cf4f-7000-8000-000000000030",
          sourceKind: "manual",
          sourceType: "direct",
        },
        path: {
          direct: {
            grantId: "0198c97d-cf4f-7000-8000-000000000030",
            provenance: {
              authoritative: false,
              grantedAt: "2026-08-23T10:00:00Z",
              reason: marker,
              sourceId: "0198c97d-cf4f-7000-8000-000000000030",
              sourceKind: "manual",
              sourceType: "direct",
            },
          },
          pathType: "direct",
        },
        roleId: "0198c97d-cf4f-7000-8000-000000000040",
        roleKey: "test_role",
        roleName: "Test role",
      },
    ],
    tenantId,
    userId: sessionFixture.user.id,
  };
}

interface Deferred<T> {
  promise: Promise<T>;
  reject: (error: unknown) => void;
  resolve: (value: T) => void;
}

function createDeferred<T>(): Deferred<T> {
  let resolve!: (value: T) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((promiseResolve, promiseReject) => {
    resolve = promiseResolve;
    reject = promiseReject;
  });
  return { promise, reject, resolve };
}
