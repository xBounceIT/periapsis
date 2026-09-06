import { act, cleanup, render } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { SessionContext } from "../auth/session-context";
import {
  PhaseTwoApiError,
  type PhaseTwoApi,
  type SessionView,
  type TenantLifecycleReceiptView,
  type TenantView,
} from "../lib/phase-two-types";
import { createPhaseTwoApi, sessionFixture } from "../test/phase-two-fixtures";
import {
  TenantLifecycleProvider,
  useTenantLifecycle,
} from "./tenant-lifecycle-context";
import { TenantLifecycleClientError } from "./tenant-lifecycle-model";

afterEach(cleanup);

describe("TenantLifecycleProvider", () => {
  it("submits the exact active-to-suspended confirmation boundary", async () => {
    const suspendTenant = vi.fn().mockResolvedValue({
      etag: '"v5"',
      value: receipt(),
    });
    const harness = renderHarness({
      api: createPhaseTwoApi({ suspendTenant }),
    });

    await expect(
      harness.current.transition(
        activeTenant,
        "suspend",
        "Approved change SEC-2048",
      ),
    ).resolves.toEqual(receipt());

    expect(suspendTenant).toHaveBeenCalledWith(
      sessionFixture.csrfToken,
      activeTenant.id,
      '"v4"',
      {
        expectedVersion: 4,
        reason: "Approved change SEC-2048",
      },
    );
    expect(harness.current.isPending(activeTenant.id)).toBe(false);
  });

  it("rejects a concurrent mutation for the same tenant", async () => {
    const pending = deferred<{
      etag: string;
      value: TenantLifecycleReceiptView;
    }>();
    const suspendTenant = vi.fn().mockReturnValue(pending.promise);
    const harness = renderHarness({
      api: createPhaseTwoApi({ suspendTenant }),
    });
    let first: Promise<TenantLifecycleReceiptView | undefined> | undefined;

    await act(async () => {
      first = harness.current.transition(activeTenant, "suspend", "Approved");
      await Promise.resolve();
    });
    expect(harness.current.isPending(activeTenant.id)).toBe(true);
    await expect(
      harness.current.transition(activeTenant, "suspend", "Approved"),
    ).rejects.toEqual(
      new TenantLifecycleClientError(
        "A lifecycle change is already pending for this tenant.",
      ),
    );
    expect(suspendTenant).toHaveBeenCalledTimes(1);

    pending.resolve({ etag: '"v5"', value: receipt() });
    await act(async () => {
      await first;
    });
    expect(harness.current.isPending(activeTenant.id)).toBe(false);
  });

  it.each([
    ["a no-op transition", activeTenant, "reactivate", "Approved"],
    ["a missing version", activeTenantWithoutVersion, "suspend", "Approved"],
    ["a leading space", activeTenant, "suspend", " Approved"],
    ["a control character", activeTenant, "suspend", "Approved\nchange"],
    ["more than 2048 UTF-8 bytes", activeTenant, "suspend", "é".repeat(1025)],
  ] as const)(
    "rejects %s before calling the API",
    async (_name, tenant, action, reason) => {
      const suspendTenant = vi.fn();
      const reactivateTenant = vi.fn();
      const harness = renderHarness({
        api: createPhaseTwoApi({ reactivateTenant, suspendTenant }),
      });

      await expect(
        harness.current.transition(tenant, action, reason),
      ).rejects.toBeInstanceOf(TenantLifecycleClientError);
      expect(suspendTenant).not.toHaveBeenCalled();
      expect(reactivateTenant).not.toHaveBeenCalled();
    },
  );

  it("drops an old receipt without clearing a new session's pending change", async () => {
    const oldPending = deferred<{
      etag: string;
      value: TenantLifecycleReceiptView;
    }>();
    const freshPending = deferred<{
      etag: string;
      value: TenantLifecycleReceiptView;
    }>();
    const api = createPhaseTwoApi({
      suspendTenant: vi
        .fn()
        .mockReturnValueOnce(oldPending.promise)
        .mockReturnValueOnce(freshPending.promise),
    });
    const harness = renderHarness({ api });
    const staleResult = harness.current.transition(
      activeTenant,
      "suspend",
      "Approved",
    );

    harness.rerender({
      api,
      session: {
        ...sessionFixture,
        id: "0198c97d-cf4f-7000-8000-000000000099",
      },
    });
    let freshResult:
      Promise<TenantLifecycleReceiptView | undefined> | undefined;
    await act(async () => {
      freshResult = harness.current.transition(
        activeTenant,
        "suspend",
        "Fresh approval",
      );
      await Promise.resolve();
    });
    expect(harness.current.isPending(activeTenant.id)).toBe(true);
    await act(async () => {
      oldPending.resolve({ etag: '"v5"', value: receipt() });
      await expect(staleResult).resolves.toBeUndefined();
    });
    expect(harness.current.isPending(activeTenant.id)).toBe(true);
    await act(async () => {
      freshPending.resolve({ etag: '"v5"', value: receipt() });
      await expect(freshResult).resolves.toEqual(receipt());
    });
    expect(harness.current.isPending(activeTenant.id)).toBe(false);
  });

  it("clears only the originating session after an unauthorized response", async () => {
    const clearSession = vi.fn();
    const harness = renderHarness({
      api: createPhaseTwoApi({
        suspendTenant: vi
          .fn()
          .mockRejectedValue(new PhaseTwoApiError("Session expired", 401)),
      }),
      clearSession,
    });

    await expect(
      harness.current.transition(activeTenant, "suspend", "Approved"),
    ).resolves.toBeUndefined();
    expect(clearSession).toHaveBeenCalledWith(sessionFixture.id);
  });
});

const activeTenant = {
  createdAt: "2026-08-23T10:00:00Z",
  id: "0198c97d-cf4f-7000-8000-000000000071",
  locale: "en",
  name: "Acme SOC",
  slug: "acme-soc",
  status: "active",
  timezone: "UTC",
  updatedAt: "2026-08-24T10:00:00Z",
  version: 4,
} satisfies TenantView;

const activeTenantWithoutVersion = {
  createdAt: activeTenant.createdAt,
  id: activeTenant.id,
  locale: activeTenant.locale,
  name: activeTenant.name,
  slug: activeTenant.slug,
  status: activeTenant.status,
  timezone: activeTenant.timezone,
  updatedAt: activeTenant.updatedAt,
} satisfies TenantView;

function receipt(): TenantLifecycleReceiptView {
  return {
    previousStatus: "active",
    replayed: false,
    status: "suspended",
    tenantId: activeTenant.id,
    updatedAt: "2026-08-26T14:15:16.789123Z",
    version: 5,
  };
}

function renderHarness({
  api,
  clearSession = vi.fn(),
  session = sessionFixture,
}: {
  api: PhaseTwoApi;
  clearSession?: (expectedSessionId: string) => void;
  session?: SessionView;
}) {
  let current: ReturnType<typeof useTenantLifecycle> | undefined;
  const resolvedClearSession =
    clearSession ?? vi.fn<(expectedSessionId: string) => void>();
  const context = (nextSession: SessionView) => ({
    api,
    clearSession: resolvedClearSession,
    membershipRevision: 0,
    refreshMemberships: vi.fn(),
    session: nextSession,
    updateSession: vi.fn(),
  });
  function Capture(): null {
    current = useTenantLifecycle();
    return null;
  }
  const rendered = render(
    <SessionContext.Provider value={context(session)}>
      <TenantLifecycleProvider>
        <Capture />
      </TenantLifecycleProvider>
    </SessionContext.Provider>,
  );

  return {
    get current() {
      if (!current) throw new Error("Lifecycle harness did not mount");
      return current;
    },
    rerender({
      api: nextApi,
      session: nextSession,
    }: {
      api: typeof api;
      session: SessionView;
    }) {
      if (nextApi !== api) throw new Error("The test harness API is immutable");
      rendered.rerender(
        <SessionContext.Provider value={context(nextSession)}>
          <TenantLifecycleProvider>
            <Capture />
          </TenantLifecycleProvider>
        </SessionContext.Provider>,
      );
    },
  };
}

function deferred<T>(): {
  promise: Promise<T>;
  resolve: (value: T) => void;
} {
  let resolve: ((value: T) => void) | undefined;
  const promise = new Promise<T>((settle) => {
    resolve = settle;
  });
  return {
    promise,
    resolve(value) {
      if (!resolve) throw new Error("Deferred promise was not initialized");
      resolve(value);
    },
  };
}
