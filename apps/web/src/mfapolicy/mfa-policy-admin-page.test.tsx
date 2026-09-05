import type {
  MfaPolicyDocument,
  MfaPolicyRequirement,
  MfaPolicySimulationResult,
} from "@periapsis/contracts";
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
  type RenderResult,
} from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { MfaPolicyWorkspace } from "./mfa-policy-admin-page";
import { MfaPolicyApiError } from "./mfa-policy-api";
import type { MfaPolicyApi } from "./model";

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe("MfaPolicyWorkspace", () => {
  it("keeps direct links closed without explicit read authority", () => {
    const list = vi.fn<MfaPolicyApi["list"]>();
    renderWorkspace(createApi({ list }), { canRead: false });

    expect(
      screen.getByRole("alert", {
        name: /MFA policy administration is unavailable/u,
      }),
    ).toBeVisible();
    expect(list).not.toHaveBeenCalled();
  });

  it("makes the absence of an implicit platform-floor seed explicit", async () => {
    const list = vi.fn<MfaPolicyApi["list"]>(async () => ({
      items: [],
      nextCursor: null,
    }));
    const api = createApi({ list });
    renderWorkspace(api);

    expect(
      await screen.findByText(/No platform floor is seeded implicitly/u),
    ).toBeVisible();
    expect(list).toHaveBeenCalledWith(
      { kind: "platform" },
      { includeRetired: false },
    );
  });

  it("shows an unsafe recovery proof and keeps publication disabled", async () => {
    const simulate = vi.fn<MfaPolicyApi["simulate"]>(async () =>
      platformSimulation(false),
    );
    renderWorkspace(createApi({ simulate }));

    fireEvent.click(
      await screen.findByRole("button", { name: "Simulate publication" }),
    );

    expect(await screen.findByText("Recovery unsafe")).toBeVisible();
    expect(
      screen.getByText("No administrator ready with local MFA"),
    ).toBeVisible();
    expect(
      screen.getByRole("button", { name: "Publish platform floor" }),
    ).toBeDisabled();
  });

  it("keeps the workspace read-only without exact manage authority", async () => {
    renderWorkspace(createApi(), { canManage: false });

    fireEvent.click(
      await screen.findByRole("button", { name: "Simulate publication" }),
    );
    await screen.findByText("Recovery safe");

    expect(
      screen.getByText("Manage permission is required to publish or retire."),
    ).toBeVisible();
    expect(
      screen.getByRole("button", { name: "Publish platform floor" }),
    ).toBeDisabled();
  });

  it("publishes only a fresh safe simulation with manage authority", async () => {
    const publish = vi.fn<MfaPolicyApi["publish"]>(async () => ({
      etag: '"v1"',
      value: { policy: platformDocument(), replayed: false },
    }));
    const api = createApi({ publish });
    renderWorkspace(api);

    fireEvent.click(
      await screen.findByRole("button", { name: "Simulate publication" }),
    );
    await screen.findByText("Recovery safe");
    expect(
      screen.getByRole("button", { name: "Publish platform floor" }),
    ).toBeDisabled();
    fireEvent.change(screen.getByLabelText("Audit reason"), {
      target: { value: "Publish the reviewed platform recovery floor" },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Publish platform floor" }),
    );

    await waitFor(() => expect(publish).toHaveBeenCalledTimes(1));
    expect(publish).toHaveBeenCalledWith(
      { kind: "platform" },
      "csrf-token",
      expect.stringMatching(uuidV7Pattern),
      "Publish the reviewed platform recovery floor",
      {
        expectedRevision: 0,
        requirement,
        target: { scope: "platform_floor" },
      },
    );
    expect(
      await screen.findByText(
        "The policy was explicitly published at revision one.",
      ),
    ).toBeVisible();
  });

  it("keeps command-changing controls disabled while a mutation is in flight", async () => {
    const deferred =
      createDeferred<Awaited<ReturnType<MfaPolicyApi["publish"]>>>();
    const publish = vi.fn<MfaPolicyApi["publish"]>(
      async () => deferred.promise,
    );
    renderWorkspace(createApi({ publish }));

    fireEvent.click(
      await screen.findByRole("button", { name: "Simulate publication" }),
    );
    await screen.findByText("Recovery safe");
    fireEvent.change(screen.getByLabelText("Audit reason"), {
      target: { value: "Publish the reviewed platform recovery floor" },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Publish platform floor" }),
    );

    await waitFor(() => expect(publish).toHaveBeenCalledTimes(1));
    expect(
      screen.getByRole("button", { name: "New explicit publication" }),
    ).toBeDisabled();
    expect(
      screen.getByRole("checkbox", { name: "Include retired revisions" }),
    ).toBeDisabled();

    await act(async () => {
      deferred.resolve({
        etag: '"v1"',
        value: { policy: platformDocument(), replayed: false },
      });
      await deferred.promise;
    });
  });

  it("invalidates a simulation when the exact draft changes", async () => {
    renderWorkspace(createApi());

    fireEvent.click(
      await screen.findByRole("button", { name: "Simulate publication" }),
    );
    await screen.findByText("Recovery safe");
    fireEvent.change(screen.getByLabelText("Freshness (seconds)"), {
      target: { value: "60" },
    });

    expect(
      screen.getByText(
        "The draft changed after simulation. Simulate the exact draft again.",
      ),
    ).toBeVisible();
    expect(
      screen.getByRole("button", { name: "Publish platform floor" }),
    ).toBeDisabled();
  });

  it("discards a simulation response after the tenant boundary changes", async () => {
    const deferred = createDeferred<MfaPolicySimulationResult>();
    const api = createApi({ simulate: vi.fn(async () => deferred.promise) });
    const view = renderWorkspace(api);

    fireEvent.click(
      await screen.findByRole("button", { name: "Simulate publication" }),
    );
    view.rerender(
      <MfaPolicyWorkspace
        api={api}
        boundary={{ kind: "tenant", tenantId }}
        canManage
        canRead
        csrfToken="csrf-token"
      />,
    );
    await act(async () => {
      deferred.resolve(platformSimulation(true));
      await deferred.promise;
    });

    expect(
      screen.queryByLabelText("Simulation result"),
    ).not.toBeInTheDocument();
    expect(
      await screen.findByRole("heading", { name: "Tenant MFA policies" }),
    ).toBeVisible();
  });

  it("requires a tenant role target to be present in the exact context", async () => {
    const simulate = vi.fn<MfaPolicyApi["simulate"]>();
    renderWorkspace(createApi({ simulate }), {
      boundary: { kind: "tenant", tenantId },
    });

    await screen.findByText(/no policy publications/u);
    fireEvent.change(screen.getByLabelText("Target scope"), {
      target: { value: "role" },
    });
    fireEvent.change(screen.getByLabelText("Role UUIDv7"), {
      target: { value: roleId },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Simulate publication" }),
    );

    expect(
      await screen.findByText(
        /simulated target must be present in the exact context/u,
      ),
    ).toBeVisible();
    expect(simulate).not.toHaveBeenCalled();
  });

  it("loads an exact ETag and retires only the selected live revision", async () => {
    const document = platformDocument();
    const retire = vi.fn<MfaPolicyApi["retire"]>(async () => ({
      etag: '"v1"',
      value: {
        policy: {
          ...document,
          retiredAt: "2026-08-30T12:30:00.000Z",
          status: "retired" as const,
        },
        replayed: false,
      },
    }));
    const simulate = vi.fn<MfaPolicyApi["simulate"]>(
      async (_boundary, _csrf, input) => ({
        ...platformSimulation(true),
        candidate: null,
        current: document,
        effective: { requirement: null, sources: [] },
        operation: input.operation,
      }),
    );
    const api = createApi({
      get: vi.fn(async () => ({ etag: '"v1"', value: document })),
      list: vi.fn(async () => ({ items: [document], nextCursor: null })),
      retire,
      simulate,
    });
    renderWorkspace(api);

    fireEvent.click(
      await screen.findByRole("button", { name: /Platform floor.*live/u }),
    );
    await screen.findByText(/Strong CAS is pinned to "v1"/u);
    fireEvent.click(
      screen.getByRole("button", { name: "Simulate retirement" }),
    );
    fireEvent.change(screen.getByLabelText("Audit reason"), {
      target: { value: "Retire the superseded floor" },
    });
    await waitFor(() =>
      expect(
        screen.getByRole("button", { name: "Retire exact revision" }),
      ).toBeEnabled(),
    );
    fireEvent.click(
      screen.getByRole("button", { name: "Retire exact revision" }),
    );

    await waitFor(() => expect(retire).toHaveBeenCalledTimes(1));
    expect(retire).toHaveBeenCalledWith(
      { kind: "platform" },
      "csrf-token",
      expect.stringMatching(uuidV7Pattern),
      "Retire the superseded floor",
      policyId,
      '"v1"',
      { expectedRevision: 1, target: { scope: "platform_floor" } },
    );
  });

  it("drops stale CAS state and reloads after a failed replacement", async () => {
    const document = platformDocument();
    const list = vi.fn<MfaPolicyApi["list"]>(async () => ({
      items: [document],
      nextCursor: null,
    }));
    const replace = vi.fn<MfaPolicyApi["replace"]>(async () => {
      throw new MfaPolicyApiError(
        "The MFA policy revision is stale; reload and simulate again.",
        "precondition_failed",
        412,
      );
    });
    const api = createApi({
      get: vi.fn(async () => ({ etag: '"v1"', value: document })),
      list,
      replace,
    });
    renderWorkspace(api);

    fireEvent.click(
      await screen.findByRole("button", { name: /Platform floor.*live/u }),
    );
    await screen.findByText(/Strong CAS is pinned to "v1"/u);
    fireEvent.click(
      screen.getByRole("button", { name: "Simulate publication" }),
    );
    await screen.findByText("Recovery safe");
    fireEvent.change(screen.getByLabelText("Audit reason"), {
      target: { value: "Replace stale floor" },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Publish replacement revision" }),
    );

    expect(
      await screen.findByText(
        "The MFA policy revision is stale; reload and simulate again.",
      ),
    ).toBeVisible();
    expect(list).toHaveBeenCalledTimes(2);
    expect(screen.queryByText(/Strong CAS is pinned/u)).not.toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Publish platform floor" }),
    ).toBeDisabled();
  });
});

function renderWorkspace(
  api: MfaPolicyApi,
  overrides: Partial<React.ComponentProps<typeof MfaPolicyWorkspace>> = {},
): RenderResult {
  return render(
    <MfaPolicyWorkspace
      api={api}
      boundary={{ kind: "platform" }}
      canManage
      canRead
      csrfToken="csrf-token"
      {...overrides}
    />,
  );
}

function createDeferred<T>(): {
  promise: Promise<T>;
  resolve: (value: T) => void;
} {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((promiseResolve) => {
    resolve = promiseResolve;
  });
  return { promise, resolve };
}

function createApi(overrides: Partial<MfaPolicyApi> = {}): MfaPolicyApi {
  return {
    get: vi.fn(async () => ({ etag: '"v1"', value: platformDocument() })),
    list: vi.fn(async () => ({ items: [], nextCursor: null })),
    publish: vi.fn(async () => ({
      etag: '"v1"',
      value: { policy: platformDocument(), replayed: false },
    })),
    replace: vi.fn(async () => ({
      etag: '"v2"',
      value: {
        policy: { ...platformDocument(), revision: 2 },
        replayed: false,
      },
    })),
    retire: vi.fn(async () => ({
      etag: '"v1"',
      value: {
        policy: {
          ...platformDocument(),
          retiredAt: "2026-08-30T12:30:00.000Z",
          status: "retired" as const,
        },
        replayed: false,
      },
    })),
    simulate: vi.fn(async () => platformSimulation(true)),
    ...overrides,
  };
}

function platformSimulation(safe: boolean): MfaPolicySimulationResult {
  return {
    candidate: { requirement, target: { scope: "platform_floor" } },
    context: null,
    current: null,
    effective: {
      requirement,
      sources: [
        {
          requirement,
          source: "candidate",
          target: { scope: "platform_floor" },
        },
      ],
    },
    operation: "publish",
    recovery: {
      eligibleDirectAdministrators: 2,
      readyDirectAdministrators: safe ? 1 : 0,
      reasonCodes: safe ? [] : ["no_ready_local_mfa"],
      safe,
    },
    target: { scope: "platform_floor" },
  };
}

function platformDocument(): MfaPolicyDocument {
  return {
    createdAt: "2026-08-30T12:00:00.000Z",
    id: policyId,
    requirement,
    retiredAt: null,
    revision: 1,
    status: "live",
    target: { scope: "platform_floor" },
  };
}

const requirement: MfaPolicyRequirement = {
  enrollmentDeadline: null,
  freshnessSeconds: 300,
  level: "mfa",
  localRequired: true,
};
const policyId = "01991c20-7d5f-7000-8000-000000000310";
const tenantId = "01991c20-7d5f-7000-8000-000000000311";
const roleId = "01991c20-7d5f-7000-8000-000000000312";
const uuidV7Pattern =
  /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
