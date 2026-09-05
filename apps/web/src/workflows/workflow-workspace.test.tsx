import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  WorkflowApiError,
  type VersionedWorkflow,
  type WorkflowAdministrationApi,
} from "./workflow-api";
import {
  alertWorkflowFixture,
  createWorkflowApiMock,
  alertWorkflowVersionFixture,
  versionedWorkflow,
  workflowSimulationFixture,
  workflowTenantId,
} from "./workflow-test-fixtures";
import { WorkflowWorkspace } from "./workflow-workspace";

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe("WorkflowWorkspace", () => {
  it("fails closed before loading without live read authority", () => {
    const list = vi.fn<WorkflowAdministrationApi["list"]>();
    render(
      <WorkflowWorkspace
        api={createWorkflowApiMock({ list })}
        canManage={false}
        canRead={false}
        csrfToken="csrf"
        tenantId={workflowTenantId}
      />,
    );
    expect(screen.getByText("Workflow authority required")).toBeVisible();
    expect(screen.getByText(/rechecks every read and mutation/u)).toBeVisible();
    expect(list).not.toHaveBeenCalled();
  });

  it("keeps published definitions inspectable for read-only users", async () => {
    render(
      <WorkflowWorkspace
        api={createWorkflowApiMock()}
        canManage={false}
        canRead
        csrfToken="csrf"
        tenantId={workflowTenantId}
      />,
    );
    fireEvent.click(
      await screen.findByRole("button", { name: /SOC alert response/u }),
    );

    const displayName = await screen.findByLabelText("Display name");
    expect(displayName).toHaveAttribute("readonly");
    expect(displayName).not.toBeDisabled();
    expect(screen.getByLabelText("States")).toHaveAttribute("readonly");
    expect(
      screen.queryByRole("button", { name: "Review publication" }),
    ).not.toBeInTheDocument();
  });

  it("rejects a workflow catalog projection from another tenant", async () => {
    render(
      <WorkflowWorkspace
        api={createWorkflowApiMock({
          list: async () => ({
            items: [
              {
                ...alertWorkflowFixture,
                tenantId: "01991c20-7d5f-7000-8000-000000000099",
              },
            ],
          }),
        })}
        canManage
        canRead
        csrfToken="csrf"
        tenantId={workflowTenantId}
      />,
    );
    expect(
      await screen.findByText(/crossed its tenant or kind boundary/u),
    ).toBeVisible();
    expect(
      screen.queryByRole("button", { name: /SOC alert response/u }),
    ).not.toBeInTheDocument();
  });

  it("does not apply a stale catalog response after the workflow kind changes", async () => {
    const alertPage = createDeferred<{
      items: Array<typeof alertWorkflowFixture>;
    }>();
    const list = vi.fn<WorkflowAdministrationApi["list"]>(async ({ kind }) =>
      kind === "alert" ? alertPage.promise : { items: [] },
    );
    render(
      <WorkflowWorkspace
        api={createWorkflowApiMock({ list })}
        canManage
        canRead
        csrfToken="csrf-token"
        tenantId={workflowTenantId}
      />,
    );
    fireEvent.click(screen.getByRole("tab", { name: "Case workflow" }));
    expect(
      await screen.findByText("No workflow lineages are visible."),
    ).toBeVisible();

    await act(async () => {
      alertPage.resolve({ items: [alertWorkflowFixture] });
      await alertPage.promise;
    });

    expect(
      screen.queryByRole("button", { name: /SOC alert response/u }),
    ).not.toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Case catalog" })).toBeVisible();
  });

  it("loads every bounded catalog page without duplicating lineages", async () => {
    const secondId = "01991c20-7d5f-7000-8000-000000000204";
    const second = {
      ...alertWorkflowFixture,
      id: secondId,
      displayName: "Second alert workflow",
      current: { ...alertWorkflowFixture.current, id: secondId },
    };
    const list = vi.fn<WorkflowAdministrationApi["list"]>(async ({ after }) =>
      after
        ? { items: [second] }
        : { items: [alertWorkflowFixture], nextCursor: "next-page" },
    );
    render(
      <WorkflowWorkspace
        api={createWorkflowApiMock({ list })}
        canManage
        canRead
        csrfToken="csrf-token"
        tenantId={workflowTenantId}
      />,
    );

    expect(
      await screen.findByRole("button", { name: /SOC alert response/u }),
    ).toBeVisible();
    fireEvent.click(
      screen.getByRole("button", { name: "Load more workflows" }),
    );
    expect(
      await screen.findByRole("button", { name: /Second alert workflow/u }),
    ).toBeVisible();
    expect(list).toHaveBeenLastCalledWith(
      expect.objectContaining({ after: "next-page" }),
    );
  });

  it("retains the loaded catalog when a later page fails", async () => {
    const list = vi.fn<WorkflowAdministrationApi["list"]>(async ({ after }) => {
      if (after) throw new WorkflowApiError("The next page failed.", 503);
      return { items: [alertWorkflowFixture], nextCursor: "next-page" };
    });
    render(
      <WorkflowWorkspace
        api={createWorkflowApiMock({ list })}
        canManage
        canRead
        csrfToken="csrf-token"
        tenantId={workflowTenantId}
      />,
    );

    const workflow = await screen.findByRole("button", {
      name: /SOC alert response/u,
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Load more workflows" }),
    );

    expect(await screen.findByText("The next page failed.")).toBeVisible();
    expect(workflow).toBeVisible();
    expect(
      screen.getByRole("button", { name: "Load more workflows" }),
    ).toBeEnabled();
  });

  it("publishes the reviewed design with the current strong ETag", async () => {
    const publish = vi.fn<WorkflowAdministrationApi["publish"]>(
      async ({ body }) =>
        versionedWorkflow({
          ...alertWorkflowFixture,
          revision: body.expectedRevision + 1,
          currentVersion: 2,
          current: {
            ...alertWorkflowFixture.current,
            ...body.design,
            version: 2,
          },
        }),
    );
    render(
      <WorkflowWorkspace
        api={createWorkflowApiMock({ publish })}
        canManage
        canRead
        csrfToken="csrf-token"
        tenantId={workflowTenantId}
      />,
    );
    fireEvent.click(
      await screen.findByRole("button", { name: /SOC alert response/u }),
    );
    await screen.findByRole("heading", { name: "SOC alert response" });
    fireEvent.click(screen.getByRole("button", { name: "Review publication" }));
    fireEvent.click(
      await screen.findByRole("button", {
        name: "Confirm and publish",
      }),
    );
    await waitFor(() => expect(publish).toHaveBeenCalledTimes(1));
    expect(publish.mock.calls[0]?.[0]).toMatchObject({
      body: { expectedRevision: 1 },
      csrfToken: "csrf-token",
      etag: '"v1-_VFDEoAgKP5tR_AyfYsxkZwrjrziGnhwdGR6LyK4ovU"',
      tenantId: workflowTenantId,
      workflowId: alertWorkflowFixture.id,
    });
    expect(publish.mock.calls[0]?.[0].idempotencyKey).toMatch(
      /^[0-9a-f-]{36}$/u,
    );
  });

  it("rejects a publication response that skips immutable versions", async () => {
    const publish = vi.fn<WorkflowAdministrationApi["publish"]>(
      async ({ body }) =>
        versionedWorkflow({
          ...alertWorkflowFixture,
          revision: 3,
          currentVersion: 3,
          current: {
            ...alertWorkflowFixture.current,
            ...body.design,
            version: 3,
          },
        }),
    );
    render(
      <WorkflowWorkspace
        api={createWorkflowApiMock({ publish })}
        canManage
        canRead
        csrfToken="csrf-token"
        tenantId={workflowTenantId}
      />,
    );
    fireEvent.click(
      await screen.findByRole("button", { name: /SOC alert response/u }),
    );
    fireEvent.click(
      await screen.findByRole("button", { name: "Review publication" }),
    );
    fireEvent.click(
      await screen.findByRole("button", { name: "Confirm and publish" }),
    );

    expect(
      (
        await screen.findAllByText(
          /did not advance exactly one immutable version/u,
        )
      ).length,
    ).toBeGreaterThan(0);
    expect(screen.getByText("version 1")).toBeVisible();
    expect(
      screen.getByRole("button", { name: "Reload latest revision" }),
    ).toBeVisible();
  });

  it("rejects catalog-only mutations that alter an immutable publication", async () => {
    const get = vi.fn<WorkflowAdministrationApi["get"]>(async () =>
      versionedWorkflow({ ...alertWorkflowFixture, isDefault: false }),
    );
    const setDefault = vi.fn<WorkflowAdministrationApi["setDefault"]>(
      async () =>
        versionedWorkflow({
          ...alertWorkflowFixture,
          isDefault: true,
          revision: 2,
          currentVersion: 2,
          current: { ...alertWorkflowFixture.current, version: 2 },
        }),
    );
    render(
      <WorkflowWorkspace
        api={createWorkflowApiMock({ get, setDefault })}
        canManage
        canRead
        csrfToken="csrf-token"
        tenantId={workflowTenantId}
      />,
    );
    fireEvent.click(
      await screen.findByRole("button", { name: /SOC alert response/u }),
    );
    fireEvent.click(await screen.findByRole("button", { name: "Set default" }));

    expect(
      await screen.findByText(/unexpectedly changed an immutable publication/u),
    ).toBeVisible();
    expect(screen.getByText("version 1")).toBeVisible();
  });

  it("offers an explicit fresh-detail reload after a stale ETag", async () => {
    const get = vi.fn<WorkflowAdministrationApi["get"]>(async () =>
      versionedWorkflow(),
    );
    const publish = vi.fn<WorkflowAdministrationApi["publish"]>(async () => {
      throw new WorkflowApiError(
        "This workflow changed. Reload it and review the latest revision before retrying.",
        412,
      );
    });
    render(
      <WorkflowWorkspace
        api={createWorkflowApiMock({ get, publish })}
        canManage
        canRead
        csrfToken="csrf-token"
        tenantId={workflowTenantId}
      />,
    );
    fireEvent.click(
      await screen.findByRole("button", { name: /SOC alert response/u }),
    );
    fireEvent.click(
      await screen.findByRole("button", { name: "Review publication" }),
    );
    fireEvent.click(
      await screen.findByRole("button", { name: "Confirm and publish" }),
    );

    const reload = await screen.findByRole("button", {
      name: "Reload latest revision",
    });
    expect(screen.getAllByText(/Reload it and review/u).length).toBeGreaterThan(
      0,
    );
    fireEvent.click(reload);
    await waitFor(() => expect(get).toHaveBeenCalledTimes(2));
  });

  it("does not apply a stale detail response after the workflow kind changes", async () => {
    const detail = createDeferred<VersionedWorkflow>();
    const api = createWorkflowApiMock({
      get: async () => detail.promise,
      list: async ({ kind }) => ({
        items: kind === "alert" ? [alertWorkflowFixture] : [],
      }),
    });
    render(
      <WorkflowWorkspace
        api={api}
        canManage
        canRead
        csrfToken="csrf-token"
        tenantId={workflowTenantId}
      />,
    );

    fireEvent.click(
      await screen.findByRole("button", { name: /SOC alert response/u }),
    );
    expect(
      await screen.findByText(/Loading the selected workflow/u),
    ).toBeVisible();
    fireEvent.click(screen.getByRole("tab", { name: "Case workflow" }));
    expect(
      await screen.findByText("No workflow lineages are visible."),
    ).toBeVisible();

    await act(async () => {
      detail.resolve(versionedWorkflow());
      await detail.promise;
    });
    expect(
      screen.queryByRole("heading", { name: "SOC alert response" }),
    ).not.toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Case catalog" })).toBeVisible();
  });

  it("does not let a completed mutation restore the previous kind context", async () => {
    const publication = createDeferred<VersionedWorkflow>();
    const list = vi.fn<WorkflowAdministrationApi["list"]>(async ({ kind }) => ({
      items: kind === "alert" ? [alertWorkflowFixture] : [],
    }));
    const publish = vi.fn<WorkflowAdministrationApi["publish"]>(
      async () => publication.promise,
    );
    render(
      <WorkflowWorkspace
        api={createWorkflowApiMock({ list, publish })}
        canManage
        canRead
        csrfToken="csrf-token"
        tenantId={workflowTenantId}
      />,
    );
    fireEvent.click(
      await screen.findByRole("button", { name: /SOC alert response/u }),
    );
    fireEvent.click(
      await screen.findByRole("button", { name: "Review publication" }),
    );
    fireEvent.click(
      await screen.findByRole("button", { name: "Confirm and publish" }),
    );
    await waitFor(() => expect(publish).toHaveBeenCalledTimes(1));

    fireEvent.click(screen.getByRole("tab", { name: "Case workflow" }));
    expect(
      await screen.findByText("No workflow lineages are visible."),
    ).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "New lineage" }));
    expect(screen.getByLabelText("Stable key")).toBeEnabled();
    await act(async () => {
      publication.resolve(
        versionedWorkflow({
          ...alertWorkflowFixture,
          revision: 2,
          currentVersion: 2,
          current: { ...alertWorkflowFixture.current, version: 2 },
        }),
      );
      await publication.promise;
    });

    await waitFor(() => expect(list).toHaveBeenCalledTimes(2));
    expect(screen.getByRole("heading", { name: "Case catalog" })).toBeVisible();
    expect(
      screen.getByRole("heading", { name: "New case workflow" }),
    ).toBeVisible();
    expect(
      screen.queryByRole("heading", { name: "SOC alert response" }),
    ).not.toBeInTheDocument();
  });

  it("rejects a stale mutation response after an alert-case-alert context cycle", async () => {
    const publication = createDeferred<VersionedWorkflow>();
    const publish = vi.fn<WorkflowAdministrationApi["publish"]>(
      async () => publication.promise,
    );
    render(
      <WorkflowWorkspace
        api={createWorkflowApiMock({
          list: async ({ kind }) => ({
            items: kind === "alert" ? [alertWorkflowFixture] : [],
          }),
          publish,
        })}
        canManage
        canRead
        csrfToken="csrf-token"
        tenantId={workflowTenantId}
      />,
    );
    fireEvent.click(
      await screen.findByRole("button", { name: /SOC alert response/u }),
    );
    fireEvent.click(
      await screen.findByRole("button", { name: "Review publication" }),
    );
    fireEvent.click(
      await screen.findByRole("button", { name: "Confirm and publish" }),
    );
    await waitFor(() => expect(publish).toHaveBeenCalledTimes(1));

    fireEvent.click(screen.getByRole("tab", { name: "Case workflow" }));
    await screen.findByText("No workflow lineages are visible.");
    fireEvent.click(screen.getByRole("tab", { name: "Alert workflow" }));
    await screen.findByRole("button", { name: /SOC alert response/u });
    await act(async () => {
      publication.resolve(
        versionedWorkflow({
          ...alertWorkflowFixture,
          revision: 2,
          currentVersion: 2,
          current: { ...alertWorkflowFixture.current, version: 2 },
        }),
      );
      await publication.promise;
    });

    expect(
      screen.queryByRole("heading", { name: "SOC alert response" }),
    ).not.toBeInTheDocument();
    expect(
      screen.getByRole("heading", { name: "Alert catalog" }),
    ).toBeVisible();
  });

  it("does not surface a failed mutation from the previous kind context", async () => {
    const publication = createDeferred<VersionedWorkflow>();
    const publish = vi.fn<WorkflowAdministrationApi["publish"]>(
      async () => publication.promise,
    );
    render(
      <WorkflowWorkspace
        api={createWorkflowApiMock({
          list: async ({ kind }) => ({
            items: kind === "alert" ? [alertWorkflowFixture] : [],
          }),
          publish,
        })}
        canManage
        canRead
        csrfToken="csrf-token"
        tenantId={workflowTenantId}
      />,
    );
    fireEvent.click(
      await screen.findByRole("button", { name: /SOC alert response/u }),
    );
    fireEvent.click(
      await screen.findByRole("button", { name: "Review publication" }),
    );
    fireEvent.click(
      await screen.findByRole("button", { name: "Confirm and publish" }),
    );
    await waitFor(() => expect(publish).toHaveBeenCalledTimes(1));
    fireEvent.click(screen.getByRole("tab", { name: "Case workflow" }));
    await screen.findByText("No workflow lineages are visible.");

    await act(async () => {
      publication.reject(new WorkflowApiError("Old alert failure.", 412));
      await publication.promise.catch(() => undefined);
    });

    expect(screen.queryByText("Old alert failure.")).not.toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Case catalog" })).toBeVisible();
  });

  it("binds default changes to the selected revision and ETag", async () => {
    const get = vi.fn<WorkflowAdministrationApi["get"]>(async () =>
      versionedWorkflow({ ...alertWorkflowFixture, isDefault: false }),
    );
    const setDefault = vi.fn<WorkflowAdministrationApi["setDefault"]>(
      async ({ body }) =>
        versionedWorkflow({
          ...alertWorkflowFixture,
          isDefault: true,
          revision: body.expectedRevision + 1,
        }),
    );
    render(
      <WorkflowWorkspace
        api={createWorkflowApiMock({ get, setDefault })}
        canManage
        canRead
        csrfToken="csrf-token"
        tenantId={workflowTenantId}
      />,
    );
    fireEvent.click(
      await screen.findByRole("button", { name: /SOC alert response/u }),
    );
    fireEvent.click(await screen.findByRole("button", { name: "Set default" }));
    await waitFor(() => expect(setDefault).toHaveBeenCalledTimes(1));
    expect(setDefault.mock.calls[0]?.[0]).toMatchObject({
      body: { expectedRevision: 1 },
      etag: '"v1-_VFDEoAgKP5tR_AyfYsxkZwrjrziGnhwdGR6LyK4ovU"',
      tenantId: workflowTenantId,
      workflowId: alertWorkflowFixture.id,
    });
  });

  it("reloads the live revision after applying an immutable replay snapshot", async () => {
    const initial = versionedWorkflow({
      ...alertWorkflowFixture,
      isDefault: false,
    });
    const replay = {
      ...versionedWorkflow({
        ...alertWorkflowFixture,
        isDefault: true,
        revision: 2,
      }),
      replayed: true,
    };
    const latest = versionedWorkflow({
      ...alertWorkflowFixture,
      displayName: "Latest alert workflow",
      isDefault: true,
      revision: 3,
    });
    const get = vi
      .fn<WorkflowAdministrationApi["get"]>()
      .mockResolvedValueOnce(initial)
      .mockResolvedValueOnce(latest);
    const setDefault = vi
      .fn<WorkflowAdministrationApi["setDefault"]>()
      .mockResolvedValue(replay);
    render(
      <WorkflowWorkspace
        api={createWorkflowApiMock({ get, setDefault })}
        canManage
        canRead
        csrfToken="csrf-token"
        tenantId={workflowTenantId}
      />,
    );
    fireEvent.click(
      await screen.findByRole("button", { name: /SOC alert response/u }),
    );
    fireEvent.click(await screen.findByRole("button", { name: "Set default" }));

    expect(
      await screen.findByRole("heading", { name: "Latest alert workflow" }),
    ).toBeVisible();
    expect(screen.getByText("revision 3")).toBeVisible();
    expect(
      screen.getByText(/Default workflow changed \(safe replay\)/u),
    ).toBeVisible();
    expect(get).toHaveBeenCalledTimes(2);
  });

  it("renders lifecycle failures without leaking an unhandled rejection", async () => {
    const get = vi.fn<WorkflowAdministrationApi["get"]>(async () =>
      versionedWorkflow({ ...alertWorkflowFixture, isDefault: false }),
    );
    const setDefault = vi.fn<WorkflowAdministrationApi["setDefault"]>(
      async () => {
        throw new WorkflowApiError("The workflow changed.", 412);
      },
    );
    render(
      <WorkflowWorkspace
        api={createWorkflowApiMock({ get, setDefault })}
        canManage
        canRead
        csrfToken="csrf-token"
        tenantId={workflowTenantId}
      />,
    );
    fireEvent.click(
      await screen.findByRole("button", { name: /SOC alert response/u }),
    );
    fireEvent.click(await screen.findByRole("button", { name: "Set default" }));

    expect(await screen.findByText("The workflow changed.")).toBeVisible();
    expect(
      screen.getByRole("button", { name: "Reload latest revision" }),
    ).toBeVisible();
  });

  it("runs an explanatory simulation and renders individual gates", async () => {
    const simulate = vi.fn<WorkflowAdministrationApi["simulate"]>(async () =>
      Promise.resolve(workflowSimulationFixture),
    );
    render(
      <WorkflowWorkspace
        api={createWorkflowApiMock({ simulate })}
        canManage
        canRead
        csrfToken="csrf-token"
        tenantId={workflowTenantId}
      />,
    );
    fireEvent.click(
      await screen.findByRole("button", { name: /SOC alert response/u }),
    );
    fireEvent.click(await screen.findByRole("tab", { name: /Simulator/u }));
    fireEvent.change(screen.getByLabelText("Permissions"), {
      target: { value: "alert.update" },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Run bounded simulation" }),
    );
    await waitFor(() => expect(simulate).toHaveBeenCalledTimes(1));
    expect(simulate.mock.calls[0]?.[0]).toMatchObject({
      csrfToken: "csrf-token",
      tenantId: workflowTenantId,
      workflowId: alertWorkflowFixture.id,
    });
    expect((await screen.findAllByText("blocked")).length).toBeGreaterThan(0);
    expect(screen.getByText("comment satisfied")).toBeVisible();
    expect(screen.getByText("Missing custom fields")).toBeVisible();
    expect(screen.getByText("resolution")).toBeVisible();
    expect(screen.getByText("Effects")).toBeVisible();
    expect(
      screen.getByText("activity, audit, sla, notification"),
    ).toBeVisible();
    expect(
      screen.getByText(/Evaluated immutable publication v1/u),
    ).toBeVisible();
  });

  it("does not treat an empty simulation version as the current sentinel", async () => {
    const simulate = vi.fn<WorkflowAdministrationApi["simulate"]>();
    render(
      <WorkflowWorkspace
        api={createWorkflowApiMock({ simulate })}
        canManage={false}
        canRead
        csrfToken="csrf-token"
        tenantId={workflowTenantId}
      />,
    );
    fireEvent.click(
      await screen.findByRole("button", { name: /SOC alert response/u }),
    );
    fireEvent.click(await screen.findByRole("tab", { name: /Simulator/u }));
    fireEvent.change(screen.getByLabelText("Version"), {
      target: { value: "" },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Run bounded simulation" }),
    );

    expect(
      await screen.findByText(/must be zero or a positive version/u),
    ).toBeVisible();
    expect(simulate).not.toHaveBeenCalled();
  });

  it("explains a terminal simulation with no outgoing transitions", async () => {
    render(
      <WorkflowWorkspace
        api={createWorkflowApiMock({
          simulate: async () => ({
            ...workflowSimulationFixture,
            transitions: [],
          }),
        })}
        canManage={false}
        canRead
        csrfToken="csrf-token"
        tenantId={workflowTenantId}
      />,
    );
    fireEvent.click(
      await screen.findByRole("button", { name: /SOC alert response/u }),
    );
    fireEvent.click(await screen.findByRole("tab", { name: /Simulator/u }));
    fireEvent.click(
      screen.getByRole("button", { name: "Run bounded simulation" }),
    );

    expect(
      await screen.findByText("No outgoing transitions exist for this state."),
    ).toBeVisible();
  });

  it("loads older immutable publications from the descending cursor", async () => {
    const resource = {
      ...alertWorkflowFixture,
      currentVersion: 101,
      current: { ...alertWorkflowFixture.current, version: 101 },
    };
    const listVersions = vi.fn<WorkflowAdministrationApi["listVersions"]>(
      async ({ afterVersion }) =>
        afterVersion === undefined
          ? { items: [workflowVersionAt(101)], nextVersion: 101 }
          : { items: [workflowVersionAt(100)] },
    );
    render(
      <WorkflowWorkspace
        api={createWorkflowApiMock({
          get: async () => versionedWorkflow(resource),
          list: async () => ({ items: [resource] }),
          listVersions,
        })}
        canManage
        canRead
        csrfToken="csrf-token"
        tenantId={workflowTenantId}
      />,
    );
    fireEvent.click(
      await screen.findByRole("button", { name: /SOC alert response/u }),
    );
    expect(
      await screen.findByRole("button", { name: "Load older publications" }),
    ).toBeVisible();
    fireEvent.click(
      screen.getByRole("button", { name: "Load older publications" }),
    );

    expect(await screen.findByText("v100")).toBeVisible();
    expect(listVersions).toHaveBeenLastCalledWith(
      expect.objectContaining({ afterVersion: 101 }),
    );
  });

  it("retains loaded history when an older page fails", async () => {
    const listVersions = vi.fn<WorkflowAdministrationApi["listVersions"]>(
      async ({ afterVersion }) => {
        if (afterVersion !== undefined) {
          throw new WorkflowApiError("The older page failed.", 503);
        }
        return {
          items: Array.from({ length: 100 }, (_, index) =>
            workflowVersionAt(101 - index),
          ),
          nextVersion: 2,
        };
      },
    );
    const current = {
      ...alertWorkflowFixture,
      currentVersion: 101,
      current: { ...alertWorkflowFixture.current, version: 101 },
    };
    render(
      <WorkflowWorkspace
        api={createWorkflowApiMock({
          get: async () => versionedWorkflow(current),
          list: async () => ({ items: [current] }),
          listVersions,
        })}
        canManage
        canRead
        csrfToken="csrf-token"
        tenantId={workflowTenantId}
      />,
    );
    fireEvent.click(
      await screen.findByRole("button", { name: /SOC alert response/u }),
    );
    const loadOlder = await screen.findByRole("button", {
      name: "Load older publications",
    });
    fireEvent.click(loadOlder);

    expect(await screen.findByText("The older page failed.")).toBeVisible();
    expect(screen.getAllByText("v101").length).toBeGreaterThan(0);
    expect(
      screen.getByRole("button", { name: "Load older publications" }),
    ).toBeEnabled();
  });

  it("supports the current-publication simulation sentinel", async () => {
    const simulate = vi.fn<WorkflowAdministrationApi["simulate"]>(async () =>
      Promise.resolve(workflowSimulationFixture),
    );
    render(
      <WorkflowWorkspace
        api={createWorkflowApiMock({ simulate })}
        canManage
        canRead
        csrfToken="csrf-token"
        tenantId={workflowTenantId}
      />,
    );
    fireEvent.click(
      await screen.findByRole("button", { name: /SOC alert response/u }),
    );
    fireEvent.click(await screen.findByRole("tab", { name: /Simulator/u }));
    fireEvent.change(screen.getByLabelText("Version"), {
      target: { value: "0" },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Run bounded simulation" }),
    );

    await waitFor(() => expect(simulate).toHaveBeenCalledTimes(1));
    expect(simulate.mock.calls[0]?.[0].body.version).toBe(0);
    expect((await screen.findAllByText("blocked")).length).toBeGreaterThan(0);
  });

  it("resets simulator inputs and results when another workflow is selected", async () => {
    const secondId = "01991c20-7d5f-7000-8000-000000000204";
    const second = {
      ...alertWorkflowFixture,
      id: secondId,
      displayName: "Second alert workflow",
      currentVersion: 2,
      current: {
        ...alertWorkflowFixture.current,
        id: secondId,
        version: 2,
      },
    };
    const api = createWorkflowApiMock({
      get: async ({ workflowId }) =>
        versionedWorkflow(
          workflowId === secondId ? second : alertWorkflowFixture,
        ),
      list: async () => ({ items: [alertWorkflowFixture, second] }),
      simulate: async () => workflowSimulationFixture,
    });
    render(
      <WorkflowWorkspace
        api={api}
        canManage
        canRead
        csrfToken="csrf-token"
        tenantId={workflowTenantId}
      />,
    );
    fireEvent.click(
      await screen.findByRole("button", { name: /SOC alert response/u }),
    );
    fireEvent.click(await screen.findByRole("tab", { name: /Simulator/u }));
    fireEvent.change(screen.getByLabelText("Version"), {
      target: { value: "0" },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Run bounded simulation" }),
    );
    expect((await screen.findAllByText("blocked")).length).toBeGreaterThan(0);

    fireEvent.click(
      screen.getByRole("button", { name: /Second alert workflow/u }),
    );
    await screen.findByRole("heading", { name: "Second alert workflow" });
    fireEvent.click(screen.getByRole("tab", { name: /Simulator/u }));

    expect(screen.getByLabelText("Version")).toHaveValue("2");
    expect(
      screen.getByText("Run a scenario to inspect every transition gate."),
    ).toBeVisible();
  });

  it("withdraws a pending publish confirmation when manage authority is lost", async () => {
    const api = createWorkflowApiMock();
    const view = (
      <WorkflowWorkspace
        api={api}
        canManage
        canRead
        csrfToken="csrf-token"
        tenantId={workflowTenantId}
      />
    );
    const { rerender } = render(view);
    fireEvent.click(
      await screen.findByRole("button", { name: /SOC alert response/u }),
    );
    fireEvent.click(
      await screen.findByRole("button", { name: "Review publication" }),
    );
    expect(
      screen.getByRole("button", { name: "Confirm and publish" }),
    ).toBeVisible();

    rerender(
      <WorkflowWorkspace
        api={api}
        canManage={false}
        canRead
        csrfToken="csrf-token"
        tenantId={workflowTenantId}
      />,
    );
    expect(
      screen.queryByRole("button", { name: "Confirm and publish" }),
    ).not.toBeInTheDocument();
  });
});

function workflowVersionAt(version: number) {
  return {
    ...alertWorkflowVersionFixture,
    definition: { ...alertWorkflowVersionFixture.definition, version },
  };
}

function createDeferred<T>(): {
  promise: Promise<T>;
  reject: (reason?: unknown) => void;
  resolve: (value: T) => void;
} {
  let reject!: (reason?: unknown) => void;
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((promiseResolve, promiseReject) => {
    reject = promiseReject;
    resolve = promiseResolve;
  });
  return { promise, reject, resolve };
}
