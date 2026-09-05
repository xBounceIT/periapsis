import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { DfirAttachment } from "@periapsis/contracts";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  CaseDfirApiError,
  projectWorkspace,
  type CaseDfirApi,
} from "./case-dfir-api";
import { CaseDfirPanel } from "./case-dfir-panel";
import {
  dfirAttachmentId,
  dfirAssetId,
  dfirCaseId,
  dfirIndicatorId,
  dfirRelationshipId,
  dfirTaskId,
  dfirTenantId,
  dfirWorkspaceFixture,
} from "./case-dfir-test-fixtures";
import { evidenceCustodyFixture } from "./evidence-custody-test-fixtures";

afterEach(cleanup);

const snapshot = projectWorkspace(
  dfirWorkspaceFixture(),
  dfirTenantId,
  dfirCaseId,
);
const actorId = "0198c97d-cf4f-7000-8000-000000000021";
const operatorTeamId = "0198c97d-cf4f-7000-8000-000000000022";
const assigneeId = "0198c97d-cf4f-7000-8000-000000000023";
const evidenceLinkId = "0198c97d-cf4f-7000-8000-000000000024";
const slaInstanceId = "0198c97d-cf4f-7000-8000-000000000025";
const checklistItemId = "0198c97d-cf4f-7000-8000-000000000026";
const taskActionSnapshot = projectWorkspace(
  dfirWorkspaceFixture({
    tasks: [
      {
        ...dfirWorkspaceFixture().tasks[0]!,
        assigneeId,
        checklist: [
          {
            completed: false,
            id: checklistItemId,
            title: "Acquire triage bundle",
          },
        ],
        dueAt: "2026-08-31T12:00:00Z",
        operatorTeamId,
        slaInstanceId,
        version: 2,
      },
    ],
  }),
  dfirTenantId,
  dfirCaseId,
);

describe("CaseDfirPanel", () => {
  it.each([999, 1_000])(
    "bounds custody actions at revision %i",
    async (version) => {
      const source = dfirWorkspaceFixture();
      const evidence = source.evidence[0]!;
      evidence.version = version;
      evidence.custody = evidenceCustodyFixture(evidence.custody[0]!, version);
      const appendCustody = vi.fn<CaseDfirApi["appendCustody"]>(
        async () => undefined,
      );
      renderPanel({
        api: createApi({
          appendCustody,
          getWorkspace: async () =>
            projectWorkspace(source, dfirTenantId, dfirCaseId),
        }),
      });
      fireEvent.click(await screen.findByRole("tab", { name: /Evidence/u }));
      fireEvent.click(
        screen.getByRole("button", { name: "Open custody record" }),
      );
      const dialog = screen.getByRole("dialog");
      if (version === 1_000) {
        expect(within(dialog).getByRole("status")).toHaveTextContent(
          "This evidence has reached the custody limit of 1000 events.",
        );
        expect(
          within(dialog).queryByRole("button", {
            name: "Append custody event",
          }),
        ).toBeNull();
        expect(appendCustody).not.toHaveBeenCalled();
        fireEvent.click(within(dialog).getByRole("button", { name: "Close" }));
        await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
        return;
      }
      fireEvent.change(within(dialog).getByLabelText("Reason"), {
        target: { value: "Final custody event" },
      });
      fireEvent.click(
        within(dialog).getByRole("button", { name: "Append custody event" }),
      );
      await waitFor(() => expect(appendCustody).toHaveBeenCalledTimes(1));
      expect(appendCustody).toHaveBeenCalledWith(
        expect.objectContaining({
          body: expect.objectContaining({ expectedVersion: 999 }),
        }),
      );
    },
  );

  it("does not request the all-capability workspace without every live read permission", async () => {
    const getWorkspace = vi.fn(async () => snapshot);
    renderPanel({
      api: createApi({ getWorkspace }),
      hasPermission: (permission) => permission !== "dfir.evidence.read",
    });

    expect(
      screen.getByRole("heading", {
        name: "Case investigation access is unavailable",
      }),
    ).toBeVisible();
    expect(getWorkspace).not.toHaveBeenCalled();
  });

  it("aborts an in-flight workspace and clears its cache when a live read permission is revoked", async () => {
    const signals: AbortSignal[] = [];
    const getWorkspace = vi.fn<CaseDfirApi["getWorkspace"]>(
      ({ signal }) =>
        new Promise((_, reject) => {
          if (!signal) throw new Error("Expected an AbortSignal");
          signals.push(signal);
          signal.addEventListener("abort", () =>
            reject(new DOMException("aborted", "AbortError")),
          );
        }),
    );
    const api = createApi({ getWorkspace });
    const { rerender, queryClient } = renderPanel({ api });
    await waitFor(() => expect(getWorkspace).toHaveBeenCalledTimes(1));

    rerender(
      <QueryClientProvider client={queryClient}>
        <CaseDfirPanel
          api={api}
          caseId={dfirCaseId}
          tenantId={dfirTenantId}
          csrfToken="csrf-test"
          hasPermission={(permission) => permission !== "dfir.evidence.read"}
        />
      </QueryClientProvider>,
    );
    expect(
      screen.getByRole("heading", {
        name: "Case investigation access is unavailable",
      }),
    ).toBeVisible();
    await waitFor(() => expect(signals[0]?.aborted).toBe(true));
    expect(
      queryClient.getQueryData(["case-dfir", dfirTenantId, dfirCaseId]),
    ).toBeUndefined();
  });

  it.each([401, 403])(
    "sanitizes a %s workspace denial without rendering backend detail",
    async (status) => {
      const getWorkspace = vi.fn(async () => {
        throw new CaseDfirApiError("secret LDAP and storage detail", status);
      });
      renderPanel({ api: createApi({ getWorkspace }) });

      expect(
        await screen.findByRole("heading", {
          name: "Case investigation unavailable",
        }),
      ).toBeVisible();
      expect(screen.queryByText(/LDAP|storage detail/u)).toBeNull();
      expect(getWorkspace).toHaveBeenCalledWith({
        caseId: dfirCaseId,
        signal: expect.any(AbortSignal),
        tenantId: dfirTenantId,
      });
    },
  );

  it("does not expose or invoke a mutation without its live manage permission", async () => {
    const create = vi.fn(async () => undefined);
    renderPanel({
      api: createApi({ create }),
      hasPermission: (permission) => permission !== "dfir.ioc.manage",
    });

    expect(
      await screen.findByRole("heading", { name: "Case evidence room" }),
    ).toBeVisible();
    expect(screen.queryByRole("button", { name: "Add ioc" })).toBeNull();
    expect(create).not.toHaveBeenCalled();
  });

  it("does not start evidence collection without the required attachment grant permission", async () => {
    const create = vi.fn(async () => undefined);
    const prepareUpload = vi.fn();
    renderPanel({
      api: createApi({ create, prepareUpload }),
      hasPermission: (permission) => permission !== "dfir.attachment.manage",
    });

    fireEvent.click(await screen.findByRole("tab", { name: /Evidence/u }));
    expect(screen.queryByRole("button", { name: "Add evidence" })).toBeNull();
    expect(prepareUpload).not.toHaveBeenCalled();
    expect(create).not.toHaveBeenCalled();
  });

  it("creates an IOC with Case-bound CSRF and opaque retry context", async () => {
    const create = vi.fn(async () => undefined);
    const getWorkspace = vi.fn(async () => snapshot);
    renderPanel({ api: createApi({ create, getWorkspace }) });

    fireEvent.click(await screen.findByRole("button", { name: "Add ioc" }));
    const dialog = screen.getByRole("dialog");
    fireEvent.change(within(dialog).getByLabelText("Observable value"), {
      target: { value: "new.example" },
    });
    fireEvent.change(within(dialog).getByLabelText("Source"), {
      target: { value: "Threat feed" },
    });
    fireEvent.change(within(dialog).getByLabelText("Description"), {
      target: { value: "New command channel" },
    });
    fireEvent.change(within(dialog).getByLabelText("First seen"), {
      target: { value: "2026-08-30T07:00" },
    });
    fireEvent.change(within(dialog).getByLabelText("Last seen"), {
      target: { value: "2026-08-30T08:00" },
    });
    fireEvent.change(within(dialog).getByLabelText("Tags, comma separated"), {
      target: { value: " phishing, c2, phishing " },
    });
    fireEvent.change(
      within(dialog).getByLabelText("Enrichment (JSON object)"),
      {
        target: { value: '{"provider":"sandbox"}' },
      },
    );
    fireEvent.click(
      within(dialog).getByRole("button", { name: "Add to investigation" }),
    );

    await waitFor(() => expect(create).toHaveBeenCalledTimes(1));
    expect(create).toHaveBeenCalledWith({
      caseId: dfirCaseId,
      csrfToken: "csrf-test",
      idempotencyKey: expect.stringMatching(/^[0-9a-f-]{36}$/u),
      operation: {
        body: {
          indicator: expect.objectContaining({
            description: "New command channel",
            enrichment: { provider: "sandbox" },
            firstSeen: new Date("2026-08-30T07:00").toISOString(),
            lastSeen: new Date("2026-08-30T08:00").toISOString(),
            source: "Threat feed",
            tags: ["c2", "phishing"],
            type: "domain",
            value: "new.example",
          }),
          indicatorId: expect.stringMatching(
            /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
          ),
        },
        panel: "iocs",
      },
      signal: expect.any(AbortSignal),
      tenantId: dfirTenantId,
    });
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(getWorkspace).toHaveBeenCalledTimes(2);
  });

  it("opens and replaces an IOC with the exact workspace version", async () => {
    const replace = vi.fn(async () => undefined);
    renderPanel({ api: createApi({ replace }) });

    fireEvent.click(
      await screen.findByRole("button", { name: /bad\.example/u }),
    );
    const dialog = screen.getByRole("dialog");
    expect(within(dialog).getByText("Edit indicator")).toBeVisible();
    fireEvent.change(within(dialog).getByLabelText("Source"), {
      target: { value: "Verified feed" },
    });
    fireEvent.click(
      within(dialog).getByRole("button", { name: "Save changes" }),
    );

    await waitFor(() => expect(replace).toHaveBeenCalledTimes(1));
    expect(replace).toHaveBeenCalledWith(
      expect.objectContaining({
        caseId: dfirCaseId,
        csrfToken: "csrf-test",
        operation: expect.objectContaining({
          body: expect.objectContaining({
            expectedVersion: 4,
            indicator: expect.objectContaining({
              description: "Command and control domain",
              source: "Verified feed",
            }),
          }),
          panel: "iocs",
          resourceId: dfirIndicatorId,
        }),
        tenantId: dfirTenantId,
      }),
    );
  });

  it("creates the contract-backed asset, timeline, task, and Case relationship panels", async () => {
    const create = vi.fn<CaseDfirApi["create"]>(async () => undefined);
    renderPanel({ api: createApi({ create }) });

    fireEvent.click(await screen.findByRole("tab", { name: /Assets/u }));
    fireEvent.click(screen.getByRole("button", { name: "Add assets" }));
    fireEvent.change(screen.getByLabelText("Hostname"), {
      target: { value: "new-host" },
    });
    fireEvent.change(screen.getByLabelText("FQDN"), {
      target: { value: "new-host.example.test" },
    });
    fireEvent.change(
      screen.getByLabelText("IP or MAC addresses, comma separated"),
      { target: { value: "10.0.0.8, aa:bb:cc:dd:ee:ff" } },
    );
    fireEvent.change(screen.getByLabelText("Operating system"), {
      target: { value: "Windows 11" },
    });
    fireEvent.change(screen.getByLabelText("Owner"), {
      target: { value: "SOC" },
    });
    fireEvent.change(screen.getByLabelText("Business unit"), {
      target: { value: "Finance" },
    });
    fireEvent.change(screen.getByLabelText("External asset ID"), {
      target: { value: "cmdb-441" },
    });
    fireEvent.change(screen.getByLabelText("Tags, comma separated"), {
      target: { value: "workstation, crown_jewel" },
    });
    fireEvent.change(screen.getByLabelText("First seen"), {
      target: { value: "2026-08-30T08:00" },
    });
    fireEvent.change(screen.getByLabelText("Last seen"), {
      target: { value: "2026-08-30T09:00" },
    });
    fireEvent.change(screen.getByLabelText("Custom attributes (JSON object)"), {
      target: { value: '{"edr":"healthy"}' },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Add to investigation" }),
    );
    await waitFor(() => expect(create).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());

    fireEvent.click(screen.getByRole("tab", { name: /Timeline/u }));
    fireEvent.click(screen.getByRole("button", { name: "Add timeline" }));
    fireEvent.change(screen.getByLabelText("Event time"), {
      target: { value: "2026-08-30T10:00" },
    });
    fireEvent.change(screen.getByLabelText("Source"), {
      target: { value: "EDR" },
    });
    fireEvent.change(screen.getByLabelText("Category"), {
      target: { value: "process_start" },
    });
    fireEvent.change(screen.getByLabelText("Event title"), {
      target: { value: "New process" },
    });
    fireEvent.change(screen.getByLabelText("Actor UUIDv7"), {
      target: { value: actorId },
    });
    fireEvent.change(screen.getByLabelText("Linked IOC UUIDv7 values"), {
      target: { value: dfirIndicatorId },
    });
    fireEvent.change(screen.getByLabelText("Linked asset UUIDv7 values"), {
      target: { value: dfirAssetId },
    });
    fireEvent.change(screen.getByLabelText("Linked evidence UUIDv7 values"), {
      target: { value: evidenceLinkId },
    });
    fireEvent.change(screen.getByLabelText("Tags, comma separated"), {
      target: { value: "execution, process" },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Add to investigation" }),
    );
    await waitFor(() => expect(create).toHaveBeenCalledTimes(2));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());

    fireEvent.click(screen.getByRole("tab", { name: /Tasks/u }));
    fireEvent.click(screen.getByRole("button", { name: "Add tasks" }));
    fireEvent.change(screen.getByLabelText("Task title"), {
      target: { value: "Acquire endpoint" },
    });
    fireEvent.change(screen.getByLabelText("Instructions"), {
      target: { value: "Preserve volatile evidence" },
    });
    fireEvent.change(screen.getByLabelText("Priority"), {
      target: { value: "urgent" },
    });
    fireEvent.change(screen.getByLabelText("Operator team UUIDv7"), {
      target: { value: operatorTeamId },
    });
    fireEvent.change(screen.getByLabelText("Assignee UUIDv7"), {
      target: { value: assigneeId },
    });
    fireEvent.change(screen.getByLabelText("Due at"), {
      target: { value: "2026-08-31T12:00" },
    });
    fireEvent.change(screen.getByLabelText("Checklist items, one per line"), {
      target: { value: "Capture memory\nCollect triage bundle" },
    });
    fireEvent.change(screen.getByLabelText("SLA instance UUIDv7"), {
      target: { value: slaInstanceId },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Add to investigation" }),
    );
    await waitFor(() => expect(create).toHaveBeenCalledTimes(3));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());

    fireEvent.click(screen.getByRole("tab", { name: /Links/u }));
    fireEvent.click(screen.getByRole("button", { name: "Add links" }));
    expect(screen.getByLabelText("Source ID")).toHaveValue(dfirCaseId);
    fireEvent.change(screen.getByLabelText("Target type"), {
      target: { value: "external" },
    });
    expect(screen.queryByLabelText("Target ID")).toBeNull();
    fireEvent.change(screen.getByLabelText("Target external type"), {
      target: { value: "misp_event" },
    });
    fireEvent.change(screen.getByLabelText("Target external ID"), {
      target: { value: "event--441" },
    });
    fireEvent.change(
      screen.getByLabelText("Relationship metadata (JSON object)"),
      { target: { value: '{"confidence":92}' } },
    );
    fireEvent.click(
      screen.getByRole("button", { name: "Add to investigation" }),
    );
    await waitFor(() => expect(create).toHaveBeenCalledTimes(4));

    expect(create.mock.calls.map(([input]) => input.operation.panel)).toEqual([
      "assets",
      "timeline",
      "tasks",
      "relationships",
    ]);
    expect(create.mock.calls[0]?.[0]).toEqual(
      expect.objectContaining({
        operation: expect.objectContaining({
          body: expect.objectContaining({
            asset: expect.objectContaining({
              businessUnit: "Finance",
              customAttributes: { edr: "healthy" },
              externalId: "cmdb-441",
              firstSeen: new Date("2026-08-30T08:00").toISOString(),
              fqdn: "new-host.example.test",
              hostname: "new-host",
              ipAddresses: ["10.0.0.8"],
              macAddresses: ["aa:bb:cc:dd:ee:ff"],
              lastSeen: new Date("2026-08-30T09:00").toISOString(),
              operatingSystem: "Windows 11",
              owner: "SOC",
              tags: ["crown_jewel", "workstation"],
            }),
          }),
          panel: "assets",
        }),
      }),
    );
    expect(create.mock.calls[1]?.[0]).toEqual(
      expect.objectContaining({
        operation: expect.objectContaining({
          body: expect.objectContaining({
            event: expect.objectContaining({
              actorId,
              assetIds: [dfirAssetId],
              evidenceIds: [evidenceLinkId],
              iocIds: [dfirIndicatorId],
              tags: ["execution", "process"],
            }),
          }),
          panel: "timeline",
        }),
      }),
    );
    expect(create.mock.calls[2]?.[0]).toEqual(
      expect.objectContaining({
        operation: expect.objectContaining({
          body: expect.objectContaining({
            task: expect.objectContaining({
              assigneeId,
              checklist: [
                expect.objectContaining({
                  completed: false,
                  id: expect.stringMatching(/^[0-9a-f-]{36}$/u),
                  title: "Capture memory",
                }),
                expect.objectContaining({
                  completed: false,
                  id: expect.stringMatching(/^[0-9a-f-]{36}$/u),
                  title: "Collect triage bundle",
                }),
              ],
              description: "Preserve volatile evidence",
              dueAt: new Date("2026-08-31T12:00").toISOString(),
              operatorTeamId,
              priority: "urgent",
              slaInstanceId,
            }),
          }),
          panel: "tasks",
        }),
      }),
    );
    expect(create.mock.calls[2]?.[0].operation.body).not.toHaveProperty(
      "task.status",
    );
    expect(create.mock.calls[3]?.[0]).toEqual(
      expect.objectContaining({
        caseId: dfirCaseId,
        operation: expect.objectContaining({
          body: expect.objectContaining({
            source: { id: dfirCaseId, kind: "case" },
            target: {
              externalId: "event--441",
              externalType: "misp_event",
              kind: "external",
            },
            metadata: { confidence: 92 },
          }),
          panel: "relationships",
        }),
        tenantId: dfirTenantId,
      }),
    );
  });

  it("opens and replaces an asset with its exact workspace version", async () => {
    const replace = vi.fn(async () => undefined);
    renderPanel({ api: createApi({ replace }) });

    fireEvent.click(await screen.findByRole("tab", { name: /Assets/u }));
    fireEvent.click(screen.getByRole("button", { name: /host/u }));
    fireEvent.change(screen.getByLabelText("Environment"), {
      target: { value: "containment" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Save changes" }));

    await waitFor(() => expect(replace).toHaveBeenCalledTimes(1));
    expect(replace).toHaveBeenCalledWith(
      expect.objectContaining({
        operation: expect.objectContaining({
          body: expect.objectContaining({ expectedVersion: 2 }),
          panel: "assets",
          resourceId: dfirAssetId,
        }),
      }),
    );
  });

  it("retracts an active Case relationship with CAS and a stable caller ID", async () => {
    const retractRelationship = vi.fn<CaseDfirApi["retractRelationship"]>(
      async () => undefined,
    );
    renderPanel({ api: createApi({ retractRelationship }) });

    fireEvent.click(await screen.findByRole("tab", { name: /Links/u }));
    fireEvent.click(
      screen.getByRole("button", { name: /case:.*observed on.*asset:/u }),
    );
    fireEvent.change(screen.getByLabelText("Reason"), {
      target: { value: "Relationship superseded" },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Retract relationship" }),
    );

    await waitFor(() => expect(retractRelationship).toHaveBeenCalledTimes(1));
    expect(retractRelationship).toHaveBeenCalledWith(
      expect.objectContaining({
        body: {
          expectedVersion: 1,
          reason: "Relationship superseded",
          retractionId: expect.stringMatching(
            /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
          ),
        },
        relationshipId: dfirRelationshipId,
      }),
    );
  });

  it("submits all six Case task actions with current CAS state and distinct retry keys", async () => {
    const getWorkspace = vi.fn(async () => taskActionSnapshot);
    const replaceTaskDetails = vi.fn<CaseDfirApi["replaceTaskDetails"]>(
      async () => undefined,
    );
    const assignTask = vi.fn<CaseDfirApi["assignTask"]>(async () => undefined);
    const rescheduleTask = vi.fn<CaseDfirApi["rescheduleTask"]>(
      async () => undefined,
    );
    const replaceTaskChecklist = vi.fn<CaseDfirApi["replaceTaskChecklist"]>(
      async () => undefined,
    );
    const replaceTaskComments = vi.fn<CaseDfirApi["replaceTaskComments"]>(
      async () => undefined,
    );
    const transitionTask = vi.fn<CaseDfirApi["transitionTask"]>(
      async () => undefined,
    );
    renderPanel({
      api: createApi({
        assignTask,
        getWorkspace,
        replaceTaskChecklist,
        replaceTaskComments,
        replaceTaskDetails,
        rescheduleTask,
        transitionTask,
      }),
    });

    let dialog = await openTaskDialog();
    const targetSelect = within(dialog).getByLabelText("Target state");
    if (!(targetSelect instanceof HTMLSelectElement)) {
      throw new Error("Task target control must be a select");
    }
    expect(Array.from(targetSelect.options, ({ value }) => value)).toEqual([
      "in_progress",
      "cancelled",
    ]);
    fireEvent.change(within(dialog).getByLabelText("Action"), {
      target: { value: "details" },
    });
    fireEvent.change(within(dialog).getByLabelText("Task title"), {
      target: { value: "Contain affected endpoint" },
    });
    fireEvent.change(within(dialog).getByLabelText("Instructions"), {
      target: { value: "Isolate, image, and preserve the endpoint" },
    });
    fireEvent.change(within(dialog).getByLabelText("Priority"), {
      target: { value: "urgent" },
    });
    fireEvent.change(within(dialog).getByLabelText(/SLA instance UUID/u), {
      target: { value: "" },
    });
    fireEvent.click(
      within(dialog).getByRole("button", { name: "Apply task action" }),
    );
    await waitFor(() => expect(replaceTaskDetails).toHaveBeenCalledTimes(1));
    expect(replaceTaskDetails).toHaveBeenCalledWith(
      expect.objectContaining({
        body: {
          description: "Isolate, image, and preserve the endpoint",
          expectedVersion: 2,
          priority: "urgent",
          title: "Contain affected endpoint",
        },
        taskId: dfirTaskId,
      }),
    );
    expect(replaceTaskDetails.mock.calls[0]?.[0].body).not.toHaveProperty(
      "slaInstanceId",
    );
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());

    dialog = await openTaskDialog();
    fireEvent.change(within(dialog).getByLabelText("Action"), {
      target: { value: "assignment" },
    });
    fireEvent.click(
      within(dialog).getByRole("button", { name: "Apply task action" }),
    );
    await waitFor(() => expect(assignTask).toHaveBeenCalledTimes(1));
    expect(assignTask).toHaveBeenCalledWith(
      expect.objectContaining({
        body: {
          assigneeId,
          expectedVersion: 2,
          operatorTeamId,
        },
        taskId: dfirTaskId,
      }),
    );
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());

    dialog = await openTaskDialog();
    fireEvent.change(within(dialog).getByLabelText("Action"), {
      target: { value: "due-date" },
    });
    fireEvent.change(within(dialog).getByLabelText(/Due date/u), {
      target: { value: "" },
    });
    fireEvent.click(
      within(dialog).getByRole("button", { name: "Apply task action" }),
    );
    await waitFor(() => expect(rescheduleTask).toHaveBeenCalledTimes(1));
    expect(rescheduleTask).toHaveBeenCalledWith(
      expect.objectContaining({
        body: { expectedVersion: 2 },
        taskId: dfirTaskId,
      }),
    );
    expect(rescheduleTask.mock.calls[0]?.[0].body).not.toHaveProperty("dueAt");
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());

    dialog = await openTaskDialog();
    fireEvent.change(within(dialog).getByLabelText("Action"), {
      target: { value: "checklist" },
    });
    fireEvent.change(within(dialog).getByLabelText(/Checklist, one/u), {
      target: { value: "[x] Acquire triage bundle\n[ ] Notify owner" },
    });
    fireEvent.click(
      within(dialog).getByRole("button", { name: "Apply task action" }),
    );
    await waitFor(() => expect(replaceTaskChecklist).toHaveBeenCalledTimes(1));
    const checklistBody = replaceTaskChecklist.mock.calls[0]?.[0].body;
    expect(checklistBody).toEqual({
      checklist: [
        {
          completed: true,
          id: checklistItemId,
          title: "Acquire triage bundle",
        },
        {
          completed: false,
          id: expect.stringMatching(/^[0-9a-f-]{36}$/u),
          title: "Notify owner",
        },
      ],
      expectedVersion: 2,
    });
    expect(checklistBody?.checklist[0]).not.toHaveProperty("completedAt");
    expect(checklistBody?.checklist[0]).not.toHaveProperty("completedBy");
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());

    dialog = await openTaskDialog();
    fireEvent.change(within(dialog).getByLabelText("Action"), {
      target: { value: "comments" },
    });
    fireEvent.change(within(dialog).getByLabelText(/Comment UUIDv7s/u), {
      target: {
        value:
          "0198c97d-cf4f-7000-8000-000000000061\n0198c97d-cf4f-7000-8000-000000000060",
      },
    });
    fireEvent.click(
      within(dialog).getByRole("button", { name: "Apply task action" }),
    );
    await waitFor(() => expect(replaceTaskComments).toHaveBeenCalledTimes(1));
    expect(replaceTaskComments).toHaveBeenCalledWith(
      expect.objectContaining({
        body: {
          commentIds: [
            "0198c97d-cf4f-7000-8000-000000000060",
            "0198c97d-cf4f-7000-8000-000000000061",
          ],
          expectedVersion: 2,
        },
        taskId: dfirTaskId,
      }),
    );
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());

    dialog = await openTaskDialog();
    fireEvent.change(within(dialog).getByLabelText("Target state"), {
      target: { value: "cancelled" },
    });
    fireEvent.change(within(dialog).getByLabelText("Reason"), {
      target: { value: "Containment approved" },
    });
    fireEvent.change(
      within(dialog).getByLabelText("Completion data (JSON object)"),
      { target: { value: '{"disposition":"duplicate"}' } },
    );
    fireEvent.click(
      within(dialog).getByRole("button", { name: "Apply task action" }),
    );
    await waitFor(() => expect(transitionTask).toHaveBeenCalledTimes(1));
    expect(transitionTask).toHaveBeenCalledWith(
      expect.objectContaining({
        body: {
          completionData: { disposition: "duplicate" },
          expectedVersion: 2,
          reason: "Containment approved",
          target: "cancelled",
        },
        taskId: dfirTaskId,
      }),
    );

    const inputs = [
      replaceTaskDetails.mock.calls[0]?.[0],
      assignTask.mock.calls[0]?.[0],
      rescheduleTask.mock.calls[0]?.[0],
      replaceTaskChecklist.mock.calls[0]?.[0],
      replaceTaskComments.mock.calls[0]?.[0],
      transitionTask.mock.calls[0]?.[0],
    ];
    const retryKeys = inputs.map((input) => input?.idempotencyKey);
    expect(retryKeys).toEqual(
      retryKeys.map(() => expect.stringMatching(/^[0-9a-f-]{36}$/u)),
    );
    expect(new Set(retryKeys).size).toBe(6);
    await waitFor(() => expect(getWorkspace).toHaveBeenCalledTimes(7));
  });

  it("fails closed for malformed task UUID, completion JSON, and checklist intent", async () => {
    const replaceTaskDetails = vi.fn<CaseDfirApi["replaceTaskDetails"]>(
      async () => undefined,
    );
    const replaceTaskChecklist = vi.fn<CaseDfirApi["replaceTaskChecklist"]>(
      async () => undefined,
    );
    const transitionTask = vi.fn<CaseDfirApi["transitionTask"]>(
      async () => undefined,
    );
    renderPanel({
      api: createApi({
        getWorkspace: async () => taskActionSnapshot,
        replaceTaskChecklist,
        replaceTaskDetails,
        transitionTask,
      }),
    });
    const dialog = await openTaskDialog();
    const form = dialog.querySelector("form");
    if (!form) throw new Error("Expected task form");

    fireEvent.change(within(dialog).getByLabelText("Target state"), {
      target: { value: "cancelled" },
    });
    fireEvent.change(within(dialog).getByLabelText("Reason"), {
      target: { value: "Done" },
    });
    fireEvent.change(
      within(dialog).getByLabelText("Completion data (JSON object)"),
      { target: { value: "{" } },
    );
    fireEvent.submit(form);
    expect(await within(dialog).findByRole("alert")).toHaveTextContent(/JSON/u);
    expect(transitionTask).not.toHaveBeenCalled();

    fireEvent.change(within(dialog).getByLabelText("Action"), {
      target: { value: "details" },
    });
    fireEvent.change(within(dialog).getByLabelText(/SLA instance UUID/u), {
      target: { value: "not-a-uuid" },
    });
    fireEvent.submit(form);
    expect(await within(dialog).findByRole("alert")).toHaveTextContent(
      /canonical UUID/u,
    );
    expect(replaceTaskDetails).not.toHaveBeenCalled();

    fireEvent.change(within(dialog).getByLabelText("Action"), {
      target: { value: "checklist" },
    });
    fireEvent.change(within(dialog).getByLabelText(/Checklist, one/u), {
      target: { value: "Acquire triage bundle" },
    });
    fireEvent.submit(form);
    expect(await within(dialog).findByRole("alert")).toHaveTextContent(
      /\[ \] title or \[x\] title/u,
    );
    expect(replaceTaskChecklist).not.toHaveBeenCalled();
  });

  it("keeps Case task actions read-only without the live manage permission", async () => {
    const replaceTaskDetails = vi.fn<CaseDfirApi["replaceTaskDetails"]>(
      async () => undefined,
    );
    const transitionTask = vi.fn<CaseDfirApi["transitionTask"]>(
      async () => undefined,
    );
    renderPanel({
      api: createApi({ replaceTaskDetails, transitionTask }),
      hasPermission: (permission) => permission !== "dfir.task.manage",
    });

    await openTaskDialog();
    expect(screen.getByText("Isolate and acquire the endpoint")).toBeVisible();
    expect(screen.queryByLabelText("Action")).toBeNull();
    expect(
      screen.queryByRole("button", { name: "Apply task action" }),
    ).toBeNull();
    expect(replaceTaskDetails).not.toHaveBeenCalled();
    expect(transitionTask).not.toHaveBeenCalled();
  });

  it("opens evidence and appends a version-bound custody event", async () => {
    const appendCustody = vi.fn(async () => undefined);
    renderPanel({ api: createApi({ appendCustody }) });

    fireEvent.click(await screen.findByRole("tab", { name: /Evidence/u }));
    fireEvent.click(
      screen.getByRole("button", { name: "Open custody record" }),
    );
    fireEvent.change(screen.getByLabelText("Reason"), {
      target: { value: "Reviewed by incident commander" },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Append custody event" }),
    );

    await waitFor(() => expect(appendCustody).toHaveBeenCalledTimes(1));
    expect(appendCustody).toHaveBeenCalledWith(
      expect.objectContaining({
        body: {
          action: "accessed",
          custodyEventId: expect.stringMatching(/^[0-9a-f-]{36}$/u),
          expectedVersion: 3,
          reason: "Reviewed by incident commander",
        },
        caseId: dfirCaseId,
        csrfToken: "csrf-test",
        tenantId: dfirTenantId,
      }),
    );
  });

  it("prepares a Case-bound attachment upload through the Files form", async () => {
    const prepareUpload = vi.fn(
      async (input: Parameters<CaseDfirApi["prepareUpload"]>[0]) => ({
        attachment: {
          id: input.body.attachmentId,
          originalFilename: input.body.originalFilename,
          scanState: "pending_upload" as const,
          storageObjectId: input.body.storageObjectId,
          subject: input.body.subject,
          tenantId: input.tenantId,
          uploadedAt: "2026-08-30T09:30:00Z",
          uploadedBy: "0198c97d-cf4f-7000-8000-000000000011",
          visibility: "private" as const,
        },
        expiresAt: "2099-08-30T10:00:00Z",
        headers: [],
        method: "PUT" as const,
        uploadUrl: "https://storage.invalid/upload?signature=opaque",
      }),
    );
    const upload = vi.fn(async () => undefined);
    renderPanel({ api: createApi({ prepareUpload, upload }) });

    fireEvent.click(await screen.findByRole("tab", { name: /Files/u }));
    fireEvent.click(screen.getByRole("button", { name: "Add files" }));
    const file = new File(["artifact"], "artifact.bin", {
      type: "application/octet-stream",
    });
    fireEvent.change(screen.getByLabelText("File"), {
      target: { files: [file] },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Prepare secure upload" }),
    );

    await waitFor(() => expect(upload).toHaveBeenCalledTimes(1));
    expect(prepareUpload).toHaveBeenCalledWith(
      expect.objectContaining({
        body: expect.objectContaining({
          originalFilename: "artifact.bin",
          sizeBytes: 8,
          subject: { id: dfirCaseId, kind: "case" },
        }),
        caseId: dfirCaseId,
        csrfToken: "csrf-test",
        tenantId: dfirTenantId,
      }),
    );
  });

  it("reauthorizes an attachment download and exposes only the returned short-lived link", async () => {
    const prepareDownload = vi.fn(async () => ({
      attachment: snapshot.workspace.attachments[0]!,
      downloadUrl: "https://storage.invalid/private?signature=opaque",
      expiresAt: "2099-08-30T10:00:00Z",
    }));
    renderPanel({ api: createApi({ prepareDownload }) });

    fireEvent.click(await screen.findByRole("tab", { name: /Files/u }));
    fireEvent.click(screen.getByRole("button", { name: /memory\.raw/u }));
    fireEvent.click(
      screen.getByRole("button", { name: "Prepare secure download" }),
    );

    expect(
      await screen.findByRole("link", { name: "Download authorized file" }),
    ).toHaveAttribute(
      "href",
      "https://storage.invalid/private?signature=opaque",
    );
    expect(prepareDownload).toHaveBeenCalledWith({
      attachmentId: dfirAttachmentId,
      body: { subject: { id: dfirCaseId, kind: "case" } },
      caseId: dfirCaseId,
      csrfToken: "csrf-test",
      signal: expect.any(AbortSignal),
      tenantId: dfirTenantId,
    });
  });

  it("uploads, waits for verification, and collects Case-bound evidence", async () => {
    let completedAttachment: DfirAttachment | undefined;
    const getWorkspace = vi.fn(async () =>
      completedAttachment
        ? {
            ...snapshot,
            workspace: {
              ...snapshot.workspace,
              attachments: [
                ...snapshot.workspace.attachments,
                completedAttachment,
              ],
            },
          }
        : snapshot,
    );
    const prepareUpload = vi.fn(
      async (input: Parameters<CaseDfirApi["prepareUpload"]>[0]) => {
        const availableAttachment: DfirAttachment = {
          id: input.body.attachmentId,
          originalFilename: input.body.originalFilename,
          scanState: "available",
          storageObjectId: input.body.storageObjectId,
          subject: input.body.subject,
          tenantId: input.tenantId,
          uploadedAt: "2026-08-30T09:30:00Z",
          uploadedBy: "0198c97d-cf4f-7000-8000-000000000011",
          visibility: "private",
        };
        completedAttachment = availableAttachment;
        const pendingAttachment: DfirAttachment = {
          ...availableAttachment,
          scanState: "pending_upload",
        };
        return {
          attachment: pendingAttachment,
          expiresAt: "2099-08-30T10:00:00Z",
          headers: [],
          method: "PUT" as const,
          uploadUrl: "https://storage.invalid/upload?signature=opaque",
        };
      },
    );
    const upload = vi.fn(async () => undefined);
    const create = vi.fn(async () => undefined);
    renderPanel({
      api: createApi({ create, getWorkspace, prepareUpload, upload }),
    });

    fireEvent.click(await screen.findByRole("tab", { name: /Evidence/u }));
    fireEvent.click(screen.getByRole("button", { name: "Add evidence" }));
    const dialog = screen.getByRole("dialog");
    fireEvent.change(within(dialog).getByLabelText("Evidence title"), {
      target: { value: "Memory capture" },
    });
    fireEvent.change(within(dialog).getByLabelText("Evidence type"), {
      target: { value: "memory_image" },
    });
    fireEvent.change(within(dialog).getByLabelText("Collection source"), {
      target: { value: "EDR" },
    });
    fireEvent.change(within(dialog).getByLabelText("Description"), {
      target: { value: "Volatile memory from the affected workstation" },
    });
    fireEvent.change(within(dialog).getByLabelText("Collected at"), {
      target: { value: "2026-08-30T09:30" },
    });
    fireEvent.change(within(dialog).getByLabelText("Retain until"), {
      target: { value: "2027-08-30T09:30" },
    });
    const file = new File(["bytes"], "capture.bin", {
      type: "application/octet-stream",
    });
    fireEvent.change(within(dialog).getByLabelText("File"), {
      target: { files: [file] },
    });
    fireEvent.click(
      within(dialog).getByRole("button", {
        name: "Begin evidence collection",
      }),
    );

    await waitFor(() => expect(create).toHaveBeenCalledTimes(1));
    expect(prepareUpload).toHaveBeenCalledWith(
      expect.objectContaining({
        body: expect.objectContaining({
          classification: "internal",
          originalFilename: "capture.bin",
          requestedVisibility: "private",
          sizeBytes: 5,
          subject: { id: dfirCaseId, kind: "case" },
        }),
        caseId: dfirCaseId,
        csrfToken: "csrf-test",
        tenantId: dfirTenantId,
      }),
    );
    expect(upload).toHaveBeenCalledWith({
      file,
      prepared: expect.objectContaining({ method: "PUT" }),
      signal: expect.any(AbortSignal),
    });
    expect(create).toHaveBeenCalledWith(
      expect.objectContaining({
        caseId: dfirCaseId,
        csrfToken: "csrf-test",
        operation: {
          body: expect.objectContaining({
            classification: "internal",
            description: "Volatile memory from the affected workstation",
            evidenceId: expect.stringMatching(/^[0-9a-f-]{36}$/u),
            evidenceType: "memory_image",
            retentionUntil: new Date("2027-08-30T09:30").toISOString(),
            source: "EDR",
            storageObjectId: completedAttachment?.storageObjectId,
            title: "Memory capture",
          }),
          panel: "evidence",
        },
        tenantId: dfirTenantId,
      }),
    );
    expect(getWorkspace).toHaveBeenCalledWith({
      caseId: dfirCaseId,
      signal: expect.any(AbortSignal),
      tenantId: dfirTenantId,
    });
  });
});

async function openTaskDialog(): Promise<HTMLElement> {
  fireEvent.click(await screen.findByRole("tab", { name: /Tasks/u }));
  fireEvent.click(screen.getByRole("button", { name: /Contain endpoint/u }));
  return screen.getByRole("dialog");
}

function renderPanel({
  api,
  hasPermission = () => true,
}: {
  api: CaseDfirApi;
  hasPermission?: React.ComponentProps<typeof CaseDfirPanel>["hasPermission"];
}): ReturnType<typeof render> & { queryClient: QueryClient } {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  const result = render(
    <QueryClientProvider client={queryClient}>
      <CaseDfirPanel
        api={api}
        caseId={dfirCaseId}
        csrfToken="csrf-test"
        hasPermission={hasPermission}
        tenantId={dfirTenantId}
      />
    </QueryClientProvider>,
  );
  return { ...result, queryClient };
}

function createApi(overrides: Partial<CaseDfirApi> = {}): CaseDfirApi {
  return {
    appendCustody: async () => undefined,
    changeLink: async () => undefined,
    assignTask: async () => undefined,
    create: async () => undefined,
    getWorkspace: async () => snapshot,
    prepareDownload: async () => {
      throw new Error("unexpected prepare download");
    },
    prepareUpload: async () => {
      throw new Error("unexpected prepare upload");
    },
    replace: async () => undefined,
    replaceTaskChecklist: async () => undefined,
    replaceTaskComments: async () => undefined,
    replaceTaskDetails: async () => undefined,
    rescheduleTask: async () => undefined,
    retractRelationship: async () => undefined,
    transitionTask: async () => undefined,
    upload: async () => undefined,
    ...overrides,
  };
}
