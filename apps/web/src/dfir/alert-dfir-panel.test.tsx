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
  AlertDfirApiError,
  projectAlertWorkspace,
  type AlertDfirApi,
} from "./alert-dfir-api";
import { AlertDfirPanel } from "./alert-dfir-panel";
import {
  alertDfirAlertId,
  alertDfirEvidenceId,
  alertDfirExtendedWorkspaceFixture,
  alertDfirRelationshipId,
  alertDfirTaskId,
  alertDfirTenantId,
  alertDfirWorkspaceFixture,
} from "./alert-dfir-test-fixtures";
import { evidenceCustodyFixture } from "./evidence-custody-test-fixtures";

afterEach(cleanup);

const snapshot = projectAlertWorkspace(
  alertDfirWorkspaceFixture(),
  alertDfirTenantId,
  alertDfirAlertId,
);
const extendedSnapshot = projectAlertWorkspace(
  alertDfirExtendedWorkspaceFixture(),
  alertDfirTenantId,
  alertDfirAlertId,
);

describe("AlertDfirPanel", () => {
  it.each([999, 1_000])(
    "bounds custody actions at revision %i",
    async (version) => {
      const source = alertDfirExtendedWorkspaceFixture();
      const evidence = source.evidence[0]!;
      evidence.version = version;
      evidence.custody = evidenceCustodyFixture(evidence.custody[0]!, version);
      const appendCustody = vi.fn<AlertDfirApi["appendCustody"]>(
        async () => undefined,
      );
      renderPanel({
        api: createApi({
          appendCustody,
          getWorkspace: async () =>
            projectAlertWorkspace(source, alertDfirTenantId, alertDfirAlertId),
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

  it("does not request the all-capability workspace without every live Alert read permission", () => {
    const getWorkspace = vi.fn(async () => snapshot);
    renderPanel({
      api: createApi({ getWorkspace }),
      hasPermission: (permission) => permission !== "dfir.timeline.read",
    });

    expect(
      screen.getByRole("heading", {
        name: "Alert investigation access is unavailable",
      }),
    ).toBeVisible();
    expect(getWorkspace).not.toHaveBeenCalled();
  });

  it("aborts an in-flight workspace when a live Alert read permission is revoked", async () => {
    const signals: AbortSignal[] = [];
    const getWorkspace = vi.fn<AlertDfirApi["getWorkspace"]>(
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
        <AlertDfirPanel
          alertId={alertDfirAlertId}
          api={api}
          csrfToken="csrf-test"
          hasPermission={(permission) => permission !== "dfir.timeline.read"}
          tenantId={alertDfirTenantId}
        />
      </QueryClientProvider>,
    );

    expect(
      screen.getByRole("heading", {
        name: "Alert investigation access is unavailable",
      }),
    ).toBeVisible();
    await waitFor(() => expect(signals[0]?.aborted).toBe(true));
    expect(
      queryClient.getQueryState([
        "alert-dfir",
        alertDfirTenantId,
        alertDfirAlertId,
      ]),
    ).toBeUndefined();
  });

  it("sanitizes a denied workspace response", async () => {
    const getWorkspace = vi.fn(async () => {
      throw new AlertDfirApiError("secret storage detail", 403);
    });
    renderPanel({ api: createApi({ getWorkspace }) });

    expect(
      await screen.findByRole("heading", {
        name: "Alert investigation unavailable",
      }),
    ).toBeVisible();
    expect(screen.queryByText(/secret storage/u)).toBeNull();
  });

  it("mounts all seven Alert-owned DFIR collections", async () => {
    renderPanel({ api: createApi() });

    expect(
      await screen.findByRole("heading", { name: "Alert investigation room" }),
    ).toBeVisible();
    expect(screen.getAllByRole("tab").map((tab) => tab.textContent)).toEqual([
      "IOC1",
      "Assets1",
      "Evidence0",
      "Timeline1",
      "Tasks0",
      "Files1",
      "Links0",
    ]);
  });

  it("hides a mutation when its exact live manage permission is absent", async () => {
    const create = vi.fn<AlertDfirApi["create"]>(async () => undefined);
    renderPanel({
      api: createApi({ create }),
      hasPermission: (permission) => permission !== "dfir.ioc.manage",
    });

    expect(
      await screen.findByRole("heading", { name: "Alert investigation room" }),
    ).toBeVisible();
    expect(screen.queryByRole("button", { name: "Add ioc" })).toBeNull();
    expect(create).not.toHaveBeenCalled();
  });

  it("does not start Alert evidence collection without attachment authority", async () => {
    const create = vi.fn<AlertDfirApi["create"]>(async () => undefined);
    const prepareUpload = vi.fn<AlertDfirApi["prepareUpload"]>();
    renderPanel({
      api: createApi({ create, prepareUpload }),
      hasPermission: (permission) => permission !== "dfir.attachment.manage",
    });

    fireEvent.click(await screen.findByRole("tab", { name: /Evidence/u }));
    expect(screen.queryByRole("button", { name: "Add evidence" })).toBeNull();
    expect(prepareUpload).not.toHaveBeenCalled();
    expect(create).not.toHaveBeenCalled();
  });

  it("creates an Alert timeline event with every supported link field", async () => {
    const create = vi.fn<AlertDfirApi["create"]>(async () => undefined);
    renderPanel({ api: createApi({ create }) });

    fireEvent.click(await screen.findByRole("tab", { name: /Timeline/u }));
    fireEvent.click(screen.getByRole("button", { name: "Add timeline" }));
    const dialog = screen.getByRole("dialog");
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
      target: { value: "Encoded command" },
    });
    fireEvent.change(screen.getByLabelText("Description"), {
      target: { value: "PowerShell launched with an encoded payload" },
    });
    fireEvent.change(screen.getByLabelText("Actor UUIDv7"), {
      target: { value: "0198c97d-cf4f-7000-8000-000000000031" },
    });
    fireEvent.change(screen.getByLabelText("Linked IOC UUIDv7 values"), {
      target: { value: "0198c97d-cf4f-7000-8000-000000000032" },
    });
    fireEvent.change(screen.getByLabelText("Linked asset UUIDv7 values"), {
      target: { value: "0198c97d-cf4f-7000-8000-000000000033" },
    });
    fireEvent.change(
      within(dialog).getByLabelText("Linked evidence UUIDv7 values"),
      {
        target: { value: "0198c97d-cf4f-7000-8000-000000000034" },
      },
    );
    fireEvent.change(screen.getByLabelText("Tags, comma separated"), {
      target: { value: "execution, suspicious" },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Add to investigation" }),
    );

    await waitFor(() => expect(create).toHaveBeenCalledTimes(1));
    expect(create).toHaveBeenCalledWith(
      expect.objectContaining({
        alertId: alertDfirAlertId,
        csrfToken: "csrf-test",
        operation: {
          body: {
            event: expect.objectContaining({
              actorId: "0198c97d-cf4f-7000-8000-000000000031",
              assetIds: ["0198c97d-cf4f-7000-8000-000000000033"],
              description: "PowerShell launched with an encoded payload",
              evidenceIds: ["0198c97d-cf4f-7000-8000-000000000034"],
              iocIds: ["0198c97d-cf4f-7000-8000-000000000032"],
              tags: ["execution", "suspicious"],
            }),
            timelineEventId: expect.stringMatching(/^[0-9a-f-]{36}$/u),
          },
          panel: "timeline",
        },
        tenantId: alertDfirTenantId,
      }),
    );
  });

  it("creates Alert-native tasks and directly rooted relationships", async () => {
    const create = vi.fn<AlertDfirApi["create"]>(async () => undefined);
    renderPanel({ api: createApi({ create }) });

    fireEvent.click(await screen.findByRole("tab", { name: /Tasks/u }));
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
    fireEvent.change(screen.getByLabelText("Checklist items, one per line"), {
      target: { value: "Capture memory\nCollect triage bundle" },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Add to investigation" }),
    );
    await waitFor(() => expect(create).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());

    fireEvent.click(screen.getByRole("tab", { name: /Links/u }));
    fireEvent.click(screen.getByRole("button", { name: "Add links" }));
    expect(screen.getByLabelText("Source type")).toHaveValue("alert");
    expect(screen.getByLabelText("Source ID")).toHaveValue(alertDfirAlertId);
    fireEvent.change(screen.getByLabelText("Target type"), {
      target: { value: "external" },
    });
    fireEvent.change(screen.getByLabelText("Target external type"), {
      target: { value: "misp_event" },
    });
    fireEvent.change(screen.getByLabelText("Target external ID"), {
      target: { value: "event--441" },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Add to investigation" }),
    );
    await waitFor(() => expect(create).toHaveBeenCalledTimes(2));

    const taskOperation = create.mock.calls[0]?.[0].operation;
    const relationshipOperation = create.mock.calls[1]?.[0].operation;
    expect(taskOperation).toEqual({
      body: {
        task: expect.objectContaining({
          checklist: [
            expect.objectContaining({
              completed: false,
              title: "Capture memory",
            }),
            expect.objectContaining({
              completed: false,
              title: "Collect triage bundle",
            }),
          ],
          description: "Preserve volatile evidence",
          priority: "urgent",
          title: "Acquire endpoint",
        }),
        taskId: expect.stringMatching(/^[0-9a-f-]{36}$/u),
      },
      panel: "tasks",
    });
    if (!taskOperation || taskOperation.panel !== "tasks") {
      throw new Error("Expected task");
    }
    expect(taskOperation.body.task).not.toHaveProperty("status");
    expect(relationshipOperation).toEqual({
      body: expect.objectContaining({
        relationshipType: "related_to",
        source: { id: alertDfirAlertId, kind: "alert" },
        target: {
          externalId: "event--441",
          externalType: "misp_event",
          kind: "external",
        },
      }),
      panel: "relationships",
    });
  });

  it("submits every Alert task CAS action without client-owned completion metadata", async () => {
    const detailsWorkspace = alertDfirExtendedWorkspaceFixture();
    detailsWorkspace.tasks[0]!.slaInstanceId =
      "0198c97d-cf4f-7000-8000-000000000043";
    const taskSnapshot = projectAlertWorkspace(
      detailsWorkspace,
      alertDfirTenantId,
      alertDfirAlertId,
    );
    const transitionTask = vi.fn<AlertDfirApi["transitionTask"]>(
      async () => undefined,
    );
    const assignTask = vi.fn<AlertDfirApi["assignTask"]>(async () => undefined);
    const replaceTaskDetails = vi.fn<AlertDfirApi["replaceTaskDetails"]>(
      async () => undefined,
    );
    const rescheduleTask = vi.fn<AlertDfirApi["rescheduleTask"]>(
      async () => undefined,
    );
    const replaceTaskChecklist = vi.fn<AlertDfirApi["replaceTaskChecklist"]>(
      async () => undefined,
    );
    const replaceTaskComments = vi.fn<AlertDfirApi["replaceTaskComments"]>(
      async () => undefined,
    );
    renderPanel({
      api: createApi({
        assignTask,
        getWorkspace: async () => taskSnapshot,
        replaceTaskDetails,
        replaceTaskChecklist,
        replaceTaskComments,
        rescheduleTask,
        transitionTask,
      }),
    });

    let dialog = await openExtendedTaskDialog();
    const targetSelect = within(dialog).getByLabelText("Target state");
    if (!(targetSelect instanceof HTMLSelectElement)) {
      throw new Error("Task target control must be a select");
    }
    expect(Array.from(targetSelect.options, ({ value }) => value)).toEqual([
      "in_progress",
      "cancelled",
    ]);
    fireEvent.change(within(dialog).getByLabelText("Reason"), {
      target: { value: "Triage started" },
    });
    fireEvent.click(
      within(dialog).getByRole("button", { name: "Apply task action" }),
    );
    await waitFor(() => expect(transitionTask).toHaveBeenCalledTimes(1));
    expect(transitionTask).toHaveBeenCalledWith(
      expect.objectContaining({
        body: {
          expectedVersion: 2,
          reason: "Triage started",
          target: "in_progress",
        },
        taskId: alertDfirTaskId,
      }),
    );

    dialog = await openExtendedTaskDialog();
    fireEvent.change(within(dialog).getByLabelText("Action"), {
      target: { value: "details" },
    });
    fireEvent.change(within(dialog).getByLabelText("Task title"), {
      target: { value: "Contain affected endpoint" },
    });
    fireEvent.change(within(dialog).getByLabelText("Instructions"), {
      target: { value: "Revised containment instructions" },
    });
    fireEvent.change(within(dialog).getByLabelText("Priority"), {
      target: { value: "high" },
    });
    const slaInput = within(dialog).getByLabelText(/SLA instance UUID/u);
    fireEvent.change(slaInput, { target: { value: "not-a-uuid" } });
    fireEvent.click(
      within(dialog).getByRole("button", { name: "Apply task action" }),
    );
    expect(replaceTaskDetails).not.toHaveBeenCalled();
    expect(slaInput).toBeInvalid();
    fireEvent.change(slaInput, { target: { value: "" } });
    fireEvent.click(
      within(dialog).getByRole("button", { name: "Apply task action" }),
    );
    await waitFor(() => expect(replaceTaskDetails).toHaveBeenCalledTimes(1));
    expect(replaceTaskDetails).toHaveBeenCalledWith(
      expect.objectContaining({
        body: {
          description: "Revised containment instructions",
          expectedVersion: 2,
          priority: "high",
          title: "Contain affected endpoint",
        },
        taskId: alertDfirTaskId,
      }),
    );

    dialog = await openExtendedTaskDialog();
    fireEvent.change(within(dialog).getByLabelText("Action"), {
      target: { value: "assignment" },
    });
    fireEvent.change(within(dialog).getByLabelText(/Operator team UUID/u), {
      target: { value: "0198c97d-cf4f-7000-8000-000000000041" },
    });
    fireEvent.change(within(dialog).getByLabelText(/Assignee UUID/u), {
      target: { value: "0198c97d-cf4f-7000-8000-000000000042" },
    });
    fireEvent.click(
      within(dialog).getByRole("button", { name: "Apply task action" }),
    );
    await waitFor(() => expect(assignTask).toHaveBeenCalledTimes(1));
    expect(assignTask).toHaveBeenCalledWith(
      expect.objectContaining({
        body: {
          assigneeId: "0198c97d-cf4f-7000-8000-000000000042",
          expectedVersion: 2,
          operatorTeamId: "0198c97d-cf4f-7000-8000-000000000041",
        },
      }),
    );

    dialog = await openExtendedTaskDialog();
    fireEvent.change(within(dialog).getByLabelText("Action"), {
      target: { value: "due-date" },
    });
    fireEvent.change(within(dialog).getByLabelText(/Due date/u), {
      target: { value: "2026-08-31T12:00" },
    });
    fireEvent.click(
      within(dialog).getByRole("button", { name: "Apply task action" }),
    );
    await waitFor(() => expect(rescheduleTask).toHaveBeenCalledTimes(1));
    expect(rescheduleTask).toHaveBeenCalledWith(
      expect.objectContaining({
        body: {
          dueAt: new Date("2026-08-31T12:00").toISOString(),
          expectedVersion: 2,
        },
      }),
    );

    dialog = await openExtendedTaskDialog();
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
          id: "0198c97d-cf4f-7000-8000-000000000026",
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

    dialog = await openExtendedTaskDialog();
    fireEvent.change(within(dialog).getByLabelText("Action"), {
      target: { value: "comments" },
    });
    fireEvent.change(within(dialog).getByLabelText(/Comment UUIDv7s/u), {
      target: {
        value:
          "0198c97d-cf4f-7000-8000-000000000045\n0198c97d-cf4f-7000-8000-000000000044",
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
            "0198c97d-cf4f-7000-8000-000000000044",
            "0198c97d-cf4f-7000-8000-000000000045",
          ],
          expectedVersion: 2,
        },
        taskId: alertDfirTaskId,
      }),
    );
  });

  it("appends Alert evidence custody and terminal relationship retraction", async () => {
    const appendCustody = vi.fn<AlertDfirApi["appendCustody"]>(
      async () => undefined,
    );
    const retractRelationship = vi.fn<AlertDfirApi["retractRelationship"]>(
      async () => undefined,
    );
    renderPanel({
      api: createApi({
        appendCustody,
        getWorkspace: async () => extendedSnapshot,
        retractRelationship,
      }),
    });

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
        body: expect.objectContaining({
          action: "accessed",
          expectedVersion: 3,
          reason: "Reviewed by incident commander",
        }),
        evidenceId: alertDfirEvidenceId,
      }),
    );

    fireEvent.click(await screen.findByRole("tab", { name: /Links/u }));
    fireEvent.click(
      screen.getByRole("button", { name: /alert:.*contains.*evidence:/u }),
    );
    fireEvent.change(screen.getByLabelText("Reason"), {
      target: { value: "Link superseded" },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Retract relationship" }),
    );
    await waitFor(() => expect(retractRelationship).toHaveBeenCalledTimes(1));
    expect(retractRelationship).toHaveBeenCalledWith(
      expect.objectContaining({
        body: expect.objectContaining({
          expectedVersion: 1,
          reason: "Link superseded",
        }),
        relationshipId: alertDfirRelationshipId,
      }),
    );
  });

  it("uploads, verifies, and collects evidence directly under the Alert", async () => {
    let completedAttachment: DfirAttachment | undefined;
    const getWorkspace = vi.fn<AlertDfirApi["getWorkspace"]>(async () =>
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
    const prepareUpload = vi.fn<AlertDfirApi["prepareUpload"]>(
      async (input) => {
        completedAttachment = {
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
        return {
          attachment: { ...completedAttachment, scanState: "pending_upload" },
          expiresAt: "2099-08-30T10:00:00Z",
          headers: [],
          method: "PUT",
          uploadUrl: "https://storage.invalid/upload?signature=opaque",
        };
      },
    );
    const upload = vi.fn<AlertDfirApi["upload"]>(async () => undefined);
    const create = vi.fn<AlertDfirApi["create"]>(async () => undefined);
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
          subject: { id: alertDfirAlertId, kind: "alert" },
        }),
        alertId: alertDfirAlertId,
        csrfToken: "csrf-test",
        tenantId: alertDfirTenantId,
      }),
    );
    expect(upload).toHaveBeenCalledWith({
      file,
      prepared: expect.objectContaining({ method: "PUT" }),
      signal: expect.any(AbortSignal),
    });
    expect(create).toHaveBeenCalledWith(
      expect.objectContaining({
        alertId: alertDfirAlertId,
        operation: {
          body: expect.objectContaining({
            classification: "internal",
            description: "Volatile memory from the affected workstation",
            evidenceType: "memory_image",
            retentionUntil: new Date("2027-08-30T09:30").toISOString(),
            source: "EDR",
            storageObjectId: completedAttachment?.storageObjectId,
            title: "Memory capture",
          }),
          panel: "evidence",
        },
        tenantId: alertDfirTenantId,
      }),
    );
  });

  it("closes an open create intent when its exact manage permission is revoked", async () => {
    const api = createApi();
    const { rerender, queryClient } = renderPanel({ api });
    expect(
      await screen.findByRole("heading", { name: "Alert investigation room" }),
    ).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "Add ioc" }));
    expect(screen.getByRole("dialog")).toBeVisible();

    rerender(
      <QueryClientProvider client={queryClient}>
        <AlertDfirPanel
          alertId={alertDfirAlertId}
          api={api}
          csrfToken="csrf-test"
          hasPermission={(permission) => permission !== "dfir.ioc.manage"}
          tenantId={alertDfirTenantId}
        />
      </QueryClientProvider>,
    );

    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(screen.queryByRole("button", { name: "Add ioc" })).toBeNull();
  });

  it("aborts the old workspace request when the Alert identity changes", async () => {
    const signals: AbortSignal[] = [];
    const getWorkspace = vi.fn<AlertDfirApi["getWorkspace"]>(
      ({ signal }) =>
        new Promise((_, reject) => {
          if (!signal) throw new Error("Expected an AbortSignal");
          signals.push(signal);
          signal.addEventListener("abort", () =>
            reject(new DOMException("aborted", "AbortError")),
          );
        }),
    );
    const { rerender, queryClient } = renderPanel({
      api: createApi({ getWorkspace }),
    });
    await waitFor(() => expect(getWorkspace).toHaveBeenCalledTimes(1));

    rerender(
      <QueryClientProvider client={queryClient}>
        <AlertDfirPanel
          alertId="0198c97d-cf4f-7000-8000-000000000099"
          api={createApi({ getWorkspace })}
          csrfToken="csrf-test"
          hasPermission={() => true}
          tenantId={alertDfirTenantId}
        />
      </QueryClientProvider>,
    );

    await waitFor(() => expect(getWorkspace).toHaveBeenCalledTimes(2));
    expect(signals[0]?.aborted).toBe(true);
    expect(
      queryClient.getQueryState([
        "alert-dfir",
        alertDfirTenantId,
        alertDfirAlertId,
      ]),
    ).toBeUndefined();
  });
});

async function openExtendedTaskDialog(): Promise<HTMLElement> {
  fireEvent.click(await screen.findByRole("tab", { name: /Tasks/u }));
  fireEvent.click(screen.getByRole("button", { name: /Contain endpoint/u }));
  return screen.getByRole("dialog");
}

function renderPanel({
  api,
  hasPermission = () => true,
}: {
  api: AlertDfirApi;
  hasPermission?: React.ComponentProps<typeof AlertDfirPanel>["hasPermission"];
}): ReturnType<typeof render> & { queryClient: QueryClient } {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  const rendered = render(
    <QueryClientProvider client={queryClient}>
      <AlertDfirPanel
        alertId={alertDfirAlertId}
        api={api}
        csrfToken="csrf-test"
        hasPermission={hasPermission}
        tenantId={alertDfirTenantId}
      />
    </QueryClientProvider>,
  );
  return { ...rendered, queryClient };
}

function createApi(overrides: Partial<AlertDfirApi> = {}): AlertDfirApi {
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
    replaceTaskDetails: async () => undefined,
    replaceTaskChecklist: async () => undefined,
    replaceTaskComments: async () => undefined,
    replace: async () => undefined,
    rescheduleTask: async () => undefined,
    retractRelationship: async () => undefined,
    transitionTask: async () => undefined,
    upload: async () => undefined,
    ...overrides,
  };
}
