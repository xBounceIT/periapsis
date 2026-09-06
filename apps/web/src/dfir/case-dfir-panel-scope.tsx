import type {
  DfirAttachment,
  DfirCustodyAction,
  DfirPreparedDownload,
  DfirRelationshipRetractRequest,
  DfirScanState,
  DfirTask,
  DfirTaskAssignmentRequest,
  DfirTaskChecklistRequest,
  DfirTaskCommentsRequest,
  DfirTaskDetailsRequest,
  DfirTaskDueDateRequest,
  DfirTaskPriority,
  DfirTaskStatus,
  DfirTaskTransitionRequest,
} from "@periapsis/contracts";
import {
  Alert,
  AlertDescription,
  AlertTitle,
} from "@periapsis/ui/components/ui/alert";
import { Button } from "@periapsis/ui/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@periapsis/ui/components/ui/dialog";
import { Input } from "@periapsis/ui/components/ui/input";
import { Label } from "@periapsis/ui/components/ui/label";
import { Textarea } from "@periapsis/ui/components/ui/textarea";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { RefreshCw, ShieldAlert } from "lucide-react";
import {
  useCallback,
  useEffect,
  useLayoutEffect,
  useRef,
  useState,
  type ReactNode,
} from "react";

import {
  idempotencyKeyForPayload,
  type IdempotencyReference,
} from "../lib/payload-idempotency";
import { generateUuidV7 } from "../lib/uuid-v7";
import {
  CaseDfirApiError,
  type CaseDfirApi,
  type CaseDfirWorkspaceSnapshot,
} from "./case-dfir-api";
import { CaseDfirWorkspace } from "./case-dfir-workspace";
import { maximumDfirCustodyEvents } from "./evidence-custody";
import {
  dfirReadPermissions,
  safeDfirProblem,
  type DfirPanel,
  type DfirPermission,
  type DfirReadPermission,
} from "./model";
import { DfirResourceForm } from "./resource-form";
import {
  assetSpecFromDraft,
  documentInputValue,
  indicatorSpecFromDraft,
  instantInputValue,
  parseOptionalDocumentText,
  relationshipReferenceFromDraft,
  taskSpecFromDraft,
  timelineSpecFromDraft,
  type DfirMutationDraft,
} from "./resource-form-model";
import { SharedResourceLinks } from "./shared-resource-links";
import { parseTaskChecklistIntent } from "./task-checklist-intent";
import { parseTaskCommentIntent } from "./task-comment-intent";
import { buildAttachmentUploadRequest } from "./upload-request";
// oxlint-disable-next-line import/no-unassigned-import -- Vite extracts this component-owned stylesheet.
import "./case-dfir-panel.css";

type Permission = DfirPermission | DfirReadPermission;
type PermissionCheck = (permission: Permission) => boolean;

const managePermission = {
  iocs: "dfir.ioc.manage",
  assets: "dfir.asset.manage",
  evidence: "dfir.evidence.manage",
  timeline: "dfir.timeline.manage",
  tasks: "dfir.task.manage",
  attachments: "dfir.attachment.manage",
  relationships: "dfir.relationship.manage",
} as const satisfies Record<DfirPanel, DfirPermission>;

const readPermission = {
  iocs: "dfir.ioc.read",
  assets: "dfir.asset.read",
  evidence: "dfir.evidence.read",
  timeline: "dfir.timeline.read",
  tasks: "dfir.task.read",
  attachments: "dfir.attachment.read",
  relationships: "dfir.relationship.read",
} as const satisfies Record<DfirPanel, DfirReadPermission>;

const taskStatuses = [
  "todo",
  "in_progress",
  "blocked",
  "done",
  "cancelled",
] as const satisfies readonly DfirTaskStatus[];
const taskPriorities = [
  "low",
  "medium",
  "high",
  "urgent",
] as const satisfies readonly DfirTaskPriority[];
const custodyActions = [
  "accessed",
  "transferred",
  "sealed",
  "unsealed",
  "scan_state_changed",
  "retention_changed",
  "legal_hold_placed",
  "legal_hold_released",
  "destroyed",
] as const satisfies readonly DfirCustodyAction[];
const selectableScanStates = [
  "quarantined",
  "scanning",
  "available",
  "rejected",
  "scan_failed",
  "retained",
  "deleted",
] as const satisfies readonly DfirScanState[];
const uuidInputPattern =
  "[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}";
const uuidInputRegex = new RegExp(`^${uuidInputPattern}$`, "u");

type CaseTaskAction =
  | { body: DfirTaskDetailsRequest; kind: "details" }
  | { body: DfirTaskAssignmentRequest; kind: "assignment" }
  | { body: DfirTaskDueDateRequest; kind: "due-date" }
  | { body: DfirTaskChecklistRequest; kind: "checklist" }
  | { body: DfirTaskCommentsRequest; kind: "comments" }
  | { body: DfirTaskTransitionRequest; kind: "transition" };

interface DialogIdentifiers {
  attachment: string;
  checklist: readonly string[];
  custody: string;
  resource: string;
  storage: string;
}

type WorkspaceDialog =
  | {
      ids: DialogIdentifiers;
      intentId: string;
      intentInstant: string;
      mode: "create";
      panel: DfirPanel;
    }
  | {
      ids: DialogIdentifiers;
      intentId: string;
      intentInstant: string;
      mode: "open";
      panel: DfirPanel;
      resourceId: string;
    };

export interface CaseDfirPanelProps {
  api: CaseDfirApi;
  caseId: string;
  csrfToken: string;
  hasPermission: PermissionCheck;
  tenantId: string;
}

function useCaseDfirPanelState({
  api,
  caseId,
  csrfToken,
  hasPermission,
  tenantId,
}: CaseDfirPanelProps) {
  const queryClient = useQueryClient();
  const canReadWorkspace = dfirReadPermissions.every(hasPermission);
  const [dialog, setDialog] = useState<WorkspaceDialog | null>(null);
  const [busy, setBusy] = useState(false);
  const [problem, setProblem] = useState<number | undefined>();
  const [downloadReceipt, setDownloadReceipt] = useState<{
    revision: number;
    value: DfirPreparedDownload;
  }>();
  const idempotencyRefs = useRef(new Map<string, IdempotencyReference>());
  const uploadedIntents = useRef(new Set<string>());
  const activeRequest = useRef<AbortController | null>(null);
  const activeRequestPermission = useRef<Permission | null>(null);
  const query = useQuery({
    enabled: canReadWorkspace,
    queryKey: ["case-dfir", tenantId, caseId],
    queryFn: ({ signal }) => api.getWorkspace({ caseId, signal, tenantId }),
    retry: (count, error) =>
      !(
        error instanceof CaseDfirApiError &&
        [401, 403, 404].includes(error.status ?? 0)
      ) && count < 1,
  });
  const download =
    downloadReceipt?.revision === query.dataUpdatedAt
      ? downloadReceipt.value
      : undefined;
  const setDownload = useCallback(
    (value: DfirPreparedDownload | undefined): void => {
      setDownloadReceipt(
        value === undefined
          ? undefined
          : { revision: query.dataUpdatedAt, value },
      );
    },
    [query.dataUpdatedAt],
  );
  const canCreatePanel = useCallback(
    (panel: DfirPanel): boolean =>
      hasPermission(managePermission[panel]) &&
      (panel !== "evidence" || hasPermission(managePermission.attachments)),
    [hasPermission],
  );
  useEffect(
    () => () => {
      activeRequest.current?.abort();
      idempotencyRefs.current.clear();
      uploadedIntents.current.clear();
    },
    [],
  );

  useEffect(() => {
    if (!download) return undefined;
    const remaining = Date.parse(download.expiresAt) - Date.now();
    if (!Number.isFinite(remaining) || remaining <= 0) {
      setDownload(undefined);
      return undefined;
    }
    const timer = globalThis.setTimeout(
      () => setDownload(undefined),
      Math.min(remaining, 2_147_483_647),
    );
    return () => globalThis.clearTimeout(timer);
  }, [download, setDownload]);
  // Commit revocation before paint while aborting the request and purging its cache.
  useLayoutEffect(() => {
    const permission = activeRequestPermission.current;
    if (canReadWorkspace && (!permission || hasPermission(permission))) return;
    activeRequest.current?.abort();
    activeRequest.current = null;
    activeRequestPermission.current = null;
    setBusy(false);
    if (!canReadWorkspace) {
      closeDialog(setDialog, setDownload);
    }
  }, [
    caseId,
    canReadWorkspace,
    hasPermission,
    queryClient,
    tenantId,
    setDownload,
  ]);
  // Query observers subscribe in passive effects; purge after their subscription update.
  useEffect(() => {
    if (canReadWorkspace) return;
    const filters = {
      exact: true,
      queryKey: ["case-dfir", tenantId, caseId],
    } as const;
    void queryClient.cancelQueries(filters);
    queryClient.removeQueries(filters);
  }, [canReadWorkspace, queryClient, tenantId, caseId]);
  useLayoutEffect(() => {
    if (dialog?.mode === "create" && !canCreatePanel(dialog.panel)) {
      activeRequest.current?.abort();
      activeRequest.current = null;
      activeRequestPermission.current = null;
      setBusy(false);
      closeDialog(setDialog, setDownload);
    }
  }, [dialog, canCreatePanel, setDownload]);
  return {
    api,
    caseId,
    csrfToken,
    hasPermission,
    tenantId,
    queryClient,
    canReadWorkspace,
    dialog,
    setDialog,
    busy,
    setBusy,
    problem,
    setProblem,
    download,
    setDownload,
    idempotencyRefs,
    uploadedIntents,
    activeRequest,
    activeRequestPermission,
    query,
    canCreatePanel,
  };
}

export function CaseDfirPanelScope(
  props: CaseDfirPanelProps,
): React.JSX.Element {
  const state = useCaseDfirPanelState(props);
  const {
    api,
    caseId,
    csrfToken,
    hasPermission,
    tenantId,
    canReadWorkspace,
    dialog,
    setDialog,
    busy,
    problem,
    setProblem,
    download,
    setDownload,
    idempotencyRefs,
    query,
    canCreatePanel,
  } = state;
  if (!canReadWorkspace) {
    return (
      <DfirTabFrame>
        <div className="dfir-panel-state">
          <ShieldAlert aria-hidden="true" />
          <h2>Case investigation access is unavailable</h2>
          <p>
            The complete workspace needs every live DFIR read permission. No
            investigation request was sent.
          </p>
        </div>
      </DfirTabFrame>
    );
  }
  if (query.isPending) {
    return (
      <DfirTabFrame>
        <div
          className="dfir-panel-skeleton"
          aria-label="Loading Case investigation"
        >
          <span />
          <span />
          <span />
        </div>
      </DfirTabFrame>
    );
  }
  if (query.isError || !query.data) {
    const status = apiErrorStatus(query.error);
    return (
      <DfirTabFrame>
        <div className="dfir-panel-state">
          <ShieldAlert aria-hidden="true" />
          <h2>Case investigation unavailable</h2>
          <p>{safeDfirProblem({ status })}</p>
          <Button variant="outline" onClick={() => void query.refetch()}>
            <RefreshCw aria-hidden="true" /> Retry investigation
          </Button>
        </div>
      </DfirTabFrame>
    );
  }
  const snapshot = query.data;
  const {
    dismissDialog,
    runMutation,
    submitResource,
    submitTaskAction,
    submitRetraction,
    prepareDownload,
  } = createCaseDfirActions({ ...state, snapshot });

  return (
    <DfirTabFrame>
      <SharedResourceLinks
        key={`${tenantId}:case:${caseId}`}
        assets={snapshot.workspace.assets}
        indicators={snapshot.workspace.indicators}
        busy={busy || query.isFetching}
        canManageAssets={hasPermission(managePermission.assets)}
        canManageIndicators={hasPermission(managePermission.iocs)}
        onSubmit={(intent) =>
          void runMutation(
            intent.resourceKind === "ioc"
              ? managePermission.iocs
              : managePermission.assets,
            (signal) =>
              api.changeLink({
                ...intent,
                caseId,
                tenantId,
                csrfToken,
                signal,
                idempotencyKey: intent.eventId,
              }),
          )
        }
      />
      <CaseDfirWorkspace
        busy={busy || query.isFetching}
        data={snapshot.data}
        hasPermission={(permission) =>
          permission === managePermission.evidence
            ? canCreatePanel("evidence")
            : hasPermission(permission)
        }
        {...(problem === undefined ? {} : { problem: { status: problem } })}
        onCreate={(panel) => {
          if (!canCreatePanel(panel)) return;
          setProblem(undefined);
          setDialog(newDialog("create", panel));
        }}
        onOpen={(panel, resourceId) => {
          setProblem(undefined);
          setDownload(undefined);
          setDialog(newDialog("open", panel, resourceId));
        }}
      />
      <Dialog
        open={dialog !== null}
        onOpenChange={(open) => !open && dismissDialog()}
      >
        {dialog ? (
          <DialogContent
            className="dfir-resource-dialog"
            showCloseButton={!busy}
          >
            <DialogHeader>
              <DialogTitle>{dialogTitle(dialog)}</DialogTitle>
              <DialogDescription>
                Every write is reauthorized by the server against this Case and
                active tenant.
              </DialogDescription>
            </DialogHeader>
            {problem === undefined ? null : (
              <Alert variant="destructive" role="alert">
                <AlertTitle>Investigation action not completed</AlertTitle>
                <AlertDescription>
                  {safeDfirProblem({ status: problem })}
                </AlertDescription>
              </Alert>
            )}
            <DialogBody
              busy={busy}
              dialog={dialog}
              {...(download ? { download } : {})}
              hasPermission={hasPermission}
              onCancel={dismissDialog}
              onDownload={() => void prepareDownload()}
              onRetract={(body) => void submitRetraction(body)}
              onSubmit={(draft) => void submitResource(draft)}
              onTaskAction={(action) => void submitTaskAction(action)}
              onCustody={(body) =>
                void runMutation(managePermission.evidence, (signal) =>
                  api.appendCustody({
                    ...mutationContext(
                      tenantId,
                      caseId,
                      csrfToken,
                      keyForIntent(
                        idempotencyRefs.current,
                        dialog,
                        "custody",
                        body,
                      ),
                      signal,
                    ),
                    body,
                    evidenceId: dialog.mode === "open" ? dialog.resourceId : "",
                  }),
                )
              }
              snapshot={snapshot}
            />
          </DialogContent>
        ) : null}
      </Dialog>
    </DfirTabFrame>
  );
}

function DialogBody({
  busy,
  dialog,
  download,
  hasPermission,
  onCancel,
  onCustody,
  onDownload,
  onRetract,
  onSubmit,
  onTaskAction,
  snapshot,
}: DialogBodyProps): React.JSX.Element {
  if (dialog.mode === "create") {
    return (
      <DfirResourceForm
        busy={busy}
        subjectKind="case"
        {...(dialog.panel === "relationships"
          ? { initialValues: { sourceId: snapshot.workspace.caseId } }
          : {})}
        panel={dialog.panel}
        onCancel={onCancel}
        onSubmit={onSubmit}
      />
    );
  }

  if (dialog.panel === "iocs") {
    return (
      <IocsDialog
        busy={busy}
        dialog={dialog}
        hasPermission={hasPermission}
        onCancel={onCancel}
        onSubmit={onSubmit}
        snapshot={snapshot}
      />
    );
  }

  if (dialog.panel === "assets") {
    return (
      <AssetsDialog
        busy={busy}
        dialog={dialog}
        hasPermission={hasPermission}
        onCancel={onCancel}
        onSubmit={onSubmit}
        snapshot={snapshot}
      />
    );
  }

  if (dialog.panel === "tasks") {
    return (
      <TasksDialog
        busy={busy}
        dialog={dialog}
        hasPermission={hasPermission}
        onCancel={onCancel}
        onSubmit={onSubmit}
        onTaskAction={onTaskAction}
        snapshot={snapshot}
      />
    );
  }

  if (dialog.panel === "evidence") {
    return (
      <EvidenceDialog
        busy={busy}
        dialog={dialog}
        hasPermission={hasPermission}
        onCancel={onCancel}
        onCustody={onCustody}
        onSubmit={onSubmit}
        snapshot={snapshot}
      />
    );
  }

  if (dialog.panel === "attachments") {
    return (
      <AttachmentsDialog
        busy={busy}
        dialog={dialog}
        download={download}
        hasPermission={hasPermission}
        onCancel={onCancel}
        onDownload={onDownload}
        snapshot={snapshot}
      />
    );
  }

  if (dialog.panel === "relationships") {
    return (
      <RelationshipsDialog
        busy={busy}
        dialog={dialog}
        hasPermission={hasPermission}
        onCancel={onCancel}
        onRetract={onRetract}
        onSubmit={onSubmit}
        snapshot={snapshot}
      />
    );
  }

  return (
    <div className="dfir-resource-dialog__readonly">
      <ResourceSummary
        panel={dialog.panel}
        resourceId={dialog.resourceId}
        snapshot={snapshot}
      />
      <Button type="button" variant="outline" onClick={onCancel}>
        Close
      </Button>
    </div>
  );
}

async function createResource(
  api: CaseDfirApi,
  dialog: Extract<WorkspaceDialog, { mode: "create" }>,
  draft: DfirMutationDraft,
  context: ReturnType<typeof mutationContext>,
  keyForStage: (stage: string, payload: unknown) => string,
  uploadCompleted: () => boolean,
  markUploadCompleted: () => void,
): Promise<void> {
  const now = dialog.intentInstant;
  switch (draft.panel) {
    case "iocs":
      await api.create({
        ...context,
        operation: {
          body: {
            indicatorId: dialog.ids.resource,
            indicator: indicatorSpecFromDraft(draft, now),
          },
          panel: "iocs",
        },
      });
      return;
    case "assets":
      await api.create({
        ...context,
        operation: {
          body: {
            asset: assetSpecFromDraft(draft, now),
            assetId: dialog.ids.resource,
          },
          panel: "assets",
        },
      });
      return;
    case "timeline":
      await api.create({
        ...context,
        operation: {
          body: {
            event: timelineSpecFromDraft(draft, "case"),
            timelineEventId: dialog.ids.resource,
          },
          panel: "timeline",
        },
      });
      return;
    case "tasks":
      await api.create({
        ...context,
        operation: {
          body: {
            task: taskSpecFromDraft(draft, dialog.ids.checklist),
            taskId: dialog.ids.resource,
          },
          panel: "tasks",
        },
      });
      return;
    case "relationships": {
      const source = relationshipReferenceFromDraft(draft, "source");
      const target = relationshipReferenceFromDraft(draft, "target");
      await api.create({
        ...context,
        operation: {
          body: {
            relationshipId: dialog.ids.resource,
            relationshipType: draft.relationshipType,
            source,
            target,
            ...(draft.metadata === undefined
              ? {}
              : { metadata: draft.metadata }),
          },
          panel: "relationships",
        },
      });
      return;
    }
    case "attachments": {
      if (uploadCompleted()) return;
      const body = buildAttachmentUploadRequest(
        {
          attachmentId: dialog.ids.attachment,
          classification: draft.classification,
          requestedVisibility: draft.visibility,
          storageObjectId: dialog.ids.storage,
          subject: { id: context.caseId, kind: "case" },
        },
        draft.file,
      );
      const prepared = await api.prepareUpload({
        ...context,
        body,
        idempotencyKey: keyForStage("prepare-upload", body),
      });
      await api.upload({ file: draft.file, prepared, signal: context.signal });
      markUploadCompleted();
      return;
    }
    case "evidence": {
      const uploadBody = buildAttachmentUploadRequest(
        {
          attachmentId: dialog.ids.attachment,
          classification: draft.classification,
          requestedVisibility: "private",
          storageObjectId: dialog.ids.storage,
          subject: { id: context.caseId, kind: "case" },
        },
        draft.file,
      );
      const existing = await existingEvidenceAttachment(
        api,
        context,
        dialog,
        draft.file,
      );
      if (!uploadCompleted() && needsUpload(existing)) {
        const prepared = await api.prepareUpload({
          ...context,
          body: uploadBody,
          idempotencyKey: keyForStage("prepare-evidence-upload", uploadBody),
        });
        await api.upload({
          file: draft.file,
          prepared,
          signal: context.signal,
        });
        markUploadCompleted();
      }
      await waitForEvidenceAttachment(api, context, dialog, draft.file);
      const body = {
        classification: draft.classification,
        collectedAt: formInstant(draft.collectedAt),
        description: draft.description ?? "",
        evidenceId: dialog.ids.resource,
        evidenceType: draft.evidenceType,
        initialCustodyEventId: dialog.ids.custody,
        legalHold: draft.legalHold,
        ...(draft.retentionUntil
          ? { retentionUntil: formInstant(draft.retentionUntil) }
          : {}),
        source: draft.source,
        storageObjectId: dialog.ids.storage,
        title: draft.title,
      };
      await api.create({
        ...context,
        idempotencyKey: keyForStage("collect-evidence", body),
        operation: { body, panel: "evidence" },
      });
      return;
    }
  }
}

async function existingEvidenceAttachment(
  api: CaseDfirApi,
  context: ReturnType<typeof mutationContext>,
  dialog: Extract<WorkspaceDialog, { mode: "create" }>,
  file: File,
): Promise<DfirAttachment | undefined> {
  const snapshot = await api.getWorkspace({
    caseId: context.caseId,
    signal: context.signal,
    tenantId: context.tenantId,
  });
  const attachment = snapshot.workspace.attachments.find(
    (item) => item.id === dialog.ids.attachment,
  );
  if (attachment) validateEvidenceAttachment(attachment, context, dialog, file);
  return attachment;
}

function needsUpload(attachment: DfirAttachment | undefined): boolean {
  if (!attachment || attachment.scanState === "pending_upload") return true;
  if (
    attachment.scanState === "uploaded" ||
    attachment.scanState === "verifying" ||
    attachment.scanState === "scanning" ||
    attachment.scanState === "available"
  ) {
    return false;
  }
  throw evidenceRejectedError();
}

async function waitForEvidenceAttachment(
  api: CaseDfirApi,
  context: ReturnType<typeof mutationContext>,
  dialog: Extract<WorkspaceDialog, { mode: "create" }>,
  file: File,
  attempt = 0,
): Promise<void> {
  const attachment = await existingEvidenceAttachment(
    api,
    context,
    dialog,
    file,
  );
  if (attachment?.scanState === "available") return;
  if (attachment) needsUpload(attachment);
  if (attempt >= 9) throw evidencePendingError();
  await abortableDelay(1_000, context.signal);
  await waitForEvidenceAttachment(api, context, dialog, file, attempt + 1);
}

function validateEvidenceAttachment(
  attachment: DfirAttachment,
  context: ReturnType<typeof mutationContext>,
  dialog: Extract<WorkspaceDialog, { mode: "create" }>,
  file: File,
): void {
  if (
    attachment.storageObjectId !== dialog.ids.storage ||
    attachment.originalFilename !== file.name ||
    attachment.subject.kind !== "case" ||
    attachment.subject.id !== context.caseId
  ) {
    throw new CaseDfirApiError(
      "The evidence upload no longer matches this Case.",
      409,
    );
  }
}

function evidenceRejectedError(): CaseDfirApiError {
  return new CaseDfirApiError(
    "The evidence upload did not pass protected object verification.",
    422,
  );
}

function evidencePendingError(): CaseDfirApiError {
  return new CaseDfirApiError(
    "The evidence upload is still awaiting protected object verification.",
    503,
  );
}

function abortableDelay(
  milliseconds: number,
  signal: AbortSignal,
): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal.aborted) {
      reject(new DOMException("Aborted", "AbortError"));
      return;
    }
    const timer = globalThis.setTimeout(() => {
      signal.removeEventListener("abort", onAbort);
      resolve();
    }, milliseconds);
    const onAbort = (): void => {
      globalThis.clearTimeout(timer);
      reject(new DOMException("Aborted", "AbortError"));
    };
    signal.addEventListener("abort", onAbort, { once: true });
  });
}

async function replaceResource(
  api: CaseDfirApi,
  snapshot: CaseDfirWorkspaceSnapshot,
  dialog: Extract<WorkspaceDialog, { mode: "open" }>,
  draft: DfirMutationDraft,
  context: ReturnType<typeof mutationContext>,
): Promise<void> {
  if (dialog.panel === "iocs" && draft.panel === "iocs") {
    const current = snapshot.workspace.indicators.find(
      (item) => item.id === dialog.resourceId,
    );
    if (!current)
      throw new CaseDfirApiError("The indicator is no longer available.", 404);
    await api.replace({
      ...context,
      operation: {
        body: {
          expectedVersion: current.version,
          indicator: indicatorSpecFromDraft(draft, dialog.intentInstant),
        },
        panel: "iocs",
        resourceId: current.id,
      },
    });
    return;
  }
  if (dialog.panel === "assets" && draft.panel === "assets") {
    const current = snapshot.workspace.assets.find(
      (item) => item.id === dialog.resourceId,
    );
    if (!current)
      throw new CaseDfirApiError("The asset is no longer available.", 404);
    await api.replace({
      ...context,
      operation: {
        body: {
          asset: assetSpecFromDraft(draft, dialog.intentInstant),
          expectedVersion: current.version,
        },
        panel: "assets",
        resourceId: current.id,
      },
    });
    return;
  }
  throw new CaseDfirApiError("This DFIR resource is append-only.");
}

function replacementVersion(
  snapshot: CaseDfirWorkspaceSnapshot,
  dialog: Extract<WorkspaceDialog, { mode: "open" }>,
): number | undefined {
  if (dialog.panel === "iocs") {
    return snapshot.workspace.indicators.find(
      (item) => item.id === dialog.resourceId,
    )?.version;
  }
  if (dialog.panel === "assets") {
    return snapshot.workspace.assets.find(
      (item) => item.id === dialog.resourceId,
    )?.version;
  }
  return undefined;
}

type TaskActionKind =
  | "details"
  | "assignment"
  | "due-date"
  | "checklist"
  | "comments"
  | "transition";

function CaseTaskActionForm({
  busy,
  checklistIds,
  onCancel,
  onSubmit,
  task,
}: {
  busy: boolean;
  checklistIds: readonly string[];
  onCancel: () => void;
  onSubmit: (action: CaseTaskAction) => void;
  task: CaseDfirWorkspaceSnapshot["workspace"]["tasks"][number];
}): React.JSX.Element {
  const [kind, setKind] = useState<TaskActionKind>("transition");
  const [target, setTarget] = useState<DfirTaskStatus>(() =>
    nextTaskStatus(task.status),
  );
  const [formError, setFormError] = useState<string>();
  return (
    <form
      className="dfir-compact-form"
      onSubmit={(event) => {
        event.preventDefault();
        const data = new FormData(event.currentTarget);
        try {
          if (kind === "details") {
            const title = requireTaskFormText(
              data,
              "title",
              512,
              "A bounded task title is required.",
            );
            const description = boundedTaskFormText(
              data,
              "description",
              16_384,
              "Task instructions must be at most 16384 characters.",
            );
            const priorityEntry = data.get("priority");
            if (!isTaskPriority(priorityEntry)) {
              throw new Error("Select a supported task priority.");
            }
            const slaInstanceId = optionalFormText(data, "slaInstanceId");
            if (slaInstanceId && !uuidInputRegex.test(slaInstanceId)) {
              throw new Error("Use a canonical UUID for the task SLA link.");
            }
            setFormError(undefined);
            onSubmit({
              body: {
                description,
                expectedVersion: task.version,
                priority: priorityEntry,
                ...(slaInstanceId ? { slaInstanceId } : {}),
                title,
              },
              kind,
            });
            return;
          }
          if (kind === "assignment") {
            const operatorTeamId = optionalFormText(data, "operatorTeamId");
            const assigneeId = optionalFormText(data, "assigneeId");
            if (assigneeId && !operatorTeamId) {
              throw new Error("Select an operator team before an assignee.");
            }
            if (
              (operatorTeamId && !uuidInputRegex.test(operatorTeamId)) ||
              (assigneeId && !uuidInputRegex.test(assigneeId))
            ) {
              throw new Error("Use canonical UUIDs for task assignment.");
            }
            setFormError(undefined);
            onSubmit({
              body: {
                expectedVersion: task.version,
                ...(operatorTeamId ? { operatorTeamId } : {}),
                ...(assigneeId ? { assigneeId } : {}),
              },
              kind,
            });
            return;
          }
          if (kind === "due-date") {
            const dueAt = optionalFormText(data, "dueAt");
            setFormError(undefined);
            onSubmit({
              body: {
                expectedVersion: task.version,
                ...(dueAt ? { dueAt: formInstant(dueAt) } : {}),
              },
              kind,
            });
            return;
          }
          if (kind === "checklist") {
            const checklistEntry = data.get("checklist");
            if (typeof checklistEntry !== "string") return;
            setFormError(undefined);
            onSubmit({
              body: {
                checklist: parseTaskChecklistIntent(
                  checklistEntry,
                  task.checklist,
                  checklistIds,
                  "Case",
                ),
                expectedVersion: task.version,
              },
              kind,
            });
            return;
          }
          if (kind === "comments") {
            const commentsEntry = data.get("comments");
            if (typeof commentsEntry !== "string") return;
            setFormError(undefined);
            onSubmit({
              body: {
                commentIds: parseTaskCommentIntent(commentsEntry, "Case"),
                expectedVersion: task.version,
              },
              kind,
            });
            return;
          }
          const reason = requireTaskFormText(
            data,
            "reason",
            2_000,
            "A bounded reason is required for this Case task action.",
          );
          const completionEntry = data.get("completionData");
          const completionData =
            terminalTaskStatus(target) && typeof completionEntry === "string"
              ? parseOptionalDocumentText(completionEntry)
              : undefined;
          setFormError(undefined);
          onSubmit({
            body: {
              ...(completionData === undefined ? {} : { completionData }),
              expectedVersion: task.version,
              reason,
              target,
            },
            kind,
          });
        } catch (error) {
          setFormError(
            error instanceof Error
              ? error.message
              : "Review this task action before retrying.",
          );
        }
      }}
    >
      <CaseTaskActionFields
        busy={busy}
        formError={formError}
        kind={kind}
        onCancel={onCancel}
        setFormError={setFormError}
        setKind={setKind}
        setTarget={setTarget}
        target={target}
        task={task}
      />
    </form>
  );
}

function CustodyForm({
  busy,
  eventId,
  evidence,
  onCancel,
  onSubmit,
}: {
  busy: boolean;
  eventId: string;
  evidence: CaseDfirWorkspaceSnapshot["workspace"]["evidence"][number];
  onCancel: () => void;
  onSubmit: (body: {
    action: DfirCustodyAction;
    custodyEventId: string;
    expectedVersion: number;
    legalHold?: boolean;
    nextScanState?: DfirScanState;
    reason: string;
    retentionUntil?: string | null;
  }) => void;
}): React.JSX.Element {
  const [action, setAction] = useState<DfirCustodyAction>("accessed");
  if (evidence.version >= maximumDfirCustodyEvents) {
    return (
      <p role="status">
        This evidence has reached the custody limit of{" "}
        {maximumDfirCustodyEvents} events. No further events can be appended.
      </p>
    );
  }
  return (
    <form
      className="dfir-compact-form"
      onSubmit={(event) => {
        event.preventDefault();
        const data = new FormData(event.currentTarget);
        const reasonEntry = data.get("reason");
        if (typeof reasonEntry !== "string") return;
        const reason = reasonEntry.trim();
        const common = {
          action,
          custodyEventId: eventId,
          expectedVersion: evidence.version,
          reason,
        };
        if (action === "scan_state_changed") {
          const next = data.get("nextScanState");
          if (isScanState(next)) onSubmit({ ...common, nextScanState: next });
          return;
        }
        if (
          action === "legal_hold_placed" ||
          action === "legal_hold_released"
        ) {
          onSubmit({ ...common, legalHold: action === "legal_hold_placed" });
          return;
        }
        if (action === "retention_changed") {
          const retentionEntry = data.get("retentionUntil");
          if (typeof retentionEntry !== "string") return;
          const value = retentionEntry;
          onSubmit({
            ...common,
            retentionUntil: value ? formInstant(value) : null,
          });
          return;
        }
        onSubmit(common);
      }}
    >
      <fieldset disabled={busy}>
        <legend>Append custody event</legend>
        <div>
          <Label htmlFor="dfir-custody-action">Action</Label>
          <select
            id="dfir-custody-action"
            name="action"
            value={action}
            onChange={(event) => {
              if (isCustodyAction(event.target.value))
                setAction(event.target.value);
            }}
          >
            {custodyActions.map((value) => (
              <option value={value} key={value}>
                {value.replaceAll("_", " ")}
              </option>
            ))}
          </select>
        </div>
        {action === "scan_state_changed" ? (
          <div>
            <Label htmlFor="dfir-custody-scan">Scan state</Label>
            <select
              id="dfir-custody-scan"
              name="nextScanState"
              defaultValue="available"
            >
              {selectableScanStates.map((value) => (
                <option value={value} key={value}>
                  {value.replaceAll("_", " ")}
                </option>
              ))}
            </select>
          </div>
        ) : null}
        {action === "retention_changed" ? (
          <div>
            <Label htmlFor="dfir-custody-retention">
              Retention until (empty clears)
            </Label>
            <Input
              id="dfir-custody-retention"
              name="retentionUntil"
              type="datetime-local"
            />
          </div>
        ) : null}
        <div>
          <Label htmlFor="dfir-custody-reason">Reason</Label>
          <Input
            id="dfir-custody-reason"
            name="reason"
            required
            maxLength={2_000}
          />
        </div>
        <FormActions
          busy={busy}
          onCancel={onCancel}
          label="Append custody event"
        />
      </fieldset>
    </form>
  );
}

function RelationshipRetractionForm({
  busy,
  expectedVersion,
  onCancel,
  onSubmit,
  retractionId,
}: {
  busy: boolean;
  expectedVersion: number;
  onCancel: () => void;
  onSubmit: (body: DfirRelationshipRetractRequest) => void;
  retractionId: string;
}): React.JSX.Element {
  const [formError, setFormError] = useState<string>();
  return (
    <form
      className="dfir-compact-form"
      onSubmit={(event) => {
        event.preventDefault();
        try {
          const reason = requireTaskFormText(
            new FormData(event.currentTarget),
            "reason",
            2_000,
            "A bounded relationship retraction reason is required.",
          );
          setFormError(undefined);
          onSubmit({ expectedVersion, reason, retractionId });
        } catch (error) {
          setFormError(
            error instanceof Error
              ? error.message
              : "Review the relationship retraction before retrying.",
          );
        }
      }}
    >
      <fieldset disabled={busy}>
        <legend>Retract relationship</legend>
        <div>
          <Label htmlFor="case-dfir-relationship-reason">Reason</Label>
          <Input
            id="case-dfir-relationship-reason"
            name="reason"
            required
            maxLength={2_000}
          />
        </div>
        {formError ? <p role="alert">{formError}</p> : null}
        <FormActions
          busy={busy}
          label="Retract relationship"
          onCancel={onCancel}
        />
      </fieldset>
    </form>
  );
}

function FormActions({
  busy,
  label,
  onCancel,
}: {
  busy: boolean;
  label: string;
  onCancel: () => void;
}): React.JSX.Element {
  return (
    <div className="dfir-compact-form__actions">
      <Button type="button" variant="outline" onClick={onCancel}>
        Cancel
      </Button>
      <Button type="submit">{busy ? "Saving…" : label}</Button>
    </div>
  );
}

function ResourceSummary({
  panel,
  resourceId,
  snapshot,
}: {
  panel: DfirPanel;
  resourceId: string;
  snapshot: CaseDfirWorkspaceSnapshot;
}): React.JSX.Element {
  if (panel === "timeline") {
    const item = snapshot.workspace.timeline.find(
      (value) => value.id === resourceId,
    );
    return (
      <ReadOnlyFacts>
        {item?.event.description ||
          item?.event.title ||
          "Timeline event unavailable."}
      </ReadOnlyFacts>
    );
  }
  if (panel === "relationships") {
    const item = snapshot.workspace.relationships.find(
      (value) => value.id === resourceId,
    );
    return (
      <ReadOnlyFacts>
        {item
          ? `${item.source.kind} ${item.relationshipType.replaceAll("_", " ")} ${item.target.kind}`
          : "Relationship unavailable."}
      </ReadOnlyFacts>
    );
  }
  return <MissingResource />;
}

function ReadOnlyFacts({
  children,
}: {
  children: ReactNode;
}): React.JSX.Element {
  return <p className="dfir-resource-dialog__facts">{children}</p>;
}

function MissingResource(): React.JSX.Element {
  return (
    <p role="status">
      This investigation resource is no longer in the current workspace.
    </p>
  );
}

function DfirTabFrame({
  children,
}: {
  children: ReactNode;
}): React.JSX.Element {
  return (
    <div
      id="ticket-panel-dfir"
      role="tabpanel"
      aria-labelledby="ticket-tab-dfir"
    >
      {children}
    </div>
  );
}

function newDialog(
  mode: WorkspaceDialog["mode"],
  panel: DfirPanel,
  resourceId?: string,
): WorkspaceDialog {
  const base = {
    ids: {
      attachment: generateUuidV7(),
      checklist:
        panel === "tasks"
          ? Array.from({ length: 100 }, () => generateUuidV7())
          : [],
      custody: generateUuidV7(),
      resource: generateUuidV7(),
      storage: generateUuidV7(),
    },
    intentId: generateUuidV7(),
    intentInstant: new Date().toISOString(),
    panel,
  };
  return mode === "create"
    ? { ...base, mode }
    : { ...base, mode, resourceId: resourceId ?? "" };
}

function dialogTitle(dialog: WorkspaceDialog): string {
  if (dialog.mode === "create")
    return `Add ${dialog.panel.replaceAll("_", " ")}`;
  return `Open ${dialog.panel.replaceAll("_", " ")}`;
}

function mutationContext(
  tenantId: string,
  caseId: string,
  csrfToken: string,
  idempotencyKey: string,
  signal: AbortSignal,
) {
  return { caseId, csrfToken, idempotencyKey, signal, tenantId };
}

function keyForIntent(
  references: Map<string, IdempotencyReference>,
  dialog: WorkspaceDialog,
  stage: string,
  payload: unknown,
): string {
  const key = `${dialog.intentId}:${stage}`;
  let reference = references.get(key);
  if (!reference) {
    reference = { current: null };
    references.set(key, reference);
  }
  return idempotencyKeyForPayload(reference, payload);
}

function clearIntentReferences(
  references: Map<string, IdempotencyReference>,
  intentId: string,
): void {
  for (const key of references.keys()) {
    if (key.startsWith(`${intentId}:`)) references.delete(key);
  }
}

function dismissAfterSuccess(
  references: Map<string, IdempotencyReference>,
  uploadedIntents: Set<string>,
  dialog: WorkspaceDialog | null,
  setDialog: (value: WorkspaceDialog | null) => void,
  setDownload: (value: DfirPreparedDownload | undefined) => void,
): void {
  if (dialog) {
    clearIntentReferences(references, dialog.intentId);
    uploadedIntents.delete(dialog.intentId);
  }
  closeDialog(setDialog, setDownload);
}

function closeDialog(
  setDialog: (value: WorkspaceDialog | null) => void,
  setDownload: (value: DfirPreparedDownload | undefined) => void,
): void {
  setDownload(undefined);
  setDialog(null);
}

function serializableDraft(draft: DfirMutationDraft): unknown {
  if (draft.panel !== "attachments" && draft.panel !== "evidence") {
    return draft;
  }
  const { file, ...withoutFile } = draft;
  return {
    ...withoutFile,
    file: { name: file.name, size: file.size, type: file.type },
  };
}

function formInstant(value: string): string {
  const instant = new Date(value);
  if (!Number.isFinite(instant.valueOf())) {
    throw new CaseDfirApiError("A valid investigation timestamp is required.");
  }
  return instant.toISOString();
}

function boundedTaskFormText(
  data: FormData,
  name: string,
  maximum: number,
  message: string,
): string {
  const entry = data.get(name);
  if (typeof entry !== "string") throw new Error(message);
  const value = entry.trim();
  if (value.length > maximum) throw new Error(message);
  return value;
}

function requireTaskFormText(
  data: FormData,
  name: string,
  maximum: number,
  message: string,
): string {
  const value = boundedTaskFormText(data, name, maximum, message);
  if (!value) throw new Error(message);
  return value;
}

function optionalFormText(data: FormData, name: string): string | undefined {
  const entry = data.get(name);
  if (typeof entry !== "string") return undefined;
  const value = entry.trim();
  return value || undefined;
}

function formatChecklistIntent(
  checklist: CaseDfirWorkspaceSnapshot["workspace"]["tasks"][number]["checklist"],
): string {
  return checklist
    .map((item) => `[${item.completed ? "x" : " "}] ${item.title}`)
    .join("\n");
}

function nextTaskStatus(current: DfirTaskStatus): DfirTaskStatus {
  return taskTransitionTargets(current)[0];
}

function taskTransitionTargets(
  current: DfirTaskStatus,
): readonly [DfirTaskStatus, ...DfirTaskStatus[]] {
  switch (current) {
    case "todo":
    case "blocked":
      return ["in_progress", "cancelled"];
    case "in_progress":
      return ["blocked", "done", "cancelled"];
    case "done":
    case "cancelled":
      return ["in_progress"];
    default:
      throw new TypeError("Unsupported task status.");
  }
}

function terminalTaskStatus(value: DfirTaskStatus): boolean {
  return value === "done" || value === "cancelled";
}

function isTaskStatus(
  value: FormDataEntryValue | null,
): value is DfirTaskStatus {
  return (
    typeof value === "string" && taskStatuses.some((item) => item === value)
  );
}

function isTaskPriority(
  value: FormDataEntryValue | null,
): value is DfirTaskPriority {
  return (
    typeof value === "string" &&
    taskPriorities.some((priority) => priority === value)
  );
}

function isTaskActionKind(value: string): value is TaskActionKind {
  return (
    value === "details" ||
    value === "assignment" ||
    value === "due-date" ||
    value === "checklist" ||
    value === "comments" ||
    value === "transition"
  );
}

function isScanState(value: FormDataEntryValue | null): value is DfirScanState {
  return (
    typeof value === "string" &&
    selectableScanStates.some((item) => item === value)
  );
}

function isCustodyAction(value: string): value is DfirCustodyAction {
  return custodyActions.some((item) => item === value);
}

function apiErrorStatus(error: unknown): number {
  return error instanceof CaseDfirApiError ? (error.status ?? 500) : 500;
}

function isAbortError(error: unknown): boolean {
  return error instanceof DOMException && error.name === "AbortError";
}

function createCaseDfirActions({
  api,
  caseId,
  csrfToken,
  hasPermission,
  tenantId,
  dialog,
  setDialog,
  busy,
  setBusy,
  setProblem,
  setDownload,
  idempotencyRefs,
  uploadedIntents,
  activeRequest,
  activeRequestPermission,
  query,
  canCreatePanel,
  snapshot,
}: ReturnType<typeof useCaseDfirPanelState> & {
  snapshot: CaseDfirWorkspaceSnapshot;
}) {
  const dismissDialog = (): void => {
    if (busy) return;
    if (dialog) {
      clearIntentReferences(idempotencyRefs.current, dialog.intentId);
      uploadedIntents.current.delete(dialog.intentId);
    }
    setProblem(undefined);
    closeDialog(setDialog, setDownload);
  };
  const runMutation = async (
    requiredPermission: DfirPermission,
    work: (signal: AbortSignal) => Promise<void>,
  ): Promise<void> => {
    if (!hasPermission(requiredPermission)) {
      setProblem(403);
      return;
    }
    const controller = new AbortController();
    activeRequest.current?.abort();
    activeRequest.current = controller;
    activeRequestPermission.current = requiredPermission;
    setBusy(true);
    setProblem(undefined);
    try {
      await work(controller.signal);
      if (controller.signal.aborted) return;
      const refreshed = await query.refetch();
      if (controller.signal.aborted || activeRequest.current !== controller)
        return;
      if (refreshed.isError) throw refreshed.error;
      dismissAfterSuccess(
        idempotencyRefs.current,
        uploadedIntents.current,
        dialog,
        setDialog,
        setDownload,
      );
    } catch (caught: unknown) {
      if (
        activeRequest.current === controller &&
        !controller.signal.aborted &&
        !isAbortError(caught)
      ) {
        setProblem(apiErrorStatus(caught));
      }
    } finally {
      if (activeRequest.current === controller) {
        activeRequest.current = null;
        activeRequestPermission.current = null;
        setBusy(false);
      }
    }
  };
  const submitResource = async (draft: DfirMutationDraft): Promise<void> => {
    if (!dialog) return;
    if (dialog.mode === "create" && !canCreatePanel(dialog.panel)) {
      setProblem(403);
      return;
    }
    const permission = managePermission[dialog.panel];
    await runMutation(permission, async (signal) => {
      if (dialog.mode === "open") {
        await replaceResource(
          api,
          snapshot,
          dialog,
          draft,
          mutationContext(
            tenantId,
            caseId,
            csrfToken,
            keyForIntent(idempotencyRefs.current, dialog, "replace", {
              draft,
              expectedVersion: replacementVersion(snapshot, dialog),
              resourceId: dialog.resourceId,
            }),
            signal,
          ),
        );
        return;
      }
      await createResource(
        api,
        dialog,
        draft,
        mutationContext(
          tenantId,
          caseId,
          csrfToken,
          keyForIntent(idempotencyRefs.current, dialog, "create", {
            draft: serializableDraft(draft),
            ids: dialog.ids,
            intentInstant: dialog.intentInstant,
          }),
          signal,
        ),
        (stage, payload) =>
          keyForIntent(idempotencyRefs.current, dialog, stage, payload),
        () => uploadedIntents.current.has(dialog.intentId),
        () => uploadedIntents.current.add(dialog.intentId),
      );
    });
  };
  const submitTaskAction = async (action: CaseTaskAction): Promise<void> => {
    if (!dialog || dialog.mode !== "open" || dialog.panel !== "tasks") return;
    const taskId = dialog.resourceId;
    await runMutation(managePermission.tasks, async (signal) => {
      const context = {
        body: action.body,
        caseId,
        csrfToken,
        idempotencyKey: keyForIntent(
          idempotencyRefs.current,
          dialog,
          `task-${action.kind}`,
          { body: action.body, taskId },
        ),
        signal,
        taskId,
        tenantId,
      };
      switch (action.kind) {
        case "details":
          await api.replaceTaskDetails({ ...context, body: action.body });
          return;
        case "assignment":
          await api.assignTask({ ...context, body: action.body });
          return;
        case "due-date":
          await api.rescheduleTask({ ...context, body: action.body });
          return;
        case "checklist":
          await api.replaceTaskChecklist({ ...context, body: action.body });
          return;
        case "comments":
          await api.replaceTaskComments({ ...context, body: action.body });
          return;
        case "transition":
          await api.transitionTask({ ...context, body: action.body });
      }
    });
  };
  const submitRetraction = async (
    body: DfirRelationshipRetractRequest,
  ): Promise<void> => {
    if (!dialog || dialog.mode !== "open" || dialog.panel !== "relationships") {
      return;
    }
    const relationshipId = dialog.resourceId;
    await runMutation(managePermission.relationships, (signal) =>
      api.retractRelationship({
        ...mutationContext(
          tenantId,
          caseId,
          csrfToken,
          keyForIntent(
            idempotencyRefs.current,
            dialog,
            "retract-relationship",
            { body, relationshipId },
          ),
          signal,
        ),
        body,
        relationshipId,
      }),
    );
  };
  const prepareDownload = async (): Promise<void> => {
    if (!dialog || dialog.mode !== "open" || dialog.panel !== "attachments")
      return;
    if (!hasPermission(readPermission.attachments)) {
      setProblem(403);
      return;
    }
    const attachment = snapshot.workspace.attachments.find(
      (item) => item.id === dialog.resourceId,
    );
    if (!attachment) {
      setProblem(404);
      return;
    }
    const controller = new AbortController();
    activeRequest.current?.abort();
    activeRequest.current = controller;
    activeRequestPermission.current = readPermission.attachments;
    setBusy(true);
    setProblem(undefined);
    setDownload(undefined);
    try {
      const prepared = await api.prepareDownload({
        attachmentId: attachment.id,
        body: { subject: attachment.subject },
        caseId,
        csrfToken,
        signal: controller.signal,
        tenantId,
      });
      if (activeRequest.current === controller && !controller.signal.aborted)
        setDownload(prepared);
    } catch (caught: unknown) {
      if (
        activeRequest.current === controller &&
        !controller.signal.aborted &&
        !isAbortError(caught)
      ) {
        setProblem(apiErrorStatus(caught));
      }
    } finally {
      if (activeRequest.current === controller) {
        activeRequest.current = null;
        activeRequestPermission.current = null;
        setBusy(false);
      }
    }
  };
  return {
    dismissDialog,
    runMutation,
    submitResource,
    submitTaskAction,
    submitRetraction,
    prepareDownload,
  };
}

interface DialogBodyProps {
  busy: ReturnType<typeof useCaseDfirPanelState>["busy"];
  dialog: WorkspaceDialog;
  download?: ReturnType<typeof useCaseDfirPanelState>["download"];
  hasPermission: ReturnType<typeof useCaseDfirPanelState>["hasPermission"];
  onCancel: () => void;
  onCustody: (body: {
    action: DfirCustodyAction;
    custodyEventId: string;
    expectedVersion: number;
    legalHold?: boolean;
    nextScanState?: DfirScanState;
    reason: string;
    retentionUntil?: string | null;
  }) => void;
  onDownload: () => void;
  onRetract: (body: DfirRelationshipRetractRequest) => void;
  onSubmit: (draft: DfirMutationDraft) => void;
  onTaskAction: (action: CaseTaskAction) => void;
  snapshot: CaseDfirWorkspaceSnapshot;
}
function IocsDialog({
  busy,
  dialog,
  hasPermission,
  onCancel,
  onSubmit,
  snapshot,
}: Pick<
  DialogBodyProps,
  "busy" | "hasPermission" | "onCancel" | "onSubmit" | "snapshot"
> & { dialog: Extract<WorkspaceDialog, { mode: "open" }> }) {
  const item = snapshot.workspace.indicators.find(
    (candidate) => candidate.id === dialog.resourceId,
  );
  if (!item) return <MissingResource />;
  if (!hasPermission(managePermission.iocs)) {
    return (
      <ReadOnlyFacts>
        {item.indicator.description || "No description recorded."}
      </ReadOnlyFacts>
    );
  }
  return (
    <DfirResourceForm
      busy={busy}
      subjectKind="case"
      initialValues={{
        confidence: item.indicator.confidence,
        description: item.indicator.description,
        enrichment: documentInputValue(item.indicator.enrichment),
        firstSeen: instantInputValue(item.indicator.firstSeen),
        lastSeen: instantInputValue(item.indicator.lastSeen),
        malicious: item.indicator.malicious,
        source: item.indicator.source,
        tags: item.indicator.tags.join(", "),
        tlp: item.indicator.tlp,
        type: item.indicator.type,
        value: item.indicator.value,
      }}
      mode="replace"
      panel="iocs"
      onCancel={onCancel}
      onSubmit={onSubmit}
    />
  );
}

function AssetsDialog({
  busy,
  dialog,
  hasPermission,
  onCancel,
  onSubmit,
  snapshot,
}: Pick<
  DialogBodyProps,
  "busy" | "hasPermission" | "onCancel" | "onSubmit" | "snapshot"
> & { dialog: Extract<WorkspaceDialog, { mode: "open" }> }) {
  const item = snapshot.workspace.assets.find(
    (candidate) => candidate.id === dialog.resourceId,
  );
  if (!item) return <MissingResource />;
  if (!hasPermission(managePermission.assets)) {
    return (
      <ReadOnlyFacts>
        {item.asset.operatingSystem || "No operating system recorded."}
      </ReadOnlyFacts>
    );
  }
  return (
    <DfirResourceForm
      busy={busy}
      subjectKind="case"
      initialValues={{
        addresses: [...item.asset.ipAddresses, ...item.asset.macAddresses].join(
          ", ",
        ),
        assetType: item.asset.assetType,
        businessUnit: item.asset.businessUnit,
        criticality: item.asset.criticality,
        customAttributes: documentInputValue(item.asset.customAttributes),
        environment: item.asset.environment,
        externalId: item.asset.externalId,
        firstSeen: instantInputValue(item.asset.firstSeen),
        fqdn: item.asset.fqdn,
        hostname: item.asset.hostname,
        lastSeen: instantInputValue(item.asset.lastSeen),
        operatingSystem: item.asset.operatingSystem,
        owner: item.asset.owner,
        tags: item.asset.tags.join(", "),
      }}
      mode="replace"
      panel="assets"
      onCancel={onCancel}
      onSubmit={onSubmit}
    />
  );
}

function TasksDialog({
  busy,
  dialog,
  hasPermission,
  onCancel,
  onTaskAction,
  snapshot,
}: Pick<
  DialogBodyProps,
  | "busy"
  | "hasPermission"
  | "onCancel"
  | "onSubmit"
  | "onTaskAction"
  | "snapshot"
> & { dialog: Extract<WorkspaceDialog, { mode: "open" }> }) {
  const task = snapshot.workspace.tasks.find(
    (candidate) => candidate.id === dialog.resourceId,
  );
  if (!task) return <MissingResource />;
  return (
    <>
      <ReadOnlyFacts>
        {task.description || "No task instructions recorded."}
      </ReadOnlyFacts>
      {hasPermission(managePermission.tasks) ? (
        <CaseTaskActionForm
          busy={busy}
          checklistIds={dialog.ids.checklist}
          onCancel={onCancel}
          onSubmit={onTaskAction}
          task={task}
        />
      ) : null}
    </>
  );
}

function EvidenceDialog({
  busy,
  dialog,
  hasPermission,
  onCancel,
  onCustody,
  snapshot,
}: Pick<
  DialogBodyProps,
  "busy" | "hasPermission" | "onCancel" | "onCustody" | "onSubmit" | "snapshot"
> & { dialog: Extract<WorkspaceDialog, { mode: "open" }> }) {
  const evidence = snapshot.workspace.evidence.find(
    (candidate) => candidate.id === dialog.resourceId,
  );
  if (!evidence) return <MissingResource />;
  return (
    <>
      <ReadOnlyFacts>
        {evidence.description || "No evidence description recorded."}
      </ReadOnlyFacts>
      {hasPermission(managePermission.evidence) ? (
        <CustodyForm
          busy={busy}
          eventId={dialog.ids.custody}
          evidence={evidence}
          onCancel={onCancel}
          onSubmit={onCustody}
        />
      ) : null}
    </>
  );
}

function AttachmentsDialog({
  busy,
  dialog,
  download,
  hasPermission,
  onCancel,
  onDownload,
  snapshot,
}: Pick<
  DialogBodyProps,
  "busy" | "download" | "hasPermission" | "onCancel" | "onDownload" | "snapshot"
> & { dialog: Extract<WorkspaceDialog, { mode: "open" }> }) {
  const attachment = snapshot.workspace.attachments.find(
    (candidate) => candidate.id === dialog.resourceId,
  );
  if (!attachment) return <MissingResource />;
  return (
    <div className="dfir-resource-dialog__download">
      <ReadOnlyFacts>
        {attachment.originalFilename} ·{" "}
        {attachment.scanState.replaceAll("_", " ")}
      </ReadOnlyFacts>
      {download ? (
        <a
          href={download.downloadUrl}
          rel="noreferrer"
          referrerPolicy="no-referrer"
          target="_blank"
        >
          Download authorized file
        </a>
      ) : (
        <Button
          type="button"
          disabled={busy || !hasPermission(readPermission.attachments)}
          onClick={onDownload}
        >
          {busy ? "Authorizing…" : "Prepare secure download"}
        </Button>
      )}
      <Button
        type="button"
        variant="outline"
        disabled={busy}
        onClick={onCancel}
      >
        Close
      </Button>
    </div>
  );
}

function RelationshipsDialog({
  busy,
  dialog,
  hasPermission,
  onCancel,
  onRetract,
  snapshot,
}: Pick<
  DialogBodyProps,
  "busy" | "hasPermission" | "onCancel" | "onRetract" | "onSubmit" | "snapshot"
> & { dialog: Extract<WorkspaceDialog, { mode: "open" }> }) {
  const relationship = snapshot.workspace.relationships.find(
    (candidate) => candidate.id === dialog.resourceId,
  );
  if (!relationship) return <MissingResource />;
  return (
    <>
      <ReadOnlyFacts>
        {`${relationship.source.kind} ${relationship.relationshipType.replaceAll("_", " ")} ${relationship.target.kind}`}
        {relationship.active ? "" : " · retracted"}
      </ReadOnlyFacts>
      {relationship.active && hasPermission(managePermission.relationships) ? (
        <RelationshipRetractionForm
          busy={busy}
          expectedVersion={relationship.version}
          onCancel={onCancel}
          onSubmit={onRetract}
          retractionId={dialog.ids.custody}
        />
      ) : (
        <Button type="button" variant="outline" onClick={onCancel}>
          Close
        </Button>
      )}
    </>
  );
}

interface CaseTaskActionFieldsProps {
  busy: ReturnType<typeof useCaseDfirPanelState>["busy"];
  formError: string | undefined;
  kind: TaskActionKind;
  onCancel: () => void;
  setFormError: React.Dispatch<React.SetStateAction<string | undefined>>;
  setKind: React.Dispatch<React.SetStateAction<TaskActionKind>>;
  setTarget: React.Dispatch<React.SetStateAction<DfirTaskStatus>>;
  target: DfirTaskStatus;
  task: DfirTask;
}

function CaseTaskActionFields({
  busy,
  formError,
  kind,
  onCancel,
  setFormError,
  setKind,
  setTarget,
  target,
  task,
}: CaseTaskActionFieldsProps): React.JSX.Element {
  return (
    <fieldset disabled={busy}>
      <legend>Update task</legend>
      <div>
        <Label htmlFor="case-dfir-task-action">Action</Label>
        <select
          id="case-dfir-task-action"
          value={kind}
          onChange={(event) => {
            const value = event.currentTarget.value;
            if (isTaskActionKind(value)) {
              setKind(value);
              setFormError(undefined);
            }
          }}
        >
          <option value="transition">Transition lifecycle</option>
          <option value="details">Replace details</option>
          <option value="assignment">Replace assignment</option>
          <option value="due-date">Replace due date</option>
          <option value="checklist">Replace checklist</option>
          <option value="comments">Replace comment links</option>
        </select>
      </div>
      {kind === "details" ? (
        <>
          <div>
            <Label htmlFor="case-dfir-task-title">Task title</Label>
            <Input
              id="case-dfir-task-title"
              name="title"
              defaultValue={task.title}
              maxLength={512}
              required
            />
          </div>
          <div>
            <Label htmlFor="case-dfir-task-description">Instructions</Label>
            <Textarea
              id="case-dfir-task-description"
              name="description"
              defaultValue={task.description}
              maxLength={16_384}
            />
          </div>
          <div>
            <Label htmlFor="case-dfir-task-priority">Priority</Label>
            <select
              id="case-dfir-task-priority"
              name="priority"
              defaultValue={task.priority}
            >
              {taskPriorities.map((priority) => (
                <option value={priority} key={priority}>
                  {priority}
                </option>
              ))}
            </select>
          </div>
          <div>
            <Label htmlFor="case-dfir-task-sla">
              SLA instance UUID (empty clears)
            </Label>
            <Input
              id="case-dfir-task-sla"
              name="slaInstanceId"
              defaultValue={task.slaInstanceId ?? ""}
              maxLength={36}
              pattern={uuidInputPattern}
            />
          </div>
        </>
      ) : null}
      {kind === "assignment" ? (
        <>
          <div>
            <Label htmlFor="case-dfir-task-team">
              Operator team UUID (empty clears)
            </Label>
            <Input
              id="case-dfir-task-team"
              name="operatorTeamId"
              defaultValue={task.operatorTeamId ?? ""}
              maxLength={36}
              pattern={uuidInputPattern}
            />
          </div>
          <div>
            <Label htmlFor="case-dfir-task-assignee">
              Assignee UUID (optional)
            </Label>
            <Input
              id="case-dfir-task-assignee"
              name="assigneeId"
              defaultValue={task.assigneeId ?? ""}
              maxLength={36}
              pattern={uuidInputPattern}
            />
          </div>
        </>
      ) : null}
      {kind === "due-date" ? (
        <div>
          <Label htmlFor="case-dfir-task-due">Due date (empty clears)</Label>
          <Input
            id="case-dfir-task-due"
            name="dueAt"
            type="datetime-local"
            defaultValue={
              task.dueAt === undefined ? "" : instantInputValue(task.dueAt)
            }
          />
        </div>
      ) : null}
      {kind === "checklist" ? (
        <div>
          <Label htmlFor="case-dfir-task-checklist">
            Checklist, one [ ] or [x] item per line
          </Label>
          <Textarea
            id="case-dfir-task-checklist"
            name="checklist"
            defaultValue={formatChecklistIntent(task.checklist)}
            maxLength={51_500}
            rows={8}
          />
        </div>
      ) : null}
      {kind === "comments" ? (
        <div>
          <Label htmlFor="case-dfir-task-comments">
            Comment UUIDv7s, one per line (empty clears)
          </Label>
          <Textarea
            id="case-dfir-task-comments"
            name="comments"
            defaultValue={task.commentIds.join("\n")}
            maxLength={36_999}
            rows={8}
          />
        </div>
      ) : null}
      {kind === "transition" ? (
        <>
          <div>
            <Label htmlFor="case-dfir-task-target">Target state</Label>
            <select
              id="case-dfir-task-target"
              name="target"
              value={target}
              onChange={(event) => {
                if (isTaskStatus(event.currentTarget.value)) {
                  setTarget(event.currentTarget.value);
                  setFormError(undefined);
                }
              }}
            >
              {taskTransitionTargets(task.status).map((status) => (
                <option value={status} key={status}>
                  {status.replaceAll("_", " ")}
                </option>
              ))}
            </select>
          </div>
          <div>
            <Label htmlFor="case-dfir-task-reason">Reason</Label>
            <Input
              id="case-dfir-task-reason"
              name="reason"
              required
              maxLength={2_000}
            />
          </div>
          {terminalTaskStatus(target) ? (
            <div>
              <Label htmlFor="case-dfir-task-completion">
                Completion data (JSON object)
              </Label>
              <Textarea
                id="case-dfir-task-completion"
                name="completionData"
                maxLength={65_536}
              />
            </div>
          ) : null}
        </>
      ) : null}
      {formError ? <p role="alert">{formError}</p> : null}
      <FormActions busy={busy} onCancel={onCancel} label="Apply task action" />
    </fieldset>
  );
}
