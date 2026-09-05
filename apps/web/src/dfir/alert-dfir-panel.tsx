import { useQuery, useQueryClient } from "@tanstack/react-query";
import type {
  DfirAlertCustodyAppendRequest,
  DfirAlertRelationshipRetractRequest,
  DfirAlertTaskAssignmentRequest,
  DfirAlertTaskChecklistRequest,
  DfirAlertTaskDueDateRequest,
  DfirAlertTaskTransitionRequest,
  DfirAttachment,
  DfirCustodyAction,
  DfirPreparedDownload,
  DfirScanState,
  DfirTaskCommentsRequest,
  DfirTaskDetailsRequest,
  DfirTaskPriority,
  DfirTaskStatus,
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
import { RefreshCw, ShieldAlert } from "lucide-react";
import { useEffect, useRef, useState, type ReactNode } from "react";

import {
  idempotencyKeyForPayload,
  type IdempotencyReference,
} from "../lib/payload-idempotency";
import { generateUuidV7 } from "../lib/uuid-v7";
import {
  AlertDfirApiError,
  type AlertDfirApi,
  type AlertDfirWorkspaceSnapshot,
} from "./alert-dfir-api";
import { AlertDfirWorkspace } from "./case-dfir-workspace";
import { maximumDfirCustodyEvents } from "./evidence-custody";
import {
  alertDfirReadPermissions,
  safeAlertDfirProblem,
  type DfirAlertPanel,
  type DfirPermission,
  type DfirReadPermission,
} from "./model";
import {
  DfirResourceForm,
  alertTaskSpecFromDraft,
  assetSpecFromDraft,
  documentInputValue,
  indicatorSpecFromDraft,
  instantInputValue,
  parseOptionalDocumentText,
  relationshipReferenceFromDraft,
  timelineSpecFromDraft,
  type DfirMutationDraft,
} from "./resource-form";
import { parseTaskChecklistIntent } from "./task-checklist-intent";
import { parseTaskCommentIntent } from "./task-comment-intent";
import { SharedResourceLinks } from "./shared-resource-links";
import { buildAttachmentUploadRequest } from "./upload-request";
// oxlint-disable-next-line import/no-unassigned-import -- Alert DFIR shares the established protected-dialog treatment.
import "./case-dfir-panel.css";

type Permission = DfirPermission | DfirReadPermission;
type PermissionCheck = (permission: Permission) => boolean;

type AlertTaskAction =
  | { body: DfirAlertTaskTransitionRequest; kind: "transition" }
  | { body: DfirTaskDetailsRequest; kind: "details" }
  | { body: DfirAlertTaskAssignmentRequest; kind: "assignment" }
  | { body: DfirAlertTaskDueDateRequest; kind: "due-date" }
  | { body: DfirAlertTaskChecklistRequest; kind: "checklist" }
  | { body: DfirTaskCommentsRequest; kind: "comments" };

const managePermission = {
  iocs: "dfir.ioc.manage",
  assets: "dfir.asset.manage",
  evidence: "dfir.evidence.manage",
  timeline: "dfir.timeline.manage",
  tasks: "dfir.task.manage",
  attachments: "dfir.attachment.manage",
  relationships: "dfir.relationship.manage",
} as const satisfies Record<DfirAlertPanel, DfirPermission>;

const taskPriorities = ["low", "medium", "high", "urgent"] as const;

const readPermission = {
  iocs: "dfir.ioc.read",
  assets: "dfir.asset.read",
  evidence: "dfir.evidence.read",
  timeline: "dfir.timeline.read",
  tasks: "dfir.task.read",
  attachments: "dfir.attachment.read",
  relationships: "dfir.relationship.read",
} as const satisfies Record<DfirAlertPanel, DfirReadPermission>;

const taskStatuses = [
  "todo",
  "in_progress",
  "blocked",
  "done",
  "cancelled",
] as const satisfies readonly DfirTaskStatus[];
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
      panel: DfirAlertPanel;
    }
  | {
      ids: DialogIdentifiers;
      intentId: string;
      intentInstant: string;
      mode: "open";
      panel: DfirAlertPanel;
      resourceId: string;
    };

interface AlertMutationContext {
  alertId: string;
  csrfToken: string;
  signal: AbortSignal;
  tenantId: string;
}

export interface AlertDfirPanelProps {
  alertId: string;
  api: AlertDfirApi;
  csrfToken: string;
  hasPermission: PermissionCheck;
  tenantId: string;
}

export function AlertDfirPanel({
  alertId,
  api,
  csrfToken,
  hasPermission,
  tenantId,
}: AlertDfirPanelProps): React.JSX.Element {
  const queryClient = useQueryClient();
  const canReadWorkspace = alertDfirReadPermissions.every(hasPermission);
  const [dialog, setDialog] = useState<WorkspaceDialog | null>(null);
  const [busy, setBusy] = useState(false);
  const [problem, setProblem] = useState<number | undefined>();
  const [download, setDownload] = useState<DfirPreparedDownload | undefined>();
  const idempotencyRefs = useRef(new Map<string, IdempotencyReference>());
  const uploadedIntents = useRef(new Set<string>());
  const activeRequest = useRef<AbortController | null>(null);
  const activeRequestPermission = useRef<Permission | null>(null);
  const query = useQuery({
    enabled: canReadWorkspace,
    queryKey: ["alert-dfir", tenantId, alertId],
    queryFn: ({ signal }) => api.getWorkspace({ alertId, signal, tenantId }),
    retry: (count, error) =>
      !(
        error instanceof AlertDfirApiError &&
        [401, 403, 404].includes(error.status ?? 0)
      ) && count < 1,
  });
  const canCreatePanel = (panel: DfirAlertPanel): boolean =>
    hasPermission(managePermission[panel]) &&
    (panel !== "evidence" || hasPermission(managePermission.attachments));

  useEffect(
    () => () => {
      activeRequest.current?.abort();
      const filters = {
        exact: true,
        queryKey: ["alert-dfir", tenantId, alertId],
      } as const;
      void queryClient.cancelQueries(filters);
      queryClient.removeQueries(filters);
      idempotencyRefs.current.clear();
      uploadedIntents.current.clear();
    },
    [alertId, queryClient, tenantId],
  );

  useEffect(() => {
    activeRequest.current?.abort();
    activeRequest.current = null;
    activeRequestPermission.current = null;
    idempotencyRefs.current.clear();
    uploadedIntents.current.clear();
    setBusy(false);
    setProblem(undefined);
    setDownload(undefined);
    setDialog(null);
  }, [alertId, tenantId]);

  useEffect(() => setDownload(undefined), [query.dataUpdatedAt]);

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
  }, [download]);

  useEffect(() => {
    const permission = activeRequestPermission.current;
    if (canReadWorkspace && (!permission || hasPermission(permission))) return;
    activeRequest.current?.abort();
    activeRequest.current = null;
    activeRequestPermission.current = null;
    setBusy(false);
    if (!canReadWorkspace) {
      const filters = {
        exact: true,
        queryKey: ["alert-dfir", tenantId, alertId],
      } as const;
      void queryClient.cancelQueries(filters);
      queryClient.removeQueries(filters);
      setDownload(undefined);
      setDialog(null);
    }
  }, [alertId, canReadWorkspace, hasPermission, queryClient, tenantId]);

  useEffect(() => {
    if (dialog?.mode === "create" && !canCreatePanel(dialog.panel)) {
      activeRequest.current?.abort();
      activeRequest.current = null;
      activeRequestPermission.current = null;
      setBusy(false);
      setDownload(undefined);
      setDialog(null);
    }
  }, [dialog, hasPermission]);

  if (!canReadWorkspace) {
    return (
      <DfirTabFrame>
        <div className="dfir-panel-state">
          <ShieldAlert aria-hidden="true" />
          <h2>Alert investigation access is unavailable</h2>
          <p>
            This bounded workspace needs every live Alert DFIR read permission.
            No investigation request was sent.
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
          aria-label="Loading Alert investigation"
        >
          <span />
          <span />
          <span />
        </div>
      </DfirTabFrame>
    );
  }

  if (query.isError || !query.data) {
    return (
      <DfirTabFrame>
        <div className="dfir-panel-state">
          <ShieldAlert aria-hidden="true" />
          <h2>Alert investigation unavailable</h2>
          <p>{safeAlertDfirProblem({ status: apiErrorStatus(query.error) })}</p>
          <Button variant="outline" onClick={() => void query.refetch()}>
            <RefreshCw aria-hidden="true" /> Retry investigation
          </Button>
        </div>
      </DfirTabFrame>
    );
  }

  const snapshot = query.data;

  const dismissDialog = (): void => {
    if (busy) return;
    if (dialog) {
      clearIntentReferences(idempotencyRefs.current, dialog.intentId);
      uploadedIntents.current.delete(dialog.intentId);
    }
    setProblem(undefined);
    setDownload(undefined);
    setDialog(null);
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
      if (dialog) {
        clearIntentReferences(idempotencyRefs.current, dialog.intentId);
        uploadedIntents.current.delete(dialog.intentId);
      }
      setDownload(undefined);
      setDialog(null);
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
    const requiredPermission = managePermission[dialog.panel];
    await runMutation(requiredPermission, async (signal) => {
      const context = {
        alertId,
        csrfToken,
        signal,
        tenantId,
      };
      if (dialog.mode === "open") {
        await replaceResource(api, snapshot, dialog, draft, {
          ...context,
          idempotencyKey: keyForIntent(
            idempotencyRefs.current,
            dialog,
            "replace",
            {
              draft,
              expectedVersion: replacementVersion(snapshot, dialog),
              resourceId: dialog.resourceId,
            },
          ),
        });
        return;
      }
      await createResource(
        api,
        dialog,
        draft,
        context,
        (stage, payload) =>
          keyForIntent(idempotencyRefs.current, dialog, stage, payload),
        () => uploadedIntents.current.has(dialog.intentId),
        () => uploadedIntents.current.add(dialog.intentId),
      );
    });
  };

  const submitCustody = async (
    body: DfirAlertCustodyAppendRequest,
  ): Promise<void> => {
    if (!dialog || dialog.mode !== "open" || dialog.panel !== "evidence")
      return;
    const evidenceId = dialog.resourceId;
    await runMutation(managePermission.evidence, (signal) =>
      api.appendCustody({
        alertId,
        body,
        csrfToken,
        evidenceId,
        idempotencyKey: keyForIntent(
          idempotencyRefs.current,
          dialog,
          "append-custody",
          { body, evidenceId },
        ),
        signal,
        tenantId,
      }),
    );
  };

  const submitTaskAction = async (action: AlertTaskAction): Promise<void> => {
    if (!dialog || dialog.mode !== "open" || dialog.panel !== "tasks") return;
    const taskId = dialog.resourceId;
    await runMutation(managePermission.tasks, async (signal) => {
      const context = {
        alertId,
        body: action.body,
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
        case "transition":
          await api.transitionTask({ ...context, body: action.body });
          return;
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
      }
    });
  };

  const submitRetraction = async (
    body: DfirAlertRelationshipRetractRequest,
  ): Promise<void> => {
    if (!dialog || dialog.mode !== "open" || dialog.panel !== "relationships") {
      return;
    }
    const relationshipId = dialog.resourceId;
    await runMutation(managePermission.relationships, (signal) =>
      api.retractRelationship({
        alertId,
        body,
        csrfToken,
        idempotencyKey: keyForIntent(
          idempotencyRefs.current,
          dialog,
          "retract-relationship",
          { body, relationshipId },
        ),
        relationshipId,
        signal,
        tenantId,
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
        alertId,
        attachmentId: attachment.id,
        body: { subject: attachment.subject },
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

  return (
    <DfirTabFrame>
      <SharedResourceLinks
        key={`${tenantId}:alert:${alertId}`}
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
                alertId,
                tenantId,
                csrfToken,
                signal,
                idempotencyKey: intent.eventId,
              }),
          )
        }
      />
      <AlertDfirWorkspace
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
                Every write is reauthorized against this autonomous Alert and
                active tenant. Case links never expand this workspace.
              </DialogDescription>
            </DialogHeader>
            {problem === undefined ? null : (
              <Alert variant="destructive" role="alert">
                <AlertTitle>Investigation action not completed</AlertTitle>
                <AlertDescription>
                  {safeAlertDfirProblem({ status: problem })}
                </AlertDescription>
              </Alert>
            )}
            <DialogBody
              busy={busy}
              dialog={dialog}
              {...(download ? { download } : {})}
              hasPermission={hasPermission}
              onCancel={dismissDialog}
              onCustody={(body) => void submitCustody(body)}
              onDownload={() => void prepareDownload()}
              onRetract={(body) => void submitRetraction(body)}
              onSubmit={(draft) => void submitResource(draft)}
              onTaskAction={(action) => void submitTaskAction(action)}
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
}: {
  busy: boolean;
  dialog: WorkspaceDialog;
  download?: DfirPreparedDownload;
  hasPermission: PermissionCheck;
  onCancel: () => void;
  onCustody: (body: DfirAlertCustodyAppendRequest) => void;
  onDownload: () => void;
  onRetract: (body: DfirAlertRelationshipRetractRequest) => void;
  onSubmit: (draft: DfirMutationDraft) => void;
  onTaskAction: (action: AlertTaskAction) => void;
  snapshot: AlertDfirWorkspaceSnapshot;
}): React.JSX.Element {
  if (dialog.mode === "create") {
    return (
      <DfirResourceForm
        busy={busy}
        subjectKind="alert"
        {...(dialog.panel === "relationships"
          ? {
              initialValues: {
                sourceId: snapshot.workspace.alertId,
                sourceKind: "alert",
              },
            }
          : {})}
        panel={dialog.panel}
        onCancel={onCancel}
        onSubmit={onSubmit}
      />
    );
  }

  if (dialog.panel === "iocs") {
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
        subjectKind="alert"
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

  if (dialog.panel === "assets") {
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
        subjectKind="alert"
        initialValues={{
          addresses: [
            ...item.asset.ipAddresses,
            ...item.asset.macAddresses,
          ].join(", "),
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

  if (dialog.panel === "tasks") {
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
          <AlertTaskActionForm
            busy={busy}
            checklistIds={dialog.ids.checklist}
            onCancel={onCancel}
            onSubmit={onTaskAction}
            task={task}
          />
        ) : (
          <Button type="button" variant="outline" onClick={onCancel}>
            Close
          </Button>
        )}
      </>
    );
  }

  if (dialog.panel === "evidence") {
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
          <AlertCustodyForm
            busy={busy}
            eventId={dialog.ids.custody}
            evidence={evidence}
            onCancel={onCancel}
            onSubmit={onCustody}
          />
        ) : (
          <Button type="button" variant="outline" onClick={onCancel}>
            Close
          </Button>
        )}
      </>
    );
  }

  if (dialog.panel === "attachments") {
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

  if (dialog.panel === "relationships") {
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
        {relationship.active &&
        hasPermission(managePermission.relationships) ? (
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

  const event = snapshot.workspace.timeline.find(
    (candidate) => candidate.id === dialog.resourceId,
  );
  return (
    <div className="dfir-resource-dialog__readonly">
      <ReadOnlyFacts>
        {event?.event.description ||
          event?.event.title ||
          "Timeline event unavailable."}
      </ReadOnlyFacts>
      <Button type="button" variant="outline" onClick={onCancel}>
        Close
      </Button>
    </div>
  );
}

async function createResource(
  api: AlertDfirApi,
  dialog: Extract<WorkspaceDialog, { mode: "create" }>,
  draft: DfirMutationDraft,
  context: AlertMutationContext,
  keyForStage: (stage: string, payload: unknown) => string,
  uploadCompleted: () => boolean,
  markUploadCompleted: () => void,
): Promise<void> {
  const now = dialog.intentInstant;
  switch (draft.panel) {
    case "iocs": {
      const body = {
        indicatorId: dialog.ids.resource,
        indicator: indicatorSpecFromDraft(draft, now),
      };
      await api.create({
        ...context,
        idempotencyKey: keyForStage("create", body),
        operation: { body, panel: "iocs" },
      });
      return;
    }
    case "assets": {
      const body = {
        asset: assetSpecFromDraft(draft, now),
        assetId: dialog.ids.resource,
      };
      await api.create({
        ...context,
        idempotencyKey: keyForStage("create", body),
        operation: { body, panel: "assets" },
      });
      return;
    }
    case "timeline": {
      const body = {
        event: timelineSpecFromDraft(draft, "alert"),
        timelineEventId: dialog.ids.resource,
      };
      await api.create({
        ...context,
        idempotencyKey: keyForStage("create", body),
        operation: { body, panel: "timeline" },
      });
      return;
    }
    case "tasks": {
      const body = {
        task: alertTaskSpecFromDraft(draft, dialog.ids.checklist),
        taskId: dialog.ids.resource,
      };
      await api.create({
        ...context,
        idempotencyKey: keyForStage("create", body),
        operation: { body, panel: "tasks" },
      });
      return;
    }
    case "relationships": {
      const source = relationshipReferenceFromDraft(draft, "source");
      const target = relationshipReferenceFromDraft(draft, "target");
      const body = {
        relationshipId: dialog.ids.resource,
        relationshipType: draft.relationshipType,
        source,
        target,
        ...(draft.metadata === undefined ? {} : { metadata: draft.metadata }),
      };
      await api.create({
        ...context,
        idempotencyKey: keyForStage("create", body),
        operation: { body, panel: "relationships" },
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
          subject: { id: context.alertId, kind: "alert" },
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
          subject: { id: context.alertId, kind: "alert" },
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
    }
  }
}

async function existingEvidenceAttachment(
  api: AlertDfirApi,
  context: AlertMutationContext,
  dialog: Extract<WorkspaceDialog, { mode: "create" }>,
  file: File,
): Promise<DfirAttachment | undefined> {
  const snapshot = await api.getWorkspace({
    alertId: context.alertId,
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
  api: AlertDfirApi,
  context: AlertMutationContext,
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
  context: AlertMutationContext,
  dialog: Extract<WorkspaceDialog, { mode: "create" }>,
  file: File,
): void {
  if (
    attachment.storageObjectId !== dialog.ids.storage ||
    attachment.originalFilename !== file.name ||
    attachment.subject.kind !== "alert" ||
    attachment.subject.id !== context.alertId
  ) {
    throw new AlertDfirApiError(
      "The evidence upload no longer matches this Alert.",
      409,
    );
  }
}

function evidenceRejectedError(): AlertDfirApiError {
  return new AlertDfirApiError(
    "The evidence upload did not pass protected object verification.",
    422,
  );
}

function evidencePendingError(): AlertDfirApiError {
  return new AlertDfirApiError(
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
  api: AlertDfirApi,
  snapshot: AlertDfirWorkspaceSnapshot,
  dialog: Extract<WorkspaceDialog, { mode: "open" }>,
  draft: DfirMutationDraft,
  context: {
    alertId: string;
    csrfToken: string;
    idempotencyKey: string;
    signal: AbortSignal;
    tenantId: string;
  },
): Promise<void> {
  if (dialog.panel === "iocs" && draft.panel === "iocs") {
    const current = snapshot.workspace.indicators.find(
      (item) => item.id === dialog.resourceId,
    );
    if (!current) {
      throw new AlertDfirApiError("The indicator is no longer available.", 404);
    }
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
    if (!current) {
      throw new AlertDfirApiError("The asset is no longer available.", 404);
    }
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
  throw new AlertDfirApiError("This Alert DFIR resource is append-only.");
}

function replacementVersion(
  snapshot: AlertDfirWorkspaceSnapshot,
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
  | "transition"
  | "details"
  | "assignment"
  | "due-date"
  | "checklist"
  | "comments";

function AlertTaskActionForm({
  busy,
  checklistIds,
  onCancel,
  onSubmit,
  task,
}: {
  busy: boolean;
  checklistIds: readonly string[];
  onCancel: () => void;
  onSubmit: (action: AlertTaskAction) => void;
  task: AlertDfirWorkspaceSnapshot["workspace"]["tasks"][number];
}): React.JSX.Element {
  const [kind, setKind] = useState<TaskActionKind>("transition");
  const [target, setTarget] = useState<DfirTaskStatus>(
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
              "Task instructions are too long.",
            );
            const priority = data.get("priority");
            if (!isTaskPriority(priority)) {
              throw new Error("Choose a supported task priority.");
            }
            const slaInstanceId = optionalFormText(data, "slaInstanceId");
            if (slaInstanceId && !uuidInputRegex.test(slaInstanceId)) {
              throw new Error("Use a canonical SLA instance UUID.");
            }
            setFormError(undefined);
            onSubmit({
              body: {
                description,
                expectedVersion: task.version,
                priority,
                ...(slaInstanceId ? { slaInstanceId } : {}),
                title,
              },
              kind,
            });
            return;
          }
          if (kind === "transition") {
            const reason = requireFormText(data, "reason");
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
          if (kind === "comments") {
            const commentsEntry = data.get("comments");
            if (typeof commentsEntry !== "string") return;
            setFormError(undefined);
            onSubmit({
              body: {
                commentIds: parseTaskCommentIntent(commentsEntry, "Alert"),
                expectedVersion: task.version,
              },
              kind,
            });
            return;
          }
          const checklistEntry = data.get("checklist");
          if (typeof checklistEntry !== "string") return;
          setFormError(undefined);
          onSubmit({
            body: {
              checklist: parseTaskChecklistIntent(
                checklistEntry,
                task.checklist,
                checklistIds,
                "Alert",
              ),
              expectedVersion: task.version,
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
      <fieldset disabled={busy}>
        <legend>Update task</legend>
        <div>
          <Label htmlFor="alert-dfir-task-action">Action</Label>
          <select
            id="alert-dfir-task-action"
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
              <Label htmlFor="alert-dfir-task-title">Task title</Label>
              <Input
                id="alert-dfir-task-title"
                name="title"
                defaultValue={task.title}
                maxLength={512}
                required
              />
            </div>
            <div>
              <Label htmlFor="alert-dfir-task-description">Instructions</Label>
              <Textarea
                id="alert-dfir-task-description"
                name="description"
                defaultValue={task.description}
                maxLength={16_384}
              />
            </div>
            <div>
              <Label htmlFor="alert-dfir-task-priority">Priority</Label>
              <select
                id="alert-dfir-task-priority"
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
              <Label htmlFor="alert-dfir-task-sla">
                SLA instance UUID (empty clears)
              </Label>
              <Input
                id="alert-dfir-task-sla"
                name="slaInstanceId"
                defaultValue={task.slaInstanceId ?? ""}
                maxLength={36}
                pattern={uuidInputPattern}
              />
            </div>
          </>
        ) : null}
        {kind === "transition" ? (
          <>
            <div>
              <Label htmlFor="alert-dfir-task-target">Target state</Label>
              <select
                id="alert-dfir-task-target"
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
              <Label htmlFor="alert-dfir-task-reason">Reason</Label>
              <Input
                id="alert-dfir-task-reason"
                name="reason"
                required
                maxLength={2_000}
              />
            </div>
            {terminalTaskStatus(target) ? (
              <div>
                <Label htmlFor="alert-dfir-task-completion">
                  Completion data (JSON object)
                </Label>
                <Textarea
                  id="alert-dfir-task-completion"
                  name="completionData"
                  maxLength={65_536}
                />
              </div>
            ) : null}
          </>
        ) : null}
        {kind === "assignment" ? (
          <>
            <div>
              <Label htmlFor="alert-dfir-task-team">
                Operator team UUID (empty clears)
              </Label>
              <Input
                id="alert-dfir-task-team"
                name="operatorTeamId"
                defaultValue={task.operatorTeamId ?? ""}
                maxLength={36}
                pattern={uuidInputPattern}
              />
            </div>
            <div>
              <Label htmlFor="alert-dfir-task-assignee">
                Assignee UUID (optional)
              </Label>
              <Input
                id="alert-dfir-task-assignee"
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
            <Label htmlFor="alert-dfir-task-due">Due date (empty clears)</Label>
            <Input
              id="alert-dfir-task-due"
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
            <Label htmlFor="alert-dfir-task-checklist">
              Checklist, one [ ] or [x] item per line
            </Label>
            <Textarea
              id="alert-dfir-task-checklist"
              name="checklist"
              defaultValue={formatChecklistIntent(task.checklist)}
              maxLength={51_500}
              rows={8}
            />
          </div>
        ) : null}
        {kind === "comments" ? (
          <div>
            <Label htmlFor="alert-dfir-task-comments">
              Comment UUIDv7s, one per line (empty clears)
            </Label>
            <Textarea
              id="alert-dfir-task-comments"
              name="comments"
              defaultValue={task.commentIds.join("\n")}
              maxLength={36_999}
              rows={8}
            />
          </div>
        ) : null}
        {formError ? <p role="alert">{formError}</p> : null}
        <FormActions
          busy={busy}
          label="Apply task action"
          onCancel={onCancel}
        />
      </fieldset>
    </form>
  );
}

function AlertCustodyForm({
  busy,
  eventId,
  evidence,
  onCancel,
  onSubmit,
}: {
  busy: boolean;
  eventId: string;
  evidence: AlertDfirWorkspaceSnapshot["workspace"]["evidence"][number];
  onCancel: () => void;
  onSubmit: (body: DfirAlertCustodyAppendRequest) => void;
}): React.JSX.Element {
  const [action, setAction] = useState<DfirCustodyAction>("accessed");
  const [formError, setFormError] = useState<string>();
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
        try {
          const data = new FormData(event.currentTarget);
          const common = {
            action,
            custodyEventId: eventId,
            expectedVersion: evidence.version,
            reason: requireFormText(data, "reason"),
          };
          setFormError(undefined);
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
            const retentionUntil = optionalFormText(data, "retentionUntil");
            onSubmit({
              ...common,
              retentionUntil: retentionUntil
                ? formInstant(retentionUntil)
                : null,
            });
            return;
          }
          onSubmit(common);
        } catch (error) {
          setFormError(
            error instanceof Error
              ? error.message
              : "Review the custody event before retrying.",
          );
        }
      }}
    >
      <fieldset disabled={busy}>
        <legend>Append custody event</legend>
        <div>
          <Label htmlFor="alert-dfir-custody-action">Action</Label>
          <select
            id="alert-dfir-custody-action"
            value={action}
            onChange={(event) => {
              if (isCustodyAction(event.currentTarget.value)) {
                setAction(event.currentTarget.value);
              }
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
            <Label htmlFor="alert-dfir-custody-scan">Scan state</Label>
            <select
              id="alert-dfir-custody-scan"
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
            <Label htmlFor="alert-dfir-custody-retention">
              Retention until (empty clears)
            </Label>
            <Input
              id="alert-dfir-custody-retention"
              name="retentionUntil"
              type="datetime-local"
            />
          </div>
        ) : null}
        <div>
          <Label htmlFor="alert-dfir-custody-reason">Reason</Label>
          <Input
            id="alert-dfir-custody-reason"
            name="reason"
            required
            maxLength={2_000}
          />
        </div>
        {formError ? <p role="alert">{formError}</p> : null}
        <FormActions
          busy={busy}
          label="Append custody event"
          onCancel={onCancel}
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
  onSubmit: (body: DfirAlertRelationshipRetractRequest) => void;
  retractionId: string;
}): React.JSX.Element {
  const [formError, setFormError] = useState<string>();
  return (
    <form
      className="dfir-compact-form"
      onSubmit={(event) => {
        event.preventDefault();
        try {
          const data = new FormData(event.currentTarget);
          const reason = requireFormText(data, "reason");
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
          <Label htmlFor="alert-dfir-relationship-reason">Reason</Label>
          <Input
            id="alert-dfir-relationship-reason"
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
      <Button
        type="button"
        variant="outline"
        disabled={busy}
        onClick={onCancel}
      >
        Cancel
      </Button>
      <Button type="submit" disabled={busy}>
        {busy ? "Saving…" : label}
      </Button>
    </div>
  );
}

function newDialog(
  mode: WorkspaceDialog["mode"],
  panel: DfirAlertPanel,
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
  return `${dialog.mode === "create" ? "Add" : "Open"} ${dialog.panel.replaceAll("_", " ")}`;
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
      This Alert investigation resource is no longer in the current workspace.
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

function formInstant(value: string): string {
  const instant = new Date(value);
  if (!Number.isFinite(instant.valueOf())) {
    throw new AlertDfirApiError(
      "A valid Alert investigation timestamp is required.",
      400,
    );
  }
  return instant.toISOString();
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

function isTaskStatus(value: string): value is DfirTaskStatus {
  return taskStatuses.some((item) => item === value);
}

function isTaskActionKind(value: string): value is TaskActionKind {
  return (
    value === "transition" ||
    value === "details" ||
    value === "assignment" ||
    value === "due-date" ||
    value === "checklist" ||
    value === "comments"
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

function isScanState(value: FormDataEntryValue | null): value is DfirScanState {
  return (
    typeof value === "string" &&
    selectableScanStates.some((item) => item === value)
  );
}

function isCustodyAction(value: string): value is DfirCustodyAction {
  return custodyActions.some((item) => item === value);
}

function requireFormText(data: FormData, name: string): string {
  const value = optionalFormText(data, name);
  if (!value || value.length > 2_000) {
    throw new AlertDfirApiError(
      "A bounded reason is required for this Alert investigation action.",
      400,
    );
  }
  return value;
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
  checklist: AlertDfirWorkspaceSnapshot["workspace"]["tasks"][number]["checklist"],
): string {
  return checklist
    .map((item) => `[${item.completed ? "x" : " "}] ${item.title}`)
    .join("\n");
}

function apiErrorStatus(error: unknown): number {
  return error instanceof AlertDfirApiError ? (error.status ?? 500) : 500;
}

function isAbortError(error: unknown): boolean {
  return error instanceof DOMException && error.name === "AbortError";
}
